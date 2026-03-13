#![forbid(unsafe_code)]
//! Integration tests for the `replacement_lineage_log` module.
//!
//! Exercises lineage log append/query, hash-chain integrity, Merkle proofs,
//! checkpoints, consistency proofs, slot lineage, auditing, and serde
//! round-trips from outside the crate boundary.

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

use std::collections::BTreeSet;

use frankenengine_engine::replacement_lineage_log::{
    AuditResult, EvidenceCategory, LineageLogConfig, LineageLogError, LineageLogEvent,
    LineageQuery, ProofDirection, ReplacementKind, ReplacementLineageLog, verify_consistency_proof,
    verify_inclusion_proof,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    CreateReceiptInput, ReplacementReceipt, ValidationArtifactKind, ValidationArtifactRef,
};
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::slot_registry::SlotId;

// ===========================================================================
// Helpers
// ===========================================================================

fn test_epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(3)
}

fn test_slot_id() -> SlotId {
    SlotId::new("lineage-slot-1").unwrap()
}

fn test_signing_key() -> SigningKey {
    SigningKey::from_bytes([5u8; 32])
}

fn test_validation_artifacts() -> Vec<ValidationArtifactRef> {
    vec![ValidationArtifactRef {
        kind: ValidationArtifactKind::EquivalenceResult,
        artifact_digest: "digest-equiv".into(),
        passed: true,
        summary: "Passed".into(),
    }]
}

fn make_receipt(old: &str, new: &str, ts_ns: u64) -> ReplacementReceipt {
    let arts = test_validation_artifacts();
    let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &test_slot_id(),
        old_cell_digest: old,
        new_cell_digest: new,
        validation_artifacts: &arts,
        rollback_token: "rollback-token",
        promotion_rationale: "Testing lineage log",
        timestamp_ns: ts_ns,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();
    receipt
        .add_signature(&test_signing_key(), "gate-runner")
        .unwrap();
    receipt
}

fn default_config() -> LineageLogConfig {
    LineageLogConfig {
        checkpoint_interval: 100,
        max_entries_in_memory: 0,
    }
}

// ===========================================================================
// 1. ReplacementKind
// ===========================================================================

#[test]
fn replacement_kind_as_str() {
    assert!(!ReplacementKind::DelegateToNative.as_str().is_empty());
    assert!(!ReplacementKind::Demotion.as_str().is_empty());
    assert!(!ReplacementKind::Rollback.as_str().is_empty());
    assert!(!ReplacementKind::RePromotion.as_str().is_empty());
}

#[test]
fn replacement_kind_display() {
    let kinds = [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::Rollback,
        ReplacementKind::RePromotion,
    ];
    for k in &kinds {
        let s = k.to_string();
        assert!(!s.is_empty());
    }
}

#[test]
fn replacement_kind_serde_round_trip() {
    for k in [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::Rollback,
        ReplacementKind::RePromotion,
    ] {
        let json = serde_json::to_string(&k).unwrap();
        let back: ReplacementKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, k);
    }
}

// ===========================================================================
// 2. ProofDirection
// ===========================================================================

#[test]
fn proof_direction_serde_round_trip() {
    for d in [ProofDirection::Left, ProofDirection::Right] {
        let json = serde_json::to_string(&d).unwrap();
        let back: ProofDirection = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }
}

// ===========================================================================
// 3. EvidenceCategory
// ===========================================================================

#[test]
fn evidence_category_display_and_serde() {
    let cats = [
        EvidenceCategory::GateResult,
        EvidenceCategory::PerformanceBenchmark,
        EvidenceCategory::SentinelRiskScore,
        EvidenceCategory::DifferentialExecutionLog,
        EvidenceCategory::Additional,
    ];
    for c in &cats {
        assert!(!c.as_str().is_empty());
        let json = serde_json::to_string(c).unwrap();
        let back: EvidenceCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, c);
    }
}

// ===========================================================================
// 4. LineageLogConfig
// ===========================================================================

#[test]
fn lineage_log_config_default() {
    let config = LineageLogConfig::default();
    assert!(config.checkpoint_interval > 0);
}

#[test]
fn lineage_log_config_serde_round_trip() {
    let config = LineageLogConfig {
        checkpoint_interval: 50,
        max_entries_in_memory: 1000,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: LineageLogConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back, config);
}

// ===========================================================================
// 5. ReplacementLineageLog — basic operations
// ===========================================================================

#[test]
fn log_starts_empty() {
    let log = ReplacementLineageLog::new(default_config());
    assert!(log.is_empty());
    assert_eq!(log.len(), 0);
    assert!(log.entries().is_empty());
    assert!(log.checkpoints().is_empty());
}

#[test]
fn log_append_single() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    let seq = log
        .append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    assert_eq!(seq, 0);
    assert_eq!(log.len(), 1);
    assert!(!log.is_empty());
}

#[test]
fn log_append_multiple() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0..5 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        let seq = log
            .append(
                receipt,
                ReplacementKind::DelegateToNative,
                (i + 1) * 1_000_000,
            )
            .unwrap();
        assert_eq!(seq, i);
    }
    assert_eq!(log.len(), 5);
}

// ===========================================================================
// 6. Hash chain integrity
// ===========================================================================

#[test]
fn log_entries_have_hash_chain() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0..3 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }

    let entries = log.entries();
    // Second entry's predecessor_hash should equal first entry's entry_hash
    assert_eq!(entries[1].predecessor_hash, entries[0].entry_hash);
    assert_eq!(entries[2].predecessor_hash, entries[1].entry_hash);
}

// ===========================================================================
// 7. Merkle root and inclusion proofs
// ===========================================================================

#[test]
fn log_merkle_root_changes_on_append() {
    let mut log = ReplacementLineageLog::new(default_config());
    let root_empty = log.merkle_root();

    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let root_one = log.merkle_root();
    assert_ne!(root_empty, root_one);

    let receipt2 = make_receipt("old-b", "new-b", 2_000_000);
    log.append(receipt2, ReplacementKind::DelegateToNative, 2_000_000)
        .unwrap();
    let root_two = log.merkle_root();
    assert_ne!(root_one, root_two);
}

#[test]
fn inclusion_proof_verifies() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0..4 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }

    // Get inclusion proof for entry 2
    let proof = log.inclusion_proof(2).unwrap();
    assert_eq!(proof.entry_index, 2);
    assert!(verify_inclusion_proof(&proof));
}

#[test]
fn inclusion_proof_missing_entry() {
    let log = ReplacementLineageLog::new(default_config());
    assert!(log.inclusion_proof(0).is_none());
}

// ===========================================================================
// 8. Checkpoints
// ===========================================================================

#[test]
fn create_checkpoint() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    let cp_seq = log.create_checkpoint(2_000_000, test_epoch()).unwrap();
    assert_eq!(cp_seq, 0);
    assert_eq!(log.checkpoints().len(), 1);

    let cp = &log.checkpoints()[0];
    assert_eq!(cp.checkpoint_seq, 0);
    assert_eq!(cp.log_length, 1);
    assert_eq!(cp.epoch, test_epoch());
}

#[test]
fn checkpoint_empty_log_error() {
    let mut log = ReplacementLineageLog::new(default_config());
    match log.create_checkpoint(1_000_000, test_epoch()) {
        Err(LineageLogError::EmptyLog) => {}
        other => panic!("expected EmptyLog, got {other:?}"),
    }
}

// ===========================================================================
// 9. Consistency proofs
// ===========================================================================

#[test]
fn consistency_proof_between_checkpoints() {
    let mut log = ReplacementLineageLog::new(default_config());

    // Add some entries, checkpoint, add more, checkpoint again
    for i in 0..3 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }
    log.create_checkpoint(4_000_000, test_epoch()).unwrap();

    for i in 3..6 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }
    log.create_checkpoint(7_000_000, test_epoch()).unwrap();

    let proof = log.consistency_proof(0, 1).unwrap();
    assert!(verify_consistency_proof(&proof));
}

// ===========================================================================
// 10. Query
// ===========================================================================

#[test]
fn query_all() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0..3 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }

    let all = log.query(&LineageQuery::all());
    assert_eq!(all.len(), 3);
}

#[test]
fn query_by_slot_id() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    let results = log.query(&LineageQuery::for_slot(test_slot_id()));
    assert_eq!(results.len(), 1);

    let other_slot = SlotId::new("other-slot").unwrap();
    let results = log.query(&LineageQuery::for_slot(other_slot));
    assert!(results.is_empty());
}

#[test]
fn query_by_kind_filter() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r1 = make_receipt("old-a", "new-a", 1_000_000);
    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let r2 = make_receipt("new-a", "old-a", 2_000_000);
    log.append(r2, ReplacementKind::Demotion, 2_000_000)
        .unwrap();

    let query = LineageQuery {
        slot_id: None,
        kinds: Some(BTreeSet::from([ReplacementKind::Demotion])),
        min_timestamp_ns: None,
        max_timestamp_ns: None,
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].kind, ReplacementKind::Demotion);
}

// ===========================================================================
// 11. Slot lineage
// ===========================================================================

#[test]
fn slot_lineage_empty() {
    let log = ReplacementLineageLog::new(default_config());
    let lineage = log.slot_lineage(&test_slot_id());
    assert!(lineage.is_empty());
}

#[test]
fn slot_lineage_with_entries() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r1 = make_receipt("old-a", "new-a", 1_000_000);
    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let r2 = make_receipt("new-a", "old-a", 2_000_000);
    log.append(r2, ReplacementKind::Demotion, 2_000_000)
        .unwrap();

    let lineage = log.slot_lineage(&test_slot_id());
    assert_eq!(lineage.len(), 2);
    assert_eq!(lineage[0].kind, ReplacementKind::DelegateToNative);
    assert_eq!(lineage[1].kind, ReplacementKind::Demotion);
}

// ===========================================================================
// 12. Slot lineage verification
// ===========================================================================

#[test]
fn verify_slot_lineage_valid() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    let verification = log.verify_slot_lineage(&test_slot_id());
    assert!(verification.chain_valid);
    assert_eq!(verification.total_entries, 1);
}

// ===========================================================================
// 13. Audit
// ===========================================================================

#[test]
fn audit_empty_log() {
    let log = ReplacementLineageLog::new(default_config());
    let result = log.audit();
    assert_eq!(result.total_entries, 0);
    assert!(result.chain_valid);
    assert!(result.merkle_valid);
}

#[test]
fn audit_populated_log() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0..4 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }
    log.create_checkpoint(5_000_000, test_epoch()).unwrap();

    let result = log.audit();
    assert_eq!(result.total_entries, 4);
    assert!(result.chain_valid);
    assert!(result.merkle_valid);
    assert_eq!(result.checkpoint_count, 1);
}

// ===========================================================================
// 14. Slot IDs
// ===========================================================================

#[test]
fn slot_ids_distinct() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    let ids = log.slot_ids();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0], test_slot_id());
}

// ===========================================================================
// 15. LineageLogError serde
// ===========================================================================

#[test]
fn lineage_log_error_serde_round_trip() {
    let errors = vec![
        LineageLogError::SequenceMismatch {
            expected: 3,
            got: 5,
        },
        LineageLogError::DuplicateReceipt {
            receipt_id: "r-1".into(),
        },
        LineageLogError::CheckpointNotFound { checkpoint_seq: 42 },
        LineageLogError::EmptyLog,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: LineageLogError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

// ===========================================================================
// 16. Serde round-trips for data types
// ===========================================================================

#[test]
fn lineage_query_serde_round_trip() {
    let query = LineageQuery {
        slot_id: Some(test_slot_id()),
        kinds: Some(BTreeSet::from([
            ReplacementKind::DelegateToNative,
            ReplacementKind::Demotion,
        ])),
        min_timestamp_ns: Some(1_000_000),
        max_timestamp_ns: Some(5_000_000),
    };
    let json = serde_json::to_string(&query).unwrap();
    let back: LineageQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, query);
}

#[test]
fn lineage_log_event_serde_round_trip() {
    let event = LineageLogEvent {
        trace_id: "trace-1".into(),
        decision_id: "dec-1".into(),
        policy_id: "pol-1".into(),
        component: "lineage-log".into(),
        event: "append".into(),
        outcome: "success".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: LineageLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn audit_result_serde_round_trip() {
    let result = AuditResult {
        total_entries: 10,
        total_slots: 2,
        chain_valid: true,
        merkle_valid: true,
        checkpoint_count: 1,
        latest_checkpoint_seq: Some(0),
        issues: vec![],
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: AuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
}

// ===========================================================================
// 17. Full lifecycle
// ===========================================================================

#[test]
fn full_lifecycle_lineage_log() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig {
        checkpoint_interval: 3,
        max_entries_in_memory: 0,
    });

    // 1. Append several replacement events
    for i in 0..5 {
        let receipt = make_receipt(
            &format!("cell-v{i}"),
            &format!("cell-v{}", i + 1),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }
    assert_eq!(log.len(), 5);

    // 2. Create a checkpoint
    let _cp_seq = log.create_checkpoint(6_000_000, test_epoch()).unwrap();

    // 3. Verify hash chain
    let entries = log.entries();
    for i in 1..entries.len() {
        assert_eq!(entries[i].predecessor_hash, entries[i - 1].entry_hash);
    }

    // 4. Generate and verify inclusion proof
    let proof = log.inclusion_proof(2).unwrap();
    assert!(verify_inclusion_proof(&proof));

    // 5. Query by slot
    let results = log.query(&LineageQuery::for_slot(test_slot_id()));
    assert_eq!(results.len(), 5);

    // 6. Get slot lineage
    let lineage = log.slot_lineage(&test_slot_id());
    assert_eq!(lineage.len(), 5);

    // 7. Verify slot lineage
    let verification = log.verify_slot_lineage(&test_slot_id());
    assert!(verification.chain_valid);

    // 8. Audit
    let audit = log.audit();
    assert_eq!(audit.total_entries, 5);
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);

    // 9. Serde round-trip of the entire log
    let json = serde_json::to_string(&log).unwrap();
    let back: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 5);
}

// ===========================================================================
// 18. LineageLogError Display coverage
// ===========================================================================

#[test]
fn lineage_log_error_display_all_variants() {
    let errors: Vec<(LineageLogError, &str)> = vec![
        (
            LineageLogError::SequenceMismatch {
                expected: 3,
                got: 5,
            },
            "sequence mismatch",
        ),
        (
            LineageLogError::DuplicateReceipt {
                receipt_id: "r-dup".into(),
            },
            "duplicate receipt",
        ),
        (
            LineageLogError::CheckpointNotFound { checkpoint_seq: 7 },
            "checkpoint not found",
        ),
        (LineageLogError::EmptyLog, "log is empty"),
    ];
    for (err, expected_substr) in &errors {
        let display = err.to_string();
        assert!(
            display.contains(expected_substr),
            "Expected '{expected_substr}' in '{display}'"
        );
    }
}

// ===========================================================================
// 19. Consistency proof error paths
// ===========================================================================

#[test]
fn consistency_proof_invalid_checkpoint_order() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0..3 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }
    log.create_checkpoint(4_000_000, test_epoch()).unwrap();

    // Same checkpoint seq for older and newer (older >= newer)
    match log.consistency_proof(0, 0) {
        Err(LineageLogError::InvalidCheckpointOrder { older, newer }) => {
            assert_eq!(older, 0);
            assert_eq!(newer, 0);
        }
        other => panic!("expected InvalidCheckpointOrder, got {other:?}"),
    }
}

#[test]
fn consistency_proof_checkpoint_not_found() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(2_000_000, test_epoch()).unwrap();

    // Checkpoint seq 99 does not exist
    match log.consistency_proof(0, 99) {
        Err(LineageLogError::CheckpointNotFound { checkpoint_seq }) => {
            assert_eq!(checkpoint_seq, 99);
        }
        other => panic!("expected CheckpointNotFound, got {other:?}"),
    }
}

// ===========================================================================
// 20. Query with timestamp filters
// ===========================================================================

#[test]
fn query_with_min_and_max_timestamp() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0..5 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }

    // Only entries with timestamp in [2_000_000, 4_000_000]
    let query = LineageQuery {
        slot_id: None,
        kinds: None,
        min_timestamp_ns: Some(2_000_000),
        max_timestamp_ns: Some(4_000_000),
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 3);
    for entry in &results {
        assert!(entry.receipt.timestamp_ns >= 2_000_000);
        assert!(entry.receipt.timestamp_ns <= 4_000_000);
    }
}

#[test]
fn query_with_only_min_timestamp() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0..5 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }

    let query = LineageQuery {
        slot_id: None,
        kinds: None,
        min_timestamp_ns: Some(4_000_000),
        max_timestamp_ns: None,
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 2);
}

// ===========================================================================
// 21. Duplicate receipt rejection
// ===========================================================================

#[test]
fn append_duplicate_receipt_is_rejected() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(
        receipt.clone(),
        ReplacementKind::DelegateToNative,
        1_000_000,
    )
    .unwrap();

    match log.append(receipt, ReplacementKind::Demotion, 2_000_000) {
        Err(LineageLogError::DuplicateReceipt { receipt_id }) => {
            assert!(!receipt_id.is_empty());
        }
        other => panic!("expected DuplicateReceipt, got {other:?}"),
    }
}

// ===========================================================================
// 22. Events accessor
// ===========================================================================

#[test]
fn events_emitted_on_append_and_checkpoint() {
    let mut log = ReplacementLineageLog::new(default_config());
    assert!(log.events().is_empty());

    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    // At least one event emitted for append
    assert!(!log.events().is_empty());
    let append_event_count = log.events().len();

    log.create_checkpoint(2_000_000, test_epoch()).unwrap();
    // Checkpoint creates an additional event
    assert!(log.events().len() > append_event_count);

    // Verify event fields are populated
    for event in log.events() {
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
        assert!(!event.policy_id.is_empty());
        assert!(!event.component.is_empty());
        assert!(!event.event.is_empty());
        assert_eq!(event.outcome, "ok");
    }
}

// ===========================================================================
// 23. Merkle root determinism
// ===========================================================================

#[test]
fn merkle_root_is_deterministic() {
    // Two logs with identical entries must produce the same Merkle root.
    let mut log1 = ReplacementLineageLog::new(default_config());
    let mut log2 = ReplacementLineageLog::new(default_config());

    for i in 0..4 {
        let r1 = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        let r2 = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log1.append(r1, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
        log2.append(r2, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }

    assert_eq!(log1.merkle_root(), log2.merkle_root());
}

// ===========================================================================
// 24. Multiple slots in the same log
// ===========================================================================

#[test]
fn multiple_slots_tracked_independently() {
    let mut log = ReplacementLineageLog::new(default_config());

    // Create receipts for different slots
    let arts = test_validation_artifacts();
    let slot_a = SlotId::new("slot-alpha").unwrap();
    let slot_b = SlotId::new("slot-beta").unwrap();

    let mut r1 = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &slot_a,
        old_cell_digest: "old-alpha",
        new_cell_digest: "new-alpha",
        validation_artifacts: &arts,
        rollback_token: "rollback-a",
        promotion_rationale: "promote alpha",
        timestamp_ns: 1_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();
    r1.add_signature(&test_signing_key(), "gate").unwrap();

    let mut r2 = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &slot_b,
        old_cell_digest: "old-beta",
        new_cell_digest: "new-beta",
        validation_artifacts: &arts,
        rollback_token: "rollback-b",
        promotion_rationale: "promote beta",
        timestamp_ns: 2_000_000,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();
    r2.add_signature(&test_signing_key(), "gate").unwrap();

    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.append(r2, ReplacementKind::DelegateToNative, 2_000_000)
        .unwrap();

    let ids = log.slot_ids();
    assert_eq!(ids.len(), 2);

    let lineage_a = log.slot_lineage(&slot_a);
    assert_eq!(lineage_a.len(), 1);
    assert_eq!(lineage_a[0].old_cell_digest, "old-alpha");

    let lineage_b = log.slot_lineage(&slot_b);
    assert_eq!(lineage_b.len(), 1);
    assert_eq!(lineage_b[0].old_cell_digest, "old-beta");
}

// ===========================================================================
// 25. LineageStep serde round-trip
// ===========================================================================

#[test]
fn lineage_step_serde_round_trip() {
    use frankenengine_engine::replacement_lineage_log::LineageStep;

    let step = LineageStep {
        sequence: 42,
        kind: ReplacementKind::Rollback,
        old_cell_digest: "old-digest-abc".into(),
        new_cell_digest: "new-digest-def".into(),
        receipt_id: "receipt-999".into(),
        timestamp_ns: 12_345_678,
        epoch: SecurityEpoch::from_raw(7),
        validation_artifact_count: 3,
    };
    let json = serde_json::to_string(&step).unwrap();
    let back: LineageStep = serde_json::from_str(&json).unwrap();
    assert_eq!(back, step);
}

// ===========================================================================
// 26. LineageVerification serde round-trip
// ===========================================================================

#[test]
fn lineage_verification_serde_round_trip() {
    use frankenengine_engine::replacement_lineage_log::LineageVerification;

    let v = LineageVerification {
        slot_id: test_slot_id(),
        total_entries: 5,
        chain_valid: true,
        all_receipts_present: true,
        issues: vec!["minor issue".into()],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: LineageVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ===========================================================================
// 27. ConsistencyProof serde round-trip
// ===========================================================================

#[test]
fn consistency_proof_serde_round_trip() {
    use frankenengine_engine::hash_tiers::ContentHash;
    use frankenengine_engine::replacement_lineage_log::ConsistencyProof;

    let h1 = ContentHash::compute(b"older-root");
    let h2 = ContentHash::compute(b"newer-root");
    let eh1 = ContentHash::compute(b"entry-1");
    let eh2 = ContentHash::compute(b"entry-2");

    let proof = ConsistencyProof {
        older_checkpoint_seq: 0,
        newer_checkpoint_seq: 1,
        older_log_length: 1,
        newer_log_length: 2,
        older_root: h1,
        newer_root: h2,
        older_entry_hashes: vec![eh1],
        newer_entry_hashes: vec![eh1, eh2],
    };
    let json = serde_json::to_string(&proof).unwrap();
    let back: ConsistencyProof = serde_json::from_str(&json).unwrap();
    assert_eq!(back, proof);
}

// ===========================================================================
// 28. InclusionProof serde round-trip
// ===========================================================================

#[test]
fn inclusion_proof_serde_round_trip() {
    use frankenengine_engine::replacement_lineage_log::InclusionProof;

    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0..3 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }

    let proof = log.inclusion_proof(1).unwrap();
    let json = serde_json::to_string(&proof).unwrap();
    let back: InclusionProof = serde_json::from_str(&json).unwrap();
    assert_eq!(back, proof);
    // Deserialized proof still verifies
    assert!(verify_inclusion_proof(&back));
}

// ===========================================================================
// 29. LogCheckpoint serde round-trip
// ===========================================================================

#[test]
fn log_checkpoint_serde_round_trip() {
    use frankenengine_engine::replacement_lineage_log::LogCheckpoint;

    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(2_000_000, test_epoch()).unwrap();

    let cp = log.checkpoints()[0].clone();
    let json = serde_json::to_string(&cp).unwrap();
    let back: LogCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(back, cp);
}

// ===========================================================================
// 30. Verify slot lineage for empty/missing slot
// ===========================================================================

#[test]
fn verify_slot_lineage_for_missing_slot() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    let other_slot = SlotId::new("nonexistent-slot").unwrap();
    let v = log.verify_slot_lineage(&other_slot);
    assert_eq!(v.total_entries, 0);
    assert!(v.chain_valid);
    assert!(!v.issues.is_empty(), "should report no entries for slot");
}

// ===========================================================================
// 31. ReplacementKind clone and Ord
// ===========================================================================

#[test]
fn replacement_kind_clone_and_ordering() {
    let kinds = [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::Rollback,
        ReplacementKind::RePromotion,
    ];

    // Clone produces equal values
    for k in &kinds {
        assert_eq!(k.clone(), *k);
    }

    // BTreeSet ordering is deterministic
    let set: BTreeSet<ReplacementKind> = kinds.iter().copied().collect();
    assert_eq!(set.len(), 4);

    // Inserting duplicates doesn't increase size
    let mut set2 = set.clone();
    set2.insert(ReplacementKind::Rollback);
    assert_eq!(set2.len(), 4);
}

// ===========================================================================
// 32. Inclusion proof for all entries in a multi-entry log
// ===========================================================================

#[test]
fn inclusion_proof_verifies_for_all_entries() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0..7 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }

    for i in 0..7 {
        let proof = log.inclusion_proof(i).expect("proof should exist");
        assert_eq!(proof.entry_index, i);
        assert!(
            verify_inclusion_proof(&proof),
            "inclusion proof failed for entry {i}"
        );
    }

    // Out-of-bounds returns None
    assert!(log.inclusion_proof(7).is_none());
    assert!(log.inclusion_proof(100).is_none());
}

// ===========================================================================
// 33. EvidencePointerInput serde round-trip
// ===========================================================================

#[test]
fn evidence_pointer_input_serde_round_trip() {
    use frankenengine_engine::replacement_lineage_log::EvidencePointerInput;

    let input = EvidencePointerInput {
        category: EvidenceCategory::SentinelRiskScore,
        artifact_digest: "sha256:abcdef1234567890".into(),
        passed: Some(true),
        summary: "Risk score within threshold".into(),
    };
    let json = serde_json::to_string(&input).unwrap();
    let back: EvidencePointerInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back, input);

    // Also test with passed = None
    let input_none = EvidencePointerInput {
        category: EvidenceCategory::Additional,
        artifact_digest: "digest-extra".into(),
        passed: None,
        summary: "Informational".into(),
    };
    let json2 = serde_json::to_string(&input_none).unwrap();
    let back2: EvidencePointerInput = serde_json::from_str(&json2).unwrap();
    assert_eq!(back2, input_none);
}

// ===========================================================================
// 34. EvidencePointer serde round-trip
// ===========================================================================

#[test]
fn evidence_pointer_serde_round_trip() {
    use frankenengine_engine::replacement_lineage_log::EvidencePointer;

    let pointer = EvidencePointer {
        receipt_id: "receipt-42".into(),
        category: EvidenceCategory::PerformanceBenchmark,
        artifact_digest: "perf-digest-001".into(),
        passed: Some(false),
        summary: "Benchmark regression detected".into(),
    };
    let json = serde_json::to_string(&pointer).unwrap();
    let back: EvidencePointer = serde_json::from_str(&json).unwrap();
    assert_eq!(back, pointer);
}

// ===========================================================================
// 35. SlotLineageQuery Default and serde
// ===========================================================================

#[test]
fn slot_lineage_query_default_and_serde() {
    use frankenengine_engine::replacement_lineage_log::SlotLineageQuery;

    let default_q = SlotLineageQuery::default();
    assert!(default_q.min_timestamp_ns.is_none());
    assert!(default_q.max_timestamp_ns.is_none());
    assert!(default_q.limit.is_none());

    let q = SlotLineageQuery {
        min_timestamp_ns: Some(100),
        max_timestamp_ns: Some(999),
        limit: Some(10),
    };
    let json = serde_json::to_string(&q).unwrap();
    let back: SlotLineageQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, q);
}

// ===========================================================================
// 36. ReplayJoinQuery Default and serde
// ===========================================================================

#[test]
fn replay_join_query_default_and_serde() {
    use frankenengine_engine::replacement_lineage_log::ReplayJoinQuery;

    let default_q = ReplayJoinQuery::default();
    assert!(default_q.slot_id.is_none());
    assert!(default_q.min_timestamp_ns.is_none());
    assert!(default_q.max_timestamp_ns.is_none());
    assert!(default_q.limit.is_none());

    let q = ReplayJoinQuery {
        slot_id: Some(test_slot_id()),
        min_timestamp_ns: Some(500),
        max_timestamp_ns: Some(5000),
        limit: Some(25),
    };
    let json = serde_json::to_string(&q).unwrap();
    let back: ReplayJoinQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, q);
}

// ===========================================================================
// 37. LineageIndexEvent serde round-trip
// ===========================================================================

#[test]
fn lineage_index_event_serde_round_trip() {
    use frankenengine_engine::replacement_lineage_log::LineageIndexEvent;

    let event = LineageIndexEvent {
        trace_id: "trace-idx-1".into(),
        decision_id: "dec-idx-1".into(),
        policy_id: "policy-idx-1".into(),
        component: "replacement_lineage_index".into(),
        event: "index_replacement_receipt".into(),
        outcome: "ok".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: LineageIndexEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);

    // With error_code present
    let event_err = LineageIndexEvent {
        trace_id: "trace-idx-2".into(),
        decision_id: "dec-idx-2".into(),
        policy_id: "policy-idx-2".into(),
        component: "replacement_lineage_index".into(),
        event: "index_demotion_receipt".into(),
        outcome: "error".into(),
        error_code: Some("FE-LIDX-0004".into()),
    };
    let json2 = serde_json::to_string(&event_err).unwrap();
    let back2: LineageIndexEvent = serde_json::from_str(&json2).unwrap();
    assert_eq!(back2, event_err);
}

// ===========================================================================
// 38. LineageIndexError code() and Display
// ===========================================================================

#[test]
fn lineage_index_error_code_and_display() {
    use frankenengine_engine::replacement_lineage_log::LineageIndexError;
    use frankenengine_engine::storage_adapter::{StorageError, StoreKind};

    let errors: Vec<(LineageIndexError, &str, &str)> = vec![
        (
            LineageIndexError::Storage(StorageError::NotFound {
                store: StoreKind::ReplacementLineage,
                key: "missing-key".into(),
            }),
            "FE-LIDX-0001",
            "storage error",
        ),
        (
            LineageIndexError::Serialization {
                operation: "serialize".into(),
                detail: "bad format".into(),
            },
            "FE-LIDX-0002",
            "serialization error",
        ),
        (
            LineageIndexError::CorruptRecord {
                key: "bad-key".into(),
                detail: "unreadable".into(),
            },
            "FE-LIDX-0003",
            "corrupt record",
        ),
        (
            LineageIndexError::InvalidInput {
                detail: "empty field".into(),
            },
            "FE-LIDX-0004",
            "invalid input",
        ),
    ];

    for (err, expected_code, expected_substr) in &errors {
        assert_eq!(err.code(), *expected_code);
        let display = err.to_string();
        assert!(
            display.contains(expected_substr),
            "Expected '{expected_substr}' in '{display}'"
        );
    }
}

// ===========================================================================
// 39. LineageChainEntry serde round-trip
// ===========================================================================

#[test]
fn lineage_chain_entry_serde_round_trip() {
    use frankenengine_engine::replacement_lineage_log::LineageChainEntry;

    let entry = LineageChainEntry {
        slot_id: test_slot_id(),
        timestamp_ns: 42_000_000,
        receipt_id: "receipt-chain-1".into(),
        kind: ReplacementKind::RePromotion,
        from_cell_digest: "from-digest".into(),
        to_cell_digest: "to-digest".into(),
        receipt_content_hash: "content-hash-hex".into(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: LineageChainEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ===========================================================================
// Enrichment tests
// ===========================================================================

// --- helpers for enrichment tests ---

fn make_receipt_for_slot(slot_name: &str, old: &str, new: &str, ts_ns: u64) -> ReplacementReceipt {
    let arts = test_validation_artifacts();
    let sid = SlotId::new(slot_name).unwrap();
    let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &sid,
        old_cell_digest: old,
        new_cell_digest: new,
        validation_artifacts: &arts,
        rollback_token: "rollback-token",
        promotion_rationale: "Testing lineage log",
        timestamp_ns: ts_ns,
        epoch: test_epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();
    receipt
        .add_signature(&test_signing_key(), "gate-runner")
        .unwrap();
    receipt
}

// --- 1. Empty log edge cases ---

#[test]
fn enrichment_empty_log_merkle_root_is_deterministic() {
    let log1 = ReplacementLineageLog::new(default_config());
    let log2 = ReplacementLineageLog::new(default_config());
    assert_eq!(log1.merkle_root(), log2.merkle_root());
}

#[test]
fn enrichment_empty_log_query_all_returns_empty() {
    let log = ReplacementLineageLog::new(default_config());
    let results = log.query(&LineageQuery::all());
    assert!(results.is_empty());
}

#[test]
fn enrichment_empty_log_slot_ids_returns_empty() {
    let log = ReplacementLineageLog::new(default_config());
    assert!(log.slot_ids().is_empty());
}

#[test]
fn enrichment_empty_log_entries_returns_empty_slice() {
    let log = ReplacementLineageLog::new(default_config());
    assert_eq!(log.entries().len(), 0);
}

#[test]
fn enrichment_empty_log_checkpoints_returns_empty_slice() {
    let log = ReplacementLineageLog::new(default_config());
    assert!(log.checkpoints().is_empty());
}

#[test]
fn enrichment_empty_log_events_returns_empty() {
    let log = ReplacementLineageLog::new(default_config());
    assert!(log.events().is_empty());
}

#[test]
fn enrichment_empty_log_audit_has_zero_slots() {
    let log = ReplacementLineageLog::new(default_config());
    let audit = log.audit();
    assert_eq!(audit.total_slots, 0);
    assert_eq!(audit.checkpoint_count, 0);
    assert!(audit.latest_checkpoint_seq.is_none());
}

// --- 2. Single-entry log properties ---

#[test]
fn enrichment_single_entry_has_genesis_predecessor() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let entry = &log.entries()[0];
    assert_eq!(entry.sequence, 0);
    // Predecessor for first entry is hash of "genesis"
    let genesis = frankenengine_engine::hash_tiers::ContentHash::compute(b"genesis");
    assert_eq!(entry.predecessor_hash, genesis);
}

#[test]
fn enrichment_single_entry_inclusion_proof_has_empty_path() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let proof = log.inclusion_proof(0).unwrap();
    assert!(proof.path.is_empty());
    assert!(verify_inclusion_proof(&proof));
}

#[test]
fn enrichment_single_entry_slot_lineage_has_one_step() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let lineage = log.slot_lineage(&test_slot_id());
    assert_eq!(lineage.len(), 1);
    assert_eq!(lineage[0].old_cell_digest, "old-a");
    assert_eq!(lineage[0].new_cell_digest, "new-a");
    assert_eq!(lineage[0].kind, ReplacementKind::DelegateToNative);
}

#[test]
fn enrichment_single_entry_audit_chain_valid() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(receipt, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let audit = log.audit();
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);
    assert_eq!(audit.total_entries, 1);
    assert_eq!(audit.total_slots, 1);
}

// --- 3. Hash chain integrity ---

#[test]
fn enrichment_hash_chain_ten_entries() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..10 {
        let receipt = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(
            receipt,
            ReplacementKind::DelegateToNative,
            (i + 1) * 1_000_000,
        )
        .unwrap();
    }
    let entries = log.entries();
    for i in 1..entries.len() {
        assert_eq!(
            entries[i].predecessor_hash, entries[i - 1].entry_hash,
            "chain break at index {i}"
        );
    }
}

#[test]
fn enrichment_entry_hash_differs_by_kind() {
    let mut log1 = ReplacementLineageLog::new(default_config());
    let mut log2 = ReplacementLineageLog::new(default_config());
    let r1 = make_receipt("old-a", "new-a", 1_000_000);
    let r2 = make_receipt("old-a", "new-a", 1_000_000);
    log1.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log2.append(r2, ReplacementKind::Demotion, 1_000_000)
        .unwrap();
    // Different kinds produce different entry hashes even with same receipt data
    assert_ne!(log1.entries()[0].entry_hash, log2.entries()[0].entry_hash);
}

#[test]
fn enrichment_entry_hash_differs_by_sequence() {
    // Two entries with different sequence numbers produce different hashes.
    let mut log = ReplacementLineageLog::new(default_config());
    let r1 = make_receipt("old-a", "new-a", 1_000_000);
    let r2 = make_receipt("old-b", "new-b", 2_000_000);
    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.append(r2, ReplacementKind::DelegateToNative, 2_000_000)
        .unwrap();
    assert_ne!(log.entries()[0].entry_hash, log.entries()[1].entry_hash);
}

// --- 4. Merkle proofs for various sizes ---

#[test]
fn enrichment_inclusion_proof_two_entries() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..2 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    for i in 0u64..2 {
        let proof = log.inclusion_proof(i).unwrap();
        assert!(verify_inclusion_proof(&proof), "proof failed for entry {i}");
    }
}

#[test]
fn enrichment_inclusion_proof_three_entries_odd_tree() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..3 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    for i in 0u64..3 {
        let proof = log.inclusion_proof(i).unwrap();
        assert!(verify_inclusion_proof(&proof), "proof failed for entry {i}");
    }
}

#[test]
fn enrichment_inclusion_proof_power_of_two_eight_entries() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..8 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    for i in 0u64..8 {
        let proof = log.inclusion_proof(i).unwrap();
        assert!(verify_inclusion_proof(&proof), "proof failed for entry {i}");
    }
}

#[test]
fn enrichment_inclusion_proof_fifteen_entries() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..15 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    for i in 0u64..15 {
        let proof = log.inclusion_proof(i).unwrap();
        assert!(verify_inclusion_proof(&proof), "proof failed for entry {i}");
    }
}

#[test]
fn enrichment_inclusion_proof_root_matches_log_merkle_root() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..5 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    let root = log.merkle_root();
    for i in 0u64..5 {
        let proof = log.inclusion_proof(i).unwrap();
        assert_eq!(proof.root, root, "proof root mismatch for entry {i}");
    }
}

#[test]
fn enrichment_tampered_inclusion_proof_wrong_sibling() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..4 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    let mut proof = log.inclusion_proof(1).unwrap();
    if !proof.path.is_empty() {
        proof.path[0].sibling_hash =
            frankenengine_engine::hash_tiers::ContentHash::compute(b"tampered-sibling");
        assert!(!verify_inclusion_proof(&proof));
    }
}

// --- 5. Checkpoint behavior ---

#[test]
fn enrichment_checkpoint_log_length_matches_entries() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..5 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log.create_checkpoint(6_000_000, test_epoch()).unwrap();
    assert_eq!(log.checkpoints()[0].log_length, 5);
}

#[test]
fn enrichment_checkpoint_merkle_root_matches_log_root() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..4 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log.create_checkpoint(5_000_000, test_epoch()).unwrap();
    assert_eq!(log.checkpoints()[0].merkle_root, log.merkle_root());
}

#[test]
fn enrichment_multiple_checkpoints_increasing_seq() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..3 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
        log.create_checkpoint((i + 1) * 1_000_000 + 500, test_epoch())
            .unwrap();
    }
    let cps = log.checkpoints();
    assert_eq!(cps.len(), 3);
    for i in 1..cps.len() {
        assert!(cps[i].checkpoint_seq > cps[i - 1].checkpoint_seq);
        assert!(cps[i].log_length >= cps[i - 1].log_length);
    }
}

#[test]
fn enrichment_checkpoint_preserves_epoch() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let ep = SecurityEpoch::from_raw(7);
    log.create_checkpoint(2_000_000, ep).unwrap();
    assert_eq!(log.checkpoints()[0].epoch, ep);
}

#[test]
fn enrichment_checkpoint_hash_is_deterministic() {
    let mut log1 = ReplacementLineageLog::new(default_config());
    let mut log2 = ReplacementLineageLog::new(default_config());
    let r1 = make_receipt("old-a", "new-a", 1_000_000);
    let r2 = make_receipt("old-a", "new-a", 1_000_000);
    log1.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log2.append(r2, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log1.create_checkpoint(2_000_000, test_epoch()).unwrap();
    log2.create_checkpoint(2_000_000, test_epoch()).unwrap();
    assert_eq!(
        log1.checkpoints()[0].checkpoint_hash,
        log2.checkpoints()[0].checkpoint_hash
    );
}

// --- 6. Auto-checkpoint ---

#[test]
fn enrichment_auto_checkpoint_fires_at_interval() {
    let config = LineageLogConfig {
        checkpoint_interval: 3,
        max_entries_in_memory: 0,
    };
    let mut log = ReplacementLineageLog::new(config);
    for i in 0u64..6 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    // After 3 entries and 6 entries, auto-checkpoints should fire
    assert_eq!(log.checkpoints().len(), 2);
}

#[test]
fn enrichment_auto_checkpoint_disabled_when_interval_zero() {
    let config = LineageLogConfig {
        checkpoint_interval: 0,
        max_entries_in_memory: 0,
    };
    let mut log = ReplacementLineageLog::new(config);
    for i in 0u64..10 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    // No auto-checkpoints when interval is 0
    assert!(log.checkpoints().is_empty());
}

// --- 7. Consistency proofs ---

#[test]
fn enrichment_consistency_proof_three_checkpoints() {
    let mut log = ReplacementLineageLog::new(default_config());
    for phase in 0u64..3 {
        for i in 0u64..2 {
            let seq = phase * 2 + i;
            let r = make_receipt(
                &format!("old-{seq}"),
                &format!("new-{seq}"),
                (seq + 1) * 1_000_000,
            );
            log.append(r, ReplacementKind::DelegateToNative, (seq + 1) * 1_000_000)
                .unwrap();
        }
        log.create_checkpoint((phase + 1) * 10_000_000, test_epoch())
            .unwrap();
    }
    // Check consistency between checkpoint 0 and 1
    let proof01 = log.consistency_proof(0, 1).unwrap();
    assert!(verify_consistency_proof(&proof01));
    // Check consistency between checkpoint 1 and 2
    let proof12 = log.consistency_proof(1, 2).unwrap();
    assert!(verify_consistency_proof(&proof12));
    // Check consistency between checkpoint 0 and 2
    let proof02 = log.consistency_proof(0, 2).unwrap();
    assert!(verify_consistency_proof(&proof02));
}

#[test]
fn enrichment_consistency_proof_older_newer_mismatch() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..4 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
        if i == 1 || i == 3 {
            log.create_checkpoint((i + 1) * 1_000_000, test_epoch())
                .unwrap();
        }
    }
    // Reversed order should fail
    match log.consistency_proof(1, 0) {
        Err(LineageLogError::InvalidCheckpointOrder { older, newer }) => {
            assert_eq!(older, 1);
            assert_eq!(newer, 0);
        }
        other => panic!("expected InvalidCheckpointOrder, got {other:?}"),
    }
}

#[test]
fn enrichment_tampered_consistency_proof_detected() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..4 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
        if i == 1 || i == 3 {
            log.create_checkpoint((i + 1) * 1_000_000, test_epoch())
                .unwrap();
        }
    }
    let mut proof = log.consistency_proof(0, 1).unwrap();
    // Tamper with the older entry hashes
    if !proof.older_entry_hashes.is_empty() {
        proof.older_entry_hashes[0] =
            frankenengine_engine::hash_tiers::ContentHash::compute(b"tampered");
    }
    assert!(!verify_consistency_proof(&proof));
}

// --- 8. Query filtering ---

#[test]
fn enrichment_query_by_multiple_kinds() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r1 = make_receipt("old-a", "new-a", 1_000_000);
    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let r2 = make_receipt("new-a", "old-a", 2_000_000);
    log.append(r2, ReplacementKind::Demotion, 2_000_000)
        .unwrap();
    let r3 = make_receipt("old-a", "new-b", 3_000_000);
    log.append(r3, ReplacementKind::Rollback, 3_000_000)
        .unwrap();
    let r4 = make_receipt("new-b", "new-c", 4_000_000);
    log.append(r4, ReplacementKind::RePromotion, 4_000_000)
        .unwrap();

    let query = LineageQuery {
        slot_id: None,
        kinds: Some(BTreeSet::from([
            ReplacementKind::Demotion,
            ReplacementKind::Rollback,
        ])),
        min_timestamp_ns: None,
        max_timestamp_ns: None,
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 2);
}

#[test]
fn enrichment_query_combined_slot_and_kind() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r1 = make_receipt("old-a", "new-a", 1_000_000);
    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let r2 = make_receipt("new-a", "old-a", 2_000_000);
    log.append(r2, ReplacementKind::Demotion, 2_000_000)
        .unwrap();

    let query = LineageQuery {
        slot_id: Some(test_slot_id()),
        kinds: Some(BTreeSet::from([ReplacementKind::Demotion])),
        min_timestamp_ns: None,
        max_timestamp_ns: None,
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].kind, ReplacementKind::Demotion);
}

#[test]
fn enrichment_query_combined_slot_kind_and_timestamp() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..6 {
        let kind = if i < 3 {
            ReplacementKind::DelegateToNative
        } else {
            ReplacementKind::Demotion
        };
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, kind, (i + 1) * 1_000_000).unwrap();
    }

    let query = LineageQuery {
        slot_id: Some(test_slot_id()),
        kinds: Some(BTreeSet::from([ReplacementKind::Demotion])),
        min_timestamp_ns: Some(4_000_000),
        max_timestamp_ns: Some(6_000_000),
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 3);
    for entry in &results {
        assert_eq!(entry.kind, ReplacementKind::Demotion);
        assert!(entry.receipt.timestamp_ns >= 4_000_000);
        assert!(entry.receipt.timestamp_ns <= 6_000_000);
    }
}

#[test]
fn enrichment_query_with_only_max_timestamp() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..5 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    let query = LineageQuery {
        slot_id: None,
        kinds: None,
        min_timestamp_ns: None,
        max_timestamp_ns: Some(2_000_000),
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 2);
}

#[test]
fn enrichment_query_no_match_returns_empty() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r = make_receipt("old-a", "new-a", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    let query = LineageQuery {
        slot_id: None,
        kinds: Some(BTreeSet::from([ReplacementKind::Rollback])),
        min_timestamp_ns: None,
        max_timestamp_ns: None,
    };
    let results = log.query(&query);
    assert!(results.is_empty());
}

#[test]
fn enrichment_query_timestamp_exact_boundary_inclusive() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..3 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    // Exact min and max boundary = second entry
    let query = LineageQuery {
        slot_id: None,
        kinds: None,
        min_timestamp_ns: Some(2_000_000),
        max_timestamp_ns: Some(2_000_000),
    };
    let results = log.query(&query);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].receipt.timestamp_ns, 2_000_000);
}

// --- 9. Multi-slot log ---

#[test]
fn enrichment_multi_slot_lineages_independent() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r1 = make_receipt_for_slot("slot-alpha", "old-a", "new-a", 1_000_000);
    let r2 = make_receipt_for_slot("slot-beta", "old-b", "new-b", 2_000_000);
    let r3 = make_receipt_for_slot("slot-alpha", "new-a", "newer-a", 3_000_000);
    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.append(r2, ReplacementKind::DelegateToNative, 2_000_000)
        .unwrap();
    log.append(r3, ReplacementKind::RePromotion, 3_000_000)
        .unwrap();

    let alpha = SlotId::new("slot-alpha").unwrap();
    let beta = SlotId::new("slot-beta").unwrap();
    let lineage_alpha = log.slot_lineage(&alpha);
    let lineage_beta = log.slot_lineage(&beta);
    assert_eq!(lineage_alpha.len(), 2);
    assert_eq!(lineage_beta.len(), 1);
}

#[test]
fn enrichment_multi_slot_slot_ids_sorted() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r1 = make_receipt_for_slot("slot-z", "old-z", "new-z", 1_000_000);
    let r2 = make_receipt_for_slot("slot-a", "old-a", "new-a", 2_000_000);
    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.append(r2, ReplacementKind::DelegateToNative, 2_000_000)
        .unwrap();

    let ids = log.slot_ids();
    assert_eq!(ids.len(), 2);
    // BTreeSet yields sorted order
    assert!(ids[0].as_str() < ids[1].as_str());
}

#[test]
fn enrichment_multi_slot_audit_counts_unique_slots() {
    let mut log = ReplacementLineageLog::new(default_config());
    let names = ["slot-1", "slot-2", "slot-3", "slot-1"];
    for (i, name) in names.iter().enumerate() {
        let r = make_receipt_for_slot(
            name,
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i as u64 + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i as u64 + 1) * 1_000_000)
            .unwrap();
    }
    let audit = log.audit();
    assert_eq!(audit.total_slots, 3);
}

#[test]
fn enrichment_multi_slot_query_filters_slot() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r1 = make_receipt_for_slot("slot-alpha", "old-a", "new-a", 1_000_000);
    let r2 = make_receipt_for_slot("slot-beta", "old-b", "new-b", 2_000_000);
    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.append(r2, ReplacementKind::DelegateToNative, 2_000_000)
        .unwrap();

    let beta = SlotId::new("slot-beta").unwrap();
    let results = log.query(&LineageQuery::for_slot(beta));
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].receipt.slot_id.as_str(), "slot-beta");
}

// --- 10. Slot lineage verification ---

#[test]
fn enrichment_verify_slot_lineage_multi_entry() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..5 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    let v = log.verify_slot_lineage(&test_slot_id());
    assert!(v.chain_valid);
    assert_eq!(v.total_entries, 5);
    assert!(v.all_receipts_present);
}

#[test]
fn enrichment_verify_slot_lineage_different_slot_empty() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r = make_receipt("old-a", "new-a", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let other = SlotId::new("other-slot").unwrap();
    let v = log.verify_slot_lineage(&other);
    assert_eq!(v.total_entries, 0);
    assert!(v.chain_valid);
    assert!(!v.issues.is_empty());
}

// --- 11. Audit with checkpoints ---

#[test]
fn enrichment_audit_with_multiple_checkpoints() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..6 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
        if i == 2 || i == 5 {
            log.create_checkpoint((i + 1) * 1_000_000 + 500, test_epoch())
                .unwrap();
        }
    }
    let audit = log.audit();
    assert_eq!(audit.total_entries, 6);
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);
    assert_eq!(audit.checkpoint_count, 2);
    assert_eq!(audit.latest_checkpoint_seq, Some(1));
}

#[test]
fn enrichment_audit_after_checkpoint_then_append() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..3 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log.create_checkpoint(4_000_000, test_epoch()).unwrap();

    // Append more after checkpoint
    for i in 3u64..5 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    let audit = log.audit();
    assert!(audit.chain_valid);
    // Checkpoint covers prefix, audit should still be valid
    assert!(audit.merkle_valid);
    assert_eq!(audit.total_entries, 5);
}

// --- 12. Events ---

#[test]
fn enrichment_events_count_matches_operations() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..3 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log.create_checkpoint(4_000_000, test_epoch()).unwrap();
    // 3 append events + 1 checkpoint event = 4 events minimum
    assert!(log.events().len() >= 4);
}

#[test]
fn enrichment_events_all_have_ok_outcome() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r = make_receipt("old-a", "new-a", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(2_000_000, test_epoch()).unwrap();
    for event in log.events() {
        assert_eq!(event.outcome, "ok");
        assert!(event.error_code.is_none());
    }
}

#[test]
fn enrichment_events_have_distinct_trace_ids() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..3 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    let events = log.events();
    let trace_ids: BTreeSet<&str> = events.iter().map(|e| e.trace_id.as_str()).collect();
    // Each event should have a unique trace_id
    assert_eq!(trace_ids.len(), events.len());
}

#[test]
fn enrichment_events_component_is_replacement_lineage_log() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r = make_receipt("old-a", "new-a", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    for event in log.events() {
        assert_eq!(event.component, "replacement_lineage_log");
    }
}

#[test]
fn enrichment_events_policy_id_is_consistent() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r = make_receipt("old-a", "new-a", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(2_000_000, test_epoch()).unwrap();
    for event in log.events() {
        assert_eq!(event.policy_id, "replacement-lineage-policy");
    }
}

// --- 13. Serialization round-trips ---

#[test]
fn enrichment_serde_roundtrip_populated_log() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..5 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log.create_checkpoint(6_000_000, test_epoch()).unwrap();

    let json = serde_json::to_string(&log).unwrap();
    let back: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), log.len());
    assert_eq!(back.merkle_root(), log.merkle_root());
    assert_eq!(back.checkpoints().len(), log.checkpoints().len());
}

#[test]
fn enrichment_serde_roundtrip_preserves_entries() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r = make_receipt("old-a", "new-a", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    let json = serde_json::to_string(&log).unwrap();
    let back: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
    assert_eq!(back.entries()[0].kind, ReplacementKind::DelegateToNative);
    assert_eq!(back.entries()[0].sequence, 0);
    assert_eq!(back.entries()[0].entry_hash, log.entries()[0].entry_hash);
}

#[test]
fn enrichment_serde_roundtrip_preserves_hash_chain() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..4 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    let json = serde_json::to_string(&log).unwrap();
    let back: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
    let entries = back.entries();
    for i in 1..entries.len() {
        assert_eq!(entries[i].predecessor_hash, entries[i - 1].entry_hash);
    }
}

#[test]
fn enrichment_serde_roundtrip_audit_still_valid() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..4 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log.create_checkpoint(5_000_000, test_epoch()).unwrap();

    let json = serde_json::to_string(&log).unwrap();
    let back: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
    let audit = back.audit();
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);
}

#[test]
fn enrichment_serde_roundtrip_inclusion_proofs_still_verify() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..4 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    let json = serde_json::to_string(&log).unwrap();
    let back: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
    for i in 0u64..4 {
        let proof = back.inclusion_proof(i).unwrap();
        assert!(verify_inclusion_proof(&proof));
    }
}

#[test]
fn enrichment_serde_roundtrip_consistency_proof_verifies() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..4 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
        if i == 1 || i == 3 {
            log.create_checkpoint((i + 1) * 1_000_000, test_epoch())
                .unwrap();
        }
    }
    let json = serde_json::to_string(&log).unwrap();
    let back: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
    let proof = back.consistency_proof(0, 1).unwrap();
    assert!(verify_consistency_proof(&proof));
}

// --- 14. ReplacementKind coverage ---

#[test]
fn enrichment_all_replacement_kinds_appendable() {
    let mut log = ReplacementLineageLog::new(default_config());
    let kinds = [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::Rollback,
        ReplacementKind::RePromotion,
    ];
    for (i, kind) in kinds.iter().enumerate() {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i as u64 + 1) * 1_000_000,
        );
        log.append(r, *kind, (i as u64 + 1) * 1_000_000).unwrap();
    }
    assert_eq!(log.len(), 4);
    for (i, kind) in kinds.iter().enumerate() {
        assert_eq!(log.entries()[i].kind, *kind);
    }
}

#[test]
fn enrichment_replacement_kind_as_str_nonempty() {
    for kind in [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::Rollback,
        ReplacementKind::RePromotion,
    ] {
        assert!(!kind.as_str().is_empty());
    }
}

#[test]
fn enrichment_replacement_kind_display_matches_as_str() {
    for kind in [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::Rollback,
        ReplacementKind::RePromotion,
    ] {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn enrichment_replacement_kind_btreeset_deduplicates() {
    let mut set = BTreeSet::new();
    set.insert(ReplacementKind::DelegateToNative);
    set.insert(ReplacementKind::DelegateToNative);
    set.insert(ReplacementKind::Rollback);
    assert_eq!(set.len(), 2);
}

// --- 15. Error edge cases ---

#[test]
fn enrichment_error_chain_break_serde_roundtrip() {
    let err = LineageLogError::ChainBreak { sequence: 42 };
    let json = serde_json::to_string(&err).unwrap();
    let back: LineageLogError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

#[test]
fn enrichment_error_checkpoint_beyond_log_serde_roundtrip() {
    let err = LineageLogError::CheckpointBeyondLog {
        checkpoint_length: 100,
        log_length: 50,
    };
    let json = serde_json::to_string(&err).unwrap();
    let back: LineageLogError = serde_json::from_str(&json).unwrap();
    assert_eq!(back, err);
}

#[test]
fn enrichment_error_display_chain_break() {
    let err = LineageLogError::ChainBreak { sequence: 7 };
    let msg = err.to_string();
    assert!(msg.contains("chain break"));
    assert!(msg.contains("7"));
}

#[test]
fn enrichment_error_display_checkpoint_beyond_log() {
    let err = LineageLogError::CheckpointBeyondLog {
        checkpoint_length: 100,
        log_length: 50,
    };
    let msg = err.to_string();
    assert!(msg.contains("100"));
    assert!(msg.contains("50"));
}

// --- 16. LineageLogEvent ---

#[test]
fn enrichment_lineage_log_event_with_error_code_roundtrip() {
    let event = LineageLogEvent {
        trace_id: "trace-err".into(),
        decision_id: "dec-err".into(),
        policy_id: "pol-err".into(),
        component: "lineage-log".into(),
        event: "append_failed".into(),
        outcome: "error".into(),
        error_code: Some("FE-LIN-001".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: LineageLogEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
    assert_eq!(back.error_code, Some("FE-LIN-001".into()));
}

// --- 17. LineageQuery factories ---

#[test]
fn enrichment_lineage_query_for_slot_has_none_kinds() {
    let q = LineageQuery::for_slot(test_slot_id());
    assert!(q.slot_id.is_some());
    assert!(q.kinds.is_none());
    assert!(q.min_timestamp_ns.is_none());
    assert!(q.max_timestamp_ns.is_none());
}

#[test]
fn enrichment_lineage_query_all_has_all_none() {
    let q = LineageQuery::all();
    assert!(q.slot_id.is_none());
    assert!(q.kinds.is_none());
    assert!(q.min_timestamp_ns.is_none());
    assert!(q.max_timestamp_ns.is_none());
}

// --- 18. EvidenceCategory ---

#[test]
fn enrichment_evidence_category_all_variants_as_str() {
    let cats = [
        EvidenceCategory::GateResult,
        EvidenceCategory::PerformanceBenchmark,
        EvidenceCategory::SentinelRiskScore,
        EvidenceCategory::DifferentialExecutionLog,
        EvidenceCategory::Additional,
    ];
    let strs: BTreeSet<&str> = cats.iter().map(|c| c.as_str()).collect();
    assert_eq!(strs.len(), 5, "all evidence categories must have distinct as_str");
}

#[test]
fn enrichment_evidence_category_display_matches_as_str() {
    for cat in [
        EvidenceCategory::GateResult,
        EvidenceCategory::PerformanceBenchmark,
        EvidenceCategory::SentinelRiskScore,
        EvidenceCategory::DifferentialExecutionLog,
        EvidenceCategory::Additional,
    ] {
        assert_eq!(cat.to_string(), cat.as_str());
    }
}

// --- 19. ProofDirection ---

#[test]
fn enrichment_proof_direction_clone_eq() {
    let left = ProofDirection::Left;
    let right = ProofDirection::Right;
    assert_eq!(left.clone(), ProofDirection::Left);
    assert_eq!(right.clone(), ProofDirection::Right);
    assert_ne!(left, right);
}

// --- 20. Determinism tests ---

#[test]
fn enrichment_deterministic_append_produces_same_log() {
    let mut log1 = ReplacementLineageLog::new(default_config());
    let mut log2 = ReplacementLineageLog::new(default_config());
    for i in 0u64..5 {
        let r1 = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        let r2 = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log1.append(r1, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
        log2.append(r2, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    assert_eq!(log1.merkle_root(), log2.merkle_root());
    assert_eq!(log1.len(), log2.len());
    for i in 0..log1.entries().len() {
        assert_eq!(log1.entries()[i].entry_hash, log2.entries()[i].entry_hash);
    }
}

#[test]
fn enrichment_deterministic_audit_results_match() {
    let mut log1 = ReplacementLineageLog::new(default_config());
    let mut log2 = ReplacementLineageLog::new(default_config());
    for i in 0u64..4 {
        let r1 = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        let r2 = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log1.append(r1, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
        log2.append(r2, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log1.create_checkpoint(5_000_000, test_epoch()).unwrap();
    log2.create_checkpoint(5_000_000, test_epoch()).unwrap();
    assert_eq!(log1.audit(), log2.audit());
}

// --- 21. Slot lineage step fields ---

#[test]
fn enrichment_slot_lineage_step_has_correct_fields() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r = make_receipt("old-cell", "new-cell", 5_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 5_000_000)
        .unwrap();
    let lineage = log.slot_lineage(&test_slot_id());
    assert_eq!(lineage.len(), 1);
    let step = &lineage[0];
    assert_eq!(step.old_cell_digest, "old-cell");
    assert_eq!(step.new_cell_digest, "new-cell");
    assert_eq!(step.kind, ReplacementKind::DelegateToNative);
    assert_eq!(step.timestamp_ns, 5_000_000);
    assert_eq!(step.epoch, test_epoch());
    assert!(step.validation_artifact_count > 0);
    assert!(!step.receipt_id.is_empty());
}

#[test]
fn enrichment_slot_lineage_ordering_follows_sequence() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..4 {
        let r = make_receipt(&format!("v{i}"), &format!("v{}", i + 1), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    let lineage = log.slot_lineage(&test_slot_id());
    for i in 1..lineage.len() {
        assert!(lineage[i].sequence > lineage[i - 1].sequence);
    }
}

// --- 22. Duplicate receipt edge case ---

#[test]
fn enrichment_duplicate_receipt_preserves_original() {
    let mut log = ReplacementLineageLog::new(default_config());
    let receipt = make_receipt("old-a", "new-a", 1_000_000);
    log.append(
        receipt.clone(),
        ReplacementKind::DelegateToNative,
        1_000_000,
    )
    .unwrap();
    let original_entry = log.entries()[0].clone();

    // Attempt duplicate
    let _ = log.append(receipt, ReplacementKind::Demotion, 2_000_000);
    // Original should be preserved
    assert_eq!(log.len(), 1);
    assert_eq!(log.entries()[0], original_entry);
}

// --- 23. Large log ---

#[test]
fn enrichment_twenty_entries_all_proofs_verify() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..20 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    assert_eq!(log.len(), 20);
    for i in 0u64..20 {
        let proof = log.inclusion_proof(i).unwrap();
        assert!(verify_inclusion_proof(&proof), "proof failed for entry {i}");
    }
}

#[test]
fn enrichment_twenty_entries_audit_chain_valid() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..20 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    let audit = log.audit();
    assert!(audit.chain_valid);
    assert_eq!(audit.total_entries, 20);
}

// --- 24. Mixed replacement kinds in lineage ---

#[test]
fn enrichment_mixed_kinds_lineage_preserves_order() {
    let mut log = ReplacementLineageLog::new(default_config());
    let kinds = [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::Rollback,
        ReplacementKind::RePromotion,
        ReplacementKind::DelegateToNative,
    ];
    for (i, kind) in kinds.iter().enumerate() {
        let r = make_receipt(
            &format!("v{i}"),
            &format!("v{}", i + 1),
            (i as u64 + 1) * 1_000_000,
        );
        log.append(r, *kind, (i as u64 + 1) * 1_000_000).unwrap();
    }
    let lineage = log.slot_lineage(&test_slot_id());
    assert_eq!(lineage.len(), 5);
    for (i, kind) in kinds.iter().enumerate() {
        assert_eq!(lineage[i].kind, *kind);
    }
}

// --- 25. Audit result serde ---

#[test]
fn enrichment_audit_result_serde_with_issues() {
    let result = AuditResult {
        total_entries: 10,
        total_slots: 2,
        chain_valid: false,
        merkle_valid: false,
        checkpoint_count: 1,
        latest_checkpoint_seq: Some(0),
        issues: vec![
            "chain break at sequence 5".into(),
            "merkle root mismatch".into(),
        ],
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: AuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back, result);
    assert_eq!(back.issues.len(), 2);
}

#[test]
fn enrichment_audit_result_serde_no_checkpoint() {
    let result = AuditResult {
        total_entries: 5,
        total_slots: 1,
        chain_valid: true,
        merkle_valid: true,
        checkpoint_count: 0,
        latest_checkpoint_seq: None,
        issues: vec![],
    };
    let json = serde_json::to_string(&result).unwrap();
    let back: AuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(back.latest_checkpoint_seq, None);
}

// --- 26. LineageLogConfig edge cases ---

#[test]
fn enrichment_config_serde_custom_values() {
    let config = LineageLogConfig {
        checkpoint_interval: 42,
        max_entries_in_memory: 999,
    };
    let json = serde_json::to_string(&config).unwrap();
    let back: LineageLogConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(back.checkpoint_interval, 42);
    assert_eq!(back.max_entries_in_memory, 999);
}

#[test]
fn enrichment_config_default_interval_positive() {
    let config = LineageLogConfig::default();
    assert!(config.checkpoint_interval > 0);
}

// --- 27. Full lifecycle with all 4 kinds ---

#[test]
fn enrichment_full_lifecycle_promote_demote_rollback_repromote() {
    let mut log = ReplacementLineageLog::new(default_config());

    // 1. Promote
    let r1 = make_receipt("delegate-v1", "native-v1", 1_000_000);
    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    // 2. Demote
    let r2 = make_receipt("native-v1", "delegate-v1", 2_000_000);
    log.append(r2, ReplacementKind::Demotion, 2_000_000)
        .unwrap();

    // 3. Rollback
    let r3 = make_receipt("delegate-v1", "delegate-v0", 3_000_000);
    log.append(r3, ReplacementKind::Rollback, 3_000_000)
        .unwrap();

    // 4. Re-promote
    let r4 = make_receipt("delegate-v0", "native-v2", 4_000_000);
    log.append(r4, ReplacementKind::RePromotion, 4_000_000)
        .unwrap();

    log.create_checkpoint(5_000_000, test_epoch()).unwrap();

    // Verify
    assert_eq!(log.len(), 4);
    let audit = log.audit();
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);
    assert_eq!(audit.total_entries, 4);
    assert_eq!(audit.checkpoint_count, 1);

    let lineage = log.slot_lineage(&test_slot_id());
    assert_eq!(lineage.len(), 4);
    assert_eq!(lineage[0].kind, ReplacementKind::DelegateToNative);
    assert_eq!(lineage[1].kind, ReplacementKind::Demotion);
    assert_eq!(lineage[2].kind, ReplacementKind::Rollback);
    assert_eq!(lineage[3].kind, ReplacementKind::RePromotion);

    // Inclusion proofs all verify
    for i in 0u64..4 {
        let proof = log.inclusion_proof(i).unwrap();
        assert!(verify_inclusion_proof(&proof));
    }

    // Serde round-trip
    let json = serde_json::to_string(&log).unwrap();
    let back: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
    assert_eq!(back.merkle_root(), log.merkle_root());
}

// --- 28. Entry sequence is monotonic ---

#[test]
fn enrichment_entry_sequences_are_monotonic() {
    let mut log = ReplacementLineageLog::new(default_config());
    for i in 0u64..10 {
        let r = make_receipt(&format!("old-{i}"), &format!("new-{i}"), (i + 1) * 1_000_000);
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    for (i, entry) in log.entries().iter().enumerate() {
        assert_eq!(entry.sequence, i as u64);
    }
}

// --- 29. Checkpoint timestamp ---

#[test]
fn enrichment_checkpoint_timestamp_preserved() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(42_000_000, test_epoch()).unwrap();
    assert_eq!(log.checkpoints()[0].timestamp_ns, 42_000_000);
}

// --- 30. Query for_slot factory returns correct slot ---

#[test]
fn enrichment_query_for_slot_matches_correct_slot() {
    let q = LineageQuery::for_slot(test_slot_id());
    assert_eq!(q.slot_id.unwrap(), test_slot_id());
}

// --- 31. Zero-timestamp entry ---

#[test]
fn enrichment_zero_timestamp_entry_is_valid() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r = make_receipt("old-a", "new-a", 0);
    log.append(r, ReplacementKind::DelegateToNative, 0).unwrap();
    assert_eq!(log.len(), 1);
    assert_eq!(log.entries()[0].receipt.timestamp_ns, 0);
}

// --- 32. Merkle root differs between different entry counts ---

#[test]
fn enrichment_merkle_root_differs_for_different_lengths() {
    let mut log = ReplacementLineageLog::new(default_config());
    let r1 = make_receipt("old-0", "new-0", 1_000_000);
    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let root_one = log.merkle_root();

    let r2 = make_receipt("old-1", "new-1", 2_000_000);
    log.append(r2, ReplacementKind::DelegateToNative, 2_000_000)
        .unwrap();
    let root_two = log.merkle_root();

    let r3 = make_receipt("old-2", "new-2", 3_000_000);
    log.append(r3, ReplacementKind::DelegateToNative, 3_000_000)
        .unwrap();
    let root_three = log.merkle_root();

    assert_ne!(root_one, root_two);
    assert_ne!(root_two, root_three);
    assert_ne!(root_one, root_three);
}
