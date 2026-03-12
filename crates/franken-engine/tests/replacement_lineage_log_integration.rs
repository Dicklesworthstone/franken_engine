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
