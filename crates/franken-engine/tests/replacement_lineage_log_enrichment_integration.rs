#![forbid(unsafe_code)]
//! Enrichment integration tests for `replacement_lineage_log`.
//!
//! Adds exact Display/as_str values, Debug distinctness, error Display exact
//! messages, JSON field-name stability, serde roundtrips for missing types,
//! error path coverage, timestamp-filtered queries, auto-checkpoint, tampered
//! proof rejection, multi-slot audit, and LineageIndexError code/Display checks
//! beyond the existing 31 integration tests.

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

use frankenengine_engine::hash_tiers::ContentHash;
use frankenengine_engine::replacement_lineage_log::{
    AuditResult, ConsistencyProof, DemotionReceiptInput, DemotionReceiptRecord, EvidenceCategory,
    EvidencePointer, EvidencePointerInput, InclusionProof, LineageChainEntry, LineageIndexError,
    LineageIndexEvent, LineageLogConfig, LineageLogEntry, LineageLogError, LineageLogEvent,
    LineageQuery, LineageStep, LineageVerification, LogCheckpoint, MerkleProofStep, ProofDirection,
    ReplacementKind, ReplacementLineageLog, ReplacementReceiptRecord, ReplayJoinQuery,
    ReplayJoinRow, SlotLineageQuery, verify_consistency_proof, verify_inclusion_proof,
};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::self_replacement::{
    CreateReceiptInput, ReplacementReceipt, ValidationArtifactKind, ValidationArtifactRef,
};
use frankenengine_engine::signature_preimage::SigningKey;
use frankenengine_engine::slot_registry::SlotId;
use frankenengine_engine::storage_adapter::{StorageError, StoreKind};

// ===========================================================================
// Helpers
// ===========================================================================

fn epoch() -> SecurityEpoch {
    SecurityEpoch::from_raw(3)
}

fn slot(name: &str) -> SlotId {
    SlotId::new(name).unwrap()
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes([5u8; 32])
}

fn validation_artifacts() -> Vec<ValidationArtifactRef> {
    vec![ValidationArtifactRef {
        kind: ValidationArtifactKind::EquivalenceResult,
        artifact_digest: "digest-equiv".into(),
        passed: true,
        summary: "Passed".into(),
    }]
}

fn make_receipt(old: &str, new: &str, ts_ns: u64) -> ReplacementReceipt {
    make_receipt_slot("lineage-slot-1", old, new, ts_ns)
}

fn make_receipt_slot(slot_name: &str, old: &str, new: &str, ts_ns: u64) -> ReplacementReceipt {
    let arts = validation_artifacts();
    let sid = slot(slot_name);
    let mut receipt = ReplacementReceipt::create_unsigned(CreateReceiptInput {
        slot_id: &sid,
        old_cell_digest: old,
        new_cell_digest: new,
        validation_artifacts: &arts,
        rollback_token: "rollback-token",
        promotion_rationale: "Testing lineage log",
        timestamp_ns: ts_ns,
        epoch: epoch(),
        zone: "zone-a",
        required_signatures: 1,
    })
    .unwrap();
    receipt
        .add_signature(&signing_key(), "gate-runner")
        .unwrap();
    receipt
}

fn cfg() -> LineageLogConfig {
    LineageLogConfig {
        checkpoint_interval: 100,
        max_entries_in_memory: 0,
    }
}

// ===========================================================================
// 1. ReplacementKind — as_str exact values
// ===========================================================================

#[test]
fn replacement_kind_as_str_exact() {
    assert_eq!(
        ReplacementKind::DelegateToNative.as_str(),
        "delegate_to_native"
    );
    assert_eq!(ReplacementKind::Demotion.as_str(), "demotion");
    assert_eq!(ReplacementKind::Rollback.as_str(), "rollback");
    assert_eq!(ReplacementKind::RePromotion.as_str(), "re_promotion");
}

#[test]
fn replacement_kind_display_exact() {
    assert_eq!(
        ReplacementKind::DelegateToNative.to_string(),
        "delegate_to_native"
    );
    assert_eq!(ReplacementKind::Demotion.to_string(), "demotion");
    assert_eq!(ReplacementKind::Rollback.to_string(), "rollback");
    assert_eq!(ReplacementKind::RePromotion.to_string(), "re_promotion");
}

// ===========================================================================
// 2. EvidenceCategory — as_str / Display exact values
// ===========================================================================

#[test]
fn evidence_category_as_str_exact() {
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
fn evidence_category_display_exact() {
    assert_eq!(EvidenceCategory::GateResult.to_string(), "gate_result");
    assert_eq!(
        EvidenceCategory::PerformanceBenchmark.to_string(),
        "performance_benchmark"
    );
    assert_eq!(
        EvidenceCategory::SentinelRiskScore.to_string(),
        "sentinel_risk_score"
    );
    assert_eq!(
        EvidenceCategory::DifferentialExecutionLog.to_string(),
        "differential_execution_log"
    );
    assert_eq!(EvidenceCategory::Additional.to_string(), "additional");
}

// ===========================================================================
// 3. Debug distinctness
// ===========================================================================

#[test]
fn debug_distinct_replacement_kind() {
    let variants = [
        ReplacementKind::DelegateToNative,
        ReplacementKind::Demotion,
        ReplacementKind::Rollback,
        ReplacementKind::RePromotion,
    ];
    let strings: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strings.len(), variants.len());
}

#[test]
fn debug_distinct_proof_direction() {
    let a = format!("{:?}", ProofDirection::Left);
    let b = format!("{:?}", ProofDirection::Right);
    assert_ne!(a, b);
}

#[test]
fn debug_distinct_evidence_category() {
    let variants = [
        EvidenceCategory::GateResult,
        EvidenceCategory::PerformanceBenchmark,
        EvidenceCategory::SentinelRiskScore,
        EvidenceCategory::DifferentialExecutionLog,
        EvidenceCategory::Additional,
    ];
    let strings: BTreeSet<String> = variants.iter().map(|v| format!("{v:?}")).collect();
    assert_eq!(strings.len(), variants.len());
}

// ===========================================================================
// 4. LineageLogError — Display exact messages
// ===========================================================================

#[test]
fn error_display_sequence_mismatch() {
    let e = LineageLogError::SequenceMismatch {
        expected: 3,
        got: 5,
    };
    assert_eq!(e.to_string(), "sequence mismatch: expected 3, got 5");
}

#[test]
fn error_display_chain_break() {
    let e = LineageLogError::ChainBreak { sequence: 7 };
    assert_eq!(e.to_string(), "chain break at sequence 7");
}

#[test]
fn error_display_duplicate_receipt() {
    let e = LineageLogError::DuplicateReceipt {
        receipt_id: "r-42".into(),
    };
    assert_eq!(e.to_string(), "duplicate receipt: r-42");
}

#[test]
fn error_display_checkpoint_beyond_log() {
    let e = LineageLogError::CheckpointBeyondLog {
        checkpoint_length: 10,
        log_length: 5,
    };
    assert_eq!(e.to_string(), "checkpoint length 10 beyond log length 5");
}

#[test]
fn error_display_checkpoint_not_found() {
    let e = LineageLogError::CheckpointNotFound { checkpoint_seq: 99 };
    assert_eq!(e.to_string(), "checkpoint not found: sequence 99");
}

#[test]
fn error_display_invalid_checkpoint_order() {
    let e = LineageLogError::InvalidCheckpointOrder { older: 5, newer: 3 };
    assert_eq!(
        e.to_string(),
        "invalid checkpoint order: older=5, newer=3 (must be older < newer)"
    );
}

#[test]
fn error_display_empty_log() {
    let e = LineageLogError::EmptyLog;
    assert_eq!(e.to_string(), "log is empty");
}

// ===========================================================================
// 5. LineageLogError — serde all 7 variants
// ===========================================================================

#[test]
fn lineage_log_error_serde_all_variants() {
    let errors = [
        LineageLogError::SequenceMismatch {
            expected: 1,
            got: 2,
        },
        LineageLogError::ChainBreak { sequence: 10 },
        LineageLogError::DuplicateReceipt {
            receipt_id: "dup".into(),
        },
        LineageLogError::CheckpointBeyondLog {
            checkpoint_length: 20,
            log_length: 10,
        },
        LineageLogError::CheckpointNotFound { checkpoint_seq: 42 },
        LineageLogError::InvalidCheckpointOrder { older: 5, newer: 3 },
        LineageLogError::EmptyLog,
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: LineageLogError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

// ===========================================================================
// 6. LineageIndexError — code(), Display exact, std::error::Error
// ===========================================================================

#[test]
fn lineage_index_error_code_exact() {
    let e1 = LineageIndexError::Storage(StorageError::NotFound {
        store: StoreKind::ReplacementLineage,
        key: "k".into(),
    });
    assert_eq!(e1.code(), "FE-LIDX-0001");

    let e2 = LineageIndexError::Serialization {
        operation: "op".into(),
        detail: "d".into(),
    };
    assert_eq!(e2.code(), "FE-LIDX-0002");

    let e3 = LineageIndexError::CorruptRecord {
        key: "k".into(),
        detail: "d".into(),
    };
    assert_eq!(e3.code(), "FE-LIDX-0003");

    let e4 = LineageIndexError::InvalidInput { detail: "d".into() };
    assert_eq!(e4.code(), "FE-LIDX-0004");
}

#[test]
fn lineage_index_error_display_serialization() {
    let e = LineageIndexError::Serialization {
        operation: "encode".into(),
        detail: "bad format".into(),
    };
    assert_eq!(e.to_string(), "serialization error (encode): bad format");
}

#[test]
fn lineage_index_error_display_corrupt_record() {
    let e = LineageIndexError::CorruptRecord {
        key: "mykey".into(),
        detail: "truncated".into(),
    };
    assert_eq!(e.to_string(), "corrupt record `mykey`: truncated");
}

#[test]
fn lineage_index_error_display_invalid_input() {
    let e = LineageIndexError::InvalidInput {
        detail: "empty id".into(),
    };
    assert_eq!(e.to_string(), "invalid input: empty id");
}

#[test]
fn lineage_index_error_is_std_error() {
    let e = LineageIndexError::InvalidInput {
        detail: "test".into(),
    };
    let _: &dyn std::error::Error = &e;
}

#[test]
fn lineage_index_error_from_storage_error() {
    let se = StorageError::NotFound {
        store: StoreKind::ReplacementLineage,
        key: "x".into(),
    };
    let lie: LineageIndexError = se.into();
    assert_eq!(lie.code(), "FE-LIDX-0001");
    let s = lie.to_string();
    assert!(s.contains("storage error"), "got: {s}");
}

// ===========================================================================
// 7. LineageIndexError — serde roundtrip
// ===========================================================================

#[test]
fn lineage_index_error_serde_roundtrip() {
    let errors = [
        LineageIndexError::Serialization {
            operation: "op".into(),
            detail: "det".into(),
        },
        LineageIndexError::CorruptRecord {
            key: "k".into(),
            detail: "d".into(),
        },
        LineageIndexError::InvalidInput {
            detail: "empty".into(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: LineageIndexError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

// ===========================================================================
// 8. JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_lineage_log_config() {
    let c = LineageLogConfig {
        checkpoint_interval: 50,
        max_entries_in_memory: 1000,
    };
    let json = serde_json::to_string(&c).unwrap();
    assert!(json.contains("\"checkpoint_interval\""), "{json}");
    assert!(json.contains("\"max_entries_in_memory\""), "{json}");
}

#[test]
fn json_fields_lineage_log_event() {
    let e = LineageLogEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "ev".into(),
        outcome: "ok".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_lineage_query() {
    let q = LineageQuery {
        slot_id: Some(slot("slot-1")),
        kinds: Some(BTreeSet::from([ReplacementKind::DelegateToNative])),
        min_timestamp_ns: Some(100),
        max_timestamp_ns: Some(200),
    };
    let json = serde_json::to_string(&q).unwrap();
    for field in ["slot_id", "kinds", "min_timestamp_ns", "max_timestamp_ns"] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_lineage_verification() {
    let v = LineageVerification {
        slot_id: slot("s"),
        total_entries: 3,
        chain_valid: true,
        all_receipts_present: true,
        issues: vec![],
    };
    let json = serde_json::to_string(&v).unwrap();
    for field in [
        "slot_id",
        "total_entries",
        "chain_valid",
        "all_receipts_present",
        "issues",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_audit_result() {
    let a = AuditResult {
        total_entries: 5,
        total_slots: 2,
        chain_valid: true,
        merkle_valid: true,
        checkpoint_count: 1,
        latest_checkpoint_seq: Some(0),
        issues: vec![],
    };
    let json = serde_json::to_string(&a).unwrap();
    for field in [
        "total_entries",
        "total_slots",
        "chain_valid",
        "merkle_valid",
        "checkpoint_count",
        "latest_checkpoint_seq",
        "issues",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_evidence_pointer_input() {
    let e = EvidencePointerInput {
        category: EvidenceCategory::GateResult,
        artifact_digest: "abc".into(),
        passed: Some(true),
        summary: "ok".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    for field in ["category", "artifact_digest", "passed", "summary"] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_evidence_pointer() {
    let e = EvidencePointer {
        receipt_id: "r-1".into(),
        category: EvidenceCategory::Additional,
        artifact_digest: "abc".into(),
        passed: None,
        summary: "s".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    for field in [
        "receipt_id",
        "category",
        "artifact_digest",
        "passed",
        "summary",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_lineage_index_event() {
    let e = LineageIndexEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "c".into(),
        event: "ev".into(),
        outcome: "ok".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&e).unwrap();
    for field in [
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "error_code",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_demotion_receipt_input() {
    let d = DemotionReceiptInput {
        receipt_id: "dem-1".into(),
        slot_id: slot("s"),
        demoted_cell_digest: "abc".into(),
        restored_cell_digest: "def".into(),
        demotion_reason: "regressed".into(),
        timestamp_ns: 999,
        rollback_token_used: "tok".into(),
        linked_replacement_receipt_id: None,
        evidence: vec![],
    };
    let json = serde_json::to_string(&d).unwrap();
    for field in [
        "receipt_id",
        "slot_id",
        "demoted_cell_digest",
        "restored_cell_digest",
        "demotion_reason",
        "timestamp_ns",
        "rollback_token_used",
        "linked_replacement_receipt_id",
        "evidence",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_demotion_receipt_record() {
    let d = DemotionReceiptRecord {
        receipt_id: "dem-1".into(),
        slot_id: slot("s"),
        demoted_cell_digest: "abc".into(),
        restored_cell_digest: "def".into(),
        demotion_reason: "regressed".into(),
        timestamp_ns: 999,
        rollback_token_used: "tok".into(),
        linked_replacement_receipt_id: Some("r-1".into()),
        receipt_content_hash: "hash".into(),
    };
    let json = serde_json::to_string(&d).unwrap();
    for field in [
        "receipt_id",
        "slot_id",
        "demoted_cell_digest",
        "restored_cell_digest",
        "demotion_reason",
        "timestamp_ns",
        "rollback_token_used",
        "linked_replacement_receipt_id",
        "receipt_content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_lineage_chain_entry() {
    let e = LineageChainEntry {
        slot_id: slot("s"),
        timestamp_ns: 100,
        receipt_id: "r".into(),
        kind: ReplacementKind::DelegateToNative,
        from_cell_digest: "old".into(),
        to_cell_digest: "new".into(),
        receipt_content_hash: "h".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    for field in [
        "slot_id",
        "timestamp_ns",
        "receipt_id",
        "kind",
        "from_cell_digest",
        "to_cell_digest",
        "receipt_content_hash",
    ] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_slot_lineage_query() {
    let q = SlotLineageQuery {
        min_timestamp_ns: Some(1),
        max_timestamp_ns: Some(2),
        limit: Some(10),
    };
    let json = serde_json::to_string(&q).unwrap();
    for field in ["min_timestamp_ns", "max_timestamp_ns", "limit"] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

#[test]
fn json_fields_replay_join_query() {
    let q = ReplayJoinQuery {
        slot_id: Some(slot("s")),
        min_timestamp_ns: Some(1),
        max_timestamp_ns: Some(2),
        limit: Some(5),
    };
    let json = serde_json::to_string(&q).unwrap();
    for field in ["slot_id", "min_timestamp_ns", "max_timestamp_ns", "limit"] {
        assert!(
            json.contains(&format!("\"{field}\"")),
            "missing {field} in {json}"
        );
    }
}

// ===========================================================================
// 9. Serde roundtrips for types not covered
// ===========================================================================

#[test]
fn serde_roundtrip_lineage_step() {
    let s = LineageStep {
        sequence: 5,
        kind: ReplacementKind::Rollback,
        old_cell_digest: "old".into(),
        new_cell_digest: "new".into(),
        receipt_id: "r-abc".into(),
        timestamp_ns: 1000,
        epoch: epoch(),
        validation_artifact_count: 2,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: LineageStep = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
}

#[test]
fn serde_roundtrip_lineage_verification() {
    let v = LineageVerification {
        slot_id: slot("s"),
        total_entries: 3,
        chain_valid: true,
        all_receipts_present: false,
        issues: vec!["issue1".into()],
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: LineageVerification = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn serde_roundtrip_evidence_pointer_input() {
    let e = EvidencePointerInput {
        category: EvidenceCategory::PerformanceBenchmark,
        artifact_digest: "bench-1".into(),
        passed: Some(false),
        summary: "slow".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: EvidencePointerInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn serde_roundtrip_evidence_pointer() {
    let e = EvidencePointer {
        receipt_id: "r-42".into(),
        category: EvidenceCategory::SentinelRiskScore,
        artifact_digest: "score-hash".into(),
        passed: Some(true),
        summary: "low risk".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: EvidencePointer = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn serde_roundtrip_demotion_receipt_input() {
    let d = DemotionReceiptInput {
        receipt_id: "dem-1".into(),
        slot_id: slot("s"),
        demoted_cell_digest: "abc".into(),
        restored_cell_digest: "def".into(),
        demotion_reason: "regression".into(),
        timestamp_ns: 999,
        rollback_token_used: "tok-1".into(),
        linked_replacement_receipt_id: Some("repl-1".into()),
        evidence: vec![EvidencePointerInput {
            category: EvidenceCategory::Additional,
            artifact_digest: "ev-1".into(),
            passed: None,
            summary: "extra".into(),
        }],
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: DemotionReceiptInput = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

#[test]
fn serde_roundtrip_demotion_receipt_record() {
    let d = DemotionReceiptRecord {
        receipt_id: "dem-2".into(),
        slot_id: slot("s"),
        demoted_cell_digest: "old".into(),
        restored_cell_digest: "new".into(),
        demotion_reason: "safety".into(),
        timestamp_ns: 500,
        rollback_token_used: "tok".into(),
        linked_replacement_receipt_id: None,
        receipt_content_hash: "hash-abc".into(),
    };
    let json = serde_json::to_string(&d).unwrap();
    let back: DemotionReceiptRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, d);
}

#[test]
fn serde_roundtrip_lineage_chain_entry() {
    let e = LineageChainEntry {
        slot_id: slot("s"),
        timestamp_ns: 123,
        receipt_id: "r-x".into(),
        kind: ReplacementKind::RePromotion,
        from_cell_digest: "a".into(),
        to_cell_digest: "b".into(),
        receipt_content_hash: "ch".into(),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: LineageChainEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

#[test]
fn serde_roundtrip_slot_lineage_query() {
    let q = SlotLineageQuery {
        min_timestamp_ns: Some(1),
        max_timestamp_ns: Some(100),
        limit: Some(50),
    };
    let json = serde_json::to_string(&q).unwrap();
    let back: SlotLineageQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, q);
}

#[test]
fn serde_roundtrip_replay_join_query() {
    let q = ReplayJoinQuery {
        slot_id: Some(slot("s")),
        min_timestamp_ns: None,
        max_timestamp_ns: Some(500),
        limit: None,
    };
    let json = serde_json::to_string(&q).unwrap();
    let back: ReplayJoinQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, q);
}

#[test]
fn serde_roundtrip_lineage_index_event() {
    let e = LineageIndexEvent {
        trace_id: "tr".into(),
        decision_id: "dec".into(),
        policy_id: "pol".into(),
        component: "comp".into(),
        event: "indexed".into(),
        outcome: "ok".into(),
        error_code: Some("E-1".into()),
    };
    let json = serde_json::to_string(&e).unwrap();
    let back: LineageIndexEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, e);
}

// ===========================================================================
// 10. LineageLogConfig — Default exact values
// ===========================================================================

#[test]
fn lineage_log_config_default_exact() {
    let c = LineageLogConfig::default();
    assert_eq!(c.checkpoint_interval, 100);
    assert_eq!(c.max_entries_in_memory, 0);
}

// ===========================================================================
// 11. SlotLineageQuery / ReplayJoinQuery defaults
// ===========================================================================

#[test]
fn slot_lineage_query_default() {
    let q = SlotLineageQuery::default();
    assert_eq!(q.min_timestamp_ns, None);
    assert_eq!(q.max_timestamp_ns, None);
    assert_eq!(q.limit, None);
}

#[test]
fn replay_join_query_default() {
    let q = ReplayJoinQuery::default();
    assert_eq!(q.slot_id, None);
    assert_eq!(q.min_timestamp_ns, None);
    assert_eq!(q.max_timestamp_ns, None);
    assert_eq!(q.limit, None);
}

// ===========================================================================
// 12. Duplicate receipt error
// ===========================================================================

#[test]
fn append_duplicate_receipt_rejected() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r.clone(), ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    // Same receipt again → DuplicateReceipt
    let result = log.append(r, ReplacementKind::Demotion, 2_000_000);
    match result {
        Err(LineageLogError::DuplicateReceipt { .. }) => {}
        other => panic!("expected DuplicateReceipt, got {other:?}"),
    }
}

// ===========================================================================
// 13. Query with timestamp filters
// ===========================================================================

#[test]
fn query_with_min_timestamp_filter() {
    let mut log = ReplacementLineageLog::new(cfg());
    for i in 0..5u64 {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }

    let q = LineageQuery {
        slot_id: None,
        kinds: None,
        min_timestamp_ns: Some(3_000_000),
        max_timestamp_ns: None,
    };
    let results = log.query(&q);
    assert_eq!(results.len(), 3); // ts=3M, 4M, 5M
}

#[test]
fn query_with_max_timestamp_filter() {
    let mut log = ReplacementLineageLog::new(cfg());
    for i in 0..5u64 {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }

    let q = LineageQuery {
        slot_id: None,
        kinds: None,
        min_timestamp_ns: None,
        max_timestamp_ns: Some(2_000_000),
    };
    let results = log.query(&q);
    assert_eq!(results.len(), 2); // ts=1M, 2M
}

#[test]
fn query_with_timestamp_range() {
    let mut log = ReplacementLineageLog::new(cfg());
    for i in 0..5u64 {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }

    let q = LineageQuery {
        slot_id: None,
        kinds: None,
        min_timestamp_ns: Some(2_000_000),
        max_timestamp_ns: Some(4_000_000),
    };
    let results = log.query(&q);
    assert_eq!(results.len(), 3); // ts=2M, 3M, 4M
}

// ===========================================================================
// 14. Query with combined filters (slot + kind + timestamp)
// ===========================================================================

#[test]
fn query_combined_slot_kind_timestamp() {
    let mut log = ReplacementLineageLog::new(cfg());
    // Add entry for slot-1 DelegateToNative
    let r1 = make_receipt_slot("slot-1", "old-a", "new-a", 1_000_000);
    log.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    // Add entry for slot-1 Demotion
    let r2 = make_receipt_slot("slot-1", "new-a", "old-a", 2_000_000);
    log.append(r2, ReplacementKind::Demotion, 2_000_000)
        .unwrap();
    // Add entry for slot-2 DelegateToNative
    let r3 = make_receipt_slot("slot-2", "old-b", "new-b", 3_000_000);
    log.append(r3, ReplacementKind::DelegateToNative, 3_000_000)
        .unwrap();

    let q = LineageQuery {
        slot_id: Some(slot("slot-1")),
        kinds: Some(BTreeSet::from([ReplacementKind::DelegateToNative])),
        min_timestamp_ns: None,
        max_timestamp_ns: Some(5_000_000),
    };
    let results = log.query(&q);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].kind, ReplacementKind::DelegateToNative);
}

// ===========================================================================
// 15. Multiple slots in log — slot_ids distinct
// ===========================================================================

#[test]
fn multiple_slots_in_log() {
    let mut log = ReplacementLineageLog::new(cfg());
    for (i, name) in ["slot-a", "slot-b", "slot-c"].iter().enumerate() {
        let r = make_receipt_slot(name, "old", "new", (i as u64 + 1) * 1_000_000);
        log.append(
            r,
            ReplacementKind::DelegateToNative,
            (i as u64 + 1) * 1_000_000,
        )
        .unwrap();
    }
    let ids = log.slot_ids();
    assert_eq!(ids.len(), 3);
}

// ===========================================================================
// 16. Auto-checkpoint when interval is reached
// ===========================================================================

#[test]
fn auto_checkpoint_at_interval() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig {
        checkpoint_interval: 3,
        max_entries_in_memory: 0,
    });

    // Append 3 entries → auto-checkpoint should trigger
    for i in 0..3u64 {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    assert_eq!(
        log.checkpoints().len(),
        1,
        "should auto-checkpoint after 3 appends"
    );
    assert_eq!(log.checkpoints()[0].log_length, 3);
}

#[test]
fn auto_checkpoint_fires_multiple_times() {
    let mut log = ReplacementLineageLog::new(LineageLogConfig {
        checkpoint_interval: 2,
        max_entries_in_memory: 0,
    });
    for i in 0..6u64 {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    // Should checkpoint at seq=1 (2 entries), seq=3 (4 entries), seq=5 (6 entries)
    assert_eq!(log.checkpoints().len(), 3);
}

// ===========================================================================
// 17. Inclusion proof edge cases
// ===========================================================================

#[test]
fn inclusion_proof_first_entry() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    let proof = log.inclusion_proof(0).unwrap();
    assert_eq!(proof.entry_index, 0);
    assert!(verify_inclusion_proof(&proof));
}

#[test]
fn inclusion_proof_out_of_range() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    assert!(log.inclusion_proof(1).is_none());
    assert!(log.inclusion_proof(999).is_none());
}

#[test]
fn inclusion_proof_tampered_rejects() {
    let mut log = ReplacementLineageLog::new(cfg());
    for i in 0..4u64 {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }

    let mut proof = log.inclusion_proof(1).unwrap();
    assert!(verify_inclusion_proof(&proof));

    // Tamper with the entry hash
    proof.entry_hash = frankenengine_engine::hash_tiers::ContentHash::compute(b"tampered");
    assert!(!verify_inclusion_proof(&proof));
}

// ===========================================================================
// 18. Consistency proof error paths
// ===========================================================================

#[test]
fn consistency_proof_equal_seq_rejected() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(2_000_000, epoch()).unwrap();

    match log.consistency_proof(0, 0) {
        Err(LineageLogError::InvalidCheckpointOrder { .. }) => {}
        other => panic!("expected InvalidCheckpointOrder, got {other:?}"),
    }
}

#[test]
fn consistency_proof_missing_checkpoint() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(2_000_000, epoch()).unwrap();

    match log.consistency_proof(0, 99) {
        Err(LineageLogError::CheckpointNotFound { checkpoint_seq: 99 }) => {}
        other => panic!("expected CheckpointNotFound(99), got {other:?}"),
    }
}

#[test]
fn consistency_proof_tampered_rejects() {
    let mut log = ReplacementLineageLog::new(cfg());
    for i in 0..3u64 {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log.create_checkpoint(4_000_000, epoch()).unwrap();
    for i in 3..6u64 {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log.create_checkpoint(7_000_000, epoch()).unwrap();

    let mut proof = log.consistency_proof(0, 1).unwrap();
    assert!(verify_consistency_proof(&proof));

    // Tamper: swap older root
    proof.older_root = frankenengine_engine::hash_tiers::ContentHash::compute(b"fake");
    assert!(!verify_consistency_proof(&proof));
}

// ===========================================================================
// 19. Verify slot lineage — non-existent slot
// ===========================================================================

#[test]
fn verify_slot_lineage_nonexistent() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    let v = log.verify_slot_lineage(&slot("nonexistent"));
    assert!(v.chain_valid);
    assert_eq!(v.total_entries, 0);
    assert_eq!(v.issues.len(), 1);
    assert!(v.issues[0].contains("no entries"), "{:?}", v.issues);
}

// ===========================================================================
// 20. LineageStep field verification
// ===========================================================================

#[test]
fn slot_lineage_step_fields() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old-x", "new-x", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    let lineage = log.slot_lineage(&slot("lineage-slot-1"));
    assert_eq!(lineage.len(), 1);
    let step = &lineage[0];
    assert_eq!(step.sequence, 0);
    assert_eq!(step.kind, ReplacementKind::DelegateToNative);
    assert_eq!(step.old_cell_digest, "old-x");
    assert_eq!(step.new_cell_digest, "new-x");
    assert_eq!(step.timestamp_ns, 1_000_000);
    assert_eq!(step.epoch, epoch());
    assert_eq!(step.validation_artifact_count, 1);
    assert!(!step.receipt_id.is_empty());
}

// ===========================================================================
// 21. Events emitted on operations
// ===========================================================================

#[test]
fn events_emitted_on_append() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    assert!(!log.events().is_empty());
    let ev = &log.events()[0];
    assert_eq!(ev.component, "replacement_lineage_log");
    assert_eq!(ev.event, "entry_appended");
    assert_eq!(ev.outcome, "ok");
    assert!(ev.error_code.is_none());
}

#[test]
fn events_emitted_on_checkpoint() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(2_000_000, epoch()).unwrap();

    // Should have at least 2 events: append + checkpoint
    assert!(log.events().len() >= 2);
    let cp_event = log
        .events()
        .iter()
        .find(|e| e.event == "checkpoint_created")
        .expect("checkpoint event");
    assert_eq!(cp_event.outcome, "ok");
}

// ===========================================================================
// 22. Audit with multiple checkpoints and consistency
// ===========================================================================

#[test]
fn audit_multiple_checkpoints_consistent() {
    let mut log = ReplacementLineageLog::new(cfg());
    for i in 0..3u64 {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log.create_checkpoint(4_000_000, epoch()).unwrap();

    for i in 3..6u64 {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log.create_checkpoint(7_000_000, epoch()).unwrap();

    let audit = log.audit();
    assert_eq!(audit.total_entries, 6);
    assert!(audit.chain_valid);
    assert!(audit.merkle_valid);
    assert_eq!(audit.checkpoint_count, 2);
    assert_eq!(audit.latest_checkpoint_seq, Some(1));
    assert!(audit.issues.is_empty(), "issues: {:?}", audit.issues);
}

// ===========================================================================
// 23. Multi-slot audit — total_slots correct
// ===========================================================================

#[test]
fn audit_multi_slot_counts() {
    let mut log = ReplacementLineageLog::new(cfg());
    for (i, name) in ["slot-a", "slot-b", "slot-a", "slot-c"].iter().enumerate() {
        let r = make_receipt_slot(name, "old", "new", (i as u64 + 1) * 1_000_000);
        log.append(
            r,
            ReplacementKind::DelegateToNative,
            (i as u64 + 1) * 1_000_000,
        )
        .unwrap();
    }
    let audit = log.audit();
    assert_eq!(audit.total_entries, 4);
    assert_eq!(audit.total_slots, 3); // a, b, c
}

// ===========================================================================
// 24. Hash chain integrity — genesis hash
// ===========================================================================

#[test]
fn first_entry_predecessor_is_genesis() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    let genesis = frankenengine_engine::hash_tiers::ContentHash::compute(b"genesis");
    assert_eq!(log.entries()[0].predecessor_hash, genesis);
}

// ===========================================================================
// 25. Merkle root deterministic
// ===========================================================================

#[test]
fn merkle_root_deterministic_same_entries() {
    let mut log1 = ReplacementLineageLog::new(cfg());
    let mut log2 = ReplacementLineageLog::new(cfg());

    for i in 0..3u64 {
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
// 26. Serde exact enum values
// ===========================================================================

#[test]
fn serde_exact_replacement_kind() {
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
fn serde_exact_proof_direction() {
    assert_eq!(
        serde_json::to_string(&ProofDirection::Left).unwrap(),
        "\"Left\""
    );
    assert_eq!(
        serde_json::to_string(&ProofDirection::Right).unwrap(),
        "\"Right\""
    );
}

#[test]
fn serde_exact_evidence_category() {
    assert_eq!(
        serde_json::to_string(&EvidenceCategory::GateResult).unwrap(),
        "\"GateResult\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceCategory::PerformanceBenchmark).unwrap(),
        "\"PerformanceBenchmark\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceCategory::SentinelRiskScore).unwrap(),
        "\"SentinelRiskScore\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceCategory::DifferentialExecutionLog).unwrap(),
        "\"DifferentialExecutionLog\""
    );
    assert_eq!(
        serde_json::to_string(&EvidenceCategory::Additional).unwrap(),
        "\"Additional\""
    );
}

// ===========================================================================
// 27. ReplacementLineageLog serde roundtrip
// ===========================================================================

#[test]
fn replacement_lineage_log_serde_roundtrip() {
    let mut log = ReplacementLineageLog::new(cfg());
    for i in 0..3u64 {
        let r = make_receipt(
            &format!("old-{i}"),
            &format!("new-{i}"),
            (i + 1) * 1_000_000,
        );
        log.append(r, ReplacementKind::DelegateToNative, (i + 1) * 1_000_000)
            .unwrap();
    }
    log.create_checkpoint(4_000_000, epoch()).unwrap();

    let json = serde_json::to_string(&log).unwrap();
    let back: ReplacementLineageLog = serde_json::from_str(&json).unwrap();
    assert_eq!(back.len(), 3);
    assert_eq!(back.checkpoints().len(), 1);
    assert_eq!(back.merkle_root(), log.merkle_root());
}

// ===========================================================================
// 28. LineageLogEntry hash deterministic
// ===========================================================================

#[test]
fn entry_hash_deterministic() {
    let mut log1 = ReplacementLineageLog::new(cfg());
    let mut log2 = ReplacementLineageLog::new(cfg());

    let r1 = make_receipt("old", "new", 1_000_000);
    let r2 = make_receipt("old", "new", 1_000_000);

    log1.append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log2.append(r2, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();

    assert_eq!(log1.entries()[0].entry_hash, log2.entries()[0].entry_hash);
}

// ===========================================================================
// 29. Different replacement kinds yield different hashes
// ===========================================================================

#[test]
fn different_kinds_different_hashes() {
    let mut log_d = ReplacementLineageLog::new(cfg());
    let mut log_r = ReplacementLineageLog::new(cfg());

    let r1 = make_receipt("old", "new", 1_000_000);
    let r2 = make_receipt("old", "new", 1_000_000);

    log_d
        .append(r1, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log_r
        .append(r2, ReplacementKind::Rollback, 1_000_000)
        .unwrap();

    assert_ne!(log_d.entries()[0].entry_hash, log_r.entries()[0].entry_hash);
}

// ===========================================================================
// 30. Checkpoint hash deterministic
// ===========================================================================

#[test]
fn checkpoint_hash_deterministic() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(2_000_000, epoch()).unwrap();

    let cp = &log.checkpoints()[0];
    assert!(!cp.checkpoint_hash.as_bytes().is_empty());
    assert_ne!(cp.checkpoint_hash, cp.merkle_root);
}

// ===========================================================================
// 31. JSON field-name stability — LineageLogEntry
// ===========================================================================

#[test]
fn json_fields_lineage_log_entry() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let entry = &log.entries()[0];
    let v: serde_json::Value = serde_json::to_value(entry).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "sequence",
        "receipt",
        "kind",
        "predecessor_hash",
        "entry_hash",
    ] {
        assert!(
            obj.contains_key(key),
            "LineageLogEntry missing field: {key}"
        );
    }
}

// ===========================================================================
// 32. JSON field-name stability — MerkleProofStep
// ===========================================================================

#[test]
fn json_fields_merkle_proof_step() {
    let step = MerkleProofStep {
        sibling_hash: ContentHash::compute(b"sibling"),
        direction: ProofDirection::Left,
    };
    let v: serde_json::Value = serde_json::to_value(&step).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["sibling_hash", "direction"] {
        assert!(
            obj.contains_key(key),
            "MerkleProofStep missing field: {key}"
        );
    }
}

// ===========================================================================
// 33. JSON field-name stability — InclusionProof
// ===========================================================================

#[test]
fn json_fields_inclusion_proof() {
    let proof = InclusionProof {
        entry_index: 0,
        entry_hash: ContentHash::compute(b"entry"),
        path: vec![],
        root: ContentHash::compute(b"root"),
    };
    let v: serde_json::Value = serde_json::to_value(&proof).unwrap();
    let obj = v.as_object().unwrap();
    for key in ["entry_index", "entry_hash", "path", "root"] {
        assert!(obj.contains_key(key), "InclusionProof missing field: {key}");
    }
}

// ===========================================================================
// 34. JSON field-name stability — ConsistencyProof
// ===========================================================================

#[test]
fn json_fields_consistency_proof() {
    let proof = ConsistencyProof {
        older_checkpoint_seq: 0,
        newer_checkpoint_seq: 1,
        older_log_length: 2,
        newer_log_length: 5,
        older_root: ContentHash::compute(b"older"),
        newer_root: ContentHash::compute(b"newer"),
        older_entry_hashes: vec![],
        newer_entry_hashes: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&proof).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "older_checkpoint_seq",
        "newer_checkpoint_seq",
        "older_log_length",
        "newer_log_length",
        "older_root",
        "newer_root",
        "older_entry_hashes",
        "newer_entry_hashes",
    ] {
        assert!(
            obj.contains_key(key),
            "ConsistencyProof missing field: {key}"
        );
    }
}

// ===========================================================================
// 35. JSON field-name stability — LogCheckpoint
// ===========================================================================

#[test]
fn json_fields_log_checkpoint() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(2_000_000, epoch()).unwrap();
    let cp = &log.checkpoints()[0];
    let v: serde_json::Value = serde_json::to_value(cp).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "checkpoint_seq",
        "log_length",
        "merkle_root",
        "timestamp_ns",
        "epoch",
        "checkpoint_hash",
    ] {
        assert!(obj.contains_key(key), "LogCheckpoint missing field: {key}");
    }
}

// ===========================================================================
// 36. JSON field-name stability — ReplacementReceiptRecord
// ===========================================================================

#[test]
fn json_fields_replacement_receipt_record() {
    let rr = ReplacementReceiptRecord {
        receipt_id: "rr-1".to_string(),
        slot_id: slot("test-slot"),
        replacement_kind: ReplacementKind::DelegateToNative,
        old_cell_digest: "old-digest".to_string(),
        new_cell_digest: "new-digest".to_string(),
        promotion_timestamp_ns: 1_000_000,
        epoch: epoch(),
        receipt_content_hash: "hash".to_string(),
        receipt: make_receipt("old", "new", 1_000_000),
    };
    let v: serde_json::Value = serde_json::to_value(&rr).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "receipt_id",
        "slot_id",
        "replacement_kind",
        "old_cell_digest",
        "new_cell_digest",
        "promotion_timestamp_ns",
        "epoch",
        "receipt_content_hash",
        "receipt",
    ] {
        assert!(
            obj.contains_key(key),
            "ReplacementReceiptRecord missing field: {key}"
        );
    }
}

// ===========================================================================
// 37. JSON field-name stability — ReplayJoinRow
// ===========================================================================

#[test]
fn json_fields_replay_join_row() {
    let row = ReplayJoinRow {
        slot_id: slot("test-slot"),
        replacement_receipt_id: "rr-1".to_string(),
        replacement_kind: ReplacementKind::DelegateToNative,
        old_cell_digest: "old".to_string(),
        new_cell_digest: "new".to_string(),
        promotion_timestamp_ns: 1_000_000,
        replacement_content_hash: "hash".to_string(),
        demotion_receipt_id: None,
        demotion_reason: None,
        demotion_timestamp_ns: None,
        gate_results: vec![],
        performance_benchmarks: vec![],
        sentinel_risk_scores: vec![],
        differential_execution_logs: vec![],
        additional_evidence: vec![],
    };
    let v: serde_json::Value = serde_json::to_value(&row).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "slot_id",
        "replacement_receipt_id",
        "replacement_kind",
        "old_cell_digest",
        "new_cell_digest",
        "promotion_timestamp_ns",
        "replacement_content_hash",
        "demotion_receipt_id",
        "demotion_reason",
        "demotion_timestamp_ns",
        "gate_results",
        "performance_benchmarks",
        "sentinel_risk_scores",
        "differential_execution_logs",
        "additional_evidence",
    ] {
        assert!(obj.contains_key(key), "ReplayJoinRow missing field: {key}");
    }
}

// ===========================================================================
// 38. Serde roundtrip — MerkleProofStep
// ===========================================================================

#[test]
fn serde_roundtrip_merkle_proof_step() {
    let step = MerkleProofStep {
        sibling_hash: ContentHash::compute(b"sib-rt"),
        direction: ProofDirection::Right,
    };
    let json = serde_json::to_string(&step).unwrap();
    let rt: MerkleProofStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, rt);
}

// ===========================================================================
// 39. Serde roundtrip — InclusionProof
// ===========================================================================

#[test]
fn serde_roundtrip_inclusion_proof() {
    let proof = InclusionProof {
        entry_index: 42,
        entry_hash: ContentHash::compute(b"entry-rt"),
        path: vec![
            MerkleProofStep {
                sibling_hash: ContentHash::compute(b"s1"),
                direction: ProofDirection::Left,
            },
            MerkleProofStep {
                sibling_hash: ContentHash::compute(b"s2"),
                direction: ProofDirection::Right,
            },
        ],
        root: ContentHash::compute(b"root-rt"),
    };
    let json = serde_json::to_string(&proof).unwrap();
    let rt: InclusionProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, rt);
}

// ===========================================================================
// 40. Serde roundtrip — ConsistencyProof
// ===========================================================================

#[test]
fn serde_roundtrip_consistency_proof() {
    let proof = ConsistencyProof {
        older_checkpoint_seq: 0,
        newer_checkpoint_seq: 1,
        older_log_length: 3,
        newer_log_length: 7,
        older_root: ContentHash::compute(b"older-rt"),
        newer_root: ContentHash::compute(b"newer-rt"),
        older_entry_hashes: vec![ContentHash::compute(b"h1"), ContentHash::compute(b"h2")],
        newer_entry_hashes: vec![ContentHash::compute(b"h3")],
    };
    let json = serde_json::to_string(&proof).unwrap();
    let rt: ConsistencyProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, rt);
}

// ===========================================================================
// 41. Serde roundtrip — LogCheckpoint
// ===========================================================================

#[test]
fn serde_roundtrip_log_checkpoint() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(2_000_000, epoch()).unwrap();
    let cp = log.checkpoints()[0].clone();
    let json = serde_json::to_string(&cp).unwrap();
    let rt: LogCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(cp, rt);
}

// ===========================================================================
// 42. Serde roundtrip — ReplacementReceiptRecord
// ===========================================================================

#[test]
fn serde_roundtrip_replacement_receipt_record() {
    let rr = ReplacementReceiptRecord {
        receipt_id: "rr-rt".to_string(),
        slot_id: slot("s-rt"),
        replacement_kind: ReplacementKind::Rollback,
        old_cell_digest: "old-rt".to_string(),
        new_cell_digest: "new-rt".to_string(),
        promotion_timestamp_ns: 42_000,
        epoch: epoch(),
        receipt_content_hash: "hash-rt".to_string(),
        receipt: make_receipt("old-rt", "new-rt", 42_000),
    };
    let json = serde_json::to_string(&rr).unwrap();
    let rt: ReplacementReceiptRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, rt);
}

// ===========================================================================
// 43. Serde roundtrip — ReplayJoinRow
// ===========================================================================

#[test]
fn serde_roundtrip_replay_join_row() {
    let row = ReplayJoinRow {
        slot_id: slot("rj-slot"),
        replacement_receipt_id: "rj-1".to_string(),
        replacement_kind: ReplacementKind::Demotion,
        old_cell_digest: "rj-old".to_string(),
        new_cell_digest: "rj-new".to_string(),
        promotion_timestamp_ns: 5_000_000,
        replacement_content_hash: "rj-hash".to_string(),
        demotion_receipt_id: Some("dem-1".to_string()),
        demotion_reason: Some("perf_regression".to_string()),
        demotion_timestamp_ns: Some(6_000_000),
        gate_results: vec![],
        performance_benchmarks: vec![],
        sentinel_risk_scores: vec![],
        differential_execution_logs: vec![],
        additional_evidence: vec![],
    };
    let json = serde_json::to_string(&row).unwrap();
    let rt: ReplayJoinRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, rt);
}

// ===========================================================================
// 44. LineageQuery::for_slot factory
// ===========================================================================

#[test]
fn lineage_query_for_slot_factory() {
    let q = LineageQuery::for_slot(slot("my-slot"));
    assert_eq!(q.slot_id, Some(slot("my-slot")));
    assert!(q.kinds.is_none());
    assert!(q.min_timestamp_ns.is_none());
    assert!(q.max_timestamp_ns.is_none());
}

// ===========================================================================
// 45. LineageQuery::all factory
// ===========================================================================

#[test]
fn lineage_query_all_factory() {
    let q = LineageQuery::all();
    assert!(q.slot_id.is_none());
    assert!(q.kinds.is_none());
    assert!(q.min_timestamp_ns.is_none());
    assert!(q.max_timestamp_ns.is_none());
}

// ===========================================================================
// 46. LineageQuery serde roundtrip
// ===========================================================================

#[test]
fn serde_roundtrip_lineage_query() {
    let q = LineageQuery::for_slot(slot("serde-slot"));
    let json = serde_json::to_string(&q).unwrap();
    let rt: LineageQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q, rt);
}

// ===========================================================================
// 31+. LineageLogEntry serde roundtrip (via live log)
// ===========================================================================

#[test]
fn serde_roundtrip_lineage_log_entry_live() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old-rt", "new-rt", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    let entry = log.entries()[0].clone();
    let json = serde_json::to_string(&entry).unwrap();
    let rt: LineageLogEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, rt);
}

// ===========================================================================
// 32+. Serde roundtrip — AuditResult
// ===========================================================================

#[test]
fn serde_roundtrip_audit_result_enrichment() {
    let ar = AuditResult {
        total_entries: 10,
        total_slots: 2,
        chain_valid: true,
        merkle_valid: true,
        checkpoint_count: 1,
        latest_checkpoint_seq: Some(0),
        issues: vec![],
    };
    let json = serde_json::to_string(&ar).unwrap();
    let rt: AuditResult = serde_json::from_str(&json).unwrap();
    assert_eq!(ar, rt);
}

// ===========================================================================
// 33+. Serde roundtrip — LineageLogConfig
// ===========================================================================

#[test]
fn serde_roundtrip_lineage_log_config_enrichment() {
    let c = LineageLogConfig {
        checkpoint_interval: 10,
        max_entries_in_memory: 500,
    };
    let json = serde_json::to_string(&c).unwrap();
    let rt: LineageLogConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(c, rt);
}

// ===========================================================================
// 34+. LineageLogConfig default values
// ===========================================================================

#[test]
fn lineage_log_config_default_values_enrichment() {
    let c = LineageLogConfig::default();
    assert_eq!(c.checkpoint_interval, 100);
    assert_eq!(c.max_entries_in_memory, 0); // 0 = unlimited
}

// ===========================================================================
// 35+. Serde roundtrip — LogCheckpoint via live log
// ===========================================================================

#[test]
fn serde_roundtrip_log_checkpoint_live() {
    let mut log = ReplacementLineageLog::new(cfg());
    let r = make_receipt("old", "new", 1_000_000);
    log.append(r, ReplacementKind::DelegateToNative, 1_000_000)
        .unwrap();
    log.create_checkpoint(2_000_000, epoch()).unwrap();
    let cp = log.checkpoints()[0].clone();
    let json = serde_json::to_string(&cp).unwrap();
    let rt: LogCheckpoint = serde_json::from_str(&json).unwrap();
    assert_eq!(cp, rt);
}

// ===========================================================================
// 36+. ProofDirection Debug distinct
// ===========================================================================

#[test]
fn proof_direction_debug_distinct() {
    let left = format!("{:?}", ProofDirection::Left);
    let right = format!("{:?}", ProofDirection::Right);
    assert_ne!(left, right);
}

// ===========================================================================
// 37+. ReplayJoinRow with evidence populated
// ===========================================================================

#[test]
fn replay_join_row_with_evidence() {
    let row = ReplayJoinRow {
        slot_id: slot("ev-slot"),
        replacement_receipt_id: "rr-ev".to_string(),
        replacement_kind: ReplacementKind::DelegateToNative,
        old_cell_digest: "ev-old".to_string(),
        new_cell_digest: "ev-new".to_string(),
        promotion_timestamp_ns: 1_000_000,
        replacement_content_hash: "ev-hash".to_string(),
        demotion_receipt_id: None,
        demotion_reason: None,
        demotion_timestamp_ns: None,
        gate_results: vec![EvidencePointer {
            receipt_id: "rr-ev".to_string(),
            category: EvidenceCategory::GateResult,
            artifact_digest: "gate-dig".to_string(),
            passed: Some(true),
            summary: "gate passed".to_string(),
        }],
        performance_benchmarks: vec![EvidencePointer {
            receipt_id: "rr-ev".to_string(),
            category: EvidenceCategory::PerformanceBenchmark,
            artifact_digest: "perf-dig".to_string(),
            passed: Some(true),
            summary: "within budget".to_string(),
        }],
        sentinel_risk_scores: vec![],
        differential_execution_logs: vec![],
        additional_evidence: vec![],
    };
    let json = serde_json::to_string(&row).unwrap();
    let rt: ReplayJoinRow = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.gate_results.len(), 1);
    assert_eq!(rt.performance_benchmarks.len(), 1);
    assert_eq!(rt.sentinel_risk_scores.len(), 0);
}

// ===========================================================================
// 38+. ReplayJoinRow with demotion populated
// ===========================================================================

#[test]
fn replay_join_row_with_demotion() {
    let row = ReplayJoinRow {
        slot_id: slot("dem-slot"),
        replacement_receipt_id: "rr-dem".to_string(),
        replacement_kind: ReplacementKind::DelegateToNative,
        old_cell_digest: "old".to_string(),
        new_cell_digest: "new".to_string(),
        promotion_timestamp_ns: 1_000_000,
        replacement_content_hash: "hash".to_string(),
        demotion_receipt_id: Some("dem-1".to_string()),
        demotion_reason: Some("perf_regression".to_string()),
        demotion_timestamp_ns: Some(2_000_000),
        gate_results: vec![],
        performance_benchmarks: vec![],
        sentinel_risk_scores: vec![],
        differential_execution_logs: vec![],
        additional_evidence: vec![],
    };
    let json = serde_json::to_string(&row).unwrap();
    let rt: ReplayJoinRow = serde_json::from_str(&json).unwrap();
    assert_eq!(rt.demotion_receipt_id.as_deref(), Some("dem-1"));
    assert_eq!(rt.demotion_reason.as_deref(), Some("perf_regression"));
    assert_eq!(rt.demotion_timestamp_ns, Some(2_000_000));
}

// ===========================================================================
// 39+. EvidenceCategory all variants as_str
// ===========================================================================

#[test]
fn evidence_category_all_variants_as_str() {
    let cases = [
        (EvidenceCategory::GateResult, "gate_result"),
        (
            EvidenceCategory::PerformanceBenchmark,
            "performance_benchmark",
        ),
        (EvidenceCategory::SentinelRiskScore, "sentinel_risk_score"),
        (
            EvidenceCategory::DifferentialExecutionLog,
            "differential_execution_log",
        ),
        (EvidenceCategory::Additional, "additional"),
    ];
    for (cat, expected) in &cases {
        assert_eq!(
            cat.as_str(),
            *expected,
            "EvidenceCategory::as_str mismatch for {cat:?}"
        );
    }
}

// ===========================================================================
// 40+. Serde roundtrip — ReplacementReceiptRecord
// ===========================================================================

#[test]
fn serde_roundtrip_replacement_receipt_record_enrichment() {
    let rr = ReplacementReceiptRecord {
        receipt_id: "rr-rt".to_string(),
        slot_id: slot("s-rt"),
        replacement_kind: ReplacementKind::Rollback,
        old_cell_digest: "old-rt".to_string(),
        new_cell_digest: "new-rt".to_string(),
        promotion_timestamp_ns: 42_000,
        epoch: epoch(),
        receipt_content_hash: "hash-rt".to_string(),
        receipt: make_receipt("old-rt", "new-rt", 42_000),
    };
    let json = serde_json::to_string(&rr).unwrap();
    let rt: ReplacementReceiptRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rr, rt);
}

// ===========================================================================
// 41+. Serde roundtrip — ReplayJoinRow
// ===========================================================================

#[test]
fn serde_roundtrip_replay_join_row_enrichment() {
    let row = ReplayJoinRow {
        slot_id: slot("rj-slot"),
        replacement_receipt_id: "rj-1".to_string(),
        replacement_kind: ReplacementKind::Demotion,
        old_cell_digest: "rj-old".to_string(),
        new_cell_digest: "rj-new".to_string(),
        promotion_timestamp_ns: 5_000_000,
        replacement_content_hash: "rj-hash".to_string(),
        demotion_receipt_id: Some("dem-1".to_string()),
        demotion_reason: Some("perf_regression".to_string()),
        demotion_timestamp_ns: Some(6_000_000),
        gate_results: vec![],
        performance_benchmarks: vec![],
        sentinel_risk_scores: vec![],
        differential_execution_logs: vec![],
        additional_evidence: vec![],
    };
    let json = serde_json::to_string(&row).unwrap();
    let rt: ReplayJoinRow = serde_json::from_str(&json).unwrap();
    assert_eq!(row, rt);
}

// ===========================================================================
// 42+. Serde roundtrip — MerkleProofStep
// ===========================================================================

#[test]
fn serde_roundtrip_merkle_proof_step_enrichment() {
    let step = MerkleProofStep {
        sibling_hash: ContentHash::compute(b"sib-rt"),
        direction: ProofDirection::Right,
    };
    let json = serde_json::to_string(&step).unwrap();
    let rt: MerkleProofStep = serde_json::from_str(&json).unwrap();
    assert_eq!(step, rt);
}

// ===========================================================================
// 43+. Serde roundtrip — InclusionProof
// ===========================================================================

#[test]
fn serde_roundtrip_inclusion_proof_enrichment() {
    let proof = InclusionProof {
        entry_index: 42,
        entry_hash: ContentHash::compute(b"entry-rt"),
        path: vec![
            MerkleProofStep {
                sibling_hash: ContentHash::compute(b"s1"),
                direction: ProofDirection::Left,
            },
            MerkleProofStep {
                sibling_hash: ContentHash::compute(b"s2"),
                direction: ProofDirection::Right,
            },
        ],
        root: ContentHash::compute(b"root-rt"),
    };
    let json = serde_json::to_string(&proof).unwrap();
    let rt: InclusionProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, rt);
}

// ===========================================================================
// 44+. Serde roundtrip — ConsistencyProof
// ===========================================================================

#[test]
fn serde_roundtrip_consistency_proof_enrichment() {
    let proof = ConsistencyProof {
        older_checkpoint_seq: 0,
        newer_checkpoint_seq: 1,
        older_log_length: 3,
        newer_log_length: 7,
        older_root: ContentHash::compute(b"older-rt"),
        newer_root: ContentHash::compute(b"newer-rt"),
        older_entry_hashes: vec![ContentHash::compute(b"h1"), ContentHash::compute(b"h2")],
        newer_entry_hashes: vec![ContentHash::compute(b"h3")],
    };
    let json = serde_json::to_string(&proof).unwrap();
    let rt: ConsistencyProof = serde_json::from_str(&json).unwrap();
    assert_eq!(proof, rt);
}

// ===========================================================================
// 45+. Serde roundtrip — LineageQuery with kinds filter
// ===========================================================================

#[test]
fn serde_roundtrip_lineage_query_with_kinds() {
    let mut kinds = BTreeSet::new();
    kinds.insert(ReplacementKind::DelegateToNative);
    kinds.insert(ReplacementKind::Rollback);
    let q = LineageQuery {
        slot_id: Some(slot("q-slot")),
        kinds: Some(kinds),
        min_timestamp_ns: Some(1000),
        max_timestamp_ns: Some(9000),
    };
    let json = serde_json::to_string(&q).unwrap();
    let rt: LineageQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(q, rt);
}

// ===========================================================================
// 46+. LineageLogEvent with error_code populated
// ===========================================================================

#[test]
fn lineage_log_event_with_error_code() {
    let ev = LineageLogEvent {
        trace_id: "t-ec".to_string(),
        decision_id: "d-ec".to_string(),
        policy_id: "p-ec".to_string(),
        component: "replacement_lineage_log".to_string(),
        event: "append_failed".to_string(),
        outcome: "error".to_string(),
        error_code: Some("FE-LINEAGE-0001".to_string()),
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    assert!(v["error_code"].is_string());
    assert_eq!(v["error_code"].as_str().unwrap(), "FE-LINEAGE-0001");
}

#[test]
fn lineage_log_event_without_error_code() {
    let ev = LineageLogEvent {
        trace_id: "t-ne".to_string(),
        decision_id: "d-ne".to_string(),
        policy_id: "p-ne".to_string(),
        component: "replacement_lineage_log".to_string(),
        event: "append".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
    assert!(v["error_code"].is_null());
}

// ===========================================================================
// 47+. ReplacementReceiptRecord JSON field-name stability
// ===========================================================================

#[test]
fn json_fields_replacement_receipt_record_enrichment() {
    let rr = ReplacementReceiptRecord {
        receipt_id: "rr-1".to_string(),
        slot_id: slot("test-slot"),
        replacement_kind: ReplacementKind::DelegateToNative,
        old_cell_digest: "old-digest".to_string(),
        new_cell_digest: "new-digest".to_string(),
        promotion_timestamp_ns: 1_000_000,
        epoch: epoch(),
        receipt_content_hash: "hash".to_string(),
        receipt: make_receipt("old", "new", 1_000_000),
    };
    let v: serde_json::Value = serde_json::to_value(&rr).unwrap();
    let obj = v.as_object().unwrap();
    for key in [
        "receipt_id",
        "slot_id",
        "replacement_kind",
        "old_cell_digest",
        "new_cell_digest",
        "promotion_timestamp_ns",
        "epoch",
        "receipt_content_hash",
        "receipt",
    ] {
        assert!(
            obj.contains_key(key),
            "ReplacementReceiptRecord missing field: {key}"
        );
    }
}
