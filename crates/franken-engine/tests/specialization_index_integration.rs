#![forbid(unsafe_code)]

//! Integration tests for the `specialization_index` module.
//!
//! Exercises the public API from outside the crate: record types, index CRUD,
//! query filters, invalidation log, audit chain traversal, aggregate views,
//! error variants, Display formatting, serde round-trips, and determinism.

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

use frankenengine_engine::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use frankenengine_engine::proof_specialization_receipt::{OptimizationClass, ProofType};
use frankenengine_engine::security_epoch::SecurityEpoch;
use frankenengine_engine::specialization_index::{
    AuditChainEntry, BenchmarkOutcome, ExtensionSpecializationSummary, InvalidationEntry,
    InvalidationReason, SpecializationIndex, SpecializationIndexError, SpecializationIndexEvent,
    SpecializationRecord, error_code,
};
use frankenengine_engine::storage_adapter::InMemoryStorageAdapter;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const SCHEMA_DEF: &[u8] = b"SpecializationIndexIntegration.v1";

fn schema_id() -> SchemaId {
    SchemaId::from_definition(SCHEMA_DEF)
}

fn make_id(tag: &str) -> EngineObjectId {
    derive_id(
        ObjectDomain::PolicyObject,
        "integration",
        &schema_id(),
        tag.as_bytes(),
    )
    .unwrap()
}

fn make_storage() -> InMemoryStorageAdapter {
    InMemoryStorageAdapter::new()
}

fn make_index() -> SpecializationIndex<InMemoryStorageAdapter> {
    SpecializationIndex::new(make_storage(), "integration-policy")
}

fn make_record(tag: &str, epoch: u64) -> SpecializationRecord {
    SpecializationRecord {
        receipt_id: make_id(tag),
        proof_input_ids: vec![make_id(&format!("{tag}-proof"))],
        proof_types: vec![ProofType::CapabilityWitness],
        optimization_class: OptimizationClass::HostcallDispatchSpecialization,
        extension_id: "ext-int".to_string(),
        epoch: SecurityEpoch::from_raw(epoch),
        timestamp_ns: epoch * 1_000,
        active: true,
    }
}

fn make_record_with_ext(tag: &str, epoch: u64, ext: &str) -> SpecializationRecord {
    let mut rec = make_record(tag, epoch);
    rec.extension_id = ext.to_string();
    rec
}

fn make_benchmark(bm_id: &str, receipt_tag: &str) -> BenchmarkOutcome {
    BenchmarkOutcome {
        benchmark_id: bm_id.to_string(),
        receipt_id: make_id(receipt_tag),
        latency_reduction_millionths: 200_000,
        throughput_increase_millionths: 150_000,
        sample_count: 100,
        timestamp_ns: 5_000,
    }
}

fn make_invalidation(receipt_tag: &str, reason: InvalidationReason, ts: u64) -> InvalidationEntry {
    InvalidationEntry {
        receipt_id: make_id(receipt_tag),
        reason,
        timestamp_ns: ts,
        fallback_confirmed: true,
    }
}

// ===========================================================================
// 1. SpecializationRecord — construction, fields, serde
// ===========================================================================

#[test]
fn specialization_record_construction_and_field_access() {
    let rec = make_record("sr-1", 7);
    assert_eq!(rec.receipt_id, make_id("sr-1"));
    assert_eq!(rec.proof_input_ids.len(), 1);
    assert_eq!(rec.proof_types, vec![ProofType::CapabilityWitness]);
    assert_eq!(
        rec.optimization_class,
        OptimizationClass::HostcallDispatchSpecialization
    );
    assert_eq!(rec.extension_id, "ext-int");
    assert_eq!(rec.epoch, SecurityEpoch::from_raw(7));
    assert_eq!(rec.timestamp_ns, 7_000);
    assert!(rec.active);
}

#[test]
fn specialization_record_serde_round_trip() {
    let rec = make_record("sr-rt", 3);
    let json = serde_json::to_string(&rec).unwrap();
    let decoded: SpecializationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, rec);
}

#[test]
fn specialization_record_inactive_serde_round_trip() {
    let mut rec = make_record("sr-inactive", 2);
    rec.active = false;
    let json = serde_json::to_string(&rec).unwrap();
    let decoded: SpecializationRecord = serde_json::from_str(&json).unwrap();
    assert!(!decoded.active);
    assert_eq!(decoded, rec);
}

#[test]
fn specialization_record_multiple_proofs_serde_round_trip() {
    let mut rec = make_record("sr-mp", 1);
    rec.proof_input_ids = vec![make_id("p1"), make_id("p2"), make_id("p3")];
    rec.proof_types = vec![
        ProofType::CapabilityWitness,
        ProofType::FlowProof,
        ProofType::ReplayMotif,
    ];
    let json = serde_json::to_string(&rec).unwrap();
    let decoded: SpecializationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, rec);
    assert_eq!(decoded.proof_types.len(), 3);
}

// ===========================================================================
// 2. BenchmarkOutcome — construction, fields, serde
// ===========================================================================

#[test]
fn benchmark_outcome_construction_and_field_access() {
    let bm = make_benchmark("bm-field", "rcpt-1");
    assert_eq!(bm.benchmark_id, "bm-field");
    assert_eq!(bm.receipt_id, make_id("rcpt-1"));
    assert_eq!(bm.latency_reduction_millionths, 200_000);
    assert_eq!(bm.throughput_increase_millionths, 150_000);
    assert_eq!(bm.sample_count, 100);
    assert_eq!(bm.timestamp_ns, 5_000);
}

#[test]
fn benchmark_outcome_serde_round_trip() {
    let bm = make_benchmark("bm-rt", "rcpt-2");
    let json = serde_json::to_string(&bm).unwrap();
    let decoded: BenchmarkOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, bm);
}

#[test]
fn benchmark_outcome_zero_values_serde() {
    let bm = BenchmarkOutcome {
        benchmark_id: "bm-zero".to_string(),
        receipt_id: make_id("r-zero"),
        latency_reduction_millionths: 0,
        throughput_increase_millionths: 0,
        sample_count: 0,
        timestamp_ns: 0,
    };
    let json = serde_json::to_string(&bm).unwrap();
    let decoded: BenchmarkOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, bm);
}

// ===========================================================================
// 3. InvalidationReason — every variant, serde
// ===========================================================================

#[test]
fn invalidation_reason_epoch_change_serde() {
    let reason = InvalidationReason::EpochChange {
        old_epoch: 1,
        new_epoch: 2,
    };
    let json = serde_json::to_string(&reason).unwrap();
    let decoded: InvalidationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, reason);
}

#[test]
fn invalidation_reason_proof_expired_serde() {
    let reason = InvalidationReason::ProofExpired {
        proof_id: make_id("expired-proof"),
    };
    let json = serde_json::to_string(&reason).unwrap();
    let decoded: InvalidationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, reason);
}

#[test]
fn invalidation_reason_proof_revoked_serde() {
    let reason = InvalidationReason::ProofRevoked {
        proof_id: make_id("revoked-proof"),
    };
    let json = serde_json::to_string(&reason).unwrap();
    let decoded: InvalidationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, reason);
}

#[test]
fn invalidation_reason_manual_revocation_serde() {
    let reason = InvalidationReason::ManualRevocation {
        operator: "admin-ops".to_string(),
    };
    let json = serde_json::to_string(&reason).unwrap();
    let decoded: InvalidationReason = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, reason);
}

// ===========================================================================
// 4. InvalidationEntry — construction, serde
// ===========================================================================

#[test]
fn invalidation_entry_construction_and_fields() {
    let entry = make_invalidation(
        "ie-1",
        InvalidationReason::EpochChange {
            old_epoch: 10,
            new_epoch: 11,
        },
        42_000,
    );
    assert_eq!(entry.receipt_id, make_id("ie-1"));
    assert_eq!(entry.timestamp_ns, 42_000);
    assert!(entry.fallback_confirmed);
}

#[test]
fn invalidation_entry_serde_round_trip() {
    let entry = InvalidationEntry {
        receipt_id: make_id("ie-rt"),
        reason: InvalidationReason::ProofRevoked {
            proof_id: make_id("rev-proof"),
        },
        timestamp_ns: 99_000,
        fallback_confirmed: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: InvalidationEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, entry);
    assert!(!decoded.fallback_confirmed);
}

// ===========================================================================
// 5. AuditChainEntry — construction, serde
// ===========================================================================

#[test]
fn audit_chain_entry_with_benchmark_serde() {
    let entry = AuditChainEntry {
        proof_id: make_id("ace-p1"),
        proof_type: ProofType::FlowProof,
        receipt_id: make_id("ace-r1"),
        optimization_class: OptimizationClass::IfcCheckElision,
        benchmark_id: Some("ace-bm-1".to_string()),
        latency_reduction_millionths: Some(350_000),
        epoch: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: AuditChainEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, entry);
}

#[test]
fn audit_chain_entry_without_benchmark_serde() {
    let entry = AuditChainEntry {
        proof_id: make_id("ace-p2"),
        proof_type: ProofType::ReplayMotif,
        receipt_id: make_id("ace-r2"),
        optimization_class: OptimizationClass::SuperinstructionFusion,
        benchmark_id: None,
        latency_reduction_millionths: None,
        epoch: SecurityEpoch::from_raw(1),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: AuditChainEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, entry);
}

// ===========================================================================
// 6. ExtensionSpecializationSummary — construction, serde
// ===========================================================================

#[test]
fn extension_summary_struct_serde_round_trip() {
    let summary = ExtensionSpecializationSummary {
        extension_id: "ext-summary-rt".to_string(),
        total_specializations: 10,
        active_specializations: 7,
        invalidated_specializations: 3,
        total_benchmarks: 20,
        avg_latency_reduction_millionths: 180_000,
        proof_utilization_count: 15,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let decoded: ExtensionSpecializationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, summary);
}

#[test]
fn extension_summary_zero_values() {
    let summary = ExtensionSpecializationSummary {
        extension_id: "ext-zero".to_string(),
        total_specializations: 0,
        active_specializations: 0,
        invalidated_specializations: 0,
        total_benchmarks: 0,
        avg_latency_reduction_millionths: 0,
        proof_utilization_count: 0,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let decoded: ExtensionSpecializationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, summary);
}

// ===========================================================================
// 7. SpecializationIndexEvent — construction, serde
// ===========================================================================

#[test]
fn index_event_serde_round_trip_with_error_code() {
    let event = SpecializationIndexEvent {
        trace_id: "t-evt-1".to_string(),
        decision_id: "d-evt-1".to_string(),
        policy_id: "p-evt-1".to_string(),
        component: "specialization_index".to_string(),
        event: "insert_receipt".to_string(),
        outcome: "duplicate".to_string(),
        error_code: Some("DUPLICATE_RECEIPT".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: SpecializationIndexEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, event);
}

#[test]
fn index_event_serde_round_trip_without_error_code() {
    let event = SpecializationIndexEvent {
        trace_id: "t-ok".to_string(),
        decision_id: String::new(),
        policy_id: "policy-1".to_string(),
        component: "specialization_index".to_string(),
        event: "build_audit_chain".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let decoded: SpecializationIndexEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, event);
}

// ===========================================================================
// 8. SpecializationIndexError — all variants, Display, error_code
// ===========================================================================

#[test]
fn error_storage_display() {
    let err = SpecializationIndexError::Storage("backend unreachable".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("storage error"));
    assert!(msg.contains("backend unreachable"));
}

#[test]
fn error_not_found_display() {
    let err = SpecializationIndexError::NotFound {
        receipt_id: "abc123".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("specialization not found"));
    assert!(msg.contains("abc123"));
}

#[test]
fn error_duplicate_receipt_display() {
    let err = SpecializationIndexError::DuplicateReceipt {
        receipt_id: "dup-rcpt".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("duplicate receipt"));
    assert!(msg.contains("dup-rcpt"));
}

#[test]
fn error_duplicate_benchmark_display() {
    let err = SpecializationIndexError::DuplicateBenchmark {
        benchmark_id: "dup-bm".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("duplicate benchmark"));
    assert!(msg.contains("dup-bm"));
}

#[test]
fn error_serialization_failed_display() {
    let err = SpecializationIndexError::SerializationFailed("invalid utf8".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("serialization failed"));
    assert!(msg.contains("invalid utf8"));
}

#[test]
fn error_invalid_context_display() {
    let err = SpecializationIndexError::InvalidContext("missing trace_id".to_string());
    let msg = format!("{err}");
    assert!(msg.contains("invalid context"));
    assert!(msg.contains("missing trace_id"));
}

#[test]
fn error_code_all_variants_stable() {
    assert_eq!(
        error_code(&SpecializationIndexError::Storage("x".to_string())),
        "SI_STORAGE_ERROR"
    );
    assert_eq!(
        error_code(&SpecializationIndexError::NotFound {
            receipt_id: "x".to_string()
        }),
        "SI_NOT_FOUND"
    );
    assert_eq!(
        error_code(&SpecializationIndexError::DuplicateReceipt {
            receipt_id: "x".to_string()
        }),
        "SI_DUPLICATE_RECEIPT"
    );
    assert_eq!(
        error_code(&SpecializationIndexError::DuplicateBenchmark {
            benchmark_id: "x".to_string()
        }),
        "SI_DUPLICATE_BENCHMARK"
    );
    assert_eq!(
        error_code(&SpecializationIndexError::SerializationFailed(
            "x".to_string()
        )),
        "SI_SERIALIZATION_FAILED"
    );
    assert_eq!(
        error_code(&SpecializationIndexError::InvalidContext("x".to_string())),
        "SI_INVALID_CONTEXT"
    );
}

#[test]
fn error_codes_are_unique() {
    let errors: Vec<SpecializationIndexError> = vec![
        SpecializationIndexError::Storage("a".to_string()),
        SpecializationIndexError::NotFound {
            receipt_id: "b".to_string(),
        },
        SpecializationIndexError::DuplicateReceipt {
            receipt_id: "c".to_string(),
        },
        SpecializationIndexError::DuplicateBenchmark {
            benchmark_id: "d".to_string(),
        },
        SpecializationIndexError::SerializationFailed("e".to_string()),
        SpecializationIndexError::InvalidContext("f".to_string()),
    ];
    let codes: BTreeSet<&str> = errors.iter().map(|e| error_code(e)).collect();
    assert_eq!(codes.len(), errors.len(), "all error codes must be unique");
}

#[test]
fn error_implements_std_error() {
    let err = SpecializationIndexError::Storage("test".to_string());
    let _: &dyn std::error::Error = &err;
}

// ===========================================================================
// 9. SpecializationIndex — insert_receipt
// ===========================================================================

#[test]
fn insert_and_get_receipt_round_trip() {
    let mut index = make_index();
    let rec = make_record("insert-get", 5);
    index.insert_receipt(&rec, "t-ig").unwrap();

    let fetched = index.get_receipt(&rec.receipt_id, "t-ig2").unwrap();
    assert_eq!(fetched, Some(rec));
}

#[test]
fn get_nonexistent_receipt_returns_none() {
    let mut index = make_index();
    let id = make_id("ghost");
    let result = index.get_receipt(&id, "t-ghost").unwrap();
    assert!(result.is_none());
}

#[test]
fn insert_duplicate_receipt_returns_error() {
    let mut index = make_index();
    let rec = make_record("dup", 1);
    index.insert_receipt(&rec, "t-1").unwrap();
    let err = index.insert_receipt(&rec, "t-2").unwrap_err();
    match err {
        SpecializationIndexError::DuplicateReceipt { receipt_id } => {
            assert_eq!(receipt_id, rec.receipt_id.to_hex());
        }
        other => panic!("expected DuplicateReceipt, got {other}"),
    }
}

#[test]
fn insert_multiple_distinct_receipts() {
    let mut index = make_index();
    for i in 0..5 {
        let rec = make_record(&format!("multi-{i}"), i as u64 + 1);
        index.insert_receipt(&rec, "t-m").unwrap();
    }
    let all = index.query_receipts(None, "t-all").unwrap();
    assert_eq!(all.len(), 5);
}

// ===========================================================================
// 10. SpecializationIndex — delete_receipt
// ===========================================================================

#[test]
fn delete_existing_receipt_returns_true() {
    let mut index = make_index();
    let rec = make_record("del-1", 1);
    index.insert_receipt(&rec, "t-d1").unwrap();
    assert!(index.delete_receipt(&rec.receipt_id, "t-d2").unwrap());
    assert!(
        index
            .get_receipt(&rec.receipt_id, "t-d3")
            .unwrap()
            .is_none()
    );
}

#[test]
fn delete_nonexistent_receipt_returns_false() {
    let mut index = make_index();
    let id = make_id("nope");
    assert!(!index.delete_receipt(&id, "t-nope").unwrap());
}

#[test]
fn delete_then_reinsert_same_receipt() {
    let mut index = make_index();
    let rec = make_record("del-reinsert", 1);
    index.insert_receipt(&rec, "t-1").unwrap();
    index.delete_receipt(&rec.receipt_id, "t-2").unwrap();
    // Should succeed since original was deleted
    index.insert_receipt(&rec, "t-3").unwrap();
    let fetched = index.get_receipt(&rec.receipt_id, "t-4").unwrap();
    assert_eq!(fetched, Some(rec));
}

// ===========================================================================
// 11. SpecializationIndex — query_receipts
// ===========================================================================

#[test]
fn query_receipts_all() {
    let mut index = make_index();
    index
        .insert_receipt(&make_record("qa-1", 1), "t-1")
        .unwrap();
    index
        .insert_receipt(&make_record("qa-2", 2), "t-2")
        .unwrap();
    index
        .insert_receipt(&make_record("qa-3", 3), "t-3")
        .unwrap();

    let all = index.query_receipts(None, "t-qa").unwrap();
    assert_eq!(all.len(), 3);
}

#[test]
fn query_receipts_by_epoch_filter() {
    let mut index = make_index();
    index
        .insert_receipt(&make_record("ep-1a", 10), "t-1")
        .unwrap();
    index
        .insert_receipt(&make_record("ep-1b", 10), "t-2")
        .unwrap();
    index
        .insert_receipt(&make_record("ep-2", 20), "t-3")
        .unwrap();

    let epoch10 = index
        .query_receipts(Some(SecurityEpoch::from_raw(10)), "t-q10")
        .unwrap();
    assert_eq!(epoch10.len(), 2);

    let epoch20 = index
        .query_receipts(Some(SecurityEpoch::from_raw(20)), "t-q20")
        .unwrap();
    assert_eq!(epoch20.len(), 1);

    let epoch99 = index
        .query_receipts(Some(SecurityEpoch::from_raw(99)), "t-q99")
        .unwrap();
    assert!(epoch99.is_empty());
}

#[test]
fn query_receipts_empty_index() {
    let mut index = make_index();
    let all = index.query_receipts(None, "t-empty").unwrap();
    assert!(all.is_empty());
}

// ===========================================================================
// 12. SpecializationIndex — query_active_receipts
// ===========================================================================

#[test]
fn query_active_receipts_filters_inactive() {
    let mut index = make_index();
    let active = make_record("act-1", 1);
    let mut inactive = make_record("inact-1", 1);
    inactive.active = false;

    index.insert_receipt(&active, "t-1").unwrap();
    index.insert_receipt(&inactive, "t-2").unwrap();

    let results = index.query_active_receipts("t-q").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].receipt_id, active.receipt_id);
}

#[test]
fn query_active_receipts_empty_when_all_inactive() {
    let mut index = make_index();
    let mut r1 = make_record("all-inact-1", 1);
    r1.active = false;
    let mut r2 = make_record("all-inact-2", 1);
    r2.active = false;

    index.insert_receipt(&r1, "t-1").unwrap();
    index.insert_receipt(&r2, "t-2").unwrap();

    let results = index.query_active_receipts("t-q").unwrap();
    assert!(results.is_empty());
}

// ===========================================================================
// 13. SpecializationIndex — find_by_proof
// ===========================================================================

#[test]
fn find_by_proof_returns_matching_receipts() {
    let mut index = make_index();
    let proof_id = make_id("shared-proof-x");

    let mut r1 = make_record("fbp-1", 1);
    r1.proof_input_ids = vec![proof_id.clone()];
    let mut r2 = make_record("fbp-2", 1);
    r2.proof_input_ids = vec![make_id("other-proof")];
    let mut r3 = make_record("fbp-3", 1);
    r3.proof_input_ids = vec![make_id("another"), proof_id.clone()];

    index.insert_receipt(&r1, "t-1").unwrap();
    index.insert_receipt(&r2, "t-2").unwrap();
    index.insert_receipt(&r3, "t-3").unwrap();

    let found = index.find_by_proof(&proof_id, "t-find").unwrap();
    assert_eq!(found.len(), 2);
}

#[test]
fn find_by_proof_no_matches() {
    let mut index = make_index();
    index
        .insert_receipt(&make_record("fbp-nm", 1), "t-1")
        .unwrap();

    let phantom = make_id("phantom-proof");
    let found = index.find_by_proof(&phantom, "t-find").unwrap();
    assert!(found.is_empty());
}

#[test]
fn find_by_proof_empty_index() {
    let mut index = make_index();
    let id = make_id("any-proof");
    let found = index.find_by_proof(&id, "t-empty").unwrap();
    assert!(found.is_empty());
}

// ===========================================================================
// 14. SpecializationIndex — insert_benchmark / find_benchmarks_by_receipt
// ===========================================================================

#[test]
fn insert_and_find_benchmark() {
    let mut index = make_index();
    let rec = make_record("bm-r1", 1);
    index.insert_receipt(&rec, "t-1").unwrap();

    let bm = make_benchmark("bm-ifb-1", "bm-r1");
    index.insert_benchmark(&bm, "t-2").unwrap();

    let benchmarks = index
        .find_benchmarks_by_receipt(&rec.receipt_id, "t-3")
        .unwrap();
    assert_eq!(benchmarks.len(), 1);
    assert_eq!(benchmarks[0].benchmark_id, "bm-ifb-1");
}

#[test]
fn insert_duplicate_benchmark_rejected() {
    let mut index = make_index();
    let bm = make_benchmark("bm-dup", "r-dup");
    index.insert_benchmark(&bm, "t-1").unwrap();
    let err = index.insert_benchmark(&bm, "t-2").unwrap_err();
    match err {
        SpecializationIndexError::DuplicateBenchmark { benchmark_id } => {
            assert_eq!(benchmark_id, "bm-dup");
        }
        other => panic!("expected DuplicateBenchmark, got {other}"),
    }
}

#[test]
fn multiple_benchmarks_for_same_receipt() {
    let mut index = make_index();
    let rec = make_record("bm-multi-r", 1);
    index.insert_receipt(&rec, "t-1").unwrap();

    for i in 0..3 {
        let bm = make_benchmark(&format!("bm-multi-{i}"), "bm-multi-r");
        index.insert_benchmark(&bm, &format!("t-bm-{i}")).unwrap();
    }

    let benchmarks = index
        .find_benchmarks_by_receipt(&rec.receipt_id, "t-q")
        .unwrap();
    assert_eq!(benchmarks.len(), 3);
}

#[test]
fn find_benchmarks_for_unrelated_receipt_returns_empty() {
    let mut index = make_index();
    let bm = make_benchmark("bm-unrel", "r-unrel");
    index.insert_benchmark(&bm, "t-1").unwrap();

    let other = make_id("r-other");
    let found = index.find_benchmarks_by_receipt(&other, "t-2").unwrap();
    assert!(found.is_empty());
}

// ===========================================================================
// 15. SpecializationIndex — record_invalidation
// ===========================================================================

#[test]
fn record_invalidation_marks_receipt_inactive() {
    let mut index = make_index();
    let rec = make_record("inv-r1", 1);
    index.insert_receipt(&rec, "t-1").unwrap();

    let entry = make_invalidation(
        "inv-r1",
        InvalidationReason::EpochChange {
            old_epoch: 1,
            new_epoch: 2,
        },
        2_000,
    );
    index.record_invalidation(&entry, "t-inv").unwrap();

    let fetched = index
        .get_receipt(&rec.receipt_id, "t-get")
        .unwrap()
        .unwrap();
    assert!(!fetched.active);
}

#[test]
fn record_invalidation_for_nonexistent_receipt_still_logs() {
    let mut index = make_index();
    // No receipt inserted, but invalidation should still be recorded in the log
    let entry = make_invalidation(
        "inv-ghost",
        InvalidationReason::ManualRevocation {
            operator: "admin".to_string(),
        },
        1_000,
    );
    index.record_invalidation(&entry, "t-inv").unwrap();

    let all = index.query_invalidations(None, None, "t-q").unwrap();
    assert_eq!(all.len(), 1);
}

#[test]
fn record_invalidation_all_reason_variants() {
    let mut index = make_index();
    let reasons = vec![
        InvalidationReason::EpochChange {
            old_epoch: 1,
            new_epoch: 2,
        },
        InvalidationReason::ProofExpired {
            proof_id: make_id("exp-p"),
        },
        InvalidationReason::ProofRevoked {
            proof_id: make_id("rev-p"),
        },
        InvalidationReason::ManualRevocation {
            operator: "ops-team".to_string(),
        },
    ];

    for (i, reason) in reasons.into_iter().enumerate() {
        let tag = format!("inv-var-{i}");
        let rec = make_record(&tag, 1);
        index.insert_receipt(&rec, "t-ins").unwrap();
        let entry = make_invalidation(&tag, reason, (i as u64 + 1) * 1_000);
        index.record_invalidation(&entry, "t-inv").unwrap();
    }

    let all = index.query_invalidations(None, None, "t-all").unwrap();
    assert_eq!(all.len(), 4);
}

// ===========================================================================
// 16. SpecializationIndex — query_invalidations with time window
// ===========================================================================

#[test]
fn query_invalidations_no_filter() {
    let mut index = make_index();
    for i in 0..3 {
        let tag = format!("qi-{i}");
        let rec = make_record(&tag, 1);
        index.insert_receipt(&rec, "t-ins").unwrap();
        let entry = make_invalidation(
            &tag,
            InvalidationReason::ManualRevocation {
                operator: format!("op-{i}"),
            },
            (i as u64 + 1) * 1_000,
        );
        index.record_invalidation(&entry, "t-inv").unwrap();
    }
    let all = index.query_invalidations(None, None, "t-q").unwrap();
    assert_eq!(all.len(), 3);
}

#[test]
fn query_invalidations_with_from_filter() {
    let mut index = make_index();
    for i in 0..3 {
        let tag = format!("qi-from-{i}");
        let rec = make_record(&tag, 1);
        index.insert_receipt(&rec, "t-ins").unwrap();
        let entry = make_invalidation(
            &tag,
            InvalidationReason::EpochChange {
                old_epoch: 1,
                new_epoch: 2,
            },
            (i as u64 + 1) * 1_000,
        );
        index.record_invalidation(&entry, "t-inv").unwrap();
    }
    // from_ns = 2000 should include ts=2000 and ts=3000
    let filtered = index.query_invalidations(Some(2_000), None, "t-q").unwrap();
    assert_eq!(filtered.len(), 2);
}

#[test]
fn query_invalidations_with_to_filter() {
    let mut index = make_index();
    for i in 0..3 {
        let tag = format!("qi-to-{i}");
        let rec = make_record(&tag, 1);
        index.insert_receipt(&rec, "t-ins").unwrap();
        let entry = make_invalidation(
            &tag,
            InvalidationReason::EpochChange {
                old_epoch: 1,
                new_epoch: 2,
            },
            (i as u64 + 1) * 1_000,
        );
        index.record_invalidation(&entry, "t-inv").unwrap();
    }
    // to_ns = 2000 should include ts=1000 and ts=2000
    let filtered = index.query_invalidations(None, Some(2_000), "t-q").unwrap();
    assert_eq!(filtered.len(), 2);
}

#[test]
fn query_invalidations_with_both_filters() {
    let mut index = make_index();
    for i in 0..5 {
        let tag = format!("qi-both-{i}");
        let rec = make_record(&tag, 1);
        index.insert_receipt(&rec, "t-ins").unwrap();
        let entry = make_invalidation(
            &tag,
            InvalidationReason::ManualRevocation {
                operator: "x".to_string(),
            },
            (i as u64 + 1) * 1_000,
        );
        index.record_invalidation(&entry, "t-inv").unwrap();
    }
    // [2000, 4000] should include ts=2000, 3000, 4000
    let filtered = index
        .query_invalidations(Some(2_000), Some(4_000), "t-q")
        .unwrap();
    assert_eq!(filtered.len(), 3);
}

#[test]
fn query_invalidations_window_excludes_all() {
    let mut index = make_index();
    let tag = "qi-excl";
    let rec = make_record(tag, 1);
    index.insert_receipt(&rec, "t-ins").unwrap();
    let entry = make_invalidation(
        tag,
        InvalidationReason::EpochChange {
            old_epoch: 1,
            new_epoch: 2,
        },
        5_000,
    );
    index.record_invalidation(&entry, "t-inv").unwrap();

    let filtered = index
        .query_invalidations(Some(6_000), Some(7_000), "t-q")
        .unwrap();
    assert!(filtered.is_empty());
}

// ===========================================================================
// 17. SpecializationIndex — build_audit_chain
// ===========================================================================

#[test]
fn audit_chain_without_benchmarks() {
    let mut index = make_index();
    index
        .insert_receipt(&make_record("ac-nb", 1), "t-1")
        .unwrap();

    let chain = index.build_audit_chain("t-ac").unwrap();
    assert_eq!(chain.len(), 1);
    assert!(chain[0].benchmark_id.is_none());
    assert!(chain[0].latency_reduction_millionths.is_none());
}

#[test]
fn audit_chain_with_single_benchmark() {
    let mut index = make_index();
    let rec = make_record("ac-sb", 1);
    index.insert_receipt(&rec, "t-1").unwrap();
    index
        .insert_benchmark(&make_benchmark("bm-ac-sb", "ac-sb"), "t-2")
        .unwrap();

    let chain = index.build_audit_chain("t-ac").unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].benchmark_id.as_deref(), Some("bm-ac-sb"));
    assert_eq!(chain[0].latency_reduction_millionths, Some(200_000));
}

#[test]
fn audit_chain_multiple_proofs_times_multiple_benchmarks() {
    let mut index = make_index();
    let mut rec = make_record("ac-mpmb", 1);
    rec.proof_input_ids = vec![make_id("p-a"), make_id("p-b"), make_id("p-c")];
    rec.proof_types = vec![
        ProofType::CapabilityWitness,
        ProofType::FlowProof,
        ProofType::ReplayMotif,
    ];
    index.insert_receipt(&rec, "t-1").unwrap();

    index
        .insert_benchmark(&make_benchmark("bm-ac-1", "ac-mpmb"), "t-2")
        .unwrap();
    index
        .insert_benchmark(&make_benchmark("bm-ac-2", "ac-mpmb"), "t-3")
        .unwrap();

    let chain = index.build_audit_chain("t-ac").unwrap();
    // 3 proofs * 2 benchmarks = 6
    assert_eq!(chain.len(), 6);
}

#[test]
fn audit_chain_proof_type_defaults_when_proof_types_shorter() {
    let mut index = make_index();
    let mut rec = make_record("ac-default-pt", 1);
    rec.proof_input_ids = vec![make_id("p-x"), make_id("p-y")];
    rec.proof_types = vec![ProofType::FlowProof]; // only 1 type for 2 proofs
    index.insert_receipt(&rec, "t-1").unwrap();

    let chain = index.build_audit_chain("t-ac").unwrap();
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].proof_type, ProofType::FlowProof);
    // Second proof defaults to CapabilityWitness
    assert_eq!(chain[1].proof_type, ProofType::CapabilityWitness);
}

#[test]
fn audit_chain_empty_index() {
    let mut index = make_index();
    let chain = index.build_audit_chain("t-empty").unwrap();
    assert!(chain.is_empty());
}

// ===========================================================================
// 18. SpecializationIndex — reverse_audit_from_benchmark
// ===========================================================================

#[test]
fn reverse_audit_finds_matching_benchmark() {
    let mut index = make_index();
    index
        .insert_receipt(&make_record("ra-1", 1), "t-1")
        .unwrap();
    index
        .insert_receipt(&make_record("ra-2", 1), "t-2")
        .unwrap();
    index
        .insert_benchmark(&make_benchmark("bm-ra-1", "ra-1"), "t-3")
        .unwrap();
    index
        .insert_benchmark(&make_benchmark("bm-ra-2", "ra-2"), "t-4")
        .unwrap();

    let result = index
        .reverse_audit_from_benchmark("bm-ra-1", "t-rev")
        .unwrap();
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].receipt_id, make_id("ra-1"));
}

#[test]
fn reverse_audit_nonexistent_benchmark_returns_empty() {
    let mut index = make_index();
    index
        .insert_receipt(&make_record("ra-ne", 1), "t-1")
        .unwrap();
    index
        .insert_benchmark(&make_benchmark("bm-ra-ne", "ra-ne"), "t-2")
        .unwrap();

    let result = index
        .reverse_audit_from_benchmark("nonexistent-bm", "t-rev")
        .unwrap();
    assert!(result.is_empty());
}

// ===========================================================================
// 19. SpecializationIndex — extension_summary
// ===========================================================================

#[test]
fn extension_summary_basic_counts() {
    let mut index = make_index();

    let r1 = make_record_with_ext("es-1", 1, "ext-A");
    let mut r2 = make_record_with_ext("es-2", 1, "ext-A");
    r2.active = false;
    let r3 = make_record_with_ext("es-3", 1, "ext-B");

    index.insert_receipt(&r1, "t-1").unwrap();
    index.insert_receipt(&r2, "t-2").unwrap();
    index.insert_receipt(&r3, "t-3").unwrap();

    let summary = index.extension_summary("ext-A", "t-sum").unwrap();
    assert_eq!(summary.extension_id, "ext-A");
    assert_eq!(summary.total_specializations, 2);
    assert_eq!(summary.active_specializations, 1);
    assert_eq!(summary.invalidated_specializations, 1);
}

#[test]
fn extension_summary_with_benchmarks_avg_latency() {
    let mut index = make_index();
    let rec = make_record_with_ext("es-bm", 1, "ext-C");
    index.insert_receipt(&rec, "t-1").unwrap();

    let mut bm1 = make_benchmark("bm-es-1", "es-bm");
    bm1.latency_reduction_millionths = 100_000;
    let mut bm2 = make_benchmark("bm-es-2", "es-bm");
    bm2.latency_reduction_millionths = 300_000;

    index.insert_benchmark(&bm1, "t-2").unwrap();
    index.insert_benchmark(&bm2, "t-3").unwrap();

    let summary = index.extension_summary("ext-C", "t-sum").unwrap();
    assert_eq!(summary.total_benchmarks, 2);
    assert_eq!(summary.avg_latency_reduction_millionths, 200_000);
}

#[test]
fn extension_summary_no_data_returns_zeroes() {
    let mut index = make_index();
    let summary = index.extension_summary("nonexistent", "t-sum").unwrap();
    assert_eq!(summary.total_specializations, 0);
    assert_eq!(summary.active_specializations, 0);
    assert_eq!(summary.invalidated_specializations, 0);
    assert_eq!(summary.total_benchmarks, 0);
    assert_eq!(summary.avg_latency_reduction_millionths, 0);
    assert_eq!(summary.proof_utilization_count, 0);
}

#[test]
fn extension_summary_proof_utilization_count() {
    let mut index = make_index();
    let mut rec = make_record_with_ext("es-pu", 1, "ext-D");
    rec.proof_input_ids = vec![make_id("pu-1"), make_id("pu-2"), make_id("pu-3")];
    index.insert_receipt(&rec, "t-1").unwrap();

    let summary = index.extension_summary("ext-D", "t-sum").unwrap();
    assert_eq!(summary.proof_utilization_count, 3);
}

// ===========================================================================
// 20. Event logging
// ===========================================================================

#[test]
fn events_recorded_on_insert_receipt() {
    let mut index = make_index();
    let rec = make_record("ev-1", 1);
    index.insert_receipt(&rec, "trace-ev").unwrap();

    assert_eq!(index.events().len(), 1);
    assert_eq!(index.events()[0].event, "insert_receipt");
    assert_eq!(index.events()[0].outcome, "ok");
    assert_eq!(index.events()[0].trace_id, "trace-ev");
    assert_eq!(index.events()[0].policy_id, "integration-policy");
    assert_eq!(index.events()[0].component, "specialization_index");
    assert!(index.events()[0].error_code.is_none());
}

#[test]
fn events_recorded_on_duplicate_receipt() {
    let mut index = make_index();
    let rec = make_record("ev-dup", 1);
    index.insert_receipt(&rec, "t-1").unwrap();
    let _ = index.insert_receipt(&rec, "t-2");

    assert_eq!(index.events().len(), 2);
    assert_eq!(index.events()[1].outcome, "duplicate");
    assert_eq!(
        index.events()[1].error_code.as_deref(),
        Some("DUPLICATE_RECEIPT")
    );
}

#[test]
fn events_recorded_on_insert_benchmark() {
    let mut index = make_index();
    let bm = make_benchmark("ev-bm", "ev-bm-r");
    index.insert_benchmark(&bm, "t-bm").unwrap();

    let bm_events: Vec<_> = index
        .events()
        .iter()
        .filter(|e| e.event == "insert_benchmark")
        .collect();
    assert_eq!(bm_events.len(), 1);
    assert_eq!(bm_events[0].outcome, "ok");
}

#[test]
fn events_recorded_on_duplicate_benchmark() {
    let mut index = make_index();
    let bm = make_benchmark("ev-dup-bm", "ev-dup-bm-r");
    index.insert_benchmark(&bm, "t-1").unwrap();
    let _ = index.insert_benchmark(&bm, "t-2");

    let dup_events: Vec<_> = index
        .events()
        .iter()
        .filter(|e| e.event == "insert_benchmark" && e.outcome == "duplicate")
        .collect();
    assert_eq!(dup_events.len(), 1);
    assert_eq!(
        dup_events[0].error_code.as_deref(),
        Some("DUPLICATE_BENCHMARK")
    );
}

#[test]
fn events_recorded_on_invalidation() {
    let mut index = make_index();
    let rec = make_record("ev-inv", 1);
    index.insert_receipt(&rec, "t-1").unwrap();

    let entry = make_invalidation(
        "ev-inv",
        InvalidationReason::ManualRevocation {
            operator: "op".to_string(),
        },
        1_000,
    );
    index.record_invalidation(&entry, "t-inv").unwrap();

    let inv_events: Vec<_> = index
        .events()
        .iter()
        .filter(|e| e.event == "record_invalidation")
        .collect();
    assert_eq!(inv_events.len(), 1);
    assert_eq!(inv_events[0].outcome, "ok");
}

#[test]
fn events_recorded_on_audit_chain() {
    let mut index = make_index();
    index
        .insert_receipt(&make_record("ev-ac", 1), "t-1")
        .unwrap();
    index.build_audit_chain("t-ac").unwrap();

    let ac_events: Vec<_> = index
        .events()
        .iter()
        .filter(|e| e.event == "build_audit_chain")
        .collect();
    assert_eq!(ac_events.len(), 1);
    assert_eq!(ac_events[0].outcome, "ok");
}

#[test]
fn events_recorded_on_delete_receipt_ok() {
    let mut index = make_index();
    let rec = make_record("ev-del", 1);
    index.insert_receipt(&rec, "t-1").unwrap();
    index.delete_receipt(&rec.receipt_id, "t-del").unwrap();

    let del_events: Vec<_> = index
        .events()
        .iter()
        .filter(|e| e.event == "delete_receipt")
        .collect();
    assert_eq!(del_events.len(), 1);
    assert_eq!(del_events[0].outcome, "ok");
}

#[test]
fn events_recorded_on_delete_receipt_not_found() {
    let mut index = make_index();
    let id = make_id("ev-del-nf");
    index.delete_receipt(&id, "t-del").unwrap();

    let del_events: Vec<_> = index
        .events()
        .iter()
        .filter(|e| e.event == "delete_receipt")
        .collect();
    assert_eq!(del_events.len(), 1);
    assert_eq!(del_events[0].outcome, "not_found");
}

// ===========================================================================
// 21. ProofType enum variant coverage
// ===========================================================================

#[test]
fn proof_type_all_variants_serde_round_trip() {
    let variants = [
        ProofType::CapabilityWitness,
        ProofType::FlowProof,
        ProofType::ReplayMotif,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let decoded: ProofType = serde_json::from_str(&json).unwrap();
        assert_eq!(&decoded, variant);
    }
}

#[test]
fn proof_type_display_coverage() {
    assert_eq!(
        format!("{}", ProofType::CapabilityWitness),
        "capability_witness"
    );
    assert_eq!(format!("{}", ProofType::FlowProof), "flow_proof");
    assert_eq!(format!("{}", ProofType::ReplayMotif), "replay_motif");
}

// ===========================================================================
// 22. OptimizationClass enum variant coverage
// ===========================================================================

#[test]
fn optimization_class_all_variants_serde_round_trip() {
    let variants = [
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::IfcCheckElision,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::PathElimination,
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let decoded: OptimizationClass = serde_json::from_str(&json).unwrap();
        assert_eq!(&decoded, variant);
    }
}

#[test]
fn optimization_class_display_coverage() {
    assert_eq!(
        format!("{}", OptimizationClass::HostcallDispatchSpecialization),
        "hostcall_dispatch_specialization"
    );
    assert_eq!(
        format!("{}", OptimizationClass::IfcCheckElision),
        "ifc_check_elision"
    );
    assert_eq!(
        format!("{}", OptimizationClass::SuperinstructionFusion),
        "superinstruction_fusion"
    );
    assert_eq!(
        format!("{}", OptimizationClass::PathElimination),
        "path_elimination"
    );
}

// ===========================================================================
// 23. Determinism — same inputs produce same outputs
// ===========================================================================

#[test]
fn deterministic_insert_and_query_produce_identical_results() {
    let run = || {
        let mut index = make_index();
        let r1 = make_record("det-1", 1);
        let r2 = make_record("det-2", 2);
        index.insert_receipt(&r1, "t-1").unwrap();
        index.insert_receipt(&r2, "t-2").unwrap();
        let all = index.query_receipts(None, "t-q").unwrap();
        serde_json::to_string(&all).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn deterministic_events_across_replays() {
    let run = || {
        let mut index = make_index();
        let rec = make_record("det-ev", 1);
        index.insert_receipt(&rec, "t-1").unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-det", "det-ev"), "t-2")
            .unwrap();
        index.build_audit_chain("t-3").unwrap();
        serde_json::to_string(index.events()).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn deterministic_audit_chain_across_replays() {
    let run = || {
        let mut index = make_index();
        let mut rec = make_record("det-ac", 1);
        rec.proof_input_ids = vec![make_id("dp-1"), make_id("dp-2")];
        rec.proof_types = vec![ProofType::FlowProof, ProofType::ReplayMotif];
        index.insert_receipt(&rec, "t-1").unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-det-ac", "det-ac"), "t-2")
            .unwrap();
        let chain = index.build_audit_chain("t-3").unwrap();
        serde_json::to_string(&chain).unwrap()
    };
    assert_eq!(run(), run());
}

#[test]
fn deterministic_extension_summary_across_replays() {
    let run = || {
        let mut index = make_index();
        let rec = make_record_with_ext("det-es", 1, "ext-det");
        index.insert_receipt(&rec, "t-1").unwrap();
        let mut bm = make_benchmark("bm-det-es", "det-es");
        bm.latency_reduction_millionths = 500_000;
        index.insert_benchmark(&bm, "t-2").unwrap();
        let summary = index.extension_summary("ext-det", "t-3").unwrap();
        serde_json::to_string(&summary).unwrap()
    };
    assert_eq!(run(), run());
}

// ===========================================================================
// 24. Cross-concern integration scenarios
// ===========================================================================

#[test]
fn full_lifecycle_insert_benchmark_invalidate_audit_summary() {
    let mut index = make_index();

    // 1. Insert receipts for two extensions
    let r1 = make_record_with_ext("lc-1", 1, "ext-X");
    let r2 = make_record_with_ext("lc-2", 1, "ext-X");
    let r3 = make_record_with_ext("lc-3", 1, "ext-Y");
    index.insert_receipt(&r1, "t-1").unwrap();
    index.insert_receipt(&r2, "t-2").unwrap();
    index.insert_receipt(&r3, "t-3").unwrap();

    // 2. Add benchmarks
    let mut bm1 = make_benchmark("bm-lc-1", "lc-1");
    bm1.latency_reduction_millionths = 100_000;
    let mut bm2 = make_benchmark("bm-lc-2", "lc-2");
    bm2.latency_reduction_millionths = 300_000;
    index.insert_benchmark(&bm1, "t-4").unwrap();
    index.insert_benchmark(&bm2, "t-5").unwrap();

    // 3. Build audit chain — should have 2 entries with benchmarks + 1 without
    let chain = index.build_audit_chain("t-6").unwrap();
    assert_eq!(chain.len(), 3);
    let with_bm: Vec<_> = chain.iter().filter(|e| e.benchmark_id.is_some()).collect();
    assert_eq!(with_bm.len(), 2);

    // 4. Invalidate r1
    let inv = make_invalidation(
        "lc-1",
        InvalidationReason::EpochChange {
            old_epoch: 1,
            new_epoch: 2,
        },
        10_000,
    );
    index.record_invalidation(&inv, "t-7").unwrap();

    // 5. Verify r1 is now inactive
    let fetched = index.get_receipt(&r1.receipt_id, "t-8").unwrap().unwrap();
    assert!(!fetched.active);

    // 6. Active query should exclude r1
    let active = index.query_active_receipts("t-9").unwrap();
    assert_eq!(active.len(), 2);

    // 7. Extension summary for ext-X
    let summary = index.extension_summary("ext-X", "t-10").unwrap();
    assert_eq!(summary.total_specializations, 2);
    assert_eq!(summary.active_specializations, 1);
    assert_eq!(summary.invalidated_specializations, 1);
    assert_eq!(summary.total_benchmarks, 2);
    assert_eq!(summary.avg_latency_reduction_millionths, 200_000);

    // 8. Reverse audit
    let reverse = index
        .reverse_audit_from_benchmark("bm-lc-1", "t-11")
        .unwrap();
    assert_eq!(reverse.len(), 1);
    assert_eq!(reverse[0].receipt_id, make_id("lc-1"));

    // 9. Events should have been accumulated
    assert!(!index.events().is_empty());
}

#[test]
fn invalidation_then_query_active_excludes_invalidated() {
    let mut index = make_index();
    let r1 = make_record("itqa-1", 1);
    let r2 = make_record("itqa-2", 1);
    index.insert_receipt(&r1, "t-1").unwrap();
    index.insert_receipt(&r2, "t-2").unwrap();

    // Invalidate r1
    let entry = make_invalidation(
        "itqa-1",
        InvalidationReason::ProofExpired {
            proof_id: make_id("itqa-1-proof"),
        },
        5_000,
    );
    index.record_invalidation(&entry, "t-inv").unwrap();

    let active = index.query_active_receipts("t-q").unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].receipt_id, r2.receipt_id);
}

#[test]
fn multiple_invalidations_same_receipt() {
    let mut index = make_index();
    let rec = make_record("mist-1", 1);
    index.insert_receipt(&rec, "t-1").unwrap();

    // Two invalidation events for the same receipt (different timestamps)
    let e1 = make_invalidation(
        "mist-1",
        InvalidationReason::EpochChange {
            old_epoch: 1,
            new_epoch: 2,
        },
        1_000,
    );
    let e2 = make_invalidation(
        "mist-1",
        InvalidationReason::ManualRevocation {
            operator: "admin".to_string(),
        },
        2_000,
    );
    index.record_invalidation(&e1, "t-inv1").unwrap();
    index.record_invalidation(&e2, "t-inv2").unwrap();

    let all = index.query_invalidations(None, None, "t-q").unwrap();
    assert_eq!(all.len(), 2);
}

#[test]
fn epoch_scoped_query_across_multiple_epochs() {
    let mut index = make_index();
    for epoch in 1u64..=5 {
        for i in 0..2 {
            let tag = format!("esq-e{epoch}-i{i}");
            let rec = make_record(&tag, epoch);
            index.insert_receipt(&rec, "t-ins").unwrap();
        }
    }

    for epoch in 1u64..=5 {
        let results = index
            .query_receipts(Some(SecurityEpoch::from_raw(epoch)), "t-q")
            .unwrap();
        assert_eq!(results.len(), 2, "epoch {epoch} should have 2 receipts");
    }
}

#[test]
fn delete_does_not_affect_other_receipts() {
    let mut index = make_index();
    let r1 = make_record("dnao-1", 1);
    let r2 = make_record("dnao-2", 1);
    index.insert_receipt(&r1, "t-1").unwrap();
    index.insert_receipt(&r2, "t-2").unwrap();

    index.delete_receipt(&r1.receipt_id, "t-del").unwrap();

    assert!(index.get_receipt(&r1.receipt_id, "t-3").unwrap().is_none());
    assert!(index.get_receipt(&r2.receipt_id, "t-4").unwrap().is_some());
}

#[test]
fn storage_fail_writes_causes_storage_error() {
    let storage = InMemoryStorageAdapter::new().with_fail_writes(true);
    let mut index = SpecializationIndex::new(storage, "fail-policy");
    let rec = make_record("fail-w", 1);
    let err = index.insert_receipt(&rec, "t-fail").unwrap_err();
    match err {
        SpecializationIndexError::Storage(_) => {}
        other => panic!("expected Storage error, got {other}"),
    }
}

// ===========================================================================
// 25. Edge cases
// ===========================================================================

#[test]
fn receipt_with_empty_proof_list() {
    let mut index = make_index();
    let mut rec = make_record("empty-proofs", 1);
    rec.proof_input_ids = vec![];
    rec.proof_types = vec![];
    index.insert_receipt(&rec, "t-1").unwrap();

    // Audit chain should have no entries (no proofs to expand)
    let chain = index.build_audit_chain("t-ac").unwrap();
    assert!(chain.is_empty());
}

#[test]
fn receipt_with_large_proof_list() {
    let mut index = make_index();
    let mut rec = make_record("large-proofs", 1);
    rec.proof_input_ids = (0..50).map(|i| make_id(&format!("lp-{i}"))).collect();
    rec.proof_types = vec![ProofType::CapabilityWitness]; // only 1 type
    index.insert_receipt(&rec, "t-1").unwrap();

    let chain = index.build_audit_chain("t-ac").unwrap();
    // 50 proofs, no benchmarks = 50 entries
    assert_eq!(chain.len(), 50);
    // First has FlowProof... no, first is CapabilityWitness (index 0), rest default
    assert_eq!(chain[0].proof_type, ProofType::CapabilityWitness);
    // Indices 1..49 default to CapabilityWitness since proof_types only has 1 entry
    assert_eq!(chain[49].proof_type, ProofType::CapabilityWitness);
}

#[test]
fn benchmark_with_max_millionths_values() {
    let bm = BenchmarkOutcome {
        benchmark_id: "bm-max".to_string(),
        receipt_id: make_id("r-max"),
        latency_reduction_millionths: u64::MAX,
        throughput_increase_millionths: u64::MAX,
        sample_count: u64::MAX,
        timestamp_ns: u64::MAX,
    };
    let json = serde_json::to_string(&bm).unwrap();
    let decoded: BenchmarkOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(decoded, bm);
}

#[test]
fn all_optimization_classes_in_records() {
    let mut index = make_index();
    let classes = [
        OptimizationClass::HostcallDispatchSpecialization,
        OptimizationClass::IfcCheckElision,
        OptimizationClass::SuperinstructionFusion,
        OptimizationClass::PathElimination,
    ];

    for (i, class) in classes.iter().enumerate() {
        let mut rec = make_record(&format!("oc-{i}"), 1);
        rec.optimization_class = *class;
        index.insert_receipt(&rec, "t-ins").unwrap();
    }

    let all = index.query_receipts(None, "t-q").unwrap();
    assert_eq!(all.len(), 4);
}

#[test]
fn invalidation_entry_fallback_not_confirmed() {
    let entry = InvalidationEntry {
        receipt_id: make_id("no-fb"),
        reason: InvalidationReason::ProofRevoked {
            proof_id: make_id("rev-proof-nfb"),
        },
        timestamp_ns: 999,
        fallback_confirmed: false,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let decoded: InvalidationEntry = serde_json::from_str(&json).unwrap();
    assert!(!decoded.fallback_confirmed);
}
