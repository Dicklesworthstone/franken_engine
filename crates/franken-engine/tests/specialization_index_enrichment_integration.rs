//! Enrichment integration tests for the `specialization_index` module.
//!
//! Exercises deeper CRUD operations, invalidation lifecycle, audit chain
//! traversal with multiple proofs, reverse audit, extension summaries,
//! error codes, Display formatting, serde roundtrips, and event tracking.

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

const SCHEMA_DEF: &[u8] = b"SpecializationIndexEnrichment.v1";

fn schema_id() -> SchemaId {
    SchemaId::from_definition(SCHEMA_DEF)
}

fn make_id(tag: &str) -> EngineObjectId {
    derive_id(ObjectDomain::PolicyObject, "enrich", &schema_id(), tag.as_bytes()).unwrap()
}

fn make_storage() -> InMemoryStorageAdapter {
    InMemoryStorageAdapter::new()
}

fn make_index() -> SpecializationIndex<InMemoryStorageAdapter> {
    SpecializationIndex::new(make_storage(), "enrichment-policy")
}

fn make_record(tag: &str, ext: &str, ep: u64) -> SpecializationRecord {
    SpecializationRecord {
        receipt_id: make_id(tag),
        proof_input_ids: vec![make_id(&format!("{tag}-proof"))],
        proof_types: vec![ProofType::CapabilityWitness],
        optimization_class: OptimizationClass::HostcallDispatchSpecialization,
        extension_id: ext.to_string(),
        epoch: SecurityEpoch::from_raw(ep),
        timestamp_ns: ep * 1000,
        active: true,
    }
}

fn make_record_multi_proof(tag: &str, proof_tags: &[&str], ext: &str, ep: u64) -> SpecializationRecord {
    SpecializationRecord {
        receipt_id: make_id(tag),
        proof_input_ids: proof_tags.iter().map(|t| make_id(t)).collect(),
        proof_types: proof_tags.iter().map(|_| ProofType::CapabilityWitness).collect(),
        optimization_class: OptimizationClass::HostcallDispatchSpecialization,
        extension_id: ext.to_string(),
        epoch: SecurityEpoch::from_raw(ep),
        timestamp_ns: ep * 1000,
        active: true,
    }
}

fn make_benchmark(bm_id: &str, receipt_tag: &str) -> BenchmarkOutcome {
    BenchmarkOutcome {
        benchmark_id: bm_id.to_string(),
        receipt_id: make_id(receipt_tag),
        latency_reduction_millionths: 200_000,
        throughput_increase_millionths: 150_000,
        sample_count: 100,
        timestamp_ns: 5000,
    }
}

// ===========================================================================
// Section 1: Receipt CRUD enrichment
// ===========================================================================

#[test]
fn enrichment_insert_many_receipts_and_query_all() {
    let mut index = make_index();
    for i in 0..10 {
        let tag = format!("r{i}");
        index.insert_receipt(&make_record(&tag, "ext-1", i + 1), &format!("t{i}")).unwrap();
    }
    let all = index.query_receipts(None, "q-all").unwrap();
    assert_eq!(all.len(), 10);
}

#[test]
fn enrichment_query_by_epoch_filters_correctly() {
    let mut index = make_index();
    index.insert_receipt(&make_record("r1", "ext-1", 10), "t1").unwrap();
    index.insert_receipt(&make_record("r2", "ext-1", 20), "t2").unwrap();
    index.insert_receipt(&make_record("r3", "ext-1", 10), "t3").unwrap();

    let epoch_10 = index.query_receipts(Some(SecurityEpoch::from_raw(10)), "q10").unwrap();
    assert_eq!(epoch_10.len(), 2);

    let epoch_20 = index.query_receipts(Some(SecurityEpoch::from_raw(20)), "q20").unwrap();
    assert_eq!(epoch_20.len(), 1);

    let epoch_99 = index.query_receipts(Some(SecurityEpoch::from_raw(99)), "q99").unwrap();
    assert!(epoch_99.is_empty());
}

#[test]
fn enrichment_query_active_receipts() {
    let mut index = make_index();
    let rec1 = make_record("r1", "ext-1", 1);
    let rec2 = make_record("r2", "ext-1", 2);
    index.insert_receipt(&rec1, "t1").unwrap();
    index.insert_receipt(&rec2, "t2").unwrap();

    // Invalidate rec1
    let inv = InvalidationEntry {
        receipt_id: rec1.receipt_id.clone(),
        reason: InvalidationReason::ManualRevocation { operator: "test".to_string() },
        timestamp_ns: 3000,
        fallback_confirmed: true,
    };
    index.record_invalidation(&inv, "t-inv").unwrap();

    let active = index.query_active_receipts("q-active").unwrap();
    assert_eq!(active.len(), 1);
    assert_eq!(active[0].receipt_id, rec2.receipt_id);
}

#[test]
fn enrichment_delete_receipt_then_reinsert() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();
    assert!(index.delete_receipt(&rec.receipt_id, "t-del").unwrap());
    assert!(index.get_receipt(&rec.receipt_id, "t-get").unwrap().is_none());

    // Reinsert should work
    index.insert_receipt(&rec, "t-reinsert").unwrap();
    assert!(index.get_receipt(&rec.receipt_id, "t-get2").unwrap().is_some());
}

// ===========================================================================
// Section 2: Benchmark CRUD enrichment
// ===========================================================================

#[test]
fn enrichment_insert_multiple_benchmarks_for_receipt() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();

    for i in 0..5 {
        let bm = BenchmarkOutcome {
            benchmark_id: format!("bm-{i}"),
            receipt_id: make_id("r1"),
            latency_reduction_millionths: (i + 1) * 50_000,
            throughput_increase_millionths: (i + 1) * 30_000,
            sample_count: 50 + i * 10,
            timestamp_ns: 1000 + i * 100,
        };
        index.insert_benchmark(&bm, &format!("t-bm{i}")).unwrap();
    }

    let bms = index.find_benchmarks_by_receipt(&make_id("r1"), "q-bm").unwrap();
    assert_eq!(bms.len(), 5);
}

#[test]
fn enrichment_duplicate_benchmark_rejected() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();
    let bm = make_benchmark("bm-dup", "r1");
    index.insert_benchmark(&bm, "t2").unwrap();
    let err = index.insert_benchmark(&bm, "t3").unwrap_err();
    assert!(matches!(err, SpecializationIndexError::DuplicateBenchmark { .. }));
}

#[test]
fn enrichment_benchmarks_for_nonexistent_receipt_empty() {
    let mut index = make_index();
    let bms = index.find_benchmarks_by_receipt(&make_id("nonexistent"), "q-none").unwrap();
    assert!(bms.is_empty());
}

// ===========================================================================
// Section 3: Invalidation lifecycle
// ===========================================================================

#[test]
fn enrichment_invalidation_marks_receipt_inactive() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();

    let inv = InvalidationEntry {
        receipt_id: rec.receipt_id.clone(),
        reason: InvalidationReason::EpochChange { old_epoch: 1, new_epoch: 2 },
        timestamp_ns: 2000,
        fallback_confirmed: true,
    };
    index.record_invalidation(&inv, "t-inv").unwrap();

    let fetched = index.get_receipt(&rec.receipt_id, "t-get").unwrap().unwrap();
    assert!(!fetched.active);
}

#[test]
fn enrichment_multiple_invalidations_for_same_receipt() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();

    let inv1 = InvalidationEntry {
        receipt_id: rec.receipt_id.clone(),
        reason: InvalidationReason::ProofExpired { proof_id: make_id("r1-proof") },
        timestamp_ns: 2000,
        fallback_confirmed: true,
    };
    index.record_invalidation(&inv1, "t-inv1").unwrap();

    let inv2 = InvalidationEntry {
        receipt_id: rec.receipt_id.clone(),
        reason: InvalidationReason::ManualRevocation { operator: "admin".to_string() },
        timestamp_ns: 3000,
        fallback_confirmed: false,
    };
    index.record_invalidation(&inv2, "t-inv2").unwrap();

    let invs = index.query_invalidations(None, None, "q-invs").unwrap();
    assert_eq!(invs.len(), 2);
}

#[test]
fn enrichment_query_invalidations_time_window() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();

    for ts in [1000u64, 2000, 3000, 4000, 5000] {
        let inv = InvalidationEntry {
            receipt_id: rec.receipt_id.clone(),
            reason: InvalidationReason::ManualRevocation { operator: "op".to_string() },
            timestamp_ns: ts,
            fallback_confirmed: true,
        };
        index.record_invalidation(&inv, &format!("t-{ts}")).unwrap();
    }

    let window = index.query_invalidations(Some(2000), Some(4000), "q-window").unwrap();
    assert_eq!(window.len(), 3); // 2000, 3000, 4000

    let from_only = index.query_invalidations(Some(3000), None, "q-from").unwrap();
    assert_eq!(from_only.len(), 3); // 3000, 4000, 5000

    let to_only = index.query_invalidations(None, Some(2000), "q-to").unwrap();
    assert_eq!(to_only.len(), 2); // 1000, 2000
}

// ===========================================================================
// Section 4: Audit chain traversal
// ===========================================================================

#[test]
fn enrichment_audit_chain_with_benchmark() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();
    let bm = make_benchmark("bm-1", "r1");
    index.insert_benchmark(&bm, "t2").unwrap();

    let chain = index.build_audit_chain("t-chain").unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].benchmark_id.as_deref(), Some("bm-1"));
    assert_eq!(chain[0].latency_reduction_millionths, Some(200_000));
}

#[test]
fn enrichment_audit_chain_without_benchmark() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();

    let chain = index.build_audit_chain("t-chain").unwrap();
    assert_eq!(chain.len(), 1);
    assert!(chain[0].benchmark_id.is_none());
    assert!(chain[0].latency_reduction_millionths.is_none());
}

#[test]
fn enrichment_audit_chain_multi_proof_receipt() {
    let mut index = make_index();
    let rec = make_record_multi_proof("r-mp", &["p1", "p2", "p3"], "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();

    let chain = index.build_audit_chain("t-chain").unwrap();
    // 3 proofs x 1 receipt (no benchmarks) = 3 chain entries
    assert_eq!(chain.len(), 3);
    let proof_ids: BTreeSet<_> = chain.iter().map(|e| e.proof_id.clone()).collect();
    assert_eq!(proof_ids.len(), 3);
}

#[test]
fn enrichment_audit_chain_multi_proof_with_benchmarks() {
    let mut index = make_index();
    let rec = make_record_multi_proof("r-mp", &["p1", "p2"], "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();
    index.insert_benchmark(&make_benchmark("bm-a", "r-mp"), "t2").unwrap();
    index.insert_benchmark(&make_benchmark("bm-b", "r-mp"), "t3").unwrap();

    let chain = index.build_audit_chain("t-chain").unwrap();
    // 2 proofs x 2 benchmarks = 4 chain entries
    assert_eq!(chain.len(), 4);
}

#[test]
fn enrichment_reverse_audit_from_benchmark() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();
    index.insert_benchmark(&make_benchmark("bm-target", "r1"), "t2").unwrap();
    index.insert_benchmark(&make_benchmark("bm-other", "r1"), "t3").unwrap();

    let chain = index.reverse_audit_from_benchmark("bm-target", "t-rev").unwrap();
    assert_eq!(chain.len(), 1);
    assert_eq!(chain[0].benchmark_id.as_deref(), Some("bm-target"));
}

#[test]
fn enrichment_reverse_audit_nonexistent_benchmark() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();

    let chain = index.reverse_audit_from_benchmark("nonexistent", "t-rev").unwrap();
    assert!(chain.is_empty());
}

// ===========================================================================
// Section 5: Extension summary
// ===========================================================================

#[test]
fn enrichment_extension_summary_basic() {
    let mut index = make_index();
    index.insert_receipt(&make_record("r1", "ext-a", 1), "t1").unwrap();
    index.insert_receipt(&make_record("r2", "ext-a", 2), "t2").unwrap();
    index.insert_receipt(&make_record("r3", "ext-b", 1), "t3").unwrap();

    let bm1 = BenchmarkOutcome {
        benchmark_id: "bm-1".to_string(),
        receipt_id: make_id("r1"),
        latency_reduction_millionths: 100_000,
        throughput_increase_millionths: 50_000,
        sample_count: 100,
        timestamp_ns: 5000,
    };
    let bm2 = BenchmarkOutcome {
        benchmark_id: "bm-2".to_string(),
        receipt_id: make_id("r2"),
        latency_reduction_millionths: 300_000,
        throughput_increase_millionths: 200_000,
        sample_count: 100,
        timestamp_ns: 6000,
    };
    index.insert_benchmark(&bm1, "t-bm1").unwrap();
    index.insert_benchmark(&bm2, "t-bm2").unwrap();

    let summary = index.extension_summary("ext-a", "t-sum").unwrap();
    assert_eq!(summary.extension_id, "ext-a");
    assert_eq!(summary.total_specializations, 2);
    assert_eq!(summary.active_specializations, 2);
    assert_eq!(summary.invalidated_specializations, 0);
    assert_eq!(summary.total_benchmarks, 2);
    assert_eq!(summary.avg_latency_reduction_millionths, 200_000); // (100k + 300k) / 2
}

#[test]
fn enrichment_extension_summary_with_invalidated() {
    let mut index = make_index();
    let rec1 = make_record("r1", "ext-a", 1);
    let rec2 = make_record("r2", "ext-a", 2);
    index.insert_receipt(&rec1, "t1").unwrap();
    index.insert_receipt(&rec2, "t2").unwrap();

    // Invalidate r1
    let inv = InvalidationEntry {
        receipt_id: rec1.receipt_id.clone(),
        reason: InvalidationReason::ProofRevoked { proof_id: make_id("r1-proof") },
        timestamp_ns: 3000,
        fallback_confirmed: true,
    };
    index.record_invalidation(&inv, "t-inv").unwrap();

    let summary = index.extension_summary("ext-a", "t-sum").unwrap();
    assert_eq!(summary.total_specializations, 2);
    assert_eq!(summary.active_specializations, 1);
    assert_eq!(summary.invalidated_specializations, 1);
}

#[test]
fn enrichment_extension_summary_no_receipts() {
    let mut index = make_index();
    let summary = index.extension_summary("nonexistent", "t-sum").unwrap();
    assert_eq!(summary.total_specializations, 0);
    assert_eq!(summary.total_benchmarks, 0);
    assert_eq!(summary.avg_latency_reduction_millionths, 0);
}

// ===========================================================================
// Section 6: Find by proof
// ===========================================================================

#[test]
fn enrichment_find_by_proof_returns_matching() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();

    let proof_id = make_id("r1-proof");
    let results = index.find_by_proof(&proof_id, "t-find").unwrap();
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].receipt_id, rec.receipt_id);
}

#[test]
fn enrichment_find_by_proof_no_match() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();

    let unrelated_proof = make_id("unrelated-proof");
    let results = index.find_by_proof(&unrelated_proof, "t-find").unwrap();
    assert!(results.is_empty());
}

#[test]
fn enrichment_find_by_proof_multi_proof_receipt() {
    let mut index = make_index();
    let rec = make_record_multi_proof("r-mp", &["shared-proof", "other-proof"], "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();

    let shared = make_id("shared-proof");
    let results = index.find_by_proof(&shared, "t-find").unwrap();
    assert_eq!(results.len(), 1);
}

// ===========================================================================
// Section 7: Error codes and Display
// ===========================================================================

#[test]
fn enrichment_error_codes_all_variants() {
    let cases = vec![
        (SpecializationIndexError::Storage("err".to_string()), "SI_STORAGE_ERROR"),
        (SpecializationIndexError::NotFound { receipt_id: "r1".to_string() }, "SI_NOT_FOUND"),
        (SpecializationIndexError::DuplicateReceipt { receipt_id: "r1".to_string() }, "SI_DUPLICATE_RECEIPT"),
        (SpecializationIndexError::DuplicateBenchmark { benchmark_id: "b1".to_string() }, "SI_DUPLICATE_BENCHMARK"),
        (SpecializationIndexError::SerializationFailed("bad".to_string()), "SI_SERIALIZATION_FAILED"),
        (SpecializationIndexError::InvalidContext("ctx".to_string()), "SI_INVALID_CONTEXT"),
    ];
    for (err, expected_code) in &cases {
        assert_eq!(error_code(err), *expected_code);
    }
}

#[test]
fn enrichment_error_display_all_variants() {
    let errors = vec![
        SpecializationIndexError::Storage("connection failed".to_string()),
        SpecializationIndexError::NotFound { receipt_id: "abc123".to_string() },
        SpecializationIndexError::DuplicateReceipt { receipt_id: "def456".to_string() },
        SpecializationIndexError::DuplicateBenchmark { benchmark_id: "bm-789".to_string() },
        SpecializationIndexError::SerializationFailed("invalid json".to_string()),
        SpecializationIndexError::InvalidContext("missing trace".to_string()),
    ];
    for err in &errors {
        let msg = err.to_string();
        assert!(!msg.is_empty(), "empty display for {:?}", err);
    }
}

#[test]
fn enrichment_error_display_contains_details() {
    let err = SpecializationIndexError::Storage("disk full".to_string());
    assert!(err.to_string().contains("disk full"));

    let err = SpecializationIndexError::NotFound { receipt_id: "xyz".to_string() };
    assert!(err.to_string().contains("xyz"));

    let err = SpecializationIndexError::DuplicateReceipt { receipt_id: "dup-r".to_string() };
    assert!(err.to_string().contains("dup-r"));
}

// ===========================================================================
// Section 8: Event tracking
// ===========================================================================

#[test]
fn enrichment_events_emitted_on_insert() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();
    let events = index.events();
    assert!(events.iter().any(|e| e.event == "insert_receipt" && e.outcome == "ok"));
}

#[test]
fn enrichment_events_emitted_on_duplicate() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();
    let _ = index.insert_receipt(&rec, "t2");
    let events = index.events();
    assert!(events.iter().any(|e| e.event == "insert_receipt" && e.outcome == "duplicate"));
}

#[test]
fn enrichment_events_emitted_on_delete() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();
    index.delete_receipt(&rec.receipt_id, "t-del").unwrap();
    let events = index.events();
    assert!(events.iter().any(|e| e.event == "delete_receipt" && e.outcome == "ok"));
}

#[test]
fn enrichment_events_delete_not_found() {
    let mut index = make_index();
    index.delete_receipt(&make_id("nope"), "t-del").unwrap();
    let events = index.events();
    assert!(events.iter().any(|e| e.event == "delete_receipt" && e.outcome == "not_found"));
}

#[test]
fn enrichment_events_on_invalidation() {
    let mut index = make_index();
    let rec = make_record("r1", "ext-1", 1);
    index.insert_receipt(&rec, "t1").unwrap();
    let inv = InvalidationEntry {
        receipt_id: rec.receipt_id.clone(),
        reason: InvalidationReason::ManualRevocation { operator: "admin".to_string() },
        timestamp_ns: 2000,
        fallback_confirmed: true,
    };
    index.record_invalidation(&inv, "t-inv").unwrap();
    let events = index.events();
    assert!(events.iter().any(|e| e.event == "record_invalidation" && e.outcome == "ok"));
}

// ===========================================================================
// Section 9: Serde roundtrips
// ===========================================================================

#[test]
fn enrichment_specialization_record_serde_roundtrip() {
    let rec = make_record("serde-r1", "ext-serde", 42);
    let json = serde_json::to_string(&rec).unwrap();
    let back: SpecializationRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(rec, back);
}

#[test]
fn enrichment_benchmark_outcome_serde_roundtrip() {
    let bm = make_benchmark("bm-serde", "r-serde");
    let json = serde_json::to_string(&bm).unwrap();
    let back: BenchmarkOutcome = serde_json::from_str(&json).unwrap();
    assert_eq!(bm, back);
}

#[test]
fn enrichment_invalidation_entry_serde_roundtrip() {
    let entries = vec![
        InvalidationEntry {
            receipt_id: make_id("inv-r1"),
            reason: InvalidationReason::EpochChange { old_epoch: 1, new_epoch: 2 },
            timestamp_ns: 1000,
            fallback_confirmed: true,
        },
        InvalidationEntry {
            receipt_id: make_id("inv-r2"),
            reason: InvalidationReason::ProofExpired { proof_id: make_id("p1") },
            timestamp_ns: 2000,
            fallback_confirmed: false,
        },
        InvalidationEntry {
            receipt_id: make_id("inv-r3"),
            reason: InvalidationReason::ProofRevoked { proof_id: make_id("p2") },
            timestamp_ns: 3000,
            fallback_confirmed: true,
        },
        InvalidationEntry {
            receipt_id: make_id("inv-r4"),
            reason: InvalidationReason::ManualRevocation { operator: "op".to_string() },
            timestamp_ns: 4000,
            fallback_confirmed: false,
        },
    ];
    for entry in &entries {
        let json = serde_json::to_string(entry).unwrap();
        let back: InvalidationEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(*entry, back);
    }
}

#[test]
fn enrichment_audit_chain_entry_serde_roundtrip() {
    let entry = AuditChainEntry {
        proof_id: make_id("p1"),
        proof_type: ProofType::CapabilityWitness,
        receipt_id: make_id("r1"),
        optimization_class: OptimizationClass::HostcallDispatchSpecialization,
        benchmark_id: Some("bm-1".to_string()),
        latency_reduction_millionths: Some(150_000),
        epoch: SecurityEpoch::from_raw(5),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: AuditChainEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(entry, back);
}

#[test]
fn enrichment_extension_summary_serde_roundtrip() {
    let summary = ExtensionSpecializationSummary {
        extension_id: "ext-serde".to_string(),
        total_specializations: 10,
        active_specializations: 7,
        invalidated_specializations: 3,
        total_benchmarks: 5,
        avg_latency_reduction_millionths: 175_000,
        proof_utilization_count: 15,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: ExtensionSpecializationSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

#[test]
fn enrichment_event_serde_roundtrip() {
    let event = SpecializationIndexEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
        component: "specialization_index".to_string(),
        event: "insert_receipt".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: SpecializationIndexEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}
