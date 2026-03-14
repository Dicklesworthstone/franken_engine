//! Integration-level enrichment tests for the `storage_adapter` module.
//!
//! Covers: Copy/Clone semantics, BTreeSet ordering, serde roundtrips,
//! Display coverage, Debug non-empty, Default correctness, constant stability,
//! std::error::Error compliance, CRUD lifecycle, migration receipts, event
//! recording, cross-store isolation, query filters, fail-writes injection,
//! JSON field-name stability, and FrankensqliteStorageAdapter via mock backend.

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::storage_adapter::{
    BatchPutEntry, EventContext, FrankensqliteBackend, FrankensqliteStorageAdapter,
    InMemoryStorageAdapter, MigrationReceipt, STORAGE_SCHEMA_VERSION, StorageAdapter, StorageError,
    StorageEvent, StoreKind, StoreQuery, StoreRecord,
};

// ── helpers ─────────────────────────────────────────────────────────────

fn ctx() -> EventContext {
    EventContext::new("trace-int", "decision-int", "policy-int").unwrap()
}

// ── Copy semantics ──────────────────────────────────────────────────────

#[test]
fn enrichment_store_kind_copy() {
    let a = StoreKind::ReplayIndex;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_store_kind_copy_all_variants() {
    let variants = [
        StoreKind::ReplayIndex,
        StoreKind::EvidenceIndex,
        StoreKind::BenchmarkLedger,
        StoreKind::PolicyCache,
        StoreKind::PlasWitness,
        StoreKind::ReplacementLineage,
        StoreKind::IfcProvenance,
        StoreKind::SpecializationIndex,
    ];
    for v in variants {
        let copy = v;
        assert_eq!(v, copy);
    }
}

// ── Clone independence ──────────────────────────────────────────────────

#[test]
fn enrichment_store_record_clone_independence() {
    let mut meta = BTreeMap::new();
    meta.insert("env".to_string(), "prod".to_string());
    let original = StoreRecord {
        store: StoreKind::EvidenceIndex,
        key: "original".to_string(),
        value: vec![1, 2, 3],
        metadata: meta,
        revision: 42,
    };
    let mut cloned = original.clone();
    cloned.key = "modified".to_string();
    cloned.value.push(4);
    cloned.revision = 99;
    assert_eq!(original.key, "original");
    assert_eq!(original.value, vec![1, 2, 3]);
    assert_eq!(original.revision, 42);
}

#[test]
fn enrichment_store_query_clone_independence() {
    let mut filters = BTreeMap::new();
    filters.insert("env".to_string(), "prod".to_string());
    let original = StoreQuery {
        key_prefix: Some("run/".to_string()),
        metadata_filters: filters,
        limit: Some(10),
    };
    let mut cloned = original.clone();
    cloned.key_prefix = Some("other/".to_string());
    cloned.limit = Some(5);
    assert_eq!(original.key_prefix, Some("run/".to_string()));
    assert_eq!(original.limit, Some(10));
}

#[test]
fn enrichment_event_context_clone_independence() {
    let original = ctx();
    let mut cloned = original.clone();
    cloned.trace_id = "modified".to_string();
    assert_eq!(original.trace_id, "trace-int");
}

#[test]
fn enrichment_storage_event_clone_independence() {
    let original = StorageEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "put".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let mut cloned = original.clone();
    cloned.outcome = "error".to_string();
    cloned.error_code = Some("FE-STOR-0001".to_string());
    assert_eq!(original.outcome, "ok");
    assert!(original.error_code.is_none());
}

#[test]
fn enrichment_migration_receipt_clone_independence() {
    let original = MigrationReceipt {
        backend: "in_memory".to_string(),
        from_version: 1,
        to_version: 2,
        stores_touched: vec![StoreKind::ReplayIndex],
        records_touched: 5,
        state_hash_before: "aabb".to_string(),
        state_hash_after: "ccdd".to_string(),
    };
    let mut cloned = original.clone();
    cloned.stores_touched.push(StoreKind::PolicyCache);
    cloned.records_touched = 99;
    assert_eq!(original.stores_touched.len(), 1);
    assert_eq!(original.records_touched, 5);
}

// ── BTreeSet ordering ───────────────────────────────────────────────────

#[test]
fn enrichment_store_kind_btreeset_deterministic_order() {
    let mut set = BTreeSet::new();
    set.insert(StoreKind::SpecializationIndex);
    set.insert(StoreKind::ReplayIndex);
    set.insert(StoreKind::PlasWitness);
    set.insert(StoreKind::BenchmarkLedger);
    set.insert(StoreKind::EvidenceIndex);
    set.insert(StoreKind::PolicyCache);
    set.insert(StoreKind::ReplacementLineage);
    set.insert(StoreKind::IfcProvenance);
    let ordered: Vec<_> = set.iter().collect();
    // Verify all 8 present and order is deterministic across runs
    assert_eq!(ordered.len(), 8);
    for window in ordered.windows(2) {
        assert!(window[0] < window[1]);
    }
}

#[test]
fn enrichment_store_kind_btreeset_dedup() {
    let mut set = BTreeSet::new();
    set.insert(StoreKind::PolicyCache);
    set.insert(StoreKind::PolicyCache);
    set.insert(StoreKind::PolicyCache);
    assert_eq!(set.len(), 1);
}

// ── Serde roundtrips ────────────────────────────────────────────────────

#[test]
fn enrichment_store_kind_serde_all_variants() {
    let variants = [
        StoreKind::ReplayIndex,
        StoreKind::EvidenceIndex,
        StoreKind::BenchmarkLedger,
        StoreKind::PolicyCache,
        StoreKind::PlasWitness,
        StoreKind::ReplacementLineage,
        StoreKind::IfcProvenance,
        StoreKind::SpecializationIndex,
    ];
    for kind in variants {
        let json = serde_json::to_string(&kind).unwrap();
        let back: StoreKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind, "StoreKind::{kind:?} roundtrip failed");
    }
}

#[test]
fn enrichment_event_context_serde_roundtrip() {
    let ctx = ctx();
    let json = serde_json::to_string(&ctx).unwrap();
    let back: EventContext = serde_json::from_str(&json).unwrap();
    assert_eq!(back.trace_id, "trace-int");
    assert_eq!(back.decision_id, "decision-int");
    assert_eq!(back.policy_id, "policy-int");
}

#[test]
fn enrichment_store_record_serde_roundtrip() {
    let mut meta = BTreeMap::new();
    meta.insert("lane".to_string(), "runtime".to_string());
    let record = StoreRecord {
        store: StoreKind::PlasWitness,
        key: "witness/1".to_string(),
        value: vec![10, 20, 30],
        metadata: meta,
        revision: 7,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: StoreRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, record);
}

#[test]
fn enrichment_store_query_serde_roundtrip_empty() {
    let query = StoreQuery::default();
    let json = serde_json::to_string(&query).unwrap();
    let back: StoreQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, query);
}

#[test]
fn enrichment_store_query_serde_roundtrip_full() {
    let mut filters = BTreeMap::new();
    filters.insert("env".to_string(), "staging".to_string());
    filters.insert("tier".to_string(), "hot".to_string());
    let query = StoreQuery {
        key_prefix: Some("replay/v2/".to_string()),
        metadata_filters: filters,
        limit: Some(50),
    };
    let json = serde_json::to_string(&query).unwrap();
    let back: StoreQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, query);
}

#[test]
fn enrichment_batch_put_entry_serde_roundtrip() {
    let mut meta = BTreeMap::new();
    meta.insert("source".to_string(), "import".to_string());
    let entry = BatchPutEntry {
        key: "batch/key".to_string(),
        value: vec![42, 43],
        metadata: meta,
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: BatchPutEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

#[test]
fn enrichment_migration_receipt_serde_roundtrip() {
    let receipt = MigrationReceipt {
        backend: "in_memory".to_string(),
        from_version: 1,
        to_version: 2,
        stores_touched: vec![StoreKind::ReplayIndex, StoreKind::EvidenceIndex],
        records_touched: 42,
        state_hash_before: "abcdef1234567890".to_string(),
        state_hash_after: "1234567890abcdef".to_string(),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: MigrationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, receipt);
}

#[test]
fn enrichment_storage_event_serde_roundtrip_with_error() {
    let event = StorageEvent {
        trace_id: "t-1".to_string(),
        decision_id: "d-1".to_string(),
        policy_id: "p-1".to_string(),
        component: "storage_adapter".to_string(),
        event: "delete".to_string(),
        outcome: "error".to_string(),
        error_code: Some("FE-STOR-0004".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StorageEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn enrichment_storage_event_serde_roundtrip_without_error() {
    let event = StorageEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "storage_adapter".to_string(),
        event: "get".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StorageEvent = serde_json::from_str(&json).unwrap();
    assert!(back.error_code.is_none());
}

#[test]
fn enrichment_storage_error_serde_roundtrip_all_variants() {
    let errors = vec![
        StorageError::InvalidContext {
            field: "trace_id".to_string(),
        },
        StorageError::InvalidKey {
            key: "".to_string(),
        },
        StorageError::InvalidQuery {
            detail: "limit=0".to_string(),
        },
        StorageError::NotFound {
            store: StoreKind::ReplayIndex,
            key: "k".to_string(),
        },
        StorageError::SchemaVersionMismatch {
            expected: 1,
            actual: 2,
        },
        StorageError::MigrationFailed {
            from: 1,
            to: 2,
            reason: "oops".to_string(),
        },
        StorageError::IntegrityViolation {
            store: StoreKind::PlasWitness,
            detail: "corrupt".to_string(),
        },
        StorageError::BackendUnavailable {
            backend: "sqlite".to_string(),
            detail: "gone".to_string(),
        },
        StorageError::WriteRejected {
            detail: "full".to_string(),
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).unwrap();
        let back: StorageError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, err);
    }
}

#[test]
fn enrichment_in_memory_adapter_serde_roundtrip() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::BenchmarkLedger,
            "bench/001".to_string(),
            vec![1, 2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let json = serde_json::to_string(&adapter).unwrap();
    let back: InMemoryStorageAdapter = serde_json::from_str(&json).unwrap();
    assert_eq!(
        back.current_schema_version(),
        adapter.current_schema_version()
    );
    assert_eq!(back.backend_name(), "in_memory");
}

// ── Display coverage ────────────────────────────────────────────────────

#[test]
fn enrichment_store_kind_display_all_unique() {
    let variants = [
        StoreKind::ReplayIndex,
        StoreKind::EvidenceIndex,
        StoreKind::BenchmarkLedger,
        StoreKind::PolicyCache,
        StoreKind::PlasWitness,
        StoreKind::ReplacementLineage,
        StoreKind::IfcProvenance,
        StoreKind::SpecializationIndex,
    ];
    let displays: Vec<String> = variants.iter().map(|k| k.to_string()).collect();
    let mut deduped = displays.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(displays.len(), deduped.len());
}

#[test]
fn enrichment_store_kind_display_matches_as_str() {
    let variants = [
        StoreKind::ReplayIndex,
        StoreKind::EvidenceIndex,
        StoreKind::BenchmarkLedger,
        StoreKind::PolicyCache,
        StoreKind::PlasWitness,
        StoreKind::ReplacementLineage,
        StoreKind::IfcProvenance,
        StoreKind::SpecializationIndex,
    ];
    for kind in variants {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn enrichment_storage_error_display_invalid_context() {
    let err = StorageError::InvalidContext {
        field: "trace_id".to_string(),
    };
    assert_eq!(err.to_string(), "invalid context field: trace_id");
}

#[test]
fn enrichment_storage_error_display_invalid_key() {
    let err = StorageError::InvalidKey {
        key: "bad key".to_string(),
    };
    assert_eq!(err.to_string(), "invalid key: `bad key`");
}

#[test]
fn enrichment_storage_error_display_invalid_query() {
    let err = StorageError::InvalidQuery {
        detail: "limit=0".to_string(),
    };
    assert_eq!(err.to_string(), "invalid query: limit=0");
}

#[test]
fn enrichment_storage_error_display_not_found() {
    let err = StorageError::NotFound {
        store: StoreKind::PolicyCache,
        key: "missing".to_string(),
    };
    assert_eq!(err.to_string(), "record not found: policy_cache/missing");
}

#[test]
fn enrichment_storage_error_display_schema_mismatch() {
    let err = StorageError::SchemaVersionMismatch {
        expected: 1,
        actual: 2,
    };
    assert_eq!(
        err.to_string(),
        "schema version mismatch: expected 1, got 2"
    );
}

#[test]
fn enrichment_storage_error_display_migration_failed() {
    let err = StorageError::MigrationFailed {
        from: 1,
        to: 2,
        reason: "oops".to_string(),
    };
    assert_eq!(err.to_string(), "migration failed: 1 -> 2: oops");
}

#[test]
fn enrichment_storage_error_display_integrity_violation() {
    let err = StorageError::IntegrityViolation {
        store: StoreKind::ReplayIndex,
        detail: "corrupt".to_string(),
    };
    assert_eq!(
        err.to_string(),
        "integrity violation in replay_index: corrupt"
    );
}

#[test]
fn enrichment_storage_error_display_backend_unavailable() {
    let err = StorageError::BackendUnavailable {
        backend: "sqlite".to_string(),
        detail: "down".to_string(),
    };
    assert_eq!(err.to_string(), "backend unavailable (sqlite): down");
}

#[test]
fn enrichment_storage_error_display_write_rejected() {
    let err = StorageError::WriteRejected {
        detail: "full".to_string(),
    };
    assert_eq!(err.to_string(), "write rejected: full");
}

// ── std::error::Error ───────────────────────────────────────────────────

#[test]
fn enrichment_storage_error_is_std_error() {
    let err = StorageError::NotFound {
        store: StoreKind::ReplayIndex,
        key: "k".to_string(),
    };
    let _: &dyn std::error::Error = &err;
}

#[test]
fn enrichment_storage_error_source_is_none() {
    use std::error::Error;
    let err = StorageError::WriteRejected {
        detail: "test".to_string(),
    };
    assert!(err.source().is_none());
}

// ── Debug nonempty ──────────────────────────────────────────────────────

#[test]
fn enrichment_store_kind_debug_nonempty() {
    assert!(!format!("{:?}", StoreKind::ReplayIndex).is_empty());
    assert!(!format!("{:?}", StoreKind::SpecializationIndex).is_empty());
}

#[test]
fn enrichment_event_context_debug_nonempty() {
    assert!(!format!("{:?}", ctx()).is_empty());
}

#[test]
fn enrichment_store_record_debug_nonempty() {
    let record = StoreRecord {
        store: StoreKind::PolicyCache,
        key: "k".to_string(),
        value: vec![],
        metadata: BTreeMap::new(),
        revision: 0,
    };
    assert!(!format!("{record:?}").is_empty());
}

#[test]
fn enrichment_store_query_debug_nonempty() {
    assert!(!format!("{:?}", StoreQuery::default()).is_empty());
}

#[test]
fn enrichment_batch_put_entry_debug_nonempty() {
    let entry = BatchPutEntry {
        key: "k".to_string(),
        value: vec![1],
        metadata: BTreeMap::new(),
    };
    assert!(!format!("{entry:?}").is_empty());
}

#[test]
fn enrichment_migration_receipt_debug_nonempty() {
    let receipt = MigrationReceipt {
        backend: "test".to_string(),
        from_version: 1,
        to_version: 2,
        stores_touched: vec![],
        records_touched: 0,
        state_hash_before: "aa".to_string(),
        state_hash_after: "bb".to_string(),
    };
    assert!(!format!("{receipt:?}").is_empty());
}

#[test]
fn enrichment_storage_event_debug_nonempty() {
    let event = StorageEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "put".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    assert!(!format!("{event:?}").is_empty());
}

#[test]
fn enrichment_storage_error_debug_nonempty() {
    let err = StorageError::InvalidKey {
        key: "test".to_string(),
    };
    assert!(!format!("{err:?}").is_empty());
}

// ── Default coverage ────────────────────────────────────────────────────

#[test]
fn enrichment_store_query_default() {
    let q = StoreQuery::default();
    assert!(q.key_prefix.is_none());
    assert!(q.metadata_filters.is_empty());
    assert!(q.limit.is_none());
}

#[test]
fn enrichment_in_memory_adapter_default_matches_new() {
    let a = InMemoryStorageAdapter::new();
    let b = InMemoryStorageAdapter::default();
    assert_eq!(a.current_schema_version(), b.current_schema_version());
    assert_eq!(a.backend_name(), b.backend_name());
    assert!(a.events().is_empty());
    assert!(b.events().is_empty());
}

// ── Constants ───────────────────────────────────────────────────────────

#[test]
fn enrichment_storage_schema_version_stable() {
    assert_eq!(STORAGE_SCHEMA_VERSION, 1);
}

// ── StorageError code stability ─────────────────────────────────────────

#[test]
fn enrichment_error_codes_are_sequential_and_unique() {
    let errors: Vec<StorageError> = vec![
        StorageError::InvalidContext {
            field: "f".to_string(),
        },
        StorageError::InvalidKey {
            key: "k".to_string(),
        },
        StorageError::InvalidQuery {
            detail: "d".to_string(),
        },
        StorageError::NotFound {
            store: StoreKind::ReplayIndex,
            key: "k".to_string(),
        },
        StorageError::SchemaVersionMismatch {
            expected: 1,
            actual: 2,
        },
        StorageError::MigrationFailed {
            from: 1,
            to: 2,
            reason: "r".to_string(),
        },
        StorageError::IntegrityViolation {
            store: StoreKind::ReplayIndex,
            detail: "d".to_string(),
        },
        StorageError::BackendUnavailable {
            backend: "b".to_string(),
            detail: "d".to_string(),
        },
        StorageError::WriteRejected {
            detail: "d".to_string(),
        },
    ];
    let codes: Vec<&str> = errors.iter().map(|e| e.code()).collect();
    assert_eq!(
        codes,
        vec![
            "FE-STOR-0001",
            "FE-STOR-0002",
            "FE-STOR-0003",
            "FE-STOR-0004",
            "FE-STOR-0005",
            "FE-STOR-0006",
            "FE-STOR-0007",
            "FE-STOR-0008",
            "FE-STOR-0009",
        ]
    );
    let mut deduped = codes.clone();
    deduped.sort();
    deduped.dedup();
    assert_eq!(codes.len(), deduped.len());
}

// ── StoreKind as_str / integration_point ────────────────────────────────

#[test]
fn enrichment_store_kind_as_str_exhaustive() {
    assert_eq!(StoreKind::ReplayIndex.as_str(), "replay_index");
    assert_eq!(StoreKind::EvidenceIndex.as_str(), "evidence_index");
    assert_eq!(StoreKind::BenchmarkLedger.as_str(), "benchmark_ledger");
    assert_eq!(StoreKind::PolicyCache.as_str(), "policy_cache");
    assert_eq!(StoreKind::PlasWitness.as_str(), "plas_witness");
    assert_eq!(
        StoreKind::ReplacementLineage.as_str(),
        "replacement_lineage"
    );
    assert_eq!(StoreKind::IfcProvenance.as_str(), "ifc_provenance");
    assert_eq!(
        StoreKind::SpecializationIndex.as_str(),
        "specialization_index"
    );
}

#[test]
fn enrichment_store_kind_integration_point_exhaustive() {
    assert_eq!(
        StoreKind::ReplayIndex.integration_point(),
        "frankensqlite::control_plane::replay_index"
    );
    assert_eq!(
        StoreKind::EvidenceIndex.integration_point(),
        "frankensqlite::control_plane::evidence_index"
    );
    assert_eq!(
        StoreKind::BenchmarkLedger.integration_point(),
        "frankensqlite::benchmark::ledger"
    );
    assert_eq!(
        StoreKind::PolicyCache.integration_point(),
        "frankensqlite::control_plane::policy_cache"
    );
    assert_eq!(
        StoreKind::PlasWitness.integration_point(),
        "frankensqlite::analysis::plas_witness"
    );
    assert_eq!(
        StoreKind::ReplacementLineage.integration_point(),
        "frankensqlite::replacement::lineage_log"
    );
    assert_eq!(
        StoreKind::IfcProvenance.integration_point(),
        "frankensqlite::control_plane::ifc_provenance"
    );
    assert_eq!(
        StoreKind::SpecializationIndex.integration_point(),
        "frankensqlite::control_plane::specialization_index"
    );
}

// ── EventContext validation ─────────────────────────────────────────────

#[test]
fn enrichment_event_context_valid() {
    let ctx = EventContext::new("t", "d", "p").unwrap();
    assert_eq!(ctx.trace_id, "t");
    assert_eq!(ctx.decision_id, "d");
    assert_eq!(ctx.policy_id, "p");
}

#[test]
fn enrichment_event_context_empty_trace_id() {
    let err = EventContext::new("", "d", "p").unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0001");
    assert!(matches!(
        err,
        StorageError::InvalidContext { field } if field == "trace_id"
    ));
}

#[test]
fn enrichment_event_context_whitespace_decision_id() {
    let err = EventContext::new("t", "  ", "p").unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0001");
}

#[test]
fn enrichment_event_context_empty_policy_id() {
    let err = EventContext::new("t", "d", "").unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0001");
}

#[test]
fn enrichment_event_context_all_whitespace() {
    let err = EventContext::new("  ", " \t ", "  ").unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0001");
}

// ── InMemoryStorageAdapter CRUD ─────────────────────────────────────────

#[test]
fn enrichment_in_memory_put_get_delete_lifecycle() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();

    // put
    let record = adapter
        .put(
            StoreKind::ReplayIndex,
            "run/001".to_string(),
            vec![1, 2, 3],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    assert_eq!(record.key, "run/001");
    assert_eq!(record.store, StoreKind::ReplayIndex);
    assert_eq!(record.value, vec![1, 2, 3]);
    assert_eq!(record.revision, 1);

    // get
    let got = adapter
        .get(StoreKind::ReplayIndex, "run/001", &context)
        .unwrap()
        .unwrap();
    assert_eq!(got.value, vec![1, 2, 3]);

    // delete
    let deleted = adapter
        .delete(StoreKind::ReplayIndex, "run/001", &context)
        .unwrap();
    assert!(deleted);

    // get after delete
    let gone = adapter
        .get(StoreKind::ReplayIndex, "run/001", &context)
        .unwrap();
    assert!(gone.is_none());
}

#[test]
fn enrichment_in_memory_put_overwrite_increments_revision() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    let r1 = adapter
        .put(
            StoreKind::PolicyCache,
            "policy/1".to_string(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let r2 = adapter
        .put(
            StoreKind::PolicyCache,
            "policy/1".to_string(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    assert!(r2.revision > r1.revision);
    let got = adapter
        .get(StoreKind::PolicyCache, "policy/1", &context)
        .unwrap()
        .unwrap();
    assert_eq!(got.value, vec![2]);
}

#[test]
fn enrichment_in_memory_get_nonexistent_returns_none() {
    let mut adapter = InMemoryStorageAdapter::new();
    let result = adapter
        .get(StoreKind::PolicyCache, "no-such", &ctx())
        .unwrap();
    assert!(result.is_none());
}

#[test]
fn enrichment_in_memory_delete_nonexistent_returns_false() {
    let mut adapter = InMemoryStorageAdapter::new();
    let deleted = adapter
        .delete(StoreKind::PolicyCache, "no-such", &ctx())
        .unwrap();
    assert!(!deleted);
}

#[test]
fn enrichment_in_memory_put_invalid_empty_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter
        .put(
            StoreKind::ReplayIndex,
            "".to_string(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0002");
}

#[test]
fn enrichment_in_memory_put_invalid_whitespace_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter
        .put(
            StoreKind::ReplayIndex,
            "  ".to_string(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0002");
}

#[test]
fn enrichment_in_memory_get_empty_key_error() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter.get(StoreKind::ReplayIndex, "", &ctx()).unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0002");
}

#[test]
fn enrichment_in_memory_delete_empty_key_error() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter
        .delete(StoreKind::ReplayIndex, "", &ctx())
        .unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0002");
}

// ── Cross-store isolation ───────────────────────────────────────────────

#[test]
fn enrichment_cross_store_isolation() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "shared".to_string(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::PolicyCache,
            "shared".to_string(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "shared".to_string(),
            vec![3],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let r1 = adapter
        .get(StoreKind::ReplayIndex, "shared", &context)
        .unwrap()
        .unwrap();
    let r2 = adapter
        .get(StoreKind::PolicyCache, "shared", &context)
        .unwrap()
        .unwrap();
    let r3 = adapter
        .get(StoreKind::EvidenceIndex, "shared", &context)
        .unwrap()
        .unwrap();
    assert_eq!(r1.value, vec![1]);
    assert_eq!(r2.value, vec![2]);
    assert_eq!(r3.value, vec![3]);

    // Delete from one store doesn't affect others
    adapter
        .delete(StoreKind::ReplayIndex, "shared", &context)
        .unwrap();
    assert!(
        adapter
            .get(StoreKind::ReplayIndex, "shared", &context)
            .unwrap()
            .is_none()
    );
    assert!(
        adapter
            .get(StoreKind::PolicyCache, "shared", &context)
            .unwrap()
            .is_some()
    );
    assert!(
        adapter
            .get(StoreKind::EvidenceIndex, "shared", &context)
            .unwrap()
            .is_some()
    );
}

// ── Query filters ───────────────────────────────────────────────────────

#[test]
fn enrichment_query_by_key_prefix() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    for i in 0..5 {
        adapter
            .put(
                StoreKind::ReplayIndex,
                format!("run/{i:03}"),
                vec![i as u8],
                BTreeMap::new(),
                &context,
            )
            .unwrap();
    }
    adapter
        .put(
            StoreKind::ReplayIndex,
            "other/x".to_string(),
            vec![99],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let query = StoreQuery {
        key_prefix: Some("run/".to_string()),
        ..Default::default()
    };
    let rows = adapter
        .query(StoreKind::ReplayIndex, &query, &context)
        .unwrap();
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().all(|r| r.key.starts_with("run/")));
}

#[test]
fn enrichment_query_by_metadata_filter() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    let mut meta_prod = BTreeMap::new();
    meta_prod.insert("env".to_string(), "prod".to_string());
    let mut meta_staging = BTreeMap::new();
    meta_staging.insert("env".to_string(), "staging".to_string());
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "a".to_string(),
            vec![1],
            meta_prod,
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "b".to_string(),
            vec![2],
            meta_staging,
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "c".to_string(),
            vec![3],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let mut filters = BTreeMap::new();
    filters.insert("env".to_string(), "prod".to_string());
    let query = StoreQuery {
        metadata_filters: filters,
        ..Default::default()
    };
    let rows = adapter
        .query(StoreKind::EvidenceIndex, &query, &context)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key, "a");
}

#[test]
fn enrichment_query_combined_prefix_and_metadata() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    let mut meta_prod = BTreeMap::new();
    meta_prod.insert("env".to_string(), "prod".to_string());
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "replay/001".to_string(),
            vec![1],
            meta_prod.clone(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "replay/002".to_string(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "bench/001".to_string(),
            vec![3],
            meta_prod,
            &context,
        )
        .unwrap();

    let mut filters = BTreeMap::new();
    filters.insert("env".to_string(), "prod".to_string());
    let query = StoreQuery {
        key_prefix: Some("replay/".to_string()),
        metadata_filters: filters,
        limit: None,
    };
    let rows = adapter
        .query(StoreKind::EvidenceIndex, &query, &context)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key, "replay/001");
}

#[test]
fn enrichment_query_with_limit() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    for i in 0..10 {
        adapter
            .put(
                StoreKind::ReplayIndex,
                format!("k/{i:03}"),
                vec![i as u8],
                BTreeMap::new(),
                &context,
            )
            .unwrap();
    }
    let query = StoreQuery {
        limit: Some(3),
        ..Default::default()
    };
    let rows = adapter
        .query(StoreKind::ReplayIndex, &query, &context)
        .unwrap();
    assert_eq!(rows.len(), 3);
}

#[test]
fn enrichment_query_limit_zero_errors() {
    let mut adapter = InMemoryStorageAdapter::new();
    let query = StoreQuery {
        limit: Some(0),
        ..Default::default()
    };
    let err = adapter
        .query(StoreKind::ReplayIndex, &query, &ctx())
        .unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0003");
}

#[test]
fn enrichment_query_empty_store_returns_empty() {
    let mut adapter = InMemoryStorageAdapter::new();
    let rows = adapter
        .query(StoreKind::PlasWitness, &StoreQuery::default(), &ctx())
        .unwrap();
    assert!(rows.is_empty());
}

// ── Batch put ───────────────────────────────────────────────────────────

#[test]
fn enrichment_batch_put_success() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    let entries = vec![
        BatchPutEntry {
            key: "a".to_string(),
            value: vec![1],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "b".to_string(),
            value: vec![2],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "c".to_string(),
            value: vec![3],
            metadata: BTreeMap::new(),
        },
    ];
    let records = adapter
        .put_batch(StoreKind::BenchmarkLedger, entries, &context)
        .unwrap();
    assert_eq!(records.len(), 3);

    let rows = adapter
        .query(StoreKind::BenchmarkLedger, &StoreQuery::default(), &context)
        .unwrap();
    assert_eq!(rows.len(), 3);
}

#[test]
fn enrichment_batch_put_empty_succeeds() {
    let mut adapter = InMemoryStorageAdapter::new();
    let records = adapter
        .put_batch(StoreKind::ReplayIndex, vec![], &ctx())
        .unwrap();
    assert!(records.is_empty());
}

#[test]
fn enrichment_batch_put_invalid_key_fails_atomically() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "existing".to_string(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let entries = vec![
        BatchPutEntry {
            key: "ok".to_string(),
            value: vec![2],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "".to_string(),
            value: vec![3],
            metadata: BTreeMap::new(),
        },
    ];
    let err = adapter
        .put_batch(StoreKind::ReplayIndex, entries, &context)
        .unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0002");

    // Pre-existing record should still be there
    let rows = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key, "existing");
}

// ── fail-writes injection ───────────────────────────────────────────────

#[test]
fn enrichment_fail_writes_put_rejected() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let err = adapter
        .put(
            StoreKind::ReplayIndex,
            "k".to_string(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        )
        .unwrap_err();
    assert!(matches!(err, StorageError::WriteRejected { .. }));
    assert_eq!(err.code(), "FE-STOR-0009");
}

#[test]
fn enrichment_fail_writes_delete_rejected() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let err = adapter
        .delete(StoreKind::ReplayIndex, "k", &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::WriteRejected { .. }));
}

#[test]
fn enrichment_fail_writes_batch_rejected() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let entries = vec![BatchPutEntry {
        key: "k".to_string(),
        value: vec![1],
        metadata: BTreeMap::new(),
    }];
    let err = adapter
        .put_batch(StoreKind::ReplayIndex, entries, &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::WriteRejected { .. }));
}

#[test]
fn enrichment_fail_writes_reads_still_work() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    // get and query should still work even when writes fail
    let result = adapter
        .get(StoreKind::ReplayIndex, "no-such", &ctx())
        .unwrap();
    assert!(result.is_none());
    let rows = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &ctx())
        .unwrap();
    assert!(rows.is_empty());
}

// ── Migration ───────────────────────────────────────────────────────────

#[test]
fn enrichment_in_memory_schema_version_starts_at_constant() {
    let adapter = InMemoryStorageAdapter::new();
    assert_eq!(adapter.current_schema_version(), STORAGE_SCHEMA_VERSION);
}

#[test]
fn enrichment_in_memory_ensure_schema_version_match() {
    let adapter = InMemoryStorageAdapter::new();
    assert!(
        adapter
            .ensure_schema_version(STORAGE_SCHEMA_VERSION)
            .is_ok()
    );
}

#[test]
fn enrichment_in_memory_ensure_schema_version_mismatch() {
    let adapter = InMemoryStorageAdapter::new();
    let err = adapter.ensure_schema_version(999).unwrap_err();
    assert!(matches!(
        err,
        StorageError::SchemaVersionMismatch {
            expected: 999,
            actual
        } if actual == STORAGE_SCHEMA_VERSION
    ));
}

#[test]
fn enrichment_in_memory_migrate_up_one() {
    let mut adapter = InMemoryStorageAdapter::new();
    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
    assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
    assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION + 1);
    assert_eq!(receipt.backend, "in_memory");
    assert_ne!(receipt.state_hash_before, receipt.state_hash_after);
    assert_eq!(adapter.current_schema_version(), STORAGE_SCHEMA_VERSION + 1);
}

#[test]
fn enrichment_in_memory_migrate_same_version_is_noop() {
    let mut adapter = InMemoryStorageAdapter::new();
    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION).unwrap();
    assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
    assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION);
}

#[test]
fn enrichment_in_memory_migrate_downgrade_rejected() {
    let mut adapter = InMemoryStorageAdapter::new();
    adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
    let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION).unwrap_err();
    assert!(matches!(err, StorageError::MigrationFailed { .. }));
    assert!(err.to_string().contains("downgrade"));
}

#[test]
fn enrichment_in_memory_migrate_skip_rejected() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 5).unwrap_err();
    assert!(matches!(err, StorageError::MigrationFailed { .. }));
    assert!(err.to_string().contains("single-step"));
}

#[test]
fn enrichment_migration_receipt_reflects_populated_stores() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "k1".to_string(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::PolicyCache,
            "k2".to_string(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "k3".to_string(),
            vec![3],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
    assert!(receipt.stores_touched.contains(&StoreKind::ReplayIndex));
    assert!(receipt.stores_touched.contains(&StoreKind::PolicyCache));
    assert!(receipt.stores_touched.contains(&StoreKind::EvidenceIndex));
    assert_eq!(receipt.records_touched, 3);
}

// ── Events ──────────────────────────────────────────────────────────────

#[test]
fn enrichment_events_record_success() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "k".to_string(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "put");
    assert_eq!(events[0].outcome, "ok");
    assert_eq!(events[0].component, "storage_adapter");
    assert_eq!(events[0].trace_id, "trace-int");
    assert_eq!(events[0].decision_id, "decision-int");
    assert_eq!(events[0].policy_id, "policy-int");
    assert!(events[0].error_code.is_none());
}

#[test]
fn enrichment_events_record_failure() {
    let mut adapter = InMemoryStorageAdapter::new();
    let _ = adapter.put(
        StoreKind::ReplayIndex,
        "".to_string(),
        vec![1],
        BTreeMap::new(),
        &ctx(),
    );
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(events[0].error_code, Some("FE-STOR-0002".to_string()));
}

#[test]
fn enrichment_events_accumulate() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "a".to_string(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "b".to_string(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let _ = adapter.put(
        StoreKind::ReplayIndex,
        "".to_string(),
        vec![3],
        BTreeMap::new(),
        &context,
    );
    adapter.get(StoreKind::ReplayIndex, "a", &context).unwrap();
    adapter
        .delete(StoreKind::ReplayIndex, "a", &context)
        .unwrap();
    assert_eq!(adapter.events().len(), 5);
}

#[test]
fn enrichment_backend_name_in_memory() {
    let adapter = InMemoryStorageAdapter::new();
    assert_eq!(adapter.backend_name(), "in_memory");
}

// ── FrankensqliteStorageAdapter via mock ─────────────────────────────────

#[derive(Debug, Default)]
struct MockBackend {
    wal_applied: bool,
    pragmas: BTreeMap<String, String>,
    schema_version: u32,
    stores: BTreeMap<StoreKind, BTreeMap<String, StoreRecord>>,
    revision_counter: u64,
}

impl FrankensqliteBackend for MockBackend {
    fn apply_wal_profile(&mut self) -> Result<(), String> {
        self.wal_applied = true;
        Ok(())
    }

    fn set_pragma(&mut self, key: &str, value: &str) -> Result<(), String> {
        self.pragmas.insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn current_schema_version(&self) -> Result<u32, String> {
        Ok(self.schema_version.max(STORAGE_SCHEMA_VERSION))
    }

    fn migrate_to(&mut self, target_version: u32) -> Result<(), String> {
        self.schema_version = target_version;
        Ok(())
    }

    fn put_record(
        &mut self,
        store: StoreKind,
        key: &str,
        value: &[u8],
        metadata: &BTreeMap<String, String>,
    ) -> Result<StoreRecord, String> {
        self.revision_counter += 1;
        let record = StoreRecord {
            store,
            key: key.to_string(),
            value: value.to_vec(),
            metadata: metadata.clone(),
            revision: self.revision_counter,
        };
        self.stores
            .entry(store)
            .or_default()
            .insert(key.to_string(), record.clone());
        Ok(record)
    }

    fn get_record(&self, store: StoreKind, key: &str) -> Result<Option<StoreRecord>, String> {
        Ok(self.stores.get(&store).and_then(|s| s.get(key).cloned()))
    }

    fn query_records(
        &self,
        store: StoreKind,
        query: &StoreQuery,
    ) -> Result<Vec<StoreRecord>, String> {
        let mut out = Vec::new();
        if let Some(state) = self.stores.get(&store) {
            for record in state.values() {
                if let Some(prefix) = &query.key_prefix
                    && !record.key.starts_with(prefix)
                {
                    continue;
                }
                if !query
                    .metadata_filters
                    .iter()
                    .all(|(k, v)| record.metadata.get(k) == Some(v))
                {
                    continue;
                }
                out.push(record.clone());
            }
        }
        if let Some(limit) = query.limit {
            out.truncate(limit);
        }
        Ok(out)
    }

    fn delete_record(&mut self, store: StoreKind, key: &str) -> Result<bool, String> {
        Ok(self
            .stores
            .get_mut(&store)
            .and_then(|s| s.remove(key))
            .is_some())
    }

    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: &[BatchPutEntry],
    ) -> Result<Vec<StoreRecord>, String> {
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            out.push(self.put_record(store, &entry.key, &entry.value, &entry.metadata)?);
        }
        Ok(out)
    }
}

#[test]
fn enrichment_frankensqlite_construction() {
    let backend = MockBackend::default();
    let adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    assert_eq!(adapter.backend_name(), "frankensqlite");
    assert_eq!(adapter.current_schema_version(), STORAGE_SCHEMA_VERSION);
}

#[test]
fn enrichment_frankensqlite_crud_lifecycle() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let context = ctx();

    let record = adapter
        .put(
            StoreKind::ReplayIndex,
            "fk/1".to_string(),
            vec![10, 20],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    assert_eq!(record.key, "fk/1");

    let got = adapter
        .get(StoreKind::ReplayIndex, "fk/1", &context)
        .unwrap()
        .unwrap();
    assert_eq!(got.value, vec![10, 20]);

    let deleted = adapter
        .delete(StoreKind::ReplayIndex, "fk/1", &context)
        .unwrap();
    assert!(deleted);

    let gone = adapter
        .get(StoreKind::ReplayIndex, "fk/1", &context)
        .unwrap();
    assert!(gone.is_none());
}

#[test]
fn enrichment_frankensqlite_batch_put() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let entries = vec![
        BatchPutEntry {
            key: "x".to_string(),
            value: vec![1],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "y".to_string(),
            value: vec![2],
            metadata: BTreeMap::new(),
        },
    ];
    let records = adapter
        .put_batch(StoreKind::ReplayIndex, entries, &ctx())
        .unwrap();
    assert_eq!(records.len(), 2);
}

#[test]
fn enrichment_frankensqlite_query_limit_zero_errors() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let query = StoreQuery {
        limit: Some(0),
        ..Default::default()
    };
    let err = adapter
        .query(StoreKind::ReplayIndex, &query, &ctx())
        .unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0003");
}

#[test]
fn enrichment_frankensqlite_invalid_key_on_put() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter
        .put(
            StoreKind::ReplayIndex,
            "  ".to_string(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        )
        .unwrap_err();
    assert_eq!(err.code(), "FE-STOR-0002");
}

#[test]
fn enrichment_frankensqlite_ensure_schema_version() {
    let backend = MockBackend::default();
    let adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    assert!(
        adapter
            .ensure_schema_version(STORAGE_SCHEMA_VERSION)
            .is_ok()
    );
    let err = adapter.ensure_schema_version(999).unwrap_err();
    assert!(matches!(err, StorageError::SchemaVersionMismatch { .. }));
}

#[test]
fn enrichment_frankensqlite_migrate_up() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
    assert_eq!(receipt.backend, "frankensqlite");
    assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
    assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION + 1);
}

#[test]
fn enrichment_frankensqlite_migrate_downgrade_rejected() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
    let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION).unwrap_err();
    assert!(matches!(err, StorageError::MigrationFailed { .. }));
}

#[test]
fn enrichment_frankensqlite_migrate_skip_rejected() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 5).unwrap_err();
    assert!(matches!(err, StorageError::MigrationFailed { .. }));
}

#[test]
fn enrichment_frankensqlite_events_recorded() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    assert!(adapter.events().is_empty());
    adapter
        .put(
            StoreKind::ReplayIndex,
            "k".to_string(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        )
        .unwrap();
    assert_eq!(adapter.events().len(), 1);
    assert_eq!(adapter.events()[0].outcome, "ok");
}

// ── Failing backend ─────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct FailingBackend {
    fail_wal: bool,
    fail_pragma: bool,
    fail_put: bool,
    fail_get: bool,
    fail_query: bool,
    fail_delete: bool,
    fail_batch: bool,
    fail_migrate: bool,
    inner: MockBackend,
}

impl FrankensqliteBackend for FailingBackend {
    fn apply_wal_profile(&mut self) -> Result<(), String> {
        if self.fail_wal {
            Err("wal failure".into())
        } else {
            self.inner.apply_wal_profile()
        }
    }
    fn set_pragma(&mut self, key: &str, value: &str) -> Result<(), String> {
        if self.fail_pragma {
            Err("pragma failure".into())
        } else {
            self.inner.set_pragma(key, value)
        }
    }
    fn current_schema_version(&self) -> Result<u32, String> {
        self.inner.current_schema_version()
    }
    fn migrate_to(&mut self, target_version: u32) -> Result<(), String> {
        if self.fail_migrate {
            Err("migration failure".into())
        } else {
            self.inner.migrate_to(target_version)
        }
    }
    fn put_record(
        &mut self,
        store: StoreKind,
        key: &str,
        value: &[u8],
        metadata: &BTreeMap<String, String>,
    ) -> Result<StoreRecord, String> {
        if self.fail_put {
            Err("put failure".into())
        } else {
            self.inner.put_record(store, key, value, metadata)
        }
    }
    fn get_record(&self, store: StoreKind, key: &str) -> Result<Option<StoreRecord>, String> {
        if self.fail_get {
            Err("get failure".into())
        } else {
            self.inner.get_record(store, key)
        }
    }
    fn query_records(
        &self,
        store: StoreKind,
        query: &StoreQuery,
    ) -> Result<Vec<StoreRecord>, String> {
        if self.fail_query {
            Err("query failure".into())
        } else {
            self.inner.query_records(store, query)
        }
    }
    fn delete_record(&mut self, store: StoreKind, key: &str) -> Result<bool, String> {
        if self.fail_delete {
            Err("delete failure".into())
        } else {
            self.inner.delete_record(store, key)
        }
    }
    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: &[BatchPutEntry],
    ) -> Result<Vec<StoreRecord>, String> {
        if self.fail_batch {
            Err("batch failure".into())
        } else {
            self.inner.put_batch(store, entries)
        }
    }
}

#[test]
fn enrichment_failing_backend_wal_failure() {
    let backend = FailingBackend {
        fail_wal: true,
        ..Default::default()
    };
    let err = FrankensqliteStorageAdapter::new(backend).unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

#[test]
fn enrichment_failing_backend_pragma_failure() {
    let backend = FailingBackend {
        fail_pragma: true,
        ..Default::default()
    };
    let err = FrankensqliteStorageAdapter::new(backend).unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

#[test]
fn enrichment_failing_backend_put_error_event() {
    let backend = FailingBackend {
        fail_put: true,
        ..Default::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let _ = adapter.put(
        StoreKind::ReplayIndex,
        "k".to_string(),
        vec![1],
        BTreeMap::new(),
        &ctx(),
    );
    let event = adapter.events().last().unwrap();
    assert_eq!(event.outcome, "error");
    assert!(event.error_code.is_some());
}

#[test]
fn enrichment_failing_backend_get_failure() {
    let backend = FailingBackend {
        fail_get: true,
        ..Default::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter
        .get(StoreKind::ReplayIndex, "k", &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

#[test]
fn enrichment_failing_backend_query_failure() {
    let backend = FailingBackend {
        fail_query: true,
        ..Default::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

#[test]
fn enrichment_failing_backend_delete_failure() {
    let backend = FailingBackend {
        fail_delete: true,
        ..Default::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter
        .delete(StoreKind::ReplayIndex, "k", &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

#[test]
fn enrichment_failing_backend_batch_failure() {
    let backend = FailingBackend {
        fail_batch: true,
        ..Default::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let entries = vec![BatchPutEntry {
        key: "k".to_string(),
        value: vec![1],
        metadata: BTreeMap::new(),
    }];
    let err = adapter
        .put_batch(StoreKind::ReplayIndex, entries, &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

#[test]
fn enrichment_failing_backend_migrate_failure() {
    let backend = FailingBackend {
        fail_migrate: true,
        ..Default::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

// ── JSON field-name stability ───────────────────────────────────────────

#[test]
fn enrichment_json_fields_store_kind() {
    let kind = StoreKind::ReplayIndex;
    let json = serde_json::to_string(&kind).unwrap();
    assert!(json.contains("ReplayIndex"));
}

#[test]
fn enrichment_json_fields_store_record() {
    let record = StoreRecord {
        store: StoreKind::PolicyCache,
        key: "test".to_string(),
        value: vec![1],
        metadata: BTreeMap::new(),
        revision: 1,
    };
    let json = serde_json::to_string(&record).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("store").is_some());
    assert!(v.get("key").is_some());
    assert!(v.get("value").is_some());
    assert!(v.get("metadata").is_some());
    assert!(v.get("revision").is_some());
}

#[test]
fn enrichment_json_fields_store_query() {
    let mut filters = BTreeMap::new();
    filters.insert("env".to_string(), "prod".to_string());
    let query = StoreQuery {
        key_prefix: Some("run/".to_string()),
        metadata_filters: filters,
        limit: Some(10),
    };
    let json = serde_json::to_string(&query).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("key_prefix").is_some());
    assert!(v.get("metadata_filters").is_some());
    assert!(v.get("limit").is_some());
}

#[test]
fn enrichment_json_fields_batch_put_entry() {
    let entry = BatchPutEntry {
        key: "k".to_string(),
        value: vec![1],
        metadata: BTreeMap::new(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("key").is_some());
    assert!(v.get("value").is_some());
    assert!(v.get("metadata").is_some());
}

#[test]
fn enrichment_json_fields_migration_receipt() {
    let receipt = MigrationReceipt {
        backend: "test".to_string(),
        from_version: 1,
        to_version: 2,
        stores_touched: vec![],
        records_touched: 0,
        state_hash_before: "aa".to_string(),
        state_hash_after: "bb".to_string(),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("backend").is_some());
    assert!(v.get("from_version").is_some());
    assert!(v.get("to_version").is_some());
    assert!(v.get("stores_touched").is_some());
    assert!(v.get("records_touched").is_some());
    assert!(v.get("state_hash_before").is_some());
    assert!(v.get("state_hash_after").is_some());
}

#[test]
fn enrichment_json_fields_storage_event() {
    let event = StorageEvent {
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "put".to_string(),
        outcome: "ok".to_string(),
        error_code: Some("FE-STOR-0001".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("trace_id").is_some());
    assert!(v.get("decision_id").is_some());
    assert!(v.get("policy_id").is_some());
    assert!(v.get("component").is_some());
    assert!(v.get("event").is_some());
    assert!(v.get("outcome").is_some());
    assert!(v.get("error_code").is_some());
}

#[test]
fn enrichment_json_fields_storage_error() {
    let err = StorageError::NotFound {
        store: StoreKind::ReplayIndex,
        key: "k".to_string(),
    };
    let json = serde_json::to_string(&err).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert!(v.get("NotFound").is_some());
}

// ── Multi-store batch and query orchestration ───────────────────────────

#[test]
fn enrichment_multi_store_batch_fill_and_query_all() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    let stores = [
        StoreKind::ReplayIndex,
        StoreKind::EvidenceIndex,
        StoreKind::BenchmarkLedger,
        StoreKind::PolicyCache,
    ];
    for (i, store) in stores.iter().enumerate() {
        let entries: Vec<BatchPutEntry> = (0..3)
            .map(|j| BatchPutEntry {
                key: format!("key/{j}"),
                value: vec![(i * 10 + j) as u8],
                metadata: BTreeMap::new(),
            })
            .collect();
        adapter.put_batch(*store, entries, &context).unwrap();
    }
    for store in &stores {
        let rows = adapter
            .query(*store, &StoreQuery::default(), &context)
            .unwrap();
        assert_eq!(rows.len(), 3, "Store {:?} should have 3 records", store);
    }
    // Stores not touched should be empty
    let rows = adapter
        .query(StoreKind::PlasWitness, &StoreQuery::default(), &context)
        .unwrap();
    assert!(rows.is_empty());
}

#[test]
fn enrichment_put_with_rich_metadata() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    let mut meta = BTreeMap::new();
    meta.insert("env".to_string(), "prod".to_string());
    meta.insert("region".to_string(), "us-east".to_string());
    meta.insert("version".to_string(), "v2".to_string());
    let record = adapter
        .put(
            StoreKind::IfcProvenance,
            "prov/001".to_string(),
            vec![42],
            meta.clone(),
            &context,
        )
        .unwrap();
    assert_eq!(record.metadata.len(), 3);
    assert_eq!(record.metadata.get("region"), Some(&"us-east".to_string()));
    let got = adapter
        .get(StoreKind::IfcProvenance, "prov/001", &context)
        .unwrap()
        .unwrap();
    assert_eq!(got.metadata, meta);
}

#[test]
fn enrichment_migration_receipt_deterministic_hash() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "x".to_string(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
    assert_ne!(receipt.state_hash_before, receipt.state_hash_after);
    assert!(!receipt.state_hash_before.is_empty());
    assert!(!receipt.state_hash_after.is_empty());
}
