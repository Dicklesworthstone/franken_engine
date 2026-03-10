#![forbid(unsafe_code)]
//! Integration tests for the `storage_adapter` module.
//!
//! These tests exercise the public API from outside the crate, covering:
//! - StoreKind enum variant exhaustiveness, Display, serde round-trips
//! - EventContext construction and validation
//! - StoreRecord, StoreQuery, BatchPutEntry, MigrationReceipt, StorageEvent structs
//! - StorageError variant coverage, Display formatting, error codes
//! - InMemoryStorageAdapter CRUD operations (put, get, delete, query, put_batch)
//! - FrankensqliteStorageAdapter via mock backend
//! - Migration paths (upgrade, downgrade rejection, skip rejection)
//! - Failure injection via with_fail_writes
//! - Event recording and structured field validation
//! - Determinism: same inputs produce same outputs
//! - Cross-concern integration scenarios

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

use std::collections::BTreeMap;

use frankenengine_engine::storage_adapter::{
    BatchPutEntry, EventContext, FrankensqliteBackend, FrankensqliteStorageAdapter,
    InMemoryStorageAdapter, MigrationReceipt, STORAGE_SCHEMA_VERSION, StorageAdapter, StorageError,
    StorageEvent, StoreKind, StoreQuery, StoreRecord,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ctx() -> EventContext {
    EventContext::new("trace-int", "decision-int", "policy-int").expect("valid test context")
}

fn ctx_custom(trace: &str, decision: &str, policy: &str) -> EventContext {
    EventContext::new(trace, decision, policy).expect("valid custom context")
}

fn make_meta(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

// ---------------------------------------------------------------------------
// Mock FrankensqliteBackend for integration tests
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct StoreState {
    next_revision: u64,
    records: BTreeMap<String, StoreRecord>,
}

impl StoreState {
    fn put(
        &mut self,
        store: StoreKind,
        key: String,
        value: Vec<u8>,
        metadata: BTreeMap<String, String>,
    ) -> StoreRecord {
        self.next_revision = self.next_revision.saturating_add(1);
        let record = StoreRecord {
            store,
            key: key.clone(),
            value,
            metadata,
            revision: self.next_revision,
        };
        self.records.insert(key, record.clone());
        record
    }
}

#[derive(Debug, Default)]
struct MockBackend {
    wal_applied: bool,
    pragmas: BTreeMap<String, String>,
    schema_version: u32,
    stores: BTreeMap<StoreKind, StoreState>,
    fail_wal: bool,
    fail_pragma: bool,
    fail_schema_version: bool,
    fail_migrate: bool,
    fail_put: bool,
    fail_get: bool,
    fail_query: bool,
    fail_delete: bool,
    fail_batch: bool,
}

impl FrankensqliteBackend for MockBackend {
    fn apply_wal_profile(&mut self) -> Result<(), String> {
        if self.fail_wal {
            return Err("wal failure".into());
        }
        self.wal_applied = true;
        Ok(())
    }

    fn set_pragma(&mut self, key: &str, value: &str) -> Result<(), String> {
        if self.fail_pragma {
            return Err("pragma failure".into());
        }
        self.pragmas.insert(key.to_string(), value.to_string());
        Ok(())
    }

    fn current_schema_version(&self) -> Result<u32, String> {
        if self.fail_schema_version {
            return Err("schema version failure".into());
        }
        Ok(self.schema_version.max(STORAGE_SCHEMA_VERSION))
    }

    fn migrate_to(&mut self, target_version: u32) -> Result<(), String> {
        if self.fail_migrate {
            return Err("migration failure".into());
        }
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
        if self.fail_put {
            return Err("put failure".into());
        }
        let state = self.stores.entry(store).or_default();
        Ok(state.put(store, key.to_string(), value.to_vec(), metadata.clone()))
    }

    fn get_record(&self, store: StoreKind, key: &str) -> Result<Option<StoreRecord>, String> {
        if self.fail_get {
            return Err("get failure".into());
        }
        Ok(self
            .stores
            .get(&store)
            .and_then(|state| state.records.get(key).cloned()))
    }

    fn query_records(
        &self,
        store: StoreKind,
        query: &StoreQuery,
    ) -> Result<Vec<StoreRecord>, String> {
        if self.fail_query {
            return Err("query failure".into());
        }
        let mut out = Vec::new();
        if let Some(state) = self.stores.get(&store) {
            for record in state.records.values() {
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
        if self.fail_delete {
            return Err("delete failure".into());
        }
        Ok(self
            .stores
            .get_mut(&store)
            .and_then(|state| state.records.remove(key))
            .is_some())
    }

    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: &[BatchPutEntry],
    ) -> Result<Vec<StoreRecord>, String> {
        if self.fail_batch {
            return Err("batch failure".into());
        }
        let mut staged = self.stores.remove(&store).unwrap_or_default();
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            out.push(staged.put(
                store,
                entry.key.clone(),
                entry.value.clone(),
                entry.metadata.clone(),
            ));
        }
        self.stores.insert(store, staged);
        Ok(out)
    }
}

// ===========================================================================
// 1. StoreKind enum — variants, Display, serde round-trip
// ===========================================================================

const ALL_STORE_KINDS: [StoreKind; 8] = [
    StoreKind::ReplayIndex,
    StoreKind::EvidenceIndex,
    StoreKind::BenchmarkLedger,
    StoreKind::PolicyCache,
    StoreKind::PlasWitness,
    StoreKind::ReplacementLineage,
    StoreKind::IfcProvenance,
    StoreKind::SpecializationIndex,
];

#[test]
fn store_kind_as_str_exhaustive() {
    let expected = [
        (StoreKind::ReplayIndex, "replay_index"),
        (StoreKind::EvidenceIndex, "evidence_index"),
        (StoreKind::BenchmarkLedger, "benchmark_ledger"),
        (StoreKind::PolicyCache, "policy_cache"),
        (StoreKind::PlasWitness, "plas_witness"),
        (StoreKind::ReplacementLineage, "replacement_lineage"),
        (StoreKind::IfcProvenance, "ifc_provenance"),
        (StoreKind::SpecializationIndex, "specialization_index"),
    ];
    for (kind, label) in expected {
        assert_eq!(kind.as_str(), label, "StoreKind::{kind:?}");
    }
}

#[test]
fn store_kind_integration_point_exhaustive() {
    let expected = [
        (
            StoreKind::ReplayIndex,
            "frankensqlite::control_plane::replay_index",
        ),
        (
            StoreKind::EvidenceIndex,
            "frankensqlite::control_plane::evidence_index",
        ),
        (
            StoreKind::BenchmarkLedger,
            "frankensqlite::benchmark::ledger",
        ),
        (
            StoreKind::PolicyCache,
            "frankensqlite::control_plane::policy_cache",
        ),
        (
            StoreKind::PlasWitness,
            "frankensqlite::analysis::plas_witness",
        ),
        (
            StoreKind::ReplacementLineage,
            "frankensqlite::replacement::lineage_log",
        ),
        (
            StoreKind::IfcProvenance,
            "frankensqlite::control_plane::ifc_provenance",
        ),
        (
            StoreKind::SpecializationIndex,
            "frankensqlite::control_plane::specialization_index",
        ),
    ];
    for (kind, point) in expected {
        assert_eq!(kind.integration_point(), point, "StoreKind::{kind:?}");
    }
}

#[test]
fn store_kind_display_matches_as_str() {
    for kind in ALL_STORE_KINDS {
        assert_eq!(format!("{kind}"), kind.as_str());
    }
}

#[test]
fn store_kind_serde_round_trip_all_variants() {
    for kind in ALL_STORE_KINDS {
        let json = serde_json::to_string(&kind).unwrap();
        let back: StoreKind = serde_json::from_str(&json).unwrap();
        assert_eq!(back, kind, "StoreKind::{kind:?} serde round-trip failed");
    }
}

#[test]
fn store_kind_ordering_is_deterministic() {
    let mut kinds = ALL_STORE_KINDS.to_vec();
    kinds.sort();
    let mut again = ALL_STORE_KINDS.to_vec();
    again.sort();
    assert_eq!(kinds, again);
}

#[test]
fn store_kind_as_str_values_are_unique() {
    let labels: std::collections::BTreeSet<&str> =
        ALL_STORE_KINDS.iter().map(|k| k.as_str()).collect();
    assert_eq!(labels.len(), ALL_STORE_KINDS.len());
}

#[test]
fn store_kind_integration_points_are_unique() {
    let points: std::collections::BTreeSet<&str> = ALL_STORE_KINDS
        .iter()
        .map(|k| k.integration_point())
        .collect();
    assert_eq!(points.len(), ALL_STORE_KINDS.len());
}

// ===========================================================================
// 2. EventContext — construction and validation
// ===========================================================================

#[test]
fn event_context_valid_construction() {
    let ctx = EventContext::new("trace-1", "decision-1", "policy-1").unwrap();
    assert_eq!(ctx.trace_id, "trace-1");
    assert_eq!(ctx.decision_id, "decision-1");
    assert_eq!(ctx.policy_id, "policy-1");
}

#[test]
fn event_context_rejects_empty_trace_id() {
    let err = EventContext::new("", "d", "p").unwrap_err();
    assert!(matches!(err, StorageError::InvalidContext { ref field } if field == "trace_id"));
    assert_eq!(err.code(), "FE-STOR-0001");
}

#[test]
fn event_context_rejects_whitespace_trace_id() {
    let err = EventContext::new("   ", "d", "p").unwrap_err();
    assert!(matches!(err, StorageError::InvalidContext { ref field } if field == "trace_id"));
}

#[test]
fn event_context_rejects_empty_decision_id() {
    let err = EventContext::new("t", "", "p").unwrap_err();
    assert!(matches!(err, StorageError::InvalidContext { ref field } if field == "decision_id"));
}

#[test]
fn event_context_rejects_whitespace_decision_id() {
    let err = EventContext::new("t", "  \t ", "p").unwrap_err();
    assert!(matches!(err, StorageError::InvalidContext { ref field } if field == "decision_id"));
}

#[test]
fn event_context_rejects_empty_policy_id() {
    let err = EventContext::new("t", "d", "").unwrap_err();
    assert!(matches!(err, StorageError::InvalidContext { ref field } if field == "policy_id"));
}

#[test]
fn event_context_rejects_whitespace_policy_id() {
    let err = EventContext::new("t", "d", " \n ").unwrap_err();
    assert!(matches!(err, StorageError::InvalidContext { ref field } if field == "policy_id"));
}

#[test]
fn event_context_serde_round_trip() {
    let ctx = EventContext::new("t", "d", "p").unwrap();
    let json = serde_json::to_string(&ctx).unwrap();
    let back: EventContext = serde_json::from_str(&json).unwrap();
    assert_eq!(back, ctx);
}

// ===========================================================================
// 3. StorageError — all variants, codes, Display, serde
// ===========================================================================

#[test]
fn storage_error_codes_exhaustive() {
    let cases: Vec<(StorageError, &str)> = vec![
        (
            StorageError::InvalidContext {
                field: "trace_id".into(),
            },
            "FE-STOR-0001",
        ),
        (
            StorageError::InvalidKey {
                key: "bad_key".into(),
            },
            "FE-STOR-0002",
        ),
        (
            StorageError::InvalidQuery {
                detail: "zero limit".into(),
            },
            "FE-STOR-0003",
        ),
        (
            StorageError::NotFound {
                store: StoreKind::PolicyCache,
                key: "k".into(),
            },
            "FE-STOR-0004",
        ),
        (
            StorageError::SchemaVersionMismatch {
                expected: 1,
                actual: 2,
            },
            "FE-STOR-0005",
        ),
        (
            StorageError::MigrationFailed {
                from: 1,
                to: 2,
                reason: "bad".into(),
            },
            "FE-STOR-0006",
        ),
        (
            StorageError::IntegrityViolation {
                store: StoreKind::ReplayIndex,
                detail: "corrupt".into(),
            },
            "FE-STOR-0007",
        ),
        (
            StorageError::BackendUnavailable {
                backend: "sqlite".into(),
                detail: "down".into(),
            },
            "FE-STOR-0008",
        ),
        (
            StorageError::WriteRejected {
                detail: "full".into(),
            },
            "FE-STOR-0009",
        ),
    ];
    for (err, expected_code) in cases {
        assert_eq!(
            err.code(),
            expected_code,
            "StorageError code mismatch for: {err}"
        );
    }
}

#[test]
fn storage_error_codes_are_unique() {
    let codes: Vec<&str> = vec![
        "FE-STOR-0001",
        "FE-STOR-0002",
        "FE-STOR-0003",
        "FE-STOR-0004",
        "FE-STOR-0005",
        "FE-STOR-0006",
        "FE-STOR-0007",
        "FE-STOR-0008",
        "FE-STOR-0009",
    ];
    let unique: std::collections::BTreeSet<&str> = codes.iter().copied().collect();
    assert_eq!(unique.len(), codes.len());
}

#[test]
fn storage_error_display_invalid_context() {
    let err = StorageError::InvalidContext {
        field: "trace_id".into(),
    };
    let display = err.to_string();
    assert!(display.contains("trace_id"), "Display: {display}");
    assert!(display.contains("invalid context"), "Display: {display}");
}

#[test]
fn storage_error_display_invalid_key() {
    let err = StorageError::InvalidKey {
        key: "bad_key".into(),
    };
    let display = err.to_string();
    assert!(display.contains("bad_key"), "Display: {display}");
    assert!(display.contains("invalid key"), "Display: {display}");
}

#[test]
fn storage_error_display_invalid_query() {
    let err = StorageError::InvalidQuery {
        detail: "limit cannot be zero".into(),
    };
    let display = err.to_string();
    assert!(
        display.contains("limit cannot be zero"),
        "Display: {display}"
    );
}

#[test]
fn storage_error_display_not_found() {
    let err = StorageError::NotFound {
        store: StoreKind::PolicyCache,
        key: "missing".into(),
    };
    let display = err.to_string();
    assert!(display.contains("missing"), "Display: {display}");
    assert!(display.contains("policy_cache"), "Display: {display}");
}

#[test]
fn storage_error_display_schema_version_mismatch() {
    let err = StorageError::SchemaVersionMismatch {
        expected: 1,
        actual: 3,
    };
    let display = err.to_string();
    assert!(display.contains("1"), "Display: {display}");
    assert!(display.contains("3"), "Display: {display}");
    assert!(display.contains("mismatch"), "Display: {display}");
}

#[test]
fn storage_error_display_migration_failed() {
    let err = StorageError::MigrationFailed {
        from: 1,
        to: 2,
        reason: "downgrade not allowed".into(),
    };
    let display = err.to_string();
    assert!(
        display.contains("downgrade not allowed"),
        "Display: {display}"
    );
}

#[test]
fn storage_error_display_integrity_violation() {
    let err = StorageError::IntegrityViolation {
        store: StoreKind::ReplayIndex,
        detail: "corrupt index".into(),
    };
    let display = err.to_string();
    assert!(display.contains("corrupt index"), "Display: {display}");
    assert!(display.contains("replay_index"), "Display: {display}");
}

#[test]
fn storage_error_display_backend_unavailable() {
    let err = StorageError::BackendUnavailable {
        backend: "frankensqlite".into(),
        detail: "connection refused".into(),
    };
    let display = err.to_string();
    assert!(display.contains("frankensqlite"), "Display: {display}");
    assert!(display.contains("connection refused"), "Display: {display}");
}

#[test]
fn storage_error_display_write_rejected() {
    let err = StorageError::WriteRejected {
        detail: "disk full".into(),
    };
    let display = err.to_string();
    assert!(display.contains("disk full"), "Display: {display}");
    assert!(display.contains("write rejected"), "Display: {display}");
}

#[test]
fn storage_error_is_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(StorageError::WriteRejected {
        detail: "test".into(),
    });
    let _display = format!("{err}");
}

#[test]
fn storage_error_serde_round_trip_all_variants() {
    let variants: Vec<StorageError> = vec![
        StorageError::InvalidContext { field: "f".into() },
        StorageError::InvalidKey { key: "k".into() },
        StorageError::InvalidQuery { detail: "d".into() },
        StorageError::NotFound {
            store: StoreKind::EvidenceIndex,
            key: "k".into(),
        },
        StorageError::SchemaVersionMismatch {
            expected: 1,
            actual: 2,
        },
        StorageError::MigrationFailed {
            from: 1,
            to: 2,
            reason: "r".into(),
        },
        StorageError::IntegrityViolation {
            store: StoreKind::PlasWitness,
            detail: "d".into(),
        },
        StorageError::BackendUnavailable {
            backend: "b".into(),
            detail: "d".into(),
        },
        StorageError::WriteRejected { detail: "d".into() },
    ];
    for variant in &variants {
        let json = serde_json::to_string(variant).unwrap();
        let back: StorageError = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, variant, "serde round-trip failed for: {variant}");
    }
}

// ===========================================================================
// 4. StoreRecord — construction, serde
// ===========================================================================

#[test]
fn store_record_construction_and_field_access() {
    let meta = make_meta(&[("env", "prod")]);
    let record = StoreRecord {
        store: StoreKind::BenchmarkLedger,
        key: "bench/alpha".into(),
        value: vec![1, 2, 3],
        metadata: meta.clone(),
        revision: 42,
    };
    assert_eq!(record.store, StoreKind::BenchmarkLedger);
    assert_eq!(record.key, "bench/alpha");
    assert_eq!(record.value, vec![1, 2, 3]);
    assert_eq!(record.metadata, meta);
    assert_eq!(record.revision, 42);
}

#[test]
fn store_record_serde_round_trip() {
    let record = StoreRecord {
        store: StoreKind::IfcProvenance,
        key: "prov/1".into(),
        value: vec![0xDE, 0xAD],
        metadata: make_meta(&[("source", "test")]),
        revision: 7,
    };
    let json = serde_json::to_string(&record).unwrap();
    let back: StoreRecord = serde_json::from_str(&json).unwrap();
    assert_eq!(back, record);
}

// ===========================================================================
// 5. StoreQuery — default, construction, serde
// ===========================================================================

#[test]
fn store_query_default_all_none() {
    let q = StoreQuery::default();
    assert!(q.key_prefix.is_none());
    assert!(q.metadata_filters.is_empty());
    assert!(q.limit.is_none());
}

#[test]
fn store_query_serde_round_trip() {
    let q = StoreQuery {
        key_prefix: Some("run/".into()),
        metadata_filters: make_meta(&[("env", "staging")]),
        limit: Some(10),
    };
    let json = serde_json::to_string(&q).unwrap();
    let back: StoreQuery = serde_json::from_str(&json).unwrap();
    assert_eq!(back, q);
}

// ===========================================================================
// 6. BatchPutEntry — construction, serde
// ===========================================================================

#[test]
fn batch_put_entry_serde_round_trip() {
    let entry = BatchPutEntry {
        key: "batch/k1".into(),
        value: vec![10, 20],
        metadata: make_meta(&[("origin", "batch")]),
    };
    let json = serde_json::to_string(&entry).unwrap();
    let back: BatchPutEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back, entry);
}

// ===========================================================================
// 7. MigrationReceipt — construction, serde
// ===========================================================================

#[test]
fn migration_receipt_serde_round_trip() {
    let receipt = MigrationReceipt {
        backend: "in_memory".into(),
        from_version: 1,
        to_version: 2,
        stores_touched: vec![StoreKind::ReplayIndex, StoreKind::EvidenceIndex],
        records_touched: 15,
        state_hash_before: "aabbccdd".into(),
        state_hash_after: "eeff0011".into(),
    };
    let json = serde_json::to_string(&receipt).unwrap();
    let back: MigrationReceipt = serde_json::from_str(&json).unwrap();
    assert_eq!(back, receipt);
}

// ===========================================================================
// 8. StorageEvent — construction, serde
// ===========================================================================

#[test]
fn storage_event_serde_round_trip() {
    let event = StorageEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "storage_adapter".into(),
        event: "put".into(),
        outcome: "ok".into(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StorageEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn storage_event_with_error_code_serde_round_trip() {
    let event = StorageEvent {
        trace_id: "t".into(),
        decision_id: "d".into(),
        policy_id: "p".into(),
        component: "storage_adapter".into(),
        event: "put".into(),
        outcome: "error".into(),
        error_code: Some("FE-STOR-0002".into()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: StorageEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

// ===========================================================================
// 9. STORAGE_SCHEMA_VERSION constant
// ===========================================================================

#[test]
fn storage_schema_version_is_positive() {
    // Runtime check so the value is exercised in test context.
    let version = STORAGE_SCHEMA_VERSION;
    assert!(version > 0);
}

// ===========================================================================
// 10. InMemoryStorageAdapter — construction, default, backend_name
// ===========================================================================

#[test]
fn in_memory_adapter_new_matches_default() {
    let a = InMemoryStorageAdapter::new();
    let b = InMemoryStorageAdapter::default();
    // Both should have same schema version and empty events
    assert_eq!(a.current_schema_version(), b.current_schema_version());
    assert_eq!(a.backend_name(), b.backend_name());
    assert!(a.events().is_empty());
    assert!(b.events().is_empty());
}

#[test]
fn in_memory_adapter_backend_name() {
    let adapter = InMemoryStorageAdapter::new();
    assert_eq!(adapter.backend_name(), "in_memory");
}

#[test]
fn in_memory_adapter_initial_schema_version() {
    let adapter = InMemoryStorageAdapter::new();
    assert_eq!(adapter.current_schema_version(), STORAGE_SCHEMA_VERSION);
}

// ===========================================================================
// 11. InMemoryStorageAdapter — put
// ===========================================================================

#[test]
fn in_memory_put_returns_record_with_key_value_metadata() {
    let mut adapter = InMemoryStorageAdapter::new();
    let meta = make_meta(&[("env", "prod")]);
    let record = adapter
        .put(
            StoreKind::ReplayIndex,
            "run/001".into(),
            vec![42],
            meta.clone(),
            &ctx(),
        )
        .unwrap();
    assert_eq!(record.store, StoreKind::ReplayIndex);
    assert_eq!(record.key, "run/001");
    assert_eq!(record.value, vec![42]);
    assert_eq!(record.metadata, meta);
    assert!(record.revision > 0);
}

#[test]
fn in_memory_put_increments_revision() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    let r1 = adapter
        .put(
            StoreKind::PolicyCache,
            "k1".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let r2 = adapter
        .put(
            StoreKind::PolicyCache,
            "k2".into(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    assert!(r2.revision > r1.revision);
}

#[test]
fn in_memory_put_overwrites_existing_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::PolicyCache,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let r2 = adapter
        .put(
            StoreKind::PolicyCache,
            "k".into(),
            vec![99],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    assert_eq!(r2.value, vec![99]);

    let got = adapter
        .get(StoreKind::PolicyCache, "k", &context)
        .unwrap()
        .unwrap();
    assert_eq!(got.value, vec![99]);
}

#[test]
fn in_memory_put_rejects_empty_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter
        .put(
            StoreKind::ReplayIndex,
            "".into(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        )
        .unwrap_err();
    assert!(matches!(err, StorageError::InvalidKey { .. }));
}

#[test]
fn in_memory_put_rejects_whitespace_only_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter
        .put(
            StoreKind::ReplayIndex,
            "   ".into(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        )
        .unwrap_err();
    assert!(matches!(err, StorageError::InvalidKey { .. }));
}

// ===========================================================================
// 12. InMemoryStorageAdapter — get
// ===========================================================================

#[test]
fn in_memory_get_existing_returns_some() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "ev/1".into(),
            vec![7],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let got = adapter
        .get(StoreKind::EvidenceIndex, "ev/1", &context)
        .unwrap();
    assert!(got.is_some());
    assert_eq!(got.unwrap().value, vec![7]);
}

#[test]
fn in_memory_get_nonexistent_returns_none() {
    let mut adapter = InMemoryStorageAdapter::new();
    let got = adapter
        .get(StoreKind::PolicyCache, "no-such-key", &ctx())
        .unwrap();
    assert!(got.is_none());
}

#[test]
fn in_memory_get_rejects_empty_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter.get(StoreKind::ReplayIndex, "", &ctx()).unwrap_err();
    assert!(matches!(err, StorageError::InvalidKey { .. }));
}

#[test]
fn in_memory_get_different_store_returns_none() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let got = adapter
        .get(StoreKind::EvidenceIndex, "k", &context)
        .unwrap();
    assert!(got.is_none());
}

// ===========================================================================
// 13. InMemoryStorageAdapter — delete
// ===========================================================================

#[test]
fn in_memory_delete_existing_returns_true() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::PolicyCache,
            "del-me".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let deleted = adapter
        .delete(StoreKind::PolicyCache, "del-me", &context)
        .unwrap();
    assert!(deleted);
}

#[test]
fn in_memory_delete_nonexistent_returns_false() {
    let mut adapter = InMemoryStorageAdapter::new();
    let deleted = adapter
        .delete(StoreKind::PolicyCache, "no-such-key", &ctx())
        .unwrap();
    assert!(!deleted);
}

#[test]
fn in_memory_delete_rejects_empty_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter
        .delete(StoreKind::ReplayIndex, "", &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::InvalidKey { .. }));
}

#[test]
fn in_memory_delete_then_get_returns_none() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .delete(StoreKind::ReplayIndex, "k", &context)
        .unwrap();
    let got = adapter.get(StoreKind::ReplayIndex, "k", &context).unwrap();
    assert!(got.is_none());
}

// ===========================================================================
// 14. InMemoryStorageAdapter — query
// ===========================================================================

#[test]
fn in_memory_query_empty_store_returns_empty() {
    let mut adapter = InMemoryStorageAdapter::new();
    let rows = adapter
        .query(StoreKind::PlasWitness, &StoreQuery::default(), &ctx())
        .unwrap();
    assert!(rows.is_empty());
}

#[test]
fn in_memory_query_returns_all_records_sorted_by_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::BenchmarkLedger,
            "z-key".into(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::BenchmarkLedger,
            "a-key".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let rows = adapter
        .query(StoreKind::BenchmarkLedger, &StoreQuery::default(), &context)
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].key, "a-key");
    assert_eq!(rows[1].key, "z-key");
}

#[test]
fn in_memory_query_with_key_prefix_filters() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "run/001".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "run/002".into(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "other/x".into(),
            vec![3],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let query = StoreQuery {
        key_prefix: Some("run/".into()),
        ..Default::default()
    };
    let rows = adapter
        .query(StoreKind::ReplayIndex, &query, &context)
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.key.starts_with("run/")));
}

#[test]
fn in_memory_query_with_metadata_filter() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "a".into(),
            vec![1],
            make_meta(&[("env", "prod")]),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "b".into(),
            vec![2],
            make_meta(&[("env", "staging")]),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "c".into(),
            vec![3],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let query = StoreQuery {
        metadata_filters: make_meta(&[("env", "prod")]),
        ..Default::default()
    };
    let rows = adapter
        .query(StoreKind::EvidenceIndex, &query, &context)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key, "a");
}

#[test]
fn in_memory_query_with_limit() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    for i in 0..10u8 {
        adapter
            .put(
                StoreKind::ReplayIndex,
                format!("k/{i:03}"),
                vec![i],
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
fn in_memory_query_limit_zero_is_error() {
    let mut adapter = InMemoryStorageAdapter::new();
    let query = StoreQuery {
        limit: Some(0),
        ..Default::default()
    };
    let err = adapter
        .query(StoreKind::ReplayIndex, &query, &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::InvalidQuery { .. }));
}

#[test]
fn in_memory_query_combined_prefix_and_metadata() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "run/1".into(),
            vec![1],
            make_meta(&[("status", "pass")]),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "run/2".into(),
            vec![2],
            make_meta(&[("status", "fail")]),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "other/3".into(),
            vec![3],
            make_meta(&[("status", "pass")]),
            &context,
        )
        .unwrap();

    let query = StoreQuery {
        key_prefix: Some("run/".into()),
        metadata_filters: make_meta(&[("status", "pass")]),
        ..Default::default()
    };
    let rows = adapter
        .query(StoreKind::ReplayIndex, &query, &context)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key, "run/1");
}

// ===========================================================================
// 15. InMemoryStorageAdapter — put_batch
// ===========================================================================

#[test]
fn in_memory_put_batch_success() {
    let mut adapter = InMemoryStorageAdapter::new();
    let entries = vec![
        BatchPutEntry {
            key: "b/1".into(),
            value: vec![10],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "b/2".into(),
            value: vec![20],
            metadata: BTreeMap::new(),
        },
    ];
    let records = adapter
        .put_batch(StoreKind::BenchmarkLedger, entries, &ctx())
        .unwrap();
    assert_eq!(records.len(), 2);
    assert!(records[0].revision < records[1].revision);
}

#[test]
fn in_memory_put_batch_atomic_on_invalid_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    // Seed one record first
    adapter
        .put(
            StoreKind::ReplayIndex,
            "seed".into(),
            vec![0],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let entries = vec![
        BatchPutEntry {
            key: "ok/1".into(),
            value: vec![1],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "   ".into(), // invalid
            value: vec![2],
            metadata: BTreeMap::new(),
        },
    ];
    let err = adapter
        .put_batch(StoreKind::ReplayIndex, entries, &context)
        .unwrap_err();
    assert!(matches!(err, StorageError::InvalidKey { .. }));

    // Seed record should still be there, batch entries should not
    let rows = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key, "seed");
}

#[test]
fn in_memory_put_batch_empty_entries_succeeds() {
    let mut adapter = InMemoryStorageAdapter::new();
    let records = adapter
        .put_batch(StoreKind::ReplayIndex, vec![], &ctx())
        .unwrap();
    assert!(records.is_empty());
}

// ===========================================================================
// 16. InMemoryStorageAdapter — ensure_schema_version
// ===========================================================================

#[test]
fn in_memory_ensure_schema_version_match() {
    let adapter = InMemoryStorageAdapter::new();
    assert!(
        adapter
            .ensure_schema_version(STORAGE_SCHEMA_VERSION)
            .is_ok()
    );
}

#[test]
fn in_memory_ensure_schema_version_mismatch() {
    let adapter = InMemoryStorageAdapter::new();
    let err = adapter.ensure_schema_version(999).unwrap_err();
    assert!(
        matches!(err, StorageError::SchemaVersionMismatch { expected: 999, actual }
            if actual == STORAGE_SCHEMA_VERSION)
    );
}

// ===========================================================================
// 17. InMemoryStorageAdapter — migration
// ===========================================================================

#[test]
fn in_memory_migrate_single_step_succeeds() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "d/1".into(),
            vec![7],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
    assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
    assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION + 1);
    assert_eq!(receipt.backend, "in_memory");
    assert_eq!(receipt.records_touched, 1);
    assert_ne!(receipt.state_hash_before, receipt.state_hash_after);
}

#[test]
fn in_memory_migrate_same_version_succeeds() {
    let mut adapter = InMemoryStorageAdapter::new();
    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION).unwrap();
    assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
    assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION);
}

#[test]
fn in_memory_migrate_downgrade_rejected() {
    let mut adapter = InMemoryStorageAdapter::new();
    adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
    let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION).unwrap_err();
    assert!(matches!(err, StorageError::MigrationFailed { .. }));
    assert!(err.to_string().contains("downgrade"));
}

#[test]
fn in_memory_migrate_skip_version_rejected() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 5).unwrap_err();
    assert!(matches!(err, StorageError::MigrationFailed { .. }));
    assert!(err.to_string().contains("single-step"));
}

#[test]
fn in_memory_migrate_receipt_stores_touched() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "r".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "e".into(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
    assert_eq!(receipt.stores_touched.len(), 2);
    assert_eq!(receipt.records_touched, 2);
}

// ===========================================================================
// 18. InMemoryStorageAdapter — with_fail_writes
// ===========================================================================

#[test]
fn in_memory_fail_writes_rejects_put() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let err = adapter
        .put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        )
        .unwrap_err();
    assert!(matches!(err, StorageError::WriteRejected { .. }));
}

#[test]
fn in_memory_fail_writes_rejects_delete() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let err = adapter
        .delete(StoreKind::ReplayIndex, "k", &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::WriteRejected { .. }));
}

#[test]
fn in_memory_fail_writes_rejects_batch() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let entries = vec![BatchPutEntry {
        key: "k".into(),
        value: vec![1],
        metadata: BTreeMap::new(),
    }];
    let err = adapter
        .put_batch(StoreKind::ReplayIndex, entries, &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::WriteRejected { .. }));
}

#[test]
fn in_memory_fail_writes_allows_reads() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let context = ctx();
    // get should succeed (not a write)
    let got = adapter.get(StoreKind::ReplayIndex, "k", &context).unwrap();
    assert!(got.is_none());
    // query should succeed
    let rows = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
        .unwrap();
    assert!(rows.is_empty());
}

// ===========================================================================
// 19. InMemoryStorageAdapter — event recording
// ===========================================================================

#[test]
fn in_memory_events_record_put_success() {
    let mut adapter = InMemoryStorageAdapter::new();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        )
        .unwrap();
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "put");
    assert_eq!(events[0].outcome, "ok");
    assert!(events[0].error_code.is_none());
}

#[test]
fn in_memory_events_record_put_failure() {
    let mut adapter = InMemoryStorageAdapter::new();
    let _ = adapter.put(
        StoreKind::ReplayIndex,
        "".into(),
        vec![1],
        BTreeMap::new(),
        &ctx(),
    );
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "put");
    assert_eq!(events[0].outcome, "error");
    assert_eq!(events[0].error_code.as_deref(), Some("FE-STOR-0002"));
}

#[test]
fn in_memory_events_record_get() {
    let mut adapter = InMemoryStorageAdapter::new();
    adapter.get(StoreKind::ReplayIndex, "k", &ctx()).unwrap();
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "get");
    assert_eq!(events[0].outcome, "ok");
}

#[test]
fn in_memory_events_record_query() {
    let mut adapter = InMemoryStorageAdapter::new();
    adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &ctx())
        .unwrap();
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "query");
    assert_eq!(events[0].outcome, "ok");
}

#[test]
fn in_memory_events_record_delete() {
    let mut adapter = InMemoryStorageAdapter::new();
    adapter.delete(StoreKind::ReplayIndex, "k", &ctx()).unwrap();
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "delete");
    assert_eq!(events[0].outcome, "ok");
}

#[test]
fn in_memory_events_record_put_batch() {
    let mut adapter = InMemoryStorageAdapter::new();
    adapter
        .put_batch(StoreKind::ReplayIndex, vec![], &ctx())
        .unwrap();
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "put_batch");
    assert_eq!(events[0].outcome, "ok");
}

#[test]
fn in_memory_events_carry_correct_context_fields() {
    let context = ctx_custom("trace-abc", "decision-xyz", "policy-123");
    let mut adapter = InMemoryStorageAdapter::new();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    let event = &adapter.events()[0];
    assert_eq!(event.trace_id, "trace-abc");
    assert_eq!(event.decision_id, "decision-xyz");
    assert_eq!(event.policy_id, "policy-123");
    assert_eq!(event.component, "storage_adapter");
}

// ===========================================================================
// 20. InMemoryStorageAdapter — serde round-trip of adapter state
// ===========================================================================

#[test]
fn in_memory_adapter_serde_round_trip() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
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
    assert_eq!(back.backend_name(), adapter.backend_name());
}

// ===========================================================================
// 21. FrankensqliteStorageAdapter — initialization
// ===========================================================================

#[test]
fn frankensqlite_adapter_initializes_successfully() {
    let backend = MockBackend::default();
    let adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    assert_eq!(adapter.backend_name(), "frankensqlite");
    assert_eq!(adapter.current_schema_version(), STORAGE_SCHEMA_VERSION);
}

#[test]
fn frankensqlite_adapter_wal_failure() {
    let backend = MockBackend {
        fail_wal: true,
        ..Default::default()
    };
    let err = FrankensqliteStorageAdapter::new(backend).unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

#[test]
fn frankensqlite_adapter_pragma_failure() {
    let backend = MockBackend {
        fail_pragma: true,
        ..Default::default()
    };
    let err = FrankensqliteStorageAdapter::new(backend).unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

#[test]
fn frankensqlite_adapter_schema_version_failure() {
    let backend = MockBackend {
        fail_schema_version: true,
        ..Default::default()
    };
    let err = FrankensqliteStorageAdapter::new(backend).unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

// ===========================================================================
// 22. FrankensqliteStorageAdapter — CRUD operations
// ===========================================================================

#[test]
fn frankensqlite_put_get_delete_cycle() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let context = ctx();

    let record = adapter
        .put(
            StoreKind::EvidenceIndex,
            "ev/1".into(),
            vec![42],
            make_meta(&[("src", "test")]),
            &context,
        )
        .unwrap();
    assert_eq!(record.key, "ev/1");
    assert_eq!(record.value, vec![42]);

    let got = adapter
        .get(StoreKind::EvidenceIndex, "ev/1", &context)
        .unwrap()
        .unwrap();
    assert_eq!(got.value, vec![42]);

    let deleted = adapter
        .delete(StoreKind::EvidenceIndex, "ev/1", &context)
        .unwrap();
    assert!(deleted);

    let gone = adapter
        .get(StoreKind::EvidenceIndex, "ev/1", &context)
        .unwrap();
    assert!(gone.is_none());
}

#[test]
fn frankensqlite_query_canonicalizes_output() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let context = ctx();

    adapter
        .put(
            StoreKind::ReplayIndex,
            "z/key".into(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "a/key".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let rows = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
        .unwrap();
    assert_eq!(rows.len(), 2);
    // Results must be canonicalized (sorted by key)
    assert_eq!(rows[0].key, "a/key");
    assert_eq!(rows[1].key, "z/key");
}

#[test]
fn frankensqlite_query_with_limit() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let context = ctx();

    for i in 0..5u8 {
        adapter
            .put(
                StoreKind::ReplayIndex,
                format!("k/{i:03}"),
                vec![i],
                BTreeMap::new(),
                &context,
            )
            .unwrap();
    }

    let query = StoreQuery {
        limit: Some(2),
        ..Default::default()
    };
    let rows = adapter
        .query(StoreKind::ReplayIndex, &query, &context)
        .unwrap();
    assert_eq!(rows.len(), 2);
}

#[test]
fn frankensqlite_query_limit_zero_rejected() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let query = StoreQuery {
        limit: Some(0),
        ..Default::default()
    };
    let err = adapter
        .query(StoreKind::ReplayIndex, &query, &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::InvalidQuery { .. }));
}

#[test]
fn frankensqlite_put_rejects_empty_key() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter
        .put(
            StoreKind::ReplayIndex,
            "".into(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        )
        .unwrap_err();
    assert!(matches!(err, StorageError::InvalidKey { .. }));
}

#[test]
fn frankensqlite_get_rejects_empty_key() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter
        .get(StoreKind::ReplayIndex, " ", &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::InvalidKey { .. }));
}

#[test]
fn frankensqlite_delete_rejects_empty_key() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter
        .delete(StoreKind::ReplayIndex, "  ", &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::InvalidKey { .. }));
}

// ===========================================================================
// 23. FrankensqliteStorageAdapter — put_batch
// ===========================================================================

#[test]
fn frankensqlite_batch_put_success() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let entries = vec![
        BatchPutEntry {
            key: "a".into(),
            value: vec![1],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "b".into(),
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
fn frankensqlite_batch_put_invalid_key_fails() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let entries = vec![
        BatchPutEntry {
            key: "ok".into(),
            value: vec![1],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "".into(),
            value: vec![2],
            metadata: BTreeMap::new(),
        },
    ];
    let err = adapter
        .put_batch(StoreKind::ReplayIndex, entries, &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::InvalidKey { .. }));
}

// ===========================================================================
// 24. FrankensqliteStorageAdapter — backend failure paths
// ===========================================================================

#[test]
fn frankensqlite_put_backend_failure() {
    let backend = MockBackend {
        fail_put: true,
        ..Default::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter
        .put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        )
        .unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

#[test]
fn frankensqlite_get_backend_failure() {
    let backend = MockBackend {
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
fn frankensqlite_query_backend_failure() {
    let backend = MockBackend {
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
fn frankensqlite_delete_backend_failure() {
    let backend = MockBackend {
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
fn frankensqlite_batch_backend_failure() {
    let backend = MockBackend {
        fail_batch: true,
        ..Default::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let entries = vec![BatchPutEntry {
        key: "k".into(),
        value: vec![1],
        metadata: BTreeMap::new(),
    }];
    let err = adapter
        .put_batch(StoreKind::ReplayIndex, entries, &ctx())
        .unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

// ===========================================================================
// 25. FrankensqliteStorageAdapter — schema version and migration
// ===========================================================================

#[test]
fn frankensqlite_ensure_schema_version_match() {
    let backend = MockBackend::default();
    let adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    assert!(
        adapter
            .ensure_schema_version(STORAGE_SCHEMA_VERSION)
            .is_ok()
    );
}

#[test]
fn frankensqlite_ensure_schema_version_mismatch() {
    let backend = MockBackend::default();
    let adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter.ensure_schema_version(999).unwrap_err();
    assert!(matches!(err, StorageError::SchemaVersionMismatch { .. }));
}

#[test]
fn frankensqlite_migrate_single_step() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
    assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
    assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION + 1);
    assert_eq!(receipt.backend, "frankensqlite");
    assert_ne!(receipt.state_hash_before, receipt.state_hash_after);
}

#[test]
fn frankensqlite_migrate_downgrade_rejected() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
    let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION).unwrap_err();
    assert!(matches!(err, StorageError::MigrationFailed { .. }));
    assert!(err.to_string().contains("downgrade"));
}

#[test]
fn frankensqlite_migrate_skip_rejected() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 5).unwrap_err();
    assert!(matches!(err, StorageError::MigrationFailed { .. }));
    assert!(err.to_string().contains("single-step"));
}

#[test]
fn frankensqlite_migrate_backend_failure() {
    let backend = MockBackend {
        fail_migrate: true,
        ..Default::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap_err();
    assert!(matches!(err, StorageError::BackendUnavailable { .. }));
}

// ===========================================================================
// 26. FrankensqliteStorageAdapter — event recording
// ===========================================================================

#[test]
fn frankensqlite_events_record_operations() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let context = ctx();

    adapter
        .put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter.get(StoreKind::ReplayIndex, "k", &context).unwrap();
    adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
        .unwrap();
    adapter
        .delete(StoreKind::ReplayIndex, "k", &context)
        .unwrap();
    adapter
        .put_batch(StoreKind::ReplayIndex, vec![], &context)
        .unwrap();

    let events = adapter.events();
    assert_eq!(events.len(), 5);
    assert_eq!(events[0].event, "put");
    assert_eq!(events[1].event, "get");
    assert_eq!(events[2].event, "query");
    assert_eq!(events[3].event, "delete");
    assert_eq!(events[4].event, "put_batch");
    for event in events {
        assert_eq!(event.outcome, "ok");
        assert_eq!(event.component, "storage_adapter");
    }
}

#[test]
fn frankensqlite_events_record_error_with_code() {
    let backend = MockBackend {
        fail_put: true,
        ..Default::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let _ = adapter.put(
        StoreKind::ReplayIndex,
        "k".into(),
        vec![1],
        BTreeMap::new(),
        &ctx(),
    );
    let event = adapter.events().last().unwrap();
    assert_eq!(event.outcome, "error");
    assert!(event.error_code.is_some());
}

// ===========================================================================
// 27. Determinism — same inputs produce same outputs
// ===========================================================================

#[test]
fn determinism_in_memory_put_get_identical_across_runs() {
    for _ in 0..3 {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        let meta = make_meta(&[("env", "prod"), ("version", "1")]);
        let record = adapter
            .put(
                StoreKind::BenchmarkLedger,
                "bench/key".into(),
                vec![1, 2, 3],
                meta.clone(),
                &context,
            )
            .unwrap();
        assert_eq!(record.key, "bench/key");
        assert_eq!(record.value, vec![1, 2, 3]);
        assert_eq!(record.metadata, meta);
        assert_eq!(record.revision, 1);
    }
}

#[test]
fn determinism_query_ordering_is_stable() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();
    // Insert in reverse order
    for i in (0..5u8).rev() {
        adapter
            .put(
                StoreKind::ReplayIndex,
                format!("k/{i:03}"),
                vec![i],
                BTreeMap::new(),
                &context,
            )
            .unwrap();
    }

    let rows = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
        .unwrap();
    let keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
    assert_eq!(keys, vec!["k/000", "k/001", "k/002", "k/003", "k/004"]);
}

#[test]
fn determinism_migration_receipt_hash_is_repeatable() {
    let hash1 = {
        let mut a = InMemoryStorageAdapter::new();
        let context = ctx();
        a.put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
        let r = a.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
        (r.state_hash_before.clone(), r.state_hash_after.clone())
    };
    let hash2 = {
        let mut a = InMemoryStorageAdapter::new();
        let context = ctx();
        a.put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
        let r = a.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();
        (r.state_hash_before.clone(), r.state_hash_after.clone())
    };
    assert_eq!(hash1, hash2);
}

// ===========================================================================
// 28. Cross-concern integration scenarios
// ===========================================================================

#[test]
fn cross_concern_full_crud_lifecycle_across_multiple_stores() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();

    // Put into multiple stores
    for (store, key) in [
        (StoreKind::ReplayIndex, "r/1"),
        (StoreKind::EvidenceIndex, "e/1"),
        (StoreKind::PolicyCache, "p/1"),
        (StoreKind::PlasWitness, "w/1"),
    ] {
        adapter
            .put(store, key.into(), vec![1], BTreeMap::new(), &context)
            .unwrap();
    }

    // Verify isolation: each store has exactly one record
    for store in [
        StoreKind::ReplayIndex,
        StoreKind::EvidenceIndex,
        StoreKind::PolicyCache,
        StoreKind::PlasWitness,
    ] {
        let rows = adapter
            .query(store, &StoreQuery::default(), &context)
            .unwrap();
        assert_eq!(rows.len(), 1, "store {store:?} should have 1 record");
    }

    // Stores that were not touched should be empty
    for store in [
        StoreKind::BenchmarkLedger,
        StoreKind::ReplacementLineage,
        StoreKind::IfcProvenance,
        StoreKind::SpecializationIndex,
    ] {
        let rows = adapter
            .query(store, &StoreQuery::default(), &context)
            .unwrap();
        assert!(rows.is_empty(), "store {store:?} should be empty");
    }
}

#[test]
fn cross_concern_events_accumulate_across_operations() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();

    adapter
        .put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter.get(StoreKind::ReplayIndex, "k", &context).unwrap();
    adapter
        .delete(StoreKind::ReplayIndex, "k", &context)
        .unwrap();
    let _ = adapter.put(
        StoreKind::ReplayIndex,
        "".into(),
        vec![1],
        BTreeMap::new(),
        &context,
    );

    let events = adapter.events();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0].outcome, "ok");
    assert_eq!(events[1].outcome, "ok");
    assert_eq!(events[2].outcome, "ok");
    assert_eq!(events[3].outcome, "error");
}

#[test]
fn cross_concern_migrate_then_continue_operations() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();

    adapter
        .put(
            StoreKind::ReplayIndex,
            "pre-migration".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap();

    // Data should still be accessible after migration
    let got = adapter
        .get(StoreKind::ReplayIndex, "pre-migration", &context)
        .unwrap()
        .unwrap();
    assert_eq!(got.value, vec![1]);

    // New writes should still work
    adapter
        .put(
            StoreKind::ReplayIndex,
            "post-migration".into(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let rows = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
        .unwrap();
    assert_eq!(rows.len(), 2);
}

#[test]
fn cross_concern_batch_then_query_with_filters() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();

    let entries = vec![
        BatchPutEntry {
            key: "run/001".into(),
            value: vec![1],
            metadata: make_meta(&[("status", "pass")]),
        },
        BatchPutEntry {
            key: "run/002".into(),
            value: vec![2],
            metadata: make_meta(&[("status", "fail")]),
        },
        BatchPutEntry {
            key: "run/003".into(),
            value: vec![3],
            metadata: make_meta(&[("status", "pass")]),
        },
    ];
    adapter
        .put_batch(StoreKind::ReplayIndex, entries, &context)
        .unwrap();

    // Query with metadata filter
    let query = StoreQuery {
        key_prefix: Some("run/".into()),
        metadata_filters: make_meta(&[("status", "pass")]),
        ..Default::default()
    };
    let rows = adapter
        .query(StoreKind::ReplayIndex, &query, &context)
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].key, "run/001");
    assert_eq!(rows[1].key, "run/003");
}

#[test]
fn cross_concern_frankensqlite_put_then_query_prefix_with_limit() {
    let backend = MockBackend::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let context = ctx();

    for i in 0..10u8 {
        adapter
            .put(
                StoreKind::EvidenceIndex,
                format!("ev/{i:03}"),
                vec![i],
                BTreeMap::new(),
                &context,
            )
            .unwrap();
    }

    let query = StoreQuery {
        key_prefix: Some("ev/".into()),
        limit: Some(3),
        ..Default::default()
    };
    let rows = adapter
        .query(StoreKind::EvidenceIndex, &query, &context)
        .unwrap();
    assert_eq!(rows.len(), 3);
    // Canonicalized: first 3 in sorted order
    assert_eq!(rows[0].key, "ev/000");
    assert_eq!(rows[1].key, "ev/001");
    assert_eq!(rows[2].key, "ev/002");
}

#[test]
fn cross_concern_multiple_contexts_tracked_in_events() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx_a = ctx_custom("trace-A", "dec-A", "pol-A");
    let ctx_b = ctx_custom("trace-B", "dec-B", "pol-B");

    adapter
        .put(
            StoreKind::ReplayIndex,
            "k1".into(),
            vec![1],
            BTreeMap::new(),
            &ctx_a,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "k2".into(),
            vec![2],
            BTreeMap::new(),
            &ctx_b,
        )
        .unwrap();

    let events = adapter.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].trace_id, "trace-A");
    assert_eq!(events[1].trace_id, "trace-B");
}

#[test]
fn cross_concern_overwrite_preserves_latest_value() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();

    for i in 0..5u8 {
        adapter
            .put(
                StoreKind::PolicyCache,
                "config".into(),
                vec![i],
                BTreeMap::new(),
                &context,
            )
            .unwrap();
    }

    let got = adapter
        .get(StoreKind::PolicyCache, "config", &context)
        .unwrap()
        .unwrap();
    assert_eq!(got.value, vec![4]); // last write wins
}

#[test]
fn cross_concern_store_kind_isolation() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();

    // Same key in two different stores
    adapter
        .put(
            StoreKind::ReplayIndex,
            "shared-key".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .unwrap();
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "shared-key".into(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let r1 = adapter
        .get(StoreKind::ReplayIndex, "shared-key", &context)
        .unwrap()
        .unwrap();
    let r2 = adapter
        .get(StoreKind::EvidenceIndex, "shared-key", &context)
        .unwrap()
        .unwrap();
    assert_eq!(r1.value, vec![1]);
    assert_eq!(r2.value, vec![2]);

    // Delete from one store does not affect the other
    adapter
        .delete(StoreKind::ReplayIndex, "shared-key", &context)
        .unwrap();
    let still_there = adapter
        .get(StoreKind::EvidenceIndex, "shared-key", &context)
        .unwrap();
    assert!(still_there.is_some());
}

#[test]
fn cross_concern_frankensqlite_events_accumulate_on_failures() {
    let backend = MockBackend {
        fail_put: true,
        fail_get: true,
        fail_delete: true,
        ..Default::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).unwrap();
    let context = ctx();

    let _ = adapter.put(
        StoreKind::ReplayIndex,
        "k".into(),
        vec![1],
        BTreeMap::new(),
        &context,
    );
    let _ = adapter.get(StoreKind::ReplayIndex, "k", &context);
    let _ = adapter.delete(StoreKind::ReplayIndex, "k", &context);

    let events = adapter.events();
    assert_eq!(events.len(), 3);
    for event in events {
        assert_eq!(event.outcome, "error");
        assert!(event.error_code.is_some());
    }
}

#[test]
fn cross_concern_empty_value_is_valid() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();

    adapter
        .put(
            StoreKind::PolicyCache,
            "empty-val".into(),
            vec![],
            BTreeMap::new(),
            &context,
        )
        .unwrap();

    let got = adapter
        .get(StoreKind::PolicyCache, "empty-val", &context)
        .unwrap()
        .unwrap();
    assert!(got.value.is_empty());
}

#[test]
fn cross_concern_large_batch_preserves_order() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = ctx();

    let entries: Vec<BatchPutEntry> = (0..50u8)
        .rev()
        .map(|i| BatchPutEntry {
            key: format!("batch/{i:03}"),
            value: vec![i],
            metadata: BTreeMap::new(),
        })
        .collect();

    adapter
        .put_batch(StoreKind::BenchmarkLedger, entries, &context)
        .unwrap();

    let rows = adapter
        .query(StoreKind::BenchmarkLedger, &StoreQuery::default(), &context)
        .unwrap();
    assert_eq!(rows.len(), 50);
    // Query results are canonicalized by key
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.key, format!("batch/{i:03}"));
    }
}
