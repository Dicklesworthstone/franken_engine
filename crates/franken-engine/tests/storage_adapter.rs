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

use std::collections::{BTreeMap, BTreeSet};

use frankenengine_engine::storage_adapter::{
    BatchPutEntry, EventContext, FrankensqliteBackend, FrankensqliteStorageAdapter,
    InMemoryStorageAdapter, STORAGE_SCHEMA_VERSION, StorageAdapter, StorageError, StoreKind,
    StoreQuery, StoreRecord,
};

fn context() -> EventContext {
    EventContext::new("trace-it", "decision-it", "policy-it").expect("context")
}

fn all_store_kinds() -> [StoreKind; 8] {
    [
        StoreKind::ReplayIndex,
        StoreKind::EvidenceIndex,
        StoreKind::BenchmarkLedger,
        StoreKind::PolicyCache,
        StoreKind::PlasWitness,
        StoreKind::ReplacementLineage,
        StoreKind::IfcProvenance,
        StoreKind::SpecializationIndex,
    ]
}

fn seed_store<A: StorageAdapter>(adapter: &mut A, store: StoreKind, context: &EventContext) {
    let mut metadata = BTreeMap::new();
    metadata.insert("zone".to_string(), "prod".to_string());
    metadata.insert("store".to_string(), store.as_str().to_string());

    adapter
        .put(
            store,
            format!("{}/z", store.as_str()),
            vec![2, 2],
            metadata.clone(),
            context,
        )
        .expect("seed z");
    adapter
        .put(
            store,
            format!("{}/a", store.as_str()),
            vec![1, 1],
            metadata,
            context,
        )
        .expect("seed a");
}

fn snapshot_all<A: StorageAdapter>(
    adapter: &mut A,
    context: &EventContext,
) -> Vec<(StoreKind, Vec<StoreRecord>)> {
    all_store_kinds()
        .iter()
        .copied()
        .map(|store| {
            let rows = adapter
                .query(store, &StoreQuery::default(), context)
                .expect("snapshot query");
            (store, rows)
        })
        .collect()
}

#[test]
fn in_memory_adapter_supports_crud_batch_and_deterministic_queries() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();

    adapter
        .put(
            StoreKind::ReplayIndex,
            "trace/2".to_string(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .expect("put trace/2");

    let mut metadata = BTreeMap::new();
    metadata.insert("zone".to_string(), "prod".to_string());
    let batch = vec![
        BatchPutEntry {
            key: "trace/1".to_string(),
            value: vec![1],
            metadata: metadata.clone(),
        },
        BatchPutEntry {
            key: "trace/3".to_string(),
            value: vec![3],
            metadata,
        },
    ];
    adapter
        .put_batch(StoreKind::ReplayIndex, batch, &context)
        .expect("batch put");

    let rows = adapter
        .query(
            StoreKind::ReplayIndex,
            &StoreQuery {
                key_prefix: Some("trace/".to_string()),
                metadata_filters: BTreeMap::new(),
                limit: None,
            },
            &context,
        )
        .expect("query");

    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].key, "trace/1");
    assert_eq!(rows[1].key, "trace/2");
    assert_eq!(rows[2].key, "trace/3");

    let loaded = adapter
        .get(StoreKind::ReplayIndex, "trace/2", &context)
        .expect("get")
        .expect("value");
    assert_eq!(loaded.value, vec![2]);

    assert!(
        adapter
            .delete(StoreKind::ReplayIndex, "trace/2", &context)
            .expect("delete")
    );

    let post_delete = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
        .expect("query after delete");
    assert_eq!(post_delete.len(), 2);
}

#[test]
fn migration_and_version_checks_are_fail_closed() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();

    adapter
        .put(
            StoreKind::EvidenceIndex,
            "decision/one".to_string(),
            vec![1, 2, 3],
            BTreeMap::new(),
            &context,
        )
        .expect("seed");

    let receipt = adapter
        .migrate_to(STORAGE_SCHEMA_VERSION + 1)
        .expect("migrate");
    assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
    assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION + 1);
    assert_eq!(receipt.records_touched, 1);

    let mismatch = adapter
        .ensure_schema_version(STORAGE_SCHEMA_VERSION)
        .expect_err("should fail closed");
    assert_eq!(mismatch.code(), "FE-STOR-0005");
}

#[test]
fn migrations_reject_version_jumps() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter
        .migrate_to(STORAGE_SCHEMA_VERSION + 2)
        .expect_err("multi-step migration must fail");

    assert_eq!(err.code(), "FE-STOR-0006");
}

#[test]
fn in_memory_adapter_rejects_zero_limit_queries() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();

    let err = adapter
        .query(
            StoreKind::ReplayIndex,
            &StoreQuery {
                key_prefix: None,
                metadata_filters: BTreeMap::new(),
                limit: Some(0),
            },
            &context,
        )
        .expect_err("limit=0 must fail");

    assert_eq!(err.code(), "FE-STOR-0003");
}

#[derive(Debug, Default)]
struct MockFrankensqlite {
    schema_version: u32,
    stores: BTreeMap<StoreKind, BTreeMap<String, StoreRecord>>,
    fail_wal_profile: bool,
    fail_put: bool,
    reverse_query_order: bool,
}

impl FrankensqliteBackend for MockFrankensqlite {
    fn apply_wal_profile(&mut self) -> Result<(), String> {
        if self.fail_wal_profile {
            return Err("wal profile unavailable".to_string());
        }
        Ok(())
    }

    fn set_pragma(&mut self, _key: &str, _value: &str) -> Result<(), String> {
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
        if self.fail_put {
            return Err("simulated backend write failure".to_string());
        }
        let records = self.stores.entry(store).or_default();
        let revision = records
            .get(key)
            .map_or(1, |existing| existing.revision.saturating_add(1));
        let record = StoreRecord {
            store,
            key: key.to_string(),
            value: value.to_vec(),
            metadata: metadata.clone(),
            revision,
        };
        records.insert(key.to_string(), record.clone());
        Ok(record)
    }

    fn get_record(&self, store: StoreKind, key: &str) -> Result<Option<StoreRecord>, String> {
        Ok(self
            .stores
            .get(&store)
            .and_then(|records| records.get(key).cloned()))
    }

    fn query_records(
        &self,
        store: StoreKind,
        query: &StoreQuery,
    ) -> Result<Vec<StoreRecord>, String> {
        let mut out = Vec::new();
        if let Some(records) = self.stores.get(&store) {
            for record in records.values() {
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
        if self.reverse_query_order {
            out.reverse();
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
            .and_then(|records| records.remove(key))
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
fn frankensqlite_adapter_works_with_backend_contract() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
    let context = context();

    adapter
        .put(
            StoreKind::PolicyCache,
            "policy/default".to_string(),
            vec![7, 7, 7],
            BTreeMap::new(),
            &context,
        )
        .expect("put policy");

    let loaded = adapter
        .get(StoreKind::PolicyCache, "policy/default", &context)
        .expect("get")
        .expect("exists");
    assert_eq!(loaded.value, vec![7, 7, 7]);

    let events = adapter.events();
    assert!(!events.is_empty());
    assert_eq!(events[0].trace_id, "trace-it");
    assert_eq!(events[0].decision_id, "decision-it");
    assert_eq!(events[0].policy_id, "policy-it");
}

#[test]
fn frankensqlite_adapter_fails_closed_when_wal_setup_fails() {
    let backend = MockFrankensqlite {
        fail_wal_profile: true,
        ..MockFrankensqlite::default()
    };

    let err = FrankensqliteStorageAdapter::new(backend).expect_err("init should fail");
    assert!(matches!(
        err,
        StorageError::BackendUnavailable { ref backend, .. } if backend == "frankensqlite"
    ));
    assert_eq!(err.code(), "FE-STOR-0008");
}

#[test]
fn frankensqlite_adapter_emits_structured_error_event_on_backend_write_failure() {
    let backend = MockFrankensqlite {
        fail_put: true,
        ..MockFrankensqlite::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
    let context = context();

    let err = adapter
        .put(
            StoreKind::PolicyCache,
            "policy/default".to_string(),
            vec![9, 9, 9],
            BTreeMap::new(),
            &context,
        )
        .expect_err("write should fail");
    assert_eq!(err.code(), "FE-STOR-0008");

    let event = adapter.events().last().expect("event emitted");
    assert_eq!(event.trace_id, "trace-it");
    assert_eq!(event.decision_id, "decision-it");
    assert_eq!(event.policy_id, "policy-it");
    assert_eq!(event.component, "storage_adapter");
    assert_eq!(event.event, "put");
    assert_eq!(event.outcome, "error");
    assert_eq!(event.error_code.as_deref(), Some("FE-STOR-0008"));
}

#[test]
fn frankensqlite_adapter_rejects_multi_step_migration() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");

    let err = adapter
        .migrate_to(STORAGE_SCHEMA_VERSION + 2)
        .expect_err("multi-step migration must fail");

    assert_eq!(err.code(), "FE-STOR-0006");
}

#[test]
fn frankensqlite_query_results_are_canonicalized_before_limit() {
    let backend = MockFrankensqlite {
        reverse_query_order: true,
        ..MockFrankensqlite::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
    let context = context();

    adapter
        .put(
            StoreKind::ReplayIndex,
            "trace/3".to_string(),
            vec![3],
            BTreeMap::new(),
            &context,
        )
        .expect("put trace/3");
    adapter
        .put(
            StoreKind::ReplayIndex,
            "trace/1".to_string(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .expect("put trace/1");
    adapter
        .put(
            StoreKind::ReplayIndex,
            "trace/2".to_string(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .expect("put trace/2");

    let rows = adapter
        .query(
            StoreKind::ReplayIndex,
            &StoreQuery {
                key_prefix: Some("trace/".to_string()),
                metadata_filters: BTreeMap::new(),
                limit: Some(2),
            },
            &context,
        )
        .expect("query");

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].key, "trace/1");
    assert_eq!(rows[1].key, "trace/2");
}

#[test]
fn frankensqlite_replay_state_is_deterministic_across_backend_orderings() {
    let mut canonical_adapter = FrankensqliteStorageAdapter::new(MockFrankensqlite::default())
        .expect("canonical adapter init");
    let mut reverse_adapter = FrankensqliteStorageAdapter::new(MockFrankensqlite {
        reverse_query_order: true,
        ..MockFrankensqlite::default()
    })
    .expect("reverse adapter init");
    let context = context();

    for store in all_store_kinds() {
        seed_store(&mut canonical_adapter, store, &context);
        seed_store(&mut reverse_adapter, store, &context);
    }

    let canonical_snapshot = snapshot_all(&mut canonical_adapter, &context);
    let reverse_snapshot = snapshot_all(&mut reverse_adapter, &context);
    assert_eq!(canonical_snapshot, reverse_snapshot);
}

#[test]
fn frankensqlite_migration_replay_receipts_match_from_identical_start_state() {
    let mut canonical_adapter = FrankensqliteStorageAdapter::new(MockFrankensqlite::default())
        .expect("canonical adapter init");
    let mut reverse_adapter = FrankensqliteStorageAdapter::new(MockFrankensqlite {
        reverse_query_order: true,
        ..MockFrankensqlite::default()
    })
    .expect("reverse adapter init");
    let context = context();

    for store in all_store_kinds() {
        seed_store(&mut canonical_adapter, store, &context);
        seed_store(&mut reverse_adapter, store, &context);
    }

    let canonical_receipt = canonical_adapter
        .migrate_to(STORAGE_SCHEMA_VERSION + 1)
        .expect("canonical migrate");
    let reverse_receipt = reverse_adapter
        .migrate_to(STORAGE_SCHEMA_VERSION + 1)
        .expect("reverse migrate");
    assert_eq!(canonical_receipt, reverse_receipt);

    let canonical_snapshot = snapshot_all(&mut canonical_adapter, &context);
    let reverse_snapshot = snapshot_all(&mut reverse_adapter, &context);
    assert_eq!(canonical_snapshot, reverse_snapshot);
}

#[test]
fn wal_order_variants_preserve_deterministic_query_results() {
    let mut wal_normal =
        FrankensqliteStorageAdapter::new(MockFrankensqlite::default()).expect("normal init");
    let mut wal_checkpoint_variant = FrankensqliteStorageAdapter::new(MockFrankensqlite {
        reverse_query_order: true,
        ..MockFrankensqlite::default()
    })
    .expect("checkpoint init");
    let context = context();

    seed_store(&mut wal_normal, StoreKind::EvidenceIndex, &context);
    seed_store(
        &mut wal_checkpoint_variant,
        StoreKind::EvidenceIndex,
        &context,
    );

    let query = StoreQuery {
        key_prefix: Some("evidence_index/".to_string()),
        metadata_filters: BTreeMap::new(),
        limit: Some(2),
    };
    let normal = wal_normal
        .query(StoreKind::EvidenceIndex, &query, &context)
        .expect("normal query");
    let checkpoint = wal_checkpoint_variant
        .query(StoreKind::EvidenceIndex, &query, &context)
        .expect("checkpoint query");
    assert_eq!(normal, checkpoint);
}

// ────────────────────────────────────────────────────────────
// Enrichment: metadata filters, delete semantics, store isolation,
// error paths, serde roundtrips, batch edge cases
// ────────────────────────────────────────────────────────────

use frankenengine_engine::storage_adapter::{MigrationReceipt, StorageEvent};

#[test]
fn in_memory_get_returns_none_for_missing_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();
    let result = adapter
        .get(StoreKind::ReplayIndex, "nonexistent/key", &context)
        .expect("get should succeed");
    assert!(result.is_none());
}

#[test]
fn in_memory_delete_returns_false_for_missing_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();
    let deleted = adapter
        .delete(StoreKind::ReplayIndex, "nonexistent/key", &context)
        .expect("delete should succeed");
    assert!(!deleted);
}

#[test]
fn stores_are_isolated_from_each_other() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();

    adapter
        .put(
            StoreKind::ReplayIndex,
            "shared/key".to_string(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .expect("put to replay");

    adapter
        .put(
            StoreKind::EvidenceIndex,
            "shared/key".to_string(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .expect("put to evidence");

    let replay_val = adapter
        .get(StoreKind::ReplayIndex, "shared/key", &context)
        .expect("get replay")
        .expect("exists");
    assert_eq!(replay_val.value, vec![1]);

    let evidence_val = adapter
        .get(StoreKind::EvidenceIndex, "shared/key", &context)
        .expect("get evidence")
        .expect("exists");
    assert_eq!(evidence_val.value, vec![2]);
}

#[test]
fn metadata_filter_narrows_query_results() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();

    let mut meta_prod = BTreeMap::new();
    meta_prod.insert("env".to_string(), "prod".to_string());
    let mut meta_staging = BTreeMap::new();
    meta_staging.insert("env".to_string(), "staging".to_string());

    adapter
        .put(
            StoreKind::PolicyCache,
            "policy/a".to_string(),
            vec![1],
            meta_prod.clone(),
            &context,
        )
        .expect("put prod a");
    adapter
        .put(
            StoreKind::PolicyCache,
            "policy/b".to_string(),
            vec![2],
            meta_staging,
            &context,
        )
        .expect("put staging b");
    adapter
        .put(
            StoreKind::PolicyCache,
            "policy/c".to_string(),
            vec![3],
            meta_prod,
            &context,
        )
        .expect("put prod c");

    let mut filters = BTreeMap::new();
    filters.insert("env".to_string(), "prod".to_string());
    let prod_results = adapter
        .query(
            StoreKind::PolicyCache,
            &StoreQuery {
                key_prefix: Some("policy/".to_string()),
                metadata_filters: filters,
                limit: None,
            },
            &context,
        )
        .expect("query prod");

    assert_eq!(prod_results.len(), 2);
    assert_eq!(prod_results[0].key, "policy/a");
    assert_eq!(prod_results[1].key, "policy/c");
}

#[test]
fn put_overwrites_existing_value() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();

    adapter
        .put(
            StoreKind::ReplayIndex,
            "key/x".to_string(),
            vec![1, 1],
            BTreeMap::new(),
            &context,
        )
        .expect("put original");

    adapter
        .put(
            StoreKind::ReplayIndex,
            "key/x".to_string(),
            vec![2, 2],
            BTreeMap::new(),
            &context,
        )
        .expect("put overwrite");

    let loaded = adapter
        .get(StoreKind::ReplayIndex, "key/x", &context)
        .expect("get")
        .expect("exists");
    assert_eq!(loaded.value, vec![2, 2]);
}

#[test]
fn query_with_limit_returns_at_most_n_results() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();

    for i in 0..5 {
        adapter
            .put(
                StoreKind::BenchmarkLedger,
                format!("bench/{i}"),
                vec![i as u8],
                BTreeMap::new(),
                &context,
            )
            .expect("put");
    }

    let results = adapter
        .query(
            StoreKind::BenchmarkLedger,
            &StoreQuery {
                key_prefix: Some("bench/".to_string()),
                metadata_filters: BTreeMap::new(),
                limit: Some(3),
            },
            &context,
        )
        .expect("query with limit");
    assert_eq!(results.len(), 3);
}

#[test]
fn batch_put_is_atomic_equivalent_to_individual_puts() {
    let mut adapter = InMemoryStorageAdapter::new();
    let context = context();

    let batch = vec![
        BatchPutEntry {
            key: "batch/alpha".to_string(),
            value: vec![10],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "batch/beta".to_string(),
            value: vec![20],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "batch/gamma".to_string(),
            value: vec![30],
            metadata: BTreeMap::new(),
        },
    ];

    adapter
        .put_batch(StoreKind::PlasWitness, batch, &context)
        .expect("batch put");

    let results = adapter
        .query(StoreKind::PlasWitness, &StoreQuery::default(), &context)
        .expect("query all");
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].key, "batch/alpha");
    assert_eq!(results[1].key, "batch/beta");
    assert_eq!(results[2].key, "batch/gamma");
}

#[test]
fn in_memory_schema_version_is_initial() {
    let adapter = InMemoryStorageAdapter::new();
    assert_eq!(adapter.current_schema_version(), STORAGE_SCHEMA_VERSION);
    assert_eq!(adapter.backend_name(), "in_memory");
}

#[test]
fn in_memory_ensure_schema_version_passes_for_current() {
    let adapter = InMemoryStorageAdapter::new();
    adapter
        .ensure_schema_version(STORAGE_SCHEMA_VERSION)
        .expect("version should match");
}

#[test]
fn frankensqlite_backend_name() {
    let backend = MockFrankensqlite::default();
    let adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
    assert_eq!(adapter.backend_name(), "frankensqlite");
}

#[test]
fn frankensqlite_delete_returns_false_for_missing_key() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
    let context = context();

    let deleted = adapter
        .delete(StoreKind::PolicyCache, "nonexistent", &context)
        .expect("delete should succeed");
    assert!(!deleted);
}

#[test]
fn frankensqlite_put_increments_revision() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
    let context = context();

    adapter
        .put(
            StoreKind::ReplayIndex,
            "rev/test".to_string(),
            vec![1],
            BTreeMap::new(),
            &context,
        )
        .expect("first put");
    let r1 = adapter
        .get(StoreKind::ReplayIndex, "rev/test", &context)
        .expect("get")
        .expect("exists");
    assert_eq!(r1.revision, 1);

    adapter
        .put(
            StoreKind::ReplayIndex,
            "rev/test".to_string(),
            vec![2],
            BTreeMap::new(),
            &context,
        )
        .expect("second put");
    let r2 = adapter
        .get(StoreKind::ReplayIndex, "rev/test", &context)
        .expect("get")
        .expect("exists");
    assert_eq!(r2.revision, 2);
}

#[test]
fn store_record_serde_roundtrip() {
    let record = StoreRecord {
        store: StoreKind::EvidenceIndex,
        key: "evidence/abc".to_string(),
        value: vec![42, 43, 44],
        metadata: {
            let mut m = BTreeMap::new();
            m.insert("zone".to_string(), "prod".to_string());
            m
        },
        revision: 3,
    };
    let json = serde_json::to_string(&record).expect("serialize");
    let recovered: StoreRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(record, recovered);
}

#[test]
fn storage_error_serde_roundtrip() {
    let errors = vec![
        StorageError::InvalidContext {
            field: "trace_id".to_string(),
        },
        StorageError::InvalidKey {
            key: "bad/key".to_string(),
        },
        StorageError::NotFound {
            store: StoreKind::ReplayIndex,
            key: "missing".to_string(),
        },
        StorageError::SchemaVersionMismatch {
            expected: 1,
            actual: 2,
        },
    ];
    for err in &errors {
        let json = serde_json::to_string(err).expect("serialize");
        let recovered: StorageError = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(err, &recovered);
    }
}

#[test]
fn storage_error_display_is_non_empty() {
    let err = StorageError::InvalidKey {
        key: "bad".to_string(),
    };
    let msg = err.to_string();
    assert!(!msg.is_empty());
    assert!(msg.contains("bad"));
}

#[test]
fn migration_receipt_serde_roundtrip() {
    let receipt = MigrationReceipt {
        backend: "in_memory".to_string(),
        from_version: 1,
        to_version: 2,
        stores_touched: vec![StoreKind::ReplayIndex, StoreKind::EvidenceIndex],
        records_touched: 42,
        state_hash_before: "aaa".to_string(),
        state_hash_after: "bbb".to_string(),
    };
    let json = serde_json::to_string(&receipt).expect("serialize");
    let recovered: MigrationReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(receipt, recovered);
}

#[test]
fn storage_event_serde_roundtrip() {
    let event = StorageEvent {
        trace_id: "trace-1".to_string(),
        decision_id: "dec-1".to_string(),
        policy_id: "pol-1".to_string(),
        component: "storage_adapter".to_string(),
        event: "put".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: StorageEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn event_context_rejects_empty_trace_id() {
    let err =
        EventContext::new("", "decision-1", "policy-1").expect_err("empty trace_id should fail");
    assert_eq!(err.code(), "FE-STOR-0001");
}

#[test]
fn all_store_kinds_have_distinct_as_str() {
    let strs: Vec<&str> = all_store_kinds().iter().map(|k| k.as_str()).collect();
    let unique: BTreeSet<&str> = strs.iter().copied().collect();
    assert_eq!(strs.len(), unique.len());
}

#[test]
fn all_store_kinds_have_nonempty_integration_point() {
    for kind in all_store_kinds() {
        let ip = kind.integration_point();
        assert!(!ip.is_empty(), "{kind:?} has empty integration_point");
    }
}
