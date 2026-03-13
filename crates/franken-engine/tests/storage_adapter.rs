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

// ────────────────────────────────────────────────────────────────────────────
// Enrichment tests: ~80 new tests covering edge cases, error paths,
// serialization contracts, determinism guarantees, store isolation,
// concurrent-like access patterns, and cross-concern scenarios.
// ────────────────────────────────────────────────────────────────────────────

// --- 1. EventContext validation edge cases ---

#[test]
fn enrichment_event_context_rejects_whitespace_only_decision_id() {
    let err = EventContext::new("trace-1", "  \t  ", "policy-1")
        .expect_err("whitespace decision_id should fail");
    assert_eq!(err.code(), "FE-STOR-0001");
    assert!(matches!(
        err,
        StorageError::InvalidContext { ref field } if field == "decision_id"
    ));
}

#[test]
fn enrichment_event_context_rejects_whitespace_only_policy_id() {
    let err = EventContext::new("trace-1", "decision-1", " \n ")
        .expect_err("whitespace policy_id should fail");
    assert_eq!(err.code(), "FE-STOR-0001");
    assert!(matches!(
        err,
        StorageError::InvalidContext { ref field } if field == "policy_id"
    ));
}

#[test]
fn enrichment_event_context_preserves_leading_trailing_content() {
    let ctx = EventContext::new(" trace ", " decision ", " policy ")
        .expect("non-empty-after-trim fields should succeed");
    assert_eq!(ctx.trace_id, " trace ");
    assert_eq!(ctx.decision_id, " decision ");
    assert_eq!(ctx.policy_id, " policy ");
}

#[test]
fn enrichment_event_context_serde_roundtrip_with_special_chars() {
    let ctx = EventContext::new("trace/1:2", "decision@3", "policy#4")
        .expect("special chars should be accepted");
    let json = serde_json::to_string(&ctx).expect("serialize");
    let recovered: EventContext = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(ctx, recovered);
}

#[test]
fn enrichment_event_context_clone_equality() {
    let ctx = context();
    let cloned = ctx.clone();
    assert_eq!(ctx, cloned);
}

// --- 2. StoreKind enum contracts ---

#[test]
fn enrichment_store_kind_display_is_as_str() {
    for kind in all_store_kinds() {
        assert_eq!(format!("{kind}"), kind.as_str());
    }
}

#[test]
fn enrichment_store_kind_ord_is_consistent_with_eq() {
    let kinds = all_store_kinds();
    for (i, a) in kinds.iter().enumerate() {
        for (j, b) in kinds.iter().enumerate() {
            if i == j {
                assert_eq!(a.cmp(b), std::cmp::Ordering::Equal);
            } else {
                assert_ne!(a.cmp(b), std::cmp::Ordering::Equal);
            }
        }
    }
}

#[test]
fn enrichment_store_kind_serde_all_variants_roundtrip() {
    for kind in all_store_kinds() {
        let serialized = serde_json::to_string(&kind).expect("serialize");
        let deserialized: StoreKind = serde_json::from_str(&serialized).expect("deserialize");
        assert_eq!(kind, deserialized);
    }
}

#[test]
fn enrichment_store_kind_integration_points_all_start_with_frankensqlite() {
    for kind in all_store_kinds() {
        assert!(
            kind.integration_point().starts_with("frankensqlite::"),
            "{:?} integration_point does not start with 'frankensqlite::'",
            kind
        );
    }
}

#[test]
fn enrichment_store_kind_as_str_uses_lowercase_snake_case() {
    for kind in all_store_kinds() {
        let s = kind.as_str();
        assert!(
            s.chars().all(|c| c.is_ascii_lowercase() || c == '_'),
            "{:?} as_str contains non-snake_case chars: {}",
            kind,
            s
        );
    }
}

// --- 3. StoreRecord contracts ---

#[test]
fn enrichment_store_record_clone_equality() {
    let record = StoreRecord {
        store: StoreKind::ReplayIndex,
        key: "test/key".to_string(),
        value: vec![1, 2, 3],
        metadata: BTreeMap::new(),
        revision: 1,
    };
    let cloned = record.clone();
    assert_eq!(record, cloned);
}

#[test]
fn enrichment_store_record_with_empty_value_roundtrip() {
    let record = StoreRecord {
        store: StoreKind::PolicyCache,
        key: "empty-val".to_string(),
        value: vec![],
        metadata: BTreeMap::new(),
        revision: 1,
    };
    let json = serde_json::to_string(&record).expect("serialize");
    let recovered: StoreRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(record, recovered);
    assert!(recovered.value.is_empty());
}

#[test]
fn enrichment_store_record_with_large_metadata_roundtrip() {
    let mut metadata = BTreeMap::new();
    for i in 0..50 {
        metadata.insert(format!("key_{i}"), format!("value_{i}"));
    }
    let record = StoreRecord {
        store: StoreKind::BenchmarkLedger,
        key: "meta-heavy".to_string(),
        value: vec![42],
        metadata: metadata.clone(),
        revision: 100,
    };
    let json = serde_json::to_string(&record).expect("serialize");
    let recovered: StoreRecord = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(record, recovered);
    assert_eq!(recovered.metadata.len(), 50);
}

#[test]
fn enrichment_store_record_different_stores_not_equal() {
    let r1 = StoreRecord {
        store: StoreKind::ReplayIndex,
        key: "k".to_string(),
        value: vec![1],
        metadata: BTreeMap::new(),
        revision: 1,
    };
    let r2 = StoreRecord {
        store: StoreKind::EvidenceIndex,
        key: "k".to_string(),
        value: vec![1],
        metadata: BTreeMap::new(),
        revision: 1,
    };
    assert_ne!(r1, r2);
}

// --- 4. StoreQuery contracts ---

#[test]
fn enrichment_store_query_default_has_no_prefix() {
    let query = StoreQuery::default();
    assert!(query.key_prefix.is_none());
    assert!(query.metadata_filters.is_empty());
    assert!(query.limit.is_none());
}

#[test]
fn enrichment_store_query_serde_roundtrip_with_all_fields() {
    let mut filters = BTreeMap::new();
    filters.insert("env".to_string(), "prod".to_string());
    filters.insert("region".to_string(), "us-east".to_string());
    let query = StoreQuery {
        key_prefix: Some("run/".to_string()),
        metadata_filters: filters,
        limit: Some(25),
    };
    let json = serde_json::to_string(&query).expect("serialize");
    let recovered: StoreQuery = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(query, recovered);
}

#[test]
fn enrichment_store_query_serde_roundtrip_no_limit() {
    let query = StoreQuery {
        key_prefix: Some("prefix/".to_string()),
        metadata_filters: BTreeMap::new(),
        limit: None,
    };
    let json = serde_json::to_string(&query).expect("serialize");
    let recovered: StoreQuery = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(query, recovered);
}

// --- 5. BatchPutEntry contracts ---

#[test]
fn enrichment_batch_put_entry_serde_roundtrip_with_metadata() {
    let mut meta = BTreeMap::new();
    meta.insert("source".to_string(), "enrichment".to_string());
    let entry = BatchPutEntry {
        key: "batch/entry".to_string(),
        value: vec![0xDE, 0xAD, 0xBE, 0xEF],
        metadata: meta,
    };
    let json = serde_json::to_string(&entry).expect("serialize");
    let recovered: BatchPutEntry = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(entry, recovered);
}

#[test]
fn enrichment_batch_put_entry_clone_equality() {
    let entry = BatchPutEntry {
        key: "k".to_string(),
        value: vec![1],
        metadata: BTreeMap::new(),
    };
    assert_eq!(entry, entry.clone());
}

// --- 6. MigrationReceipt contracts ---

#[test]
fn enrichment_migration_receipt_with_all_stores_touched() {
    let receipt = MigrationReceipt {
        backend: "in_memory".to_string(),
        from_version: 1,
        to_version: 2,
        stores_touched: all_store_kinds().to_vec(),
        records_touched: 100,
        state_hash_before: "before".to_string(),
        state_hash_after: "after".to_string(),
    };
    let json = serde_json::to_string(&receipt).expect("serialize");
    let recovered: MigrationReceipt = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(receipt, recovered);
    assert_eq!(recovered.stores_touched.len(), 8);
}

#[test]
fn enrichment_migration_receipt_clone_equality() {
    let receipt = MigrationReceipt {
        backend: "test".to_string(),
        from_version: 1,
        to_version: 2,
        stores_touched: vec![],
        records_touched: 0,
        state_hash_before: "a".to_string(),
        state_hash_after: "b".to_string(),
    };
    assert_eq!(receipt, receipt.clone());
}

// --- 7. StorageEvent contracts ---

#[test]
fn enrichment_storage_event_with_error_code_roundtrip() {
    let event = StorageEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "storage_adapter".to_string(),
        event: "delete".to_string(),
        outcome: "error".to_string(),
        error_code: Some("FE-STOR-0004".to_string()),
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: StorageEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
}

#[test]
fn enrichment_storage_event_without_error_code_roundtrip() {
    let event = StorageEvent {
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        component: "storage_adapter".to_string(),
        event: "query".to_string(),
        outcome: "ok".to_string(),
        error_code: None,
    };
    let json = serde_json::to_string(&event).expect("serialize");
    let recovered: StorageEvent = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(event, recovered);
    assert!(recovered.error_code.is_none());
}

// --- 8. StorageError contracts ---

#[test]
fn enrichment_storage_error_all_codes_start_with_fe_stor() {
    let errors: Vec<StorageError> = vec![
        StorageError::InvalidContext { field: "f".to_string() },
        StorageError::InvalidKey { key: "k".to_string() },
        StorageError::InvalidQuery { detail: "d".to_string() },
        StorageError::NotFound { store: StoreKind::ReplayIndex, key: "k".to_string() },
        StorageError::SchemaVersionMismatch { expected: 1, actual: 2 },
        StorageError::MigrationFailed { from: 1, to: 3, reason: "r".to_string() },
        StorageError::IntegrityViolation { store: StoreKind::PlasWitness, detail: "d".to_string() },
        StorageError::BackendUnavailable { backend: "b".to_string(), detail: "d".to_string() },
        StorageError::WriteRejected { detail: "d".to_string() },
    ];
    for err in &errors {
        assert!(
            err.code().starts_with("FE-STOR-"),
            "error code {} does not start with FE-STOR-",
            err.code()
        );
    }
}

#[test]
fn enrichment_storage_error_codes_are_sequential() {
    let errors: Vec<StorageError> = vec![
        StorageError::InvalidContext { field: "f".to_string() },
        StorageError::InvalidKey { key: "k".to_string() },
        StorageError::InvalidQuery { detail: "d".to_string() },
        StorageError::NotFound { store: StoreKind::ReplayIndex, key: "k".to_string() },
        StorageError::SchemaVersionMismatch { expected: 1, actual: 2 },
        StorageError::MigrationFailed { from: 1, to: 3, reason: "r".to_string() },
        StorageError::IntegrityViolation { store: StoreKind::PlasWitness, detail: "d".to_string() },
        StorageError::BackendUnavailable { backend: "b".to_string(), detail: "d".to_string() },
        StorageError::WriteRejected { detail: "d".to_string() },
    ];
    for (i, err) in errors.iter().enumerate() {
        let expected_code = format!("FE-STOR-{:04}", i + 1);
        assert_eq!(err.code(), expected_code.as_str());
    }
}

#[test]
fn enrichment_storage_error_display_contains_relevant_info() {
    let err = StorageError::NotFound {
        store: StoreKind::EvidenceIndex,
        key: "missing/key".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("missing/key"));
    assert!(msg.contains("evidence_index"));
}

#[test]
fn enrichment_storage_error_schema_version_mismatch_display() {
    let err = StorageError::SchemaVersionMismatch {
        expected: 5,
        actual: 7,
    };
    let msg = err.to_string();
    assert!(msg.contains("5"));
    assert!(msg.contains("7"));
    assert!(msg.contains("mismatch"));
}

#[test]
fn enrichment_storage_error_migration_failed_display_includes_reason() {
    let err = StorageError::MigrationFailed {
        from: 1,
        to: 2,
        reason: "disk full".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("disk full"));
}

#[test]
fn enrichment_storage_error_backend_unavailable_display() {
    let err = StorageError::BackendUnavailable {
        backend: "frankensqlite".to_string(),
        detail: "connection reset".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("frankensqlite"));
    assert!(msg.contains("connection reset"));
}

#[test]
fn enrichment_storage_error_write_rejected_display() {
    let err = StorageError::WriteRejected {
        detail: "quota exceeded".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("quota exceeded"));
}

#[test]
fn enrichment_storage_error_integrity_violation_display() {
    let err = StorageError::IntegrityViolation {
        store: StoreKind::BenchmarkLedger,
        detail: "checksum mismatch".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("benchmark_ledger"));
    assert!(msg.contains("checksum mismatch"));
}

#[test]
fn enrichment_storage_error_invalid_query_display() {
    let err = StorageError::InvalidQuery {
        detail: "limit cannot be zero".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("limit cannot be zero"));
}

#[test]
fn enrichment_storage_error_implements_std_error() {
    let err: Box<dyn std::error::Error> = Box::new(StorageError::InvalidKey {
        key: "bad".to_string(),
    });
    let _ = format!("{err}");
}

// --- 9. InMemoryStorageAdapter put edge cases ---

#[test]
fn enrichment_in_memory_put_empty_value_succeeds() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    let record = adapter
        .put(
            StoreKind::PolicyCache,
            "empty/val".to_string(),
            vec![],
            BTreeMap::new(),
            &ctx,
        )
        .expect("empty value should be accepted");
    assert!(record.value.is_empty());

    let loaded = adapter
        .get(StoreKind::PolicyCache, "empty/val", &ctx)
        .expect("get")
        .expect("exists");
    assert!(loaded.value.is_empty());
}

#[test]
fn enrichment_in_memory_put_large_value_succeeds() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    let large_value: Vec<u8> = (0..10_000).map(|i| (i % 256) as u8).collect();
    let record = adapter
        .put(
            StoreKind::BenchmarkLedger,
            "large/val".to_string(),
            large_value.clone(),
            BTreeMap::new(),
            &ctx,
        )
        .expect("large value should be accepted");
    assert_eq!(record.value.len(), 10_000);

    let loaded = adapter
        .get(StoreKind::BenchmarkLedger, "large/val", &ctx)
        .expect("get")
        .expect("exists");
    assert_eq!(loaded.value, large_value);
}

#[test]
fn enrichment_in_memory_put_rejects_tab_only_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter
        .put(
            StoreKind::ReplayIndex,
            "\t\t".to_string(),
            vec![1],
            BTreeMap::new(),
            &context(),
        )
        .expect_err("tab-only key should fail");
    assert_eq!(err.code(), "FE-STOR-0002");
}

#[test]
fn enrichment_in_memory_put_overwrites_metadata() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();

    let mut meta1 = BTreeMap::new();
    meta1.insert("env".to_string(), "staging".to_string());
    adapter
        .put(
            StoreKind::PolicyCache,
            "config/x".to_string(),
            vec![1],
            meta1,
            &ctx,
        )
        .expect("put 1");

    let mut meta2 = BTreeMap::new();
    meta2.insert("env".to_string(), "prod".to_string());
    adapter
        .put(
            StoreKind::PolicyCache,
            "config/x".to_string(),
            vec![2],
            meta2.clone(),
            &ctx,
        )
        .expect("put 2");

    let loaded = adapter
        .get(StoreKind::PolicyCache, "config/x", &ctx)
        .expect("get")
        .expect("exists");
    assert_eq!(loaded.metadata, meta2);
    assert_eq!(loaded.value, vec![2]);
}

#[test]
fn enrichment_in_memory_put_revision_increments_per_store() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();

    let r1 = adapter
        .put(
            StoreKind::ReplayIndex,
            "a".to_string(),
            vec![1],
            BTreeMap::new(),
            &ctx,
        )
        .expect("put 1");
    let r2 = adapter
        .put(
            StoreKind::ReplayIndex,
            "b".to_string(),
            vec![2],
            BTreeMap::new(),
            &ctx,
        )
        .expect("put 2");
    assert!(r2.revision > r1.revision);
}

// --- 10. InMemoryStorageAdapter get edge cases ---

#[test]
fn enrichment_in_memory_get_rejects_empty_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter
        .get(StoreKind::ReplayIndex, "", &context())
        .expect_err("empty key should fail");
    assert_eq!(err.code(), "FE-STOR-0002");
}

#[test]
fn enrichment_in_memory_get_rejects_whitespace_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter
        .get(StoreKind::ReplayIndex, "   ", &context())
        .expect_err("whitespace key should fail");
    assert_eq!(err.code(), "FE-STOR-0002");
}

#[test]
fn enrichment_in_memory_get_after_overwrite_returns_latest() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    for i in 0..5u8 {
        adapter
            .put(
                StoreKind::PolicyCache,
                "key".to_string(),
                vec![i],
                BTreeMap::new(),
                &ctx,
            )
            .expect("put");
    }
    let loaded = adapter
        .get(StoreKind::PolicyCache, "key", &ctx)
        .expect("get")
        .expect("exists");
    assert_eq!(loaded.value, vec![4]);
}

// --- 11. InMemoryStorageAdapter delete edge cases ---

#[test]
fn enrichment_in_memory_delete_rejects_empty_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let err = adapter
        .delete(StoreKind::ReplayIndex, "", &context())
        .expect_err("empty key should fail");
    assert_eq!(err.code(), "FE-STOR-0002");
}

#[test]
fn enrichment_in_memory_delete_idempotent() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "k".to_string(),
            vec![1],
            BTreeMap::new(),
            &ctx,
        )
        .expect("put");
    assert!(adapter.delete(StoreKind::ReplayIndex, "k", &ctx).expect("delete 1"));
    assert!(!adapter.delete(StoreKind::ReplayIndex, "k", &ctx).expect("delete 2"));
}

#[test]
fn enrichment_in_memory_delete_does_not_affect_other_keys() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    adapter
        .put(StoreKind::ReplayIndex, "a".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect("put a");
    adapter
        .put(StoreKind::ReplayIndex, "b".to_string(), vec![2], BTreeMap::new(), &ctx)
        .expect("put b");
    adapter.delete(StoreKind::ReplayIndex, "a", &ctx).expect("delete a");

    assert!(adapter.get(StoreKind::ReplayIndex, "a", &ctx).expect("get a").is_none());
    assert!(adapter.get(StoreKind::ReplayIndex, "b", &ctx).expect("get b").is_some());
}

// --- 12. InMemoryStorageAdapter query edge cases ---

#[test]
fn enrichment_in_memory_query_no_prefix_returns_all() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    for i in 0..5 {
        adapter
            .put(
                StoreKind::EvidenceIndex,
                format!("ev/{i}"),
                vec![i as u8],
                BTreeMap::new(),
                &ctx,
            )
            .expect("put");
    }
    let rows = adapter
        .query(StoreKind::EvidenceIndex, &StoreQuery::default(), &ctx)
        .expect("query");
    assert_eq!(rows.len(), 5);
}

#[test]
fn enrichment_in_memory_query_prefix_no_match_returns_empty() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    adapter
        .put(StoreKind::ReplayIndex, "run/1".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect("put");
    let rows = adapter
        .query(
            StoreKind::ReplayIndex,
            &StoreQuery {
                key_prefix: Some("other/".to_string()),
                metadata_filters: BTreeMap::new(),
                limit: None,
            },
            &ctx,
        )
        .expect("query");
    assert!(rows.is_empty());
}

#[test]
fn enrichment_in_memory_query_metadata_filter_no_match_returns_empty() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    let mut meta = BTreeMap::new();
    meta.insert("env".to_string(), "prod".to_string());
    adapter
        .put(StoreKind::PolicyCache, "p/1".to_string(), vec![1], meta, &ctx)
        .expect("put");

    let mut filters = BTreeMap::new();
    filters.insert("env".to_string(), "staging".to_string());
    let rows = adapter
        .query(
            StoreKind::PolicyCache,
            &StoreQuery {
                key_prefix: None,
                metadata_filters: filters,
                limit: None,
            },
            &ctx,
        )
        .expect("query");
    assert!(rows.is_empty());
}

#[test]
fn enrichment_in_memory_query_multiple_metadata_filters_intersect() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();

    let mut meta_both = BTreeMap::new();
    meta_both.insert("env".to_string(), "prod".to_string());
    meta_both.insert("region".to_string(), "us-east".to_string());
    adapter
        .put(StoreKind::PolicyCache, "p/a".to_string(), vec![1], meta_both, &ctx)
        .expect("put a");

    let mut meta_partial = BTreeMap::new();
    meta_partial.insert("env".to_string(), "prod".to_string());
    adapter
        .put(StoreKind::PolicyCache, "p/b".to_string(), vec![2], meta_partial, &ctx)
        .expect("put b");

    let mut filters = BTreeMap::new();
    filters.insert("env".to_string(), "prod".to_string());
    filters.insert("region".to_string(), "us-east".to_string());
    let rows = adapter
        .query(
            StoreKind::PolicyCache,
            &StoreQuery {
                key_prefix: None,
                metadata_filters: filters,
                limit: None,
            },
            &ctx,
        )
        .expect("query");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key, "p/a");
}

#[test]
fn enrichment_in_memory_query_limit_larger_than_result_set() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    adapter
        .put(StoreKind::ReplayIndex, "k/1".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect("put");
    let rows = adapter
        .query(
            StoreKind::ReplayIndex,
            &StoreQuery {
                key_prefix: None,
                metadata_filters: BTreeMap::new(),
                limit: Some(100),
            },
            &ctx,
        )
        .expect("query");
    assert_eq!(rows.len(), 1);
}

#[test]
fn enrichment_in_memory_query_limit_one_returns_lexicographically_first() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    adapter
        .put(StoreKind::BenchmarkLedger, "z/key".to_string(), vec![3], BTreeMap::new(), &ctx)
        .expect("put z");
    adapter
        .put(StoreKind::BenchmarkLedger, "a/key".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect("put a");
    adapter
        .put(StoreKind::BenchmarkLedger, "m/key".to_string(), vec![2], BTreeMap::new(), &ctx)
        .expect("put m");

    let rows = adapter
        .query(
            StoreKind::BenchmarkLedger,
            &StoreQuery {
                key_prefix: None,
                metadata_filters: BTreeMap::new(),
                limit: Some(1),
            },
            &ctx,
        )
        .expect("query");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].key, "a/key");
}

#[test]
fn enrichment_in_memory_query_with_prefix_and_limit() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    for i in 0..10 {
        adapter
            .put(
                StoreKind::ReplayIndex,
                format!("run/{i:03}"),
                vec![i as u8],
                BTreeMap::new(),
                &ctx,
            )
            .expect("put");
    }
    adapter
        .put(StoreKind::ReplayIndex, "other/x".to_string(), vec![99], BTreeMap::new(), &ctx)
        .expect("put other");

    let rows = adapter
        .query(
            StoreKind::ReplayIndex,
            &StoreQuery {
                key_prefix: Some("run/".to_string()),
                metadata_filters: BTreeMap::new(),
                limit: Some(3),
            },
            &ctx,
        )
        .expect("query");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].key, "run/000");
    assert_eq!(rows[2].key, "run/002");
}

// --- 13. InMemoryStorageAdapter batch edge cases ---

#[test]
fn enrichment_in_memory_batch_empty_succeeds() {
    let mut adapter = InMemoryStorageAdapter::new();
    let records = adapter
        .put_batch(StoreKind::PlasWitness, vec![], &context())
        .expect("empty batch should succeed");
    assert!(records.is_empty());
}

#[test]
fn enrichment_in_memory_batch_single_entry() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    let entries = vec![BatchPutEntry {
        key: "single".to_string(),
        value: vec![42],
        metadata: BTreeMap::new(),
    }];
    let records = adapter
        .put_batch(StoreKind::ReplayIndex, entries, &ctx)
        .expect("single-entry batch");
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].key, "single");
    assert_eq!(records[0].value, vec![42]);
}

#[test]
fn enrichment_in_memory_batch_atomicity_on_second_invalid_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    adapter
        .put(StoreKind::ReplayIndex, "seed".to_string(), vec![0], BTreeMap::new(), &ctx)
        .expect("seed");

    let entries = vec![
        BatchPutEntry {
            key: "valid/1".to_string(),
            value: vec![1],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "valid/2".to_string(),
            value: vec![2],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: " ".to_string(),
            value: vec![3],
            metadata: BTreeMap::new(),
        },
    ];
    let err = adapter.put_batch(StoreKind::ReplayIndex, entries, &ctx).expect_err("should fail");
    assert_eq!(err.code(), "FE-STOR-0002");

    let rows = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &ctx)
        .expect("query");
    assert_eq!(rows.len(), 1, "only seed should remain after failed batch");
    assert_eq!(rows[0].key, "seed");
}

#[test]
fn enrichment_in_memory_batch_overwrites_existing_keys() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    adapter
        .put(StoreKind::EvidenceIndex, "k".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect("initial put");

    let entries = vec![BatchPutEntry {
        key: "k".to_string(),
        value: vec![99],
        metadata: BTreeMap::new(),
    }];
    adapter.put_batch(StoreKind::EvidenceIndex, entries, &ctx).expect("batch overwrite");

    let loaded = adapter
        .get(StoreKind::EvidenceIndex, "k", &ctx)
        .expect("get")
        .expect("exists");
    assert_eq!(loaded.value, vec![99]);
}

// --- 14. InMemoryStorageAdapter migration edge cases ---

#[test]
fn enrichment_in_memory_migrate_same_version_is_noop() {
    let mut adapter = InMemoryStorageAdapter::new();
    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION).expect("same-version migration");
    assert_eq!(receipt.from_version, receipt.to_version);
    assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
}

#[test]
fn enrichment_in_memory_migrate_downgrade_rejected() {
    let mut adapter = InMemoryStorageAdapter::new();
    adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).expect("upgrade");
    let err = adapter
        .migrate_to(STORAGE_SCHEMA_VERSION)
        .expect_err("downgrade should fail");
    assert_eq!(err.code(), "FE-STOR-0006");
    let msg = err.to_string();
    assert!(msg.contains("downgrade"));
}

#[test]
fn enrichment_in_memory_migration_receipt_includes_backend_name() {
    let mut adapter = InMemoryStorageAdapter::new();
    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).expect("migrate");
    assert_eq!(receipt.backend, "in_memory");
}

#[test]
fn enrichment_in_memory_migration_state_hash_changes_on_version_bump() {
    let mut adapter = InMemoryStorageAdapter::new();
    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).expect("migrate");
    assert_ne!(receipt.state_hash_before, receipt.state_hash_after);
}

#[test]
fn enrichment_in_memory_ensure_schema_version_after_migration() {
    let mut adapter = InMemoryStorageAdapter::new();
    adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).expect("migrate");

    adapter
        .ensure_schema_version(STORAGE_SCHEMA_VERSION + 1)
        .expect("should match new version");

    let err = adapter
        .ensure_schema_version(STORAGE_SCHEMA_VERSION)
        .expect_err("old version should fail");
    assert_eq!(err.code(), "FE-STOR-0005");
}

// --- 15. InMemoryStorageAdapter with_fail_writes ---

#[test]
fn enrichment_in_memory_fail_writes_put_emits_error_event() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let ctx = context();
    let _ = adapter.put(StoreKind::ReplayIndex, "k".to_string(), vec![1], BTreeMap::new(), &ctx);
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(events[0].error_code.as_deref(), Some("FE-STOR-0009"));
}

#[test]
fn enrichment_in_memory_fail_writes_delete_emits_error_event() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let ctx = context();
    let _ = adapter.delete(StoreKind::ReplayIndex, "k", &ctx);
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(events[0].error_code.as_deref(), Some("FE-STOR-0009"));
}

#[test]
fn enrichment_in_memory_fail_writes_batch_emits_error_event() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let ctx = context();
    let entries = vec![BatchPutEntry {
        key: "k".to_string(),
        value: vec![1],
        metadata: BTreeMap::new(),
    }];
    let _ = adapter.put_batch(StoreKind::ReplayIndex, entries, &ctx);
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
}

#[test]
fn enrichment_in_memory_fail_writes_does_not_affect_query() {
    let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
    let ctx = context();
    let rows = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &ctx)
        .expect("query should succeed even with fail_writes");
    assert!(rows.is_empty());
}

// --- 16. InMemoryStorageAdapter event recording ---

#[test]
fn enrichment_in_memory_events_accumulate_sequentially() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    for i in 0..10 {
        adapter
            .put(
                StoreKind::ReplayIndex,
                format!("k/{i}"),
                vec![i as u8],
                BTreeMap::new(),
                &ctx,
            )
            .expect("put");
    }
    assert_eq!(adapter.events().len(), 10);
    for event in adapter.events() {
        assert_eq!(event.event, "put");
        assert_eq!(event.outcome, "ok");
        assert_eq!(event.component, "storage_adapter");
    }
}

#[test]
fn enrichment_in_memory_events_carry_distinct_contexts() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx1 = EventContext::new("trace-A", "dec-A", "pol-A").expect("ctx1");
    let ctx2 = EventContext::new("trace-B", "dec-B", "pol-B").expect("ctx2");

    adapter
        .put(StoreKind::ReplayIndex, "k1".to_string(), vec![1], BTreeMap::new(), &ctx1)
        .expect("put 1");
    adapter
        .put(StoreKind::ReplayIndex, "k2".to_string(), vec![2], BTreeMap::new(), &ctx2)
        .expect("put 2");

    let events = adapter.events();
    assert_eq!(events[0].trace_id, "trace-A");
    assert_eq!(events[1].trace_id, "trace-B");
}

#[test]
fn enrichment_in_memory_query_event_records_ok() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &ctx)
        .expect("query");
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "query");
    assert_eq!(events[0].outcome, "ok");
}

#[test]
fn enrichment_in_memory_query_error_event_recorded() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    let _ = adapter.query(
        StoreKind::ReplayIndex,
        &StoreQuery {
            key_prefix: None,
            metadata_filters: BTreeMap::new(),
            limit: Some(0),
        },
        &ctx,
    );
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "query");
    assert_eq!(events[0].outcome, "error");
    assert_eq!(events[0].error_code.as_deref(), Some("FE-STOR-0003"));
}

// --- 17. InMemoryStorageAdapter store isolation ---

#[test]
fn enrichment_in_memory_stores_are_fully_isolated() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();

    for kind in all_store_kinds() {
        adapter
            .put(
                kind,
                format!("{}/key", kind.as_str()),
                vec![kind as u8],
                BTreeMap::new(),
                &ctx,
            )
            .expect("put");
    }

    for kind in all_store_kinds() {
        let rows = adapter
            .query(kind, &StoreQuery::default(), &ctx)
            .expect("query");
        assert_eq!(rows.len(), 1, "store {:?} should have exactly 1 record", kind);
        assert_eq!(rows[0].store, kind);
    }
}

#[test]
fn enrichment_in_memory_delete_in_one_store_does_not_affect_another() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();

    adapter
        .put(StoreKind::ReplayIndex, "shared".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect("put replay");
    adapter
        .put(StoreKind::EvidenceIndex, "shared".to_string(), vec![2], BTreeMap::new(), &ctx)
        .expect("put evidence");

    adapter.delete(StoreKind::ReplayIndex, "shared", &ctx).expect("delete");
    assert!(adapter.get(StoreKind::ReplayIndex, "shared", &ctx).expect("get").is_none());
    assert!(adapter.get(StoreKind::EvidenceIndex, "shared", &ctx).expect("get").is_some());
}

// --- 18. FrankensqliteStorageAdapter edge cases ---

#[test]
fn enrichment_frankensqlite_put_empty_value_succeeds() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    let record = adapter
        .put(StoreKind::PolicyCache, "empty".to_string(), vec![], BTreeMap::new(), &ctx)
        .expect("empty value put");
    assert!(record.value.is_empty());
}

#[test]
fn enrichment_frankensqlite_get_nonexistent_returns_none() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    let result = adapter
        .get(StoreKind::PolicyCache, "no-such", &ctx)
        .expect("get");
    assert!(result.is_none());
}

#[test]
fn enrichment_frankensqlite_query_empty_store_returns_empty() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    let rows = adapter
        .query(StoreKind::PlasWitness, &StoreQuery::default(), &ctx)
        .expect("query");
    assert!(rows.is_empty());
}

#[test]
fn enrichment_frankensqlite_batch_empty_succeeds() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    let records = adapter
        .put_batch(StoreKind::ReplayIndex, vec![], &ctx)
        .expect("empty batch");
    assert!(records.is_empty());
}

#[test]
fn enrichment_frankensqlite_put_rejects_whitespace_only_key() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    let err = adapter
        .put(StoreKind::ReplayIndex, "\t".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect_err("tab-only key should fail");
    assert_eq!(err.code(), "FE-STOR-0002");
}

#[test]
fn enrichment_frankensqlite_delete_rejects_whitespace_key() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    let err = adapter
        .delete(StoreKind::ReplayIndex, "\n", &ctx)
        .expect_err("newline-only key should fail");
    assert_eq!(err.code(), "FE-STOR-0002");
}

#[test]
fn enrichment_frankensqlite_batch_rejects_invalid_key_in_entries() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    let entries = vec![
        BatchPutEntry {
            key: "valid".to_string(),
            value: vec![1],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "".to_string(),
            value: vec![2],
            metadata: BTreeMap::new(),
        },
    ];
    let err = adapter.put_batch(StoreKind::ReplayIndex, entries, &ctx).expect_err("should fail");
    assert_eq!(err.code(), "FE-STOR-0002");
}

// --- 19. FrankensqliteStorageAdapter event recording on errors ---

#[test]
fn enrichment_frankensqlite_put_error_records_event_with_code() {
    let backend = MockFrankensqlite {
        fail_put: true,
        ..MockFrankensqlite::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    let _ = adapter.put(StoreKind::ReplayIndex, "k".to_string(), vec![1], BTreeMap::new(), &ctx);
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert!(events[0].error_code.is_some());
}

#[test]
fn enrichment_frankensqlite_get_records_ok_event() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    adapter.get(StoreKind::ReplayIndex, "k", &ctx).expect("get");
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "get");
    assert_eq!(events[0].outcome, "ok");
}

#[test]
fn enrichment_frankensqlite_delete_records_ok_event() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    adapter.delete(StoreKind::ReplayIndex, "k", &ctx).expect("delete");
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "delete");
    assert_eq!(events[0].outcome, "ok");
}

#[test]
fn enrichment_frankensqlite_batch_records_ok_event() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    adapter.put_batch(StoreKind::ReplayIndex, vec![], &ctx).expect("batch");
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event, "put_batch");
    assert_eq!(events[0].outcome, "ok");
}

// --- 20. FrankensqliteStorageAdapter migration edge cases ---

#[test]
fn enrichment_frankensqlite_migrate_same_version_succeeds() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION).expect("same-version");
    assert_eq!(receipt.from_version, receipt.to_version);
}

#[test]
fn enrichment_frankensqlite_migrate_downgrade_rejected() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).expect("upgrade");
    let err = adapter
        .migrate_to(STORAGE_SCHEMA_VERSION)
        .expect_err("downgrade should fail");
    assert_eq!(err.code(), "FE-STOR-0006");
}

#[test]
fn enrichment_frankensqlite_ensure_schema_version_after_migration() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).expect("migrate");
    adapter
        .ensure_schema_version(STORAGE_SCHEMA_VERSION + 1)
        .expect("should match");
    let err = adapter
        .ensure_schema_version(STORAGE_SCHEMA_VERSION)
        .expect_err("old version should fail");
    assert_eq!(err.code(), "FE-STOR-0005");
}

// --- 21. Determinism guarantees ---

#[test]
fn enrichment_determinism_query_order_stable_after_mixed_inserts() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    let keys = ["z/3", "a/1", "m/2", "d/4", "b/5"];
    for key in &keys {
        adapter
            .put(StoreKind::BenchmarkLedger, key.to_string(), vec![1], BTreeMap::new(), &ctx)
            .expect("put");
    }
    let rows = adapter
        .query(StoreKind::BenchmarkLedger, &StoreQuery::default(), &ctx)
        .expect("query");
    let returned_keys: Vec<&str> = rows.iter().map(|r| r.key.as_str()).collect();
    let mut sorted_keys = keys.to_vec();
    sorted_keys.sort();
    assert_eq!(returned_keys, sorted_keys);
}

#[test]
fn enrichment_determinism_repeated_put_get_cycle_is_consistent() {
    for _ in 0..5 {
        let mut adapter = InMemoryStorageAdapter::new();
        let ctx = context();
        adapter
            .put(StoreKind::ReplayIndex, "key".to_string(), vec![42, 43], BTreeMap::new(), &ctx)
            .expect("put");
        let loaded = adapter
            .get(StoreKind::ReplayIndex, "key", &ctx)
            .expect("get")
            .expect("exists");
        assert_eq!(loaded.value, vec![42, 43]);
        assert_eq!(loaded.revision, 1);
    }
}

#[test]
fn enrichment_determinism_batch_then_query_order_is_canonical() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();

    let entries: Vec<BatchPutEntry> = (0..20u8)
        .rev()
        .map(|i| BatchPutEntry {
            key: format!("item/{i:03}"),
            value: vec![i],
            metadata: BTreeMap::new(),
        })
        .collect();
    adapter
        .put_batch(StoreKind::IfcProvenance, entries, &ctx)
        .expect("batch");

    let rows = adapter
        .query(StoreKind::IfcProvenance, &StoreQuery::default(), &ctx)
        .expect("query");
    assert_eq!(rows.len(), 20);
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.key, format!("item/{i:03}"));
    }
}

#[test]
fn enrichment_determinism_migration_receipt_hashes_stable_across_runs() {
    let mut hashes = Vec::new();
    for _ in 0..3 {
        let mut adapter = InMemoryStorageAdapter::new();
        let ctx = context();
        adapter
            .put(StoreKind::EvidenceIndex, "d/1".to_string(), vec![7], BTreeMap::new(), &ctx)
            .expect("put");
        let receipt = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).expect("migrate");
        hashes.push((receipt.state_hash_before.clone(), receipt.state_hash_after.clone()));
    }
    assert_eq!(hashes[0], hashes[1]);
    assert_eq!(hashes[1], hashes[2]);
}

// --- 22. Cross-concern integration ---

#[test]
fn enrichment_cross_concern_put_delete_put_same_key() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    adapter
        .put(StoreKind::ReplayIndex, "recycle".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect("put 1");
    adapter.delete(StoreKind::ReplayIndex, "recycle", &ctx).expect("delete");
    adapter
        .put(StoreKind::ReplayIndex, "recycle".to_string(), vec![2], BTreeMap::new(), &ctx)
        .expect("put 2");

    let loaded = adapter
        .get(StoreKind::ReplayIndex, "recycle", &ctx)
        .expect("get")
        .expect("exists");
    assert_eq!(loaded.value, vec![2]);
}

#[test]
fn enrichment_cross_concern_batch_then_individual_overwrites() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();

    let entries = vec![
        BatchPutEntry {
            key: "batch/a".to_string(),
            value: vec![10],
            metadata: BTreeMap::new(),
        },
        BatchPutEntry {
            key: "batch/b".to_string(),
            value: vec![20],
            metadata: BTreeMap::new(),
        },
    ];
    adapter.put_batch(StoreKind::PlasWitness, entries, &ctx).expect("batch");

    adapter
        .put(StoreKind::PlasWitness, "batch/a".to_string(), vec![99], BTreeMap::new(), &ctx)
        .expect("overwrite");

    let loaded = adapter
        .get(StoreKind::PlasWitness, "batch/a", &ctx)
        .expect("get")
        .expect("exists");
    assert_eq!(loaded.value, vec![99]);

    let b = adapter
        .get(StoreKind::PlasWitness, "batch/b", &ctx)
        .expect("get")
        .expect("exists");
    assert_eq!(b.value, vec![20]);
}

#[test]
fn enrichment_cross_concern_migration_preserves_existing_data() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    adapter
        .put(StoreKind::SpecializationIndex, "spec/1".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect("put");
    adapter
        .put(StoreKind::ReplacementLineage, "rep/1".to_string(), vec![2], BTreeMap::new(), &ctx)
        .expect("put");

    adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).expect("migrate");

    let s = adapter
        .get(StoreKind::SpecializationIndex, "spec/1", &ctx)
        .expect("get")
        .expect("exists");
    assert_eq!(s.value, vec![1]);
    let r = adapter
        .get(StoreKind::ReplacementLineage, "rep/1", &ctx)
        .expect("get")
        .expect("exists");
    assert_eq!(r.value, vec![2]);
}

#[test]
fn enrichment_cross_concern_all_stores_populated_and_queried() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();

    for kind in all_store_kinds() {
        for i in 0..3 {
            adapter
                .put(
                    kind,
                    format!("{}/{i}", kind.as_str()),
                    vec![i as u8],
                    BTreeMap::new(),
                    &ctx,
                )
                .expect("put");
        }
    }

    for kind in all_store_kinds() {
        let rows = adapter
            .query(kind, &StoreQuery::default(), &ctx)
            .expect("query");
        assert_eq!(rows.len(), 3, "store {:?} should have 3 records", kind);
    }
}

#[test]
fn enrichment_cross_concern_events_track_mixed_operations() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();

    adapter
        .put(StoreKind::ReplayIndex, "k".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect("put");
    adapter.get(StoreKind::ReplayIndex, "k", &ctx).expect("get");
    adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &ctx)
        .expect("query");
    adapter.delete(StoreKind::ReplayIndex, "k", &ctx).expect("delete");
    adapter.put_batch(StoreKind::ReplayIndex, vec![], &ctx).expect("batch");

    let events = adapter.events();
    assert_eq!(events.len(), 5);
    let event_names: Vec<&str> = events.iter().map(|e| e.event.as_str()).collect();
    assert_eq!(event_names, vec!["put", "get", "query", "delete", "put_batch"]);
    for e in events {
        assert_eq!(e.outcome, "ok");
        assert!(e.error_code.is_none());
    }
}

#[test]
fn enrichment_cross_concern_frankensqlite_full_lifecycle() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();

    // Put several records
    for i in 0..5 {
        adapter
            .put(
                StoreKind::EvidenceIndex,
                format!("ev/{i:03}"),
                vec![i as u8],
                BTreeMap::new(),
                &ctx,
            )
            .expect("put");
    }

    // Query all
    let all = adapter
        .query(StoreKind::EvidenceIndex, &StoreQuery::default(), &ctx)
        .expect("query all");
    assert_eq!(all.len(), 5);

    // Query with limit
    let limited = adapter
        .query(
            StoreKind::EvidenceIndex,
            &StoreQuery {
                key_prefix: None,
                metadata_filters: BTreeMap::new(),
                limit: Some(2),
            },
            &ctx,
        )
        .expect("query limited");
    assert_eq!(limited.len(), 2);

    // Delete one
    assert!(adapter.delete(StoreKind::EvidenceIndex, "ev/002", &ctx).expect("delete"));

    // Verify deletion
    let after_delete = adapter
        .query(StoreKind::EvidenceIndex, &StoreQuery::default(), &ctx)
        .expect("query after delete");
    assert_eq!(after_delete.len(), 4);

    // Events should track all operations: 5 puts + 3 queries + 1 delete
    assert_eq!(adapter.events().len(), 9);
}

#[test]
fn enrichment_cross_concern_frankensqlite_stores_isolated() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();

    adapter
        .put(StoreKind::ReplayIndex, "shared".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect("put replay");
    adapter
        .put(StoreKind::PolicyCache, "shared".to_string(), vec![2], BTreeMap::new(), &ctx)
        .expect("put policy");

    let replay = adapter
        .get(StoreKind::ReplayIndex, "shared", &ctx)
        .expect("get replay")
        .expect("exists");
    let policy = adapter
        .get(StoreKind::PolicyCache, "shared", &ctx)
        .expect("get policy")
        .expect("exists");
    assert_eq!(replay.value, vec![1]);
    assert_eq!(policy.value, vec![2]);

    adapter.delete(StoreKind::ReplayIndex, "shared", &ctx).expect("delete");
    assert!(adapter.get(StoreKind::ReplayIndex, "shared", &ctx).expect("get").is_none());
    assert!(adapter.get(StoreKind::PolicyCache, "shared", &ctx).expect("get").is_some());
}

#[test]
fn enrichment_in_memory_adapter_serde_roundtrip_preserves_data() {
    let mut adapter = InMemoryStorageAdapter::new();
    let ctx = context();
    adapter
        .put(
            StoreKind::ReplayIndex,
            "serde/test".to_string(),
            vec![1, 2, 3],
            BTreeMap::new(),
            &ctx,
        )
        .expect("put");
    adapter
        .put(
            StoreKind::EvidenceIndex,
            "serde/other".to_string(),
            vec![4, 5, 6],
            BTreeMap::new(),
            &ctx,
        )
        .expect("put");

    let json = serde_json::to_string(&adapter).expect("serialize");
    let mut recovered: InMemoryStorageAdapter = serde_json::from_str(&json).expect("deserialize");

    let r1 = recovered
        .get(StoreKind::ReplayIndex, "serde/test", &ctx)
        .expect("get")
        .expect("exists");
    assert_eq!(r1.value, vec![1, 2, 3]);

    let r2 = recovered
        .get(StoreKind::EvidenceIndex, "serde/other", &ctx)
        .expect("get")
        .expect("exists");
    assert_eq!(r2.value, vec![4, 5, 6]);
}

#[test]
fn enrichment_in_memory_adapter_default_fail_writes_false() {
    let adapter = InMemoryStorageAdapter::new();
    let json = serde_json::to_string(&adapter).expect("serialize");
    assert!(json.contains("\"fail_writes\":false"));
}

#[test]
fn enrichment_storage_schema_version_is_positive() {
    assert!(STORAGE_SCHEMA_VERSION > 0);
}

#[test]
fn enrichment_frankensqlite_query_canonicalizes_reverse_order_backend() {
    let backend = MockFrankensqlite {
        reverse_query_order: true,
        ..MockFrankensqlite::default()
    };
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();

    adapter
        .put(StoreKind::ReplayIndex, "c".to_string(), vec![3], BTreeMap::new(), &ctx)
        .expect("put c");
    adapter
        .put(StoreKind::ReplayIndex, "a".to_string(), vec![1], BTreeMap::new(), &ctx)
        .expect("put a");
    adapter
        .put(StoreKind::ReplayIndex, "b".to_string(), vec![2], BTreeMap::new(), &ctx)
        .expect("put b");

    let rows = adapter
        .query(StoreKind::ReplayIndex, &StoreQuery::default(), &ctx)
        .expect("query");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].key, "a");
    assert_eq!(rows[1].key, "b");
    assert_eq!(rows[2].key, "c");
}

#[test]
fn enrichment_frankensqlite_query_zero_limit_records_error_event() {
    let backend = MockFrankensqlite::default();
    let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("init");
    let ctx = context();
    let _ = adapter.query(
        StoreKind::ReplayIndex,
        &StoreQuery {
            key_prefix: None,
            metadata_filters: BTreeMap::new(),
            limit: Some(0),
        },
        &ctx,
    );
    let events = adapter.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].outcome, "error");
    assert_eq!(events[0].error_code.as_deref(), Some("FE-STOR-0003"));
}
