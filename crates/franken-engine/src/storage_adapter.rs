//! Storage adapter boundary for deterministic FrankenEngine persistence paths.
//!
//! This module introduces a thin adapter layer between runtime persistence
//! contracts and `/dp/frankensqlite` backends. The interface is intentionally
//! store-agnostic and deterministic:
//! - stable query ordering
//! - explicit schema version checks and migration receipts
//! - structured operation events with canonical logging fields
//!
//! Plan references: Section 10.14 item 6 (`bd-89l2`), ADR-0004.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::typed_persistence_models::{
    TypedFrankenSqliteSession, open_typed_frankensqlite_memory_session,
};

/// Current schema version for storage-adapter contracts.
pub const STORAGE_SCHEMA_VERSION: u32 = 1;
pub(crate) const TYPED_HEAVY_GENERIC_ACCESS_MODE_KEY: &str = "typed_authority_mode";
pub(crate) const TYPED_HEAVY_GENERIC_COMPAT_MODE_VALUE: &str = "explicit_legacy_compat_v1";
const TYPED_HEAVY_BACKFILL_QUERY_MODE_VALUE: &str = "explicit_legacy_backfill_planning_v1";
const TYPED_RECORD_FORMAT_KEY: &str = "record_format";
const TYPED_RECORD_FORMAT_VALUE: &str = "sqlmodel_rust_typed_v1";
const TYPED_MODEL_KEY: &str = "typed_model";
const TYPED_STORE_KIND_KEY: &str = "store_kind";
const TYPED_RECORD_ID_KEY: &str = "typed_record_id";

/// Canonical control-plane stores mapped in the persistence inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum StoreKind {
    ReplayIndex,
    EvidenceIndex,
    ShadowEvidenceJournal,
    BenchmarkLedger,
    PolicyCache,
    PlasWitness,
    ReplacementLineage,
    IfcProvenance,
    SpecializationIndex,
}

impl StoreKind {
    /// Stable string name used in logs and deterministic serialization.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ReplayIndex => "replay_index",
            Self::EvidenceIndex => "evidence_index",
            Self::ShadowEvidenceJournal => "shadow_evidence_journal",
            Self::BenchmarkLedger => "benchmark_ledger",
            Self::PolicyCache => "policy_cache",
            Self::PlasWitness => "plas_witness",
            Self::ReplacementLineage => "replacement_lineage",
            Self::IfcProvenance => "ifc_provenance",
            Self::SpecializationIndex => "specialization_index",
        }
    }

    /// Inventory-mapped integration point for the store.
    ///
    /// Typed-heavy stores use sqlmodel_rust boundaries for compile-time schema validation,
    /// while generic stores continue using frankensqlite integration points.
    pub fn integration_point(self) -> &'static str {
        match self {
            Self::ReplayIndex => "frankensqlite::control_plane::replay_index",
            Self::EvidenceIndex => "frankensqlite::control_plane::evidence_index",
            Self::ShadowEvidenceJournal => "sqlmodel_rust::ShadowEvidenceJournalEntry",
            Self::BenchmarkLedger => "frankensqlite::benchmark::ledger",
            Self::PolicyCache => "frankensqlite::control_plane::policy_cache",
            Self::PlasWitness => "frankensqlite::analysis::plas_witness",
            // Typed-heavy stores use sqlmodel_rust typed boundaries
            Self::ReplacementLineage => "sqlmodel_rust::ReplacementLineageEntry",
            Self::IfcProvenance => "sqlmodel_rust::IfcProvenanceEntry",
            Self::SpecializationIndex => "sqlmodel_rust::SpecializationIndexEntry",
        }
    }
}

impl fmt::Display for StoreKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

pub(crate) fn mark_typed_heavy_generic_compat_metadata(metadata: &mut BTreeMap<String, String>) {
    metadata.insert(
        TYPED_HEAVY_GENERIC_ACCESS_MODE_KEY.to_string(),
        TYPED_HEAVY_GENERIC_COMPAT_MODE_VALUE.to_string(),
    );
}

fn is_typed_heavy_store(store: StoreKind) -> bool {
    matches!(
        store,
        StoreKind::ShadowEvidenceJournal
            | StoreKind::ReplacementLineage
            | StoreKind::IfcProvenance
            | StoreKind::SpecializationIndex
    )
}

fn typed_store_prefix(store: StoreKind) -> String {
    format!("typed/{}/", store.as_str())
}

fn typed_heavy_legacy_prefixes(store: StoreKind) -> &'static [&'static str] {
    match store {
        StoreKind::ReplacementLineage => &[
            "replacement_receipts/",
            "demotion_receipts/",
            "lineage_chain/",
            "replacement_by_hash/",
            "demotion_by_hash/",
        ],
        StoreKind::IfcProvenance => &[
            "flow_event::",
            "flow_proof::",
            "declass_receipt::",
            "confinement_claim::",
        ],
        StoreKind::SpecializationIndex => &["receipt:", "benchmark:", "invalidation:"],
        StoreKind::ShadowEvidenceJournal => &[],
        _ => &[],
    }
}

fn typed_heavy_key_is_recognized(store: StoreKind, key: &str) -> bool {
    let typed_prefix = typed_store_prefix(store);
    key.starts_with(&typed_prefix)
        || typed_heavy_legacy_prefixes(store)
            .iter()
            .any(|prefix| key.starts_with(prefix))
}

fn typed_heavy_put_is_current_typed_envelope(
    store: StoreKind,
    key: &str,
    metadata: &BTreeMap<String, String>,
) -> bool {
    let typed_prefix = typed_store_prefix(store);
    key.starts_with(&typed_prefix)
        && metadata
            .get(TYPED_RECORD_FORMAT_KEY)
            .is_some_and(|format| format == TYPED_RECORD_FORMAT_VALUE)
        && metadata.contains_key(TYPED_MODEL_KEY)
        && metadata
            .get(TYPED_STORE_KIND_KEY)
            .is_some_and(|store_kind| store_kind == store.as_str())
        && metadata.contains_key(TYPED_RECORD_ID_KEY)
}

fn typed_heavy_put_is_explicit_legacy_compat(
    store: StoreKind,
    key: &str,
    metadata: &BTreeMap<String, String>,
) -> bool {
    typed_heavy_legacy_prefixes(store)
        .iter()
        .any(|prefix| key.starts_with(prefix))
        && metadata
            .get(TYPED_HEAVY_GENERIC_ACCESS_MODE_KEY)
            .is_some_and(|mode| mode == TYPED_HEAVY_GENERIC_COMPAT_MODE_VALUE)
}

fn typed_heavy_write_policy_error(store: StoreKind, operation: &str, key: &str) -> StorageError {
    StorageError::WriteRejected {
        detail: format!(
            "generic {operation} on typed-heavy store {store} for key `{key}` is non-authoritative; use a sqlmodel_rust typed envelope or an explicitly marked legacy compatibility row"
        ),
    }
}

fn typed_heavy_read_policy_error(
    store: StoreKind,
    operation: &str,
    detail: String,
) -> StorageError {
    StorageError::IntegrityViolation {
        store,
        detail: format!(
            "generic {operation} on typed-heavy store {store} is non-authoritative: {detail}"
        ),
    }
}

fn enforce_typed_heavy_put_policy(
    store: StoreKind,
    key: &str,
    metadata: &BTreeMap<String, String>,
) -> Result<(), StorageError> {
    if !is_typed_heavy_store(store) {
        return Ok(());
    }
    if typed_heavy_put_is_current_typed_envelope(store, key, metadata)
        || typed_heavy_put_is_explicit_legacy_compat(store, key, metadata)
    {
        return Ok(());
    }
    Err(typed_heavy_write_policy_error(store, "put", key))
}

fn enforce_typed_heavy_key_access_policy(
    store: StoreKind,
    key: &str,
    operation: &str,
) -> Result<(), StorageError> {
    if !is_typed_heavy_store(store) || typed_heavy_key_is_recognized(store, key) {
        return Ok(());
    }
    Err(typed_heavy_read_policy_error(
        store,
        operation,
        format!(
            "key `{key}` is neither a typed `{}` envelope nor a recognized compatibility prefix",
            typed_store_prefix(store)
        ),
    ))
}

fn enforce_typed_heavy_query_policy(
    store: StoreKind,
    query: &StoreQuery,
) -> Result<(), StorageError> {
    if !is_typed_heavy_store(store) {
        return Ok(());
    }

    if let Some(prefix) = &query.key_prefix {
        if typed_heavy_key_is_recognized(store, prefix) {
            return Ok(());
        }
        return Err(typed_heavy_read_policy_error(
            store,
            "query",
            format!("key_prefix `{prefix}` is not a typed or recognized compatibility prefix"),
        ));
    }

    if query
        .metadata_filters
        .get(TYPED_HEAVY_GENERIC_ACCESS_MODE_KEY)
        .is_some_and(|mode| mode == TYPED_HEAVY_BACKFILL_QUERY_MODE_VALUE)
    {
        return Ok(());
    }

    Err(typed_heavy_read_policy_error(
        store,
        "query",
        "unscoped generic scans require an explicit backfill-planning marker".to_string(),
    ))
}

/// Canonical context carried into adapter operations.
///
/// Field names intentionally match required structured log keys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventContext {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

impl EventContext {
    /// Build a validated operation context.
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
    ) -> Result<Self, StorageError> {
        let trace_id = trace_id.into();
        let decision_id = decision_id.into();
        let policy_id = policy_id.into();
        if trace_id.trim().is_empty() {
            return Err(StorageError::InvalidContext {
                field: "trace_id".to_string(),
            });
        }
        if decision_id.trim().is_empty() {
            return Err(StorageError::InvalidContext {
                field: "decision_id".to_string(),
            });
        }
        if policy_id.trim().is_empty() {
            return Err(StorageError::InvalidContext {
                field: "policy_id".to_string(),
            });
        }
        Ok(Self {
            trace_id,
            decision_id,
            policy_id,
        })
    }
}

/// Stored value with deterministic metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreRecord {
    pub store: StoreKind,
    pub key: String,
    pub value: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
    pub revision: u64,
}

/// Query selector for deterministic reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct StoreQuery {
    /// Optional key prefix filter.
    pub key_prefix: Option<String>,
    /// Equality filters that must all match.
    pub metadata_filters: BTreeMap<String, String>,
    /// Optional max result size.
    pub limit: Option<usize>,
}

/// Batched write entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchPutEntry {
    pub key: String,
    pub value: Vec<u8>,
    pub metadata: BTreeMap<String, String>,
}

/// Deterministic migration receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationReceipt {
    pub backend: String,
    pub from_version: u32,
    pub to_version: u32,
    pub stores_touched: Vec<StoreKind>,
    pub records_touched: u64,
    pub state_hash_before: String,
    pub state_hash_after: String,
}

/// Canonical structured event emitted by adapter operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

/// Stable error taxonomy for storage operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageError {
    InvalidContext { field: String },
    InvalidKey { key: String },
    InvalidQuery { detail: String },
    NotFound { store: StoreKind, key: String },
    SchemaVersionMismatch { expected: u32, actual: u32 },
    MigrationFailed { from: u32, to: u32, reason: String },
    IntegrityViolation { store: StoreKind, detail: String },
    BackendUnavailable { backend: String, detail: String },
    WriteRejected { detail: String },
}

impl StorageError {
    /// Stable machine-readable error code.
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidContext { .. } => "FE-STOR-0001",
            Self::InvalidKey { .. } => "FE-STOR-0002",
            Self::InvalidQuery { .. } => "FE-STOR-0003",
            Self::NotFound { .. } => "FE-STOR-0004",
            Self::SchemaVersionMismatch { .. } => "FE-STOR-0005",
            Self::MigrationFailed { .. } => "FE-STOR-0006",
            Self::IntegrityViolation { .. } => "FE-STOR-0007",
            Self::BackendUnavailable { .. } => "FE-STOR-0008",
            Self::WriteRejected { .. } => "FE-STOR-0009",
        }
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidContext { field } => write!(f, "invalid context field: {field}"),
            Self::InvalidKey { key } => write!(f, "invalid key: `{key}`"),
            Self::InvalidQuery { detail } => write!(f, "invalid query: {detail}"),
            Self::NotFound { store, key } => write!(f, "record not found: {store}/{key}"),
            Self::SchemaVersionMismatch { expected, actual } => {
                write!(
                    f,
                    "schema version mismatch: expected {expected}, got {actual}"
                )
            }
            Self::MigrationFailed { from, to, reason } => {
                write!(f, "migration failed: {from} -> {to}: {reason}")
            }
            Self::IntegrityViolation { store, detail } => {
                write!(f, "integrity violation in {store}: {detail}")
            }
            Self::BackendUnavailable { backend, detail } => {
                write!(f, "backend unavailable ({backend}): {detail}")
            }
            Self::WriteRejected { detail } => write!(f, "write rejected: {detail}"),
        }
    }
}

impl std::error::Error for StorageError {}

/// Generic storage adapter contract.
pub trait StorageAdapter {
    /// Adapter backend identifier.
    fn backend_name(&self) -> &'static str;
    /// Current schema version.
    fn current_schema_version(&self) -> u32;
    /// Fail-closed schema check for callers requiring a specific version.
    fn ensure_schema_version(&self, expected: u32) -> Result<(), StorageError>;
    /// Apply deterministic schema migration.
    fn migrate_to(&mut self, target_version: u32) -> Result<MigrationReceipt, StorageError>;

    fn put(
        &mut self,
        store: StoreKind,
        key: String,
        value: Vec<u8>,
        metadata: BTreeMap<String, String>,
        context: &EventContext,
    ) -> Result<StoreRecord, StorageError>;

    fn get(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<Option<StoreRecord>, StorageError>;

    fn query(
        &mut self,
        store: StoreKind,
        query: &StoreQuery,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError>;

    fn delete(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<bool, StorageError>;

    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: Vec<BatchPutEntry>,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError>;

    fn events(&self) -> &[StorageEvent];
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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

/// Deterministic in-memory adapter used for tests and local workflows.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InMemoryStorageAdapter {
    schema_version: u32,
    stores: BTreeMap<StoreKind, StoreState>,
    events: Vec<StorageEvent>,
    fail_writes: bool,
}

impl Default for InMemoryStorageAdapter {
    fn default() -> Self {
        Self {
            schema_version: STORAGE_SCHEMA_VERSION,
            stores: BTreeMap::new(),
            events: Vec::new(),
            fail_writes: false,
        }
    }
}

impl InMemoryStorageAdapter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Optional failure-injection mode for tests.
    pub fn with_fail_writes(mut self, fail_writes: bool) -> Self {
        self.fail_writes = fail_writes;
        self
    }

    fn validate_key(key: &str) -> Result<(), StorageError> {
        if key.trim().is_empty() {
            return Err(StorageError::InvalidKey {
                key: key.to_string(),
            });
        }
        Ok(())
    }

    fn get_or_insert_state(&mut self, store: StoreKind) -> &mut StoreState {
        self.stores.entry(store).or_default()
    }

    fn record_event(
        &mut self,
        context: &EventContext,
        event: &str,
        outcome: &str,
        error: Option<&StorageError>,
    ) {
        self.events.push(StorageEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: "storage_adapter".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error.map(|err| err.code().to_string()),
        });
    }

    fn state_hash(&self) -> String {
        let bytes = serde_json::to_vec(&(self.schema_version, &self.stores))
            .expect("storage adapter state should serialize for hashing");
        digest_hex(&bytes)
    }

    fn total_records(&self) -> u64 {
        self.stores
            .values()
            .map(|state| state.records.len() as u64)
            .sum()
    }

    pub fn events(&self) -> &[StorageEvent] {
        &self.events
    }
}

impl StorageAdapter for InMemoryStorageAdapter {
    fn backend_name(&self) -> &'static str {
        "in_memory"
    }

    fn current_schema_version(&self) -> u32 {
        self.schema_version
    }

    fn ensure_schema_version(&self, expected: u32) -> Result<(), StorageError> {
        if self.schema_version == expected {
            Ok(())
        } else {
            Err(StorageError::SchemaVersionMismatch {
                expected,
                actual: self.schema_version,
            })
        }
    }

    fn migrate_to(&mut self, target_version: u32) -> Result<MigrationReceipt, StorageError> {
        if target_version < self.schema_version {
            return Err(StorageError::MigrationFailed {
                from: self.schema_version,
                to: target_version,
                reason: "downgrade is not supported".to_string(),
            });
        }
        if target_version > self.schema_version.saturating_add(1) {
            return Err(StorageError::MigrationFailed {
                from: self.schema_version,
                to: target_version,
                reason: "only single-step migrations are allowed".to_string(),
            });
        }

        let from_version = self.schema_version;
        let state_hash_before = self.state_hash();
        self.schema_version = target_version;
        let state_hash_after = self.state_hash();
        let stores_touched = self.stores.keys().copied().collect();

        Ok(MigrationReceipt {
            backend: self.backend_name().to_string(),
            from_version,
            to_version: target_version,
            stores_touched,
            records_touched: self.total_records(),
            state_hash_before,
            state_hash_after,
        })
    }

    fn put(
        &mut self,
        store: StoreKind,
        key: String,
        value: Vec<u8>,
        metadata: BTreeMap<String, String>,
        context: &EventContext,
    ) -> Result<StoreRecord, StorageError> {
        let result = (|| {
            if self.fail_writes {
                return Err(StorageError::WriteRejected {
                    detail: "write failure injected".to_string(),
                });
            }
            Self::validate_key(&key)?;
            enforce_typed_heavy_put_policy(store, &key, &metadata)?;
            Ok(self
                .get_or_insert_state(store)
                .put(store, key, value, metadata))
        })();

        self.record_event(
            context,
            "put",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn get(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<Option<StoreRecord>, StorageError> {
        let result = (|| {
            Self::validate_key(key)?;
            enforce_typed_heavy_key_access_policy(store, key, "get")?;
            Ok(self
                .stores
                .get(&store)
                .and_then(|state| state.records.get(key).cloned()))
        })();

        self.record_event(
            context,
            "get",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn query(
        &mut self,
        store: StoreKind,
        query: &StoreQuery,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError> {
        let result = (|| {
            if matches!(query.limit, Some(0)) {
                return Err(StorageError::InvalidQuery {
                    detail: "limit cannot be zero".to_string(),
                });
            }
            enforce_typed_heavy_query_policy(store, query)?;

            let Some(state) = self.stores.get(&store) else {
                return Ok(Vec::new());
            };

            let out: Vec<StoreRecord> = state
                .records
                .values()
                .filter(|record| {
                    if let Some(prefix) = &query.key_prefix
                        && !record.key.starts_with(prefix)
                    {
                        return false;
                    }
                    query
                        .metadata_filters
                        .iter()
                        .all(|(k, v)| record.metadata.get(k) == Some(v))
                })
                .cloned()
                .collect();

            Ok(canonicalize_records(out, query.limit))
        })();

        self.record_event(
            context,
            "query",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn delete(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<bool, StorageError> {
        let result = (|| {
            if self.fail_writes {
                return Err(StorageError::WriteRejected {
                    detail: "write failure injected".to_string(),
                });
            }
            Self::validate_key(key)?;
            enforce_typed_heavy_key_access_policy(store, key, "delete")?;
            Ok(self
                .stores
                .get_mut(&store)
                .and_then(|state| state.records.remove(key))
                .is_some())
        })();

        self.record_event(
            context,
            "delete",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: Vec<BatchPutEntry>,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError> {
        let result = (|| {
            if self.fail_writes {
                return Err(StorageError::WriteRejected {
                    detail: "write failure injected".to_string(),
                });
            }
            let mut staged = self.stores.get(&store).cloned().unwrap_or_default();
            let mut out = Vec::with_capacity(entries.len());
            for entry in entries {
                Self::validate_key(&entry.key)?;
                enforce_typed_heavy_put_policy(store, &entry.key, &entry.metadata)?;
                out.push(staged.put(store, entry.key, entry.value, entry.metadata));
            }
            self.stores.insert(store, staged);
            Ok(out)
        })();

        self.record_event(
            context,
            "put_batch",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn events(&self) -> &[StorageEvent] {
        self.events()
    }
}

/// Minimal backend contract expected from `/dp/frankensqlite` integration.
///
/// This seam lets `franken_engine` depend on stable adapter behavior without
/// owning WAL/PRAGMA/migration internals locally.
pub trait FrankensqliteBackend {
    /// Apply the backend-owned control-plane durability/profile policy.
    ///
    /// Implementations are expected to delegate this to `/dp/frankensqlite`.
    /// FrankenEngine must not hard-code PRAGMA names, PRAGMA values, or journal
    /// mode choices here; those remain sibling-repo policy.
    fn apply_control_plane_profile(&mut self) -> Result<(), String>;
    fn current_schema_version(&self) -> Result<u32, String>;
    fn migrate_to(&mut self, target_version: u32) -> Result<(), String>;
    fn put_record(
        &mut self,
        store: StoreKind,
        key: &str,
        value: &[u8],
        metadata: &BTreeMap<String, String>,
    ) -> Result<StoreRecord, String>;
    fn get_record(&self, store: StoreKind, key: &str) -> Result<Option<StoreRecord>, String>;
    fn query_records(
        &self,
        store: StoreKind,
        query: &StoreQuery,
    ) -> Result<Vec<StoreRecord>, String>;
    fn delete_record(&mut self, store: StoreKind, key: &str) -> Result<bool, String>;
    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: &[BatchPutEntry],
    ) -> Result<Vec<StoreRecord>, String>;
}

/// Adapter implementation backed by a frankensqlite integration backend.
pub struct FrankensqliteStorageAdapter<B: FrankensqliteBackend> {
    backend: B,
    schema_version: u32,
    events: Vec<StorageEvent>,
    /// Optional typed SQLModel session for ReplacementLineage, ShadowEvidenceJournal,
    /// IfcProvenance, EvidenceIndex, and SpecializationIndex stores.
    /// When present, typed operations use SQLModel boundaries instead of generic record operations.
    typed_session: Option<TypedFrankenSqliteSession>,
}

impl<B> fmt::Debug for FrankensqliteStorageAdapter<B>
where
    B: FrankensqliteBackend + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrankensqliteStorageAdapter")
            .field("backend", &self.backend)
            .field("schema_version", &self.schema_version)
            .field("events", &self.events)
            .field("typed_session_present", &self.typed_session.is_some())
            .finish()
    }
}

impl<B: FrankensqliteBackend> FrankensqliteStorageAdapter<B> {
    pub fn new(mut backend: B) -> Result<Self, StorageError> {
        backend.apply_control_plane_profile().map_err(|detail| {
            StorageError::BackendUnavailable {
                backend: "frankensqlite".to_string(),
                detail,
            }
        })?;

        let schema_version = backend.current_schema_version().map_err(|detail| {
            StorageError::BackendUnavailable {
                backend: "frankensqlite".to_string(),
                detail,
            }
        })?;

        Ok(Self {
            backend,
            schema_version,
            events: Vec::new(),
            typed_session: None,
        })
    }

    /// Create a new storage adapter with typed SQLModel session enabled for typed persistence operations.
    ///
    /// This enables typed operations for ReplacementLineage, ShadowEvidenceJournal,
    /// IfcProvenance, EvidenceIndex, and SpecializationIndex stores
    /// using SQLModel boundaries instead of generic record operations. Uses in-memory typed session
    /// for development/testing; production callers should extend this to use file-backed sessions.
    pub fn new_with_typed_session(mut backend: B) -> Result<Self, StorageError> {
        backend.apply_control_plane_profile().map_err(|detail| {
            StorageError::BackendUnavailable {
                backend: "frankensqlite".to_string(),
                detail,
            }
        })?;

        let schema_version = backend.current_schema_version().map_err(|detail| {
            StorageError::BackendUnavailable {
                backend: "frankensqlite".to_string(),
                detail,
            }
        })?;

        // Initialize typed session for SQLModel operations
        let typed_session = open_typed_frankensqlite_memory_session().map_err(|err| {
            StorageError::BackendUnavailable {
                backend: "frankensqlite_typed".to_string(),
                detail: format!("failed to initialize typed SQLModel session: {}", err),
            }
        })?;

        Ok(Self {
            backend,
            schema_version,
            events: Vec::new(),
            typed_session: Some(typed_session),
        })
    }

    /// Check if typed SQLModel session is available for typed store operations.
    pub fn has_typed_session(&self) -> bool {
        self.typed_session.is_some()
    }

    /// Get immutable reference to typed session if available.
    pub fn typed_session(&self) -> Option<&TypedFrankenSqliteSession> {
        self.typed_session.as_ref()
    }

    /// Get mutable reference to typed session if available.
    pub fn typed_session_mut(&mut self) -> Option<&mut TypedFrankenSqliteSession> {
        self.typed_session.as_mut()
    }

    fn map_backend_error(detail: String) -> StorageError {
        StorageError::BackendUnavailable {
            backend: "frankensqlite".to_string(),
            detail,
        }
    }

    fn record_event(
        &mut self,
        context: &EventContext,
        event: &str,
        outcome: &str,
        error: Option<&StorageError>,
    ) {
        self.events.push(StorageEvent {
            trace_id: context.trace_id.clone(),
            decision_id: context.decision_id.clone(),
            policy_id: context.policy_id.clone(),
            component: "storage_adapter".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error.map(|err| err.code().to_string()),
        });
    }
}

impl<B: FrankensqliteBackend> StorageAdapter for FrankensqliteStorageAdapter<B> {
    fn backend_name(&self) -> &'static str {
        "frankensqlite"
    }

    fn current_schema_version(&self) -> u32 {
        self.schema_version
    }

    fn ensure_schema_version(&self, expected: u32) -> Result<(), StorageError> {
        if self.schema_version == expected {
            Ok(())
        } else {
            Err(StorageError::SchemaVersionMismatch {
                expected,
                actual: self.schema_version,
            })
        }
    }

    fn migrate_to(&mut self, target_version: u32) -> Result<MigrationReceipt, StorageError> {
        if target_version < self.schema_version {
            return Err(StorageError::MigrationFailed {
                from: self.schema_version,
                to: target_version,
                reason: "downgrade is not supported".to_string(),
            });
        }
        if target_version > self.schema_version.saturating_add(1) {
            return Err(StorageError::MigrationFailed {
                from: self.schema_version,
                to: target_version,
                reason: "only single-step migrations are allowed".to_string(),
            });
        }

        let from_version = self.schema_version;
        let state_hash_before = digest_hex(format!("schema:{from_version}").as_bytes());
        self.backend
            .migrate_to(target_version)
            .map_err(Self::map_backend_error)?;
        self.schema_version = target_version;
        let state_hash_after = digest_hex(format!("schema:{target_version}").as_bytes());

        Ok(MigrationReceipt {
            backend: self.backend_name().to_string(),
            from_version,
            to_version: target_version,
            stores_touched: Vec::new(),
            records_touched: 0,
            state_hash_before,
            state_hash_after,
        })
    }

    fn put(
        &mut self,
        store: StoreKind,
        key: String,
        value: Vec<u8>,
        metadata: BTreeMap<String, String>,
        context: &EventContext,
    ) -> Result<StoreRecord, StorageError> {
        let result = (|| {
            InMemoryStorageAdapter::validate_key(&key)?;
            enforce_typed_heavy_put_policy(store, &key, &metadata)?;
            self.backend
                .put_record(store, &key, &value, &metadata)
                .map_err(Self::map_backend_error)
        })();

        self.record_event(
            context,
            "put",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn get(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<Option<StoreRecord>, StorageError> {
        let result = (|| {
            InMemoryStorageAdapter::validate_key(key)?;
            enforce_typed_heavy_key_access_policy(store, key, "get")?;
            self.backend
                .get_record(store, key)
                .map_err(Self::map_backend_error)
        })();

        self.record_event(
            context,
            "get",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn query(
        &mut self,
        store: StoreKind,
        query: &StoreQuery,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError> {
        let result = (|| {
            if matches!(query.limit, Some(0)) {
                return Err(StorageError::InvalidQuery {
                    detail: "limit cannot be zero".to_string(),
                });
            }
            enforce_typed_heavy_query_policy(store, query)?;

            // Query without a limit first, then canonicalize and truncate locally.
            // This prevents backend row-order variation from changing visible results.
            let mut unconstrained = query.clone();
            unconstrained.limit = None;

            let rows = self
                .backend
                .query_records(store, &unconstrained)
                .map_err(Self::map_backend_error)?;
            Ok(canonicalize_records(rows, query.limit))
        })();

        self.record_event(
            context,
            "query",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn delete(
        &mut self,
        store: StoreKind,
        key: &str,
        context: &EventContext,
    ) -> Result<bool, StorageError> {
        let result = (|| {
            InMemoryStorageAdapter::validate_key(key)?;
            enforce_typed_heavy_key_access_policy(store, key, "delete")?;
            self.backend
                .delete_record(store, key)
                .map_err(Self::map_backend_error)
        })();

        self.record_event(
            context,
            "delete",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn put_batch(
        &mut self,
        store: StoreKind,
        entries: Vec<BatchPutEntry>,
        context: &EventContext,
    ) -> Result<Vec<StoreRecord>, StorageError> {
        let result = (|| {
            for entry in &entries {
                InMemoryStorageAdapter::validate_key(&entry.key)?;
                enforce_typed_heavy_put_policy(store, &entry.key, &entry.metadata)?;
            }
            self.backend
                .put_batch(store, &entries)
                .map_err(Self::map_backend_error)
        })();

        self.record_event(
            context,
            "put_batch",
            if result.is_ok() { "ok" } else { "error" },
            result.as_ref().err(),
        );
        result
    }

    fn events(&self) -> &[StorageEvent] {
        &self.events
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    format!("{:016x}", fnv1a64(bytes))
}

fn canonicalize_records(mut rows: Vec<StoreRecord>, limit: Option<usize>) -> Vec<StoreRecord> {
    rows.sort_by(|a, b| {
        a.key
            .cmp(&b.key)
            .then(a.revision.cmp(&b.revision))
            .then(a.value.cmp(&b.value))
            .then(a.metadata.cmp(&b.metadata))
    });

    if let Some(limit) = limit {
        rows.truncate(limit);
    }
    rows
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;

    let mut hash = OFFSET;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> EventContext {
        EventContext::new("trace-storage", "decision-storage", "policy-storage")
            .expect("context should be valid")
    }

    #[test]
    fn in_memory_adapter_crud_and_query_are_deterministic() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();

        let mut meta_a = BTreeMap::new();
        meta_a.insert("kind".to_string(), "benchmark".to_string());
        let mut meta_b = BTreeMap::new();
        meta_b.insert("kind".to_string(), "benchmark".to_string());

        adapter
            .put(
                StoreKind::BenchmarkLedger,
                "bench/z".to_string(),
                vec![2],
                meta_a,
                &context,
            )
            .expect("put z");
        adapter
            .put(
                StoreKind::BenchmarkLedger,
                "bench/a".to_string(),
                vec![1],
                meta_b,
                &context,
            )
            .expect("put a");

        let rows = adapter
            .query(StoreKind::BenchmarkLedger, &StoreQuery::default(), &context)
            .expect("query");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].key, "bench/a");
        assert_eq!(rows[1].key, "bench/z");

        let loaded = adapter
            .get(StoreKind::BenchmarkLedger, "bench/a", &context)
            .expect("get")
            .expect("must exist");
        assert_eq!(loaded.value, vec![1]);

        assert!(
            adapter
                .delete(StoreKind::BenchmarkLedger, "bench/z", &context)
                .expect("delete")
        );
    }

    #[test]
    fn in_memory_batch_put_is_atomic_on_invalid_key() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();

        adapter
            .put(
                StoreKind::ReplayIndex,
                "run/seed".to_string(),
                vec![9],
                BTreeMap::new(),
                &context,
            )
            .expect("seed row");

        let bad_batch = vec![
            BatchPutEntry {
                key: "run/1".to_string(),
                value: vec![1],
                metadata: BTreeMap::new(),
            },
            BatchPutEntry {
                key: "   ".to_string(),
                value: vec![2],
                metadata: BTreeMap::new(),
            },
        ];

        let err = adapter
            .put_batch(StoreKind::ReplayIndex, bad_batch, &context)
            .expect_err("batch should fail");
        assert!(matches!(err, StorageError::InvalidKey { .. }));

        let rows = adapter
            .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
            .expect("query");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key, "run/seed");
    }

    #[test]
    fn in_memory_migration_receipt_is_deterministic() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();

        adapter
            .put(
                StoreKind::EvidenceIndex,
                "decision/1".to_string(),
                vec![7, 7],
                BTreeMap::new(),
                &context,
            )
            .expect("put");

        let receipt = adapter
            .migrate_to(STORAGE_SCHEMA_VERSION + 1)
            .expect("migrate");
        assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
        assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION + 1);
        assert_eq!(receipt.records_touched, 1);
        assert_ne!(receipt.state_hash_before, receipt.state_hash_after);
    }

    #[test]
    fn events_include_required_structured_fields() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();

        let err = adapter
            .put(
                StoreKind::PolicyCache,
                "".to_string(),
                vec![1],
                BTreeMap::new(),
                &context,
            )
            .expect_err("invalid key must fail");
        assert_eq!(err.code(), "FE-STOR-0002");

        let event = adapter.events().last().expect("event");
        assert_eq!(event.trace_id, "trace-storage");
        assert_eq!(event.decision_id, "decision-storage");
        assert_eq!(event.policy_id, "policy-storage");
        assert_eq!(event.component, "storage_adapter");
        assert_eq!(event.event, "put");
        assert_eq!(event.outcome, "error");
        assert_eq!(event.error_code.as_deref(), Some("FE-STOR-0002"));
    }

    #[derive(Debug, Default)]
    struct MockFrankenSqlite {
        control_plane_profile_applied: bool,
        schema_version: u32,
        stores: BTreeMap<StoreKind, StoreState>,
    }

    impl FrankensqliteBackend for MockFrankenSqlite {
        fn apply_control_plane_profile(&mut self) -> Result<(), String> {
            self.control_plane_profile_applied = true;
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
            let state = self.stores.entry(store).or_default();
            Ok(state.put(store, key.to_string(), value.to_vec(), metadata.clone()))
        }

        fn get_record(&self, store: StoreKind, key: &str) -> Result<Option<StoreRecord>, String> {
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
            let mut staged = self.stores.get(&store).cloned().unwrap_or_default();
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

    #[test]
    fn frankensqlite_adapter_delegates_control_plane_profile() {
        let backend = MockFrankenSqlite::default();
        let adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
        assert_eq!(adapter.current_schema_version(), STORAGE_SCHEMA_VERSION);
    }

    // ── EventContext validation ──────────────────────────────────────────

    #[test]
    fn event_context_valid() {
        let ctx = EventContext::new("t", "d", "p").expect("serde deserialization should succeed");
        assert_eq!(ctx.trace_id, "t");
        assert_eq!(ctx.decision_id, "d");
        assert_eq!(ctx.policy_id, "p");
    }

    #[test]
    fn event_context_empty_trace_id_errors() {
        let err = EventContext::new("", "d", "p").unwrap_err();
        assert!(matches!(err, StorageError::InvalidContext { field } if field == "trace_id"));
    }

    #[test]
    fn event_context_empty_decision_id_errors() {
        let err = EventContext::new("t", "  ", "p").unwrap_err();
        assert!(matches!(err, StorageError::InvalidContext { field } if field == "decision_id"));
    }

    #[test]
    fn event_context_empty_policy_id_errors() {
        let err = EventContext::new("t", "d", "").unwrap_err();
        assert!(matches!(err, StorageError::InvalidContext { field } if field == "policy_id"));
    }

    // ── StoreKind ────────────────────────────────────────────────────────

    #[test]
    fn store_kind_as_str_exhaustive() {
        let cases = [
            (StoreKind::ReplayIndex, "replay_index"),
            (StoreKind::EvidenceIndex, "evidence_index"),
            (StoreKind::ShadowEvidenceJournal, "shadow_evidence_journal"),
            (StoreKind::BenchmarkLedger, "benchmark_ledger"),
            (StoreKind::PolicyCache, "policy_cache"),
            (StoreKind::PlasWitness, "plas_witness"),
            (StoreKind::ReplacementLineage, "replacement_lineage"),
            (StoreKind::IfcProvenance, "ifc_provenance"),
            (StoreKind::SpecializationIndex, "specialization_index"),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.as_str(), expected, "StoreKind::{kind:?}");
        }
    }

    #[test]
    fn store_kind_integration_point_exhaustive() {
        let cases = [
            (
                StoreKind::ReplayIndex,
                "frankensqlite::control_plane::replay_index",
            ),
            (
                StoreKind::EvidenceIndex,
                "frankensqlite::control_plane::evidence_index",
            ),
            (
                StoreKind::ShadowEvidenceJournal,
                "sqlmodel_rust::ShadowEvidenceJournalEntry",
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
                "sqlmodel_rust::ReplacementLineageEntry",
            ),
            (
                StoreKind::IfcProvenance,
                "sqlmodel_rust::IfcProvenanceEntry",
            ),
            (
                StoreKind::SpecializationIndex,
                "sqlmodel_rust::SpecializationIndexEntry",
            ),
        ];
        for (kind, expected) in cases {
            assert_eq!(kind.integration_point(), expected, "StoreKind::{kind:?}");
        }
    }

    #[test]
    fn store_kind_display_matches_as_str() {
        for kind in [
            StoreKind::ReplayIndex,
            StoreKind::EvidenceIndex,
            StoreKind::ShadowEvidenceJournal,
            StoreKind::BenchmarkLedger,
            StoreKind::PolicyCache,
            StoreKind::PlasWitness,
            StoreKind::ReplacementLineage,
            StoreKind::IfcProvenance,
            StoreKind::SpecializationIndex,
        ] {
            assert_eq!(format!("{kind}"), kind.as_str());
        }
    }

    #[test]
    fn store_kind_serde_round_trip() {
        let kind = StoreKind::PlasWitness;
        let json = serde_json::to_string(&kind).expect("serde deserialization should succeed");
        let back: StoreKind =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, kind);
    }

    // ── StorageError ─────────────────────────────────────────────────────

    #[test]
    fn storage_error_code_exhaustive() {
        let cases: Vec<(StorageError, &str)> = vec![
            (
                StorageError::InvalidContext { field: "x".into() },
                "FE-STOR-0001",
            ),
            (StorageError::InvalidKey { key: "k".into() }, "FE-STOR-0002"),
            (
                StorageError::InvalidQuery { detail: "d".into() },
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
                    reason: "r".into(),
                },
                "FE-STOR-0006",
            ),
            (
                StorageError::IntegrityViolation {
                    store: StoreKind::ReplayIndex,
                    detail: "d".into(),
                },
                "FE-STOR-0007",
            ),
            (
                StorageError::BackendUnavailable {
                    backend: "b".into(),
                    detail: "d".into(),
                },
                "FE-STOR-0008",
            ),
            (
                StorageError::WriteRejected { detail: "d".into() },
                "FE-STOR-0009",
            ),
        ];
        for (err, code) in cases {
            assert_eq!(err.code(), code, "{err}");
        }
    }

    #[test]
    fn storage_error_display_all_variants() {
        let err = StorageError::InvalidContext {
            field: "trace_id".into(),
        };
        assert!(err.to_string().contains("trace_id"));

        let err = StorageError::InvalidKey { key: "bad".into() };
        assert!(err.to_string().contains("bad"));

        let err = StorageError::InvalidQuery {
            detail: "oops".into(),
        };
        assert!(err.to_string().contains("oops"));

        let err = StorageError::NotFound {
            store: StoreKind::PolicyCache,
            key: "missing".into(),
        };
        assert!(err.to_string().contains("missing"));

        let err = StorageError::SchemaVersionMismatch {
            expected: 1,
            actual: 2,
        };
        assert!(err.to_string().contains("1") && err.to_string().contains("2"));

        let err = StorageError::MigrationFailed {
            from: 1,
            to: 2,
            reason: "test".into(),
        };
        assert!(err.to_string().contains("test"));

        let err = StorageError::IntegrityViolation {
            store: StoreKind::ReplayIndex,
            detail: "corrupt".into(),
        };
        assert!(err.to_string().contains("corrupt"));

        let err = StorageError::BackendUnavailable {
            backend: "sqlite".into(),
            detail: "down".into(),
        };
        assert!(err.to_string().contains("sqlite") && err.to_string().contains("down"));

        let err = StorageError::WriteRejected {
            detail: "full".into(),
        };
        assert!(err.to_string().contains("full"));
    }

    #[test]
    fn storage_error_is_std_error() {
        let err = StorageError::NotFound {
            store: StoreKind::ReplayIndex,
            key: "k".into(),
        };
        let _: &dyn std::error::Error = &err;
    }

    // ── InMemoryStorageAdapter ───────────────────────────────────────────

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
            matches!(err, StorageError::SchemaVersionMismatch { expected: 999, actual } if actual == STORAGE_SCHEMA_VERSION)
        );
    }

    #[test]
    fn in_memory_migrate_downgrade_rejected() {
        let mut adapter = InMemoryStorageAdapter::new();
        adapter
            .migrate_to(STORAGE_SCHEMA_VERSION + 1)
            .expect("serde deserialization should succeed");
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
    fn in_memory_fail_writes_put_rejected() {
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
    }

    #[test]
    fn in_memory_fail_writes_delete_rejected() {
        let mut adapter = InMemoryStorageAdapter::new().with_fail_writes(true);
        let err = adapter
            .delete(StoreKind::ReplayIndex, "k", &ctx())
            .unwrap_err();
        assert!(matches!(err, StorageError::WriteRejected { .. }));
    }

    #[test]
    fn in_memory_fail_writes_batch_rejected() {
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
    fn in_memory_query_limit_zero_errors() {
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
    fn in_memory_query_with_key_prefix() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        adapter
            .put(
                StoreKind::ReplayIndex,
                "run/1".into(),
                vec![1],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        adapter
            .put(
                StoreKind::ReplayIndex,
                "run/2".into(),
                vec![2],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        adapter
            .put(
                StoreKind::ReplayIndex,
                "other/x".into(),
                vec![3],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");

        let query = StoreQuery {
            key_prefix: Some("run/".to_string()),
            ..Default::default()
        };
        let rows = adapter
            .query(StoreKind::ReplayIndex, &query, &context)
            .expect("serde deserialization should succeed");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.key.starts_with("run/")));
    }

    #[test]
    fn in_memory_query_with_metadata_filter() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        let mut meta = BTreeMap::new();
        meta.insert("env".to_string(), "prod".to_string());
        adapter
            .put(
                StoreKind::EvidenceIndex,
                "a".into(),
                vec![1],
                meta,
                &context,
            )
            .expect("serde deserialization should succeed");
        adapter
            .put(
                StoreKind::EvidenceIndex,
                "b".into(),
                vec![2],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");

        let mut filters = BTreeMap::new();
        filters.insert("env".to_string(), "prod".to_string());
        let query = StoreQuery {
            metadata_filters: filters,
            ..Default::default()
        };
        let rows = adapter
            .query(StoreKind::EvidenceIndex, &query, &context)
            .expect("serde deserialization should succeed");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key, "a");
    }

    #[test]
    fn in_memory_query_with_limit() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        for i in 0..5 {
            adapter
                .put(
                    StoreKind::ReplayIndex,
                    format!("k/{i:03}"),
                    vec![i as u8],
                    BTreeMap::new(),
                    &context,
                )
                .expect("serde deserialization should succeed");
        }
        let query = StoreQuery {
            limit: Some(2),
            ..Default::default()
        };
        let rows = adapter
            .query(StoreKind::ReplayIndex, &query, &context)
            .expect("serde deserialization should succeed");
        assert_eq!(rows.len(), 2);
    }

    #[test]
    fn in_memory_get_nonexistent_returns_none() {
        let mut adapter = InMemoryStorageAdapter::new();
        let result = adapter
            .get(StoreKind::PolicyCache, "no-such-key", &ctx())
            .expect("serde deserialization should succeed");
        assert!(result.is_none());
    }

    #[test]
    fn in_memory_delete_nonexistent_returns_false() {
        let mut adapter = InMemoryStorageAdapter::new();
        let deleted = adapter
            .delete(StoreKind::PolicyCache, "no-such-key", &ctx())
            .expect("serde deserialization should succeed");
        assert!(!deleted);
    }

    #[test]
    fn in_memory_query_empty_store_returns_empty() {
        let mut adapter = InMemoryStorageAdapter::new();
        let rows = adapter
            .query(StoreKind::PlasWitness, &StoreQuery::default(), &ctx())
            .expect("serde deserialization should succeed");
        assert!(rows.is_empty());
    }

    #[test]
    fn in_memory_put_updates_revision() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        let r1 = adapter
            .put(
                StoreKind::PolicyCache,
                "k".into(),
                vec![1],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        let r2 = adapter
            .put(
                StoreKind::PolicyCache,
                "k".into(),
                vec![2],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        assert!(r2.revision > r1.revision);
        assert_eq!(r2.value, vec![2]);
    }

    #[test]
    fn in_memory_backend_name() {
        let adapter = InMemoryStorageAdapter::new();
        assert_eq!(adapter.backend_name(), "in_memory");
    }

    // ── FrankensqliteStorageAdapter ──────────────────────────────────────

    #[derive(Debug, Default)]
    struct FailingBackend {
        fail_control_plane_profile: bool,
        fail_schema_version: bool,
        fail_migrate: bool,
        fail_put: bool,
        fail_get: bool,
        fail_query: bool,
        fail_delete: bool,
        fail_batch: bool,
        inner: MockFrankenSqlite,
    }

    impl FrankensqliteBackend for FailingBackend {
        fn apply_control_plane_profile(&mut self) -> Result<(), String> {
            if self.fail_control_plane_profile {
                Err("control-plane profile failure".into())
            } else {
                self.inner.apply_control_plane_profile()
            }
        }
        fn current_schema_version(&self) -> Result<u32, String> {
            if self.fail_schema_version {
                Err("schema version failure".into())
            } else {
                self.inner.current_schema_version()
            }
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
    fn frankensqlite_new_control_plane_profile_failure() {
        let backend = FailingBackend {
            fail_control_plane_profile: true,
            ..Default::default()
        };
        let err = FrankensqliteStorageAdapter::new(backend).unwrap_err();
        assert!(matches!(err, StorageError::BackendUnavailable { .. }));
    }

    #[test]
    fn frankensqlite_new_schema_version_failure() {
        let backend = FailingBackend {
            fail_schema_version: true,
            ..Default::default()
        };
        let err = FrankensqliteStorageAdapter::new(backend).unwrap_err();
        assert!(matches!(err, StorageError::BackendUnavailable { .. }));
    }

    #[test]
    fn frankensqlite_crud_operations() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        let context = ctx();

        let record = adapter
            .put(
                StoreKind::ReplayIndex,
                "k1".into(),
                vec![1, 2],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        assert_eq!(record.key, "k1");
        assert_eq!(record.value, vec![1, 2]);

        let got = adapter
            .get(StoreKind::ReplayIndex, "k1", &context)
            .expect("serde deserialization should succeed");
        assert!(got.is_some());
        assert_eq!(
            got.expect("serde deserialization should succeed").value,
            vec![1, 2]
        );

        let deleted = adapter
            .delete(StoreKind::ReplayIndex, "k1", &context)
            .expect("serde deserialization should succeed");
        assert!(deleted);

        let got = adapter
            .get(StoreKind::ReplayIndex, "k1", &context)
            .expect("serde deserialization should succeed");
        assert!(got.is_none());
    }

    #[test]
    fn frankensqlite_query_limit_zero_errors() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
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
    fn frankensqlite_put_failure_emits_error_event() {
        let backend = FailingBackend {
            fail_put: true,
            ..Default::default()
        };
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        let _ = adapter.put(
            StoreKind::ReplayIndex,
            "k".into(),
            vec![1],
            BTreeMap::new(),
            &ctx(),
        );
        let event = adapter
            .events()
            .last()
            .expect("serde deserialization should succeed");
        assert_eq!(event.outcome, "error");
        assert!(event.error_code.is_some());
    }

    #[test]
    fn frankensqlite_get_failure() {
        let backend = FailingBackend {
            fail_get: true,
            ..Default::default()
        };
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        let err = adapter
            .get(StoreKind::ReplayIndex, "k", &ctx())
            .unwrap_err();
        assert!(matches!(err, StorageError::BackendUnavailable { .. }));
    }

    #[test]
    fn frankensqlite_query_failure() {
        let backend = FailingBackend {
            fail_query: true,
            ..Default::default()
        };
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        let err = adapter
            .query(StoreKind::ReplayIndex, &StoreQuery::default(), &ctx())
            .unwrap_err();
        assert!(matches!(err, StorageError::BackendUnavailable { .. }));
    }

    #[test]
    fn frankensqlite_delete_failure() {
        let backend = FailingBackend {
            fail_delete: true,
            ..Default::default()
        };
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        let err = adapter
            .delete(StoreKind::ReplayIndex, "k", &ctx())
            .unwrap_err();
        assert!(matches!(err, StorageError::BackendUnavailable { .. }));
    }

    #[test]
    fn frankensqlite_batch_failure() {
        let backend = FailingBackend {
            fail_batch: true,
            ..Default::default()
        };
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
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

    #[test]
    fn frankensqlite_migrate_downgrade_rejected() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        adapter
            .migrate_to(STORAGE_SCHEMA_VERSION + 1)
            .expect("serde deserialization should succeed");
        let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION).unwrap_err();
        assert!(matches!(err, StorageError::MigrationFailed { .. }));
    }

    #[test]
    fn frankensqlite_migrate_skip_rejected() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 5).unwrap_err();
        assert!(matches!(err, StorageError::MigrationFailed { .. }));
    }

    #[test]
    fn frankensqlite_migrate_backend_failure() {
        let backend = FailingBackend {
            fail_migrate: true,
            ..Default::default()
        };
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        let err = adapter.migrate_to(STORAGE_SCHEMA_VERSION + 1).unwrap_err();
        assert!(matches!(err, StorageError::BackendUnavailable { .. }));
    }

    #[test]
    fn frankensqlite_ensure_schema_version() {
        let backend = MockFrankenSqlite::default();
        let adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        assert!(
            adapter
                .ensure_schema_version(STORAGE_SCHEMA_VERSION)
                .is_ok()
        );
        let err = adapter.ensure_schema_version(999).unwrap_err();
        assert!(matches!(err, StorageError::SchemaVersionMismatch { .. }));
    }

    #[test]
    fn frankensqlite_backend_name() {
        let backend = MockFrankenSqlite::default();
        let adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        assert_eq!(adapter.backend_name(), "frankensqlite");
    }

    #[test]
    fn frankensqlite_batch_put_success() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
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
            .expect("serde deserialization should succeed");
        assert_eq!(records.len(), 2);
    }

    #[test]
    fn frankensqlite_invalid_key_on_put() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        let err = adapter
            .put(
                StoreKind::ReplayIndex,
                "  ".into(),
                vec![1],
                BTreeMap::new(),
                &ctx(),
            )
            .unwrap_err();
        assert!(matches!(err, StorageError::InvalidKey { .. }));
    }

    #[test]
    fn frankensqlite_invalid_key_on_batch() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
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

    // ── Utility functions ────────────────────────────────────────────────

    #[test]
    fn digest_hex_deterministic() {
        let a = digest_hex(b"hello");
        let b = digest_hex(b"hello");
        assert_eq!(a, b);
        assert_ne!(a, digest_hex(b"world"));
    }

    #[test]
    fn fnv1a64_deterministic() {
        let a = fnv1a64(b"test");
        let b = fnv1a64(b"test");
        assert_eq!(a, b);
    }

    #[test]
    fn fnv1a64_empty_is_offset_basis() {
        assert_eq!(fnv1a64(b""), 0xcbf2_9ce4_8422_2325);
    }

    #[test]
    fn canonicalize_records_sorts_by_key() {
        let r1 = StoreRecord {
            store: StoreKind::ReplayIndex,
            key: "z".into(),
            value: vec![1],
            metadata: BTreeMap::new(),
            revision: 1,
        };
        let r2 = StoreRecord {
            store: StoreKind::ReplayIndex,
            key: "a".into(),
            value: vec![2],
            metadata: BTreeMap::new(),
            revision: 2,
        };
        let sorted = canonicalize_records(vec![r1, r2], None);
        assert_eq!(sorted[0].key, "a");
        assert_eq!(sorted[1].key, "z");
    }

    #[test]
    fn canonicalize_records_with_limit() {
        let records: Vec<StoreRecord> = (0..5)
            .map(|i| StoreRecord {
                store: StoreKind::ReplayIndex,
                key: format!("k{i}"),
                value: vec![i as u8],
                metadata: BTreeMap::new(),
                revision: i as u64,
            })
            .collect();
        let truncated = canonicalize_records(records, Some(3));
        assert_eq!(truncated.len(), 3);
    }

    // ── Serde round-trips ────────────────────────────────────────────────

    #[test]
    fn store_record_serde_round_trip() {
        let record = StoreRecord {
            store: StoreKind::EvidenceIndex,
            key: "test".into(),
            value: vec![1, 2, 3],
            metadata: BTreeMap::new(),
            revision: 42,
        };
        let json = serde_json::to_string(&record).expect("serde deserialization should succeed");
        let back: StoreRecord =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, record);
    }

    #[test]
    fn storage_event_serde_round_trip() {
        let event = StorageEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "put".into(),
            outcome: "ok".into(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let back: StorageEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, event);
    }

    #[test]
    fn migration_receipt_serde_round_trip() {
        let receipt = MigrationReceipt {
            backend: "in_memory".into(),
            from_version: 1,
            to_version: 2,
            stores_touched: vec![StoreKind::ReplayIndex],
            records_touched: 10,
            state_hash_before: "aabb".into(),
            state_hash_after: "ccdd".into(),
        };
        let json = serde_json::to_string(&receipt).expect("serde deserialization should succeed");
        let back: MigrationReceipt =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, receipt);
    }

    #[test]
    fn batch_put_entry_serde_round_trip() {
        let entry = BatchPutEntry {
            key: "k".into(),
            value: vec![1],
            metadata: BTreeMap::new(),
        };
        let json = serde_json::to_string(&entry).expect("serde deserialization should succeed");
        let back: BatchPutEntry =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back, entry);
    }

    #[test]
    fn store_query_default() {
        let q = StoreQuery::default();
        assert!(q.key_prefix.is_none());
        assert!(q.metadata_filters.is_empty());
        assert!(q.limit.is_none());
    }

    #[test]
    fn in_memory_events_record_success_and_failure() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        adapter
            .put(
                StoreKind::ReplayIndex,
                "valid".into(),
                vec![1],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        let _ = adapter.put(
            StoreKind::ReplayIndex,
            "".into(),
            vec![1],
            BTreeMap::new(),
            &context,
        );

        let events = adapter.events();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].outcome, "ok");
        assert_eq!(events[1].outcome, "error");
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn store_query_default_has_no_filters() {
        let query = StoreQuery::default();
        assert!(query.key_prefix.is_none());
        assert!(query.metadata_filters.is_empty());
        assert!(query.limit.is_none());
    }

    #[test]
    fn store_query_serde_roundtrip_with_filters() {
        let mut filters = BTreeMap::new();
        filters.insert("env".to_string(), "prod".to_string());
        let query = StoreQuery {
            key_prefix: Some("replay/".to_string()),
            metadata_filters: filters,
            limit: Some(10),
        };
        let json = serde_json::to_string(&query).expect("serde deserialization should succeed");
        let back: StoreQuery =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(query, back);
    }

    #[test]
    fn event_context_serde_roundtrip() {
        let context = ctx();
        let json = serde_json::to_string(&context).expect("serde deserialization should succeed");
        let back: EventContext =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(context, back);
    }

    #[test]
    fn storage_error_serde_roundtrip_all_variants() {
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
                reason: "err".to_string(),
            },
            StorageError::IntegrityViolation {
                store: StoreKind::PlasWitness,
                detail: "bad".to_string(),
            },
            StorageError::BackendUnavailable {
                backend: "test".to_string(),
                detail: "down".to_string(),
            },
            StorageError::WriteRejected {
                detail: "injection".to_string(),
            },
        ];
        for error in &errors {
            let json = serde_json::to_string(error).expect("serde deserialization should succeed");
            let back: StorageError =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(error, &back);
        }
    }

    #[test]
    fn in_memory_revision_increments_on_overwrite() {
        let context = ctx();
        let mut adapter = InMemoryStorageAdapter::new();
        let r1 = adapter
            .put(
                StoreKind::PolicyCache,
                "key-a".into(),
                vec![1],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        let r2 = adapter
            .put(
                StoreKind::PolicyCache,
                "key-a".into(),
                vec![2],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        assert!(r2.revision > r1.revision);
        // Get should return latest value
        let got = adapter
            .get(StoreKind::PolicyCache, "key-a", &context)
            .expect("serde deserialization should succeed")
            .expect("serde deserialization should succeed");
        assert_eq!(got.value, vec![2]);
    }

    #[test]
    fn in_memory_query_both_prefix_and_metadata() {
        let context = ctx();
        let mut adapter = InMemoryStorageAdapter::new();
        let mut meta_a = BTreeMap::new();
        meta_a.insert("env".to_string(), "prod".to_string());
        let mut meta_b = BTreeMap::new();
        meta_b.insert("env".to_string(), "staging".to_string());
        adapter
            .put(
                StoreKind::EvidenceIndex,
                "replay/001".into(),
                vec![1],
                meta_a.clone(),
                &context,
            )
            .expect("serde deserialization should succeed");
        adapter
            .put(
                StoreKind::EvidenceIndex,
                "replay/002".into(),
                vec![2],
                meta_b,
                &context,
            )
            .expect("serde deserialization should succeed");
        adapter
            .put(
                StoreKind::EvidenceIndex,
                "bench/001".into(),
                vec![3],
                meta_a,
                &context,
            )
            .expect("serde deserialization should succeed");
        // Prefix + metadata filter
        let mut filters = BTreeMap::new();
        filters.insert("env".to_string(), "prod".to_string());
        let query = StoreQuery {
            key_prefix: Some("replay/".to_string()),
            metadata_filters: filters,
            limit: None,
        };
        let results = adapter
            .query(StoreKind::EvidenceIndex, &query, &context)
            .expect("serde deserialization should succeed");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].key, "replay/001");
    }

    #[test]
    fn in_memory_query_limit_one() {
        let context = ctx();
        let mut adapter = InMemoryStorageAdapter::new();
        for i in 0..5 {
            adapter
                .put(
                    StoreKind::ReplayIndex,
                    format!("key-{i}"),
                    vec![i as u8],
                    BTreeMap::new(),
                    &context,
                )
                .expect("serde deserialization should succeed");
        }
        let query = StoreQuery {
            limit: Some(1),
            ..Default::default()
        };
        let results = adapter
            .query(StoreKind::ReplayIndex, &query, &context)
            .expect("serde deserialization should succeed");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn migration_receipt_serde_with_empty_stores() {
        let receipt = MigrationReceipt {
            backend: "in_memory".to_string(),
            from_version: 1,
            to_version: 2,
            stores_touched: Vec::new(),
            records_touched: 0,
            state_hash_before: "0000000000000000".to_string(),
            state_hash_after: "0000000000000000".to_string(),
        };
        let json = serde_json::to_string(&receipt).expect("serde deserialization should succeed");
        let back: MigrationReceipt =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(receipt, back);
        assert!(back.stores_touched.is_empty());
    }

    #[test]
    fn storage_event_error_code_none_serde() {
        let event = StorageEvent {
            trace_id: "t".to_string(),
            decision_id: "d".to_string(),
            policy_id: "p".to_string(),
            component: "storage_adapter".to_string(),
            event: "put".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let back: StorageEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert!(back.error_code.is_none());
    }

    #[test]
    fn in_memory_default_matches_new() {
        let a = InMemoryStorageAdapter::new();
        let b = InMemoryStorageAdapter::default();
        assert_eq!(a.current_schema_version(), b.current_schema_version());
        assert!(a.events().is_empty());
        assert!(b.events().is_empty());
    }

    #[test]
    fn store_kind_display_all_variants_unique() {
        let kinds = [
            StoreKind::ReplayIndex,
            StoreKind::EvidenceIndex,
            StoreKind::ShadowEvidenceJournal,
            StoreKind::BenchmarkLedger,
            StoreKind::PolicyCache,
            StoreKind::PlasWitness,
            StoreKind::ReplacementLineage,
            StoreKind::IfcProvenance,
            StoreKind::SpecializationIndex,
        ];
        let displays: Vec<String> = kinds.iter().map(|k| k.to_string()).collect();
        let mut deduped = displays.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(displays.len(), deduped.len());
    }

    // ── Enrichment batch 4: isolation, migrate same, batch, adapter serde ─

    #[test]
    fn storage_schema_version_constant_is_stable() {
        assert_eq!(STORAGE_SCHEMA_VERSION, 1);
    }

    #[test]
    fn store_kind_serde_round_trip_all_variants() {
        for kind in [
            StoreKind::ReplayIndex,
            StoreKind::EvidenceIndex,
            StoreKind::ShadowEvidenceJournal,
            StoreKind::BenchmarkLedger,
            StoreKind::PolicyCache,
            StoreKind::PlasWitness,
            StoreKind::ReplacementLineage,
            StoreKind::IfcProvenance,
            StoreKind::SpecializationIndex,
        ] {
            let json = serde_json::to_string(&kind).expect("serde deserialization should succeed");
            let back: StoreKind =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(back, kind, "StoreKind::{kind:?}");
        }
    }

    #[test]
    fn store_kind_ord_is_deterministic() {
        let mut kinds = vec![
            StoreKind::SpecializationIndex,
            StoreKind::ReplayIndex,
            StoreKind::PlasWitness,
            StoreKind::BenchmarkLedger,
        ];
        let mut kinds2 = kinds.clone();
        kinds.sort();
        kinds2.sort();
        assert_eq!(kinds, kinds2);
    }

    #[test]
    fn in_memory_migrate_same_version_is_noop() {
        let mut adapter = InMemoryStorageAdapter::new();
        let receipt = adapter
            .migrate_to(STORAGE_SCHEMA_VERSION)
            .expect("serde deserialization should succeed");
        assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
        assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION);
    }

    #[test]
    fn different_stores_are_isolated() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        adapter
            .put(
                StoreKind::ReplayIndex,
                "shared-key".into(),
                vec![1],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        adapter
            .put(
                StoreKind::PolicyCache,
                "shared-key".into(),
                vec![2],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        let r1 = adapter
            .get(StoreKind::ReplayIndex, "shared-key", &context)
            .expect("serde deserialization should succeed")
            .expect("serde deserialization should succeed");
        let r2 = adapter
            .get(StoreKind::PolicyCache, "shared-key", &context)
            .expect("serde deserialization should succeed")
            .expect("serde deserialization should succeed");
        assert_eq!(r1.value, vec![1]);
        assert_eq!(r2.value, vec![2]);
    }

    #[test]
    fn in_memory_batch_put_then_query() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        let entries = vec![
            BatchPutEntry {
                key: "batch/c".into(),
                value: vec![3],
                metadata: BTreeMap::new(),
            },
            BatchPutEntry {
                key: "batch/a".into(),
                value: vec![1],
                metadata: BTreeMap::new(),
            },
            BatchPutEntry {
                key: "batch/b".into(),
                value: vec![2],
                metadata: BTreeMap::new(),
            },
        ];
        adapter
            .put_batch(StoreKind::BenchmarkLedger, entries, &context)
            .expect("serde deserialization should succeed");
        let rows = adapter
            .query(StoreKind::BenchmarkLedger, &StoreQuery::default(), &context)
            .expect("serde deserialization should succeed");
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].key, "batch/a");
        assert_eq!(rows[1].key, "batch/b");
        assert_eq!(rows[2].key, "batch/c");
    }

    #[test]
    fn in_memory_delete_then_query_empty() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        adapter
            .put(
                StoreKind::ReplayIndex,
                "only".into(),
                vec![1],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        adapter
            .delete(StoreKind::ReplayIndex, "only", &context)
            .expect("serde deserialization should succeed");
        let rows = adapter
            .query(StoreKind::ReplayIndex, &StoreQuery::default(), &context)
            .expect("serde deserialization should succeed");
        assert!(rows.is_empty());
    }

    #[test]
    fn canonicalize_records_empty() {
        let result = canonicalize_records(vec![], None);
        assert!(result.is_empty());
    }

    #[test]
    fn canonicalize_records_limit_exceeds_count() {
        let records = vec![StoreRecord {
            store: StoreKind::ReplayIndex,
            key: "k".into(),
            value: vec![],
            metadata: BTreeMap::new(),
            revision: 1,
        }];
        let result = canonicalize_records(records, Some(100));
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn storage_event_with_error_code_some() {
        let event = StorageEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "storage_adapter".into(),
            event: "put".into(),
            outcome: "error".into(),
            error_code: Some("FE-STOR-0002".into()),
        };
        let json = serde_json::to_string(&event).expect("serde deserialization should succeed");
        let back: StorageEvent =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back.error_code, Some("FE-STOR-0002".into()));
    }

    #[test]
    fn store_record_with_metadata() {
        let mut meta = BTreeMap::new();
        meta.insert("env".into(), "prod".into());
        meta.insert("lane".into(), "runtime".into());
        let record = StoreRecord {
            store: StoreKind::EvidenceIndex,
            key: "k".into(),
            value: vec![42],
            metadata: meta,
            revision: 1,
        };
        let json = serde_json::to_string(&record).expect("serde deserialization should succeed");
        let back: StoreRecord =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(back.metadata.len(), 2);
        assert_eq!(back.metadata.get("env"), Some(&"prod".to_string()));
    }

    #[test]
    fn frankensqlite_migrate_success_receipt() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        let receipt = adapter
            .migrate_to(STORAGE_SCHEMA_VERSION + 1)
            .expect("serde deserialization should succeed");
        assert_eq!(receipt.backend, "frankensqlite");
        assert_eq!(receipt.from_version, STORAGE_SCHEMA_VERSION);
        assert_eq!(receipt.to_version, STORAGE_SCHEMA_VERSION + 1);
        assert_ne!(receipt.state_hash_before, receipt.state_hash_after);
    }

    #[test]
    fn frankensqlite_events_accessor() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend)
            .expect("serde deserialization should succeed");
        assert!(adapter.events().is_empty());
        adapter
            .put(
                StoreKind::ReplayIndex,
                "k".into(),
                vec![1],
                BTreeMap::new(),
                &ctx(),
            )
            .expect("serde deserialization should succeed");
        assert_eq!(adapter.events().len(), 1);
        assert_eq!(adapter.events()[0].event, "put");
        assert_eq!(adapter.events()[0].outcome, "ok");
    }

    #[test]
    fn in_memory_adapter_serde_roundtrip() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        adapter
            .put(
                StoreKind::ReplayIndex,
                "k1".into(),
                vec![1],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        let json = serde_json::to_string(&adapter).expect("serde deserialization should succeed");
        let back: InMemoryStorageAdapter =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(
            back.current_schema_version(),
            adapter.current_schema_version()
        );
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn storage_error_display_exact_format_all_9() {
        assert_eq!(
            StorageError::InvalidContext {
                field: "trace_id".into()
            }
            .to_string(),
            "invalid context field: trace_id"
        );
        assert_eq!(
            StorageError::InvalidKey { key: "bad".into() }.to_string(),
            "invalid key: `bad`"
        );
        assert_eq!(
            StorageError::InvalidQuery {
                detail: "limit=0".into()
            }
            .to_string(),
            "invalid query: limit=0"
        );
        assert_eq!(
            StorageError::NotFound {
                store: StoreKind::PolicyCache,
                key: "missing".into()
            }
            .to_string(),
            "record not found: policy_cache/missing"
        );
        assert_eq!(
            StorageError::SchemaVersionMismatch {
                expected: 1,
                actual: 2
            }
            .to_string(),
            "schema version mismatch: expected 1, got 2"
        );
        assert_eq!(
            StorageError::MigrationFailed {
                from: 1,
                to: 2,
                reason: "oops".into()
            }
            .to_string(),
            "migration failed: 1 -> 2: oops"
        );
        assert_eq!(
            StorageError::IntegrityViolation {
                store: StoreKind::ReplayIndex,
                detail: "corrupt".into()
            }
            .to_string(),
            "integrity violation in replay_index: corrupt"
        );
        assert_eq!(
            StorageError::BackendUnavailable {
                backend: "sqlite".into(),
                detail: "down".into()
            }
            .to_string(),
            "backend unavailable (sqlite): down"
        );
        assert_eq!(
            StorageError::WriteRejected {
                detail: "full".into()
            }
            .to_string(),
            "write rejected: full"
        );
    }

    #[test]
    fn event_context_new_whitespace_only_trace_id_fails() {
        let err = EventContext::new("   ", "d", "p").unwrap_err();
        assert_eq!(err.code(), "FE-STOR-0001");
    }

    #[test]
    fn event_context_new_whitespace_only_decision_id_fails() {
        let err = EventContext::new("t", " \t ", "p").unwrap_err();
        assert_eq!(err.code(), "FE-STOR-0001");
    }

    #[test]
    fn event_context_new_whitespace_only_policy_id_fails() {
        let err = EventContext::new("t", "d", "  ").unwrap_err();
        assert_eq!(err.code(), "FE-STOR-0001");
    }

    #[test]
    fn digest_hex_is_16_char_lowercase_hex() {
        let h = digest_hex(b"deterministic");
        assert_eq!(h.len(), 16);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
        assert_eq!(h, h.to_lowercase());
    }

    #[test]
    fn canonicalize_records_tiebreaks_by_revision() {
        let r1 = StoreRecord {
            store: StoreKind::ReplayIndex,
            key: "same".into(),
            value: vec![2],
            metadata: BTreeMap::new(),
            revision: 5,
        };
        let r2 = StoreRecord {
            store: StoreKind::ReplayIndex,
            key: "same".into(),
            value: vec![2],
            metadata: BTreeMap::new(),
            revision: 1,
        };
        let sorted = canonicalize_records(vec![r1, r2], None);
        assert_eq!(sorted[0].revision, 1);
        assert_eq!(sorted[1].revision, 5);
    }

    #[test]
    fn in_memory_get_empty_key_returns_invalid_key() {
        let mut adapter = InMemoryStorageAdapter::new();
        let err = adapter.get(StoreKind::ReplayIndex, "", &ctx()).unwrap_err();
        assert_eq!(err.code(), "FE-STOR-0002");
    }

    #[test]
    fn in_memory_delete_empty_key_returns_invalid_key() {
        let mut adapter = InMemoryStorageAdapter::new();
        let err = adapter
            .delete(StoreKind::ReplayIndex, "", &ctx())
            .unwrap_err();
        assert_eq!(err.code(), "FE-STOR-0002");
    }

    #[test]
    fn in_memory_batch_put_empty_entries_succeeds() {
        let mut adapter = InMemoryStorageAdapter::new();
        let results = adapter
            .put_batch(StoreKind::ReplayIndex, vec![], &ctx())
            .expect("serde deserialization should succeed");
        assert!(results.is_empty());
    }

    #[test]
    fn storage_error_source_returns_none() {
        use std::error::Error;
        let err = StorageError::NotFound {
            store: StoreKind::ReplayIndex,
            key: "k".into(),
        };
        assert!(err.source().is_none());
    }

    #[test]
    fn in_memory_migration_receipt_stores_touched_reflects_populated_stores() {
        let mut adapter = InMemoryStorageAdapter::new();
        let context = ctx();
        adapter
            .put(
                StoreKind::ReplayIndex,
                "k1".into(),
                vec![1],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        adapter
            .put(
                StoreKind::PolicyCache,
                "k2".into(),
                vec![2],
                BTreeMap::new(),
                &context,
            )
            .expect("serde deserialization should succeed");
        let receipt = adapter
            .migrate_to(STORAGE_SCHEMA_VERSION + 1)
            .expect("serde deserialization should succeed");
        assert!(receipt.stores_touched.contains(&StoreKind::ReplayIndex));
        assert!(receipt.stores_touched.contains(&StoreKind::PolicyCache));
        assert_eq!(receipt.records_touched, 2);
    }

    #[test]
    fn storage_error_code_all_unique() {
        let errors = vec![
            StorageError::InvalidContext {
                field: String::new(),
            },
            StorageError::InvalidKey { key: String::new() },
            StorageError::InvalidQuery {
                detail: String::new(),
            },
            StorageError::NotFound {
                store: StoreKind::ReplayIndex,
                key: String::new(),
            },
            StorageError::SchemaVersionMismatch {
                expected: 0,
                actual: 0,
            },
            StorageError::MigrationFailed {
                from: 0,
                to: 0,
                reason: String::new(),
            },
            StorageError::IntegrityViolation {
                store: StoreKind::ReplayIndex,
                detail: String::new(),
            },
            StorageError::BackendUnavailable {
                backend: String::new(),
                detail: String::new(),
            },
            StorageError::WriteRejected {
                detail: String::new(),
            },
        ];
        let codes: Vec<&str> = errors.iter().map(|e| e.code()).collect();
        let mut deduped = codes.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(codes.len(), deduped.len());
    }

    #[test]
    fn frankensqlite_adapter_new_creates_no_typed_session() {
        let backend = MockFrankenSqlite::default();
        let adapter = FrankensqliteStorageAdapter::new(backend).expect("should create adapter");
        assert!(!adapter.has_typed_session());
        assert!(adapter.typed_session().is_none());
    }

    #[test]
    fn frankensqlite_adapter_new_with_typed_session_enables_typed_operations() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new_with_typed_session(backend)
            .expect("should create adapter with typed session");
        assert!(adapter.has_typed_session());
        assert!(adapter.typed_session().is_some());
        assert!(adapter.typed_session_mut().is_some());
    }

    fn typed_replacement_metadata() -> BTreeMap<String, String> {
        BTreeMap::from([
            (
                TYPED_RECORD_FORMAT_KEY.to_string(),
                TYPED_RECORD_FORMAT_VALUE.to_string(),
            ),
            (
                TYPED_MODEL_KEY.to_string(),
                "ReplacementLineageEntry".to_string(),
            ),
            (
                TYPED_STORE_KIND_KEY.to_string(),
                StoreKind::ReplacementLineage.as_str().to_string(),
            ),
            (TYPED_RECORD_ID_KEY.to_string(), "7".to_string()),
        ])
    }

    #[test]
    fn frankensqlite_typed_heavy_put_rejects_unmarked_generic_legacy_rows() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
        let err = adapter
            .put(
                StoreKind::ReplacementLineage,
                "replacement_receipts/slot-a/00000000000000000001/receipt-a".to_string(),
                vec![1],
                BTreeMap::from([("slot_id".to_string(), "slot-a".to_string())]),
                &ctx(),
            )
            .expect_err("unmarked legacy row should fail closed");
        assert!(matches!(err, StorageError::WriteRejected { .. }));
        assert!(err.to_string().contains("non-authoritative"));
    }

    #[test]
    fn frankensqlite_typed_heavy_put_allows_explicit_generic_compat_rows() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
        let mut metadata = BTreeMap::from([("slot_id".to_string(), "slot-a".to_string())]);
        mark_typed_heavy_generic_compat_metadata(&mut metadata);
        let stored = adapter
            .put(
                StoreKind::ReplacementLineage,
                "replacement_receipts/slot-a/00000000000000000001/receipt-a".to_string(),
                vec![1],
                metadata,
                &ctx(),
            )
            .expect("explicit compatibility row should be accepted");
        assert_eq!(
            stored.key,
            "replacement_receipts/slot-a/00000000000000000001/receipt-a"
        );
    }

    #[test]
    fn frankensqlite_typed_heavy_put_rejects_marker_on_unknown_prefix() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
        let mut metadata = BTreeMap::new();
        mark_typed_heavy_generic_compat_metadata(&mut metadata);
        let err = adapter
            .put(
                StoreKind::IfcProvenance,
                "mystery::record".to_string(),
                vec![1],
                metadata,
                &ctx(),
            )
            .expect_err("unknown generic prefix should still fail closed");
        assert!(matches!(err, StorageError::WriteRejected { .. }));
    }

    #[test]
    fn frankensqlite_typed_heavy_put_allows_current_typed_envelopes() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
        let stored = adapter
            .put(
                StoreKind::ReplacementLineage,
                "typed/replacement_lineage/00000000000000000007".to_string(),
                b"{\"typed_record_id\":7}".to_vec(),
                typed_replacement_metadata(),
                &ctx(),
            )
            .expect("current typed envelope should be accepted");
        assert_eq!(stored.key, "typed/replacement_lineage/00000000000000000007");
    }

    #[test]
    fn frankensqlite_typed_heavy_get_rejects_unknown_keys() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
        let err = adapter
            .get(StoreKind::SpecializationIndex, "opaque-key", &ctx())
            .expect_err("unknown generic get should fail closed");
        assert!(matches!(err, StorageError::IntegrityViolation { .. }));
        assert!(err.to_string().contains("non-authoritative"));
    }

    #[test]
    fn frankensqlite_typed_heavy_query_requires_typed_or_compatibility_scope() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
        let err = adapter
            .query(StoreKind::IfcProvenance, &StoreQuery::default(), &ctx())
            .expect_err("unscoped typed-heavy query should fail closed");
        assert!(matches!(err, StorageError::IntegrityViolation { .. }));
        assert!(err.to_string().contains("backfill-planning marker"));
    }

    #[test]
    fn frankensqlite_typed_heavy_query_allows_recognized_compatibility_prefixes() {
        let backend = MockFrankenSqlite::default();
        let mut adapter = FrankensqliteStorageAdapter::new(backend).expect("adapter init");
        let mut metadata = BTreeMap::from([("receipt_id".to_string(), "abc".to_string())]);
        mark_typed_heavy_generic_compat_metadata(&mut metadata);
        adapter
            .put(
                StoreKind::SpecializationIndex,
                "benchmark:bm-1".to_string(),
                vec![3],
                metadata,
                &ctx(),
            )
            .expect("compatibility benchmark row should be accepted");
        let rows = adapter
            .query(
                StoreKind::SpecializationIndex,
                &StoreQuery {
                    key_prefix: Some("benchmark:".to_string()),
                    ..StoreQuery::default()
                },
                &ctx(),
            )
            .expect("recognized compatibility query should succeed");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].key, "benchmark:bm-1");
    }

    #[test]
    fn in_memory_typed_heavy_put_rejects_unmarked_generic_legacy_rows() {
        let mut adapter = InMemoryStorageAdapter::new();
        let err = adapter
            .put(
                StoreKind::ReplacementLineage,
                "replacement_receipts/slot-a/00000000000000000001/receipt-a".to_string(),
                vec![1],
                BTreeMap::from([("slot_id".to_string(), "slot-a".to_string())]),
                &ctx(),
            )
            .expect_err("unmarked legacy row should fail closed");
        assert!(matches!(err, StorageError::WriteRejected { .. }));
        assert!(err.to_string().contains("non-authoritative"));
    }

    #[test]
    fn in_memory_typed_heavy_get_query_and_delete_reject_unrecognized_keys() {
        let mut adapter = InMemoryStorageAdapter::new();

        let get_err = adapter
            .get(StoreKind::SpecializationIndex, "opaque-key", &ctx())
            .expect_err("unknown generic get should fail closed");
        assert!(matches!(get_err, StorageError::IntegrityViolation { .. }));

        let query_err = adapter
            .query(StoreKind::IfcProvenance, &StoreQuery::default(), &ctx())
            .expect_err("unscoped typed-heavy query should fail closed");
        assert!(matches!(query_err, StorageError::IntegrityViolation { .. }));
        assert!(query_err.to_string().contains("backfill-planning marker"));

        let delete_err = adapter
            .delete(StoreKind::ReplacementLineage, "opaque-key", &ctx())
            .expect_err("unknown generic delete should fail closed");
        assert!(matches!(
            delete_err,
            StorageError::IntegrityViolation { .. }
        ));
    }

    #[test]
    fn in_memory_typed_heavy_batch_put_is_atomic_when_policy_rejects_entry() {
        let mut adapter = InMemoryStorageAdapter::new();
        let mut metadata = BTreeMap::from([("slot_id".to_string(), "slot-a".to_string())]);
        mark_typed_heavy_generic_compat_metadata(&mut metadata);

        let err = adapter
            .put_batch(
                StoreKind::ReplacementLineage,
                vec![
                    BatchPutEntry {
                        key: "replacement_receipts/slot-a/00000000000000000001/receipt-a"
                            .to_string(),
                        value: vec![1],
                        metadata,
                    },
                    BatchPutEntry {
                        key: "opaque-key".to_string(),
                        value: vec![2],
                        metadata: BTreeMap::new(),
                    },
                ],
                &ctx(),
            )
            .expect_err("batch with an unmarked generic row should fail closed");
        assert!(matches!(err, StorageError::WriteRejected { .. }));

        let rows = adapter
            .query(
                StoreKind::ReplacementLineage,
                &StoreQuery {
                    key_prefix: Some("replacement_receipts/".to_string()),
                    ..StoreQuery::default()
                },
                &ctx(),
            )
            .expect("recognized compatibility query should succeed");
        assert!(rows.is_empty());
    }
}
