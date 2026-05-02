//! Typed persistence models for sqlmodel_rust integration.
//!
//! This module provides strongly-typed models for stores that require
//! compile-time schema validation and type safety via `/dp/sqlmodel_rust`,
//! as mandated by AGENTS.md and documented in FRANKENSQLITE_PERSISTENCE_INVENTORY.md.
//!
//! Implements typed boundaries for:
//! - ReplacementLineage: replacement/promotion lineage + signed receipts
//! - IfcProvenance: label-flow provenance edges + declassification references
//! - SpecializationIndex: proof-specialization mapping + invalidation markers

#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sqlmodel::prelude::*;
use sqlmodel::{Connection, Cx, Outcome, Session, SessionConfig, SessionDebugInfo, create_table};

use crate::storage_adapter::{
    BatchPutEntry, EventContext, StorageAdapter, StorageError, StoreKind, StoreQuery, StoreRecord,
};

const TYPED_RECORD_FORMAT_KEY: &str = "record_format";
const TYPED_RECORD_FORMAT_VALUE: &str = "sqlmodel_rust_typed_v1";
const TYPED_MODEL_KEY: &str = "typed_model";
const TYPED_STORE_KIND_KEY: &str = "store_kind";
const TYPED_RECORD_ID_KEY: &str = "typed_record_id";

type StorageResult<T> = std::result::Result<T, StorageError>;

fn typed_record_key(store: StoreKind, typed_record_id: i64) -> StorageResult<String> {
    if typed_record_id < 0 {
        return Err(StorageError::InvalidKey {
            key: format!("typed/{}/{typed_record_id}", store.as_str()),
        });
    }
    Ok(format!("typed/{}/{typed_record_id:020}", store.as_str()))
}

fn typed_record_metadata<T: TypedStoreRecord>(
    typed_record_id: i64,
    extra: BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut metadata = BTreeMap::new();
    metadata.insert(
        TYPED_RECORD_FORMAT_KEY.to_string(),
        TYPED_RECORD_FORMAT_VALUE.to_string(),
    );
    metadata.insert(TYPED_MODEL_KEY.to_string(), T::MODEL_NAME.to_string());
    metadata.insert(
        TYPED_STORE_KIND_KEY.to_string(),
        T::STORE_KIND.as_str().to_string(),
    );
    metadata.insert(TYPED_RECORD_ID_KEY.to_string(), typed_record_id.to_string());
    metadata.extend(extra);
    metadata
}

fn require_typed_metadata<T: TypedStoreRecord>(
    record: &StoreRecord,
    key: &str,
    expected: &str,
) -> StorageResult<()> {
    match record.metadata.get(key) {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(StorageError::IntegrityViolation {
            store: T::STORE_KIND,
            detail: format!(
                "typed metadata mismatch for {key}: expected `{expected}`, got `{actual}`"
            ),
        }),
        None => Err(StorageError::IntegrityViolation {
            store: T::STORE_KIND,
            detail: format!("missing typed metadata `{key}`"),
        }),
    }
}

fn validate_typed_record_metadata<T: TypedStoreRecord>(record: &StoreRecord) -> StorageResult<()> {
    require_typed_metadata::<T>(record, TYPED_RECORD_FORMAT_KEY, TYPED_RECORD_FORMAT_VALUE)?;
    require_typed_metadata::<T>(record, TYPED_MODEL_KEY, T::MODEL_NAME)?;
    require_typed_metadata::<T>(record, TYPED_STORE_KIND_KEY, T::STORE_KIND.as_str())?;
    require_typed_metadata::<T>(
        record,
        TYPED_RECORD_ID_KEY,
        &T::record_id_from_key(&record.key)?.to_string(),
    )
}

fn typed_key_prefix(store: StoreKind) -> String {
    format!("typed/{}/", store.as_str())
}

fn has_current_typed_format(record: &StoreRecord) -> bool {
    record
        .metadata
        .get(TYPED_RECORD_FORMAT_KEY)
        .is_some_and(|format| format == TYPED_RECORD_FORMAT_VALUE)
}

fn has_partial_typed_marker<T: TypedStoreRecord>(record: &StoreRecord) -> bool {
    record.key.starts_with(&typed_key_prefix(T::STORE_KIND))
        || record.metadata.contains_key(TYPED_MODEL_KEY)
        || record.metadata.contains_key(TYPED_STORE_KIND_KEY)
        || record.metadata.contains_key(TYPED_RECORD_ID_KEY)
}

/// Typed model boundary for records persisted through [`StorageAdapter`].
///
/// This intentionally only accepts records produced by this typed boundary.
/// Legacy generic payloads remain migration inputs, not implicitly trusted typed rows.
pub trait TypedStoreRecord: Serialize + DeserializeOwned + Sized {
    /// Store kind backing this typed model.
    const STORE_KIND: StoreKind;
    /// Stable model name recorded in metadata for fail-closed deserialization.
    const MODEL_NAME: &'static str;

    /// Stable integer identifier for deterministic storage keys.
    fn typed_record_id(&self) -> i64;

    /// Additional query-friendly metadata copied from typed fields.
    fn typed_record_extra_metadata(&self) -> BTreeMap<String, String>;

    /// Deterministic storage key for this typed model.
    fn typed_record_key(&self) -> StorageResult<String> {
        typed_record_key(Self::STORE_KIND, self.typed_record_id())
    }

    /// Deterministic storage key for an id of this typed model.
    fn typed_record_key_for_id(typed_record_id: i64) -> StorageResult<String> {
        typed_record_key(Self::STORE_KIND, typed_record_id)
    }

    /// Parse and verify an id from this model's deterministic storage key.
    fn record_id_from_key(key: &str) -> StorageResult<i64> {
        let prefix = format!("typed/{}/", Self::STORE_KIND.as_str());
        let Some(raw_id) = key.strip_prefix(&prefix) else {
            return Err(StorageError::InvalidKey {
                key: key.to_string(),
            });
        };
        raw_id.parse::<i64>().map_err(|_| StorageError::InvalidKey {
            key: key.to_string(),
        })
    }

    /// Convert this typed model into a generic store record.
    fn to_store_record(&self, revision: u64) -> StorageResult<StoreRecord> {
        let typed_record_id = self.typed_record_id();
        let value = serde_json::to_vec(self).map_err(|err| StorageError::IntegrityViolation {
            store: Self::STORE_KIND,
            detail: format!(
                "failed to serialize {} typed payload: {err}",
                Self::MODEL_NAME
            ),
        })?;

        Ok(StoreRecord {
            store: Self::STORE_KIND,
            key: self.typed_record_key()?,
            value,
            metadata: typed_record_metadata::<Self>(
                typed_record_id,
                self.typed_record_extra_metadata(),
            ),
            revision,
        })
    }

    /// Convert this typed model into a batch write entry.
    fn to_batch_put_entry(&self) -> StorageResult<BatchPutEntry> {
        let record = self.to_store_record(0)?;
        Ok(BatchPutEntry {
            key: record.key,
            value: record.value,
            metadata: record.metadata,
        })
    }

    /// Recover a typed model from a generic store record.
    fn from_store_record(record: &StoreRecord) -> StorageResult<Self> {
        if record.store != Self::STORE_KIND {
            return Err(StorageError::IntegrityViolation {
                store: Self::STORE_KIND,
                detail: format!(
                    "store kind mismatch for {}: expected {}, got {}",
                    Self::MODEL_NAME,
                    Self::STORE_KIND,
                    record.store
                ),
            });
        }

        validate_typed_record_metadata::<Self>(record)?;
        let typed_record_id = Self::record_id_from_key(&record.key)?;
        let model: Self = serde_json::from_slice(&record.value).map_err(|err| {
            StorageError::IntegrityViolation {
                store: Self::STORE_KIND,
                detail: format!(
                    "failed to deserialize {} typed payload from {}: {err}",
                    Self::MODEL_NAME,
                    record.key
                ),
            }
        })?;
        if model.typed_record_id() != typed_record_id {
            return Err(StorageError::IntegrityViolation {
                store: Self::STORE_KIND,
                detail: format!(
                    "payload id mismatch for {}: key has {}, payload has {}",
                    Self::MODEL_NAME,
                    typed_record_id,
                    model.typed_record_id()
                ),
            });
        }
        Ok(model)
    }
}

/// Backfill classification for generic store rows seen during typed migration planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypedBackfillStatus {
    /// Row already uses the current typed StoreRecord envelope and can be replayed as typed data.
    Ready,
    /// Row is a legacy or non-current envelope that needs an explicit lossless domain mapper.
    LegacyUnsupported,
    /// Row is malformed, corrupt, or addressed to the wrong typed store.
    Rejected,
}

/// Per-row typed backfill decision with structured, log-friendly details.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedBackfillDecision {
    pub store: StoreKind,
    pub key: String,
    pub model_name: String,
    pub status: TypedBackfillStatus,
    pub typed_record_id: Option<i64>,
    pub reason: String,
    pub error_code: Option<String>,
}

/// Dry-run plan for migrating generic StoreRecord data into one typed SQLModel table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedBackfillPlan {
    pub target_store: StoreKind,
    pub model_name: String,
    pub decisions: Vec<TypedBackfillDecision>,
}

impl TypedBackfillPlan {
    /// Number of rows that already pass the typed boundary.
    pub fn ready_count(&self) -> usize {
        self.decisions
            .iter()
            .filter(|decision| decision.status == TypedBackfillStatus::Ready)
            .count()
    }

    /// Number of rows requiring an explicit legacy-to-typed mapper.
    pub fn legacy_unsupported_count(&self) -> usize {
        self.decisions
            .iter()
            .filter(|decision| decision.status == TypedBackfillStatus::LegacyUnsupported)
            .count()
    }

    /// Number of rows that must not be migrated without operator intervention.
    pub fn rejected_count(&self) -> usize {
        self.decisions
            .iter()
            .filter(|decision| decision.status == TypedBackfillStatus::Rejected)
            .count()
    }

    /// True when one or more rows need store-specific lossless conversion logic.
    pub fn requires_explicit_legacy_mapper(&self) -> bool {
        self.legacy_unsupported_count() > 0
    }

    /// True only when every examined row can be replayed through the typed boundary.
    pub fn all_ready(&self) -> bool {
        !self.decisions.is_empty() && self.ready_count() == self.decisions.len()
    }
}

fn typed_backfill_rejection<T: TypedStoreRecord>(
    record: &StoreRecord,
    reason: String,
    error_code: Option<String>,
) -> TypedBackfillDecision {
    TypedBackfillDecision {
        store: record.store,
        key: record.key.clone(),
        model_name: T::MODEL_NAME.to_string(),
        status: TypedBackfillStatus::Rejected,
        typed_record_id: None,
        reason,
        error_code,
    }
}

fn typed_backfill_integrity_rejection<T: TypedStoreRecord>(
    record: &StoreRecord,
    detail: String,
) -> TypedBackfillDecision {
    let err = StorageError::IntegrityViolation {
        store: T::STORE_KIND,
        detail,
    };
    typed_backfill_rejection::<T>(record, err.to_string(), Some(err.code().to_string()))
}

fn typed_backfill_decision<T: TypedStoreRecord>(record: &StoreRecord) -> TypedBackfillDecision {
    if record.store != T::STORE_KIND {
        return typed_backfill_integrity_rejection::<T>(
            record,
            format!(
                "backfill store mismatch for {}: expected {}, got {}",
                T::MODEL_NAME,
                T::STORE_KIND,
                record.store
            ),
        );
    }

    if !has_current_typed_format(record) {
        if has_partial_typed_marker::<T>(record) {
            return typed_backfill_integrity_rejection::<T>(
                record,
                format!(
                    "partial typed envelope for {} cannot be treated as legacy input",
                    T::MODEL_NAME
                ),
            );
        }

        let reason = match record.metadata.get(TYPED_RECORD_FORMAT_KEY) {
            Some(format) => format!(
                "record format `{format}` is not `{TYPED_RECORD_FORMAT_VALUE}`; explicit lossless mapper required"
            ),
            None => "legacy or untyped StoreRecord lacks sqlmodel_rust typed metadata; explicit lossless mapper required".to_string(),
        };
        return TypedBackfillDecision {
            store: record.store,
            key: record.key.clone(),
            model_name: T::MODEL_NAME.to_string(),
            status: TypedBackfillStatus::LegacyUnsupported,
            typed_record_id: None,
            reason,
            error_code: None,
        };
    }

    match T::from_store_record(record) {
        Ok(model) => TypedBackfillDecision {
            store: record.store,
            key: record.key.clone(),
            model_name: T::MODEL_NAME.to_string(),
            status: TypedBackfillStatus::Ready,
            typed_record_id: Some(model.typed_record_id()),
            reason: "typed record passed sqlmodel_rust boundary validation".to_string(),
            error_code: None,
        },
        Err(err) => typed_backfill_rejection::<T>(
            record,
            format!("typed payload rejected: {err}"),
            Some(err.code().to_string()),
        ),
    }
}

/// Build a dry-run typed backfill plan without mutating storage.
///
/// This intentionally does not auto-convert legacy records. Existing generic stores
/// have store-specific payloads and keys, so a production backfill must provide an
/// explicit lossless mapper before writing typed SQLModel rows.
pub fn plan_typed_store_backfill<T: TypedStoreRecord>(
    records: &[StoreRecord],
) -> TypedBackfillPlan {
    TypedBackfillPlan {
        target_store: T::STORE_KIND,
        model_name: T::MODEL_NAME.to_string(),
        decisions: records.iter().map(typed_backfill_decision::<T>).collect(),
    }
}

/// Convenience extension for storing typed SQLModel records through any adapter.
pub trait TypedStorageAdapterExt: StorageAdapter {
    /// Put one typed model through the adapter's canonical store kind and key.
    fn put_typed<T: TypedStoreRecord>(
        &mut self,
        record: &T,
        context: &EventContext,
    ) -> StorageResult<StoreRecord> {
        let entry = record.to_batch_put_entry()?;
        self.put(
            T::STORE_KIND,
            entry.key,
            entry.value,
            entry.metadata,
            context,
        )
    }

    /// Put typed models as a single adapter batch.
    fn put_typed_batch<T: TypedStoreRecord>(
        &mut self,
        records: &[T],
        context: &EventContext,
    ) -> StorageResult<Vec<StoreRecord>> {
        let entries = records
            .iter()
            .map(TypedStoreRecord::to_batch_put_entry)
            .collect::<StorageResult<Vec<_>>>()?;
        self.put_batch(T::STORE_KIND, entries, context)
    }

    /// Fetch and deserialize one typed record by deterministic key.
    fn get_typed<T: TypedStoreRecord>(
        &mut self,
        key: &str,
        context: &EventContext,
    ) -> StorageResult<Option<T>> {
        self.get(T::STORE_KIND, key, context)?
            .map(|record| T::from_store_record(&record))
            .transpose()
    }

    /// Fetch and deserialize one typed record by typed integer id.
    fn get_typed_by_id<T: TypedStoreRecord>(
        &mut self,
        typed_record_id: i64,
        context: &EventContext,
    ) -> StorageResult<Option<T>> {
        let key = T::typed_record_key_for_id(typed_record_id)?;
        self.get_typed::<T>(&key, context)
    }

    /// Query and deserialize typed records, failing closed if any row is corrupt.
    fn query_typed<T: TypedStoreRecord>(
        &mut self,
        query: &StoreQuery,
        context: &EventContext,
    ) -> StorageResult<Vec<T>> {
        self.query(T::STORE_KIND, query, context)?
            .into_iter()
            .map(|record| T::from_store_record(&record))
            .collect()
    }
}

impl<A: StorageAdapter + ?Sized> TypedStorageAdapterExt for A {}

/// Session config used for deterministic typed persistence operations.
pub fn typed_sqlmodel_session_config() -> SessionConfig {
    SessionConfig {
        auto_begin: true,
        auto_flush: false,
        // Keep committed audit rows inspectable; callers may opt into expiration explicitly.
        expire_on_commit: false,
    }
}

/// SQLModel CREATE TABLE statements for all typed persistence models.
pub fn typed_persistence_create_table_sql() -> Vec<String> {
    vec![
        create_table::<ReplacementLineageEntry>()
            .if_not_exists()
            .build(),
        create_table::<IfcProvenanceEntry>().if_not_exists().build(),
        create_table::<SpecializationIndexEntry>()
            .if_not_exists()
            .build(),
    ]
}

/// Thin typed wrapper around the real SQLModel ORM session.
pub struct TypedSqlModelSession<C: Connection> {
    inner: Session<C>,
}

impl<C: Connection> TypedSqlModelSession<C> {
    /// Initialize a typed SQLModel session with deterministic FrankenEngine defaults.
    pub fn new(connection: C) -> Self {
        Self::with_config(connection, typed_sqlmodel_session_config())
    }

    /// Initialize a typed SQLModel session with caller-supplied SQLModel config.
    pub fn with_config(connection: C, config: SessionConfig) -> Self {
        Self {
            inner: Session::with_config(connection, config),
        }
    }

    /// Return the SQL statements required before using this typed session.
    pub fn create_table_sql() -> Vec<String> {
        typed_persistence_create_table_sql()
    }

    /// Borrow the underlying SQLModel session.
    pub fn inner(&self) -> &Session<C> {
        &self.inner
    }

    /// Mutably borrow the underlying SQLModel session for advanced callers.
    pub fn inner_mut(&mut self) -> &mut Session<C> {
        &mut self.inner
    }

    /// Current SQLModel session config.
    pub fn config(&self) -> &SessionConfig {
        self.inner.config()
    }

    /// Current SQLModel session debug state.
    pub fn debug_state(&self) -> SessionDebugInfo {
        self.inner.debug_state()
    }

    /// Add any typed persistence model to the SQLModel unit of work.
    pub fn add_typed<T>(&mut self, record: &T)
    where
        T: TypedStoreRecord + Model + Clone + Send + Sync + 'static,
    {
        self.inner.add(record);
    }

    /// Check whether a typed persistence model is tracked by the unit of work.
    pub fn contains_typed<T>(&self, record: &T) -> bool
    where
        T: TypedStoreRecord + Model + 'static,
    {
        self.inner.contains(record)
    }

    /// Add a replacement-lineage row to the SQLModel unit of work.
    pub fn add_replacement_lineage(&mut self, record: &ReplacementLineageEntry) {
        self.add_typed(record);
    }

    /// Add an IFC provenance row to the SQLModel unit of work.
    pub fn add_ifc_provenance(&mut self, record: &IfcProvenanceEntry) {
        self.add_typed(record);
    }

    /// Add a specialization-index row to the SQLModel unit of work.
    pub fn add_specialization_index(&mut self, record: &SpecializationIndexEntry) {
        self.add_typed(record);
    }

    /// Flush pending typed rows through the underlying SQLModel session.
    pub async fn flush(&mut self, cx: &Cx) -> Outcome<(), sqlmodel::Error> {
        self.inner.flush(cx).await
    }

    /// Commit pending typed rows through the underlying SQLModel session.
    pub async fn commit(&mut self, cx: &Cx) -> Outcome<(), sqlmodel::Error> {
        self.inner.commit(cx).await
    }

    /// Roll back pending typed rows through the underlying SQLModel session.
    pub async fn rollback(&mut self, cx: &Cx) -> Outcome<(), sqlmodel::Error> {
        self.inner.rollback(cx).await
    }
}

// ---------------------------------------------------------------------------
// ReplacementLineage: sqlmodel_rust typed model
// ---------------------------------------------------------------------------

/// Typed model for replacement lineage log entries.
///
/// Tracks slot promotion/demotion lineage with signed receipts for audit
/// replay. Maps to `frankensqlite::replacement::lineage_log` integration point
/// with compile-time schema validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Model)]
#[sqlmodel(table = "replacement_lineage")]
pub struct ReplacementLineageEntry {
    /// Unique sequence ID for this lineage entry.
    #[sqlmodel(primary_key)]
    pub sequence_id: i64,

    /// Slot identifier being promoted/demoted.
    pub slot_id: String,

    /// Type of lineage operation (promotion, demotion, transfer).
    pub operation_type: String,

    /// Source slot/state before the operation.
    pub source_state: String,

    /// Target slot/state after the operation.
    pub target_state: String,

    /// Signed receipt artifact ID for audit verification.
    pub receipt_artifact_id: String,

    /// Receipt signature for lineage integrity.
    pub receipt_signature: String,

    /// Unix timestamp (milliseconds) of the lineage operation.
    pub timestamp_ms: i64,

    /// Additional structured metadata for the lineage entry.
    pub metadata_json: String,
}

impl ReplacementLineageEntry {
    /// Build a deterministic typed lookup for one lineage sequence entry.
    pub fn select_by_sequence_id(sequence_id: i64) -> Select<Self> {
        Select::<Self>::new().filter(Expr::col("sequence_id").eq(sequence_id))
    }

    /// Build a deterministic typed lookup for all lineage rows for a slot.
    pub fn select_by_slot_id(slot_id: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("slot_id").eq(slot_id.into()))
            .order_by(Expr::col("sequence_id").asc())
    }

    /// Build a deterministic typed lookup by audit receipt artifact.
    pub fn select_by_receipt_artifact_id(receipt_artifact_id: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("receipt_artifact_id").eq(receipt_artifact_id.into()))
            .order_by(Expr::col("sequence_id").asc())
    }
}

impl TypedStoreRecord for ReplacementLineageEntry {
    const STORE_KIND: StoreKind = StoreKind::ReplacementLineage;
    const MODEL_NAME: &'static str = "ReplacementLineageEntry";

    fn typed_record_id(&self) -> i64 {
        self.sequence_id
    }

    fn typed_record_extra_metadata(&self) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("operation_type".to_string(), self.operation_type.clone()),
            (
                "receipt_artifact_id".to_string(),
                self.receipt_artifact_id.clone(),
            ),
            ("slot_id".to_string(), self.slot_id.clone()),
        ])
    }
}

// ---------------------------------------------------------------------------
// IfcProvenance: sqlmodel_rust typed model
// ---------------------------------------------------------------------------

/// Typed model for IFC (Information Flow Control) provenance index.
///
/// Tracks label-flow provenance edges and declassification references for
/// non-interference enforcement traceability. Maps to
/// `frankensqlite::control_plane::ifc_provenance` with typed boundaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Model)]
#[sqlmodel(table = "ifc_provenance")]
pub struct IfcProvenanceEntry {
    /// Unique provenance entry ID.
    #[sqlmodel(primary_key)]
    pub provenance_id: i64,

    /// Source label/entity in the flow.
    pub source_label: String,

    /// Target label/entity in the flow.
    pub target_label: String,

    /// Type of provenance edge (flow, declassification, aggregation).
    pub edge_type: String,

    /// Flow operation that created this provenance edge.
    pub flow_operation: String,

    /// Security level/classification of the flow.
    pub security_level: String,

    /// Reference to declassification authority (if applicable).
    pub declassification_ref: Option<String>,

    /// Unix timestamp (milliseconds) when the flow occurred.
    pub timestamp_ms: i64,

    /// Trace ID for linking to originating operation.
    pub trace_id: String,

    /// Additional edge metadata and validation artifacts.
    pub metadata_json: String,
}

impl IfcProvenanceEntry {
    /// Build a deterministic typed lookup for one provenance entry.
    pub fn select_by_provenance_id(provenance_id: i64) -> Select<Self> {
        Select::<Self>::new().filter(Expr::col("provenance_id").eq(provenance_id))
    }

    /// Build a deterministic typed lookup for all provenance rows for a trace.
    pub fn select_by_trace_id(trace_id: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("trace_id").eq(trace_id.into()))
            .order_by(Expr::col("provenance_id").asc())
    }

    /// Build a deterministic typed lookup for one label-flow edge.
    pub fn select_by_label_flow(
        source_label: impl Into<String>,
        target_label: impl Into<String>,
    ) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("source_label").eq(source_label.into()))
            .filter(Expr::col("target_label").eq(target_label.into()))
            .order_by(Expr::col("provenance_id").asc())
    }

    /// Build a deterministic typed lookup for declassification rows.
    pub fn select_declassifications() -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("edge_type").eq("declassification"))
            .order_by(Expr::col("provenance_id").asc())
    }
}

impl TypedStoreRecord for IfcProvenanceEntry {
    const STORE_KIND: StoreKind = StoreKind::IfcProvenance;
    const MODEL_NAME: &'static str = "IfcProvenanceEntry";

    fn typed_record_id(&self) -> i64 {
        self.provenance_id
    }

    fn typed_record_extra_metadata(&self) -> BTreeMap<String, String> {
        let mut metadata = BTreeMap::from([
            ("edge_type".to_string(), self.edge_type.clone()),
            ("security_level".to_string(), self.security_level.clone()),
            ("source_label".to_string(), self.source_label.clone()),
            ("target_label".to_string(), self.target_label.clone()),
            ("trace_id".to_string(), self.trace_id.clone()),
        ]);
        if let Some(declassification_ref) = &self.declassification_ref {
            metadata.insert(
                "declassification_ref".to_string(),
                declassification_ref.clone(),
            );
        }
        metadata
    }
}

// ---------------------------------------------------------------------------
// SpecializationIndex: sqlmodel_rust typed model
// ---------------------------------------------------------------------------

/// Typed model for specialization index entries.
///
/// Tracks proof-specialization mapping and invalidation markers for
/// fallback/invalidation replay determinism. Maps to
/// `frankensqlite::control_plane::specialization_index` with typed safety.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Model)]
#[sqlmodel(table = "specialization_index")]
pub struct SpecializationIndexEntry {
    /// Unique specialization entry ID.
    #[sqlmodel(primary_key)]
    pub specialization_id: i64,

    /// Proof artifact ID being specialized.
    pub proof_artifact_id: String,

    /// Type of specialization (optimization, validation, fallback).
    pub specialization_type: String,

    /// Specialized version/variant identifier.
    pub specialized_version: String,

    /// Status of the specialization (active, invalidated, archived).
    pub status: String,

    /// Invalidation marker timestamp (if invalidated).
    pub invalidation_timestamp_ms: Option<i64>,

    /// Reason for invalidation (if applicable).
    pub invalidation_reason: Option<String>,

    /// Security epoch when specialization was created.
    pub security_epoch: i64,

    /// Unix timestamp (milliseconds) of specialization creation.
    pub created_timestamp_ms: i64,

    /// Specialized proof artifact content hash.
    pub specialized_content_hash: String,

    /// Metadata for specialization parameters and constraints.
    pub metadata_json: String,
}

impl SpecializationIndexEntry {
    /// Build a deterministic typed lookup for one specialization entry.
    pub fn select_by_specialization_id(specialization_id: i64) -> Select<Self> {
        Select::<Self>::new().filter(Expr::col("specialization_id").eq(specialization_id))
    }

    /// Build a deterministic typed lookup for all specializations for a proof artifact.
    pub fn select_by_proof_artifact_id(proof_artifact_id: impl Into<String>) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("proof_artifact_id").eq(proof_artifact_id.into()))
            .order_by(Expr::col("specialization_id").asc())
    }

    /// Build a deterministic typed lookup for all active specializations.
    pub fn select_active() -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("status").eq("active"))
            .order_by(Expr::col("specialization_id").asc())
    }

    /// Build a deterministic typed lookup for all invalidated specializations.
    pub fn select_invalidated() -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("status").eq("invalidated"))
            .order_by(Expr::col("invalidation_timestamp_ms").desc())
            .order_by(Expr::col("specialization_id").asc())
    }

    /// Build a deterministic typed lookup by security epoch.
    pub fn select_by_security_epoch(security_epoch: i64) -> Select<Self> {
        Select::<Self>::new()
            .filter(Expr::col("security_epoch").eq(security_epoch))
            .order_by(Expr::col("specialization_id").asc())
    }
}

impl TypedStoreRecord for SpecializationIndexEntry {
    const STORE_KIND: StoreKind = StoreKind::SpecializationIndex;
    const MODEL_NAME: &'static str = "SpecializationIndexEntry";

    fn typed_record_id(&self) -> i64 {
        self.specialization_id
    }

    fn typed_record_extra_metadata(&self) -> BTreeMap<String, String> {
        let mut metadata = BTreeMap::from([
            (
                "proof_artifact_id".to_string(),
                self.proof_artifact_id.clone(),
            ),
            (
                "security_epoch".to_string(),
                self.security_epoch.to_string(),
            ),
            (
                "specialization_type".to_string(),
                self.specialization_type.clone(),
            ),
            ("status".to_string(), self.status.clone()),
        ]);
        if let Some(invalidation_reason) = &self.invalidation_reason {
            metadata.insert(
                "invalidation_reason".to_string(),
                invalidation_reason.clone(),
            );
        }
        metadata
    }
}

#[cfg(test)]
#[allow(clippy::manual_async_fn)] // Mock trait impls must match sqlmodel_core::Connection signatures.
mod tests {
    use super::*;
    use crate::storage_adapter::InMemoryStorageAdapter;
    use sqlmodel::{FieldInfo, Model, Row, SqlType, Value};
    use sqlmodel_core::{
        Connection, Dialect, Error, IsolationLevel, PreparedStatement, TransactionOps,
    };

    fn field<T: Model>(field_name: &str) -> &'static FieldInfo {
        T::fields()
            .iter()
            .find(|field| field.name == field_name)
            .expect("typed persistence field exists")
    }

    fn assert_round_trips<T>(model: T)
    where
        T: Clone + Model + PartialEq + std::fmt::Debug,
    {
        let values = model.to_row();
        let row = Row::new(
            values
                .iter()
                .map(|(column, _)| (*column).to_string())
                .collect(),
            values.into_iter().map(|(_, value)| value).collect(),
        );

        let restored = T::from_row(&row).expect("typed persistence row round-trips");
        assert_eq!(restored, model);
    }

    fn replacement_entry(sequence_id: i64) -> ReplacementLineageEntry {
        ReplacementLineageEntry {
            sequence_id,
            slot_id: "slot-alpha".to_string(),
            operation_type: "promotion".to_string(),
            source_state: "candidate".to_string(),
            target_state: "active".to_string(),
            receipt_artifact_id: "receipt-7".to_string(),
            receipt_signature: "sig-7".to_string(),
            timestamp_ms: 1_700_000_000_007,
            metadata_json: r#"{"trace_id":"trace-replacement"}"#.to_string(),
        }
    }

    fn ifc_entry(provenance_id: i64, trace_id: &str) -> IfcProvenanceEntry {
        IfcProvenanceEntry {
            provenance_id,
            source_label: "secret/model".to_string(),
            target_label: "operator/audit".to_string(),
            edge_type: "declassification".to_string(),
            flow_operation: "emit_receipt".to_string(),
            security_level: "high".to_string(),
            declassification_ref: Some("decision-11".to_string()),
            timestamp_ms: 1_700_000_000_011,
            trace_id: trace_id.to_string(),
            metadata_json: r#"{"policy_id":"ifc-policy"}"#.to_string(),
        }
    }

    fn specialization_entry(specialization_id: i64) -> SpecializationIndexEntry {
        SpecializationIndexEntry {
            specialization_id,
            proof_artifact_id: "proof-13".to_string(),
            specialization_type: "fallback".to_string(),
            specialized_version: "v2-safe".to_string(),
            status: "invalidated".to_string(),
            invalidation_timestamp_ms: None,
            invalidation_reason: None,
            security_epoch: 4,
            created_timestamp_ms: 1_700_000_000_013,
            specialized_content_hash: "sha256:abc123".to_string(),
            metadata_json: r#"{"fallback":"deterministic"}"#.to_string(),
        }
    }

    fn legacy_record(
        store: StoreKind,
        key: &str,
        value: &'static [u8],
        metadata: BTreeMap<String, String>,
    ) -> StoreRecord {
        StoreRecord {
            store,
            key: key.to_string(),
            value: value.to_vec(),
            metadata,
            revision: 1,
        }
    }

    #[derive(Debug, Clone, Copy)]
    struct NoopConnection;

    #[derive(Debug, Clone, Copy)]
    struct NoopTransaction;

    fn noop_error(operation: &str) -> Error {
        Error::Custom(format!(
            "noop typed session test connection does not execute {operation}"
        ))
    }

    impl Connection for NoopConnection {
        type Tx<'conn>
            = NoopTransaction
        where
            Self: 'conn;

        fn dialect(&self) -> Dialect {
            Dialect::Sqlite
        }

        fn query(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<Vec<Row>, Error>> + Send {
            let operation = format!("query `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn query_one(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<Option<Row>, Error>> + Send {
            let operation = format!("query_one `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn execute(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<u64, Error>> + Send {
            let operation = format!("execute `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn insert(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<i64, Error>> + Send {
            let operation = format!("insert `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn batch(
            &self,
            _cx: &Cx,
            statements: &[(String, Vec<Value>)],
        ) -> impl Future<Output = Outcome<Vec<u64>, Error>> + Send {
            let operation = format!("batch with {} statements", statements.len());
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn begin(&self, _cx: &Cx) -> impl Future<Output = Outcome<Self::Tx<'_>, Error>> + Send {
            async { Outcome::Ok(NoopTransaction) }
        }

        fn begin_with(
            &self,
            _cx: &Cx,
            _isolation: IsolationLevel,
        ) -> impl Future<Output = Outcome<Self::Tx<'_>, Error>> + Send {
            async { Outcome::Ok(NoopTransaction) }
        }

        fn prepare(
            &self,
            _cx: &Cx,
            sql: &str,
        ) -> impl Future<Output = Outcome<PreparedStatement, Error>> + Send {
            let sql = sql.to_string();
            async move { Outcome::Ok(PreparedStatement::new(1, sql, 0)) }
        }

        fn query_prepared(
            &self,
            _cx: &Cx,
            stmt: &PreparedStatement,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<Vec<Row>, Error>> + Send {
            let operation = format!("query_prepared `{}`", stmt.sql());
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn execute_prepared(
            &self,
            _cx: &Cx,
            stmt: &PreparedStatement,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<u64, Error>> + Send {
            let operation = format!("execute_prepared `{}`", stmt.sql());
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn ping(&self, _cx: &Cx) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }

        fn close(self, _cx: &Cx) -> impl Future<Output = sqlmodel_core::Result<()>> + Send {
            async { Ok(()) }
        }
    }

    impl TransactionOps for NoopTransaction {
        fn query(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<Vec<Row>, Error>> + Send {
            let operation = format!("transaction query `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn query_one(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<Option<Row>, Error>> + Send {
            let operation = format!("transaction query_one `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn execute(
            &self,
            _cx: &Cx,
            sql: &str,
            _params: &[Value],
        ) -> impl Future<Output = Outcome<u64, Error>> + Send {
            let operation = format!("transaction execute `{sql}`");
            async move { Outcome::Err(noop_error(&operation)) }
        }

        fn savepoint(
            &self,
            _cx: &Cx,
            _name: &str,
        ) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }

        fn rollback_to(
            &self,
            _cx: &Cx,
            _name: &str,
        ) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }

        fn release(
            &self,
            _cx: &Cx,
            _name: &str,
        ) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }

        fn commit(self, _cx: &Cx) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }

        fn rollback(self, _cx: &Cx) -> impl Future<Output = Outcome<(), Error>> + Send {
            async { Outcome::Ok(()) }
        }
    }

    #[test]
    fn replacement_lineage_model_exports_sqlmodel_metadata() {
        assert_eq!(ReplacementLineageEntry::TABLE_NAME, "replacement_lineage");
        assert_eq!(ReplacementLineageEntry::PRIMARY_KEY, &["sequence_id"]);

        let fields = ReplacementLineageEntry::fields();
        assert_eq!(fields.len(), 9);
        assert!(field::<ReplacementLineageEntry>("sequence_id").primary_key);
        assert_eq!(
            field::<ReplacementLineageEntry>("metadata_json").sql_type,
            SqlType::Text
        );
    }

    #[test]
    fn ifc_provenance_model_marks_declassification_ref_nullable() {
        assert_eq!(IfcProvenanceEntry::TABLE_NAME, "ifc_provenance");
        assert_eq!(IfcProvenanceEntry::PRIMARY_KEY, &["provenance_id"]);

        let declassification_ref = field::<IfcProvenanceEntry>("declassification_ref");
        assert_eq!(declassification_ref.sql_type, SqlType::Text);
        assert!(declassification_ref.nullable);
    }

    #[test]
    fn specialization_index_model_marks_invalidation_fields_nullable() {
        assert_eq!(SpecializationIndexEntry::TABLE_NAME, "specialization_index");
        assert_eq!(
            SpecializationIndexEntry::PRIMARY_KEY,
            &["specialization_id"]
        );

        assert!(field::<SpecializationIndexEntry>("invalidation_timestamp_ms").nullable);
        assert!(field::<SpecializationIndexEntry>("invalidation_reason").nullable);
        assert_eq!(
            field::<SpecializationIndexEntry>("specialized_content_hash").sql_type,
            SqlType::Text
        );
    }

    #[test]
    fn typed_persistence_models_round_trip_through_sqlmodel_rows() {
        assert_round_trips(ReplacementLineageEntry {
            sequence_id: 7,
            slot_id: "slot-alpha".to_string(),
            operation_type: "promotion".to_string(),
            source_state: "candidate".to_string(),
            target_state: "active".to_string(),
            receipt_artifact_id: "receipt-7".to_string(),
            receipt_signature: "sig-7".to_string(),
            timestamp_ms: 1_700_000_000_007,
            metadata_json: r#"{"trace_id":"trace-replacement"}"#.to_string(),
        });

        assert_round_trips(IfcProvenanceEntry {
            provenance_id: 11,
            source_label: "secret/model".to_string(),
            target_label: "operator/audit".to_string(),
            edge_type: "declassification".to_string(),
            flow_operation: "emit_receipt".to_string(),
            security_level: "high".to_string(),
            declassification_ref: Some("decision-11".to_string()),
            timestamp_ms: 1_700_000_000_011,
            trace_id: "trace-ifc".to_string(),
            metadata_json: r#"{"policy_id":"ifc-policy"}"#.to_string(),
        });

        assert_round_trips(SpecializationIndexEntry {
            specialization_id: 13,
            proof_artifact_id: "proof-13".to_string(),
            specialization_type: "fallback".to_string(),
            specialized_version: "v2-safe".to_string(),
            status: "invalidated".to_string(),
            invalidation_timestamp_ms: None,
            invalidation_reason: None,
            security_epoch: 4,
            created_timestamp_ms: 1_700_000_000_013,
            specialized_content_hash: "sha256:abc123".to_string(),
            metadata_json: r#"{"fallback":"deterministic"}"#.to_string(),
        });

        let null_option_values = SpecializationIndexEntry {
            specialization_id: 17,
            proof_artifact_id: "proof-17".to_string(),
            specialization_type: "optimization".to_string(),
            specialized_version: "v3".to_string(),
            status: "active".to_string(),
            invalidation_timestamp_ms: None,
            invalidation_reason: None,
            security_epoch: 5,
            created_timestamp_ms: 1_700_000_000_017,
            specialized_content_hash: "sha256:def456".to_string(),
            metadata_json: "{}".to_string(),
        }
        .to_row();

        assert!(
            null_option_values
                .iter()
                .any(|(column, value)| *column == "invalidation_timestamp_ms"
                    && *value == Value::Null)
        );
        assert!(
            null_option_values
                .iter()
                .any(|(column, value)| *column == "invalidation_reason" && *value == Value::Null)
        );
    }

    #[test]
    fn typed_query_builders_emit_stable_sql_and_params() {
        let (sql, params) = ReplacementLineageEntry::select_by_slot_id("slot-alpha").build();
        assert_eq!(
            sql,
            r#"SELECT * FROM replacement_lineage WHERE "slot_id" = $1 ORDER BY "sequence_id" ASC"#
        );
        assert_eq!(params, vec![Value::Text("slot-alpha".to_string())]);

        let (sql, params) =
            IfcProvenanceEntry::select_by_label_flow("secret/model", "operator/audit").build();
        assert_eq!(
            sql,
            r#"SELECT * FROM ifc_provenance WHERE "source_label" = $1 AND "target_label" = $2 ORDER BY "provenance_id" ASC"#
        );
        assert_eq!(
            params,
            vec![
                Value::Text("secret/model".to_string()),
                Value::Text("operator/audit".to_string())
            ]
        );

        let (sql, params) = SpecializationIndexEntry::select_invalidated()
            .limit(50)
            .build();
        assert_eq!(
            sql,
            r#"SELECT * FROM specialization_index WHERE "status" = $1 ORDER BY "invalidation_timestamp_ms" DESC, "specialization_id" ASC LIMIT 50"#
        );
        assert_eq!(params, vec![Value::Text("invalidated".to_string())]);
    }

    #[test]
    fn typed_session_schema_sql_lists_all_typed_tables() {
        let sql = typed_persistence_create_table_sql();
        assert_eq!(sql.len(), 3);
        assert!(
            sql.iter()
                .all(|statement| statement.starts_with("CREATE TABLE IF NOT EXISTS ")),
            "all typed tables must be explicit CREATE TABLE statements: {sql:#?}"
        );
        assert!(
            sql[0].contains("\"replacement_lineage\"")
                && sql[0].contains("\"sequence_id\" BIGINT NOT NULL")
                && sql[0].contains("PRIMARY KEY (\"sequence_id\")"),
            "replacement lineage DDL should expose the typed primary key: {}",
            sql[0]
        );
        assert!(
            sql[1].contains("\"ifc_provenance\"")
                && sql[1].contains("\"declassification_ref\" TEXT")
                && sql[1].contains("PRIMARY KEY (\"provenance_id\")"),
            "IFC provenance DDL should expose nullable declassification refs: {}",
            sql[1]
        );
        assert!(
            sql[2].contains("\"specialization_index\"")
                && sql[2].contains("\"invalidation_reason\" TEXT")
                && sql[2].contains("PRIMARY KEY (\"specialization_id\")"),
            "specialization index DDL should expose nullable invalidation fields: {}",
            sql[2]
        );
    }

    #[test]
    fn typed_sqlmodel_session_tracks_models_with_deterministic_defaults() {
        let mut session = TypedSqlModelSession::new(NoopConnection);
        assert!(session.config().auto_begin);
        assert!(!session.config().auto_flush);
        assert!(!session.config().expire_on_commit);
        assert_eq!(
            TypedSqlModelSession::<NoopConnection>::create_table_sql(),
            typed_persistence_create_table_sql()
        );

        let replacement = replacement_entry(7);
        let ifc = ifc_entry(11, "trace-ifc");
        let specialization = specialization_entry(13);

        session.add_replacement_lineage(&replacement);
        session.add_ifc_provenance(&ifc);
        session.add_specialization_index(&specialization);

        assert!(session.contains_typed(&replacement));
        assert!(session.contains_typed(&ifc));
        assert!(session.contains_typed(&specialization));

        let debug = session.debug_state();
        assert_eq!(debug.tracked, 3);
        assert_eq!(debug.pending_new, 3);
        assert_eq!(debug.pending_delete, 0);
        assert_eq!(debug.pending_dirty, 0);
        assert!(!debug.in_transaction);
    }

    #[test]
    fn typed_store_record_boundary_emits_deterministic_keys_and_metadata() {
        let model = replacement_entry(7);
        let record = model
            .to_store_record(42)
            .expect("typed record should serialize");

        assert_eq!(record.store, StoreKind::ReplacementLineage);
        assert_eq!(record.key, "typed/replacement_lineage/00000000000000000007");
        assert_eq!(record.revision, 42);
        assert_eq!(
            record.metadata.get(TYPED_RECORD_FORMAT_KEY),
            Some(&TYPED_RECORD_FORMAT_VALUE.to_string())
        );
        assert_eq!(
            record.metadata.get(TYPED_MODEL_KEY),
            Some(&"ReplacementLineageEntry".to_string())
        );
        assert_eq!(
            record.metadata.get("slot_id"),
            Some(&"slot-alpha".to_string())
        );
        assert_eq!(
            record.metadata.get("receipt_artifact_id"),
            Some(&"receipt-7".to_string())
        );

        let restored = ReplacementLineageEntry::from_store_record(&record)
            .expect("typed record should deserialize");
        assert_eq!(restored, model);
    }

    #[test]
    fn typed_store_record_boundary_fails_closed_on_wrong_kind_or_metadata() {
        let model = replacement_entry(7);
        let mut wrong_store = model
            .to_store_record(0)
            .expect("typed record should serialize");
        wrong_store.store = StoreKind::IfcProvenance;
        let err = ReplacementLineageEntry::from_store_record(&wrong_store).unwrap_err();
        assert!(matches!(
            err,
            StorageError::IntegrityViolation {
                store: StoreKind::ReplacementLineage,
                ..
            }
        ));
        assert!(err.to_string().contains("store kind mismatch"));

        let mut missing_metadata = model
            .to_store_record(0)
            .expect("typed record should serialize");
        missing_metadata.metadata.remove(TYPED_RECORD_FORMAT_KEY);
        let err = ReplacementLineageEntry::from_store_record(&missing_metadata).unwrap_err();
        assert!(matches!(
            err,
            StorageError::IntegrityViolation {
                store: StoreKind::ReplacementLineage,
                ..
            }
        ));
        assert!(err.to_string().contains("missing typed metadata"));
    }

    #[test]
    fn typed_store_record_boundary_fails_closed_on_malformed_or_legacy_payload() {
        let model = replacement_entry(7);
        let mut malformed = model
            .to_store_record(0)
            .expect("typed record should serialize");
        malformed.value = b"{not json}".to_vec();
        let err = ReplacementLineageEntry::from_store_record(&malformed).unwrap_err();
        assert!(err.to_string().contains("failed to deserialize"));

        let mut legacy_shaped = model
            .to_store_record(0)
            .expect("typed record should serialize");
        legacy_shaped.value = br#"{"sequence":7,"kind":"DelegateToNative"}"#.to_vec();
        let err = ReplacementLineageEntry::from_store_record(&legacy_shaped).unwrap_err();
        assert!(err.to_string().contains("failed to deserialize"));

        let mut id_mismatch = model
            .to_store_record(0)
            .expect("typed record should serialize");
        id_mismatch.value =
            serde_json::to_vec(&replacement_entry(8)).expect("test payload serializes");
        let err = ReplacementLineageEntry::from_store_record(&id_mismatch).unwrap_err();
        assert!(err.to_string().contains("payload id mismatch"));
    }

    #[test]
    fn typed_store_record_boundary_rejects_negative_ids() {
        let err = replacement_entry(-1).to_store_record(0).unwrap_err();
        assert!(matches!(err, StorageError::InvalidKey { .. }));
        assert!(err.to_string().contains("typed/replacement_lineage/-1"));
    }

    #[test]
    fn typed_storage_adapter_extension_puts_gets_batches_and_queries_models() {
        let context = EventContext::new("trace-typed", "decision-typed", "policy-typed")
            .expect("context is valid");
        let mut adapter = InMemoryStorageAdapter::new();

        let stored = adapter
            .put_typed(&replacement_entry(7), &context)
            .expect("typed put succeeds");
        assert_eq!(stored.revision, 1);

        let fetched = adapter
            .get_typed_by_id::<ReplacementLineageEntry>(7, &context)
            .expect("typed get succeeds")
            .expect("typed record exists");
        assert_eq!(fetched, replacement_entry(7));

        let ifc_rows = vec![ifc_entry(11, "trace-ifc"), ifc_entry(12, "trace-ifc")];
        adapter
            .put_typed_batch(&ifc_rows, &context)
            .expect("typed batch succeeds");

        let query = StoreQuery {
            key_prefix: Some("typed/ifc_provenance/".to_string()),
            metadata_filters: BTreeMap::from([("trace_id".to_string(), "trace-ifc".to_string())]),
            limit: None,
        };
        let fetched = adapter
            .query_typed::<IfcProvenanceEntry>(&query, &context)
            .expect("typed query succeeds");
        assert_eq!(fetched, ifc_rows);

        let specialization = specialization_entry(13);
        let entry = specialization
            .to_batch_put_entry()
            .expect("batch entry conversion succeeds");
        assert_eq!(entry.key, "typed/specialization_index/00000000000000000013");
        assert_eq!(
            entry.metadata.get("proof_artifact_id"),
            Some(&"proof-13".to_string())
        );
    }

    #[test]
    fn typed_backfill_plan_separates_ready_legacy_corrupt_and_wrong_store_records() {
        let ready = replacement_entry(7)
            .to_store_record(5)
            .expect("typed record should serialize");
        let ready_key = ready.key.clone();

        let legacy = legacy_record(
            StoreKind::ReplacementLineage,
            "lineage_chain/slot-alpha/00000000000000000007/receipt-7",
            br#"{"receipt_id":"receipt-7","slot_id":"slot-alpha"}"#,
            BTreeMap::from([("table".to_string(), "lineage_chain".to_string())]),
        );
        let legacy_key = legacy.key.clone();

        let mut corrupt = replacement_entry(8)
            .to_store_record(6)
            .expect("typed record should serialize");
        corrupt.value = b"{not json}".to_vec();
        let corrupt_key = corrupt.key.clone();

        let wrong_store = ifc_entry(11, "trace-ifc")
            .to_store_record(7)
            .expect("typed record should serialize");
        let wrong_store_key = wrong_store.key.clone();

        let plan = plan_typed_store_backfill::<ReplacementLineageEntry>(&[
            ready,
            legacy,
            corrupt,
            wrong_store,
        ]);

        assert_eq!(plan.target_store, StoreKind::ReplacementLineage);
        assert_eq!(plan.model_name, "ReplacementLineageEntry");
        assert_eq!(plan.ready_count(), 1);
        assert_eq!(plan.legacy_unsupported_count(), 1);
        assert_eq!(plan.rejected_count(), 2);
        assert!(plan.requires_explicit_legacy_mapper());
        assert!(!plan.all_ready());

        let ready_decision = plan
            .decisions
            .iter()
            .find(|decision| decision.key == ready_key)
            .expect("ready typed row is present");
        assert_eq!(ready_decision.status, TypedBackfillStatus::Ready);
        assert_eq!(ready_decision.typed_record_id, Some(7));
        assert!(ready_decision.error_code.is_none());

        let legacy_decision = plan
            .decisions
            .iter()
            .find(|decision| decision.key == legacy_key)
            .expect("legacy row is present");
        assert_eq!(
            legacy_decision.status,
            TypedBackfillStatus::LegacyUnsupported
        );
        assert!(legacy_decision.typed_record_id.is_none());
        assert!(legacy_decision.error_code.is_none());
        assert!(
            legacy_decision
                .reason
                .contains("explicit lossless mapper required"),
            "legacy records must not be coerced implicitly: {legacy_decision:#?}"
        );

        let corrupt_decision = plan
            .decisions
            .iter()
            .find(|decision| decision.key == corrupt_key)
            .expect("corrupt typed row is present");
        assert_eq!(corrupt_decision.status, TypedBackfillStatus::Rejected);
        assert_eq!(corrupt_decision.error_code.as_deref(), Some("FE-STOR-0007"));
        assert!(corrupt_decision.reason.contains("typed payload rejected"));

        let wrong_store_decision = plan
            .decisions
            .iter()
            .find(|decision| decision.key == wrong_store_key)
            .expect("wrong-store row is present");
        assert_eq!(wrong_store_decision.status, TypedBackfillStatus::Rejected);
        assert_eq!(
            wrong_store_decision.error_code.as_deref(),
            Some("FE-STOR-0007")
        );
        assert!(
            wrong_store_decision
                .reason
                .contains("backfill store mismatch")
        );

        let json = serde_json::to_string(&plan).expect("backfill plan is loggable JSON");
        assert!(json.contains("\"status\":\"LegacyUnsupported\""));
        assert!(json.contains("\"error_code\":\"FE-STOR-0007\""));
    }

    #[test]
    fn typed_backfill_plan_rejects_partial_typed_envelopes() {
        let partial = legacy_record(
            StoreKind::ReplacementLineage,
            "typed/replacement_lineage/00000000000000000009",
            br#"{"sequence":9,"kind":"legacy"}"#,
            BTreeMap::new(),
        );

        let plan = plan_typed_store_backfill::<ReplacementLineageEntry>(&[partial]);

        assert_eq!(plan.ready_count(), 0);
        assert_eq!(plan.legacy_unsupported_count(), 0);
        assert_eq!(plan.rejected_count(), 1);
        assert!(!plan.requires_explicit_legacy_mapper());
        assert_eq!(plan.decisions[0].status, TypedBackfillStatus::Rejected);
        assert_eq!(
            plan.decisions[0].error_code.as_deref(),
            Some("FE-STOR-0007")
        );
        assert!(
            plan.decisions[0].reason.contains("partial typed envelope"),
            "typed-looking rows without complete metadata are corrupt, not legacy: {:#?}",
            plan.decisions[0]
        );
    }

    #[test]
    fn typed_backfill_plan_marks_domain_legacy_prefixes_as_mapper_required() {
        let ifc_legacy = legacy_record(
            StoreKind::IfcProvenance,
            "flow_event::ev-1",
            br#"{"event_id":"ev-1","extension_id":"ext-a"}"#,
            BTreeMap::new(),
        );
        let ifc_plan = plan_typed_store_backfill::<IfcProvenanceEntry>(&[ifc_legacy]);
        assert_eq!(ifc_plan.ready_count(), 0);
        assert_eq!(ifc_plan.legacy_unsupported_count(), 1);
        assert_eq!(ifc_plan.rejected_count(), 0);
        assert!(ifc_plan.requires_explicit_legacy_mapper());
        assert_eq!(
            ifc_plan.decisions[0].status,
            TypedBackfillStatus::LegacyUnsupported
        );

        let specialization_legacy = legacy_record(
            StoreKind::SpecializationIndex,
            "receipt:proof-13",
            br#"{"receipt_id":"proof-13","active":true}"#,
            BTreeMap::new(),
        );
        let specialization_plan =
            plan_typed_store_backfill::<SpecializationIndexEntry>(&[specialization_legacy]);
        assert_eq!(specialization_plan.ready_count(), 0);
        assert_eq!(specialization_plan.legacy_unsupported_count(), 1);
        assert_eq!(specialization_plan.rejected_count(), 0);
        assert!(specialization_plan.requires_explicit_legacy_mapper());
        assert!(
            specialization_plan.decisions[0]
                .reason
                .contains("explicit lossless mapper required")
        );
    }

    #[test]
    fn typed_backfill_plan_all_ready_when_every_row_is_current_typed_format() {
        let rows = vec![
            ifc_entry(11, "trace-ifc")
                .to_store_record(1)
                .expect("typed record serializes"),
            ifc_entry(12, "trace-ifc")
                .to_store_record(2)
                .expect("typed record serializes"),
        ];

        let plan = plan_typed_store_backfill::<IfcProvenanceEntry>(&rows);

        assert_eq!(plan.ready_count(), 2);
        assert_eq!(plan.legacy_unsupported_count(), 0);
        assert_eq!(plan.rejected_count(), 0);
        assert!(plan.all_ready());
        assert_eq!(
            plan.decisions
                .iter()
                .map(|decision| decision.typed_record_id)
                .collect::<Vec<_>>(),
            vec![Some(11), Some(12)]
        );
    }
}

// ---------------------------------------------------------------------------
// TODO: Integration scaffolding
// ---------------------------------------------------------------------------

// TODO: Implement SQLModel session management for typed store operations
// ✓ DONE: Add explicit typed backfill dry-run planning for legacy generic StoreRecord data
// TODO: Add store-specific lossless legacy-to-typed backfill mappers
// ✓ DONE: Add typed StoreRecord boundaries and StorageAdapter extension methods
// TODO: Add validation rules for each model (foreign keys, constraints)
// ✓ DONE: Implement query builders for common access patterns
// TODO: Add integration tests with actual sqlmodel_rust session
// TODO: Wire production SQLModel sessions behind typed adapter methods
// TODO: Add sqlmodel_rust session initialization in storage adapter constructor
// TODO: Update all callers to use typed store operations instead of generic record operations
