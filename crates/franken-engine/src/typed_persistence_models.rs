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
mod tests {
    use super::*;
    use crate::storage_adapter::InMemoryStorageAdapter;
    use sqlmodel::{FieldInfo, Model, Row, SqlType, Value};

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
}

// ---------------------------------------------------------------------------
// TODO: Integration scaffolding
// ---------------------------------------------------------------------------

// TODO: Implement SQLModel session management for typed store operations
// TODO: Add explicit migration/backfill support for legacy generic StoreRecord data
// ✓ DONE: Add typed StoreRecord boundaries and StorageAdapter extension methods
// TODO: Add validation rules for each model (foreign keys, constraints)
// ✓ DONE: Implement query builders for common access patterns
// TODO: Add integration tests with actual sqlmodel_rust session
// TODO: Wire production SQLModel sessions behind typed adapter methods
// TODO: Add sqlmodel_rust session initialization in storage adapter constructor
// TODO: Update all callers to use typed store operations instead of generic record operations
