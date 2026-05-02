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

use serde::{Deserialize, Serialize};
use sqlmodel::prelude::*;

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

#[cfg(test)]
mod tests {
    use super::*;
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
}

// ---------------------------------------------------------------------------
// TODO: Integration scaffolding
// ---------------------------------------------------------------------------

// TODO: Implement SQLModel session management for typed store operations
// TODO: Add migration support for existing generic StoreRecord data
// ✓ DONE: Update storage_adapter.rs to use these typed models
// TODO: Add validation rules for each model (foreign keys, constraints)
// TODO: Implement query builders for common access patterns
// TODO: Add integration tests with actual sqlmodel_rust session
// TODO: Implement StorageAdapter trait methods to use typed models instead of StoreRecord
// TODO: Add sqlmodel_rust session initialization in storage adapter constructor
// TODO: Update all callers to use typed store operations instead of generic record operations
