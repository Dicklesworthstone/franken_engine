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