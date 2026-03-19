//! Frankensqlite-backed provenance index for IFC evidence.
//!
//! Supports deterministic source-to-sink lineage queries and replay joins.
//! All records are keyed and stored via the [`StorageAdapter`] trait using
//! `StoreKind::IfcProvenance`.  Queries are deterministic: the same index
//! state always returns the same results in the same order.
//!
//! Fixed-point millionths (1_000_000 = 1.0) for fractional values.
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//!
//! Plan reference: Section 10.15 item 9I.7, bd-1hh4.
//! Dependencies: bd-3hkk (declassification pipeline), bd-89l2 (storage adapter).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::ifc_artifacts::{ClaimStrength, DeclassificationDecision, Label, ProofMethod};
use crate::storage_adapter::{
    EventContext, StorageAdapter, StorageError, StoreKind, StoreQuery, StoreRecord,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const STORE: StoreKind = StoreKind::IfcProvenance;
const COMPONENT: &str = "ifc_provenance_index";

// Key prefixes for different record types.
const FLOW_EVENT_PREFIX: &str = "flow_event::";
const FLOW_PROOF_PREFIX: &str = "flow_proof::";
const DECLASS_RECEIPT_PREFIX: &str = "declass_receipt::";
const CONFINEMENT_CLAIM_PREFIX: &str = "confinement_claim::";

// ---------------------------------------------------------------------------
// Record types
// ---------------------------------------------------------------------------

/// A flow-check event (allowed, blocked, or declassified).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowEventRecord {
    pub event_id: String,
    pub extension_id: String,
    pub source_label: Label,
    pub sink_clearance: Label,
    pub flow_location: String,
    pub decision: FlowDecision,
    pub receipt_ref: Option<String>,
    pub timestamp_ms: u64,
}

/// Decision outcome for a flow check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FlowDecision {
    Allowed,
    Blocked,
    Declassified,
}

impl fmt::Display for FlowDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allowed => write!(f, "allowed"),
            Self::Blocked => write!(f, "blocked"),
            Self::Declassified => write!(f, "declassified"),
        }
    }
}

/// A flow proof record stored in the index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FlowProofRecord {
    pub proof_id: String,
    pub extension_id: String,
    pub source_label: Label,
    pub sink_clearance: Label,
    pub proof_method: ProofMethod,
    pub epoch_id: u64,
}

/// A declassification receipt record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DeclassReceiptRecord {
    pub receipt_id: String,
    pub extension_id: String,
    pub decision: DeclassificationDecision,
    pub source_label: Label,
    pub sink_clearance: Label,
    /// Governing policy route; defaults empty for pre-route legacy receipts.
    #[serde(default)]
    pub declassification_route_ref: String,
    /// Governing decision contract; defaults empty for legacy receipts.
    #[serde(default)]
    pub decision_contract_id: String,
    pub timestamp_ms: u64,
}

/// A confinement claim record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ConfinementClaimRecord {
    pub claim_id: String,
    pub extension_id: String,
    pub claim_strength: ClaimStrength,
    pub epoch_id: u64,
}

// ---------------------------------------------------------------------------
// Lineage types
// ---------------------------------------------------------------------------

/// A single hop in a source-to-sink lineage path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LineageHop {
    /// Source label at this hop.
    pub source_label: Label,
    /// Sink clearance at this hop.
    pub sink_clearance: Label,
    /// Evidence reference (proof_id, receipt_id, or event_id).
    pub evidence_ref: String,
    /// Type of evidence.
    pub evidence_type: LineageEvidenceType,
}

/// Type of evidence backing a lineage hop.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum LineageEvidenceType {
    FlowEvent,
    FlowProof,
    DeclassificationReceipt,
}

impl fmt::Display for LineageEvidenceType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FlowEvent => write!(f, "flow_event"),
            Self::FlowProof => write!(f, "flow_proof"),
            Self::DeclassificationReceipt => write!(f, "declassification_receipt"),
        }
    }
}

/// A complete lineage path from source to sink.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct LineagePath {
    /// Extension this path belongs to.
    pub extension_id: String,
    /// Ordered hops from source to sink.
    pub hops: Vec<LineageHop>,
}

/// Extension confinement status aggregated from flow proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfinementStatus {
    pub extension_id: String,
    /// Flows covered by proofs.
    pub proven_flows: usize,
    /// Flows with events but no proof.
    pub unproven_flows: usize,
    /// Strongest confinement claim on record.
    pub strongest_claim: Option<ClaimStrength>,
    /// Epoch of the latest proof.
    pub latest_proof_epoch: Option<u64>,
}

// ---------------------------------------------------------------------------
// Structured events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceEvent {
    pub trace_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub extension_id: Option<String>,
    pub record_count: Option<usize>,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Provenance index error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProvenanceError {
    /// Record ID is empty.
    EmptyId { record_type: String },
    /// Extension ID is empty.
    EmptyExtensionId,
    /// Duplicate record.
    DuplicateRecord { key: String },
    /// Storage backend error.
    StorageError(String),
    /// Serialization failed.
    SerializationError(String),
}

impl fmt::Display for ProvenanceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyId { record_type } => {
                write!(f, "{record_type} has empty ID")
            }
            Self::EmptyExtensionId => write!(f, "extension_id is empty"),
            Self::DuplicateRecord { key } => write!(f, "duplicate record: {key}"),
            Self::StorageError(msg) => write!(f, "storage: {msg}"),
            Self::SerializationError(msg) => write!(f, "serialization: {msg}"),
        }
    }
}

impl std::error::Error for ProvenanceError {}

/// Stable error codes.
pub fn error_code(err: &ProvenanceError) -> &'static str {
    match err {
        ProvenanceError::EmptyId { .. } => "PROV_EMPTY_ID",
        ProvenanceError::EmptyExtensionId => "PROV_EMPTY_EXTENSION_ID",
        ProvenanceError::DuplicateRecord { .. } => "PROV_DUPLICATE",
        ProvenanceError::StorageError(_) => "PROV_STORAGE_ERROR",
        ProvenanceError::SerializationError(_) => "PROV_SERIALIZATION_ERROR",
    }
}

impl From<StorageError> for ProvenanceError {
    fn from(e: StorageError) -> Self {
        Self::StorageError(e.code().to_string())
    }
}

// ---------------------------------------------------------------------------
// Provenance index
// ---------------------------------------------------------------------------

/// IFC provenance index backed by a `StorageAdapter`.
#[derive(Debug)]
pub struct IfcProvenanceIndex<S: StorageAdapter> {
    store: S,
    events: Vec<ProvenanceEvent>,
}

impl<S: StorageAdapter> IfcProvenanceIndex<S> {
    pub fn new(store: S) -> Self {
        Self {
            store,
            events: Vec::new(),
        }
    }

    // -- Write operations ---------------------------------------------------

    /// Insert a flow event record.
    pub fn insert_flow_event(
        &mut self,
        record: &FlowEventRecord,
        ctx: &EventContext,
    ) -> Result<(), ProvenanceError> {
        if record.event_id.is_empty() {
            return Err(ProvenanceError::EmptyId {
                record_type: "flow_event".to_string(),
            });
        }
        if record.extension_id.is_empty() {
            return Err(ProvenanceError::EmptyExtensionId);
        }
        let key = format!("{FLOW_EVENT_PREFIX}{}", record.event_id);
        self.put_record(&key, record, ctx)?;
        self.push_event(&ctx.trace_id, "flow_event_inserted", "ok", None);
        Ok(())
    }

    /// Insert a flow proof record.
    pub fn insert_flow_proof(
        &mut self,
        record: &FlowProofRecord,
        ctx: &EventContext,
    ) -> Result<(), ProvenanceError> {
        if record.proof_id.is_empty() {
            return Err(ProvenanceError::EmptyId {
                record_type: "flow_proof".to_string(),
            });
        }
        if record.extension_id.is_empty() {
            return Err(ProvenanceError::EmptyExtensionId);
        }
        let key = format!("{FLOW_PROOF_PREFIX}{}", record.proof_id);
        self.put_record(&key, record, ctx)?;
        self.push_event(&ctx.trace_id, "flow_proof_inserted", "ok", None);
        Ok(())
    }

    /// Insert a declassification receipt record.
    pub fn insert_declass_receipt(
        &mut self,
        record: &DeclassReceiptRecord,
        ctx: &EventContext,
    ) -> Result<(), ProvenanceError> {
        if record.receipt_id.is_empty() {
            return Err(ProvenanceError::EmptyId {
                record_type: "declass_receipt".to_string(),
            });
        }
        if record.extension_id.is_empty() {
            return Err(ProvenanceError::EmptyExtensionId);
        }
        let key = format!("{DECLASS_RECEIPT_PREFIX}{}", record.receipt_id);
        self.put_record(&key, record, ctx)?;
        self.push_event(&ctx.trace_id, "declass_receipt_inserted", "ok", None);
        Ok(())
    }

    /// Insert a confinement claim record.
    pub fn insert_confinement_claim(
        &mut self,
        record: &ConfinementClaimRecord,
        ctx: &EventContext,
    ) -> Result<(), ProvenanceError> {
        if record.claim_id.is_empty() {
            return Err(ProvenanceError::EmptyId {
                record_type: "confinement_claim".to_string(),
            });
        }
        if record.extension_id.is_empty() {
            return Err(ProvenanceError::EmptyExtensionId);
        }
        let key = format!("{CONFINEMENT_CLAIM_PREFIX}{}", record.claim_id);
        self.put_record(&key, record, ctx)?;
        self.push_event(&ctx.trace_id, "confinement_claim_inserted", "ok", None);
        Ok(())
    }

    // -- Query operations ---------------------------------------------------

    /// Get all flow events for an extension.
    pub fn flow_events_by_extension(
        &mut self,
        extension_id: &str,
        ctx: &EventContext,
    ) -> Result<Vec<FlowEventRecord>, ProvenanceError> {
        let records = self.query_prefix(FLOW_EVENT_PREFIX, ctx)?;
        let mut results = Vec::new();
        for r in records {
            if let Ok(rec) = serde_json::from_slice::<FlowEventRecord>(&r.value)
                && rec.extension_id == extension_id
            {
                results.push(rec);
            }
        }
        results.sort();
        Ok(results)
    }

    /// Get all flow proofs for an extension.
    pub fn flow_proofs_by_extension(
        &mut self,
        extension_id: &str,
        ctx: &EventContext,
    ) -> Result<Vec<FlowProofRecord>, ProvenanceError> {
        let records = self.query_prefix(FLOW_PROOF_PREFIX, ctx)?;
        let mut results = Vec::new();
        for r in records {
            if let Ok(rec) = serde_json::from_slice::<FlowProofRecord>(&r.value)
                && rec.extension_id == extension_id
            {
                results.push(rec);
            }
        }
        results.sort();
        Ok(results)
    }

    /// Get all declassification receipts for an extension.
    pub fn declass_receipts_by_extension(
        &mut self,
        extension_id: &str,
        ctx: &EventContext,
    ) -> Result<Vec<DeclassReceiptRecord>, ProvenanceError> {
        let records = self.query_prefix(DECLASS_RECEIPT_PREFIX, ctx)?;
        let mut results = Vec::new();
        for r in records {
            if let Ok(rec) = serde_json::from_slice::<DeclassReceiptRecord>(&r.value)
                && rec.extension_id == extension_id
            {
                results.push(rec);
            }
        }
        results.sort();
        Ok(results)
    }

    /// Get all confinement claims for an extension.
    pub fn confinement_claims_by_extension(
        &mut self,
        extension_id: &str,
        ctx: &EventContext,
    ) -> Result<Vec<ConfinementClaimRecord>, ProvenanceError> {
        let records = self.query_prefix(CONFINEMENT_CLAIM_PREFIX, ctx)?;
        let mut results = Vec::new();
        for r in records {
            if let Ok(rec) = serde_json::from_slice::<ConfinementClaimRecord>(&r.value)
                && rec.extension_id == extension_id
            {
                results.push(rec);
            }
        }
        results.sort();
        Ok(results)
    }

    // -- Lineage queries ----------------------------------------------------

    /// Maximum transitive closure depth to prevent runaway graph walks.
    const MAX_LINEAGE_DEPTH: usize = 16;

    /// Source-to-sink lineage: given a source label, find all proven flow
    /// paths to sinks with evidence references.
    ///
    /// Supports multi-hop transitive closure: if data flows A→B and B→C,
    /// the result includes the path A→B→C with evidence at each hop.
    /// Depth is bounded by [`MAX_LINEAGE_DEPTH`] to prevent cycles.
    pub fn source_to_sink_lineage(
        &mut self,
        extension_id: &str,
        source_label: &Label,
        ctx: &EventContext,
    ) -> Result<Vec<LineagePath>, ProvenanceError> {
        let edges = self.collect_edges(extension_id, ctx)?;

        let mut paths = Vec::new();
        let initial_path = LineagePath {
            extension_id: extension_id.to_string(),
            hops: Vec::new(),
        };

        Self::traverse_lineage(source_label, &edges, initial_path, &mut paths);

        paths.sort();
        self.push_event(&ctx.trace_id, "lineage_query", "ok", None);
        Ok(paths)
    }

    /// Sink provenance: given a sink clearance, find all data sources that
    /// have flowed to it. Includes transitive sources (if A→B→sink, both
    /// A and B are returned).
    pub fn sink_provenance(
        &mut self,
        extension_id: &str,
        sink_clearance: &Label,
        ctx: &EventContext,
    ) -> Result<BTreeSet<Label>, ProvenanceError> {
        let events = self.flow_events_by_extension(extension_id, ctx)?;
        let proofs = self.flow_proofs_by_extension(extension_id, ctx)?;
        let receipts = self.declass_receipts_by_extension(extension_id, ctx)?;

        let mut sources = BTreeSet::new();

        // Direct sources from events.
        for ev in &events {
            if ev.sink_clearance == *sink_clearance {
                sources.insert(ev.source_label.clone());
            }
        }
        // Direct sources from proofs.
        for proof in &proofs {
            if proof.sink_clearance == *sink_clearance {
                sources.insert(proof.source_label.clone());
            }
        }
        // Direct sources from allowed declassification receipts.
        for receipt in &receipts {
            if receipt.sink_clearance == *sink_clearance
                && receipt.decision == DeclassificationDecision::Allow
            {
                sources.insert(receipt.source_label.clone());
            }
        }

        // Transitive: for each source, find labels that flow into it.
        let mut frontier: Vec<Label> = sources.iter().cloned().collect();
        let mut depth = 0;
        while !frontier.is_empty() && depth < Self::MAX_LINEAGE_DEPTH {
            let mut next_frontier = Vec::new();
            for label in &frontier {
                for ev in &events {
                    if ev.sink_clearance == *label && !sources.contains(&ev.source_label) {
                        sources.insert(ev.source_label.clone());
                        next_frontier.push(ev.source_label.clone());
                    }
                }
                for proof in &proofs {
                    if proof.sink_clearance == *label && !sources.contains(&proof.source_label) {
                        sources.insert(proof.source_label.clone());
                        next_frontier.push(proof.source_label.clone());
                    }
                }
            }
            frontier = next_frontier;
            depth += 1;
        }
        Ok(sources)
    }

    /// Query flow events within a time range (inclusive).
    pub fn flow_events_by_time_range(
        &mut self,
        extension_id: &str,
        start_ms: u64,
        end_ms: u64,
        ctx: &EventContext,
    ) -> Result<Vec<FlowEventRecord>, ProvenanceError> {
        let all = self.flow_events_by_extension(extension_id, ctx)?;
        let filtered: Vec<FlowEventRecord> = all
            .into_iter()
            .filter(|ev| ev.timestamp_ms >= start_ms && ev.timestamp_ms <= end_ms)
            .collect();
        Ok(filtered)
    }

    /// Query flow proofs by security epoch.
    pub fn flow_proofs_by_epoch(
        &mut self,
        extension_id: &str,
        epoch_id: u64,
        ctx: &EventContext,
    ) -> Result<Vec<FlowProofRecord>, ProvenanceError> {
        let all = self.flow_proofs_by_extension(extension_id, ctx)?;
        let filtered: Vec<FlowProofRecord> =
            all.into_iter().filter(|p| p.epoch_id == epoch_id).collect();
        Ok(filtered)
    }

    /// Get a single flow event by ID.
    pub fn get_flow_event(
        &mut self,
        event_id: &str,
        ctx: &EventContext,
    ) -> Result<Option<FlowEventRecord>, ProvenanceError> {
        let key = format!("{FLOW_EVENT_PREFIX}{event_id}");
        self.get_record(&key, ctx)
    }

    /// Get a single flow proof by ID.
    pub fn get_flow_proof(
        &mut self,
        proof_id: &str,
        ctx: &EventContext,
    ) -> Result<Option<FlowProofRecord>, ProvenanceError> {
        let key = format!("{FLOW_PROOF_PREFIX}{proof_id}");
        self.get_record(&key, ctx)
    }

    /// Get a single declassification receipt by ID.
    pub fn get_declass_receipt(
        &mut self,
        receipt_id: &str,
        ctx: &EventContext,
    ) -> Result<Option<DeclassReceiptRecord>, ProvenanceError> {
        let key = format!("{DECLASS_RECEIPT_PREFIX}{receipt_id}");
        self.get_record(&key, ctx)
    }

    /// Get a single confinement claim by ID.
    pub fn get_confinement_claim(
        &mut self,
        claim_id: &str,
        ctx: &EventContext,
    ) -> Result<Option<ConfinementClaimRecord>, ProvenanceError> {
        let key = format!("{CONFINEMENT_CLAIM_PREFIX}{claim_id}");
        self.get_record(&key, ctx)
    }

    /// Count total records of each type for an extension.
    pub fn record_counts(
        &mut self,
        extension_id: &str,
        ctx: &EventContext,
    ) -> Result<RecordCounts, ProvenanceError> {
        Ok(RecordCounts {
            flow_events: self.flow_events_by_extension(extension_id, ctx)?.len(),
            flow_proofs: self.flow_proofs_by_extension(extension_id, ctx)?.len(),
            declass_receipts: self.declass_receipts_by_extension(extension_id, ctx)?.len(),
            confinement_claims: self
                .confinement_claims_by_extension(extension_id, ctx)?
                .len(),
        })
    }

    /// Drain accumulated events.
    pub fn drain_events(&mut self) -> Vec<ProvenanceEvent> {
        std::mem::take(&mut self.events)
    }

    /// Extension confinement status: aggregate flow proof coverage.
    pub fn confinement_status(
        &mut self,
        extension_id: &str,
        ctx: &EventContext,
    ) -> Result<ConfinementStatus, ProvenanceError> {
        let events = self.flow_events_by_extension(extension_id, ctx)?;
        let proofs = self.flow_proofs_by_extension(extension_id, ctx)?;
        let claims = self.confinement_claims_by_extension(extension_id, ctx)?;

        // Collect unique flows from events.
        let event_flows: BTreeSet<(String, String)> = events
            .iter()
            .map(|e| (e.source_label.to_string(), e.sink_clearance.to_string()))
            .collect();

        // Collect unique flows from proofs.
        let proof_flows: BTreeSet<(String, String)> = proofs
            .iter()
            .map(|p| (p.source_label.to_string(), p.sink_clearance.to_string()))
            .collect();

        let proven = event_flows.intersection(&proof_flows).count();
        let unproven = event_flows.difference(&proof_flows).count();

        let strongest_claim = claims
            .iter()
            .map(|c| c.claim_strength)
            .max_by_key(|s| match s {
                ClaimStrength::Full => 1,
                ClaimStrength::Partial => 0,
            });

        let latest_epoch = proofs.iter().map(|p| p.epoch_id).max();

        Ok(ConfinementStatus {
            extension_id: extension_id.to_string(),
            proven_flows: proven,
            unproven_flows: unproven,
            strongest_claim,
            latest_proof_epoch: latest_epoch,
        })
    }

    // -- Replay join support ------------------------------------------------

    /// Join flow events with their corresponding declassification receipts.
    pub fn join_events_with_receipts(
        &mut self,
        extension_id: &str,
        ctx: &EventContext,
    ) -> Result<Vec<(FlowEventRecord, Option<DeclassReceiptRecord>)>, ProvenanceError> {
        let events = self.flow_events_by_extension(extension_id, ctx)?;
        let receipts = self.declass_receipts_by_extension(extension_id, ctx)?;

        let receipt_map: BTreeMap<String, DeclassReceiptRecord> = receipts
            .into_iter()
            .map(|r| (r.receipt_id.clone(), r))
            .collect();

        let results: Vec<(FlowEventRecord, Option<DeclassReceiptRecord>)> = events
            .into_iter()
            .map(|ev| {
                let receipt = ev
                    .receipt_ref
                    .as_ref()
                    .and_then(|ref_id| receipt_map.get(ref_id).cloned());
                (ev, receipt)
            })
            .collect();

        Ok(results)
    }

    // -- Accessors ----------------------------------------------------------

    /// Events emitted during index operations.
    pub fn events(&self) -> &[ProvenanceEvent] {
        &self.events
    }

    /// Mutable access to the underlying store.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    // -- Internal helpers ---------------------------------------------------

    /// Collect all flow edges from events, proofs, and allowed receipts.
    fn collect_edges(
        &mut self,
        extension_id: &str,
        ctx: &EventContext,
    ) -> Result<Vec<LineageHop>, ProvenanceError> {
        let events = self.flow_events_by_extension(extension_id, ctx)?;
        let proofs = self.flow_proofs_by_extension(extension_id, ctx)?;
        let receipts = self.declass_receipts_by_extension(extension_id, ctx)?;

        let mut edges = Vec::new();
        for ev in &events {
            edges.push(LineageHop {
                source_label: ev.source_label.clone(),
                sink_clearance: ev.sink_clearance.clone(),
                evidence_ref: ev.event_id.clone(),
                evidence_type: LineageEvidenceType::FlowEvent,
            });
        }
        for proof in &proofs {
            edges.push(LineageHop {
                source_label: proof.source_label.clone(),
                sink_clearance: proof.sink_clearance.clone(),
                evidence_ref: proof.proof_id.clone(),
                evidence_type: LineageEvidenceType::FlowProof,
            });
        }
        for receipt in &receipts {
            if receipt.decision == DeclassificationDecision::Allow {
                edges.push(LineageHop {
                    source_label: receipt.source_label.clone(),
                    sink_clearance: receipt.sink_clearance.clone(),
                    evidence_ref: receipt.receipt_id.clone(),
                    evidence_type: LineageEvidenceType::DeclassificationReceipt,
                });
            }
        }
        Ok(edges)
    }

    /// DFS traverse from the given label, extending the current path.
    /// When a hop leads to a sink with no further outgoing edges or
    /// depth is exhausted, the path is collected.
    fn traverse_lineage(
        current_label: &Label,
        edges: &[LineageHop],
        current_path: LineagePath,
        paths: &mut Vec<LineagePath>,
    ) {
        if current_path.hops.len() >= Self::MAX_LINEAGE_DEPTH {
            if !current_path.hops.is_empty() {
                paths.push(current_path);
            }
            return;
        }

        // Prevent visiting the same label twice in a single path (cycle guard).
        let visited: BTreeSet<&Label> = current_path.hops.iter().map(|h| &h.source_label).collect();

        let mut found_continuation = false;
        for edge in edges {
            if edge.source_label == *current_label && !visited.contains(&edge.sink_clearance) {
                found_continuation = true;
                let mut extended = current_path.clone();
                extended.hops.push(edge.clone());

                // Continue traversal from the sink of this edge.
                Self::traverse_lineage(&edge.sink_clearance, edges, extended.clone(), paths);

                // Also collect the partial path (this edge itself is a valid path).
                paths.push(extended);
            }
        }

        // If no continuation was found and we have hops, this is a terminal path.
        // (Already collected above via extended push.)
        let _ = found_continuation;
    }

    fn get_record<T: serde::de::DeserializeOwned>(
        &mut self,
        key: &str,
        ctx: &EventContext,
    ) -> Result<Option<T>, ProvenanceError> {
        match self.store.get(STORE, key, ctx) {
            Ok(Some(record)) => {
                let parsed = serde_json::from_slice(&record.value)
                    .map_err(|e| ProvenanceError::SerializationError(e.to_string()))?;
                Ok(Some(parsed))
            }
            Ok(None) | Err(_) => Ok(None),
        }
    }

    fn put_record<T: Serialize>(
        &mut self,
        key: &str,
        record: &T,
        ctx: &EventContext,
    ) -> Result<StoreRecord, ProvenanceError> {
        let value = serde_json::to_vec(record)
            .map_err(|e| ProvenanceError::SerializationError(e.to_string()))?;
        let metadata = BTreeMap::new();
        self.store
            .put(STORE, key.to_string(), value, metadata, ctx)
            .map_err(ProvenanceError::from)
    }

    fn query_prefix(
        &mut self,
        prefix: &str,
        ctx: &EventContext,
    ) -> Result<Vec<StoreRecord>, ProvenanceError> {
        let query = StoreQuery {
            key_prefix: Some(prefix.to_string()),
            ..StoreQuery::default()
        };
        self.store
            .query(STORE, &query, ctx)
            .map_err(ProvenanceError::from)
    }

    fn push_event(&mut self, trace_id: &str, event: &str, outcome: &str, err_code: Option<&str>) {
        self.events.push(ProvenanceEvent {
            trace_id: trace_id.to_string(),
            component: COMPONENT.to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: err_code.map(str::to_string),
            extension_id: None,
            record_count: None,
        });
    }
}

// ---------------------------------------------------------------------------
// Record counts
// ---------------------------------------------------------------------------

/// Record counts per extension for summary reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordCounts {
    pub flow_events: usize,
    pub flow_proofs: usize,
    pub declass_receipts: usize,
    pub confinement_claims: usize,
}

impl RecordCounts {
    /// Total records across all types.
    pub fn total(&self) -> usize {
        self.flow_events + self.flow_proofs + self.declass_receipts + self.confinement_claims
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage_adapter::InMemoryStorageAdapter;

    // -- helpers ------------------------------------------------------------

    fn test_ctx() -> EventContext {
        EventContext::new("trace-test", "decision-test", "policy-test").expect("test ctx")
    }

    fn make_index() -> IfcProvenanceIndex<InMemoryStorageAdapter> {
        IfcProvenanceIndex::new(InMemoryStorageAdapter::new())
    }

    fn flow_event(
        id: &str,
        ext: &str,
        src: Label,
        sink: Label,
        dec: FlowDecision,
    ) -> FlowEventRecord {
        FlowEventRecord {
            event_id: id.to_string(),
            extension_id: ext.to_string(),
            source_label: src,
            sink_clearance: sink,
            flow_location: "src/main.rs:10".to_string(),
            decision: dec,
            receipt_ref: None,
            timestamp_ms: 1000,
        }
    }

    fn flow_proof(id: &str, ext: &str, src: Label, sink: Label, epoch: u64) -> FlowProofRecord {
        FlowProofRecord {
            proof_id: id.to_string(),
            extension_id: ext.to_string(),
            source_label: src,
            sink_clearance: sink,
            proof_method: ProofMethod::StaticAnalysis,
            epoch_id: epoch,
        }
    }

    fn declass_receipt(
        id: &str,
        ext: &str,
        src: Label,
        sink: Label,
        decision: DeclassificationDecision,
    ) -> DeclassReceiptRecord {
        DeclassReceiptRecord {
            receipt_id: id.to_string(),
            extension_id: ext.to_string(),
            decision,
            source_label: src,
            sink_clearance: sink,
            declassification_route_ref: format!("route-{id}"),
            decision_contract_id: format!("decision-{id}"),
            timestamp_ms: 2000,
        }
    }

    fn confinement_claim(
        id: &str,
        ext: &str,
        strength: ClaimStrength,
        epoch: u64,
    ) -> ConfinementClaimRecord {
        ConfinementClaimRecord {
            claim_id: id.to_string(),
            extension_id: ext.to_string(),
            claim_strength: strength,
            epoch_id: epoch,
        }
    }

    // -- insert / query tests -----------------------------------------------

    #[test]
    fn insert_and_query_flow_event() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let ev = flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        idx.insert_flow_event(&ev, &ctx).unwrap();

        let results = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, "ev1");
    }

    #[test]
    fn insert_and_query_flow_proof() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let proof = flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1);
        idx.insert_flow_proof(&proof, &ctx).unwrap();

        let results = idx.flow_proofs_by_extension("ext-a", &ctx).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].proof_id, "p1");
    }

    #[test]
    fn insert_and_query_declass_receipt() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let receipt = declass_receipt(
            "r1",
            "ext-a",
            Label::Confidential,
            Label::Public,
            DeclassificationDecision::Allow,
        );
        idx.insert_declass_receipt(&receipt, &ctx).unwrap();

        let results = idx.declass_receipts_by_extension("ext-a", &ctx).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].receipt_id, "r1");
        assert_eq!(results[0].decision_contract_id, "decision-r1");
    }

    #[test]
    fn insert_and_query_confinement_claim() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let claim = confinement_claim("c1", "ext-a", ClaimStrength::Full, 1);
        idx.insert_confinement_claim(&claim, &ctx).unwrap();

        let results = idx.confinement_claims_by_extension("ext-a", &ctx).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].claim_id, "c1");
    }

    // -- validation tests ---------------------------------------------------

    #[test]
    fn reject_empty_event_id() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let ev = flow_event(
            "",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        let err = idx.insert_flow_event(&ev, &ctx).unwrap_err();
        assert!(matches!(err, ProvenanceError::EmptyId { .. }));
    }

    #[test]
    fn reject_empty_extension_id() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let ev = flow_event(
            "ev1",
            "",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        let err = idx.insert_flow_event(&ev, &ctx).unwrap_err();
        assert_eq!(err, ProvenanceError::EmptyExtensionId);
    }

    #[test]
    fn reject_empty_proof_id() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let proof = flow_proof("", "ext-a", Label::Public, Label::Internal, 1);
        let err = idx.insert_flow_proof(&proof, &ctx).unwrap_err();
        assert!(matches!(err, ProvenanceError::EmptyId { .. }));
    }

    #[test]
    fn reject_empty_receipt_id() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let receipt = declass_receipt(
            "",
            "ext-a",
            Label::Public,
            Label::Internal,
            DeclassificationDecision::Allow,
        );
        let err = idx.insert_declass_receipt(&receipt, &ctx).unwrap_err();
        assert!(matches!(err, ProvenanceError::EmptyId { .. }));
    }

    #[test]
    fn reject_empty_claim_id() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let claim = confinement_claim("", "ext-a", ClaimStrength::Full, 1);
        let err = idx.insert_confinement_claim(&claim, &ctx).unwrap_err();
        assert!(matches!(err, ProvenanceError::EmptyId { .. }));
    }

    // -- extension isolation ------------------------------------------------

    #[test]
    fn queries_filter_by_extension() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.insert_flow_event(
            &flow_event(
                "ev1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "ev2",
                "ext-b",
                Label::Internal,
                Label::Confidential,
                FlowDecision::Blocked,
            ),
            &ctx,
        )
        .unwrap();

        let a = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].event_id, "ev1");

        let b = idx.flow_events_by_extension("ext-b", &ctx).unwrap();
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].event_id, "ev2");
    }

    // -- lineage queries ----------------------------------------------------

    #[test]
    fn source_to_sink_lineage_from_events() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.insert_flow_event(
            &flow_event(
                "ev1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "ev2",
                "ext-a",
                Label::Public,
                Label::Confidential,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "ev3",
                "ext-a",
                Label::Internal,
                Label::Confidential,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();

        let paths = idx
            .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
            .unwrap();
        // Multi-hop: Public→Internal (ev1), Public→Confidential (ev2),
        // and transitive Public→Internal→Confidential (ev1+ev3).
        assert_eq!(paths.len(), 3);
        let single_hop: Vec<_> = paths.iter().filter(|p| p.hops.len() == 1).collect();
        let multi_hop: Vec<_> = paths.iter().filter(|p| p.hops.len() == 2).collect();
        assert_eq!(single_hop.len(), 2);
        assert_eq!(multi_hop.len(), 1);
        assert_eq!(multi_hop[0].hops[0].sink_clearance, Label::Internal);
        assert_eq!(multi_hop[0].hops[1].sink_clearance, Label::Confidential);
    }

    #[test]
    fn source_to_sink_lineage_from_proofs() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Internal, Label::Confidential, 1),
            &ctx,
        )
        .unwrap();

        let paths = idx
            .source_to_sink_lineage("ext-a", &Label::Internal, &ctx)
            .unwrap();
        assert_eq!(paths.len(), 1);
        assert_eq!(
            paths[0].hops[0].evidence_type,
            LineageEvidenceType::FlowProof
        );
    }

    #[test]
    fn source_to_sink_lineage_from_declass_receipts() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.insert_declass_receipt(
            &declass_receipt(
                "r1",
                "ext-a",
                Label::Secret,
                Label::Public,
                DeclassificationDecision::Allow,
            ),
            &ctx,
        )
        .unwrap();
        // Deny receipt should not appear in lineage.
        idx.insert_declass_receipt(
            &declass_receipt(
                "r2",
                "ext-a",
                Label::Secret,
                Label::Internal,
                DeclassificationDecision::Deny,
            ),
            &ctx,
        )
        .unwrap();

        let paths = idx
            .source_to_sink_lineage("ext-a", &Label::Secret, &ctx)
            .unwrap();
        assert_eq!(paths.len(), 1); // Only the Allow receipt.
        assert_eq!(
            paths[0].hops[0].evidence_type,
            LineageEvidenceType::DeclassificationReceipt
        );
    }

    #[test]
    fn source_to_sink_empty_for_no_match() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let paths = idx
            .source_to_sink_lineage("ext-a", &Label::Secret, &ctx)
            .unwrap();
        assert!(paths.is_empty());
    }

    // -- sink provenance ----------------------------------------------------

    #[test]
    fn sink_provenance_collects_sources() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.insert_flow_event(
            &flow_event(
                "ev1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "ev2",
                "ext-a",
                Label::Confidential,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();

        let sources = idx
            .sink_provenance("ext-a", &Label::Internal, &ctx)
            .unwrap();
        assert_eq!(sources.len(), 2);
        assert!(sources.contains(&Label::Public));
        assert!(sources.contains(&Label::Confidential));
    }

    #[test]
    fn sink_provenance_empty_for_no_match() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let sources = idx.sink_provenance("ext-a", &Label::Secret, &ctx).unwrap();
        assert!(sources.is_empty());
    }

    // -- confinement status -------------------------------------------------

    #[test]
    fn confinement_status_basic() {
        let mut idx = make_index();
        let ctx = test_ctx();

        // 2 flow events.
        idx.insert_flow_event(
            &flow_event(
                "ev1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "ev2",
                "ext-a",
                Label::Internal,
                Label::Confidential,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();

        // 1 proof covering the first flow.
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
            &ctx,
        )
        .unwrap();

        // 1 claim.
        idx.insert_confinement_claim(
            &confinement_claim("c1", "ext-a", ClaimStrength::Partial, 1),
            &ctx,
        )
        .unwrap();

        let status = idx.confinement_status("ext-a", &ctx).unwrap();
        assert_eq!(status.extension_id, "ext-a");
        assert_eq!(status.proven_flows, 1);
        assert_eq!(status.unproven_flows, 1);
        assert_eq!(status.strongest_claim, Some(ClaimStrength::Partial));
        assert_eq!(status.latest_proof_epoch, Some(1));
    }

    #[test]
    fn confinement_status_full_coverage() {
        let mut idx = make_index();
        let ctx = test_ctx();

        idx.insert_flow_event(
            &flow_event(
                "ev1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 2),
            &ctx,
        )
        .unwrap();
        idx.insert_confinement_claim(
            &confinement_claim("c1", "ext-a", ClaimStrength::Full, 2),
            &ctx,
        )
        .unwrap();

        let status = idx.confinement_status("ext-a", &ctx).unwrap();
        assert_eq!(status.proven_flows, 1);
        assert_eq!(status.unproven_flows, 0);
        assert_eq!(status.strongest_claim, Some(ClaimStrength::Full));
        assert_eq!(status.latest_proof_epoch, Some(2));
    }

    #[test]
    fn confinement_status_empty_extension() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let status = idx.confinement_status("ext-empty", &ctx).unwrap();
        assert_eq!(status.proven_flows, 0);
        assert_eq!(status.unproven_flows, 0);
        assert!(status.strongest_claim.is_none());
        assert!(status.latest_proof_epoch.is_none());
    }

    // -- replay join --------------------------------------------------------

    #[test]
    fn join_events_with_receipts_matched() {
        let mut idx = make_index();
        let ctx = test_ctx();

        let mut ev = flow_event(
            "ev1",
            "ext-a",
            Label::Confidential,
            Label::Public,
            FlowDecision::Declassified,
        );
        ev.receipt_ref = Some("r1".to_string());
        idx.insert_flow_event(&ev, &ctx).unwrap();

        idx.insert_declass_receipt(
            &declass_receipt(
                "r1",
                "ext-a",
                Label::Confidential,
                Label::Public,
                DeclassificationDecision::Allow,
            ),
            &ctx,
        )
        .unwrap();

        let joined = idx.join_events_with_receipts("ext-a", &ctx).unwrap();
        assert_eq!(joined.len(), 1);
        assert!(joined[0].1.is_some());
        assert_eq!(joined[0].1.as_ref().unwrap().receipt_id, "r1");
        assert_eq!(
            joined[0].1.as_ref().unwrap().declassification_route_ref,
            "route-r1"
        );
        assert_eq!(
            joined[0].1.as_ref().unwrap().decision_contract_id,
            "decision-r1"
        );
    }

    #[test]
    fn join_events_with_receipts_unmatched() {
        let mut idx = make_index();
        let ctx = test_ctx();

        let ev = flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        idx.insert_flow_event(&ev, &ctx).unwrap();

        let joined = idx.join_events_with_receipts("ext-a", &ctx).unwrap();
        assert_eq!(joined.len(), 1);
        assert!(joined[0].1.is_none());
    }

    // -- serde roundtrips ---------------------------------------------------

    #[test]
    fn flow_event_record_serde_roundtrip() {
        let ev = flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        let json = serde_json::to_string(&ev).unwrap();
        let deser: FlowEventRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, deser);
    }

    #[test]
    fn flow_proof_record_serde_roundtrip() {
        let proof = flow_proof("p1", "ext-a", Label::Internal, Label::Confidential, 1);
        let json = serde_json::to_string(&proof).unwrap();
        let deser: FlowProofRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(proof, deser);
    }

    #[test]
    fn declass_receipt_record_serde_roundtrip() {
        let receipt = declass_receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        );
        let json = serde_json::to_string(&receipt).unwrap();
        let deser: DeclassReceiptRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, deser);
    }

    #[test]
    fn declass_receipt_record_legacy_serde_defaults_route_ref() {
        let mut value = serde_json::to_value(declass_receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        ))
        .unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("declassification_route_ref");
        value
            .as_object_mut()
            .unwrap()
            .remove("decision_contract_id");
        let deser: DeclassReceiptRecord = serde_json::from_value(value).unwrap();
        assert_eq!(deser.receipt_id, "r1");
        assert!(deser.declassification_route_ref.is_empty());
        assert!(deser.decision_contract_id.is_empty());
    }

    #[test]
    fn confinement_claim_record_serde_roundtrip() {
        let claim = confinement_claim("c1", "ext-a", ClaimStrength::Full, 1);
        let json = serde_json::to_string(&claim).unwrap();
        let deser: ConfinementClaimRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(claim, deser);
    }

    #[test]
    fn flow_decision_serde_roundtrip() {
        for d in [
            FlowDecision::Allowed,
            FlowDecision::Blocked,
            FlowDecision::Declassified,
        ] {
            let json = serde_json::to_string(&d).unwrap();
            let deser: FlowDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(d, deser);
        }
    }

    #[test]
    fn lineage_evidence_type_serde_roundtrip() {
        for t in [
            LineageEvidenceType::FlowEvent,
            LineageEvidenceType::FlowProof,
            LineageEvidenceType::DeclassificationReceipt,
        ] {
            let json = serde_json::to_string(&t).unwrap();
            let deser: LineageEvidenceType = serde_json::from_str(&json).unwrap();
            assert_eq!(t, deser);
        }
    }

    #[test]
    fn confinement_status_serde_roundtrip() {
        let status = ConfinementStatus {
            extension_id: "ext-a".to_string(),
            proven_flows: 5,
            unproven_flows: 2,
            strongest_claim: Some(ClaimStrength::Full),
            latest_proof_epoch: Some(3),
        };
        let json = serde_json::to_string(&status).unwrap();
        let deser: ConfinementStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(status, deser);
    }

    #[test]
    fn provenance_error_serde_roundtrip() {
        let errors = vec![
            ProvenanceError::EmptyId {
                record_type: "flow_event".to_string(),
            },
            ProvenanceError::EmptyExtensionId,
            ProvenanceError::DuplicateRecord {
                key: "k1".to_string(),
            },
            ProvenanceError::StorageError("test".to_string()),
            ProvenanceError::SerializationError("test".to_string()),
        ];
        for err in errors {
            let json = serde_json::to_string(&err).unwrap();
            let deser: ProvenanceError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, deser);
        }
    }

    #[test]
    fn provenance_event_serde_roundtrip() {
        let ev = ProvenanceEvent {
            trace_id: "t1".to_string(),
            component: COMPONENT.to_string(),
            event: "flow_event_inserted".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
            extension_id: Some("ext-a".to_string()),
            record_count: Some(1),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let deser: ProvenanceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, deser);
    }

    // -- display tests ------------------------------------------------------

    #[test]
    fn flow_decision_display() {
        assert_eq!(FlowDecision::Allowed.to_string(), "allowed");
        assert_eq!(FlowDecision::Blocked.to_string(), "blocked");
        assert_eq!(FlowDecision::Declassified.to_string(), "declassified");
    }

    #[test]
    fn lineage_evidence_type_display() {
        assert_eq!(LineageEvidenceType::FlowEvent.to_string(), "flow_event");
        assert_eq!(LineageEvidenceType::FlowProof.to_string(), "flow_proof");
        assert_eq!(
            LineageEvidenceType::DeclassificationReceipt.to_string(),
            "declassification_receipt"
        );
    }

    #[test]
    fn error_display_coverage() {
        let err = ProvenanceError::EmptyExtensionId;
        assert!(err.to_string().contains("empty"));
        let err = ProvenanceError::DuplicateRecord {
            key: "k".to_string(),
        };
        assert!(err.to_string().contains("duplicate"));
    }

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            error_code(&ProvenanceError::EmptyId {
                record_type: "x".to_string()
            }),
            "PROV_EMPTY_ID"
        );
        assert_eq!(
            error_code(&ProvenanceError::EmptyExtensionId),
            "PROV_EMPTY_EXTENSION_ID"
        );
        assert_eq!(
            error_code(&ProvenanceError::DuplicateRecord {
                key: "k".to_string()
            }),
            "PROV_DUPLICATE"
        );
        assert_eq!(
            error_code(&ProvenanceError::StorageError(String::new())),
            "PROV_STORAGE_ERROR"
        );
        assert_eq!(
            error_code(&ProvenanceError::SerializationError(String::new())),
            "PROV_SERIALIZATION_ERROR"
        );
    }

    // -- events emitted ----------------------------------------------------

    #[test]
    fn events_emitted_on_insert() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let ev = flow_event(
            "ev1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        idx.insert_flow_event(&ev, &ctx).unwrap();
        assert_eq!(idx.events().len(), 1);
        assert_eq!(idx.events()[0].event, "flow_event_inserted");
    }

    #[test]
    fn events_emitted_on_lineage_query() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.source_to_sink_lineage("ext-a", &Label::Public, &ctx)
            .unwrap();
        assert!(idx.events().iter().any(|e| e.event == "lineage_query"));
    }

    // -- multiple records ---------------------------------------------------

    #[test]
    fn multiple_records_of_each_type() {
        let mut idx = make_index();
        let ctx = test_ctx();

        for i in 0..5 {
            idx.insert_flow_event(
                &flow_event(
                    &format!("ev{i}"),
                    "ext-a",
                    Label::Public,
                    Label::Internal,
                    FlowDecision::Allowed,
                ),
                &ctx,
            )
            .unwrap();
        }
        for i in 0..3 {
            idx.insert_flow_proof(
                &flow_proof(&format!("p{i}"), "ext-a", Label::Public, Label::Internal, 1),
                &ctx,
            )
            .unwrap();
        }

        let events = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
        assert_eq!(events.len(), 5);
        let proofs = idx.flow_proofs_by_extension("ext-a", &ctx).unwrap();
        assert_eq!(proofs.len(), 3);
    }

    // -- multi-hop lineage --------------------------------------------------

    #[test]
    fn multi_hop_transitive_lineage() {
        let mut idx = make_index();
        let ctx = test_ctx();
        // Chain: Public → Internal → Confidential → Secret
        idx.insert_flow_event(
            &flow_event(
                "e1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "e2",
                "ext-a",
                Label::Internal,
                Label::Confidential,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "e3",
                "ext-a",
                Label::Confidential,
                Label::Secret,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();

        let paths = idx
            .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
            .unwrap();
        // Should include: 1-hop (Public→Internal), 2-hop (Public→Internal→Confidential),
        // 3-hop (Public→Internal→Confidential→Secret).
        let max_hops = paths.iter().map(|p| p.hops.len()).max().unwrap();
        assert_eq!(max_hops, 3);
        assert!(paths.len() >= 3);
        // The 3-hop path should trace Public→Internal→Confidential→Secret.
        let three_hop: Vec<_> = paths.iter().filter(|p| p.hops.len() == 3).collect();
        assert_eq!(three_hop.len(), 1);
        assert_eq!(three_hop[0].hops[0].sink_clearance, Label::Internal);
        assert_eq!(three_hop[0].hops[1].sink_clearance, Label::Confidential);
        assert_eq!(three_hop[0].hops[2].sink_clearance, Label::Secret);
    }

    #[test]
    fn lineage_cycle_detection() {
        let mut idx = make_index();
        let ctx = test_ctx();
        // Create cycle: Public → Internal → Public (should not loop).
        idx.insert_flow_event(
            &flow_event(
                "e1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "e2",
                "ext-a",
                Label::Internal,
                Label::Public,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();

        let paths = idx
            .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
            .unwrap();
        // Should terminate without infinite loop.
        assert!(!paths.is_empty());
        // No path should have more than 2 hops in this scenario.
        assert!(paths.iter().all(|p| p.hops.len() <= 2));
    }

    #[test]
    fn transitive_sink_provenance() {
        let mut idx = make_index();
        let ctx = test_ctx();
        // Chain: Public → Internal → Confidential
        idx.insert_flow_event(
            &flow_event(
                "e1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "e2",
                "ext-a",
                Label::Internal,
                Label::Confidential,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();

        let sources = idx
            .sink_provenance("ext-a", &Label::Confidential, &ctx)
            .unwrap();
        // Both Internal (direct) and Public (transitive) should appear.
        assert_eq!(sources.len(), 2);
        assert!(sources.contains(&Label::Internal));
        assert!(sources.contains(&Label::Public));
    }

    #[test]
    fn sink_provenance_from_declass_receipts() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.insert_declass_receipt(
            &declass_receipt(
                "r1",
                "ext-a",
                Label::Secret,
                Label::Public,
                DeclassificationDecision::Allow,
            ),
            &ctx,
        )
        .unwrap();
        // Deny receipts should not contribute sources.
        idx.insert_declass_receipt(
            &declass_receipt(
                "r2",
                "ext-a",
                Label::Confidential,
                Label::Public,
                DeclassificationDecision::Deny,
            ),
            &ctx,
        )
        .unwrap();

        let sources = idx.sink_provenance("ext-a", &Label::Public, &ctx).unwrap();
        assert_eq!(sources.len(), 1);
        assert!(sources.contains(&Label::Secret));
    }

    // -- time range queries -------------------------------------------------

    #[test]
    fn flow_events_by_time_range_basic() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let mut ev1 = flow_event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        ev1.timestamp_ms = 100;
        let mut ev2 = flow_event(
            "e2",
            "ext-a",
            Label::Internal,
            Label::Confidential,
            FlowDecision::Blocked,
        );
        ev2.timestamp_ms = 200;
        let mut ev3 = flow_event(
            "e3",
            "ext-a",
            Label::Public,
            Label::Secret,
            FlowDecision::Allowed,
        );
        ev3.timestamp_ms = 300;

        idx.insert_flow_event(&ev1, &ctx).unwrap();
        idx.insert_flow_event(&ev2, &ctx).unwrap();
        idx.insert_flow_event(&ev3, &ctx).unwrap();

        let results = idx
            .flow_events_by_time_range("ext-a", 150, 250, &ctx)
            .unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].event_id, "e2");
    }

    #[test]
    fn flow_events_by_time_range_inclusive() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let mut ev = flow_event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        ev.timestamp_ms = 500;
        idx.insert_flow_event(&ev, &ctx).unwrap();

        // Exact boundaries should be inclusive.
        let results = idx
            .flow_events_by_time_range("ext-a", 500, 500, &ctx)
            .unwrap();
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn flow_events_by_time_range_empty() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let ev = flow_event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        idx.insert_flow_event(&ev, &ctx).unwrap();

        let results = idx
            .flow_events_by_time_range("ext-a", 5000, 6000, &ctx)
            .unwrap();
        assert!(results.is_empty());
    }

    // -- epoch queries ------------------------------------------------------

    #[test]
    fn flow_proofs_by_epoch_basic() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_proof(
            &flow_proof("p2", "ext-a", Label::Internal, Label::Confidential, 2),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_proof(
            &flow_proof("p3", "ext-a", Label::Public, Label::Secret, 1),
            &ctx,
        )
        .unwrap();

        let epoch1 = idx.flow_proofs_by_epoch("ext-a", 1, &ctx).unwrap();
        assert_eq!(epoch1.len(), 2);
        let epoch2 = idx.flow_proofs_by_epoch("ext-a", 2, &ctx).unwrap();
        assert_eq!(epoch2.len(), 1);
        assert_eq!(epoch2[0].proof_id, "p2");
    }

    #[test]
    fn flow_proofs_by_epoch_empty() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
            &ctx,
        )
        .unwrap();

        let results = idx.flow_proofs_by_epoch("ext-a", 99, &ctx).unwrap();
        assert!(results.is_empty());
    }

    // -- single-record getters ----------------------------------------------

    #[test]
    fn get_flow_event_found() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let ev = flow_event(
            "e1",
            "ext-a",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        idx.insert_flow_event(&ev, &ctx).unwrap();

        let result = idx.get_flow_event("e1", &ctx).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().event_id, "e1");
    }

    #[test]
    fn get_flow_event_missing() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let result = idx.get_flow_event("nonexistent", &ctx).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_flow_proof_found() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let proof = flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1);
        idx.insert_flow_proof(&proof, &ctx).unwrap();

        let result = idx.get_flow_proof("p1", &ctx).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().proof_id, "p1");
    }

    #[test]
    fn get_flow_proof_missing() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let result = idx.get_flow_proof("nonexistent", &ctx).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_declass_receipt_found() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let receipt = declass_receipt(
            "r1",
            "ext-a",
            Label::Secret,
            Label::Public,
            DeclassificationDecision::Allow,
        );
        idx.insert_declass_receipt(&receipt, &ctx).unwrap();

        let result = idx.get_declass_receipt("r1", &ctx).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().receipt_id, "r1");
    }

    #[test]
    fn get_declass_receipt_missing() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let result = idx.get_declass_receipt("nonexistent", &ctx).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn get_confinement_claim_found() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let claim = confinement_claim("c1", "ext-a", ClaimStrength::Full, 1);
        idx.insert_confinement_claim(&claim, &ctx).unwrap();

        let result = idx.get_confinement_claim("c1", &ctx).unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().claim_id, "c1");
    }

    #[test]
    fn get_confinement_claim_missing() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let result = idx.get_confinement_claim("nonexistent", &ctx).unwrap();
        assert!(result.is_none());
    }

    // -- record counts ------------------------------------------------------

    #[test]
    fn record_counts_basic() {
        let mut idx = make_index();
        let ctx = test_ctx();

        idx.insert_flow_event(
            &flow_event(
                "e1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "e2",
                "ext-a",
                Label::Internal,
                Label::Secret,
                FlowDecision::Blocked,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
            &ctx,
        )
        .unwrap();
        idx.insert_declass_receipt(
            &declass_receipt(
                "r1",
                "ext-a",
                Label::Secret,
                Label::Public,
                DeclassificationDecision::Allow,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_confinement_claim(
            &confinement_claim("c1", "ext-a", ClaimStrength::Full, 1),
            &ctx,
        )
        .unwrap();

        let counts = idx.record_counts("ext-a", &ctx).unwrap();
        assert_eq!(counts.flow_events, 2);
        assert_eq!(counts.flow_proofs, 1);
        assert_eq!(counts.declass_receipts, 1);
        assert_eq!(counts.confinement_claims, 1);
        assert_eq!(counts.total(), 5);
    }

    #[test]
    fn record_counts_empty_extension() {
        let mut idx = make_index();
        let ctx = test_ctx();

        let counts = idx.record_counts("ext-none", &ctx).unwrap();
        assert_eq!(counts.flow_events, 0);
        assert_eq!(counts.flow_proofs, 0);
        assert_eq!(counts.declass_receipts, 0);
        assert_eq!(counts.confinement_claims, 0);
        assert_eq!(counts.total(), 0);
    }

    #[test]
    fn record_counts_isolates_extensions() {
        let mut idx = make_index();
        let ctx = test_ctx();

        idx.insert_flow_event(
            &flow_event(
                "e1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "e2",
                "ext-b",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();

        let counts_a = idx.record_counts("ext-a", &ctx).unwrap();
        assert_eq!(counts_a.flow_events, 1);
        let counts_b = idx.record_counts("ext-b", &ctx).unwrap();
        assert_eq!(counts_b.flow_events, 1);
    }

    // -- drain events -------------------------------------------------------

    #[test]
    fn drain_events_clears_buffer() {
        let mut idx = make_index();
        let ctx = test_ctx();

        idx.insert_flow_event(
            &flow_event(
                "e1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
            &ctx,
        )
        .unwrap();

        assert_eq!(idx.events().len(), 2);
        let drained = idx.drain_events();
        assert_eq!(drained.len(), 2);
        assert!(idx.events().is_empty());
    }

    #[test]
    fn drain_events_empty() {
        let mut idx = make_index();
        let drained = idx.drain_events();
        assert!(drained.is_empty());
    }

    // -- RecordCounts serde -------------------------------------------------

    #[test]
    fn record_counts_serde_roundtrip() {
        let counts = RecordCounts {
            flow_events: 10,
            flow_proofs: 5,
            declass_receipts: 3,
            confinement_claims: 2,
        };
        let json = serde_json::to_string(&counts).unwrap();
        let deser: RecordCounts = serde_json::from_str(&json).unwrap();
        assert_eq!(counts, deser);
        assert_eq!(deser.total(), 20);
    }

    // -- deterministic ordering ---------------------------------------------

    #[test]
    fn query_results_deterministic() {
        // Insert in non-alphabetical order, verify queries always return sorted.
        let mut idx = make_index();
        let ctx = test_ctx();

        idx.insert_flow_event(
            &flow_event(
                "ev-z",
                "ext-a",
                Label::Secret,
                Label::Public,
                FlowDecision::Blocked,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "ev-a",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_event(
            &flow_event(
                "ev-m",
                "ext-a",
                Label::Internal,
                Label::Confidential,
                FlowDecision::Declassified,
            ),
            &ctx,
        )
        .unwrap();

        let results = idx.flow_events_by_extension("ext-a", &ctx).unwrap();
        assert_eq!(results.len(), 3);
        // Results should be sorted by Ord (event_id is first field in struct).
        for i in 1..results.len() {
            assert!(results[i - 1] <= results[i]);
        }
    }

    #[test]
    fn lineage_paths_deterministic() {
        let mut idx = make_index();
        let ctx = test_ctx();

        idx.insert_flow_event(
            &flow_event(
                "e1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Public, Label::Confidential, 1),
            &ctx,
        )
        .unwrap();

        let paths1 = idx
            .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
            .unwrap();
        let paths2 = idx
            .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
            .unwrap();
        assert_eq!(paths1, paths2);
    }

    // -- store_mut accessor -------------------------------------------------

    #[test]
    fn store_mut_accessible() {
        let mut idx = make_index();
        // Verifies the accessor compiles and returns the right type.
        let _store: &mut InMemoryStorageAdapter = idx.store_mut();
    }

    // -- lineage hop serde --------------------------------------------------

    #[test]
    fn lineage_hop_serde_roundtrip() {
        let hop = LineageHop {
            source_label: Label::Confidential,
            sink_clearance: Label::Public,
            evidence_ref: "ev1".to_string(),
            evidence_type: LineageEvidenceType::FlowEvent,
        };
        let json = serde_json::to_string(&hop).unwrap();
        let deser: LineageHop = serde_json::from_str(&json).unwrap();
        assert_eq!(hop, deser);
    }

    #[test]
    fn lineage_path_serde_roundtrip() {
        let path = LineagePath {
            extension_id: "ext-a".to_string(),
            hops: vec![LineageHop {
                source_label: Label::Public,
                sink_clearance: Label::Internal,
                evidence_ref: "p1".to_string(),
                evidence_type: LineageEvidenceType::FlowProof,
            }],
        };
        let json = serde_json::to_string(&path).unwrap();
        let deser: LineagePath = serde_json::from_str(&json).unwrap();
        assert_eq!(path, deser);
    }

    // -- edge cases ---------------------------------------------------------

    #[test]
    fn lineage_with_mixed_evidence_types() {
        let mut idx = make_index();
        let ctx = test_ctx();
        // Event: Public → Internal
        idx.insert_flow_event(
            &flow_event(
                "e1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        // Proof: Internal → Confidential
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Internal, Label::Confidential, 1),
            &ctx,
        )
        .unwrap();
        // Declass receipt: Confidential → Secret (Allow)
        idx.insert_declass_receipt(
            &declass_receipt(
                "r1",
                "ext-a",
                Label::Confidential,
                Label::Secret,
                DeclassificationDecision::Allow,
            ),
            &ctx,
        )
        .unwrap();

        let paths = idx
            .source_to_sink_lineage("ext-a", &Label::Public, &ctx)
            .unwrap();
        // Should have paths including the 3-hop chain Public→Internal→Confidential→Secret.
        let three_hop: Vec<_> = paths.iter().filter(|p| p.hops.len() == 3).collect();
        assert_eq!(three_hop.len(), 1);
        assert_eq!(
            three_hop[0].hops[0].evidence_type,
            LineageEvidenceType::FlowEvent
        );
        assert_eq!(
            three_hop[0].hops[1].evidence_type,
            LineageEvidenceType::FlowProof
        );
        assert_eq!(
            three_hop[0].hops[2].evidence_type,
            LineageEvidenceType::DeclassificationReceipt
        );
    }

    #[test]
    fn record_counts_total_zero() {
        let counts = RecordCounts {
            flow_events: 0,
            flow_proofs: 0,
            declass_receipts: 0,
            confinement_claims: 0,
        };
        assert_eq!(counts.total(), 0);
    }

    #[test]
    fn sink_provenance_from_proofs() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_proof(
            &flow_proof("p2", "ext-a", Label::Confidential, Label::Internal, 1),
            &ctx,
        )
        .unwrap();

        let sources = idx
            .sink_provenance("ext-a", &Label::Internal, &ctx)
            .unwrap();
        assert_eq!(sources.len(), 2);
        assert!(sources.contains(&Label::Public));
        assert!(sources.contains(&Label::Confidential));
    }

    #[test]
    fn join_events_with_multiple_receipts() {
        let mut idx = make_index();
        let ctx = test_ctx();

        let mut ev1 = flow_event(
            "ev1",
            "ext-a",
            Label::Confidential,
            Label::Public,
            FlowDecision::Declassified,
        );
        ev1.receipt_ref = Some("r1".to_string());
        idx.insert_flow_event(&ev1, &ctx).unwrap();

        let mut ev2 = flow_event(
            "ev2",
            "ext-a",
            Label::Secret,
            Label::Internal,
            FlowDecision::Declassified,
        );
        ev2.receipt_ref = Some("r2".to_string());
        idx.insert_flow_event(&ev2, &ctx).unwrap();

        idx.insert_declass_receipt(
            &declass_receipt(
                "r1",
                "ext-a",
                Label::Confidential,
                Label::Public,
                DeclassificationDecision::Allow,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_declass_receipt(
            &declass_receipt(
                "r2",
                "ext-a",
                Label::Secret,
                Label::Internal,
                DeclassificationDecision::Allow,
            ),
            &ctx,
        )
        .unwrap();

        let joined = idx.join_events_with_receipts("ext-a", &ctx).unwrap();
        assert_eq!(joined.len(), 2);
        assert!(joined.iter().all(|(_, receipt)| receipt.is_some()));
    }

    #[test]
    fn flow_decision_ord() {
        assert!(FlowDecision::Allowed < FlowDecision::Blocked);
        assert!(FlowDecision::Blocked < FlowDecision::Declassified);
    }

    #[test]
    fn lineage_evidence_type_ord() {
        assert!(LineageEvidenceType::FlowEvent < LineageEvidenceType::FlowProof);
        assert!(LineageEvidenceType::FlowProof < LineageEvidenceType::DeclassificationReceipt);
    }

    #[test]
    fn provenance_error_std_error() {
        let variants: Vec<Box<dyn std::error::Error>> = vec![
            Box::new(ProvenanceError::EmptyId {
                record_type: "flow".into(),
            }),
            Box::new(ProvenanceError::EmptyExtensionId),
            Box::new(ProvenanceError::DuplicateRecord { key: "k1".into() }),
            Box::new(ProvenanceError::StorageError("full".into())),
            Box::new(ProvenanceError::SerializationError("bad json".into())),
        ];
        let mut displays = std::collections::BTreeSet::new();
        for v in &variants {
            displays.insert(format!("{v}"));
        }
        assert_eq!(displays.len(), 5);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn flow_decision_display_all_distinct() {
        let variants = [
            FlowDecision::Allowed,
            FlowDecision::Blocked,
            FlowDecision::Declassified,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn lineage_evidence_type_display_all_distinct() {
        let variants = [
            LineageEvidenceType::FlowEvent,
            LineageEvidenceType::FlowProof,
            LineageEvidenceType::DeclassificationReceipt,
        ];
        let mut set = std::collections::BTreeSet::new();
        for v in &variants {
            set.insert(v.to_string());
        }
        assert_eq!(set.len(), variants.len());
    }

    #[test]
    fn record_counts_total_matches_fields_sum() {
        let counts = RecordCounts {
            flow_events: 3,
            flow_proofs: 2,
            declass_receipts: 1,
            confinement_claims: 4,
        };
        assert_eq!(counts.total(), 3 + 2 + 1 + 4);
    }

    #[test]
    fn record_counts_total_all_zero() {
        let counts = RecordCounts {
            flow_events: 0,
            flow_proofs: 0,
            declass_receipts: 0,
            confinement_claims: 0,
        };
        assert_eq!(counts.total(), 0);
    }

    #[test]
    fn confinement_status_no_proofs_no_claims() {
        let status = ConfinementStatus {
            extension_id: "ext-z".into(),
            proven_flows: 0,
            unproven_flows: 5,
            strongest_claim: None,
            latest_proof_epoch: None,
        };
        assert_eq!(status.proven_flows, 0);
        assert!(status.strongest_claim.is_none());
        assert!(status.latest_proof_epoch.is_none());
    }

    #[test]
    fn lineage_hop_with_each_evidence_type() {
        let types = [
            LineageEvidenceType::FlowEvent,
            LineageEvidenceType::FlowProof,
            LineageEvidenceType::DeclassificationReceipt,
        ];
        for et in &types {
            let hop = LineageHop {
                source_label: Label::Public,
                sink_clearance: Label::Internal,
                evidence_ref: format!("ref-{et}"),
                evidence_type: *et,
            };
            let json = serde_json::to_string(&hop).unwrap();
            let back: LineageHop = serde_json::from_str(&json).unwrap();
            assert_eq!(hop, back);
        }
    }

    #[test]
    fn lineage_path_sort_is_deterministic() {
        let path_a = LineagePath {
            extension_id: "ext-a".into(),
            hops: vec![LineageHop {
                source_label: Label::Public,
                sink_clearance: Label::Internal,
                evidence_ref: "e1".into(),
                evidence_type: LineageEvidenceType::FlowEvent,
            }],
        };
        let path_b = LineagePath {
            extension_id: "ext-b".into(),
            hops: vec![LineageHop {
                source_label: Label::Public,
                sink_clearance: Label::Secret,
                evidence_ref: "e2".into(),
                evidence_type: LineageEvidenceType::FlowProof,
            }],
        };
        assert!(path_a < path_b);
        let mut sorted = [path_b.clone(), path_a.clone()];
        sorted.sort();
        assert_eq!(sorted[0], path_a);
        assert_eq!(sorted[1], path_b);
    }

    #[test]
    fn provenance_event_optional_fields_none() {
        let event = ProvenanceEvent {
            trace_id: "t-1".into(),
            component: "test".into(),
            event: "insert".into(),
            outcome: "ok".into(),
            error_code: None,
            extension_id: None,
            record_count: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ProvenanceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert!(back.error_code.is_none());
        assert!(back.extension_id.is_none());
        assert!(back.record_count.is_none());
    }

    #[test]
    fn flow_event_record_ord_deterministic() {
        let a = flow_event(
            "ev-a",
            "ext-1",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        let b = flow_event(
            "ev-b",
            "ext-1",
            Label::Public,
            Label::Internal,
            FlowDecision::Allowed,
        );
        assert!(a < b);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn provenance_error_display_exact_all_5() {
        assert_eq!(
            ProvenanceError::EmptyId {
                record_type: "flow_event".to_string()
            }
            .to_string(),
            "flow_event has empty ID"
        );
        assert_eq!(
            ProvenanceError::EmptyExtensionId.to_string(),
            "extension_id is empty"
        );
        assert_eq!(
            ProvenanceError::DuplicateRecord {
                key: "k1".to_string()
            }
            .to_string(),
            "duplicate record: k1"
        );
        assert_eq!(
            ProvenanceError::StorageError("disk full".to_string()).to_string(),
            "storage: disk full"
        );
        assert_eq!(
            ProvenanceError::SerializationError("bad json".to_string()).to_string(),
            "serialization: bad json"
        );
    }

    #[test]
    fn provenance_error_source_returns_none_all() {
        use std::error::Error;
        let errors: Vec<ProvenanceError> = vec![
            ProvenanceError::EmptyId {
                record_type: "x".into(),
            },
            ProvenanceError::EmptyExtensionId,
            ProvenanceError::DuplicateRecord { key: "k".into() },
            ProvenanceError::StorageError("e".into()),
            ProvenanceError::SerializationError("e".into()),
        ];
        for err in &errors {
            assert!(err.source().is_none(), "source() should be None for {err}");
        }
    }

    #[test]
    fn flow_proof_record_ord_deterministic() {
        let a = flow_proof("p-a", "ext-1", Label::Public, Label::Internal, 1);
        let b = flow_proof("p-b", "ext-1", Label::Public, Label::Internal, 1);
        assert!(a < b);
    }

    #[test]
    fn declass_receipt_record_ord_deterministic() {
        let a = declass_receipt(
            "r-a",
            "ext-1",
            Label::Public,
            Label::Internal,
            DeclassificationDecision::Allow,
        );
        let b = declass_receipt(
            "r-b",
            "ext-1",
            Label::Public,
            Label::Internal,
            DeclassificationDecision::Allow,
        );
        assert!(a < b);
    }

    #[test]
    fn confinement_claim_record_ord_deterministic() {
        let a = confinement_claim("c-a", "ext-1", ClaimStrength::Full, 1);
        let b = confinement_claim("c-b", "ext-1", ClaimStrength::Full, 1);
        assert!(a < b);
    }

    #[test]
    fn confinement_status_selects_full_over_partial() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.insert_flow_event(
            &flow_event(
                "ev1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 1),
            &ctx,
        )
        .unwrap();
        idx.insert_confinement_claim(
            &confinement_claim("c1", "ext-a", ClaimStrength::Partial, 1),
            &ctx,
        )
        .unwrap();
        idx.insert_confinement_claim(
            &confinement_claim("c2", "ext-a", ClaimStrength::Full, 2),
            &ctx,
        )
        .unwrap();

        let status = idx.confinement_status("ext-a", &ctx).unwrap();
        assert_eq!(
            status.strongest_claim,
            Some(ClaimStrength::Full),
            "Full should be selected over Partial"
        );
    }

    #[test]
    fn reject_empty_extension_id_on_proof_insert() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let proof = flow_proof("p1", "", Label::Public, Label::Internal, 1);
        let err = idx.insert_flow_proof(&proof, &ctx).unwrap_err();
        assert_eq!(err, ProvenanceError::EmptyExtensionId);
    }

    #[test]
    fn reject_empty_extension_id_on_receipt_insert() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let receipt = declass_receipt(
            "r1",
            "",
            Label::Public,
            Label::Internal,
            DeclassificationDecision::Allow,
        );
        let err = idx.insert_declass_receipt(&receipt, &ctx).unwrap_err();
        assert_eq!(err, ProvenanceError::EmptyExtensionId);
    }

    #[test]
    fn reject_empty_extension_id_on_claim_insert() {
        let mut idx = make_index();
        let ctx = test_ctx();
        let claim = confinement_claim("c1", "", ClaimStrength::Full, 1);
        let err = idx.insert_confinement_claim(&claim, &ctx).unwrap_err();
        assert_eq!(err, ProvenanceError::EmptyExtensionId);
    }

    #[test]
    fn flow_event_serde_with_receipt_ref() {
        let mut ev = flow_event(
            "ev1",
            "ext-a",
            Label::Confidential,
            Label::Public,
            FlowDecision::Declassified,
        );
        ev.receipt_ref = Some("r1".to_string());
        let json = serde_json::to_string(&ev).unwrap();
        let back: FlowEventRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
        assert_eq!(back.receipt_ref, Some("r1".to_string()));
    }

    #[test]
    fn provenance_event_with_error_code_serde() {
        let event = ProvenanceEvent {
            trace_id: "t1".into(),
            component: COMPONENT.into(),
            event: "insert_failed".into(),
            outcome: "error".into(),
            error_code: Some("PROV_EMPTY_ID".into()),
            extension_id: Some("ext-a".into()),
            record_count: Some(0),
        };
        let json = serde_json::to_string(&event).unwrap();
        let back: ProvenanceEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, back);
        assert_eq!(back.error_code.as_deref(), Some("PROV_EMPTY_ID"));
    }

    #[test]
    fn confinement_status_latest_epoch_from_multiple_proofs() {
        let mut idx = make_index();
        let ctx = test_ctx();
        idx.insert_flow_event(
            &flow_event(
                "ev1",
                "ext-a",
                Label::Public,
                Label::Internal,
                FlowDecision::Allowed,
            ),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_proof(
            &flow_proof("p1", "ext-a", Label::Public, Label::Internal, 3),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_proof(
            &flow_proof("p2", "ext-a", Label::Public, Label::Internal, 7),
            &ctx,
        )
        .unwrap();
        idx.insert_flow_proof(
            &flow_proof("p3", "ext-a", Label::Public, Label::Internal, 5),
            &ctx,
        )
        .unwrap();

        let status = idx.confinement_status("ext-a", &ctx).unwrap();
        assert_eq!(
            status.latest_proof_epoch,
            Some(7),
            "should select the maximum epoch"
        );
    }
}
