//! Frankensqlite-backed specialization index for deterministic audit queries.
//!
//! Provides the data substrate for querying the full audit chain:
//! security proof -> specialization receipt -> benchmark outcome.
//! Supports epoch-scoped queries, invalidation logs, replay joins,
//! and aggregate views for operator dashboards.
//!
//! Plan reference: Section 10.15, subsection 9I.8, item 4 of 4, bd-133a.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::engine_object_id::EngineObjectId;
use crate::proof_specialization_receipt::{OptimizationClass, ProofType};
use crate::security_epoch::SecurityEpoch;
use crate::storage_adapter::{EventContext, StorageAdapter, StorageError, StoreKind, StoreQuery};

// ---------------------------------------------------------------------------
// Record types stored in the index
// ---------------------------------------------------------------------------

/// A specialization receipt record stored in the index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationRecord {
    /// Receipt identifier.
    pub receipt_id: EngineObjectId,
    /// Proof input identifiers that justified this specialization.
    pub proof_input_ids: Vec<EngineObjectId>,
    /// Proof types associated with each proof input.
    pub proof_types: Vec<ProofType>,
    /// Optimization class applied.
    pub optimization_class: OptimizationClass,
    /// Extension or slot identifier.
    pub extension_id: String,
    /// Epoch under which this specialization is valid.
    pub epoch: SecurityEpoch,
    /// Timestamp in nanoseconds.
    pub timestamp_ns: u64,
    /// Whether this specialization is currently active (not invalidated).
    pub active: bool,
}

/// A benchmark outcome linked to a specialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkOutcome {
    /// Identifier for this benchmark result.
    pub benchmark_id: String,
    /// Receipt ID of the specialization being benchmarked.
    pub receipt_id: EngineObjectId,
    /// Measured performance delta.
    pub latency_reduction_millionths: u64,
    /// Throughput increase in millionths.
    pub throughput_increase_millionths: u64,
    /// Number of benchmark samples.
    pub sample_count: u64,
    /// Timestamp of the benchmark run.
    pub timestamp_ns: u64,
}

/// Reason a specialization was invalidated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum InvalidationReason {
    EpochChange { old_epoch: u64, new_epoch: u64 },
    ProofExpired { proof_id: EngineObjectId },
    ProofRevoked { proof_id: EngineObjectId },
    ManualRevocation { operator: String },
}

/// An invalidation event in the log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvalidationEntry {
    /// Receipt ID that was invalidated.
    pub receipt_id: EngineObjectId,
    /// Reason for invalidation.
    pub reason: InvalidationReason,
    /// Timestamp of invalidation.
    pub timestamp_ns: u64,
    /// Whether fallback to unspecialized path was confirmed.
    pub fallback_confirmed: bool,
}

/// Audit chain entry: proof -> specialization -> benchmark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditChainEntry {
    pub proof_id: EngineObjectId,
    pub proof_type: ProofType,
    pub receipt_id: EngineObjectId,
    pub optimization_class: OptimizationClass,
    pub benchmark_id: Option<String>,
    pub latency_reduction_millionths: Option<u64>,
    pub epoch: SecurityEpoch,
}

/// Aggregate stats for an extension's specializations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtensionSpecializationSummary {
    pub extension_id: String,
    pub total_specializations: u64,
    pub active_specializations: u64,
    pub invalidated_specializations: u64,
    pub total_benchmarks: u64,
    pub avg_latency_reduction_millionths: u64,
    pub proof_utilization_count: u64,
}

// ---------------------------------------------------------------------------
// SpecializationIndexEvent — structured log events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecializationIndexEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// SpecializationIndexError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecializationIndexError {
    Storage(String),
    NotFound { receipt_id: String },
    DuplicateReceipt { receipt_id: String },
    DuplicateBenchmark { benchmark_id: String },
    SerializationFailed(String),
    InvalidContext(String),
}

impl std::fmt::Display for SpecializationIndexError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(msg) => write!(f, "storage error: {msg}"),
            Self::NotFound { receipt_id } => {
                write!(f, "specialization not found: {receipt_id}")
            }
            Self::DuplicateReceipt { receipt_id } => {
                write!(f, "duplicate receipt: {receipt_id}")
            }
            Self::DuplicateBenchmark { benchmark_id } => {
                write!(f, "duplicate benchmark: {benchmark_id}")
            }
            Self::SerializationFailed(msg) => write!(f, "serialization failed: {msg}"),
            Self::InvalidContext(msg) => write!(f, "invalid context: {msg}"),
        }
    }
}

impl std::error::Error for SpecializationIndexError {}

/// Stable error codes for the specialization index.
pub fn error_code(err: &SpecializationIndexError) -> &'static str {
    match err {
        SpecializationIndexError::Storage(_) => "SI_STORAGE_ERROR",
        SpecializationIndexError::NotFound { .. } => "SI_NOT_FOUND",
        SpecializationIndexError::DuplicateReceipt { .. } => "SI_DUPLICATE_RECEIPT",
        SpecializationIndexError::DuplicateBenchmark { .. } => "SI_DUPLICATE_BENCHMARK",
        SpecializationIndexError::SerializationFailed(_) => "SI_SERIALIZATION_FAILED",
        SpecializationIndexError::InvalidContext(_) => "SI_INVALID_CONTEXT",
    }
}

impl From<StorageError> for SpecializationIndexError {
    fn from(e: StorageError) -> Self {
        Self::Storage(format!("{e:?}"))
    }
}

// ---------------------------------------------------------------------------
// SpecializationIndex — main index engine
// ---------------------------------------------------------------------------

const STORE: StoreKind = StoreKind::SpecializationIndex;
const RECEIPT_PREFIX: &str = "receipt:";
const BENCHMARK_PREFIX: &str = "benchmark:";
const INVALIDATION_PREFIX: &str = "invalidation:";

/// Frankensqlite-backed specialization index for audit queries.
pub struct SpecializationIndex<S: StorageAdapter> {
    storage: S,
    policy_id: String,
    events: Vec<SpecializationIndexEvent>,
}

impl<S: StorageAdapter> SpecializationIndex<S> {
    pub fn new(storage: S, policy_id: impl Into<String>) -> Self {
        Self {
            storage,
            policy_id: policy_id.into(),
            events: Vec::new(),
        }
    }

    pub fn events(&self) -> &[SpecializationIndexEvent] {
        &self.events
    }

    fn make_ctx(&self, trace_id: &str) -> EventContext {
        EventContext {
            trace_id: trace_id.to_string(),
            decision_id: String::new(),
            policy_id: self.policy_id.clone(),
        }
    }

    fn emit_event(&mut self, trace_id: &str, event: &str, outcome: &str, error_code: Option<&str>) {
        self.events.push(SpecializationIndexEvent {
            trace_id: trace_id.to_string(),
            decision_id: String::new(),
            policy_id: self.policy_id.clone(),
            component: "specialization_index".to_string(),
            event: event.to_string(),
            outcome: outcome.to_string(),
            error_code: error_code.map(String::from),
        });
    }

    // -----------------------------------------------------------------------
    // CRUD: Specialization Records
    // -----------------------------------------------------------------------

    /// Insert a specialization record into the index.
    pub fn insert_receipt(
        &mut self,
        record: &SpecializationRecord,
        trace_id: &str,
    ) -> Result<(), SpecializationIndexError> {
        let key = format!("{RECEIPT_PREFIX}{}", record.receipt_id.to_hex());
        let ctx = self.make_ctx(trace_id);

        // Check for duplicates
        if self.storage.get(STORE, &key, &ctx)?.is_some() {
            self.emit_event(
                trace_id,
                "insert_receipt",
                "duplicate",
                Some("DUPLICATE_RECEIPT"),
            );
            return Err(SpecializationIndexError::DuplicateReceipt {
                receipt_id: record.receipt_id.to_hex(),
            });
        }

        let value = serde_json::to_vec(record)
            .map_err(|e| SpecializationIndexError::SerializationFailed(e.to_string()))?;

        let mut metadata = BTreeMap::new();
        metadata.insert(
            "optimization_class".to_string(),
            record.optimization_class.to_string(),
        );
        metadata.insert("extension_id".to_string(), record.extension_id.clone());
        metadata.insert("epoch".to_string(), record.epoch.as_u64().to_string());
        metadata.insert("active".to_string(), record.active.to_string());

        self.storage.put(STORE, key, value, metadata, &ctx)?;
        self.emit_event(trace_id, "insert_receipt", "ok", None);
        Ok(())
    }

    /// Get a specialization record by receipt ID.
    pub fn get_receipt(
        &mut self,
        receipt_id: &EngineObjectId,
        trace_id: &str,
    ) -> Result<Option<SpecializationRecord>, SpecializationIndexError> {
        let key = format!("{RECEIPT_PREFIX}{}", receipt_id.to_hex());
        let ctx = self.make_ctx(trace_id);
        let record = self.storage.get(STORE, &key, &ctx)?;
        match record {
            Some(r) => {
                let spec: SpecializationRecord = serde_json::from_slice(&r.value)
                    .map_err(|e| SpecializationIndexError::SerializationFailed(e.to_string()))?;
                Ok(Some(spec))
            }
            None => Ok(None),
        }
    }

    /// Query all specialization records, optionally filtered by epoch.
    pub fn query_receipts(
        &mut self,
        epoch: Option<SecurityEpoch>,
        trace_id: &str,
    ) -> Result<Vec<SpecializationRecord>, SpecializationIndexError> {
        let ctx = self.make_ctx(trace_id);
        let mut metadata_filters = BTreeMap::new();
        if let Some(ep) = epoch {
            metadata_filters.insert("epoch".to_string(), ep.as_u64().to_string());
        }
        let query = StoreQuery {
            key_prefix: Some(RECEIPT_PREFIX.to_string()),
            metadata_filters,
            limit: None,
        };
        let records = self.storage.query(STORE, &query, &ctx)?;
        let mut results = Vec::new();
        for r in &records {
            let spec: SpecializationRecord = serde_json::from_slice(&r.value)
                .map_err(|e| SpecializationIndexError::SerializationFailed(e.to_string()))?;
            results.push(spec);
        }
        Ok(results)
    }

    /// Query active specialization records only.
    pub fn query_active_receipts(
        &mut self,
        trace_id: &str,
    ) -> Result<Vec<SpecializationRecord>, SpecializationIndexError> {
        let ctx = self.make_ctx(trace_id);
        let mut metadata_filters = BTreeMap::new();
        metadata_filters.insert("active".to_string(), "true".to_string());
        let query = StoreQuery {
            key_prefix: Some(RECEIPT_PREFIX.to_string()),
            metadata_filters,
            limit: None,
        };
        let records = self.storage.query(STORE, &query, &ctx)?;
        let mut results = Vec::new();
        for r in &records {
            let spec: SpecializationRecord = serde_json::from_slice(&r.value)
                .map_err(|e| SpecializationIndexError::SerializationFailed(e.to_string()))?;
            results.push(spec);
        }
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Proof-to-Specialization index
    // -----------------------------------------------------------------------

    /// Find all specializations enabled by a given proof ID.
    pub fn find_by_proof(
        &mut self,
        proof_id: &EngineObjectId,
        trace_id: &str,
    ) -> Result<Vec<SpecializationRecord>, SpecializationIndexError> {
        let all = self.query_receipts(None, trace_id)?;
        let proof_hex = proof_id.to_hex();
        Ok(all
            .into_iter()
            .filter(|r| r.proof_input_ids.iter().any(|p| p.to_hex() == proof_hex))
            .collect())
    }

    // -----------------------------------------------------------------------
    // CRUD: Benchmark Outcomes
    // -----------------------------------------------------------------------

    /// Insert a benchmark outcome linked to a specialization.
    pub fn insert_benchmark(
        &mut self,
        outcome: &BenchmarkOutcome,
        trace_id: &str,
    ) -> Result<(), SpecializationIndexError> {
        let key = format!("{BENCHMARK_PREFIX}{}", outcome.benchmark_id);
        let ctx = self.make_ctx(trace_id);

        // Check duplicate
        if self.storage.get(STORE, &key, &ctx)?.is_some() {
            self.emit_event(
                trace_id,
                "insert_benchmark",
                "duplicate",
                Some("DUPLICATE_BENCHMARK"),
            );
            return Err(SpecializationIndexError::DuplicateBenchmark {
                benchmark_id: outcome.benchmark_id.clone(),
            });
        }

        let value = serde_json::to_vec(outcome)
            .map_err(|e| SpecializationIndexError::SerializationFailed(e.to_string()))?;

        let mut metadata = BTreeMap::new();
        metadata.insert("receipt_id".to_string(), outcome.receipt_id.to_hex());

        self.storage.put(STORE, key, value, metadata, &ctx)?;
        self.emit_event(trace_id, "insert_benchmark", "ok", None);
        Ok(())
    }

    /// Find benchmarks for a given specialization receipt.
    pub fn find_benchmarks_by_receipt(
        &mut self,
        receipt_id: &EngineObjectId,
        trace_id: &str,
    ) -> Result<Vec<BenchmarkOutcome>, SpecializationIndexError> {
        let ctx = self.make_ctx(trace_id);
        let mut metadata_filters = BTreeMap::new();
        metadata_filters.insert("receipt_id".to_string(), receipt_id.to_hex());
        let query = StoreQuery {
            key_prefix: Some(BENCHMARK_PREFIX.to_string()),
            metadata_filters,
            limit: None,
        };
        let records = self.storage.query(STORE, &query, &ctx)?;
        let mut results = Vec::new();
        for r in &records {
            let bm: BenchmarkOutcome = serde_json::from_slice(&r.value)
                .map_err(|e| SpecializationIndexError::SerializationFailed(e.to_string()))?;
            results.push(bm);
        }
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Invalidation Log
    // -----------------------------------------------------------------------

    /// Record an invalidation event and mark the receipt as inactive.
    pub fn record_invalidation(
        &mut self,
        entry: &InvalidationEntry,
        trace_id: &str,
    ) -> Result<(), SpecializationIndexError> {
        // Store the invalidation entry
        let inv_key = format!(
            "{INVALIDATION_PREFIX}{}:{}",
            entry.receipt_id.to_hex(),
            entry.timestamp_ns
        );
        let ctx = self.make_ctx(trace_id);
        let value = serde_json::to_vec(entry)
            .map_err(|e| SpecializationIndexError::SerializationFailed(e.to_string()))?;

        let mut metadata = BTreeMap::new();
        metadata.insert("receipt_id".to_string(), entry.receipt_id.to_hex());

        self.storage.put(STORE, inv_key, value, metadata, &ctx)?;

        // Mark the receipt as inactive
        let receipt_key = format!("{RECEIPT_PREFIX}{}", entry.receipt_id.to_hex());
        if let Some(existing) = self.storage.get(STORE, &receipt_key, &ctx)? {
            let mut record: SpecializationRecord = serde_json::from_slice(&existing.value)
                .map_err(|e| SpecializationIndexError::SerializationFailed(e.to_string()))?;
            record.active = false;
            let updated_value = serde_json::to_vec(&record)
                .map_err(|e| SpecializationIndexError::SerializationFailed(e.to_string()))?;

            let mut updated_metadata = existing.metadata.clone();
            updated_metadata.insert("active".to_string(), "false".to_string());

            self.storage
                .put(STORE, receipt_key, updated_value, updated_metadata, &ctx)?;
        }

        self.emit_event(trace_id, "record_invalidation", "ok", None);
        Ok(())
    }

    /// Query invalidation entries, optionally filtered by time window.
    pub fn query_invalidations(
        &mut self,
        from_ns: Option<u64>,
        to_ns: Option<u64>,
        trace_id: &str,
    ) -> Result<Vec<InvalidationEntry>, SpecializationIndexError> {
        let ctx = self.make_ctx(trace_id);
        let query = StoreQuery {
            key_prefix: Some(INVALIDATION_PREFIX.to_string()),
            metadata_filters: BTreeMap::new(),
            limit: None,
        };
        let records = self.storage.query(STORE, &query, &ctx)?;
        let mut results = Vec::new();
        for r in &records {
            let entry: InvalidationEntry = serde_json::from_slice(&r.value)
                .map_err(|e| SpecializationIndexError::SerializationFailed(e.to_string()))?;
            let in_range = from_ns.is_none_or(|f| entry.timestamp_ns >= f)
                && to_ns.is_none_or(|t| entry.timestamp_ns <= t);
            if in_range {
                results.push(entry);
            }
        }
        Ok(results)
    }

    // -----------------------------------------------------------------------
    // Audit Chain Traversal
    // -----------------------------------------------------------------------

    /// Build the full audit chain: proof -> specialization -> benchmark.
    pub fn build_audit_chain(
        &mut self,
        trace_id: &str,
    ) -> Result<Vec<AuditChainEntry>, SpecializationIndexError> {
        let receipts = self.query_receipts(None, trace_id)?;
        let mut chain = Vec::new();

        for receipt in &receipts {
            let benchmarks = self.find_benchmarks_by_receipt(&receipt.receipt_id, trace_id)?;

            for (i, proof_id) in receipt.proof_input_ids.iter().enumerate() {
                let proof_type = receipt
                    .proof_types
                    .get(i)
                    .copied()
                    .unwrap_or(ProofType::CapabilityWitness);

                if benchmarks.is_empty() {
                    chain.push(AuditChainEntry {
                        proof_id: proof_id.clone(),
                        proof_type,
                        receipt_id: receipt.receipt_id.clone(),
                        optimization_class: receipt.optimization_class,
                        benchmark_id: None,
                        latency_reduction_millionths: None,
                        epoch: receipt.epoch,
                    });
                } else {
                    for bm in &benchmarks {
                        chain.push(AuditChainEntry {
                            proof_id: proof_id.clone(),
                            proof_type,
                            receipt_id: receipt.receipt_id.clone(),
                            optimization_class: receipt.optimization_class,
                            benchmark_id: Some(bm.benchmark_id.clone()),
                            latency_reduction_millionths: Some(bm.latency_reduction_millionths),
                            epoch: receipt.epoch,
                        });
                    }
                }
            }
        }

        self.emit_event(trace_id, "build_audit_chain", "ok", None);
        Ok(chain)
    }

    /// Reverse audit: find which proofs led to a given benchmark outcome.
    pub fn reverse_audit_from_benchmark(
        &mut self,
        benchmark_id: &str,
        trace_id: &str,
    ) -> Result<Vec<AuditChainEntry>, SpecializationIndexError> {
        let chain = self.build_audit_chain(trace_id)?;
        Ok(chain
            .into_iter()
            .filter(|e| e.benchmark_id.as_deref() == Some(benchmark_id))
            .collect())
    }

    // -----------------------------------------------------------------------
    // Aggregate Views
    // -----------------------------------------------------------------------

    /// Compute per-extension specialization summary.
    pub fn extension_summary(
        &mut self,
        extension_id: &str,
        trace_id: &str,
    ) -> Result<ExtensionSpecializationSummary, SpecializationIndexError> {
        let all_receipts = self.query_receipts(None, trace_id)?;
        let ext_receipts: Vec<&SpecializationRecord> = all_receipts
            .iter()
            .filter(|r| r.extension_id == extension_id)
            .collect();

        let total = ext_receipts.len() as u64;
        let active = ext_receipts.iter().filter(|r| r.active).count() as u64;
        let invalidated = total - active;

        // Gather all proof input IDs for utilization count
        let proof_count: u64 = ext_receipts
            .iter()
            .map(|r| r.proof_input_ids.len() as u64)
            .sum();

        // Gather benchmark data
        let mut total_benchmarks: u64 = 0;
        let mut total_latency_reduction: u64 = 0;
        for receipt in &ext_receipts {
            let benchmarks = self.find_benchmarks_by_receipt(&receipt.receipt_id, trace_id)?;
            for bm in &benchmarks {
                total_benchmarks += 1;
                total_latency_reduction += bm.latency_reduction_millionths;
            }
        }
        let avg_latency = total_latency_reduction
            .checked_div(total_benchmarks)
            .unwrap_or(0);

        Ok(ExtensionSpecializationSummary {
            extension_id: extension_id.to_string(),
            total_specializations: total,
            active_specializations: active,
            invalidated_specializations: invalidated,
            total_benchmarks,
            avg_latency_reduction_millionths: avg_latency,
            proof_utilization_count: proof_count,
        })
    }

    /// Delete a receipt from the index.
    pub fn delete_receipt(
        &mut self,
        receipt_id: &EngineObjectId,
        trace_id: &str,
    ) -> Result<bool, SpecializationIndexError> {
        let key = format!("{RECEIPT_PREFIX}{}", receipt_id.to_hex());
        let ctx = self.make_ctx(trace_id);
        let deleted = self.storage.delete(STORE, &key, &ctx)?;
        self.emit_event(
            trace_id,
            "delete_receipt",
            if deleted { "ok" } else { "not_found" },
            None,
        );
        Ok(deleted)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine_object_id::{ObjectDomain, SchemaId, derive_id};
    use crate::storage_adapter::InMemoryStorageAdapter;

    const SCHEMA_DEF: &[u8] = b"SpecializationIndex.v1";

    fn test_schema_id() -> SchemaId {
        SchemaId::from_definition(SCHEMA_DEF)
    }

    fn make_id(tag: &str) -> EngineObjectId {
        derive_id(
            ObjectDomain::PolicyObject,
            "test",
            &test_schema_id(),
            tag.as_bytes(),
        )
        .unwrap()
    }

    fn make_storage() -> InMemoryStorageAdapter {
        InMemoryStorageAdapter::new()
    }

    fn make_index() -> SpecializationIndex<InMemoryStorageAdapter> {
        SpecializationIndex::new(make_storage(), "test-policy")
    }

    fn make_record(tag: &str, epoch: u64) -> SpecializationRecord {
        SpecializationRecord {
            receipt_id: make_id(tag),
            proof_input_ids: vec![make_id(&format!("{tag}-proof"))],
            proof_types: vec![ProofType::CapabilityWitness],
            optimization_class: OptimizationClass::HostcallDispatchSpecialization,
            extension_id: "ext-1".to_string(),
            epoch: SecurityEpoch::from_raw(epoch),
            timestamp_ns: epoch * 1000,
            active: true,
        }
    }

    fn make_benchmark(bm_id: &str, receipt_tag: &str) -> BenchmarkOutcome {
        BenchmarkOutcome {
            benchmark_id: bm_id.to_string(),
            receipt_id: make_id(receipt_tag),
            latency_reduction_millionths: 200_000,
            throughput_increase_millionths: 150_000,
            sample_count: 100,
            timestamp_ns: 5000,
        }
    }

    // -----------------------------------------------------------------------
    // Receipt CRUD
    // -----------------------------------------------------------------------

    #[test]
    fn insert_and_get_receipt() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();

        let fetched = index.get_receipt(&rec.receipt_id, "t2").unwrap();
        assert_eq!(fetched.unwrap(), rec);
    }

    #[test]
    fn get_nonexistent_receipt_returns_none() {
        let mut index = make_index();
        let id = make_id("nonexistent");
        assert!(index.get_receipt(&id, "t1").unwrap().is_none());
    }

    #[test]
    fn duplicate_receipt_rejected() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();
        let err = index.insert_receipt(&rec, "t2").unwrap_err();
        match err {
            SpecializationIndexError::DuplicateReceipt { .. } => {}
            other => panic!("expected DuplicateReceipt, got {other}"),
        }
    }

    #[test]
    fn delete_receipt() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();

        assert!(index.delete_receipt(&rec.receipt_id, "t2").unwrap());
        assert!(index.get_receipt(&rec.receipt_id, "t3").unwrap().is_none());
    }

    #[test]
    fn delete_nonexistent_returns_false() {
        let mut index = make_index();
        let id = make_id("nonexistent");
        assert!(!index.delete_receipt(&id, "t1").unwrap());
    }

    // -----------------------------------------------------------------------
    // Query receipts
    // -----------------------------------------------------------------------

    #[test]
    fn query_all_receipts() {
        let mut index = make_index();
        index.insert_receipt(&make_record("r1", 1), "t1").unwrap();
        index.insert_receipt(&make_record("r2", 2), "t2").unwrap();
        index.insert_receipt(&make_record("r3", 1), "t3").unwrap();

        let all = index.query_receipts(None, "t4").unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn query_receipts_by_epoch() {
        let mut index = make_index();
        index.insert_receipt(&make_record("r1", 1), "t1").unwrap();
        index.insert_receipt(&make_record("r2", 2), "t2").unwrap();
        index.insert_receipt(&make_record("r3", 1), "t3").unwrap();

        let epoch1 = index
            .query_receipts(Some(SecurityEpoch::from_raw(1)), "t4")
            .unwrap();
        assert_eq!(epoch1.len(), 2);

        let epoch2 = index
            .query_receipts(Some(SecurityEpoch::from_raw(2)), "t5")
            .unwrap();
        assert_eq!(epoch2.len(), 1);

        let epoch3 = index
            .query_receipts(Some(SecurityEpoch::from_raw(99)), "t6")
            .unwrap();
        assert!(epoch3.is_empty());
    }

    #[test]
    fn query_active_receipts_only() {
        let mut index = make_index();
        let mut active_rec = make_record("r1", 1);
        active_rec.active = true;
        let mut inactive_rec = make_record("r2", 1);
        inactive_rec.active = false;

        index.insert_receipt(&active_rec, "t1").unwrap();
        index.insert_receipt(&inactive_rec, "t2").unwrap();

        let active = index.query_active_receipts("t3").unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].receipt_id, active_rec.receipt_id);
    }

    // -----------------------------------------------------------------------
    // Proof-to-specialization index
    // -----------------------------------------------------------------------

    #[test]
    fn find_by_proof_id() {
        let mut index = make_index();
        let proof_id = make_id("shared-proof");

        let mut r1 = make_record("r1", 1);
        r1.proof_input_ids = vec![proof_id.clone()];
        let mut r2 = make_record("r2", 1);
        r2.proof_input_ids = vec![make_id("other-proof")];
        let mut r3 = make_record("r3", 1);
        r3.proof_input_ids = vec![proof_id.clone(), make_id("another-proof")];

        index.insert_receipt(&r1, "t1").unwrap();
        index.insert_receipt(&r2, "t2").unwrap();
        index.insert_receipt(&r3, "t3").unwrap();

        let found = index.find_by_proof(&proof_id, "t4").unwrap();
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn find_by_proof_no_matches() {
        let mut index = make_index();
        index.insert_receipt(&make_record("r1", 1), "t1").unwrap();

        let phantom = make_id("phantom-proof");
        let found = index.find_by_proof(&phantom, "t2").unwrap();
        assert!(found.is_empty());
    }

    // -----------------------------------------------------------------------
    // Benchmark CRUD
    // -----------------------------------------------------------------------

    #[test]
    fn insert_and_find_benchmark() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();

        let bm = make_benchmark("bm-1", "r1");
        index.insert_benchmark(&bm, "t2").unwrap();

        let benchmarks = index
            .find_benchmarks_by_receipt(&rec.receipt_id, "t3")
            .unwrap();
        assert_eq!(benchmarks.len(), 1);
        assert_eq!(benchmarks[0].benchmark_id, "bm-1");
        assert_eq!(benchmarks[0].latency_reduction_millionths, 200_000);
    }

    #[test]
    fn duplicate_benchmark_rejected() {
        let mut index = make_index();
        let bm = make_benchmark("bm-1", "r1");
        index.insert_benchmark(&bm, "t1").unwrap();
        let err = index.insert_benchmark(&bm, "t2").unwrap_err();
        match err {
            SpecializationIndexError::DuplicateBenchmark { .. } => {}
            other => panic!("expected DuplicateBenchmark, got {other}"),
        }
    }

    #[test]
    fn multiple_benchmarks_per_receipt() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();

        index
            .insert_benchmark(&make_benchmark("bm-1", "r1"), "t2")
            .unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-2", "r1"), "t3")
            .unwrap();

        let benchmarks = index
            .find_benchmarks_by_receipt(&rec.receipt_id, "t4")
            .unwrap();
        assert_eq!(benchmarks.len(), 2);
    }

    #[test]
    fn benchmarks_not_found_for_other_receipt() {
        let mut index = make_index();
        let bm = make_benchmark("bm-1", "r1");
        index.insert_benchmark(&bm, "t1").unwrap();

        let other_id = make_id("r2");
        let benchmarks = index.find_benchmarks_by_receipt(&other_id, "t2").unwrap();
        assert!(benchmarks.is_empty());
    }

    // -----------------------------------------------------------------------
    // Invalidation Log
    // -----------------------------------------------------------------------

    #[test]
    fn record_invalidation_marks_receipt_inactive() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();

        let entry = InvalidationEntry {
            receipt_id: rec.receipt_id.clone(),
            reason: InvalidationReason::EpochChange {
                old_epoch: 1,
                new_epoch: 2,
            },
            timestamp_ns: 2000,
            fallback_confirmed: true,
        };
        index.record_invalidation(&entry, "t2").unwrap();

        // Receipt should now be inactive
        let fetched = index.get_receipt(&rec.receipt_id, "t3").unwrap().unwrap();
        assert!(!fetched.active);
    }

    #[test]
    fn query_invalidations_by_time_window() {
        let mut index = make_index();
        let r1 = make_record("r1", 1);
        let r2 = make_record("r2", 1);
        index.insert_receipt(&r1, "t1").unwrap();
        index.insert_receipt(&r2, "t2").unwrap();

        let e1 = InvalidationEntry {
            receipt_id: r1.receipt_id.clone(),
            reason: InvalidationReason::ProofExpired {
                proof_id: make_id("p1"),
            },
            timestamp_ns: 1000,
            fallback_confirmed: true,
        };
        let e2 = InvalidationEntry {
            receipt_id: r2.receipt_id.clone(),
            reason: InvalidationReason::ManualRevocation {
                operator: "admin".to_string(),
            },
            timestamp_ns: 5000,
            fallback_confirmed: false,
        };
        index.record_invalidation(&e1, "t3").unwrap();
        index.record_invalidation(&e2, "t4").unwrap();

        // All invalidations
        let all = index.query_invalidations(None, None, "t5").unwrap();
        assert_eq!(all.len(), 2);

        // Window [2000, 6000]
        let windowed = index
            .query_invalidations(Some(2000), Some(6000), "t6")
            .unwrap();
        assert_eq!(windowed.len(), 1);
        assert_eq!(windowed[0].receipt_id, r2.receipt_id);

        // Window [0, 1000]
        let early = index
            .query_invalidations(Some(0), Some(1000), "t7")
            .unwrap();
        assert_eq!(early.len(), 1);
        assert_eq!(early[0].receipt_id, r1.receipt_id);
    }

    #[test]
    fn invalidation_reason_variants() {
        let mut index = make_index();

        for (i, reason) in [
            InvalidationReason::EpochChange {
                old_epoch: 1,
                new_epoch: 2,
            },
            InvalidationReason::ProofExpired {
                proof_id: make_id("p1"),
            },
            InvalidationReason::ProofRevoked {
                proof_id: make_id("p2"),
            },
            InvalidationReason::ManualRevocation {
                operator: "ops".to_string(),
            },
        ]
        .into_iter()
        .enumerate()
        {
            let rec = make_record(&format!("inv-{i}"), 1);
            index.insert_receipt(&rec, "t1").unwrap();
            let entry = InvalidationEntry {
                receipt_id: rec.receipt_id.clone(),
                reason,
                timestamp_ns: (i as u64 + 1) * 1000,
                fallback_confirmed: true,
            };
            index.record_invalidation(&entry, "t2").unwrap();
        }

        let all = index.query_invalidations(None, None, "t3").unwrap();
        assert_eq!(all.len(), 4);
    }

    // -----------------------------------------------------------------------
    // Audit Chain
    // -----------------------------------------------------------------------

    #[test]
    fn build_audit_chain_without_benchmarks() {
        let mut index = make_index();
        index.insert_receipt(&make_record("r1", 1), "t1").unwrap();

        let chain = index.build_audit_chain("t2").unwrap();
        assert_eq!(chain.len(), 1);
        assert!(chain[0].benchmark_id.is_none());
        assert!(chain[0].latency_reduction_millionths.is_none());
    }

    #[test]
    fn build_audit_chain_with_benchmarks() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-1", "r1"), "t2")
            .unwrap();

        let chain = index.build_audit_chain("t3").unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].benchmark_id.as_deref(), Some("bm-1"));
        assert_eq!(chain[0].latency_reduction_millionths, Some(200_000));
    }

    #[test]
    fn audit_chain_multiple_proofs_and_benchmarks() {
        let mut index = make_index();
        let mut rec = make_record("r1", 1);
        rec.proof_input_ids = vec![make_id("p1"), make_id("p2")];
        rec.proof_types = vec![ProofType::CapabilityWitness, ProofType::FlowProof];
        index.insert_receipt(&rec, "t1").unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-1", "r1"), "t2")
            .unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-2", "r1"), "t3")
            .unwrap();

        let chain = index.build_audit_chain("t4").unwrap();
        // 2 proofs * 2 benchmarks = 4 entries
        assert_eq!(chain.len(), 4);
    }

    #[test]
    fn reverse_audit_from_benchmark() {
        let mut index = make_index();
        index.insert_receipt(&make_record("r1", 1), "t1").unwrap();
        index.insert_receipt(&make_record("r2", 1), "t2").unwrap();

        index
            .insert_benchmark(&make_benchmark("bm-1", "r1"), "t3")
            .unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-2", "r2"), "t4")
            .unwrap();

        let result = index.reverse_audit_from_benchmark("bm-1", "t5").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].receipt_id, make_id("r1"));
    }

    // -----------------------------------------------------------------------
    // Extension Summary / Aggregate Views
    // -----------------------------------------------------------------------

    #[test]
    fn extension_summary_basic() {
        let mut index = make_index();

        let mut r1 = make_record("r1", 1);
        r1.extension_id = "ext-A".to_string();
        let mut r2 = make_record("r2", 1);
        r2.extension_id = "ext-A".to_string();
        r2.active = false;
        let mut r3 = make_record("r3", 1);
        r3.extension_id = "ext-B".to_string();

        index.insert_receipt(&r1, "t1").unwrap();
        index.insert_receipt(&r2, "t2").unwrap();
        index.insert_receipt(&r3, "t3").unwrap();

        let summary = index.extension_summary("ext-A", "t4").unwrap();
        assert_eq!(summary.total_specializations, 2);
        assert_eq!(summary.active_specializations, 1);
        assert_eq!(summary.invalidated_specializations, 1);
    }

    #[test]
    fn extension_summary_with_benchmarks() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();

        let mut bm1 = make_benchmark("bm-1", "r1");
        bm1.latency_reduction_millionths = 100_000;
        let mut bm2 = make_benchmark("bm-2", "r1");
        bm2.latency_reduction_millionths = 300_000;

        index.insert_benchmark(&bm1, "t2").unwrap();
        index.insert_benchmark(&bm2, "t3").unwrap();

        let summary = index.extension_summary("ext-1", "t4").unwrap();
        assert_eq!(summary.total_benchmarks, 2);
        assert_eq!(summary.avg_latency_reduction_millionths, 200_000);
    }

    #[test]
    fn extension_summary_no_data() {
        let mut index = make_index();
        let summary = index.extension_summary("nonexistent", "t1").unwrap();
        assert_eq!(summary.total_specializations, 0);
        assert_eq!(summary.active_specializations, 0);
        assert_eq!(summary.total_benchmarks, 0);
        assert_eq!(summary.avg_latency_reduction_millionths, 0);
    }

    // -----------------------------------------------------------------------
    // Event logging
    // -----------------------------------------------------------------------

    #[test]
    fn events_are_recorded() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();
        index.insert_receipt(&rec, "t2").unwrap_err(); // duplicate

        assert_eq!(index.events().len(), 2);
        assert_eq!(index.events()[0].event, "insert_receipt");
        assert_eq!(index.events()[0].outcome, "ok");
        assert!(index.events()[0].error_code.is_none());

        assert_eq!(index.events()[1].event, "insert_receipt");
        assert_eq!(index.events()[1].outcome, "duplicate");
        assert_eq!(
            index.events()[1].error_code.as_deref(),
            Some("DUPLICATE_RECEIPT")
        );
    }

    #[test]
    fn event_fields_populated() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "trace-42").unwrap();

        let event = &index.events()[0];
        assert_eq!(event.trace_id, "trace-42");
        assert_eq!(event.policy_id, "test-policy");
        assert_eq!(event.component, "specialization_index");
    }

    // -----------------------------------------------------------------------
    // Serialization round-trips
    // -----------------------------------------------------------------------

    #[test]
    fn specialization_record_serde_roundtrip() {
        let rec = make_record("r1", 1);
        let json = serde_json::to_string(&rec).unwrap();
        let decoded: SpecializationRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rec, decoded);
    }

    #[test]
    fn benchmark_outcome_serde_roundtrip() {
        let bm = make_benchmark("bm-1", "r1");
        let json = serde_json::to_string(&bm).unwrap();
        let decoded: BenchmarkOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(bm, decoded);
    }

    #[test]
    fn invalidation_entry_serde_roundtrip() {
        let entry = InvalidationEntry {
            receipt_id: make_id("r1"),
            reason: InvalidationReason::EpochChange {
                old_epoch: 1,
                new_epoch: 2,
            },
            timestamp_ns: 1000,
            fallback_confirmed: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: InvalidationEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, decoded);
    }

    #[test]
    fn audit_chain_entry_serde_roundtrip() {
        let entry = AuditChainEntry {
            proof_id: make_id("p1"),
            proof_type: ProofType::FlowProof,
            receipt_id: make_id("r1"),
            optimization_class: OptimizationClass::IfcCheckElision,
            benchmark_id: Some("bm-1".to_string()),
            latency_reduction_millionths: Some(150_000),
            epoch: SecurityEpoch::from_raw(3),
        };
        let json = serde_json::to_string(&entry).unwrap();
        let decoded: AuditChainEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, decoded);
    }

    // -----------------------------------------------------------------------
    // Error display
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_coverage() {
        let errors = vec![
            SpecializationIndexError::Storage("backend down".to_string()),
            SpecializationIndexError::NotFound {
                receipt_id: "abc".to_string(),
            },
            SpecializationIndexError::DuplicateReceipt {
                receipt_id: "abc".to_string(),
            },
            SpecializationIndexError::DuplicateBenchmark {
                benchmark_id: "bm-1".to_string(),
            },
            SpecializationIndexError::SerializationFailed("bad json".to_string()),
            SpecializationIndexError::InvalidContext("missing trace".to_string()),
        ];
        for err in &errors {
            let msg = format!("{err}");
            assert!(!msg.is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // End-to-end lifecycle
    // -----------------------------------------------------------------------

    #[test]
    fn full_lifecycle_insert_benchmark_invalidate_audit() {
        let mut index = make_index();

        // 1. Insert receipts
        let r1 = make_record("r1", 1);
        let r2 = make_record("r2", 1);
        index.insert_receipt(&r1, "t1").unwrap();
        index.insert_receipt(&r2, "t2").unwrap();

        // 2. Add benchmarks
        index
            .insert_benchmark(&make_benchmark("bm-1", "r1"), "t3")
            .unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-2", "r2"), "t4")
            .unwrap();

        // 3. Build audit chain (should have 2 entries)
        let chain = index.build_audit_chain("t5").unwrap();
        assert_eq!(chain.len(), 2);
        assert!(chain.iter().all(|e| e.benchmark_id.is_some()));

        // 4. Invalidate r1
        let inv = InvalidationEntry {
            receipt_id: r1.receipt_id.clone(),
            reason: InvalidationReason::EpochChange {
                old_epoch: 1,
                new_epoch: 2,
            },
            timestamp_ns: 10_000,
            fallback_confirmed: true,
        };
        index.record_invalidation(&inv, "t6").unwrap();

        // 5. Verify r1 is inactive
        let fetched = index.get_receipt(&r1.receipt_id, "t7").unwrap().unwrap();
        assert!(!fetched.active);

        // 6. Active query should only return r2
        let active = index.query_active_receipts("t8").unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].receipt_id, r2.receipt_id);

        // 7. Summary
        let summary = index.extension_summary("ext-1", "t9").unwrap();
        assert_eq!(summary.total_specializations, 2);
        assert_eq!(summary.active_specializations, 1);
        assert_eq!(summary.invalidated_specializations, 1);
        assert_eq!(summary.total_benchmarks, 2);
    }

    // -----------------------------------------------------------------------
    // Error codes (stable)
    // -----------------------------------------------------------------------

    #[test]
    fn error_codes_are_stable() {
        assert_eq!(
            error_code(&SpecializationIndexError::Storage("x".to_string())),
            "SI_STORAGE_ERROR"
        );
        assert_eq!(
            error_code(&SpecializationIndexError::NotFound {
                receipt_id: "x".to_string()
            }),
            "SI_NOT_FOUND"
        );
        assert_eq!(
            error_code(&SpecializationIndexError::DuplicateReceipt {
                receipt_id: "x".to_string()
            }),
            "SI_DUPLICATE_RECEIPT"
        );
        assert_eq!(
            error_code(&SpecializationIndexError::DuplicateBenchmark {
                benchmark_id: "x".to_string()
            }),
            "SI_DUPLICATE_BENCHMARK"
        );
        assert_eq!(
            error_code(&SpecializationIndexError::SerializationFailed(
                "x".to_string()
            )),
            "SI_SERIALIZATION_FAILED"
        );
        assert_eq!(
            error_code(&SpecializationIndexError::InvalidContext("x".to_string())),
            "SI_INVALID_CONTEXT"
        );
    }

    // -----------------------------------------------------------------------
    // Deterministic replay
    // -----------------------------------------------------------------------

    #[test]
    fn deterministic_replay_identical_events() {
        let run = || {
            let mut index = make_index();
            let rec = make_record("r1", 1);
            index.insert_receipt(&rec, "t1").unwrap();
            index
                .insert_benchmark(&make_benchmark("bm-1", "r1"), "t2")
                .unwrap();
            serde_json::to_string(index.events()).unwrap()
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn extension_summary_serde_roundtrip() {
        let summary = ExtensionSpecializationSummary {
            extension_id: "ext-1".to_string(),
            total_specializations: 5,
            active_specializations: 3,
            invalidated_specializations: 2,
            total_benchmarks: 10,
            avg_latency_reduction_millionths: 200_000,
            proof_utilization_count: 4,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let decoded: ExtensionSpecializationSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, decoded);
    }

    #[test]
    fn event_serde_roundtrip() {
        let event = SpecializationIndexEvent {
            trace_id: "t-1".to_string(),
            decision_id: "d-1".to_string(),
            policy_id: "p-1".to_string(),
            component: "specialization_index".to_string(),
            event: "insert_receipt".to_string(),
            outcome: "ok".to_string(),
            error_code: None,
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: SpecializationIndexEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event, decoded);
    }

    // -- Enrichment batch 2: Display uniqueness, boundaries, error paths --

    #[test]
    fn error_display_uniqueness_btreeset() {
        use std::collections::BTreeSet;
        let errors = [
            SpecializationIndexError::Storage("x".to_string()),
            SpecializationIndexError::NotFound {
                receipt_id: "x".to_string(),
            },
            SpecializationIndexError::DuplicateReceipt {
                receipt_id: "x".to_string(),
            },
            SpecializationIndexError::DuplicateBenchmark {
                benchmark_id: "x".to_string(),
            },
            SpecializationIndexError::SerializationFailed("x".to_string()),
            SpecializationIndexError::InvalidContext("x".to_string()),
        ];
        let set: BTreeSet<String> = errors.iter().map(|e| e.to_string()).collect();
        assert_eq!(
            set.len(),
            errors.len(),
            "all error Display strings must be unique"
        );
    }

    #[test]
    fn invalidation_reason_serde_all_variants() {
        let variants = vec![
            InvalidationReason::EpochChange {
                old_epoch: 1,
                new_epoch: 2,
            },
            InvalidationReason::ProofExpired {
                proof_id: make_id("p0"),
            },
            InvalidationReason::ProofRevoked {
                proof_id: make_id("p1"),
            },
            InvalidationReason::ManualRevocation {
                operator: "admin".to_string(),
            },
        ];
        for v in &variants {
            let json = serde_json::to_string(v).unwrap();
            let back: InvalidationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn get_receipt_nonexistent_returns_none() {
        let mut index = make_index();
        let result = index.get_receipt(&make_id("nonexistent"), "t1").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn query_active_receipts_empty_index() {
        let mut index = make_index();
        let active = index.query_active_receipts("t1").unwrap();
        assert!(active.is_empty());
    }

    #[test]
    fn insert_benchmark_for_nonexistent_receipt_succeeds() {
        let mut index = make_index();
        let bm = make_benchmark("bm-orphan", "nonexistent-receipt");
        // insert_benchmark does not require the receipt to exist beforehand
        index.insert_benchmark(&bm, "t1").unwrap();
    }

    #[test]
    fn build_audit_chain_empty_index() {
        let mut index = make_index();
        let chain = index.build_audit_chain("t1").unwrap();
        assert!(chain.is_empty());
    }

    #[test]
    fn multiple_invalidations_same_receipt_idempotent() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();

        let inv = InvalidationEntry {
            receipt_id: make_id("r1"),
            reason: InvalidationReason::EpochChange {
                old_epoch: 1,
                new_epoch: 2,
            },
            timestamp_ns: 1000,
            fallback_confirmed: true,
        };
        index.record_invalidation(&inv, "t2").unwrap();
        // Second invalidation should succeed without error
        index.record_invalidation(&inv, "t3").unwrap();

        let fetched = index.get_receipt(&rec.receipt_id, "t4").unwrap().unwrap();
        assert!(!fetched.active);
    }

    #[test]
    fn extension_summary_with_benchmarks_has_avg_latency() {
        let mut index = make_index();
        let r1 = make_record("r1", 1);
        index.insert_receipt(&r1, "t1").unwrap();

        let mut bm = make_benchmark("bm-1", "r1");
        bm.latency_reduction_millionths = 200_000;
        index.insert_benchmark(&bm, "t2").unwrap();

        let summary = index.extension_summary("ext-1", "t3").unwrap();
        assert_eq!(summary.total_benchmarks, 1);
        assert_eq!(summary.avg_latency_reduction_millionths, 200_000);
    }

    // -- Enrichment batch 3: clone, stress, boundary, reverse audit, invalidation queries --

    #[test]
    fn specialization_record_clone_equality() {
        let rec = make_record("r1", 1);
        let cloned = rec.clone();
        assert_eq!(rec, cloned);
        assert_eq!(rec.receipt_id, cloned.receipt_id);
        assert_eq!(rec.proof_input_ids, cloned.proof_input_ids);
    }

    #[test]
    fn benchmark_outcome_clone_equality() {
        let bm = make_benchmark("bm-1", "r1");
        let cloned = bm.clone();
        assert_eq!(bm, cloned);
    }

    #[test]
    fn audit_chain_entry_without_benchmark() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();
        // No benchmark inserted — chain entry should have benchmark_id=None
        let chain = index.build_audit_chain("t2").unwrap();
        assert_eq!(chain.len(), 1);
        assert!(chain[0].benchmark_id.is_none());
        assert!(chain[0].latency_reduction_millionths.is_none());
    }

    #[test]
    fn reverse_audit_from_benchmark_finds_correct_entry() {
        let mut index = make_index();
        let r1 = make_record("r1", 1);
        let r2 = make_record("r2", 1);
        index.insert_receipt(&r1, "t1").unwrap();
        index.insert_receipt(&r2, "t2").unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-1", "r1"), "t3")
            .unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-2", "r2"), "t4")
            .unwrap();

        let result = index.reverse_audit_from_benchmark("bm-1", "t5").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].receipt_id, r1.receipt_id);
    }

    #[test]
    fn reverse_audit_nonexistent_benchmark_returns_empty() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-1", "r1"), "t2")
            .unwrap();

        let result = index
            .reverse_audit_from_benchmark("bm-nonexistent", "t3")
            .unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn query_invalidations_no_filter() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();

        let inv = InvalidationEntry {
            receipt_id: make_id("r1"),
            reason: InvalidationReason::EpochChange {
                old_epoch: 1,
                new_epoch: 2,
            },
            timestamp_ns: 5000,
            fallback_confirmed: true,
        };
        index.record_invalidation(&inv, "t2").unwrap();

        let results = index.query_invalidations(None, None, "t3").unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].receipt_id, make_id("r1"));
    }

    #[test]
    fn query_invalidations_with_time_window() {
        let mut index = make_index();
        for i in 1..=3u64 {
            let rec = make_record(&format!("r{i}"), 1);
            index.insert_receipt(&rec, &format!("t-ins-{i}")).unwrap();
            let inv = InvalidationEntry {
                receipt_id: make_id(&format!("r{i}")),
                reason: InvalidationReason::ManualRevocation {
                    operator: "admin".to_string(),
                },
                timestamp_ns: i * 1000,
                fallback_confirmed: true,
            };
            index
                .record_invalidation(&inv, &format!("t-inv-{i}"))
                .unwrap();
        }

        // Only entries in [2000, 3000]
        let results = index
            .query_invalidations(Some(2000), Some(3000), "t-q")
            .unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn duplicate_receipt_insert_returns_error() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();
        let err = index.insert_receipt(&rec, "t2").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("r1") || msg.contains("duplicate"),
            "error should mention the duplicate: {msg}"
        );
    }

    #[test]
    fn duplicate_benchmark_insert_returns_error() {
        let mut index = make_index();
        let bm = make_benchmark("bm-1", "r1");
        index.insert_benchmark(&bm, "t1").unwrap();
        let err = index.insert_benchmark(&bm, "t2").unwrap_err();
        let msg = err.to_string();
        assert!(!msg.is_empty());
    }

    #[test]
    fn stress_insert_20_receipts() {
        let mut index = make_index();
        for i in 0..20u64 {
            let rec = make_record(&format!("r-{i}"), 1);
            index.insert_receipt(&rec, &format!("t-{i}")).unwrap();
        }
        let active = index.query_active_receipts("t-q").unwrap();
        assert_eq!(active.len(), 20);
    }

    #[test]
    fn error_is_std_error() {
        let err = SpecializationIndexError::Storage("fail".to_string());
        let _: &dyn std::error::Error = &err;
    }

    #[test]
    fn specialization_record_json_field_presence() {
        let rec = make_record("r1", 1);
        let json = serde_json::to_string(&rec).unwrap();
        assert!(json.contains("\"receipt_id\""));
        assert!(json.contains("\"proof_input_ids\""));
        assert!(json.contains("\"proof_types\""));
        assert!(json.contains("\"optimization_class\""));
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"timestamp_ns\""));
    }

    #[test]
    fn benchmark_outcome_json_field_presence() {
        let bm = make_benchmark("bm-1", "r1");
        let json = serde_json::to_string(&bm).unwrap();
        assert!(json.contains("\"benchmark_id\""));
        assert!(json.contains("\"receipt_id\""));
        assert!(json.contains("\"latency_reduction_millionths\""));
        assert!(json.contains("\"sample_count\""));
        assert!(json.contains("\"timestamp_ns\""));
    }

    #[test]
    fn events_accumulate_across_operations() {
        let mut index = make_index();
        let rec = make_record("r1", 1);
        index.insert_receipt(&rec, "t1").unwrap();
        index
            .insert_benchmark(&make_benchmark("bm-1", "r1"), "t2")
            .unwrap();
        let _ = index.build_audit_chain("t3").unwrap();
        // insert_receipt + insert_benchmark + build_audit_chain = at least 3 events
        assert!(
            index.events().len() >= 3,
            "expected at least 3 events, got {}",
            index.events().len()
        );
    }

    #[test]
    fn extension_summary_avg_latency_multiple_benchmarks() {
        let mut index = make_index();
        let r1 = make_record("r1", 1);
        let r2 = make_record("r2", 1);
        index.insert_receipt(&r1, "t1").unwrap();
        index.insert_receipt(&r2, "t2").unwrap();

        let mut bm1 = make_benchmark("bm-1", "r1");
        bm1.latency_reduction_millionths = 100_000;
        let mut bm2 = make_benchmark("bm-2", "r2");
        bm2.latency_reduction_millionths = 300_000;
        index.insert_benchmark(&bm1, "t3").unwrap();
        index.insert_benchmark(&bm2, "t4").unwrap();

        let summary = index.extension_summary("ext-1", "t5").unwrap();
        assert_eq!(summary.total_benchmarks, 2);
        assert_eq!(summary.avg_latency_reduction_millionths, 200_000);
    }

    #[test]
    fn invalidation_entry_clone_equality() {
        let inv = InvalidationEntry {
            receipt_id: make_id("r1"),
            reason: InvalidationReason::ProofRevoked {
                proof_id: make_id("p1"),
            },
            timestamp_ns: 42,
            fallback_confirmed: false,
        };
        let cloned = inv.clone();
        assert_eq!(inv, cloned);
    }

    #[test]
    fn error_code_all_unique() {
        use std::collections::BTreeSet;
        let errors = [
            SpecializationIndexError::Storage("x".to_string()),
            SpecializationIndexError::NotFound {
                receipt_id: "x".to_string(),
            },
            SpecializationIndexError::DuplicateReceipt {
                receipt_id: "x".to_string(),
            },
            SpecializationIndexError::DuplicateBenchmark {
                benchmark_id: "x".to_string(),
            },
            SpecializationIndexError::SerializationFailed("x".to_string()),
            SpecializationIndexError::InvalidContext("x".to_string()),
        ];
        let codes: BTreeSet<&str> = errors.iter().map(|e| error_code(e)).collect();
        assert_eq!(codes.len(), errors.len(), "all error codes must be unique");
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 4: deeper coverage, edge cases, Debug, JSON fields
    // -----------------------------------------------------------------------

    #[test]
    fn enrichment_specialization_record_debug_format() {
        let rec = make_record("dbg-1", 1);
        let dbg = format!("{rec:?}");
        assert!(dbg.contains("SpecializationRecord"));
        assert!(dbg.contains("receipt_id"));
        assert!(dbg.contains("active"));
    }

    #[test]
    fn enrichment_benchmark_outcome_debug_format() {
        let bm = make_benchmark("dbg-bm", "r1");
        let dbg = format!("{bm:?}");
        assert!(dbg.contains("BenchmarkOutcome"));
        assert!(dbg.contains("latency_reduction_millionths"));
        assert!(dbg.contains("sample_count"));
    }

    #[test]
    fn enrichment_invalidation_entry_debug_format() {
        let entry = InvalidationEntry {
            receipt_id: make_id("dbg-inv"),
            reason: InvalidationReason::ManualRevocation {
                operator: "ops-team".to_string(),
            },
            timestamp_ns: 999,
            fallback_confirmed: false,
        };
        let dbg = format!("{entry:?}");
        assert!(dbg.contains("InvalidationEntry"));
        assert!(dbg.contains("ManualRevocation"));
        assert!(dbg.contains("ops-team"));
    }

    #[test]
    fn enrichment_audit_chain_entry_debug_format() {
        let ace = AuditChainEntry {
            proof_id: make_id("p-dbg"),
            proof_type: ProofType::ReplayMotif,
            receipt_id: make_id("r-dbg"),
            optimization_class: OptimizationClass::SuperinstructionFusion,
            benchmark_id: None,
            latency_reduction_millionths: None,
            epoch: SecurityEpoch::from_raw(7),
        };
        let dbg = format!("{ace:?}");
        assert!(dbg.contains("AuditChainEntry"));
        assert!(dbg.contains("ReplayMotif"));
        assert!(dbg.contains("SuperinstructionFusion"));
    }

    #[test]
    fn enrichment_extension_summary_debug_format() {
        let summary = ExtensionSpecializationSummary {
            extension_id: "ext-dbg".to_string(),
            total_specializations: 3,
            active_specializations: 2,
            invalidated_specializations: 1,
            total_benchmarks: 5,
            avg_latency_reduction_millionths: 150_000,
            proof_utilization_count: 4,
        };
        let dbg = format!("{summary:?}");
        assert!(dbg.contains("ExtensionSpecializationSummary"));
        assert!(dbg.contains("proof_utilization_count"));
    }

    #[test]
    fn enrichment_event_debug_format() {
        let evt = SpecializationIndexEvent {
            trace_id: "t-dbg".to_string(),
            decision_id: "d-dbg".to_string(),
            policy_id: "p-dbg".to_string(),
            component: "specialization_index".to_string(),
            event: "test_event".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("TEST_CODE".to_string()),
        };
        let dbg = format!("{evt:?}");
        assert!(dbg.contains("SpecializationIndexEvent"));
        assert!(dbg.contains("TEST_CODE"));
    }

    #[test]
    fn enrichment_record_with_all_optimization_classes() {
        let mut index = make_index();
        let classes = [
            OptimizationClass::HostcallDispatchSpecialization,
            OptimizationClass::IfcCheckElision,
            OptimizationClass::SuperinstructionFusion,
            OptimizationClass::PathElimination,
        ];
        for (i, class) in classes.iter().enumerate() {
            let mut rec = make_record(&format!("opt-{i}"), 1);
            rec.optimization_class = *class;
            index.insert_receipt(&rec, &format!("t-{i}")).unwrap();
        }
        let all = index.query_receipts(None, "t-q").unwrap();
        assert_eq!(all.len(), 4);
        let found_classes: std::collections::BTreeSet<String> = all
            .iter()
            .map(|r| r.optimization_class.to_string())
            .collect();
        assert_eq!(found_classes.len(), 4);
    }

    #[test]
    fn enrichment_record_with_all_proof_types() {
        let mut index = make_index();
        let types = [
            ProofType::CapabilityWitness,
            ProofType::FlowProof,
            ProofType::ReplayMotif,
        ];
        for (i, pt) in types.iter().enumerate() {
            let mut rec = make_record(&format!("pt-{i}"), 1);
            rec.proof_types = vec![*pt];
            index.insert_receipt(&rec, &format!("t-{i}")).unwrap();
        }
        let all = index.query_receipts(None, "t-q").unwrap();
        assert_eq!(all.len(), 3);
        // Query order is not guaranteed, so collect all proof types
        let found_types: std::collections::BTreeSet<String> =
            all.iter().map(|r| r.proof_types[0].to_string()).collect();
        assert_eq!(found_types.len(), 3);
        assert!(found_types.contains("capability_witness"));
        assert!(found_types.contains("flow_proof"));
        assert!(found_types.contains("replay_motif"));
    }

    #[test]
    fn enrichment_record_empty_proof_inputs() {
        let mut rec = make_record("empty-proofs", 1);
        rec.proof_input_ids = vec![];
        rec.proof_types = vec![];
        let mut index = make_index();
        index.insert_receipt(&rec, "t1").unwrap();
        let chain = index.build_audit_chain("t2").unwrap();
        // No proof inputs means no chain entries for this receipt
        assert!(chain.is_empty());
    }

    #[test]
    fn enrichment_record_many_proof_inputs() {
        let mut rec = make_record("many-proofs", 1);
        rec.proof_input_ids = (0..5).map(|i| make_id(&format!("proof-{i}"))).collect();
        rec.proof_types = vec![
            ProofType::CapabilityWitness,
            ProofType::FlowProof,
            ProofType::ReplayMotif,
            ProofType::CapabilityWitness,
            ProofType::FlowProof,
        ];
        let mut index = make_index();
        index.insert_receipt(&rec, "t1").unwrap();
        let chain = index.build_audit_chain("t2").unwrap();
        assert_eq!(chain.len(), 5);
        assert_eq!(chain[2].proof_type, ProofType::ReplayMotif);
    }

    #[test]
    fn enrichment_benchmark_zero_latency_and_throughput() {
        let bm = BenchmarkOutcome {
            benchmark_id: "bm-zero".to_string(),
            receipt_id: make_id("r-zero"),
            latency_reduction_millionths: 0,
            throughput_increase_millionths: 0,
            sample_count: 0,
            timestamp_ns: 0,
        };
        let json = serde_json::to_string(&bm).unwrap();
        let decoded: BenchmarkOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.latency_reduction_millionths, 0);
        assert_eq!(decoded.throughput_increase_millionths, 0);
        assert_eq!(decoded.sample_count, 0);
    }

    #[test]
    fn enrichment_benchmark_max_values() {
        let bm = BenchmarkOutcome {
            benchmark_id: "bm-max".to_string(),
            receipt_id: make_id("r-max"),
            latency_reduction_millionths: u64::MAX,
            throughput_increase_millionths: u64::MAX,
            sample_count: u64::MAX,
            timestamp_ns: u64::MAX,
        };
        let json = serde_json::to_string(&bm).unwrap();
        let decoded: BenchmarkOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.latency_reduction_millionths, u64::MAX);
        assert_eq!(decoded.timestamp_ns, u64::MAX);
    }

    #[test]
    fn enrichment_invalidation_for_nonexistent_receipt_stores_entry() {
        let mut index = make_index();
        // No receipt inserted — invalidation should still succeed
        let entry = InvalidationEntry {
            receipt_id: make_id("ghost"),
            reason: InvalidationReason::ProofExpired {
                proof_id: make_id("expired-proof"),
            },
            timestamp_ns: 7777,
            fallback_confirmed: false,
        };
        index.record_invalidation(&entry, "t1").unwrap();
        let results = index.query_invalidations(None, None, "t2").unwrap();
        assert_eq!(results.len(), 1);
        assert!(!results[0].fallback_confirmed);
    }

    #[test]
    fn enrichment_delete_receipt_emits_event() {
        let mut index = make_index();
        let rec = make_record("del-evt", 1);
        index.insert_receipt(&rec, "t1").unwrap();
        index.delete_receipt(&rec.receipt_id, "t2").unwrap();

        let delete_events: Vec<_> = index
            .events()
            .iter()
            .filter(|e| e.event == "delete_receipt")
            .collect();
        assert_eq!(delete_events.len(), 1);
        assert_eq!(delete_events[0].outcome, "ok");
    }

    #[test]
    fn enrichment_delete_nonexistent_receipt_emits_not_found_event() {
        let mut index = make_index();
        let id = make_id("missing");
        let deleted = index.delete_receipt(&id, "t1").unwrap();
        assert!(!deleted);

        let delete_events: Vec<_> = index
            .events()
            .iter()
            .filter(|e| e.event == "delete_receipt")
            .collect();
        assert_eq!(delete_events.len(), 1);
        assert_eq!(delete_events[0].outcome, "not_found");
    }

    #[test]
    fn enrichment_audit_chain_entry_json_field_presence() {
        let ace = AuditChainEntry {
            proof_id: make_id("p-json"),
            proof_type: ProofType::FlowProof,
            receipt_id: make_id("r-json"),
            optimization_class: OptimizationClass::PathElimination,
            benchmark_id: Some("bm-json".to_string()),
            latency_reduction_millionths: Some(500_000),
            epoch: SecurityEpoch::from_raw(10),
        };
        let json = serde_json::to_string(&ace).unwrap();
        assert!(json.contains("\"proof_id\""));
        assert!(json.contains("\"proof_type\""));
        assert!(json.contains("\"receipt_id\""));
        assert!(json.contains("\"optimization_class\""));
        assert!(json.contains("\"benchmark_id\""));
        assert!(json.contains("\"latency_reduction_millionths\""));
        assert!(json.contains("\"epoch\""));
    }

    #[test]
    fn enrichment_extension_summary_json_field_presence() {
        let summary = ExtensionSpecializationSummary {
            extension_id: "ext-json".to_string(),
            total_specializations: 10,
            active_specializations: 7,
            invalidated_specializations: 3,
            total_benchmarks: 20,
            avg_latency_reduction_millionths: 180_000,
            proof_utilization_count: 15,
        };
        let json = serde_json::to_string(&summary).unwrap();
        assert!(json.contains("\"extension_id\""));
        assert!(json.contains("\"total_specializations\""));
        assert!(json.contains("\"active_specializations\""));
        assert!(json.contains("\"invalidated_specializations\""));
        assert!(json.contains("\"total_benchmarks\""));
        assert!(json.contains("\"avg_latency_reduction_millionths\""));
        assert!(json.contains("\"proof_utilization_count\""));
    }

    #[test]
    fn enrichment_invalidation_entry_json_field_presence() {
        let entry = InvalidationEntry {
            receipt_id: make_id("inv-json"),
            reason: InvalidationReason::ProofRevoked {
                proof_id: make_id("rev-proof"),
            },
            timestamp_ns: 12345,
            fallback_confirmed: true,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"receipt_id\""));
        assert!(json.contains("\"reason\""));
        assert!(json.contains("\"timestamp_ns\""));
        assert!(json.contains("\"fallback_confirmed\""));
        assert!(json.contains("\"ProofRevoked\""));
    }

    #[test]
    fn enrichment_event_json_field_presence() {
        let evt = SpecializationIndexEvent {
            trace_id: "t-jf".to_string(),
            decision_id: "d-jf".to_string(),
            policy_id: "p-jf".to_string(),
            component: "specialization_index".to_string(),
            event: "test".to_string(),
            outcome: "ok".to_string(),
            error_code: Some("E001".to_string()),
        };
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"decision_id\""));
        assert!(json.contains("\"policy_id\""));
        assert!(json.contains("\"component\""));
        assert!(json.contains("\"event\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"error_code\""));
    }

    #[test]
    fn enrichment_extension_summary_proof_utilization_count() {
        let mut index = make_index();
        let mut r1 = make_record("r-util-1", 1);
        r1.proof_input_ids = vec![make_id("p1"), make_id("p2"), make_id("p3")];
        let mut r2 = make_record("r-util-2", 1);
        r2.proof_input_ids = vec![make_id("p4")];
        index.insert_receipt(&r1, "t1").unwrap();
        index.insert_receipt(&r2, "t2").unwrap();

        let summary = index.extension_summary("ext-1", "t3").unwrap();
        assert_eq!(summary.proof_utilization_count, 4); // 3 + 1
    }

    #[test]
    fn enrichment_query_invalidations_empty_window_returns_empty() {
        let mut index = make_index();
        let rec = make_record("r-ew", 1);
        index.insert_receipt(&rec, "t1").unwrap();
        let inv = InvalidationEntry {
            receipt_id: make_id("r-ew"),
            reason: InvalidationReason::EpochChange {
                old_epoch: 1,
                new_epoch: 2,
            },
            timestamp_ns: 5000,
            fallback_confirmed: true,
        };
        index.record_invalidation(&inv, "t2").unwrap();

        // Window entirely before the invalidation
        let results = index.query_invalidations(Some(1), Some(100), "t3").unwrap();
        assert!(results.is_empty());

        // Window entirely after the invalidation
        let results = index
            .query_invalidations(Some(10_000), Some(20_000), "t4")
            .unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn enrichment_error_display_contains_payload() {
        let err = SpecializationIndexError::Storage("backend-unavailable".to_string());
        assert!(err.to_string().contains("backend-unavailable"));

        let err = SpecializationIndexError::NotFound {
            receipt_id: "abc-123".to_string(),
        };
        assert!(err.to_string().contains("abc-123"));

        let err = SpecializationIndexError::SerializationFailed("invalid utf8".to_string());
        assert!(err.to_string().contains("invalid utf8"));

        let err = SpecializationIndexError::InvalidContext("no trace id".to_string());
        assert!(err.to_string().contains("no trace id"));
    }
}
