//! Workload-manifold compression and cross-workload transfer plane.
//!
//! Derives deterministic workload embeddings from trace and IR evidence,
//! computes neighborhood certificates, and transfers specialization
//! knowledge (rewrite rules, tiering decisions, cache priors) across
//! workload neighborhoods with drift guards.
//!
//! ## Design
//!
//! - **Workload embeddings**: fixed-dimension vectors from IR shape,
//!   allocation profile, call-graph topology, and type-feedback
//!   distributions.
//! - **Neighborhood certificates**: formal attestation that two workloads
//!   are close enough in the manifold for safe knowledge transfer.
//! - **Transfer policies**: what knowledge can be transferred, under
//!   what conditions, and what happens when drift is detected.
//! - **Drift guards**: continuous monitoring that transferred knowledge
//!   remains valid as workloads evolve.
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.7, bd-1lsy.7.12 (RGC-612).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "workload_manifold_transfer";
pub const SCHEMA_VERSION: &str = "franken-engine.workload-manifold-transfer.v1";
pub const BEAD_ID: &str = "bd-1lsy.7.12";
pub const EMBEDDING_DIMENSIONS: usize = 32;
pub const MAX_EMBEDDINGS: usize = 10_000;
pub const NEIGHBORHOOD_THRESHOLD_MILLIONTHS: u64 = 800_000;

// ---------------------------------------------------------------------------
// Embedding feature
// ---------------------------------------------------------------------------

/// Feature axes for workload embeddings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddingFeature {
    IrNodeCount,
    IrEdgeCount,
    LoopNestingDepth,
    CallGraphFanout,
    AllocationRate,
    TypeFeedbackEntropy,
    BranchingFactor,
    MemoryFootprint,
    AsyncAwaitDepth,
    ModuleGraphSize,
    StringOperationRatio,
    RegexComplexity,
    ObjectShapeCount,
    PrototypeChainsLength,
    ClosureCaptureCount,
    HostcallFrequency,
}

impl EmbeddingFeature {
    pub const ALL: &'static [Self] = &[
        Self::IrNodeCount,
        Self::IrEdgeCount,
        Self::LoopNestingDepth,
        Self::CallGraphFanout,
        Self::AllocationRate,
        Self::TypeFeedbackEntropy,
        Self::BranchingFactor,
        Self::MemoryFootprint,
        Self::AsyncAwaitDepth,
        Self::ModuleGraphSize,
        Self::StringOperationRatio,
        Self::RegexComplexity,
        Self::ObjectShapeCount,
        Self::PrototypeChainsLength,
        Self::ClosureCaptureCount,
        Self::HostcallFrequency,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IrNodeCount => "ir_node_count",
            Self::IrEdgeCount => "ir_edge_count",
            Self::LoopNestingDepth => "loop_nesting_depth",
            Self::CallGraphFanout => "call_graph_fanout",
            Self::AllocationRate => "allocation_rate",
            Self::TypeFeedbackEntropy => "type_feedback_entropy",
            Self::BranchingFactor => "branching_factor",
            Self::MemoryFootprint => "memory_footprint",
            Self::AsyncAwaitDepth => "async_await_depth",
            Self::ModuleGraphSize => "module_graph_size",
            Self::StringOperationRatio => "string_operation_ratio",
            Self::RegexComplexity => "regex_complexity",
            Self::ObjectShapeCount => "object_shape_count",
            Self::PrototypeChainsLength => "prototype_chains_length",
            Self::ClosureCaptureCount => "closure_capture_count",
            Self::HostcallFrequency => "hostcall_frequency",
        }
    }
}

impl fmt::Display for EmbeddingFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Workload embedding
// ---------------------------------------------------------------------------

/// A fixed-dimension embedding vector for a workload.
/// Values are in fixed-point millionths for determinism.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkloadEmbedding {
    pub workload_id: String,
    pub dimensions: BTreeMap<EmbeddingFeature, i64>,
    pub source_hash: ContentHash,
}

impl WorkloadEmbedding {
    pub fn new(workload_id: String, source_hash: ContentHash) -> Self {
        Self {
            workload_id,
            dimensions: BTreeMap::new(),
            source_hash,
        }
    }

    pub fn set_dimension(&mut self, feature: EmbeddingFeature, value: i64) {
        self.dimensions.insert(feature, value);
    }

    pub fn get_dimension(&self, feature: &EmbeddingFeature) -> i64 {
        self.dimensions.get(feature).copied().unwrap_or(0)
    }

    /// Compute L2 distance squared (in millionths) to another embedding.
    pub fn distance_squared(&self, other: &Self) -> u64 {
        let mut sum: u64 = 0;
        for feature in EmbeddingFeature::ALL {
            let a = self.get_dimension(feature);
            let b = other.get_dimension(feature);
            let abs_diff = a.wrapping_sub(b).unsigned_abs();
            sum = sum.saturating_add(abs_diff.saturating_mul(abs_diff));
        }
        sum
    }

    /// Compute cosine similarity (millionths) to another embedding.
    pub fn cosine_similarity_millionths(&self, other: &Self) -> u64 {
        let mut dot: i64 = 0;
        let mut mag_a: u64 = 0;
        let mut mag_b: u64 = 0;
        for feature in EmbeddingFeature::ALL {
            let a = self.get_dimension(feature);
            let b = other.get_dimension(feature);
            dot = dot.saturating_add(a.saturating_mul(b));
            mag_a = mag_a.saturating_add(a.unsigned_abs().saturating_mul(a.unsigned_abs()));
            mag_b = mag_b.saturating_add(b.unsigned_abs().saturating_mul(b.unsigned_abs()));
        }
        if mag_a == 0 || mag_b == 0 {
            return 0;
        }
        // Approximate: dot / (sqrt(mag_a) * sqrt(mag_b)) * 1_000_000
        // Use integer sqrt approximation
        let sqrt_a = isqrt(mag_a);
        let sqrt_b = isqrt(mag_b);
        let denom = sqrt_a.saturating_mul(sqrt_b);
        if denom == 0 {
            return 0;
        }
        let abs_dot = dot.unsigned_abs();
        abs_dot
            .saturating_mul(1_000_000)
            .checked_div(denom)
            .unwrap_or(0)
    }
}

/// Integer square root (floor).
fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

// ---------------------------------------------------------------------------
// Neighborhood certificate
// ---------------------------------------------------------------------------

/// Attestation that two workloads are in the same neighborhood.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NeighborhoodCertificate {
    pub source_workload: String,
    pub target_workload: String,
    pub similarity_millionths: u64,
    pub distance_squared: u64,
    pub threshold_millionths: u64,
    pub is_neighbor: bool,
    pub certificate_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Transfer kind
// ---------------------------------------------------------------------------

/// What type of knowledge is being transferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferKind {
    RewriteRules,
    TieringDecisions,
    CachePriors,
    InlineCandidates,
    AllocationHints,
    TypeProfileHints,
}

impl TransferKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RewriteRules => "rewrite_rules",
            Self::TieringDecisions => "tiering_decisions",
            Self::CachePriors => "cache_priors",
            Self::InlineCandidates => "inline_candidates",
            Self::AllocationHints => "allocation_hints",
            Self::TypeProfileHints => "type_profile_hints",
        }
    }
}

impl fmt::Display for TransferKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A transfer record from one workload to another.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TransferRecord {
    pub id: String,
    pub kind: TransferKind,
    pub source_workload: String,
    pub target_workload: String,
    pub certificate_hash: ContentHash,
    pub items_transferred: u64,
    pub drift_detected: bool,
    pub rollback_triggered: bool,
}

// ---------------------------------------------------------------------------
// Transfer manifest
// ---------------------------------------------------------------------------

/// Manifest of all transfers in the system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferManifest {
    pub version: String,
    pub embeddings: Vec<WorkloadEmbedding>,
    pub certificates: Vec<NeighborhoodCertificate>,
    pub transfers: Vec<TransferRecord>,
}

impl TransferManifest {
    pub fn new() -> Self {
        Self {
            version: SCHEMA_VERSION.to_string(),
            embeddings: Vec::new(),
            certificates: Vec::new(),
            transfers: Vec::new(),
        }
    }

    pub fn add_embedding(&mut self, embedding: WorkloadEmbedding) -> Result<(), ManifoldError> {
        if self.embeddings.len() >= MAX_EMBEDDINGS {
            return Err(ManifoldError::EmbeddingOverflow {
                max: MAX_EMBEDDINGS,
            });
        }
        if self
            .embeddings
            .iter()
            .any(|e| e.workload_id == embedding.workload_id)
        {
            return Err(ManifoldError::DuplicateEmbedding {
                id: embedding.workload_id.clone(),
            });
        }
        self.embeddings.push(embedding);
        Ok(())
    }

    pub fn compute_certificate(
        &self,
        source_id: &str,
        target_id: &str,
    ) -> Option<NeighborhoodCertificate> {
        let source = self
            .embeddings
            .iter()
            .find(|e| e.workload_id == source_id)?;
        let target = self
            .embeddings
            .iter()
            .find(|e| e.workload_id == target_id)?;
        let similarity = source.cosine_similarity_millionths(target);
        let dist_sq = source.distance_squared(target);
        let is_neighbor = similarity >= NEIGHBORHOOD_THRESHOLD_MILLIONTHS;
        let cert_data = format!("{source_id}:{target_id}:{similarity}");
        Some(NeighborhoodCertificate {
            source_workload: source_id.to_string(),
            target_workload: target_id.to_string(),
            similarity_millionths: similarity,
            distance_squared: dist_sq,
            threshold_millionths: NEIGHBORHOOD_THRESHOLD_MILLIONTHS,
            is_neighbor,
            certificate_hash: ContentHash::compute(cert_data.as_bytes()),
        })
    }

    pub fn content_hash(&self) -> ContentHash {
        let mut entries = Vec::new();
        entries.push(CanonicalValue::String(self.version.clone()));

        // Hash embeddings (sorted by workload_id for determinism via BTreeMap)
        let mut sorted_embeddings: Vec<_> = self.embeddings.iter().collect();
        sorted_embeddings.sort_by(|a, b| a.workload_id.cmp(&b.workload_id));
        for e in &sorted_embeddings {
            let mut dim_entries = Vec::new();
            for (feat, val) in &e.dimensions {
                dim_entries.push(CanonicalValue::Map(BTreeMap::from([
                    (
                        "feature".to_string(),
                        CanonicalValue::String(feat.as_str().to_string()),
                    ),
                    ("value".to_string(), CanonicalValue::String(val.to_string())),
                ])));
            }
            entries.push(CanonicalValue::Map(BTreeMap::from([
                (
                    "id".to_string(),
                    CanonicalValue::String(e.workload_id.clone()),
                ),
                (
                    "source_hash".to_string(),
                    CanonicalValue::String(e.source_hash.to_hex()),
                ),
                ("dims".to_string(), CanonicalValue::Array(dim_entries)),
            ])));
        }

        // Hash certificates (sorted by source+target for determinism)
        let mut sorted_certs: Vec<_> = self.certificates.iter().collect();
        sorted_certs.sort_by(|a, b| {
            (&a.source_workload, &a.target_workload).cmp(&(&b.source_workload, &b.target_workload))
        });
        for c in &sorted_certs {
            entries.push(CanonicalValue::Map(BTreeMap::from([
                (
                    "cert_source".to_string(),
                    CanonicalValue::String(c.source_workload.clone()),
                ),
                (
                    "cert_target".to_string(),
                    CanonicalValue::String(c.target_workload.clone()),
                ),
                (
                    "similarity".to_string(),
                    CanonicalValue::String(c.similarity_millionths.to_string()),
                ),
                (
                    "is_neighbor".to_string(),
                    CanonicalValue::String(c.is_neighbor.to_string()),
                ),
            ])));
        }

        // Hash transfers (sorted by id for determinism)
        let mut sorted_transfers: Vec<_> = self.transfers.iter().collect();
        sorted_transfers.sort_by(|a, b| a.id.cmp(&b.id));
        for t in &sorted_transfers {
            entries.push(CanonicalValue::Map(BTreeMap::from([
                (
                    "transfer_id".to_string(),
                    CanonicalValue::String(t.id.clone()),
                ),
                (
                    "kind".to_string(),
                    CanonicalValue::String(t.kind.as_str().to_string()),
                ),
                (
                    "source".to_string(),
                    CanonicalValue::String(t.source_workload.clone()),
                ),
                (
                    "target".to_string(),
                    CanonicalValue::String(t.target_workload.clone()),
                ),
                (
                    "items".to_string(),
                    CanonicalValue::String(t.items_transferred.to_string()),
                ),
                (
                    "drift".to_string(),
                    CanonicalValue::String(t.drift_detected.to_string()),
                ),
                (
                    "rollback".to_string(),
                    CanonicalValue::String(t.rollback_triggered.to_string()),
                ),
            ])));
        }

        let canonical = CanonicalValue::Array(entries);
        let bytes = encode_value(&canonical);
        ContentHash::compute(&bytes)
    }

    pub fn drift_count(&self) -> usize {
        self.transfers.iter().filter(|t| t.drift_detected).count()
    }

    pub fn rollback_count(&self) -> usize {
        self.transfers
            .iter()
            .filter(|t| t.rollback_triggered)
            .count()
    }
}

impl Default for TransferManifest {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Seed builder
// ---------------------------------------------------------------------------

pub fn build_seed_manifest() -> TransferManifest {
    let mut manifest = TransferManifest::new();
    let workloads = [
        (
            "express_app",
            vec![
                (EmbeddingFeature::ModuleGraphSize, 500_000),
                (EmbeddingFeature::HostcallFrequency, 300_000),
                (EmbeddingFeature::AsyncAwaitDepth, 200_000),
            ],
        ),
        (
            "react_ssr",
            vec![
                (EmbeddingFeature::IrNodeCount, 800_000),
                (EmbeddingFeature::ObjectShapeCount, 600_000),
                (EmbeddingFeature::AllocationRate, 700_000),
            ],
        ),
        (
            "cli_tool",
            vec![
                (EmbeddingFeature::ModuleGraphSize, 100_000),
                (EmbeddingFeature::StringOperationRatio, 400_000),
                (EmbeddingFeature::HostcallFrequency, 200_000),
            ],
        ),
    ];
    for (id, dims) in &workloads {
        let mut emb = WorkloadEmbedding::new(id.to_string(), ContentHash::compute(id.as_bytes()));
        for (feat, val) in dims {
            emb.set_dimension(*feat, *val);
        }
        let _ = manifest.add_embedding(emb);
    }
    manifest
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManifoldError {
    EmbeddingOverflow { max: usize },
    DuplicateEmbedding { id: String },
}

impl fmt::Display for ManifoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmbeddingOverflow { max } => write!(f, "embedding overflow: max {max}"),
            Self::DuplicateEmbedding { id } => write!(f, "duplicate embedding: {id}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_embedding(id: &str, features: &[(EmbeddingFeature, i64)]) -> WorkloadEmbedding {
        let mut e = WorkloadEmbedding::new(id.to_string(), ContentHash::compute(id.as_bytes()));
        for (f, v) in features {
            e.set_dimension(*f, *v);
        }
        e
    }

    #[test]
    fn embedding_feature_count() {
        assert_eq!(EmbeddingFeature::ALL.len(), 16);
    }

    #[test]
    fn embedding_feature_serde() {
        for f in EmbeddingFeature::ALL {
            let json = serde_json::to_string(f).unwrap();
            let back: EmbeddingFeature = serde_json::from_str(&json).unwrap();
            assert_eq!(*f, back);
        }
    }

    #[test]
    fn embedding_get_set() {
        let mut e = WorkloadEmbedding::new("test".to_string(), ContentHash::compute(b"test"));
        e.set_dimension(EmbeddingFeature::IrNodeCount, 42_000);
        assert_eq!(e.get_dimension(&EmbeddingFeature::IrNodeCount), 42_000);
        assert_eq!(e.get_dimension(&EmbeddingFeature::AllocationRate), 0);
    }

    #[test]
    fn distance_zero_to_self() {
        let e = test_embedding("a", &[(EmbeddingFeature::IrNodeCount, 100)]);
        assert_eq!(e.distance_squared(&e), 0);
    }

    #[test]
    fn distance_nonzero() {
        let a = test_embedding("a", &[(EmbeddingFeature::IrNodeCount, 100)]);
        let b = test_embedding("b", &[(EmbeddingFeature::IrNodeCount, 200)]);
        assert!(a.distance_squared(&b) > 0);
    }

    #[test]
    fn cosine_similarity_identical() {
        let a = test_embedding(
            "a",
            &[
                (EmbeddingFeature::IrNodeCount, 100_000),
                (EmbeddingFeature::AllocationRate, 200_000),
            ],
        );
        let sim = a.cosine_similarity_millionths(&a);
        assert!(sim >= 990_000); // ~1.0
    }

    #[test]
    fn cosine_similarity_zero_vector() {
        let a = test_embedding("a", &[]);
        let b = test_embedding("b", &[(EmbeddingFeature::IrNodeCount, 100)]);
        assert_eq!(a.cosine_similarity_millionths(&b), 0);
    }

    #[test]
    fn isqrt_basic() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(100), 10);
        assert_eq!(isqrt(99), 9);
    }

    #[test]
    fn transfer_kind_serde() {
        for kind in [
            TransferKind::RewriteRules,
            TransferKind::TieringDecisions,
            TransferKind::CachePriors,
            TransferKind::InlineCandidates,
            TransferKind::AllocationHints,
            TransferKind::TypeProfileHints,
        ] {
            let json = serde_json::to_string(&kind).unwrap();
            let back: TransferKind = serde_json::from_str(&json).unwrap();
            assert_eq!(kind, back);
        }
    }

    #[test]
    fn manifest_add_embedding() {
        let mut m = TransferManifest::new();
        m.add_embedding(test_embedding("a", &[])).unwrap();
        assert_eq!(m.embeddings.len(), 1);
    }

    #[test]
    fn manifest_duplicate_rejected() {
        let mut m = TransferManifest::new();
        m.add_embedding(test_embedding("a", &[])).unwrap();
        let err = m.add_embedding(test_embedding("a", &[])).unwrap_err();
        assert!(matches!(err, ManifoldError::DuplicateEmbedding { .. }));
    }

    #[test]
    fn compute_certificate_same_workload() {
        let mut m = TransferManifest::new();
        m.add_embedding(test_embedding(
            "a",
            &[(EmbeddingFeature::IrNodeCount, 100_000)],
        ))
        .unwrap();
        let cert = m.compute_certificate("a", "a").unwrap();
        assert!(cert.is_neighbor);
    }

    #[test]
    fn compute_certificate_different_workloads() {
        let mut m = TransferManifest::new();
        m.add_embedding(test_embedding(
            "a",
            &[(EmbeddingFeature::IrNodeCount, 100_000)],
        ))
        .unwrap();
        m.add_embedding(test_embedding(
            "b",
            &[(EmbeddingFeature::IrNodeCount, 100_000)],
        ))
        .unwrap();
        let cert = m.compute_certificate("a", "b").unwrap();
        assert!(cert.is_neighbor);
    }

    #[test]
    fn compute_certificate_missing() {
        let m = TransferManifest::new();
        assert!(m.compute_certificate("a", "b").is_none());
    }

    #[test]
    fn content_hash_deterministic() {
        let m1 = build_seed_manifest();
        let m2 = build_seed_manifest();
        assert_eq!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn manifest_serde_roundtrip() {
        let m = build_seed_manifest();
        let json = serde_json::to_string(&m).unwrap();
        let back: TransferManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(m.embeddings.len(), back.embeddings.len());
        assert_eq!(m.content_hash(), back.content_hash());
    }

    #[test]
    fn seed_manifest_has_embeddings() {
        let m = build_seed_manifest();
        assert_eq!(m.embeddings.len(), 3);
    }

    #[test]
    fn drift_and_rollback_counts() {
        let mut m = TransferManifest::new();
        m.transfers.push(TransferRecord {
            id: "t1".to_string(),
            kind: TransferKind::RewriteRules,
            source_workload: "a".to_string(),
            target_workload: "b".to_string(),
            certificate_hash: ContentHash::compute(b"cert"),
            items_transferred: 10,
            drift_detected: true,
            rollback_triggered: false,
        });
        m.transfers.push(TransferRecord {
            id: "t2".to_string(),
            kind: TransferKind::CachePriors,
            source_workload: "a".to_string(),
            target_workload: "c".to_string(),
            certificate_hash: ContentHash::compute(b"cert2"),
            items_transferred: 5,
            drift_detected: true,
            rollback_triggered: true,
        });
        assert_eq!(m.drift_count(), 2);
        assert_eq!(m.rollback_count(), 1);
    }

    #[test]
    fn default_manifest_empty() {
        let m = TransferManifest::default();
        assert!(m.embeddings.is_empty());
    }

    #[test]
    fn error_display() {
        let e = ManifoldError::DuplicateEmbedding {
            id: "foo".to_string(),
        };
        assert!(format!("{e}").contains("foo"));
    }

    #[test]
    fn constants() {
        assert_eq!(COMPONENT, "workload_manifold_transfer");
        assert_eq!(BEAD_ID, "bd-1lsy.7.12");
    }
}
