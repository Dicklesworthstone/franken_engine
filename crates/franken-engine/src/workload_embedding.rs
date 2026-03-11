#![forbid(unsafe_code)]

//! Deterministic workload embeddings and neighborhood certificates from trace and IR evidence.
//!
//! Implements [RGC-612A]: extracts fixed-dimensional feature vectors from execution traces,
//! IR instruction distributions, and profiling signals, then issues neighborhood certificates
//! attesting that two workloads are semantically close enough for safe transfer of optimization
//! priors.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for workload embedding artifacts.
pub const EMBEDDING_SCHEMA_VERSION: &str = "franken-engine.workload-embedding.v1";

/// Maximum embedding dimensionality.
pub const MAX_EMBEDDING_DIM: usize = 128;

/// Minimum number of trace observations required before producing an embedding.
pub const MIN_OBSERVATIONS_FOR_EMBEDDING: u64 = 8;

/// Default neighborhood radius in millionths (5% = 50_000).
pub const DEFAULT_NEIGHBORHOOD_RADIUS: i64 = 50_000;

/// Cosine similarity threshold (millionths) above which two embeddings are
/// considered "near" for transfer purposes.  700_000 = 0.70.
pub const DEFAULT_COSINE_NEAR_THRESHOLD: i64 = 700_000;

/// Fixed-point unit: 1_000_000 = 1.0.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Feature extraction
// ---------------------------------------------------------------------------

/// Which family of features a component belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum FeatureFamily {
    /// Instruction-distribution features (opcode histogram).
    InstructionDistribution,
    /// Hot-path profile features (IP frequency, cache hit rates).
    HotPathProfile,
    /// Control-flow features (branch density, loop depth).
    ControlFlow,
    /// Memory-access features (allocation rate, GC pressure).
    MemoryAccess,
    /// Call-graph features (call depth, polymorphism degree).
    CallGraph,
    /// String/regexp features (average length, unicode ratio).
    StringPattern,
    /// Module-graph features (import depth, circular refs).
    ModuleGraph,
    /// Regime features (regime label distribution).
    RegimeDistribution,
}

impl fmt::Display for FeatureFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InstructionDistribution => write!(f, "instruction_distribution"),
            Self::HotPathProfile => write!(f, "hot_path_profile"),
            Self::ControlFlow => write!(f, "control_flow"),
            Self::MemoryAccess => write!(f, "memory_access"),
            Self::CallGraph => write!(f, "call_graph"),
            Self::StringPattern => write!(f, "string_pattern"),
            Self::ModuleGraph => write!(f, "module_graph"),
            Self::RegimeDistribution => write!(f, "regime_distribution"),
        }
    }
}

/// A single named feature component within an embedding vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureComponent {
    /// Unique key for this feature (e.g. "opcode.Add.ratio").
    pub key: String,
    /// Which family this feature belongs to.
    pub family: FeatureFamily,
    /// Value in fixed-point millionths.
    pub value_millionths: i64,
    /// Number of observations backing this value.
    pub observation_count: u64,
}

/// Configuration for the feature extraction pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeatureExtractionConfig {
    /// Schema version tag.
    pub schema_version: String,
    /// Maximum number of features to extract.
    pub max_features: usize,
    /// Minimum observation count per feature before it is included.
    pub min_observations: u64,
    /// Which families to include; if empty, all families are included.
    pub enabled_families: BTreeSet<FeatureFamily>,
    /// Whether to normalize feature values to [0, MILLION] range.
    pub normalize: bool,
}

impl Default for FeatureExtractionConfig {
    fn default() -> Self {
        Self {
            schema_version: EMBEDDING_SCHEMA_VERSION.to_string(),
            max_features: MAX_EMBEDDING_DIM,
            min_observations: MIN_OBSERVATIONS_FOR_EMBEDDING,
            enabled_families: BTreeSet::new(), // empty = all enabled
            normalize: true,
        }
    }
}

impl FeatureExtractionConfig {
    /// Returns true if the given family should be included.
    pub fn family_enabled(&self, family: FeatureFamily) -> bool {
        self.enabled_families.is_empty() || self.enabled_families.contains(&family)
    }

    /// Content hash of this config for audit trails.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = self.schema_version.as_bytes().to_vec();
        buf.extend_from_slice(&(self.max_features as u64).to_le_bytes());
        buf.extend_from_slice(&self.min_observations.to_le_bytes());
        buf.push(if self.normalize { 1 } else { 0 });
        for fam in &self.enabled_families {
            buf.extend_from_slice(fam.to_string().as_bytes());
        }
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// Embedding vector
// ---------------------------------------------------------------------------

/// Validity status for an embedding vector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EmbeddingValidity {
    /// All requirements met; embedding is trustworthy.
    Valid,
    /// Too few observations; embedding may be noisy.
    InsufficientObservations,
    /// Dimensionality exceeds maximum.
    DimensionOverflow,
    /// No features extracted.
    Empty,
}

impl fmt::Display for EmbeddingValidity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Valid => write!(f, "valid"),
            Self::InsufficientObservations => write!(f, "insufficient_observations"),
            Self::DimensionOverflow => write!(f, "dimension_overflow"),
            Self::Empty => write!(f, "empty"),
        }
    }
}

/// A deterministic workload embedding: a fixed-dimensional feature vector
/// computed from execution traces and IR evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadEmbedding {
    /// Schema version.
    pub schema_version: String,
    /// Unique identifier for this embedding.
    pub embedding_id: String,
    /// Trace ID this embedding was derived from.
    pub source_trace_id: String,
    /// Security epoch at extraction time.
    pub epoch: SecurityEpoch,
    /// Feature components in deterministic order (sorted by key).
    pub components: Vec<FeatureComponent>,
    /// Total observations across all components.
    pub total_observations: u64,
    /// Dimensionality of the embedding vector.
    pub dimension: usize,
    /// Validity assessment.
    pub validity: EmbeddingValidity,
    /// Content hash for deduplication and audit.
    pub content_hash: ContentHash,
    /// Config hash used during extraction.
    pub config_hash: ContentHash,
}

impl WorkloadEmbedding {
    /// Extract the raw value vector (millionths) in component order.
    pub fn value_vector(&self) -> Vec<i64> {
        self.components.iter().map(|c| c.value_millionths).collect()
    }

    /// Extract keys in component order.
    pub fn keys(&self) -> Vec<&str> {
        self.components.iter().map(|c| c.key.as_str()).collect()
    }

    /// Look up a component by key.
    pub fn get_component(&self, key: &str) -> Option<&FeatureComponent> {
        self.components.iter().find(|c| c.key == key)
    }

    /// Returns the value for a key, or None.
    pub fn value_for(&self, key: &str) -> Option<i64> {
        self.get_component(key).map(|c| c.value_millionths)
    }

    /// Number of features from a specific family.
    pub fn family_count(&self, family: FeatureFamily) -> usize {
        self.components
            .iter()
            .filter(|c| c.family == family)
            .count()
    }

    /// True if the embedding is usable for distance calculations.
    pub fn is_valid(&self) -> bool {
        self.validity == EmbeddingValidity::Valid
    }

    /// The L2 squared norm of the value vector (in millionths²).
    pub fn squared_norm(&self) -> i64 {
        self.components
            .iter()
            .map(|c| {
                c.value_millionths
                    .checked_mul(c.value_millionths)
                    .unwrap_or(i64::MAX)
            })
            .fold(0i64, |acc, v| acc.saturating_add(v))
    }
}

// ---------------------------------------------------------------------------
// Embedding builder
// ---------------------------------------------------------------------------

/// Builds a `WorkloadEmbedding` from raw feature components.
#[derive(Debug, Clone)]
pub struct EmbeddingBuilder {
    config: FeatureExtractionConfig,
    trace_id: String,
    epoch: SecurityEpoch,
    components: BTreeMap<String, FeatureComponent>,
}

impl EmbeddingBuilder {
    /// Create a new builder for the given trace.
    pub fn new(config: FeatureExtractionConfig, trace_id: String, epoch: SecurityEpoch) -> Self {
        Self {
            config,
            trace_id,
            epoch,
            components: BTreeMap::new(),
        }
    }

    /// Add a feature component. Replaces any existing component with the same key.
    pub fn add_component(&mut self, component: FeatureComponent) {
        if self.config.family_enabled(component.family) {
            self.components.insert(component.key.clone(), component);
        }
    }

    /// Add a feature by parts.
    pub fn add_feature(
        &mut self,
        key: &str,
        family: FeatureFamily,
        value_millionths: i64,
        observation_count: u64,
    ) {
        self.add_component(FeatureComponent {
            key: key.to_string(),
            family,
            value_millionths,
            observation_count,
        });
    }

    /// How many components are currently staged.
    pub fn component_count(&self) -> usize {
        self.components.len()
    }

    /// Finalize into a `WorkloadEmbedding`.
    pub fn build(self) -> WorkloadEmbedding {
        let config_hash = self.config.content_hash();

        // Filter by min observations and take up to max_features.
        let mut filtered: Vec<FeatureComponent> = self
            .components
            .into_values()
            .filter(|c| c.observation_count >= self.config.min_observations)
            .collect();

        // BTreeMap iteration is already sorted by key, but after filtering
        // we re-sort to be explicit about determinism.
        filtered.sort_by(|a, b| a.key.cmp(&b.key));

        if filtered.len() > self.config.max_features {
            filtered.truncate(self.config.max_features);
        }

        // Normalize if requested.
        if self.config.normalize && !filtered.is_empty() {
            let (min_val, max_val) = filtered.iter().fold((i64::MAX, i64::MIN), |(lo, hi), c| {
                (lo.min(c.value_millionths), hi.max(c.value_millionths))
            });
            let range = max_val.saturating_sub(min_val);
            if range > 0 {
                for comp in &mut filtered {
                    // Map [min, max] → [0, MILLION]
                    let shifted = comp.value_millionths.saturating_sub(min_val);
                    comp.value_millionths = shifted
                        .checked_mul(MILLION)
                        .map(|n| n / range)
                        .unwrap_or(MILLION);
                }
            }
        }

        let total_observations: u64 = filtered.iter().map(|c| c.observation_count).sum();
        let dimension = filtered.len();

        // Determine validity.
        let validity = if filtered.is_empty() {
            EmbeddingValidity::Empty
        } else if dimension > MAX_EMBEDDING_DIM {
            EmbeddingValidity::DimensionOverflow
        } else if total_observations < MIN_OBSERVATIONS_FOR_EMBEDDING {
            EmbeddingValidity::InsufficientObservations
        } else {
            EmbeddingValidity::Valid
        };

        // Content hash over all components.
        let mut hash_buf = Vec::new();
        hash_buf.extend_from_slice(EMBEDDING_SCHEMA_VERSION.as_bytes());
        hash_buf.extend_from_slice(self.trace_id.as_bytes());
        for comp in &filtered {
            hash_buf.extend_from_slice(comp.key.as_bytes());
            hash_buf.extend_from_slice(&comp.value_millionths.to_le_bytes());
            hash_buf.extend_from_slice(&comp.observation_count.to_le_bytes());
        }
        let content_hash = ContentHash::compute(&hash_buf);

        let embedding_id = format!("emb-{}-{}", &self.trace_id, &content_hash.to_hex()[..12]);

        WorkloadEmbedding {
            schema_version: EMBEDDING_SCHEMA_VERSION.to_string(),
            embedding_id,
            source_trace_id: self.trace_id,
            epoch: self.epoch,
            components: filtered,
            total_observations,
            dimension,
            validity,
            content_hash,
            config_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// Distance metrics
// ---------------------------------------------------------------------------

/// Which distance metric to use for embedding comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum DistanceMetric {
    /// L1 (Manhattan) distance.
    Manhattan,
    /// L2² (squared Euclidean) distance.
    SquaredEuclidean,
    /// L∞ (Chebyshev) distance — conservative for cliff detection.
    Chebyshev,
    /// 1 - cosine_similarity, scaled to millionths.
    Cosine,
}

impl fmt::Display for DistanceMetric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Manhattan => write!(f, "manhattan"),
            Self::SquaredEuclidean => write!(f, "squared_euclidean"),
            Self::Chebyshev => write!(f, "chebyshev"),
            Self::Cosine => write!(f, "cosine"),
        }
    }
}

/// Result of a distance computation between two embeddings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DistanceResult {
    /// Which metric was used.
    pub metric: DistanceMetric,
    /// Distance value in millionths (for cosine: 1M = maximally distant, 0 = identical).
    pub distance_millionths: i64,
    /// Number of shared dimensions used in the calculation.
    pub shared_dimensions: usize,
    /// Number of dimensions present in A but not B.
    pub missing_in_b: usize,
    /// Number of dimensions present in B but not A.
    pub missing_in_a: usize,
}

/// Compute distance between two embeddings on their shared feature keys.
pub fn compute_distance(
    a: &WorkloadEmbedding,
    b: &WorkloadEmbedding,
    metric: DistanceMetric,
) -> DistanceResult {
    let keys_a: BTreeSet<&str> = a.components.iter().map(|c| c.key.as_str()).collect();
    let keys_b: BTreeSet<&str> = b.components.iter().map(|c| c.key.as_str()).collect();

    let shared: BTreeSet<&&str> = keys_a.intersection(&keys_b).collect();
    let shared_dimensions = shared.len();
    let missing_in_b = keys_a.difference(&keys_b).count();
    let missing_in_a = keys_b.difference(&keys_a).count();

    let distance_millionths = match metric {
        DistanceMetric::Manhattan => {
            let mut sum: i64 = 0;
            for key in &shared {
                let va = a.value_for(key).unwrap_or(0);
                let vb = b.value_for(key).unwrap_or(0);
                sum = sum.saturating_add(va.saturating_sub(vb).abs());
            }
            sum
        }
        DistanceMetric::SquaredEuclidean => {
            let mut sum: i64 = 0;
            for key in &shared {
                let va = a.value_for(key).unwrap_or(0);
                let vb = b.value_for(key).unwrap_or(0);
                let diff = va.saturating_sub(vb);
                sum = sum.saturating_add(diff.checked_mul(diff).unwrap_or(i64::MAX));
            }
            sum
        }
        DistanceMetric::Chebyshev => {
            let mut max_diff: i64 = 0;
            for key in &shared {
                let va = a.value_for(key).unwrap_or(0);
                let vb = b.value_for(key).unwrap_or(0);
                max_diff = max_diff.max(va.saturating_sub(vb).abs());
            }
            max_diff
        }
        DistanceMetric::Cosine => {
            // cosine_distance = 1 - cosine_similarity
            // cosine_similarity = dot(a,b) / (|a| * |b|)
            let mut dot: i128 = 0;
            let mut norm_a: i128 = 0;
            let mut norm_b: i128 = 0;
            for key in &shared {
                let va = a.value_for(key).unwrap_or(0) as i128;
                let vb = b.value_for(key).unwrap_or(0) as i128;
                dot += va * vb;
                norm_a += va * va;
                norm_b += vb * vb;
            }
            if norm_a == 0 || norm_b == 0 {
                MILLION // maximally distant if either is zero
            } else {
                // similarity = dot / sqrt(norm_a * norm_b) in [−1, 1]
                // We approximate using integer sqrt.
                let denom_sq = norm_a * norm_b;
                let denom = isqrt_i128(denom_sq);
                if denom == 0 {
                    MILLION
                } else {
                    let similarity = (dot * (MILLION as i128)) / denom;
                    let similarity_clamped = similarity.clamp(-(MILLION as i128), MILLION as i128);
                    // distance = MILLION - similarity
                    (MILLION as i128 - similarity_clamped) as i64
                }
            }
        }
    };

    DistanceResult {
        metric,
        distance_millionths,
        shared_dimensions,
        missing_in_b,
        missing_in_a,
    }
}

/// Integer square root for i128 (Babylonian method).
fn isqrt_i128(n: i128) -> i128 {
    if n <= 0 {
        return 0;
    }
    if n == 1 {
        return 1;
    }
    let mut x = n;
    #[allow(clippy::manual_div_ceil)]
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

// ---------------------------------------------------------------------------
// Neighborhood certificate
// ---------------------------------------------------------------------------

/// Why a neighborhood certificate was issued or denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CertificateVerdict {
    /// Embeddings are near enough; transfer is safe.
    Near,
    /// Embeddings are in a marginal zone; transfer carries risk.
    Marginal,
    /// Embeddings are too far apart; transfer is unsafe.
    Distant,
    /// Cannot determine (insufficient data or invalid embeddings).
    Abstained,
}

impl fmt::Display for CertificateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Near => write!(f, "near"),
            Self::Marginal => write!(f, "marginal"),
            Self::Distant => write!(f, "distant"),
            Self::Abstained => write!(f, "abstained"),
        }
    }
}

/// A reason the certificate abstained instead of issuing a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AbstentionReason {
    /// One or both embeddings are invalid.
    InvalidEmbedding,
    /// No shared dimensions between the embeddings.
    NoSharedDimensions,
    /// Too few shared dimensions for a meaningful comparison.
    InsufficientSharedDimensions,
    /// Embedding epoch mismatch beyond tolerance.
    EpochMismatch,
}

impl fmt::Display for AbstentionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEmbedding => write!(f, "invalid_embedding"),
            Self::NoSharedDimensions => write!(f, "no_shared_dimensions"),
            Self::InsufficientSharedDimensions => write!(f, "insufficient_shared_dimensions"),
            Self::EpochMismatch => write!(f, "epoch_mismatch"),
        }
    }
}

/// Configuration for neighborhood certificate issuance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborhoodCertificateConfig {
    /// Distance metric to use.
    pub metric: DistanceMetric,
    /// Threshold below which the verdict is Near (millionths).
    pub near_threshold_millionths: i64,
    /// Threshold below which the verdict is Marginal (above Near, below this).
    pub marginal_threshold_millionths: i64,
    /// Minimum shared dimensions required (below this: abstain).
    pub min_shared_dimensions: usize,
    /// Maximum epoch gap tolerated (0 = same epoch required).
    pub max_epoch_gap: u64,
}

impl Default for NeighborhoodCertificateConfig {
    fn default() -> Self {
        Self {
            metric: DistanceMetric::Chebyshev,
            near_threshold_millionths: DEFAULT_NEIGHBORHOOD_RADIUS,
            marginal_threshold_millionths: DEFAULT_NEIGHBORHOOD_RADIUS * 2,
            min_shared_dimensions: 3,
            max_epoch_gap: 5,
        }
    }
}

/// A neighborhood certificate attesting the semantic proximity of two workloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborhoodCertificate {
    /// Schema version.
    pub schema_version: String,
    /// Certificate ID.
    pub certificate_id: String,
    /// Embedding ID of the source workload.
    pub source_embedding_id: String,
    /// Embedding ID of the target workload.
    pub target_embedding_id: String,
    /// Distance result.
    pub distance: DistanceResult,
    /// Verdict.
    pub verdict: CertificateVerdict,
    /// If abstained, why.
    pub abstention_reason: Option<AbstentionReason>,
    /// Epoch at certificate issuance.
    pub epoch: SecurityEpoch,
    /// Content hash for audit.
    pub content_hash: ContentHash,
}

impl NeighborhoodCertificate {
    /// True if transfer is safe.
    pub fn is_near(&self) -> bool {
        self.verdict == CertificateVerdict::Near
    }

    /// True if the certificate abstained.
    pub fn is_abstained(&self) -> bool {
        self.verdict == CertificateVerdict::Abstained
    }

    /// True if transfer should be blocked.
    pub fn is_distant(&self) -> bool {
        self.verdict == CertificateVerdict::Distant
    }
}

/// Issue a neighborhood certificate for two workload embeddings.
pub fn issue_neighborhood_certificate(
    source: &WorkloadEmbedding,
    target: &WorkloadEmbedding,
    config: &NeighborhoodCertificateConfig,
    epoch: SecurityEpoch,
) -> NeighborhoodCertificate {
    // Check abstention conditions.
    let abstention = if !source.is_valid() || !target.is_valid() {
        Some(AbstentionReason::InvalidEmbedding)
    } else {
        let epoch_gap = source.epoch.as_u64().abs_diff(target.epoch.as_u64());
        if epoch_gap > config.max_epoch_gap {
            Some(AbstentionReason::EpochMismatch)
        } else {
            None
        }
    };

    if let Some(reason) = abstention {
        let cert_hash = compute_cert_hash(source, target, &reason.to_string());
        let cert_id = format!("ncert-abstained-{}", &cert_hash.to_hex()[..12]);
        return NeighborhoodCertificate {
            schema_version: EMBEDDING_SCHEMA_VERSION.to_string(),
            certificate_id: cert_id,
            source_embedding_id: source.embedding_id.clone(),
            target_embedding_id: target.embedding_id.clone(),
            distance: DistanceResult {
                metric: config.metric,
                distance_millionths: 0,
                shared_dimensions: 0,
                missing_in_b: 0,
                missing_in_a: 0,
            },
            verdict: CertificateVerdict::Abstained,
            abstention_reason: Some(reason),
            epoch,
            content_hash: cert_hash,
        };
    }

    let distance = compute_distance(source, target, config.metric);

    // Check shared dimension threshold.
    if distance.shared_dimensions == 0 {
        let cert_hash = compute_cert_hash(source, target, "no_shared");
        let cert_id = format!("ncert-abstained-{}", &cert_hash.to_hex()[..12]);
        return NeighborhoodCertificate {
            schema_version: EMBEDDING_SCHEMA_VERSION.to_string(),
            certificate_id: cert_id,
            source_embedding_id: source.embedding_id.clone(),
            target_embedding_id: target.embedding_id.clone(),
            distance,
            verdict: CertificateVerdict::Abstained,
            abstention_reason: Some(AbstentionReason::NoSharedDimensions),
            epoch,
            content_hash: cert_hash,
        };
    }

    if distance.shared_dimensions < config.min_shared_dimensions {
        let cert_hash = compute_cert_hash(source, target, "insufficient_shared");
        let cert_id = format!("ncert-abstained-{}", &cert_hash.to_hex()[..12]);
        return NeighborhoodCertificate {
            schema_version: EMBEDDING_SCHEMA_VERSION.to_string(),
            certificate_id: cert_id,
            source_embedding_id: source.embedding_id.clone(),
            target_embedding_id: target.embedding_id.clone(),
            distance,
            verdict: CertificateVerdict::Abstained,
            abstention_reason: Some(AbstentionReason::InsufficientSharedDimensions),
            epoch,
            content_hash: cert_hash,
        };
    }

    // Compute verdict.
    let verdict = if distance.distance_millionths <= config.near_threshold_millionths {
        CertificateVerdict::Near
    } else if distance.distance_millionths <= config.marginal_threshold_millionths {
        CertificateVerdict::Marginal
    } else {
        CertificateVerdict::Distant
    };

    let cert_hash = compute_cert_hash(source, target, &verdict.to_string());
    let cert_id = format!("ncert-{}-{}", verdict, &cert_hash.to_hex()[..12]);

    NeighborhoodCertificate {
        schema_version: EMBEDDING_SCHEMA_VERSION.to_string(),
        certificate_id: cert_id,
        source_embedding_id: source.embedding_id.clone(),
        target_embedding_id: target.embedding_id.clone(),
        distance,
        verdict,
        abstention_reason: None,
        epoch,
        content_hash: cert_hash,
    }
}

fn compute_cert_hash(
    source: &WorkloadEmbedding,
    target: &WorkloadEmbedding,
    tag: &str,
) -> ContentHash {
    let mut buf = Vec::new();
    buf.extend_from_slice(EMBEDDING_SCHEMA_VERSION.as_bytes());
    buf.extend_from_slice(source.content_hash.as_bytes());
    buf.extend_from_slice(target.content_hash.as_bytes());
    buf.extend_from_slice(tag.as_bytes());
    ContentHash::compute(&buf)
}

// ---------------------------------------------------------------------------
// Embedding catalog
// ---------------------------------------------------------------------------

/// A catalog of workload embeddings with nearest-neighbor query support.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbeddingCatalog {
    /// Schema version.
    pub schema_version: String,
    /// All embeddings indexed by embedding_id.
    pub entries: Vec<CatalogEntry>,
    /// Epoch at catalog construction.
    pub epoch: SecurityEpoch,
}

/// A single entry in the catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEntry {
    /// The embedding.
    pub embedding: WorkloadEmbedding,
    /// Optional user-provided label for this workload.
    pub label: Option<String>,
    /// Tags for filtering.
    pub tags: BTreeSet<String>,
}

impl EmbeddingCatalog {
    /// Create a new empty catalog.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            schema_version: EMBEDDING_SCHEMA_VERSION.to_string(),
            entries: Vec::new(),
            epoch,
        }
    }

    /// Add an embedding to the catalog.
    pub fn insert(
        &mut self,
        embedding: WorkloadEmbedding,
        label: Option<String>,
        tags: BTreeSet<String>,
    ) {
        self.entries.push(CatalogEntry {
            embedding,
            label,
            tags,
        });
    }

    /// Number of embeddings in the catalog.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if the catalog is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Find the k nearest neighbors of a query embedding.
    pub fn k_nearest(
        &self,
        query: &WorkloadEmbedding,
        k: usize,
        metric: DistanceMetric,
    ) -> Vec<NeighborResult> {
        let mut results: Vec<NeighborResult> = self
            .entries
            .iter()
            .filter(|e| e.embedding.is_valid() && e.embedding.embedding_id != query.embedding_id)
            .map(|e| {
                let distance = compute_distance(query, &e.embedding, metric);
                NeighborResult {
                    embedding_id: e.embedding.embedding_id.clone(),
                    label: e.label.clone(),
                    distance,
                }
            })
            .collect();

        results.sort_by_key(|r| r.distance.distance_millionths);
        results.truncate(k);
        results
    }

    /// Find all embeddings within the given radius.
    pub fn within_radius(
        &self,
        query: &WorkloadEmbedding,
        radius_millionths: i64,
        metric: DistanceMetric,
    ) -> Vec<NeighborResult> {
        self.entries
            .iter()
            .filter(|e| e.embedding.is_valid() && e.embedding.embedding_id != query.embedding_id)
            .filter_map(|e| {
                let distance = compute_distance(query, &e.embedding, metric);
                if distance.distance_millionths <= radius_millionths {
                    Some(NeighborResult {
                        embedding_id: e.embedding.embedding_id.clone(),
                        label: e.label.clone(),
                        distance,
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    /// Compute catalog summary statistics.
    pub fn summary(&self) -> CatalogSummary {
        let valid_count = self
            .entries
            .iter()
            .filter(|e| e.embedding.is_valid())
            .count();
        let invalid_count = self.entries.len() - valid_count;
        let family_counts = {
            let mut counts: BTreeMap<String, usize> = BTreeMap::new();
            for entry in &self.entries {
                for comp in &entry.embedding.components {
                    *counts.entry(comp.family.to_string()).or_insert(0) += 1;
                }
            }
            counts
        };
        let total_dimensions: usize = self.entries.iter().map(|e| e.embedding.dimension).sum();
        let avg_dimension = if self.entries.is_empty() {
            0
        } else {
            total_dimensions / self.entries.len()
        };

        CatalogSummary {
            total_entries: self.entries.len(),
            valid_count,
            invalid_count,
            avg_dimension,
            family_feature_counts: family_counts,
        }
    }
}

/// Result from a nearest-neighbor query.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborResult {
    /// ID of the neighbor embedding.
    pub embedding_id: String,
    /// Optional label.
    pub label: Option<String>,
    /// Distance from the query.
    pub distance: DistanceResult,
}

/// Summary statistics for an embedding catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogSummary {
    /// Total number of entries.
    pub total_entries: usize,
    /// Number of valid embeddings.
    pub valid_count: usize,
    /// Number of invalid embeddings.
    pub invalid_count: usize,
    /// Average dimensionality across all embeddings.
    pub avg_dimension: usize,
    /// Count of features per family across all embeddings.
    pub family_feature_counts: BTreeMap<String, usize>,
}

// ---------------------------------------------------------------------------
// Transfer safety assessment
// ---------------------------------------------------------------------------

/// Assessment of whether optimization priors can safely transfer between workloads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferSafetyAssessment {
    /// Schema version.
    pub schema_version: String,
    /// Source workload embedding ID.
    pub source_id: String,
    /// Target workload embedding ID.
    pub target_id: String,
    /// Neighborhood certificate.
    pub certificate: NeighborhoodCertificate,
    /// Which optimization families are safe to transfer.
    pub safe_families: BTreeSet<String>,
    /// Which optimization families should be blocked.
    pub blocked_families: BTreeSet<String>,
    /// Per-family distance contributions.
    pub family_distances: BTreeMap<String, i64>,
    /// Overall recommendation.
    pub recommendation: TransferRecommendation,
    /// Content hash.
    pub content_hash: ContentHash,
}

/// Overall transfer recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TransferRecommendation {
    /// Safe to transfer all applicable priors.
    TransferAll,
    /// Transfer only priors in safe_families.
    TransferSelective,
    /// Do not transfer; workloads are too different.
    BlockTransfer,
    /// Cannot assess; abstained.
    CannotAssess,
}

impl fmt::Display for TransferRecommendation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransferAll => write!(f, "transfer_all"),
            Self::TransferSelective => write!(f, "transfer_selective"),
            Self::BlockTransfer => write!(f, "block_transfer"),
            Self::CannotAssess => write!(f, "cannot_assess"),
        }
    }
}

/// Assess transfer safety between two workload embeddings.
pub fn assess_transfer_safety(
    source: &WorkloadEmbedding,
    target: &WorkloadEmbedding,
    cert_config: &NeighborhoodCertificateConfig,
    epoch: SecurityEpoch,
) -> TransferSafetyAssessment {
    let certificate = issue_neighborhood_certificate(source, target, cert_config, epoch);

    // Per-family distance: compute distance using only features from each family.
    let all_families: BTreeSet<FeatureFamily> = source
        .components
        .iter()
        .chain(target.components.iter())
        .map(|c| c.family)
        .collect();

    let mut family_distances: BTreeMap<String, i64> = BTreeMap::new();
    let mut safe_families: BTreeSet<String> = BTreeSet::new();
    let mut blocked_families: BTreeSet<String> = BTreeSet::new();

    for family in &all_families {
        let family_key = family.to_string();
        // Compute per-family max absolute difference.
        let mut max_diff: i64 = 0;
        let source_comps: BTreeMap<&str, i64> = source
            .components
            .iter()
            .filter(|c| c.family == *family)
            .map(|c| (c.key.as_str(), c.value_millionths))
            .collect();
        let target_comps: BTreeMap<&str, i64> = target
            .components
            .iter()
            .filter(|c| c.family == *family)
            .map(|c| (c.key.as_str(), c.value_millionths))
            .collect();

        for (k, sv) in &source_comps {
            if let Some(tv) = target_comps.get(k) {
                max_diff = max_diff.max(sv.saturating_sub(*tv).abs());
            } else {
                max_diff = max_diff.max(sv.abs());
            }
        }
        for (k, tv) in &target_comps {
            if !source_comps.contains_key(k) {
                max_diff = max_diff.max(tv.abs());
            }
        }

        family_distances.insert(family_key.clone(), max_diff);

        if max_diff <= cert_config.near_threshold_millionths {
            safe_families.insert(family_key);
        } else {
            blocked_families.insert(family_key);
        }
    }

    let recommendation = if certificate.is_abstained() {
        TransferRecommendation::CannotAssess
    } else if certificate.is_near() && blocked_families.is_empty() {
        TransferRecommendation::TransferAll
    } else if certificate.is_distant() || safe_families.is_empty() {
        TransferRecommendation::BlockTransfer
    } else {
        TransferRecommendation::TransferSelective
    };

    let mut hash_buf = Vec::new();
    hash_buf.extend_from_slice(EMBEDDING_SCHEMA_VERSION.as_bytes());
    hash_buf.extend_from_slice(certificate.content_hash.as_bytes());
    hash_buf.extend_from_slice(recommendation.to_string().as_bytes());
    let content_hash = ContentHash::compute(&hash_buf);

    TransferSafetyAssessment {
        schema_version: EMBEDDING_SCHEMA_VERSION.to_string(),
        source_id: source.embedding_id.clone(),
        target_id: target.embedding_id.clone(),
        certificate,
        safe_families,
        blocked_families,
        family_distances,
        recommendation,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Evidence harness
// ---------------------------------------------------------------------------

/// Specimen family for embedding evidence corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EmbeddingSpecimenFamily {
    /// Simple compute-bound workload.
    ComputeBound,
    /// Memory-intensive workload.
    MemoryIntensive,
    /// IO-heavy workload.
    IoHeavy,
    /// Mixed workload.
    Mixed,
    /// Minimal/trivial workload.
    Trivial,
    /// Adversarial edge case.
    Adversarial,
}

impl fmt::Display for EmbeddingSpecimenFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ComputeBound => write!(f, "compute_bound"),
            Self::MemoryIntensive => write!(f, "memory_intensive"),
            Self::IoHeavy => write!(f, "io_heavy"),
            Self::Mixed => write!(f, "mixed"),
            Self::Trivial => write!(f, "trivial"),
            Self::Adversarial => write!(f, "adversarial"),
        }
    }
}

/// A specimen in the evidence corpus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingSpecimen {
    /// Specimen ID.
    pub id: String,
    /// Family classification.
    pub family: EmbeddingSpecimenFamily,
    /// Human-readable description.
    pub description: String,
    /// The embedding.
    pub embedding: WorkloadEmbedding,
}

/// Build the standard evidence corpus.
pub fn build_evidence_corpus(epoch: SecurityEpoch) -> Vec<EmbeddingSpecimen> {
    let config = FeatureExtractionConfig::default();

    let mut specimens = Vec::new();

    // Compute-bound specimen
    {
        let mut builder = EmbeddingBuilder::new(config.clone(), "trace-compute-01".into(), epoch);
        builder.add_feature(
            "opcode.Add.ratio",
            FeatureFamily::InstructionDistribution,
            300_000,
            100,
        );
        builder.add_feature(
            "opcode.Mul.ratio",
            FeatureFamily::InstructionDistribution,
            250_000,
            100,
        );
        builder.add_feature(
            "opcode.Load.ratio",
            FeatureFamily::InstructionDistribution,
            150_000,
            100,
        );
        builder.add_feature("branch_density", FeatureFamily::ControlFlow, 80_000, 50);
        builder.add_feature("loop_depth_avg", FeatureFamily::ControlFlow, 3_000_000, 50);
        builder.add_feature("alloc_rate", FeatureFamily::MemoryAccess, 20_000, 50);
        builder.add_feature("gc_pressure", FeatureFamily::MemoryAccess, 10_000, 50);
        specimens.push(EmbeddingSpecimen {
            id: "specimen-compute-01".into(),
            family: EmbeddingSpecimenFamily::ComputeBound,
            description: "Arithmetic-heavy compute loop".into(),
            embedding: builder.build(),
        });
    }

    // Memory-intensive specimen
    {
        let mut builder = EmbeddingBuilder::new(config.clone(), "trace-memory-01".into(), epoch);
        builder.add_feature(
            "opcode.Add.ratio",
            FeatureFamily::InstructionDistribution,
            50_000,
            100,
        );
        builder.add_feature(
            "opcode.Load.ratio",
            FeatureFamily::InstructionDistribution,
            400_000,
            100,
        );
        builder.add_feature(
            "opcode.Store.ratio",
            FeatureFamily::InstructionDistribution,
            350_000,
            100,
        );
        builder.add_feature("branch_density", FeatureFamily::ControlFlow, 120_000, 50);
        builder.add_feature("alloc_rate", FeatureFamily::MemoryAccess, 800_000, 80);
        builder.add_feature("gc_pressure", FeatureFamily::MemoryAccess, 600_000, 80);
        specimens.push(EmbeddingSpecimen {
            id: "specimen-memory-01".into(),
            family: EmbeddingSpecimenFamily::MemoryIntensive,
            description: "Object allocation and traversal heavy workload".into(),
            embedding: builder.build(),
        });
    }

    // IO-heavy specimen
    {
        let mut builder = EmbeddingBuilder::new(config.clone(), "trace-io-01".into(), epoch);
        builder.add_feature(
            "opcode.Call.ratio",
            FeatureFamily::InstructionDistribution,
            400_000,
            100,
        );
        builder.add_feature("hostcall_rate", FeatureFamily::CallGraph, 700_000, 90);
        builder.add_feature("call_depth_max", FeatureFamily::CallGraph, 5_000_000, 90);
        builder.add_feature(
            "module_import_depth",
            FeatureFamily::ModuleGraph,
            4_000_000,
            60,
        );
        builder.add_feature("alloc_rate", FeatureFamily::MemoryAccess, 200_000, 50);
        specimens.push(EmbeddingSpecimen {
            id: "specimen-io-01".into(),
            family: EmbeddingSpecimenFamily::IoHeavy,
            description: "Hostcall and module-import heavy server workload".into(),
            embedding: builder.build(),
        });
    }

    // Mixed specimen
    {
        let mut builder = EmbeddingBuilder::new(config.clone(), "trace-mixed-01".into(), epoch);
        builder.add_feature(
            "opcode.Add.ratio",
            FeatureFamily::InstructionDistribution,
            200_000,
            100,
        );
        builder.add_feature(
            "opcode.Load.ratio",
            FeatureFamily::InstructionDistribution,
            200_000,
            100,
        );
        builder.add_feature(
            "opcode.Call.ratio",
            FeatureFamily::InstructionDistribution,
            200_000,
            100,
        );
        builder.add_feature("branch_density", FeatureFamily::ControlFlow, 150_000, 60);
        builder.add_feature("alloc_rate", FeatureFamily::MemoryAccess, 300_000, 60);
        builder.add_feature("hostcall_rate", FeatureFamily::CallGraph, 250_000, 60);
        builder.add_feature("string_avg_len", FeatureFamily::StringPattern, 150_000, 40);
        specimens.push(EmbeddingSpecimen {
            id: "specimen-mixed-01".into(),
            family: EmbeddingSpecimenFamily::Mixed,
            description: "Balanced web-app workload with mixed features".into(),
            embedding: builder.build(),
        });
    }

    // Trivial specimen
    {
        let mut builder = EmbeddingBuilder::new(config.clone(), "trace-trivial-01".into(), epoch);
        builder.add_feature(
            "opcode.Add.ratio",
            FeatureFamily::InstructionDistribution,
            500_000,
            10,
        );
        builder.add_feature(
            "opcode.Return.ratio",
            FeatureFamily::InstructionDistribution,
            500_000,
            10,
        );
        specimens.push(EmbeddingSpecimen {
            id: "specimen-trivial-01".into(),
            family: EmbeddingSpecimenFamily::Trivial,
            description: "Single function returning sum of two constants".into(),
            embedding: builder.build(),
        });
    }

    // Adversarial specimen — all zero features
    {
        let mut builder = EmbeddingBuilder::new(config, "trace-adversarial-01".into(), epoch);
        builder.add_feature(
            "opcode.Nop.ratio",
            FeatureFamily::InstructionDistribution,
            0,
            100,
        );
        builder.add_feature("alloc_rate", FeatureFamily::MemoryAccess, 0, 100);
        builder.add_feature("gc_pressure", FeatureFamily::MemoryAccess, 0, 100);
        specimens.push(EmbeddingSpecimen {
            id: "specimen-adversarial-01".into(),
            family: EmbeddingSpecimenFamily::Adversarial,
            description: "All-zero feature embedding for edge-case testing".into(),
            embedding: builder.build(),
        });
    }

    specimens
}

/// Run the evidence corpus and return a deterministic manifest hash.
pub fn run_embedding_corpus(epoch: SecurityEpoch) -> (Vec<EmbeddingSpecimen>, ContentHash) {
    let specimens = build_evidence_corpus(epoch);
    let mut hash_buf = Vec::new();
    hash_buf.extend_from_slice(EMBEDDING_SCHEMA_VERSION.as_bytes());
    for s in &specimens {
        hash_buf.extend_from_slice(s.id.as_bytes());
        hash_buf.extend_from_slice(s.embedding.content_hash.as_bytes());
    }
    let manifest_hash = ContentHash::compute(&hash_buf);
    (specimens, manifest_hash)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn default_config() -> FeatureExtractionConfig {
        FeatureExtractionConfig::default()
    }

    fn make_embedding(
        trace_id: &str,
        features: &[(&str, FeatureFamily, i64, u64)],
    ) -> WorkloadEmbedding {
        let mut builder = EmbeddingBuilder::new(default_config(), trace_id.into(), test_epoch());
        for (key, family, val, obs) in features {
            builder.add_feature(key, *family, *val, *obs);
        }
        builder.build()
    }

    // --- Schema and constants ---

    #[test]
    fn schema_version_format() {
        assert!(EMBEDDING_SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(EMBEDDING_SCHEMA_VERSION.contains(".v1"));
    }

    #[test]
    fn max_embedding_dim_reasonable() {
        let med = MAX_EMBEDDING_DIM;
        assert!(med >= 32);
        assert!(med <= 1024);
    }

    #[test]
    fn min_observations_positive() {
        let mofe = MIN_OBSERVATIONS_FOR_EMBEDDING;
        assert!(mofe > 0);
    }

    #[test]
    fn default_thresholds_ordered() {
        let dnr = DEFAULT_NEIGHBORHOOD_RADIUS;
        let dcnt = DEFAULT_COSINE_NEAR_THRESHOLD;
        assert!(dnr > 0);
        assert!(dcnt > 0);
        assert!(dcnt < MILLION);
    }

    // --- FeatureFamily ---

    #[test]
    fn feature_family_all_variants_display() {
        let families = [
            FeatureFamily::InstructionDistribution,
            FeatureFamily::HotPathProfile,
            FeatureFamily::ControlFlow,
            FeatureFamily::MemoryAccess,
            FeatureFamily::CallGraph,
            FeatureFamily::StringPattern,
            FeatureFamily::ModuleGraph,
            FeatureFamily::RegimeDistribution,
        ];
        for fam in families {
            let s = fam.to_string();
            assert!(!s.is_empty());
        }
        assert_eq!(families.len(), 8);
    }

    #[test]
    fn feature_family_ordering() {
        assert!(FeatureFamily::InstructionDistribution < FeatureFamily::HotPathProfile);
        assert!(FeatureFamily::CallGraph < FeatureFamily::StringPattern);
    }

    #[test]
    fn feature_family_serde_roundtrip() {
        let fam = FeatureFamily::ControlFlow;
        let json = serde_json::to_string(&fam).unwrap();
        let back: FeatureFamily = serde_json::from_str(&json).unwrap();
        assert_eq!(fam, back);
    }

    // --- FeatureExtractionConfig ---

    #[test]
    fn default_config_is_sane() {
        let cfg = default_config();
        assert_eq!(cfg.max_features, MAX_EMBEDDING_DIM);
        assert_eq!(cfg.min_observations, MIN_OBSERVATIONS_FOR_EMBEDDING);
        assert!(cfg.normalize);
        assert!(cfg.enabled_families.is_empty());
    }

    #[test]
    fn config_family_enabled_all_when_empty() {
        let cfg = default_config();
        assert!(cfg.family_enabled(FeatureFamily::InstructionDistribution));
        assert!(cfg.family_enabled(FeatureFamily::MemoryAccess));
    }

    #[test]
    fn config_family_filter() {
        let mut cfg = default_config();
        cfg.enabled_families.insert(FeatureFamily::ControlFlow);
        assert!(cfg.family_enabled(FeatureFamily::ControlFlow));
        assert!(!cfg.family_enabled(FeatureFamily::MemoryAccess));
    }

    #[test]
    fn config_content_hash_deterministic() {
        let cfg1 = default_config();
        let cfg2 = default_config();
        assert_eq!(cfg1.content_hash(), cfg2.content_hash());
    }

    #[test]
    fn config_content_hash_changes_with_params() {
        let cfg1 = default_config();
        let mut cfg2 = default_config();
        cfg2.max_features = 64;
        assert_ne!(cfg1.content_hash(), cfg2.content_hash());
    }

    // --- EmbeddingValidity ---

    #[test]
    fn embedding_validity_display() {
        assert_eq!(EmbeddingValidity::Valid.to_string(), "valid");
        assert_eq!(
            EmbeddingValidity::InsufficientObservations.to_string(),
            "insufficient_observations"
        );
        assert_eq!(
            EmbeddingValidity::DimensionOverflow.to_string(),
            "dimension_overflow"
        );
        assert_eq!(EmbeddingValidity::Empty.to_string(), "empty");
    }

    #[test]
    fn embedding_validity_serde() {
        let v = EmbeddingValidity::Valid;
        let json = serde_json::to_string(&v).unwrap();
        let back: EmbeddingValidity = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // --- EmbeddingBuilder + WorkloadEmbedding ---

    #[test]
    fn builder_basic_embedding() {
        let emb = make_embedding(
            "t1",
            &[
                ("a", FeatureFamily::ControlFlow, 500_000, 20),
                ("b", FeatureFamily::MemoryAccess, 300_000, 20),
            ],
        );
        assert_eq!(emb.dimension, 2);
        assert!(emb.is_valid());
        assert_eq!(emb.validity, EmbeddingValidity::Valid);
        assert!(emb.embedding_id.starts_with("emb-t1-"));
    }

    #[test]
    fn builder_empty_embedding() {
        let builder = EmbeddingBuilder::new(default_config(), "empty".into(), test_epoch());
        let emb = builder.build();
        assert_eq!(emb.validity, EmbeddingValidity::Empty);
        assert!(!emb.is_valid());
        assert_eq!(emb.dimension, 0);
    }

    #[test]
    fn builder_insufficient_observations() {
        let emb = make_embedding(
            "t2",
            &[
                ("a", FeatureFamily::ControlFlow, 500_000, 2),
                ("b", FeatureFamily::MemoryAccess, 300_000, 2),
            ],
        );
        // total_observations = 4, below MIN_OBSERVATIONS_FOR_EMBEDDING = 8
        // But individual components are filtered by min_observations (8 by default),
        // so these components get filtered out → empty.
        assert_eq!(emb.validity, EmbeddingValidity::Empty);
    }

    #[test]
    fn builder_filters_by_min_observations() {
        let mut builder = EmbeddingBuilder::new(default_config(), "t3".into(), test_epoch());
        builder.add_feature("good", FeatureFamily::ControlFlow, 500_000, 100);
        builder.add_feature("bad", FeatureFamily::ControlFlow, 200_000, 2);
        let emb = builder.build();
        assert_eq!(emb.dimension, 1);
        assert!(emb.get_component("good").is_some());
        assert!(emb.get_component("bad").is_none());
    }

    #[test]
    fn builder_respects_family_filter() {
        let mut cfg = default_config();
        cfg.enabled_families.insert(FeatureFamily::ControlFlow);
        let mut builder = EmbeddingBuilder::new(cfg, "t4".into(), test_epoch());
        builder.add_feature("cf", FeatureFamily::ControlFlow, 500_000, 100);
        builder.add_feature("mem", FeatureFamily::MemoryAccess, 300_000, 100);
        assert_eq!(builder.component_count(), 1);
        let emb = builder.build();
        assert_eq!(emb.dimension, 1);
    }

    #[test]
    fn builder_replaces_duplicate_key() {
        let mut builder = EmbeddingBuilder::new(default_config(), "t5".into(), test_epoch());
        builder.add_feature("a", FeatureFamily::ControlFlow, 100_000, 50);
        builder.add_feature("a", FeatureFamily::ControlFlow, 200_000, 50);
        assert_eq!(builder.component_count(), 1);
    }

    #[test]
    fn embedding_value_vector() {
        let emb = make_embedding(
            "t6",
            &[
                ("a", FeatureFamily::ControlFlow, 100_000, 50),
                ("b", FeatureFamily::ControlFlow, 300_000, 50),
            ],
        );
        let vec = emb.value_vector();
        assert_eq!(vec.len(), 2);
    }

    #[test]
    fn embedding_keys_sorted() {
        let emb = make_embedding(
            "t7",
            &[
                ("z_feat", FeatureFamily::ControlFlow, 100_000, 50),
                ("a_feat", FeatureFamily::ControlFlow, 300_000, 50),
            ],
        );
        let keys = emb.keys();
        assert_eq!(keys[0], "a_feat");
        assert_eq!(keys[1], "z_feat");
    }

    #[test]
    fn embedding_content_hash_deterministic() {
        let emb1 = make_embedding("same", &[("a", FeatureFamily::ControlFlow, 100_000, 50)]);
        let emb2 = make_embedding("same", &[("a", FeatureFamily::ControlFlow, 100_000, 50)]);
        assert_eq!(emb1.content_hash, emb2.content_hash);
    }

    #[test]
    fn embedding_content_hash_varies_with_data() {
        let emb1 = make_embedding("t_a", &[("a", FeatureFamily::ControlFlow, 100_000, 50)]);
        let emb2 = make_embedding("t_b", &[("a", FeatureFamily::ControlFlow, 200_000, 50)]);
        assert_ne!(emb1.content_hash, emb2.content_hash);
    }

    #[test]
    fn embedding_squared_norm() {
        let mut cfg = default_config();
        cfg.normalize = false;
        let mut builder = EmbeddingBuilder::new(cfg, "norm".into(), test_epoch());
        builder.add_feature("x", FeatureFamily::ControlFlow, 3_000, 50);
        builder.add_feature("y", FeatureFamily::ControlFlow, 4_000, 50);
        let emb = builder.build();
        // 3000² + 4000² = 9_000_000 + 16_000_000 = 25_000_000
        assert_eq!(emb.squared_norm(), 25_000_000);
    }

    #[test]
    fn embedding_family_count() {
        let emb = make_embedding(
            "fc",
            &[
                ("a", FeatureFamily::ControlFlow, 100_000, 50),
                ("b", FeatureFamily::ControlFlow, 200_000, 50),
                ("c", FeatureFamily::MemoryAccess, 300_000, 50),
            ],
        );
        assert_eq!(emb.family_count(FeatureFamily::ControlFlow), 2);
        assert_eq!(emb.family_count(FeatureFamily::MemoryAccess), 1);
        assert_eq!(emb.family_count(FeatureFamily::CallGraph), 0);
    }

    #[test]
    fn embedding_serde_roundtrip() {
        let emb = make_embedding(
            "serde",
            &[
                ("a", FeatureFamily::ControlFlow, 100_000, 50),
                ("b", FeatureFamily::MemoryAccess, 200_000, 50),
            ],
        );
        let json = serde_json::to_string(&emb).unwrap();
        let back: WorkloadEmbedding = serde_json::from_str(&json).unwrap();
        assert_eq!(emb, back);
    }

    #[test]
    fn embedding_normalization() {
        let emb = make_embedding(
            "norm_test",
            &[
                ("lo", FeatureFamily::ControlFlow, 100_000, 50),
                ("hi", FeatureFamily::ControlFlow, 500_000, 50),
            ],
        );
        // After normalization: lo → 0, hi → MILLION
        let lo = emb.value_for("lo").unwrap();
        let hi = emb.value_for("hi").unwrap();
        assert_eq!(lo, 0);
        assert_eq!(hi, MILLION);
    }

    // --- Distance metrics ---

    #[test]
    fn distance_identical_embeddings() {
        let emb = make_embedding("same", &[("a", FeatureFamily::ControlFlow, 500_000, 50)]);
        for metric in [
            DistanceMetric::Manhattan,
            DistanceMetric::SquaredEuclidean,
            DistanceMetric::Chebyshev,
            DistanceMetric::Cosine,
        ] {
            let result = compute_distance(&emb, &emb, metric);
            assert_eq!(result.distance_millionths, 0, "metric={metric}");
            assert_eq!(result.missing_in_a, 0);
            assert_eq!(result.missing_in_b, 0);
        }
    }

    #[test]
    fn distance_manhattan_simple() {
        let mut cfg = default_config();
        cfg.normalize = false;
        let mut b1 = EmbeddingBuilder::new(cfg.clone(), "d1".into(), test_epoch());
        b1.add_feature("a", FeatureFamily::ControlFlow, 100_000, 50);
        b1.add_feature("b", FeatureFamily::ControlFlow, 200_000, 50);
        let mut b2 = EmbeddingBuilder::new(cfg, "d2".into(), test_epoch());
        b2.add_feature("a", FeatureFamily::ControlFlow, 300_000, 50);
        b2.add_feature("b", FeatureFamily::ControlFlow, 400_000, 50);
        let e1 = b1.build();
        let e2 = b2.build();
        let result = compute_distance(&e1, &e2, DistanceMetric::Manhattan);
        // |100k - 300k| + |200k - 400k| = 200k + 200k = 400k
        assert_eq!(result.distance_millionths, 400_000);
        assert_eq!(result.shared_dimensions, 2);
    }

    #[test]
    fn distance_chebyshev_takes_max() {
        let mut cfg = default_config();
        cfg.normalize = false;
        let mut b1 = EmbeddingBuilder::new(cfg.clone(), "ch1".into(), test_epoch());
        b1.add_feature("a", FeatureFamily::ControlFlow, 100_000, 50);
        b1.add_feature("b", FeatureFamily::ControlFlow, 200_000, 50);
        let mut b2 = EmbeddingBuilder::new(cfg, "ch2".into(), test_epoch());
        b2.add_feature("a", FeatureFamily::ControlFlow, 150_000, 50);
        b2.add_feature("b", FeatureFamily::ControlFlow, 500_000, 50);
        let e1 = b1.build();
        let e2 = b2.build();
        let result = compute_distance(&e1, &e2, DistanceMetric::Chebyshev);
        // max(|100k-150k|, |200k-500k|) = max(50k, 300k) = 300k
        assert_eq!(result.distance_millionths, 300_000);
    }

    #[test]
    fn distance_cosine_orthogonal() {
        let mut cfg = default_config();
        cfg.normalize = false;
        let mut b1 = EmbeddingBuilder::new(cfg.clone(), "cos1".into(), test_epoch());
        b1.add_feature("a", FeatureFamily::ControlFlow, 1_000_000, 50);
        b1.add_feature("b", FeatureFamily::ControlFlow, 0, 50);
        let mut b2 = EmbeddingBuilder::new(cfg, "cos2".into(), test_epoch());
        b2.add_feature("a", FeatureFamily::ControlFlow, 0, 50);
        b2.add_feature("b", FeatureFamily::ControlFlow, 1_000_000, 50);
        let e1 = b1.build();
        let e2 = b2.build();
        let result = compute_distance(&e1, &e2, DistanceMetric::Cosine);
        // Orthogonal → cosine similarity ≈ 0 → distance ≈ MILLION
        assert_eq!(result.distance_millionths, MILLION);
    }

    #[test]
    fn distance_missing_dimensions_tracked() {
        let mut cfg = default_config();
        cfg.normalize = false;
        let mut b1 = EmbeddingBuilder::new(cfg.clone(), "m1".into(), test_epoch());
        b1.add_feature("shared", FeatureFamily::ControlFlow, 100_000, 50);
        b1.add_feature("only_a", FeatureFamily::ControlFlow, 200_000, 50);
        let mut b2 = EmbeddingBuilder::new(cfg, "m2".into(), test_epoch());
        b2.add_feature("shared", FeatureFamily::ControlFlow, 100_000, 50);
        b2.add_feature("only_b", FeatureFamily::ControlFlow, 300_000, 50);
        let e1 = b1.build();
        let e2 = b2.build();
        let result = compute_distance(&e1, &e2, DistanceMetric::Manhattan);
        assert_eq!(result.shared_dimensions, 1);
        assert_eq!(result.missing_in_b, 1);
        assert_eq!(result.missing_in_a, 1);
    }

    #[test]
    fn distance_metric_display() {
        assert_eq!(DistanceMetric::Manhattan.to_string(), "manhattan");
        assert_eq!(DistanceMetric::Chebyshev.to_string(), "chebyshev");
        assert_eq!(DistanceMetric::Cosine.to_string(), "cosine");
        assert_eq!(
            DistanceMetric::SquaredEuclidean.to_string(),
            "squared_euclidean"
        );
    }

    #[test]
    fn distance_metric_serde() {
        let m = DistanceMetric::Cosine;
        let json = serde_json::to_string(&m).unwrap();
        let back: DistanceMetric = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    // --- isqrt ---

    #[test]
    fn isqrt_known_values() {
        assert_eq!(isqrt_i128(0), 0);
        assert_eq!(isqrt_i128(1), 1);
        assert_eq!(isqrt_i128(4), 2);
        assert_eq!(isqrt_i128(9), 3);
        assert_eq!(isqrt_i128(100), 10);
        assert_eq!(isqrt_i128(1_000_000), 1_000);
    }

    #[test]
    fn isqrt_negative() {
        assert_eq!(isqrt_i128(-5), 0);
    }

    #[test]
    fn isqrt_non_perfect() {
        // sqrt(10) = 3.16... → floor = 3
        let s = isqrt_i128(10);
        assert_eq!(s, 3);
        assert!(s * s <= 10);
        assert!((s + 1) * (s + 1) > 10);
    }

    // --- Neighborhood certificates ---

    #[test]
    fn certificate_near_identical() {
        let emb = make_embedding(
            "cert1",
            &[
                ("a", FeatureFamily::ControlFlow, 500_000, 50),
                ("b", FeatureFamily::MemoryAccess, 300_000, 50),
                ("c", FeatureFamily::CallGraph, 200_000, 50),
            ],
        );
        let cfg = NeighborhoodCertificateConfig::default();
        let cert = issue_neighborhood_certificate(&emb, &emb, &cfg, test_epoch());
        assert!(cert.is_near());
        assert!(!cert.is_abstained());
        assert!(cert.certificate_id.starts_with("ncert-near-"));
    }

    #[test]
    fn certificate_distant_workloads() {
        let mut cfg_e = default_config();
        cfg_e.normalize = false;
        let mut b1 = EmbeddingBuilder::new(cfg_e.clone(), "far1".into(), test_epoch());
        b1.add_feature("a", FeatureFamily::ControlFlow, 0, 50);
        b1.add_feature("b", FeatureFamily::ControlFlow, 0, 50);
        b1.add_feature("c", FeatureFamily::ControlFlow, 0, 50);
        let mut b2 = EmbeddingBuilder::new(cfg_e, "far2".into(), test_epoch());
        b2.add_feature("a", FeatureFamily::ControlFlow, 900_000, 50);
        b2.add_feature("b", FeatureFamily::ControlFlow, 900_000, 50);
        b2.add_feature("c", FeatureFamily::ControlFlow, 900_000, 50);
        let e1 = b1.build();
        let e2 = b2.build();
        let cfg = NeighborhoodCertificateConfig::default();
        let cert = issue_neighborhood_certificate(&e1, &e2, &cfg, test_epoch());
        assert!(cert.is_distant());
    }

    #[test]
    fn certificate_abstains_on_invalid() {
        let builder = EmbeddingBuilder::new(default_config(), "invalid".into(), test_epoch());
        let empty = builder.build();
        let good = make_embedding(
            "good",
            &[
                ("a", FeatureFamily::ControlFlow, 500_000, 50),
                ("b", FeatureFamily::ControlFlow, 300_000, 50),
                ("c", FeatureFamily::ControlFlow, 200_000, 50),
            ],
        );
        let cfg = NeighborhoodCertificateConfig::default();
        let cert = issue_neighborhood_certificate(&empty, &good, &cfg, test_epoch());
        assert!(cert.is_abstained());
        assert_eq!(
            cert.abstention_reason,
            Some(AbstentionReason::InvalidEmbedding)
        );
    }

    #[test]
    fn certificate_abstains_on_epoch_mismatch() {
        let e1 = {
            let mut builder =
                EmbeddingBuilder::new(default_config(), "ep1".into(), SecurityEpoch::from_raw(1));
            builder.add_feature("a", FeatureFamily::ControlFlow, 500_000, 50);
            builder.add_feature("b", FeatureFamily::ControlFlow, 300_000, 50);
            builder.add_feature("c", FeatureFamily::ControlFlow, 200_000, 50);
            builder.build()
        };
        let e2 = {
            let mut builder =
                EmbeddingBuilder::new(default_config(), "ep2".into(), SecurityEpoch::from_raw(100));
            builder.add_feature("a", FeatureFamily::ControlFlow, 500_000, 50);
            builder.add_feature("b", FeatureFamily::ControlFlow, 300_000, 50);
            builder.add_feature("c", FeatureFamily::ControlFlow, 200_000, 50);
            builder.build()
        };
        let cfg = NeighborhoodCertificateConfig::default();
        let cert = issue_neighborhood_certificate(&e1, &e2, &cfg, test_epoch());
        assert!(cert.is_abstained());
        assert_eq!(
            cert.abstention_reason,
            Some(AbstentionReason::EpochMismatch)
        );
    }

    #[test]
    fn certificate_abstains_on_no_shared_dims() {
        let mut cfg_e = default_config();
        cfg_e.normalize = false;
        let mut b1 = EmbeddingBuilder::new(cfg_e.clone(), "ns1".into(), test_epoch());
        b1.add_feature("only_a1", FeatureFamily::ControlFlow, 100_000, 50);
        b1.add_feature("only_a2", FeatureFamily::ControlFlow, 200_000, 50);
        b1.add_feature("only_a3", FeatureFamily::ControlFlow, 300_000, 50);
        let mut b2 = EmbeddingBuilder::new(cfg_e, "ns2".into(), test_epoch());
        b2.add_feature("only_b1", FeatureFamily::ControlFlow, 400_000, 50);
        b2.add_feature("only_b2", FeatureFamily::ControlFlow, 500_000, 50);
        b2.add_feature("only_b3", FeatureFamily::ControlFlow, 600_000, 50);
        let e1 = b1.build();
        let e2 = b2.build();
        let cfg = NeighborhoodCertificateConfig::default();
        let cert = issue_neighborhood_certificate(&e1, &e2, &cfg, test_epoch());
        assert!(cert.is_abstained());
        assert_eq!(
            cert.abstention_reason,
            Some(AbstentionReason::NoSharedDimensions)
        );
    }

    #[test]
    fn certificate_abstains_on_insufficient_shared() {
        let mut cfg_e = default_config();
        cfg_e.normalize = false;
        let mut b1 = EmbeddingBuilder::new(cfg_e.clone(), "is1".into(), test_epoch());
        b1.add_feature("shared", FeatureFamily::ControlFlow, 100_000, 50);
        b1.add_feature("only_a", FeatureFamily::ControlFlow, 200_000, 50);
        b1.add_feature("only_a2", FeatureFamily::ControlFlow, 300_000, 50);
        let mut b2 = EmbeddingBuilder::new(cfg_e, "is2".into(), test_epoch());
        b2.add_feature("shared", FeatureFamily::ControlFlow, 100_000, 50);
        b2.add_feature("only_b", FeatureFamily::ControlFlow, 400_000, 50);
        b2.add_feature("only_b2", FeatureFamily::ControlFlow, 500_000, 50);
        let e1 = b1.build();
        let e2 = b2.build();
        // Default min_shared_dimensions = 3, but only 1 shared dim
        let cfg = NeighborhoodCertificateConfig::default();
        let cert = issue_neighborhood_certificate(&e1, &e2, &cfg, test_epoch());
        assert!(cert.is_abstained());
        assert_eq!(
            cert.abstention_reason,
            Some(AbstentionReason::InsufficientSharedDimensions)
        );
    }

    #[test]
    fn certificate_serde_roundtrip() {
        let emb = make_embedding(
            "cs",
            &[
                ("a", FeatureFamily::ControlFlow, 500_000, 50),
                ("b", FeatureFamily::ControlFlow, 300_000, 50),
                ("c", FeatureFamily::ControlFlow, 200_000, 50),
            ],
        );
        let cfg = NeighborhoodCertificateConfig::default();
        let cert = issue_neighborhood_certificate(&emb, &emb, &cfg, test_epoch());
        let json = serde_json::to_string(&cert).unwrap();
        let back: NeighborhoodCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
    }

    #[test]
    fn certificate_verdict_display() {
        assert_eq!(CertificateVerdict::Near.to_string(), "near");
        assert_eq!(CertificateVerdict::Marginal.to_string(), "marginal");
        assert_eq!(CertificateVerdict::Distant.to_string(), "distant");
        assert_eq!(CertificateVerdict::Abstained.to_string(), "abstained");
    }

    #[test]
    fn abstention_reason_display() {
        assert_eq!(
            AbstentionReason::InvalidEmbedding.to_string(),
            "invalid_embedding"
        );
        assert_eq!(
            AbstentionReason::NoSharedDimensions.to_string(),
            "no_shared_dimensions"
        );
        assert_eq!(
            AbstentionReason::EpochMismatch.to_string(),
            "epoch_mismatch"
        );
    }

    // --- EmbeddingCatalog ---

    #[test]
    fn catalog_new_empty() {
        let cat = EmbeddingCatalog::new(test_epoch());
        assert!(cat.is_empty());
        assert_eq!(cat.len(), 0);
    }

    #[test]
    fn catalog_insert_and_len() {
        let mut cat = EmbeddingCatalog::new(test_epoch());
        let emb = make_embedding("cat1", &[("a", FeatureFamily::ControlFlow, 500_000, 50)]);
        cat.insert(emb, Some("test".into()), BTreeSet::new());
        assert_eq!(cat.len(), 1);
        assert!(!cat.is_empty());
    }

    #[test]
    fn catalog_k_nearest_basic() {
        let mut cat = EmbeddingCatalog::new(test_epoch());
        let mut cfg_e = default_config();
        cfg_e.normalize = false;
        for i in 0..5 {
            let mut b = EmbeddingBuilder::new(cfg_e.clone(), format!("kn-{i}"), test_epoch());
            b.add_feature("a", FeatureFamily::ControlFlow, (i as i64) * 100_000, 50);
            b.add_feature("b", FeatureFamily::ControlFlow, (i as i64) * 50_000, 50);
            b.add_feature("c", FeatureFamily::ControlFlow, 0, 50);
            cat.insert(b.build(), Some(format!("entry-{i}")), BTreeSet::new());
        }
        let query = {
            let mut b = EmbeddingBuilder::new(cfg_e, "query".into(), test_epoch());
            b.add_feature("a", FeatureFamily::ControlFlow, 0, 50);
            b.add_feature("b", FeatureFamily::ControlFlow, 0, 50);
            b.add_feature("c", FeatureFamily::ControlFlow, 0, 50);
            b.build()
        };
        let results = cat.k_nearest(&query, 2, DistanceMetric::Manhattan);
        assert_eq!(results.len(), 2);
        // Nearest should be kn-0 (all zeros)
        assert!(results[0].embedding_id.contains("kn-0"));
    }

    #[test]
    fn catalog_within_radius() {
        let mut cat = EmbeddingCatalog::new(test_epoch());
        let mut cfg_e = default_config();
        cfg_e.normalize = false;
        for i in 0..5 {
            let mut b = EmbeddingBuilder::new(cfg_e.clone(), format!("wr-{i}"), test_epoch());
            b.add_feature("x", FeatureFamily::ControlFlow, (i as i64) * 10_000, 50);
            b.add_feature("y", FeatureFamily::ControlFlow, 0, 50);
            b.add_feature("z", FeatureFamily::ControlFlow, 0, 50);
            cat.insert(b.build(), None, BTreeSet::new());
        }
        let query = {
            let mut b = EmbeddingBuilder::new(cfg_e, "wr-q".into(), test_epoch());
            b.add_feature("x", FeatureFamily::ControlFlow, 0, 50);
            b.add_feature("y", FeatureFamily::ControlFlow, 0, 50);
            b.add_feature("z", FeatureFamily::ControlFlow, 0, 50);
            b.build()
        };
        // Chebyshev radius = 15_000: should catch entries 0 and 1 (max diff 0 and 10k)
        let results = cat.within_radius(&query, 15_000, DistanceMetric::Chebyshev);
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn catalog_summary() {
        let mut cat = EmbeddingCatalog::new(test_epoch());
        let emb = make_embedding(
            "s1",
            &[
                ("a", FeatureFamily::ControlFlow, 500_000, 50),
                ("b", FeatureFamily::MemoryAccess, 300_000, 50),
            ],
        );
        cat.insert(emb, None, BTreeSet::new());
        let summary = cat.summary();
        assert_eq!(summary.total_entries, 1);
        assert_eq!(summary.valid_count, 1);
        assert_eq!(summary.invalid_count, 0);
    }

    // --- Transfer safety ---

    #[test]
    fn transfer_all_for_identical() {
        let emb = make_embedding(
            "tsf1",
            &[
                ("a", FeatureFamily::ControlFlow, 500_000, 50),
                ("b", FeatureFamily::MemoryAccess, 300_000, 50),
                ("c", FeatureFamily::CallGraph, 200_000, 50),
            ],
        );
        let cfg = NeighborhoodCertificateConfig::default();
        let assessment = assess_transfer_safety(&emb, &emb, &cfg, test_epoch());
        assert_eq!(
            assessment.recommendation,
            TransferRecommendation::TransferAll
        );
        assert!(assessment.blocked_families.is_empty());
    }

    #[test]
    fn transfer_blocked_for_distant() {
        let mut cfg_e = default_config();
        cfg_e.normalize = false;
        let mut b1 = EmbeddingBuilder::new(cfg_e.clone(), "tb1".into(), test_epoch());
        b1.add_feature("a", FeatureFamily::ControlFlow, 0, 50);
        b1.add_feature("b", FeatureFamily::ControlFlow, 0, 50);
        b1.add_feature("c", FeatureFamily::ControlFlow, 0, 50);
        let mut b2 = EmbeddingBuilder::new(cfg_e, "tb2".into(), test_epoch());
        b2.add_feature("a", FeatureFamily::ControlFlow, 900_000, 50);
        b2.add_feature("b", FeatureFamily::ControlFlow, 900_000, 50);
        b2.add_feature("c", FeatureFamily::ControlFlow, 900_000, 50);
        let e1 = b1.build();
        let e2 = b2.build();
        let cfg = NeighborhoodCertificateConfig::default();
        let assessment = assess_transfer_safety(&e1, &e2, &cfg, test_epoch());
        assert_eq!(
            assessment.recommendation,
            TransferRecommendation::BlockTransfer
        );
    }

    #[test]
    fn transfer_cannot_assess_on_invalid() {
        let empty = EmbeddingBuilder::new(default_config(), "empty".into(), test_epoch()).build();
        let good = make_embedding(
            "good",
            &[
                ("a", FeatureFamily::ControlFlow, 500_000, 50),
                ("b", FeatureFamily::ControlFlow, 300_000, 50),
                ("c", FeatureFamily::ControlFlow, 200_000, 50),
            ],
        );
        let cfg = NeighborhoodCertificateConfig::default();
        let assessment = assess_transfer_safety(&empty, &good, &cfg, test_epoch());
        assert_eq!(
            assessment.recommendation,
            TransferRecommendation::CannotAssess
        );
    }

    #[test]
    fn transfer_recommendation_display() {
        assert_eq!(
            TransferRecommendation::TransferAll.to_string(),
            "transfer_all"
        );
        assert_eq!(
            TransferRecommendation::TransferSelective.to_string(),
            "transfer_selective"
        );
        assert_eq!(
            TransferRecommendation::BlockTransfer.to_string(),
            "block_transfer"
        );
        assert_eq!(
            TransferRecommendation::CannotAssess.to_string(),
            "cannot_assess"
        );
    }

    #[test]
    fn transfer_serde_roundtrip() {
        let emb = make_embedding(
            "tserde",
            &[
                ("a", FeatureFamily::ControlFlow, 500_000, 50),
                ("b", FeatureFamily::ControlFlow, 300_000, 50),
                ("c", FeatureFamily::ControlFlow, 200_000, 50),
            ],
        );
        let cfg = NeighborhoodCertificateConfig::default();
        let assessment = assess_transfer_safety(&emb, &emb, &cfg, test_epoch());
        let json = serde_json::to_string(&assessment).unwrap();
        let back: TransferSafetyAssessment = serde_json::from_str(&json).unwrap();
        assert_eq!(assessment, back);
    }

    // --- Evidence corpus ---

    #[test]
    fn evidence_corpus_builds() {
        let (specimens, hash) = run_embedding_corpus(test_epoch());
        assert_eq!(specimens.len(), 6);
        assert!(!hash.to_hex().is_empty());
    }

    #[test]
    fn evidence_corpus_deterministic() {
        let (_, h1) = run_embedding_corpus(test_epoch());
        let (_, h2) = run_embedding_corpus(test_epoch());
        assert_eq!(h1, h2);
    }

    #[test]
    fn evidence_corpus_all_families_represented() {
        let (specimens, _) = run_embedding_corpus(test_epoch());
        let families: BTreeSet<EmbeddingSpecimenFamily> =
            specimens.iter().map(|s| s.family).collect();
        assert!(families.contains(&EmbeddingSpecimenFamily::ComputeBound));
        assert!(families.contains(&EmbeddingSpecimenFamily::MemoryIntensive));
        assert!(families.contains(&EmbeddingSpecimenFamily::IoHeavy));
        assert!(families.contains(&EmbeddingSpecimenFamily::Mixed));
        assert!(families.contains(&EmbeddingSpecimenFamily::Trivial));
        assert!(families.contains(&EmbeddingSpecimenFamily::Adversarial));
    }

    #[test]
    fn evidence_corpus_ids_unique() {
        let (specimens, _) = run_embedding_corpus(test_epoch());
        let ids: BTreeSet<&str> = specimens.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids.len(), specimens.len());
    }

    #[test]
    fn evidence_corpus_specimen_serde() {
        let (specimens, _) = run_embedding_corpus(test_epoch());
        for s in &specimens {
            let json = serde_json::to_string(s).unwrap();
            let back: EmbeddingSpecimen = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn specimen_family_display() {
        assert_eq!(
            EmbeddingSpecimenFamily::ComputeBound.to_string(),
            "compute_bound"
        );
        assert_eq!(
            EmbeddingSpecimenFamily::MemoryIntensive.to_string(),
            "memory_intensive"
        );
        assert_eq!(EmbeddingSpecimenFamily::IoHeavy.to_string(), "io_heavy");
        assert_eq!(EmbeddingSpecimenFamily::Mixed.to_string(), "mixed");
        assert_eq!(EmbeddingSpecimenFamily::Trivial.to_string(), "trivial");
        assert_eq!(
            EmbeddingSpecimenFamily::Adversarial.to_string(),
            "adversarial"
        );
    }
}
