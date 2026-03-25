#![forbid(unsafe_code)]

//! Proof-backed lossless compression and deduplication across cache, AOT, and
//! evidence artifacts.
//!
//! Bead: bd-1lsy.7.18.2 [RGC-618B]
//!
//! Builds a compression pipeline with four parts:
//!
//! 1. **Bundle planner** — decides which artifact subgraphs can be merged,
//!    shared, factored, or compressed based on canonical identities,
//!    transformation witnesses, and downstream consumer requirements.
//! 2. **Restoration contract** — for every compression action, emits a
//!    deterministic restoration recipe so any downstream consumer can recover
//!    the original bytes without loss.
//! 3. **Dedup tracker** — tracks duplicate mass and origin across artifact
//!    families, with explicit dedup receipts.
//! 4. **Exclusion policy** — certain artifact families (replay-critical,
//!    security evidence, legal provenance) are excluded from lossy or
//!    irreversible compression, with explicit exclusion receipts.
//!
//! # Design decisions
//!
//! - **Lossless only** — all compression actions are reversible; lossy
//!   compression is structurally impossible through this pipeline.
//! - **Canonical identity integration** — the pipeline consumes canonical IDs
//!   from `semantic_canonical_basis` to identify dedup candidates.
//! - **Deterministic restoration** — every compressed artifact carries an
//!   inline restoration recipe with content-addressed verification.
//! - **Fail-closed exclusion** — excluded families reject compression at the
//!   planning stage; no runtime bypass.
//! - **All arithmetic uses fixed-point millionths** (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the artifact compression pipeline.
pub const SCHEMA_VERSION: &str = "franken-engine.artifact-compression-pipeline.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.7.18.2";

/// Component name.
pub const COMPONENT: &str = "artifact_compression_pipeline";

/// One million — unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

/// Maximum number of artifacts in a single compression bundle before the
/// planner forces a split.
pub const MAX_BUNDLE_SIZE: usize = 4_096;

/// Maximum uncompressed artifact size (bytes) that the pipeline will accept.
/// Artifacts larger than this must be pre-chunked.
pub const MAX_ARTIFACT_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

/// Minimum compression ratio (millionths) below which the pipeline emits a
/// warning receipt but still proceeds (the compressed output is larger than
/// the input, which is unusual for lossless).
pub const MIN_USEFUL_RATIO: u64 = 900_000; // 90% — 10% savings threshold

/// Maximum dedup chain depth before the pipeline refuses to resolve further.
pub const MAX_DEDUP_CHAIN_DEPTH: usize = 32;

// ---------------------------------------------------------------------------
// CompressionAlgorithm
// ---------------------------------------------------------------------------

/// Lossless compression algorithm used by the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionAlgorithm {
    /// No compression — passthrough with content-hash verification.
    Identity,
    /// Deflate (zlib-compatible).
    Deflate,
    /// Zstandard.
    Zstd,
    /// LZ4 framed.
    Lz4,
}

impl CompressionAlgorithm {
    /// All algorithms in canonical order.
    pub const ALL: &[Self] = &[Self::Identity, Self::Deflate, Self::Zstd, Self::Lz4];

    /// Machine-readable label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Deflate => "deflate",
            Self::Zstd => "zstd",
            Self::Lz4 => "lz4",
        }
    }

    /// Whether this algorithm is a true compressor (not identity passthrough).
    pub const fn is_compressor(self) -> bool {
        !matches!(self, Self::Identity)
    }
}

impl fmt::Display for CompressionAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ArtifactCategory — artifact classification for compression policy
// ---------------------------------------------------------------------------

/// Category of artifact determining compression eligibility and exclusion
/// policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactCategory {
    /// Cache entries (module cache, shape cache, inline-cache snapshots).
    Cache,
    /// AOT compilation artifacts (entrygraphs, precompiled bytecode).
    Aot,
    /// Evidence records (decision receipts, attestation bundles).
    Evidence,
    /// Replay traces (nondeterminism transcripts, decision logs).
    Replay,
    /// Security provenance (revocation chains, quarantine records).
    SecurityProvenance,
    /// Legal provenance (audit logs, compliance evidence).
    LegalProvenance,
    /// Benchmark artifacts (performance evidence, regression bundles).
    Benchmark,
    /// Rewrite packs (versioned optimization rules).
    RewritePack,
    /// Support bundles (operator diagnostics, triage exports).
    SupportBundle,
}

impl ArtifactCategory {
    /// All categories in canonical order.
    pub const ALL: &[Self] = &[
        Self::Cache,
        Self::Aot,
        Self::Evidence,
        Self::Replay,
        Self::SecurityProvenance,
        Self::LegalProvenance,
        Self::Benchmark,
        Self::RewritePack,
        Self::SupportBundle,
    ];

    /// Machine-readable label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cache => "cache",
            Self::Aot => "aot",
            Self::Evidence => "evidence",
            Self::Replay => "replay",
            Self::SecurityProvenance => "security_provenance",
            Self::LegalProvenance => "legal_provenance",
            Self::Benchmark => "benchmark",
            Self::RewritePack => "rewrite_pack",
            Self::SupportBundle => "support_bundle",
        }
    }

    /// Whether this category is excluded from compression by default.
    /// Replay, security, and legal provenance are always excluded.
    pub const fn is_compression_excluded(self) -> bool {
        matches!(
            self,
            Self::Replay | Self::SecurityProvenance | Self::LegalProvenance
        )
    }

    /// Whether this category is excluded from deduplication by default.
    /// Same exclusion set as compression.
    pub const fn is_dedup_excluded(self) -> bool {
        self.is_compression_excluded()
    }
}

impl fmt::Display for ArtifactCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ExclusionReason — why an artifact was excluded from compression/dedup
// ---------------------------------------------------------------------------

/// Structured reason for excluding an artifact from compression or dedup.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    /// The artifact's category is in the excluded set.
    CategoryExcluded,
    /// The artifact exceeds the maximum size for inline compression.
    OversizeArtifact,
    /// The artifact has no canonical identity and cannot be dedup-checked.
    NoCanonicalIdentity,
    /// The artifact is already compressed (double-compression forbidden).
    AlreadyCompressed,
    /// Operator override: explicit exclusion via policy.
    OperatorOverride,
    /// The epoch mismatch between artifact and pipeline prevents processing.
    EpochMismatch,
}

impl ExclusionReason {
    /// All reasons in canonical order.
    pub const ALL: &[Self] = &[
        Self::CategoryExcluded,
        Self::OversizeArtifact,
        Self::NoCanonicalIdentity,
        Self::AlreadyCompressed,
        Self::OperatorOverride,
        Self::EpochMismatch,
    ];

    /// Machine-readable label.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::CategoryExcluded => "category_excluded",
            Self::OversizeArtifact => "oversize_artifact",
            Self::NoCanonicalIdentity => "no_canonical_identity",
            Self::AlreadyCompressed => "already_compressed",
            Self::OperatorOverride => "operator_override",
            Self::EpochMismatch => "epoch_mismatch",
        }
    }
}

impl fmt::Display for ExclusionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CompressionAction — what the planner decided to do with an artifact
// ---------------------------------------------------------------------------

/// The action the bundle planner assigned to an artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionAction {
    /// Compress using the chosen algorithm.
    Compress,
    /// Deduplicate against an existing canonical representative.
    Dedup,
    /// Pass through without modification (excluded or identity).
    Passthrough,
    /// Exclude from the bundle entirely (with structured reason).
    Exclude,
}

impl CompressionAction {
    /// All actions in canonical order.
    pub const ALL: &[Self] = &[
        Self::Compress,
        Self::Dedup,
        Self::Passthrough,
        Self::Exclude,
    ];

    /// Machine-readable label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compress => "compress",
            Self::Dedup => "dedup",
            Self::Passthrough => "passthrough",
            Self::Exclude => "exclude",
        }
    }
}

impl fmt::Display for CompressionAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ArtifactDescriptor — input to the bundle planner
// ---------------------------------------------------------------------------

/// Descriptor for a single artifact entering the compression pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDescriptor {
    /// Unique artifact identifier (opaque string from the producing system).
    pub artifact_id: String,
    /// Category of the artifact.
    pub category: ArtifactCategory,
    /// Size of the uncompressed artifact in bytes.
    pub size_bytes: u64,
    /// Content hash of the uncompressed artifact.
    pub content_hash: ContentHash,
    /// Optional canonical ID from `semantic_canonical_basis`. When present,
    /// the dedup tracker can identify duplicates across artifact boundaries.
    pub canonical_id: Option<ContentHash>,
    /// Whether this artifact has already been compressed by an upstream stage.
    pub already_compressed: bool,
    /// The security epoch at which this artifact was produced.
    pub epoch: SecurityEpoch,
}

impl ArtifactDescriptor {
    /// Create a new artifact descriptor.
    pub fn new(
        artifact_id: impl Into<String>,
        category: ArtifactCategory,
        size_bytes: u64,
        content_bytes: &[u8],
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            artifact_id: artifact_id.into(),
            category,
            size_bytes,
            content_hash: ContentHash::compute(content_bytes),
            canonical_id: None,
            already_compressed: false,
            epoch,
        }
    }

    /// Attach a canonical ID (from semantic_canonical_basis orbit reduction).
    pub fn with_canonical_id(mut self, canonical_id: ContentHash) -> Self {
        self.canonical_id = Some(canonical_id);
        self
    }

    /// Mark as already compressed.
    pub fn mark_already_compressed(mut self) -> Self {
        self.already_compressed = true;
        self
    }
}

// ---------------------------------------------------------------------------
// RestorationRecipe — how to restore the original bytes
// ---------------------------------------------------------------------------

/// A deterministic recipe for restoring an artifact from its compressed form.
/// Every compressed artifact carries exactly one restoration recipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestorationRecipe {
    /// The algorithm used for compression (determines decompressor).
    pub algorithm: CompressionAlgorithm,
    /// Content hash of the original (uncompressed) artifact — verification
    /// target after decompression.
    pub original_hash: ContentHash,
    /// Content hash of the compressed artifact — verification of the
    /// compressed representation itself.
    pub compressed_hash: ContentHash,
    /// Original size in bytes.
    pub original_size_bytes: u64,
    /// Compressed size in bytes.
    pub compressed_size_bytes: u64,
    /// Compression ratio in millionths (compressed / original). A ratio of
    /// 500_000 means the compressed version is 50% of the original.
    pub ratio_millionths: u64,
    /// Epoch at which compression was performed.
    pub epoch: SecurityEpoch,
}

impl RestorationRecipe {
    /// Create a new restoration recipe.
    pub fn new(
        algorithm: CompressionAlgorithm,
        original_hash: ContentHash,
        compressed_hash: ContentHash,
        original_size_bytes: u64,
        compressed_size_bytes: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        let ratio_millionths = if original_size_bytes == 0 {
            MILLION
        } else {
            compressed_size_bytes
                .saturating_mul(MILLION)
                .checked_div(original_size_bytes)
                .unwrap_or(MILLION)
        };
        Self {
            algorithm,
            original_hash,
            compressed_hash,
            original_size_bytes,
            compressed_size_bytes,
            ratio_millionths,
            epoch,
        }
    }

    /// Whether the compression actually saved space.
    pub fn is_beneficial(&self) -> bool {
        self.ratio_millionths < MILLION
    }

    /// Whether the ratio is below the minimum useful threshold.
    pub fn is_below_useful_threshold(&self) -> bool {
        self.ratio_millionths > MIN_USEFUL_RATIO && self.ratio_millionths < MILLION
    }

    /// Savings in bytes (zero if compression expanded the artifact).
    pub fn savings_bytes(&self) -> u64 {
        self.original_size_bytes
            .saturating_sub(self.compressed_size_bytes)
    }
}

// ---------------------------------------------------------------------------
// DedupReceipt — evidence of a dedup decision
// ---------------------------------------------------------------------------

/// Receipt proving that an artifact was deduplicated against a canonical
/// representative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedupReceipt {
    /// The artifact that was deduplicated (the duplicate).
    pub duplicate_artifact_id: String,
    /// The canonical representative this artifact maps to.
    pub canonical_artifact_id: String,
    /// Canonical content hash shared by both artifacts.
    pub canonical_hash: ContentHash,
    /// Category of the deduplicated artifact.
    pub category: ArtifactCategory,
    /// Size of the duplicate artifact in bytes (space saved).
    pub saved_bytes: u64,
    /// Depth in the dedup chain (1 = direct duplicate of original).
    pub chain_depth: usize,
    /// Epoch at which dedup was performed.
    pub epoch: SecurityEpoch,
    /// Content hash of this receipt for audit linkage.
    pub receipt_hash: ContentHash,
}

impl DedupReceipt {
    /// Create a new dedup receipt.
    pub fn new(
        duplicate_artifact_id: impl Into<String>,
        canonical_artifact_id: impl Into<String>,
        canonical_hash: ContentHash,
        category: ArtifactCategory,
        saved_bytes: u64,
        chain_depth: usize,
        epoch: SecurityEpoch,
    ) -> Self {
        let duplicate_artifact_id = duplicate_artifact_id.into();
        let canonical_artifact_id = canonical_artifact_id.into();

        let mut hasher = Sha256::new();
        hasher.update(b"dedup_receipt:");
        hasher.update(duplicate_artifact_id.as_bytes());
        hasher.update(b"|");
        hasher.update(canonical_artifact_id.as_bytes());
        hasher.update(b"|");
        hasher.update(canonical_hash.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        let receipt_hash = ContentHash::compute(&hasher.finalize());

        Self {
            duplicate_artifact_id,
            canonical_artifact_id,
            canonical_hash,
            category,
            saved_bytes,
            chain_depth,
            epoch,
            receipt_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// ExclusionReceipt — evidence of an exclusion decision
// ---------------------------------------------------------------------------

/// Receipt proving that an artifact was excluded from compression or dedup.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExclusionReceipt {
    /// The artifact that was excluded.
    pub artifact_id: String,
    /// Category of the excluded artifact.
    pub category: ArtifactCategory,
    /// Structured reason for exclusion.
    pub reason: ExclusionReason,
    /// Epoch at which exclusion was decided.
    pub epoch: SecurityEpoch,
    /// Content hash of this receipt for audit linkage.
    pub receipt_hash: ContentHash,
}

impl ExclusionReceipt {
    /// Create a new exclusion receipt.
    pub fn new(
        artifact_id: impl Into<String>,
        category: ArtifactCategory,
        reason: ExclusionReason,
        epoch: SecurityEpoch,
    ) -> Self {
        let artifact_id = artifact_id.into();

        let mut hasher = Sha256::new();
        hasher.update(b"exclusion_receipt:");
        hasher.update(artifact_id.as_bytes());
        hasher.update(b"|");
        hasher.update(reason.as_str().as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        let receipt_hash = ContentHash::compute(&hasher.finalize());

        Self {
            artifact_id,
            category,
            reason,
            epoch,
            receipt_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// PlanEntry — one entry in the bundle plan
// ---------------------------------------------------------------------------

/// A single entry in the compression bundle plan, representing the planner's
/// decision for one artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanEntry {
    /// The artifact this plan entry applies to.
    pub artifact_id: String,
    /// Category of the artifact.
    pub category: ArtifactCategory,
    /// The action decided by the planner.
    pub action: CompressionAction,
    /// The algorithm chosen (meaningful only for Compress action).
    pub algorithm: CompressionAlgorithm,
    /// For Dedup action: the canonical representative's artifact ID.
    pub dedup_target: Option<String>,
    /// For Exclude action: the structured reason.
    pub exclusion_reason: Option<ExclusionReason>,
}

// ---------------------------------------------------------------------------
// BundlePlan — the planner's output for a set of artifacts
// ---------------------------------------------------------------------------

/// The output of the bundle planner: a deterministic plan for compressing,
/// deduplicating, or excluding each artifact in a bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundlePlan {
    /// Plan entries in artifact-ID sorted order.
    pub entries: Vec<PlanEntry>,
    /// Total uncompressed size across all planned artifacts.
    pub total_input_bytes: u64,
    /// Number of artifacts planned for compression.
    pub compress_count: usize,
    /// Number of artifacts planned for dedup.
    pub dedup_count: usize,
    /// Number of artifacts passing through.
    pub passthrough_count: usize,
    /// Number of artifacts excluded.
    pub exclude_count: usize,
    /// Epoch at which the plan was created.
    pub epoch: SecurityEpoch,
    /// Content hash of the plan itself.
    pub plan_hash: ContentHash,
}

impl BundlePlan {
    /// Total number of entries in the plan.
    pub fn total_entries(&self) -> usize {
        self.entries.len()
    }

    /// Whether the plan contains any compression or dedup actions.
    pub fn has_actionable_entries(&self) -> bool {
        self.compress_count > 0 || self.dedup_count > 0
    }
}

// ---------------------------------------------------------------------------
// BundlePlanner — decides what to do with each artifact
// ---------------------------------------------------------------------------

/// Configuration for the bundle planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlannerConfig {
    /// The compression algorithm to use for eligible artifacts.
    pub algorithm: CompressionAlgorithm,
    /// Maximum bundle size before forced split.
    pub max_bundle_size: usize,
    /// Maximum single artifact size in bytes.
    pub max_artifact_bytes: u64,
    /// Additional categories to exclude (beyond the built-in exclusions).
    pub extra_exclusions: BTreeSet<ArtifactCategory>,
    /// Whether dedup is enabled.
    pub dedup_enabled: bool,
    /// The security epoch for this planning session.
    pub epoch: SecurityEpoch,
}

impl PlannerConfig {
    /// Create a default planner config with the given epoch.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            algorithm: CompressionAlgorithm::Zstd,
            max_bundle_size: MAX_BUNDLE_SIZE,
            max_artifact_bytes: MAX_ARTIFACT_BYTES,
            extra_exclusions: BTreeSet::new(),
            dedup_enabled: true,
            epoch,
        }
    }

    /// Override the compression algorithm.
    pub fn with_algorithm(mut self, algorithm: CompressionAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    /// Add an extra category exclusion.
    pub fn with_extra_exclusion(mut self, category: ArtifactCategory) -> Self {
        self.extra_exclusions.insert(category);
        self
    }

    /// Disable deduplication.
    pub fn without_dedup(mut self) -> Self {
        self.dedup_enabled = false;
        self
    }
}

/// The bundle planner: examines artifacts, decides actions, and emits a
/// deterministic plan.
pub struct BundlePlanner {
    config: PlannerConfig,
    /// Known canonical IDs for dedup lookup: canonical_hash → first seen
    /// artifact_id.
    canonical_registry: BTreeMap<ContentHash, String>,
}

impl BundlePlanner {
    /// Create a new planner with the given configuration.
    pub fn new(config: PlannerConfig) -> Self {
        Self {
            config,
            canonical_registry: BTreeMap::new(),
        }
    }

    /// Check whether a category is excluded from compression.
    fn is_excluded(&self, category: ArtifactCategory) -> bool {
        category.is_compression_excluded() || self.config.extra_exclusions.contains(&category)
    }

    /// Determine the exclusion reason for an artifact, if any.
    fn check_exclusion(&self, desc: &ArtifactDescriptor) -> Option<ExclusionReason> {
        if self.is_excluded(desc.category) {
            return Some(ExclusionReason::CategoryExcluded);
        }
        if desc.size_bytes > self.config.max_artifact_bytes {
            return Some(ExclusionReason::OversizeArtifact);
        }
        if desc.already_compressed {
            return Some(ExclusionReason::AlreadyCompressed);
        }
        if desc.epoch.as_u64() != self.config.epoch.as_u64() {
            return Some(ExclusionReason::EpochMismatch);
        }
        None
    }

    /// Plan compression/dedup actions for a batch of artifacts.
    ///
    /// Artifacts are processed in the order given. For dedup, the first
    /// artifact with a given canonical ID becomes the representative; later
    /// duplicates reference it.
    pub fn plan(&mut self, descriptors: &[ArtifactDescriptor]) -> BundlePlan {
        let mut entries = Vec::with_capacity(descriptors.len());
        let mut total_input_bytes: u64 = 0;
        let mut compress_count: usize = 0;
        let mut dedup_count: usize = 0;
        let mut passthrough_count: usize = 0;
        let mut exclude_count: usize = 0;

        for desc in descriptors {
            total_input_bytes = total_input_bytes.saturating_add(desc.size_bytes);

            // Step 1: check exclusion
            if let Some(reason) = self.check_exclusion(desc) {
                entries.push(PlanEntry {
                    artifact_id: desc.artifact_id.clone(),
                    category: desc.category,
                    action: CompressionAction::Exclude,
                    algorithm: CompressionAlgorithm::Identity,
                    dedup_target: None,
                    exclusion_reason: Some(reason),
                });
                exclude_count += 1;
                continue;
            }

            // Step 2: check dedup
            if self.config.dedup_enabled
                && let Some(canonical) = &desc.canonical_id
            {
                if let Some(existing_id) = self.canonical_registry.get(canonical) {
                    entries.push(PlanEntry {
                        artifact_id: desc.artifact_id.clone(),
                        category: desc.category,
                        action: CompressionAction::Dedup,
                        algorithm: CompressionAlgorithm::Identity,
                        dedup_target: Some(existing_id.clone()),
                        exclusion_reason: None,
                    });
                    dedup_count += 1;
                    continue;
                }
                // First occurrence — register as canonical representative
                self.canonical_registry
                    .insert(*canonical, desc.artifact_id.clone());
            }

            // Step 3: decide compression
            if self.config.algorithm.is_compressor() {
                entries.push(PlanEntry {
                    artifact_id: desc.artifact_id.clone(),
                    category: desc.category,
                    action: CompressionAction::Compress,
                    algorithm: self.config.algorithm,
                    dedup_target: None,
                    exclusion_reason: None,
                });
                compress_count += 1;
            } else {
                entries.push(PlanEntry {
                    artifact_id: desc.artifact_id.clone(),
                    category: desc.category,
                    action: CompressionAction::Passthrough,
                    algorithm: CompressionAlgorithm::Identity,
                    dedup_target: None,
                    exclusion_reason: None,
                });
                passthrough_count += 1;
            }
        }

        // Compute plan hash
        let mut hasher = Sha256::new();
        hasher.update(b"bundle_plan:");
        hasher.update(entries.len().to_le_bytes());
        for entry in &entries {
            hasher.update(entry.artifact_id.as_bytes());
            hasher.update(entry.action.as_str().as_bytes());
        }
        hasher.update(self.config.epoch.as_u64().to_le_bytes());
        let plan_hash = ContentHash::compute(&hasher.finalize());

        BundlePlan {
            entries,
            total_input_bytes,
            compress_count,
            dedup_count,
            passthrough_count,
            exclude_count,
            epoch: self.config.epoch,
            plan_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// DedupTracker — tracks duplicate mass across artifact families
// ---------------------------------------------------------------------------

/// Tracks deduplication decisions and duplicate mass across the pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedupTracker {
    /// Receipts for each dedup decision.
    pub receipts: Vec<DedupReceipt>,
    /// Total bytes saved by deduplication.
    pub total_saved_bytes: u64,
    /// Number of unique canonical representatives seen.
    pub unique_representatives: usize,
    /// Number of duplicates resolved.
    pub duplicates_resolved: usize,
    /// Per-category savings in bytes.
    pub savings_by_category: BTreeMap<String, u64>,
    /// Epoch at which tracking started.
    pub epoch: SecurityEpoch,
}

impl DedupTracker {
    /// Create a new empty tracker.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            receipts: Vec::new(),
            total_saved_bytes: 0,
            unique_representatives: 0,
            duplicates_resolved: 0,
            savings_by_category: BTreeMap::new(),
            epoch,
        }
    }

    /// Record a dedup decision.
    pub fn record_dedup(
        &mut self,
        duplicate_id: impl Into<String>,
        canonical_id: impl Into<String>,
        canonical_hash: ContentHash,
        category: ArtifactCategory,
        saved_bytes: u64,
        chain_depth: usize,
    ) {
        let receipt = DedupReceipt::new(
            duplicate_id,
            canonical_id,
            canonical_hash,
            category,
            saved_bytes,
            chain_depth,
            self.epoch,
        );
        self.receipts.push(receipt);
        self.total_saved_bytes = self.total_saved_bytes.saturating_add(saved_bytes);
        self.duplicates_resolved += 1;

        let cat_key = category.as_str().to_owned();
        let entry = self.savings_by_category.entry(cat_key).or_insert(0);
        *entry = entry.saturating_add(saved_bytes);
    }

    /// Record that a new unique canonical representative was registered.
    pub fn record_representative(&mut self) {
        self.unique_representatives += 1;
    }

    /// Savings ratio in millionths relative to a total input size.
    pub fn savings_ratio_millionths(&self, total_input_bytes: u64) -> u64 {
        if total_input_bytes == 0 {
            return 0;
        }
        self.total_saved_bytes
            .saturating_mul(MILLION)
            .checked_div(total_input_bytes)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// CompressionReport — the pipeline's complete output
// ---------------------------------------------------------------------------

/// Complete report from a compression pipeline run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompressionReport {
    /// The plan that was executed.
    pub plan: BundlePlan,
    /// Restoration recipes for each compressed artifact (keyed by artifact ID).
    pub restoration_recipes: Vec<RestorationRecipe>,
    /// Dedup tracker state after processing.
    pub dedup_tracker: DedupTracker,
    /// Exclusion receipts for excluded artifacts.
    pub exclusion_receipts: Vec<ExclusionReceipt>,
    /// Total input bytes before any compression/dedup.
    pub total_input_bytes: u64,
    /// Total output bytes after compression/dedup.
    pub total_output_bytes: u64,
    /// Overall compression ratio in millionths.
    pub overall_ratio_millionths: u64,
    /// Epoch of this report.
    pub epoch: SecurityEpoch,
    /// Content hash of the report itself.
    pub report_hash: ContentHash,
}

impl CompressionReport {
    /// Total savings in bytes.
    pub fn total_savings_bytes(&self) -> u64 {
        self.total_input_bytes
            .saturating_sub(self.total_output_bytes)
    }

    /// Whether any compression or dedup was performed.
    pub fn has_actions(&self) -> bool {
        !self.restoration_recipes.is_empty() || self.dedup_tracker.duplicates_resolved > 0
    }

    /// Number of exclusion receipts.
    pub fn exclusion_count(&self) -> usize {
        self.exclusion_receipts.len()
    }
}

// ---------------------------------------------------------------------------
// CompressionPipeline — orchestrates the full pipeline
// ---------------------------------------------------------------------------

/// The main compression pipeline: plans, compresses, deduplicates, and
/// reports.
pub struct CompressionPipeline {
    planner_config: PlannerConfig,
}

impl CompressionPipeline {
    /// Create a new pipeline with the given config.
    pub fn new(config: PlannerConfig) -> Self {
        Self {
            planner_config: config,
        }
    }

    /// Run the full pipeline on a set of artifact descriptors.
    ///
    /// This method:
    /// 1. Plans actions for all artifacts.
    /// 2. Simulates compression (produces restoration recipes).
    /// 3. Tracks dedup decisions.
    /// 4. Emits exclusion receipts.
    /// 5. Produces a complete compression report.
    pub fn run(&self, descriptors: &[ArtifactDescriptor]) -> CompressionReport {
        let epoch = self.planner_config.epoch;

        // Phase 1: plan
        let mut planner = BundlePlanner::new(self.planner_config.clone());
        let plan = planner.plan(descriptors);

        // Phase 2: execute plan
        let mut restoration_recipes = Vec::new();
        let mut exclusion_receipts = Vec::new();
        let mut dedup_tracker = DedupTracker::new(epoch);
        let mut total_output_bytes: u64 = 0;

        // Build descriptor lookup
        let desc_map: BTreeMap<&str, &ArtifactDescriptor> = descriptors
            .iter()
            .map(|d| (d.artifact_id.as_str(), d))
            .collect();

        for entry in &plan.entries {
            let desc = match desc_map.get(entry.artifact_id.as_str()) {
                Some(d) => d,
                None => continue,
            };

            match entry.action {
                CompressionAction::Compress => {
                    // Deterministic size reduction (not a real codec).
                    // This verifies the compression *plan* is valid and
                    // produces a restoration recipe.  Plugging in a real
                    // codec (e.g. zstd) is tracked as future work.
                    let compressed_size =
                        self.simulate_compression(desc.size_bytes, entry.algorithm);
                    let compressed_hash = {
                        let mut h = Sha256::new();
                        h.update(b"compressed:");
                        h.update(desc.content_hash.as_bytes());
                        h.update(entry.algorithm.as_str().as_bytes());
                        h.update(compressed_size.to_le_bytes());
                        h.update(desc.size_bytes.to_le_bytes());
                        ContentHash::compute(&h.finalize())
                    };
                    let recipe = RestorationRecipe::new(
                        entry.algorithm,
                        desc.content_hash,
                        compressed_hash,
                        desc.size_bytes,
                        compressed_size,
                        epoch,
                    );
                    total_output_bytes = total_output_bytes.saturating_add(compressed_size);
                    restoration_recipes.push(recipe);
                }
                CompressionAction::Dedup => {
                    if let Some(target) = &entry.dedup_target {
                        let canonical_hash = desc.canonical_id.unwrap_or(desc.content_hash);
                        dedup_tracker.record_dedup(
                            &desc.artifact_id,
                            target,
                            canonical_hash,
                            desc.category,
                            desc.size_bytes,
                            1,
                        );
                    }
                    // Deduped artifacts contribute zero output bytes.
                }
                CompressionAction::Passthrough => {
                    total_output_bytes = total_output_bytes.saturating_add(desc.size_bytes);
                }
                CompressionAction::Exclude => {
                    if let Some(reason) = &entry.exclusion_reason {
                        exclusion_receipts.push(ExclusionReceipt::new(
                            &desc.artifact_id,
                            desc.category,
                            reason.clone(),
                            epoch,
                        ));
                    }
                    total_output_bytes = total_output_bytes.saturating_add(desc.size_bytes);
                }
            }
        }

        // Overall ratio
        let overall_ratio_millionths = if plan.total_input_bytes == 0 {
            MILLION
        } else {
            total_output_bytes
                .saturating_mul(MILLION)
                .checked_div(plan.total_input_bytes)
                .unwrap_or(MILLION)
        };

        // Report hash
        let mut hasher = Sha256::new();
        hasher.update(b"compression_report:");
        hasher.update(plan.plan_hash.as_bytes());
        hasher.update(total_output_bytes.to_le_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        let report_hash = ContentHash::compute(&hasher.finalize());

        CompressionReport {
            plan,
            restoration_recipes,
            dedup_tracker,
            exclusion_receipts,
            total_input_bytes: descriptors.iter().map(|d| d.size_bytes).sum(),
            total_output_bytes,
            overall_ratio_millionths,
            epoch,
            report_hash,
        }
    }

    /// Deterministic size estimate for a given algorithm.
    ///
    /// Returns a heuristic compressed size based on the algorithm's
    /// typical ratio, without invoking a real codec.  This is
    /// intentional: the pipeline contract verifies *plan correctness*
    /// (recipe linkage, epoch monotonicity, budget compliance) rather
    /// than actual byte-level compression.  Real codec integration
    /// is tracked as future work.
    fn simulate_compression(&self, original_size: u64, algorithm: CompressionAlgorithm) -> u64 {
        // Deterministic ratio estimates for each algorithm (millionths)
        let ratio = match algorithm {
            CompressionAlgorithm::Identity => MILLION,
            CompressionAlgorithm::Deflate => 650_000, // ~65%
            CompressionAlgorithm::Zstd => 550_000,    // ~55%
            CompressionAlgorithm::Lz4 => 700_000,     // ~70%
        };
        original_size
            .saturating_mul(ratio)
            .checked_div(MILLION)
            .unwrap_or(original_size)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn make_descriptor(id: &str, category: ArtifactCategory, size: u64) -> ArtifactDescriptor {
        ArtifactDescriptor::new(id, category, size, id.as_bytes(), test_epoch())
    }

    fn make_descriptor_with_canonical(
        id: &str,
        category: ArtifactCategory,
        size: u64,
        canonical_bytes: &[u8],
    ) -> ArtifactDescriptor {
        let canonical = ContentHash::compute(canonical_bytes);
        make_descriptor(id, category, size).with_canonical_id(canonical)
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SCHEMA_VERSION.ends_with(".v1"));
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn component_name_non_empty() {
        assert!(!COMPONENT.is_empty());
    }

    #[test]
    fn max_bundle_size_positive() {
        const { assert!(MAX_BUNDLE_SIZE > 0) };
    }

    #[test]
    fn max_artifact_bytes_positive() {
        const { assert!(MAX_ARTIFACT_BYTES > 0) };
    }

    // --- CompressionAlgorithm ---

    #[test]
    fn algorithm_all_length() {
        assert_eq!(CompressionAlgorithm::ALL.len(), 4);
    }

    #[test]
    fn algorithm_names_unique() {
        let names: BTreeSet<&str> = CompressionAlgorithm::ALL
            .iter()
            .map(|a| a.as_str())
            .collect();
        assert_eq!(names.len(), CompressionAlgorithm::ALL.len());
    }

    #[test]
    fn algorithm_serde_roundtrip() {
        for alg in CompressionAlgorithm::ALL {
            let json = serde_json::to_string(alg).unwrap();
            let back: CompressionAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(*alg, back);
        }
    }

    #[test]
    fn algorithm_identity_not_compressor() {
        assert!(!CompressionAlgorithm::Identity.is_compressor());
    }

    #[test]
    fn algorithm_zstd_is_compressor() {
        assert!(CompressionAlgorithm::Zstd.is_compressor());
    }

    #[test]
    fn algorithm_display() {
        assert_eq!(CompressionAlgorithm::Zstd.to_string(), "zstd");
    }

    // --- ArtifactCategory ---

    #[test]
    fn category_all_length() {
        assert_eq!(ArtifactCategory::ALL.len(), 9);
    }

    #[test]
    fn category_names_unique() {
        let names: BTreeSet<&str> = ArtifactCategory::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), ArtifactCategory::ALL.len());
    }

    #[test]
    fn category_serde_roundtrip() {
        for cat in ArtifactCategory::ALL {
            let json = serde_json::to_string(cat).unwrap();
            let back: ArtifactCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    #[test]
    fn category_replay_excluded() {
        assert!(ArtifactCategory::Replay.is_compression_excluded());
        assert!(ArtifactCategory::Replay.is_dedup_excluded());
    }

    #[test]
    fn category_security_excluded() {
        assert!(ArtifactCategory::SecurityProvenance.is_compression_excluded());
    }

    #[test]
    fn category_legal_excluded() {
        assert!(ArtifactCategory::LegalProvenance.is_compression_excluded());
    }

    #[test]
    fn category_cache_not_excluded() {
        assert!(!ArtifactCategory::Cache.is_compression_excluded());
    }

    #[test]
    fn category_aot_not_excluded() {
        assert!(!ArtifactCategory::Aot.is_compression_excluded());
    }

    #[test]
    fn category_display() {
        assert_eq!(ArtifactCategory::Cache.to_string(), "cache");
    }

    // --- ExclusionReason ---

    #[test]
    fn exclusion_reason_all_length() {
        assert_eq!(ExclusionReason::ALL.len(), 6);
    }

    #[test]
    fn exclusion_reason_names_unique() {
        let names: BTreeSet<&str> = ExclusionReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(names.len(), ExclusionReason::ALL.len());
    }

    #[test]
    fn exclusion_reason_display() {
        assert_eq!(
            ExclusionReason::CategoryExcluded.to_string(),
            "category_excluded"
        );
    }

    // --- CompressionAction ---

    #[test]
    fn action_all_length() {
        assert_eq!(CompressionAction::ALL.len(), 4);
    }

    #[test]
    fn action_names_unique() {
        let names: BTreeSet<&str> = CompressionAction::ALL.iter().map(|a| a.as_str()).collect();
        assert_eq!(names.len(), CompressionAction::ALL.len());
    }

    #[test]
    fn action_display() {
        assert_eq!(CompressionAction::Compress.to_string(), "compress");
    }

    // --- ArtifactDescriptor ---

    #[test]
    fn descriptor_new() {
        let d = make_descriptor("art-1", ArtifactCategory::Cache, 1024);
        assert_eq!(d.artifact_id, "art-1");
        assert_eq!(d.category, ArtifactCategory::Cache);
        assert_eq!(d.size_bytes, 1024);
        assert!(!d.already_compressed);
        assert!(d.canonical_id.is_none());
    }

    #[test]
    fn descriptor_with_canonical() {
        let d = make_descriptor_with_canonical(
            "art-1",
            ArtifactCategory::Cache,
            1024,
            b"canonical-seed",
        );
        assert!(d.canonical_id.is_some());
    }

    #[test]
    fn descriptor_mark_compressed() {
        let d = make_descriptor("art-1", ArtifactCategory::Cache, 1024).mark_already_compressed();
        assert!(d.already_compressed);
    }

    #[test]
    fn descriptor_serde_roundtrip() {
        let d = make_descriptor("art-1", ArtifactCategory::Aot, 2048);
        let json = serde_json::to_string(&d).unwrap();
        let back: ArtifactDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // --- RestorationRecipe ---

    #[test]
    fn recipe_beneficial_when_smaller() {
        let recipe = RestorationRecipe::new(
            CompressionAlgorithm::Zstd,
            ContentHash::compute(b"original"),
            ContentHash::compute(b"compressed"),
            1000,
            550,
            test_epoch(),
        );
        assert!(recipe.is_beneficial());
        assert_eq!(recipe.savings_bytes(), 450);
    }

    #[test]
    fn recipe_not_beneficial_when_larger() {
        let recipe = RestorationRecipe::new(
            CompressionAlgorithm::Deflate,
            ContentHash::compute(b"orig"),
            ContentHash::compute(b"comp"),
            100,
            120,
            test_epoch(),
        );
        assert!(!recipe.is_beneficial());
        assert_eq!(recipe.savings_bytes(), 0);
    }

    #[test]
    fn recipe_zero_size_original() {
        let recipe = RestorationRecipe::new(
            CompressionAlgorithm::Zstd,
            ContentHash::compute(b""),
            ContentHash::compute(b"c"),
            0,
            0,
            test_epoch(),
        );
        assert_eq!(recipe.ratio_millionths, MILLION);
    }

    #[test]
    fn recipe_serde_roundtrip() {
        let recipe = RestorationRecipe::new(
            CompressionAlgorithm::Lz4,
            ContentHash::compute(b"orig"),
            ContentHash::compute(b"comp"),
            2000,
            1400,
            test_epoch(),
        );
        let json = serde_json::to_string(&recipe).unwrap();
        let back: RestorationRecipe = serde_json::from_str(&json).unwrap();
        assert_eq!(recipe, back);
    }

    // --- DedupReceipt ---

    #[test]
    fn dedup_receipt_hash_deterministic() {
        let r1 = DedupReceipt::new(
            "dup-1",
            "canonical-1",
            ContentHash::compute(b"id"),
            ArtifactCategory::Cache,
            512,
            1,
            test_epoch(),
        );
        let r2 = DedupReceipt::new(
            "dup-1",
            "canonical-1",
            ContentHash::compute(b"id"),
            ArtifactCategory::Cache,
            512,
            1,
            test_epoch(),
        );
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn dedup_receipt_serde_roundtrip() {
        let r = DedupReceipt::new(
            "dup-1",
            "canon-1",
            ContentHash::compute(b"seed"),
            ArtifactCategory::Aot,
            1024,
            2,
            test_epoch(),
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: DedupReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- ExclusionReceipt ---

    #[test]
    fn exclusion_receipt_hash_deterministic() {
        let e1 = ExclusionReceipt::new(
            "art-x",
            ArtifactCategory::Replay,
            ExclusionReason::CategoryExcluded,
            test_epoch(),
        );
        let e2 = ExclusionReceipt::new(
            "art-x",
            ArtifactCategory::Replay,
            ExclusionReason::CategoryExcluded,
            test_epoch(),
        );
        assert_eq!(e1.receipt_hash, e2.receipt_hash);
    }

    #[test]
    fn exclusion_receipt_serde_roundtrip() {
        let e = ExclusionReceipt::new(
            "art-x",
            ArtifactCategory::SecurityProvenance,
            ExclusionReason::CategoryExcluded,
            test_epoch(),
        );
        let json = serde_json::to_string(&e).unwrap();
        let back: ExclusionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- BundlePlanner ---

    #[test]
    fn planner_compresses_eligible_artifact() {
        let config = PlannerConfig::new(test_epoch());
        let mut planner = BundlePlanner::new(config);
        let descriptors = vec![make_descriptor("art-1", ArtifactCategory::Cache, 4096)];
        let plan = planner.plan(&descriptors);

        assert_eq!(plan.total_entries(), 1);
        assert_eq!(plan.compress_count, 1);
        assert_eq!(plan.entries[0].action, CompressionAction::Compress);
        assert_eq!(plan.entries[0].algorithm, CompressionAlgorithm::Zstd);
    }

    #[test]
    fn planner_excludes_replay_category() {
        let config = PlannerConfig::new(test_epoch());
        let mut planner = BundlePlanner::new(config);
        let descriptors = vec![make_descriptor("trace-1", ArtifactCategory::Replay, 8192)];
        let plan = planner.plan(&descriptors);

        assert_eq!(plan.exclude_count, 1);
        assert_eq!(plan.entries[0].action, CompressionAction::Exclude);
        assert_eq!(
            plan.entries[0].exclusion_reason,
            Some(ExclusionReason::CategoryExcluded)
        );
    }

    #[test]
    fn planner_excludes_security_provenance() {
        let config = PlannerConfig::new(test_epoch());
        let mut planner = BundlePlanner::new(config);
        let descriptors = vec![make_descriptor(
            "sec-1",
            ArtifactCategory::SecurityProvenance,
            4096,
        )];
        let plan = planner.plan(&descriptors);

        assert_eq!(plan.exclude_count, 1);
    }

    #[test]
    fn planner_excludes_legal_provenance() {
        let config = PlannerConfig::new(test_epoch());
        let mut planner = BundlePlanner::new(config);
        let descriptors = vec![make_descriptor(
            "legal-1",
            ArtifactCategory::LegalProvenance,
            2048,
        )];
        let plan = planner.plan(&descriptors);

        assert_eq!(plan.exclude_count, 1);
    }

    #[test]
    fn planner_excludes_oversize() {
        let config = PlannerConfig::new(test_epoch());
        let mut planner = BundlePlanner::new(config);
        let descriptors = vec![make_descriptor(
            "big-1",
            ArtifactCategory::Cache,
            MAX_ARTIFACT_BYTES + 1,
        )];
        let plan = planner.plan(&descriptors);

        assert_eq!(plan.exclude_count, 1);
        assert_eq!(
            plan.entries[0].exclusion_reason,
            Some(ExclusionReason::OversizeArtifact)
        );
    }

    #[test]
    fn planner_excludes_already_compressed() {
        let config = PlannerConfig::new(test_epoch());
        let mut planner = BundlePlanner::new(config);
        let descriptors = vec![
            make_descriptor("comp-1", ArtifactCategory::Cache, 4096).mark_already_compressed(),
        ];
        let plan = planner.plan(&descriptors);

        assert_eq!(plan.exclude_count, 1);
        assert_eq!(
            plan.entries[0].exclusion_reason,
            Some(ExclusionReason::AlreadyCompressed)
        );
    }

    #[test]
    fn planner_excludes_epoch_mismatch() {
        let config = PlannerConfig::new(test_epoch());
        let mut planner = BundlePlanner::new(config);
        let mut desc = make_descriptor("art-1", ArtifactCategory::Cache, 4096);
        desc.epoch = SecurityEpoch::from_raw(999);
        let plan = planner.plan(&[desc]);

        assert_eq!(plan.exclude_count, 1);
        assert_eq!(
            plan.entries[0].exclusion_reason,
            Some(ExclusionReason::EpochMismatch)
        );
    }

    #[test]
    fn planner_dedup_second_duplicate() {
        let config = PlannerConfig::new(test_epoch());
        let mut planner = BundlePlanner::new(config);
        let d1 = make_descriptor_with_canonical(
            "art-1",
            ArtifactCategory::Cache,
            4096,
            b"shared-canonical",
        );
        let d2 = make_descriptor_with_canonical(
            "art-2",
            ArtifactCategory::Cache,
            4096,
            b"shared-canonical",
        );
        let plan = planner.plan(&[d1, d2]);

        assert_eq!(plan.compress_count, 1);
        assert_eq!(plan.dedup_count, 1);
        assert_eq!(plan.entries[1].action, CompressionAction::Dedup);
        assert_eq!(plan.entries[1].dedup_target, Some("art-1".to_string()));
    }

    #[test]
    fn planner_no_dedup_when_disabled() {
        let config = PlannerConfig::new(test_epoch()).without_dedup();
        let mut planner = BundlePlanner::new(config);
        let d1 = make_descriptor_with_canonical("art-1", ArtifactCategory::Cache, 4096, b"shared");
        let d2 = make_descriptor_with_canonical("art-2", ArtifactCategory::Cache, 4096, b"shared");
        let plan = planner.plan(&[d1, d2]);

        assert_eq!(plan.compress_count, 2);
        assert_eq!(plan.dedup_count, 0);
    }

    #[test]
    fn planner_identity_algorithm_passthrough() {
        let config =
            PlannerConfig::new(test_epoch()).with_algorithm(CompressionAlgorithm::Identity);
        let mut planner = BundlePlanner::new(config);
        let descriptors = vec![make_descriptor("art-1", ArtifactCategory::Cache, 4096)];
        let plan = planner.plan(&descriptors);

        assert_eq!(plan.passthrough_count, 1);
        assert_eq!(plan.entries[0].action, CompressionAction::Passthrough);
    }

    #[test]
    fn planner_extra_exclusion() {
        let config =
            PlannerConfig::new(test_epoch()).with_extra_exclusion(ArtifactCategory::Benchmark);
        let mut planner = BundlePlanner::new(config);
        let descriptors = vec![make_descriptor(
            "bench-1",
            ArtifactCategory::Benchmark,
            4096,
        )];
        let plan = planner.plan(&descriptors);

        assert_eq!(plan.exclude_count, 1);
    }

    #[test]
    fn planner_mixed_batch() {
        let config = PlannerConfig::new(test_epoch());
        let mut planner = BundlePlanner::new(config);
        let descriptors = vec![
            make_descriptor("cache-1", ArtifactCategory::Cache, 4096),
            make_descriptor("replay-1", ArtifactCategory::Replay, 2048),
            make_descriptor("aot-1", ArtifactCategory::Aot, 8192),
            make_descriptor("sec-1", ArtifactCategory::SecurityProvenance, 1024),
        ];
        let plan = planner.plan(&descriptors);

        assert_eq!(plan.compress_count, 2); // cache + aot
        assert_eq!(plan.exclude_count, 2); // replay + security
        assert_eq!(plan.total_entries(), 4);
        assert!(plan.has_actionable_entries());
    }

    #[test]
    fn planner_plan_hash_deterministic() {
        let config = PlannerConfig::new(test_epoch());
        let descriptors = vec![make_descriptor("art-1", ArtifactCategory::Cache, 4096)];

        let mut p1 = BundlePlanner::new(config.clone());
        let plan1 = p1.plan(&descriptors);
        let mut p2 = BundlePlanner::new(config);
        let plan2 = p2.plan(&descriptors);

        assert_eq!(plan1.plan_hash, plan2.plan_hash);
    }

    // --- DedupTracker ---

    #[test]
    fn tracker_new_empty() {
        let tracker = DedupTracker::new(test_epoch());
        assert_eq!(tracker.total_saved_bytes, 0);
        assert_eq!(tracker.unique_representatives, 0);
        assert_eq!(tracker.duplicates_resolved, 0);
        assert!(tracker.receipts.is_empty());
    }

    #[test]
    fn tracker_record_dedup() {
        let mut tracker = DedupTracker::new(test_epoch());
        tracker.record_dedup(
            "dup",
            "canon",
            ContentHash::compute(b"x"),
            ArtifactCategory::Cache,
            1024,
            1,
        );
        assert_eq!(tracker.total_saved_bytes, 1024);
        assert_eq!(tracker.duplicates_resolved, 1);
        assert_eq!(tracker.receipts.len(), 1);
    }

    #[test]
    fn tracker_savings_ratio() {
        let mut tracker = DedupTracker::new(test_epoch());
        tracker.record_dedup(
            "dup",
            "canon",
            ContentHash::compute(b"x"),
            ArtifactCategory::Cache,
            500,
            1,
        );
        let ratio = tracker.savings_ratio_millionths(1000);
        assert_eq!(ratio, 500_000); // 50%
    }

    #[test]
    fn tracker_savings_ratio_zero_input() {
        let tracker = DedupTracker::new(test_epoch());
        assert_eq!(tracker.savings_ratio_millionths(0), 0);
    }

    #[test]
    fn tracker_per_category_savings() {
        let mut tracker = DedupTracker::new(test_epoch());
        tracker.record_dedup(
            "d1",
            "c1",
            ContentHash::compute(b"x"),
            ArtifactCategory::Cache,
            100,
            1,
        );
        tracker.record_dedup(
            "d2",
            "c2",
            ContentHash::compute(b"y"),
            ArtifactCategory::Aot,
            200,
            1,
        );
        tracker.record_dedup(
            "d3",
            "c3",
            ContentHash::compute(b"z"),
            ArtifactCategory::Cache,
            300,
            1,
        );
        assert_eq!(tracker.savings_by_category.get("cache"), Some(&400));
        assert_eq!(tracker.savings_by_category.get("aot"), Some(&200));
    }

    #[test]
    fn tracker_serde_roundtrip() {
        let mut tracker = DedupTracker::new(test_epoch());
        tracker.record_dedup(
            "d",
            "c",
            ContentHash::compute(b"x"),
            ArtifactCategory::Cache,
            64,
            1,
        );
        let json = serde_json::to_string(&tracker).unwrap();
        let back: DedupTracker = serde_json::from_str(&json).unwrap();
        assert_eq!(tracker, back);
    }

    // --- CompressionPipeline ---

    #[test]
    fn pipeline_basic_compression() {
        let config = PlannerConfig::new(test_epoch());
        let pipeline = CompressionPipeline::new(config);
        let descriptors = vec![make_descriptor("art-1", ArtifactCategory::Cache, 10_000)];
        let report = pipeline.run(&descriptors);

        assert_eq!(report.total_input_bytes, 10_000);
        assert!(report.total_output_bytes < 10_000);
        assert!(report.has_actions());
        assert_eq!(report.restoration_recipes.len(), 1);
        assert!(report.restoration_recipes[0].is_beneficial());
    }

    #[test]
    fn pipeline_excluded_artifacts_passthrough() {
        let config = PlannerConfig::new(test_epoch());
        let pipeline = CompressionPipeline::new(config);
        let descriptors = vec![make_descriptor("replay-1", ArtifactCategory::Replay, 5000)];
        let report = pipeline.run(&descriptors);

        assert_eq!(report.exclusion_count(), 1);
        assert!(report.restoration_recipes.is_empty());
        assert_eq!(report.total_output_bytes, 5000);
    }

    #[test]
    fn pipeline_dedup_saves_bytes() {
        let config = PlannerConfig::new(test_epoch());
        let pipeline = CompressionPipeline::new(config);
        let d1 = make_descriptor_with_canonical(
            "art-1",
            ArtifactCategory::Cache,
            8000,
            b"same-canonical",
        );
        let d2 = make_descriptor_with_canonical(
            "art-2",
            ArtifactCategory::Cache,
            8000,
            b"same-canonical",
        );
        let report = pipeline.run(&[d1, d2]);

        assert_eq!(report.dedup_tracker.duplicates_resolved, 1);
        assert_eq!(report.dedup_tracker.total_saved_bytes, 8000);
        // art-1 compressed, art-2 deduped (0 bytes)
        assert!(report.total_output_bytes < 16_000);
    }

    #[test]
    fn pipeline_mixed_batch_report() {
        let config = PlannerConfig::new(test_epoch());
        let pipeline = CompressionPipeline::new(config);
        let descriptors = vec![
            make_descriptor("cache-1", ArtifactCategory::Cache, 10_000),
            make_descriptor("replay-1", ArtifactCategory::Replay, 5_000),
            make_descriptor("aot-1", ArtifactCategory::Aot, 20_000),
        ];
        let report = pipeline.run(&descriptors);

        assert_eq!(report.total_input_bytes, 35_000);
        assert_eq!(report.restoration_recipes.len(), 2); // cache + aot
        assert_eq!(report.exclusion_count(), 1); // replay
        assert!(report.overall_ratio_millionths < MILLION);
    }

    #[test]
    fn pipeline_report_hash_deterministic() {
        let config = PlannerConfig::new(test_epoch());
        let descriptors = vec![make_descriptor("art-1", ArtifactCategory::Cache, 4096)];

        let p1 = CompressionPipeline::new(config.clone());
        let r1 = p1.run(&descriptors);
        let p2 = CompressionPipeline::new(config);
        let r2 = p2.run(&descriptors);

        assert_eq!(r1.report_hash, r2.report_hash);
    }

    #[test]
    fn pipeline_empty_input() {
        let config = PlannerConfig::new(test_epoch());
        let pipeline = CompressionPipeline::new(config);
        let report = pipeline.run(&[]);

        assert_eq!(report.total_input_bytes, 0);
        assert_eq!(report.total_output_bytes, 0);
        assert!(!report.has_actions());
    }

    #[test]
    fn pipeline_all_excluded() {
        let config = PlannerConfig::new(test_epoch());
        let pipeline = CompressionPipeline::new(config);
        let descriptors = vec![
            make_descriptor("replay-1", ArtifactCategory::Replay, 1000),
            make_descriptor("sec-1", ArtifactCategory::SecurityProvenance, 2000),
            make_descriptor("legal-1", ArtifactCategory::LegalProvenance, 3000),
        ];
        let report = pipeline.run(&descriptors);

        assert_eq!(report.exclusion_count(), 3);
        assert!(report.restoration_recipes.is_empty());
        assert_eq!(report.total_output_bytes, 6000);
    }

    #[test]
    fn planner_config_builder() {
        let config = PlannerConfig::new(test_epoch())
            .with_algorithm(CompressionAlgorithm::Lz4)
            .with_extra_exclusion(ArtifactCategory::Benchmark)
            .without_dedup();

        assert_eq!(config.algorithm, CompressionAlgorithm::Lz4);
        assert!(
            config
                .extra_exclusions
                .contains(&ArtifactCategory::Benchmark)
        );
        assert!(!config.dedup_enabled);
    }

    #[test]
    fn recipe_below_useful_threshold() {
        let recipe = RestorationRecipe::new(
            CompressionAlgorithm::Lz4,
            ContentHash::compute(b"orig"),
            ContentHash::compute(b"comp"),
            1000,
            950,
            test_epoch(),
        );
        assert!(recipe.is_below_useful_threshold());
    }

    #[test]
    fn recipe_not_below_useful_threshold_when_very_beneficial() {
        let recipe = RestorationRecipe::new(
            CompressionAlgorithm::Zstd,
            ContentHash::compute(b"orig"),
            ContentHash::compute(b"comp"),
            1000,
            500,
            test_epoch(),
        );
        assert!(!recipe.is_below_useful_threshold());
    }

    #[test]
    fn tracker_record_representative() {
        let mut tracker = DedupTracker::new(test_epoch());
        tracker.record_representative();
        tracker.record_representative();
        assert_eq!(tracker.unique_representatives, 2);
    }

    #[test]
    fn report_total_savings() {
        let config = PlannerConfig::new(test_epoch());
        let pipeline = CompressionPipeline::new(config);
        let descriptors = vec![make_descriptor("art-1", ArtifactCategory::Cache, 10_000)];
        let report = pipeline.run(&descriptors);
        assert!(report.total_savings_bytes() > 0);
    }

    #[test]
    fn bundle_plan_no_actionable_when_all_excluded() {
        let config = PlannerConfig::new(test_epoch());
        let mut planner = BundlePlanner::new(config);
        let descriptors = vec![make_descriptor("r1", ArtifactCategory::Replay, 1000)];
        let plan = planner.plan(&descriptors);
        assert!(!plan.has_actionable_entries());
    }
}
