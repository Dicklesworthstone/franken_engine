//! Benchmark-board coverage saturation and distributional representativeness gate.
//!
//! Bead: bd-1lsy.8.5.5 [RGC-705E]
//!
//! Proves that the declared benchmark board is not a narrow cherry-picked slice
//! by enforcing a corpus-coverage and distributional-representativeness gate
//! across branch-heavy, vectorizable, proof-specialized, native-addon,
//! hostcall-boundary, startup-image, metadata-locality, observability-sensitive,
//! and resource-bounded workload families.
//!
//! # Design
//!
//! - `WorkloadFamily`: 12-variant enum covering all engine workload families.
//! - `CoverageStatus`: four-valued coverage assessment per family.
//! - `RepresentativenessMetric`: how distributional representativeness is measured.
//! - `BenchmarkEntry`: a single benchmark with family, complexity, feature tags.
//! - `FamilyCoverage`: per-family coverage statistics and saturation score.
//! - `SaturationConfig`: thresholds for the gate evaluation.
//! - `SaturationBoard`: the full board registry with add/evaluate methods.
//! - `SaturationVerdict`: five-valued outcome of gate evaluation.
//! - `SaturationReport`: artifact-rich report with per-family breakdown.
//! - `SaturationGate`: top-level gate evaluating the board.
//! - `DecisionReceipt`: hash-chained receipt for audit trail.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-705E]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.benchmark-coverage-saturation.v1";

/// Component name.
pub const COMPONENT: &str = "benchmark_coverage_saturation";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.8.5.5";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-705E";

/// One in fixed-point millionths.
const MILLIONTHS: u64 = 1_000_000;

/// Default minimum entries per family.
pub const DEFAULT_MIN_ENTRIES_PER_FAMILY: u64 = 3;

/// Default minimum families that must be covered.
pub const DEFAULT_MIN_FAMILIES_COVERED: u64 = 8;

/// Default minimum saturation score in millionths.
pub const DEFAULT_MIN_SATURATION_SCORE_MILLIONTHS: u64 = 700_000;

/// Default minimum feature diversity per family.
pub const DEFAULT_MIN_FEATURE_DIVERSITY: u64 = 2;

/// Maximum entries per board.
pub const MAX_ENTRIES_PER_BOARD: usize = 4096;

/// Maximum feature tags per entry.
pub const MAX_FEATURE_TAGS_PER_ENTRY: usize = 64;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn append_str(buf: &mut Vec<u8>, val: &str) {
    let bytes = val.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn compute_digest(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// WorkloadFamily
// ---------------------------------------------------------------------------

/// Workload family classification for benchmark board entries.
///
/// Each family represents a distinct dimension of engine behavior that must
/// be represented on the benchmark board to prevent cherry-picking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadFamily {
    /// Branch-heavy control flow (deeply nested if/else, switch, try/catch).
    BranchHeavy,
    /// Vectorizable numeric workloads (typed arrays, SIMD-friendly loops).
    Vectorizable,
    /// Proof-specialized workloads (governance, certificate, evidence).
    ProofSpecialized,
    /// Native addon boundary crossing (N-API, FFI, handle discipline).
    NativeAddon,
    /// Hostcall boundary workloads (session protocol, batch transport).
    HostcallBoundary,
    /// Startup image workloads (cold start, snapshot, AOT compilation).
    StartupImage,
    /// Metadata locality workloads (substrate, inline caches, shapes).
    MetadataLocality,
    /// Observability-sensitive workloads (telemetry, tracing, profiling).
    ObservabilitySensitive,
    /// Resource-bounded workloads (memory pressure, GC, budget constraints).
    ResourceBounded,
    /// String and regexp heavy workloads (parsing, matching, normalization).
    StringRegexp,
    /// React lifecycle workloads (SSR, hydration, reconciliation).
    ReactLifecycle,
    /// Async iterator workloads (for-await, generator, stream processing).
    AsyncIterator,
}

impl WorkloadFamily {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::BranchHeavy,
        Self::Vectorizable,
        Self::ProofSpecialized,
        Self::NativeAddon,
        Self::HostcallBoundary,
        Self::StartupImage,
        Self::MetadataLocality,
        Self::ObservabilitySensitive,
        Self::ResourceBounded,
        Self::StringRegexp,
        Self::ReactLifecycle,
        Self::AsyncIterator,
    ];

    /// Total number of defined families.
    pub const COUNT: usize = 12;

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BranchHeavy => "branch_heavy",
            Self::Vectorizable => "vectorizable",
            Self::ProofSpecialized => "proof_specialized",
            Self::NativeAddon => "native_addon",
            Self::HostcallBoundary => "hostcall_boundary",
            Self::StartupImage => "startup_image",
            Self::MetadataLocality => "metadata_locality",
            Self::ObservabilitySensitive => "observability_sensitive",
            Self::ResourceBounded => "resource_bounded",
            Self::StringRegexp => "string_regexp",
            Self::ReactLifecycle => "react_lifecycle",
            Self::AsyncIterator => "async_iterator",
        }
    }

    /// Whether this family is considered performance-critical (higher weight
    /// in saturation scoring).
    pub const fn is_performance_critical(self) -> bool {
        matches!(
            self,
            Self::BranchHeavy
                | Self::Vectorizable
                | Self::StartupImage
                | Self::MetadataLocality
                | Self::StringRegexp
        )
    }
}

impl fmt::Display for WorkloadFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CoverageStatus
// ---------------------------------------------------------------------------

/// Per-family coverage assessment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    /// No benchmarks cover this family.
    Uncovered,
    /// Below the minimum entry threshold.
    Sparse,
    /// Meets the minimum threshold.
    Adequate,
    /// Exceeds the saturation target.
    Saturated,
}

impl CoverageStatus {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::Uncovered,
        Self::Sparse,
        Self::Adequate,
        Self::Saturated,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uncovered => "uncovered",
            Self::Sparse => "sparse",
            Self::Adequate => "adequate",
            Self::Saturated => "saturated",
        }
    }

    /// Whether this status is at least adequate.
    pub const fn is_acceptable(self) -> bool {
        matches!(self, Self::Adequate | Self::Saturated)
    }

    /// Whether this status blocks the gate.
    pub const fn blocks_gate(self) -> bool {
        matches!(self, Self::Uncovered | Self::Sparse)
    }
}

impl fmt::Display for CoverageStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RepresentativenessMetric
// ---------------------------------------------------------------------------

/// How distributional representativeness is measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RepresentativenessMetric {
    /// Ratio of covered families to total families.
    CorpusRatio,
    /// Shannon entropy of feature tags across entries.
    FeatureEntropy,
    /// Jaccard similarity between benchmark domain tags and target domain.
    DomainJaccardSimilarity,
    /// KL divergence of complexity histogram vs reference distribution.
    ComplexityHistogramKl,
}

impl RepresentativenessMetric {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::CorpusRatio,
        Self::FeatureEntropy,
        Self::DomainJaccardSimilarity,
        Self::ComplexityHistogramKl,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CorpusRatio => "corpus_ratio",
            Self::FeatureEntropy => "feature_entropy",
            Self::DomainJaccardSimilarity => "domain_jaccard_similarity",
            Self::ComplexityHistogramKl => "complexity_histogram_kl",
        }
    }
}

impl fmt::Display for RepresentativenessMetric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BenchmarkEntry
// ---------------------------------------------------------------------------

/// A single benchmark registered on the board.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkEntry {
    /// Unique benchmark name.
    pub name: String,
    /// Workload family this benchmark belongs to.
    pub family: WorkloadFamily,
    /// Complexity score (higher = more complex workload).
    pub complexity_score: u64,
    /// Feature tags describing the benchmark's characteristics.
    pub feature_tags: BTreeSet<String>,
    /// Content hash of the entry for integrity verification.
    pub entry_hash: ContentHash,
}

impl BenchmarkEntry {
    /// Create a new benchmark entry with computed hash.
    pub fn new(
        name: impl Into<String>,
        family: WorkloadFamily,
        complexity_score: u64,
        feature_tags: BTreeSet<String>,
    ) -> Self {
        let name = name.into();
        let mut buf = Vec::new();
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, &name);
        append_str(&mut buf, family.as_str());
        append_u64(&mut buf, complexity_score);
        for tag in &feature_tags {
            append_str(&mut buf, tag);
        }
        let entry_hash = compute_digest(&buf);
        Self {
            name,
            family,
            complexity_score,
            feature_tags,
            entry_hash,
        }
    }

    /// Recompute the hash and check if it matches the stored hash.
    pub fn verify_hash(&self) -> bool {
        let mut buf = Vec::new();
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, &self.name);
        append_str(&mut buf, self.family.as_str());
        append_u64(&mut buf, self.complexity_score);
        for tag in &self.feature_tags {
            append_str(&mut buf, tag);
        }
        compute_digest(&buf) == self.entry_hash
    }
}

impl fmt::Display for BenchmarkEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}[{}] complexity={} tags={}",
            self.name,
            self.family,
            self.complexity_score,
            self.feature_tags.len()
        )
    }
}

// ---------------------------------------------------------------------------
// FamilyCoverage
// ---------------------------------------------------------------------------

/// Coverage statistics for a single workload family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FamilyCoverage {
    /// Which family this coverage tracks.
    pub family: WorkloadFamily,
    /// Number of benchmark entries in this family.
    pub entry_count: u64,
    /// Sum of complexity scores across all entries.
    pub total_complexity: u64,
    /// Minimum complexity score seen.
    pub min_complexity: u64,
    /// Maximum complexity score seen.
    pub max_complexity: u64,
    /// Mean complexity in millionths: (total / count) * 1_000_000.
    pub mean_complexity_millionths: u64,
    /// Coverage status derived from entry count vs threshold.
    pub coverage_status: CoverageStatus,
    /// Number of unique feature tags across all entries in this family.
    pub feature_diversity: u64,
    /// Saturation score in millionths: a composite of entry count, complexity
    /// spread, and feature diversity.
    pub saturation_score_millionths: u64,
}

impl FamilyCoverage {
    /// Compute coverage for a family from a set of entries and config.
    pub fn compute(
        family: WorkloadFamily,
        entries: &[&BenchmarkEntry],
        config: &SaturationConfig,
    ) -> Self {
        if entries.is_empty() {
            return Self {
                family,
                entry_count: 0,
                total_complexity: 0,
                min_complexity: 0,
                max_complexity: 0,
                mean_complexity_millionths: 0,
                coverage_status: CoverageStatus::Uncovered,
                feature_diversity: 0,
                saturation_score_millionths: 0,
            };
        }

        let entry_count = entries.len() as u64;
        let total_complexity: u64 = entries.iter().map(|e| e.complexity_score).sum();
        let min_complexity = entries
            .iter()
            .map(|e| e.complexity_score)
            .min()
            .unwrap_or(0);
        let max_complexity = entries
            .iter()
            .map(|e| e.complexity_score)
            .max()
            .unwrap_or(0);
        let mean_complexity_millionths = total_complexity
            .saturating_mul(MILLIONTHS)
            .checked_div(entry_count)
            .unwrap_or(0);

        let mut all_tags = BTreeSet::new();
        for entry in entries {
            for tag in &entry.feature_tags {
                all_tags.insert(tag.clone());
            }
        }
        let feature_diversity = all_tags.len() as u64;

        // Determine coverage status.
        let coverage_status = if entry_count < config.min_entries_per_family {
            CoverageStatus::Sparse
        } else {
            CoverageStatus::Adequate
        };

        // Compute saturation score:
        // saturation = (entry_contribution + diversity_contribution + spread_contribution) / 3
        //
        // entry_contribution: min(entry_count / min_entries, 2.0) * 500_000
        //   capped at 1_000_000
        // diversity_contribution: min(feature_diversity / min_diversity, 2.0) * 500_000
        //   capped at 1_000_000
        // spread_contribution: complexity_spread_ratio * 1_000_000
        //   where spread_ratio = (max - min) / max, capped at 1_000_000

        let entry_contribution = if config.min_entries_per_family == 0 {
            MILLIONTHS
        } else {
            let ratio = entry_count
                .saturating_mul(MILLIONTHS)
                .checked_div(config.min_entries_per_family)
                .unwrap_or(0);
            ratio.min(2 * MILLIONTHS).saturating_mul(500_000) / MILLIONTHS
        };

        let diversity_contribution = if config.min_feature_diversity == 0 {
            MILLIONTHS
        } else {
            let ratio = feature_diversity
                .saturating_mul(MILLIONTHS)
                .checked_div(config.min_feature_diversity)
                .unwrap_or(0);
            ratio.min(2 * MILLIONTHS).saturating_mul(500_000) / MILLIONTHS
        };

        let spread_contribution = if max_complexity == 0 {
            0
        } else {
            let spread = max_complexity.saturating_sub(min_complexity);
            spread
                .saturating_mul(MILLIONTHS)
                .checked_div(max_complexity)
                .unwrap_or(0)
                .min(MILLIONTHS)
        };

        let saturation_score_millionths = (entry_contribution
            .saturating_add(diversity_contribution)
            .saturating_add(spread_contribution))
            / 3;

        // Upgrade to Saturated if saturation score exceeds the config target.
        let coverage_status = if coverage_status == CoverageStatus::Adequate
            && saturation_score_millionths >= config.min_saturation_score_millionths
        {
            CoverageStatus::Saturated
        } else {
            coverage_status
        };

        Self {
            family,
            entry_count,
            total_complexity,
            min_complexity,
            max_complexity,
            mean_complexity_millionths,
            coverage_status,
            feature_diversity,
            saturation_score_millionths,
        }
    }
}

impl fmt::Display for FamilyCoverage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} entries, status={}, saturation={} millionths, diversity={}",
            self.family,
            self.entry_count,
            self.coverage_status,
            self.saturation_score_millionths,
            self.feature_diversity
        )
    }
}

// ---------------------------------------------------------------------------
// SaturationConfig
// ---------------------------------------------------------------------------

/// Configuration for the coverage saturation gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaturationConfig {
    /// Minimum number of benchmark entries required per family.
    pub min_entries_per_family: u64,
    /// Minimum number of families that must be covered (non-zero entries).
    pub min_families_covered: u64,
    /// Minimum saturation score in millionths for a family to be Saturated.
    pub min_saturation_score_millionths: u64,
    /// Minimum feature diversity (unique tags) required per family.
    pub min_feature_diversity: u64,
    /// Set of families that must be present on the board. If empty, all
    /// families in `WorkloadFamily::ALL` are required.
    pub target_families: BTreeSet<WorkloadFamily>,
    /// Current epoch for staleness checks in reports.
    pub current_epoch: SecurityEpoch,
}

impl SaturationConfig {
    /// Default configuration with moderate thresholds.
    pub fn default_config() -> Self {
        let target_families = WorkloadFamily::ALL.iter().copied().collect();
        Self {
            min_entries_per_family: DEFAULT_MIN_ENTRIES_PER_FAMILY,
            min_families_covered: DEFAULT_MIN_FAMILIES_COVERED,
            min_saturation_score_millionths: DEFAULT_MIN_SATURATION_SCORE_MILLIONTHS,
            min_feature_diversity: DEFAULT_MIN_FEATURE_DIVERSITY,
            target_families,
            current_epoch: SecurityEpoch::from_raw(1),
        }
    }

    /// Strict configuration: all 12 families required, high thresholds.
    pub fn strict() -> Self {
        let target_families = WorkloadFamily::ALL.iter().copied().collect();
        Self {
            min_entries_per_family: 5,
            min_families_covered: WorkloadFamily::COUNT as u64,
            min_saturation_score_millionths: 850_000,
            min_feature_diversity: 4,
            target_families,
            current_epoch: SecurityEpoch::from_raw(1),
        }
    }

    /// Relaxed configuration for testing: low thresholds.
    pub fn relaxed() -> Self {
        Self {
            min_entries_per_family: 1,
            min_families_covered: 4,
            min_saturation_score_millionths: 300_000,
            min_feature_diversity: 1,
            target_families: BTreeSet::new(),
            current_epoch: SecurityEpoch::from_raw(1),
        }
    }

    /// Set of effective target families.
    pub fn effective_targets(&self) -> BTreeSet<WorkloadFamily> {
        if self.target_families.is_empty() {
            WorkloadFamily::ALL.iter().copied().collect()
        } else {
            self.target_families.clone()
        }
    }
}

impl Default for SaturationConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// SaturationVerdict
// ---------------------------------------------------------------------------

/// Overall gate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SaturationVerdict {
    /// All families saturated. Board is publication-ready.
    Saturated,
    /// All required families covered at Adequate or better.
    Adequate,
    /// Some families are Sparse. Board needs more benchmarks.
    Sparse,
    /// Too few families covered. Board is insufficient.
    Insufficient,
    /// Configuration violation (e.g., empty board, contradictory config).
    ConfigViolation,
}

impl SaturationVerdict {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::Saturated,
        Self::Adequate,
        Self::Sparse,
        Self::Insufficient,
        Self::ConfigViolation,
    ];

    /// Stable string representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Saturated => "saturated",
            Self::Adequate => "adequate",
            Self::Sparse => "sparse",
            Self::Insufficient => "insufficient",
            Self::ConfigViolation => "config_violation",
        }
    }

    /// Whether this verdict allows publication.
    pub const fn allows_publication(self) -> bool {
        matches!(self, Self::Saturated | Self::Adequate)
    }

    /// Whether this verdict blocks the gate.
    pub const fn blocks_gate(self) -> bool {
        matches!(
            self,
            Self::Sparse | Self::Insufficient | Self::ConfigViolation
        )
    }
}

impl fmt::Display for SaturationVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RepresentativenessScore
// ---------------------------------------------------------------------------

/// Scored representativeness measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepresentativenessScore {
    /// Which metric was used.
    pub metric: RepresentativenessMetric,
    /// Score in millionths (1_000_000 = perfect representativeness).
    pub score_millionths: u64,
    /// Human-readable detail.
    pub detail: String,
}

impl RepresentativenessScore {
    /// Create a new score.
    pub fn new(
        metric: RepresentativenessMetric,
        score_millionths: u64,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            metric,
            score_millionths,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for RepresentativenessScore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} millionths", self.metric, self.score_millionths)
    }
}

// ---------------------------------------------------------------------------
// SaturationReport
// ---------------------------------------------------------------------------

/// Artifact-rich report for the saturation gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaturationReport {
    /// Schema version.
    pub schema_version: String,
    /// Policy reference.
    pub policy_id: String,
    /// Component name.
    pub component: String,
    /// Overall verdict.
    pub verdict: SaturationVerdict,
    /// Per-family coverage breakdown.
    pub family_coverages: BTreeMap<WorkloadFamily, FamilyCoverage>,
    /// Total entries on the board.
    pub total_entries: u64,
    /// Number of families with at least one entry.
    pub covered_families: u64,
    /// Families with zero entries.
    pub uncovered_families: BTreeSet<WorkloadFamily>,
    /// Overall saturation score in millionths (mean of per-family scores,
    /// including zero for uncovered).
    pub overall_saturation_millionths: u64,
    /// Representativeness scores.
    pub representativeness_scores: Vec<RepresentativenessScore>,
    /// Epoch at which the report was generated.
    pub epoch: SecurityEpoch,
    /// Content hash of the report (excludes this field).
    pub content_hash: ContentHash,
}

impl SaturationReport {
    /// Whether the report passes the gate.
    pub fn passes_gate(&self) -> bool {
        self.verdict.allows_publication()
    }

    /// Number of families that block the gate.
    pub fn blocking_family_count(&self) -> usize {
        self.family_coverages
            .values()
            .filter(|fc| fc.coverage_status.blocks_gate())
            .count()
    }
}

impl fmt::Display for SaturationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SaturationReport[{}]: verdict={}, entries={}, covered={}/{}, saturation={} millionths",
            self.policy_id,
            self.verdict,
            self.total_entries,
            self.covered_families,
            self.family_coverages.len(),
            self.overall_saturation_millionths
        )
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Hash-chained decision receipt for audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Receipt identifier.
    pub receipt_id: String,
    /// Report content hash this receipt covers.
    pub report_hash: ContentHash,
    /// Verdict at time of receipt.
    pub verdict: SaturationVerdict,
    /// Epoch of the receipt.
    pub epoch: SecurityEpoch,
    /// Hash of the previous receipt in the chain.
    pub previous_receipt_hash: ContentHash,
    /// This receipt's own hash.
    pub receipt_hash: ContentHash,
}

impl DecisionReceipt {
    /// Create a new receipt with computed hash chain.
    pub fn new(
        receipt_id: impl Into<String>,
        report: &SaturationReport,
        previous_receipt_hash: ContentHash,
    ) -> Self {
        let receipt_id = receipt_id.into();
        let report_hash = report.content_hash;
        let verdict = report.verdict;
        let epoch = report.epoch;

        let mut buf = Vec::new();
        append_str(&mut buf, &receipt_id);
        buf.extend_from_slice(report_hash.as_bytes());
        append_str(&mut buf, verdict.as_str());
        append_u64(&mut buf, epoch.as_u64());
        buf.extend_from_slice(previous_receipt_hash.as_bytes());
        let receipt_hash = compute_digest(&buf);

        Self {
            receipt_id,
            report_hash,
            verdict,
            epoch,
            previous_receipt_hash,
            receipt_hash,
        }
    }

    /// Verify the receipt hash.
    pub fn verify(&self) -> bool {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.receipt_id);
        buf.extend_from_slice(self.report_hash.as_bytes());
        append_str(&mut buf, self.verdict.as_str());
        append_u64(&mut buf, self.epoch.as_u64());
        buf.extend_from_slice(self.previous_receipt_hash.as_bytes());
        compute_digest(&buf) == self.receipt_hash
    }
}

// ---------------------------------------------------------------------------
// BoardError
// ---------------------------------------------------------------------------

/// Errors from board operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoardError {
    /// Board has too many entries.
    TooManyEntries { count: usize, max: usize },
    /// Entry has too many feature tags.
    TooManyFeatureTags {
        name: String,
        count: usize,
        max: usize,
    },
    /// Duplicate entry name.
    DuplicateEntryName { name: String },
    /// Entry hash verification failed.
    IntegrityFailure { name: String },
}

impl BoardError {
    /// Stable tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::TooManyEntries { .. } => "too_many_entries",
            Self::TooManyFeatureTags { .. } => "too_many_feature_tags",
            Self::DuplicateEntryName { .. } => "duplicate_entry_name",
            Self::IntegrityFailure { .. } => "integrity_failure",
        }
    }
}

impl fmt::Display for BoardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyEntries { count, max } => {
                write!(f, "too many entries: {count} > {max}")
            }
            Self::TooManyFeatureTags { name, count, max } => {
                write!(f, "too many feature tags for {name}: {count} > {max}")
            }
            Self::DuplicateEntryName { name } => {
                write!(f, "duplicate entry name: {name}")
            }
            Self::IntegrityFailure { name } => {
                write!(f, "hash integrity failure for entry: {name}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SaturationBoard
// ---------------------------------------------------------------------------

/// The full benchmark board registry.
///
/// Collects benchmark entries and evaluates them against a saturation config.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaturationBoard {
    /// All registered entries.
    pub entries: Vec<BenchmarkEntry>,
    /// Entry names for duplicate detection.
    entry_names: BTreeSet<String>,
}

impl SaturationBoard {
    /// Create an empty board.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            entry_names: BTreeSet::new(),
        }
    }

    /// Number of entries on the board.
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Whether the board is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Add an entry to the board.
    pub fn add_entry(&mut self, entry: BenchmarkEntry) -> Result<(), BoardError> {
        if self.entries.len() >= MAX_ENTRIES_PER_BOARD {
            return Err(BoardError::TooManyEntries {
                count: self.entries.len() + 1,
                max: MAX_ENTRIES_PER_BOARD,
            });
        }
        if entry.feature_tags.len() > MAX_FEATURE_TAGS_PER_ENTRY {
            return Err(BoardError::TooManyFeatureTags {
                name: entry.name.clone(),
                count: entry.feature_tags.len(),
                max: MAX_FEATURE_TAGS_PER_ENTRY,
            });
        }
        if self.entry_names.contains(&entry.name) {
            return Err(BoardError::DuplicateEntryName {
                name: entry.name.clone(),
            });
        }
        if !entry.verify_hash() {
            return Err(BoardError::IntegrityFailure {
                name: entry.name.clone(),
            });
        }
        self.entry_names.insert(entry.name.clone());
        self.entries.push(entry);
        Ok(())
    }

    /// Get entries for a specific family.
    pub fn entries_for_family(&self, family: WorkloadFamily) -> Vec<&BenchmarkEntry> {
        self.entries.iter().filter(|e| e.family == family).collect()
    }

    /// Compute coverage for all families.
    pub fn compute_family_coverages(
        &self,
        config: &SaturationConfig,
    ) -> BTreeMap<WorkloadFamily, FamilyCoverage> {
        let targets = config.effective_targets();
        let mut coverages = BTreeMap::new();
        for family in &targets {
            let family_entries = self.entries_for_family(*family);
            let family_refs: Vec<&BenchmarkEntry> = family_entries;
            let coverage = FamilyCoverage::compute(*family, &family_refs, config);
            coverages.insert(*family, coverage);
        }
        coverages
    }

    /// Evaluate the board and produce a full report.
    pub fn evaluate(&self, config: &SaturationConfig) -> SaturationReport {
        let family_coverages = self.compute_family_coverages(config);
        let total_entries = self.entries.len() as u64;

        let covered_families = family_coverages
            .values()
            .filter(|fc| fc.entry_count > 0)
            .count() as u64;

        let uncovered_families: BTreeSet<WorkloadFamily> = family_coverages
            .iter()
            .filter(|(_, fc)| fc.entry_count == 0)
            .map(|(f, _)| *f)
            .collect();

        // Compute overall saturation: mean of per-family saturation scores.
        let overall_saturation_millionths = if family_coverages.is_empty() {
            0
        } else {
            let total: u64 = family_coverages
                .values()
                .map(|fc| fc.saturation_score_millionths)
                .sum();
            total
                .checked_div(family_coverages.len() as u64)
                .unwrap_or(0)
        };

        // Compute representativeness scores.
        let representativeness_scores = self.compute_representativeness(config, &family_coverages);

        // Determine verdict.
        let verdict =
            Self::determine_verdict(&family_coverages, covered_families, config, total_entries);

        // Compute content hash.
        let content_hash = Self::compute_report_hash(
            &verdict,
            &family_coverages,
            total_entries,
            covered_families,
            overall_saturation_millionths,
            config.current_epoch,
        );

        SaturationReport {
            schema_version: SCHEMA_VERSION.to_string(),
            policy_id: POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            verdict,
            family_coverages,
            total_entries,
            covered_families,
            uncovered_families,
            overall_saturation_millionths,
            representativeness_scores,
            epoch: config.current_epoch,
            content_hash,
        }
    }

    /// Determine the verdict from coverage data.
    fn determine_verdict(
        family_coverages: &BTreeMap<WorkloadFamily, FamilyCoverage>,
        covered_families: u64,
        config: &SaturationConfig,
        total_entries: u64,
    ) -> SaturationVerdict {
        // ConfigViolation: empty board.
        if total_entries == 0 {
            return SaturationVerdict::ConfigViolation;
        }

        // Insufficient: too few families covered.
        if covered_families < config.min_families_covered {
            return SaturationVerdict::Insufficient;
        }

        // Check for sparse families.
        let has_sparse = family_coverages
            .values()
            .any(|fc| fc.coverage_status == CoverageStatus::Sparse);
        let has_uncovered = family_coverages
            .values()
            .any(|fc| fc.coverage_status == CoverageStatus::Uncovered);

        if has_uncovered || has_sparse {
            return SaturationVerdict::Sparse;
        }

        // All families are Adequate or Saturated.
        let all_saturated = family_coverages
            .values()
            .all(|fc| fc.coverage_status == CoverageStatus::Saturated);

        if all_saturated {
            SaturationVerdict::Saturated
        } else {
            SaturationVerdict::Adequate
        }
    }

    /// Compute representativeness scores.
    fn compute_representativeness(
        &self,
        config: &SaturationConfig,
        family_coverages: &BTreeMap<WorkloadFamily, FamilyCoverage>,
    ) -> Vec<RepresentativenessScore> {
        let mut scores = Vec::new();

        // Corpus ratio: covered / total target families.
        let targets = config.effective_targets();
        let target_count = targets.len() as u64;
        let covered = family_coverages
            .values()
            .filter(|fc| fc.entry_count > 0)
            .count() as u64;
        let corpus_ratio = if target_count == 0 {
            0
        } else {
            covered
                .saturating_mul(MILLIONTHS)
                .checked_div(target_count)
                .unwrap_or(0)
        };
        scores.push(RepresentativenessScore::new(
            RepresentativenessMetric::CorpusRatio,
            corpus_ratio,
            format!("{covered}/{target_count} families covered"),
        ));

        // Feature entropy: approximate based on tag frequency distribution.
        let total_tags: u64 = family_coverages
            .values()
            .map(|fc| fc.feature_diversity)
            .sum();
        let family_count = family_coverages.len() as u64;
        let max_possible_entropy_approx = if family_count == 0 {
            0
        } else {
            // Perfect entropy: each family has equal tags. Use log2-like approx.
            // We use a simplified score: diversity / (max_possible) * MILLIONTHS.
            let max_per_family = config.min_feature_diversity.max(1) * 4;
            let max_total = max_per_family.saturating_mul(family_count);
            if max_total == 0 {
                0
            } else {
                total_tags
                    .saturating_mul(MILLIONTHS)
                    .checked_div(max_total)
                    .unwrap_or(0)
                    .min(MILLIONTHS)
            }
        };
        scores.push(RepresentativenessScore::new(
            RepresentativenessMetric::FeatureEntropy,
            max_possible_entropy_approx,
            format!("total feature tags: {total_tags}"),
        ));

        // Domain Jaccard: entries with target-family tags vs total entries.
        let board_families: BTreeSet<WorkloadFamily> =
            self.entries.iter().map(|e| e.family).collect();
        let intersection = targets.intersection(&board_families).count() as u64;
        let union = targets.union(&board_families).count() as u64;
        let jaccard = if union == 0 {
            0
        } else {
            intersection
                .saturating_mul(MILLIONTHS)
                .checked_div(union)
                .unwrap_or(0)
        };
        scores.push(RepresentativenessScore::new(
            RepresentativenessMetric::DomainJaccardSimilarity,
            jaccard,
            format!("intersection={intersection}, union={union}"),
        ));

        // Complexity histogram KL: measure complexity spread.
        // Use simplified approach: coefficient of variation proxy.
        let complexities: Vec<u64> = self.entries.iter().map(|e| e.complexity_score).collect();
        let kl_score = if complexities.is_empty() {
            0
        } else {
            let total: u64 = complexities.iter().sum();
            let count = complexities.len() as u64;
            let mean = total.checked_div(count).unwrap_or(0);
            if mean == 0 {
                0
            } else {
                let variance_sum: u64 = complexities
                    .iter()
                    .map(|&c| {
                        let diff = if c > mean { c - mean } else { mean - c };
                        diff.saturating_mul(diff)
                    })
                    .sum();
                let variance = variance_sum.checked_div(count).unwrap_or(0);
                // Use sqrt approximation: integer sqrt.
                let std_dev = isqrt(variance);
                // CV = std_dev / mean * MILLIONTHS. Higher CV = more spread = more representative.
                std_dev
                    .saturating_mul(MILLIONTHS)
                    .checked_div(mean)
                    .unwrap_or(0)
                    .min(MILLIONTHS)
            }
        };
        scores.push(RepresentativenessScore::new(
            RepresentativenessMetric::ComplexityHistogramKl,
            kl_score,
            "complexity spread proxy".to_string(),
        ));

        scores
    }

    /// Compute report content hash.
    fn compute_report_hash(
        verdict: &SaturationVerdict,
        family_coverages: &BTreeMap<WorkloadFamily, FamilyCoverage>,
        total_entries: u64,
        covered_families: u64,
        overall_saturation: u64,
        epoch: SecurityEpoch,
    ) -> ContentHash {
        let mut buf = Vec::new();
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, POLICY_ID);
        append_str(&mut buf, verdict.as_str());
        append_u64(&mut buf, total_entries);
        append_u64(&mut buf, covered_families);
        append_u64(&mut buf, overall_saturation);
        append_u64(&mut buf, epoch.as_u64());
        for (family, coverage) in family_coverages {
            append_str(&mut buf, family.as_str());
            append_u64(&mut buf, coverage.entry_count);
            append_u64(&mut buf, coverage.saturation_score_millionths);
            append_str(&mut buf, coverage.coverage_status.as_str());
        }
        compute_digest(&buf)
    }
}

impl Default for SaturationBoard {
    fn default() -> Self {
        Self::new()
    }
}

/// Integer square root (floor).
fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

// ---------------------------------------------------------------------------
// SaturationGate
// ---------------------------------------------------------------------------

/// Top-level gate that evaluates the board and produces a gated verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SaturationGate {
    /// Gate identifier.
    pub gate_id: String,
    /// Configuration.
    pub config: SaturationConfig,
}

impl SaturationGate {
    /// Create a new gate.
    pub fn new(gate_id: impl Into<String>, config: SaturationConfig) -> Self {
        Self {
            gate_id: gate_id.into(),
            config,
        }
    }

    /// Evaluate a board and produce a report.
    pub fn evaluate(&self, board: &SaturationBoard) -> SaturationReport {
        board.evaluate(&self.config)
    }

    /// Evaluate and produce a decision receipt.
    pub fn evaluate_with_receipt(
        &self,
        board: &SaturationBoard,
        previous_receipt_hash: ContentHash,
    ) -> (SaturationReport, DecisionReceipt) {
        let report = board.evaluate(&self.config);
        let receipt = DecisionReceipt::new(&self.gate_id, &report, previous_receipt_hash);
        (report, receipt)
    }

    /// Whether a board passes this gate.
    pub fn passes(&self, board: &SaturationBoard) -> bool {
        let report = self.evaluate(board);
        report.passes_gate()
    }
}

impl fmt::Display for SaturationGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SaturationGate[{}] min_families={} min_entries={}",
            self.gate_id, self.config.min_families_covered, self.config.min_entries_per_family
        )
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(ts: &[&str]) -> BTreeSet<String> {
        ts.iter().map(|s| (*s).to_string()).collect()
    }

    fn make_entry(name: &str, family: WorkloadFamily, complexity: u64) -> BenchmarkEntry {
        BenchmarkEntry::new(name, family, complexity, tags(&["default"]))
    }

    fn make_entry_with_tags(
        name: &str,
        family: WorkloadFamily,
        complexity: u64,
        ts: &[&str],
    ) -> BenchmarkEntry {
        BenchmarkEntry::new(name, family, complexity, tags(ts))
    }

    fn relaxed_config() -> SaturationConfig {
        SaturationConfig::relaxed()
    }

    fn default_config() -> SaturationConfig {
        SaturationConfig::default_config()
    }

    fn populate_board_all_families(entries_per_family: u64) -> SaturationBoard {
        let mut board = SaturationBoard::new();
        for family in WorkloadFamily::ALL {
            for i in 0..entries_per_family {
                let name = format!("{}_{}", family.as_str(), i);
                let complexity = (i + 1) * 100;
                let entry = make_entry_with_tags(
                    &name,
                    *family,
                    complexity,
                    &["tag_a", "tag_b", &format!("tag_{i}")],
                );
                board.add_entry(entry).unwrap();
            }
        }
        board
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn constants_schema_version() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SCHEMA_VERSION.contains("benchmark-coverage-saturation"));
    }

    #[test]
    fn constants_component() {
        assert_eq!(COMPONENT, "benchmark_coverage_saturation");
    }

    #[test]
    fn constants_bead_id() {
        assert!(BEAD_ID.starts_with("bd-"));
        assert_eq!(BEAD_ID, "bd-1lsy.8.5.5");
    }

    #[test]
    fn constants_policy_id() {
        assert!(POLICY_ID.starts_with("RGC-"));
        assert_eq!(POLICY_ID, "RGC-705E");
    }

    #[test]
    fn constants_defaults_valid() {
        assert_eq!(DEFAULT_MIN_ENTRIES_PER_FAMILY, 3);
        assert_eq!(DEFAULT_MIN_FAMILIES_COVERED, 8);
        assert!(DEFAULT_MIN_SATURATION_SCORE_MILLIONTHS <= MILLIONTHS);
        assert!(DEFAULT_MIN_FEATURE_DIVERSITY >= 1);
    }

    // -----------------------------------------------------------------------
    // WorkloadFamily
    // -----------------------------------------------------------------------

    #[test]
    fn workload_family_all_count() {
        assert_eq!(WorkloadFamily::ALL.len(), 12);
        assert_eq!(WorkloadFamily::ALL.len(), WorkloadFamily::COUNT);
    }

    #[test]
    fn workload_family_ordering_is_deterministic() {
        let mut sorted: Vec<WorkloadFamily> = WorkloadFamily::ALL.to_vec();
        sorted.sort();
        // The derive(Ord) ensures deterministic ordering.
        assert_eq!(sorted, WorkloadFamily::ALL.to_vec());
    }

    #[test]
    fn workload_family_names_unique() {
        let names: BTreeSet<&str> = WorkloadFamily::ALL.iter().map(|f| f.as_str()).collect();
        assert_eq!(names.len(), WorkloadFamily::COUNT);
    }

    #[test]
    fn workload_family_display() {
        for f in WorkloadFamily::ALL {
            assert_eq!(f.to_string(), f.as_str());
        }
    }

    #[test]
    fn workload_family_serde_roundtrip() {
        for f in WorkloadFamily::ALL {
            let json = serde_json::to_string(f).unwrap();
            let back: WorkloadFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(*f, back);
        }
    }

    #[test]
    fn workload_family_performance_critical_subset() {
        let critical: Vec<WorkloadFamily> = WorkloadFamily::ALL
            .iter()
            .copied()
            .filter(|f| f.is_performance_critical())
            .collect();
        assert!(critical.contains(&WorkloadFamily::BranchHeavy));
        assert!(critical.contains(&WorkloadFamily::Vectorizable));
        assert!(critical.contains(&WorkloadFamily::StartupImage));
        assert!(!critical.contains(&WorkloadFamily::ProofSpecialized));
        assert!(!critical.contains(&WorkloadFamily::ReactLifecycle));
    }

    // -----------------------------------------------------------------------
    // CoverageStatus
    // -----------------------------------------------------------------------

    #[test]
    fn coverage_status_ordering() {
        assert!(CoverageStatus::Uncovered < CoverageStatus::Sparse);
        assert!(CoverageStatus::Sparse < CoverageStatus::Adequate);
        assert!(CoverageStatus::Adequate < CoverageStatus::Saturated);
    }

    #[test]
    fn coverage_status_all_length() {
        assert_eq!(CoverageStatus::ALL.len(), 4);
    }

    #[test]
    fn coverage_status_acceptability() {
        assert!(!CoverageStatus::Uncovered.is_acceptable());
        assert!(!CoverageStatus::Sparse.is_acceptable());
        assert!(CoverageStatus::Adequate.is_acceptable());
        assert!(CoverageStatus::Saturated.is_acceptable());
    }

    #[test]
    fn coverage_status_blocks_gate() {
        assert!(CoverageStatus::Uncovered.blocks_gate());
        assert!(CoverageStatus::Sparse.blocks_gate());
        assert!(!CoverageStatus::Adequate.blocks_gate());
        assert!(!CoverageStatus::Saturated.blocks_gate());
    }

    #[test]
    fn coverage_status_serde_roundtrip() {
        for s in CoverageStatus::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: CoverageStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // -----------------------------------------------------------------------
    // RepresentativenessMetric
    // -----------------------------------------------------------------------

    #[test]
    fn representativeness_metric_all_length() {
        assert_eq!(RepresentativenessMetric::ALL.len(), 4);
    }

    #[test]
    fn representativeness_metric_display() {
        for m in RepresentativenessMetric::ALL {
            assert_eq!(m.to_string(), m.as_str());
        }
    }

    #[test]
    fn representativeness_metric_serde_roundtrip() {
        for m in RepresentativenessMetric::ALL {
            let json = serde_json::to_string(m).unwrap();
            let back: RepresentativenessMetric = serde_json::from_str(&json).unwrap();
            assert_eq!(*m, back);
        }
    }

    // -----------------------------------------------------------------------
    // BenchmarkEntry
    // -----------------------------------------------------------------------

    #[test]
    fn benchmark_entry_hash_determinism() {
        let e1 = make_entry("test_bench", WorkloadFamily::BranchHeavy, 500);
        let e2 = make_entry("test_bench", WorkloadFamily::BranchHeavy, 500);
        assert_eq!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn benchmark_entry_different_name_different_hash() {
        let e1 = make_entry("bench_a", WorkloadFamily::BranchHeavy, 500);
        let e2 = make_entry("bench_b", WorkloadFamily::BranchHeavy, 500);
        assert_ne!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn benchmark_entry_different_family_different_hash() {
        let e1 = make_entry("bench", WorkloadFamily::BranchHeavy, 500);
        let e2 = make_entry("bench", WorkloadFamily::Vectorizable, 500);
        assert_ne!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn benchmark_entry_different_complexity_different_hash() {
        let e1 = make_entry("bench", WorkloadFamily::BranchHeavy, 500);
        let e2 = make_entry("bench", WorkloadFamily::BranchHeavy, 600);
        assert_ne!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn benchmark_entry_different_tags_different_hash() {
        let e1 = make_entry_with_tags("bench", WorkloadFamily::BranchHeavy, 500, &["a"]);
        let e2 = make_entry_with_tags("bench", WorkloadFamily::BranchHeavy, 500, &["b"]);
        assert_ne!(e1.entry_hash, e2.entry_hash);
    }

    #[test]
    fn benchmark_entry_verify_hash() {
        let entry = make_entry("verify_test", WorkloadFamily::Vectorizable, 100);
        assert!(entry.verify_hash());
    }

    #[test]
    fn benchmark_entry_display() {
        let entry = make_entry_with_tags(
            "display_test",
            WorkloadFamily::BranchHeavy,
            999,
            &["a", "b"],
        );
        let display = entry.to_string();
        assert!(display.contains("display_test"));
        assert!(display.contains("branch_heavy"));
        assert!(display.contains("999"));
    }

    #[test]
    fn benchmark_entry_serde_roundtrip() {
        let entry = make_entry_with_tags(
            "serde_test",
            WorkloadFamily::NativeAddon,
            42,
            &["ffi", "handle"],
        );
        let json = serde_json::to_string(&entry).unwrap();
        let back: BenchmarkEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // -----------------------------------------------------------------------
    // FamilyCoverage
    // -----------------------------------------------------------------------

    #[test]
    fn family_coverage_empty() {
        let config = default_config();
        let coverage = FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[], &config);
        assert_eq!(coverage.entry_count, 0);
        assert_eq!(coverage.total_complexity, 0);
        assert_eq!(coverage.coverage_status, CoverageStatus::Uncovered);
        assert_eq!(coverage.feature_diversity, 0);
        assert_eq!(coverage.saturation_score_millionths, 0);
    }

    #[test]
    fn family_coverage_single_entry() {
        let config = default_config();
        let entry = make_entry("single", WorkloadFamily::BranchHeavy, 100);
        let coverage = FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[&entry], &config);
        assert_eq!(coverage.entry_count, 1);
        assert_eq!(coverage.total_complexity, 100);
        assert_eq!(coverage.min_complexity, 100);
        assert_eq!(coverage.max_complexity, 100);
        // 1 < DEFAULT_MIN_ENTRIES_PER_FAMILY(3) => Sparse.
        assert_eq!(coverage.coverage_status, CoverageStatus::Sparse);
    }

    #[test]
    fn family_coverage_adequate_entries() {
        let config = default_config();
        let e1 = make_entry("a1", WorkloadFamily::BranchHeavy, 100);
        let e2 = make_entry("a2", WorkloadFamily::BranchHeavy, 200);
        let e3 = make_entry("a3", WorkloadFamily::BranchHeavy, 300);
        let coverage =
            FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[&e1, &e2, &e3], &config);
        assert_eq!(coverage.entry_count, 3);
        assert_eq!(coverage.total_complexity, 600);
        assert_eq!(coverage.min_complexity, 100);
        assert_eq!(coverage.max_complexity, 300);
        // entry_count == min_entries_per_family(3) => at least Adequate.
        assert!(coverage.coverage_status.is_acceptable());
    }

    #[test]
    fn family_coverage_mean_complexity() {
        let config = default_config();
        let e1 = make_entry("m1", WorkloadFamily::Vectorizable, 100);
        let e2 = make_entry("m2", WorkloadFamily::Vectorizable, 200);
        let e3 = make_entry("m3", WorkloadFamily::Vectorizable, 300);
        let coverage =
            FamilyCoverage::compute(WorkloadFamily::Vectorizable, &[&e1, &e2, &e3], &config);
        // mean = 600 / 3 = 200 => 200 * 1_000_000 / 3 entries = 200_000_000.
        // Actually: total_complexity(600) * 1_000_000 / entry_count(3) = 200_000_000.
        assert_eq!(coverage.mean_complexity_millionths, 200_000_000);
    }

    #[test]
    fn family_coverage_feature_diversity() {
        let config = default_config();
        let e1 = make_entry_with_tags("d1", WorkloadFamily::BranchHeavy, 100, &["a", "b"]);
        let e2 = make_entry_with_tags("d2", WorkloadFamily::BranchHeavy, 200, &["b", "c"]);
        let e3 = make_entry_with_tags("d3", WorkloadFamily::BranchHeavy, 300, &["c", "d"]);
        let coverage =
            FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[&e1, &e2, &e3], &config);
        // unique tags: a, b, c, d = 4.
        assert_eq!(coverage.feature_diversity, 4);
    }

    #[test]
    fn family_coverage_saturation_score_positive() {
        let config = relaxed_config();
        let e1 = make_entry_with_tags("s1", WorkloadFamily::BranchHeavy, 100, &["a", "b"]);
        let e2 = make_entry_with_tags("s2", WorkloadFamily::BranchHeavy, 500, &["c", "d"]);
        let coverage = FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[&e1, &e2], &config);
        assert!(coverage.saturation_score_millionths > 0);
    }

    #[test]
    fn family_coverage_display() {
        let config = default_config();
        let entry = make_entry("disp", WorkloadFamily::BranchHeavy, 100);
        let coverage = FamilyCoverage::compute(WorkloadFamily::BranchHeavy, &[&entry], &config);
        let display = coverage.to_string();
        assert!(display.contains("branch_heavy"));
        assert!(display.contains("1 entries"));
    }

    // -----------------------------------------------------------------------
    // SaturationConfig
    // -----------------------------------------------------------------------

    #[test]
    fn config_default_targets_all_families() {
        let config = default_config();
        assert_eq!(config.target_families.len(), WorkloadFamily::COUNT);
        assert_eq!(config.effective_targets().len(), WorkloadFamily::COUNT);
    }

    #[test]
    fn config_strict_higher_thresholds() {
        let config = SaturationConfig::strict();
        let default = default_config();
        assert!(config.min_entries_per_family >= default.min_entries_per_family);
        assert!(config.min_saturation_score_millionths >= default.min_saturation_score_millionths);
        assert!(config.min_feature_diversity >= default.min_feature_diversity);
    }

    #[test]
    fn config_relaxed_lower_thresholds() {
        let config = relaxed_config();
        let default = default_config();
        assert!(config.min_entries_per_family <= default.min_entries_per_family);
        assert!(config.min_families_covered <= default.min_families_covered);
    }

    #[test]
    fn config_effective_targets_empty_means_all() {
        let mut config = relaxed_config();
        config.target_families = BTreeSet::new();
        assert_eq!(config.effective_targets().len(), WorkloadFamily::COUNT);
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = default_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: SaturationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // -----------------------------------------------------------------------
    // SaturationVerdict
    // -----------------------------------------------------------------------

    #[test]
    fn verdict_all_count() {
        assert_eq!(SaturationVerdict::ALL.len(), 5);
    }

    #[test]
    fn verdict_allows_publication() {
        assert!(SaturationVerdict::Saturated.allows_publication());
        assert!(SaturationVerdict::Adequate.allows_publication());
        assert!(!SaturationVerdict::Sparse.allows_publication());
        assert!(!SaturationVerdict::Insufficient.allows_publication());
        assert!(!SaturationVerdict::ConfigViolation.allows_publication());
    }

    #[test]
    fn verdict_blocks_gate() {
        assert!(!SaturationVerdict::Saturated.blocks_gate());
        assert!(!SaturationVerdict::Adequate.blocks_gate());
        assert!(SaturationVerdict::Sparse.blocks_gate());
        assert!(SaturationVerdict::Insufficient.blocks_gate());
        assert!(SaturationVerdict::ConfigViolation.blocks_gate());
    }

    #[test]
    fn verdict_display() {
        for v in SaturationVerdict::ALL {
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in SaturationVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: SaturationVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // -----------------------------------------------------------------------
    // SaturationBoard — add entries
    // -----------------------------------------------------------------------

    #[test]
    fn board_empty() {
        let board = SaturationBoard::new();
        assert!(board.is_empty());
        assert_eq!(board.entry_count(), 0);
    }

    #[test]
    fn board_add_single_entry() {
        let mut board = SaturationBoard::new();
        let entry = make_entry("test_a", WorkloadFamily::BranchHeavy, 100);
        assert!(board.add_entry(entry).is_ok());
        assert_eq!(board.entry_count(), 1);
    }

    #[test]
    fn board_add_multiple_families() {
        let mut board = SaturationBoard::new();
        let e1 = make_entry("branch_1", WorkloadFamily::BranchHeavy, 100);
        let e2 = make_entry("vec_1", WorkloadFamily::Vectorizable, 200);
        let e3 = make_entry("proof_1", WorkloadFamily::ProofSpecialized, 300);
        assert!(board.add_entry(e1).is_ok());
        assert!(board.add_entry(e2).is_ok());
        assert!(board.add_entry(e3).is_ok());
        assert_eq!(board.entry_count(), 3);
    }

    #[test]
    fn board_reject_duplicate_name() {
        let mut board = SaturationBoard::new();
        let e1 = make_entry("same_name", WorkloadFamily::BranchHeavy, 100);
        let e2 = make_entry("same_name", WorkloadFamily::Vectorizable, 200);
        assert!(board.add_entry(e1).is_ok());
        let err = board.add_entry(e2).unwrap_err();
        assert_eq!(err.tag(), "duplicate_entry_name");
    }

    #[test]
    fn board_entries_for_family() {
        let mut board = SaturationBoard::new();
        let e1 = make_entry("bh_1", WorkloadFamily::BranchHeavy, 100);
        let e2 = make_entry("bh_2", WorkloadFamily::BranchHeavy, 200);
        let e3 = make_entry("vec_1", WorkloadFamily::Vectorizable, 300);
        board.add_entry(e1).unwrap();
        board.add_entry(e2).unwrap();
        board.add_entry(e3).unwrap();
        assert_eq!(
            board.entries_for_family(WorkloadFamily::BranchHeavy).len(),
            2
        );
        assert_eq!(
            board.entries_for_family(WorkloadFamily::Vectorizable).len(),
            1
        );
        assert_eq!(
            board.entries_for_family(WorkloadFamily::NativeAddon).len(),
            0
        );
    }

    // -----------------------------------------------------------------------
    // Board evaluation — verdicts
    // -----------------------------------------------------------------------

    #[test]
    fn empty_board_config_violation() {
        let board = SaturationBoard::new();
        let config = default_config();
        let report = board.evaluate(&config);
        assert_eq!(report.verdict, SaturationVerdict::ConfigViolation);
        assert!(!report.passes_gate());
    }

    #[test]
    fn single_family_insufficient() {
        let mut board = SaturationBoard::new();
        for i in 0..5 {
            let entry = make_entry(
                &format!("bh_{i}"),
                WorkloadFamily::BranchHeavy,
                (i + 1) * 100,
            );
            board.add_entry(entry).unwrap();
        }
        let config = default_config();
        let report = board.evaluate(&config);
        // Only 1 family covered, need 8 => Insufficient.
        assert_eq!(report.verdict, SaturationVerdict::Insufficient);
        assert_eq!(report.covered_families, 1);
    }

    #[test]
    fn saturated_board_all_families() {
        let board = populate_board_all_families(5);
        let mut config = default_config();
        config.min_saturation_score_millionths = 200_000; // lower threshold for test.
        let report = board.evaluate(&config);
        assert_eq!(report.total_entries, 60);
        assert_eq!(report.covered_families, 12);
        assert!(report.uncovered_families.is_empty());
        assert!(report.passes_gate());
    }

    #[test]
    fn sparse_board_some_families_below_threshold() {
        let mut board = SaturationBoard::new();
        // Add 3+ entries to 8 families.
        let families_full: Vec<WorkloadFamily> = WorkloadFamily::ALL[..8].to_vec();
        for family in &families_full {
            for i in 0..3 {
                let name = format!("{}_{}", family.as_str(), i);
                let entry = make_entry_with_tags(&name, *family, (i + 1) * 100, &["a", "b"]);
                board.add_entry(entry).unwrap();
            }
        }
        // Add only 1 entry to remaining families (sparse).
        for family in &WorkloadFamily::ALL[8..] {
            let name = format!("{}_sparse", family.as_str());
            let entry = make_entry(&name, *family, 50);
            board.add_entry(entry).unwrap();
        }
        let config = default_config();
        let report = board.evaluate(&config);
        assert_eq!(report.verdict, SaturationVerdict::Sparse);
    }

    #[test]
    fn adequate_board() {
        let mut board = SaturationBoard::new();
        // Add exactly min_entries to all families, but low saturation.
        for family in WorkloadFamily::ALL {
            for i in 0..3_u64 {
                let name = format!("{}_{}", family.as_str(), i);
                // Same complexity = no spread, so saturation will be lower.
                let entry = make_entry_with_tags(&name, *family, 100, &["tag_a", "tag_b"]);
                board.add_entry(entry).unwrap();
            }
        }
        let mut config = default_config();
        // Set saturation target very high so Adequate not Saturated.
        config.min_saturation_score_millionths = 999_999;
        let report = board.evaluate(&config);
        assert!(
            report.verdict == SaturationVerdict::Adequate
                || report.verdict == SaturationVerdict::Saturated
        );
        assert!(report.passes_gate());
    }

    // -----------------------------------------------------------------------
    // Report content
    // -----------------------------------------------------------------------

    #[test]
    fn report_schema_and_policy() {
        let board = populate_board_all_families(3);
        let config = default_config();
        let report = board.evaluate(&config);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.policy_id, POLICY_ID);
        assert_eq!(report.component, COMPONENT);
    }

    #[test]
    fn report_content_hash_deterministic() {
        let board = populate_board_all_families(3);
        let config = default_config();
        let r1 = board.evaluate(&config);
        let r2 = board.evaluate(&config);
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_content_hash_changes_with_entries() {
        let board1 = populate_board_all_families(3);
        let board2 = populate_board_all_families(4);
        let config = default_config();
        let r1 = board1.evaluate(&config);
        let r2 = board2.evaluate(&config);
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_uncovered_families_listed() {
        let mut board = SaturationBoard::new();
        let entry = make_entry("only_one", WorkloadFamily::BranchHeavy, 100);
        board.add_entry(entry).unwrap();
        let config = default_config();
        let report = board.evaluate(&config);
        // Should have 11 uncovered families.
        assert_eq!(report.uncovered_families.len(), 11);
        assert!(
            !report
                .uncovered_families
                .contains(&WorkloadFamily::BranchHeavy)
        );
        assert!(
            report
                .uncovered_families
                .contains(&WorkloadFamily::Vectorizable)
        );
    }

    #[test]
    fn report_representativeness_scores_present() {
        let board = populate_board_all_families(3);
        let config = default_config();
        let report = board.evaluate(&config);
        assert_eq!(report.representativeness_scores.len(), 4);
        let metrics: BTreeSet<RepresentativenessMetric> = report
            .representativeness_scores
            .iter()
            .map(|s| s.metric)
            .collect();
        assert!(metrics.contains(&RepresentativenessMetric::CorpusRatio));
        assert!(metrics.contains(&RepresentativenessMetric::FeatureEntropy));
        assert!(metrics.contains(&RepresentativenessMetric::DomainJaccardSimilarity));
        assert!(metrics.contains(&RepresentativenessMetric::ComplexityHistogramKl));
    }

    #[test]
    fn report_corpus_ratio_full_coverage() {
        let board = populate_board_all_families(3);
        let config = default_config();
        let report = board.evaluate(&config);
        let corpus = report
            .representativeness_scores
            .iter()
            .find(|s| s.metric == RepresentativenessMetric::CorpusRatio)
            .unwrap();
        assert_eq!(corpus.score_millionths, MILLIONTHS);
    }

    #[test]
    fn report_display() {
        let board = populate_board_all_families(3);
        let config = default_config();
        let report = board.evaluate(&config);
        let display = report.to_string();
        assert!(display.contains("SaturationReport"));
        assert!(display.contains(POLICY_ID));
    }

    #[test]
    fn report_blocking_family_count() {
        let mut board = SaturationBoard::new();
        let entry = make_entry("only", WorkloadFamily::BranchHeavy, 100);
        board.add_entry(entry).unwrap();
        let config = default_config();
        let report = board.evaluate(&config);
        // 11 uncovered + the 1 sparse = some blocking families.
        assert!(report.blocking_family_count() > 0);
    }

    // -----------------------------------------------------------------------
    // SaturationGate
    // -----------------------------------------------------------------------

    #[test]
    fn gate_evaluate_passes() {
        let board = populate_board_all_families(5);
        let mut config = default_config();
        config.min_saturation_score_millionths = 200_000;
        let gate = SaturationGate::new("gate_test", config);
        assert!(gate.passes(&board));
    }

    #[test]
    fn gate_evaluate_fails_empty() {
        let board = SaturationBoard::new();
        let config = default_config();
        let gate = SaturationGate::new("gate_empty", config);
        assert!(!gate.passes(&board));
    }

    #[test]
    fn gate_display() {
        let config = default_config();
        let gate = SaturationGate::new("test_gate", config);
        let display = gate.to_string();
        assert!(display.contains("SaturationGate"));
        assert!(display.contains("test_gate"));
    }

    // -----------------------------------------------------------------------
    // DecisionReceipt
    // -----------------------------------------------------------------------

    #[test]
    fn receipt_hash_deterministic() {
        let board = populate_board_all_families(3);
        let config = default_config();
        let report = board.evaluate(&config);
        let zero_hash = ContentHash::compute(b"genesis");
        let r1 = DecisionReceipt::new("receipt_1", &report, zero_hash.clone());
        let r2 = DecisionReceipt::new("receipt_1", &report, zero_hash);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn receipt_verify_passes() {
        let board = populate_board_all_families(3);
        let config = default_config();
        let report = board.evaluate(&config);
        let zero_hash = ContentHash::compute(b"genesis");
        let receipt = DecisionReceipt::new("receipt_verify", &report, zero_hash);
        assert!(receipt.verify());
    }

    #[test]
    fn receipt_chain_integrity() {
        let board = populate_board_all_families(3);
        let config = default_config();
        let report = board.evaluate(&config);

        let genesis = ContentHash::compute(b"genesis");
        let r1 = DecisionReceipt::new("receipt_chain_1", &report, genesis);
        assert!(r1.verify());

        let r2 = DecisionReceipt::new("receipt_chain_2", &report, r1.receipt_hash.clone());
        assert!(r2.verify());
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn gate_evaluate_with_receipt() {
        let board = populate_board_all_families(5);
        let mut config = default_config();
        config.min_saturation_score_millionths = 200_000;
        let gate = SaturationGate::new("gate_receipt", config);
        let genesis = ContentHash::compute(b"genesis");
        let (report, receipt) = gate.evaluate_with_receipt(&board, genesis);
        assert!(report.passes_gate());
        assert!(receipt.verify());
        assert_eq!(receipt.verdict, report.verdict);
    }

    // -----------------------------------------------------------------------
    // BoardError
    // -----------------------------------------------------------------------

    #[test]
    fn board_error_duplicate_display() {
        let err = BoardError::DuplicateEntryName {
            name: "dup".to_string(),
        };
        let display = err.to_string();
        assert!(display.contains("dup"));
        assert_eq!(err.tag(), "duplicate_entry_name");
    }

    #[test]
    fn board_error_integrity_display() {
        let err = BoardError::IntegrityFailure {
            name: "bad".to_string(),
        };
        assert_eq!(err.tag(), "integrity_failure");
        assert!(err.to_string().contains("bad"));
    }

    #[test]
    fn board_error_too_many_tags() {
        let err = BoardError::TooManyFeatureTags {
            name: "x".to_string(),
            count: 100,
            max: 64,
        };
        assert_eq!(err.tag(), "too_many_feature_tags");
        assert!(err.to_string().contains("100"));
    }

    // -----------------------------------------------------------------------
    // isqrt
    // -----------------------------------------------------------------------

    #[test]
    fn isqrt_known_values() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(16), 4);
        assert_eq!(isqrt(100), 10);
        assert_eq!(isqrt(99), 9);
        assert_eq!(isqrt(101), 10);
    }

    // -----------------------------------------------------------------------
    // Multiple entries same family accumulation
    // -----------------------------------------------------------------------

    #[test]
    fn same_family_accumulates() {
        let mut board = SaturationBoard::new();
        for i in 0..10_u64 {
            let entry = make_entry_with_tags(
                &format!("acc_{i}"),
                WorkloadFamily::ResourceBounded,
                (i + 1) * 50,
                &["mem", "gc", &format!("tag_{i}")],
            );
            board.add_entry(entry).unwrap();
        }
        let config = default_config();
        let coverages = board.compute_family_coverages(&config);
        let rb = coverages.get(&WorkloadFamily::ResourceBounded).unwrap();
        assert_eq!(rb.entry_count, 10);
        assert_eq!(rb.total_complexity, 2750); // sum of 50..500 step 50.
        assert_eq!(rb.min_complexity, 50);
        assert_eq!(rb.max_complexity, 500);
        assert!(rb.feature_diversity >= 3); // at least mem, gc, tag_0.
    }

    #[test]
    fn overall_saturation_mean_of_families() {
        let board = populate_board_all_families(3);
        let config = default_config();
        let report = board.evaluate(&config);
        // Overall = mean of per-family scores. Check it is positive and plausible.
        assert!(report.overall_saturation_millionths > 0);
        assert!(report.overall_saturation_millionths <= MILLIONTHS);
    }

    // -----------------------------------------------------------------------
    // RepresentativenessScore
    // -----------------------------------------------------------------------

    #[test]
    fn representativeness_score_display() {
        let score = RepresentativenessScore::new(
            RepresentativenessMetric::CorpusRatio,
            750_000,
            "test detail",
        );
        let display = score.to_string();
        assert!(display.contains("corpus_ratio"));
        assert!(display.contains("750000"));
    }
}
