#![forbid(unsafe_code)]

//! MDL, information-gain, obstruction, and topology-aware novelty scoring
//! contract for program-universe dark-matter discovery.
//!
//! Bead: bd-1lsy.8.7.1 [RGC-707A]
//!
//! Defines the scoring contract that tells the synthesis engine how novel
//! and informative a candidate program is relative to the current board.
//! A candidate with a high novelty score is expected to reduce genuine
//! uncertainty about support, performance, or claim scope.
//!
//! # Design decisions
//!
//! - **MDL (Minimum Description Length)** — candidates that cannot be
//!   compressed using the current model are more novel.
//! - **Information gain** — measures how much a candidate would shift
//!   posterior beliefs about board cells.
//! - **Obstruction** — detects whether a candidate witnesses a failure
//!   of glueability across compilation or evaluation surfaces.
//! - **Topological novelty** — captures structural position in program
//!   space (distance from explored frontier, persistent homology holes).
//! - **Ecosystem relevance** — weights novelty by real-world package
//!   prevalence and workload frequency to avoid optimizing for theatrics.
//! - **Composite score** uses fixed-point millionths (1_000_000 = 1.0)
//!   with explicit weight vectors and abstention semantics.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the novelty scoring contract.
pub const SCHEMA_VERSION: &str = "franken-engine.novelty-scoring-contract.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.8.7.1";

/// Component name.
pub const COMPONENT: &str = "novelty_scoring_contract";

/// One million — unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

/// Maximum number of novelty dimensions in a composite score.
pub const MAX_DIMENSIONS: usize = 16;

/// Minimum sample size before the system will produce a novelty estimate
/// (below this it must abstain).
pub const MIN_SAMPLE_SIZE: usize = 10;

/// Default abstention threshold: if fewer than this fraction (millionths)
/// of the dimensions are available, the composite score abstains.
pub const DEFAULT_ABSTENTION_THRESHOLD: u64 = 300_000; // 30%

/// Maximum description length (in abstract units) before a candidate is
/// considered entirely incompressible.
pub const MAX_DESCRIPTION_LENGTH: u64 = 10_000_000;

// ---------------------------------------------------------------------------
// NoveltyDimension — which novelty axis is being measured
// ---------------------------------------------------------------------------

/// A named axis of novelty measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoveltyDimension {
    /// MDL-based incompressibility relative to the current model.
    MinimumDescriptionLength,
    /// Information gain (expected reduction in posterior entropy).
    InformationGain,
    /// Obstruction detection (witnesses of non-glueability).
    Obstruction,
    /// Topological novelty (distance from explored frontier).
    TopologicalDistance,
    /// Persistent homology hole detection (structural gaps in coverage).
    HomologicalHole,
    /// Ecosystem relevance weighting (package prevalence, workload frequency).
    EcosystemRelevance,
    /// Behavioral divergence from existing board specimens.
    BehavioralDivergence,
    /// Compilation path novelty (exercises untested compiler paths).
    CompilationPathNovelty,
}

impl NoveltyDimension {
    /// All known novelty dimensions in canonical order.
    pub const ALL: &[Self] = &[
        Self::MinimumDescriptionLength,
        Self::InformationGain,
        Self::Obstruction,
        Self::TopologicalDistance,
        Self::HomologicalHole,
        Self::EcosystemRelevance,
        Self::BehavioralDivergence,
        Self::CompilationPathNovelty,
    ];

    /// Machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MinimumDescriptionLength => "minimum_description_length",
            Self::InformationGain => "information_gain",
            Self::Obstruction => "obstruction",
            Self::TopologicalDistance => "topological_distance",
            Self::HomologicalHole => "homological_hole",
            Self::EcosystemRelevance => "ecosystem_relevance",
            Self::BehavioralDivergence => "behavioral_divergence",
            Self::CompilationPathNovelty => "compilation_path_novelty",
        }
    }

    /// Whether this dimension requires a populated reference board to compute.
    pub fn requires_reference_board(&self) -> bool {
        matches!(
            self,
            Self::InformationGain
                | Self::TopologicalDistance
                | Self::HomologicalHole
                | Self::BehavioralDivergence
        )
    }
}

impl fmt::Display for NoveltyDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// AbstentionReason — why a dimension cannot be scored
// ---------------------------------------------------------------------------

/// Structured reason why a novelty dimension was not scored.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbstentionReason {
    /// Insufficient sample size to produce a reliable estimate.
    InsufficientSampleSize { available: usize, required: usize },
    /// The reference board is empty or missing for this dimension.
    EmptyReferenceBoard,
    /// The candidate contains opaque regions that prevent analysis.
    OpaqueCandidate { region_label: String },
    /// The model for this dimension is not yet calibrated.
    UncalibratedModel,
    /// The dimension is disabled by operator policy.
    DisabledByPolicy,
}

impl AbstentionReason {
    /// Machine-readable tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::InsufficientSampleSize { .. } => "insufficient_sample_size",
            Self::EmptyReferenceBoard => "empty_reference_board",
            Self::OpaqueCandidate { .. } => "opaque_candidate",
            Self::UncalibratedModel => "uncalibrated_model",
            Self::DisabledByPolicy => "disabled_by_policy",
        }
    }
}

impl fmt::Display for AbstentionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSampleSize {
                available,
                required,
            } => write!(
                f,
                "insufficient sample size: {} available, {} required",
                available, required
            ),
            Self::EmptyReferenceBoard => write!(f, "empty reference board"),
            Self::OpaqueCandidate { region_label } => {
                write!(f, "opaque candidate region: {}", region_label)
            }
            Self::UncalibratedModel => write!(f, "uncalibrated model"),
            Self::DisabledByPolicy => write!(f, "disabled by policy"),
        }
    }
}

// ---------------------------------------------------------------------------
// DimensionScore — score for a single dimension
// ---------------------------------------------------------------------------

/// A score for a single novelty dimension: either a measured value or an
/// abstention with a structured reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DimensionScore {
    /// The dimension was scored successfully.
    Scored {
        /// The raw score in millionths (0 = no novelty, 1_000_000 = max novelty).
        score_millionths: u64,
        /// Confidence in the score, in millionths.
        confidence_millionths: u64,
        /// Number of reference samples used to derive this score.
        sample_count: usize,
    },
    /// The dimension could not be scored.
    Abstained { reason: AbstentionReason },
}

impl DimensionScore {
    /// Create a scored result, clamping to [0, MILLION].
    pub fn scored(score_millionths: u64, confidence_millionths: u64, sample_count: usize) -> Self {
        Self::Scored {
            score_millionths: score_millionths.min(MILLION),
            confidence_millionths: confidence_millionths.min(MILLION),
            sample_count,
        }
    }

    /// Create an abstention.
    pub fn abstained(reason: AbstentionReason) -> Self {
        Self::Abstained { reason }
    }

    /// Whether this dimension was successfully scored.
    pub fn is_scored(&self) -> bool {
        matches!(self, Self::Scored { .. })
    }

    /// Whether this dimension abstained.
    pub fn is_abstained(&self) -> bool {
        matches!(self, Self::Abstained { .. })
    }

    /// Extract the raw score, if scored.
    pub fn raw_score(&self) -> Option<u64> {
        match self {
            Self::Scored {
                score_millionths, ..
            } => Some(*score_millionths),
            Self::Abstained { .. } => None,
        }
    }

    /// Extract the confidence, if scored.
    pub fn confidence(&self) -> Option<u64> {
        match self {
            Self::Scored {
                confidence_millionths,
                ..
            } => Some(*confidence_millionths),
            Self::Abstained { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// DimensionWeight — configurable weight for a dimension
// ---------------------------------------------------------------------------

/// A weight for a novelty dimension in the composite score calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct DimensionWeight {
    /// The dimension being weighted.
    pub dimension: NoveltyDimension,
    /// The weight in millionths (how much this dimension contributes to the
    /// composite score).
    pub weight_millionths: u64,
}

impl DimensionWeight {
    /// Construct a new weight.
    pub fn new(dimension: NoveltyDimension, weight_millionths: u64) -> Self {
        Self {
            dimension,
            weight_millionths,
        }
    }
}

/// Default weight vector giving equal weight to all dimensions.
pub fn default_weight_vector() -> Vec<DimensionWeight> {
    let per_dim = MILLION / NoveltyDimension::ALL.len() as u64;
    NoveltyDimension::ALL
        .iter()
        .map(|d| DimensionWeight::new(*d, per_dim))
        .collect()
}

// ---------------------------------------------------------------------------
// NoveltyProfile — per-candidate multi-dimensional score
// ---------------------------------------------------------------------------

/// A scored novelty entry for one dimension of a candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoveltyEntry {
    /// Which dimension this entry measures.
    pub dimension: NoveltyDimension,
    /// The dimension score (scored or abstained).
    pub score: DimensionScore,
}

/// A multi-dimensional novelty profile for a single candidate program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoveltyProfile {
    /// Fingerprint of the candidate being scored.
    pub candidate_fingerprint: String,
    /// Per-dimension scores.
    pub entries: Vec<NoveltyEntry>,
    /// Content hash of this profile.
    pub content_hash: ContentHash,
}

impl NoveltyProfile {
    /// Construct a new profile, computing the content hash.
    pub fn new(candidate_fingerprint: String, entries: Vec<NoveltyEntry>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(candidate_fingerprint.as_bytes());
        hasher.update((entries.len() as u64).to_le_bytes());
        for entry in &entries {
            hasher.update(entry.dimension.as_str().as_bytes());
            match &entry.score {
                DimensionScore::Scored {
                    score_millionths,
                    confidence_millionths,
                    sample_count,
                } => {
                    hasher.update(b"scored");
                    hasher.update(score_millionths.to_le_bytes());
                    hasher.update(confidence_millionths.to_le_bytes());
                    hasher.update((*sample_count as u64).to_le_bytes());
                }
                DimensionScore::Abstained { reason } => {
                    hasher.update(b"abstained");
                    hasher.update(reason.tag().as_bytes());
                }
            }
        }
        let content_hash = ContentHash::compute(&hasher.finalize());
        Self {
            candidate_fingerprint,
            entries,
            content_hash,
        }
    }

    /// Number of dimensions that were scored (not abstained).
    pub fn scored_count(&self) -> usize {
        self.entries.iter().filter(|e| e.score.is_scored()).count()
    }

    /// Number of dimensions that abstained.
    pub fn abstained_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.score.is_abstained())
            .count()
    }

    /// Coverage fraction: scored / total, in millionths.
    pub fn coverage_millionths(&self) -> u64 {
        if self.entries.is_empty() {
            return 0;
        }
        let scored = self.scored_count() as u64;
        let total = self.entries.len() as u64;
        scored.saturating_mul(MILLION) / total
    }

    /// Whether the profile has sufficient coverage to produce a composite
    /// score (above the abstention threshold).
    pub fn has_sufficient_coverage(&self, threshold_millionths: u64) -> bool {
        self.coverage_millionths() >= threshold_millionths
    }

    /// Dimensions that were scored.
    pub fn scored_dimensions(&self) -> BTreeSet<NoveltyDimension> {
        self.entries
            .iter()
            .filter(|e| e.score.is_scored())
            .map(|e| e.dimension)
            .collect()
    }

    /// Dimensions that abstained.
    pub fn abstained_dimensions(&self) -> BTreeSet<NoveltyDimension> {
        self.entries
            .iter()
            .filter(|e| e.score.is_abstained())
            .map(|e| e.dimension)
            .collect()
    }

    /// Get the score for a specific dimension.
    pub fn score_for(&self, dim: NoveltyDimension) -> Option<&DimensionScore> {
        self.entries
            .iter()
            .find(|e| e.dimension == dim)
            .map(|e| &e.score)
    }
}

// ---------------------------------------------------------------------------
// CompositeVerdict — the final novelty judgment
// ---------------------------------------------------------------------------

/// The verdict from computing a composite novelty score.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositeVerdict {
    /// The candidate has high novelty and should be prioritized for board
    /// expansion.
    HighNovelty,
    /// The candidate has moderate novelty — worth including but not urgent.
    ModerateNovelty,
    /// The candidate has low novelty — likely redundant with existing board.
    LowNovelty,
    /// Could not determine novelty due to insufficient evidence.
    Inconclusive,
}

impl CompositeVerdict {
    /// All verdicts in canonical order.
    pub const ALL: &[Self] = &[
        Self::HighNovelty,
        Self::ModerateNovelty,
        Self::LowNovelty,
        Self::Inconclusive,
    ];

    /// Machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HighNovelty => "high_novelty",
            Self::ModerateNovelty => "moderate_novelty",
            Self::LowNovelty => "low_novelty",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// Whether this verdict recommends the candidate for board inclusion.
    pub fn recommends_inclusion(&self) -> bool {
        matches!(self, Self::HighNovelty | Self::ModerateNovelty)
    }
}

impl fmt::Display for CompositeVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CompositeNoveltyScore — the weighted composite
// ---------------------------------------------------------------------------

/// High-novelty threshold (millionths).  Scores above this receive
/// `HighNovelty` verdict.
pub const HIGH_NOVELTY_THRESHOLD: u64 = 700_000; // 70%

/// Moderate-novelty threshold (millionths).  Scores in
/// [MODERATE_NOVELTY_THRESHOLD, HIGH_NOVELTY_THRESHOLD) receive
/// `ModerateNovelty`.
pub const MODERATE_NOVELTY_THRESHOLD: u64 = 400_000; // 40%

/// A weighted composite novelty score with verdict and audit trail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompositeNoveltyScore {
    /// The candidate fingerprint.
    pub candidate_fingerprint: String,
    /// The weighted composite score in millionths.
    pub composite_millionths: u64,
    /// The verdict derived from the composite score.
    pub verdict: CompositeVerdict,
    /// The weight vector used.
    pub weights: Vec<DimensionWeight>,
    /// Security epoch at scoring time.
    pub epoch: SecurityEpoch,
    /// Content hash of this score record.
    pub content_hash: ContentHash,
}

impl CompositeNoveltyScore {
    /// Compute a composite score from a profile and weight vector.
    #[allow(clippy::collapsible_if)]
    pub fn compute(
        profile: &NoveltyProfile,
        weights: &[DimensionWeight],
        abstention_threshold: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        let coverage = profile.coverage_millionths();
        let (composite, verdict) = if coverage < abstention_threshold {
            (0, CompositeVerdict::Inconclusive)
        } else {
            let mut weighted_sum: u64 = 0;
            let mut weight_total: u64 = 0;

            for w in weights {
                if let Some(score) = profile.score_for(w.dimension) {
                    if let Some(raw) = score.raw_score() {
                        // weighted_sum += raw * weight / MILLION
                        weighted_sum = weighted_sum
                            .saturating_add(raw.saturating_mul(w.weight_millionths) / MILLION);
                        weight_total = weight_total.saturating_add(w.weight_millionths);
                    }
                }
            }

            let composite = weighted_sum
                .saturating_mul(MILLION)
                .checked_div(weight_total)
                .unwrap_or(0);

            let verdict = if composite >= HIGH_NOVELTY_THRESHOLD {
                CompositeVerdict::HighNovelty
            } else if composite >= MODERATE_NOVELTY_THRESHOLD {
                CompositeVerdict::ModerateNovelty
            } else {
                CompositeVerdict::LowNovelty
            };

            (composite, verdict)
        };

        let mut hasher = Sha256::new();
        hasher.update(profile.candidate_fingerprint.as_bytes());
        hasher.update(composite.to_le_bytes());
        hasher.update(verdict.as_str().as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        let content_hash = ContentHash::compute(&hasher.finalize());

        Self {
            candidate_fingerprint: profile.candidate_fingerprint.clone(),
            composite_millionths: composite,
            verdict,
            weights: weights.to_vec(),
            epoch,
            content_hash,
        }
    }

    /// Whether the verdict recommends board inclusion.
    pub fn recommends_inclusion(&self) -> bool {
        self.verdict.recommends_inclusion()
    }
}

// ---------------------------------------------------------------------------
// NoveltyBatch — scoring multiple candidates
// ---------------------------------------------------------------------------

/// A batch of novelty scores for ranking candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoveltyBatch {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// The scored candidates, sorted by composite score (descending) for
    /// deterministic iteration.
    pub scores: Vec<CompositeNoveltyScore>,
    /// Content hash of the batch.
    pub content_hash: ContentHash,
}

impl NoveltyBatch {
    /// Build a batch from scored candidates, sorting by descending composite
    /// score and computing the content hash.
    pub fn new(epoch: SecurityEpoch, mut scores: Vec<CompositeNoveltyScore>) -> Self {
        scores.sort_by_key(|s| std::cmp::Reverse(s.composite_millionths));

        let mut hasher = Sha256::new();
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update((scores.len() as u64).to_le_bytes());
        for s in &scores {
            hasher.update(s.candidate_fingerprint.as_bytes());
            hasher.update(s.composite_millionths.to_le_bytes());
        }
        let content_hash = ContentHash::compute(&hasher.finalize());

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch,
            scores,
            content_hash,
        }
    }

    /// Number of candidates in the batch.
    pub fn candidate_count(&self) -> usize {
        self.scores.len()
    }

    /// Candidates that are recommended for inclusion.
    pub fn recommended_candidates(&self) -> Vec<&CompositeNoveltyScore> {
        self.scores
            .iter()
            .filter(|s| s.recommends_inclusion())
            .collect()
    }

    /// Candidates with high novelty only.
    pub fn high_novelty_candidates(&self) -> Vec<&CompositeNoveltyScore> {
        self.scores
            .iter()
            .filter(|s| s.verdict == CompositeVerdict::HighNovelty)
            .collect()
    }

    /// The highest composite score in the batch (millionths), or 0 if empty.
    pub fn max_score(&self) -> u64 {
        self.scores
            .first()
            .map(|s| s.composite_millionths)
            .unwrap_or(0)
    }

    /// Fraction of candidates that are inconclusive (millionths).
    pub fn inconclusive_fraction(&self) -> u64 {
        if self.scores.is_empty() {
            return 0;
        }
        let inc = self
            .scores
            .iter()
            .filter(|s| s.verdict == CompositeVerdict::Inconclusive)
            .count() as u64;
        inc.saturating_mul(MILLION) / self.scores.len() as u64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(77)
    }

    fn make_scored_entry(dim: NoveltyDimension, score: u64, confidence: u64) -> NoveltyEntry {
        NoveltyEntry {
            dimension: dim,
            score: DimensionScore::scored(score, confidence, 100),
        }
    }

    fn make_abstained_entry(dim: NoveltyDimension, reason: AbstentionReason) -> NoveltyEntry {
        NoveltyEntry {
            dimension: dim,
            score: DimensionScore::abstained(reason),
        }
    }

    fn full_scored_profile(score: u64) -> NoveltyProfile {
        let entries: Vec<_> = NoveltyDimension::ALL
            .iter()
            .map(|d| make_scored_entry(*d, score, 900_000))
            .collect();
        NoveltyProfile::new("candidate_full".into(), entries)
    }

    // --- NoveltyDimension tests ---

    #[test]
    fn dimension_all_count() {
        assert_eq!(NoveltyDimension::ALL.len(), 8);
    }

    #[test]
    fn dimension_names_unique() {
        let names: BTreeSet<&str> = NoveltyDimension::ALL.iter().map(|d| d.as_str()).collect();
        assert_eq!(names.len(), NoveltyDimension::ALL.len());
    }

    #[test]
    fn dimension_display_matches_as_str() {
        for d in NoveltyDimension::ALL {
            assert_eq!(d.to_string(), d.as_str());
        }
    }

    #[test]
    fn dimension_serde_roundtrip() {
        for d in NoveltyDimension::ALL {
            let json = serde_json::to_string(d).unwrap();
            let back: NoveltyDimension = serde_json::from_str(&json).unwrap();
            assert_eq!(*d, back);
        }
    }

    #[test]
    fn dimension_reference_board_subset() {
        let needs_board: Vec<_> = NoveltyDimension::ALL
            .iter()
            .filter(|d| d.requires_reference_board())
            .collect();
        assert!(!needs_board.is_empty());
        assert!(needs_board.len() < NoveltyDimension::ALL.len());
    }

    // --- AbstentionReason tests ---

    #[test]
    fn abstention_reason_tags_unique() {
        let reasons = vec![
            AbstentionReason::InsufficientSampleSize {
                available: 5,
                required: 10,
            },
            AbstentionReason::EmptyReferenceBoard,
            AbstentionReason::OpaqueCandidate {
                region_label: "n".into(),
            },
            AbstentionReason::UncalibratedModel,
            AbstentionReason::DisabledByPolicy,
        ];
        let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), 5);
    }

    #[test]
    fn abstention_reason_serde_roundtrip() {
        let r = AbstentionReason::InsufficientSampleSize {
            available: 3,
            required: 10,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: AbstentionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn abstention_reason_display() {
        let r = AbstentionReason::EmptyReferenceBoard;
        assert!(r.to_string().contains("empty reference board"));
    }

    // --- DimensionScore tests ---

    #[test]
    fn dimension_score_scored() {
        let s = DimensionScore::scored(750_000, 950_000, 200);
        assert!(s.is_scored());
        assert!(!s.is_abstained());
        assert_eq!(s.raw_score(), Some(750_000));
        assert_eq!(s.confidence(), Some(950_000));
    }

    #[test]
    fn dimension_score_clamped() {
        let s = DimensionScore::scored(2_000_000, 3_000_000, 50);
        assert_eq!(s.raw_score(), Some(MILLION));
        assert_eq!(s.confidence(), Some(MILLION));
    }

    #[test]
    fn dimension_score_abstained() {
        let s = DimensionScore::abstained(AbstentionReason::UncalibratedModel);
        assert!(s.is_abstained());
        assert!(!s.is_scored());
        assert_eq!(s.raw_score(), None);
        assert_eq!(s.confidence(), None);
    }

    #[test]
    fn dimension_score_serde_roundtrip() {
        let scored = DimensionScore::scored(500_000, 800_000, 100);
        let json = serde_json::to_string(&scored).unwrap();
        let back: DimensionScore = serde_json::from_str(&json).unwrap();
        assert_eq!(scored, back);

        let abstained = DimensionScore::abstained(AbstentionReason::DisabledByPolicy);
        let json2 = serde_json::to_string(&abstained).unwrap();
        let back2: DimensionScore = serde_json::from_str(&json2).unwrap();
        assert_eq!(abstained, back2);
    }

    // --- DimensionWeight tests ---

    #[test]
    fn weight_construction() {
        let w = DimensionWeight::new(NoveltyDimension::InformationGain, 250_000);
        assert_eq!(w.dimension, NoveltyDimension::InformationGain);
        assert_eq!(w.weight_millionths, 250_000);
    }

    #[test]
    fn default_weight_vector_coverage() {
        let weights = default_weight_vector();
        assert_eq!(weights.len(), NoveltyDimension::ALL.len());
        let dims: BTreeSet<_> = weights.iter().map(|w| w.dimension).collect();
        assert_eq!(dims.len(), NoveltyDimension::ALL.len());
    }

    // --- NoveltyProfile tests ---

    #[test]
    fn profile_all_scored() {
        let p = full_scored_profile(600_000);
        assert_eq!(p.scored_count(), 8);
        assert_eq!(p.abstained_count(), 0);
        assert_eq!(p.coverage_millionths(), MILLION);
        assert!(p.has_sufficient_coverage(DEFAULT_ABSTENTION_THRESHOLD));
    }

    #[test]
    fn profile_all_abstained() {
        let entries: Vec<_> = NoveltyDimension::ALL
            .iter()
            .map(|d| make_abstained_entry(*d, AbstentionReason::UncalibratedModel))
            .collect();
        let p = NoveltyProfile::new("empty".into(), entries);
        assert_eq!(p.scored_count(), 0);
        assert_eq!(p.abstained_count(), 8);
        assert_eq!(p.coverage_millionths(), 0);
        assert!(!p.has_sufficient_coverage(DEFAULT_ABSTENTION_THRESHOLD));
    }

    #[test]
    fn profile_mixed_coverage() {
        let entries = vec![
            make_scored_entry(NoveltyDimension::MinimumDescriptionLength, 800_000, 900_000),
            make_scored_entry(NoveltyDimension::InformationGain, 600_000, 850_000),
            make_abstained_entry(
                NoveltyDimension::Obstruction,
                AbstentionReason::EmptyReferenceBoard,
            ),
        ];
        let p = NoveltyProfile::new("mixed".into(), entries);
        assert_eq!(p.scored_count(), 2);
        assert_eq!(p.abstained_count(), 1);
        // 2/3 = 666_666
        let cov = p.coverage_millionths();
        assert!(cov > 600_000);
        assert!(cov < 700_000);
    }

    #[test]
    fn profile_content_hash_deterministic() {
        let p1 = full_scored_profile(500_000);
        let p2 = full_scored_profile(500_000);
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn profile_different_scores_different_hash() {
        let p1 = full_scored_profile(500_000);
        let p2 = full_scored_profile(600_000);
        assert_ne!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn profile_score_for_lookup() {
        let entries = vec![make_scored_entry(
            NoveltyDimension::Obstruction,
            750_000,
            950_000,
        )];
        let p = NoveltyProfile::new("lookup".into(), entries);
        assert!(p.score_for(NoveltyDimension::Obstruction).is_some());
        assert!(p.score_for(NoveltyDimension::InformationGain).is_none());
    }

    #[test]
    fn profile_serde_roundtrip() {
        let p = full_scored_profile(700_000);
        let json = serde_json::to_string(&p).unwrap();
        let back: NoveltyProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(p, back);
    }

    #[test]
    fn profile_scored_and_abstained_dimensions() {
        let entries = vec![
            make_scored_entry(NoveltyDimension::MinimumDescriptionLength, 500_000, 900_000),
            make_abstained_entry(
                NoveltyDimension::HomologicalHole,
                AbstentionReason::UncalibratedModel,
            ),
        ];
        let p = NoveltyProfile::new("dims".into(), entries);
        let scored = p.scored_dimensions();
        let abstained = p.abstained_dimensions();
        assert!(scored.contains(&NoveltyDimension::MinimumDescriptionLength));
        assert!(abstained.contains(&NoveltyDimension::HomologicalHole));
    }

    // --- CompositeVerdict tests ---

    #[test]
    fn verdict_all_count() {
        assert_eq!(CompositeVerdict::ALL.len(), 4);
    }

    #[test]
    fn verdict_inclusion_semantics() {
        assert!(CompositeVerdict::HighNovelty.recommends_inclusion());
        assert!(CompositeVerdict::ModerateNovelty.recommends_inclusion());
        assert!(!CompositeVerdict::LowNovelty.recommends_inclusion());
        assert!(!CompositeVerdict::Inconclusive.recommends_inclusion());
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in CompositeVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: CompositeVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- CompositeNoveltyScore tests ---

    #[test]
    fn composite_high_novelty() {
        let p = full_scored_profile(800_000);
        let weights = default_weight_vector();
        let score = CompositeNoveltyScore::compute(
            &p,
            &weights,
            DEFAULT_ABSTENTION_THRESHOLD,
            test_epoch(),
        );
        assert_eq!(score.verdict, CompositeVerdict::HighNovelty);
        assert!(score.recommends_inclusion());
        assert!(score.composite_millionths >= HIGH_NOVELTY_THRESHOLD);
    }

    #[test]
    fn composite_moderate_novelty() {
        let p = full_scored_profile(500_000);
        let weights = default_weight_vector();
        let score = CompositeNoveltyScore::compute(
            &p,
            &weights,
            DEFAULT_ABSTENTION_THRESHOLD,
            test_epoch(),
        );
        assert_eq!(score.verdict, CompositeVerdict::ModerateNovelty);
        assert!(score.recommends_inclusion());
    }

    #[test]
    fn composite_low_novelty() {
        let p = full_scored_profile(200_000);
        let weights = default_weight_vector();
        let score = CompositeNoveltyScore::compute(
            &p,
            &weights,
            DEFAULT_ABSTENTION_THRESHOLD,
            test_epoch(),
        );
        assert_eq!(score.verdict, CompositeVerdict::LowNovelty);
        assert!(!score.recommends_inclusion());
    }

    #[test]
    fn composite_inconclusive_below_threshold() {
        // 1 scored + 7 abstained = 12.5% coverage < 30% threshold
        let mut entries = vec![make_scored_entry(
            NoveltyDimension::MinimumDescriptionLength,
            900_000,
            950_000,
        )];
        for d in &NoveltyDimension::ALL[1..] {
            entries.push(make_abstained_entry(
                *d,
                AbstentionReason::UncalibratedModel,
            ));
        }
        let p = NoveltyProfile::new("sparse".into(), entries);
        let weights = default_weight_vector();
        // Coverage is 1/8 = 12.5%, below default 30% threshold
        let score = CompositeNoveltyScore::compute(
            &p,
            &weights,
            DEFAULT_ABSTENTION_THRESHOLD,
            test_epoch(),
        );
        assert_eq!(score.verdict, CompositeVerdict::Inconclusive);
    }

    #[test]
    fn composite_content_hash_deterministic() {
        let p = full_scored_profile(600_000);
        let weights = default_weight_vector();
        let s1 = CompositeNoveltyScore::compute(
            &p,
            &weights,
            DEFAULT_ABSTENTION_THRESHOLD,
            test_epoch(),
        );
        let s2 = CompositeNoveltyScore::compute(
            &p,
            &weights,
            DEFAULT_ABSTENTION_THRESHOLD,
            test_epoch(),
        );
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn composite_serde_roundtrip() {
        let p = full_scored_profile(700_000);
        let weights = default_weight_vector();
        let score = CompositeNoveltyScore::compute(
            &p,
            &weights,
            DEFAULT_ABSTENTION_THRESHOLD,
            test_epoch(),
        );
        let json = serde_json::to_string(&score).unwrap();
        let back: CompositeNoveltyScore = serde_json::from_str(&json).unwrap();
        assert_eq!(score, back);
    }

    // --- NoveltyBatch tests ---

    #[test]
    fn batch_empty() {
        let batch = NoveltyBatch::new(test_epoch(), Vec::new());
        assert_eq!(batch.candidate_count(), 0);
        assert!(batch.recommended_candidates().is_empty());
        assert_eq!(batch.max_score(), 0);
        assert_eq!(batch.inconclusive_fraction(), 0);
        assert_eq!(batch.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn batch_sorted_descending() {
        let weights = default_weight_vector();
        let scores = vec![
            CompositeNoveltyScore::compute(
                &full_scored_profile(200_000),
                &weights,
                DEFAULT_ABSTENTION_THRESHOLD,
                test_epoch(),
            ),
            CompositeNoveltyScore::compute(
                &full_scored_profile(800_000),
                &weights,
                DEFAULT_ABSTENTION_THRESHOLD,
                test_epoch(),
            ),
            CompositeNoveltyScore::compute(
                &full_scored_profile(500_000),
                &weights,
                DEFAULT_ABSTENTION_THRESHOLD,
                test_epoch(),
            ),
        ];
        let batch = NoveltyBatch::new(test_epoch(), scores);
        assert_eq!(batch.candidate_count(), 3);
        // Should be sorted descending
        assert!(batch.scores[0].composite_millionths >= batch.scores[1].composite_millionths);
        assert!(batch.scores[1].composite_millionths >= batch.scores[2].composite_millionths);
    }

    #[test]
    fn batch_recommended_filtering() {
        let weights = default_weight_vector();
        let scores = vec![
            CompositeNoveltyScore::compute(
                &full_scored_profile(800_000),
                &weights,
                DEFAULT_ABSTENTION_THRESHOLD,
                test_epoch(),
            ),
            CompositeNoveltyScore::compute(
                &full_scored_profile(100_000),
                &weights,
                DEFAULT_ABSTENTION_THRESHOLD,
                test_epoch(),
            ),
        ];
        let batch = NoveltyBatch::new(test_epoch(), scores);
        let recommended = batch.recommended_candidates();
        assert_eq!(recommended.len(), 1);
        let high = batch.high_novelty_candidates();
        assert_eq!(high.len(), 1);
    }

    #[test]
    fn batch_content_hash_deterministic() {
        let weights = default_weight_vector();
        let s1 = CompositeNoveltyScore::compute(
            &full_scored_profile(600_000),
            &weights,
            DEFAULT_ABSTENTION_THRESHOLD,
            test_epoch(),
        );
        let s2 = CompositeNoveltyScore::compute(
            &full_scored_profile(600_000),
            &weights,
            DEFAULT_ABSTENTION_THRESHOLD,
            test_epoch(),
        );
        let b1 = NoveltyBatch::new(test_epoch(), vec![s1]);
        let b2 = NoveltyBatch::new(test_epoch(), vec![s2]);
        assert_eq!(b1.content_hash, b2.content_hash);
    }

    #[test]
    fn batch_serde_roundtrip() {
        let weights = default_weight_vector();
        let score = CompositeNoveltyScore::compute(
            &full_scored_profile(700_000),
            &weights,
            DEFAULT_ABSTENTION_THRESHOLD,
            test_epoch(),
        );
        let batch = NoveltyBatch::new(test_epoch(), vec![score]);
        let json = serde_json::to_string(&batch).unwrap();
        let back: NoveltyBatch = serde_json::from_str(&json).unwrap();
        assert_eq!(batch, back);
    }

    // --- Constants tests ---

    #[test]
    fn constants_valid() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!COMPONENT.is_empty());
        assert!(MAX_DIMENSIONS > 0);
        assert!(MIN_SAMPLE_SIZE > 0);
        assert!(DEFAULT_ABSTENTION_THRESHOLD > 0);
        assert!(DEFAULT_ABSTENTION_THRESHOLD <= MILLION);
        assert!(MAX_DESCRIPTION_LENGTH > 0);
        assert!(HIGH_NOVELTY_THRESHOLD > MODERATE_NOVELTY_THRESHOLD);
        assert!(MODERATE_NOVELTY_THRESHOLD > 0);
    }

    #[test]
    fn million_value() {
        assert_eq!(MILLION, 1_000_000);
    }
}
