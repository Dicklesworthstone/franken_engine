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

/// Alias matching the spec's naming convention.
pub const NOVELTY_SCHEMA_VERSION: &str = "franken-engine.novelty-scoring-contract.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.8.7.1";

/// Component name.
pub const COMPONENT: &str = "novelty_scoring_contract";

/// Alias matching the spec's naming convention.
pub const NOVELTY_COMPONENT: &str = "novelty_scoring_contract";

/// Policy ID for RGC-707A.
pub const NOVELTY_POLICY_ID: &str = "RGC-707A";

/// One million — unit for fixed-point millionths arithmetic.
pub const MILLIONTHS: u64 = 1_000_000;

/// Internal alias for backwards compatibility.
const MILLION: u64 = MILLIONTHS;

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
// CandidateKind — what kind of entity is being scored
// ---------------------------------------------------------------------------

/// The kind of entity being evaluated for novelty.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    /// A standalone program.
    Program,
    /// An npm/crates.io package.
    Package,
    /// A React component.
    ReactComponent,
    /// A module dependency graph.
    ModuleGraph,
    /// A workload execution trace.
    WorkloadTrace,
}

impl CandidateKind {
    /// All candidate kinds in canonical order.
    pub const ALL: &[Self] = &[
        Self::Program,
        Self::Package,
        Self::ReactComponent,
        Self::ModuleGraph,
        Self::WorkloadTrace,
    ];

    /// Machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Program => "program",
            Self::Package => "package",
            Self::ReactComponent => "react_component",
            Self::ModuleGraph => "module_graph",
            Self::WorkloadTrace => "workload_trace",
        }
    }
}

impl fmt::Display for CandidateKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// NoveltyCandidate — a candidate entity to be scored
// ---------------------------------------------------------------------------

/// A candidate entity submitted for novelty scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoveltyCandidate {
    /// Unique identifier for this candidate.
    pub candidate_id: String,
    /// What kind of entity this is.
    pub kind: CandidateKind,
    /// MDL in bits — the minimum description length of this candidate
    /// under the current model.
    pub description_length_bits: u64,
    /// Feature vector with one fixed-point millionths entry per dimension.
    pub feature_vector: Vec<u64>,
    /// Content hash of the candidate's source representation.
    pub source_hash: ContentHash,
}

impl NoveltyCandidate {
    /// Create a new candidate with computed source hash from the given bytes.
    pub fn new(
        candidate_id: String,
        kind: CandidateKind,
        description_length_bits: u64,
        feature_vector: Vec<u64>,
        source_bytes: &[u8],
    ) -> Self {
        Self {
            candidate_id,
            kind,
            description_length_bits,
            feature_vector,
            source_hash: ContentHash::compute(source_bytes),
        }
    }
}

// ---------------------------------------------------------------------------
// ScoringConfig — configuration for the novelty scoring pipeline
// ---------------------------------------------------------------------------

/// Configuration for the novelty scoring pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoringConfig {
    /// Weights for each dimension. Must sum to MILLIONTHS.
    pub dimension_weights: Vec<DimensionWeight>,
    /// Baseline description length in bits for MDL scoring.
    pub mdl_baseline_bits: u64,
    /// Threshold (millionths) below which information gain is considered negligible.
    pub information_gain_threshold_millionths: u64,
    /// Exponential decay rate (millionths) for frontier proximity scoring.
    pub frontier_proximity_decay_millionths: u64,
    /// Minimum novelty threshold (millionths) — scores below this are Redundant.
    pub min_novelty_threshold_millionths: u64,
}

impl ScoringConfig {
    /// Returns a sensible default config with equal weights across all
    /// standard dimensions.
    pub fn default_config() -> Self {
        let dims = [
            NoveltyDimension::MinimumDescriptionLength,
            NoveltyDimension::InformationGain,
            NoveltyDimension::Obstruction,
            NoveltyDimension::TopologicalDistance,
            NoveltyDimension::HomologicalHole,
            NoveltyDimension::EcosystemRelevance,
            NoveltyDimension::BehavioralDivergence,
        ];
        let per_dim = MILLIONTHS / dims.len() as u64;
        let remainder = MILLIONTHS - per_dim * dims.len() as u64;
        let mut weights: Vec<DimensionWeight> = dims
            .iter()
            .map(|d| DimensionWeight::new(*d, per_dim))
            .collect();
        // Distribute remainder to the first dimension for exact sum.
        if let Some(first) = weights.first_mut() {
            first.weight_millionths += remainder;
        }
        Self {
            dimension_weights: weights,
            mdl_baseline_bits: 10_000,
            information_gain_threshold_millionths: 50_000, // 5%
            frontier_proximity_decay_millionths: 100_000,  // 10%
            min_novelty_threshold_millionths: 200_000,     // 20%
        }
    }

    /// Validate the config. Returns an error if weights do not sum to MILLIONTHS.
    pub fn validate(&self) -> Result<(), NoveltyError> {
        let total: u64 = self
            .dimension_weights
            .iter()
            .map(|w| w.weight_millionths)
            .sum();
        if total != MILLIONTHS {
            return Err(NoveltyError::InvalidWeights {
                expected: MILLIONTHS,
                actual: total,
            });
        }
        if self.mdl_baseline_bits == 0 {
            return Err(NoveltyError::MdlBaselineZero);
        }
        Ok(())
    }

    /// Compute a content hash of this config for certificate binding.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"scoring_config_v1");
        hasher.update((self.dimension_weights.len() as u64).to_le_bytes());
        for w in &self.dimension_weights {
            hasher.update(w.dimension.as_str().as_bytes());
            hasher.update(w.weight_millionths.to_le_bytes());
        }
        hasher.update(self.mdl_baseline_bits.to_le_bytes());
        hasher.update(self.information_gain_threshold_millionths.to_le_bytes());
        hasher.update(self.frontier_proximity_decay_millionths.to_le_bytes());
        hasher.update(self.min_novelty_threshold_millionths.to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// NoveltyError — error types for the scoring pipeline
// ---------------------------------------------------------------------------

/// Errors that can occur during novelty scoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoveltyError {
    /// Dimension weights do not sum to the expected total.
    InvalidWeights { expected: u64, actual: u64 },
    /// The candidate set is empty.
    EmptyCandidateSet,
    /// Feature vector has wrong number of dimensions.
    InvalidFeatureVector {
        expected_dims: usize,
        actual_dims: usize,
    },
    /// MDL baseline is zero, which would cause division by zero.
    MdlBaselineZero,
}

impl fmt::Display for NoveltyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWeights { expected, actual } => {
                write!(
                    f,
                    "invalid weights: expected sum {}, got {}",
                    expected, actual
                )
            }
            Self::EmptyCandidateSet => write!(f, "empty candidate set"),
            Self::InvalidFeatureVector {
                expected_dims,
                actual_dims,
            } => {
                write!(
                    f,
                    "invalid feature vector: expected {} dims, got {}",
                    expected_dims, actual_dims
                )
            }
            Self::MdlBaselineZero => write!(f, "MDL baseline must be non-zero"),
        }
    }
}

// ---------------------------------------------------------------------------
// NoveltyVerdict — the final verdict for a candidate
// ---------------------------------------------------------------------------

/// The verdict for a candidate after novelty scoring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoveltyVerdict {
    /// The candidate is genuinely novel — it adds new information.
    Novel,
    /// The candidate is redundant with existing knowledge.
    Redundant,
    /// The candidate is on the border — marginally novel.
    Marginal,
    /// The candidate witnesses an obstruction in the program space.
    ObstructionWitness,
}

impl NoveltyVerdict {
    /// All verdicts in canonical order.
    pub const ALL: &[Self] = &[
        Self::Novel,
        Self::Redundant,
        Self::Marginal,
        Self::ObstructionWitness,
    ];

    /// Machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Novel => "novel",
            Self::Redundant => "redundant",
            Self::Marginal => "marginal",
            Self::ObstructionWitness => "obstruction_witness",
        }
    }
}

impl fmt::Display for NoveltyVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// NoveltyScore — scored result for a single candidate
// ---------------------------------------------------------------------------

/// A scored result for a single candidate across all dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoveltyScore {
    /// The candidate this score belongs to.
    pub candidate_id: String,
    /// Total composite score in millionths.
    pub total_score_millionths: u64,
    /// Per-dimension scores.
    pub dimension_scores: Vec<(NoveltyDimension, u64)>,
    /// Whether the candidate is above the novelty threshold.
    pub is_novel: bool,
    /// Rank position in the scored batch (0-based).
    pub rank: u32,
}

// ---------------------------------------------------------------------------
// NoveltyCertificate — certified novelty result
// ---------------------------------------------------------------------------

/// A certified novelty result binding a candidate to its score and verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoveltyCertificate {
    /// Schema version.
    pub schema_version: String,
    /// The candidate this certificate covers.
    pub candidate_id: String,
    /// The verdict.
    pub verdict: NoveltyVerdict,
    /// The full score.
    pub score: NoveltyScore,
    /// Hash of the config used for scoring.
    pub config_hash: ContentHash,
    /// Content hash of this certificate.
    pub certificate_hash: ContentHash,
}

impl NoveltyCertificate {
    /// Compute the certificate hash from the certificate contents.
    fn compute_hash(
        candidate_id: &str,
        verdict: &NoveltyVerdict,
        score: &NoveltyScore,
        config_hash: &ContentHash,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(NOVELTY_SCHEMA_VERSION.as_bytes());
        hasher.update(candidate_id.as_bytes());
        hasher.update(verdict.as_str().as_bytes());
        hasher.update(score.total_score_millionths.to_le_bytes());
        hasher.update(score.rank.to_le_bytes());
        for (dim, val) in &score.dimension_scores {
            hasher.update(dim.as_str().as_bytes());
            hasher.update(val.to_le_bytes());
        }
        hasher.update(config_hash.as_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// NoveltyBatch — batch scoring result
// ---------------------------------------------------------------------------

/// A batch of novelty scores for ranking candidates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoveltyBatch {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// The scored candidates, sorted by composite score (descending).
    pub scores: Vec<CompositeNoveltyScore>,
    /// Content hash of the batch.
    pub content_hash: ContentHash,
    /// Candidates submitted for scoring.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidates: Vec<NoveltyCandidate>,
    /// Scoring config used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ScoringConfig>,
    /// Certificates produced.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificates: Vec<NoveltyCertificate>,
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
            candidates: Vec::new(),
            config: None,
            certificates: Vec::new(),
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
// NoveltyEvidenceManifest — evidence manifest for the scoring pipeline
// ---------------------------------------------------------------------------

/// Evidence manifest produced by `run_novelty_evidence`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoveltyEvidenceManifest {
    /// Schema version.
    pub schema_version: String,
    /// Number of candidates scored.
    pub candidates_scored: usize,
    /// Number of candidates judged novel.
    pub novel_count: usize,
    /// Number of candidates judged redundant.
    pub redundant_count: usize,
    /// Certificates produced.
    pub certificates: Vec<NoveltyCertificate>,
    /// Content hash of this manifest.
    pub manifest_hash: ContentHash,
    /// Error message, if any.
    pub error: Option<String>,
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
// CompositeVerdict — the final novelty judgment (legacy API)
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
// CompositeNoveltyScore — the weighted composite (legacy API)
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
// Scoring functions — RGC-707A candidate scoring pipeline
// ---------------------------------------------------------------------------

/// Compute the MDL novelty score for a candidate.
///
/// Shorter-than-baseline description length yields a higher novelty score.
/// The score is: `(baseline - min(candidate, baseline)) * MILLIONTHS / baseline`
/// clamped to [0, MILLIONTHS].
pub fn compute_mdl_score(candidate: &NoveltyCandidate, baseline_bits: u64) -> u64 {
    if baseline_bits == 0 {
        return 0;
    }
    let clamped = candidate.description_length_bits.min(baseline_bits);
    let difference = baseline_bits.saturating_sub(clamped);
    difference.saturating_mul(MILLIONTHS) / baseline_bits
}

/// Compute the information gain of a candidate relative to prior candidates.
///
/// Measures how much the candidate's feature vector differs from the
/// centroid of the prior candidates' feature vectors. Higher divergence
/// implies more information gain.
pub fn compute_information_gain(
    candidate: &NoveltyCandidate,
    prior_candidates: &[NoveltyCandidate],
) -> u64 {
    if prior_candidates.is_empty() {
        // No prior knowledge — maximum information gain.
        return MILLIONTHS;
    }
    if candidate.feature_vector.is_empty() {
        return 0;
    }

    // Compute the centroid of prior feature vectors.
    let dim_count = candidate.feature_vector.len();
    let mut centroid: Vec<u64> = vec![0; dim_count];
    let mut contributing = 0u64;

    for prior in prior_candidates {
        if prior.feature_vector.len() == dim_count {
            for (i, val) in prior.feature_vector.iter().enumerate() {
                centroid[i] = centroid[i].saturating_add(*val);
            }
            contributing += 1;
        }
    }

    if contributing == 0 {
        return MILLIONTHS;
    }

    for val in &mut centroid {
        *val /= contributing;
    }

    // Compute the L1 distance from the centroid, normalized.
    let mut total_distance: u64 = 0;
    for (i, candidate_val) in candidate.feature_vector.iter().enumerate() {
        let diff = if *candidate_val >= centroid[i] {
            candidate_val - centroid[i]
        } else {
            centroid[i] - *candidate_val
        };
        total_distance = total_distance.saturating_add(diff);
    }

    // Normalize: divide by (dim_count * MILLIONTHS) to get a [0, 1] range,
    // then scale back to millionths.
    let max_possible = (dim_count as u64).saturating_mul(MILLIONTHS);
    if max_possible == 0 {
        return 0;
    }
    total_distance
        .saturating_mul(MILLIONTHS)
        .checked_div(max_possible)
        .unwrap_or(0)
        .min(MILLIONTHS)
}

/// Compute the score for a single dimension of a candidate.
pub fn compute_dimension_score(
    candidate: &NoveltyCandidate,
    dimension: NoveltyDimension,
    config: &ScoringConfig,
    prior: &[NoveltyCandidate],
) -> u64 {
    match dimension {
        NoveltyDimension::MinimumDescriptionLength => {
            compute_mdl_score(candidate, config.mdl_baseline_bits)
        }
        NoveltyDimension::InformationGain => compute_information_gain(candidate, prior),
        NoveltyDimension::Obstruction => {
            // Use the obstruction feature if available (index 2).
            candidate.feature_vector.get(2).copied().unwrap_or(0)
        }
        NoveltyDimension::TopologicalDistance => {
            // Use the topological coverage feature if available (index 3).
            candidate.feature_vector.get(3).copied().unwrap_or(0)
        }
        NoveltyDimension::HomologicalHole => {
            // Use the homological hole feature if available (index 4).
            candidate.feature_vector.get(4).copied().unwrap_or(0)
        }
        NoveltyDimension::EcosystemRelevance => {
            // Use the ecosystem diversity feature if available (index 5).
            candidate.feature_vector.get(5).copied().unwrap_or(0)
        }
        NoveltyDimension::BehavioralDivergence => {
            // Frontier proximity with exponential decay.
            let raw = candidate.feature_vector.get(6).copied().unwrap_or(0);
            // Apply decay: raw * (MILLIONTHS - decay) / MILLIONTHS
            let decay = config.frontier_proximity_decay_millionths;
            raw.saturating_mul(MILLIONTHS.saturating_sub(decay)) / MILLIONTHS
        }
        NoveltyDimension::CompilationPathNovelty => {
            // Claim scope expansion feature (index 6 or 7).
            candidate.feature_vector.get(7).copied().unwrap_or(0)
        }
    }
}

/// Score a single candidate against the given config and prior candidates.
///
/// Returns a `NoveltyScore` with all dimension scores computed and the
/// total weighted score.
pub fn score_candidate(
    candidate: &NoveltyCandidate,
    config: &ScoringConfig,
    prior: &[NoveltyCandidate],
) -> NoveltyScore {
    let mut dimension_scores: Vec<(NoveltyDimension, u64)> = Vec::new();

    for weight in &config.dimension_weights {
        let dim_score = compute_dimension_score(candidate, weight.dimension, config, prior);
        dimension_scores.push((weight.dimension, dim_score));
    }

    // Compute weighted total.
    let mut weighted_sum: u64 = 0;
    let mut weight_total: u64 = 0;
    for weight in &config.dimension_weights {
        let dim_val = dimension_scores
            .iter()
            .find(|(d, _)| *d == weight.dimension)
            .map(|(_, v)| *v)
            .unwrap_or(0);
        weighted_sum = weighted_sum
            .saturating_add(dim_val.saturating_mul(weight.weight_millionths) / MILLIONTHS);
        weight_total = weight_total.saturating_add(weight.weight_millionths);
    }

    let total = weighted_sum
        .saturating_mul(MILLIONTHS)
        .checked_div(weight_total)
        .unwrap_or(0)
        .min(MILLIONTHS);

    let is_novel = total >= config.min_novelty_threshold_millionths;

    NoveltyScore {
        candidate_id: candidate.candidate_id.clone(),
        total_score_millionths: total,
        dimension_scores,
        is_novel,
        rank: 0, // Rank is assigned by score_batch.
    }
}

/// Score a batch of candidates, assign ranks, and produce certificates.
///
/// Candidates are scored against each other: the first candidate has no
/// prior, the second has the first as prior, etc. This captures how each
/// successive candidate adds information relative to the growing set.
pub fn score_batch(candidates: &[NoveltyCandidate], config: &ScoringConfig) -> NoveltyBatch {
    let mut scored: Vec<NoveltyScore> = Vec::with_capacity(candidates.len());

    for (i, candidate) in candidates.iter().enumerate() {
        let prior = &candidates[..i];
        let score = score_candidate(candidate, config, prior);
        scored.push(score);
    }

    // Sort by total score descending and assign ranks.
    scored.sort_by_key(|s| std::cmp::Reverse(s.total_score_millionths));
    for (rank, score) in scored.iter_mut().enumerate() {
        score.rank = rank as u32;
    }

    // Produce certificates.
    let certificates: Vec<NoveltyCertificate> = scored
        .iter()
        .map(|score| {
            let candidate = candidates
                .iter()
                .find(|c| c.candidate_id == score.candidate_id)
                .expect("candidate must exist");
            certify_candidate(candidate, score, config)
        })
        .collect();

    // Build batch hash.
    let mut hasher = Sha256::new();
    hasher.update(NOVELTY_SCHEMA_VERSION.as_bytes());
    hasher.update((candidates.len() as u64).to_le_bytes());
    for cert in &certificates {
        hasher.update(cert.certificate_hash.as_bytes());
    }
    let batch_hash = ContentHash::compute(&hasher.finalize());

    // Build legacy CompositeNoveltyScore entries for backward compatibility.
    let epoch = SecurityEpoch::from_raw(1);
    let composite_scores: Vec<CompositeNoveltyScore> = scored
        .iter()
        .map(|s| {
            let composite = s.total_score_millionths;
            let verdict = if composite >= HIGH_NOVELTY_THRESHOLD {
                CompositeVerdict::HighNovelty
            } else if composite >= MODERATE_NOVELTY_THRESHOLD {
                CompositeVerdict::ModerateNovelty
            } else {
                CompositeVerdict::LowNovelty
            };

            let mut ch = Sha256::new();
            ch.update(s.candidate_id.as_bytes());
            ch.update(composite.to_le_bytes());
            ch.update(verdict.as_str().as_bytes());
            ch.update(epoch.as_u64().to_le_bytes());
            let content_hash = ContentHash::compute(&ch.finalize());

            CompositeNoveltyScore {
                candidate_fingerprint: s.candidate_id.clone(),
                composite_millionths: composite,
                verdict,
                weights: config.dimension_weights.clone(),
                epoch,
                content_hash,
            }
        })
        .collect();

    NoveltyBatch {
        schema_version: NOVELTY_SCHEMA_VERSION.to_string(),
        epoch,
        scores: composite_scores,
        content_hash: batch_hash,
        candidates: candidates.to_vec(),
        config: Some(config.clone()),
        certificates,
    }
}

/// Certify a candidate with its score and config, producing a
/// `NoveltyCertificate`.
pub fn certify_candidate(
    candidate: &NoveltyCandidate,
    score: &NoveltyScore,
    config: &ScoringConfig,
) -> NoveltyCertificate {
    let verdict = classify_verdict(score, config);
    let config_hash = config.content_hash();

    let certificate_hash =
        NoveltyCertificate::compute_hash(&candidate.candidate_id, &verdict, score, &config_hash);

    NoveltyCertificate {
        schema_version: NOVELTY_SCHEMA_VERSION.to_string(),
        candidate_id: candidate.candidate_id.clone(),
        verdict,
        score: score.clone(),
        config_hash,
        certificate_hash,
    }
}

/// Classify a score into a `NoveltyVerdict`.
fn classify_verdict(score: &NoveltyScore, config: &ScoringConfig) -> NoveltyVerdict {
    // Check if any dimension is an obstruction witness.
    for (dim, val) in &score.dimension_scores {
        if *dim == NoveltyDimension::Obstruction && *val >= MILLIONTHS / 2 {
            return NoveltyVerdict::ObstructionWitness;
        }
    }

    let threshold = config.min_novelty_threshold_millionths;
    let marginal_band = threshold / 5; // 20% of threshold is the marginal band

    if score.total_score_millionths >= threshold {
        NoveltyVerdict::Novel
    } else if score.total_score_millionths >= threshold.saturating_sub(marginal_band) {
        NoveltyVerdict::Marginal
    } else {
        NoveltyVerdict::Redundant
    }
}

/// Build a corpus of sample candidates, score them, and produce an evidence
/// manifest demonstrating the scoring pipeline.
pub fn run_novelty_evidence() -> NoveltyEvidenceManifest {
    let config = ScoringConfig::default_config();

    let candidates = vec![
        NoveltyCandidate::new(
            "evidence-candidate-1".to_string(),
            CandidateKind::Program,
            5_000, // shorter than baseline => high MDL novelty
            vec![
                800_000, 700_000, 100_000, 600_000, 500_000, 400_000, 300_000,
            ],
            b"program-alpha-source",
        ),
        NoveltyCandidate::new(
            "evidence-candidate-2".to_string(),
            CandidateKind::Package,
            15_000, // longer than baseline => low MDL novelty
            vec![200_000, 300_000, 50_000, 150_000, 100_000, 250_000, 200_000],
            b"package-beta-source",
        ),
        NoveltyCandidate::new(
            "evidence-candidate-3".to_string(),
            CandidateKind::ReactComponent,
            8_000,
            vec![
                500_000, 500_000, 800_000, 400_000, 300_000, 600_000, 700_000,
            ],
            b"react-component-gamma-source",
        ),
        NoveltyCandidate::new(
            "evidence-candidate-4".to_string(),
            CandidateKind::ModuleGraph,
            10_000, // exactly baseline => zero MDL novelty
            vec![100_000, 100_000, 50_000, 100_000, 100_000, 100_000, 100_000],
            b"module-graph-delta-source",
        ),
        NoveltyCandidate::new(
            "evidence-candidate-5".to_string(),
            CandidateKind::WorkloadTrace,
            3_000, // very short => high MDL novelty
            vec![
                900_000, 800_000, 200_000, 700_000, 600_000, 500_000, 900_000,
            ],
            b"workload-trace-epsilon-source",
        ),
    ];

    let batch = score_batch(&candidates, &config);

    let novel_count = batch
        .certificates
        .iter()
        .filter(|c| c.verdict == NoveltyVerdict::Novel)
        .count();
    let redundant_count = batch
        .certificates
        .iter()
        .filter(|c| c.verdict == NoveltyVerdict::Redundant)
        .count();

    let mut hasher = Sha256::new();
    hasher.update(NOVELTY_SCHEMA_VERSION.as_bytes());
    hasher.update(b"evidence_manifest");
    hasher.update((candidates.len() as u64).to_le_bytes());
    hasher.update((novel_count as u64).to_le_bytes());
    hasher.update((redundant_count as u64).to_le_bytes());
    for cert in &batch.certificates {
        hasher.update(cert.certificate_hash.as_bytes());
    }
    let manifest_hash = ContentHash::compute(&hasher.finalize());

    NoveltyEvidenceManifest {
        schema_version: NOVELTY_SCHEMA_VERSION.to_string(),
        candidates_scored: candidates.len(),
        novel_count,
        redundant_count,
        certificates: batch.certificates,
        manifest_hash,
        error: None,
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

    fn sample_candidate(id: &str, desc_len: u64, features: Vec<u64>) -> NoveltyCandidate {
        NoveltyCandidate::new(
            id.to_string(),
            CandidateKind::Program,
            desc_len,
            features,
            id.as_bytes(),
        )
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

    // --- CandidateKind tests ---

    #[test]
    fn candidate_kind_all_count() {
        assert_eq!(CandidateKind::ALL.len(), 5);
    }

    #[test]
    fn candidate_kind_serde_roundtrip() {
        for kind in CandidateKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: CandidateKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn candidate_kind_display() {
        assert_eq!(CandidateKind::Program.to_string(), "program");
        assert_eq!(CandidateKind::ReactComponent.to_string(), "react_component");
    }

    // --- NoveltyVerdict tests ---

    #[test]
    fn verdict_serde_roundtrip() {
        for v in NoveltyVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: NoveltyVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn verdict_display() {
        assert_eq!(NoveltyVerdict::Novel.to_string(), "novel");
        assert_eq!(NoveltyVerdict::Redundant.to_string(), "redundant");
        assert_eq!(NoveltyVerdict::Marginal.to_string(), "marginal");
        assert_eq!(
            NoveltyVerdict::ObstructionWitness.to_string(),
            "obstruction_witness"
        );
    }

    // --- NoveltyError tests ---

    #[test]
    fn error_serde_roundtrip() {
        let errors = vec![
            NoveltyError::InvalidWeights {
                expected: MILLIONTHS,
                actual: 500_000,
            },
            NoveltyError::EmptyCandidateSet,
            NoveltyError::InvalidFeatureVector {
                expected_dims: 7,
                actual_dims: 3,
            },
            NoveltyError::MdlBaselineZero,
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: NoveltyError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    #[test]
    fn error_display_messages() {
        let err = NoveltyError::InvalidWeights {
            expected: MILLIONTHS,
            actual: 500_000,
        };
        assert!(err.to_string().contains("1000000"));
        assert!(err.to_string().contains("500000"));

        let err2 = NoveltyError::EmptyCandidateSet;
        assert!(err2.to_string().contains("empty"));

        let err3 = NoveltyError::MdlBaselineZero;
        assert!(err3.to_string().contains("non-zero"));
    }

    // --- ScoringConfig tests ---

    #[test]
    fn default_config_validates() {
        let config = ScoringConfig::default_config();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn invalid_weights_rejected() {
        let mut config = ScoringConfig::default_config();
        // Corrupt the weights so they don't sum to MILLIONTHS.
        config.dimension_weights[0].weight_millionths += 1;
        let result = config.validate();
        assert!(result.is_err());
        if let Err(NoveltyError::InvalidWeights { expected, actual }) = result {
            assert_eq!(expected, MILLIONTHS);
            assert_eq!(actual, MILLIONTHS + 1);
        } else {
            panic!("expected InvalidWeights error");
        }
    }

    #[test]
    fn zero_mdl_baseline_rejected() {
        let mut config = ScoringConfig::default_config();
        config.mdl_baseline_bits = 0;
        let result = config.validate();
        assert!(result.is_err());
        assert!(matches!(result, Err(NoveltyError::MdlBaselineZero)));
    }

    #[test]
    fn config_content_hash_deterministic() {
        let c1 = ScoringConfig::default_config();
        let c2 = ScoringConfig::default_config();
        assert_eq!(c1.content_hash(), c2.content_hash());
    }

    // --- MDL scoring tests ---

    #[test]
    fn mdl_shorter_is_more_novel() {
        let short = sample_candidate("short", 2_000, vec![]);
        let long = sample_candidate("long", 9_000, vec![]);
        let baseline = 10_000;
        let short_score = compute_mdl_score(&short, baseline);
        let long_score = compute_mdl_score(&long, baseline);
        assert!(
            short_score > long_score,
            "shorter candidate should score higher"
        );
    }

    #[test]
    fn mdl_exact_baseline_is_zero() {
        let at_baseline = sample_candidate("baseline", 10_000, vec![]);
        let score = compute_mdl_score(&at_baseline, 10_000);
        assert_eq!(score, 0);
    }

    #[test]
    fn mdl_longer_than_baseline_is_zero() {
        let longer = sample_candidate("longer", 20_000, vec![]);
        let score = compute_mdl_score(&longer, 10_000);
        assert_eq!(score, 0);
    }

    #[test]
    fn mdl_zero_length_is_max() {
        let zero_len = sample_candidate("zero", 0, vec![]);
        let score = compute_mdl_score(&zero_len, 10_000);
        assert_eq!(score, MILLIONTHS);
    }

    #[test]
    fn mdl_zero_baseline_returns_zero() {
        let candidate = sample_candidate("any", 5_000, vec![]);
        let score = compute_mdl_score(&candidate, 0);
        assert_eq!(score, 0);
    }

    // --- Information gain tests ---

    #[test]
    fn information_gain_no_prior_is_max() {
        let candidate = sample_candidate("first", 5_000, vec![500_000, 500_000]);
        let gain = compute_information_gain(&candidate, &[]);
        assert_eq!(gain, MILLIONTHS);
    }

    #[test]
    fn information_gain_identical_prior_is_zero() {
        let features = vec![500_000, 500_000, 500_000];
        let candidate = sample_candidate("new", 5_000, features.clone());
        let prior = vec![sample_candidate("old", 5_000, features)];
        let gain = compute_information_gain(&candidate, &prior);
        assert_eq!(gain, 0);
    }

    #[test]
    fn information_gain_divergent_candidate_is_high() {
        let candidate = sample_candidate("divergent", 5_000, vec![900_000, 900_000, 900_000]);
        let prior = vec![
            sample_candidate("a", 5_000, vec![100_000, 100_000, 100_000]),
            sample_candidate("b", 5_000, vec![100_000, 100_000, 100_000]),
        ];
        let gain = compute_information_gain(&candidate, &prior);
        assert!(
            gain > 500_000,
            "divergent candidate should have high info gain, got {}",
            gain
        );
    }

    #[test]
    fn information_gain_empty_features_is_zero() {
        let candidate = sample_candidate("empty", 5_000, vec![]);
        let prior = vec![sample_candidate("p", 5_000, vec![500_000])];
        let gain = compute_information_gain(&candidate, &prior);
        assert_eq!(gain, 0);
    }

    // --- Batch scoring tests ---

    #[test]
    fn batch_scoring_assigns_ranks() {
        let config = ScoringConfig::default_config();
        let candidates = vec![
            sample_candidate(
                "c1",
                2_000,
                vec![
                    800_000, 700_000, 100_000, 600_000, 500_000, 400_000, 300_000,
                ],
            ),
            sample_candidate(
                "c2",
                9_000,
                vec![200_000, 300_000, 50_000, 150_000, 100_000, 250_000, 200_000],
            ),
            sample_candidate(
                "c3",
                5_000,
                vec![
                    500_000, 500_000, 100_000, 400_000, 300_000, 600_000, 700_000,
                ],
            ),
        ];
        let batch = score_batch(&candidates, &config);
        assert_eq!(batch.certificates.len(), 3);

        // Verify ranks are sequential.
        let mut ranks: Vec<u32> = batch.certificates.iter().map(|c| c.score.rank).collect();
        ranks.sort();
        assert_eq!(ranks, vec![0, 1, 2]);
    }

    #[test]
    fn batch_scoring_descending_order() {
        let config = ScoringConfig::default_config();
        let candidates = vec![
            sample_candidate(
                "c1",
                2_000,
                vec![
                    800_000, 700_000, 100_000, 600_000, 500_000, 400_000, 300_000,
                ],
            ),
            sample_candidate(
                "c2",
                9_000,
                vec![200_000, 300_000, 50_000, 150_000, 100_000, 250_000, 200_000],
            ),
        ];
        let batch = score_batch(&candidates, &config);
        // Rank 0 should have higher score than rank 1.
        let rank0 = batch
            .certificates
            .iter()
            .find(|c| c.score.rank == 0)
            .unwrap();
        let rank1 = batch
            .certificates
            .iter()
            .find(|c| c.score.rank == 1)
            .unwrap();
        assert!(rank0.score.total_score_millionths >= rank1.score.total_score_millionths);
    }

    // --- Certificate tests ---

    #[test]
    fn certificate_hash_deterministic() {
        let config = ScoringConfig::default_config();
        let candidate = sample_candidate(
            "det",
            5_000,
            vec![
                500_000, 500_000, 100_000, 400_000, 300_000, 600_000, 700_000,
            ],
        );
        let score = score_candidate(&candidate, &config, &[]);
        let cert1 = certify_candidate(&candidate, &score, &config);
        let cert2 = certify_candidate(&candidate, &score, &config);
        assert_eq!(cert1.certificate_hash, cert2.certificate_hash);
    }

    #[test]
    fn certificate_contains_schema_version() {
        let config = ScoringConfig::default_config();
        let candidate = sample_candidate(
            "sv",
            5_000,
            vec![
                500_000, 500_000, 100_000, 400_000, 300_000, 600_000, 700_000,
            ],
        );
        let score = score_candidate(&candidate, &config, &[]);
        let cert = certify_candidate(&candidate, &score, &config);
        assert_eq!(cert.schema_version, NOVELTY_SCHEMA_VERSION);
    }

    #[test]
    fn certificate_serde_roundtrip() {
        let config = ScoringConfig::default_config();
        let candidate = sample_candidate(
            "serde",
            5_000,
            vec![
                500_000, 500_000, 100_000, 400_000, 300_000, 600_000, 700_000,
            ],
        );
        let score = score_candidate(&candidate, &config, &[]);
        let cert = certify_candidate(&candidate, &score, &config);
        let json = serde_json::to_string(&cert).unwrap();
        let back: NoveltyCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(cert, back);
    }

    // --- Verdict classification tests ---

    #[test]
    fn verdict_novel_for_high_score() {
        let config = ScoringConfig::default_config();
        let candidate = sample_candidate(
            "novel",
            2_000,
            vec![
                800_000, 700_000, 100_000, 600_000, 500_000, 400_000, 300_000,
            ],
        );
        let score = score_candidate(&candidate, &config, &[]);
        let cert = certify_candidate(&candidate, &score, &config);
        // A high-scoring candidate should be Novel.
        assert!(
            cert.verdict == NoveltyVerdict::Novel
                || cert.verdict == NoveltyVerdict::ObstructionWitness,
            "expected Novel or ObstructionWitness, got {:?}",
            cert.verdict
        );
    }

    #[test]
    fn verdict_redundant_for_low_score() {
        let config = ScoringConfig::default_config();
        let candidate = sample_candidate(
            "redundant",
            10_000,
            vec![10_000, 10_000, 5_000, 10_000, 10_000, 10_000, 10_000],
        );
        let score = score_candidate(&candidate, &config, &[]);
        let cert = certify_candidate(&candidate, &score, &config);
        assert_eq!(cert.verdict, NoveltyVerdict::Redundant);
    }

    #[test]
    fn verdict_obstruction_witness_for_high_obstruction() {
        let config = ScoringConfig::default_config();
        // High obstruction dimension (index 2).
        let candidate = sample_candidate(
            "obs",
            10_000,
            vec![
                100_000, 100_000, 900_000, 100_000, 100_000, 100_000, 100_000,
            ],
        );
        let score = score_candidate(&candidate, &config, &[]);
        let cert = certify_candidate(&candidate, &score, &config);
        assert_eq!(cert.verdict, NoveltyVerdict::ObstructionWitness);
    }

    // --- Evidence manifest tests ---

    #[test]
    fn evidence_manifest_runs_without_error() {
        let manifest = run_novelty_evidence();
        assert!(manifest.error.is_none());
        assert_eq!(manifest.schema_version, NOVELTY_SCHEMA_VERSION);
        assert_eq!(manifest.candidates_scored, 5);
        assert!(manifest.certificates.len() == 5);
    }

    #[test]
    fn evidence_manifest_has_novel_and_redundant() {
        let manifest = run_novelty_evidence();
        // At least some should be novel and some redundant or marginal.
        assert!(manifest.novel_count + manifest.redundant_count > 0);
    }

    #[test]
    fn evidence_manifest_hash_deterministic() {
        let m1 = run_novelty_evidence();
        let m2 = run_novelty_evidence();
        assert_eq!(m1.manifest_hash, m2.manifest_hash);
    }

    #[test]
    fn evidence_manifest_serde_roundtrip() {
        let manifest = run_novelty_evidence();
        let json = serde_json::to_string(&manifest).unwrap();
        let back: NoveltyEvidenceManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, back);
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
    fn composite_verdict_all_count() {
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
    fn composite_verdict_serde_roundtrip() {
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
        assert!(!NOVELTY_SCHEMA_VERSION.is_empty());
        assert!(!NOVELTY_COMPONENT.is_empty());
        assert!(!NOVELTY_POLICY_ID.is_empty());
        assert_eq!(NOVELTY_POLICY_ID, "RGC-707A");
        assert!(MAX_DIMENSIONS > 0);
        assert!(MIN_SAMPLE_SIZE > 0);
        assert!(DEFAULT_ABSTENTION_THRESHOLD > 0);
        assert!(DEFAULT_ABSTENTION_THRESHOLD <= MILLION);
        assert!(MAX_DESCRIPTION_LENGTH > 0);
        assert!(HIGH_NOVELTY_THRESHOLD > MODERATE_NOVELTY_THRESHOLD);
        assert!(MODERATE_NOVELTY_THRESHOLD > 0);
    }

    #[test]
    fn millionths_value() {
        assert_eq!(MILLIONTHS, 1_000_000);
        assert_eq!(MILLION, MILLIONTHS);
    }

    // --- NoveltyCandidate tests ---

    #[test]
    fn candidate_construction_and_serde() {
        let c = NoveltyCandidate::new(
            "test-candidate".to_string(),
            CandidateKind::Package,
            8_000,
            vec![100_000, 200_000, 300_000],
            b"source-bytes",
        );
        assert_eq!(c.candidate_id, "test-candidate");
        assert_eq!(c.kind, CandidateKind::Package);
        assert_eq!(c.description_length_bits, 8_000);
        assert_eq!(c.feature_vector.len(), 3);

        let json = serde_json::to_string(&c).unwrap();
        let back: NoveltyCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn candidate_source_hash_deterministic() {
        let c1 = NoveltyCandidate::new("a".into(), CandidateKind::Program, 5_000, vec![], b"same");
        let c2 = NoveltyCandidate::new("a".into(), CandidateKind::Program, 5_000, vec![], b"same");
        assert_eq!(c1.source_hash, c2.source_hash);
    }

    #[test]
    fn candidate_different_source_different_hash() {
        let c1 = NoveltyCandidate::new("a".into(), CandidateKind::Program, 5_000, vec![], b"alpha");
        let c2 = NoveltyCandidate::new("a".into(), CandidateKind::Program, 5_000, vec![], b"beta");
        assert_ne!(c1.source_hash, c2.source_hash);
    }

    // --- NoveltyScore tests ---

    #[test]
    fn novelty_score_serde_roundtrip() {
        let score = NoveltyScore {
            candidate_id: "test".to_string(),
            total_score_millionths: 750_000,
            dimension_scores: vec![
                (NoveltyDimension::MinimumDescriptionLength, 800_000),
                (NoveltyDimension::InformationGain, 700_000),
            ],
            is_novel: true,
            rank: 0,
        };
        let json = serde_json::to_string(&score).unwrap();
        let back: NoveltyScore = serde_json::from_str(&json).unwrap();
        assert_eq!(score, back);
    }

    // --- score_candidate tests ---

    #[test]
    fn score_candidate_produces_dimension_scores() {
        let config = ScoringConfig::default_config();
        let candidate = sample_candidate(
            "sc",
            5_000,
            vec![
                500_000, 500_000, 100_000, 400_000, 300_000, 600_000, 700_000,
            ],
        );
        let score = score_candidate(&candidate, &config, &[]);
        assert_eq!(score.candidate_id, "sc");
        assert!(!score.dimension_scores.is_empty());
        assert_eq!(score.dimension_scores.len(), config.dimension_weights.len());
    }

    // --- Empty candidate set test (via batch) ---

    #[test]
    fn empty_batch_produces_empty_results() {
        let config = ScoringConfig::default_config();
        let batch = score_batch(&[], &config);
        assert!(batch.certificates.is_empty());
        assert!(batch.candidates.is_empty());
    }
}
