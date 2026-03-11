//! Differentially verify supported React SSR and client-entry execution
//! paths so runtime claims are grounded in actual shipped-path evidence
//! rather than only compile-time parity.
//!
//! Models five execution-path kinds (SSR, ClientEntry, Hydration,
//! StaticGeneration, StreamingSSR) and four verification modes
//! (FullDifferential, SampledDifferential, SnapshotComparison,
//! HashEquivalence). A differential pair couples a reference path with a
//! candidate path; verification produces a `PathVerdict` with an optional
//! `DivergenceReport` and a hash-chained `DecisionReceipt`.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-807B], bead bd-1lsy.9.7.2.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the react SSR verification module.
pub const SCHEMA_VERSION: &str = "franken-engine.react-ssr-verification.v1";

/// Component name for evidence linkage.
pub const COMPONENT: &str = "react_ssr_verification";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.9.7.2";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-807B";

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLIONTHS: u64 = 1_000_000;

/// Default maximum divergence: 2% = 20_000 millionths.
pub const DEFAULT_MAX_DIVERGENCE: u64 = 20_000;

/// Default minimum number of paths required per batch.
pub const DEFAULT_MIN_PATHS: usize = 2;

/// Maximum number of mismatch records per pair verification.
const MAX_MISMATCHES_PER_PAIR: usize = 10_000;

/// Maximum number of pairs in a batch.
const MAX_BATCH_SIZE: usize = 5_000;

// ---------------------------------------------------------------------------
// ExecutionPathKind
// ---------------------------------------------------------------------------

/// Kind of execution path being verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionPathKind {
    /// Server-side rendering (synchronous).
    Ssr,
    /// Client-entry (browser bootstrap).
    ClientEntry,
    /// Hydration (client-side reconciliation of SSR output).
    Hydration,
    /// Static generation (build-time rendering).
    StaticGeneration,
    /// Streaming SSR (chunked server rendering).
    StreamingSsr,
}

impl ExecutionPathKind {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::Ssr,
        Self::ClientEntry,
        Self::Hydration,
        Self::StaticGeneration,
        Self::StreamingSsr,
    ];

    /// String representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ssr => "ssr",
            Self::ClientEntry => "client_entry",
            Self::Hydration => "hydration",
            Self::StaticGeneration => "static_generation",
            Self::StreamingSsr => "streaming_ssr",
        }
    }
}

impl fmt::Display for ExecutionPathKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// VerificationMode
// ---------------------------------------------------------------------------

/// Mode of differential verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationMode {
    /// Full bit-for-bit differential comparison.
    FullDifferential,
    /// Sampled differential: random subset of outputs compared.
    SampledDifferential,
    /// Snapshot comparison: compare against a stored reference snapshot.
    SnapshotComparison,
    /// Hash equivalence: only content hashes are compared.
    HashEquivalence,
}

impl VerificationMode {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::FullDifferential,
        Self::SampledDifferential,
        Self::SnapshotComparison,
        Self::HashEquivalence,
    ];

    /// String representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullDifferential => "full_differential",
            Self::SampledDifferential => "sampled_differential",
            Self::SnapshotComparison => "snapshot_comparison",
            Self::HashEquivalence => "hash_equivalence",
        }
    }

    /// Whether this mode compares full output content (not just hashes).
    pub fn is_content_level(self) -> bool {
        matches!(self, Self::FullDifferential | Self::SampledDifferential)
    }
}

impl fmt::Display for VerificationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MismatchKind
// ---------------------------------------------------------------------------

/// Kind of mismatch detected between two execution paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchKind {
    /// Rendered output differs between reference and candidate.
    OutputMismatch,
    /// Execution timing diverges beyond threshold.
    TimingAnomaly,
    /// Internal state is incoherent between paths.
    StateIncoherence,
    /// Hydration produced a different DOM than SSR output.
    HydrationMismatch,
    /// Stream chunks diverge between streaming SSR paths.
    StreamChunkDivergence,
    /// Event ordering differs between paths.
    EventOrderViolation,
}

impl MismatchKind {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::OutputMismatch,
        Self::TimingAnomaly,
        Self::StateIncoherence,
        Self::HydrationMismatch,
        Self::StreamChunkDivergence,
        Self::EventOrderViolation,
    ];

    /// String representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutputMismatch => "output_mismatch",
            Self::TimingAnomaly => "timing_anomaly",
            Self::StateIncoherence => "state_incoherence",
            Self::HydrationMismatch => "hydration_mismatch",
            Self::StreamChunkDivergence => "stream_chunk_divergence",
            Self::EventOrderViolation => "event_order_violation",
        }
    }

    /// Severity weight in millionths for divergence scoring.
    pub const fn weight(self) -> u64 {
        match self {
            Self::OutputMismatch => 1_000_000,      // 1.0 — critical
            Self::TimingAnomaly => 200_000,         // 0.2
            Self::StateIncoherence => 800_000,      // 0.8
            Self::HydrationMismatch => 900_000,     // 0.9
            Self::StreamChunkDivergence => 700_000, // 0.7
            Self::EventOrderViolation => 600_000,   // 0.6
        }
    }
}

impl fmt::Display for MismatchKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MismatchSeverity
// ---------------------------------------------------------------------------

/// Severity classification of a mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchSeverity {
    /// Informational: observed but likely benign.
    Info,
    /// Warning: may indicate a real problem.
    Warning,
    /// Error: definitely a real problem.
    Error,
    /// Critical: blocks release.
    Critical,
}

impl MismatchSeverity {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[Self::Info, Self::Warning, Self::Error, Self::Critical];

    /// String representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// Numeric weight for scoring (millionths).
    pub const fn weight(self) -> u64 {
        match self {
            Self::Info => 50_000,        // 0.05
            Self::Warning => 200_000,    // 0.2
            Self::Error => 600_000,      // 0.6
            Self::Critical => 1_000_000, // 1.0
        }
    }
}

impl fmt::Display for MismatchSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// classify_severity
// ---------------------------------------------------------------------------

/// Classify the severity of a mismatch kind.
pub fn classify_severity(kind: MismatchKind) -> MismatchSeverity {
    match kind {
        MismatchKind::OutputMismatch => MismatchSeverity::Critical,
        MismatchKind::TimingAnomaly => MismatchSeverity::Info,
        MismatchKind::StateIncoherence => MismatchSeverity::Error,
        MismatchKind::HydrationMismatch => MismatchSeverity::Critical,
        MismatchKind::StreamChunkDivergence => MismatchSeverity::Error,
        MismatchKind::EventOrderViolation => MismatchSeverity::Warning,
    }
}

// ---------------------------------------------------------------------------
// MismatchRecord
// ---------------------------------------------------------------------------

/// A single mismatch record between two execution paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MismatchRecord {
    /// Kind of mismatch.
    pub kind: MismatchKind,
    /// Severity classification.
    pub severity: MismatchSeverity,
    /// Human-readable detail.
    pub detail: String,
    /// Content hash of the reference output fragment.
    pub reference_hash: ContentHash,
    /// Content hash of the candidate output fragment.
    pub candidate_hash: ContentHash,
}

impl MismatchRecord {
    /// Compute a content hash for this record.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.kind.as_str().as_bytes());
        h.update(self.severity.as_str().as_bytes());
        h.update(self.detail.as_bytes());
        h.update(self.reference_hash.as_bytes());
        h.update(self.candidate_hash.as_bytes());
        ContentHash::compute(&h.finalize())
    }
}

impl fmt::Display for MismatchRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.kind, self.detail)
    }
}

// ---------------------------------------------------------------------------
// PathEvidence
// ---------------------------------------------------------------------------

/// Evidence for a single execution path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathEvidence {
    /// Unique identifier for this path execution.
    pub path_id: String,
    /// Kind of execution path.
    pub execution_kind: ExecutionPathKind,
    /// Verification mode used.
    pub mode: VerificationMode,
    /// Content hash of the execution output.
    pub hash: ContentHash,
    /// Security epoch at evidence collection time.
    pub epoch: SecurityEpoch,
    /// Execution duration in microseconds.
    pub duration_micros: u64,
    /// Number of output bytes produced.
    pub output_size_bytes: u64,
}

impl PathEvidence {
    /// Compute a content hash for this evidence.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.path_id.as_bytes());
        h.update(self.execution_kind.as_str().as_bytes());
        h.update(self.mode.as_str().as_bytes());
        h.update(self.hash.as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update(self.duration_micros.to_le_bytes());
        h.update(self.output_size_bytes.to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

impl fmt::Display for PathEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PathEvidence({}, {}, {}, epoch={})",
            self.path_id,
            self.execution_kind,
            self.mode,
            self.epoch.as_u64()
        )
    }
}

// ---------------------------------------------------------------------------
// DifferentialPair
// ---------------------------------------------------------------------------

/// A pair of execution paths to be differentially verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialPair {
    /// The reference (expected) path evidence.
    pub reference: PathEvidence,
    /// The candidate (actual) path evidence.
    pub candidate: PathEvidence,
    /// Detected mismatches between the two paths.
    pub mismatches: Vec<MismatchRecord>,
}

impl DifferentialPair {
    /// Create a new pair with no mismatches.
    pub fn new(reference: PathEvidence, candidate: PathEvidence) -> Self {
        Self {
            reference,
            candidate,
            mismatches: Vec::new(),
        }
    }

    /// Create a pair with pre-detected mismatches.
    pub fn with_mismatches(
        reference: PathEvidence,
        candidate: PathEvidence,
        mismatches: Vec<MismatchRecord>,
    ) -> Self {
        Self {
            reference,
            candidate,
            mismatches,
        }
    }

    /// Whether the pair's execution kinds match.
    pub fn kinds_match(&self) -> bool {
        self.reference.execution_kind == self.candidate.execution_kind
    }

    /// Whether verification modes match.
    pub fn modes_match(&self) -> bool {
        self.reference.mode == self.candidate.mode
    }

    /// Compute a content hash for this pair.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.reference.content_hash().as_bytes());
        h.update(self.candidate.content_hash().as_bytes());
        h.update((self.mismatches.len() as u64).to_le_bytes());
        for m in &self.mismatches {
            h.update(m.content_hash().as_bytes());
        }
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// VerificationConfig
// ---------------------------------------------------------------------------

/// Configuration for differential SSR verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Minimum number of paths required in a batch.
    pub min_paths: usize,
    /// Maximum divergence score (millionths) before failing.
    pub max_divergence_millionths: u64,
    /// Whether hydration-check is required when Hydration paths are present.
    pub require_hydration_check: bool,
    /// Whether timing anomalies count as failures.
    pub fail_on_timing_anomaly: bool,
    /// Maximum allowed timing ratio divergence (millionths).
    /// E.g. 100_000 = 10% timing divergence allowed.
    pub max_timing_divergence_millionths: u64,
    /// Whether streaming chunk order must be exact.
    pub require_exact_stream_order: bool,
}

impl VerificationConfig {
    /// Strict configuration: minimal tolerance.
    pub fn strict() -> Self {
        Self {
            min_paths: 2,
            max_divergence_millionths: 0,
            require_hydration_check: true,
            fail_on_timing_anomaly: true,
            max_timing_divergence_millionths: 10_000, // 1%
            require_exact_stream_order: true,
        }
    }

    /// Permissive configuration for exploratory runs.
    pub fn permissive() -> Self {
        Self {
            min_paths: 1,
            max_divergence_millionths: 500_000, // 50%
            require_hydration_check: false,
            fail_on_timing_anomaly: false,
            max_timing_divergence_millionths: 500_000, // 50%
            require_exact_stream_order: false,
        }
    }
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            min_paths: DEFAULT_MIN_PATHS,
            max_divergence_millionths: DEFAULT_MAX_DIVERGENCE,
            require_hydration_check: true,
            fail_on_timing_anomaly: false,
            max_timing_divergence_millionths: 100_000, // 10%
            require_exact_stream_order: true,
        }
    }
}

// ---------------------------------------------------------------------------
// validate_config
// ---------------------------------------------------------------------------

/// Validate a verification configuration.
///
/// # Errors
///
/// Returns `VerificationError::InvalidConfig` if the config is malformed.
pub fn validate_config(config: &VerificationConfig) -> Result<(), VerificationError> {
    if config.min_paths == 0 {
        return Err(VerificationError::InvalidConfig {
            reason: "min_paths must be at least 1".to_string(),
        });
    }
    if config.max_divergence_millionths > MILLIONTHS {
        return Err(VerificationError::InvalidConfig {
            reason: format!(
                "max_divergence_millionths {} exceeds 1.0 ({})",
                config.max_divergence_millionths, MILLIONTHS
            ),
        });
    }
    if config.max_timing_divergence_millionths > MILLIONTHS {
        return Err(VerificationError::InvalidConfig {
            reason: format!(
                "max_timing_divergence_millionths {} exceeds 1.0 ({})",
                config.max_timing_divergence_millionths, MILLIONTHS
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PathVerdict
// ---------------------------------------------------------------------------

/// Verdict for a single path-pair verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathVerdict {
    /// Paths are verified equivalent within tolerance.
    Verified,
    /// Paths diverge beyond configured threshold.
    Divergent,
    /// Verification could not complete.
    Inconclusive,
}

impl PathVerdict {
    /// All variants for exhaustive iteration.
    pub const ALL: &[Self] = &[Self::Verified, Self::Divergent, Self::Inconclusive];

    /// String representation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Divergent => "divergent",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// Whether this verdict is positive.
    pub fn is_verified(self) -> bool {
        matches!(self, Self::Verified)
    }

    /// Whether this verdict indicates divergence.
    pub fn is_divergent(self) -> bool {
        matches!(self, Self::Divergent)
    }
}

impl fmt::Display for PathVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DivergenceReport
// ---------------------------------------------------------------------------

/// Detailed report on divergence between a differential pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceReport {
    /// Total divergence score (millionths).
    pub divergence_score: u64,
    /// Mismatches grouped by kind.
    pub mismatch_counts: BTreeMap<String, usize>,
    /// Maximum single-mismatch weight observed.
    pub max_single_weight: u64,
    /// Total number of mismatches.
    pub total_mismatches: usize,
}

impl DivergenceReport {
    /// Whether the report contains any critical mismatches.
    pub fn has_critical(&self) -> bool {
        self.mismatch_counts
            .get(MismatchKind::OutputMismatch.as_str())
            .copied()
            .unwrap_or(0)
            > 0
            || self
                .mismatch_counts
                .get(MismatchKind::HydrationMismatch.as_str())
                .copied()
                .unwrap_or(0)
                > 0
    }

    /// Content hash of this report.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.divergence_score.to_le_bytes());
        for (k, v) in &self.mismatch_counts {
            h.update(k.as_bytes());
            h.update((*v as u64).to_le_bytes());
        }
        h.update(self.max_single_weight.to_le_bytes());
        h.update((self.total_mismatches as u64).to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// PathVerificationResult
// ---------------------------------------------------------------------------

/// Result of verifying a single differential pair.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathVerificationResult {
    /// The verdict.
    pub verdict: PathVerdict,
    /// Divergence report (present when verdict is Divergent or Inconclusive).
    pub divergence_report: Option<DivergenceReport>,
    /// Decision receipt.
    pub receipt: DecisionReceipt,
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Tamper-evident receipt of a verification decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component name.
    pub component: String,
    /// Bead ID.
    pub bead_id: String,
    /// Policy ID.
    pub policy_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Hash of the verification inputs.
    pub input_hash: ContentHash,
    /// Hash of the verdict.
    pub verdict_hash: ContentHash,
    /// Previous receipt hash for chaining (None for first receipt).
    pub previous_hash: Option<ContentHash>,
    /// Timestamp in microseconds.
    pub timestamp_micros: u64,
}

impl DecisionReceipt {
    /// Compute a content hash for the receipt itself.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.schema_version.as_bytes());
        h.update(self.component.as_bytes());
        h.update(self.bead_id.as_bytes());
        h.update(self.policy_id.as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update(self.input_hash.as_bytes());
        h.update(self.verdict_hash.as_bytes());
        if let Some(prev) = &self.previous_hash {
            h.update(prev.as_bytes());
        }
        h.update(self.timestamp_micros.to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// BatchVerdict
// ---------------------------------------------------------------------------

/// Batch verification result over multiple differential pairs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchVerdict {
    /// Schema version.
    pub schema_version: String,
    /// Individual results.
    pub results: Vec<PathVerificationResult>,
    /// Overall verdict.
    pub overall_verdict: PathVerdict,
    /// Total divergence score across all pairs (millionths, capped).
    pub total_divergence_score: u64,
    /// Number of verified pairs.
    pub verified_count: usize,
    /// Number of divergent pairs.
    pub divergent_count: usize,
    /// Number of inconclusive pairs.
    pub inconclusive_count: usize,
    /// Content hash of the batch result.
    pub content_hash: ContentHash,
}

impl BatchVerdict {
    /// Pass rate in millionths.
    pub fn pass_rate(&self) -> u64 {
        let total = self.results.len() as u64;
        if total == 0 {
            return 0;
        }
        (self.verified_count as u64)
            .saturating_mul(MILLIONTHS)
            .checked_div(total)
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// VerificationError
// ---------------------------------------------------------------------------

/// Errors from verification operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(rename_all = "snake_case")]
pub enum VerificationError {
    /// Execution path kinds do not match.
    #[error("path kind mismatch: reference={reference}, candidate={candidate}")]
    PathKindMismatch {
        reference: ExecutionPathKind,
        candidate: ExecutionPathKind,
    },

    /// Verification modes do not match.
    #[error("mode mismatch: reference={reference}, candidate={candidate}")]
    ModeMismatch {
        reference: VerificationMode,
        candidate: VerificationMode,
    },

    /// Too many mismatches in a pair.
    #[error("too many mismatches: {count} > {max}")]
    TooManyMismatches { count: usize, max: usize },

    /// Batch too large.
    #[error("batch too large: {count} > {max}")]
    BatchTooLarge { count: usize, max: usize },

    /// Batch too small (below min_paths).
    #[error("batch too small: {count} < {min}")]
    BatchTooSmall { count: usize, min: usize },

    /// Invalid configuration.
    #[error("invalid config: {reason}")]
    InvalidConfig { reason: String },

    /// Duplicate path IDs in a batch.
    #[error("duplicate path id: {path_id}")]
    DuplicatePathId { path_id: String },
}

// ---------------------------------------------------------------------------
// compute_divergence_score
// ---------------------------------------------------------------------------

/// Compute the aggregate divergence score from a list of mismatch records.
///
/// The score is the sum of each mismatch's kind weight, capped at `MILLIONTHS`.
/// Returns a value in millionths.
pub fn compute_divergence_score(mismatches: &[MismatchRecord]) -> u64 {
    let raw: u64 = mismatches
        .iter()
        .map(|m| m.kind.weight())
        .fold(0u64, |acc, w| acc.saturating_add(w));
    raw.min(MILLIONTHS)
}

// ---------------------------------------------------------------------------
// build_divergence_report
// ---------------------------------------------------------------------------

fn build_divergence_report(mismatches: &[MismatchRecord]) -> DivergenceReport {
    let divergence_score = compute_divergence_score(mismatches);

    let mut mismatch_counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut max_single_weight: u64 = 0;

    for m in mismatches {
        *mismatch_counts
            .entry(m.kind.as_str().to_string())
            .or_insert(0) += 1;
        let w = m.kind.weight();
        if w > max_single_weight {
            max_single_weight = w;
        }
    }

    DivergenceReport {
        divergence_score,
        mismatch_counts,
        max_single_weight,
        total_mismatches: mismatches.len(),
    }
}

// ---------------------------------------------------------------------------
// compute_receipt
// ---------------------------------------------------------------------------

/// Compute a decision receipt.
pub fn compute_receipt(
    input_hash: ContentHash,
    verdict: &PathVerdict,
    epoch: &SecurityEpoch,
    previous_hash: Option<ContentHash>,
    timestamp_micros: u64,
) -> DecisionReceipt {
    let verdict_hash = ContentHash::compute(verdict.as_str().as_bytes());
    DecisionReceipt {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        epoch: *epoch,
        input_hash,
        verdict_hash,
        previous_hash,
        timestamp_micros,
    }
}

// ---------------------------------------------------------------------------
// verify_path_pair
// ---------------------------------------------------------------------------

/// Verify a single differential pair.
///
/// # Errors
///
/// Returns `VerificationError` if the pair is structurally invalid.
pub fn verify_path_pair(
    pair: &DifferentialPair,
    config: &VerificationConfig,
) -> Result<PathVerificationResult, VerificationError> {
    validate_config(config)?;

    // Structural validation.
    if !pair.kinds_match() {
        return Err(VerificationError::PathKindMismatch {
            reference: pair.reference.execution_kind,
            candidate: pair.candidate.execution_kind,
        });
    }
    if !pair.modes_match() {
        return Err(VerificationError::ModeMismatch {
            reference: pair.reference.mode,
            candidate: pair.candidate.mode,
        });
    }
    if pair.mismatches.len() > MAX_MISMATCHES_PER_PAIR {
        return Err(VerificationError::TooManyMismatches {
            count: pair.mismatches.len(),
            max: MAX_MISMATCHES_PER_PAIR,
        });
    }

    let epoch = &pair.reference.epoch;
    let input_hash = pair.content_hash();
    let timestamp_micros = 0; // Caller-controlled in batch; standalone uses 0.

    // If no mismatches, path is verified.
    if pair.mismatches.is_empty() {
        let verdict = PathVerdict::Verified;
        let receipt = compute_receipt(input_hash, &verdict, epoch, None, timestamp_micros);
        return Ok(PathVerificationResult {
            verdict,
            divergence_report: None,
            receipt,
        });
    }

    // Build divergence report.
    let report = build_divergence_report(&pair.mismatches);

    // Check hydration requirement.
    if config.require_hydration_check
        && pair.reference.execution_kind == ExecutionPathKind::Hydration
        && report.has_critical()
    {
        let verdict = PathVerdict::Divergent;
        let receipt = compute_receipt(input_hash, &verdict, epoch, None, timestamp_micros);
        return Ok(PathVerificationResult {
            verdict,
            divergence_report: Some(report),
            receipt,
        });
    }

    // Check timing anomaly policy.
    if config.fail_on_timing_anomaly {
        let has_timing = pair
            .mismatches
            .iter()
            .any(|m| m.kind == MismatchKind::TimingAnomaly);
        if has_timing {
            let verdict = PathVerdict::Divergent;
            let receipt = compute_receipt(input_hash, &verdict, epoch, None, timestamp_micros);
            return Ok(PathVerificationResult {
                verdict,
                divergence_report: Some(report),
                receipt,
            });
        }
    }

    // Check divergence score threshold.
    let verdict = if report.divergence_score > config.max_divergence_millionths {
        PathVerdict::Divergent
    } else {
        PathVerdict::Verified
    };

    let receipt = compute_receipt(input_hash, &verdict, epoch, None, timestamp_micros);
    Ok(PathVerificationResult {
        verdict,
        divergence_report: Some(report),
        receipt,
    })
}

// ---------------------------------------------------------------------------
// verify_batch
// ---------------------------------------------------------------------------

/// Verify a batch of differential pairs with hash-chained receipts.
///
/// # Errors
///
/// Returns `VerificationError` if validation fails or a pair is invalid.
pub fn verify_batch(
    pairs: &[DifferentialPair],
    config: &VerificationConfig,
) -> Result<BatchVerdict, VerificationError> {
    validate_config(config)?;

    if pairs.len() > MAX_BATCH_SIZE {
        return Err(VerificationError::BatchTooLarge {
            count: pairs.len(),
            max: MAX_BATCH_SIZE,
        });
    }
    if pairs.len() < config.min_paths {
        return Err(VerificationError::BatchTooSmall {
            count: pairs.len(),
            min: config.min_paths,
        });
    }

    // Check for duplicate path IDs.
    let mut seen_ids: BTreeMap<&str, bool> = BTreeMap::new();
    for pair in pairs {
        if seen_ids.contains_key(pair.reference.path_id.as_str()) {
            return Err(VerificationError::DuplicatePathId {
                path_id: pair.reference.path_id.clone(),
            });
        }
        seen_ids.insert(&pair.reference.path_id, true);
        if seen_ids.contains_key(pair.candidate.path_id.as_str()) {
            return Err(VerificationError::DuplicatePathId {
                path_id: pair.candidate.path_id.clone(),
            });
        }
        seen_ids.insert(&pair.candidate.path_id, true);
    }

    let mut results = Vec::with_capacity(pairs.len());
    let mut previous_hash: Option<ContentHash> = None;
    let mut verified_count = 0usize;
    let mut divergent_count = 0usize;
    let mut inconclusive_count = 0usize;
    let mut total_divergence_score = 0u64;

    for (i, pair) in pairs.iter().enumerate() {
        // Structural validation per pair.
        if !pair.kinds_match() {
            return Err(VerificationError::PathKindMismatch {
                reference: pair.reference.execution_kind,
                candidate: pair.candidate.execution_kind,
            });
        }
        if !pair.modes_match() {
            return Err(VerificationError::ModeMismatch {
                reference: pair.reference.mode,
                candidate: pair.candidate.mode,
            });
        }
        if pair.mismatches.len() > MAX_MISMATCHES_PER_PAIR {
            return Err(VerificationError::TooManyMismatches {
                count: pair.mismatches.len(),
                max: MAX_MISMATCHES_PER_PAIR,
            });
        }

        let epoch = &pair.reference.epoch;
        let input_hash = pair.content_hash();
        let timestamp_micros = i as u64;

        if pair.mismatches.is_empty() {
            let verdict = PathVerdict::Verified;
            let receipt = compute_receipt(
                input_hash,
                &verdict,
                epoch,
                previous_hash.clone(),
                timestamp_micros,
            );
            previous_hash = Some(receipt.content_hash());
            verified_count += 1;
            results.push(PathVerificationResult {
                verdict,
                divergence_report: None,
                receipt,
            });
            continue;
        }

        let report = build_divergence_report(&pair.mismatches);
        total_divergence_score = total_divergence_score.saturating_add(report.divergence_score);

        // Determine verdict.
        let mut verdict = PathVerdict::Verified;

        if config.require_hydration_check
            && pair.reference.execution_kind == ExecutionPathKind::Hydration
            && report.has_critical()
        {
            verdict = PathVerdict::Divergent;
        }

        if verdict == PathVerdict::Verified && config.fail_on_timing_anomaly {
            let has_timing = pair
                .mismatches
                .iter()
                .any(|m| m.kind == MismatchKind::TimingAnomaly);
            if has_timing {
                verdict = PathVerdict::Divergent;
            }
        }

        if verdict == PathVerdict::Verified
            && report.divergence_score > config.max_divergence_millionths
        {
            verdict = PathVerdict::Divergent;
        }

        match verdict {
            PathVerdict::Verified => verified_count += 1,
            PathVerdict::Divergent => divergent_count += 1,
            PathVerdict::Inconclusive => inconclusive_count += 1,
        }

        let receipt = compute_receipt(
            input_hash,
            &verdict,
            epoch,
            previous_hash.clone(),
            timestamp_micros,
        );
        previous_hash = Some(receipt.content_hash());

        results.push(PathVerificationResult {
            verdict,
            divergence_report: Some(report),
            receipt,
        });
    }

    let overall_verdict = if divergent_count > 0 {
        PathVerdict::Divergent
    } else if inconclusive_count > 0 {
        PathVerdict::Inconclusive
    } else {
        PathVerdict::Verified
    };

    let mut h = Sha256::new();
    h.update(SCHEMA_VERSION.as_bytes());
    h.update((results.len() as u64).to_le_bytes());
    for r in &results {
        h.update(r.verdict.as_str().as_bytes());
        h.update(r.receipt.input_hash.as_bytes());
    }
    let content_hash = ContentHash::compute(&h.finalize());

    Ok(BatchVerdict {
        schema_version: SCHEMA_VERSION.to_string(),
        results,
        overall_verdict,
        total_divergence_score,
        verified_count,
        divergent_count,
        inconclusive_count,
        content_hash,
    })
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    fn make_evidence(
        path_id: &str,
        kind: ExecutionPathKind,
        mode: VerificationMode,
        content: &[u8],
    ) -> PathEvidence {
        PathEvidence {
            path_id: path_id.to_string(),
            execution_kind: kind,
            mode,
            hash: ContentHash::compute(content),
            epoch: epoch(),
            duration_micros: 1000,
            output_size_bytes: content.len() as u64,
        }
    }

    fn ssr_evidence(path_id: &str, content: &[u8]) -> PathEvidence {
        make_evidence(
            path_id,
            ExecutionPathKind::Ssr,
            VerificationMode::FullDifferential,
            content,
        )
    }

    fn client_evidence(path_id: &str, content: &[u8]) -> PathEvidence {
        make_evidence(
            path_id,
            ExecutionPathKind::ClientEntry,
            VerificationMode::FullDifferential,
            content,
        )
    }

    fn hydration_evidence(path_id: &str, content: &[u8]) -> PathEvidence {
        make_evidence(
            path_id,
            ExecutionPathKind::Hydration,
            VerificationMode::FullDifferential,
            content,
        )
    }

    fn make_mismatch(kind: MismatchKind) -> MismatchRecord {
        MismatchRecord {
            kind,
            severity: classify_severity(kind),
            detail: format!("test mismatch: {}", kind),
            reference_hash: ContentHash::compute(b"ref"),
            candidate_hash: ContentHash::compute(b"cand"),
        }
    }

    fn default_config() -> VerificationConfig {
        VerificationConfig::default()
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SCHEMA_VERSION.contains("react-ssr-verification"));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "react_ssr_verification");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
        assert_eq!(BEAD_ID, "bd-1lsy.9.7.2");
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
        assert_eq!(POLICY_ID, "RGC-807B");
    }

    #[test]
    fn default_max_divergence_within_bounds() {
        const { assert!(DEFAULT_MAX_DIVERGENCE <= MILLIONTHS) };
    }

    #[test]
    fn default_min_paths_positive() {
        assert_eq!(DEFAULT_MIN_PATHS, 2);
    }

    // --- ExecutionPathKind ---

    #[test]
    fn execution_path_kind_all_variants() {
        assert_eq!(ExecutionPathKind::ALL.len(), 5);
    }

    #[test]
    fn execution_path_kind_as_str_roundtrip() {
        for kind in ExecutionPathKind::ALL {
            let s = kind.as_str();
            assert!(!s.is_empty());
            assert_eq!(kind.to_string(), s);
        }
    }

    #[test]
    fn execution_path_kind_display() {
        assert_eq!(ExecutionPathKind::Ssr.to_string(), "ssr");
        assert_eq!(ExecutionPathKind::ClientEntry.to_string(), "client_entry");
        assert_eq!(ExecutionPathKind::Hydration.to_string(), "hydration");
        assert_eq!(
            ExecutionPathKind::StaticGeneration.to_string(),
            "static_generation"
        );
        assert_eq!(ExecutionPathKind::StreamingSsr.to_string(), "streaming_ssr");
    }

    #[test]
    fn execution_path_kind_serde_roundtrip() {
        for kind in ExecutionPathKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: ExecutionPathKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn execution_path_kind_ordering() {
        assert!(ExecutionPathKind::Ssr < ExecutionPathKind::ClientEntry);
    }

    // --- VerificationMode ---

    #[test]
    fn verification_mode_all_variants() {
        assert_eq!(VerificationMode::ALL.len(), 4);
    }

    #[test]
    fn verification_mode_as_str() {
        assert_eq!(
            VerificationMode::FullDifferential.as_str(),
            "full_differential"
        );
        assert_eq!(
            VerificationMode::SampledDifferential.as_str(),
            "sampled_differential"
        );
        assert_eq!(
            VerificationMode::SnapshotComparison.as_str(),
            "snapshot_comparison"
        );
        assert_eq!(
            VerificationMode::HashEquivalence.as_str(),
            "hash_equivalence"
        );
    }

    #[test]
    fn verification_mode_is_content_level() {
        assert!(VerificationMode::FullDifferential.is_content_level());
        assert!(VerificationMode::SampledDifferential.is_content_level());
        assert!(!VerificationMode::SnapshotComparison.is_content_level());
        assert!(!VerificationMode::HashEquivalence.is_content_level());
    }

    #[test]
    fn verification_mode_serde_roundtrip() {
        for mode in VerificationMode::ALL {
            let json = serde_json::to_string(mode).unwrap();
            let back: VerificationMode = serde_json::from_str(&json).unwrap();
            assert_eq!(*mode, back);
        }
    }

    #[test]
    fn verification_mode_display() {
        for mode in VerificationMode::ALL {
            assert_eq!(mode.to_string(), mode.as_str());
        }
    }

    // --- MismatchKind ---

    #[test]
    fn mismatch_kind_all_variants() {
        assert_eq!(MismatchKind::ALL.len(), 6);
    }

    #[test]
    fn mismatch_kind_as_str() {
        assert_eq!(MismatchKind::OutputMismatch.as_str(), "output_mismatch");
        assert_eq!(MismatchKind::TimingAnomaly.as_str(), "timing_anomaly");
        assert_eq!(MismatchKind::StateIncoherence.as_str(), "state_incoherence");
        assert_eq!(
            MismatchKind::HydrationMismatch.as_str(),
            "hydration_mismatch"
        );
        assert_eq!(
            MismatchKind::StreamChunkDivergence.as_str(),
            "stream_chunk_divergence"
        );
        assert_eq!(
            MismatchKind::EventOrderViolation.as_str(),
            "event_order_violation"
        );
    }

    #[test]
    fn mismatch_kind_weights_positive() {
        for kind in MismatchKind::ALL {
            assert!(kind.weight() > 0);
            assert!(kind.weight() <= MILLIONTHS);
        }
    }

    #[test]
    fn mismatch_kind_serde_roundtrip() {
        for kind in MismatchKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: MismatchKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn mismatch_kind_display() {
        for kind in MismatchKind::ALL {
            assert_eq!(kind.to_string(), kind.as_str());
        }
    }

    // --- MismatchSeverity ---

    #[test]
    fn mismatch_severity_all_variants() {
        assert_eq!(MismatchSeverity::ALL.len(), 4);
    }

    #[test]
    fn mismatch_severity_weights_increasing() {
        let weights: Vec<u64> = MismatchSeverity::ALL.iter().map(|s| s.weight()).collect();
        for w in weights.windows(2) {
            assert!(w[0] < w[1], "severity weights must be strictly increasing");
        }
    }

    #[test]
    fn mismatch_severity_serde_roundtrip() {
        for sev in MismatchSeverity::ALL {
            let json = serde_json::to_string(sev).unwrap();
            let back: MismatchSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(*sev, back);
        }
    }

    // --- classify_severity ---

    #[test]
    fn classify_severity_output_mismatch_is_critical() {
        assert_eq!(
            classify_severity(MismatchKind::OutputMismatch),
            MismatchSeverity::Critical
        );
    }

    #[test]
    fn classify_severity_timing_is_info() {
        assert_eq!(
            classify_severity(MismatchKind::TimingAnomaly),
            MismatchSeverity::Info
        );
    }

    #[test]
    fn classify_severity_hydration_is_critical() {
        assert_eq!(
            classify_severity(MismatchKind::HydrationMismatch),
            MismatchSeverity::Critical
        );
    }

    #[test]
    fn classify_severity_all_kinds_covered() {
        for kind in MismatchKind::ALL {
            let _sev = classify_severity(*kind);
        }
    }

    // --- MismatchRecord ---

    #[test]
    fn mismatch_record_content_hash_deterministic() {
        let m1 = make_mismatch(MismatchKind::OutputMismatch);
        let m2 = make_mismatch(MismatchKind::OutputMismatch);
        assert_eq!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn mismatch_record_different_kinds_different_hash() {
        let m1 = make_mismatch(MismatchKind::OutputMismatch);
        let m2 = make_mismatch(MismatchKind::TimingAnomaly);
        assert_ne!(m1.content_hash(), m2.content_hash());
    }

    #[test]
    fn mismatch_record_display() {
        let m = make_mismatch(MismatchKind::OutputMismatch);
        let s = m.to_string();
        assert!(s.contains("critical"));
        assert!(s.contains("output_mismatch"));
    }

    // --- PathEvidence ---

    #[test]
    fn path_evidence_content_hash_deterministic() {
        let e1 = ssr_evidence("p1", b"hello");
        let e2 = ssr_evidence("p1", b"hello");
        assert_eq!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn path_evidence_different_content_different_hash() {
        let e1 = ssr_evidence("p1", b"hello");
        let e2 = ssr_evidence("p1", b"world");
        assert_ne!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn path_evidence_display() {
        let e = ssr_evidence("p1", b"data");
        let s = e.to_string();
        assert!(s.contains("p1"));
        assert!(s.contains("ssr"));
    }

    #[test]
    fn path_evidence_serde_roundtrip() {
        let e = ssr_evidence("p1", b"data");
        let json = serde_json::to_string(&e).unwrap();
        let back: PathEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- DifferentialPair ---

    #[test]
    fn differential_pair_new_no_mismatches() {
        let pair = DifferentialPair::new(ssr_evidence("ref", b"a"), ssr_evidence("cand", b"a"));
        assert!(pair.mismatches.is_empty());
        assert!(pair.kinds_match());
        assert!(pair.modes_match());
    }

    #[test]
    fn differential_pair_with_mismatches() {
        let pair = DifferentialPair::with_mismatches(
            ssr_evidence("ref", b"a"),
            ssr_evidence("cand", b"b"),
            vec![make_mismatch(MismatchKind::OutputMismatch)],
        );
        assert_eq!(pair.mismatches.len(), 1);
    }

    #[test]
    fn differential_pair_kinds_mismatch() {
        let pair = DifferentialPair::new(ssr_evidence("ref", b"a"), client_evidence("cand", b"a"));
        assert!(!pair.kinds_match());
    }

    #[test]
    fn differential_pair_content_hash_deterministic() {
        let p1 = DifferentialPair::new(ssr_evidence("ref", b"a"), ssr_evidence("cand", b"b"));
        let p2 = DifferentialPair::new(ssr_evidence("ref", b"a"), ssr_evidence("cand", b"b"));
        assert_eq!(p1.content_hash(), p2.content_hash());
    }

    // --- VerificationConfig ---

    #[test]
    fn config_default_valid() {
        let c = VerificationConfig::default();
        assert!(validate_config(&c).is_ok());
    }

    #[test]
    fn config_strict_valid() {
        let c = VerificationConfig::strict();
        assert!(validate_config(&c).is_ok());
    }

    #[test]
    fn config_permissive_valid() {
        let c = VerificationConfig::permissive();
        assert!(validate_config(&c).is_ok());
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = default_config();
        let json = serde_json::to_string(&c).unwrap();
        let back: VerificationConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- validate_config ---

    #[test]
    fn validate_config_zero_min_paths_rejected() {
        let mut c = default_config();
        c.min_paths = 0;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_divergence_over_one_rejected() {
        let mut c = default_config();
        c.max_divergence_millionths = MILLIONTHS + 1;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_timing_over_one_rejected() {
        let mut c = default_config();
        c.max_timing_divergence_millionths = MILLIONTHS + 1;
        assert!(validate_config(&c).is_err());
    }

    #[test]
    fn validate_config_boundary_one_accepted() {
        let mut c = default_config();
        c.max_divergence_millionths = MILLIONTHS;
        c.max_timing_divergence_millionths = MILLIONTHS;
        assert!(validate_config(&c).is_ok());
    }

    // --- PathVerdict ---

    #[test]
    fn path_verdict_all_variants() {
        assert_eq!(PathVerdict::ALL.len(), 3);
    }

    #[test]
    fn path_verdict_is_verified() {
        assert!(PathVerdict::Verified.is_verified());
        assert!(!PathVerdict::Divergent.is_verified());
        assert!(!PathVerdict::Inconclusive.is_verified());
    }

    #[test]
    fn path_verdict_is_divergent() {
        assert!(!PathVerdict::Verified.is_divergent());
        assert!(PathVerdict::Divergent.is_divergent());
        assert!(!PathVerdict::Inconclusive.is_divergent());
    }

    #[test]
    fn path_verdict_serde_roundtrip() {
        for v in PathVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: PathVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn path_verdict_display() {
        for v in PathVerdict::ALL {
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    // --- compute_divergence_score ---

    #[test]
    fn divergence_score_empty() {
        assert_eq!(compute_divergence_score(&[]), 0);
    }

    #[test]
    fn divergence_score_single_output_mismatch() {
        let score = compute_divergence_score(&[make_mismatch(MismatchKind::OutputMismatch)]);
        assert_eq!(score, MismatchKind::OutputMismatch.weight());
    }

    #[test]
    fn divergence_score_capped_at_millionths() {
        let many: Vec<MismatchRecord> = (0..10)
            .map(|_| make_mismatch(MismatchKind::OutputMismatch))
            .collect();
        let score = compute_divergence_score(&many);
        assert_eq!(score, MILLIONTHS);
    }

    #[test]
    fn divergence_score_additive() {
        let mismatches = vec![
            make_mismatch(MismatchKind::TimingAnomaly),
            make_mismatch(MismatchKind::EventOrderViolation),
        ];
        let score = compute_divergence_score(&mismatches);
        let expected =
            MismatchKind::TimingAnomaly.weight() + MismatchKind::EventOrderViolation.weight();
        assert_eq!(score, expected);
    }

    // --- verify_path_pair ---

    #[test]
    fn verify_pair_no_mismatches_is_verified() {
        let pair =
            DifferentialPair::new(ssr_evidence("ref", b"same"), ssr_evidence("cand", b"same"));
        let result = verify_path_pair(&pair, &default_config()).unwrap();
        assert_eq!(result.verdict, PathVerdict::Verified);
        assert!(result.divergence_report.is_none());
    }

    #[test]
    fn verify_pair_high_divergence_is_divergent() {
        let pair = DifferentialPair::with_mismatches(
            ssr_evidence("ref", b"a"),
            ssr_evidence("cand", b"b"),
            vec![make_mismatch(MismatchKind::OutputMismatch)],
        );
        let result = verify_path_pair(&pair, &default_config()).unwrap();
        assert_eq!(result.verdict, PathVerdict::Divergent);
        assert!(result.divergence_report.is_some());
    }

    #[test]
    fn verify_pair_kind_mismatch_error() {
        let pair = DifferentialPair::new(ssr_evidence("ref", b"a"), client_evidence("cand", b"a"));
        let err = verify_path_pair(&pair, &default_config()).unwrap_err();
        assert!(matches!(err, VerificationError::PathKindMismatch { .. }));
    }

    #[test]
    fn verify_pair_mode_mismatch_error() {
        let ref_ev = make_evidence(
            "ref",
            ExecutionPathKind::Ssr,
            VerificationMode::FullDifferential,
            b"a",
        );
        let cand_ev = make_evidence(
            "cand",
            ExecutionPathKind::Ssr,
            VerificationMode::HashEquivalence,
            b"a",
        );
        let pair = DifferentialPair::new(ref_ev, cand_ev);
        let err = verify_path_pair(&pair, &default_config()).unwrap_err();
        assert!(matches!(err, VerificationError::ModeMismatch { .. }));
    }

    #[test]
    fn verify_pair_hydration_critical_is_divergent() {
        let pair = DifferentialPair::with_mismatches(
            hydration_evidence("ref", b"a"),
            hydration_evidence("cand", b"b"),
            vec![make_mismatch(MismatchKind::HydrationMismatch)],
        );
        let config = VerificationConfig {
            require_hydration_check: true,
            max_divergence_millionths: MILLIONTHS, // would pass on score alone
            ..default_config()
        };
        let result = verify_path_pair(&pair, &config).unwrap();
        assert_eq!(result.verdict, PathVerdict::Divergent);
    }

    #[test]
    fn verify_pair_timing_anomaly_with_fail_on_timing() {
        let pair = DifferentialPair::with_mismatches(
            ssr_evidence("ref", b"a"),
            ssr_evidence("cand", b"a"),
            vec![make_mismatch(MismatchKind::TimingAnomaly)],
        );
        let config = VerificationConfig {
            fail_on_timing_anomaly: true,
            ..default_config()
        };
        let result = verify_path_pair(&pair, &config).unwrap();
        assert_eq!(result.verdict, PathVerdict::Divergent);
    }

    #[test]
    fn verify_pair_timing_anomaly_without_fail_on_timing() {
        let pair = DifferentialPair::with_mismatches(
            ssr_evidence("ref", b"a"),
            ssr_evidence("cand", b"a"),
            vec![make_mismatch(MismatchKind::TimingAnomaly)],
        );
        let config = VerificationConfig {
            fail_on_timing_anomaly: false,
            max_divergence_millionths: MILLIONTHS, // permissive score
            ..default_config()
        };
        let result = verify_path_pair(&pair, &config).unwrap();
        assert_eq!(result.verdict, PathVerdict::Verified);
    }

    #[test]
    fn verify_pair_receipt_has_correct_metadata() {
        let pair =
            DifferentialPair::new(ssr_evidence("ref", b"same"), ssr_evidence("cand", b"same"));
        let result = verify_path_pair(&pair, &default_config()).unwrap();
        assert_eq!(result.receipt.schema_version, SCHEMA_VERSION);
        assert_eq!(result.receipt.component, COMPONENT);
        assert_eq!(result.receipt.bead_id, BEAD_ID);
        assert_eq!(result.receipt.policy_id, POLICY_ID);
    }

    #[test]
    fn verify_pair_receipt_content_hash_deterministic() {
        let pair = DifferentialPair::new(ssr_evidence("ref", b"x"), ssr_evidence("cand", b"x"));
        let r1 = verify_path_pair(&pair, &default_config()).unwrap();
        let r2 = verify_path_pair(&pair, &default_config()).unwrap();
        assert_eq!(r1.receipt.content_hash(), r2.receipt.content_hash());
    }

    // --- verify_batch ---

    #[test]
    fn verify_batch_all_verified() {
        let pairs = vec![
            DifferentialPair::new(ssr_evidence("r1", b"a"), ssr_evidence("c1", b"a")),
            DifferentialPair::new(ssr_evidence("r2", b"b"), ssr_evidence("c2", b"b")),
        ];
        let result = verify_batch(&pairs, &default_config()).unwrap();
        assert_eq!(result.overall_verdict, PathVerdict::Verified);
        assert_eq!(result.verified_count, 2);
        assert_eq!(result.divergent_count, 0);
        assert_eq!(result.pass_rate(), MILLIONTHS);
    }

    #[test]
    fn verify_batch_one_divergent() {
        let pairs = vec![
            DifferentialPair::new(ssr_evidence("r1", b"a"), ssr_evidence("c1", b"a")),
            DifferentialPair::with_mismatches(
                ssr_evidence("r2", b"b"),
                ssr_evidence("c2", b"c"),
                vec![make_mismatch(MismatchKind::OutputMismatch)],
            ),
        ];
        let result = verify_batch(&pairs, &default_config()).unwrap();
        assert_eq!(result.overall_verdict, PathVerdict::Divergent);
        assert_eq!(result.verified_count, 1);
        assert_eq!(result.divergent_count, 1);
    }

    #[test]
    fn verify_batch_empty_below_min_paths() {
        let err = verify_batch(&[], &default_config()).unwrap_err();
        assert!(matches!(err, VerificationError::BatchTooSmall { .. }));
    }

    #[test]
    fn verify_batch_duplicate_path_id_rejected() {
        let pairs = vec![
            DifferentialPair::new(ssr_evidence("dup", b"a"), ssr_evidence("c1", b"a")),
            DifferentialPair::new(ssr_evidence("r2", b"b"), ssr_evidence("dup", b"b")),
        ];
        let err = verify_batch(&pairs, &default_config()).unwrap_err();
        assert!(matches!(err, VerificationError::DuplicatePathId { .. }));
    }

    #[test]
    fn verify_batch_receipt_chaining() {
        let pairs = vec![
            DifferentialPair::new(ssr_evidence("r1", b"a"), ssr_evidence("c1", b"a")),
            DifferentialPair::new(ssr_evidence("r2", b"b"), ssr_evidence("c2", b"b")),
            DifferentialPair::new(ssr_evidence("r3", b"c"), ssr_evidence("c3", b"c")),
        ];
        let result = verify_batch(&pairs, &default_config()).unwrap();
        // First receipt has no previous hash.
        assert!(result.results[0].receipt.previous_hash.is_none());
        // Subsequent receipts chain to previous.
        assert!(result.results[1].receipt.previous_hash.is_some());
        assert!(result.results[2].receipt.previous_hash.is_some());
        // Chain is deterministic.
        let r2 = verify_batch(&pairs, &default_config()).unwrap();
        assert_eq!(
            result.results[2].receipt.previous_hash,
            r2.results[2].receipt.previous_hash
        );
    }

    #[test]
    fn verify_batch_pass_rate_zero_when_all_divergent() {
        let pairs = vec![
            DifferentialPair::with_mismatches(
                ssr_evidence("r1", b"a"),
                ssr_evidence("c1", b"b"),
                vec![make_mismatch(MismatchKind::OutputMismatch)],
            ),
            DifferentialPair::with_mismatches(
                ssr_evidence("r2", b"c"),
                ssr_evidence("c2", b"d"),
                vec![make_mismatch(MismatchKind::OutputMismatch)],
            ),
        ];
        let result = verify_batch(&pairs, &default_config()).unwrap();
        assert_eq!(result.pass_rate(), 0);
    }

    #[test]
    fn verify_batch_content_hash_deterministic() {
        let pairs = vec![
            DifferentialPair::new(ssr_evidence("r1", b"x"), ssr_evidence("c1", b"x")),
            DifferentialPair::new(ssr_evidence("r2", b"y"), ssr_evidence("c2", b"y")),
        ];
        let b1 = verify_batch(&pairs, &default_config()).unwrap();
        let b2 = verify_batch(&pairs, &default_config()).unwrap();
        assert_eq!(b1.content_hash, b2.content_hash);
    }

    // --- DivergenceReport ---

    #[test]
    fn divergence_report_has_critical_output() {
        let report = build_divergence_report(&[make_mismatch(MismatchKind::OutputMismatch)]);
        assert!(report.has_critical());
    }

    #[test]
    fn divergence_report_has_critical_hydration() {
        let report = build_divergence_report(&[make_mismatch(MismatchKind::HydrationMismatch)]);
        assert!(report.has_critical());
    }

    #[test]
    fn divergence_report_not_critical_timing() {
        let report = build_divergence_report(&[make_mismatch(MismatchKind::TimingAnomaly)]);
        assert!(!report.has_critical());
    }

    #[test]
    fn divergence_report_counts_by_kind() {
        let report = build_divergence_report(&[
            make_mismatch(MismatchKind::TimingAnomaly),
            make_mismatch(MismatchKind::TimingAnomaly),
            make_mismatch(MismatchKind::OutputMismatch),
        ]);
        assert_eq!(
            report
                .mismatch_counts
                .get(MismatchKind::TimingAnomaly.as_str()),
            Some(&2)
        );
        assert_eq!(
            report
                .mismatch_counts
                .get(MismatchKind::OutputMismatch.as_str()),
            Some(&1)
        );
        assert_eq!(report.total_mismatches, 3);
    }

    #[test]
    fn divergence_report_content_hash_deterministic() {
        let r1 = build_divergence_report(&[make_mismatch(MismatchKind::OutputMismatch)]);
        let r2 = build_divergence_report(&[make_mismatch(MismatchKind::OutputMismatch)]);
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    // --- DecisionReceipt ---

    #[test]
    fn receipt_content_hash_deterministic() {
        let input_hash = ContentHash::compute(b"input");
        let r1 = compute_receipt(
            input_hash.clone(),
            &PathVerdict::Verified,
            &epoch(),
            None,
            1000,
        );
        let r2 = compute_receipt(input_hash, &PathVerdict::Verified, &epoch(), None, 1000);
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn receipt_different_verdicts_different_hash() {
        let input_hash = ContentHash::compute(b"input");
        let r1 = compute_receipt(
            input_hash.clone(),
            &PathVerdict::Verified,
            &epoch(),
            None,
            1000,
        );
        let r2 = compute_receipt(input_hash, &PathVerdict::Divergent, &epoch(), None, 1000);
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn receipt_with_previous_hash_differs() {
        let input_hash = ContentHash::compute(b"input");
        let prev = ContentHash::compute(b"prev");
        let r1 = compute_receipt(
            input_hash.clone(),
            &PathVerdict::Verified,
            &epoch(),
            None,
            1000,
        );
        let r2 = compute_receipt(
            input_hash,
            &PathVerdict::Verified,
            &epoch(),
            Some(prev),
            1000,
        );
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    // --- VerificationError ---

    #[test]
    fn verification_error_display() {
        let err = VerificationError::PathKindMismatch {
            reference: ExecutionPathKind::Ssr,
            candidate: ExecutionPathKind::ClientEntry,
        };
        let s = err.to_string();
        assert!(s.contains("ssr"));
        assert!(s.contains("client_entry"));
    }

    #[test]
    fn verification_error_serde_roundtrip() {
        let err = VerificationError::InvalidConfig {
            reason: "test".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: VerificationError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // --- BatchVerdict ---

    #[test]
    fn batch_verdict_pass_rate_empty() {
        let bv = BatchVerdict {
            schema_version: SCHEMA_VERSION.to_string(),
            results: Vec::new(),
            overall_verdict: PathVerdict::Verified,
            total_divergence_score: 0,
            verified_count: 0,
            divergent_count: 0,
            inconclusive_count: 0,
            content_hash: ContentHash::compute(b"empty"),
        };
        assert_eq!(bv.pass_rate(), 0);
    }

    #[test]
    fn batch_verdict_serde_roundtrip() {
        let pairs = vec![
            DifferentialPair::new(ssr_evidence("r1", b"a"), ssr_evidence("c1", b"a")),
            DifferentialPair::new(ssr_evidence("r2", b"b"), ssr_evidence("c2", b"b")),
        ];
        let bv = verify_batch(&pairs, &default_config()).unwrap();
        let json = serde_json::to_string(&bv).unwrap();
        let back: BatchVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(bv, back);
    }
}
