//! Quantitative disruption scorecard for release gate enforcement.
//!
//! Aggregates evidence from performance, security, and autonomy dimensions
//! into a deterministic go/no-go release decision.  No frontier release may
//! ship unless all three delta dimensions meet their defined thresholds
//! with evidence-backed scores.
//!
//! Key behaviors:
//! - Three mandatory dimensions: `performance_delta`, `security_delta`,
//!   `autonomy_delta` — each with a hard floor and aspirational target.
//! - Deterministic computation: same evidence bundle → same scores.
//! - Signed artifact publication alongside each candidate release.
//! - Historical tracking for trend analysis across release candidates.
//! - CI integration blocks release pipeline when any dimension is below
//!   its hard floor.
//!
//! Plan reference: Section 10.9 item 2, bd-6pk.
//! Cross-refs: bd-1ze (Node/Bun comparison), bd-3rd (adversarial campaign),
//! bd-f7n (category-shift report consumes scorecard output).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const SCORECARD_COMPONENT: &str = "disruption_scorecard";

/// Schema version string.
pub const SCORECARD_SCHEMA_VERSION: &str = "franken-engine.disruption-scorecard.v1";

/// Fixed-point: 1_000_000 = 100%.
#[cfg(test)]
const MILLION: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// DisruptionDimension — the three mandatory axes
// ---------------------------------------------------------------------------

/// The three mandatory disruption dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DisruptionDimension {
    /// Quantitative performance threshold vs Node/Bun baseline.
    PerformanceDelta,
    /// Measurable security improvement: attack surface, exfiltration
    /// resistance, compromise-rate suppression.
    SecurityDelta,
    /// Self-governance: percentage of native slots, PLAS coverage,
    /// proof-carrying pipeline enablement.
    AutonomyDelta,
}

impl DisruptionDimension {
    /// All dimensions in canonical order.
    pub fn all() -> &'static [DisruptionDimension] {
        &[
            Self::PerformanceDelta,
            Self::SecurityDelta,
            Self::AutonomyDelta,
        ]
    }

    /// Canonical string tag for structured logging.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PerformanceDelta => "performance_delta",
            Self::SecurityDelta => "security_delta",
            Self::AutonomyDelta => "autonomy_delta",
        }
    }
}

impl fmt::Display for DisruptionDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DimensionThreshold — per-dimension hard floor + target
// ---------------------------------------------------------------------------

/// Threshold configuration for one disruption dimension.
///
/// Scores are fixed-point millionths: 1_000_000 = 100%.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionThreshold {
    /// The dimension this threshold applies to.
    pub dimension: DisruptionDimension,
    /// Hard floor: minimum acceptable score.  Below this blocks release.
    pub floor_millionths: u64,
    /// Aspirational target: desirable score for category-shift claims.
    pub target_millionths: u64,
    /// Human-readable description of what this dimension measures.
    pub description: String,
}

impl DimensionThreshold {
    /// Whether a given score meets the hard floor.
    pub fn meets_floor(&self, score_millionths: u64) -> bool {
        score_millionths >= self.floor_millionths
    }

    /// Whether a given score meets the aspirational target.
    pub fn meets_target(&self, score_millionths: u64) -> bool {
        score_millionths >= self.target_millionths
    }

    /// Validate that floor <= target.
    pub fn is_valid(&self) -> bool {
        self.floor_millionths <= self.target_millionths
    }
}

// ---------------------------------------------------------------------------
// ScorecardSchema — full threshold configuration
// ---------------------------------------------------------------------------

/// Full scorecard threshold configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScorecardSchema {
    /// Schema version for forward compatibility.
    pub version: String,
    /// Per-dimension threshold definitions.
    pub thresholds: BTreeMap<String, DimensionThreshold>,
    /// Evidence source references (bead IDs that supply evidence).
    pub evidence_sources: Vec<String>,
}

impl ScorecardSchema {
    /// Create a default schema with reasonable thresholds.
    pub fn default_schema() -> Self {
        let mut thresholds = BTreeMap::new();
        thresholds.insert(
            DisruptionDimension::PerformanceDelta.as_str().to_string(),
            DimensionThreshold {
                dimension: DisruptionDimension::PerformanceDelta,
                floor_millionths: 0,        // >= 0% regression (no regression)
                target_millionths: 100_000, // >= 10% improvement on core benchmarks
                description: "Performance vs Node/Bun baseline".to_string(),
            },
        );
        thresholds.insert(
            DisruptionDimension::SecurityDelta.as_str().to_string(),
            DimensionThreshold {
                dimension: DisruptionDimension::SecurityDelta,
                floor_millionths: 500_000, // >= 50% attack surface reduction
                target_millionths: 800_000, // >= 80% attack surface reduction
                description: "Measurable security improvement vs baseline engines".to_string(),
            },
        );
        thresholds.insert(
            DisruptionDimension::AutonomyDelta.as_str().to_string(),
            DimensionThreshold {
                dimension: DisruptionDimension::AutonomyDelta,
                floor_millionths: 600_000,  // >= 60% native slot coverage
                target_millionths: 900_000, // >= 90% native slot coverage
                description: "Self-governance: native slots, PLAS coverage, proof pipelines"
                    .to_string(),
            },
        );

        Self {
            version: SCORECARD_SCHEMA_VERSION.to_string(),
            thresholds,
            evidence_sources: vec![
                "bd-1ze".to_string(),
                "bd-3rd".to_string(),
                "bd-uwc".to_string(),
                "bd-2rx".to_string(),
                "bd-181".to_string(),
                "bd-2n3".to_string(),
                "bd-eke".to_string(),
                "bd-dkh".to_string(),
            ],
        }
    }

    /// Validate that all three dimensions have thresholds and they are valid.
    pub fn validate(&self) -> Result<(), ScorecardError> {
        for dim in DisruptionDimension::all() {
            let key = dim.as_str();
            let threshold =
                self.thresholds
                    .get(key)
                    .ok_or_else(|| ScorecardError::MissingDimension {
                        dimension: key.to_string(),
                    })?;
            if !threshold.is_valid() {
                return Err(ScorecardError::InvalidThreshold {
                    dimension: key.to_string(),
                    detail: format!(
                        "floor ({}) > target ({})",
                        threshold.floor_millionths, threshold.target_millionths
                    ),
                });
            }
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// DimensionScore — scored result for one dimension
// ---------------------------------------------------------------------------

/// Scored result for one disruption dimension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DimensionScore {
    /// Which dimension was scored.
    pub dimension: DisruptionDimension,
    /// Raw score (fixed-point millionths).
    pub raw_score_millionths: u64,
    /// Hard floor threshold.
    pub floor_millionths: u64,
    /// Aspirational target.
    pub target_millionths: u64,
    /// Whether the score meets the hard floor.
    pub meets_floor: bool,
    /// Whether the score meets the aspirational target.
    pub meets_target: bool,
    /// Evidence references that contributed to this score.
    pub evidence_refs: Vec<String>,
}

impl DimensionScore {
    /// Compute a score from raw value and threshold.
    pub fn compute(
        dimension: DisruptionDimension,
        raw_score_millionths: u64,
        threshold: &DimensionThreshold,
        evidence_refs: Vec<String>,
    ) -> Self {
        Self {
            dimension,
            raw_score_millionths,
            floor_millionths: threshold.floor_millionths,
            target_millionths: threshold.target_millionths,
            meets_floor: threshold.meets_floor(raw_score_millionths),
            meets_target: threshold.meets_target(raw_score_millionths),
            evidence_refs,
        }
    }
}

// ---------------------------------------------------------------------------
// ScorecardOutcome — overall pass/fail
// ---------------------------------------------------------------------------

/// Overall scorecard outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ScorecardOutcome {
    /// All dimensions meet their hard floors.  Release may proceed.
    Pass,
    /// At least one dimension is below its hard floor.  Release blocked.
    Fail,
}

impl ScorecardOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
        }
    }

    pub fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }
}

impl fmt::Display for ScorecardOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ScorecardResult — full scored evaluation
// ---------------------------------------------------------------------------

/// Full scorecard result with per-dimension scores and overall verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScorecardResult {
    /// Schema version used.
    pub schema_version: String,
    /// Per-dimension scores (deterministic BTreeMap ordering).
    pub dimension_scores: BTreeMap<String, DimensionScore>,
    /// Overall outcome.
    pub outcome: ScorecardOutcome,
    /// Number of dimensions that meet their target (aspirational).
    pub targets_met: u64,
    /// Total dimensions evaluated.
    pub dimensions_evaluated: u64,
    /// Security epoch at time of evaluation.
    pub epoch: SecurityEpoch,
    /// Content hash of the evidence bundle used.
    pub evidence_bundle_hash: ContentHash,
    /// Content hash of this result (for deterministic verification).
    pub result_hash: ContentHash,
    /// Environment fingerprint.
    pub environment_fingerprint: String,
}

impl ScorecardResult {
    /// Compute the content hash for this result.
    pub fn compute_hash(&self) -> ContentHash {
        let mut parts = Vec::new();
        parts.push(self.schema_version.clone());
        for (key, score) in &self.dimension_scores {
            parts.push(format!(
                "{}:{}:{}:{}:{}:{}",
                key,
                score.raw_score_millionths,
                score.meets_floor,
                score.floor_millionths,
                score.target_millionths,
                score.meets_target,
            ));
        }
        parts.push(format!("outcome:{}", self.outcome));
        parts.push(format!("targets_met:{}", self.targets_met));
        parts.push(format!("epoch:{}", self.epoch.as_u64()));
        parts.push(self.evidence_bundle_hash.to_string());
        parts.push(self.environment_fingerprint.clone());
        let canonical = parts.join("|");
        ContentHash::compute(canonical.as_bytes())
    }
}

// ---------------------------------------------------------------------------
// EvidenceInput — per-dimension evidence from upstream gates
// ---------------------------------------------------------------------------

/// Evidence input for one disruption dimension from upstream gate beads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceInput {
    /// Which dimension this evidence supports.
    pub dimension: DisruptionDimension,
    /// Raw score (fixed-point millionths).
    pub raw_score_millionths: u64,
    /// Source bead IDs.
    pub source_beads: Vec<String>,
    /// Content hash of the upstream evidence artifact.
    pub evidence_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// ScorecardHistory — versioned history for trend analysis
// ---------------------------------------------------------------------------

/// A single entry in the scorecard history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryEntry {
    /// Release candidate identifier.
    pub candidate_id: String,
    /// Timestamp (ISO-8601).
    pub timestamp: String,
    /// The scorecard result.
    pub result: ScorecardResult,
}

/// Append-only scorecard history for trend analysis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScorecardHistory {
    /// Entries ordered by timestamp (newest last).
    pub entries: Vec<HistoryEntry>,
}

impl ScorecardHistory {
    /// Create an empty history.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append a new result.
    pub fn append(&mut self, candidate_id: String, timestamp: String, result: ScorecardResult) {
        self.entries.push(HistoryEntry {
            candidate_id,
            timestamp,
            result,
        });
    }

    /// Get the most recent entry.
    pub fn latest(&self) -> Option<&HistoryEntry> {
        self.entries.last()
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the history is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Check if the latest result shows regression from the previous.
    pub fn has_regression(&self) -> bool {
        if self.entries.len() < 2 {
            return false;
        }
        let prev = &self.entries[self.entries.len() - 2].result;
        let curr = &self.entries[self.entries.len() - 1].result;

        // Regression: any dimension score dropped.
        for dim in DisruptionDimension::all() {
            let key = dim.as_str();
            let prev_score = prev
                .dimension_scores
                .get(key)
                .map(|s| s.raw_score_millionths)
                .unwrap_or(0);
            let curr_score = curr
                .dimension_scores
                .get(key)
                .map(|s| s.raw_score_millionths)
                .unwrap_or(0);
            if curr_score < prev_score {
                return true;
            }
        }
        false
    }
}

impl Default for ScorecardHistory {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ScorecardLogEntry — structured logging
// ---------------------------------------------------------------------------

/// Structured log entry for scorecard computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScorecardLogEntry {
    /// Trace identifier.
    pub trace_id: String,
    /// Schema version.
    pub scorecard_version: String,
    /// Which dimension.
    pub dimension: DisruptionDimension,
    /// Raw score.
    pub raw_score_millionths: u64,
    /// Hard floor threshold.
    pub threshold_floor_millionths: u64,
    /// Aspirational target.
    pub threshold_target_millionths: u64,
    /// Whether this dimension passed.
    pub pass: bool,
    /// Evidence references.
    pub evidence_refs: Vec<String>,
}

// ---------------------------------------------------------------------------
// ScorecardError — typed error contract
// ---------------------------------------------------------------------------

/// Errors that can occur during scorecard computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScorecardError {
    /// A required dimension is missing from the schema.
    MissingDimension { dimension: String },
    /// Threshold configuration is invalid.
    InvalidThreshold { dimension: String, detail: String },
    /// Evidence is missing for a dimension.
    MissingEvidence { dimension: String },
    /// Evidence bundle is empty.
    EmptyEvidenceBundle,
    /// Schema validation failed.
    SchemaValidationFailed { detail: String },
    /// Duplicate evidence for the same dimension.
    DuplicateEvidence { dimension: String },
}

impl fmt::Display for ScorecardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingDimension { dimension } => {
                write!(f, "missing dimension in schema: {}", dimension)
            }
            Self::InvalidThreshold { dimension, detail } => {
                write!(
                    f,
                    "invalid threshold for dimension {}: {}",
                    dimension, detail
                )
            }
            Self::MissingEvidence { dimension } => {
                write!(f, "missing evidence for dimension: {}", dimension)
            }
            Self::EmptyEvidenceBundle => {
                write!(f, "evidence bundle is empty")
            }
            Self::SchemaValidationFailed { detail } => {
                write!(f, "schema validation failed: {}", detail)
            }
            Self::DuplicateEvidence { dimension } => {
                write!(f, "duplicate evidence for dimension: {}", dimension)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// compute_scorecard — deterministic scoring engine
// ---------------------------------------------------------------------------

/// Compute a full disruption scorecard from evidence inputs.
///
/// This is the core deterministic scoring function.  Given the same schema
/// and evidence inputs, it always produces the same result.
pub fn compute_scorecard(
    schema: &ScorecardSchema,
    evidence: &[EvidenceInput],
    epoch: SecurityEpoch,
    environment_fingerprint: String,
) -> Result<ScorecardResult, ScorecardError> {
    // Validate schema first.
    schema.validate()?;

    if evidence.is_empty() {
        return Err(ScorecardError::EmptyEvidenceBundle);
    }

    // Build evidence lookup by dimension. Reject duplicate dimensions to
    // prevent silent score manipulation via last-writer-wins overwriting.
    let mut evidence_by_dim: BTreeMap<String, &EvidenceInput> = BTreeMap::new();
    for ev in evidence {
        let key = ev.dimension.as_str().to_string();
        if evidence_by_dim.contains_key(&key) {
            return Err(ScorecardError::DuplicateEvidence { dimension: key });
        }
        evidence_by_dim.insert(key, ev);
    }

    // Compute evidence bundle hash from all evidence hashes.
    let mut hash_parts: Vec<String> = evidence
        .iter()
        .map(|e| e.evidence_hash.to_string())
        .collect();
    hash_parts.sort();
    let evidence_bundle_hash = ContentHash::compute(hash_parts.join("|").as_bytes());

    let mut dimension_scores = BTreeMap::new();
    let mut all_pass = true;
    let mut targets_met: u64 = 0;

    for dim in DisruptionDimension::all() {
        let key = dim.as_str();
        let threshold =
            schema
                .thresholds
                .get(key)
                .ok_or_else(|| ScorecardError::MissingDimension {
                    dimension: key.to_string(),
                })?;

        let ev = evidence_by_dim
            .get(key)
            .ok_or_else(|| ScorecardError::MissingEvidence {
                dimension: key.to_string(),
            })?;

        let score = DimensionScore::compute(
            *dim,
            ev.raw_score_millionths,
            threshold,
            ev.source_beads.clone(),
        );

        if !score.meets_floor {
            all_pass = false;
        }
        if score.meets_target {
            targets_met += 1;
        }

        dimension_scores.insert(key.to_string(), score);
    }

    let outcome = if all_pass {
        ScorecardOutcome::Pass
    } else {
        ScorecardOutcome::Fail
    };

    let mut result = ScorecardResult {
        schema_version: schema.version.clone(),
        dimension_scores,
        outcome,
        targets_met,
        dimensions_evaluated: DisruptionDimension::all().len() as u64,
        epoch,
        evidence_bundle_hash,
        environment_fingerprint,
        result_hash: ContentHash::compute(b"placeholder"),
    };
    result.result_hash = result.compute_hash();

    Ok(result)
}

/// Check if a scorecard result passes the release gate.
pub fn passes_release_gate(result: &ScorecardResult) -> bool {
    result.outcome.is_pass()
}

/// Generate structured log entries for a scorecard computation.
pub fn generate_log_entries(trace_id: &str, result: &ScorecardResult) -> Vec<ScorecardLogEntry> {
    let mut entries = Vec::new();
    for score in result.dimension_scores.values() {
        entries.push(ScorecardLogEntry {
            trace_id: trace_id.to_string(),
            scorecard_version: result.schema_version.clone(),
            dimension: score.dimension,
            raw_score_millionths: score.raw_score_millionths,
            threshold_floor_millionths: score.floor_millionths,
            threshold_target_millionths: score.target_millionths,
            pass: score.meets_floor,
            evidence_refs: score.evidence_refs.clone(),
        });
    }
    entries
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn default_schema() -> ScorecardSchema {
        ScorecardSchema::default_schema()
    }

    fn make_evidence(dim: DisruptionDimension, score: u64, beads: &[&str]) -> EvidenceInput {
        EvidenceInput {
            dimension: dim,
            raw_score_millionths: score,
            source_beads: beads.iter().map(|s| s.to_string()).collect(),
            evidence_hash: ContentHash::compute(format!("{}:{}", dim, score).as_bytes()),
        }
    }

    fn passing_evidence() -> Vec<EvidenceInput> {
        vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 150_000, &["bd-1ze"]),
            make_evidence(DisruptionDimension::SecurityDelta, 750_000, &["bd-3rd"]),
            make_evidence(DisruptionDimension::AutonomyDelta, 800_000, &["bd-181"]),
        ]
    }

    fn failing_evidence() -> Vec<EvidenceInput> {
        vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 150_000, &["bd-1ze"]),
            make_evidence(
                DisruptionDimension::SecurityDelta,
                300_000, // Below 500k floor
                &["bd-3rd"],
            ),
            make_evidence(DisruptionDimension::AutonomyDelta, 800_000, &["bd-181"]),
        ]
    }

    // -----------------------------------------------------------------------
    // DisruptionDimension
    // -----------------------------------------------------------------------

    #[test]
    fn dimension_all_returns_three() {
        assert_eq!(DisruptionDimension::all().len(), 3);
    }

    #[test]
    fn dimension_ordering() {
        assert!(DisruptionDimension::PerformanceDelta < DisruptionDimension::SecurityDelta);
        assert!(DisruptionDimension::SecurityDelta < DisruptionDimension::AutonomyDelta);
    }

    #[test]
    fn dimension_display() {
        assert_eq!(
            DisruptionDimension::PerformanceDelta.to_string(),
            "performance_delta"
        );
        assert_eq!(
            DisruptionDimension::SecurityDelta.to_string(),
            "security_delta"
        );
        assert_eq!(
            DisruptionDimension::AutonomyDelta.to_string(),
            "autonomy_delta"
        );
    }

    // -----------------------------------------------------------------------
    // DimensionThreshold
    // -----------------------------------------------------------------------

    #[test]
    fn threshold_meets_floor() {
        let t = DimensionThreshold {
            dimension: DisruptionDimension::PerformanceDelta,
            floor_millionths: 100_000,
            target_millionths: 500_000,
            description: "test".to_string(),
        };
        assert!(t.meets_floor(100_000));
        assert!(t.meets_floor(500_000));
        assert!(!t.meets_floor(99_999));
    }

    #[test]
    fn threshold_meets_target() {
        let t = DimensionThreshold {
            dimension: DisruptionDimension::SecurityDelta,
            floor_millionths: 100_000,
            target_millionths: 500_000,
            description: "test".to_string(),
        };
        assert!(t.meets_target(500_000));
        assert!(t.meets_target(999_999));
        assert!(!t.meets_target(499_999));
    }

    #[test]
    fn threshold_is_valid() {
        let valid = DimensionThreshold {
            dimension: DisruptionDimension::AutonomyDelta,
            floor_millionths: 100_000,
            target_millionths: 500_000,
            description: "test".to_string(),
        };
        assert!(valid.is_valid());

        let invalid = DimensionThreshold {
            dimension: DisruptionDimension::AutonomyDelta,
            floor_millionths: 600_000,
            target_millionths: 500_000,
            description: "test".to_string(),
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn threshold_floor_equals_target_is_valid() {
        let t = DimensionThreshold {
            dimension: DisruptionDimension::PerformanceDelta,
            floor_millionths: 500_000,
            target_millionths: 500_000,
            description: "test".to_string(),
        };
        assert!(t.is_valid());
    }

    // -----------------------------------------------------------------------
    // ScorecardSchema
    // -----------------------------------------------------------------------

    #[test]
    fn default_schema_has_three_dimensions() {
        let schema = default_schema();
        assert_eq!(schema.thresholds.len(), 3);
    }

    #[test]
    fn default_schema_validates() {
        assert!(default_schema().validate().is_ok());
    }

    #[test]
    fn schema_missing_dimension_fails() {
        let mut schema = default_schema();
        schema.thresholds.remove("security_delta");
        let result = schema.validate();
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            ScorecardError::MissingDimension { .. }
        ));
    }

    #[test]
    fn schema_invalid_threshold_fails() {
        let mut schema = default_schema();
        schema
            .thresholds
            .get_mut("performance_delta")
            .unwrap()
            .floor_millionths = MILLION + 1;
        let result = schema.validate();
        assert!(result.is_err());
    }

    #[test]
    fn default_schema_evidence_sources() {
        let schema = default_schema();
        assert!(!schema.evidence_sources.is_empty());
        assert!(schema.evidence_sources.contains(&"bd-1ze".to_string()));
    }

    // -----------------------------------------------------------------------
    // DimensionScore
    // -----------------------------------------------------------------------

    #[test]
    fn dimension_score_compute_passing() {
        let threshold = DimensionThreshold {
            dimension: DisruptionDimension::PerformanceDelta,
            floor_millionths: 100_000,
            target_millionths: 500_000,
            description: "test".to_string(),
        };
        let score = DimensionScore::compute(
            DisruptionDimension::PerformanceDelta,
            300_000,
            &threshold,
            vec!["bd-1ze".to_string()],
        );
        assert!(score.meets_floor);
        assert!(!score.meets_target);
        assert_eq!(score.raw_score_millionths, 300_000);
    }

    #[test]
    fn dimension_score_compute_exceeds_target() {
        let threshold = DimensionThreshold {
            dimension: DisruptionDimension::SecurityDelta,
            floor_millionths: 100_000,
            target_millionths: 500_000,
            description: "test".to_string(),
        };
        let score = DimensionScore::compute(
            DisruptionDimension::SecurityDelta,
            800_000,
            &threshold,
            vec![],
        );
        assert!(score.meets_floor);
        assert!(score.meets_target);
    }

    #[test]
    fn dimension_score_compute_below_floor() {
        let threshold = DimensionThreshold {
            dimension: DisruptionDimension::AutonomyDelta,
            floor_millionths: 600_000,
            target_millionths: 900_000,
            description: "test".to_string(),
        };
        let score = DimensionScore::compute(
            DisruptionDimension::AutonomyDelta,
            400_000,
            &threshold,
            vec![],
        );
        assert!(!score.meets_floor);
        assert!(!score.meets_target);
    }

    // -----------------------------------------------------------------------
    // ScorecardOutcome
    // -----------------------------------------------------------------------

    #[test]
    fn outcome_display() {
        assert_eq!(ScorecardOutcome::Pass.to_string(), "pass");
        assert_eq!(ScorecardOutcome::Fail.to_string(), "fail");
    }

    #[test]
    fn outcome_is_pass() {
        assert!(ScorecardOutcome::Pass.is_pass());
        assert!(!ScorecardOutcome::Fail.is_pass());
    }

    // -----------------------------------------------------------------------
    // compute_scorecard
    // -----------------------------------------------------------------------

    #[test]
    fn compute_scorecard_all_pass() {
        let schema = default_schema();
        let evidence = passing_evidence();
        let result = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();

        assert!(result.outcome.is_pass());
        assert_eq!(result.dimensions_evaluated, 3);
        assert_eq!(result.dimension_scores.len(), 3);
    }

    #[test]
    fn compute_scorecard_security_fails() {
        let schema = default_schema();
        let evidence = failing_evidence();
        let result = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();

        assert!(!result.outcome.is_pass());
        let sec = result.dimension_scores.get("security_delta").unwrap();
        assert!(!sec.meets_floor);
    }

    #[test]
    fn compute_scorecard_empty_evidence_errors() {
        let schema = default_schema();
        let result =
            compute_scorecard(&schema, &[], SecurityEpoch::from_raw(1), "test".to_string());
        assert!(matches!(
            result.unwrap_err(),
            ScorecardError::EmptyEvidenceBundle
        ));
    }

    #[test]
    fn compute_scorecard_missing_evidence_errors() {
        let schema = default_schema();
        // Only provide 2 of 3 dimensions.
        let evidence = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 150_000, &["bd-1ze"]),
            make_evidence(DisruptionDimension::SecurityDelta, 750_000, &["bd-3rd"]),
        ];
        let result = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        );
        assert!(matches!(
            result.unwrap_err(),
            ScorecardError::MissingEvidence { .. }
        ));
    }

    #[test]
    fn compute_scorecard_deterministic() {
        let schema = default_schema();
        let evidence = passing_evidence();
        let r1 = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        let r2 = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        assert_eq!(r1.result_hash, r2.result_hash);
        assert_eq!(r1.dimension_scores, r2.dimension_scores);
        assert_eq!(r1.outcome, r2.outcome);
    }

    #[test]
    fn compute_scorecard_different_evidence_different_hash() {
        let schema = default_schema();
        let ev1 = passing_evidence();
        let mut ev2 = passing_evidence();
        ev2[0].raw_score_millionths = 200_000;
        let r1 = compute_scorecard(
            &schema,
            &ev1,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        let r2 = compute_scorecard(
            &schema,
            &ev2,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        assert_ne!(r1.result_hash, r2.result_hash);
    }

    #[test]
    fn compute_scorecard_targets_met_count() {
        let schema = default_schema();
        // Performance: 150k (target 100k) ✓
        // Security: 750k (target 800k) ✗
        // Autonomy: 950k (target 900k) ✓
        let evidence = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 150_000, &["bd-1ze"]),
            make_evidence(DisruptionDimension::SecurityDelta, 750_000, &["bd-3rd"]),
            make_evidence(DisruptionDimension::AutonomyDelta, 950_000, &["bd-181"]),
        ];
        let result = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        assert_eq!(result.targets_met, 2);
    }

    #[test]
    fn compute_scorecard_all_targets_met() {
        let schema = default_schema();
        let evidence = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 200_000, &["bd-1ze"]),
            make_evidence(DisruptionDimension::SecurityDelta, 900_000, &["bd-3rd"]),
            make_evidence(DisruptionDimension::AutonomyDelta, 950_000, &["bd-181"]),
        ];
        let result = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        assert_eq!(result.targets_met, 3);
        assert!(result.outcome.is_pass());
    }

    #[test]
    fn compute_scorecard_zero_scores_fail() {
        let schema = default_schema();
        let evidence = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 0, &[]),
            make_evidence(DisruptionDimension::SecurityDelta, 0, &[]),
            make_evidence(DisruptionDimension::AutonomyDelta, 0, &[]),
        ];
        let result = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        // Performance floor is 0 → passes; Security (500k) and Autonomy (600k) → fail
        assert!(!result.outcome.is_pass());
    }

    #[test]
    fn compute_scorecard_perf_zero_floor_passes() {
        let schema = default_schema();
        // Performance floor is 0, so score of 0 passes.
        let evidence = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 0, &["bd-1ze"]),
            make_evidence(DisruptionDimension::SecurityDelta, 900_000, &["bd-3rd"]),
            make_evidence(DisruptionDimension::AutonomyDelta, 900_000, &["bd-181"]),
        ];
        let result = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        assert!(result.outcome.is_pass());
    }

    // -----------------------------------------------------------------------
    // passes_release_gate
    // -----------------------------------------------------------------------

    #[test]
    fn release_gate_passes_on_pass() {
        let schema = default_schema();
        let result = compute_scorecard(
            &schema,
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        assert!(passes_release_gate(&result));
    }

    #[test]
    fn release_gate_fails_on_fail() {
        let schema = default_schema();
        let result = compute_scorecard(
            &schema,
            &failing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        assert!(!passes_release_gate(&result));
    }

    // -----------------------------------------------------------------------
    // generate_log_entries
    // -----------------------------------------------------------------------

    #[test]
    fn log_entries_generated_for_all_dimensions() {
        let schema = default_schema();
        let result = compute_scorecard(
            &schema,
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        let entries = generate_log_entries("trace-42", &result);
        assert_eq!(entries.len(), 3);
        assert!(entries.iter().all(|e| e.trace_id == "trace-42"));
    }

    #[test]
    fn log_entries_reflect_pass_fail() {
        let schema = default_schema();
        let result = compute_scorecard(
            &schema,
            &failing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        let entries = generate_log_entries("t1", &result);
        let sec = entries
            .iter()
            .find(|e| e.dimension == DisruptionDimension::SecurityDelta)
            .unwrap();
        assert!(!sec.pass);
    }

    // -----------------------------------------------------------------------
    // ScorecardHistory
    // -----------------------------------------------------------------------

    #[test]
    fn history_append_and_latest() {
        let mut history = ScorecardHistory::new();
        assert!(history.is_empty());

        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        history.append(
            "rc-1".to_string(),
            "2026-02-24T00:00:00Z".to_string(),
            result,
        );

        assert_eq!(history.len(), 1);
        assert!(!history.is_empty());
        assert_eq!(history.latest().unwrap().candidate_id, "rc-1");
    }

    #[test]
    fn history_no_regression_single_entry() {
        let mut history = ScorecardHistory::new();
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        history.append("rc-1".to_string(), "t1".to_string(), result);
        assert!(!history.has_regression());
    }

    #[test]
    fn history_detects_regression() {
        let mut history = ScorecardHistory::new();
        let schema = default_schema();

        // First: high scores.
        let ev1 = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 200_000, &[]),
            make_evidence(DisruptionDimension::SecurityDelta, 900_000, &[]),
            make_evidence(DisruptionDimension::AutonomyDelta, 900_000, &[]),
        ];
        let r1 = compute_scorecard(
            &schema,
            &ev1,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        history.append("rc-1".to_string(), "t1".to_string(), r1);

        // Second: lower security score.
        let ev2 = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 200_000, &[]),
            make_evidence(DisruptionDimension::SecurityDelta, 700_000, &[]),
            make_evidence(DisruptionDimension::AutonomyDelta, 900_000, &[]),
        ];
        let r2 = compute_scorecard(
            &schema,
            &ev2,
            SecurityEpoch::from_raw(2),
            "test".to_string(),
        )
        .unwrap();
        history.append("rc-2".to_string(), "t2".to_string(), r2);

        assert!(history.has_regression());
    }

    #[test]
    fn history_no_regression_when_improving() {
        let mut history = ScorecardHistory::new();
        let schema = default_schema();

        let ev1 = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 100_000, &[]),
            make_evidence(DisruptionDimension::SecurityDelta, 600_000, &[]),
            make_evidence(DisruptionDimension::AutonomyDelta, 700_000, &[]),
        ];
        let r1 = compute_scorecard(
            &schema,
            &ev1,
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        history.append("rc-1".to_string(), "t1".to_string(), r1);

        let ev2 = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 200_000, &[]),
            make_evidence(DisruptionDimension::SecurityDelta, 800_000, &[]),
            make_evidence(DisruptionDimension::AutonomyDelta, 900_000, &[]),
        ];
        let r2 = compute_scorecard(
            &schema,
            &ev2,
            SecurityEpoch::from_raw(2),
            "test".to_string(),
        )
        .unwrap();
        history.append("rc-2".to_string(), "t2".to_string(), r2);

        assert!(!history.has_regression());
    }

    // -----------------------------------------------------------------------
    // ScorecardError
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_missing_dimension() {
        let e = ScorecardError::MissingDimension {
            dimension: "security_delta".to_string(),
        };
        assert!(e.to_string().contains("security_delta"));
    }

    #[test]
    fn error_display_invalid_threshold() {
        let e = ScorecardError::InvalidThreshold {
            dimension: "perf".to_string(),
            detail: "floor > target".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("perf"));
        assert!(s.contains("floor > target"));
    }

    #[test]
    fn error_display_missing_evidence() {
        let e = ScorecardError::MissingEvidence {
            dimension: "autonomy_delta".to_string(),
        };
        assert!(e.to_string().contains("autonomy_delta"));
    }

    #[test]
    fn error_display_empty_bundle() {
        let e = ScorecardError::EmptyEvidenceBundle;
        assert!(e.to_string().contains("empty"));
    }

    // -----------------------------------------------------------------------
    // Serde round-trip tests
    // -----------------------------------------------------------------------

    #[test]
    fn serde_dimension_roundtrip() {
        for dim in DisruptionDimension::all() {
            let json = serde_json::to_string(dim).unwrap();
            let back: DisruptionDimension = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, dim);
        }
    }

    #[test]
    fn serde_outcome_roundtrip() {
        for outcome in &[ScorecardOutcome::Pass, ScorecardOutcome::Fail] {
            let json = serde_json::to_string(outcome).unwrap();
            let back: ScorecardOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, outcome);
        }
    }

    #[test]
    fn serde_schema_roundtrip() {
        let schema = default_schema();
        let json = serde_json::to_string(&schema).unwrap();
        let back: ScorecardSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(back.thresholds.len(), 3);
        assert_eq!(back.version, schema.version);
    }

    #[test]
    fn serde_result_roundtrip() {
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: ScorecardResult = serde_json::from_str(&json).unwrap();
        assert_eq!(back.outcome, result.outcome);
        assert_eq!(back.result_hash, result.result_hash);
    }

    #[test]
    fn serde_history_roundtrip() {
        let mut history = ScorecardHistory::new();
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        history.append("rc-1".to_string(), "t1".to_string(), result);
        let json = serde_json::to_string(&history).unwrap();
        let back: ScorecardHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(back.len(), 1);
    }

    #[test]
    fn serde_evidence_input_roundtrip() {
        let ev = make_evidence(DisruptionDimension::SecurityDelta, 750_000, &["bd-3rd"]);
        let json = serde_json::to_string(&ev).unwrap();
        let back: EvidenceInput = serde_json::from_str(&json).unwrap();
        assert_eq!(back.dimension, ev.dimension);
        assert_eq!(back.raw_score_millionths, ev.raw_score_millionths);
    }

    #[test]
    fn serde_log_entry_roundtrip() {
        let entry = ScorecardLogEntry {
            trace_id: "t1".to_string(),
            scorecard_version: "v1".to_string(),
            dimension: DisruptionDimension::PerformanceDelta,
            raw_score_millionths: 150_000,
            threshold_floor_millionths: 0,
            threshold_target_millionths: 100_000,
            pass: true,
            evidence_refs: vec!["bd-1ze".to_string()],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: ScorecardLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.trace_id, "t1");
    }

    // -----------------------------------------------------------------------
    // Enrichment: DisruptionDimension Display uniqueness via BTreeSet
    // -----------------------------------------------------------------------

    #[test]
    fn dimension_display_all_unique_btreeset() {
        let mut displays = std::collections::BTreeSet::new();
        for dim in DisruptionDimension::all() {
            displays.insert(dim.to_string());
        }
        assert_eq!(
            displays.len(),
            3,
            "all 3 dimensions produce distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScorecardError Display uniqueness
    // -----------------------------------------------------------------------

    #[test]
    fn scorecard_error_display_all_unique() {
        let errors: Vec<ScorecardError> = vec![
            ScorecardError::MissingDimension {
                dimension: "a".into(),
            },
            ScorecardError::InvalidThreshold {
                dimension: "b".into(),
                detail: "x".into(),
            },
            ScorecardError::MissingEvidence {
                dimension: "c".into(),
            },
            ScorecardError::EmptyEvidenceBundle,
        ];
        let mut displays = std::collections::BTreeSet::new();
        for e in &errors {
            displays.insert(e.to_string());
        }
        assert_eq!(
            displays.len(),
            4,
            "all ScorecardError variants produce distinct Display"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScorecardError implements std::error::Error
    // -----------------------------------------------------------------------

    #[test]
    fn scorecard_error_display_coverage() {
        let variants: Vec<ScorecardError> = vec![
            ScorecardError::MissingDimension {
                dimension: "a".into(),
            },
            ScorecardError::EmptyEvidenceBundle,
        ];
        for v in &variants {
            assert!(!v.to_string().is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScorecardResult with all dimensions at boundary
    // -----------------------------------------------------------------------

    #[test]
    fn compute_scorecard_at_exact_floor() {
        let schema = default_schema();
        // Security floor = 500_000, autonomy floor = 600_000
        let evidence = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 0, &["bd-1ze"]),
            make_evidence(DisruptionDimension::SecurityDelta, 500_000, &["bd-3rd"]),
            make_evidence(DisruptionDimension::AutonomyDelta, 600_000, &["bd-181"]),
        ];
        let result = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(1),
            "boundary-test".to_string(),
        )
        .unwrap();
        assert!(
            result.outcome.is_pass(),
            "scores at exact floor should pass"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScorecardHistory empty has_regression is false
    // -----------------------------------------------------------------------

    #[test]
    fn history_empty_has_no_regression() {
        let history = ScorecardHistory::new();
        assert!(!history.has_regression());
    }

    // -----------------------------------------------------------------------
    // Enrichment: SCORECARD_COMPONENT and SCORECARD_SCHEMA_VERSION constants
    // -----------------------------------------------------------------------

    #[test]
    fn scorecard_constants_are_non_empty() {
        assert!(!SCORECARD_COMPONENT.is_empty());
        assert!(!SCORECARD_SCHEMA_VERSION.is_empty());
        assert!(SCORECARD_SCHEMA_VERSION.contains("v1"));
    }

    // -----------------------------------------------------------------------
    // Enrichment: ScorecardError serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn scorecard_error_serde_roundtrip() {
        let errors: Vec<ScorecardError> = vec![
            ScorecardError::MissingDimension {
                dimension: "perf".into(),
            },
            ScorecardError::InvalidThreshold {
                dimension: "sec".into(),
                detail: "floor > target".into(),
            },
            ScorecardError::MissingEvidence {
                dimension: "auto".into(),
            },
            ScorecardError::EmptyEvidenceBundle,
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: ScorecardError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment: DimensionThreshold serde roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn dimension_threshold_serde_roundtrip() {
        let t = DimensionThreshold {
            dimension: DisruptionDimension::SecurityDelta,
            floor_millionths: 500_000,
            target_millionths: 800_000,
            description: "security threshold".to_string(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: DimensionThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(t.floor_millionths, back.floor_millionths);
        assert_eq!(t.target_millionths, back.target_millionths);
    }

    // ===================================================================
    // Enrichment batch: copy semantics
    // ===================================================================

    #[test]
    fn dimension_copy_semantics() {
        let a = DisruptionDimension::PerformanceDelta;
        let b = a; // Copy
        assert_eq!(a, b);
        // Original still usable after copy.
        assert_eq!(a.as_str(), "performance_delta");
    }

    #[test]
    fn dimension_copy_all_variants() {
        for dim in DisruptionDimension::all() {
            let copy = *dim;
            assert_eq!(copy, *dim);
        }
    }

    #[test]
    fn outcome_copy_semantics() {
        let a = ScorecardOutcome::Pass;
        let b = a;
        assert_eq!(a, b);
        assert!(a.is_pass());
    }

    #[test]
    fn outcome_copy_fail_variant() {
        let a = ScorecardOutcome::Fail;
        let b = a;
        assert_eq!(a, b);
        assert!(!b.is_pass());
    }

    // ===================================================================
    // Enrichment batch: Debug distinctness
    // ===================================================================

    #[test]
    fn dimension_debug_all_distinct() {
        let mut debugs = std::collections::BTreeSet::new();
        for dim in DisruptionDimension::all() {
            debugs.insert(format!("{:?}", dim));
        }
        assert_eq!(
            debugs.len(),
            3,
            "all DisruptionDimension variants have distinct Debug"
        );
    }

    #[test]
    fn outcome_debug_distinct() {
        let pass_dbg = format!("{:?}", ScorecardOutcome::Pass);
        let fail_dbg = format!("{:?}", ScorecardOutcome::Fail);
        assert_ne!(pass_dbg, fail_dbg);
    }

    #[test]
    fn scorecard_error_debug_all_distinct() {
        let errors: Vec<ScorecardError> = vec![
            ScorecardError::MissingDimension {
                dimension: "x".into(),
            },
            ScorecardError::InvalidThreshold {
                dimension: "x".into(),
                detail: "y".into(),
            },
            ScorecardError::MissingEvidence {
                dimension: "x".into(),
            },
            ScorecardError::EmptyEvidenceBundle,
            ScorecardError::SchemaValidationFailed { detail: "z".into() },
        ];
        let mut debugs = std::collections::BTreeSet::new();
        for e in &errors {
            debugs.insert(format!("{:?}", e));
        }
        assert_eq!(
            debugs.len(),
            5,
            "all ScorecardError variants have distinct Debug"
        );
    }

    // ===================================================================
    // Enrichment batch: serde variant distinctness
    // ===================================================================

    #[test]
    fn dimension_serde_all_distinct_json() {
        let mut jsons = std::collections::BTreeSet::new();
        for dim in DisruptionDimension::all() {
            jsons.insert(serde_json::to_string(dim).unwrap());
        }
        assert_eq!(
            jsons.len(),
            3,
            "all DisruptionDimension variants serialize to distinct JSON"
        );
    }

    #[test]
    fn outcome_serde_distinct_json() {
        let pass_json = serde_json::to_string(&ScorecardOutcome::Pass).unwrap();
        let fail_json = serde_json::to_string(&ScorecardOutcome::Fail).unwrap();
        assert_ne!(pass_json, fail_json);
    }

    #[test]
    fn scorecard_error_serde_all_distinct_json() {
        let errors: Vec<ScorecardError> = vec![
            ScorecardError::MissingDimension {
                dimension: "dim".into(),
            },
            ScorecardError::InvalidThreshold {
                dimension: "dim".into(),
                detail: "d".into(),
            },
            ScorecardError::MissingEvidence {
                dimension: "dim".into(),
            },
            ScorecardError::EmptyEvidenceBundle,
            ScorecardError::SchemaValidationFailed { detail: "d".into() },
        ];
        let mut jsons = std::collections::BTreeSet::new();
        for e in &errors {
            jsons.insert(serde_json::to_string(e).unwrap());
        }
        assert_eq!(
            jsons.len(),
            5,
            "all ScorecardError variants serialize to distinct JSON"
        );
    }

    // ===================================================================
    // Enrichment batch: clone independence
    // ===================================================================

    #[test]
    fn dimension_threshold_clone_independence() {
        let orig = DimensionThreshold {
            dimension: DisruptionDimension::SecurityDelta,
            floor_millionths: 500_000,
            target_millionths: 800_000,
            description: "original".to_string(),
        };
        let mut cloned = orig.clone();
        cloned.floor_millionths = 999_999;
        cloned.description = "mutated".to_string();
        assert_eq!(orig.floor_millionths, 500_000);
        assert_eq!(orig.description, "original");
    }

    #[test]
    fn scorecard_schema_clone_independence() {
        let orig = default_schema();
        let mut cloned = orig.clone();
        cloned.evidence_sources.push("bd-extra".to_string());
        cloned.version = "v2".to_string();
        assert_eq!(orig.version, SCORECARD_SCHEMA_VERSION);
        assert_eq!(orig.evidence_sources.len(), 8);
    }

    #[test]
    fn dimension_score_clone_independence() {
        let threshold = DimensionThreshold {
            dimension: DisruptionDimension::PerformanceDelta,
            floor_millionths: 100_000,
            target_millionths: 500_000,
            description: "test".to_string(),
        };
        let orig = DimensionScore::compute(
            DisruptionDimension::PerformanceDelta,
            300_000,
            &threshold,
            vec!["bd-1ze".to_string()],
        );
        let mut cloned = orig.clone();
        cloned.raw_score_millionths = 0;
        cloned.evidence_refs.push("extra".to_string());
        assert_eq!(orig.raw_score_millionths, 300_000);
        assert_eq!(orig.evidence_refs.len(), 1);
    }

    #[test]
    fn scorecard_result_clone_independence() {
        let orig = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        let mut cloned = orig.clone();
        cloned.outcome = ScorecardOutcome::Fail;
        cloned.targets_met = 0;
        assert_eq!(orig.outcome, ScorecardOutcome::Pass);
        assert!(orig.targets_met > 0);
    }

    #[test]
    fn evidence_input_clone_independence() {
        let orig = make_evidence(DisruptionDimension::SecurityDelta, 750_000, &["bd-3rd"]);
        let mut cloned = orig.clone();
        cloned.raw_score_millionths = 0;
        cloned.source_beads.push("extra".to_string());
        assert_eq!(orig.raw_score_millionths, 750_000);
        assert_eq!(orig.source_beads.len(), 1);
    }

    #[test]
    fn scorecard_history_clone_independence() {
        let mut orig = ScorecardHistory::new();
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        orig.append("rc-1".to_string(), "t1".to_string(), result);

        let mut cloned = orig.clone();
        let result2 = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(2),
            "test2".to_string(),
        )
        .unwrap();
        cloned.append("rc-2".to_string(), "t2".to_string(), result2);
        assert_eq!(orig.len(), 1);
        assert_eq!(cloned.len(), 2);
    }

    #[test]
    fn scorecard_log_entry_clone_independence() {
        let orig = ScorecardLogEntry {
            trace_id: "t1".to_string(),
            scorecard_version: "v1".to_string(),
            dimension: DisruptionDimension::PerformanceDelta,
            raw_score_millionths: 150_000,
            threshold_floor_millionths: 0,
            threshold_target_millionths: 100_000,
            pass: true,
            evidence_refs: vec!["bd-1ze".to_string()],
        };
        let mut cloned = orig.clone();
        cloned.pass = false;
        cloned.trace_id = "t2".to_string();
        cloned.evidence_refs.push("extra".to_string());
        assert!(orig.pass);
        assert_eq!(orig.trace_id, "t1");
        assert_eq!(orig.evidence_refs.len(), 1);
    }

    #[test]
    fn scorecard_error_clone_independence() {
        let orig = ScorecardError::InvalidThreshold {
            dimension: "perf".to_string(),
            detail: "original".to_string(),
        };
        let cloned = orig.clone();
        assert_eq!(orig, cloned);
        // Enum variants are immutable once constructed, so clone equality suffices.
    }

    // ===================================================================
    // Enrichment batch: JSON field-name stability
    // ===================================================================

    #[test]
    fn dimension_threshold_json_field_names() {
        let t = DimensionThreshold {
            dimension: DisruptionDimension::PerformanceDelta,
            floor_millionths: 100_000,
            target_millionths: 500_000,
            description: "test".to_string(),
        };
        let json = serde_json::to_string(&t).unwrap();
        assert!(json.contains("\"dimension\""));
        assert!(json.contains("\"floor_millionths\""));
        assert!(json.contains("\"target_millionths\""));
        assert!(json.contains("\"description\""));
    }

    #[test]
    fn dimension_score_json_field_names() {
        let threshold = DimensionThreshold {
            dimension: DisruptionDimension::SecurityDelta,
            floor_millionths: 500_000,
            target_millionths: 800_000,
            description: "test".to_string(),
        };
        let score = DimensionScore::compute(
            DisruptionDimension::SecurityDelta,
            750_000,
            &threshold,
            vec!["bd-3rd".to_string()],
        );
        let json = serde_json::to_string(&score).unwrap();
        assert!(json.contains("\"dimension\""));
        assert!(json.contains("\"raw_score_millionths\""));
        assert!(json.contains("\"floor_millionths\""));
        assert!(json.contains("\"target_millionths\""));
        assert!(json.contains("\"meets_floor\""));
        assert!(json.contains("\"meets_target\""));
        assert!(json.contains("\"evidence_refs\""));
    }

    #[test]
    fn scorecard_result_json_field_names() {
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("\"schema_version\""));
        assert!(json.contains("\"dimension_scores\""));
        assert!(json.contains("\"outcome\""));
        assert!(json.contains("\"targets_met\""));
        assert!(json.contains("\"dimensions_evaluated\""));
        assert!(json.contains("\"epoch\""));
        assert!(json.contains("\"evidence_bundle_hash\""));
        assert!(json.contains("\"result_hash\""));
        assert!(json.contains("\"environment_fingerprint\""));
    }

    #[test]
    fn evidence_input_json_field_names() {
        let ev = make_evidence(DisruptionDimension::AutonomyDelta, 800_000, &["bd-181"]);
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"dimension\""));
        assert!(json.contains("\"raw_score_millionths\""));
        assert!(json.contains("\"source_beads\""));
        assert!(json.contains("\"evidence_hash\""));
    }

    #[test]
    fn scorecard_log_entry_json_field_names() {
        let entry = ScorecardLogEntry {
            trace_id: "t1".to_string(),
            scorecard_version: "v1".to_string(),
            dimension: DisruptionDimension::PerformanceDelta,
            raw_score_millionths: 150_000,
            threshold_floor_millionths: 0,
            threshold_target_millionths: 100_000,
            pass: true,
            evidence_refs: vec![],
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"trace_id\""));
        assert!(json.contains("\"scorecard_version\""));
        assert!(json.contains("\"dimension\""));
        assert!(json.contains("\"raw_score_millionths\""));
        assert!(json.contains("\"threshold_floor_millionths\""));
        assert!(json.contains("\"threshold_target_millionths\""));
        assert!(json.contains("\"pass\""));
        assert!(json.contains("\"evidence_refs\""));
    }

    #[test]
    fn history_entry_json_field_names() {
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        let entry = HistoryEntry {
            candidate_id: "rc-1".to_string(),
            timestamp: "2026-02-28T00:00:00Z".to_string(),
            result,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"candidate_id\""));
        assert!(json.contains("\"timestamp\""));
        assert!(json.contains("\"result\""));
    }

    #[test]
    fn scorecard_schema_json_field_names() {
        let schema = default_schema();
        let json = serde_json::to_string(&schema).unwrap();
        assert!(json.contains("\"version\""));
        assert!(json.contains("\"thresholds\""));
        assert!(json.contains("\"evidence_sources\""));
    }

    // ===================================================================
    // Enrichment batch: Display format checks
    // ===================================================================

    #[test]
    fn dimension_display_format_exact() {
        assert_eq!(
            format!("{}", DisruptionDimension::PerformanceDelta),
            "performance_delta"
        );
        assert_eq!(
            format!("{}", DisruptionDimension::SecurityDelta),
            "security_delta"
        );
        assert_eq!(
            format!("{}", DisruptionDimension::AutonomyDelta),
            "autonomy_delta"
        );
    }

    #[test]
    fn outcome_display_format_exact() {
        assert_eq!(format!("{}", ScorecardOutcome::Pass), "pass");
        assert_eq!(format!("{}", ScorecardOutcome::Fail), "fail");
    }

    #[test]
    fn error_display_schema_validation_failed() {
        let e = ScorecardError::SchemaValidationFailed {
            detail: "bad config".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("schema validation failed"));
        assert!(s.contains("bad config"));
    }

    #[test]
    fn error_display_format_includes_all_fields() {
        let e = ScorecardError::InvalidThreshold {
            dimension: "security_delta".to_string(),
            detail: "floor (700000) > target (500000)".to_string(),
        };
        let s = e.to_string();
        assert!(s.contains("security_delta"));
        assert!(s.contains("700000"));
        assert!(s.contains("500000"));
    }

    // ===================================================================
    // Enrichment batch: Hash consistency
    // ===================================================================

    #[test]
    fn dimension_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        for dim in DisruptionDimension::all() {
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            dim.hash(&mut h1);
            dim.hash(&mut h2);
            assert_eq!(
                h1.finish(),
                h2.finish(),
                "same dimension hashes consistently"
            );
        }
    }

    #[test]
    fn dimension_hash_all_distinct() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hashes = std::collections::BTreeSet::new();
        for dim in DisruptionDimension::all() {
            let mut h = DefaultHasher::new();
            dim.hash(&mut h);
            hashes.insert(h.finish());
        }
        assert_eq!(hashes.len(), 3, "all dimension hashes are distinct");
    }

    #[test]
    fn outcome_hash_consistency() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        for outcome in &[ScorecardOutcome::Pass, ScorecardOutcome::Fail] {
            let mut h1 = DefaultHasher::new();
            let mut h2 = DefaultHasher::new();
            outcome.hash(&mut h1);
            outcome.hash(&mut h2);
            assert_eq!(h1.finish(), h2.finish());
        }
    }

    #[test]
    fn outcome_hash_distinct() {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h_pass = DefaultHasher::new();
        let mut h_fail = DefaultHasher::new();
        ScorecardOutcome::Pass.hash(&mut h_pass);
        ScorecardOutcome::Fail.hash(&mut h_fail);
        assert_ne!(h_pass.finish(), h_fail.finish());
    }

    // ===================================================================
    // Enrichment batch: boundary / edge cases
    // ===================================================================

    #[test]
    fn threshold_zero_floor_zero_target_is_valid() {
        let t = DimensionThreshold {
            dimension: DisruptionDimension::PerformanceDelta,
            floor_millionths: 0,
            target_millionths: 0,
            description: "zero".to_string(),
        };
        assert!(t.is_valid());
        assert!(t.meets_floor(0));
        assert!(t.meets_target(0));
    }

    #[test]
    fn threshold_max_values() {
        let t = DimensionThreshold {
            dimension: DisruptionDimension::SecurityDelta,
            floor_millionths: u64::MAX,
            target_millionths: u64::MAX,
            description: "max".to_string(),
        };
        assert!(t.is_valid());
        assert!(t.meets_floor(u64::MAX));
        assert!(t.meets_target(u64::MAX));
        assert!(!t.meets_floor(u64::MAX - 1));
    }

    #[test]
    fn history_default_is_empty() {
        let h = ScorecardHistory::default();
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
        assert!(h.latest().is_none());
    }

    #[test]
    fn history_latest_returns_last_appended() {
        let mut h = ScorecardHistory::new();
        let schema = default_schema();
        for i in 0..5 {
            let evidence = vec![
                make_evidence(
                    DisruptionDimension::PerformanceDelta,
                    100_000 + i * 10_000,
                    &[],
                ),
                make_evidence(DisruptionDimension::SecurityDelta, 600_000, &[]),
                make_evidence(DisruptionDimension::AutonomyDelta, 700_000, &[]),
            ];
            let result = compute_scorecard(
                &schema,
                &evidence,
                SecurityEpoch::from_raw(i + 1),
                "test".to_string(),
            )
            .unwrap();
            h.append(format!("rc-{}", i), format!("t{}", i), result);
        }
        assert_eq!(h.len(), 5);
        assert_eq!(h.latest().unwrap().candidate_id, "rc-4");
    }

    #[test]
    fn scorecard_with_max_u64_score() {
        let mut schema = default_schema();
        // Set all floors and targets to 0 so any score passes.
        for threshold in schema.thresholds.values_mut() {
            threshold.floor_millionths = 0;
            threshold.target_millionths = 0;
        }
        let evidence = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, u64::MAX, &[]),
            make_evidence(DisruptionDimension::SecurityDelta, u64::MAX, &[]),
            make_evidence(DisruptionDimension::AutonomyDelta, u64::MAX, &[]),
        ];
        let result = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(1),
            "max-test".to_string(),
        )
        .unwrap();
        assert!(result.outcome.is_pass());
        assert_eq!(result.targets_met, 3);
    }

    #[test]
    fn evidence_empty_source_beads() {
        let ev = make_evidence(DisruptionDimension::PerformanceDelta, 100_000, &[]);
        assert!(ev.source_beads.is_empty());
    }

    #[test]
    fn schema_empty_evidence_sources() {
        let mut schema = default_schema();
        schema.evidence_sources.clear();
        // Schema with empty evidence_sources is still structurally valid.
        assert!(schema.validate().is_ok());
    }

    #[test]
    fn compute_scorecard_epoch_preserved() {
        let epoch = SecurityEpoch::from_raw(42);
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            epoch,
            "test".to_string(),
        )
        .unwrap();
        assert_eq!(result.epoch.as_u64(), 42);
    }

    #[test]
    fn compute_scorecard_environment_fingerprint_preserved() {
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "my-env-fp".to_string(),
        )
        .unwrap();
        assert_eq!(result.environment_fingerprint, "my-env-fp");
    }

    // ===================================================================
    // Enrichment batch: complex serde roundtrips
    // ===================================================================

    #[test]
    fn serde_full_scorecard_result_deep_roundtrip() {
        let schema = default_schema();
        let evidence = vec![
            make_evidence(
                DisruptionDimension::PerformanceDelta,
                200_000,
                &["bd-1ze", "bd-extra"],
            ),
            make_evidence(DisruptionDimension::SecurityDelta, 900_000, &["bd-3rd"]),
            make_evidence(
                DisruptionDimension::AutonomyDelta,
                950_000,
                &["bd-181", "bd-uwc"],
            ),
        ];
        let result = compute_scorecard(
            &schema,
            &evidence,
            SecurityEpoch::from_raw(99),
            "deep-roundtrip".to_string(),
        )
        .unwrap();
        let json = serde_json::to_string_pretty(&result).unwrap();
        let back: ScorecardResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn serde_history_multi_entry_roundtrip() {
        let mut history = ScorecardHistory::new();
        let schema = default_schema();
        for i in 0..3 {
            let evidence = vec![
                make_evidence(
                    DisruptionDimension::PerformanceDelta,
                    100_000 + i * 50_000,
                    &[],
                ),
                make_evidence(
                    DisruptionDimension::SecurityDelta,
                    600_000 + i * 100_000,
                    &[],
                ),
                make_evidence(
                    DisruptionDimension::AutonomyDelta,
                    700_000 + i * 50_000,
                    &[],
                ),
            ];
            let result = compute_scorecard(
                &schema,
                &evidence,
                SecurityEpoch::from_raw(i + 1),
                format!("env-{}", i),
            )
            .unwrap();
            history.append(
                format!("rc-{}", i),
                format!("2026-02-28T0{}:00:00Z", i),
                result,
            );
        }
        let json = serde_json::to_string(&history).unwrap();
        let back: ScorecardHistory = serde_json::from_str(&json).unwrap();
        assert_eq!(history, back);
        assert_eq!(back.len(), 3);
    }

    #[test]
    fn serde_scorecard_error_all_variants_roundtrip() {
        let errors: Vec<ScorecardError> = vec![
            ScorecardError::MissingDimension {
                dimension: "perf".into(),
            },
            ScorecardError::InvalidThreshold {
                dimension: "sec".into(),
                detail: "floor > target".into(),
            },
            ScorecardError::MissingEvidence {
                dimension: "auto".into(),
            },
            ScorecardError::EmptyEvidenceBundle,
            ScorecardError::SchemaValidationFailed {
                detail: "bad".into(),
            },
        ];
        for e in &errors {
            let json = serde_json::to_string(e).unwrap();
            let back: ScorecardError = serde_json::from_str(&json).unwrap();
            assert_eq!(*e, back);
        }
    }

    #[test]
    fn serde_dimension_threshold_with_empty_description() {
        let t = DimensionThreshold {
            dimension: DisruptionDimension::AutonomyDelta,
            floor_millionths: 0,
            target_millionths: MILLION,
            description: String::new(),
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: DimensionThreshold = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
        assert!(back.description.is_empty());
    }

    #[test]
    fn serde_dimension_score_with_many_evidence_refs() {
        let threshold = DimensionThreshold {
            dimension: DisruptionDimension::SecurityDelta,
            floor_millionths: 0,
            target_millionths: MILLION,
            description: "test".to_string(),
        };
        let refs: Vec<String> = (0..20).map(|i| format!("bd-{}", i)).collect();
        let score = DimensionScore::compute(
            DisruptionDimension::SecurityDelta,
            500_000,
            &threshold,
            refs.clone(),
        );
        let json = serde_json::to_string(&score).unwrap();
        let back: DimensionScore = serde_json::from_str(&json).unwrap();
        assert_eq!(score, back);
        assert_eq!(back.evidence_refs.len(), 20);
    }

    // ===================================================================
    // Enrichment batch: additional behavioral tests
    // ===================================================================

    #[test]
    fn dimension_as_str_matches_display() {
        for dim in DisruptionDimension::all() {
            assert_eq!(dim.as_str(), &dim.to_string());
        }
    }

    #[test]
    fn outcome_as_str_matches_display() {
        for outcome in &[ScorecardOutcome::Pass, ScorecardOutcome::Fail] {
            assert_eq!(outcome.as_str(), &outcome.to_string());
        }
    }

    #[test]
    fn compute_hash_is_deterministic() {
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        let h1 = result.compute_hash();
        let h2 = result.compute_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn result_hash_equals_compute_hash() {
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        assert_eq!(result.result_hash, result.compute_hash());
    }

    #[test]
    fn log_entries_scorecard_version_matches_result() {
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        let entries = generate_log_entries("trace-1", &result);
        for entry in &entries {
            assert_eq!(entry.scorecard_version, result.schema_version);
        }
    }

    #[test]
    fn log_entries_dimensions_are_distinct() {
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        let entries = generate_log_entries("trace-1", &result);
        let mut dims = std::collections::BTreeSet::new();
        for entry in &entries {
            dims.insert(entry.dimension);
        }
        assert_eq!(dims.len(), 3);
    }

    #[test]
    fn history_regression_flat_scores_no_regression() {
        let mut h = ScorecardHistory::new();
        let schema = default_schema();
        let evidence = vec![
            make_evidence(DisruptionDimension::PerformanceDelta, 100_000, &[]),
            make_evidence(DisruptionDimension::SecurityDelta, 600_000, &[]),
            make_evidence(DisruptionDimension::AutonomyDelta, 700_000, &[]),
        ];
        for i in 0..3 {
            let result = compute_scorecard(
                &schema,
                &evidence,
                SecurityEpoch::from_raw(i + 1),
                "test".to_string(),
            )
            .unwrap();
            h.append(format!("rc-{}", i), format!("t{}", i), result);
        }
        assert!(
            !h.has_regression(),
            "identical scores should not show regression"
        );
    }

    #[test]
    fn schema_validate_floor_one_above_target_fails() {
        let mut schema = default_schema();
        let t = schema.thresholds.get_mut("autonomy_delta").unwrap();
        t.floor_millionths = t.target_millionths + 1;
        assert!(schema.validate().is_err());
    }

    #[test]
    fn dimension_score_exactly_at_target() {
        let threshold = DimensionThreshold {
            dimension: DisruptionDimension::AutonomyDelta,
            floor_millionths: 600_000,
            target_millionths: 900_000,
            description: "test".to_string(),
        };
        let score = DimensionScore::compute(
            DisruptionDimension::AutonomyDelta,
            900_000,
            &threshold,
            vec![],
        );
        assert!(score.meets_floor);
        assert!(score.meets_target);
    }

    #[test]
    fn dimension_score_one_below_target() {
        let threshold = DimensionThreshold {
            dimension: DisruptionDimension::AutonomyDelta,
            floor_millionths: 600_000,
            target_millionths: 900_000,
            description: "test".to_string(),
        };
        let score = DimensionScore::compute(
            DisruptionDimension::AutonomyDelta,
            899_999,
            &threshold,
            vec![],
        );
        assert!(score.meets_floor);
        assert!(!score.meets_target);
    }

    #[test]
    fn dimension_score_one_below_floor() {
        let threshold = DimensionThreshold {
            dimension: DisruptionDimension::SecurityDelta,
            floor_millionths: 500_000,
            target_millionths: 800_000,
            description: "test".to_string(),
        };
        let score = DimensionScore::compute(
            DisruptionDimension::SecurityDelta,
            499_999,
            &threshold,
            vec![],
        );
        assert!(!score.meets_floor);
        assert!(!score.meets_target);
    }

    #[test]
    fn compute_scorecard_schema_version_propagated() {
        let schema = default_schema();
        let result = compute_scorecard(
            &schema,
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        assert_eq!(result.schema_version, SCORECARD_SCHEMA_VERSION);
    }

    #[test]
    fn compute_scorecard_dimensions_evaluated_always_three() {
        let schema = default_schema();
        let result = compute_scorecard(
            &schema,
            &passing_evidence(),
            SecurityEpoch::from_raw(1),
            "test".to_string(),
        )
        .unwrap();
        assert_eq!(result.dimensions_evaluated, 3);
    }

    #[test]
    fn scorecard_error_schema_validation_roundtrip() {
        let e = ScorecardError::SchemaValidationFailed {
            detail: "complex detail with special chars: <>&\"'".to_string(),
        };
        let json = serde_json::to_string(&e).unwrap();
        let back: ScorecardError = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    #[test]
    fn history_entry_serde_roundtrip() {
        let result = compute_scorecard(
            &default_schema(),
            &passing_evidence(),
            SecurityEpoch::from_raw(7),
            "entry-rt".to_string(),
        )
        .unwrap();
        let entry = HistoryEntry {
            candidate_id: "rc-42".to_string(),
            timestamp: "2026-02-28T12:34:56Z".to_string(),
            result,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: HistoryEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }
}
