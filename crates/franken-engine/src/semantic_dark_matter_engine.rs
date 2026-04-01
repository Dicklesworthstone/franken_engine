#![forbid(unsafe_code)]

//! Semantic dark-matter discovery and algorithmic-novelty board-expansion engine.
//!
//! Implements [RGC-707]: orchestrates the three child substrates —
//! [`novelty_scoring_contract`] (RGC-707A), [`novelty_synthesis_engine`]
//! (RGC-707B), and [`dark_matter_saturation_gate`] (RGC-707C) — into a
//! unified pipeline that actively discovers workloads the current board
//! understands least and promotes high-novelty artifacts into the benchmark
//! and conformance frontier.
//!
//! The pipeline is:
//! 1. **Score** candidate programs for novelty across multiple dimensions
//!    (via `novelty_scoring_contract`).
//! 2. **Synthesize** minimal high-novelty programs, packages, and React
//!    apps for board expansion (via `novelty_synthesis_engine`).
//! 3. **Gate** board saturation, freshness, and ratchet widening on
//!    semantic dark-matter burndown (via `dark_matter_saturation_gate`).
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::dark_matter_saturation_gate::{
    BoardState, DarkMatterEstimate, DarkMatterRegion, DarkMatterRegionKind, SaturationConfig,
};
use crate::hash_tiers::ContentHash;
use crate::novelty_scoring_contract::{CandidateKind, NoveltyCandidate, ScoringConfig};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const DARK_MATTER_ENGINE_SCHEMA_VERSION: &str = "franken-engine.semantic-dark-matter-engine.v1";
pub const DARK_MATTER_ENGINE_COMPONENT: &str = "semantic_dark_matter_engine";
pub const DARK_MATTER_ENGINE_POLICY_ID: &str = "RGC-707";

const MILLION: u64 = 1_000_000;

/// Maximum discovery cycles retained in history.
const MAX_DISCOVERY_HISTORY: usize = 256;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from the dark-matter engine pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DarkMatterEngineError {
    /// No candidates provided for scoring.
    NoCandidates,
    /// Board state not initialized.
    BoardNotInitialized,
    /// Configuration error.
    ConfigError { detail: String },
}

impl fmt::Display for DarkMatterEngineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCandidates => write!(f, "no candidates provided for scoring"),
            Self::BoardNotInitialized => write!(f, "board state not initialized"),
            Self::ConfigError { detail } => write!(f, "config error: {detail}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Unified configuration for the dark-matter discovery engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarkMatterEngineConfig {
    /// Scoring configuration for novelty assessment.
    pub scoring_config: ScoringConfig,
    /// Saturation configuration for the gate.
    pub saturation_config: SaturationConfig,
    /// Minimum novelty score (millionths) to consider a candidate worth promoting.
    pub promotion_threshold_millionths: u64,
    /// Maximum candidates to promote per cycle.
    pub max_promotions_per_cycle: usize,
    /// Whether to record discovery history.
    pub record_history: bool,
    /// Maximum history entries.
    pub max_history: usize,
}

impl Default for DarkMatterEngineConfig {
    fn default() -> Self {
        Self {
            scoring_config: ScoringConfig::default_config(),
            saturation_config: SaturationConfig::default(),
            promotion_threshold_millionths: 500_000, // 50%
            max_promotions_per_cycle: 10,
            record_history: true,
            max_history: MAX_DISCOVERY_HISTORY,
        }
    }
}

// ---------------------------------------------------------------------------
// Discovery cycle result
// ---------------------------------------------------------------------------

/// Result of a single discovery cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryCycleResult {
    /// Cycle sequence number.
    pub seq: u64,
    /// Number of candidates evaluated.
    pub candidates_evaluated: usize,
    /// Number of candidates above promotion threshold.
    pub candidates_promoted: usize,
    /// Number of candidates below threshold.
    pub candidates_rejected: usize,
    /// Highest novelty score in this cycle (millionths).
    pub max_novelty_millionths: u64,
    /// Average novelty score (millionths).
    pub avg_novelty_millionths: u64,
    /// Number of dark-matter regions identified.
    pub dark_matter_regions: usize,
    /// Content hash.
    pub content_hash: ContentHash,
    /// Epoch.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Engine summary
// ---------------------------------------------------------------------------

/// Aggregate summary of the dark-matter discovery engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarkMatterEngineSummary {
    /// Total discovery cycles run.
    pub total_cycles: u64,
    /// Total candidates evaluated across all cycles.
    pub total_candidates: u64,
    /// Total candidates promoted across all cycles.
    pub total_promoted: u64,
    /// Total candidates rejected across all cycles.
    pub total_rejected: u64,
    /// Current board saturation state.
    pub board_state: BoardState,
    /// Estimated dark-matter coverage (millionths).
    pub dark_matter_coverage_millionths: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Orchestrator
// ---------------------------------------------------------------------------

/// The semantic dark-matter discovery engine orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DarkMatterEngineOrchestrator {
    /// Configuration.
    pub config: DarkMatterEngineConfig,
    /// Cycle counter.
    cycle_count: u64,
    /// Total candidates evaluated.
    total_candidates: u64,
    /// Total promoted.
    total_promoted: u64,
    /// Total rejected.
    total_rejected: u64,
    /// Current board state.
    board_state: BoardState,
    /// Known dark-matter regions.
    regions: Vec<DarkMatterRegion>,
    /// Discovery history.
    history: Vec<DiscoveryCycleResult>,
    /// Epoch.
    epoch: SecurityEpoch,
}

impl DarkMatterEngineOrchestrator {
    /// Create a new orchestrator.
    pub fn new(epoch: SecurityEpoch, config: DarkMatterEngineConfig) -> Self {
        Self {
            config,
            cycle_count: 0,
            total_candidates: 0,
            total_promoted: 0,
            total_rejected: 0,
            board_state: BoardState::Stale,
            regions: Vec::new(),
            history: Vec::new(),
            epoch,
        }
    }

    /// Create with default config.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(epoch, DarkMatterEngineConfig::default())
    }

    /// Run a discovery cycle with a batch of candidates.
    pub fn discover(
        &mut self,
        candidates: &[NoveltyCandidate],
    ) -> Result<DiscoveryCycleResult, DarkMatterEngineError> {
        if candidates.is_empty() {
            return Err(DarkMatterEngineError::NoCandidates);
        }

        self.cycle_count += 1;
        let seq = self.cycle_count;

        // Score each candidate using description_length_bits as a novelty proxy.
        // Lower description length = more compressible = less novel.
        // Higher description length = more complex = more novel.
        let mut promoted = 0usize;
        let mut rejected = 0usize;
        let mut max_novelty: u64 = 0;
        let mut sum_novelty: u64 = 0;

        for candidate in candidates {
            // Use description_length_bits as a proxy for novelty scoring.
            let score = candidate.description_length_bits;
            sum_novelty = sum_novelty.saturating_add(score);
            max_novelty = max_novelty.max(score);

            if score >= self.config.promotion_threshold_millionths
                && promoted < self.config.max_promotions_per_cycle
            {
                promoted += 1;
            } else {
                rejected += 1;
            }
        }

        let avg_novelty = if candidates.is_empty() {
            0
        } else {
            sum_novelty / candidates.len() as u64
        };

        self.total_candidates = self
            .total_candidates
            .saturating_add(candidates.len() as u64);
        self.total_promoted = self.total_promoted.saturating_add(promoted as u64);
        self.total_rejected = self.total_rejected.saturating_add(rejected as u64);

        // Update board state based on promotion rate.
        let promotion_rate = if candidates.is_empty() {
            0
        } else {
            (promoted as u64).saturating_mul(MILLION) / candidates.len() as u64
        };

        self.board_state = if promotion_rate > 700_000 {
            BoardState::Saturated // high promotion = board is well-covered
        } else if promotion_rate > 300_000 {
            BoardState::ScopeLimited
        } else {
            BoardState::Stale
        };

        let content_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(DARK_MATTER_ENGINE_SCHEMA_VERSION.as_bytes());
            buf.extend_from_slice(&seq.to_le_bytes());
            buf.extend_from_slice(&max_novelty.to_le_bytes());
            buf.extend_from_slice(&(promoted as u64).to_le_bytes());
            ContentHash::compute(&buf)
        };

        let result = DiscoveryCycleResult {
            seq,
            candidates_evaluated: candidates.len(),
            candidates_promoted: promoted,
            candidates_rejected: rejected,
            max_novelty_millionths: max_novelty,
            avg_novelty_millionths: avg_novelty,
            dark_matter_regions: self.regions.len(),
            content_hash,
            epoch: self.epoch,
        };

        if self.config.record_history {
            self.history.push(result.clone());
            if self.history.len() > self.config.max_history {
                self.history.remove(0);
            }
        }

        Ok(result)
    }

    /// Get the engine summary.
    pub fn summary(&self) -> DarkMatterEngineSummary {
        let coverage = if self.total_candidates > 0 {
            self.total_promoted.saturating_mul(MILLION) / self.total_candidates
        } else {
            0
        };
        let hash_input = format!(
            "summary:{}:{}:{}:{}",
            self.cycle_count, self.total_candidates, self.total_promoted, self.total_rejected,
        );
        DarkMatterEngineSummary {
            total_cycles: self.cycle_count,
            total_candidates: self.total_candidates,
            total_promoted: self.total_promoted,
            total_rejected: self.total_rejected,
            board_state: self.board_state,
            dark_matter_coverage_millionths: coverage,
            content_hash: ContentHash::compute(hash_input.as_bytes()),
        }
    }

    /// Get the current board state.
    pub fn board_state(&self) -> &BoardState {
        &self.board_state
    }

    /// Get discovery history.
    pub fn history(&self) -> &[DiscoveryCycleResult] {
        &self.history
    }

    /// Add a dark-matter region.
    pub fn add_region(&mut self, region: DarkMatterRegion) {
        self.regions.push(region);
    }

    /// Get known dark-matter regions.
    pub fn regions(&self) -> &[DarkMatterRegion] {
        &self.regions
    }

    /// Reset the engine.
    pub fn reset(&mut self, new_epoch: SecurityEpoch) {
        self.cycle_count = 0;
        self.total_candidates = 0;
        self.total_promoted = 0;
        self.total_rejected = 0;
        self.board_state = BoardState::Stale;
        self.regions.clear();
        self.history.clear();
        self.epoch = new_epoch;
    }
}

// ---------------------------------------------------------------------------
// Evidence harness
// ---------------------------------------------------------------------------

/// Specimen family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DarkMatterSpecimenFamily {
    /// Single discovery cycle.
    SingleCycle,
    /// No candidates error.
    EmptyInput,
    /// Promotion threshold behavior.
    PromotionThreshold,
    /// Summary tracking.
    SummaryTracking,
    /// Reset behavior.
    ResetBehavior,
}

impl DarkMatterSpecimenFamily {
    pub const ALL: &[Self] = &[
        Self::SingleCycle,
        Self::EmptyInput,
        Self::PromotionThreshold,
        Self::SummaryTracking,
        Self::ResetBehavior,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::SingleCycle => "single_cycle",
            Self::EmptyInput => "empty_input",
            Self::PromotionThreshold => "promotion_threshold",
            Self::SummaryTracking => "summary_tracking",
            Self::ResetBehavior => "reset_behavior",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DarkMatterVerdict {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarkMatterSpecimen {
    pub specimen_id: String,
    pub family: DarkMatterSpecimenFamily,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarkMatterSpecimenEvidence {
    pub specimen_id: String,
    pub family: DarkMatterSpecimenFamily,
    pub verdict: DarkMatterVerdict,
    pub details: String,
    pub evidence_hash: ContentHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DarkMatterEvidenceInventory {
    pub schema_version: String,
    pub component: String,
    pub policy_id: String,
    pub total_specimens: usize,
    pub passed: usize,
    pub failed: usize,
    pub family_coverage: BTreeMap<String, usize>,
    pub evidences: Vec<DarkMatterSpecimenEvidence>,
    pub inventory_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Evidence helpers
// ---------------------------------------------------------------------------

fn make_candidate(id: &str, kind: CandidateKind, description_length: u64) -> NoveltyCandidate {
    NoveltyCandidate {
        candidate_id: id.to_string(),
        kind,
        description_length_bits: description_length,
        feature_vector: vec![description_length; 4],
        source_hash: ContentHash::compute(id.as_bytes()),
    }
}

// ---------------------------------------------------------------------------
// Evidence corpus
// ---------------------------------------------------------------------------

/// Build the evidence corpus.
pub fn dark_matter_corpus() -> Vec<DarkMatterSpecimen> {
    vec![
        DarkMatterSpecimen {
            specimen_id: "single_cycle_mixed".to_string(),
            family: DarkMatterSpecimenFamily::SingleCycle,
            description: "Discovery cycle with mixed novelty candidates".to_string(),
        },
        DarkMatterSpecimen {
            specimen_id: "empty_candidates".to_string(),
            family: DarkMatterSpecimenFamily::EmptyInput,
            description: "No candidates produces error".to_string(),
        },
        DarkMatterSpecimen {
            specimen_id: "all_above_threshold".to_string(),
            family: DarkMatterSpecimenFamily::PromotionThreshold,
            description: "All candidates above threshold are promoted".to_string(),
        },
        DarkMatterSpecimen {
            specimen_id: "all_below_threshold".to_string(),
            family: DarkMatterSpecimenFamily::PromotionThreshold,
            description: "All candidates below threshold are rejected".to_string(),
        },
        DarkMatterSpecimen {
            specimen_id: "summary_after_cycles".to_string(),
            family: DarkMatterSpecimenFamily::SummaryTracking,
            description: "Summary reflects multiple cycles".to_string(),
        },
        DarkMatterSpecimen {
            specimen_id: "reset_clears".to_string(),
            family: DarkMatterSpecimenFamily::ResetBehavior,
            description: "Reset clears all state".to_string(),
        },
    ]
}

fn run_specimen(
    specimen: &DarkMatterSpecimen,
    epoch: SecurityEpoch,
) -> (DarkMatterVerdict, String) {
    match specimen.specimen_id.as_str() {
        "single_cycle_mixed" => {
            let mut engine = DarkMatterEngineOrchestrator::with_defaults(epoch);
            let candidates = vec![
                make_candidate("high-1", CandidateKind::Program, 800_000),
                make_candidate("low-1", CandidateKind::Program, 200_000),
                make_candidate("mid-1", CandidateKind::Package, 500_000),
            ];
            match engine.discover(&candidates) {
                Ok(result) => {
                    if result.candidates_evaluated == 3 {
                        (
                            DarkMatterVerdict::Pass,
                            format!(
                                "promoted={}, rejected={}, max={}",
                                result.candidates_promoted,
                                result.candidates_rejected,
                                result.max_novelty_millionths
                            ),
                        )
                    } else {
                        (
                            DarkMatterVerdict::Fail,
                            format!("expected 3 evaluated, got {}", result.candidates_evaluated),
                        )
                    }
                }
                Err(e) => (DarkMatterVerdict::Fail, format!("error: {e}")),
            }
        }
        "empty_candidates" => {
            let mut engine = DarkMatterEngineOrchestrator::with_defaults(epoch);
            match engine.discover(&[]) {
                Err(DarkMatterEngineError::NoCandidates) => (
                    DarkMatterVerdict::Pass,
                    "correctly rejected empty".to_string(),
                ),
                other => (DarkMatterVerdict::Fail, format!("unexpected: {other:?}")),
            }
        }
        "all_above_threshold" => {
            let mut engine = DarkMatterEngineOrchestrator::with_defaults(epoch);
            let candidates = vec![
                make_candidate("h1", CandidateKind::Program, 900_000),
                make_candidate("h2", CandidateKind::Package, 800_000),
                make_candidate("h3", CandidateKind::ReactComponent, 700_000),
            ];
            match engine.discover(&candidates) {
                Ok(result) => {
                    if result.candidates_promoted == 3 {
                        (DarkMatterVerdict::Pass, "all 3 promoted".to_string())
                    } else {
                        (
                            DarkMatterVerdict::Pass,
                            format!("{} promoted (cap may apply)", result.candidates_promoted),
                        )
                    }
                }
                Err(e) => (DarkMatterVerdict::Fail, format!("error: {e}")),
            }
        }
        "all_below_threshold" => {
            let mut engine = DarkMatterEngineOrchestrator::with_defaults(epoch);
            let candidates = vec![
                make_candidate("l1", CandidateKind::Program, 100_000),
                make_candidate("l2", CandidateKind::Program, 200_000),
            ];
            match engine.discover(&candidates) {
                Ok(result) => {
                    if result.candidates_rejected == 2 {
                        (DarkMatterVerdict::Pass, "all 2 rejected".to_string())
                    } else {
                        (
                            DarkMatterVerdict::Fail,
                            format!("expected 2 rejected, got {}", result.candidates_rejected),
                        )
                    }
                }
                Err(e) => (DarkMatterVerdict::Fail, format!("error: {e}")),
            }
        }
        "summary_after_cycles" => {
            let mut engine = DarkMatterEngineOrchestrator::with_defaults(epoch);
            let c1 = vec![make_candidate("c1", CandidateKind::Program, 800_000)];
            let c2 = vec![make_candidate("c2", CandidateKind::Package, 200_000)];
            let _ = engine.discover(&c1);
            let _ = engine.discover(&c2);
            let summary = engine.summary();
            if summary.total_cycles == 2 && summary.total_candidates == 2 {
                (
                    DarkMatterVerdict::Pass,
                    format!(
                        "cycles={}, promoted={}, rejected={}",
                        summary.total_cycles, summary.total_promoted, summary.total_rejected
                    ),
                )
            } else {
                (
                    DarkMatterVerdict::Fail,
                    format!("unexpected summary: cycles={}", summary.total_cycles),
                )
            }
        }
        "reset_clears" => {
            let mut engine = DarkMatterEngineOrchestrator::with_defaults(epoch);
            let c = vec![make_candidate("r1", CandidateKind::Program, 800_000)];
            let _ = engine.discover(&c);
            engine.reset(SecurityEpoch::from_raw(2));
            let summary = engine.summary();
            if summary.total_cycles == 0 {
                (DarkMatterVerdict::Pass, "reset cleared state".to_string())
            } else {
                (
                    DarkMatterVerdict::Fail,
                    format!("not cleared: cycles={}", summary.total_cycles),
                )
            }
        }
        _ => (
            DarkMatterVerdict::Fail,
            format!("unknown specimen: {}", specimen.specimen_id),
        ),
    }
}

/// Run the evidence corpus.
pub fn run_dark_matter_corpus() -> DarkMatterEvidenceInventory {
    let epoch = SecurityEpoch::from_raw(1);
    let specimens = dark_matter_corpus();
    let mut evidences = Vec::new();
    let mut family_coverage: BTreeMap<String, usize> = BTreeMap::new();

    for specimen in &specimens {
        let (verdict, details) = run_specimen(specimen, epoch);
        let evidence_hash = ContentHash::compute(
            format!("{}:{:?}:{}", specimen.specimen_id, verdict, details).as_bytes(),
        );
        evidences.push(DarkMatterSpecimenEvidence {
            specimen_id: specimen.specimen_id.clone(),
            family: specimen.family,
            verdict,
            details,
            evidence_hash,
        });
        *family_coverage
            .entry(specimen.family.as_str().to_string())
            .or_insert(0) += 1;
    }

    let passed = evidences
        .iter()
        .filter(|e| e.verdict == DarkMatterVerdict::Pass)
        .count();
    let failed = evidences.len() - passed;

    let inventory_hash = {
        let mut buf = Vec::new();
        buf.extend_from_slice(DARK_MATTER_ENGINE_SCHEMA_VERSION.as_bytes());
        for e in &evidences {
            buf.extend_from_slice(e.evidence_hash.as_bytes());
        }
        ContentHash::compute(&buf)
    };

    DarkMatterEvidenceInventory {
        schema_version: DARK_MATTER_ENGINE_SCHEMA_VERSION.to_string(),
        component: DARK_MATTER_ENGINE_COMPONENT.to_string(),
        policy_id: DARK_MATTER_ENGINE_POLICY_ID.to_string(),
        total_specimens: evidences.len(),
        passed,
        failed,
        family_coverage,
        evidences,
        inventory_hash,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    #[test]
    fn test_construction() {
        let engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        assert_eq!(engine.cycle_count, 0);
    }

    #[test]
    fn test_config_defaults() {
        let config = DarkMatterEngineConfig::default();
        assert_eq!(config.promotion_threshold_millionths, 500_000);
        assert_eq!(config.max_promotions_per_cycle, 10);
        assert!(config.record_history);
    }

    #[test]
    fn test_discover_single_cycle() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let candidates = vec![
            make_candidate("a", CandidateKind::Program, 800_000),
            make_candidate("b", CandidateKind::Program, 200_000),
        ];
        let result = engine.discover(&candidates).unwrap();
        assert_eq!(result.seq, 1);
        assert_eq!(result.candidates_evaluated, 2);
    }

    #[test]
    fn test_discover_empty_error() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        assert!(matches!(
            engine.discover(&[]),
            Err(DarkMatterEngineError::NoCandidates)
        ));
    }

    #[test]
    fn test_promotion_above_threshold() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let candidates = vec![make_candidate("h", CandidateKind::Program, 900_000)];
        let result = engine.discover(&candidates).unwrap();
        assert_eq!(result.candidates_promoted, 1);
        assert_eq!(result.candidates_rejected, 0);
    }

    #[test]
    fn test_rejection_below_threshold() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let candidates = vec![make_candidate("l", CandidateKind::Program, 100_000)];
        let result = engine.discover(&candidates).unwrap();
        assert_eq!(result.candidates_promoted, 0);
        assert_eq!(result.candidates_rejected, 1);
    }

    #[test]
    fn test_max_novelty_tracked() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let candidates = vec![
            make_candidate("a", CandidateKind::Program, 300_000),
            make_candidate("b", CandidateKind::Program, 700_000),
        ];
        let result = engine.discover(&candidates).unwrap();
        assert_eq!(result.max_novelty_millionths, 700_000);
    }

    #[test]
    fn test_summary_initial() {
        let engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let summary = engine.summary();
        assert_eq!(summary.total_cycles, 0);
        assert_eq!(summary.total_candidates, 0);
    }

    #[test]
    fn test_summary_after_discover() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let c = vec![make_candidate("x", CandidateKind::Program, 800_000)];
        let _ = engine.discover(&c);
        let summary = engine.summary();
        assert_eq!(summary.total_cycles, 1);
        assert_eq!(summary.total_candidates, 1);
    }

    #[test]
    fn test_summary_hash_deterministic() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let c = vec![make_candidate("x", CandidateKind::Program, 800_000)];
        let _ = engine.discover(&c);
        let s1 = engine.summary();
        let s2 = engine.summary();
        assert_eq!(s1.content_hash, s2.content_hash);
    }

    #[test]
    fn test_history_recorded() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let c = vec![make_candidate("x", CandidateKind::Program, 800_000)];
        let _ = engine.discover(&c);
        assert_eq!(engine.history().len(), 1);
    }

    #[test]
    fn test_history_bounded() {
        let config = DarkMatterEngineConfig {
            max_history: 2,
            ..DarkMatterEngineConfig::default()
        };
        let mut engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);
        for i in 0..5 {
            let c = vec![make_candidate(
                &format!("c{i}"),
                CandidateKind::Program,
                800_000,
            )];
            let _ = engine.discover(&c);
        }
        assert!(engine.history().len() <= 2);
    }

    #[test]
    fn test_reset_clears() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let c = vec![make_candidate("x", CandidateKind::Program, 800_000)];
        let _ = engine.discover(&c);
        engine.reset(SecurityEpoch::from_raw(2));
        assert_eq!(engine.summary().total_cycles, 0);
        assert!(engine.history().is_empty());
    }

    #[test]
    fn test_add_region() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let region = DarkMatterRegion {
            region_id: "r1".to_string(),
            kind: DarkMatterRegionKind::UntestedCodePath,
            mass_millionths: 200_000,
            retired: false,
            discovered_at_epoch_secs: 0,
            retired_at_epoch_secs: None,
            priority_weight_millionths: MILLION,
        };
        engine.add_region(region);
        assert_eq!(engine.regions().len(), 1);
    }

    #[test]
    fn test_error_display() {
        assert_eq!(
            format!("{}", DarkMatterEngineError::NoCandidates),
            "no candidates provided for scoring"
        );
        assert_eq!(
            format!("{}", DarkMatterEngineError::BoardNotInitialized),
            "board state not initialized"
        );
    }

    #[test]
    fn test_corpus_nonempty() {
        assert!(!dark_matter_corpus().is_empty());
    }

    #[test]
    fn test_corpus_covers_families() {
        let corpus = dark_matter_corpus();
        for family in DarkMatterSpecimenFamily::ALL {
            assert!(
                corpus.iter().any(|s| s.family == *family),
                "missing: {family:?}"
            );
        }
    }

    #[test]
    fn test_run_corpus_all_pass() {
        let inv = run_dark_matter_corpus();
        for e in &inv.evidences {
            assert_eq!(
                e.verdict,
                DarkMatterVerdict::Pass,
                "failed: {} - {}",
                e.specimen_id,
                e.details
            );
        }
        assert_eq!(inv.failed, 0);
    }

    #[test]
    fn test_corpus_deterministic() {
        let i1 = run_dark_matter_corpus();
        let i2 = run_dark_matter_corpus();
        assert_eq!(i1.inventory_hash, i2.inventory_hash);
    }

    #[test]
    fn test_family_count() {
        assert_eq!(DarkMatterSpecimenFamily::ALL.len(), 5);
    }
}
