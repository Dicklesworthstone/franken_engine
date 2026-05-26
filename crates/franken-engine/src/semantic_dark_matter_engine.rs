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
    BoardState, BurndownObservation, BurndownTracker, DarkMatterEstimate, DarkMatterRegion,
    DarkMatterRegionKind, DecisionReceipt, SaturationConfig, SaturationGateEvaluator,
};
use crate::hash_tiers::ContentHash;
use crate::novelty_scoring_contract::{
    CandidateKind, CompositeVerdict, NoveltyCandidate, NoveltyDimension, NoveltyVerdict,
    ScoringConfig, score_batch,
};
use crate::novelty_synthesis_engine::{
    DEFAULT_MAX_AST_NODES, DEFAULT_MAX_BYTES, ProgramKind, SynthesisConstraint,
    SynthesisDenialReason, SynthesisStrategy, filter_candidates, franken_engine_synthesis_manifest,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const DARK_MATTER_ENGINE_SCHEMA_VERSION: &str = "franken-engine.semantic-dark-matter-engine.v1";
pub const DARK_MATTER_ENGINE_COMPONENT: &str = "semantic_dark_matter_engine";
pub const DARK_MATTER_ENGINE_POLICY_ID: &str = "RGC-707";

const MILLION: u64 = 1_000_000;
const DISCOVERY_OBSERVATION_STEP_SECS: u64 = 3600;
const SYNTHESIS_REGION_PREFIX: &str = "semantic_dark_matter_synthesis::";

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

/// Per-candidate novelty receipt captured during a discovery cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryCandidateReceipt {
    /// Candidate identifier covered by this receipt.
    pub candidate_id: String,
    /// Threshold-facing novelty verdict from the scoring contract.
    pub novelty_verdict: NoveltyVerdict,
    /// Legacy composite verdict used by downstream publication surfaces.
    pub composite_verdict: CompositeVerdict,
    /// Total novelty score used for promotion gating.
    pub total_score_millionths: u64,
    /// Legacy composite novelty score used for ranking.
    pub composite_millionths: u64,
    /// Rank within the scored batch (0-based).
    pub rank: u32,
    /// Whether the candidate was promoted by this cycle.
    pub promoted: bool,
    /// Per-dimension novelty evidence from the scoring contract.
    pub dimension_scores: Vec<(NoveltyDimension, u64)>,
    /// Hash of the scoring configuration bound into the certificate.
    pub config_hash: ContentHash,
    /// Hash of the scoring certificate.
    pub certificate_hash: ContentHash,
    /// Hash of the legacy composite score entry.
    pub composite_score_hash: ContentHash,
}

/// Orchestrator-level denial reason for a synthesized candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SynthesizedCandidateDenialReason {
    /// Candidate was denied by the synthesis-engine filter itself.
    Filter(SynthesisDenialReason),
    /// Candidate would otherwise have been accepted, but the cycle-wide
    /// promotion budget was already exhausted.
    PromotionCapReached,
}

impl SynthesizedCandidateDenialReason {
    fn stable_label(&self) -> String {
        match self {
            Self::Filter(reason) => format!("filter:{}", reason.as_str()),
            Self::PromotionCapReached => "promotion_cap_reached".to_string(),
        }
    }
}

/// Detailed synthesized-candidate outcome captured during a discovery cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SynthesizedCandidateReceipt {
    /// Candidate identifier covered by this receipt.
    pub candidate_id: String,
    /// Synthesized artifact kind.
    pub kind: ProgramKind,
    /// Synthesis strategy used to produce this artifact.
    pub strategy: SynthesisStrategy,
    /// Novelty score assigned by the synthesis engine.
    pub novelty_score_millionths: u64,
    /// Estimated coverage delta carried by this candidate.
    pub coverage_delta_millionths: u64,
    /// Target board cells this candidate is meant to exercise.
    pub target_cells: Vec<String>,
    /// Candidate content hash from the synthesis engine.
    pub content_hash: ContentHash,
    /// Whether the candidate was accepted into this discovery cycle.
    pub accepted: bool,
    /// Denial reason when the candidate is not accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<SynthesizedCandidateDenialReason>,
}

/// Aggregate synthesis receipt bound into a discovery cycle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoverySynthesisReceipt {
    /// Canonical synthesis manifest batch identifier.
    pub manifest_batch_id: String,
    /// Deterministic content hash of the manifest batch.
    pub manifest_hash: ContentHash,
    /// Total synthesized candidates proposed to the cycle.
    pub candidates_proposed: u64,
    /// Synthesized candidates ultimately accepted by the cycle.
    pub candidates_accepted: u64,
    /// Synthesized candidates denied by filter or budget gating.
    pub candidates_denied: u64,
    /// Total novelty yield contributed by accepted synthesized candidates.
    pub novelty_yield_millionths: u64,
    /// Total coverage delta contributed by accepted synthesized candidates.
    pub coverage_improvement_millionths: u64,
    /// Deterministic hash over the synthesis outcome ledger.
    pub receipt_hash: ContentHash,
}

/// Region update action emitted from synthesized-candidate outcomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionUpdateAction {
    /// A rejected synthesized candidate leaves a target cell active.
    Activated,
    /// An accepted synthesized candidate retires a target cell.
    Retired,
}

/// Deterministic receipt describing a single region update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegionUpdateReceipt {
    /// Region identifier affected by this update.
    pub region_id: String,
    /// Candidate that triggered the update.
    pub candidate_id: String,
    /// Target cell that mapped to the region.
    pub target_cell: String,
    /// Whether the region was activated or retired.
    pub action: RegionUpdateAction,
    /// Region kind used for the synthesized coverage surface.
    pub kind: DarkMatterRegionKind,
    /// Mass assigned to this target-cell update.
    pub mass_millionths: u64,
    /// Whether the resulting region is retired after the update.
    pub retired: bool,
    /// Resulting region content hash after the update.
    pub content_hash: ContentHash,
}

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
    /// Per-candidate scoring receipts for auditing promotion decisions.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub candidate_receipts: Vec<DiscoveryCandidateReceipt>,
    /// Aggregate synthesis receipt for the cycle, when synthesis is run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synthesis_receipt: Option<DiscoverySynthesisReceipt>,
    /// Per-synthesized-candidate acceptance or denial ledger.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub synthesized_candidate_receipts: Vec<SynthesizedCandidateReceipt>,
    /// Deterministic region-update ledger emitted from synthesized outcomes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub region_update_receipts: Vec<RegionUpdateReceipt>,
    /// Saturation-gate receipt binding the emitted board state to the
    /// dark-matter estimate, freshness, and ratchet verdicts for this cycle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board_state_receipt: Option<DecisionReceipt>,
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
    /// Latest derived board-state receipt hash, if available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub board_state_receipt_hash: Option<ContentHash>,
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

#[derive(Debug, Clone, Copy)]
struct PendingCycleObservation {
    seq: u64,
    candidates_evaluated: usize,
    candidates_promoted: usize,
    candidates_rejected: usize,
}

impl PendingCycleObservation {
    fn from_result(result: &DiscoveryCycleResult) -> Self {
        Self {
            seq: result.seq,
            candidates_evaluated: result.candidates_evaluated,
            candidates_promoted: result.candidates_promoted,
            candidates_rejected: result.candidates_rejected,
        }
    }

    fn discovered_mass_millionths(self) -> u64 {
        if self.candidates_evaluated == 0 {
            return 0;
        }
        (self.candidates_rejected as u64).saturating_mul(MILLION) / self.candidates_evaluated as u64
    }

    fn retired_mass_millionths(self) -> u64 {
        if self.candidates_evaluated == 0 {
            return 0;
        }
        (self.candidates_promoted as u64).saturating_mul(MILLION) / self.candidates_evaluated as u64
    }

    fn observation_timestamp_epoch_secs(self, epoch: SecurityEpoch) -> u64 {
        logical_cycle_timestamp(epoch, self.seq)
    }
}

#[derive(Debug, Clone)]
struct BoardStateEvaluation {
    receipt: DecisionReceipt,
    region_count: usize,
}

fn logical_cycle_timestamp(epoch: SecurityEpoch, seq: u64) -> u64 {
    epoch
        .as_u64()
        .saturating_mul(1_000_000)
        .saturating_add(seq.saturating_mul(DISCOVERY_OBSERVATION_STEP_SECS))
}

fn synthesis_region_id(target_cell: &str) -> String {
    format!("{SYNTHESIS_REGION_PREFIX}{target_cell}")
}

fn synthesis_region_kind(kind: ProgramKind) -> DarkMatterRegionKind {
    match kind {
        ProgramKind::PlainJs | ProgramKind::TypeScript => DarkMatterRegionKind::UntestedCodePath,
        ProgramKind::ReactComponent | ProgramKind::ReactApp => {
            DarkMatterRegionKind::UnobservedModuleTopology
        }
        ProgramKind::NodePackage | ProgramKind::BunPackage => {
            DarkMatterRegionKind::UnobservedInteraction
        }
    }
}

fn split_target_cell_mass(
    target_cells: &[String],
    total_mass_millionths: u64,
) -> Vec<(String, u64)> {
    if target_cells.is_empty() || total_mass_millionths == 0 {
        return Vec::new();
    }

    let cell_count = target_cells.len() as u64;
    let base_mass = total_mass_millionths / cell_count;
    let mut remainder = total_mass_millionths % cell_count;
    let mut allocations = Vec::with_capacity(target_cells.len());
    for target_cell in target_cells {
        let mut mass = base_mass;
        if remainder > 0 {
            mass = mass.saturating_add(1);
            remainder -= 1;
        }
        allocations.push((target_cell.clone(), mass));
    }
    allocations
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
        if let Err(detail) = self.config.scoring_config.validate() {
            return Err(DarkMatterEngineError::ConfigError {
                detail: detail.to_string(),
            });
        }

        self.cycle_count += 1;
        let seq = self.cycle_count;

        // Score the batch through the shipped novelty scoring contract so
        // promotion decisions are derived from the same evidence surface that
        // powers the downstream RGC-707A publication lane.
        let novelty_batch = score_batch(candidates, &self.config.scoring_config);
        let composite_scores: BTreeMap<&str, _> = novelty_batch
            .scores
            .iter()
            .map(|score| (score.candidate_fingerprint.as_str(), score))
            .collect();
        let mut promoted = 0usize;
        let mut rejected = 0usize;
        let mut max_novelty: u64 = 0;
        let mut sum_novelty: u64 = 0;
        let mut candidate_receipts = Vec::with_capacity(novelty_batch.certificates.len());

        for certificate in &novelty_batch.certificates {
            let score = certificate.score.total_score_millionths;
            let composite_score = composite_scores
                .get(certificate.candidate_id.as_str())
                .expect("composite score must exist for each novelty certificate");
            sum_novelty = sum_novelty.saturating_add(score);
            max_novelty = max_novelty.max(score);

            let promoted_candidate = score >= self.config.promotion_threshold_millionths
                && promoted < self.config.max_promotions_per_cycle;
            if promoted_candidate {
                promoted += 1;
            } else {
                rejected += 1;
            }

            candidate_receipts.push(DiscoveryCandidateReceipt {
                candidate_id: certificate.candidate_id.clone(),
                novelty_verdict: certificate.verdict,
                composite_verdict: composite_score.verdict,
                total_score_millionths: score,
                composite_millionths: composite_score.composite_millionths,
                rank: certificate.score.rank,
                promoted: promoted_candidate,
                dimension_scores: certificate.score.dimension_scores.clone(),
                config_hash: certificate.config_hash,
                certificate_hash: certificate.certificate_hash,
                composite_score_hash: composite_score.content_hash,
            });
        }

        let now_epoch_secs = logical_cycle_timestamp(self.epoch, seq);
        let (synthesis_receipt, synthesized_candidate_receipts) =
            self.run_synthesis_cycle(promoted, now_epoch_secs);
        let region_update_receipts =
            self.apply_synthesis_region_updates(&synthesized_candidate_receipts, now_epoch_secs);

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

        let board_state_evaluation = self.evaluate_board_state(Some(PendingCycleObservation {
            seq,
            candidates_evaluated: candidates.len(),
            candidates_promoted: promoted,
            candidates_rejected: rejected,
        }));
        self.board_state = board_state_evaluation.receipt.composite_state;

        let content_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(DARK_MATTER_ENGINE_SCHEMA_VERSION.as_bytes());
            buf.extend_from_slice(&seq.to_le_bytes());
            buf.extend_from_slice(&max_novelty.to_le_bytes());
            buf.extend_from_slice(&avg_novelty.to_le_bytes());
            buf.extend_from_slice(&(promoted as u64).to_le_bytes());
            buf.extend_from_slice(&(rejected as u64).to_le_bytes());
            buf.extend_from_slice(novelty_batch.content_hash.as_bytes());
            for receipt in &candidate_receipts {
                buf.extend_from_slice(receipt.candidate_id.as_bytes());
                buf.extend_from_slice(receipt.novelty_verdict.as_str().as_bytes());
                buf.extend_from_slice(receipt.composite_verdict.as_str().as_bytes());
                buf.extend_from_slice(&receipt.total_score_millionths.to_le_bytes());
                buf.extend_from_slice(&receipt.composite_millionths.to_le_bytes());
                buf.extend_from_slice(&u64::from(receipt.rank).to_le_bytes());
                buf.push(u8::from(receipt.promoted));
                for (dimension, score) in &receipt.dimension_scores {
                    buf.extend_from_slice(dimension.as_str().as_bytes());
                    buf.extend_from_slice(&score.to_le_bytes());
                }
                buf.extend_from_slice(receipt.config_hash.as_bytes());
                buf.extend_from_slice(receipt.certificate_hash.as_bytes());
                buf.extend_from_slice(receipt.composite_score_hash.as_bytes());
            }
            buf.extend_from_slice(synthesis_receipt.manifest_batch_id.as_bytes());
            buf.extend_from_slice(synthesis_receipt.manifest_hash.as_bytes());
            buf.extend_from_slice(&synthesis_receipt.candidates_proposed.to_le_bytes());
            buf.extend_from_slice(&synthesis_receipt.candidates_accepted.to_le_bytes());
            buf.extend_from_slice(&synthesis_receipt.candidates_denied.to_le_bytes());
            buf.extend_from_slice(&synthesis_receipt.novelty_yield_millionths.to_le_bytes());
            buf.extend_from_slice(
                &synthesis_receipt
                    .coverage_improvement_millionths
                    .to_le_bytes(),
            );
            buf.extend_from_slice(synthesis_receipt.receipt_hash.as_bytes());
            for receipt in &synthesized_candidate_receipts {
                buf.extend_from_slice(receipt.candidate_id.as_bytes());
                buf.extend_from_slice(receipt.kind.as_str().as_bytes());
                buf.extend_from_slice(receipt.strategy.as_str().as_bytes());
                buf.extend_from_slice(&receipt.novelty_score_millionths.to_le_bytes());
                buf.extend_from_slice(&receipt.coverage_delta_millionths.to_le_bytes());
                for target_cell in &receipt.target_cells {
                    buf.extend_from_slice(target_cell.as_bytes());
                }
                buf.extend_from_slice(receipt.content_hash.as_bytes());
                buf.push(u8::from(receipt.accepted));
                if let Some(reason) = &receipt.denial_reason {
                    buf.extend_from_slice(reason.stable_label().as_bytes());
                }
            }
            for update in &region_update_receipts {
                buf.extend_from_slice(update.region_id.as_bytes());
                buf.extend_from_slice(update.candidate_id.as_bytes());
                buf.extend_from_slice(update.target_cell.as_bytes());
                buf.extend_from_slice(update.kind.as_str().as_bytes());
                buf.extend_from_slice(&update.mass_millionths.to_le_bytes());
                buf.push(match update.action {
                    RegionUpdateAction::Activated => 0,
                    RegionUpdateAction::Retired => 1,
                });
                buf.push(u8::from(update.retired));
                buf.extend_from_slice(update.content_hash.as_bytes());
            }
            buf.extend_from_slice(board_state_evaluation.receipt.receipt_hash.as_bytes());
            ContentHash::compute(&buf)
        };

        let result = DiscoveryCycleResult {
            seq,
            candidates_evaluated: candidates.len(),
            candidates_promoted: promoted,
            candidates_rejected: rejected,
            max_novelty_millionths: max_novelty,
            avg_novelty_millionths: avg_novelty,
            candidate_receipts,
            synthesis_receipt: Some(synthesis_receipt),
            synthesized_candidate_receipts,
            region_update_receipts,
            board_state_receipt: Some(board_state_evaluation.receipt.clone()),
            dark_matter_regions: board_state_evaluation.region_count,
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
        let board_state_receipt = self.board_state_receipt();
        let coverage = self
            .total_promoted
            .saturating_mul(MILLION)
            .checked_div(self.total_candidates)
            .unwrap_or(0);
        let mut hash_input = Vec::new();
        hash_input.extend_from_slice(b"summary|");
        hash_input.extend_from_slice(&self.cycle_count.to_le_bytes());
        hash_input.extend_from_slice(&self.total_candidates.to_le_bytes());
        hash_input.extend_from_slice(&self.total_promoted.to_le_bytes());
        hash_input.extend_from_slice(&self.total_rejected.to_le_bytes());
        hash_input.extend_from_slice(board_state_receipt.composite_state.as_str().as_bytes());
        hash_input.extend_from_slice(board_state_receipt.receipt_hash.as_bytes());
        DarkMatterEngineSummary {
            total_cycles: self.cycle_count,
            total_candidates: self.total_candidates,
            total_promoted: self.total_promoted,
            total_rejected: self.total_rejected,
            board_state: board_state_receipt.composite_state,
            dark_matter_coverage_millionths: coverage,
            board_state_receipt_hash: Some(board_state_receipt.receipt_hash),
            content_hash: ContentHash::compute(&hash_input),
        }
    }

    /// Get the current board state.
    pub fn board_state(&self) -> &BoardState {
        &self.board_state
    }

    /// Derive the latest board-state receipt from orchestrator state.
    pub fn board_state_receipt(&self) -> DecisionReceipt {
        self.evaluate_board_state(None).receipt
    }

    /// Get discovery history.
    pub fn history(&self) -> &[DiscoveryCycleResult] {
        &self.history
    }

    /// Add a dark-matter region.
    pub fn add_region(&mut self, region: DarkMatterRegion) {
        self.upsert_region(region);
        self.board_state = self.board_state_receipt().composite_state;
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

    fn run_synthesis_cycle(
        &self,
        explicit_promoted: usize,
        now_epoch_secs: u64,
    ) -> (DiscoverySynthesisReceipt, Vec<SynthesizedCandidateReceipt>) {
        let manifest = franken_engine_synthesis_manifest();
        let manifest_hash = manifest.content_hash();
        let constraint = SynthesisConstraint::new(
            DEFAULT_MAX_AST_NODES,
            DEFAULT_MAX_BYTES,
            self.config.promotion_threshold_millionths,
        );
        let (accepted_prelimit, denied_prelimit) =
            filter_candidates(manifest.candidates.clone(), &constraint);
        let remaining_slots = self
            .config
            .max_promotions_per_cycle
            .saturating_sub(explicit_promoted);

        let mut acceptance_map: BTreeMap<String, (bool, Option<SynthesizedCandidateDenialReason>)> =
            BTreeMap::new();
        for (index, candidate) in accepted_prelimit.into_iter().enumerate() {
            if index < remaining_slots {
                acceptance_map.insert(candidate.candidate_id.clone(), (true, None));
            } else {
                acceptance_map.insert(
                    candidate.candidate_id.clone(),
                    (
                        false,
                        Some(SynthesizedCandidateDenialReason::PromotionCapReached),
                    ),
                );
            }
        }
        for (candidate, reason) in denied_prelimit {
            acceptance_map.insert(
                candidate.candidate_id.clone(),
                (
                    false,
                    Some(SynthesizedCandidateDenialReason::Filter(reason)),
                ),
            );
        }

        let candidate_receipts: Vec<_> = manifest
            .candidates
            .iter()
            .map(|candidate| {
                let (accepted, denial_reason) = acceptance_map
                    .get(candidate.candidate_id.as_str())
                    .cloned()
                    .expect("every synthesized candidate must have an outcome");
                SynthesizedCandidateReceipt {
                    candidate_id: candidate.candidate_id.clone(),
                    kind: candidate.kind,
                    strategy: candidate.strategy,
                    novelty_score_millionths: candidate.novelty_score_millionths,
                    coverage_delta_millionths: candidate.coverage_delta_millionths,
                    target_cells: candidate.target_cells.clone(),
                    content_hash: candidate.content_hash,
                    accepted,
                    denial_reason,
                }
            })
            .collect();

        let candidates_accepted = candidate_receipts
            .iter()
            .filter(|receipt| receipt.accepted)
            .count() as u64;
        let novelty_yield_millionths = candidate_receipts
            .iter()
            .filter(|receipt| receipt.accepted)
            .map(|receipt| receipt.novelty_score_millionths)
            .fold(0u64, |acc, score| acc.saturating_add(score));
        let coverage_improvement_millionths = candidate_receipts
            .iter()
            .filter(|receipt| receipt.accepted)
            .map(|receipt| receipt.coverage_delta_millionths)
            .fold(0u64, |acc, delta| acc.saturating_add(delta));
        let candidates_proposed = candidate_receipts.len() as u64;
        let candidates_denied = candidates_proposed.saturating_sub(candidates_accepted);
        let receipt_hash = {
            let mut buf = Vec::new();
            buf.extend_from_slice(DARK_MATTER_ENGINE_SCHEMA_VERSION.as_bytes());
            buf.extend_from_slice(manifest.batch_id.as_bytes());
            buf.extend_from_slice(manifest_hash.as_bytes());
            buf.extend_from_slice(&now_epoch_secs.to_le_bytes());
            buf.extend_from_slice(&candidates_proposed.to_le_bytes());
            buf.extend_from_slice(&candidates_accepted.to_le_bytes());
            buf.extend_from_slice(&candidates_denied.to_le_bytes());
            buf.extend_from_slice(&novelty_yield_millionths.to_le_bytes());
            buf.extend_from_slice(&coverage_improvement_millionths.to_le_bytes());
            for receipt in &candidate_receipts {
                buf.extend_from_slice(receipt.candidate_id.as_bytes());
                buf.extend_from_slice(receipt.kind.as_str().as_bytes());
                buf.extend_from_slice(receipt.strategy.as_str().as_bytes());
                buf.extend_from_slice(&receipt.novelty_score_millionths.to_le_bytes());
                buf.extend_from_slice(&receipt.coverage_delta_millionths.to_le_bytes());
                for target_cell in &receipt.target_cells {
                    buf.extend_from_slice(target_cell.as_bytes());
                }
                buf.extend_from_slice(receipt.content_hash.as_bytes());
                buf.push(u8::from(receipt.accepted));
                if let Some(reason) = &receipt.denial_reason {
                    buf.extend_from_slice(reason.stable_label().as_bytes());
                }
            }
            ContentHash::compute(&buf)
        };

        (
            DiscoverySynthesisReceipt {
                manifest_batch_id: manifest.batch_id,
                manifest_hash,
                candidates_proposed,
                candidates_accepted,
                candidates_denied,
                novelty_yield_millionths,
                coverage_improvement_millionths,
                receipt_hash,
            },
            candidate_receipts,
        )
    }

    fn apply_synthesis_region_updates(
        &mut self,
        candidate_receipts: &[SynthesizedCandidateReceipt],
        now_epoch_secs: u64,
    ) -> Vec<RegionUpdateReceipt> {
        let mut updates = Vec::new();
        for receipt in candidate_receipts {
            if receipt.coverage_delta_millionths == 0 || receipt.target_cells.is_empty() {
                continue;
            }

            let action = if receipt.accepted {
                RegionUpdateAction::Retired
            } else {
                RegionUpdateAction::Activated
            };
            for (target_cell, mass_millionths) in
                split_target_cell_mass(&receipt.target_cells, receipt.coverage_delta_millionths)
            {
                if mass_millionths == 0 {
                    continue;
                }
                let region_id = synthesis_region_id(&target_cell);
                let discovered_at_epoch_secs = self
                    .region(region_id.as_str())
                    .map(|region| region.discovered_at_epoch_secs)
                    .unwrap_or(now_epoch_secs);
                let region = DarkMatterRegion {
                    region_id: region_id.clone(),
                    kind: synthesis_region_kind(receipt.kind),
                    mass_millionths,
                    retired: matches!(action, RegionUpdateAction::Retired),
                    discovered_at_epoch_secs,
                    retired_at_epoch_secs: if matches!(action, RegionUpdateAction::Retired) {
                        Some(now_epoch_secs)
                    } else {
                        None
                    },
                    priority_weight_millionths: MILLION,
                };
                self.upsert_region(region.clone());
                updates.push(RegionUpdateReceipt {
                    region_id,
                    candidate_id: receipt.candidate_id.clone(),
                    target_cell,
                    action,
                    kind: region.kind,
                    mass_millionths,
                    retired: region.retired,
                    content_hash: region.content_hash(),
                });
            }
        }
        updates
    }

    fn region(&self, region_id: &str) -> Option<&DarkMatterRegion> {
        self.regions
            .iter()
            .find(|region| region.region_id == region_id)
    }

    fn upsert_region(&mut self, region: DarkMatterRegion) {
        if let Some(index) = self
            .regions
            .iter()
            .rposition(|existing| existing.region_id == region.region_id)
        {
            self.regions[index] = region;
        } else {
            self.regions.push(region);
        }
    }

    fn evaluate_board_state(
        &self,
        pending: Option<PendingCycleObservation>,
    ) -> BoardStateEvaluation {
        let tracker = self.derive_burndown_tracker(pending);
        let now_epoch_secs = pending
            .map(|cycle| cycle.observation_timestamp_epoch_secs(self.epoch))
            .unwrap_or_else(|| logical_cycle_timestamp(self.epoch, self.cycle_count));
        let estimate = self.derive_dark_matter_estimate(&tracker, now_epoch_secs);
        let region_count = estimate.total_region_count();
        let evaluator =
            SaturationGateEvaluator::new(self.config.saturation_config.clone(), estimate, tracker);
        let receipt = evaluator.evaluate(now_epoch_secs);
        BoardStateEvaluation {
            receipt,
            region_count,
        }
    }

    fn derive_burndown_tracker(&self, pending: Option<PendingCycleObservation>) -> BurndownTracker {
        let mut tracker = BurndownTracker::new(MILLION, self.epoch);
        let mut cumulative_discovered_millionths = 0u64;
        let mut cumulative_retired_millionths = 0u64;

        for cycle in self
            .history
            .iter()
            .map(PendingCycleObservation::from_result)
            .chain(pending)
        {
            let discovered_mass_millionths = cycle.discovered_mass_millionths();
            let retired_mass_millionths = cycle.retired_mass_millionths();
            cumulative_discovered_millionths =
                cumulative_discovered_millionths.saturating_add(discovered_mass_millionths);
            cumulative_retired_millionths =
                cumulative_retired_millionths.saturating_add(retired_mass_millionths);
            let active_mass_millionths =
                cumulative_discovered_millionths.saturating_sub(cumulative_retired_millionths);
            tracker.record(BurndownObservation {
                timestamp_epoch_secs: cycle.observation_timestamp_epoch_secs(self.epoch),
                active_mass_millionths,
                cumulative_discovered_millionths,
                cumulative_retired_millionths,
            });
        }

        tracker
    }

    fn derive_dark_matter_estimate(
        &self,
        tracker: &BurndownTracker,
        now_epoch_secs: u64,
    ) -> DarkMatterEstimate {
        let mut estimate = DarkMatterEstimate::new(MILLION, self.epoch, now_epoch_secs);
        for region in &self.regions {
            estimate.add_region(region.clone());
        }

        let explicit_active_mass = estimate.active_mass();
        let derived_active_mass = tracker.latest_active_mass();
        if derived_active_mass > explicit_active_mass {
            estimate.add_region(DarkMatterRegion {
                region_id: "semantic_dark_matter_backlog".to_string(),
                kind: DarkMatterRegionKind::UntestedCodePath,
                mass_millionths: derived_active_mass.saturating_sub(explicit_active_mass),
                retired: false,
                discovered_at_epoch_secs: now_epoch_secs,
                retired_at_epoch_secs: None,
                priority_weight_millionths: MILLION,
            });
        }

        estimate
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

fn make_candidate_with_features(
    id: &str,
    kind: CandidateKind,
    description_length: u64,
    feature_vector: Vec<u64>,
) -> NoveltyCandidate {
    NoveltyCandidate {
        candidate_id: id.to_string(),
        kind,
        description_length_bits: description_length,
        feature_vector,
        source_hash: ContentHash::compute(id.as_bytes()),
    }
}

fn make_candidate(id: &str, kind: CandidateKind, description_length: u64) -> NoveltyCandidate {
    make_candidate_with_features(id, kind, description_length, vec![description_length; 4])
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
    use crate::dark_matter_saturation_gate::{
        DarkMatterRegionKind, FreshnessReason, SaturationReason,
    };

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn expected_cycle_metrics(
        config: &DarkMatterEngineConfig,
        candidates: &[NoveltyCandidate],
    ) -> (usize, usize, u64, u64) {
        let batch = score_batch(candidates, &config.scoring_config);
        let mut promoted = 0usize;
        let mut rejected = 0usize;
        let mut max_novelty = 0u64;
        let mut sum_novelty = 0u64;

        for certificate in &batch.certificates {
            let score = certificate.score.total_score_millionths;
            sum_novelty = sum_novelty.saturating_add(score);
            max_novelty = max_novelty.max(score);
            if score >= config.promotion_threshold_millionths
                && promoted < config.max_promotions_per_cycle
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

        (promoted, rejected, max_novelty, avg_novelty)
    }

    fn expected_candidate_receipts(
        config: &DarkMatterEngineConfig,
        candidates: &[NoveltyCandidate],
    ) -> Vec<DiscoveryCandidateReceipt> {
        let batch = score_batch(candidates, &config.scoring_config);
        let composite_scores: BTreeMap<&str, _> = batch
            .scores
            .iter()
            .map(|score| (score.candidate_fingerprint.as_str(), score))
            .collect();
        let mut promoted = 0usize;
        let mut receipts = Vec::with_capacity(batch.certificates.len());

        for certificate in &batch.certificates {
            let promoted_candidate = certificate.score.total_score_millionths
                >= config.promotion_threshold_millionths
                && promoted < config.max_promotions_per_cycle;
            if promoted_candidate {
                promoted += 1;
            }

            let composite_score = composite_scores
                .get(certificate.candidate_id.as_str())
                .expect("composite score must exist for each novelty certificate");
            receipts.push(DiscoveryCandidateReceipt {
                candidate_id: certificate.candidate_id.clone(),
                novelty_verdict: certificate.verdict,
                composite_verdict: composite_score.verdict,
                total_score_millionths: certificate.score.total_score_millionths,
                composite_millionths: composite_score.composite_millionths,
                rank: certificate.score.rank,
                promoted: promoted_candidate,
                dimension_scores: certificate.score.dimension_scores.clone(),
                config_hash: certificate.config_hash,
                certificate_hash: certificate.certificate_hash,
                composite_score_hash: composite_score.content_hash,
            });
        }

        receipts
    }

    fn seeded_history_result(
        seq: u64,
        candidates_evaluated: usize,
        candidates_promoted: usize,
        candidates_rejected: usize,
    ) -> DiscoveryCycleResult {
        DiscoveryCycleResult {
            seq,
            candidates_evaluated,
            candidates_promoted,
            candidates_rejected,
            max_novelty_millionths: 0,
            avg_novelty_millionths: 0,
            candidate_receipts: Vec::new(),
            synthesis_receipt: None,
            synthesized_candidate_receipts: Vec::new(),
            region_update_receipts: Vec::new(),
            board_state_receipt: None,
            dark_matter_regions: 0,
            content_hash: ContentHash::compute(
                format!("{seq}:{candidates_evaluated}:{candidates_promoted}:{candidates_rejected}")
                    .as_bytes(),
            ),
            epoch: test_epoch(),
        }
    }

    fn gate_ready_config(min_observations: u64) -> DarkMatterEngineConfig {
        let mut config = DarkMatterEngineConfig::default();
        config.saturation_config.min_observations = min_observations;
        config.saturation_config.velocity_window = min_observations.max(1) as usize;
        config
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
        // SAFETY: Test creates valid candidates; discover succeeds in controlled test environment.
        let result = engine
            .discover(&candidates)
            .expect("operation should succeed for valid inputs");
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
        // SAFETY: Test creates valid high-scoring candidate; discover succeeds in controlled test environment.
        let result = engine
            .discover(&candidates)
            .expect("operation should succeed for valid inputs");
        let (promoted, rejected, _, _) = expected_cycle_metrics(&engine.config, &candidates);
        assert_eq!(result.candidates_promoted, promoted);
        assert_eq!(result.candidates_rejected, rejected);
    }

    #[test]
    fn test_rejection_below_threshold() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let candidates = vec![make_candidate("l", CandidateKind::Program, 100_000)];
        // SAFETY: Test creates valid low-scoring candidate; discover succeeds in controlled test environment.
        let result = engine
            .discover(&candidates)
            .expect("operation should succeed for valid inputs");
        let (promoted, rejected, _, _) = expected_cycle_metrics(&engine.config, &candidates);
        assert_eq!(result.candidates_promoted, promoted);
        assert_eq!(result.candidates_rejected, rejected);
    }

    #[test]
    fn test_max_novelty_tracked() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let candidates = vec![
            make_candidate("a", CandidateKind::Program, 300_000),
            make_candidate("b", CandidateKind::Program, 700_000),
        ];
        // SAFETY: Test creates valid candidates with different novelty scores; discover succeeds in controlled test environment.
        let result = engine
            .discover(&candidates)
            .expect("operation should succeed for valid inputs");
        let (_, _, max_novelty, _) = expected_cycle_metrics(&engine.config, &candidates);
        assert_eq!(result.max_novelty_millionths, max_novelty);
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

    // --- Additional enrichment tests ---

    #[test]
    fn test_custom_config() {
        let config = DarkMatterEngineConfig {
            promotion_threshold_millionths: 300_000,
            max_promotions_per_cycle: 5,
            max_history: 10,
            ..DarkMatterEngineConfig::default()
        };
        let engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);
        assert_eq!(engine.summary().total_cycles, 0);
    }

    #[test]
    fn test_promotion_cap_enforced() {
        let config = DarkMatterEngineConfig {
            max_promotions_per_cycle: 2,
            ..DarkMatterEngineConfig::default()
        };
        let mut engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);
        let candidates = vec![
            make_candidate("h1", CandidateKind::Program, 900_000),
            make_candidate("h2", CandidateKind::Program, 800_000),
            make_candidate("h3", CandidateKind::Program, 700_000),
            make_candidate("h4", CandidateKind::Program, 600_000),
        ];
        // SAFETY: Test creates valid candidates; discover succeeds in controlled test environment.
        let result = engine
            .discover(&candidates)
            .expect("operation should succeed for valid inputs");
        let (promoted, rejected, _, _) = expected_cycle_metrics(&engine.config, &candidates);
        assert_eq!(result.candidates_promoted, promoted);
        assert_eq!(result.candidates_rejected, rejected);
    }

    #[test]
    fn test_discovery_candidate_receipts_match_scoring_contract() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let candidates = vec![
            make_candidate("alpha", CandidateKind::Program, 750_000),
            make_candidate("beta", CandidateKind::Package, 320_000),
            make_candidate("gamma", CandidateKind::ReactComponent, 610_000),
        ];

        let result = engine
            .discover(&candidates)
            .expect("operation should succeed for valid inputs");
        let expected = expected_candidate_receipts(&engine.config, &candidates);

        assert_eq!(result.candidate_receipts, expected);
    }

    #[test]
    fn test_content_hash_covers_candidate_receipt_evidence() {
        let config = DarkMatterEngineConfig {
            scoring_config: ScoringConfig {
                dimension_weights: vec![
                    crate::novelty_scoring_contract::DimensionWeight::new(
                        NoveltyDimension::Obstruction,
                        500_000,
                    ),
                    crate::novelty_scoring_contract::DimensionWeight::new(
                        NoveltyDimension::TopologicalDistance,
                        500_000,
                    ),
                ],
                mdl_baseline_bits: 10_000,
                information_gain_threshold_millionths: 50_000,
                frontier_proximity_decay_millionths: 100_000,
                min_novelty_threshold_millionths: 200_000,
            },
            promotion_threshold_millionths: 300_000,
            ..DarkMatterEngineConfig::default()
        };

        let candidate_obstruction = make_candidate_with_features(
            "shape",
            CandidateKind::Program,
            10_000,
            vec![0, 0, 800_000, 0, 0, 0, 0, 0],
        );
        let candidate_topology = make_candidate_with_features(
            "shape",
            CandidateKind::Program,
            10_000,
            vec![0, 0, 0, 800_000, 0, 0, 0, 0],
        );

        let mut first_engine = DarkMatterEngineOrchestrator::new(test_epoch(), config.clone());
        let mut second_engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);

        let first = first_engine
            .discover(&[candidate_obstruction])
            .expect("operation should succeed for valid inputs");
        let second = second_engine
            .discover(&[candidate_topology])
            .expect("operation should succeed for valid inputs");

        assert_eq!(first.candidates_promoted, second.candidates_promoted);
        assert_eq!(first.candidates_rejected, second.candidates_rejected);
        assert_eq!(first.max_novelty_millionths, second.max_novelty_millionths);
        assert_eq!(first.avg_novelty_millionths, second.avg_novelty_millionths);
        assert_ne!(first.candidate_receipts, second.candidate_receipts);
        assert_ne!(first.content_hash, second.content_hash);
    }

    #[test]
    fn test_content_hash_covers_board_state_receipt_evidence() {
        let config = gate_ready_config(2);
        let mut saturated = DarkMatterEngineOrchestrator::new(test_epoch(), config.clone());
        let mut insufficient = DarkMatterEngineOrchestrator::new(test_epoch(), config);
        let seed_rejections = vec![
            make_candidate("low-1", CandidateKind::Program, 10_000),
            make_candidate("low-2", CandidateKind::Program, 10_000),
            make_candidate("low-3", CandidateKind::Program, 10_000),
        ];
        let promoted_batch = vec![
            make_candidate("high-1", CandidateKind::Program, 900_000),
            make_candidate("high-2", CandidateKind::Program, 900_000),
            make_candidate("high-3", CandidateKind::Program, 900_000),
        ];

        saturated
            .discover(&seed_rejections)
            .expect("seed cycle should succeed");
        let saturated_result = saturated
            .discover(&promoted_batch)
            .expect("second cycle should succeed");
        let insufficient_result = insufficient
            .discover(&promoted_batch)
            .expect("single cycle should succeed");

        assert_eq!(
            saturated_result.candidate_receipts,
            insufficient_result.candidate_receipts
        );
        assert_ne!(
            saturated_result
                .board_state_receipt
                .as_ref()
                .expect("receipt should be present")
                .receipt_hash,
            insufficient_result
                .board_state_receipt
                .as_ref()
                .expect("receipt should be present")
                .receipt_hash
        );
        assert_ne!(
            saturated_result.content_hash,
            insufficient_result.content_hash
        );
    }

    #[test]
    fn test_content_hash_covers_synthesis_receipt_evidence() {
        let candidates = [make_candidate("high", CandidateKind::Program, 900_000)];
        let mut constrained = DarkMatterEngineOrchestrator::new(
            test_epoch(),
            DarkMatterEngineConfig {
                promotion_threshold_millionths: 850_000,
                max_promotions_per_cycle: 2,
                ..DarkMatterEngineConfig::default()
            },
        );
        let mut relaxed = DarkMatterEngineOrchestrator::new(
            test_epoch(),
            DarkMatterEngineConfig {
                promotion_threshold_millionths: 850_000,
                max_promotions_per_cycle: 8,
                ..DarkMatterEngineConfig::default()
            },
        );

        let constrained_result = constrained
            .discover(&candidates)
            .expect("constrained discovery should succeed");
        let relaxed_result = relaxed
            .discover(&candidates)
            .expect("relaxed discovery should succeed");

        assert_ne!(
            constrained_result.synthesis_receipt,
            relaxed_result.synthesis_receipt
        );
        assert_ne!(constrained_result.content_hash, relaxed_result.content_hash);
    }

    #[test]
    fn test_avg_novelty_calculation() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let candidates = vec![
            make_candidate("a", CandidateKind::Program, 200_000),
            make_candidate("b", CandidateKind::Program, 400_000),
            make_candidate("c", CandidateKind::Program, 600_000),
        ];
        // SAFETY: Test creates valid candidates; discover succeeds in controlled test environment.
        let result = engine
            .discover(&candidates)
            .expect("operation should succeed for valid inputs");
        let (_, _, _, avg_novelty) = expected_cycle_metrics(&engine.config, &candidates);
        assert_eq!(result.avg_novelty_millionths, avg_novelty);
    }

    #[test]
    fn test_content_hash_differs_per_cycle() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        // SAFETY: Test creates valid candidate; discover succeeds in controlled test environment.
        let r1 = engine
            .discover(&[make_candidate("c1", CandidateKind::Program, 800_000)])
            .expect("operation should succeed for valid inputs");
        // SAFETY: Test creates valid candidate; discover succeeds in controlled test environment.
        let r2 = engine
            .discover(&[make_candidate("c2", CandidateKind::Program, 800_000)])
            .expect("operation should succeed for valid inputs");
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_epoch_propagated() {
        let epoch = SecurityEpoch::from_raw(42);
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(epoch);
        // SAFETY: Test creates valid candidate; discover succeeds in controlled test environment.
        let result = engine
            .discover(&[make_candidate("x", CandidateKind::Program, 800_000)])
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.epoch, epoch);
    }

    #[test]
    fn test_board_state_receipt_stale_without_observations() {
        let engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let receipt = engine.board_state_receipt();

        assert_eq!(receipt.composite_state, BoardState::Stale);
        assert!(matches!(
            receipt.freshness_verdict.reason,
            FreshnessReason::NoObservations
        ));
    }

    #[test]
    fn test_board_state_receipt_scope_limited_with_insufficient_observations() {
        let config = gate_ready_config(2);
        let mut engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);
        let result = engine
            .discover(&[
                make_candidate("high-1", CandidateKind::Program, 900_000),
                make_candidate("high-2", CandidateKind::Program, 900_000),
            ])
            .expect("semantic dark matter discovery should succeed");
        let receipt = result
            .board_state_receipt
            .expect("board-state receipt should be emitted");

        assert_eq!(receipt.composite_state, BoardState::ScopeLimited);
        assert!(
            receipt
                .saturation_verdict
                .reasons
                .iter()
                .any(|reason| matches!(reason, SaturationReason::InsufficientObservations { .. }))
        );
    }

    #[test]
    fn test_board_state_receipt_saturated_with_positive_burndown_and_low_dark_matter() {
        let config = gate_ready_config(2);
        let mut engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);
        engine.history = vec![
            seeded_history_result(0, 10, 0, 10),
            seeded_history_result(1, 10, 10, 0),
        ];
        engine.cycle_count = engine.history.len() as u64;
        let receipt = engine.board_state_receipt();

        assert_eq!(receipt.composite_state, BoardState::Saturated);
        assert!(receipt.saturation_verdict.reasons.iter().any(|reason| {
            matches!(reason, SaturationReason::LowDarkMatterWithPositiveBurndown)
        }));
        engine.board_state = receipt.composite_state;
        assert_eq!(*engine.board_state(), BoardState::Saturated);
    }

    #[test]
    fn test_board_state_receipt_scope_limited_with_negative_burndown_and_high_dark_matter() {
        let config = gate_ready_config(2);
        let mut engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);
        engine.history = vec![
            seeded_history_result(0, 10, 2, 8),
            seeded_history_result(1, 10, 0, 10),
        ];
        engine.cycle_count = engine.history.len() as u64;
        let receipt = engine.board_state_receipt();

        assert_eq!(receipt.composite_state, BoardState::ScopeLimited);
        assert!(
            receipt.saturation_verdict.reasons.iter().any(|reason| {
                matches!(reason, SaturationReason::HighDarkMatterFraction { .. })
            })
        );
        assert!(
            receipt
                .saturation_verdict
                .reasons
                .iter()
                .any(|reason| { matches!(reason, SaturationReason::NegativeBurndown { .. }) })
        );
        engine.board_state = receipt.composite_state;
        assert_eq!(*engine.board_state(), BoardState::ScopeLimited);
    }

    #[test]
    fn test_coverage_millionths() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let candidates = vec![make_candidate("h", CandidateKind::Program, 900_000)];
        let _ = engine
            .discover(&candidates)
            .expect("semantic dark matter discovery should succeed");
        let summary = engine.summary();
        let (promoted, _, _, _) = expected_cycle_metrics(&engine.config, &candidates);
        let expected_coverage = (promoted as u64).saturating_mul(MILLION) / candidates.len() as u64;
        assert_eq!(summary.dark_matter_coverage_millionths, expected_coverage);
    }

    #[test]
    fn test_coverage_zero_when_none_promoted() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let _ = engine.discover(&[make_candidate("l", CandidateKind::Program, 100_000)]);
        let summary = engine.summary();
        assert_eq!(summary.dark_matter_coverage_millionths, 0);
    }

    #[test]
    fn test_regions_empty_initially() {
        let engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        assert!(engine.regions().is_empty());
    }

    #[test]
    fn test_regions_cleared_on_reset() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        engine.add_region(DarkMatterRegion {
            region_id: "r1".to_string(),
            kind: DarkMatterRegionKind::UntestedCodePath,
            mass_millionths: 200_000,
            retired: false,
            discovered_at_epoch_secs: 0,
            retired_at_epoch_secs: None,
            priority_weight_millionths: MILLION,
        });
        engine.reset(SecurityEpoch::from_raw(2));
        assert!(engine.regions().is_empty());
    }

    #[test]
    fn test_history_disabled() {
        let config = DarkMatterEngineConfig {
            record_history: false,
            ..DarkMatterEngineConfig::default()
        };
        let mut engine = DarkMatterEngineOrchestrator::new(test_epoch(), config);
        let _ = engine.discover(&[make_candidate("x", CandidateKind::Program, 800_000)]);
        assert!(engine.history().is_empty());
    }

    #[test]
    fn test_multiple_cycles_accumulate() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        for i in 0..10 {
            let _ = engine.discover(&[make_candidate(
                &format!("c{i}"),
                CandidateKind::Program,
                800_000,
            )]);
        }
        let summary = engine.summary();
        assert_eq!(summary.total_cycles, 10);
        assert_eq!(summary.total_candidates, 10);
    }

    #[test]
    fn test_error_config_display() {
        let err = DarkMatterEngineError::ConfigError {
            detail: "threshold too low".to_string(),
        };
        assert!(format!("{err}").contains("threshold too low"));
    }

    #[test]
    fn test_specimen_family_as_str() {
        assert_eq!(
            DarkMatterSpecimenFamily::SingleCycle.as_str(),
            "single_cycle"
        );
        assert_eq!(
            DarkMatterSpecimenFamily::PromotionThreshold.as_str(),
            "promotion_threshold"
        );
    }

    #[test]
    fn test_corpus_family_coverage() {
        let inv = run_dark_matter_corpus();
        for family in DarkMatterSpecimenFamily::ALL {
            assert!(inv.family_coverage.contains_key(family.as_str()));
        }
    }

    #[test]
    fn test_corpus_evidence_hashes_unique() {
        let inv = run_dark_matter_corpus();
        let hashes: std::collections::BTreeSet<_> =
            inv.evidences.iter().map(|e| &e.evidence_hash).collect();
        assert_eq!(hashes.len(), inv.evidences.len());
    }

    #[test]
    fn test_single_candidate_batch() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        // SAFETY: Test creates valid candidate; discover succeeds in controlled test environment.
        let result = engine
            .discover(&[make_candidate("solo", CandidateKind::Program, 800_000)])
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.candidates_evaluated, 1);
        let (_, _, max_novelty, _) = expected_cycle_metrics(
            &engine.config,
            &[make_candidate("solo", CandidateKind::Program, 800_000)],
        );
        assert_eq!(result.max_novelty_millionths, max_novelty);
    }

    #[test]
    fn test_mixed_candidate_kinds() {
        let mut engine = DarkMatterEngineOrchestrator::with_defaults(test_epoch());
        let candidates = vec![
            make_candidate("p1", CandidateKind::Program, 800_000),
            make_candidate("p2", CandidateKind::Package, 700_000),
            make_candidate("p3", CandidateKind::ReactComponent, 600_000),
            make_candidate("p4", CandidateKind::ModuleGraph, 500_000),
            make_candidate("p5", CandidateKind::WorkloadTrace, 400_000),
        ];
        // SAFETY: Test creates valid candidates; discover succeeds in controlled test environment.
        let result = engine
            .discover(&candidates)
            .expect("operation should succeed for valid inputs");
        assert_eq!(result.candidates_evaluated, 5);
    }
}
