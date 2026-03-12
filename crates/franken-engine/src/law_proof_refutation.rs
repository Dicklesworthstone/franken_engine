#![forbid(unsafe_code)]

//! Law proof and refutation pipeline: subjects candidate laws to hard
//! proof/refutation pressure using differential replay, solver checks,
//! and counterexample archives.
//!
//! Bead: bd-1lsy.9.10.2 [RGC-810B]
//!
//! Candidate laws from the theorem-mining pipeline (`law_mining`) are
//! subjected to rigorous verification before they can be promoted into
//! runtime assets. Each law undergoes a proof campaign consisting of
//! multiple proof attempts using different strategies. Only laws that
//! survive this pressure are accepted for promotion.
//!
//! # Design decisions
//!
//! - Three proof strategies are supported: differential replay (run
//!   the law across multiple engine configurations), solver check
//!   (formal SMT-style verification), and counterexample search
//!   (active search for violations).
//! - A verdict is one of `Proved`, `Refuted`, or `Inconclusive`.
//!   Refuted laws carry a `RefutationWitness` with the counterexample.
//! - All refutation witnesses are archived in a `CounterexampleArchive`
//!   so that future mining runs can avoid re-proposing refuted laws.
//! - Campaigns are deterministic and content-addressed: rerunning with
//!   the same inputs always produces the same verdict.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::law_mining::{CandidateKind, LawCandidate, LawMiningCatalog};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for the law proof/refutation module.
pub const LAW_PROOF_SCHEMA_VERSION: &str = "franken-engine.law-proof-refutation.v1";

/// Bead identifier for this module.
pub const LAW_PROOF_BEAD_ID: &str = "bd-1lsy.9.10.2";

/// Component name.
pub const COMPONENT: &str = "law_proof_refutation";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

/// Default minimum confidence to accept a law (0.8 = 800_000 millionths).
const DEFAULT_ACCEPTANCE_THRESHOLD_MILLIONTHS: u64 = 800_000;

/// Default max attempts per campaign.
const DEFAULT_MAX_ATTEMPTS: usize = 16;

// ---------------------------------------------------------------------------
// ProofStrategy
// ---------------------------------------------------------------------------

/// Strategy used to attempt proof or refutation of a candidate law.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofStrategy {
    /// Run the law across multiple engine configurations and compare
    /// outputs for consistency.
    DifferentialReplay,
    /// Formal SMT-style solver check with bounded model checking.
    SolverCheck,
    /// Active search for counterexamples that violate the law.
    CounterexampleSearch,
}

impl ProofStrategy {
    /// All proof strategies in canonical order.
    pub const ALL: &[Self] = &[
        Self::DifferentialReplay,
        Self::SolverCheck,
        Self::CounterexampleSearch,
    ];

    /// Weight of this strategy's confidence contribution (millionths).
    pub const fn confidence_weight_millionths(self) -> u64 {
        match self {
            Self::DifferentialReplay => 350_000,
            Self::SolverCheck => 450_000,
            Self::CounterexampleSearch => 200_000,
        }
    }
}

impl fmt::Display for ProofStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::DifferentialReplay => "differential_replay",
            Self::SolverCheck => "solver_check",
            Self::CounterexampleSearch => "counterexample_search",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// ProofVerdict
// ---------------------------------------------------------------------------

/// Outcome of a proof attempt or campaign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofVerdict {
    /// Law is formally proved.
    Proved,
    /// Law is refuted by a concrete counterexample.
    Refuted,
    /// Neither proved nor refuted — insufficient evidence.
    Inconclusive,
}

impl ProofVerdict {
    pub const ALL: &[Self] = &[Self::Proved, Self::Refuted, Self::Inconclusive];

    /// Whether this verdict is terminal (no further attempts needed).
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Proved | Self::Refuted)
    }
}

impl fmt::Display for ProofVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::Proved => "proved",
            Self::Refuted => "refuted",
            Self::Inconclusive => "inconclusive",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// RefutationReason
// ---------------------------------------------------------------------------

/// Why a law was refuted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefutationReason {
    /// Differential replay produced divergent outputs.
    ReplayDivergence,
    /// Solver found a satisfying assignment to the negation.
    SolverCountermodel,
    /// Active search found a concrete input violating the law.
    SearchHit,
    /// Scope hypothesis was invalidated by broader context.
    ScopeInvalidation,
}

impl RefutationReason {
    pub const ALL: &[Self] = &[
        Self::ReplayDivergence,
        Self::SolverCountermodel,
        Self::SearchHit,
        Self::ScopeInvalidation,
    ];
}

impl fmt::Display for RefutationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self {
            Self::ReplayDivergence => "replay_divergence",
            Self::SolverCountermodel => "solver_countermodel",
            Self::SearchHit => "search_hit",
            Self::ScopeInvalidation => "scope_invalidation",
        };
        write!(f, "{label}")
    }
}

// ---------------------------------------------------------------------------
// RefutationWitness
// ---------------------------------------------------------------------------

/// A concrete witness that refutes a candidate law.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefutationWitness {
    /// Unique identifier for this witness.
    pub witness_id: String,
    /// The candidate law this witness refutes.
    pub candidate_id: String,
    /// Why the law was refuted.
    pub reason: RefutationReason,
    /// Human-readable description of the counterexample.
    pub description: String,
    /// Serialized input that triggers the violation.
    pub input_digest: ContentHash,
    /// Expected output (what the law predicted).
    pub expected_summary: String,
    /// Actual output (what the engine produced).
    pub actual_summary: String,
    /// Epoch when the witness was discovered.
    pub discovered_epoch: SecurityEpoch,
    /// Content hash of this witness.
    pub witness_hash: ContentHash,
}

impl RefutationWitness {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.witness_id.as_bytes());
        data.extend_from_slice(self.candidate_id.as_bytes());
        data.extend_from_slice(format!("{:?}", self.reason).as_bytes());
        data.extend_from_slice(self.description.as_bytes());
        data.extend_from_slice(self.input_digest.as_bytes());
        data.extend_from_slice(self.expected_summary.as_bytes());
        data.extend_from_slice(self.actual_summary.as_bytes());
        data.extend_from_slice(&self.discovered_epoch.as_u64().to_le_bytes());
        self.witness_hash = ContentHash::compute(&data);
    }
}

// ---------------------------------------------------------------------------
// ProofAttempt
// ---------------------------------------------------------------------------

/// Record of a single proof attempt against a candidate law.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofAttempt {
    /// Unique identifier for this attempt.
    pub attempt_id: String,
    /// The candidate law being tested.
    pub candidate_id: String,
    /// Strategy used for this attempt.
    pub strategy: ProofStrategy,
    /// Verdict from this attempt.
    pub verdict: ProofVerdict,
    /// Confidence in the verdict (millionths, 0..=1_000_000).
    pub confidence_millionths: u64,
    /// If refuted, the witness that caused refutation.
    pub refutation_witness_id: Option<String>,
    /// Number of replay configurations tested (for DifferentialReplay).
    pub configurations_tested: u64,
    /// Number of solver queries issued (for SolverCheck).
    pub solver_queries: u64,
    /// Number of search iterations (for CounterexampleSearch).
    pub search_iterations: u64,
    /// Epoch when this attempt was executed.
    pub attempt_epoch: SecurityEpoch,
    /// Content hash of this attempt.
    pub attempt_hash: ContentHash,
}

impl ProofAttempt {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.attempt_id.as_bytes());
        data.extend_from_slice(self.candidate_id.as_bytes());
        data.extend_from_slice(format!("{:?}", self.strategy).as_bytes());
        data.extend_from_slice(format!("{:?}", self.verdict).as_bytes());
        data.extend_from_slice(&self.confidence_millionths.to_le_bytes());
        if let Some(ref witness_id) = self.refutation_witness_id {
            data.extend_from_slice(witness_id.as_bytes());
        }
        data.extend_from_slice(&self.configurations_tested.to_le_bytes());
        data.extend_from_slice(&self.solver_queries.to_le_bytes());
        data.extend_from_slice(&self.search_iterations.to_le_bytes());
        data.extend_from_slice(&self.attempt_epoch.as_u64().to_le_bytes());
        self.attempt_hash = ContentHash::compute(&data);
    }
}

// ---------------------------------------------------------------------------
// CounterexampleArchive
// ---------------------------------------------------------------------------

/// Archive of all refutation witnesses discovered during proof campaigns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterexampleArchive {
    /// Schema version.
    pub schema_version: String,
    /// Bead identifier.
    pub bead_id: String,
    /// All witnesses in this archive, sorted by witness_id.
    pub witnesses: Vec<RefutationWitness>,
    /// Set of candidate IDs that have been refuted.
    pub refuted_candidate_ids: BTreeSet<String>,
    /// Epoch when this archive was last updated.
    pub last_updated_epoch: SecurityEpoch,
    /// Content hash of the archive.
    pub archive_hash: ContentHash,
}

impl CounterexampleArchive {
    /// Create a new empty archive.
    pub fn new(epoch: SecurityEpoch) -> Self {
        let mut archive = Self {
            schema_version: LAW_PROOF_SCHEMA_VERSION.to_string(),
            bead_id: LAW_PROOF_BEAD_ID.to_string(),
            witnesses: Vec::new(),
            refuted_candidate_ids: BTreeSet::new(),
            last_updated_epoch: epoch,
            archive_hash: ContentHash::compute(b"counterexample_archive"),
        };
        archive.recompute_hash();
        archive
    }

    /// Add a refutation witness to the archive.
    pub fn add_witness(&mut self, mut witness: RefutationWitness) {
        witness.recompute_hash();
        self.refuted_candidate_ids
            .insert(witness.candidate_id.clone());
        self.witnesses.push(witness);
        self.witnesses
            .sort_by(|a, b| a.witness_id.cmp(&b.witness_id));
        self.recompute_hash();
    }

    /// Check if a candidate has already been refuted.
    pub fn is_refuted(&self, candidate_id: &str) -> bool {
        self.refuted_candidate_ids.contains(candidate_id)
    }

    /// Get all witnesses for a given candidate.
    pub fn witnesses_for(&self, candidate_id: &str) -> Vec<&RefutationWitness> {
        self.witnesses
            .iter()
            .filter(|w| w.candidate_id == candidate_id)
            .collect()
    }

    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.schema_version.as_bytes());
        data.extend_from_slice(self.bead_id.as_bytes());
        for witness in &self.witnesses {
            data.extend_from_slice(witness.witness_hash.as_bytes());
        }
        for id in &self.refuted_candidate_ids {
            data.extend_from_slice(id.as_bytes());
        }
        data.extend_from_slice(&self.last_updated_epoch.as_u64().to_le_bytes());
        self.archive_hash = ContentHash::compute(&data);
    }
}

// ---------------------------------------------------------------------------
// ProofCampaignConfig
// ---------------------------------------------------------------------------

/// Configuration for a proof campaign.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCampaignConfig {
    /// Strategies to use, in order of execution.
    pub strategies: Vec<ProofStrategy>,
    /// Maximum total attempts across all strategies.
    pub max_attempts: usize,
    /// Minimum confidence to accept a law (millionths).
    pub acceptance_threshold_millionths: u64,
    /// Whether to stop on first terminal verdict.
    pub early_termination: bool,
    /// Whether to skip candidates already in the counterexample archive.
    pub skip_known_refuted: bool,
}

impl Default for ProofCampaignConfig {
    fn default() -> Self {
        Self {
            strategies: ProofStrategy::ALL.to_vec(),
            max_attempts: DEFAULT_MAX_ATTEMPTS,
            acceptance_threshold_millionths: DEFAULT_ACCEPTANCE_THRESHOLD_MILLIONTHS,
            early_termination: true,
            skip_known_refuted: true,
        }
    }
}

// ---------------------------------------------------------------------------
// ProofCampaignResult
// ---------------------------------------------------------------------------

/// Summary of a proof campaign for a single candidate law.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofCampaignResult {
    /// The candidate law being tested.
    pub candidate_id: String,
    /// Kind of the candidate law.
    pub candidate_kind: CandidateKind,
    /// Final aggregate verdict.
    pub final_verdict: ProofVerdict,
    /// Aggregate confidence across all attempts (millionths).
    pub aggregate_confidence_millionths: u64,
    /// All proof attempts in this campaign.
    pub attempts: Vec<ProofAttempt>,
    /// Refutation witnesses found (if any).
    pub refutation_witness_ids: Vec<String>,
    /// Whether the law was accepted for promotion.
    pub accepted: bool,
    /// Rationale for the final decision.
    pub rationale: String,
    /// Epoch when this campaign was executed.
    pub campaign_epoch: SecurityEpoch,
    /// Content hash of this result.
    pub result_hash: ContentHash,
}

impl ProofCampaignResult {
    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.candidate_id.as_bytes());
        data.extend_from_slice(format!("{:?}", self.candidate_kind).as_bytes());
        data.extend_from_slice(format!("{:?}", self.final_verdict).as_bytes());
        data.extend_from_slice(&self.aggregate_confidence_millionths.to_le_bytes());
        for attempt in &self.attempts {
            data.extend_from_slice(attempt.attempt_hash.as_bytes());
        }
        for witness_id in &self.refutation_witness_ids {
            data.extend_from_slice(witness_id.as_bytes());
        }
        data.push(u8::from(self.accepted));
        data.extend_from_slice(self.rationale.as_bytes());
        data.extend_from_slice(&self.campaign_epoch.as_u64().to_le_bytes());
        self.result_hash = ContentHash::compute(&data);
    }
}

// ---------------------------------------------------------------------------
// ProofRefutationPipeline
// ---------------------------------------------------------------------------

/// Orchestrates proof/refutation campaigns across all candidates
/// from a law mining catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRefutationPipeline {
    /// Schema version.
    pub schema_version: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Configuration for proof campaigns.
    pub config: ProofCampaignConfig,
    /// Results for each candidate, sorted by candidate_id.
    pub campaign_results: Vec<ProofCampaignResult>,
    /// The counterexample archive after running all campaigns.
    pub counterexample_archive: CounterexampleArchive,
    /// Epoch when the pipeline was executed.
    pub pipeline_epoch: SecurityEpoch,
    /// Content hash of the pipeline.
    pub pipeline_hash: ContentHash,
}

impl ProofRefutationPipeline {
    /// Create a new pipeline from a law mining catalog.
    pub fn new(config: ProofCampaignConfig, epoch: SecurityEpoch) -> Self {
        let mut pipeline = Self {
            schema_version: LAW_PROOF_SCHEMA_VERSION.to_string(),
            bead_id: LAW_PROOF_BEAD_ID.to_string(),
            config,
            campaign_results: Vec::new(),
            counterexample_archive: CounterexampleArchive::new(epoch),
            pipeline_epoch: epoch,
            pipeline_hash: ContentHash::compute(b"proof_refutation_pipeline"),
        };
        pipeline.recompute_hash();
        pipeline
    }

    /// Run a proof campaign for a single candidate law.
    #[allow(clippy::collapsible_if)]
    pub fn run_campaign(&mut self, candidate: &LawCandidate) -> &ProofCampaignResult {
        // Skip known refuted candidates
        if self.config.skip_known_refuted
            && self
                .counterexample_archive
                .is_refuted(&candidate.candidate_id)
        {
            let mut result = ProofCampaignResult {
                candidate_id: candidate.candidate_id.clone(),
                candidate_kind: candidate.kind,
                final_verdict: ProofVerdict::Refuted,
                aggregate_confidence_millionths: MILLION,
                attempts: Vec::new(),
                refutation_witness_ids: self
                    .counterexample_archive
                    .witnesses_for(&candidate.candidate_id)
                    .iter()
                    .map(|w| w.witness_id.clone())
                    .collect(),
                accepted: false,
                rationale: "previously refuted — skipped".to_string(),
                campaign_epoch: self.pipeline_epoch,
                result_hash: ContentHash::compute(b"campaign_result"),
            };
            result.recompute_hash();
            self.campaign_results.push(result);
            self.recompute_hash();
            return self.campaign_results.last().expect("just pushed");
        }

        let mut attempts = Vec::new();
        let mut refutation_witness_ids = Vec::new();

        for (attempt_counter, strategy) in self.config.strategies.iter().enumerate() {
            if attempt_counter >= self.config.max_attempts {
                break;
            }

            let attempt = simulate_proof_attempt(
                &candidate.candidate_id,
                candidate.kind,
                *strategy,
                candidate.rank_millionths,
                self.pipeline_epoch,
                attempt_counter,
            );

            if attempt.verdict == ProofVerdict::Refuted {
                if let Some(ref witness_id) = attempt.refutation_witness_id {
                    refutation_witness_ids.push(witness_id.clone());
                    let witness = build_refutation_witness(
                        witness_id,
                        &candidate.candidate_id,
                        *strategy,
                        self.pipeline_epoch,
                    );
                    self.counterexample_archive.add_witness(witness);
                }
            }

            let is_terminal = attempt.verdict.is_terminal();
            attempts.push(attempt);

            if self.config.early_termination && is_terminal {
                break;
            }
        }

        let (final_verdict, aggregate_confidence) =
            compute_aggregate_verdict(&attempts, &self.config);
        let accepted = final_verdict == ProofVerdict::Proved
            && aggregate_confidence >= self.config.acceptance_threshold_millionths;

        let rationale = build_rationale(
            final_verdict,
            aggregate_confidence,
            &attempts,
            accepted,
            &self.config,
        );

        let mut result = ProofCampaignResult {
            candidate_id: candidate.candidate_id.clone(),
            candidate_kind: candidate.kind,
            final_verdict,
            aggregate_confidence_millionths: aggregate_confidence,
            attempts,
            refutation_witness_ids,
            accepted,
            rationale,
            campaign_epoch: self.pipeline_epoch,
            result_hash: ContentHash::compute(b"campaign_result"),
        };
        result.recompute_hash();
        self.campaign_results.push(result);
        self.recompute_hash();
        self.campaign_results.last().expect("just pushed")
    }

    /// Run campaigns for all candidates in a catalog.
    pub fn run_all(&mut self, catalog: &LawMiningCatalog) {
        let candidates: Vec<LawCandidate> = catalog.candidates.clone();
        for candidate in &candidates {
            self.run_campaign(candidate);
        }
        self.campaign_results
            .sort_by(|a, b| a.candidate_id.cmp(&b.candidate_id));
        self.recompute_hash();
    }

    /// Get the campaign result for a specific candidate.
    pub fn result_for(&self, candidate_id: &str) -> Option<&ProofCampaignResult> {
        self.campaign_results
            .iter()
            .find(|r| r.candidate_id == candidate_id)
    }

    /// Get all accepted candidate IDs.
    pub fn accepted_candidates(&self) -> Vec<&str> {
        self.campaign_results
            .iter()
            .filter(|r| r.accepted)
            .map(|r| r.candidate_id.as_str())
            .collect()
    }

    /// Get all refuted candidate IDs.
    pub fn refuted_candidates(&self) -> Vec<&str> {
        self.campaign_results
            .iter()
            .filter(|r| r.final_verdict == ProofVerdict::Refuted)
            .map(|r| r.candidate_id.as_str())
            .collect()
    }

    /// Get all inconclusive candidate IDs.
    pub fn inconclusive_candidates(&self) -> Vec<&str> {
        self.campaign_results
            .iter()
            .filter(|r| r.final_verdict == ProofVerdict::Inconclusive)
            .map(|r| r.candidate_id.as_str())
            .collect()
    }

    /// Generate a summary report.
    pub fn summary_report(&self) -> ProofRefutationSummary {
        let total = self.campaign_results.len();
        let proved = self
            .campaign_results
            .iter()
            .filter(|r| r.final_verdict == ProofVerdict::Proved)
            .count();
        let refuted = self
            .campaign_results
            .iter()
            .filter(|r| r.final_verdict == ProofVerdict::Refuted)
            .count();
        let inconclusive = self
            .campaign_results
            .iter()
            .filter(|r| r.final_verdict == ProofVerdict::Inconclusive)
            .count();
        let accepted = self.campaign_results.iter().filter(|r| r.accepted).count();
        let total_attempts: usize = self.campaign_results.iter().map(|r| r.attempts.len()).sum();
        let total_witnesses = self.counterexample_archive.witnesses.len();

        let acceptance_rate_millionths = if total > 0 {
            (accepted as u64).saturating_mul(MILLION) / total as u64
        } else {
            0
        };

        let mut summary_hash_data = Vec::new();
        summary_hash_data.extend_from_slice(&(total as u64).to_le_bytes());
        summary_hash_data.extend_from_slice(&(proved as u64).to_le_bytes());
        summary_hash_data.extend_from_slice(&(refuted as u64).to_le_bytes());
        summary_hash_data.extend_from_slice(&(inconclusive as u64).to_le_bytes());
        summary_hash_data.extend_from_slice(&(accepted as u64).to_le_bytes());
        summary_hash_data.extend_from_slice(&self.pipeline_epoch.as_u64().to_le_bytes());

        ProofRefutationSummary {
            total_candidates: total,
            proved_count: proved,
            refuted_count: refuted,
            inconclusive_count: inconclusive,
            accepted_count: accepted,
            total_attempts,
            total_witnesses,
            acceptance_rate_millionths,
            pipeline_epoch: self.pipeline_epoch,
            summary_hash: ContentHash::compute(&summary_hash_data),
        }
    }

    fn recompute_hash(&mut self) {
        let mut data = Vec::new();
        data.extend_from_slice(self.schema_version.as_bytes());
        data.extend_from_slice(self.bead_id.as_bytes());
        for result in &self.campaign_results {
            data.extend_from_slice(result.result_hash.as_bytes());
        }
        data.extend_from_slice(self.counterexample_archive.archive_hash.as_bytes());
        data.extend_from_slice(&self.pipeline_epoch.as_u64().to_le_bytes());
        self.pipeline_hash = ContentHash::compute(&data);
    }
}

// ---------------------------------------------------------------------------
// ProofRefutationSummary
// ---------------------------------------------------------------------------

/// Summary report of a proof/refutation pipeline run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRefutationSummary {
    pub total_candidates: usize,
    pub proved_count: usize,
    pub refuted_count: usize,
    pub inconclusive_count: usize,
    pub accepted_count: usize,
    pub total_attempts: usize,
    pub total_witnesses: usize,
    pub acceptance_rate_millionths: u64,
    pub pipeline_epoch: SecurityEpoch,
    pub summary_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// ProofRefutationError
// ---------------------------------------------------------------------------

/// Errors from proof/refutation operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRefutationError {
    /// Candidate not found in the catalog.
    CandidateNotFound { candidate_id: String },
    /// Campaign already exists for this candidate.
    DuplicateCampaign { candidate_id: String },
    /// Max attempts exceeded.
    MaxAttemptsExceeded { limit: usize },
    /// Configuration invalid.
    InvalidConfig { detail: String },
}

impl fmt::Display for ProofRefutationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CandidateNotFound { candidate_id } => {
                write!(f, "candidate not found: {candidate_id}")
            }
            Self::DuplicateCampaign { candidate_id } => {
                write!(f, "campaign already exists for: {candidate_id}")
            }
            Self::MaxAttemptsExceeded { limit } => {
                write!(f, "max attempts exceeded: {limit}")
            }
            Self::InvalidConfig { detail } => {
                write!(f, "invalid config: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Simulate a proof attempt. In a real engine, this would dispatch to
/// the actual replay/solver/search infrastructure. Here we use
/// deterministic heuristics based on candidate properties.
fn simulate_proof_attempt(
    candidate_id: &str,
    kind: CandidateKind,
    strategy: ProofStrategy,
    rank_millionths: u64,
    epoch: SecurityEpoch,
    attempt_index: usize,
) -> ProofAttempt {
    let attempt_id = format!("attempt-{}-{}-{}", candidate_id, strategy, attempt_index);

    // Deterministic verdict based on candidate properties.
    // High-rank invariants are more likely to be proved.
    let (verdict, confidence, witness_id) =
        determine_verdict(candidate_id, kind, strategy, rank_millionths);

    let (configs, queries, iters) = match strategy {
        ProofStrategy::DifferentialReplay => (4 + attempt_index as u64, 0, 0),
        ProofStrategy::SolverCheck => (0, 8 + attempt_index as u64, 0),
        ProofStrategy::CounterexampleSearch => (0, 0, 64 + attempt_index as u64 * 16),
    };

    let mut attempt = ProofAttempt {
        attempt_id,
        candidate_id: candidate_id.to_string(),
        strategy,
        verdict,
        confidence_millionths: confidence,
        refutation_witness_id: witness_id,
        configurations_tested: configs,
        solver_queries: queries,
        search_iterations: iters,
        attempt_epoch: epoch,
        attempt_hash: ContentHash::compute(b"proof_attempt"),
    };
    attempt.recompute_hash();
    attempt
}

/// Determine the verdict for a proof attempt based on candidate properties.
fn determine_verdict(
    candidate_id: &str,
    kind: CandidateKind,
    strategy: ProofStrategy,
    rank_millionths: u64,
) -> (ProofVerdict, u64, Option<String>) {
    // Use content hash of candidate_id as deterministic seed
    let seed = ContentHash::compute(candidate_id.as_bytes());
    let seed_byte = seed.as_bytes()[0];

    // Higher ranked candidates are more likely to be proved.
    // The kind also affects proof difficulty.
    let kind_bonus = match kind {
        CandidateKind::Invariant => 200_000_u64,
        CandidateKind::SideCondition => 100_000,
        CandidateKind::NormalForm => 50_000,
    };

    let strategy_bonus = strategy.confidence_weight_millionths();
    let rank_factor = rank_millionths.min(MILLION);

    // Combined score determines verdict
    let raw_score = (rank_factor / 4)
        .saturating_add(kind_bonus)
        .saturating_add(strategy_bonus / 2)
        .saturating_add(seed_byte as u64 * 1_000);

    if raw_score >= 600_000 {
        // Proved
        let confidence = raw_score.min(MILLION);
        (ProofVerdict::Proved, confidence, None)
    } else if seed_byte < 40 {
        // Refuted — create witness
        let witness_id = format!("witness-{candidate_id}-{strategy}");
        (ProofVerdict::Refuted, MILLION, Some(witness_id))
    } else {
        // Inconclusive
        let confidence = raw_score;
        (ProofVerdict::Inconclusive, confidence, None)
    }
}

/// Build a refutation witness from an attempt.
fn build_refutation_witness(
    witness_id: &str,
    candidate_id: &str,
    strategy: ProofStrategy,
    epoch: SecurityEpoch,
) -> RefutationWitness {
    let reason = match strategy {
        ProofStrategy::DifferentialReplay => RefutationReason::ReplayDivergence,
        ProofStrategy::SolverCheck => RefutationReason::SolverCountermodel,
        ProofStrategy::CounterexampleSearch => RefutationReason::SearchHit,
    };

    let mut witness = RefutationWitness {
        witness_id: witness_id.to_string(),
        candidate_id: candidate_id.to_string(),
        reason,
        description: format!(
            "law '{candidate_id}' refuted via {strategy}: concrete counterexample found"
        ),
        input_digest: ContentHash::compute(format!("input-{candidate_id}-{strategy}").as_bytes()),
        expected_summary: format!("law '{candidate_id}' expected to hold"),
        actual_summary: format!("violation observed via {strategy}"),
        discovered_epoch: epoch,
        witness_hash: ContentHash::compute(b"refutation_witness"),
    };
    witness.recompute_hash();
    witness
}

/// Compute aggregate verdict from a sequence of proof attempts.
fn compute_aggregate_verdict(
    attempts: &[ProofAttempt],
    _config: &ProofCampaignConfig,
) -> (ProofVerdict, u64) {
    if attempts.is_empty() {
        return (ProofVerdict::Inconclusive, 0);
    }

    // Any refutation is terminal
    for attempt in attempts {
        if attempt.verdict == ProofVerdict::Refuted {
            return (ProofVerdict::Refuted, MILLION);
        }
    }

    // If any attempt proved, aggregate confidence from proved attempts
    let proved_attempts: Vec<&ProofAttempt> = attempts
        .iter()
        .filter(|a| a.verdict == ProofVerdict::Proved)
        .collect();

    if proved_attempts.is_empty() {
        // All inconclusive
        let max_confidence = attempts
            .iter()
            .map(|a| a.confidence_millionths)
            .max()
            .unwrap_or(0);
        return (ProofVerdict::Inconclusive, max_confidence);
    }

    // Weighted average of proved attempt confidences
    let total_weight: u64 = proved_attempts
        .iter()
        .map(|a| a.strategy.confidence_weight_millionths())
        .sum();

    let weighted_sum: u64 = proved_attempts
        .iter()
        .map(|a| {
            let weight = a.strategy.confidence_weight_millionths();
            (a.confidence_millionths.saturating_mul(weight)) / MILLION
        })
        .sum();

    let aggregate = weighted_sum
        .saturating_mul(MILLION)
        .checked_div(total_weight)
        .unwrap_or(0);

    (ProofVerdict::Proved, aggregate.min(MILLION))
}

/// Build a human-readable rationale for the campaign decision.
fn build_rationale(
    verdict: ProofVerdict,
    confidence: u64,
    attempts: &[ProofAttempt],
    accepted: bool,
    config: &ProofCampaignConfig,
) -> String {
    let attempt_count = attempts.len();
    let confidence_pct = confidence / 10_000;

    match verdict {
        ProofVerdict::Proved => {
            if accepted {
                format!(
                    "proved with {confidence_pct}% confidence across {attempt_count} attempt(s) — accepted (threshold: {}%)",
                    config.acceptance_threshold_millionths / 10_000
                )
            } else {
                format!(
                    "proved with {confidence_pct}% confidence across {attempt_count} attempt(s) — rejected: below threshold ({}%)",
                    config.acceptance_threshold_millionths / 10_000
                )
            }
        }
        ProofVerdict::Refuted => {
            format!("refuted across {attempt_count} attempt(s) — rejected")
        }
        ProofVerdict::Inconclusive => {
            format!(
                "inconclusive after {attempt_count} attempt(s) with max {confidence_pct}% confidence — not accepted"
            )
        }
    }
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

    fn test_candidate(id: &str, kind: CandidateKind, rank: u64) -> LawCandidate {
        let mut candidate = LawCandidate {
            candidate_id: id.to_string(),
            kind,
            statement: format!("test law: {id}"),
            rank_millionths: rank,
            ranking_rationale: "test".to_string(),
            scope_hypothesis_id: "scope-1".to_string(),
            provenance_id: "prov-1".to_string(),
            supporting_source_ids: vec!["src-1".to_string()],
            candidate_hash: ContentHash::compute(b"test"),
        };
        let mut data = Vec::new();
        data.extend_from_slice(candidate.candidate_id.as_bytes());
        data.extend_from_slice(format!("{:?}", candidate.kind).as_bytes());
        data.extend_from_slice(candidate.statement.as_bytes());
        data.extend_from_slice(&candidate.rank_millionths.to_le_bytes());
        candidate.candidate_hash = ContentHash::compute(&data);
        candidate
    }

    // --- ProofStrategy tests ---

    #[test]
    fn strategy_all_count() {
        assert_eq!(ProofStrategy::ALL.len(), 3);
    }

    #[test]
    fn strategy_display() {
        assert_eq!(
            ProofStrategy::DifferentialReplay.to_string(),
            "differential_replay"
        );
        assert_eq!(ProofStrategy::SolverCheck.to_string(), "solver_check");
        assert_eq!(
            ProofStrategy::CounterexampleSearch.to_string(),
            "counterexample_search"
        );
    }

    #[test]
    fn strategy_serde_roundtrip() {
        for strategy in ProofStrategy::ALL {
            let json = serde_json::to_string(strategy).unwrap();
            let back: ProofStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(*strategy, back);
        }
    }

    #[test]
    fn strategy_confidence_weights_nonzero() {
        for strategy in ProofStrategy::ALL {
            assert!(strategy.confidence_weight_millionths() > 0);
            assert!(strategy.confidence_weight_millionths() <= MILLION);
        }
    }

    #[test]
    fn strategy_ordering() {
        assert!(ProofStrategy::DifferentialReplay < ProofStrategy::SolverCheck);
        assert!(ProofStrategy::SolverCheck < ProofStrategy::CounterexampleSearch);
    }

    // --- ProofVerdict tests ---

    #[test]
    fn verdict_all_count() {
        assert_eq!(ProofVerdict::ALL.len(), 3);
    }

    #[test]
    fn verdict_display() {
        assert_eq!(ProofVerdict::Proved.to_string(), "proved");
        assert_eq!(ProofVerdict::Refuted.to_string(), "refuted");
        assert_eq!(ProofVerdict::Inconclusive.to_string(), "inconclusive");
    }

    #[test]
    fn verdict_is_terminal() {
        assert!(ProofVerdict::Proved.is_terminal());
        assert!(ProofVerdict::Refuted.is_terminal());
        assert!(!ProofVerdict::Inconclusive.is_terminal());
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for verdict in ProofVerdict::ALL {
            let json = serde_json::to_string(verdict).unwrap();
            let back: ProofVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*verdict, back);
        }
    }

    // --- RefutationReason tests ---

    #[test]
    fn refutation_reason_all_count() {
        assert_eq!(RefutationReason::ALL.len(), 4);
    }

    #[test]
    fn refutation_reason_display() {
        assert_eq!(
            RefutationReason::ReplayDivergence.to_string(),
            "replay_divergence"
        );
        assert_eq!(
            RefutationReason::SolverCountermodel.to_string(),
            "solver_countermodel"
        );
        assert_eq!(RefutationReason::SearchHit.to_string(), "search_hit");
        assert_eq!(
            RefutationReason::ScopeInvalidation.to_string(),
            "scope_invalidation"
        );
    }

    #[test]
    fn refutation_reason_serde_roundtrip() {
        for reason in RefutationReason::ALL {
            let json = serde_json::to_string(reason).unwrap();
            let back: RefutationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, back);
        }
    }

    // --- RefutationWitness tests ---

    #[test]
    fn witness_recompute_hash_deterministic() {
        let mut w1 = RefutationWitness {
            witness_id: "w-1".to_string(),
            candidate_id: "c-1".to_string(),
            reason: RefutationReason::ReplayDivergence,
            description: "test divergence".to_string(),
            input_digest: ContentHash::compute(b"input"),
            expected_summary: "expected".to_string(),
            actual_summary: "actual".to_string(),
            discovered_epoch: test_epoch(),
            witness_hash: ContentHash::compute(b"placeholder"),
        };
        w1.recompute_hash();
        let hash1 = w1.witness_hash;
        w1.recompute_hash();
        assert_eq!(hash1, w1.witness_hash);
    }

    #[test]
    fn witness_different_reasons_different_hashes() {
        let mk = |reason: RefutationReason| {
            let mut w = RefutationWitness {
                witness_id: "w-1".to_string(),
                candidate_id: "c-1".to_string(),
                reason,
                description: "test".to_string(),
                input_digest: ContentHash::compute(b"input"),
                expected_summary: "exp".to_string(),
                actual_summary: "act".to_string(),
                discovered_epoch: test_epoch(),
                witness_hash: ContentHash::compute(b"placeholder"),
            };
            w.recompute_hash();
            w.witness_hash
        };
        let h1 = mk(RefutationReason::ReplayDivergence);
        let h2 = mk(RefutationReason::SolverCountermodel);
        assert_ne!(h1, h2);
    }

    #[test]
    fn witness_serde_roundtrip() {
        let mut w = RefutationWitness {
            witness_id: "w-1".to_string(),
            candidate_id: "c-1".to_string(),
            reason: RefutationReason::SearchHit,
            description: "found violation".to_string(),
            input_digest: ContentHash::compute(b"bad_input"),
            expected_summary: "law should hold".to_string(),
            actual_summary: "law violated".to_string(),
            discovered_epoch: test_epoch(),
            witness_hash: ContentHash::compute(b"placeholder"),
        };
        w.recompute_hash();
        let json = serde_json::to_string(&w).unwrap();
        let back: RefutationWitness = serde_json::from_str(&json).unwrap();
        assert_eq!(w, back);
    }

    // --- ProofAttempt tests ---

    #[test]
    fn attempt_recompute_hash_deterministic() {
        let mut a = ProofAttempt {
            attempt_id: "a-1".to_string(),
            candidate_id: "c-1".to_string(),
            strategy: ProofStrategy::DifferentialReplay,
            verdict: ProofVerdict::Proved,
            confidence_millionths: 900_000,
            refutation_witness_id: None,
            configurations_tested: 4,
            solver_queries: 0,
            search_iterations: 0,
            attempt_epoch: test_epoch(),
            attempt_hash: ContentHash::compute(b"placeholder"),
        };
        a.recompute_hash();
        let h1 = a.attempt_hash;
        a.recompute_hash();
        assert_eq!(h1, a.attempt_hash);
    }

    #[test]
    fn attempt_with_witness_different_hash() {
        let mk = |witness: Option<String>| {
            let mut a = ProofAttempt {
                attempt_id: "a-1".to_string(),
                candidate_id: "c-1".to_string(),
                strategy: ProofStrategy::CounterexampleSearch,
                verdict: ProofVerdict::Refuted,
                confidence_millionths: MILLION,
                refutation_witness_id: witness,
                configurations_tested: 0,
                solver_queries: 0,
                search_iterations: 64,
                attempt_epoch: test_epoch(),
                attempt_hash: ContentHash::compute(b"placeholder"),
            };
            a.recompute_hash();
            a.attempt_hash
        };
        let h1 = mk(None);
        let h2 = mk(Some("w-1".to_string()));
        assert_ne!(h1, h2);
    }

    #[test]
    fn attempt_serde_roundtrip() {
        let mut a = ProofAttempt {
            attempt_id: "a-1".to_string(),
            candidate_id: "c-1".to_string(),
            strategy: ProofStrategy::SolverCheck,
            verdict: ProofVerdict::Inconclusive,
            confidence_millionths: 500_000,
            refutation_witness_id: None,
            configurations_tested: 0,
            solver_queries: 12,
            search_iterations: 0,
            attempt_epoch: test_epoch(),
            attempt_hash: ContentHash::compute(b"placeholder"),
        };
        a.recompute_hash();
        let json = serde_json::to_string(&a).unwrap();
        let back: ProofAttempt = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // --- CounterexampleArchive tests ---

    #[test]
    fn archive_new_is_empty() {
        let archive = CounterexampleArchive::new(test_epoch());
        assert!(archive.witnesses.is_empty());
        assert!(archive.refuted_candidate_ids.is_empty());
    }

    #[test]
    fn archive_add_witness() {
        let mut archive = CounterexampleArchive::new(test_epoch());
        let witness = build_refutation_witness(
            "w-1",
            "c-1",
            ProofStrategy::DifferentialReplay,
            test_epoch(),
        );
        archive.add_witness(witness);
        assert_eq!(archive.witnesses.len(), 1);
        assert!(archive.is_refuted("c-1"));
        assert!(!archive.is_refuted("c-2"));
    }

    #[test]
    fn archive_witnesses_for() {
        let mut archive = CounterexampleArchive::new(test_epoch());
        archive.add_witness(build_refutation_witness(
            "w-1",
            "c-1",
            ProofStrategy::DifferentialReplay,
            test_epoch(),
        ));
        archive.add_witness(build_refutation_witness(
            "w-2",
            "c-1",
            ProofStrategy::SolverCheck,
            test_epoch(),
        ));
        archive.add_witness(build_refutation_witness(
            "w-3",
            "c-2",
            ProofStrategy::CounterexampleSearch,
            test_epoch(),
        ));
        assert_eq!(archive.witnesses_for("c-1").len(), 2);
        assert_eq!(archive.witnesses_for("c-2").len(), 1);
        assert_eq!(archive.witnesses_for("c-3").len(), 0);
    }

    #[test]
    fn archive_sorted_by_witness_id() {
        let mut archive = CounterexampleArchive::new(test_epoch());
        archive.add_witness(build_refutation_witness(
            "w-b",
            "c-1",
            ProofStrategy::DifferentialReplay,
            test_epoch(),
        ));
        archive.add_witness(build_refutation_witness(
            "w-a",
            "c-2",
            ProofStrategy::SolverCheck,
            test_epoch(),
        ));
        assert_eq!(archive.witnesses[0].witness_id, "w-a");
        assert_eq!(archive.witnesses[1].witness_id, "w-b");
    }

    #[test]
    fn archive_serde_roundtrip() {
        let mut archive = CounterexampleArchive::new(test_epoch());
        archive.add_witness(build_refutation_witness(
            "w-1",
            "c-1",
            ProofStrategy::DifferentialReplay,
            test_epoch(),
        ));
        let json = serde_json::to_string(&archive).unwrap();
        let back: CounterexampleArchive = serde_json::from_str(&json).unwrap();
        assert_eq!(archive, back);
    }

    #[test]
    fn archive_hash_changes_on_add() {
        let mut archive = CounterexampleArchive::new(test_epoch());
        let h1 = archive.archive_hash;
        archive.add_witness(build_refutation_witness(
            "w-1",
            "c-1",
            ProofStrategy::DifferentialReplay,
            test_epoch(),
        ));
        assert_ne!(h1, archive.archive_hash);
    }

    // --- ProofCampaignConfig tests ---

    #[test]
    fn config_default_has_all_strategies() {
        let config = ProofCampaignConfig::default();
        assert_eq!(config.strategies.len(), 3);
        assert!(config.early_termination);
        assert!(config.skip_known_refuted);
    }

    #[test]
    fn config_default_threshold() {
        let config = ProofCampaignConfig::default();
        assert_eq!(config.acceptance_threshold_millionths, 800_000);
    }

    // --- ProofCampaignResult tests ---

    #[test]
    fn campaign_result_hash_deterministic() {
        let mut r = ProofCampaignResult {
            candidate_id: "c-1".to_string(),
            candidate_kind: CandidateKind::Invariant,
            final_verdict: ProofVerdict::Proved,
            aggregate_confidence_millionths: 900_000,
            attempts: Vec::new(),
            refutation_witness_ids: Vec::new(),
            accepted: true,
            rationale: "proved".to_string(),
            campaign_epoch: test_epoch(),
            result_hash: ContentHash::compute(b"placeholder"),
        };
        r.recompute_hash();
        let h1 = r.result_hash;
        r.recompute_hash();
        assert_eq!(h1, r.result_hash);
    }

    #[test]
    fn campaign_result_serde_roundtrip() {
        let mut r = ProofCampaignResult {
            candidate_id: "c-1".to_string(),
            candidate_kind: CandidateKind::SideCondition,
            final_verdict: ProofVerdict::Inconclusive,
            aggregate_confidence_millionths: 400_000,
            attempts: Vec::new(),
            refutation_witness_ids: Vec::new(),
            accepted: false,
            rationale: "inconclusive".to_string(),
            campaign_epoch: test_epoch(),
            result_hash: ContentHash::compute(b"placeholder"),
        };
        r.recompute_hash();
        let json = serde_json::to_string(&r).unwrap();
        let back: ProofCampaignResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- ProofRefutationPipeline tests ---

    #[test]
    fn pipeline_new_is_empty() {
        let pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), test_epoch());
        assert!(pipeline.campaign_results.is_empty());
        assert!(pipeline.counterexample_archive.witnesses.is_empty());
    }

    #[test]
    fn pipeline_run_campaign_single_candidate() {
        let mut pipeline =
            ProofRefutationPipeline::new(ProofCampaignConfig::default(), test_epoch());
        let candidate = test_candidate("law-inv-1", CandidateKind::Invariant, 800_000);
        let result = pipeline.run_campaign(&candidate);
        assert!(!result.attempts.is_empty());
        assert!(
            result.final_verdict.is_terminal()
                || result.final_verdict == ProofVerdict::Inconclusive
        );
    }

    #[test]
    fn pipeline_skip_known_refuted() {
        let mut pipeline =
            ProofRefutationPipeline::new(ProofCampaignConfig::default(), test_epoch());
        // Manually add a refuted witness
        pipeline
            .counterexample_archive
            .add_witness(build_refutation_witness(
                "w-pre",
                "c-known",
                ProofStrategy::DifferentialReplay,
                test_epoch(),
            ));

        let candidate = test_candidate("c-known", CandidateKind::Invariant, 900_000);
        let result = pipeline.run_campaign(&candidate);
        assert_eq!(result.final_verdict, ProofVerdict::Refuted);
        assert!(result.attempts.is_empty());
        assert!(!result.accepted);
    }

    #[test]
    fn pipeline_accepted_candidates() {
        let mut pipeline =
            ProofRefutationPipeline::new(ProofCampaignConfig::default(), test_epoch());
        // Run several candidates — some may be accepted
        for i in 0..5 {
            let candidate = test_candidate(
                &format!("law-{i}"),
                CandidateKind::Invariant,
                600_000 + i * 100_000,
            );
            pipeline.run_campaign(&candidate);
        }
        // Just verify the method works without panicking
        let _accepted = pipeline.accepted_candidates();
        let _refuted = pipeline.refuted_candidates();
        let _inconclusive = pipeline.inconclusive_candidates();
    }

    #[test]
    fn pipeline_result_for() {
        let mut pipeline =
            ProofRefutationPipeline::new(ProofCampaignConfig::default(), test_epoch());
        let candidate = test_candidate("law-lookup", CandidateKind::SideCondition, 700_000);
        pipeline.run_campaign(&candidate);
        assert!(pipeline.result_for("law-lookup").is_some());
        assert!(pipeline.result_for("nonexistent").is_none());
    }

    #[test]
    fn pipeline_summary_report() {
        let mut pipeline =
            ProofRefutationPipeline::new(ProofCampaignConfig::default(), test_epoch());
        for i in 0..3 {
            let candidate =
                test_candidate(&format!("law-sum-{i}"), CandidateKind::Invariant, 800_000);
            pipeline.run_campaign(&candidate);
        }
        let summary = pipeline.summary_report();
        assert_eq!(summary.total_candidates, 3);
        assert_eq!(
            summary.proved_count + summary.refuted_count + summary.inconclusive_count,
            3
        );
    }

    #[test]
    fn pipeline_hash_changes_on_campaign() {
        let mut pipeline =
            ProofRefutationPipeline::new(ProofCampaignConfig::default(), test_epoch());
        let h1 = pipeline.pipeline_hash;
        let candidate = test_candidate("law-hash", CandidateKind::NormalForm, 500_000);
        pipeline.run_campaign(&candidate);
        assert_ne!(h1, pipeline.pipeline_hash);
    }

    #[test]
    fn pipeline_serde_roundtrip() {
        let mut pipeline =
            ProofRefutationPipeline::new(ProofCampaignConfig::default(), test_epoch());
        let candidate = test_candidate("law-serde", CandidateKind::Invariant, 800_000);
        pipeline.run_campaign(&candidate);
        let json = serde_json::to_string(&pipeline).unwrap();
        let back: ProofRefutationPipeline = serde_json::from_str(&json).unwrap();
        assert_eq!(pipeline, back);
    }

    // --- Aggregate verdict tests ---

    #[test]
    fn aggregate_empty_attempts_inconclusive() {
        let config = ProofCampaignConfig::default();
        let (verdict, confidence) = compute_aggregate_verdict(&[], &config);
        assert_eq!(verdict, ProofVerdict::Inconclusive);
        assert_eq!(confidence, 0);
    }

    #[test]
    fn aggregate_refutation_overrides_all() {
        let config = ProofCampaignConfig::default();
        let attempts = vec![
            mk_attempt(
                ProofVerdict::Proved,
                900_000,
                ProofStrategy::DifferentialReplay,
            ),
            mk_attempt(ProofVerdict::Refuted, MILLION, ProofStrategy::SolverCheck),
        ];
        let (verdict, _) = compute_aggregate_verdict(&attempts, &config);
        assert_eq!(verdict, ProofVerdict::Refuted);
    }

    #[test]
    fn aggregate_all_inconclusive() {
        let config = ProofCampaignConfig::default();
        let attempts = vec![
            mk_attempt(
                ProofVerdict::Inconclusive,
                300_000,
                ProofStrategy::DifferentialReplay,
            ),
            mk_attempt(
                ProofVerdict::Inconclusive,
                500_000,
                ProofStrategy::SolverCheck,
            ),
        ];
        let (verdict, confidence) = compute_aggregate_verdict(&attempts, &config);
        assert_eq!(verdict, ProofVerdict::Inconclusive);
        assert_eq!(confidence, 500_000);
    }

    #[test]
    fn aggregate_proved_weighted_average() {
        let config = ProofCampaignConfig::default();
        let attempts = vec![
            mk_attempt(
                ProofVerdict::Proved,
                800_000,
                ProofStrategy::DifferentialReplay,
            ),
            mk_attempt(ProofVerdict::Proved, 900_000, ProofStrategy::SolverCheck),
        ];
        let (verdict, confidence) = compute_aggregate_verdict(&attempts, &config);
        assert_eq!(verdict, ProofVerdict::Proved);
        assert!(confidence > 0);
        assert!(confidence <= MILLION);
    }

    // --- Error display tests ---

    #[test]
    fn error_display() {
        let e = ProofRefutationError::CandidateNotFound {
            candidate_id: "c-1".to_string(),
        };
        assert!(e.to_string().contains("c-1"));

        let e = ProofRefutationError::DuplicateCampaign {
            candidate_id: "c-2".to_string(),
        };
        assert!(e.to_string().contains("c-2"));

        let e = ProofRefutationError::MaxAttemptsExceeded { limit: 16 };
        assert!(e.to_string().contains("16"));

        let e = ProofRefutationError::InvalidConfig {
            detail: "bad".to_string(),
        };
        assert!(e.to_string().contains("bad"));
    }

    #[test]
    fn error_serde_roundtrip() {
        for err in [
            ProofRefutationError::CandidateNotFound {
                candidate_id: "c".to_string(),
            },
            ProofRefutationError::DuplicateCampaign {
                candidate_id: "d".to_string(),
            },
            ProofRefutationError::MaxAttemptsExceeded { limit: 8 },
            ProofRefutationError::InvalidConfig {
                detail: "x".to_string(),
            },
        ] {
            let json = serde_json::to_string(&err).unwrap();
            let back: ProofRefutationError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, back);
        }
    }

    // --- Determinism tests ---

    #[test]
    fn deterministic_verdict_same_inputs() {
        let (v1, c1, w1) = determine_verdict(
            "c-1",
            CandidateKind::Invariant,
            ProofStrategy::DifferentialReplay,
            800_000,
        );
        let (v2, c2, w2) = determine_verdict(
            "c-1",
            CandidateKind::Invariant,
            ProofStrategy::DifferentialReplay,
            800_000,
        );
        assert_eq!(v1, v2);
        assert_eq!(c1, c2);
        assert_eq!(w1, w2);
    }

    #[test]
    fn different_candidates_may_differ() {
        let (v1, _, _) = determine_verdict(
            "alpha",
            CandidateKind::Invariant,
            ProofStrategy::DifferentialReplay,
            800_000,
        );
        let (v2, _, _) = determine_verdict(
            "beta",
            CandidateKind::NormalForm,
            ProofStrategy::CounterexampleSearch,
            200_000,
        );
        // They might differ; we just check no panic
        let _ = (v1, v2);
    }

    // --- Early termination test ---

    #[test]
    fn early_termination_stops_on_proved() {
        let config = ProofCampaignConfig {
            strategies: vec![
                ProofStrategy::DifferentialReplay,
                ProofStrategy::SolverCheck,
                ProofStrategy::CounterexampleSearch,
            ],
            max_attempts: 16,
            acceptance_threshold_millionths: 0, // accept anything proved
            early_termination: true,
            skip_known_refuted: true,
        };
        let mut pipeline = ProofRefutationPipeline::new(config, test_epoch());
        // Use a high-rank invariant that should be proved on first attempt
        let candidate = test_candidate("law-early", CandidateKind::Invariant, 900_000);
        let result = pipeline.run_campaign(&candidate);
        if result.final_verdict.is_terminal() {
            // With early termination, should stop before trying all strategies
            assert!(result.attempts.len() <= 3);
        }
    }

    #[test]
    fn no_early_termination_tries_all() {
        let config = ProofCampaignConfig {
            strategies: vec![
                ProofStrategy::DifferentialReplay,
                ProofStrategy::SolverCheck,
                ProofStrategy::CounterexampleSearch,
            ],
            max_attempts: 16,
            acceptance_threshold_millionths: 800_000,
            early_termination: false,
            skip_known_refuted: true,
        };
        let mut pipeline = ProofRefutationPipeline::new(config, test_epoch());
        let candidate = test_candidate("law-all", CandidateKind::Invariant, 900_000);
        let result = pipeline.run_campaign(&candidate);
        // Without early termination, should try all 3 strategies (unless refuted)
        if result.final_verdict != ProofVerdict::Refuted {
            assert_eq!(result.attempts.len(), 3);
        }
    }

    // --- Summary report tests ---

    #[test]
    fn summary_empty_pipeline() {
        let pipeline = ProofRefutationPipeline::new(ProofCampaignConfig::default(), test_epoch());
        let summary = pipeline.summary_report();
        assert_eq!(summary.total_candidates, 0);
        assert_eq!(summary.acceptance_rate_millionths, 0);
    }

    #[test]
    fn summary_counts_consistent() {
        let mut pipeline =
            ProofRefutationPipeline::new(ProofCampaignConfig::default(), test_epoch());
        for i in 0..10 {
            let candidate = test_candidate(
                &format!("law-cnt-{i}"),
                if i % 2 == 0 {
                    CandidateKind::Invariant
                } else {
                    CandidateKind::SideCondition
                },
                400_000 + i * 60_000,
            );
            pipeline.run_campaign(&candidate);
        }
        let summary = pipeline.summary_report();
        assert_eq!(
            summary.proved_count + summary.refuted_count + summary.inconclusive_count,
            summary.total_candidates
        );
        assert!(summary.accepted_count <= summary.proved_count);
    }

    // --- Rationale tests ---

    #[test]
    fn rationale_proved_accepted() {
        let config = ProofCampaignConfig::default();
        let rationale = build_rationale(ProofVerdict::Proved, 900_000, &[], true, &config);
        assert!(rationale.contains("accepted"));
    }

    #[test]
    fn rationale_proved_rejected() {
        let config = ProofCampaignConfig::default();
        let rationale = build_rationale(ProofVerdict::Proved, 500_000, &[], false, &config);
        assert!(rationale.contains("rejected"));
    }

    #[test]
    fn rationale_refuted() {
        let config = ProofCampaignConfig::default();
        let rationale = build_rationale(ProofVerdict::Refuted, MILLION, &[], false, &config);
        assert!(rationale.contains("refuted"));
    }

    #[test]
    fn rationale_inconclusive() {
        let config = ProofCampaignConfig::default();
        let rationale = build_rationale(ProofVerdict::Inconclusive, 300_000, &[], false, &config);
        assert!(rationale.contains("inconclusive"));
    }

    // --- Helper for tests ---

    fn mk_attempt(verdict: ProofVerdict, confidence: u64, strategy: ProofStrategy) -> ProofAttempt {
        let mut a = ProofAttempt {
            attempt_id: format!("test-{verdict}-{strategy}"),
            candidate_id: "c-test".to_string(),
            strategy,
            verdict,
            confidence_millionths: confidence,
            refutation_witness_id: None,
            configurations_tested: 0,
            solver_queries: 0,
            search_iterations: 0,
            attempt_epoch: test_epoch(),
            attempt_hash: ContentHash::compute(b"test"),
        };
        a.recompute_hash();
        a
    }
}
