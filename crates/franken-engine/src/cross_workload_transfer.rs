//! Cross-workload transfer of rewrite, tiering, and cache priors with drift guards.
//!
//! Implements [RGC-612B]: transfers rewrite packs, tiering priors, and cache/AOT
//! hints across workload neighborhoods so the engine can warm-start optimization
//! on never-before-seen code — safely, with drift detection and automatic rollback.
//!
//! # Design
//!
//! - `TransferableKind` enumerates what can be transferred (rewrite packs,
//!   tiering priors, cache hints, AOT artifacts).
//! - `TransferCandidate` represents a prior from a donor workload.
//! - `DriftSignal` detects when transferred priors diverge from local evidence.
//! - `TransferDecision` records whether a transfer was accepted, deferred, or
//!   rejected, with auditable justification.
//! - `TransferSession` orchestrates the full transfer pipeline: candidate
//!   selection, neighborhood check, budget enforcement, and drift monitoring.
//! - `TransferRollback` undoes a transfer when drift exceeds tolerance.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-612B]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.cross-workload-transfer.v1";

/// Component name.
pub const COMPONENT: &str = "cross_workload_transfer";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.12.2";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-612B";

/// Fixed-point unit.
const MILLION: i64 = 1_000_000;

/// Maximum concurrent transfer candidates per session.
pub const MAX_TRANSFER_CANDIDATES: usize = 64;

/// Maximum number of active transfers (transfers in monitoring phase).
pub const MAX_ACTIVE_TRANSFERS: usize = 128;

/// Default drift tolerance in millionths.  If observed performance diverges
/// from predicted by more than this fraction, the transfer is rolled back.
/// 150_000 = 15%.
pub const DEFAULT_DRIFT_TOLERANCE: i64 = 150_000;

/// Minimum neighborhood proximity score (millionths) required before
/// attempting transfer.  600_000 = 0.60 cosine similarity.
pub const MIN_PROXIMITY_SCORE: i64 = 600_000;

/// Minimum observation count before drift detection is meaningful.
pub const MIN_DRIFT_OBSERVATIONS: u64 = 16;

/// Maximum rollback history retained per transfer target.
pub const MAX_ROLLBACK_HISTORY: usize = 8;

// ---------------------------------------------------------------------------
// TransferableKind
// ---------------------------------------------------------------------------

/// What kind of optimization prior is being transferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferableKind {
    /// Versioned rewrite pack (e.g., peephole rules, strength reductions).
    RewritePack,
    /// Tiering prior (initial tier assignment, tier-up thresholds).
    TieringPrior,
    /// Cache hint (entry priorities, eviction weights).
    CacheHint,
    /// AOT compilation artifact (precompiled code for predicted hot paths).
    AotArtifact,
    /// Specialization guard (type-feedback assumptions from donor).
    SpecializationGuard,
}

impl TransferableKind {
    pub const ALL: &[Self] = &[
        Self::RewritePack,
        Self::TieringPrior,
        Self::CacheHint,
        Self::AotArtifact,
        Self::SpecializationGuard,
    ];
}

impl fmt::Display for TransferableKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RewritePack => write!(f, "rewrite_pack"),
            Self::TieringPrior => write!(f, "tiering_prior"),
            Self::CacheHint => write!(f, "cache_hint"),
            Self::AotArtifact => write!(f, "aot_artifact"),
            Self::SpecializationGuard => write!(f, "specialization_guard"),
        }
    }
}

// ---------------------------------------------------------------------------
// TransferCandidate
// ---------------------------------------------------------------------------

/// A prior from a donor workload proposed for transfer to a recipient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferCandidate {
    /// Unique key for this candidate within the session.
    pub candidate_key: String,
    /// Kind of prior being transferred.
    pub kind: TransferableKind,
    /// Content hash of the donor workload embedding.
    pub donor_embedding_hash: ContentHash,
    /// Content hash of the specific prior artifact.
    pub prior_hash: ContentHash,
    /// Proximity score between donor and recipient (millionths).
    pub proximity_score: i64,
    /// Donor-side performance estimate (e.g., speedup in millionths).
    pub donor_performance_estimate: i64,
    /// Epoch in which the donor prior was collected.
    pub donor_epoch: SecurityEpoch,
    /// Human-readable label for the donor workload.
    pub donor_label: String,
}

// ---------------------------------------------------------------------------
// DriftKind
// ---------------------------------------------------------------------------

/// Classification of observed drift between transferred prior and local behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftKind {
    /// Performance regression — transferred prior is slower than baseline.
    PerformanceRegression,
    /// Correctness divergence — transferred prior produced different output.
    CorrectnessDivergence,
    /// Type-feedback mismatch — specialization guards don't match local types.
    TypeFeedbackMismatch,
    /// Cache pollution — transferred hints cause eviction of locally hot entries.
    CachePollution,
    /// Epoch mismatch — donor epoch is too far from recipient epoch.
    EpochDrift,
}

impl DriftKind {
    pub const ALL: &[Self] = &[
        Self::PerformanceRegression,
        Self::CorrectnessDivergence,
        Self::TypeFeedbackMismatch,
        Self::CachePollution,
        Self::EpochDrift,
    ];
}

impl fmt::Display for DriftKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PerformanceRegression => write!(f, "performance_regression"),
            Self::CorrectnessDivergence => write!(f, "correctness_divergence"),
            Self::TypeFeedbackMismatch => write!(f, "type_feedback_mismatch"),
            Self::CachePollution => write!(f, "cache_pollution"),
            Self::EpochDrift => write!(f, "epoch_drift"),
        }
    }
}

// ---------------------------------------------------------------------------
// DriftSignal
// ---------------------------------------------------------------------------

/// A signal indicating that a transferred prior is diverging from local evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftSignal {
    /// Kind of drift observed.
    pub kind: DriftKind,
    /// Magnitude of the drift in millionths (positive = worse).
    pub magnitude_millionths: i64,
    /// Number of observations contributing to this signal.
    pub observation_count: u64,
    /// Whether the signal is statistically confident.
    pub confident: bool,
    /// Content hash of the evidence supporting this signal.
    pub evidence_hash: ContentHash,
}

impl DriftSignal {
    /// Whether this signal exceeds a tolerance threshold.
    pub fn exceeds_tolerance(&self, tolerance: i64) -> bool {
        self.confident && self.magnitude_millionths > tolerance
    }
}

// ---------------------------------------------------------------------------
// TransferDecision
// ---------------------------------------------------------------------------

/// Outcome of evaluating a transfer candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferVerdict {
    /// Transfer accepted — prior will be applied and monitored.
    Accepted,
    /// Transfer deferred — conditions not yet met, may re-evaluate later.
    Deferred,
    /// Transfer rejected — proximity too low, budget exhausted, or policy refusal.
    Rejected,
}

impl fmt::Display for TransferVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted => write!(f, "accepted"),
            Self::Deferred => write!(f, "deferred"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

/// Reason for rejecting or deferring a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferRejectionReason {
    /// Proximity score below minimum threshold.
    ProximityTooLow,
    /// Transfer budget (max active transfers) exhausted.
    BudgetExhausted,
    /// Transferable kind blocked by policy.
    KindBlocked,
    /// Donor epoch too stale relative to recipient.
    EpochGapTooLarge,
    /// Prior artifact already exists locally (no transfer needed).
    AlreadyPresent,
    /// Previous transfer of same kind rolled back too recently.
    RecentRollback,
    /// Insufficient donor performance evidence.
    InsufficientEvidence,
}

impl fmt::Display for TransferRejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProximityTooLow => write!(f, "proximity_too_low"),
            Self::BudgetExhausted => write!(f, "budget_exhausted"),
            Self::KindBlocked => write!(f, "kind_blocked"),
            Self::EpochGapTooLarge => write!(f, "epoch_gap_too_large"),
            Self::AlreadyPresent => write!(f, "already_present"),
            Self::RecentRollback => write!(f, "recent_rollback"),
            Self::InsufficientEvidence => write!(f, "insufficient_evidence"),
        }
    }
}

/// Full decision record for a transfer candidate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferDecision {
    /// The candidate being evaluated.
    pub candidate_key: String,
    /// Verdict.
    pub verdict: TransferVerdict,
    /// Reason (set when verdict is Rejected or Deferred).
    pub reason: Option<TransferRejectionReason>,
    /// Content hash of the decision (for audit trail).
    pub decision_hash: ContentHash,
    /// Epoch at which this decision was made.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// TransferConfig
// ---------------------------------------------------------------------------

/// Configuration for cross-workload transfer sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferConfig {
    /// Maximum concurrent active transfers.
    pub max_active_transfers: usize,
    /// Maximum candidates to evaluate per session.
    pub max_candidates: usize,
    /// Drift tolerance (millionths) before rollback.
    pub drift_tolerance: i64,
    /// Minimum proximity score required for transfer.
    pub min_proximity_score: i64,
    /// Maximum epoch gap (raw) between donor and recipient.
    pub max_epoch_gap: u64,
    /// Kinds allowed for transfer (empty = all allowed).
    pub allowed_kinds: BTreeSet<TransferableKind>,
    /// Kinds explicitly blocked from transfer.
    pub blocked_kinds: BTreeSet<TransferableKind>,
    /// Minimum observation count before drift detection activates.
    pub min_drift_observations: u64,
    /// Cooldown period (epochs) after rollback before re-attempting same kind.
    pub rollback_cooldown_epochs: u64,
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            max_active_transfers: MAX_ACTIVE_TRANSFERS,
            max_candidates: MAX_TRANSFER_CANDIDATES,
            drift_tolerance: DEFAULT_DRIFT_TOLERANCE,
            min_proximity_score: MIN_PROXIMITY_SCORE,
            max_epoch_gap: 10,
            allowed_kinds: BTreeSet::new(),
            blocked_kinds: BTreeSet::new(),
            min_drift_observations: MIN_DRIFT_OBSERVATIONS,
            rollback_cooldown_epochs: 3,
        }
    }
}

impl TransferConfig {
    /// Whether a kind is permitted by this config.
    pub fn kind_allowed(&self, kind: TransferableKind) -> bool {
        if self.blocked_kinds.contains(&kind) {
            return false;
        }
        if self.allowed_kinds.is_empty() {
            return true;
        }
        self.allowed_kinds.contains(&kind)
    }
}

// ---------------------------------------------------------------------------
// ActiveTransfer
// ---------------------------------------------------------------------------

/// An in-flight transfer currently being monitored for drift.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveTransfer {
    /// Original candidate key.
    pub candidate_key: String,
    /// Kind.
    pub kind: TransferableKind,
    /// Hash of the transferred prior.
    pub prior_hash: ContentHash,
    /// Epoch when transfer was accepted.
    pub accepted_epoch: SecurityEpoch,
    /// Accumulated drift signals.
    pub drift_signals: Vec<DriftSignal>,
    /// Total observations collected since activation.
    pub observation_count: u64,
    /// Whether this transfer has been rolled back.
    pub rolled_back: bool,
    /// Hash of the decision that accepted this transfer.
    pub decision_hash: ContentHash,
}

impl ActiveTransfer {
    /// Worst-case drift magnitude across all confident signals.
    pub fn worst_drift_millionths(&self) -> i64 {
        self.drift_signals
            .iter()
            .filter(|s| s.confident)
            .map(|s| s.magnitude_millionths)
            .max()
            .unwrap_or(0)
    }

    /// Whether any confident signal exceeds tolerance.
    pub fn exceeds_tolerance(&self, tolerance: i64) -> bool {
        self.drift_signals
            .iter()
            .any(|s| s.exceeds_tolerance(tolerance))
    }

    /// Count of distinct drift kinds observed with confidence.
    pub fn confident_drift_kind_count(&self) -> usize {
        self.drift_signals
            .iter()
            .filter(|s| s.confident)
            .map(|s| s.kind)
            .collect::<BTreeSet<_>>()
            .len()
    }
}

// ---------------------------------------------------------------------------
// TransferRollback
// ---------------------------------------------------------------------------

/// Record of a rolled-back transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferRollback {
    /// Original candidate key.
    pub candidate_key: String,
    /// Kind of prior that was rolled back.
    pub kind: TransferableKind,
    /// Epoch at which rollback occurred.
    pub rollback_epoch: SecurityEpoch,
    /// Drift signal(s) that triggered rollback.
    pub trigger_signals: Vec<DriftSignal>,
    /// Hash of the prior that was removed.
    pub prior_hash: ContentHash,
    /// Content hash of the rollback record.
    pub rollback_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// TransferSession
// ---------------------------------------------------------------------------

/// Orchestrates the full transfer pipeline for a recipient workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferSession {
    /// Session identifier.
    pub session_key: String,
    /// Content hash of the recipient workload embedding.
    pub recipient_embedding_hash: ContentHash,
    /// Current epoch.
    pub epoch: SecurityEpoch,
    /// Configuration.
    pub config: TransferConfig,
    /// Decisions made during this session.
    pub decisions: Vec<TransferDecision>,
    /// Active (monitored) transfers.
    pub active_transfers: Vec<ActiveTransfer>,
    /// Rollback history.
    pub rollback_history: Vec<TransferRollback>,
    /// Set of prior hashes already present locally (skip re-transfer).
    pub local_prior_hashes: BTreeSet<ContentHash>,
    /// Per-kind rollback timestamps (epoch when last rollback occurred).
    pub kind_rollback_epochs: BTreeMap<TransferableKind, SecurityEpoch>,
}

impl TransferSession {
    /// Create a new session.
    pub fn new(
        session_key: String,
        recipient_embedding_hash: ContentHash,
        epoch: SecurityEpoch,
        config: TransferConfig,
    ) -> Self {
        Self {
            session_key,
            recipient_embedding_hash,
            epoch,
            config,
            decisions: Vec::new(),
            active_transfers: Vec::new(),
            rollback_history: Vec::new(),
            local_prior_hashes: BTreeSet::new(),
            kind_rollback_epochs: BTreeMap::new(),
        }
    }

    /// Evaluate a candidate and produce a decision.
    pub fn evaluate_candidate(&mut self, candidate: &TransferCandidate) -> TransferDecision {
        let verdict;
        let reason;

        if !self.config.kind_allowed(candidate.kind) {
            verdict = TransferVerdict::Rejected;
            reason = Some(TransferRejectionReason::KindBlocked);
        } else if candidate.proximity_score < self.config.min_proximity_score {
            verdict = TransferVerdict::Rejected;
            reason = Some(TransferRejectionReason::ProximityTooLow);
        } else if self.local_prior_hashes.contains(&candidate.prior_hash) {
            verdict = TransferVerdict::Rejected;
            reason = Some(TransferRejectionReason::AlreadyPresent);
        } else if self.active_transfers.len() >= self.config.max_active_transfers {
            verdict = TransferVerdict::Deferred;
            reason = Some(TransferRejectionReason::BudgetExhausted);
        } else if self.epoch_gap_too_large(candidate) {
            verdict = TransferVerdict::Rejected;
            reason = Some(TransferRejectionReason::EpochGapTooLarge);
        } else if self.in_rollback_cooldown(candidate.kind) {
            verdict = TransferVerdict::Deferred;
            reason = Some(TransferRejectionReason::RecentRollback);
        } else if candidate.donor_performance_estimate < 0 {
            verdict = TransferVerdict::Rejected;
            reason = Some(TransferRejectionReason::InsufficientEvidence);
        } else {
            verdict = TransferVerdict::Accepted;
            reason = None;
        }

        let decision_hash = self.compute_decision_hash(candidate, verdict);

        let decision = TransferDecision {
            candidate_key: candidate.candidate_key.clone(),
            verdict,
            reason,
            decision_hash: decision_hash.clone(),
            epoch: self.epoch,
        };

        if verdict == TransferVerdict::Accepted {
            self.active_transfers.push(ActiveTransfer {
                candidate_key: candidate.candidate_key.clone(),
                kind: candidate.kind,
                prior_hash: candidate.prior_hash.clone(),
                accepted_epoch: self.epoch,
                drift_signals: Vec::new(),
                observation_count: 0,
                rolled_back: false,
                decision_hash,
            });
        }

        self.decisions.push(decision.clone());
        decision
    }

    /// Record a drift observation on an active transfer.
    pub fn record_drift(&mut self, candidate_key: &str, signal: DriftSignal) -> bool {
        for transfer in &mut self.active_transfers {
            if transfer.candidate_key == candidate_key && !transfer.rolled_back {
                transfer.drift_signals.push(signal);
                transfer.observation_count += 1;
                return true;
            }
        }
        false
    }

    /// Increment observation count on an active transfer (no drift).
    pub fn record_clean_observation(&mut self, candidate_key: &str) -> bool {
        for transfer in &mut self.active_transfers {
            if transfer.candidate_key == candidate_key && !transfer.rolled_back {
                transfer.observation_count += 1;
                return true;
            }
        }
        false
    }

    /// Check all active transfers for drift and roll back as needed.
    /// Returns list of rollbacks executed.
    pub fn enforce_drift_guards(&mut self) -> Vec<TransferRollback> {
        let mut rollbacks = Vec::new();
        let tolerance = self.config.drift_tolerance;
        let min_obs = self.config.min_drift_observations;

        // Collect indices needing rollback first.
        let rollback_indices: Vec<usize> = self
            .active_transfers
            .iter()
            .enumerate()
            .filter(|(_, t)| {
                !t.rolled_back && t.observation_count >= min_obs && t.exceeds_tolerance(tolerance)
            })
            .map(|(i, _)| i)
            .collect();

        for idx in &rollback_indices {
            // Clone the needed data before taking a mutable borrow.
            let (candidate_key, kind, prior_hash, trigger_signals) = {
                let transfer = &mut self.active_transfers[*idx];
                transfer.rolled_back = true;
                let trigger_signals: Vec<DriftSignal> = transfer
                    .drift_signals
                    .iter()
                    .filter(|s| s.exceeds_tolerance(tolerance))
                    .cloned()
                    .collect();
                (
                    transfer.candidate_key.clone(),
                    transfer.kind,
                    transfer.prior_hash.clone(),
                    trigger_signals,
                )
            };

            let rollback_hash = self.compute_rollback_hash(&candidate_key, kind, &prior_hash);

            let rollback = TransferRollback {
                candidate_key,
                kind,
                rollback_epoch: self.epoch,
                trigger_signals,
                prior_hash,
                rollback_hash,
            };

            self.kind_rollback_epochs.insert(kind, self.epoch);
            rollbacks.push(rollback);
        }

        // Trim rollback history.
        for rb in &rollbacks {
            self.rollback_history.push(rb.clone());
        }
        while self.rollback_history.len() > MAX_ROLLBACK_HISTORY {
            self.rollback_history.remove(0);
        }

        rollbacks
    }

    /// Generate a transfer report summarizing the session.
    pub fn build_report(&self) -> TransferReport {
        let total_candidates = self.decisions.len() as u64;
        let accepted = self
            .decisions
            .iter()
            .filter(|d| d.verdict == TransferVerdict::Accepted)
            .count() as u64;
        let rejected = self
            .decisions
            .iter()
            .filter(|d| d.verdict == TransferVerdict::Rejected)
            .count() as u64;
        let deferred = self
            .decisions
            .iter()
            .filter(|d| d.verdict == TransferVerdict::Deferred)
            .count() as u64;

        let active_count = self
            .active_transfers
            .iter()
            .filter(|t| !t.rolled_back)
            .count() as u64;
        let rolled_back_count = self
            .active_transfers
            .iter()
            .filter(|t| t.rolled_back)
            .count() as u64;

        // Per-kind acceptance rate.
        let mut kind_stats: BTreeMap<TransferableKind, KindTransferStats> = BTreeMap::new();
        for decision in &self.decisions {
            // Find kind from active transfers or by scanning candidates.
            let kind = self
                .active_transfers
                .iter()
                .find(|t| t.candidate_key == decision.candidate_key)
                .map(|t| t.kind);
            if let Some(k) = kind {
                let entry = kind_stats.entry(k).or_default();
                entry.total += 1;
                match decision.verdict {
                    TransferVerdict::Accepted => entry.accepted += 1,
                    TransferVerdict::Rejected => entry.rejected += 1,
                    TransferVerdict::Deferred => entry.deferred += 1,
                }
            }
        }

        let worst_drift = self
            .active_transfers
            .iter()
            .map(|t| t.worst_drift_millionths())
            .max()
            .unwrap_or(0);

        let report_hash = self.compute_report_hash(total_candidates, accepted, rolled_back_count);

        TransferReport {
            session_key: self.session_key.clone(),
            epoch: self.epoch,
            total_candidates,
            accepted,
            rejected,
            deferred,
            active_count,
            rolled_back_count,
            worst_drift_millionths: worst_drift,
            kind_stats,
            report_hash,
        }
    }

    // -- Helpers ---------------------------------------------------------

    fn epoch_gap_too_large(&self, candidate: &TransferCandidate) -> bool {
        let gap = if self.epoch.as_u64() >= candidate.donor_epoch.as_u64() {
            self.epoch.as_u64() - candidate.donor_epoch.as_u64()
        } else {
            candidate.donor_epoch.as_u64() - self.epoch.as_u64()
        };
        gap > self.config.max_epoch_gap
    }

    fn in_rollback_cooldown(&self, kind: TransferableKind) -> bool {
        if let Some(last_rollback_epoch) = self.kind_rollback_epochs.get(&kind) {
            let gap = self
                .epoch
                .as_u64()
                .saturating_sub(last_rollback_epoch.as_u64());
            gap < self.config.rollback_cooldown_epochs
        } else {
            false
        }
    }

    fn compute_decision_hash(
        &self,
        candidate: &TransferCandidate,
        verdict: TransferVerdict,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(self.session_key.as_bytes());
        hasher.update(candidate.candidate_key.as_bytes());
        hasher.update(candidate.prior_hash.as_bytes());
        hasher.update(format!("{verdict}").as_bytes());
        hasher.update(self.epoch.as_u64().to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }

    fn compute_rollback_hash(
        &self,
        candidate_key: &str,
        kind: TransferableKind,
        prior_hash: &ContentHash,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"rollback:");
        hasher.update(candidate_key.as_bytes());
        hasher.update(format!("{kind}").as_bytes());
        hasher.update(prior_hash.as_bytes());
        hasher.update(self.epoch.as_u64().to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }

    fn compute_report_hash(&self, total: u64, accepted: u64, rolled_back: u64) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(b"report:");
        hasher.update(self.session_key.as_bytes());
        hasher.update(total.to_le_bytes());
        hasher.update(accepted.to_le_bytes());
        hasher.update(rolled_back.to_le_bytes());
        hasher.update(self.epoch.as_u64().to_le_bytes());
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// KindTransferStats
// ---------------------------------------------------------------------------

/// Per-kind statistics for the transfer report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KindTransferStats {
    pub total: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub deferred: u64,
}

impl KindTransferStats {
    /// Acceptance rate in millionths.
    pub fn acceptance_rate_millionths(&self) -> i64 {
        if self.total == 0 {
            return 0;
        }
        (self.accepted as i64)
            .checked_mul(MILLION)
            .and_then(|n| n.checked_div(self.total as i64))
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// TransferReport
// ---------------------------------------------------------------------------

/// Summary of a transfer session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferReport {
    pub session_key: String,
    pub epoch: SecurityEpoch,
    pub total_candidates: u64,
    pub accepted: u64,
    pub rejected: u64,
    pub deferred: u64,
    pub active_count: u64,
    pub rolled_back_count: u64,
    pub worst_drift_millionths: i64,
    pub kind_stats: BTreeMap<TransferableKind, KindTransferStats>,
    pub report_hash: ContentHash,
}

impl TransferReport {
    /// Overall acceptance rate in millionths.
    pub fn acceptance_rate_millionths(&self) -> i64 {
        if self.total_candidates == 0 {
            return 0;
        }
        (self.accepted as i64)
            .checked_mul(MILLION)
            .and_then(|n| n.checked_div(self.total_candidates as i64))
            .unwrap_or(0)
    }

    /// Rollback rate in millionths (rolled back / accepted).
    pub fn rollback_rate_millionths(&self) -> i64 {
        if self.accepted == 0 {
            return 0;
        }
        (self.rolled_back_count as i64)
            .checked_mul(MILLION)
            .and_then(|n| n.checked_div(self.accepted as i64))
            .unwrap_or(0)
    }

    /// Whether the session is healthy: low rollback rate and moderate drift.
    pub fn is_healthy(&self) -> bool {
        self.rollback_rate_millionths() < 300_000 // < 30%
            && self.worst_drift_millionths < DEFAULT_DRIFT_TOLERANCE
    }
}

impl fmt::Display for TransferReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TransferReport(session={}, epoch={}, candidates={}, accepted={}, rejected={}, deferred={}, active={}, rolled_back={}, worst_drift={})",
            self.session_key,
            self.epoch.as_u64(),
            self.total_candidates,
            self.accepted,
            self.rejected,
            self.deferred,
            self.active_count,
            self.rolled_back_count,
            self.worst_drift_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// Evidence harness
// ---------------------------------------------------------------------------

/// Specimen for testing: creates a transfer candidate with known properties.
pub fn specimen_candidate(key: &str, kind: TransferableKind, proximity: i64) -> TransferCandidate {
    TransferCandidate {
        candidate_key: key.to_string(),
        kind,
        donor_embedding_hash: ContentHash::compute(format!("donor-{key}").as_bytes()),
        prior_hash: ContentHash::compute(format!("prior-{key}").as_bytes()),
        proximity_score: proximity,
        donor_performance_estimate: 100_000, // 10% speedup
        donor_epoch: SecurityEpoch::from_raw(1),
        donor_label: format!("donor-{key}"),
    }
}

/// Specimen drift signal.
pub fn specimen_drift_signal(kind: DriftKind, magnitude: i64, confident: bool) -> DriftSignal {
    DriftSignal {
        kind,
        magnitude_millionths: magnitude,
        observation_count: 32,
        confident,
        evidence_hash: ContentHash::compute(format!("drift-{kind}-{magnitude}").as_bytes()),
    }
}

/// Default session for testing.
pub fn specimen_session() -> TransferSession {
    TransferSession::new(
        "test-session".to_string(),
        ContentHash::compute(b"recipient"),
        SecurityEpoch::from_raw(5),
        TransferConfig::default(),
    )
}

// ---------------------------------------------------------------------------
// render helpers
// ---------------------------------------------------------------------------

/// Render a one-line summary of a transfer decision.
pub fn render_decision_summary(decision: &TransferDecision) -> String {
    match decision.verdict {
        TransferVerdict::Accepted => {
            format!(
                "[ACCEPTED] {} at epoch {}",
                decision.candidate_key,
                decision.epoch.as_u64()
            )
        }
        TransferVerdict::Rejected => {
            let reason = decision
                .reason
                .map(|r| format!("{r}"))
                .unwrap_or_else(|| "unknown".to_string());
            format!(
                "[REJECTED] {} — {} at epoch {}",
                decision.candidate_key,
                reason,
                decision.epoch.as_u64()
            )
        }
        TransferVerdict::Deferred => {
            let reason = decision
                .reason
                .map(|r| format!("{r}"))
                .unwrap_or_else(|| "unknown".to_string());
            format!(
                "[DEFERRED] {} — {} at epoch {}",
                decision.candidate_key,
                reason,
                decision.epoch.as_u64()
            )
        }
    }
}

/// Render a one-line summary of a rollback.
pub fn render_rollback_summary(rollback: &TransferRollback) -> String {
    let triggers: Vec<String> = rollback
        .trigger_signals
        .iter()
        .map(|s| format!("{}({})", s.kind, s.magnitude_millionths))
        .collect();
    format!(
        "[ROLLBACK] {} ({}) at epoch {} — triggers: [{}]",
        rollback.candidate_key,
        rollback.kind,
        rollback.rollback_epoch.as_u64(),
        triggers.join(", "),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session() -> TransferSession {
        specimen_session()
    }

    fn make_candidate(key: &str, kind: TransferableKind) -> TransferCandidate {
        specimen_candidate(key, kind, 800_000) // well above threshold
    }

    #[test]
    fn transferable_kind_display_roundtrip() {
        for kind in TransferableKind::ALL {
            let s = format!("{kind}");
            assert!(!s.is_empty(), "Display for {kind:?} should not be empty");
        }
    }

    #[test]
    fn transferable_kind_serde_roundtrip() {
        for kind in TransferableKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: TransferableKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn drift_kind_display_roundtrip() {
        for kind in DriftKind::ALL {
            let s = format!("{kind}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn drift_kind_serde_roundtrip() {
        for kind in DriftKind::ALL {
            let json = serde_json::to_string(kind).unwrap();
            let back: DriftKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*kind, back);
        }
    }

    #[test]
    fn verdict_display() {
        assert_eq!(format!("{}", TransferVerdict::Accepted), "accepted");
        assert_eq!(format!("{}", TransferVerdict::Rejected), "rejected");
        assert_eq!(format!("{}", TransferVerdict::Deferred), "deferred");
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in &[
            TransferVerdict::Accepted,
            TransferVerdict::Rejected,
            TransferVerdict::Deferred,
        ] {
            let json = serde_json::to_string(v).unwrap();
            let back: TransferVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn rejection_reason_display() {
        for r in &[
            TransferRejectionReason::ProximityTooLow,
            TransferRejectionReason::BudgetExhausted,
            TransferRejectionReason::KindBlocked,
            TransferRejectionReason::EpochGapTooLarge,
            TransferRejectionReason::AlreadyPresent,
            TransferRejectionReason::RecentRollback,
            TransferRejectionReason::InsufficientEvidence,
        ] {
            let s = format!("{r}");
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn config_default_allows_all_kinds() {
        let config = TransferConfig::default();
        for kind in TransferableKind::ALL {
            assert!(config.kind_allowed(*kind));
        }
    }

    #[test]
    fn config_blocked_kinds() {
        let mut config = TransferConfig::default();
        config.blocked_kinds.insert(TransferableKind::AotArtifact);
        assert!(!config.kind_allowed(TransferableKind::AotArtifact));
        assert!(config.kind_allowed(TransferableKind::RewritePack));
    }

    #[test]
    fn config_allowed_kinds_whitelist() {
        let mut config = TransferConfig::default();
        config.allowed_kinds.insert(TransferableKind::CacheHint);
        assert!(config.kind_allowed(TransferableKind::CacheHint));
        assert!(!config.kind_allowed(TransferableKind::RewritePack));
    }

    #[test]
    fn evaluate_candidate_accepts_good_candidate() {
        let mut session = make_session();
        let candidate = make_candidate("c1", TransferableKind::RewritePack);
        let decision = session.evaluate_candidate(&candidate);
        assert_eq!(decision.verdict, TransferVerdict::Accepted);
        assert!(decision.reason.is_none());
        assert_eq!(session.active_transfers.len(), 1);
    }

    #[test]
    fn evaluate_candidate_rejects_low_proximity() {
        let mut session = make_session();
        let candidate = specimen_candidate("c1", TransferableKind::RewritePack, 100_000);
        let decision = session.evaluate_candidate(&candidate);
        assert_eq!(decision.verdict, TransferVerdict::Rejected);
        assert_eq!(
            decision.reason,
            Some(TransferRejectionReason::ProximityTooLow)
        );
    }

    #[test]
    fn evaluate_candidate_rejects_blocked_kind() {
        let mut session = make_session();
        session
            .config
            .blocked_kinds
            .insert(TransferableKind::CacheHint);
        let candidate = make_candidate("c1", TransferableKind::CacheHint);
        let decision = session.evaluate_candidate(&candidate);
        assert_eq!(decision.verdict, TransferVerdict::Rejected);
        assert_eq!(decision.reason, Some(TransferRejectionReason::KindBlocked));
    }

    #[test]
    fn evaluate_candidate_rejects_already_present() {
        let mut session = make_session();
        let candidate = make_candidate("c1", TransferableKind::RewritePack);
        session
            .local_prior_hashes
            .insert(candidate.prior_hash.clone());
        let decision = session.evaluate_candidate(&candidate);
        assert_eq!(decision.verdict, TransferVerdict::Rejected);
        assert_eq!(
            decision.reason,
            Some(TransferRejectionReason::AlreadyPresent)
        );
    }

    #[test]
    fn evaluate_candidate_defers_when_budget_exhausted() {
        let mut session = make_session();
        session.config.max_active_transfers = 0;
        let candidate = make_candidate("c1", TransferableKind::RewritePack);
        let decision = session.evaluate_candidate(&candidate);
        assert_eq!(decision.verdict, TransferVerdict::Deferred);
        assert_eq!(
            decision.reason,
            Some(TransferRejectionReason::BudgetExhausted)
        );
    }

    #[test]
    fn evaluate_candidate_rejects_epoch_gap() {
        let mut session = make_session();
        session.config.max_epoch_gap = 1;
        let mut candidate = make_candidate("c1", TransferableKind::RewritePack);
        candidate.donor_epoch = SecurityEpoch::from_raw(0);
        // session epoch = 5, donor = 0, gap = 5 > 1
        let decision = session.evaluate_candidate(&candidate);
        assert_eq!(decision.verdict, TransferVerdict::Rejected);
        assert_eq!(
            decision.reason,
            Some(TransferRejectionReason::EpochGapTooLarge)
        );
    }

    #[test]
    fn evaluate_candidate_defers_during_rollback_cooldown() {
        let mut session = make_session();
        // Simulate a recent rollback at epoch 4; session epoch = 5, cooldown = 3
        // gap = 5 - 4 = 1 < 3, so in cooldown.
        session
            .kind_rollback_epochs
            .insert(TransferableKind::RewritePack, SecurityEpoch::from_raw(4));
        let candidate = make_candidate("c1", TransferableKind::RewritePack);
        let decision = session.evaluate_candidate(&candidate);
        assert_eq!(decision.verdict, TransferVerdict::Deferred);
        assert_eq!(
            decision.reason,
            Some(TransferRejectionReason::RecentRollback)
        );
    }

    #[test]
    fn evaluate_candidate_rejects_negative_performance() {
        let mut session = make_session();
        let mut candidate = make_candidate("c1", TransferableKind::RewritePack);
        candidate.donor_performance_estimate = -50_000;
        let decision = session.evaluate_candidate(&candidate);
        assert_eq!(decision.verdict, TransferVerdict::Rejected);
        assert_eq!(
            decision.reason,
            Some(TransferRejectionReason::InsufficientEvidence)
        );
    }

    #[test]
    fn record_drift_on_active_transfer() {
        let mut session = make_session();
        let candidate = make_candidate("c1", TransferableKind::RewritePack);
        session.evaluate_candidate(&candidate);

        let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
        assert!(session.record_drift("c1", signal));
        assert_eq!(session.active_transfers[0].drift_signals.len(), 1);
    }

    #[test]
    fn record_drift_returns_false_for_unknown_key() {
        let mut session = make_session();
        let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
        assert!(!session.record_drift("nonexistent", signal));
    }

    #[test]
    fn record_clean_observation() {
        let mut session = make_session();
        let candidate = make_candidate("c1", TransferableKind::RewritePack);
        session.evaluate_candidate(&candidate);
        assert!(session.record_clean_observation("c1"));
        assert_eq!(session.active_transfers[0].observation_count, 1);
    }

    #[test]
    fn enforce_drift_guards_rollback_on_exceeded_tolerance() {
        let mut session = make_session();
        session.config.min_drift_observations = 2;
        let candidate = make_candidate("c1", TransferableKind::RewritePack);
        session.evaluate_candidate(&candidate);

        // Add confident drift signal exceeding tolerance (150_000).
        let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
        session.record_drift("c1", signal);
        session.record_clean_observation("c1");
        session.record_clean_observation("c1");

        let rollbacks = session.enforce_drift_guards();
        assert_eq!(rollbacks.len(), 1);
        assert_eq!(rollbacks[0].candidate_key, "c1");
        assert!(session.active_transfers[0].rolled_back);
    }

    #[test]
    fn enforce_drift_guards_no_rollback_when_not_confident() {
        let mut session = make_session();
        session.config.min_drift_observations = 1;
        let candidate = make_candidate("c1", TransferableKind::RewritePack);
        session.evaluate_candidate(&candidate);

        let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, false);
        session.record_drift("c1", signal);
        session.record_clean_observation("c1");

        let rollbacks = session.enforce_drift_guards();
        assert!(rollbacks.is_empty());
    }

    #[test]
    fn enforce_drift_guards_no_rollback_below_threshold() {
        let mut session = make_session();
        session.config.min_drift_observations = 1;
        let candidate = make_candidate("c1", TransferableKind::RewritePack);
        session.evaluate_candidate(&candidate);

        let signal = specimen_drift_signal(DriftKind::CachePollution, 100_000, true);
        session.record_drift("c1", signal);
        session.record_clean_observation("c1");

        let rollbacks = session.enforce_drift_guards();
        assert!(rollbacks.is_empty());
    }

    #[test]
    fn enforce_drift_guards_no_rollback_insufficient_observations() {
        let mut session = make_session();
        // Need 16 observations (default), but only 1.
        let candidate = make_candidate("c1", TransferableKind::RewritePack);
        session.evaluate_candidate(&candidate);

        let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 300_000, true);
        session.record_drift("c1", signal);

        let rollbacks = session.enforce_drift_guards();
        assert!(rollbacks.is_empty());
    }

    #[test]
    fn build_report_empty_session() {
        let session = make_session();
        let report = session.build_report();
        assert_eq!(report.total_candidates, 0);
        assert_eq!(report.accepted, 0);
        assert_eq!(report.rejected, 0);
        assert_eq!(report.deferred, 0);
        assert_eq!(report.active_count, 0);
        assert_eq!(report.rolled_back_count, 0);
        assert!(report.is_healthy());
    }

    #[test]
    fn build_report_with_accepted_candidates() {
        let mut session = make_session();
        for i in 0..3 {
            let candidate = make_candidate(&format!("c{i}"), TransferableKind::RewritePack);
            session.evaluate_candidate(&candidate);
        }
        let report = session.build_report();
        assert_eq!(report.total_candidates, 3);
        assert_eq!(report.accepted, 3);
        assert_eq!(report.active_count, 3);
        assert!(report.is_healthy());
    }

    #[test]
    fn build_report_with_mixed_decisions() {
        let mut session = make_session();
        // One accepted.
        let c1 = make_candidate("c1", TransferableKind::RewritePack);
        session.evaluate_candidate(&c1);
        // One rejected (low proximity).
        let c2 = specimen_candidate("c2", TransferableKind::CacheHint, 100_000);
        session.evaluate_candidate(&c2);
        // One deferred (budget).
        session.config.max_active_transfers = 1;
        let c3 = make_candidate("c3", TransferableKind::TieringPrior);
        session.evaluate_candidate(&c3);

        let report = session.build_report();
        assert_eq!(report.total_candidates, 3);
        assert_eq!(report.accepted, 1);
        assert_eq!(report.rejected, 1);
        assert_eq!(report.deferred, 1);
    }

    #[test]
    fn report_acceptance_rate() {
        let mut session = make_session();
        for i in 0..4 {
            let candidate = make_candidate(&format!("c{i}"), TransferableKind::RewritePack);
            session.evaluate_candidate(&candidate);
        }
        let c5 = specimen_candidate("c5", TransferableKind::RewritePack, 100_000);
        session.evaluate_candidate(&c5); // rejected

        let report = session.build_report();
        assert_eq!(report.total_candidates, 5);
        assert_eq!(report.accepted, 4);
        assert_eq!(report.acceptance_rate_millionths(), 800_000); // 80%
    }

    #[test]
    fn report_rollback_rate() {
        let mut session = make_session();
        session.config.min_drift_observations = 1;

        let c1 = make_candidate("c1", TransferableKind::RewritePack);
        session.evaluate_candidate(&c1);
        let c2 = make_candidate("c2", TransferableKind::CacheHint);
        session.evaluate_candidate(&c2);

        let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
        session.record_drift("c1", signal);
        session.record_clean_observation("c1");
        session.enforce_drift_guards();

        let report = session.build_report();
        assert_eq!(report.accepted, 2);
        assert_eq!(report.rolled_back_count, 1);
        assert_eq!(report.rollback_rate_millionths(), 500_000); // 50%
    }

    #[test]
    fn report_is_healthy_false_when_high_rollback_rate() {
        let mut session = make_session();
        session.config.min_drift_observations = 1;

        let c1 = make_candidate("c1", TransferableKind::RewritePack);
        session.evaluate_candidate(&c1);

        let signal = specimen_drift_signal(DriftKind::CorrectnessDivergence, 500_000, true);
        session.record_drift("c1", signal);
        session.record_clean_observation("c1");
        session.enforce_drift_guards();

        let report = session.build_report();
        assert!(!report.is_healthy());
    }

    #[test]
    fn report_display() {
        let session = make_session();
        let report = session.build_report();
        let s = format!("{report}");
        assert!(s.contains("TransferReport"));
        assert!(s.contains("test-session"));
    }

    #[test]
    fn active_transfer_worst_drift() {
        let transfer = ActiveTransfer {
            candidate_key: "c1".to_string(),
            kind: TransferableKind::RewritePack,
            prior_hash: ContentHash::compute(b"test"),
            accepted_epoch: SecurityEpoch::from_raw(1),
            drift_signals: vec![
                specimen_drift_signal(DriftKind::PerformanceRegression, 50_000, true),
                specimen_drift_signal(DriftKind::CachePollution, 120_000, true),
                specimen_drift_signal(DriftKind::TypeFeedbackMismatch, 80_000, false), // not confident
            ],
            observation_count: 32,
            rolled_back: false,
            decision_hash: ContentHash::compute(b"decision"),
        };
        assert_eq!(transfer.worst_drift_millionths(), 120_000);
        assert_eq!(transfer.confident_drift_kind_count(), 2);
    }

    #[test]
    fn active_transfer_no_drift() {
        let transfer = ActiveTransfer {
            candidate_key: "c1".to_string(),
            kind: TransferableKind::CacheHint,
            prior_hash: ContentHash::compute(b"test"),
            accepted_epoch: SecurityEpoch::from_raw(1),
            drift_signals: Vec::new(),
            observation_count: 100,
            rolled_back: false,
            decision_hash: ContentHash::compute(b"decision"),
        };
        assert_eq!(transfer.worst_drift_millionths(), 0);
        assert!(!transfer.exceeds_tolerance(DEFAULT_DRIFT_TOLERANCE));
    }

    #[test]
    fn drift_signal_exceeds_tolerance() {
        let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
        assert!(signal.exceeds_tolerance(150_000));
        assert!(!signal.exceeds_tolerance(250_000));
    }

    #[test]
    fn drift_signal_not_confident_does_not_exceed() {
        let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, false);
        assert!(!signal.exceeds_tolerance(150_000));
    }

    #[test]
    fn transfer_candidate_serde_roundtrip() {
        let candidate = specimen_candidate("c1", TransferableKind::RewritePack, 800_000);
        let json = serde_json::to_string(&candidate).unwrap();
        let back: TransferCandidate = serde_json::from_str(&json).unwrap();
        assert_eq!(candidate, back);
    }

    #[test]
    fn transfer_decision_serde_roundtrip() {
        let decision = TransferDecision {
            candidate_key: "c1".to_string(),
            verdict: TransferVerdict::Rejected,
            reason: Some(TransferRejectionReason::ProximityTooLow),
            decision_hash: ContentHash::compute(b"test"),
            epoch: SecurityEpoch::from_raw(1),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let back: TransferDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    #[test]
    fn transfer_rollback_serde_roundtrip() {
        let rollback = TransferRollback {
            candidate_key: "c1".to_string(),
            kind: TransferableKind::RewritePack,
            rollback_epoch: SecurityEpoch::from_raw(5),
            trigger_signals: vec![specimen_drift_signal(
                DriftKind::PerformanceRegression,
                200_000,
                true,
            )],
            prior_hash: ContentHash::compute(b"test"),
            rollback_hash: ContentHash::compute(b"rollback"),
        };
        let json = serde_json::to_string(&rollback).unwrap();
        let back: TransferRollback = serde_json::from_str(&json).unwrap();
        assert_eq!(rollback, back);
    }

    #[test]
    fn transfer_config_serde_roundtrip() {
        let config = TransferConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: TransferConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn kind_transfer_stats_acceptance_rate() {
        let stats = KindTransferStats {
            total: 10,
            accepted: 7,
            rejected: 2,
            deferred: 1,
        };
        assert_eq!(stats.acceptance_rate_millionths(), 700_000);
    }

    #[test]
    fn kind_transfer_stats_zero_total() {
        let stats = KindTransferStats::default();
        assert_eq!(stats.acceptance_rate_millionths(), 0);
    }

    #[test]
    fn render_decision_summary_accepted() {
        let decision = TransferDecision {
            candidate_key: "c1".to_string(),
            verdict: TransferVerdict::Accepted,
            reason: None,
            decision_hash: ContentHash::compute(b"test"),
            epoch: SecurityEpoch::from_raw(5),
        };
        let summary = render_decision_summary(&decision);
        assert!(summary.contains("[ACCEPTED]"));
        assert!(summary.contains("c1"));
    }

    #[test]
    fn render_decision_summary_rejected() {
        let decision = TransferDecision {
            candidate_key: "c2".to_string(),
            verdict: TransferVerdict::Rejected,
            reason: Some(TransferRejectionReason::ProximityTooLow),
            decision_hash: ContentHash::compute(b"test"),
            epoch: SecurityEpoch::from_raw(5),
        };
        let summary = render_decision_summary(&decision);
        assert!(summary.contains("[REJECTED]"));
        assert!(summary.contains("proximity_too_low"));
    }

    #[test]
    fn render_rollback_summary_format() {
        let rollback = TransferRollback {
            candidate_key: "c1".to_string(),
            kind: TransferableKind::RewritePack,
            rollback_epoch: SecurityEpoch::from_raw(5),
            trigger_signals: vec![specimen_drift_signal(
                DriftKind::PerformanceRegression,
                200_000,
                true,
            )],
            prior_hash: ContentHash::compute(b"test"),
            rollback_hash: ContentHash::compute(b"rollback"),
        };
        let summary = render_rollback_summary(&rollback);
        assert!(summary.contains("[ROLLBACK]"));
        assert!(summary.contains("rewrite_pack"));
    }

    #[test]
    fn multiple_candidates_different_kinds() {
        let mut session = make_session();
        for kind in TransferableKind::ALL {
            let candidate = make_candidate(&format!("{kind}"), *kind);
            let decision = session.evaluate_candidate(&candidate);
            assert_eq!(decision.verdict, TransferVerdict::Accepted);
        }
        assert_eq!(session.active_transfers.len(), TransferableKind::ALL.len());
    }

    #[test]
    fn rollback_updates_cooldown_epoch() {
        let mut session = make_session();
        session.config.min_drift_observations = 1;

        let c1 = make_candidate("c1", TransferableKind::TieringPrior);
        session.evaluate_candidate(&c1);

        let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
        session.record_drift("c1", signal);
        session.record_clean_observation("c1");
        session.enforce_drift_guards();

        assert_eq!(
            session
                .kind_rollback_epochs
                .get(&TransferableKind::TieringPrior),
            Some(&SecurityEpoch::from_raw(5))
        );
    }

    #[test]
    fn rollback_history_trimmed_to_max() {
        let mut session = make_session();
        session.config.min_drift_observations = 1;

        for i in 0..(MAX_ROLLBACK_HISTORY + 4) {
            let candidate = make_candidate(&format!("c{i}"), TransferableKind::RewritePack);
            session.evaluate_candidate(&candidate);

            let signal = specimen_drift_signal(DriftKind::PerformanceRegression, 200_000, true);
            session.record_drift(&format!("c{i}"), signal);
            session.record_clean_observation(&format!("c{i}"));
            session.enforce_drift_guards();

            // Reset cooldown to allow next iteration.
            session.kind_rollback_epochs.clear();
        }

        assert!(session.rollback_history.len() <= MAX_ROLLBACK_HISTORY);
    }

    #[test]
    fn session_serde_roundtrip() {
        let mut session = make_session();
        let c1 = make_candidate("c1", TransferableKind::RewritePack);
        session.evaluate_candidate(&c1);

        let json = serde_json::to_string(&session).unwrap();
        let back: TransferSession = serde_json::from_str(&json).unwrap();
        assert_eq!(session, back);
    }

    #[test]
    fn report_serde_roundtrip() {
        let session = make_session();
        let report = session.build_report();
        let json = serde_json::to_string(&report).unwrap();
        let back: TransferReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    #[test]
    fn decision_hash_deterministic() {
        let mut s1 = make_session();
        let mut s2 = make_session();
        let c = make_candidate("c1", TransferableKind::RewritePack);
        let d1 = s1.evaluate_candidate(&c);
        let d2 = s2.evaluate_candidate(&c);
        assert_eq!(d1.decision_hash, d2.decision_hash);
    }

    #[test]
    fn record_drift_on_rolled_back_transfer_fails() {
        let mut session = make_session();
        session.config.min_drift_observations = 1;
        let c1 = make_candidate("c1", TransferableKind::RewritePack);
        session.evaluate_candidate(&c1);

        let signal = specimen_drift_signal(DriftKind::CorrectnessDivergence, 300_000, true);
        session.record_drift("c1", signal);
        session.record_clean_observation("c1");
        session.enforce_drift_guards();

        // Now try to record more drift — should fail because rolled back.
        let signal2 = specimen_drift_signal(DriftKind::CachePollution, 100_000, true);
        assert!(!session.record_drift("c1", signal2));
    }

    #[test]
    fn specimen_helpers_produce_valid_objects() {
        let c = specimen_candidate("test", TransferableKind::CacheHint, 700_000);
        assert_eq!(c.candidate_key, "test");
        assert_eq!(c.kind, TransferableKind::CacheHint);
        assert_eq!(c.proximity_score, 700_000);

        let s = specimen_drift_signal(DriftKind::EpochDrift, 50_000, false);
        assert_eq!(s.kind, DriftKind::EpochDrift);
        assert!(!s.confident);

        let session = specimen_session();
        assert_eq!(session.session_key, "test-session");
    }
}
