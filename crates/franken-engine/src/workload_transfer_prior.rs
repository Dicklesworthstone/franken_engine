#![forbid(unsafe_code)]

//! Cross-workload transfer of rewrite packs, tiering priors, and cache/AOT hints
//! with neighborhood-gated drift guards.
//!
//! Implements [RGC-612B]: uses [`NeighborhoodCertificate`] verdicts from
//! [`workload_embedding`] to decide whether optimization priors from a known
//! workload can be safely applied to a never-before-seen workload. Transfers
//! are gated by distance thresholds, epoch freshness, and post-transfer drift
//! monitors that can revoke transferred priors if runtime behavior diverges.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for transfer prior artifacts.
pub const TRANSFER_PRIOR_SCHEMA_VERSION: &str = "franken-engine.workload-transfer-prior.v1";

/// Maximum number of rules that can be transferred in a single pack.
pub const MAX_TRANSFERRED_RULES: usize = 512;

/// Default drift budget (millionths). If observed divergence exceeds this,
/// the transfer is revoked. 100_000 = 10%.
pub const DEFAULT_DRIFT_BUDGET_MILLIONTHS: i64 = 100_000;

/// Default confidence floor for transfer eligibility (millionths).
/// 700_000 = 70%.
pub const DEFAULT_CONFIDENCE_FLOOR_MILLIONTHS: i64 = 700_000;

/// Maximum age in epochs before a transferred prior is considered stale.
pub const DEFAULT_MAX_PRIOR_AGE_EPOCHS: u64 = 10;

/// Fixed-point unit: 1_000_000 = 1.0.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Transfer kind
// ---------------------------------------------------------------------------

/// What kind of optimization prior is being transferred.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum TransferKind {
    /// Rewrite-pack rules (algebraic simplifications, CSE, etc.).
    RewritePack,
    /// Tiering decisions (which functions to tier up, expected hot paths).
    TieringPrior,
    /// Code-cache / AOT compilation hints.
    CacheHint,
    /// Specialization shape priors (expected object shapes).
    ShapePrior,
    /// GC tuning priors (heap sizing, collection frequency).
    GcTuningPrior,
    /// Scheduler lane affinity priors.
    SchedulerPrior,
}

impl fmt::Display for TransferKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RewritePack => write!(f, "rewrite_pack"),
            Self::TieringPrior => write!(f, "tiering_prior"),
            Self::CacheHint => write!(f, "cache_hint"),
            Self::ShapePrior => write!(f, "shape_prior"),
            Self::GcTuningPrior => write!(f, "gc_tuning_prior"),
            Self::SchedulerPrior => write!(f, "scheduler_prior"),
        }
    }
}

// ---------------------------------------------------------------------------
// Transfer eligibility
// ---------------------------------------------------------------------------

/// Why a transfer was denied.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TransferDenialReason {
    /// Neighborhood certificate verdict was Distant.
    DistantWorkloads,
    /// Neighborhood certificate verdict was Abstained.
    CertificateAbstained,
    /// Source prior is too old (epoch gap exceeds limit).
    StalePrior,
    /// Source prior has been revoked.
    RevokedPrior,
    /// Confidence in the source prior is below floor.
    InsufficientConfidence,
    /// Transfer kind is not permitted by policy.
    KindNotPermitted,
    /// Drift budget already exhausted for this target workload.
    DriftBudgetExhausted,
    /// Maximum transferred rule count would be exceeded.
    RuleLimitExceeded,
    /// Source and target epochs are incompatible.
    EpochIncompatible,
    /// Source embedding is invalid.
    InvalidSourceEmbedding,
}

impl fmt::Display for TransferDenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DistantWorkloads => write!(f, "distant_workloads"),
            Self::CertificateAbstained => write!(f, "certificate_abstained"),
            Self::StalePrior => write!(f, "stale_prior"),
            Self::RevokedPrior => write!(f, "revoked_prior"),
            Self::InsufficientConfidence => write!(f, "insufficient_confidence"),
            Self::KindNotPermitted => write!(f, "kind_not_permitted"),
            Self::DriftBudgetExhausted => write!(f, "drift_budget_exhausted"),
            Self::RuleLimitExceeded => write!(f, "rule_limit_exceeded"),
            Self::EpochIncompatible => write!(f, "epoch_incompatible"),
            Self::InvalidSourceEmbedding => write!(f, "invalid_source_embedding"),
        }
    }
}

/// Outcome of a transfer eligibility check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferEligibility {
    /// Transfer is permitted with optional confidence discount.
    Eligible {
        /// Confidence in the transfer (millionths, ≤ 1_000_000).
        confidence_millionths: i64,
        /// Whether this is a marginal transfer that needs extra monitoring.
        marginal: bool,
    },
    /// Transfer is denied.
    Denied {
        reason: TransferDenialReason,
    },
}

impl TransferEligibility {
    pub fn is_eligible(&self) -> bool {
        matches!(self, Self::Eligible { .. })
    }

    pub fn is_marginal(&self) -> bool {
        matches!(self, Self::Eligible { marginal: true, .. })
    }

    pub fn confidence(&self) -> Option<i64> {
        match self {
            Self::Eligible { confidence_millionths, .. } => Some(*confidence_millionths),
            Self::Denied { .. } => None,
        }
    }
}

impl fmt::Display for TransferEligibility {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Eligible { confidence_millionths, marginal } => {
                write!(f, "eligible(confidence={}, marginal={})", confidence_millionths, marginal)
            }
            Self::Denied { reason } => write!(f, "denied({})", reason),
        }
    }
}

// ---------------------------------------------------------------------------
// Transfer policy
// ---------------------------------------------------------------------------

/// Configuration for transfer eligibility and drift monitoring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferPolicy {
    /// Schema version.
    pub schema_version: String,
    /// Which transfer kinds are permitted.
    pub permitted_kinds: BTreeSet<TransferKind>,
    /// Maximum epoch gap between source prior and current epoch.
    pub max_prior_age_epochs: u64,
    /// Minimum confidence for the source prior (millionths).
    pub confidence_floor_millionths: i64,
    /// Drift budget per target workload (millionths).
    pub drift_budget_millionths: i64,
    /// Maximum number of rules transferred per target workload.
    pub max_transferred_rules: usize,
    /// Whether marginal neighborhood certificates allow transfer (with discount).
    pub allow_marginal_transfer: bool,
    /// Confidence discount for marginal transfers (millionths subtracted from confidence).
    pub marginal_discount_millionths: i64,
    /// Whether to require post-transfer drift monitoring.
    pub require_drift_monitoring: bool,
}

impl Default for TransferPolicy {
    fn default() -> Self {
        let mut permitted = BTreeSet::new();
        permitted.insert(TransferKind::RewritePack);
        permitted.insert(TransferKind::TieringPrior);
        permitted.insert(TransferKind::CacheHint);
        permitted.insert(TransferKind::ShapePrior);
        permitted.insert(TransferKind::GcTuningPrior);
        permitted.insert(TransferKind::SchedulerPrior);
        Self {
            schema_version: TRANSFER_PRIOR_SCHEMA_VERSION.to_string(),
            permitted_kinds: permitted,
            max_prior_age_epochs: DEFAULT_MAX_PRIOR_AGE_EPOCHS,
            confidence_floor_millionths: DEFAULT_CONFIDENCE_FLOOR_MILLIONTHS,
            drift_budget_millionths: DEFAULT_DRIFT_BUDGET_MILLIONTHS,
            max_transferred_rules: MAX_TRANSFERRED_RULES,
            allow_marginal_transfer: true,
            marginal_discount_millionths: 200_000, // 20% discount
            require_drift_monitoring: true,
        }
    }
}

impl TransferPolicy {
    /// Content hash of this policy for audit trails.
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = self.schema_version.as_bytes().to_vec();
        for kind in &self.permitted_kinds {
            buf.extend_from_slice(kind.to_string().as_bytes());
        }
        buf.extend_from_slice(&self.max_prior_age_epochs.to_le_bytes());
        buf.extend_from_slice(&self.confidence_floor_millionths.to_le_bytes());
        buf.extend_from_slice(&self.drift_budget_millionths.to_le_bytes());
        buf.extend_from_slice(&(self.max_transferred_rules as u64).to_le_bytes());
        buf.push(if self.allow_marginal_transfer { 1 } else { 0 });
        buf.extend_from_slice(&self.marginal_discount_millionths.to_le_bytes());
        buf.push(if self.require_drift_monitoring { 1 } else { 0 });
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// Prior entry
// ---------------------------------------------------------------------------

/// A single transferable optimization prior from a source workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorEntry {
    /// Unique identifier for this prior.
    pub prior_id: String,
    /// What kind of prior this is.
    pub kind: TransferKind,
    /// Source workload embedding ID.
    pub source_embedding_id: String,
    /// Epoch when the prior was created.
    pub source_epoch: SecurityEpoch,
    /// Confidence in the prior's effectiveness (millionths).
    pub confidence_millionths: i64,
    /// Number of observations backing this prior.
    pub observation_count: u64,
    /// Rule-level details (opaque to transfer layer; interpreted by consumers).
    pub rule_keys: Vec<String>,
    /// Number of rules in this prior.
    pub rule_count: usize,
    /// Whether this prior has been revoked.
    pub revoked: bool,
    /// Content hash of the underlying optimization artifact.
    pub artifact_hash: ContentHash,
}

impl PriorEntry {
    /// Check if this prior is fresh enough relative to the current epoch.
    pub fn is_fresh(&self, current_epoch: SecurityEpoch, max_age: u64) -> bool {
        let gap = current_epoch.as_u64().saturating_sub(self.source_epoch.as_u64());
        gap <= max_age
    }

    /// Check if this prior meets the confidence floor.
    pub fn meets_confidence(&self, floor_millionths: i64) -> bool {
        self.confidence_millionths >= floor_millionths
    }
}

// ---------------------------------------------------------------------------
// Transfer record
// ---------------------------------------------------------------------------

/// Status of a transferred prior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum TransferStatus {
    /// Transfer is active and being used.
    Active,
    /// Transfer is under drift monitoring (probationary).
    Probationary,
    /// Transfer was revoked due to drift.
    RevokedDrift,
    /// Transfer was revoked due to epoch expiry.
    RevokedStale,
    /// Transfer was manually revoked by operator.
    RevokedManual,
    /// Transfer completed successfully (no longer needed).
    Completed,
}

impl fmt::Display for TransferStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "active"),
            Self::Probationary => write!(f, "probationary"),
            Self::RevokedDrift => write!(f, "revoked_drift"),
            Self::RevokedStale => write!(f, "revoked_stale"),
            Self::RevokedManual => write!(f, "revoked_manual"),
            Self::Completed => write!(f, "completed"),
        }
    }
}

impl TransferStatus {
    /// Whether this status means the transfer is currently in use.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active | Self::Probationary)
    }

    /// Whether this status means the transfer was revoked for any reason.
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::RevokedDrift | Self::RevokedStale | Self::RevokedManual)
    }
}

/// A record of a completed or in-progress transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferRecord {
    /// Unique transfer ID.
    pub transfer_id: String,
    /// The prior that was transferred.
    pub prior_id: String,
    /// Source workload embedding ID.
    pub source_embedding_id: String,
    /// Target workload embedding ID.
    pub target_embedding_id: String,
    /// Neighborhood certificate ID that authorized this transfer.
    pub certificate_id: String,
    /// Transfer kind.
    pub kind: TransferKind,
    /// Current status.
    pub status: TransferStatus,
    /// Eligibility at transfer time.
    pub eligibility: TransferEligibility,
    /// Epoch when the transfer was initiated.
    pub transfer_epoch: SecurityEpoch,
    /// Number of rules transferred.
    pub rules_transferred: usize,
    /// Accumulated drift (millionths).
    pub accumulated_drift_millionths: i64,
    /// Number of drift observations collected.
    pub drift_observations: u64,
    /// Content hash of the transfer record.
    pub content_hash: ContentHash,
}

impl TransferRecord {
    /// Compute a deterministic content hash for this record.
    pub fn compute_hash(&self) -> ContentHash {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.transfer_id.as_bytes());
        buf.extend_from_slice(self.prior_id.as_bytes());
        buf.extend_from_slice(self.source_embedding_id.as_bytes());
        buf.extend_from_slice(self.target_embedding_id.as_bytes());
        buf.extend_from_slice(self.certificate_id.as_bytes());
        buf.extend_from_slice(self.kind.to_string().as_bytes());
        buf.extend_from_slice(self.status.to_string().as_bytes());
        buf.extend_from_slice(&self.transfer_epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(&(self.rules_transferred as u64).to_le_bytes());
        buf.extend_from_slice(&self.accumulated_drift_millionths.to_le_bytes());
        buf.extend_from_slice(&self.drift_observations.to_le_bytes());
        ContentHash::compute(&buf)
    }
}

// ---------------------------------------------------------------------------
// Drift observation
// ---------------------------------------------------------------------------

/// A single drift observation after transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DriftObservation {
    /// Transfer ID this observation belongs to.
    pub transfer_id: String,
    /// Metric name (e.g. "execution_time_millionths", "gc_pressure_millionths").
    pub metric_name: String,
    /// Expected value from the source prior (millionths).
    pub expected_millionths: i64,
    /// Observed value on the target workload (millionths).
    pub observed_millionths: i64,
    /// Absolute divergence (millionths).
    pub divergence_millionths: i64,
    /// Epoch of observation.
    pub observation_epoch: SecurityEpoch,
    /// Tick timestamp.
    pub tick: u64,
}

impl DriftObservation {
    /// Create a new drift observation, computing divergence automatically.
    pub fn new(
        transfer_id: &str,
        metric_name: &str,
        expected_millionths: i64,
        observed_millionths: i64,
        epoch: SecurityEpoch,
        tick: u64,
    ) -> Self {
        let divergence = (observed_millionths - expected_millionths).abs();
        Self {
            transfer_id: transfer_id.to_string(),
            metric_name: metric_name.to_string(),
            expected_millionths,
            observed_millionths,
            divergence_millionths: divergence,
            observation_epoch: epoch,
            tick,
        }
    }

    /// Whether this observation exceeds a given budget.
    pub fn exceeds_budget(&self, budget_millionths: i64) -> bool {
        self.divergence_millionths > budget_millionths
    }
}

// ---------------------------------------------------------------------------
// Drift verdict
// ---------------------------------------------------------------------------

/// Aggregate drift verdict for a transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DriftVerdict {
    /// Drift is within budget; transfer remains valid.
    WithinBudget {
        /// Current accumulated drift (millionths).
        accumulated_millionths: i64,
        /// Remaining budget (millionths).
        remaining_millionths: i64,
    },
    /// Drift exceeds budget; transfer should be revoked.
    BudgetExceeded {
        /// Accumulated drift (millionths).
        accumulated_millionths: i64,
        /// Budget that was exceeded (millionths).
        budget_millionths: i64,
        /// Which metric triggered the breach.
        trigger_metric: String,
    },
    /// Not enough observations to judge.
    InsufficientData {
        /// Observations collected so far.
        observations: u64,
        /// Minimum required.
        minimum_required: u64,
    },
}

impl fmt::Display for DriftVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WithinBudget { accumulated_millionths, remaining_millionths } => {
                write!(f, "within_budget(drift={}, remaining={})", accumulated_millionths, remaining_millionths)
            }
            Self::BudgetExceeded { accumulated_millionths, budget_millionths, trigger_metric } => {
                write!(f, "budget_exceeded(drift={}, budget={}, trigger={})",
                    accumulated_millionths, budget_millionths, trigger_metric)
            }
            Self::InsufficientData { observations, minimum_required } => {
                write!(f, "insufficient_data(obs={}, min={})", observations, minimum_required)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Transfer error
// ---------------------------------------------------------------------------

/// Errors that can occur during transfer operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransferError {
    /// Prior not found.
    PriorNotFound { prior_id: String },
    /// Transfer not found.
    TransferNotFound { transfer_id: String },
    /// Transfer is not in an active state.
    TransferNotActive { transfer_id: String, status: TransferStatus },
    /// Policy violation.
    PolicyViolation { reason: TransferDenialReason },
    /// Duplicate transfer ID.
    DuplicateTransfer { transfer_id: String },
    /// Duplicate prior ID.
    DuplicatePrior { prior_id: String },
    /// Certificate verdict does not permit transfer.
    CertificateRejection { certificate_id: String },
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PriorNotFound { prior_id } => write!(f, "prior not found: {}", prior_id),
            Self::TransferNotFound { transfer_id } => write!(f, "transfer not found: {}", transfer_id),
            Self::TransferNotActive { transfer_id, status } => {
                write!(f, "transfer {} not active (status={})", transfer_id, status)
            }
            Self::PolicyViolation { reason } => write!(f, "policy violation: {}", reason),
            Self::DuplicateTransfer { transfer_id } => write!(f, "duplicate transfer: {}", transfer_id),
            Self::DuplicatePrior { prior_id } => write!(f, "duplicate prior: {}", prior_id),
            Self::CertificateRejection { certificate_id } => {
                write!(f, "certificate rejected transfer: {}", certificate_id)
            }
        }
    }
}

impl std::error::Error for TransferError {}

// ---------------------------------------------------------------------------
// Revocation receipt
// ---------------------------------------------------------------------------

/// A signed receipt recording the revocation of a transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationReceipt {
    /// Transfer ID that was revoked.
    pub transfer_id: String,
    /// Why it was revoked.
    pub reason: TransferStatus,
    /// Drift verdict at revocation time (if drift-triggered).
    pub drift_verdict: Option<DriftVerdict>,
    /// Epoch of revocation.
    pub revocation_epoch: SecurityEpoch,
    /// Tick timestamp.
    pub tick: u64,
    /// Content hash of the receipt.
    pub content_hash: ContentHash,
    /// Signature for audit.
    pub signature: ContentHash,
}

impl RevocationReceipt {
    /// Compute the signing preimage for this receipt.
    fn signing_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.transfer_id.as_bytes());
        buf.extend_from_slice(self.reason.to_string().as_bytes());
        buf.extend_from_slice(&self.revocation_epoch.as_u64().to_le_bytes());
        buf.extend_from_slice(&self.tick.to_le_bytes());
        buf.extend_from_slice(self.content_hash.as_bytes());
        buf
    }

    /// Verify the signature against a key.
    pub fn verify_signature(&self, key: &[u8]) -> bool {
        let preimage = self.signing_preimage();
        let expected = ContentHash::compute(&[&preimage, key].concat());
        self.signature == expected
    }

    /// Sign this receipt with a key.
    pub fn sign(mut self, key: &[u8]) -> Self {
        let preimage = self.signing_preimage();
        self.signature = ContentHash::compute(&[&preimage, key].concat());
        self
    }
}

// ---------------------------------------------------------------------------
// Transfer summary
// ---------------------------------------------------------------------------

/// Aggregate summary of all transfers for a target workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferSummary {
    /// Target workload embedding ID.
    pub target_embedding_id: String,
    /// Total active transfers.
    pub active_count: usize,
    /// Total probationary transfers.
    pub probationary_count: usize,
    /// Total revoked transfers.
    pub revoked_count: usize,
    /// Total completed transfers.
    pub completed_count: usize,
    /// Total rules currently active from transfers.
    pub active_rules: usize,
    /// Per-kind breakdown of active transfers.
    pub kind_breakdown: BTreeMap<String, usize>,
    /// Maximum observed drift across all active transfers (millionths).
    pub max_drift_millionths: i64,
    /// Epoch of summary computation.
    pub summary_epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Transfer engine
// ---------------------------------------------------------------------------

/// The transfer engine manages prior registration, eligibility checks,
/// transfer execution, drift monitoring, and revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferEngine {
    /// Active policy.
    policy: TransferPolicy,
    /// Registered priors by prior_id.
    priors: BTreeMap<String, PriorEntry>,
    /// Transfer records by transfer_id.
    transfers: BTreeMap<String, TransferRecord>,
    /// Revocation receipts by transfer_id.
    revocations: BTreeMap<String, RevocationReceipt>,
    /// Per-target accumulated drift budgets: target_embedding_id -> used drift.
    target_drift_used: BTreeMap<String, i64>,
    /// Per-target rule counts: target_embedding_id -> active rule count.
    target_rule_counts: BTreeMap<String, usize>,
    /// Current epoch.
    current_epoch: SecurityEpoch,
    /// Monotonic tick counter.
    tick: u64,
}

impl TransferEngine {
    /// Create a new transfer engine with the given policy.
    pub fn new(policy: TransferPolicy, epoch: SecurityEpoch) -> Self {
        Self {
            policy,
            priors: BTreeMap::new(),
            transfers: BTreeMap::new(),
            revocations: BTreeMap::new(),
            target_drift_used: BTreeMap::new(),
            target_rule_counts: BTreeMap::new(),
            current_epoch: epoch,
            tick: 0,
        }
    }

    /// Create with default policy.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(TransferPolicy::default(), epoch)
    }

    /// Advance the epoch.
    pub fn advance_epoch(&mut self, epoch: SecurityEpoch) {
        self.current_epoch = epoch;
    }

    /// Get the current policy.
    pub fn policy(&self) -> &TransferPolicy {
        &self.policy
    }

    /// Update the policy.
    pub fn set_policy(&mut self, policy: TransferPolicy) {
        self.policy = policy;
    }

    /// Register a prior entry. Returns error if duplicate.
    pub fn register_prior(&mut self, prior: PriorEntry) -> Result<(), TransferError> {
        if self.priors.contains_key(&prior.prior_id) {
            return Err(TransferError::DuplicatePrior {
                prior_id: prior.prior_id,
            });
        }
        self.priors.insert(prior.prior_id.clone(), prior);
        Ok(())
    }

    /// Get a prior by ID.
    pub fn get_prior(&self, prior_id: &str) -> Option<&PriorEntry> {
        self.priors.get(prior_id)
    }

    /// Get a transfer record by ID.
    pub fn get_transfer(&self, transfer_id: &str) -> Option<&TransferRecord> {
        self.transfers.get(transfer_id)
    }

    /// Get a revocation receipt by transfer ID.
    pub fn get_revocation(&self, transfer_id: &str) -> Option<&RevocationReceipt> {
        self.revocations.get(transfer_id)
    }

    /// Number of registered priors.
    pub fn prior_count(&self) -> usize {
        self.priors.len()
    }

    /// Number of active transfers.
    pub fn active_transfer_count(&self) -> usize {
        self.transfers.values().filter(|t| t.status.is_active()).count()
    }

    /// Number of revoked transfers.
    pub fn revoked_transfer_count(&self) -> usize {
        self.transfers.values().filter(|t| t.status.is_revoked()).count()
    }

    /// Check eligibility for transferring a prior to a target workload.
    ///
    /// `certificate_verdict_near` should be true if the neighborhood certificate
    /// says Near, false if Marginal.
    /// `certificate_abstained` should be true if the certificate abstained.
    /// `certificate_distant` should be true if the certificate says Distant.
    pub fn check_eligibility(
        &self,
        prior_id: &str,
        target_embedding_id: &str,
        certificate_near: bool,
        certificate_marginal: bool,
        certificate_abstained: bool,
    ) -> Result<TransferEligibility, TransferError> {
        let prior = self.priors.get(prior_id).ok_or_else(|| TransferError::PriorNotFound {
            prior_id: prior_id.to_string(),
        })?;

        // Check kind is permitted
        if !self.policy.permitted_kinds.contains(&prior.kind) {
            return Ok(TransferEligibility::Denied {
                reason: TransferDenialReason::KindNotPermitted,
            });
        }

        // Check revocation
        if prior.revoked {
            return Ok(TransferEligibility::Denied {
                reason: TransferDenialReason::RevokedPrior,
            });
        }

        // Check freshness
        if !prior.is_fresh(self.current_epoch, self.policy.max_prior_age_epochs) {
            return Ok(TransferEligibility::Denied {
                reason: TransferDenialReason::StalePrior,
            });
        }

        // Check confidence
        if !prior.meets_confidence(self.policy.confidence_floor_millionths) {
            return Ok(TransferEligibility::Denied {
                reason: TransferDenialReason::InsufficientConfidence,
            });
        }

        // Check certificate verdict
        if certificate_abstained {
            return Ok(TransferEligibility::Denied {
                reason: TransferDenialReason::CertificateAbstained,
            });
        }
        if !certificate_near && !certificate_marginal {
            return Ok(TransferEligibility::Denied {
                reason: TransferDenialReason::DistantWorkloads,
            });
        }
        if certificate_marginal && !self.policy.allow_marginal_transfer {
            return Ok(TransferEligibility::Denied {
                reason: TransferDenialReason::DistantWorkloads,
            });
        }

        // Check drift budget
        let used_drift = self.target_drift_used.get(target_embedding_id).copied().unwrap_or(0);
        if used_drift >= self.policy.drift_budget_millionths {
            return Ok(TransferEligibility::Denied {
                reason: TransferDenialReason::DriftBudgetExhausted,
            });
        }

        // Check rule limits
        let current_rules = self.target_rule_counts.get(target_embedding_id).copied().unwrap_or(0);
        if current_rules + prior.rule_count > self.policy.max_transferred_rules {
            return Ok(TransferEligibility::Denied {
                reason: TransferDenialReason::RuleLimitExceeded,
            });
        }

        // Compute confidence with optional marginal discount
        let mut confidence = prior.confidence_millionths;
        let marginal = certificate_marginal && !certificate_near;
        if marginal {
            confidence = confidence.saturating_sub(self.policy.marginal_discount_millionths);
            if confidence < self.policy.confidence_floor_millionths {
                return Ok(TransferEligibility::Denied {
                    reason: TransferDenialReason::InsufficientConfidence,
                });
            }
        }

        Ok(TransferEligibility::Eligible {
            confidence_millionths: confidence,
            marginal,
        })
    }

    /// Execute a transfer: create a transfer record if eligible.
    pub fn execute_transfer(
        &mut self,
        transfer_id: &str,
        prior_id: &str,
        target_embedding_id: &str,
        certificate_id: &str,
        certificate_near: bool,
        certificate_marginal: bool,
        certificate_abstained: bool,
    ) -> Result<TransferRecord, TransferError> {
        // Check for duplicate
        if self.transfers.contains_key(transfer_id) {
            return Err(TransferError::DuplicateTransfer {
                transfer_id: transfer_id.to_string(),
            });
        }

        // Check eligibility
        let eligibility = self.check_eligibility(
            prior_id,
            target_embedding_id,
            certificate_near,
            certificate_marginal,
            certificate_abstained,
        )?;

        if !eligibility.is_eligible() {
            if let TransferEligibility::Denied { reason } = eligibility {
                return Err(TransferError::PolicyViolation { reason });
            }
        }

        let prior = self.priors.get(prior_id).ok_or_else(|| TransferError::PriorNotFound {
            prior_id: prior_id.to_string(),
        })?;

        self.tick += 1;

        let status = if eligibility.is_marginal() || self.policy.require_drift_monitoring {
            TransferStatus::Probationary
        } else {
            TransferStatus::Active
        };

        let record = TransferRecord {
            transfer_id: transfer_id.to_string(),
            prior_id: prior_id.to_string(),
            source_embedding_id: prior.source_embedding_id.clone(),
            target_embedding_id: target_embedding_id.to_string(),
            certificate_id: certificate_id.to_string(),
            kind: prior.kind,
            status,
            eligibility,
            transfer_epoch: self.current_epoch,
            rules_transferred: prior.rule_count,
            accumulated_drift_millionths: 0,
            drift_observations: 0,
            content_hash: ContentHash::compute(transfer_id.as_bytes()),
        };

        // Update accounting
        let rule_count = self.target_rule_counts.entry(target_embedding_id.to_string()).or_insert(0);
        *rule_count += prior.rule_count;

        let record_clone = record.clone();
        self.transfers.insert(transfer_id.to_string(), record);

        Ok(record_clone)
    }

    /// Record a drift observation for an active transfer.
    pub fn record_drift(
        &mut self,
        observation: DriftObservation,
    ) -> Result<DriftVerdict, TransferError> {
        let transfer = self.transfers.get_mut(&observation.transfer_id).ok_or_else(|| {
            TransferError::TransferNotFound {
                transfer_id: observation.transfer_id.clone(),
            }
        })?;

        if !transfer.status.is_active() {
            return Err(TransferError::TransferNotActive {
                transfer_id: observation.transfer_id.clone(),
                status: transfer.status,
            });
        }

        // Update accumulated drift using weighted moving average
        transfer.drift_observations += 1;
        let weight = MILLION / transfer.drift_observations as i64;
        let old_weight = MILLION - weight;
        transfer.accumulated_drift_millionths =
            (transfer.accumulated_drift_millionths.saturating_mul(old_weight) / MILLION)
                .saturating_add(observation.divergence_millionths.saturating_mul(weight) / MILLION);

        // Update target drift budget
        let target_drift = self
            .target_drift_used
            .entry(transfer.target_embedding_id.clone())
            .or_insert(0);
        *target_drift = (*target_drift).max(transfer.accumulated_drift_millionths);

        // Evaluate drift verdict
        if transfer.accumulated_drift_millionths > self.policy.drift_budget_millionths {
            let verdict = DriftVerdict::BudgetExceeded {
                accumulated_millionths: transfer.accumulated_drift_millionths,
                budget_millionths: self.policy.drift_budget_millionths,
                trigger_metric: observation.metric_name.clone(),
            };

            // Auto-revoke
            transfer.status = TransferStatus::RevokedDrift;

            // Reclaim rule budget
            if let Some(count) = self.target_rule_counts.get_mut(&transfer.target_embedding_id) {
                *count = count.saturating_sub(transfer.rules_transferred);
            }

            self.tick += 1;
            let receipt = RevocationReceipt {
                transfer_id: observation.transfer_id.clone(),
                reason: TransferStatus::RevokedDrift,
                drift_verdict: Some(verdict.clone()),
                revocation_epoch: self.current_epoch,
                tick: self.tick,
                content_hash: ContentHash::compute(observation.transfer_id.as_bytes()),
                signature: ContentHash::compute(b"unsigned"),
            };
            self.revocations.insert(observation.transfer_id, receipt);

            Ok(verdict)
        } else {
            Ok(DriftVerdict::WithinBudget {
                accumulated_millionths: transfer.accumulated_drift_millionths,
                remaining_millionths: self.policy.drift_budget_millionths
                    - transfer.accumulated_drift_millionths,
            })
        }
    }

    /// Promote a probationary transfer to active status.
    pub fn promote_transfer(&mut self, transfer_id: &str) -> Result<(), TransferError> {
        let transfer = self.transfers.get_mut(transfer_id).ok_or_else(|| {
            TransferError::TransferNotFound {
                transfer_id: transfer_id.to_string(),
            }
        })?;
        if transfer.status != TransferStatus::Probationary {
            return Err(TransferError::TransferNotActive {
                transfer_id: transfer_id.to_string(),
                status: transfer.status,
            });
        }
        transfer.status = TransferStatus::Active;
        Ok(())
    }

    /// Manually revoke a transfer.
    pub fn revoke_transfer(&mut self, transfer_id: &str) -> Result<RevocationReceipt, TransferError> {
        let transfer = self.transfers.get_mut(transfer_id).ok_or_else(|| {
            TransferError::TransferNotFound {
                transfer_id: transfer_id.to_string(),
            }
        })?;
        if !transfer.status.is_active() {
            return Err(TransferError::TransferNotActive {
                transfer_id: transfer_id.to_string(),
                status: transfer.status,
            });
        }

        transfer.status = TransferStatus::RevokedManual;

        // Reclaim rule budget
        if let Some(count) = self.target_rule_counts.get_mut(&transfer.target_embedding_id) {
            *count = count.saturating_sub(transfer.rules_transferred);
        }

        self.tick += 1;
        let receipt = RevocationReceipt {
            transfer_id: transfer_id.to_string(),
            reason: TransferStatus::RevokedManual,
            drift_verdict: None,
            revocation_epoch: self.current_epoch,
            tick: self.tick,
            content_hash: ContentHash::compute(transfer_id.as_bytes()),
            signature: ContentHash::compute(b"unsigned"),
        };
        self.revocations.insert(transfer_id.to_string(), receipt.clone());
        Ok(receipt)
    }

    /// Mark a transfer as completed (target workload has gathered its own priors).
    pub fn complete_transfer(&mut self, transfer_id: &str) -> Result<(), TransferError> {
        let transfer = self.transfers.get_mut(transfer_id).ok_or_else(|| {
            TransferError::TransferNotFound {
                transfer_id: transfer_id.to_string(),
            }
        })?;
        if !transfer.status.is_active() {
            return Err(TransferError::TransferNotActive {
                transfer_id: transfer_id.to_string(),
                status: transfer.status,
            });
        }
        transfer.status = TransferStatus::Completed;

        // Reclaim rule budget
        if let Some(count) = self.target_rule_counts.get_mut(&transfer.target_embedding_id) {
            *count = count.saturating_sub(transfer.rules_transferred);
        }

        Ok(())
    }

    /// Expire stale priors based on current epoch.
    pub fn expire_stale_priors(&mut self) -> Vec<String> {
        let mut expired = Vec::new();
        for (tid, transfer) in &mut self.transfers {
            if transfer.status.is_active() {
                let prior = self.priors.get(&transfer.prior_id);
                let stale = prior.map_or(true, |p| {
                    !p.is_fresh(self.current_epoch, self.policy.max_prior_age_epochs)
                });
                if stale {
                    transfer.status = TransferStatus::RevokedStale;
                    expired.push(tid.clone());
                }
            }
        }

        // Reclaim rule budgets for expired transfers
        for tid in &expired {
            if let Some(transfer) = self.transfers.get(tid) {
                if let Some(count) = self.target_rule_counts.get_mut(&transfer.target_embedding_id) {
                    *count = count.saturating_sub(transfer.rules_transferred);
                }
            }
        }

        expired
    }

    /// Compute a summary for a target workload.
    pub fn summarize_target(&self, target_embedding_id: &str) -> TransferSummary {
        let mut active_count = 0;
        let mut probationary_count = 0;
        let mut revoked_count = 0;
        let mut completed_count = 0;
        let mut active_rules = 0;
        let mut kind_breakdown: BTreeMap<String, usize> = BTreeMap::new();
        let mut max_drift: i64 = 0;

        for transfer in self.transfers.values() {
            if transfer.target_embedding_id != target_embedding_id {
                continue;
            }
            match transfer.status {
                TransferStatus::Active => {
                    active_count += 1;
                    active_rules += transfer.rules_transferred;
                    *kind_breakdown.entry(transfer.kind.to_string()).or_insert(0) += 1;
                    max_drift = max_drift.max(transfer.accumulated_drift_millionths);
                }
                TransferStatus::Probationary => {
                    probationary_count += 1;
                    active_rules += transfer.rules_transferred;
                    *kind_breakdown.entry(transfer.kind.to_string()).or_insert(0) += 1;
                    max_drift = max_drift.max(transfer.accumulated_drift_millionths);
                }
                TransferStatus::RevokedDrift
                | TransferStatus::RevokedStale
                | TransferStatus::RevokedManual => {
                    revoked_count += 1;
                }
                TransferStatus::Completed => {
                    completed_count += 1;
                }
            }
        }

        TransferSummary {
            target_embedding_id: target_embedding_id.to_string(),
            active_count,
            probationary_count,
            revoked_count,
            completed_count,
            active_rules,
            kind_breakdown,
            max_drift_millionths: max_drift,
            summary_epoch: self.current_epoch,
        }
    }

    /// List all active transfer IDs for a target workload.
    pub fn active_transfers_for(&self, target_embedding_id: &str) -> Vec<String> {
        self.transfers
            .values()
            .filter(|t| t.target_embedding_id == target_embedding_id && t.status.is_active())
            .map(|t| t.transfer_id.clone())
            .collect()
    }

    /// Collect an evidence inventory of all transfers.
    pub fn evidence_inventory(&self) -> TransferEvidenceInventory {
        let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
        let mut by_status: BTreeMap<String, usize> = BTreeMap::new();

        for transfer in self.transfers.values() {
            *by_kind.entry(transfer.kind.to_string()).or_insert(0) += 1;
            *by_status.entry(transfer.status.to_string()).or_insert(0) += 1;
        }

        TransferEvidenceInventory {
            schema_version: TRANSFER_PRIOR_SCHEMA_VERSION.to_string(),
            total_priors: self.priors.len(),
            total_transfers: self.transfers.len(),
            total_revocations: self.revocations.len(),
            by_kind,
            by_status,
            policy_hash: self.policy.content_hash(),
            epoch: self.current_epoch,
        }
    }
}

/// Evidence inventory for audit and governance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferEvidenceInventory {
    /// Schema version.
    pub schema_version: String,
    /// Total registered priors.
    pub total_priors: usize,
    /// Total transfer records.
    pub total_transfers: usize,
    /// Total revocation receipts.
    pub total_revocations: usize,
    /// Transfers by kind.
    pub by_kind: BTreeMap<String, usize>,
    /// Transfers by status.
    pub by_status: BTreeMap<String, usize>,
    /// Policy content hash.
    pub policy_hash: ContentHash,
    /// Epoch of inventory.
    pub epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn test_hash(label: &str) -> ContentHash {
        ContentHash::compute(label.as_bytes())
    }

    fn make_prior(id: &str, kind: TransferKind, epoch: u64, confidence: i64, rules: usize) -> PriorEntry {
        PriorEntry {
            prior_id: id.to_string(),
            kind,
            source_embedding_id: format!("emb-src-{}", id),
            source_epoch: test_epoch(epoch),
            confidence_millionths: confidence,
            observation_count: 100,
            rule_keys: (0..rules).map(|i| format!("rule-{}", i)).collect(),
            rule_count: rules,
            revoked: false,
            artifact_hash: test_hash(id),
        }
    }

    fn default_engine(epoch: u64) -> TransferEngine {
        TransferEngine::with_defaults(test_epoch(epoch))
    }

    // -- TransferKind Display --

    #[test]
    fn test_transfer_kind_display() {
        assert_eq!(TransferKind::RewritePack.to_string(), "rewrite_pack");
        assert_eq!(TransferKind::TieringPrior.to_string(), "tiering_prior");
        assert_eq!(TransferKind::CacheHint.to_string(), "cache_hint");
        assert_eq!(TransferKind::ShapePrior.to_string(), "shape_prior");
        assert_eq!(TransferKind::GcTuningPrior.to_string(), "gc_tuning_prior");
        assert_eq!(TransferKind::SchedulerPrior.to_string(), "scheduler_prior");
    }

    // -- TransferDenialReason Display --

    #[test]
    fn test_denial_reason_display() {
        assert_eq!(TransferDenialReason::DistantWorkloads.to_string(), "distant_workloads");
        assert_eq!(TransferDenialReason::StalePrior.to_string(), "stale_prior");
        assert_eq!(TransferDenialReason::RevokedPrior.to_string(), "revoked_prior");
        assert_eq!(TransferDenialReason::DriftBudgetExhausted.to_string(), "drift_budget_exhausted");
    }

    // -- TransferEligibility --

    #[test]
    fn test_eligibility_eligible() {
        let e = TransferEligibility::Eligible {
            confidence_millionths: 900_000,
            marginal: false,
        };
        assert!(e.is_eligible());
        assert!(!e.is_marginal());
        assert_eq!(e.confidence(), Some(900_000));
    }

    #[test]
    fn test_eligibility_marginal() {
        let e = TransferEligibility::Eligible {
            confidence_millionths: 700_000,
            marginal: true,
        };
        assert!(e.is_eligible());
        assert!(e.is_marginal());
    }

    #[test]
    fn test_eligibility_denied() {
        let e = TransferEligibility::Denied {
            reason: TransferDenialReason::StalePrior,
        };
        assert!(!e.is_eligible());
        assert!(!e.is_marginal());
        assert_eq!(e.confidence(), None);
    }

    #[test]
    fn test_eligibility_display() {
        let e = TransferEligibility::Eligible {
            confidence_millionths: 900_000,
            marginal: false,
        };
        assert!(e.to_string().contains("eligible"));

        let d = TransferEligibility::Denied {
            reason: TransferDenialReason::DistantWorkloads,
        };
        assert!(d.to_string().contains("denied"));
    }

    // -- TransferPolicy --

    #[test]
    fn test_default_policy() {
        let p = TransferPolicy::default();
        assert_eq!(p.permitted_kinds.len(), 6);
        assert!(p.permitted_kinds.contains(&TransferKind::RewritePack));
        assert!(p.allow_marginal_transfer);
        assert!(p.require_drift_monitoring);
    }

    #[test]
    fn test_policy_content_hash_deterministic() {
        let p1 = TransferPolicy::default();
        let p2 = TransferPolicy::default();
        assert_eq!(p1.content_hash(), p2.content_hash());
    }

    #[test]
    fn test_policy_content_hash_changes() {
        let p1 = TransferPolicy::default();
        let mut p2 = TransferPolicy::default();
        p2.max_prior_age_epochs = 99;
        assert_ne!(p1.content_hash(), p2.content_hash());
    }

    // -- PriorEntry --

    #[test]
    fn test_prior_freshness() {
        let prior = make_prior("p1", TransferKind::RewritePack, 5, 900_000, 10);
        assert!(prior.is_fresh(test_epoch(10), 10));
        assert!(prior.is_fresh(test_epoch(15), 10));
        assert!(!prior.is_fresh(test_epoch(16), 10));
    }

    #[test]
    fn test_prior_confidence() {
        let prior = make_prior("p1", TransferKind::RewritePack, 5, 900_000, 10);
        assert!(prior.meets_confidence(700_000));
        assert!(prior.meets_confidence(900_000));
        assert!(!prior.meets_confidence(900_001));
    }

    // -- TransferStatus --

    #[test]
    fn test_transfer_status_active() {
        assert!(TransferStatus::Active.is_active());
        assert!(TransferStatus::Probationary.is_active());
        assert!(!TransferStatus::RevokedDrift.is_active());
        assert!(!TransferStatus::Completed.is_active());
    }

    #[test]
    fn test_transfer_status_revoked() {
        assert!(TransferStatus::RevokedDrift.is_revoked());
        assert!(TransferStatus::RevokedStale.is_revoked());
        assert!(TransferStatus::RevokedManual.is_revoked());
        assert!(!TransferStatus::Active.is_revoked());
        assert!(!TransferStatus::Completed.is_revoked());
    }

    #[test]
    fn test_transfer_status_display() {
        assert_eq!(TransferStatus::Active.to_string(), "active");
        assert_eq!(TransferStatus::Probationary.to_string(), "probationary");
        assert_eq!(TransferStatus::RevokedDrift.to_string(), "revoked_drift");
    }

    // -- DriftObservation --

    #[test]
    fn test_drift_observation_new() {
        let obs = DriftObservation::new("t1", "exec_time", 500_000, 600_000, test_epoch(5), 42);
        assert_eq!(obs.divergence_millionths, 100_000);
        assert!(!obs.exceeds_budget(200_000));
        assert!(obs.exceeds_budget(50_000));
    }

    #[test]
    fn test_drift_observation_negative_divergence() {
        let obs = DriftObservation::new("t1", "exec_time", 600_000, 500_000, test_epoch(5), 42);
        assert_eq!(obs.divergence_millionths, 100_000); // abs
    }

    // -- DriftVerdict Display --

    #[test]
    fn test_drift_verdict_display() {
        let v = DriftVerdict::WithinBudget {
            accumulated_millionths: 50_000,
            remaining_millionths: 50_000,
        };
        assert!(v.to_string().contains("within_budget"));

        let v2 = DriftVerdict::BudgetExceeded {
            accumulated_millionths: 150_000,
            budget_millionths: 100_000,
            trigger_metric: "exec_time".to_string(),
        };
        assert!(v2.to_string().contains("budget_exceeded"));
    }

    // -- TransferError Display --

    #[test]
    fn test_transfer_error_display() {
        let e = TransferError::PriorNotFound { prior_id: "p1".to_string() };
        assert!(e.to_string().contains("p1"));

        let e2 = TransferError::PolicyViolation {
            reason: TransferDenialReason::StalePrior,
        };
        assert!(e2.to_string().contains("stale_prior"));
    }

    // -- TransferRecord --

    #[test]
    fn test_transfer_record_compute_hash() {
        let record = TransferRecord {
            transfer_id: "t1".to_string(),
            prior_id: "p1".to_string(),
            source_embedding_id: "src".to_string(),
            target_embedding_id: "tgt".to_string(),
            certificate_id: "cert1".to_string(),
            kind: TransferKind::RewritePack,
            status: TransferStatus::Active,
            eligibility: TransferEligibility::Eligible {
                confidence_millionths: 900_000,
                marginal: false,
            },
            transfer_epoch: test_epoch(5),
            rules_transferred: 10,
            accumulated_drift_millionths: 0,
            drift_observations: 0,
            content_hash: test_hash("t1"),
        };
        let h1 = record.compute_hash();
        let h2 = record.compute_hash();
        assert_eq!(h1, h2);
    }

    // -- RevocationReceipt --

    #[test]
    fn test_revocation_receipt_sign_verify() {
        let key = b"test-key";
        let receipt = RevocationReceipt {
            transfer_id: "t1".to_string(),
            reason: TransferStatus::RevokedManual,
            drift_verdict: None,
            revocation_epoch: test_epoch(5),
            tick: 42,
            content_hash: test_hash("t1"),
            signature: test_hash("unsigned"),
        };
        let signed = receipt.sign(key);
        assert!(signed.verify_signature(key));
        assert!(!signed.verify_signature(b"wrong-key"));
    }

    // -- TransferEngine: registration --

    #[test]
    fn test_register_prior() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        assert!(engine.register_prior(prior).is_ok());
        assert_eq!(engine.prior_count(), 1);
    }

    #[test]
    fn test_register_duplicate_prior() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior.clone()).unwrap();
        let result = engine.register_prior(prior);
        assert!(matches!(result, Err(TransferError::DuplicatePrior { .. })));
    }

    // -- TransferEngine: eligibility --

    #[test]
    fn test_eligibility_near_certificate() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();

        let result = engine.check_eligibility("p1", "tgt1", true, false, false).unwrap();
        assert!(result.is_eligible());
        assert!(!result.is_marginal());
    }

    #[test]
    fn test_eligibility_marginal_certificate() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();

        let result = engine.check_eligibility("p1", "tgt1", false, true, false).unwrap();
        assert!(result.is_eligible());
        assert!(result.is_marginal());
        // Confidence should be discounted
        assert_eq!(result.confidence(), Some(700_000)); // 900k - 200k discount
    }

    #[test]
    fn test_eligibility_distant_denied() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();

        let result = engine.check_eligibility("p1", "tgt1", false, false, false).unwrap();
        assert!(!result.is_eligible());
    }

    #[test]
    fn test_eligibility_abstained_denied() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();

        let result = engine.check_eligibility("p1", "tgt1", false, false, true).unwrap();
        assert!(matches!(
            result,
            TransferEligibility::Denied { reason: TransferDenialReason::CertificateAbstained }
        ));
    }

    #[test]
    fn test_eligibility_stale_prior() {
        let mut engine = default_engine(100); // epoch 100, prior at epoch 3
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();

        let result = engine.check_eligibility("p1", "tgt1", true, false, false).unwrap();
        assert!(matches!(
            result,
            TransferEligibility::Denied { reason: TransferDenialReason::StalePrior }
        ));
    }

    #[test]
    fn test_eligibility_revoked_prior() {
        let mut engine = default_engine(5);
        let mut prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        prior.revoked = true;
        engine.register_prior(prior).unwrap();

        let result = engine.check_eligibility("p1", "tgt1", true, false, false).unwrap();
        assert!(matches!(
            result,
            TransferEligibility::Denied { reason: TransferDenialReason::RevokedPrior }
        ));
    }

    #[test]
    fn test_eligibility_insufficient_confidence() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 500_000, 10); // below 700k floor
        engine.register_prior(prior).unwrap();

        let result = engine.check_eligibility("p1", "tgt1", true, false, false).unwrap();
        assert!(matches!(
            result,
            TransferEligibility::Denied { reason: TransferDenialReason::InsufficientConfidence }
        ));
    }

    #[test]
    fn test_eligibility_kind_not_permitted() {
        let mut policy = TransferPolicy::default();
        policy.permitted_kinds.remove(&TransferKind::GcTuningPrior);
        let mut engine = TransferEngine::new(policy, test_epoch(5));
        let prior = make_prior("p1", TransferKind::GcTuningPrior, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();

        let result = engine.check_eligibility("p1", "tgt1", true, false, false).unwrap();
        assert!(matches!(
            result,
            TransferEligibility::Denied { reason: TransferDenialReason::KindNotPermitted }
        ));
    }

    #[test]
    fn test_eligibility_rule_limit() {
        let mut policy = TransferPolicy::default();
        policy.max_transferred_rules = 5;
        let mut engine = TransferEngine::new(policy, test_epoch(5));
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10); // 10 rules > 5 limit
        engine.register_prior(prior).unwrap();

        let result = engine.check_eligibility("p1", "tgt1", true, false, false).unwrap();
        assert!(matches!(
            result,
            TransferEligibility::Denied { reason: TransferDenialReason::RuleLimitExceeded }
        ));
    }

    #[test]
    fn test_eligibility_prior_not_found() {
        let engine = default_engine(5);
        let result = engine.check_eligibility("nonexistent", "tgt1", true, false, false);
        assert!(matches!(result, Err(TransferError::PriorNotFound { .. })));
    }

    // -- TransferEngine: execute --

    #[test]
    fn test_execute_transfer_success() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();

        let record = engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();
        assert_eq!(record.transfer_id, "t1");
        assert_eq!(record.rules_transferred, 10);
        // Default policy requires drift monitoring, so status should be Probationary
        assert_eq!(record.status, TransferStatus::Probationary);
        assert_eq!(engine.active_transfer_count(), 1);
    }

    #[test]
    fn test_execute_transfer_duplicate() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();

        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();
        let result = engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false);
        assert!(matches!(result, Err(TransferError::DuplicateTransfer { .. })));
    }

    #[test]
    fn test_execute_transfer_denied() {
        let mut engine = default_engine(100);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10); // stale
        engine.register_prior(prior).unwrap();

        let result = engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false);
        assert!(matches!(result, Err(TransferError::PolicyViolation { .. })));
    }

    // -- TransferEngine: drift monitoring --

    #[test]
    fn test_record_drift_within_budget() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();

        let obs = DriftObservation::new("t1", "exec_time", 500_000, 510_000, test_epoch(5), 1);
        let verdict = engine.record_drift(obs).unwrap();
        assert!(matches!(verdict, DriftVerdict::WithinBudget { .. }));
    }

    #[test]
    fn test_record_drift_exceeds_budget() {
        let mut policy = TransferPolicy::default();
        policy.drift_budget_millionths = 50_000; // tight budget
        policy.require_drift_monitoring = false;
        let mut engine = TransferEngine::new(policy, test_epoch(5));
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();

        let obs = DriftObservation::new("t1", "exec_time", 500_000, 700_000, test_epoch(5), 1);
        let verdict = engine.record_drift(obs).unwrap();
        assert!(matches!(verdict, DriftVerdict::BudgetExceeded { .. }));

        // Transfer should be revoked
        let transfer = engine.get_transfer("t1").unwrap();
        assert_eq!(transfer.status, TransferStatus::RevokedDrift);
        assert!(engine.get_revocation("t1").is_some());
    }

    #[test]
    fn test_record_drift_not_active() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();
        engine.revoke_transfer("t1").unwrap();

        let obs = DriftObservation::new("t1", "exec_time", 500_000, 510_000, test_epoch(5), 1);
        let result = engine.record_drift(obs);
        assert!(matches!(result, Err(TransferError::TransferNotActive { .. })));
    }

    // -- TransferEngine: promote --

    #[test]
    fn test_promote_probationary() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();

        assert_eq!(engine.get_transfer("t1").unwrap().status, TransferStatus::Probationary);
        engine.promote_transfer("t1").unwrap();
        assert_eq!(engine.get_transfer("t1").unwrap().status, TransferStatus::Active);
    }

    #[test]
    fn test_promote_non_probationary_fails() {
        let mut policy = TransferPolicy::default();
        policy.require_drift_monitoring = false;
        let mut engine = TransferEngine::new(policy, test_epoch(5));
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();

        // Already Active, not Probationary
        let result = engine.promote_transfer("t1");
        assert!(matches!(result, Err(TransferError::TransferNotActive { .. })));
    }

    // -- TransferEngine: revoke --

    #[test]
    fn test_revoke_transfer() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();

        let receipt = engine.revoke_transfer("t1").unwrap();
        assert_eq!(receipt.reason, TransferStatus::RevokedManual);
        assert_eq!(engine.revoked_transfer_count(), 1);
    }

    #[test]
    fn test_revoke_already_revoked() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();
        engine.revoke_transfer("t1").unwrap();

        let result = engine.revoke_transfer("t1");
        assert!(matches!(result, Err(TransferError::TransferNotActive { .. })));
    }

    // -- TransferEngine: complete --

    #[test]
    fn test_complete_transfer() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();

        engine.complete_transfer("t1").unwrap();
        let transfer = engine.get_transfer("t1").unwrap();
        assert_eq!(transfer.status, TransferStatus::Completed);
    }

    // -- TransferEngine: expire stale --

    #[test]
    fn test_expire_stale_priors() {
        let mut engine = default_engine(5);
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();

        // Advance epoch past staleness threshold
        engine.advance_epoch(test_epoch(100));
        let expired = engine.expire_stale_priors();
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0], "t1");

        let transfer = engine.get_transfer("t1").unwrap();
        assert_eq!(transfer.status, TransferStatus::RevokedStale);
    }

    // -- TransferEngine: summary --

    #[test]
    fn test_summarize_target() {
        let mut engine = default_engine(5);
        let p1 = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        let p2 = make_prior("p2", TransferKind::TieringPrior, 3, 800_000, 5);
        engine.register_prior(p1).unwrap();
        engine.register_prior(p2).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();
        engine.execute_transfer("t2", "p2", "tgt1", "cert2", true, false, false).unwrap();

        let summary = engine.summarize_target("tgt1");
        assert_eq!(summary.probationary_count, 2);
        assert_eq!(summary.active_rules, 15);
        assert_eq!(summary.kind_breakdown.len(), 2);
    }

    #[test]
    fn test_summarize_empty_target() {
        let engine = default_engine(5);
        let summary = engine.summarize_target("nonexistent");
        assert_eq!(summary.active_count, 0);
        assert_eq!(summary.active_rules, 0);
    }

    // -- TransferEngine: active transfers --

    #[test]
    fn test_active_transfers_for() {
        let mut engine = default_engine(5);
        let p1 = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        let p2 = make_prior("p2", TransferKind::CacheHint, 3, 800_000, 5);
        engine.register_prior(p1).unwrap();
        engine.register_prior(p2).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();
        engine.execute_transfer("t2", "p2", "tgt1", "cert2", true, false, false).unwrap();
        engine.execute_transfer("t3", "p1", "tgt2", "cert3", true, false, false).unwrap();

        let active = engine.active_transfers_for("tgt1");
        assert_eq!(active.len(), 2);
    }

    // -- TransferEngine: evidence inventory --

    #[test]
    fn test_evidence_inventory() {
        let mut engine = default_engine(5);
        let p1 = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(p1).unwrap();
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();

        let inv = engine.evidence_inventory();
        assert_eq!(inv.total_priors, 1);
        assert_eq!(inv.total_transfers, 1);
        assert_eq!(inv.total_revocations, 0);
        assert_eq!(inv.schema_version, TRANSFER_PRIOR_SCHEMA_VERSION);
    }

    // -- Serde roundtrips --

    #[test]
    fn test_serde_transfer_kind() {
        let kind = TransferKind::RewritePack;
        let json = serde_json::to_string(&kind).unwrap();
        let back: TransferKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }

    #[test]
    fn test_serde_transfer_policy() {
        let policy = TransferPolicy::default();
        let json = serde_json::to_string(&policy).unwrap();
        let back: TransferPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, back);
    }

    #[test]
    fn test_serde_prior_entry() {
        let prior = make_prior("p1", TransferKind::CacheHint, 3, 900_000, 10);
        let json = serde_json::to_string(&prior).unwrap();
        let back: PriorEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(prior, back);
    }

    #[test]
    fn test_serde_transfer_record() {
        let record = TransferRecord {
            transfer_id: "t1".to_string(),
            prior_id: "p1".to_string(),
            source_embedding_id: "src".to_string(),
            target_embedding_id: "tgt".to_string(),
            certificate_id: "cert1".to_string(),
            kind: TransferKind::RewritePack,
            status: TransferStatus::Probationary,
            eligibility: TransferEligibility::Eligible {
                confidence_millionths: 900_000,
                marginal: false,
            },
            transfer_epoch: test_epoch(5),
            rules_transferred: 10,
            accumulated_drift_millionths: 0,
            drift_observations: 0,
            content_hash: test_hash("t1"),
        };
        let json = serde_json::to_string(&record).unwrap();
        let back: TransferRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn test_serde_drift_observation() {
        let obs = DriftObservation::new("t1", "exec_time", 500_000, 510_000, test_epoch(5), 1);
        let json = serde_json::to_string(&obs).unwrap();
        let back: DriftObservation = serde_json::from_str(&json).unwrap();
        assert_eq!(obs, back);
    }

    #[test]
    fn test_serde_drift_verdict() {
        let v = DriftVerdict::BudgetExceeded {
            accumulated_millionths: 150_000,
            budget_millionths: 100_000,
            trigger_metric: "exec_time".to_string(),
        };
        let json = serde_json::to_string(&v).unwrap();
        let back: DriftVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn test_serde_revocation_receipt() {
        let receipt = RevocationReceipt {
            transfer_id: "t1".to_string(),
            reason: TransferStatus::RevokedDrift,
            drift_verdict: Some(DriftVerdict::BudgetExceeded {
                accumulated_millionths: 150_000,
                budget_millionths: 100_000,
                trigger_metric: "gc_pressure".to_string(),
            }),
            revocation_epoch: test_epoch(10),
            tick: 42,
            content_hash: test_hash("t1"),
            signature: test_hash("sig"),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let back: RevocationReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn test_serde_transfer_summary() {
        let summary = TransferSummary {
            target_embedding_id: "tgt1".to_string(),
            active_count: 2,
            probationary_count: 1,
            revoked_count: 0,
            completed_count: 0,
            active_rules: 15,
            kind_breakdown: BTreeMap::new(),
            max_drift_millionths: 50_000,
            summary_epoch: test_epoch(5),
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: TransferSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn test_serde_evidence_inventory() {
        let inv = TransferEvidenceInventory {
            schema_version: TRANSFER_PRIOR_SCHEMA_VERSION.to_string(),
            total_priors: 5,
            total_transfers: 3,
            total_revocations: 1,
            by_kind: BTreeMap::new(),
            by_status: BTreeMap::new(),
            policy_hash: test_hash("policy"),
            epoch: test_epoch(10),
        };
        let json = serde_json::to_string(&inv).unwrap();
        let back: TransferEvidenceInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }

    // -- Multi-transfer pipeline --

    #[test]
    fn test_full_transfer_lifecycle() {
        let mut engine = default_engine(5);
        let p1 = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(p1).unwrap();

        // Execute
        let record = engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();
        assert_eq!(record.status, TransferStatus::Probationary);

        // Record drift within budget
        let obs1 = DriftObservation::new("t1", "exec_time", 500_000, 510_000, test_epoch(5), 1);
        let v1 = engine.record_drift(obs1).unwrap();
        assert!(matches!(v1, DriftVerdict::WithinBudget { .. }));

        // Promote
        engine.promote_transfer("t1").unwrap();
        assert_eq!(engine.get_transfer("t1").unwrap().status, TransferStatus::Active);

        // Complete
        engine.complete_transfer("t1").unwrap();
        assert_eq!(engine.get_transfer("t1").unwrap().status, TransferStatus::Completed);
    }

    #[test]
    fn test_rule_budget_accounting() {
        let mut policy = TransferPolicy::default();
        policy.max_transferred_rules = 20;
        let mut engine = TransferEngine::new(policy, test_epoch(5));

        let p1 = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 15);
        let p2 = make_prior("p2", TransferKind::CacheHint, 3, 900_000, 10);
        engine.register_prior(p1).unwrap();
        engine.register_prior(p2).unwrap();

        // First transfer: 15 rules
        engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();

        // Second transfer would exceed 20 rule limit (15 + 10 = 25 > 20)
        let result = engine.execute_transfer("t2", "p2", "tgt1", "cert2", true, false, false);
        assert!(matches!(result, Err(TransferError::PolicyViolation {
            reason: TransferDenialReason::RuleLimitExceeded
        })));

        // Revoke first transfer, freeing budget
        engine.revoke_transfer("t1").unwrap();

        // Now second transfer should succeed (0 + 10 ≤ 20)
        let record = engine.execute_transfer("t2", "p2", "tgt1", "cert2", true, false, false).unwrap();
        assert_eq!(record.rules_transferred, 10);
    }

    #[test]
    fn test_marginal_transfer_disabled() {
        let mut policy = TransferPolicy::default();
        policy.allow_marginal_transfer = false;
        let mut engine = TransferEngine::new(policy, test_epoch(5));
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();

        let result = engine.check_eligibility("p1", "tgt1", false, true, false).unwrap();
        assert!(matches!(
            result,
            TransferEligibility::Denied { reason: TransferDenialReason::DistantWorkloads }
        ));
    }

    #[test]
    fn test_no_monitoring_gives_active() {
        let mut policy = TransferPolicy::default();
        policy.require_drift_monitoring = false;
        let mut engine = TransferEngine::new(policy, test_epoch(5));
        let prior = make_prior("p1", TransferKind::RewritePack, 3, 900_000, 10);
        engine.register_prior(prior).unwrap();

        let record = engine.execute_transfer("t1", "p1", "tgt1", "cert1", true, false, false).unwrap();
        assert_eq!(record.status, TransferStatus::Active);
    }
}
