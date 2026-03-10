#![forbid(unsafe_code)]

//! Transfer Governance Gate — RGC-612C
//!
//! Bead: bd-1lsy.7.12.3
//!
//! Wires workload-transfer evidence into benchmark-board coverage, rollout
//! gating, and published supremacy claims.  Transfer governance ensures that
//! priors from one workload neighborhood actually apply to other regions:
//! generalization quality is measured rather than assumed.
//!
//! # Design
//!
//! - `TransferEvidence` captures the fidelity with which a policy, heuristic,
//!   or prior transfers from a source workload to a target workload.
//! - `evaluate_transfer` classifies evidence into a `TransferVerdict` based
//!   on fidelity thresholds and drift detection.
//! - `CoverageRecord` tracks which workload regions have validated transfer
//!   evidence, enabling `evaluate_coverage` to produce a `CoverageLevel`.
//! - `evaluate_rollout` aggregates transfer evidence into a `RolloutGateResult`
//!   that gates deployment on sufficient cross-workload generalization.
//! - `SupremacyConstraint` downgrades published supremacy claims when transfer
//!   coverage is incomplete or drift is detected.
//! - `evaluate_batch` processes a batch of transfer evidence and returns
//!   per-evidence governance decisions plus a `GovernanceSummary`.
//!
//! All fractional arithmetic uses fixed-point millionths (1_000_000 = 1.0).

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for transfer governance artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.transfer-governance-gate.v1";

/// Component name used in evidence records and receipts.
pub const COMPONENT: &str = "transfer_governance_gate";

/// Bead identifier originating this module.
pub const BEAD_ID: &str = "bd-1lsy.7.12.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-612C";

/// One in fixed-point millionths.
const MILLION: u64 = 1_000_000;

/// Default high-fidelity threshold in millionths.  900_000 = 90%.
pub const DEFAULT_HIGH_FIDELITY_THRESHOLD: u64 = 900_000;

/// Default moderate-fidelity threshold in millionths.  700_000 = 70%.
pub const DEFAULT_MODERATE_FIDELITY_THRESHOLD: u64 = 700_000;

/// Default drift alarm threshold in millionths.  200_000 = 20%.
pub const DEFAULT_DRIFT_ALARM_THRESHOLD: u64 = 200_000;

/// Default minimum sample count for evidence to be considered sufficient.
pub const DEFAULT_MIN_SAMPLE_COUNT: u64 = 30;

/// Default minimum coverage fraction in millionths.  800_000 = 80%.
pub const DEFAULT_MIN_COVERAGE_FRACTION: u64 = 800_000;

/// Default maximum batch size for governance evaluation.
pub const DEFAULT_MAX_BATCH_SIZE: usize = 512;

/// Sparse threshold: coverage fractions below this are Sparse.  300_000 = 30%.
const SPARSE_THRESHOLD: u64 = 300_000;

/// Partial threshold: coverage fractions below this are Partial.  700_000 = 70%.
const PARTIAL_THRESHOLD: u64 = 700_000;

// ---------------------------------------------------------------------------
// TransferDomain
// ---------------------------------------------------------------------------

/// Domain of knowledge being transferred across workload neighborhoods.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDomain {
    /// Rewrite priors: optimization transformations learned from one workload.
    RewritePrior,
    /// Tiering policies: hot/cold/lukewarm tier boundaries.
    TieringPolicy,
    /// Cache policies: eviction strategies and admission heuristics.
    CachePolicy,
    /// Scheduling heuristics: task ordering and priority learned from profiling.
    SchedulingHeuristic,
    /// Inlining decisions: call-site inlining thresholds and budget splits.
    InliningDecision,
    /// Specialization strategies: type-specialization selections.
    SpecializationStrategy,
}

impl TransferDomain {
    /// All variants in canonical order.
    pub const ALL: &[Self] = &[
        Self::RewritePrior,
        Self::TieringPolicy,
        Self::CachePolicy,
        Self::SchedulingHeuristic,
        Self::InliningDecision,
        Self::SpecializationStrategy,
    ];

    /// Human-readable label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RewritePrior => "rewrite_prior",
            Self::TieringPolicy => "tiering_policy",
            Self::CachePolicy => "cache_policy",
            Self::SchedulingHeuristic => "scheduling_heuristic",
            Self::InliningDecision => "inlining_decision",
            Self::SpecializationStrategy => "specialization_strategy",
        }
    }
}

impl fmt::Display for TransferDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TransferVerdict
// ---------------------------------------------------------------------------

/// Verdict from evaluating a single piece of transfer evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferVerdict {
    /// Transfer fidelity is above the high threshold — fully validated.
    Validated,
    /// Transfer fidelity is between moderate and high thresholds.
    ConditionallyValid,
    /// Drift magnitude exceeds alarm threshold.
    DriftDetected,
    /// Transfer fidelity is below moderate threshold.
    Rejected,
    /// Not enough samples to draw a conclusion.
    InsufficientEvidence,
}

impl TransferVerdict {
    /// Human-readable label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Validated => "validated",
            Self::ConditionallyValid => "conditionally_valid",
            Self::DriftDetected => "drift_detected",
            Self::Rejected => "rejected",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }

    /// Whether this verdict permits rollout without conditions.
    #[must_use]
    pub const fn allows_unconditional_rollout(&self) -> bool {
        matches!(self, Self::Validated)
    }
}

impl fmt::Display for TransferVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CoverageLevel
// ---------------------------------------------------------------------------

/// How thoroughly the transfer evidence covers target workload regions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageLevel {
    /// All target regions have validated transfer evidence.
    Full,
    /// Most regions covered but some gaps remain.
    Partial,
    /// Significant uncovered regions.
    Sparse,
    /// No coverage evidence available.
    Uncovered,
}

impl CoverageLevel {
    /// Human-readable label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::Sparse => "sparse",
            Self::Uncovered => "uncovered",
        }
    }

    /// Whether this level is sufficient for rollout.
    #[must_use]
    pub const fn sufficient_for_rollout(&self) -> bool {
        matches!(self, Self::Full | Self::Partial)
    }
}

impl fmt::Display for CoverageLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GovernanceAction
// ---------------------------------------------------------------------------

/// Action prescribed by the governance gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceAction {
    /// Rollout is safe — transfer evidence validates generalization.
    AllowRollout,
    /// Rollout is permitted with conditions (e.g., canary-only).
    ConditionalRollout,
    /// Rollout is blocked until evidence improves.
    BlockRollout,
    /// Existing evidence is stale; fresh measurements required.
    RequireFreshEvidence,
    /// Published supremacy claim must be downgraded.
    DowngradeSupremacy,
}

impl GovernanceAction {
    /// Human-readable label.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::AllowRollout => "allow_rollout",
            Self::ConditionalRollout => "conditional_rollout",
            Self::BlockRollout => "block_rollout",
            Self::RequireFreshEvidence => "require_fresh_evidence",
            Self::DowngradeSupremacy => "downgrade_supremacy",
        }
    }
}

impl fmt::Display for GovernanceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// TransferEvidence
// ---------------------------------------------------------------------------

/// Evidence of how well a prior transfers from source to target workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferEvidence {
    /// Domain of the transferred prior.
    pub domain: TransferDomain,
    /// Source workload identifier.
    pub source_workload_id: String,
    /// Target workload identifier.
    pub target_workload_id: String,
    /// Transfer fidelity in millionths (1_000_000 = perfect transfer).
    pub transfer_fidelity: u64,
    /// Drift magnitude in millionths (0 = no drift).
    pub drift_magnitude: u64,
    /// Number of samples used to measure fidelity.
    pub sample_count: u64,
    /// Security epoch when evidence was collected.
    pub epoch: SecurityEpoch,
    /// Content hash of this evidence for deterministic identity.
    pub evidence_hash: ContentHash,
}

impl TransferEvidence {
    /// Create new transfer evidence, computing its content hash.
    #[must_use]
    pub fn new(
        domain: TransferDomain,
        source_workload_id: &str,
        target_workload_id: &str,
        transfer_fidelity: u64,
        drift_magnitude: u64,
        sample_count: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        let evidence_hash = Self::compute_hash(
            domain,
            source_workload_id,
            target_workload_id,
            transfer_fidelity,
            drift_magnitude,
            sample_count,
            epoch,
        );
        Self {
            domain,
            source_workload_id: source_workload_id.to_string(),
            target_workload_id: target_workload_id.to_string(),
            transfer_fidelity,
            drift_magnitude,
            sample_count,
            epoch,
            evidence_hash,
        }
    }

    fn compute_hash(
        domain: TransferDomain,
        source: &str,
        target: &str,
        fidelity: u64,
        drift: u64,
        samples: u64,
        epoch: SecurityEpoch,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(domain.as_str().as_bytes());
        hasher.update(source.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update(fidelity.to_le_bytes());
        hasher.update(drift.to_le_bytes());
        hasher.update(samples.to_le_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        let result = hasher.finalize();
        ContentHash::compute(&result)
    }
}

impl fmt::Display for TransferEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TransferEvidence({} {}->{}  fidelity={} drift={} n={})",
            self.domain,
            self.source_workload_id,
            self.target_workload_id,
            self.transfer_fidelity,
            self.drift_magnitude,
            self.sample_count,
        )
    }
}

// ---------------------------------------------------------------------------
// CoverageRecord
// ---------------------------------------------------------------------------

/// Record of transfer coverage for a particular workload region.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageRecord {
    /// Domain being covered.
    pub domain: TransferDomain,
    /// Identifier of the workload region.
    pub region_id: String,
    /// Level of coverage for this region.
    pub coverage_level: CoverageLevel,
    /// Hash of the transfer evidence supporting this coverage.
    pub transfer_evidence_hash: ContentHash,
    /// Last epoch in which this coverage was validated.
    pub last_validated_epoch: SecurityEpoch,
}

impl CoverageRecord {
    /// Create a new coverage record.
    #[must_use]
    pub fn new(
        domain: TransferDomain,
        region_id: &str,
        coverage_level: CoverageLevel,
        transfer_evidence_hash: ContentHash,
        last_validated_epoch: SecurityEpoch,
    ) -> Self {
        Self {
            domain,
            region_id: region_id.to_string(),
            coverage_level,
            transfer_evidence_hash,
            last_validated_epoch,
        }
    }

    /// Content hash of this record.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(self.domain.as_str().as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.region_id.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.coverage_level.as_str().as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.transfer_evidence_hash.as_bytes());
        buf.extend_from_slice(&self.last_validated_epoch.as_u64().to_le_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for CoverageRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Coverage({} region={} level={})",
            self.domain, self.region_id, self.coverage_level,
        )
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the transfer governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum fidelity for Validated verdict (millionths).
    pub min_transfer_fidelity_high: u64,
    /// Minimum fidelity for ConditionallyValid verdict (millionths).
    pub min_transfer_fidelity_moderate: u64,
    /// Drift magnitude above which DriftDetected is raised (millionths).
    pub drift_alarm_threshold: u64,
    /// Minimum sample count for evidence to be considered sufficient.
    pub min_sample_count: u64,
    /// Minimum coverage fraction for rollout (millionths).
    pub min_coverage_fraction: u64,
    /// Maximum batch size.
    pub max_batch_size: usize,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_transfer_fidelity_high: DEFAULT_HIGH_FIDELITY_THRESHOLD,
            min_transfer_fidelity_moderate: DEFAULT_MODERATE_FIDELITY_THRESHOLD,
            drift_alarm_threshold: DEFAULT_DRIFT_ALARM_THRESHOLD,
            min_sample_count: DEFAULT_MIN_SAMPLE_COUNT,
            min_coverage_fraction: DEFAULT_MIN_COVERAGE_FRACTION,
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
        }
    }
}

impl fmt::Display for GateConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GateConfig(high={} mod={} drift={} min_n={} cov={})",
            self.min_transfer_fidelity_high,
            self.min_transfer_fidelity_moderate,
            self.drift_alarm_threshold,
            self.min_sample_count,
            self.min_coverage_fraction,
        )
    }
}

// ---------------------------------------------------------------------------
// GovernanceDecision
// ---------------------------------------------------------------------------

/// A governance decision for a single piece of transfer evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceDecision {
    /// Prescribed action.
    pub action: GovernanceAction,
    /// Content hashes of evidence supporting this decision.
    pub evidence_hashes: Vec<ContentHash>,
    /// Human-readable explanation.
    pub explanation: String,
    /// Epoch when this decision was made.
    pub epoch: SecurityEpoch,
    /// Content hash of this decision.
    pub receipt_hash: ContentHash,
}

impl GovernanceDecision {
    /// Create a new governance decision, computing its receipt hash.
    #[must_use]
    pub fn new(
        action: GovernanceAction,
        evidence_hashes: Vec<ContentHash>,
        explanation: &str,
        epoch: SecurityEpoch,
    ) -> Self {
        let receipt_hash = Self::compute_receipt_hash(action, &evidence_hashes, explanation, epoch);
        Self {
            action,
            evidence_hashes,
            explanation: explanation.to_string(),
            epoch,
            receipt_hash,
        }
    }

    fn compute_receipt_hash(
        action: GovernanceAction,
        evidence_hashes: &[ContentHash],
        explanation: &str,
        epoch: SecurityEpoch,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(COMPONENT.as_bytes());
        hasher.update(action.as_str().as_bytes());
        for h in evidence_hashes {
            hasher.update(h.as_bytes());
        }
        hasher.update(explanation.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        let result = hasher.finalize();
        ContentHash::compute(&result)
    }
}

impl fmt::Display for GovernanceDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GovernanceDecision({} evidence_count={} epoch={})",
            self.action,
            self.evidence_hashes.len(),
            self.epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// RolloutGateResult
// ---------------------------------------------------------------------------

/// Result of evaluating rollout readiness from transfer evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutGateResult {
    /// Whether rollout is allowed.
    pub allowed: bool,
    /// Conditions that must be met for conditional rollout.
    pub conditions: Vec<String>,
    /// Reasons rollout is blocked.
    pub blocking_reasons: Vec<String>,
    /// Summary of coverage across domains.
    pub coverage_summary: CoverageLevel,
}

impl RolloutGateResult {
    /// Create a passing rollout gate result.
    #[must_use]
    pub fn allowed(coverage_summary: CoverageLevel) -> Self {
        Self {
            allowed: true,
            conditions: Vec::new(),
            blocking_reasons: Vec::new(),
            coverage_summary,
        }
    }

    /// Create a blocked rollout gate result.
    #[must_use]
    pub fn blocked(blocking_reasons: Vec<String>, coverage_summary: CoverageLevel) -> Self {
        Self {
            allowed: false,
            conditions: Vec::new(),
            blocking_reasons,
            coverage_summary,
        }
    }

    /// Create a conditional rollout gate result.
    #[must_use]
    pub fn conditional(conditions: Vec<String>, coverage_summary: CoverageLevel) -> Self {
        Self {
            allowed: true,
            conditions,
            blocking_reasons: Vec::new(),
            coverage_summary,
        }
    }
}

impl fmt::Display for RolloutGateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.allowed {
            if self.conditions.is_empty() {
                write!(f, "RolloutGate(ALLOWED coverage={})", self.coverage_summary)
            } else {
                write!(
                    f,
                    "RolloutGate(CONDITIONAL conditions={} coverage={})",
                    self.conditions.len(),
                    self.coverage_summary,
                )
            }
        } else {
            write!(
                f,
                "RolloutGate(BLOCKED reasons={} coverage={})",
                self.blocking_reasons.len(),
                self.coverage_summary,
            )
        }
    }
}

// ---------------------------------------------------------------------------
// SupremacyConstraint
// ---------------------------------------------------------------------------

/// A constraint on a published supremacy claim imposed by transfer governance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupremacyConstraint {
    /// Identifier of the supremacy claim being constrained.
    pub claim_id: String,
    /// Kind of constraint (e.g. "coverage_gap", "drift_detected").
    pub constraint_kind: String,
    /// Severity of the constraint in millionths (1_000_000 = maximum).
    pub severity: u64,
    /// Human-readable explanation.
    pub explanation: String,
}

impl SupremacyConstraint {
    /// Create a new supremacy constraint.
    #[must_use]
    pub fn new(
        claim_id: &str,
        constraint_kind: &str,
        severity: u64,
        explanation: &str,
    ) -> Self {
        Self {
            claim_id: claim_id.to_string(),
            constraint_kind: constraint_kind.to_string(),
            severity,
            explanation: explanation.to_string(),
        }
    }

    /// Whether this constraint is critical (severity >= 800_000).
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.severity >= 800_000
    }

    /// Content hash of this constraint.
    #[must_use]
    pub fn content_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(self.claim_id.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.constraint_kind.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(&self.severity.to_le_bytes());
        buf.push(b'|');
        buf.extend_from_slice(self.explanation.as_bytes());
        ContentHash::compute(&buf)
    }
}

impl fmt::Display for SupremacyConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SupremacyConstraint(claim={} kind={} severity={})",
            self.claim_id, self.constraint_kind, self.severity,
        )
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Content-hashed receipt for a governance decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Content hash of the receipt itself.
    pub receipt_hash: ContentHash,
    /// Component that produced this receipt.
    pub component: String,
    /// Epoch when the decision was made.
    pub epoch: SecurityEpoch,
    /// Action taken.
    pub action: GovernanceAction,
    /// Hash of the evidence that triggered the decision.
    pub evidence_hash: ContentHash,
}

impl DecisionReceipt {
    /// Create a new decision receipt, computing its content hash.
    #[must_use]
    pub fn new(
        epoch: SecurityEpoch,
        action: GovernanceAction,
        evidence_hash: ContentHash,
    ) -> Self {
        let receipt_hash = Self::compute_hash(epoch, action, &evidence_hash);
        Self {
            receipt_hash,
            component: COMPONENT.to_string(),
            epoch,
            action,
            evidence_hash,
        }
    }

    fn compute_hash(
        epoch: SecurityEpoch,
        action: GovernanceAction,
        evidence_hash: &ContentHash,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(COMPONENT.as_bytes());
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(action.as_str().as_bytes());
        hasher.update(evidence_hash.as_bytes());
        let result = hasher.finalize();
        ContentHash::compute(&result)
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DecisionReceipt({} action={} epoch={})",
            self.component,
            self.action,
            self.epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// GovernanceSummary
// ---------------------------------------------------------------------------

/// Summary statistics from a batch governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceSummary {
    /// Total number of transfer evidence items evaluated.
    pub total_transfers: u64,
    /// Count of Validated verdicts.
    pub validated: u64,
    /// Count of ConditionallyValid verdicts.
    pub conditionally_valid: u64,
    /// Count of DriftDetected verdicts.
    pub drift_detected: u64,
    /// Count of Rejected verdicts.
    pub rejected: u64,
    /// Count of InsufficientEvidence verdicts.
    pub insufficient: u64,
    /// Fraction of transfers that passed (Validated + ConditionallyValid)
    /// in millionths.
    pub coverage_fraction: u64,
}

impl GovernanceSummary {
    /// Create a summary from verdict counts.
    #[must_use]
    pub fn from_counts(
        validated: u64,
        conditionally_valid: u64,
        drift_detected: u64,
        rejected: u64,
        insufficient: u64,
    ) -> Self {
        let total = validated
            .saturating_add(conditionally_valid)
            .saturating_add(drift_detected)
            .saturating_add(rejected)
            .saturating_add(insufficient);
        let passing = validated.saturating_add(conditionally_valid);
        let coverage_fraction = if total == 0 {
            0
        } else {
            passing.saturating_mul(MILLION).checked_div(total).unwrap_or(0)
        };
        Self {
            total_transfers: total,
            validated,
            conditionally_valid,
            drift_detected,
            rejected,
            insufficient,
            coverage_fraction,
        }
    }

    /// Pass rate: fraction of Validated verdicts only, in millionths.
    #[must_use]
    pub fn pass_rate(&self) -> u64 {
        if self.total_transfers == 0 {
            return 0;
        }
        self.validated
            .saturating_mul(MILLION)
            .checked_div(self.total_transfers)
            .unwrap_or(0)
    }
}

impl fmt::Display for GovernanceSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GovernanceSummary(total={} validated={} conditional={} drift={} rejected={} insufficient={} cov={})",
            self.total_transfers,
            self.validated,
            self.conditionally_valid,
            self.drift_detected,
            self.rejected,
            self.insufficient,
            self.coverage_fraction,
        )
    }
}

// ---------------------------------------------------------------------------
// Core evaluation functions
// ---------------------------------------------------------------------------

/// Evaluate a single piece of transfer evidence against the gate config.
///
/// Decision order:
/// 1. If `sample_count < min_sample_count` -> `InsufficientEvidence`
/// 2. If `drift_magnitude > drift_alarm_threshold` -> `DriftDetected`
/// 3. If `transfer_fidelity >= high_threshold` -> `Validated`
/// 4. If `transfer_fidelity >= moderate_threshold` -> `ConditionallyValid`
/// 5. Otherwise -> `Rejected`
#[must_use]
pub fn evaluate_transfer(evidence: &TransferEvidence, config: &GateConfig) -> TransferVerdict {
    if evidence.sample_count < config.min_sample_count {
        return TransferVerdict::InsufficientEvidence;
    }
    if evidence.drift_magnitude > config.drift_alarm_threshold {
        return TransferVerdict::DriftDetected;
    }
    if evidence.transfer_fidelity >= config.min_transfer_fidelity_high {
        return TransferVerdict::Validated;
    }
    if evidence.transfer_fidelity >= config.min_transfer_fidelity_moderate {
        return TransferVerdict::ConditionallyValid;
    }
    TransferVerdict::Rejected
}

/// Evaluate coverage level from a set of coverage records.
///
/// Computes the fraction of records with Full or Partial coverage and maps
/// that to a `CoverageLevel`.
#[must_use]
pub fn evaluate_coverage(records: &[CoverageRecord], config: &GateConfig) -> CoverageLevel {
    if records.is_empty() {
        return CoverageLevel::Uncovered;
    }
    let covered = records
        .iter()
        .filter(|r| r.coverage_level.sufficient_for_rollout())
        .count() as u64;
    let total = records.len() as u64;
    let fraction = covered.saturating_mul(MILLION).checked_div(total).unwrap_or(0);

    if fraction >= config.min_coverage_fraction {
        CoverageLevel::Full
    } else if fraction >= PARTIAL_THRESHOLD {
        CoverageLevel::Partial
    } else if fraction >= SPARSE_THRESHOLD {
        CoverageLevel::Sparse
    } else {
        CoverageLevel::Uncovered
    }
}

/// Evaluate rollout readiness from a batch of transfer evidence.
///
/// Collects verdicts, checks coverage, and produces a `RolloutGateResult`.
#[must_use]
pub fn evaluate_rollout(
    evidences: &[TransferEvidence],
    config: &GateConfig,
) -> RolloutGateResult {
    if evidences.is_empty() {
        return RolloutGateResult::blocked(
            vec!["no transfer evidence provided".to_string()],
            CoverageLevel::Uncovered,
        );
    }

    let mut validated_count: u64 = 0;
    let mut conditional_count: u64 = 0;
    let mut blocking_reasons = Vec::new();
    let mut conditions = Vec::new();
    let mut drift_domains = Vec::new();

    for ev in evidences {
        let verdict = evaluate_transfer(ev, config);
        match verdict {
            TransferVerdict::Validated => {
                validated_count += 1;
            }
            TransferVerdict::ConditionallyValid => {
                conditional_count += 1;
                conditions.push(format!(
                    "conditional transfer: {} {} -> {} (fidelity={})",
                    ev.domain, ev.source_workload_id, ev.target_workload_id, ev.transfer_fidelity,
                ));
            }
            TransferVerdict::DriftDetected => {
                drift_domains.push(ev.domain);
                blocking_reasons.push(format!(
                    "drift detected: {} {} -> {} (drift={})",
                    ev.domain, ev.source_workload_id, ev.target_workload_id, ev.drift_magnitude,
                ));
            }
            TransferVerdict::Rejected => {
                blocking_reasons.push(format!(
                    "rejected transfer: {} {} -> {} (fidelity={})",
                    ev.domain, ev.source_workload_id, ev.target_workload_id, ev.transfer_fidelity,
                ));
            }
            TransferVerdict::InsufficientEvidence => {
                blocking_reasons.push(format!(
                    "insufficient evidence: {} {} -> {} (n={})",
                    ev.domain, ev.source_workload_id, ev.target_workload_id, ev.sample_count,
                ));
            }
        }
    }

    let total = evidences.len() as u64;
    let passing = validated_count.saturating_add(conditional_count);
    let coverage_frac = passing.saturating_mul(MILLION).checked_div(total).unwrap_or(0);

    let coverage_summary = if coverage_frac >= config.min_coverage_fraction {
        CoverageLevel::Full
    } else if coverage_frac >= PARTIAL_THRESHOLD {
        CoverageLevel::Partial
    } else if coverage_frac >= SPARSE_THRESHOLD {
        CoverageLevel::Sparse
    } else {
        CoverageLevel::Uncovered
    };

    if !blocking_reasons.is_empty() {
        if !drift_domains.is_empty() && conditional_count > 0 {
            // Mixed: some drift, some conditional
            RolloutGateResult {
                allowed: false,
                conditions,
                blocking_reasons,
                coverage_summary,
            }
        } else {
            RolloutGateResult::blocked(blocking_reasons, coverage_summary)
        }
    } else if !conditions.is_empty() {
        RolloutGateResult::conditional(conditions, coverage_summary)
    } else {
        RolloutGateResult::allowed(coverage_summary)
    }
}

/// Evaluate a batch of transfer evidence and produce governance decisions
/// plus a summary.
#[must_use]
pub fn evaluate_batch(
    evidences: &[TransferEvidence],
    config: &GateConfig,
) -> (Vec<GovernanceDecision>, GovernanceSummary) {
    let mut decisions = Vec::with_capacity(evidences.len());
    let mut validated: u64 = 0;
    let mut conditionally_valid: u64 = 0;
    let mut drift_detected: u64 = 0;
    let mut rejected: u64 = 0;
    let mut insufficient: u64 = 0;

    let batch = if evidences.len() > config.max_batch_size {
        &evidences[..config.max_batch_size]
    } else {
        evidences
    };

    for ev in batch {
        let verdict = evaluate_transfer(ev, config);
        let (action, explanation) = match verdict {
            TransferVerdict::Validated => {
                validated += 1;
                (
                    GovernanceAction::AllowRollout,
                    format!(
                        "transfer validated: {} {}->{} fidelity={}",
                        ev.domain, ev.source_workload_id, ev.target_workload_id,
                        ev.transfer_fidelity,
                    ),
                )
            }
            TransferVerdict::ConditionallyValid => {
                conditionally_valid += 1;
                (
                    GovernanceAction::ConditionalRollout,
                    format!(
                        "conditional: {} {}->{} fidelity={}",
                        ev.domain, ev.source_workload_id, ev.target_workload_id,
                        ev.transfer_fidelity,
                    ),
                )
            }
            TransferVerdict::DriftDetected => {
                drift_detected += 1;
                (
                    GovernanceAction::DowngradeSupremacy,
                    format!(
                        "drift detected: {} {}->{} drift={}",
                        ev.domain, ev.source_workload_id, ev.target_workload_id,
                        ev.drift_magnitude,
                    ),
                )
            }
            TransferVerdict::Rejected => {
                rejected += 1;
                (
                    GovernanceAction::BlockRollout,
                    format!(
                        "rejected: {} {}->{} fidelity={}",
                        ev.domain, ev.source_workload_id, ev.target_workload_id,
                        ev.transfer_fidelity,
                    ),
                )
            }
            TransferVerdict::InsufficientEvidence => {
                insufficient += 1;
                (
                    GovernanceAction::RequireFreshEvidence,
                    format!(
                        "insufficient evidence: {} {}->{} n={}",
                        ev.domain, ev.source_workload_id, ev.target_workload_id,
                        ev.sample_count,
                    ),
                )
            }
        };

        let decision = GovernanceDecision::new(
            action,
            vec![ev.evidence_hash.clone()],
            &explanation,
            ev.epoch,
        );
        decisions.push(decision);
    }

    let summary = GovernanceSummary::from_counts(
        validated,
        conditionally_valid,
        drift_detected,
        rejected,
        insufficient,
    );

    (decisions, summary)
}

/// Generate supremacy constraints from a set of transfer evidence.
///
/// Any drift or rejected evidence produces a constraint on the associated
/// supremacy claim.
#[must_use]
pub fn generate_supremacy_constraints(
    claim_id: &str,
    evidences: &[TransferEvidence],
    config: &GateConfig,
) -> Vec<SupremacyConstraint> {
    let mut constraints = Vec::new();

    for ev in evidences {
        let verdict = evaluate_transfer(ev, config);
        match verdict {
            TransferVerdict::DriftDetected => {
                constraints.push(SupremacyConstraint::new(
                    claim_id,
                    "drift_detected",
                    ev.drift_magnitude.min(MILLION),
                    &format!(
                        "drift in {} from {} to {} (magnitude={})",
                        ev.domain, ev.source_workload_id, ev.target_workload_id,
                        ev.drift_magnitude,
                    ),
                ));
            }
            TransferVerdict::Rejected => {
                constraints.push(SupremacyConstraint::new(
                    claim_id,
                    "coverage_gap",
                    MILLION.saturating_sub(ev.transfer_fidelity).min(MILLION),
                    &format!(
                        "rejected transfer in {} from {} to {} (fidelity={})",
                        ev.domain, ev.source_workload_id, ev.target_workload_id,
                        ev.transfer_fidelity,
                    ),
                ));
            }
            TransferVerdict::InsufficientEvidence => {
                constraints.push(SupremacyConstraint::new(
                    claim_id,
                    "insufficient_evidence",
                    500_000, // 50% severity — uncertain
                    &format!(
                        "insufficient evidence in {} from {} to {} (n={})",
                        ev.domain, ev.source_workload_id, ev.target_workload_id,
                        ev.sample_count,
                    ),
                ));
            }
            TransferVerdict::Validated | TransferVerdict::ConditionallyValid => {}
        }
    }

    constraints
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn make_evidence(
        domain: TransferDomain,
        fidelity: u64,
        drift: u64,
        samples: u64,
    ) -> TransferEvidence {
        TransferEvidence::new(domain, "src_wl", "tgt_wl", fidelity, drift, samples, epoch(10))
    }

    fn make_coverage(
        domain: TransferDomain,
        region: &str,
        level: CoverageLevel,
    ) -> CoverageRecord {
        CoverageRecord::new(
            domain,
            region,
            level,
            ContentHash::compute(b"test_hash"),
            epoch(5),
        )
    }

    // --- Constants ---

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("transfer-governance-gate"));
    }

    #[test]
    fn test_component_name() {
        assert_eq!(COMPONENT, "transfer_governance_gate");
    }

    #[test]
    fn test_bead_and_policy_ids() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.12.3");
        assert_eq!(POLICY_ID, "RGC-612C");
    }

    #[test]
    fn test_default_thresholds_ordering() {
        assert!(DEFAULT_HIGH_FIDELITY_THRESHOLD > DEFAULT_MODERATE_FIDELITY_THRESHOLD);
        assert!(DEFAULT_MODERATE_FIDELITY_THRESHOLD > DEFAULT_DRIFT_ALARM_THRESHOLD);
    }

    // --- TransferDomain ---

    #[test]
    fn test_transfer_domain_all_count() {
        assert_eq!(TransferDomain::ALL.len(), 6);
    }

    #[test]
    fn test_transfer_domain_display() {
        assert_eq!(TransferDomain::RewritePrior.to_string(), "rewrite_prior");
        assert_eq!(TransferDomain::CachePolicy.to_string(), "cache_policy");
        assert_eq!(
            TransferDomain::SpecializationStrategy.to_string(),
            "specialization_strategy",
        );
    }

    #[test]
    fn test_transfer_domain_serde_roundtrip() {
        for domain in TransferDomain::ALL {
            let json = serde_json::to_string(domain).unwrap();
            let back: TransferDomain = serde_json::from_str(&json).unwrap();
            assert_eq!(*domain, back);
        }
    }

    // --- TransferVerdict ---

    #[test]
    fn test_verdict_display() {
        assert_eq!(TransferVerdict::Validated.to_string(), "validated");
        assert_eq!(
            TransferVerdict::ConditionallyValid.to_string(),
            "conditionally_valid",
        );
        assert_eq!(TransferVerdict::DriftDetected.to_string(), "drift_detected");
        assert_eq!(TransferVerdict::Rejected.to_string(), "rejected");
        assert_eq!(
            TransferVerdict::InsufficientEvidence.to_string(),
            "insufficient_evidence",
        );
    }

    #[test]
    fn test_verdict_serde_roundtrip() {
        let verdicts = [
            TransferVerdict::Validated,
            TransferVerdict::ConditionallyValid,
            TransferVerdict::DriftDetected,
            TransferVerdict::Rejected,
            TransferVerdict::InsufficientEvidence,
        ];
        for v in &verdicts {
            let json = serde_json::to_string(v).unwrap();
            let back: TransferVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn test_verdict_unconditional_rollout() {
        assert!(TransferVerdict::Validated.allows_unconditional_rollout());
        assert!(!TransferVerdict::ConditionallyValid.allows_unconditional_rollout());
        assert!(!TransferVerdict::DriftDetected.allows_unconditional_rollout());
        assert!(!TransferVerdict::Rejected.allows_unconditional_rollout());
        assert!(!TransferVerdict::InsufficientEvidence.allows_unconditional_rollout());
    }

    // --- CoverageLevel ---

    #[test]
    fn test_coverage_level_display() {
        assert_eq!(CoverageLevel::Full.to_string(), "full");
        assert_eq!(CoverageLevel::Partial.to_string(), "partial");
        assert_eq!(CoverageLevel::Sparse.to_string(), "sparse");
        assert_eq!(CoverageLevel::Uncovered.to_string(), "uncovered");
    }

    #[test]
    fn test_coverage_level_serde_roundtrip() {
        let levels = [
            CoverageLevel::Full,
            CoverageLevel::Partial,
            CoverageLevel::Sparse,
            CoverageLevel::Uncovered,
        ];
        for l in &levels {
            let json = serde_json::to_string(l).unwrap();
            let back: CoverageLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(*l, back);
        }
    }

    #[test]
    fn test_coverage_sufficient_for_rollout() {
        assert!(CoverageLevel::Full.sufficient_for_rollout());
        assert!(CoverageLevel::Partial.sufficient_for_rollout());
        assert!(!CoverageLevel::Sparse.sufficient_for_rollout());
        assert!(!CoverageLevel::Uncovered.sufficient_for_rollout());
    }

    // --- GovernanceAction ---

    #[test]
    fn test_governance_action_display() {
        assert_eq!(GovernanceAction::AllowRollout.to_string(), "allow_rollout");
        assert_eq!(GovernanceAction::BlockRollout.to_string(), "block_rollout");
        assert_eq!(
            GovernanceAction::DowngradeSupremacy.to_string(),
            "downgrade_supremacy",
        );
    }

    #[test]
    fn test_governance_action_serde_roundtrip() {
        let actions = [
            GovernanceAction::AllowRollout,
            GovernanceAction::ConditionalRollout,
            GovernanceAction::BlockRollout,
            GovernanceAction::RequireFreshEvidence,
            GovernanceAction::DowngradeSupremacy,
        ];
        for a in &actions {
            let json = serde_json::to_string(a).unwrap();
            let back: GovernanceAction = serde_json::from_str(&json).unwrap();
            assert_eq!(*a, back);
        }
    }

    // --- TransferEvidence ---

    #[test]
    fn test_evidence_creation() {
        let ev = make_evidence(TransferDomain::CachePolicy, 950_000, 10_000, 100);
        assert_eq!(ev.domain, TransferDomain::CachePolicy);
        assert_eq!(ev.source_workload_id, "src_wl");
        assert_eq!(ev.target_workload_id, "tgt_wl");
        assert_eq!(ev.transfer_fidelity, 950_000);
        assert_eq!(ev.drift_magnitude, 10_000);
        assert_eq!(ev.sample_count, 100);
    }

    #[test]
    fn test_evidence_hash_deterministic() {
        let e1 = make_evidence(TransferDomain::RewritePrior, 900_000, 50_000, 50);
        let e2 = make_evidence(TransferDomain::RewritePrior, 900_000, 50_000, 50);
        assert_eq!(e1.evidence_hash, e2.evidence_hash);
    }

    #[test]
    fn test_evidence_hash_differs_on_domain() {
        let e1 = make_evidence(TransferDomain::RewritePrior, 900_000, 50_000, 50);
        let e2 = make_evidence(TransferDomain::CachePolicy, 900_000, 50_000, 50);
        assert_ne!(e1.evidence_hash, e2.evidence_hash);
    }

    #[test]
    fn test_evidence_display() {
        let ev = make_evidence(TransferDomain::TieringPolicy, 800_000, 20_000, 40);
        let s = ev.to_string();
        assert!(s.contains("TransferEvidence"));
        assert!(s.contains("tiering_policy"));
    }

    #[test]
    fn test_evidence_serde_roundtrip() {
        let ev = make_evidence(TransferDomain::InliningDecision, 750_000, 100_000, 60);
        let json = serde_json::to_string(&ev).unwrap();
        let back: TransferEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    // --- evaluate_transfer ---

    #[test]
    fn test_evaluate_validated() {
        let config = GateConfig::default();
        let ev = make_evidence(TransferDomain::RewritePrior, 950_000, 100_000, 50);
        assert_eq!(evaluate_transfer(&ev, &config), TransferVerdict::Validated);
    }

    #[test]
    fn test_evaluate_conditionally_valid() {
        let config = GateConfig::default();
        let ev = make_evidence(TransferDomain::CachePolicy, 750_000, 100_000, 50);
        assert_eq!(
            evaluate_transfer(&ev, &config),
            TransferVerdict::ConditionallyValid,
        );
    }

    #[test]
    fn test_evaluate_drift_detected() {
        let config = GateConfig::default();
        // drift=300_000 > default alarm=200_000, even with high fidelity
        let ev = make_evidence(TransferDomain::TieringPolicy, 950_000, 300_000, 50);
        assert_eq!(
            evaluate_transfer(&ev, &config),
            TransferVerdict::DriftDetected,
        );
    }

    #[test]
    fn test_evaluate_rejected() {
        let config = GateConfig::default();
        let ev = make_evidence(TransferDomain::SchedulingHeuristic, 500_000, 100_000, 50);
        assert_eq!(evaluate_transfer(&ev, &config), TransferVerdict::Rejected);
    }

    #[test]
    fn test_evaluate_insufficient_evidence() {
        let config = GateConfig::default();
        // samples=5 < default min=30
        let ev = make_evidence(TransferDomain::InliningDecision, 950_000, 0, 5);
        assert_eq!(
            evaluate_transfer(&ev, &config),
            TransferVerdict::InsufficientEvidence,
        );
    }

    #[test]
    fn test_evaluate_drift_takes_priority_over_fidelity() {
        let config = GateConfig::default();
        // High fidelity but also high drift
        let ev = make_evidence(TransferDomain::RewritePrior, 990_000, 500_000, 100);
        assert_eq!(
            evaluate_transfer(&ev, &config),
            TransferVerdict::DriftDetected,
        );
    }

    #[test]
    fn test_evaluate_insufficient_takes_priority_over_all() {
        let config = GateConfig::default();
        // Low samples even with perfect fidelity and high drift
        let ev = make_evidence(TransferDomain::CachePolicy, 1_000_000, 500_000, 1);
        assert_eq!(
            evaluate_transfer(&ev, &config),
            TransferVerdict::InsufficientEvidence,
        );
    }

    // --- CoverageRecord ---

    #[test]
    fn test_coverage_record_creation() {
        let rec = make_coverage(TransferDomain::CachePolicy, "region_a", CoverageLevel::Full);
        assert_eq!(rec.domain, TransferDomain::CachePolicy);
        assert_eq!(rec.region_id, "region_a");
        assert_eq!(rec.coverage_level, CoverageLevel::Full);
    }

    #[test]
    fn test_coverage_record_hash_deterministic() {
        let r1 = make_coverage(TransferDomain::RewritePrior, "r1", CoverageLevel::Full);
        let r2 = make_coverage(TransferDomain::RewritePrior, "r1", CoverageLevel::Full);
        assert_eq!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn test_coverage_record_hash_differs_on_level() {
        let r1 = make_coverage(TransferDomain::RewritePrior, "r1", CoverageLevel::Full);
        let r2 = make_coverage(TransferDomain::RewritePrior, "r1", CoverageLevel::Sparse);
        assert_ne!(r1.content_hash(), r2.content_hash());
    }

    #[test]
    fn test_coverage_record_display() {
        let rec = make_coverage(TransferDomain::TieringPolicy, "zone_b", CoverageLevel::Partial);
        let s = rec.to_string();
        assert!(s.contains("Coverage"));
        assert!(s.contains("zone_b"));
    }

    // --- evaluate_coverage ---

    #[test]
    fn test_coverage_empty_is_uncovered() {
        let config = GateConfig::default();
        assert_eq!(evaluate_coverage(&[], &config), CoverageLevel::Uncovered);
    }

    #[test]
    fn test_coverage_all_full_is_full() {
        let config = GateConfig::default();
        let records = vec![
            make_coverage(TransferDomain::RewritePrior, "r1", CoverageLevel::Full),
            make_coverage(TransferDomain::CachePolicy, "r2", CoverageLevel::Full),
            make_coverage(TransferDomain::TieringPolicy, "r3", CoverageLevel::Full),
            make_coverage(TransferDomain::InliningDecision, "r4", CoverageLevel::Full),
            make_coverage(TransferDomain::SchedulingHeuristic, "r5", CoverageLevel::Partial),
        ];
        assert_eq!(evaluate_coverage(&records, &config), CoverageLevel::Full);
    }

    #[test]
    fn test_coverage_all_uncovered_is_uncovered() {
        let config = GateConfig::default();
        let records = vec![
            make_coverage(TransferDomain::RewritePrior, "r1", CoverageLevel::Uncovered),
            make_coverage(TransferDomain::CachePolicy, "r2", CoverageLevel::Sparse),
        ];
        assert_eq!(evaluate_coverage(&records, &config), CoverageLevel::Uncovered);
    }

    #[test]
    fn test_coverage_mixed_partial() {
        let config = GateConfig::default();
        let records = vec![
            make_coverage(TransferDomain::RewritePrior, "r1", CoverageLevel::Full),
            make_coverage(TransferDomain::CachePolicy, "r2", CoverageLevel::Sparse),
            make_coverage(TransferDomain::TieringPolicy, "r3", CoverageLevel::Full),
            make_coverage(TransferDomain::InliningDecision, "r4", CoverageLevel::Full),
        ];
        // 3/4 = 750_000 -> Partial (>= 700k but < 800k)
        assert_eq!(evaluate_coverage(&records, &config), CoverageLevel::Partial);
    }

    // --- GateConfig ---

    #[test]
    fn test_gate_config_default() {
        let config = GateConfig::default();
        assert_eq!(config.min_transfer_fidelity_high, DEFAULT_HIGH_FIDELITY_THRESHOLD);
        assert_eq!(config.min_transfer_fidelity_moderate, DEFAULT_MODERATE_FIDELITY_THRESHOLD);
        assert_eq!(config.drift_alarm_threshold, DEFAULT_DRIFT_ALARM_THRESHOLD);
        assert_eq!(config.min_sample_count, DEFAULT_MIN_SAMPLE_COUNT);
        assert_eq!(config.min_coverage_fraction, DEFAULT_MIN_COVERAGE_FRACTION);
        assert_eq!(config.max_batch_size, DEFAULT_MAX_BATCH_SIZE);
    }

    #[test]
    fn test_gate_config_custom() {
        let config = GateConfig {
            min_transfer_fidelity_high: 800_000,
            min_transfer_fidelity_moderate: 600_000,
            drift_alarm_threshold: 300_000,
            min_sample_count: 10,
            min_coverage_fraction: 500_000,
            max_batch_size: 100,
        };
        // Fidelity=750_000 is now above moderate=600_000 but below high=800_000
        let ev = make_evidence(TransferDomain::CachePolicy, 750_000, 100_000, 20);
        assert_eq!(
            evaluate_transfer(&ev, &config),
            TransferVerdict::ConditionallyValid,
        );
    }

    #[test]
    fn test_gate_config_display() {
        let config = GateConfig::default();
        let s = config.to_string();
        assert!(s.contains("GateConfig"));
        assert!(s.contains("900000"));
    }

    #[test]
    fn test_gate_config_serde_roundtrip() {
        let config = GateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // --- GovernanceDecision ---

    #[test]
    fn test_governance_decision_creation() {
        let hash = ContentHash::compute(b"evidence");
        let d = GovernanceDecision::new(
            GovernanceAction::AllowRollout,
            vec![hash],
            "validated transfer",
            epoch(10),
        );
        assert_eq!(d.action, GovernanceAction::AllowRollout);
        assert_eq!(d.evidence_hashes.len(), 1);
        assert_eq!(d.explanation, "validated transfer");
    }

    #[test]
    fn test_governance_decision_receipt_hash_deterministic() {
        let hash = ContentHash::compute(b"ev");
        let d1 = GovernanceDecision::new(
            GovernanceAction::BlockRollout,
            vec![hash],
            "reason",
            epoch(5),
        );
        let d2 = GovernanceDecision::new(
            GovernanceAction::BlockRollout,
            vec![hash],
            "reason",
            epoch(5),
        );
        assert_eq!(d1.receipt_hash, d2.receipt_hash);
    }

    #[test]
    fn test_governance_decision_display() {
        let d = GovernanceDecision::new(
            GovernanceAction::ConditionalRollout,
            vec![],
            "conditional",
            epoch(7),
        );
        let s = d.to_string();
        assert!(s.contains("GovernanceDecision"));
        assert!(s.contains("conditional_rollout"));
    }

    // --- RolloutGateResult ---

    #[test]
    fn test_rollout_gate_allowed() {
        let r = RolloutGateResult::allowed(CoverageLevel::Full);
        assert!(r.allowed);
        assert!(r.conditions.is_empty());
        assert!(r.blocking_reasons.is_empty());
        assert_eq!(r.coverage_summary, CoverageLevel::Full);
    }

    #[test]
    fn test_rollout_gate_blocked() {
        let r = RolloutGateResult::blocked(
            vec!["drift in cache_policy".to_string()],
            CoverageLevel::Sparse,
        );
        assert!(!r.allowed);
        assert_eq!(r.blocking_reasons.len(), 1);
        assert_eq!(r.coverage_summary, CoverageLevel::Sparse);
    }

    #[test]
    fn test_rollout_gate_conditional() {
        let r = RolloutGateResult::conditional(
            vec!["canary-only deployment".to_string()],
            CoverageLevel::Partial,
        );
        assert!(r.allowed);
        assert_eq!(r.conditions.len(), 1);
        assert_eq!(r.coverage_summary, CoverageLevel::Partial);
    }

    #[test]
    fn test_rollout_gate_display_variants() {
        let allowed = RolloutGateResult::allowed(CoverageLevel::Full);
        assert!(allowed.to_string().contains("ALLOWED"));

        let blocked = RolloutGateResult::blocked(vec!["x".to_string()], CoverageLevel::Uncovered);
        assert!(blocked.to_string().contains("BLOCKED"));

        let cond = RolloutGateResult::conditional(vec!["c".to_string()], CoverageLevel::Partial);
        assert!(cond.to_string().contains("CONDITIONAL"));
    }

    // --- SupremacyConstraint ---

    #[test]
    fn test_supremacy_constraint_creation() {
        let c = SupremacyConstraint::new("claim_1", "drift_detected", 600_000, "drift in region");
        assert_eq!(c.claim_id, "claim_1");
        assert_eq!(c.constraint_kind, "drift_detected");
        assert_eq!(c.severity, 600_000);
        assert!(!c.is_critical());
    }

    #[test]
    fn test_supremacy_constraint_critical() {
        let c = SupremacyConstraint::new("claim_2", "coverage_gap", 900_000, "large gap");
        assert!(c.is_critical());
    }

    #[test]
    fn test_supremacy_constraint_hash_deterministic() {
        let c1 = SupremacyConstraint::new("c", "k", 500_000, "e");
        let c2 = SupremacyConstraint::new("c", "k", 500_000, "e");
        assert_eq!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn test_supremacy_constraint_display() {
        let c = SupremacyConstraint::new("claim_3", "drift", 700_000, "explanation");
        let s = c.to_string();
        assert!(s.contains("SupremacyConstraint"));
        assert!(s.contains("claim_3"));
    }

    // --- DecisionReceipt ---

    #[test]
    fn test_decision_receipt_creation() {
        let hash = ContentHash::compute(b"evidence");
        let r = DecisionReceipt::new(epoch(15), GovernanceAction::AllowRollout, hash);
        assert_eq!(r.component, COMPONENT);
        assert_eq!(r.epoch.as_u64(), 15);
        assert_eq!(r.action, GovernanceAction::AllowRollout);
        assert_eq!(r.evidence_hash, hash);
    }

    #[test]
    fn test_decision_receipt_hash_deterministic() {
        let hash = ContentHash::compute(b"ev");
        let r1 = DecisionReceipt::new(epoch(10), GovernanceAction::BlockRollout, hash);
        let r2 = DecisionReceipt::new(epoch(10), GovernanceAction::BlockRollout, hash);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn test_decision_receipt_hash_differs_on_action() {
        let hash = ContentHash::compute(b"ev");
        let r1 = DecisionReceipt::new(epoch(10), GovernanceAction::AllowRollout, hash);
        let r2 = DecisionReceipt::new(epoch(10), GovernanceAction::BlockRollout, hash);
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn test_decision_receipt_display() {
        let hash = ContentHash::compute(b"ev");
        let r = DecisionReceipt::new(epoch(20), GovernanceAction::RequireFreshEvidence, hash);
        let s = r.to_string();
        assert!(s.contains("DecisionReceipt"));
        assert!(s.contains("require_fresh_evidence"));
    }

    // --- evaluate_rollout ---

    #[test]
    fn test_rollout_empty_evidence_blocked() {
        let config = GateConfig::default();
        let result = evaluate_rollout(&[], &config);
        assert!(!result.allowed);
        assert!(!result.blocking_reasons.is_empty());
    }

    #[test]
    fn test_rollout_all_validated() {
        let config = GateConfig::default();
        let evidences = vec![
            make_evidence(TransferDomain::RewritePrior, 950_000, 50_000, 100),
            make_evidence(TransferDomain::CachePolicy, 920_000, 30_000, 80),
        ];
        let result = evaluate_rollout(&evidences, &config);
        assert!(result.allowed);
        assert!(result.conditions.is_empty());
        assert_eq!(result.coverage_summary, CoverageLevel::Full);
    }

    #[test]
    fn test_rollout_with_drift_blocked() {
        let config = GateConfig::default();
        let evidences = vec![
            make_evidence(TransferDomain::RewritePrior, 950_000, 50_000, 100),
            make_evidence(TransferDomain::CachePolicy, 920_000, 400_000, 80), // drift
        ];
        let result = evaluate_rollout(&evidences, &config);
        assert!(!result.allowed);
        assert!(!result.blocking_reasons.is_empty());
    }

    #[test]
    fn test_rollout_conditional_when_moderate_fidelity() {
        let config = GateConfig::default();
        let evidences = vec![
            make_evidence(TransferDomain::RewritePrior, 750_000, 50_000, 100),
            make_evidence(TransferDomain::CachePolicy, 800_000, 100_000, 80),
        ];
        let result = evaluate_rollout(&evidences, &config);
        assert!(result.allowed);
        assert!(!result.conditions.is_empty());
    }

    // --- evaluate_batch ---

    #[test]
    fn test_batch_mixed_evidence() {
        let config = GateConfig::default();
        let evidences = vec![
            make_evidence(TransferDomain::RewritePrior, 950_000, 50_000, 100),  // Validated
            make_evidence(TransferDomain::CachePolicy, 750_000, 100_000, 50),   // Conditional
            make_evidence(TransferDomain::TieringPolicy, 950_000, 400_000, 60), // Drift
            make_evidence(TransferDomain::SchedulingHeuristic, 300_000, 50_000, 40), // Rejected
            make_evidence(TransferDomain::InliningDecision, 950_000, 0, 5),      // Insufficient
        ];
        let (decisions, summary) = evaluate_batch(&evidences, &config);
        assert_eq!(decisions.len(), 5);
        assert_eq!(summary.validated, 1);
        assert_eq!(summary.conditionally_valid, 1);
        assert_eq!(summary.drift_detected, 1);
        assert_eq!(summary.rejected, 1);
        assert_eq!(summary.insufficient, 1);
        assert_eq!(summary.total_transfers, 5);
    }

    #[test]
    fn test_batch_all_validated() {
        let config = GateConfig::default();
        let evidences = vec![
            make_evidence(TransferDomain::RewritePrior, 950_000, 50_000, 100),
            make_evidence(TransferDomain::CachePolicy, 920_000, 30_000, 80),
        ];
        let (decisions, summary) = evaluate_batch(&evidences, &config);
        assert_eq!(decisions.len(), 2);
        assert_eq!(summary.validated, 2);
        assert_eq!(summary.coverage_fraction, MILLION);
    }

    #[test]
    fn test_batch_respects_max_size() {
        let config = GateConfig {
            max_batch_size: 2,
            ..GateConfig::default()
        };
        let evidences = vec![
            make_evidence(TransferDomain::RewritePrior, 950_000, 50_000, 100),
            make_evidence(TransferDomain::CachePolicy, 920_000, 30_000, 80),
            make_evidence(TransferDomain::TieringPolicy, 910_000, 40_000, 90),
        ];
        let (decisions, summary) = evaluate_batch(&evidences, &config);
        assert_eq!(decisions.len(), 2);
        assert_eq!(summary.total_transfers, 2);
    }

    // --- GovernanceSummary ---

    #[test]
    fn test_summary_pass_rate() {
        let summary = GovernanceSummary::from_counts(3, 1, 1, 0, 0);
        // pass_rate = 3/5 = 600_000
        assert_eq!(summary.pass_rate(), 600_000);
    }

    #[test]
    fn test_summary_coverage_fraction() {
        let summary = GovernanceSummary::from_counts(2, 2, 1, 0, 0);
        // coverage = (2+2)/5 = 800_000
        assert_eq!(summary.coverage_fraction, 800_000);
    }

    #[test]
    fn test_summary_empty() {
        let summary = GovernanceSummary::from_counts(0, 0, 0, 0, 0);
        assert_eq!(summary.total_transfers, 0);
        assert_eq!(summary.pass_rate(), 0);
        assert_eq!(summary.coverage_fraction, 0);
    }

    #[test]
    fn test_summary_display() {
        let summary = GovernanceSummary::from_counts(5, 2, 1, 1, 1);
        let s = summary.to_string();
        assert!(s.contains("GovernanceSummary"));
        assert!(s.contains("total=10"));
    }

    // --- Supremacy constraint generation ---

    #[test]
    fn test_generate_supremacy_constraints_drift() {
        let config = GateConfig::default();
        let evidences = vec![
            make_evidence(TransferDomain::CachePolicy, 950_000, 400_000, 80),
        ];
        let constraints = generate_supremacy_constraints("claim_x", &evidences, &config);
        assert_eq!(constraints.len(), 1);
        assert_eq!(constraints[0].constraint_kind, "drift_detected");
        assert_eq!(constraints[0].claim_id, "claim_x");
    }

    #[test]
    fn test_generate_supremacy_constraints_none_for_validated() {
        let config = GateConfig::default();
        let evidences = vec![
            make_evidence(TransferDomain::RewritePrior, 950_000, 50_000, 100),
        ];
        let constraints = generate_supremacy_constraints("claim_y", &evidences, &config);
        assert!(constraints.is_empty());
    }

    // --- Edge cases ---

    #[test]
    fn test_boundary_fidelity_high_threshold() {
        let config = GateConfig::default();
        // Exactly at high threshold
        let ev = make_evidence(TransferDomain::RewritePrior, 900_000, 100_000, 50);
        assert_eq!(evaluate_transfer(&ev, &config), TransferVerdict::Validated);
    }

    #[test]
    fn test_boundary_fidelity_moderate_threshold() {
        let config = GateConfig::default();
        // Exactly at moderate threshold
        let ev = make_evidence(TransferDomain::RewritePrior, 700_000, 100_000, 50);
        assert_eq!(
            evaluate_transfer(&ev, &config),
            TransferVerdict::ConditionallyValid,
        );
    }

    #[test]
    fn test_boundary_drift_at_threshold() {
        let config = GateConfig::default();
        // Drift exactly at alarm threshold: not exceeding, so no drift
        let ev = make_evidence(TransferDomain::RewritePrior, 950_000, 200_000, 50);
        assert_eq!(evaluate_transfer(&ev, &config), TransferVerdict::Validated);
    }

    #[test]
    fn test_boundary_drift_just_over_threshold() {
        let config = GateConfig::default();
        let ev = make_evidence(TransferDomain::RewritePrior, 950_000, 200_001, 50);
        assert_eq!(
            evaluate_transfer(&ev, &config),
            TransferVerdict::DriftDetected,
        );
    }

    #[test]
    fn test_boundary_samples_at_min() {
        let config = GateConfig::default();
        // Exactly at min sample count
        let ev = make_evidence(TransferDomain::RewritePrior, 950_000, 50_000, 30);
        assert_eq!(evaluate_transfer(&ev, &config), TransferVerdict::Validated);
    }

    #[test]
    fn test_boundary_samples_just_below_min() {
        let config = GateConfig::default();
        let ev = make_evidence(TransferDomain::RewritePrior, 950_000, 50_000, 29);
        assert_eq!(
            evaluate_transfer(&ev, &config),
            TransferVerdict::InsufficientEvidence,
        );
    }
}
