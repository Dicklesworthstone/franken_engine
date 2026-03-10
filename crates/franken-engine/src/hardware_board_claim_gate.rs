#![forbid(unsafe_code)]

//! Hardware board claim gate — RGC-616C
//!
//! Bead: bd-1lsy.7.16.3
//!
//! Gates hardware-board claims, promotion, and unsupported-hardware surfacing
//! on localization residuals.  Cross-microarchitecture wins are only claimed
//! where transport evidence actually supports them.  If a benchmark result or
//! optimized artifact does not transport cleanly, the runtime must downgrade
//! the claim, require fresh local measurement, or mark the hardware region
//! unsupported.  Users and operators see a precise explanation rather than a
//! silent mismatch between promised and observed behavior.
//!
//! # Design decisions
//!
//! - Each hardware claim carries source/target cell IDs, a measured value,
//!   a claimed improvement, and a transport residual — all in fixed-point
//!   millionths (1_000_000 = 1.0).
//! - `evaluate` maps the transport residual to a `ClaimVerdict` using
//!   configurable thresholds, then collects degradation reasons from the
//!   claim properties.
//! - `evaluate_promotion` converts a `ClaimEvidence` into a `PromotionDecision`
//!   to decide whether to promote, hold, rollback, or require fresh local
//!   measurement.
//! - `evaluate_batch` processes multiple claims, returning per-claim evidence
//!   and an aggregate `GateSummary` with a pass rate.
//! - All structures use `BTreeMap`/`BTreeSet` for deterministic ordering.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-616C]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for hardware board claim gate artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.hardware-board-claim-gate.v1";

/// Bead identifier for this module.
pub const BEAD_ID: &str = "bd-1lsy.7.16.3";

/// Component name.
pub const COMPONENT: &str = "hardware_board_claim_gate";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-616C";

/// One million — unit for fixed-point millionths arithmetic.
const MILLIONTHS: u64 = 1_000_000;

/// Default threshold above which a claim is `Confirmed` (95%).
const DEFAULT_FULL_TRANSPORT_THRESHOLD: u64 = 950_000;

/// Default threshold above which a claim is `Downgraded` (70%).
const DEFAULT_PARTIAL_TRANSPORT_THRESHOLD: u64 = 700_000;

/// Default threshold above which a claim is `RequiresLocal` (30%).
const DEFAULT_DEGRADED_THRESHOLD: u64 = 300_000;

/// Default minimum sample count for sufficient evidence.
const DEFAULT_MIN_SAMPLES: u64 = 10;

/// Default rollback regression threshold (5%).
const DEFAULT_ROLLBACK_REGRESSION_THRESHOLD: u64 = 50_000;

/// Maximum degradation reasons per evidence record.
const MAX_DEGRADATION_REASONS: usize = 16;

// ---------------------------------------------------------------------------
// HardwareClaimKind
// ---------------------------------------------------------------------------

/// Classification of the hardware performance claim being made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareClaimKind {
    /// Throughput (operations per second).
    Throughput,
    /// Latency (response time).
    Latency,
    /// Memory efficiency (bytes per operation).
    MemoryEfficiency,
    /// Startup time (time to first useful work).
    StartupTime,
    /// Tail latency (p99, p999).
    TailLatency,
    /// Energy efficiency (operations per joule).
    EnergyEfficiency,
}

impl HardwareClaimKind {
    /// All claim kinds for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::Throughput,
        Self::Latency,
        Self::MemoryEfficiency,
        Self::StartupTime,
        Self::TailLatency,
        Self::EnergyEfficiency,
    ];

    /// String identifier for this claim kind.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Throughput => "throughput",
            Self::Latency => "latency",
            Self::MemoryEfficiency => "memory_efficiency",
            Self::StartupTime => "startup_time",
            Self::TailLatency => "tail_latency",
            Self::EnergyEfficiency => "energy_efficiency",
        }
    }
}

impl fmt::Display for HardwareClaimKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ClaimVerdict
// ---------------------------------------------------------------------------

/// Verdict after evaluating a hardware claim against transport evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimVerdict {
    /// Transport residual fully supports the claim (>= full threshold).
    Confirmed,
    /// Transport residual partially supports; claim is downgraded.
    Downgraded,
    /// Residual is too low; fresh local measurement required.
    RequiresLocal,
    /// Residual below degraded threshold; hardware region unsupported.
    Unsupported,
    /// Not enough samples to make a determination.
    InsufficientEvidence,
}

impl ClaimVerdict {
    /// All verdict variants for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::Confirmed,
        Self::Downgraded,
        Self::RequiresLocal,
        Self::Unsupported,
        Self::InsufficientEvidence,
    ];

    /// String identifier for this verdict.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Downgraded => "downgraded",
            Self::RequiresLocal => "requires_local",
            Self::Unsupported => "unsupported",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }

    /// Whether this verdict permits the claim to be used.
    pub fn is_usable(self) -> bool {
        matches!(self, Self::Confirmed | Self::Downgraded)
    }
}

impl fmt::Display for ClaimVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// PromotionDecision
// ---------------------------------------------------------------------------

/// Decision on whether to promote an artifact based on claim evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionDecision {
    /// Evidence supports promotion.
    Promote,
    /// Hold current state; not enough evidence for promotion.
    Hold,
    /// Roll back to a previous known-good state.
    Rollback,
    /// Require fresh local measurement before deciding.
    RequireFreshMeasurement,
}

impl PromotionDecision {
    /// All decision variants for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::Promote,
        Self::Hold,
        Self::Rollback,
        Self::RequireFreshMeasurement,
    ];

    /// String identifier for this decision.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Promote => "promote",
            Self::Hold => "hold",
            Self::Rollback => "rollback",
            Self::RequireFreshMeasurement => "require_fresh_measurement",
        }
    }
}

impl fmt::Display for PromotionDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DegradationReason
// ---------------------------------------------------------------------------

/// Reason why a hardware claim is degraded during transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DegradationReason {
    /// Source and target architecture families differ.
    ArchMismatch,
    /// Target has narrower vector width than source.
    VectorWidthLoss,
    /// Target has different cache line size.
    CacheSizeDifference,
    /// Microarchitecture varies between source and target.
    MicroarchVariance,
    /// Not enough samples collected.
    InsufficientSamples,
    /// Transport residual is too low to support the claim.
    ResidualTooLow,
}

impl DegradationReason {
    /// All reason variants for exhaustive iteration.
    pub const ALL: &[Self] = &[
        Self::ArchMismatch,
        Self::VectorWidthLoss,
        Self::CacheSizeDifference,
        Self::MicroarchVariance,
        Self::InsufficientSamples,
        Self::ResidualTooLow,
    ];

    /// String identifier for this reason.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArchMismatch => "arch_mismatch",
            Self::VectorWidthLoss => "vector_width_loss",
            Self::CacheSizeDifference => "cache_size_difference",
            Self::MicroarchVariance => "microarch_variance",
            Self::InsufficientSamples => "insufficient_samples",
            Self::ResidualTooLow => "residual_too_low",
        }
    }
}

impl fmt::Display for DegradationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// HardwareClaim
// ---------------------------------------------------------------------------

/// A hardware performance claim asserting that an optimization or benchmark
/// result transports from a source cell to a target cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HardwareClaim {
    /// Kind of performance claim.
    pub kind: HardwareClaimKind,
    /// Source hardware cell identifier.
    pub source_cell_id: String,
    /// Target hardware cell identifier.
    pub target_cell_id: String,
    /// Measured value on source cell (millionths).
    pub measured_value: u64,
    /// Claimed improvement factor (millionths, e.g., 1_200_000 = 1.2x).
    pub claimed_improvement: u64,
    /// Transport residual fraction (millionths, 0–1_000_000).
    /// How much of the source-cell advantage survives on the target.
    pub transport_residual: u64,
    /// Number of samples backing this claim.
    pub sample_count: u64,
    /// Security epoch of the claim.
    pub epoch: SecurityEpoch,
}

impl HardwareClaim {
    /// Create a new hardware claim.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kind: HardwareClaimKind,
        source_cell_id: impl Into<String>,
        target_cell_id: impl Into<String>,
        measured_value: u64,
        claimed_improvement: u64,
        transport_residual: u64,
        sample_count: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            kind,
            source_cell_id: source_cell_id.into(),
            target_cell_id: target_cell_id.into(),
            measured_value,
            claimed_improvement,
            transport_residual,
            sample_count,
            epoch,
        }
    }

    /// Compute a content hash for this claim.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(self.kind.as_str().as_bytes());
        h.update(self.source_cell_id.as_bytes());
        h.update(self.target_cell_id.as_bytes());
        h.update(self.measured_value.to_le_bytes());
        h.update(self.claimed_improvement.to_le_bytes());
        h.update(self.transport_residual.to_le_bytes());
        h.update(self.sample_count.to_le_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        ContentHash::compute(&h.finalize())
    }

    /// Whether source and target are the same cell.
    pub fn is_same_cell(&self) -> bool {
        self.source_cell_id == self.target_cell_id
    }
}

impl fmt::Display for HardwareClaim {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}->{} residual={}",
            self.kind, self.source_cell_id, self.target_cell_id, self.transport_residual,
        )
    }
}

// ---------------------------------------------------------------------------
// ClaimEvidence
// ---------------------------------------------------------------------------

/// Evidence record produced by evaluating a hardware claim against transport
/// residuals.  Includes the verdict, degradation reasons, and an explanation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimEvidence {
    /// The original claim.
    pub claim: HardwareClaim,
    /// Verdict reached after evaluation.
    pub verdict: ClaimVerdict,
    /// Reasons for degradation (empty if Confirmed).
    pub degradation_reasons: Vec<DegradationReason>,
    /// Residual fraction after accounting for degradation (millionths).
    pub residual_fraction: u64,
    /// Content hash of the transport certificate backing this evidence.
    pub transport_certificate_hash: ContentHash,
    /// Human-readable explanation of the verdict.
    pub explanation: String,
}

impl ClaimEvidence {
    /// Content hash of this evidence record.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(b"evidence");
        h.update(self.claim.content_hash().as_bytes());
        h.update(self.verdict.as_str().as_bytes());
        h.update(self.residual_fraction.to_le_bytes());
        h.update(self.transport_certificate_hash.as_bytes());
        h.update(self.explanation.as_bytes());
        for r in &self.degradation_reasons {
            h.update(r.as_str().as_bytes());
        }
        ContentHash::compute(&h.finalize())
    }

    /// Whether the evidence supports the claim.
    pub fn is_supported(&self) -> bool {
        self.verdict.is_usable()
    }
}

impl fmt::Display for ClaimEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} (residual={}, reasons={})",
            self.verdict,
            self.claim,
            self.residual_fraction,
            self.degradation_reasons.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// PromotionRecord
// ---------------------------------------------------------------------------

/// Record of a promotion decision for a hardware claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionRecord {
    /// Identifier of the claim being promoted.
    pub claim_id: String,
    /// Decision reached.
    pub decision: PromotionDecision,
    /// Content hash of the evidence backing this decision.
    pub evidence_hash: ContentHash,
    /// Security epoch of the decision.
    pub epoch: SecurityEpoch,
    /// Human-readable reason for the decision.
    pub reason: String,
}

impl PromotionRecord {
    /// Content hash of this promotion record.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(b"promotion");
        h.update(self.claim_id.as_bytes());
        h.update(self.decision.as_str().as_bytes());
        h.update(self.evidence_hash.as_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        h.update(self.reason.as_bytes());
        ContentHash::compute(&h.finalize())
    }
}

impl fmt::Display for PromotionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "promotion[{}]: {} — {}", self.claim_id, self.decision, self.reason)
    }
}

// ---------------------------------------------------------------------------
// RollbackRecord
// ---------------------------------------------------------------------------

/// Record of a rollback triggered by regression after promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackRecord {
    /// Identifier of the claim being rolled back.
    pub claim_id: String,
    /// Original verdict before rollback.
    pub original_verdict: ClaimVerdict,
    /// Verdict after rollback (always Unsupported or RequiresLocal).
    pub rollback_verdict: ClaimVerdict,
    /// What triggered the rollback.
    pub trigger: String,
    /// Security epoch of the rollback.
    pub epoch: SecurityEpoch,
    /// Content hash of the receipt.
    pub receipt_hash: ContentHash,
}

impl RollbackRecord {
    /// Create a new rollback record with computed receipt hash.
    pub fn new(
        claim_id: impl Into<String>,
        original_verdict: ClaimVerdict,
        rollback_verdict: ClaimVerdict,
        trigger: impl Into<String>,
        epoch: SecurityEpoch,
    ) -> Self {
        let claim_id = claim_id.into();
        let trigger = trigger.into();
        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(b"rollback");
        h.update(claim_id.as_bytes());
        h.update(original_verdict.as_str().as_bytes());
        h.update(rollback_verdict.as_str().as_bytes());
        h.update(trigger.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        let receipt_hash = ContentHash::compute(&h.finalize());
        Self {
            claim_id,
            original_verdict,
            rollback_verdict,
            trigger,
            epoch,
            receipt_hash,
        }
    }
}

impl fmt::Display for RollbackRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "rollback[{}]: {} -> {} (trigger: {})",
            self.claim_id, self.original_verdict, self.rollback_verdict, self.trigger,
        )
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the hardware board claim gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Residual threshold for `Confirmed` verdict (millionths).
    pub full_transport_threshold: u64,
    /// Residual threshold for `Downgraded` verdict (millionths).
    pub partial_transport_threshold: u64,
    /// Residual threshold for `RequiresLocal` verdict (millionths).
    pub degraded_threshold: u64,
    /// Minimum number of samples required.
    pub min_samples: u64,
    /// Regression threshold that triggers rollback (millionths).
    pub rollback_regression_threshold: u64,
}

impl GateConfig {
    /// Create configuration with default thresholds.
    pub fn default_config() -> Self {
        Self {
            full_transport_threshold: DEFAULT_FULL_TRANSPORT_THRESHOLD,
            partial_transport_threshold: DEFAULT_PARTIAL_TRANSPORT_THRESHOLD,
            degraded_threshold: DEFAULT_DEGRADED_THRESHOLD,
            min_samples: DEFAULT_MIN_SAMPLES,
            rollback_regression_threshold: DEFAULT_ROLLBACK_REGRESSION_THRESHOLD,
        }
    }

    /// Permissive configuration that confirms everything.
    pub fn permissive() -> Self {
        Self {
            full_transport_threshold: 0,
            partial_transport_threshold: 0,
            degraded_threshold: 0,
            min_samples: 0,
            rollback_regression_threshold: MILLIONTHS,
        }
    }

    /// Strict configuration with higher thresholds.
    pub fn strict() -> Self {
        Self {
            full_transport_threshold: 980_000,
            partial_transport_threshold: 800_000,
            degraded_threshold: 500_000,
            min_samples: 50,
            rollback_regression_threshold: 20_000,
        }
    }
}

impl Default for GateConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

/// Aggregate summary of a batch evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Total claims evaluated.
    pub total_claims: usize,
    /// Number of Confirmed verdicts.
    pub confirmed: usize,
    /// Number of Downgraded verdicts.
    pub downgraded: usize,
    /// Number of RequiresLocal verdicts.
    pub requires_local: usize,
    /// Number of Unsupported verdicts.
    pub unsupported: usize,
    /// Number of InsufficientEvidence verdicts.
    pub insufficient: usize,
    /// Pass rate: (confirmed + downgraded) / total (millionths).
    pub pass_rate: u64,
}

impl GateSummary {
    /// Compute a summary from a list of verdicts.
    pub fn from_verdicts(verdicts: &[ClaimVerdict]) -> Self {
        let total_claims = verdicts.len();
        let confirmed = verdicts.iter().filter(|v| **v == ClaimVerdict::Confirmed).count();
        let downgraded = verdicts.iter().filter(|v| **v == ClaimVerdict::Downgraded).count();
        let requires_local = verdicts
            .iter()
            .filter(|v| **v == ClaimVerdict::RequiresLocal)
            .count();
        let unsupported = verdicts.iter().filter(|v| **v == ClaimVerdict::Unsupported).count();
        let insufficient = verdicts
            .iter()
            .filter(|v| **v == ClaimVerdict::InsufficientEvidence)
            .count();

        let passed = (confirmed + downgraded) as u64;
        let pass_rate = passed
            .saturating_mul(MILLIONTHS)
            .checked_div(total_claims as u64)
            .unwrap_or(0);

        Self {
            total_claims,
            confirmed,
            downgraded,
            requires_local,
            unsupported,
            insufficient,
            pass_rate,
        }
    }

    /// Whether all claims passed.
    pub fn all_passed(&self) -> bool {
        self.total_claims > 0
            && self.requires_local == 0
            && self.unsupported == 0
            && self.insufficient == 0
    }

    /// Whether any claims are unsupported.
    pub fn has_unsupported(&self) -> bool {
        self.unsupported > 0
    }

    /// Content hash of the summary.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(b"summary");
        h.update((self.total_claims as u64).to_le_bytes());
        h.update((self.confirmed as u64).to_le_bytes());
        h.update((self.downgraded as u64).to_le_bytes());
        h.update((self.requires_local as u64).to_le_bytes());
        h.update((self.unsupported as u64).to_le_bytes());
        h.update((self.insufficient as u64).to_le_bytes());
        h.update(self.pass_rate.to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

impl fmt::Display for GateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "claims={} confirmed={} downgraded={} local={} unsupported={} insufficient={} pass_rate={}",
            self.total_claims,
            self.confirmed,
            self.downgraded,
            self.requires_local,
            self.unsupported,
            self.insufficient,
            self.pass_rate,
        )
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Content-hashed receipt of a gate evaluation decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Content hash of this receipt.
    pub receipt_hash: ContentHash,
    /// Component that produced the receipt.
    pub component: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Verdict rendered.
    pub verdict: ClaimVerdict,
    /// Content hash of the claim.
    pub claim_hash: ContentHash,
}

impl DecisionReceipt {
    /// Create a new decision receipt with computed hash.
    pub fn new(
        epoch: SecurityEpoch,
        verdict: ClaimVerdict,
        claim_hash: ContentHash,
    ) -> Self {
        let component = COMPONENT.to_string();
        let mut h = Sha256::new();
        h.update(component.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(verdict.as_str().as_bytes());
        h.update(claim_hash.as_bytes());
        let receipt_hash = ContentHash::compute(&h.finalize());
        Self {
            receipt_hash,
            component,
            epoch,
            verdict,
            claim_hash,
        }
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "receipt[{}]: {} at {}",
            self.verdict, self.component, self.epoch,
        )
    }
}

// ---------------------------------------------------------------------------
// Core evaluation functions
// ---------------------------------------------------------------------------

/// Collect degradation reasons from a hardware claim's properties.
fn collect_degradation_reasons(claim: &HardwareClaim, config: &GateConfig) -> Vec<DegradationReason> {
    let mut reasons = Vec::new();

    // If residual is below the full transport threshold, something is degraded.
    if claim.transport_residual < config.full_transport_threshold {
        reasons.push(DegradationReason::MicroarchVariance);
    }

    // If residual is below partial threshold, likely an arch mismatch.
    if claim.transport_residual < config.partial_transport_threshold {
        reasons.push(DegradationReason::ArchMismatch);
    }

    // If residual is below degraded threshold, vector width loss likely.
    if claim.transport_residual < config.degraded_threshold {
        reasons.push(DegradationReason::VectorWidthLoss);
        reasons.push(DegradationReason::CacheSizeDifference);
    }

    // Insufficient samples.
    if claim.sample_count < config.min_samples {
        reasons.push(DegradationReason::InsufficientSamples);
    }

    // Very low residual.
    if claim.transport_residual < config.degraded_threshold.saturating_div(2) {
        reasons.push(DegradationReason::ResidualTooLow);
    }

    reasons.truncate(MAX_DEGRADATION_REASONS);
    reasons
}

/// Build a human-readable explanation of the verdict.
fn build_explanation(
    claim: &HardwareClaim,
    verdict: ClaimVerdict,
    reasons: &[DegradationReason],
) -> String {
    match verdict {
        ClaimVerdict::Confirmed => format!(
            "{} claim from {} to {} confirmed: transport residual {} supports \
             claimed improvement {}",
            claim.kind,
            claim.source_cell_id,
            claim.target_cell_id,
            claim.transport_residual,
            claim.claimed_improvement,
        ),
        ClaimVerdict::Downgraded => format!(
            "{} claim from {} to {} downgraded: transport residual {} is below \
             full-transport threshold; {} degradation reason(s) identified",
            claim.kind,
            claim.source_cell_id,
            claim.target_cell_id,
            claim.transport_residual,
            reasons.len(),
        ),
        ClaimVerdict::RequiresLocal => format!(
            "{} claim from {} to {} requires fresh local measurement: \
             transport residual {} is too low for cross-cell promotion; \
             {} degradation reason(s)",
            claim.kind,
            claim.source_cell_id,
            claim.target_cell_id,
            claim.transport_residual,
            reasons.len(),
        ),
        ClaimVerdict::Unsupported => format!(
            "{} claim from {} to {} marked unsupported: transport residual {} \
             below minimum threshold; hardware region cannot be served. \
             Reasons: {}",
            claim.kind,
            claim.source_cell_id,
            claim.target_cell_id,
            claim.transport_residual,
            reasons
                .iter()
                .map(|r| r.as_str())
                .collect::<Vec<_>>()
                .join(", "),
        ),
        ClaimVerdict::InsufficientEvidence => format!(
            "{} claim from {} to {} has insufficient evidence: {} sample(s) collected",
            claim.kind,
            claim.source_cell_id,
            claim.target_cell_id,
            claim.sample_count,
        ),
    }
}

/// Evaluate a single hardware claim against a gate configuration.
///
/// Returns a `ClaimEvidence` containing the verdict, degradation reasons,
/// transport certificate hash, and a human-readable explanation.
pub fn evaluate(claim: &HardwareClaim, config: &GateConfig) -> ClaimEvidence {
    // 1. Check sample sufficiency first.
    if claim.sample_count < config.min_samples {
        let reasons = vec![DegradationReason::InsufficientSamples];
        let explanation = build_explanation(claim, ClaimVerdict::InsufficientEvidence, &reasons);
        return ClaimEvidence {
            claim: claim.clone(),
            verdict: ClaimVerdict::InsufficientEvidence,
            degradation_reasons: reasons,
            residual_fraction: claim.transport_residual,
            transport_certificate_hash: claim.content_hash(),
            explanation,
        };
    }

    // 2. Classify by transport residual.
    let verdict = if claim.transport_residual >= config.full_transport_threshold {
        ClaimVerdict::Confirmed
    } else if claim.transport_residual >= config.partial_transport_threshold {
        ClaimVerdict::Downgraded
    } else if claim.transport_residual >= config.degraded_threshold {
        ClaimVerdict::RequiresLocal
    } else {
        ClaimVerdict::Unsupported
    };

    // 3. Collect degradation reasons.
    let reasons = collect_degradation_reasons(claim, config);

    // 4. Build explanation.
    let explanation = build_explanation(claim, verdict, &reasons);

    ClaimEvidence {
        claim: claim.clone(),
        verdict,
        degradation_reasons: reasons,
        residual_fraction: claim.transport_residual,
        transport_certificate_hash: claim.content_hash(),
        explanation,
    }
}

/// Evaluate a promotion decision based on claim evidence.
///
/// Maps the evidence verdict to a promotion decision with a content-hashed
/// record.
pub fn evaluate_promotion(evidence: &ClaimEvidence, config: &GateConfig) -> PromotionRecord {
    let (decision, reason) = match evidence.verdict {
        ClaimVerdict::Confirmed => (
            PromotionDecision::Promote,
            "transport evidence fully supports promotion".to_string(),
        ),
        ClaimVerdict::Downgraded => {
            // Downgraded can still promote if residual is close enough.
            if evidence.residual_fraction
                >= config.full_transport_threshold.saturating_sub(config.rollback_regression_threshold)
            {
                (
                    PromotionDecision::Promote,
                    format!(
                        "downgraded but residual {} within regression tolerance",
                        evidence.residual_fraction
                    ),
                )
            } else {
                (
                    PromotionDecision::Hold,
                    format!(
                        "downgraded with residual {}; holding pending further evidence",
                        evidence.residual_fraction
                    ),
                )
            }
        }
        ClaimVerdict::RequiresLocal => (
            PromotionDecision::RequireFreshMeasurement,
            format!(
                "transport residual {} too low; fresh local measurement required",
                evidence.residual_fraction
            ),
        ),
        ClaimVerdict::Unsupported => (
            PromotionDecision::Rollback,
            format!(
                "hardware region unsupported (residual {}); rolling back",
                evidence.residual_fraction
            ),
        ),
        ClaimVerdict::InsufficientEvidence => (
            PromotionDecision::Hold,
            "insufficient evidence to make promotion decision".to_string(),
        ),
    };

    let claim_id = format!(
        "{}:{}->{}", evidence.claim.kind, evidence.claim.source_cell_id, evidence.claim.target_cell_id,
    );

    PromotionRecord {
        claim_id,
        decision,
        evidence_hash: evidence.content_hash(),
        epoch: evidence.claim.epoch,
        reason,
    }
}

/// Evaluate a batch of hardware claims, returning per-claim evidence and
/// an aggregate summary.
pub fn evaluate_batch(
    claims: &[HardwareClaim],
    config: &GateConfig,
) -> (Vec<ClaimEvidence>, GateSummary) {
    let evidence: Vec<ClaimEvidence> = claims.iter().map(|c| evaluate(c, config)).collect();
    let verdicts: Vec<ClaimVerdict> = evidence.iter().map(|e| e.verdict).collect();
    let summary = GateSummary::from_verdicts(&verdicts);
    (evidence, summary)
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(500)
    }

    fn confirmed_claim() -> HardwareClaim {
        HardwareClaim::new(
            HardwareClaimKind::Throughput,
            "cell-a",
            "cell-b",
            2_000_000,
            1_200_000,
            960_000, // 96% — above default 95% full threshold
            100,
            epoch(),
        )
    }

    fn downgraded_claim() -> HardwareClaim {
        HardwareClaim::new(
            HardwareClaimKind::Latency,
            "cell-a",
            "cell-c",
            1_500_000,
            1_100_000,
            800_000, // 80% — between 70% and 95%
            50,
            epoch(),
        )
    }

    fn requires_local_claim() -> HardwareClaim {
        HardwareClaim::new(
            HardwareClaimKind::MemoryEfficiency,
            "cell-a",
            "cell-d",
            1_000_000,
            1_050_000,
            400_000, // 40% — between 30% and 70%
            30,
            epoch(),
        )
    }

    fn unsupported_claim() -> HardwareClaim {
        HardwareClaim::new(
            HardwareClaimKind::StartupTime,
            "cell-a",
            "cell-e",
            800_000,
            1_300_000,
            100_000, // 10% — below 30%
            25,
            epoch(),
        )
    }

    fn insufficient_claim() -> HardwareClaim {
        HardwareClaim::new(
            HardwareClaimKind::TailLatency,
            "cell-a",
            "cell-f",
            900_000,
            1_150_000,
            950_000,
            5, // below default min_samples=10
            epoch(),
        )
    }

    // --- Constants ---

    #[test]
    fn test_schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SCHEMA_VERSION.contains("hardware-board-claim-gate"));
    }

    #[test]
    fn test_bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
        assert_eq!(BEAD_ID, "bd-1lsy.7.16.3");
    }

    #[test]
    fn test_component_name() {
        assert_eq!(COMPONENT, "hardware_board_claim_gate");
    }

    #[test]
    fn test_policy_id() {
        assert!(POLICY_ID.starts_with("RGC-"));
        assert_eq!(POLICY_ID, "RGC-616C");
    }

    #[test]
    fn test_millionths_constant() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    #[test]
    fn test_threshold_ordering() {
        assert!(DEFAULT_FULL_TRANSPORT_THRESHOLD > DEFAULT_PARTIAL_TRANSPORT_THRESHOLD);
        assert!(DEFAULT_PARTIAL_TRANSPORT_THRESHOLD > DEFAULT_DEGRADED_THRESHOLD);
        assert!(DEFAULT_DEGRADED_THRESHOLD > 0);
    }

    // --- HardwareClaimKind ---

    #[test]
    fn test_claim_kind_all_length() {
        assert_eq!(HardwareClaimKind::ALL.len(), 6);
    }

    #[test]
    fn test_claim_kind_names_unique() {
        let names: std::collections::BTreeSet<&str> =
            HardwareClaimKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), HardwareClaimKind::ALL.len());
    }

    #[test]
    fn test_claim_kind_display() {
        for k in HardwareClaimKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn test_claim_kind_serde_roundtrip() {
        for k in HardwareClaimKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: HardwareClaimKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- ClaimVerdict ---

    #[test]
    fn test_verdict_all_length() {
        assert_eq!(ClaimVerdict::ALL.len(), 5);
    }

    #[test]
    fn test_verdict_names_unique() {
        let names: std::collections::BTreeSet<&str> =
            ClaimVerdict::ALL.iter().map(|v| v.as_str()).collect();
        assert_eq!(names.len(), ClaimVerdict::ALL.len());
    }

    #[test]
    fn test_verdict_display() {
        for v in ClaimVerdict::ALL {
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    #[test]
    fn test_verdict_serde_roundtrip() {
        for v in ClaimVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: ClaimVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    #[test]
    fn test_verdict_is_usable() {
        assert!(ClaimVerdict::Confirmed.is_usable());
        assert!(ClaimVerdict::Downgraded.is_usable());
        assert!(!ClaimVerdict::RequiresLocal.is_usable());
        assert!(!ClaimVerdict::Unsupported.is_usable());
        assert!(!ClaimVerdict::InsufficientEvidence.is_usable());
    }

    // --- PromotionDecision ---

    #[test]
    fn test_promotion_all_length() {
        assert_eq!(PromotionDecision::ALL.len(), 4);
    }

    #[test]
    fn test_promotion_display() {
        for d in PromotionDecision::ALL {
            assert_eq!(d.to_string(), d.as_str());
        }
    }

    #[test]
    fn test_promotion_serde_roundtrip() {
        for d in PromotionDecision::ALL {
            let json = serde_json::to_string(d).unwrap();
            let back: PromotionDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(*d, back);
        }
    }

    // --- DegradationReason ---

    #[test]
    fn test_degradation_all_length() {
        assert_eq!(DegradationReason::ALL.len(), 6);
    }

    #[test]
    fn test_degradation_names_unique() {
        let names: std::collections::BTreeSet<&str> =
            DegradationReason::ALL.iter().map(|r| r.as_str()).collect();
        assert_eq!(names.len(), DegradationReason::ALL.len());
    }

    #[test]
    fn test_degradation_display() {
        for r in DegradationReason::ALL {
            assert_eq!(r.to_string(), r.as_str());
        }
    }

    #[test]
    fn test_degradation_serde_roundtrip() {
        for r in DegradationReason::ALL {
            let json = serde_json::to_string(r).unwrap();
            let back: DegradationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*r, back);
        }
    }

    // --- HardwareClaim ---

    #[test]
    fn test_hardware_claim_construction() {
        let c = confirmed_claim();
        assert_eq!(c.kind, HardwareClaimKind::Throughput);
        assert_eq!(c.source_cell_id, "cell-a");
        assert_eq!(c.target_cell_id, "cell-b");
        assert_eq!(c.transport_residual, 960_000);
        assert_eq!(c.sample_count, 100);
    }

    #[test]
    fn test_hardware_claim_content_hash_deterministic() {
        let c1 = confirmed_claim();
        let c2 = confirmed_claim();
        assert_eq!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn test_hardware_claim_content_hash_changes() {
        let c1 = confirmed_claim();
        let c2 = downgraded_claim();
        assert_ne!(c1.content_hash(), c2.content_hash());
    }

    #[test]
    fn test_hardware_claim_is_same_cell() {
        let same = HardwareClaim::new(
            HardwareClaimKind::Throughput,
            "cell-a",
            "cell-a",
            1_000_000,
            1_000_000,
            1_000_000,
            100,
            epoch(),
        );
        assert!(same.is_same_cell());
        assert!(!confirmed_claim().is_same_cell());
    }

    #[test]
    fn test_hardware_claim_display() {
        let c = confirmed_claim();
        let s = c.to_string();
        assert!(s.contains("throughput"));
        assert!(s.contains("cell-a"));
        assert!(s.contains("cell-b"));
    }

    #[test]
    fn test_hardware_claim_serde_roundtrip() {
        let c = confirmed_claim();
        let json = serde_json::to_string(&c).unwrap();
        let back: HardwareClaim = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- evaluate lifecycle ---

    #[test]
    fn test_evaluate_confirmed() {
        let config = GateConfig::default();
        let ev = evaluate(&confirmed_claim(), &config);
        assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
        assert!(ev.is_supported());
        assert!(ev.explanation.contains("confirmed"));
    }

    #[test]
    fn test_evaluate_downgraded() {
        let config = GateConfig::default();
        let ev = evaluate(&downgraded_claim(), &config);
        assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
        assert!(ev.is_supported());
        assert!(ev.explanation.contains("downgraded"));
        assert!(!ev.degradation_reasons.is_empty());
    }

    #[test]
    fn test_evaluate_requires_local() {
        let config = GateConfig::default();
        let ev = evaluate(&requires_local_claim(), &config);
        assert_eq!(ev.verdict, ClaimVerdict::RequiresLocal);
        assert!(!ev.is_supported());
        assert!(ev.explanation.contains("local measurement"));
    }

    #[test]
    fn test_evaluate_unsupported() {
        let config = GateConfig::default();
        let ev = evaluate(&unsupported_claim(), &config);
        assert_eq!(ev.verdict, ClaimVerdict::Unsupported);
        assert!(!ev.is_supported());
        assert!(ev.explanation.contains("unsupported"));
    }

    #[test]
    fn test_evaluate_insufficient_evidence() {
        let config = GateConfig::default();
        let ev = evaluate(&insufficient_claim(), &config);
        assert_eq!(ev.verdict, ClaimVerdict::InsufficientEvidence);
        assert!(!ev.is_supported());
        assert!(ev.explanation.contains("insufficient"));
    }

    #[test]
    fn test_evaluate_evidence_hash_deterministic() {
        let config = GateConfig::default();
        let ev1 = evaluate(&confirmed_claim(), &config);
        let ev2 = evaluate(&confirmed_claim(), &config);
        assert_eq!(ev1.content_hash(), ev2.content_hash());
    }

    // --- evaluate_promotion lifecycle ---

    #[test]
    fn test_evaluate_promotion_confirmed_promotes() {
        let config = GateConfig::default();
        let ev = evaluate(&confirmed_claim(), &config);
        let pr = evaluate_promotion(&ev, &config);
        assert_eq!(pr.decision, PromotionDecision::Promote);
        assert!(pr.reason.contains("promotion"));
    }

    #[test]
    fn test_evaluate_promotion_downgraded_holds() {
        let config = GateConfig::default();
        let ev = evaluate(&downgraded_claim(), &config);
        let pr = evaluate_promotion(&ev, &config);
        assert_eq!(pr.decision, PromotionDecision::Hold);
    }

    #[test]
    fn test_evaluate_promotion_requires_local_measurement() {
        let config = GateConfig::default();
        let ev = evaluate(&requires_local_claim(), &config);
        let pr = evaluate_promotion(&ev, &config);
        assert_eq!(pr.decision, PromotionDecision::RequireFreshMeasurement);
    }

    #[test]
    fn test_evaluate_promotion_unsupported_rollback() {
        let config = GateConfig::default();
        let ev = evaluate(&unsupported_claim(), &config);
        let pr = evaluate_promotion(&ev, &config);
        assert_eq!(pr.decision, PromotionDecision::Rollback);
    }

    #[test]
    fn test_evaluate_promotion_insufficient_holds() {
        let config = GateConfig::default();
        let ev = evaluate(&insufficient_claim(), &config);
        let pr = evaluate_promotion(&ev, &config);
        assert_eq!(pr.decision, PromotionDecision::Hold);
    }

    #[test]
    fn test_promotion_record_content_hash() {
        let config = GateConfig::default();
        let ev = evaluate(&confirmed_claim(), &config);
        let pr = evaluate_promotion(&ev, &config);
        let h1 = pr.content_hash();
        let h2 = pr.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_promotion_record_display() {
        let config = GateConfig::default();
        let ev = evaluate(&confirmed_claim(), &config);
        let pr = evaluate_promotion(&ev, &config);
        let s = pr.to_string();
        assert!(s.contains("promotion"));
        assert!(s.contains("promote"));
    }

    // --- RollbackRecord ---

    #[test]
    fn test_rollback_record_creation() {
        let rb = RollbackRecord::new(
            "claim-1",
            ClaimVerdict::Downgraded,
            ClaimVerdict::Unsupported,
            "regression detected",
            epoch(),
        );
        assert_eq!(rb.claim_id, "claim-1");
        assert_eq!(rb.original_verdict, ClaimVerdict::Downgraded);
        assert_eq!(rb.rollback_verdict, ClaimVerdict::Unsupported);
        assert_eq!(rb.trigger, "regression detected");
    }

    #[test]
    fn test_rollback_record_hash_deterministic() {
        let rb1 = RollbackRecord::new(
            "claim-1",
            ClaimVerdict::Confirmed,
            ClaimVerdict::RequiresLocal,
            "drift",
            epoch(),
        );
        let rb2 = RollbackRecord::new(
            "claim-1",
            ClaimVerdict::Confirmed,
            ClaimVerdict::RequiresLocal,
            "drift",
            epoch(),
        );
        assert_eq!(rb1.receipt_hash, rb2.receipt_hash);
    }

    #[test]
    fn test_rollback_record_display() {
        let rb = RollbackRecord::new(
            "claim-2",
            ClaimVerdict::Confirmed,
            ClaimVerdict::Unsupported,
            "arch change",
            epoch(),
        );
        let s = rb.to_string();
        assert!(s.contains("rollback"));
        assert!(s.contains("claim-2"));
    }

    #[test]
    fn test_rollback_record_serde() {
        let rb = RollbackRecord::new(
            "claim-3",
            ClaimVerdict::Downgraded,
            ClaimVerdict::RequiresLocal,
            "cache miss spike",
            epoch(),
        );
        let json = serde_json::to_string(&rb).unwrap();
        let back: RollbackRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(rb, back);
    }

    // --- GateConfig ---

    #[test]
    fn test_gate_config_default() {
        let config = GateConfig::default();
        assert_eq!(config.full_transport_threshold, 950_000);
        assert_eq!(config.partial_transport_threshold, 700_000);
        assert_eq!(config.degraded_threshold, 300_000);
        assert_eq!(config.min_samples, 10);
        assert_eq!(config.rollback_regression_threshold, 50_000);
    }

    #[test]
    fn test_gate_config_permissive() {
        let config = GateConfig::permissive();
        assert_eq!(config.full_transport_threshold, 0);
        assert_eq!(config.min_samples, 0);
    }

    #[test]
    fn test_gate_config_strict() {
        let config = GateConfig::strict();
        assert!(config.full_transport_threshold > GateConfig::default().full_transport_threshold);
        assert!(config.min_samples > GateConfig::default().min_samples);
    }

    #[test]
    fn test_gate_config_serde() {
        let config = GateConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    // --- evaluate_batch ---

    #[test]
    fn test_evaluate_batch_mixed() {
        let config = GateConfig::default();
        let claims = vec![
            confirmed_claim(),
            downgraded_claim(),
            requires_local_claim(),
            unsupported_claim(),
            insufficient_claim(),
        ];
        let (evidence, summary) = evaluate_batch(&claims, &config);
        assert_eq!(evidence.len(), 5);
        assert_eq!(summary.total_claims, 5);
        assert_eq!(summary.confirmed, 1);
        assert_eq!(summary.downgraded, 1);
        assert_eq!(summary.requires_local, 1);
        assert_eq!(summary.unsupported, 1);
        assert_eq!(summary.insufficient, 1);
        // pass_rate = 2/5 = 400_000
        assert_eq!(summary.pass_rate, 400_000);
    }

    #[test]
    fn test_evaluate_batch_all_confirmed() {
        let config = GateConfig::default();
        let claims = vec![confirmed_claim(), confirmed_claim(), confirmed_claim()];
        let (_, summary) = evaluate_batch(&claims, &config);
        assert_eq!(summary.confirmed, 3);
        assert!(summary.all_passed());
        assert_eq!(summary.pass_rate, MILLIONTHS);
    }

    #[test]
    fn test_evaluate_batch_empty() {
        let config = GateConfig::default();
        let (evidence, summary) = evaluate_batch(&[], &config);
        assert!(evidence.is_empty());
        assert_eq!(summary.total_claims, 0);
        assert_eq!(summary.pass_rate, 0);
        assert!(!summary.all_passed());
    }

    // --- GateSummary ---

    #[test]
    fn test_gate_summary_has_unsupported() {
        let summary = GateSummary::from_verdicts(&[
            ClaimVerdict::Confirmed,
            ClaimVerdict::Unsupported,
        ]);
        assert!(summary.has_unsupported());
    }

    #[test]
    fn test_gate_summary_content_hash_deterministic() {
        let s1 = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed, ClaimVerdict::Downgraded]);
        let s2 = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed, ClaimVerdict::Downgraded]);
        assert_eq!(s1.content_hash(), s2.content_hash());
    }

    #[test]
    fn test_gate_summary_display() {
        let s = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed]);
        let d = s.to_string();
        assert!(d.contains("claims=1"));
        assert!(d.contains("confirmed=1"));
    }

    #[test]
    fn test_gate_summary_pass_rate_all_confirmed() {
        let s = GateSummary::from_verdicts(&[ClaimVerdict::Confirmed; 4]);
        assert_eq!(s.pass_rate, MILLIONTHS);
    }

    #[test]
    fn test_gate_summary_pass_rate_none() {
        let s = GateSummary::from_verdicts(&[ClaimVerdict::Unsupported; 3]);
        assert_eq!(s.pass_rate, 0);
        assert!(!s.all_passed());
    }

    // --- DecisionReceipt ---

    #[test]
    fn test_decision_receipt_creation() {
        let claim_hash = ContentHash::compute(b"test-claim");
        let receipt = DecisionReceipt::new(epoch(), ClaimVerdict::Confirmed, claim_hash.clone());
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.verdict, ClaimVerdict::Confirmed);
        assert_eq!(receipt.claim_hash, claim_hash);
    }

    #[test]
    fn test_decision_receipt_hash_deterministic() {
        let claim_hash = ContentHash::compute(b"claim-x");
        let r1 = DecisionReceipt::new(epoch(), ClaimVerdict::Downgraded, claim_hash.clone());
        let r2 = DecisionReceipt::new(epoch(), ClaimVerdict::Downgraded, claim_hash);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn test_decision_receipt_different_verdicts_different_hashes() {
        let claim_hash = ContentHash::compute(b"claim-y");
        let r1 = DecisionReceipt::new(epoch(), ClaimVerdict::Confirmed, claim_hash.clone());
        let r2 = DecisionReceipt::new(epoch(), ClaimVerdict::Unsupported, claim_hash);
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn test_decision_receipt_display() {
        let receipt = DecisionReceipt::new(
            epoch(),
            ClaimVerdict::RequiresLocal,
            ContentHash::compute(b"abc"),
        );
        let s = receipt.to_string();
        assert!(s.contains("receipt"));
        assert!(s.contains("requires_local"));
    }

    #[test]
    fn test_decision_receipt_serde() {
        let receipt = DecisionReceipt::new(
            epoch(),
            ClaimVerdict::Confirmed,
            ContentHash::compute(b"serde-test"),
        );
        let json = serde_json::to_string(&receipt).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    // --- Edge cases ---

    #[test]
    fn test_zero_residual_unsupported() {
        let claim = HardwareClaim::new(
            HardwareClaimKind::EnergyEfficiency,
            "src",
            "dst",
            1_000_000,
            1_100_000,
            0, // zero residual
            100,
            epoch(),
        );
        let config = GateConfig::default();
        let ev = evaluate(&claim, &config);
        assert_eq!(ev.verdict, ClaimVerdict::Unsupported);
    }

    #[test]
    fn test_max_residual_confirmed() {
        let claim = HardwareClaim::new(
            HardwareClaimKind::Throughput,
            "src",
            "dst",
            1_000_000,
            1_500_000,
            MILLIONTHS, // 100% residual
            100,
            epoch(),
        );
        let config = GateConfig::default();
        let ev = evaluate(&claim, &config);
        assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
    }

    #[test]
    fn test_boundary_full_threshold_exact() {
        let claim = HardwareClaim::new(
            HardwareClaimKind::Latency,
            "src",
            "dst",
            1_000_000,
            1_050_000,
            950_000, // exactly at full threshold
            100,
            epoch(),
        );
        let config = GateConfig::default();
        let ev = evaluate(&claim, &config);
        assert_eq!(ev.verdict, ClaimVerdict::Confirmed);
    }

    #[test]
    fn test_boundary_just_below_full_threshold() {
        let claim = HardwareClaim::new(
            HardwareClaimKind::Latency,
            "src",
            "dst",
            1_000_000,
            1_050_000,
            949_999, // one below full threshold
            100,
            epoch(),
        );
        let config = GateConfig::default();
        let ev = evaluate(&claim, &config);
        assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
    }

    #[test]
    fn test_boundary_partial_threshold_exact() {
        let claim = HardwareClaim::new(
            HardwareClaimKind::MemoryEfficiency,
            "src",
            "dst",
            1_000_000,
            1_050_000,
            700_000, // exactly at partial threshold
            100,
            epoch(),
        );
        let config = GateConfig::default();
        let ev = evaluate(&claim, &config);
        assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
    }

    #[test]
    fn test_boundary_degraded_threshold_exact() {
        let claim = HardwareClaim::new(
            HardwareClaimKind::TailLatency,
            "src",
            "dst",
            1_000_000,
            1_050_000,
            300_000, // exactly at degraded threshold
            100,
            epoch(),
        );
        let config = GateConfig::default();
        let ev = evaluate(&claim, &config);
        assert_eq!(ev.verdict, ClaimVerdict::RequiresLocal);
    }

    #[test]
    fn test_custom_config_thresholds() {
        let config = GateConfig {
            full_transport_threshold: 500_000,
            partial_transport_threshold: 300_000,
            degraded_threshold: 100_000,
            min_samples: 5,
            rollback_regression_threshold: 10_000,
        };
        // Claim with residual 400_000 => between 300k and 500k => Downgraded
        let claim = HardwareClaim::new(
            HardwareClaimKind::Throughput,
            "x",
            "y",
            1_000_000,
            1_200_000,
            400_000,
            10,
            epoch(),
        );
        let ev = evaluate(&claim, &config);
        assert_eq!(ev.verdict, ClaimVerdict::Downgraded);
    }

    #[test]
    fn test_claim_evidence_display() {
        let config = GateConfig::default();
        let ev = evaluate(&confirmed_claim(), &config);
        let s = ev.to_string();
        assert!(s.contains("confirmed"));
    }

    #[test]
    fn test_claim_evidence_serde() {
        let config = GateConfig::default();
        let ev = evaluate(&downgraded_claim(), &config);
        let json = serde_json::to_string(&ev).unwrap();
        let back: ClaimEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }
}
