//! Synthesis kernel promotion into shipped paths, AOT artifacts, and evidence.
//!
//! Implements [RGC-613C]: promotes verified synthesized kernels from the
//! budgeted synthesis engine into real shipped execution paths, AOT artifacts,
//! and public supremacy evidence.  A kernel may only be promoted when it has:
//!
//! 1. A verified equivalence proof from the synthesis session.
//! 2. Speedup exceeding the promotion threshold on the target hardware.
//! 3. No active counterexamples above severity threshold.
//! 4. A regression gate pass from the performance pipeline.
//! 5. An AOT compile receipt confirming the kernel compiles cleanly.
//!
//! Promotion is monotonic: once promoted, a kernel cannot silently revert.
//! Demotion requires an explicit `DemotionReceipt` recording the cause.
//!
//! # Design
//!
//! - `PromotionTarget` classifies where a kernel will be shipped.
//! - `PromotionEligibility` captures the evidence needed for promotion.
//! - `PromotionDecision` is the accept/reject/defer result.
//! - `PromotionGate` evaluates candidates against configurable thresholds.
//! - `DemotionReceipt` records when and why a promoted kernel was rolled back.
//! - `PromotionLedger` tracks the full lifecycle of promoted kernels.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-613C]

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.synthesis-kernel-promotion.v1";

/// Component name.
pub const COMPONENT: &str = "synthesis_kernel_promotion";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.13.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-613C";

/// Fixed-point unit.
const MILLION: u64 = 1_000_000;

/// Minimum speedup required for promotion (millionths).
/// 10% = 100_000.
pub const MIN_PROMOTION_SPEEDUP: u64 = 100_000;

/// Minimum equivalence proof coverage for promotion (millionths).
/// 95% = 950_000.
pub const MIN_PROOF_COVERAGE: u64 = 950_000;

/// Maximum allowed active counterexamples for promotion.
pub const MAX_ACTIVE_COUNTEREXAMPLES: usize = 0;

/// Maximum severity for any counterexample (millionths).
/// 0 means zero tolerance.
pub const MAX_COUNTEREXAMPLE_SEVERITY: u64 = 0;

/// Minimum regression gate confidence (millionths).
/// 90% = 900_000.
pub const MIN_REGRESSION_CONFIDENCE: u64 = 900_000;

// ---------------------------------------------------------------------------
// PromotionTarget
// ---------------------------------------------------------------------------

/// Where a promoted kernel will be shipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionTarget {
    /// Shipped in the baseline interpreter hot path.
    BaselineHotPath,
    /// Shipped as an AOT-compiled artifact.
    AotArtifact,
    /// Shipped in the adaptive profile router.
    AdaptiveRouter,
    /// Shipped as supremacy evidence for public claims.
    SupremacyEvidence,
    /// Shipped as a support-surface artifact for operator tools.
    SupportSurface,
}

impl PromotionTarget {
    pub const ALL: &[Self] = &[
        Self::BaselineHotPath,
        Self::AotArtifact,
        Self::AdaptiveRouter,
        Self::SupremacyEvidence,
        Self::SupportSurface,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BaselineHotPath => "baseline_hot_path",
            Self::AotArtifact => "aot_artifact",
            Self::AdaptiveRouter => "adaptive_router",
            Self::SupremacyEvidence => "supremacy_evidence",
            Self::SupportSurface => "support_surface",
        }
    }
}

impl fmt::Display for PromotionTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// PromotionStatus
// ---------------------------------------------------------------------------

/// Lifecycle state of a promoted kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromotionStatus {
    /// Candidate evaluated but not yet promoted.
    Pending,
    /// Promoted and active in the shipped path.
    Active,
    /// Demoted due to regression, failure, or policy change.
    Demoted,
    /// Superseded by a better candidate.
    Superseded,
}

impl PromotionStatus {
    pub const ALL: &[Self] = &[Self::Pending, Self::Active, Self::Demoted, Self::Superseded];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Demoted => "demoted",
            Self::Superseded => "superseded",
        }
    }

    pub const fn is_active(self) -> bool {
        matches!(self, Self::Active)
    }

    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Demoted | Self::Superseded)
    }
}

impl fmt::Display for PromotionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DemotionCause
// ---------------------------------------------------------------------------

/// Why a promoted kernel was demoted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DemotionCause {
    /// Performance regression detected in production.
    PerformanceRegression,
    /// New counterexample invalidates equivalence.
    CounterexampleFound,
    /// Hardware-specific failure on a target platform.
    HardwareFailure,
    /// Policy change requires rollback.
    PolicyChange,
    /// Superseded by a strictly better candidate.
    Superseded,
    /// Manual operator demotion.
    OperatorOverride,
    /// AOT compilation failure on a target.
    CompileFailure,
}

impl DemotionCause {
    pub const ALL: &[Self] = &[
        Self::PerformanceRegression,
        Self::CounterexampleFound,
        Self::HardwareFailure,
        Self::PolicyChange,
        Self::Superseded,
        Self::OperatorOverride,
        Self::CompileFailure,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerformanceRegression => "performance_regression",
            Self::CounterexampleFound => "counterexample_found",
            Self::HardwareFailure => "hardware_failure",
            Self::PolicyChange => "policy_change",
            Self::Superseded => "superseded",
            Self::OperatorOverride => "operator_override",
            Self::CompileFailure => "compile_failure",
        }
    }
}

impl fmt::Display for DemotionCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RejectionReason
// ---------------------------------------------------------------------------

/// Why a promotion candidate was rejected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionReason {
    /// Equivalence proof not verified.
    ProofNotVerified,
    /// Proof coverage below threshold.
    InsufficientProofCoverage {
        coverage_millionths: u64,
        threshold_millionths: u64,
    },
    /// Speedup below promotion threshold.
    InsufficientSpeedup {
        speedup_millionths: u64,
        threshold_millionths: u64,
    },
    /// Active counterexamples exist.
    ActiveCounterexamples { count: usize },
    /// Counterexample severity exceeds threshold.
    CounterexampleSeverity {
        max_severity_millionths: u64,
        threshold_millionths: u64,
    },
    /// Regression gate did not pass.
    RegressionGateFailure {
        confidence_millionths: u64,
        threshold_millionths: u64,
    },
    /// AOT compilation not confirmed.
    NoAotReceipt,
    /// Target not eligible for this kernel type.
    TargetIneligible { target: PromotionTarget },
}

impl RejectionReason {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::ProofNotVerified => "proof_not_verified",
            Self::InsufficientProofCoverage { .. } => "insufficient_proof_coverage",
            Self::InsufficientSpeedup { .. } => "insufficient_speedup",
            Self::ActiveCounterexamples { .. } => "active_counterexamples",
            Self::CounterexampleSeverity { .. } => "counterexample_severity",
            Self::RegressionGateFailure { .. } => "regression_gate_failure",
            Self::NoAotReceipt => "no_aot_receipt",
            Self::TargetIneligible { .. } => "target_ineligible",
        }
    }
}

impl fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProofNotVerified => write!(f, "equivalence proof not verified"),
            Self::InsufficientProofCoverage {
                coverage_millionths,
                threshold_millionths,
            } => write!(
                f,
                "proof coverage {coverage_millionths} < threshold {threshold_millionths}"
            ),
            Self::InsufficientSpeedup {
                speedup_millionths,
                threshold_millionths,
            } => write!(
                f,
                "speedup {speedup_millionths} < threshold {threshold_millionths}"
            ),
            Self::ActiveCounterexamples { count } => {
                write!(f, "{count} active counterexample(s)")
            }
            Self::CounterexampleSeverity {
                max_severity_millionths,
                threshold_millionths,
            } => write!(
                f,
                "counterexample severity {max_severity_millionths} > threshold {threshold_millionths}"
            ),
            Self::RegressionGateFailure {
                confidence_millionths,
                threshold_millionths,
            } => write!(
                f,
                "regression confidence {confidence_millionths} < threshold {threshold_millionths}"
            ),
            Self::NoAotReceipt => write!(f, "AOT compilation receipt missing"),
            Self::TargetIneligible { target } => write!(f, "target {target} ineligible"),
        }
    }
}

// ---------------------------------------------------------------------------
// PromotionEvidence
// ---------------------------------------------------------------------------

/// Evidence package supporting a promotion decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionEvidence {
    /// Whether the equivalence proof is verified.
    pub proof_verified: bool,
    /// Proof coverage (millionths, 0–1_000_000).
    pub proof_coverage_millionths: u64,
    /// Measured speedup over original (millionths, 1_000_000 = no change).
    pub speedup_millionths: u64,
    /// Active counterexample count.
    pub active_counterexamples: usize,
    /// Maximum severity of any active counterexample (millionths).
    pub max_counterexample_severity_millionths: u64,
    /// Regression gate confidence (millionths).
    pub regression_confidence_millionths: u64,
    /// Whether AOT compilation succeeded.
    pub aot_compiled: bool,
    /// Eligible promotion targets.
    pub eligible_targets: BTreeSet<PromotionTarget>,
}

/// Input for constructing partial evidence with known issues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartialEvidenceInput {
    /// Whether the equivalence proof is verified.
    pub proof_verified: bool,
    /// Proof coverage (millionths).
    pub coverage: u64,
    /// Measured speedup (millionths).
    pub speedup: u64,
    /// Active counterexample count.
    pub counterexamples: usize,
    /// Maximum severity of any counterexample (millionths).
    pub max_severity: u64,
    /// Regression gate confidence (millionths).
    pub regression_confidence: u64,
    /// Whether AOT compilation succeeded.
    pub aot_compiled: bool,
    /// Eligible promotion targets.
    pub targets: BTreeSet<PromotionTarget>,
}

impl PromotionEvidence {
    /// Create evidence for a fully verified candidate.
    pub fn verified(
        coverage: u64,
        speedup: u64,
        regression_confidence: u64,
        targets: BTreeSet<PromotionTarget>,
    ) -> Self {
        Self {
            proof_verified: true,
            proof_coverage_millionths: coverage,
            speedup_millionths: speedup,
            active_counterexamples: 0,
            max_counterexample_severity_millionths: 0,
            regression_confidence_millionths: regression_confidence,
            aot_compiled: true,
            eligible_targets: targets,
        }
    }

    /// Create evidence for a candidate with known issues.
    pub fn partial(input: PartialEvidenceInput) -> Self {
        Self {
            proof_verified: input.proof_verified,
            proof_coverage_millionths: input.coverage,
            speedup_millionths: input.speedup,
            active_counterexamples: input.counterexamples,
            max_counterexample_severity_millionths: input.max_severity,
            regression_confidence_millionths: input.regression_confidence,
            aot_compiled: input.aot_compiled,
            eligible_targets: input.targets,
        }
    }
}

// ---------------------------------------------------------------------------
// PromotionDecision
// ---------------------------------------------------------------------------

/// Result of evaluating a candidate for promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PromotionDecision {
    /// Candidate is promoted to the specified targets.
    Promoted {
        kernel_id: String,
        targets: BTreeSet<PromotionTarget>,
        content_hash: ContentHash,
    },
    /// Candidate is rejected.
    Rejected {
        kernel_id: String,
        reasons: Vec<RejectionReason>,
    },
    /// Candidate is deferred (e.g., pending further evidence).
    Deferred {
        kernel_id: String,
        pending_reasons: Vec<RejectionReason>,
    },
}

impl PromotionDecision {
    pub fn is_promoted(&self) -> bool {
        matches!(self, Self::Promoted { .. })
    }

    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    pub fn is_deferred(&self) -> bool {
        matches!(self, Self::Deferred { .. })
    }

    pub fn kernel_id(&self) -> &str {
        match self {
            Self::Promoted { kernel_id, .. }
            | Self::Rejected { kernel_id, .. }
            | Self::Deferred { kernel_id, .. } => kernel_id,
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Promoted { .. } => "promoted",
            Self::Rejected { .. } => "rejected",
            Self::Deferred { .. } => "deferred",
        }
    }
}

impl fmt::Display for PromotionDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Promoted {
                kernel_id, targets, ..
            } => write!(f, "PROMOTED {kernel_id} to {} target(s)", targets.len()),
            Self::Rejected {
                kernel_id, reasons, ..
            } => write!(f, "REJECTED {kernel_id}: {} reason(s)", reasons.len()),
            Self::Deferred {
                kernel_id,
                pending_reasons,
            } => write!(
                f,
                "DEFERRED {kernel_id}: {} pending reason(s)",
                pending_reasons.len()
            ),
        }
    }
}

// ---------------------------------------------------------------------------
// DemotionReceipt
// ---------------------------------------------------------------------------

/// Receipt recording when and why a promoted kernel was demoted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DemotionReceipt {
    /// Kernel that was demoted.
    pub kernel_id: String,
    /// Cause of demotion.
    pub cause: DemotionCause,
    /// Epoch when demotion occurred.
    pub epoch: SecurityEpoch,
    /// Targets from which the kernel was removed.
    pub removed_from: BTreeSet<PromotionTarget>,
    /// Description of the regression or failure.
    pub description: String,
    /// Content hash of the demotion evidence.
    pub content_hash: ContentHash,
}

impl DemotionReceipt {
    pub fn new(
        kernel_id: impl Into<String>,
        cause: DemotionCause,
        epoch: SecurityEpoch,
        removed_from: BTreeSet<PromotionTarget>,
        description: impl Into<String>,
    ) -> Self {
        let kernel_id = kernel_id.into();
        let description = description.into();
        let mut h = Sha256::new();
        h.update(kernel_id.as_bytes());
        h.update(cause.as_str().as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(description.as_bytes());
        for t in &removed_from {
            h.update(t.as_str().as_bytes());
        }
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            kernel_id,
            cause,
            epoch,
            removed_from,
            description,
            content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// PromotionGateConfig
// ---------------------------------------------------------------------------

/// Configuration for the promotion gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionGateConfig {
    /// Minimum speedup required (millionths above 1_000_000).
    pub min_speedup: u64,
    /// Minimum proof coverage (millionths).
    pub min_proof_coverage: u64,
    /// Maximum active counterexamples.
    pub max_counterexamples: usize,
    /// Maximum counterexample severity (millionths).
    pub max_counterexample_severity: u64,
    /// Minimum regression gate confidence (millionths).
    pub min_regression_confidence: u64,
    /// Whether AOT receipt is required.
    pub require_aot: bool,
}

impl PromotionGateConfig {
    pub fn default_config() -> Self {
        Self {
            min_speedup: MIN_PROMOTION_SPEEDUP,
            min_proof_coverage: MIN_PROOF_COVERAGE,
            max_counterexamples: MAX_ACTIVE_COUNTEREXAMPLES,
            max_counterexample_severity: MAX_COUNTEREXAMPLE_SEVERITY,
            min_regression_confidence: MIN_REGRESSION_CONFIDENCE,
            require_aot: true,
        }
    }

    pub fn permissive() -> Self {
        Self {
            min_speedup: 0,
            min_proof_coverage: 0,
            max_counterexamples: usize::MAX,
            max_counterexample_severity: MILLION,
            min_regression_confidence: 0,
            require_aot: false,
        }
    }
}

impl Default for PromotionGateConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// PromotionGate
// ---------------------------------------------------------------------------

/// Gate that evaluates synthesis candidates for promotion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionGate {
    pub config: PromotionGateConfig,
    pub schema_version: String,
}

impl PromotionGate {
    pub fn with_defaults() -> Self {
        Self {
            config: PromotionGateConfig::default(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    pub fn with_config(config: PromotionGateConfig) -> Self {
        Self {
            config,
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Evaluate a candidate for promotion.
    pub fn evaluate(&self, kernel_id: &str, evidence: &PromotionEvidence) -> PromotionDecision {
        let mut hard_rejections = Vec::new();
        let mut soft_rejections = Vec::new();

        // 1. Proof must be verified.
        if !evidence.proof_verified {
            hard_rejections.push(RejectionReason::ProofNotVerified);
        }

        // 2. Proof coverage threshold.
        if evidence.proof_coverage_millionths < self.config.min_proof_coverage {
            hard_rejections.push(RejectionReason::InsufficientProofCoverage {
                coverage_millionths: evidence.proof_coverage_millionths,
                threshold_millionths: self.config.min_proof_coverage,
            });
        }

        // 3. Speedup threshold.
        if evidence.speedup_millionths < self.config.min_speedup {
            hard_rejections.push(RejectionReason::InsufficientSpeedup {
                speedup_millionths: evidence.speedup_millionths,
                threshold_millionths: self.config.min_speedup,
            });
        }

        // 4. Counterexample count.
        if evidence.active_counterexamples > self.config.max_counterexamples {
            hard_rejections.push(RejectionReason::ActiveCounterexamples {
                count: evidence.active_counterexamples,
            });
        }

        // 5. Counterexample severity.
        if evidence.max_counterexample_severity_millionths > self.config.max_counterexample_severity
        {
            hard_rejections.push(RejectionReason::CounterexampleSeverity {
                max_severity_millionths: evidence.max_counterexample_severity_millionths,
                threshold_millionths: self.config.max_counterexample_severity,
            });
        }

        // 6. Regression confidence.
        if evidence.regression_confidence_millionths < self.config.min_regression_confidence {
            soft_rejections.push(RejectionReason::RegressionGateFailure {
                confidence_millionths: evidence.regression_confidence_millionths,
                threshold_millionths: self.config.min_regression_confidence,
            });
        }

        // 7. AOT receipt.
        if self.config.require_aot && !evidence.aot_compiled {
            soft_rejections.push(RejectionReason::NoAotReceipt);
        }

        // 8. Target eligibility.
        if evidence.eligible_targets.is_empty() {
            hard_rejections.push(RejectionReason::TargetIneligible {
                target: PromotionTarget::BaselineHotPath,
            });
        }

        if !hard_rejections.is_empty() {
            // Hard rejections: reject immediately.
            hard_rejections.extend(soft_rejections);
            return PromotionDecision::Rejected {
                kernel_id: kernel_id.to_string(),
                reasons: hard_rejections,
            };
        }

        if !soft_rejections.is_empty() {
            // Soft rejections only: defer.
            return PromotionDecision::Deferred {
                kernel_id: kernel_id.to_string(),
                pending_reasons: soft_rejections,
            };
        }

        // All checks passed: promote.
        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(kernel_id.as_bytes());
        h.update(evidence.speedup_millionths.to_le_bytes());
        h.update(evidence.proof_coverage_millionths.to_le_bytes());
        for t in &evidence.eligible_targets {
            h.update(t.as_str().as_bytes());
        }
        let content_hash = ContentHash::compute(&h.finalize());

        PromotionDecision::Promoted {
            kernel_id: kernel_id.to_string(),
            targets: evidence.eligible_targets.clone(),
            content_hash,
        }
    }

    /// Evaluate a batch of candidates.
    pub fn evaluate_batch(
        &self,
        candidates: &[(String, PromotionEvidence)],
    ) -> Vec<PromotionDecision> {
        candidates
            .iter()
            .map(|(kid, ev)| self.evaluate(kid, ev))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// PromotedKernel
// ---------------------------------------------------------------------------

/// A kernel that has been promoted to shipped paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotedKernel {
    /// Kernel identifier.
    pub kernel_id: String,
    /// Original kernel this replaces.
    pub original_kernel_id: String,
    /// Current status.
    pub status: PromotionStatus,
    /// Targets where this kernel is active.
    pub active_targets: BTreeSet<PromotionTarget>,
    /// Epoch when promoted.
    pub promotion_epoch: SecurityEpoch,
    /// Speedup at promotion time (millionths).
    pub speedup_at_promotion: u64,
    /// Proof coverage at promotion time (millionths).
    pub proof_coverage_at_promotion: u64,
    /// Demotion receipt if demoted.
    pub demotion: Option<DemotionReceipt>,
    /// Content hash of promotion evidence.
    pub content_hash: ContentHash,
}

impl PromotedKernel {
    pub fn new(
        kernel_id: impl Into<String>,
        original_kernel_id: impl Into<String>,
        targets: BTreeSet<PromotionTarget>,
        epoch: SecurityEpoch,
        speedup: u64,
        coverage: u64,
    ) -> Self {
        let kernel_id = kernel_id.into();
        let original_kernel_id = original_kernel_id.into();
        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(kernel_id.as_bytes());
        h.update(original_kernel_id.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(speedup.to_le_bytes());
        h.update(coverage.to_le_bytes());
        for t in &targets {
            h.update(t.as_str().as_bytes());
        }
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            kernel_id,
            original_kernel_id,
            status: PromotionStatus::Active,
            active_targets: targets,
            promotion_epoch: epoch,
            speedup_at_promotion: speedup,
            proof_coverage_at_promotion: coverage,
            demotion: None,
            content_hash,
        }
    }

    /// Demote this kernel.
    pub fn demote(&mut self, receipt: DemotionReceipt) {
        self.status = PromotionStatus::Demoted;
        self.active_targets.clear();
        self.demotion = Some(receipt);
    }

    /// Supersede this kernel with a better candidate.
    pub fn supersede(&mut self, successor_id: &str, epoch: SecurityEpoch) {
        let receipt = DemotionReceipt::new(
            self.kernel_id.clone(),
            DemotionCause::Superseded,
            epoch,
            self.active_targets.clone(),
            format!("superseded by {successor_id}"),
        );
        self.status = PromotionStatus::Superseded;
        self.active_targets.clear();
        self.demotion = Some(receipt);
    }

    pub fn is_active(&self) -> bool {
        self.status.is_active()
    }
}

// ---------------------------------------------------------------------------
// PromotionLedger
// ---------------------------------------------------------------------------

/// Tracks the full lifecycle of promoted kernels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionLedger {
    pub schema_version: String,
    pub entries: Vec<PromotedKernel>,
}

impl PromotionLedger {
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            entries: Vec::new(),
        }
    }

    /// Record a new promotion.
    pub fn record_promotion(&mut self, kernel: PromotedKernel) {
        self.entries.push(kernel);
    }

    /// Demote a kernel by ID.
    pub fn demote_kernel(&mut self, kernel_id: &str, receipt: DemotionReceipt) -> bool {
        for entry in &mut self.entries {
            if entry.kernel_id == kernel_id && entry.is_active() {
                entry.demote(receipt);
                return true;
            }
        }
        false
    }

    /// Supersede a kernel.
    pub fn supersede_kernel(
        &mut self,
        kernel_id: &str,
        successor_id: &str,
        epoch: SecurityEpoch,
    ) -> bool {
        for entry in &mut self.entries {
            if entry.kernel_id == kernel_id && entry.is_active() {
                entry.supersede(successor_id, epoch);
                return true;
            }
        }
        false
    }

    /// Count active kernels.
    pub fn active_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_active()).count()
    }

    /// Count demoted kernels.
    pub fn demoted_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.status == PromotionStatus::Demoted)
            .count()
    }

    /// Count superseded kernels.
    pub fn superseded_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| e.status == PromotionStatus::Superseded)
            .count()
    }

    /// Get a kernel by ID.
    pub fn get_kernel(&self, kernel_id: &str) -> Option<&PromotedKernel> {
        self.entries.iter().find(|e| e.kernel_id == kernel_id)
    }

    /// Get all active kernels for a target.
    pub fn active_for_target(&self, target: PromotionTarget) -> Vec<&PromotedKernel> {
        self.entries
            .iter()
            .filter(|e| e.is_active() && e.active_targets.contains(&target))
            .collect()
    }

    /// Get all demotion receipts.
    pub fn demotion_receipts(&self) -> Vec<&DemotionReceipt> {
        self.entries
            .iter()
            .filter_map(|e| e.demotion.as_ref())
            .collect()
    }
}

impl Default for PromotionLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// PromotionReport
// ---------------------------------------------------------------------------

/// Summary report from a promotion evaluation session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromotionReport {
    pub schema_version: String,
    pub epoch: SecurityEpoch,
    pub decisions: Vec<PromotionDecision>,
    pub promoted_count: usize,
    pub rejected_count: usize,
    pub deferred_count: usize,
    pub content_hash: ContentHash,
}

impl PromotionReport {
    pub fn new(epoch: SecurityEpoch, decisions: Vec<PromotionDecision>) -> Self {
        let promoted_count = decisions.iter().filter(|d| d.is_promoted()).count();
        let rejected_count = decisions.iter().filter(|d| d.is_rejected()).count();
        let deferred_count = decisions.iter().filter(|d| d.is_deferred()).count();

        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update((decisions.len() as u64).to_le_bytes());
        h.update((promoted_count as u64).to_le_bytes());
        h.update((rejected_count as u64).to_le_bytes());
        h.update((deferred_count as u64).to_le_bytes());
        for d in &decisions {
            h.update(d.kernel_id().as_bytes());
            h.update(d.tag().as_bytes());
        }
        let content_hash = ContentHash::compute(&h.finalize());

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch,
            decisions,
            promoted_count,
            rejected_count,
            deferred_count,
            content_hash,
        }
    }

    pub fn total_count(&self) -> usize {
        self.decisions.len()
    }

    pub fn promotion_rate(&self) -> u64 {
        (self.promoted_count as u64)
            .saturating_mul(MILLION)
            .checked_div(self.decisions.len() as u64)
            .unwrap_or(0)
    }

    pub fn all_promoted(&self) -> bool {
        !self.decisions.is_empty() && self.promoted_count == self.decisions.len()
    }

    pub fn has_rejections(&self) -> bool {
        self.rejected_count > 0
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1000)
    }

    fn all_targets() -> BTreeSet<PromotionTarget> {
        PromotionTarget::ALL.iter().copied().collect()
    }

    fn baseline_target() -> BTreeSet<PromotionTarget> {
        BTreeSet::from([PromotionTarget::BaselineHotPath])
    }

    fn good_evidence() -> PromotionEvidence {
        PromotionEvidence::verified(960_000, 150_000, 950_000, baseline_target())
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "synthesis_kernel_promotion");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
    }

    #[test]
    fn threshold_invariants() {
        const {
            assert!(MIN_PROMOTION_SPEEDUP > 0);
            assert!(MIN_PROOF_COVERAGE > 0);
            assert!(MIN_PROOF_COVERAGE <= MILLION);
            assert!(MAX_ACTIVE_COUNTEREXAMPLES == 0);
            assert!(MAX_COUNTEREXAMPLE_SEVERITY == 0);
            assert!(MIN_REGRESSION_CONFIDENCE > 0);
        }
    }

    // --- PromotionTarget ---

    #[test]
    fn target_all_length() {
        assert_eq!(PromotionTarget::ALL.len(), 5);
    }

    #[test]
    fn target_names_unique() {
        let names: BTreeSet<&str> = PromotionTarget::ALL.iter().map(|t| t.as_str()).collect();
        assert_eq!(names.len(), PromotionTarget::ALL.len());
    }

    #[test]
    fn target_display_matches_as_str() {
        for t in PromotionTarget::ALL {
            assert_eq!(t.to_string(), t.as_str());
        }
    }

    #[test]
    fn target_serde_roundtrip() {
        for t in PromotionTarget::ALL {
            let json = serde_json::to_string(t).unwrap();
            let back: PromotionTarget = serde_json::from_str(&json).unwrap();
            assert_eq!(*t, back);
        }
    }

    // --- PromotionStatus ---

    #[test]
    fn status_all_length() {
        assert_eq!(PromotionStatus::ALL.len(), 4);
    }

    #[test]
    fn status_active_classification() {
        assert!(PromotionStatus::Active.is_active());
        assert!(!PromotionStatus::Pending.is_active());
        assert!(!PromotionStatus::Demoted.is_active());
        assert!(!PromotionStatus::Superseded.is_active());
    }

    #[test]
    fn status_terminal_classification() {
        assert!(PromotionStatus::Demoted.is_terminal());
        assert!(PromotionStatus::Superseded.is_terminal());
        assert!(!PromotionStatus::Active.is_terminal());
        assert!(!PromotionStatus::Pending.is_terminal());
    }

    #[test]
    fn status_serde_roundtrip() {
        for s in PromotionStatus::ALL {
            let json = serde_json::to_string(s).unwrap();
            let back: PromotionStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    // --- DemotionCause ---

    #[test]
    fn demotion_cause_all_length() {
        assert_eq!(DemotionCause::ALL.len(), 7);
    }

    #[test]
    fn demotion_cause_names_unique() {
        let names: BTreeSet<&str> = DemotionCause::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(names.len(), DemotionCause::ALL.len());
    }

    #[test]
    fn demotion_cause_serde() {
        for c in DemotionCause::ALL {
            let json = serde_json::to_string(c).unwrap();
            let back: DemotionCause = serde_json::from_str(&json).unwrap();
            assert_eq!(*c, back);
        }
    }

    // --- RejectionReason ---

    #[test]
    fn rejection_tags_unique() {
        let reasons = [
            RejectionReason::ProofNotVerified,
            RejectionReason::InsufficientProofCoverage {
                coverage_millionths: 0,
                threshold_millionths: 0,
            },
            RejectionReason::InsufficientSpeedup {
                speedup_millionths: 0,
                threshold_millionths: 0,
            },
            RejectionReason::ActiveCounterexamples { count: 0 },
            RejectionReason::CounterexampleSeverity {
                max_severity_millionths: 0,
                threshold_millionths: 0,
            },
            RejectionReason::RegressionGateFailure {
                confidence_millionths: 0,
                threshold_millionths: 0,
            },
            RejectionReason::NoAotReceipt,
            RejectionReason::TargetIneligible {
                target: PromotionTarget::BaselineHotPath,
            },
        ];
        let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), 8);
    }

    #[test]
    fn rejection_display_not_empty() {
        let r = RejectionReason::ProofNotVerified;
        assert!(!r.to_string().is_empty());
    }

    #[test]
    fn rejection_serde() {
        let r = RejectionReason::ActiveCounterexamples { count: 5 };
        let json = serde_json::to_string(&r).unwrap();
        let back: RejectionReason = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- PromotionEvidence ---

    #[test]
    fn evidence_verified() {
        let e = good_evidence();
        assert!(e.proof_verified);
        assert!(e.aot_compiled);
        assert_eq!(e.active_counterexamples, 0);
    }

    #[test]
    fn evidence_partial() {
        let e = PromotionEvidence::partial(PartialEvidenceInput {
            proof_verified: false,
            coverage: 500_000,
            speedup: 50_000,
            counterexamples: 2,
            max_severity: 100_000,
            regression_confidence: 800_000,
            aot_compiled: false,
            targets: BTreeSet::new(),
        });
        assert!(!e.proof_verified);
        assert!(!e.aot_compiled);
        assert_eq!(e.active_counterexamples, 2);
    }

    #[test]
    fn evidence_serde() {
        let e = good_evidence();
        let json = serde_json::to_string(&e).unwrap();
        let back: PromotionEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- PromotionGate ---

    #[test]
    fn gate_promotes_good_candidate() {
        let gate = PromotionGate::with_defaults();
        let d = gate.evaluate("k1", &good_evidence());
        assert!(d.is_promoted());
    }

    #[test]
    fn gate_rejects_unverified_proof() {
        let gate = PromotionGate::with_defaults();
        let mut e = good_evidence();
        e.proof_verified = false;
        let d = gate.evaluate("k1", &e);
        assert!(d.is_rejected());
    }

    #[test]
    fn gate_rejects_low_coverage() {
        let gate = PromotionGate::with_defaults();
        let mut e = good_evidence();
        e.proof_coverage_millionths = 500_000;
        let d = gate.evaluate("k1", &e);
        assert!(d.is_rejected());
    }

    #[test]
    fn gate_rejects_low_speedup() {
        let gate = PromotionGate::with_defaults();
        let mut e = good_evidence();
        e.speedup_millionths = 10_000;
        let d = gate.evaluate("k1", &e);
        assert!(d.is_rejected());
    }

    #[test]
    fn gate_rejects_counterexamples() {
        let gate = PromotionGate::with_defaults();
        let mut e = good_evidence();
        e.active_counterexamples = 1;
        let d = gate.evaluate("k1", &e);
        assert!(d.is_rejected());
    }

    #[test]
    fn gate_defers_low_regression_confidence() {
        let gate = PromotionGate::with_defaults();
        let mut e = good_evidence();
        e.regression_confidence_millionths = 500_000;
        let d = gate.evaluate("k1", &e);
        assert!(d.is_deferred());
    }

    #[test]
    fn gate_defers_no_aot() {
        let gate = PromotionGate::with_defaults();
        let mut e = good_evidence();
        e.aot_compiled = false;
        let d = gate.evaluate("k1", &e);
        assert!(d.is_deferred());
    }

    #[test]
    fn gate_rejects_empty_targets() {
        let gate = PromotionGate::with_defaults();
        let mut e = good_evidence();
        e.eligible_targets.clear();
        let d = gate.evaluate("k1", &e);
        assert!(d.is_rejected());
    }

    #[test]
    fn gate_permissive_promotes_anything() {
        let gate = PromotionGate::with_config(PromotionGateConfig::permissive());
        // proof_verified must be true because that check is unconditional (no config knob).
        let e = PromotionEvidence::partial(PartialEvidenceInput {
            proof_verified: true,
            coverage: 0,
            speedup: 0,
            counterexamples: 100,
            max_severity: 500_000,
            regression_confidence: 0,
            aot_compiled: false,
            targets: baseline_target(),
        });
        let d = gate.evaluate("k1", &e);
        assert!(d.is_promoted());
    }

    #[test]
    fn gate_batch_evaluation() {
        let gate = PromotionGate::with_defaults();
        let candidates = vec![
            ("k1".to_string(), good_evidence()),
            ("k2".to_string(), {
                let mut e = good_evidence();
                e.proof_verified = false;
                e
            }),
        ];
        let results = gate.evaluate_batch(&candidates);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_promoted());
        assert!(results[1].is_rejected());
    }

    // --- PromotionDecision ---

    #[test]
    fn decision_kernel_id() {
        let d = PromotionDecision::Rejected {
            kernel_id: "kx".into(),
            reasons: vec![],
        };
        assert_eq!(d.kernel_id(), "kx");
    }

    #[test]
    fn decision_tags() {
        let promoted = PromotionDecision::Promoted {
            kernel_id: "k".into(),
            targets: BTreeSet::new(),
            content_hash: ContentHash::compute(b"test"),
        };
        assert_eq!(promoted.tag(), "promoted");

        let rejected = PromotionDecision::Rejected {
            kernel_id: "k".into(),
            reasons: vec![],
        };
        assert_eq!(rejected.tag(), "rejected");

        let deferred = PromotionDecision::Deferred {
            kernel_id: "k".into(),
            pending_reasons: vec![],
        };
        assert_eq!(deferred.tag(), "deferred");
    }

    #[test]
    fn decision_display() {
        let d = PromotionDecision::Promoted {
            kernel_id: "k1".into(),
            targets: baseline_target(),
            content_hash: ContentHash::compute(b"test"),
        };
        let s = d.to_string();
        assert!(s.contains("PROMOTED"));
        assert!(s.contains("k1"));
    }

    #[test]
    fn decision_serde() {
        let d = PromotionDecision::Rejected {
            kernel_id: "k1".into(),
            reasons: vec![RejectionReason::ProofNotVerified],
        };
        let json = serde_json::to_string(&d).unwrap();
        let back: PromotionDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(d, back);
    }

    // --- DemotionReceipt ---

    #[test]
    fn demotion_receipt_hash_deterministic() {
        let r1 = DemotionReceipt::new(
            "k1",
            DemotionCause::PerformanceRegression,
            epoch(),
            baseline_target(),
            "regression found",
        );
        let r2 = DemotionReceipt::new(
            "k1",
            DemotionCause::PerformanceRegression,
            epoch(),
            baseline_target(),
            "regression found",
        );
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn demotion_receipt_serde() {
        let r = DemotionReceipt::new(
            "k1",
            DemotionCause::CounterexampleFound,
            epoch(),
            all_targets(),
            "counterexample discovered",
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: DemotionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- PromotedKernel ---

    #[test]
    fn promoted_kernel_new() {
        let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        assert!(k.is_active());
        assert!(k.demotion.is_none());
    }

    #[test]
    fn promoted_kernel_demote() {
        let mut k =
            PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        let receipt = DemotionReceipt::new(
            "k1",
            DemotionCause::PerformanceRegression,
            epoch(),
            baseline_target(),
            "regressed",
        );
        k.demote(receipt);
        assert!(!k.is_active());
        assert_eq!(k.status, PromotionStatus::Demoted);
        assert!(k.active_targets.is_empty());
        assert!(k.demotion.is_some());
    }

    #[test]
    fn promoted_kernel_supersede() {
        let mut k =
            PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        k.supersede("k2", epoch());
        assert!(!k.is_active());
        assert_eq!(k.status, PromotionStatus::Superseded);
        assert!(k.active_targets.is_empty());
    }

    #[test]
    fn promoted_kernel_hash_deterministic() {
        let k1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        let k2 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        assert_eq!(k1.content_hash, k2.content_hash);
    }

    #[test]
    fn promoted_kernel_serde() {
        let k = PromotedKernel::new("k1", "orig1", all_targets(), epoch(), 200_000, 980_000);
        let json = serde_json::to_string(&k).unwrap();
        let back: PromotedKernel = serde_json::from_str(&json).unwrap();
        assert_eq!(k, back);
    }

    // --- PromotionLedger ---

    #[test]
    fn ledger_empty() {
        let ledger = PromotionLedger::new();
        assert_eq!(ledger.active_count(), 0);
        assert_eq!(ledger.demoted_count(), 0);
    }

    #[test]
    fn ledger_record_and_count() {
        let mut ledger = PromotionLedger::new();
        let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        ledger.record_promotion(k);
        assert_eq!(ledger.active_count(), 1);
    }

    #[test]
    fn ledger_demote() {
        let mut ledger = PromotionLedger::new();
        let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        ledger.record_promotion(k);

        let receipt = DemotionReceipt::new(
            "k1",
            DemotionCause::HardwareFailure,
            epoch(),
            baseline_target(),
            "hw fail",
        );
        assert!(ledger.demote_kernel("k1", receipt));
        assert_eq!(ledger.active_count(), 0);
        assert_eq!(ledger.demoted_count(), 1);
    }

    #[test]
    fn ledger_demote_nonexistent_returns_false() {
        let mut ledger = PromotionLedger::new();
        let receipt = DemotionReceipt::new(
            "k999",
            DemotionCause::PolicyChange,
            epoch(),
            BTreeSet::new(),
            "nope",
        );
        assert!(!ledger.demote_kernel("k999", receipt));
    }

    #[test]
    fn ledger_supersede() {
        let mut ledger = PromotionLedger::new();
        let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        ledger.record_promotion(k);
        assert!(ledger.supersede_kernel("k1", "k2", epoch()));
        assert_eq!(ledger.superseded_count(), 1);
        assert_eq!(ledger.active_count(), 0);
    }

    #[test]
    fn ledger_get_kernel() {
        let mut ledger = PromotionLedger::new();
        let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        ledger.record_promotion(k);
        assert!(ledger.get_kernel("k1").is_some());
        assert!(ledger.get_kernel("k999").is_none());
    }

    #[test]
    fn ledger_active_for_target() {
        let mut ledger = PromotionLedger::new();
        let k1 = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        let k2 = PromotedKernel::new(
            "k2",
            "orig2",
            BTreeSet::from([PromotionTarget::AotArtifact]),
            epoch(),
            200_000,
            980_000,
        );
        ledger.record_promotion(k1);
        ledger.record_promotion(k2);

        let baseline = ledger.active_for_target(PromotionTarget::BaselineHotPath);
        assert_eq!(baseline.len(), 1);
        assert_eq!(baseline[0].kernel_id, "k1");

        let aot = ledger.active_for_target(PromotionTarget::AotArtifact);
        assert_eq!(aot.len(), 1);
        assert_eq!(aot[0].kernel_id, "k2");
    }

    #[test]
    fn ledger_demotion_receipts() {
        let mut ledger = PromotionLedger::new();
        let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        ledger.record_promotion(k);
        let receipt = DemotionReceipt::new(
            "k1",
            DemotionCause::PerformanceRegression,
            epoch(),
            baseline_target(),
            "regressed",
        );
        ledger.demote_kernel("k1", receipt);
        let receipts = ledger.demotion_receipts();
        assert_eq!(receipts.len(), 1);
    }

    #[test]
    fn ledger_serde() {
        let mut ledger = PromotionLedger::new();
        let k = PromotedKernel::new("k1", "orig1", baseline_target(), epoch(), 150_000, 960_000);
        ledger.record_promotion(k);
        let json = serde_json::to_string(&ledger).unwrap();
        let back: PromotionLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(ledger, back);
    }

    // --- PromotionReport ---

    #[test]
    fn report_empty() {
        let r = PromotionReport::new(epoch(), Vec::new());
        assert_eq!(r.total_count(), 0);
        assert!(!r.all_promoted());
        assert!(!r.has_rejections());
    }

    #[test]
    fn report_all_promoted() {
        let gate = PromotionGate::with_defaults();
        let d = gate.evaluate("k1", &good_evidence());
        let r = PromotionReport::new(epoch(), vec![d]);
        assert!(r.all_promoted());
        assert_eq!(r.promotion_rate(), MILLION);
    }

    #[test]
    fn report_mixed() {
        let decisions = vec![
            PromotionDecision::Promoted {
                kernel_id: "k1".into(),
                targets: baseline_target(),
                content_hash: ContentHash::compute(b"k1"),
            },
            PromotionDecision::Rejected {
                kernel_id: "k2".into(),
                reasons: vec![RejectionReason::ProofNotVerified],
            },
        ];
        let r = PromotionReport::new(epoch(), decisions);
        assert_eq!(r.promoted_count, 1);
        assert_eq!(r.rejected_count, 1);
        assert!(r.has_rejections());
        assert!(!r.all_promoted());
        assert_eq!(r.promotion_rate(), 500_000);
    }

    #[test]
    fn report_hash_deterministic() {
        let d = vec![PromotionDecision::Promoted {
            kernel_id: "k1".into(),
            targets: baseline_target(),
            content_hash: ContentHash::compute(b"k1"),
        }];
        let r1 = PromotionReport::new(epoch(), d.clone());
        let r2 = PromotionReport::new(epoch(), d);
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_serde() {
        let decisions = vec![
            PromotionDecision::Promoted {
                kernel_id: "k1".into(),
                targets: baseline_target(),
                content_hash: ContentHash::compute(b"k1"),
            },
            PromotionDecision::Deferred {
                kernel_id: "k2".into(),
                pending_reasons: vec![RejectionReason::NoAotReceipt],
            },
        ];
        let r = PromotionReport::new(epoch(), decisions);
        let json = serde_json::to_string(&r).unwrap();
        let back: PromotionReport = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- PromotionGateConfig ---

    #[test]
    fn config_default_matches_constants() {
        let c = PromotionGateConfig::default();
        assert_eq!(c.min_speedup, MIN_PROMOTION_SPEEDUP);
        assert_eq!(c.min_proof_coverage, MIN_PROOF_COVERAGE);
        assert_eq!(c.max_counterexamples, MAX_ACTIVE_COUNTEREXAMPLES);
        assert!(c.require_aot);
    }

    #[test]
    fn config_permissive() {
        let c = PromotionGateConfig::permissive();
        assert_eq!(c.min_speedup, 0);
        assert!(!c.require_aot);
    }

    #[test]
    fn config_serde() {
        let c = PromotionGateConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: PromotionGateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- Gate serde ---

    #[test]
    fn gate_serde() {
        let g = PromotionGate::with_defaults();
        let json = serde_json::to_string(&g).unwrap();
        let back: PromotionGate = serde_json::from_str(&json).unwrap();
        assert_eq!(g, back);
    }
}
