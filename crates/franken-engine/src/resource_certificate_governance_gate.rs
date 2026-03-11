//! Resource certificate governance gate for regression, tail-risk, and publication.
//!
//! Bead: bd-1lsy.7.25.3 [RGC-625C]
//!
//! Turns resource-bound certificates into regression, tail-risk, observability,
//! and publication gates so budgeted execution becomes part of the supremacy
//! story rather than a hidden side constraint.
//!
//! # Design
//!
//! - `CertificateEvidence` captures a resource-budget observation with consumed
//!   headroom, tail-risk fraction, and sample metadata.
//! - `evaluate_regression` compares current evidence against a baseline to
//!   detect budget overruns, tail spikes, allocation bursts, effect leaks,
//!   and latency regressions.
//! - `assess_tail_risk` examines p99/p999/max/tail-heaviness to flag
//!   unacceptable tail behaviour.
//! - `evaluate` combines regression detection, tail-risk assessment, and
//!   publication-constraint generation into a `GateResult`.
//! - `evaluate_batch` processes a vector of evidence pairs and produces
//!   a `GateSummary`.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-625C]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.resource-certificate-governance-gate.v1";

/// Component name.
pub const COMPONENT: &str = "resource_certificate_governance_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.25.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-625C";

/// Fixed-point unit: 1.0 in millionths.
const MILLION: u64 = 1_000_000;

/// Default maximum budget overrun fraction (5% = 50_000 millionths).
pub const DEFAULT_MAX_BUDGET_OVERRUN: u64 = 50_000;

/// Default tail-risk threshold (95% = 950_000 millionths).
pub const DEFAULT_TAIL_RISK_THRESHOLD: u64 = 950_000;

/// Default maximum tail heaviness (200_000 millionths = 0.2).
pub const DEFAULT_MAX_TAIL_HEAVINESS: u64 = 200_000;

/// Default regression sensitivity (30_000 millionths = 3%).
pub const DEFAULT_REGRESSION_SENSITIVITY: u64 = 30_000;

/// Default minimum sample count for evidence to be considered sufficient.
pub const DEFAULT_MIN_SAMPLE_COUNT: u64 = 30;

/// Maximum publication improvement claimable by default (100_000 = 10%).
pub const DEFAULT_MAX_CLAIMABLE_IMPROVEMENT: u64 = 100_000;

// ---------------------------------------------------------------------------
// ResourceKind
// ---------------------------------------------------------------------------

/// Kind of resource governed by a budget certificate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    /// CPU time budget.
    CpuBudget,
    /// Memory usage budget.
    MemoryBudget,
    /// I/O operations budget.
    IoBudget,
    /// Side-effect budget.
    EffectBudget,
    /// Latency (wall-clock) budget.
    LatencyBudget,
    /// Heap allocation count budget.
    AllocationBudget,
}

impl ResourceKind {
    pub const ALL: &[Self] = &[
        Self::CpuBudget,
        Self::MemoryBudget,
        Self::IoBudget,
        Self::EffectBudget,
        Self::LatencyBudget,
        Self::AllocationBudget,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CpuBudget => "cpu_budget",
            Self::MemoryBudget => "memory_budget",
            Self::IoBudget => "io_budget",
            Self::EffectBudget => "effect_budget",
            Self::LatencyBudget => "latency_budget",
            Self::AllocationBudget => "allocation_budget",
        }
    }
}

impl fmt::Display for ResourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RiskLevel
// ---------------------------------------------------------------------------

/// Risk level determined by the governance gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    /// Within normal operating bounds.
    Nominal,
    /// Some concern; bears monitoring.
    Elevated,
    /// Significant risk; conditional controls required.
    High,
    /// Severe; immediate action needed.
    Critical,
}

impl RiskLevel {
    pub const ALL: &[Self] = &[Self::Nominal, Self::Elevated, Self::High, Self::Critical];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Nominal => "nominal",
            Self::Elevated => "elevated",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// Verdict produced by the governance gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// Evidence passes all checks.
    Pass,
    /// Evidence passes with conditions attached.
    ConditionalPass,
    /// Evidence fails one or more checks.
    Fail,
    /// Not enough samples to make a determination.
    InsufficientEvidence,
}

impl GateVerdict {
    pub const ALL: &[Self] = &[
        Self::Pass,
        Self::ConditionalPass,
        Self::Fail,
        Self::InsufficientEvidence,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::ConditionalPass => "conditional_pass",
            Self::Fail => "fail",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }

    pub fn is_passing(self) -> bool {
        matches!(self, Self::Pass | Self::ConditionalPass)
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RegressionKind
// ---------------------------------------------------------------------------

/// Kind of regression detected between baseline and current evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegressionKind {
    /// Budget consumed exceeds baseline by more than sensitivity threshold.
    BudgetOverrun,
    /// Tail-risk fraction spiked relative to baseline.
    TailSpike,
    /// Effect consumption leaked beyond baseline.
    EffectLeak,
    /// Allocation count burst beyond baseline.
    AllocationBurst,
    /// Latency regressed beyond baseline.
    LatencyRegression,
}

impl RegressionKind {
    pub const ALL: &[Self] = &[
        Self::BudgetOverrun,
        Self::TailSpike,
        Self::EffectLeak,
        Self::AllocationBurst,
        Self::LatencyRegression,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BudgetOverrun => "budget_overrun",
            Self::TailSpike => "tail_spike",
            Self::EffectLeak => "effect_leak",
            Self::AllocationBurst => "allocation_burst",
            Self::LatencyRegression => "latency_regression",
        }
    }
}

impl fmt::Display for RegressionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// CertificateEvidence
// ---------------------------------------------------------------------------

/// Evidence captured from a resource certificate observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateEvidence {
    /// Kind of resource this evidence pertains to.
    pub resource_kind: ResourceKind,
    /// Total budget allocated (millionths).
    pub budget_millionths: u64,
    /// Budget consumed (millionths).
    pub consumed_millionths: u64,
    /// Remaining headroom as fraction of budget (millionths).
    pub headroom_fraction: u64,
    /// Tail-risk fraction (millionths). Higher means more tail risk.
    pub tail_risk_fraction: u64,
    /// Number of samples backing this evidence.
    pub sample_count: u64,
    /// Security epoch at which the evidence was collected.
    pub epoch: SecurityEpoch,
}

impl CertificateEvidence {
    /// Utilisation fraction: consumed / budget (millionths).
    pub fn utilisation_fraction(&self) -> u64 {
        if self.budget_millionths == 0 {
            return MILLION;
        }
        self.consumed_millionths
            .saturating_mul(MILLION)
            .checked_div(self.budget_millionths)
            .unwrap_or(MILLION)
    }

    /// Whether the budget was exceeded.
    pub fn is_overrun(&self) -> bool {
        self.consumed_millionths > self.budget_millionths
    }

    /// Compute a content hash for this evidence.
    pub fn content_hash(&self) -> ContentHash {
        let mut h = Sha256::new();
        h.update(self.resource_kind.as_str().as_bytes());
        h.update(self.budget_millionths.to_le_bytes());
        h.update(self.consumed_millionths.to_le_bytes());
        h.update(self.headroom_fraction.to_le_bytes());
        h.update(self.tail_risk_fraction.to_le_bytes());
        h.update(self.sample_count.to_le_bytes());
        h.update(self.epoch.as_u64().to_le_bytes());
        ContentHash::compute(&h.finalize())
    }
}

// ---------------------------------------------------------------------------
// RegressionRecord
// ---------------------------------------------------------------------------

/// A detected regression between baseline and current evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionRecord {
    /// Kind of regression.
    pub kind: RegressionKind,
    /// Resource where the regression occurred.
    pub resource_kind: ResourceKind,
    /// Baseline measurement (millionths).
    pub baseline_millionths: u64,
    /// Current measurement (millionths).
    pub current_millionths: u64,
    /// Delta as a fraction of baseline (millionths). Positive means regression.
    pub delta_fraction: u64,
    /// Severity score (millionths, higher = worse).
    pub severity: u64,
    /// Epoch at which regression was detected.
    pub epoch: SecurityEpoch,
}

impl fmt::Display for RegressionRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} on {}: baseline={} current={} delta={}",
            self.kind,
            self.resource_kind,
            self.baseline_millionths,
            self.current_millionths,
            self.delta_fraction,
        )
    }
}

// ---------------------------------------------------------------------------
// TailRiskAssessment
// ---------------------------------------------------------------------------

/// Assessment of tail-risk characteristics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskAssessment {
    /// 99th percentile fraction (millionths).
    pub p99_fraction: u64,
    /// 99.9th percentile fraction (millionths).
    pub p999_fraction: u64,
    /// Maximum observed value (millionths).
    pub max_observed: u64,
    /// Tail heaviness ratio: p999 / p99 (millionths). Heavy tail > 1.0.
    pub tail_heaviness: u64,
    /// Whether the tail risk is considered acceptable.
    pub acceptable: bool,
}

impl TailRiskAssessment {
    /// Whether the tail is heavy (heaviness > 1_000_000 = 1.0x).
    pub fn is_heavy_tailed(&self) -> bool {
        self.tail_heaviness > MILLION
    }
}

impl fmt::Display for TailRiskAssessment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tail: p99={} p999={} max={} heaviness={} acceptable={}",
            self.p99_fraction,
            self.p999_fraction,
            self.max_observed,
            self.tail_heaviness,
            self.acceptable,
        )
    }
}

// ---------------------------------------------------------------------------
// PublicationConstraint
// ---------------------------------------------------------------------------

/// Constraint on what may be publicly claimed about a resource improvement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationConstraint {
    /// Resource kind the constraint applies to.
    pub resource_kind: ResourceKind,
    /// Whether this resource must be disclosed in publications.
    pub must_disclose: bool,
    /// Maximum improvement claimable (millionths).
    pub max_claimable_improvement: u64,
    /// Free-form caveats that must accompany publication.
    pub caveats: Vec<String>,
}

impl fmt::Display for PublicationConstraint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "publication[{}]: disclose={} max_claim={} caveats={}",
            self.resource_kind,
            self.must_disclose,
            self.max_claimable_improvement,
            self.caveats.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

/// Complete result from the governance gate for a single evidence evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Overall verdict.
    pub verdict: GateVerdict,
    /// Risk level.
    pub risk_level: RiskLevel,
    /// Any regressions detected.
    pub regressions: Vec<RegressionRecord>,
    /// Tail-risk assessment.
    pub tail_assessment: TailRiskAssessment,
    /// Publication constraints imposed.
    pub publication_constraints: Vec<PublicationConstraint>,
    /// Content hash of the result for auditability.
    pub receipt_hash: ContentHash,
}

impl GateResult {
    /// Whether the result is a passing verdict.
    pub fn is_passing(&self) -> bool {
        self.verdict.is_passing()
    }

    /// Number of regressions found.
    pub fn regression_count(&self) -> usize {
        self.regressions.len()
    }
}

impl fmt::Display for GateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] risk={} regressions={} tail_ok={}",
            self.verdict,
            self.risk_level,
            self.regressions.len(),
            self.tail_assessment.acceptable,
        )
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the resource certificate governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Maximum budget overrun fraction before flagging regression (millionths).
    pub max_budget_overrun_fraction: u64,
    /// Tail-risk threshold: the p99 fraction above which tail risk is elevated (millionths).
    pub tail_risk_threshold: u64,
    /// Maximum acceptable tail heaviness (millionths).
    pub max_tail_heaviness: u64,
    /// Regression sensitivity: minimum delta fraction to count as regression (millionths).
    pub regression_sensitivity: u64,
    /// Minimum sample count for evidence to be considered sufficient.
    pub min_sample_count: u64,
}

impl GateConfig {
    /// Strict configuration with low tolerances.
    pub fn strict() -> Self {
        Self {
            max_budget_overrun_fraction: 20_000, // 2%
            tail_risk_threshold: 980_000,        // 98%
            max_tail_heaviness: 100_000,         // 0.1
            regression_sensitivity: 10_000,      // 1%
            min_sample_count: 100,
        }
    }

    /// Permissive configuration with high tolerances.
    pub fn permissive() -> Self {
        Self {
            max_budget_overrun_fraction: 200_000, // 20%
            tail_risk_threshold: 800_000,         // 80%
            max_tail_heaviness: 500_000,          // 0.5
            regression_sensitivity: 100_000,      // 10%
            min_sample_count: 5,
        }
    }
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            max_budget_overrun_fraction: DEFAULT_MAX_BUDGET_OVERRUN,
            tail_risk_threshold: DEFAULT_TAIL_RISK_THRESHOLD,
            max_tail_heaviness: DEFAULT_MAX_TAIL_HEAVINESS,
            regression_sensitivity: DEFAULT_REGRESSION_SENSITIVITY,
            min_sample_count: DEFAULT_MIN_SAMPLE_COUNT,
        }
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Auditable receipt for a gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Content hash of this receipt.
    pub receipt_hash: ContentHash,
    /// Component that produced the receipt.
    pub component: String,
    /// Epoch at which the decision was made.
    pub epoch: SecurityEpoch,
    /// Verdict rendered.
    pub verdict: GateVerdict,
    /// Hash of the evidence that drove the decision.
    pub evidence_hash: ContentHash,
}

impl DecisionReceipt {
    /// Produce a receipt from a gate result and evidence.
    pub fn from_result(result: &GateResult, evidence: &CertificateEvidence) -> Self {
        let evidence_hash = evidence.content_hash();

        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(evidence.epoch.as_u64().to_le_bytes());
        h.update(result.verdict.as_str().as_bytes());
        h.update(evidence_hash.as_bytes());
        let receipt_hash = ContentHash::compute(&h.finalize());

        Self {
            receipt_hash,
            component: COMPONENT.to_string(),
            epoch: evidence.epoch,
            verdict: result.verdict,
            evidence_hash,
        }
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "receipt[{}]: {} at epoch {}",
            self.component,
            self.verdict,
            self.epoch.as_u64(),
        )
    }
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

/// Summary statistics from a batch evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Total evidence items evaluated.
    pub total: u64,
    /// Number that passed.
    pub passed: u64,
    /// Number that conditionally passed.
    pub conditional: u64,
    /// Number that failed.
    pub failed: u64,
    /// Number with insufficient evidence.
    pub insufficient: u64,
    /// Pass rate (millionths). Counts both Pass and ConditionalPass.
    pub pass_rate: u64,
}

impl GateSummary {
    /// Whether every item passed or conditionally passed.
    pub fn all_passing(&self) -> bool {
        self.total > 0 && self.failed == 0 && self.insufficient == 0
    }

    /// Whether any item failed.
    pub fn has_failures(&self) -> bool {
        self.failed > 0
    }
}

impl fmt::Display for GateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "summary: {}/{} passed ({} conditional, {} failed, {} insufficient) rate={}",
            self.passed.saturating_add(self.conditional),
            self.total,
            self.conditional,
            self.failed,
            self.insufficient,
            self.pass_rate,
        )
    }
}

// ---------------------------------------------------------------------------
// Core evaluation functions
// ---------------------------------------------------------------------------

/// Compute the fractional delta between two values, as millionths of the baseline.
/// Returns 0 if baseline is 0.
fn fractional_delta(baseline: u64, current: u64) -> u64 {
    if baseline == 0 {
        if current == 0 {
            return 0;
        }
        return MILLION; // infinite regression
    }
    current
        .saturating_sub(baseline)
        .saturating_mul(MILLION)
        .checked_div(baseline)
        .unwrap_or(0)
}

/// Compute severity from delta fraction.  Severity is the delta clamped to MILLION.
fn severity_from_delta(delta_fraction: u64) -> u64 {
    delta_fraction.min(MILLION)
}

/// Evaluate regressions between current evidence and a baseline.
pub fn evaluate_regression(
    evidence: &CertificateEvidence,
    baseline: &CertificateEvidence,
    config: &GateConfig,
) -> Vec<RegressionRecord> {
    let mut regressions = Vec::new();

    // 1. Budget overrun regression: consumed grew relative to baseline.
    let consumed_delta =
        fractional_delta(baseline.consumed_millionths, evidence.consumed_millionths);
    if consumed_delta > config.max_budget_overrun_fraction {
        regressions.push(RegressionRecord {
            kind: RegressionKind::BudgetOverrun,
            resource_kind: evidence.resource_kind,
            baseline_millionths: baseline.consumed_millionths,
            current_millionths: evidence.consumed_millionths,
            delta_fraction: consumed_delta,
            severity: severity_from_delta(consumed_delta),
            epoch: evidence.epoch,
        });
    }

    // 2. Tail spike: tail_risk_fraction grew.
    let tail_delta = fractional_delta(baseline.tail_risk_fraction, evidence.tail_risk_fraction);
    if tail_delta > config.regression_sensitivity {
        regressions.push(RegressionRecord {
            kind: RegressionKind::TailSpike,
            resource_kind: evidence.resource_kind,
            baseline_millionths: baseline.tail_risk_fraction,
            current_millionths: evidence.tail_risk_fraction,
            delta_fraction: tail_delta,
            severity: severity_from_delta(tail_delta),
            epoch: evidence.epoch,
        });
    }

    // 3. Resource-specific regressions.
    match evidence.resource_kind {
        ResourceKind::EffectBudget => {
            let effect_delta =
                fractional_delta(baseline.consumed_millionths, evidence.consumed_millionths);
            if effect_delta > config.regression_sensitivity
                && !regressions
                    .iter()
                    .any(|r| r.kind == RegressionKind::BudgetOverrun)
            {
                regressions.push(RegressionRecord {
                    kind: RegressionKind::EffectLeak,
                    resource_kind: evidence.resource_kind,
                    baseline_millionths: baseline.consumed_millionths,
                    current_millionths: evidence.consumed_millionths,
                    delta_fraction: effect_delta,
                    severity: severity_from_delta(effect_delta),
                    epoch: evidence.epoch,
                });
            }
        }
        ResourceKind::AllocationBudget => {
            let alloc_delta =
                fractional_delta(baseline.consumed_millionths, evidence.consumed_millionths);
            if alloc_delta > config.regression_sensitivity
                && !regressions
                    .iter()
                    .any(|r| r.kind == RegressionKind::BudgetOverrun)
            {
                regressions.push(RegressionRecord {
                    kind: RegressionKind::AllocationBurst,
                    resource_kind: evidence.resource_kind,
                    baseline_millionths: baseline.consumed_millionths,
                    current_millionths: evidence.consumed_millionths,
                    delta_fraction: alloc_delta,
                    severity: severity_from_delta(alloc_delta),
                    epoch: evidence.epoch,
                });
            }
        }
        ResourceKind::LatencyBudget => {
            let lat_delta =
                fractional_delta(baseline.consumed_millionths, evidence.consumed_millionths);
            if lat_delta > config.regression_sensitivity
                && !regressions
                    .iter()
                    .any(|r| r.kind == RegressionKind::BudgetOverrun)
            {
                regressions.push(RegressionRecord {
                    kind: RegressionKind::LatencyRegression,
                    resource_kind: evidence.resource_kind,
                    baseline_millionths: baseline.consumed_millionths,
                    current_millionths: evidence.consumed_millionths,
                    delta_fraction: lat_delta,
                    severity: severity_from_delta(lat_delta),
                    epoch: evidence.epoch,
                });
            }
        }
        _ => {}
    }

    regressions
}

/// Assess tail risk from a single evidence observation.
pub fn assess_tail_risk(evidence: &CertificateEvidence, config: &GateConfig) -> TailRiskAssessment {
    // Derive synthetic p99/p999 from evidence fields.
    // p99 ≈ consumed + tail_risk_fraction scaled by budget.
    let p99_fraction = evidence
        .utilisation_fraction()
        .saturating_add(evidence.tail_risk_fraction / 10);
    let p999_fraction = p99_fraction.saturating_add(evidence.tail_risk_fraction / 5);
    let max_observed = p999_fraction.saturating_add(evidence.tail_risk_fraction / 3);

    // Tail heaviness: ratio of p999 to p99 (millionths).
    let tail_heaviness = if p99_fraction == 0 {
        0
    } else {
        p999_fraction
            .saturating_mul(MILLION)
            .checked_div(p99_fraction)
            .unwrap_or(0)
    };

    // Acceptable if p99 below threshold AND tail heaviness below max.
    let acceptable =
        p99_fraction <= config.tail_risk_threshold && tail_heaviness <= config.max_tail_heaviness;

    TailRiskAssessment {
        p99_fraction,
        p999_fraction,
        max_observed,
        tail_heaviness,
        acceptable,
    }
}

/// Determine risk level from regressions and tail assessment.
fn determine_risk_level(regressions: &[RegressionRecord], tail: &TailRiskAssessment) -> RiskLevel {
    let max_severity = regressions.iter().map(|r| r.severity).max().unwrap_or(0);

    if max_severity > 500_000 || (!tail.acceptable && tail.tail_heaviness > 2 * MILLION) {
        RiskLevel::Critical
    } else if max_severity > 200_000 || !tail.acceptable {
        RiskLevel::High
    } else if max_severity > 0 || tail.is_heavy_tailed() {
        RiskLevel::Elevated
    } else {
        RiskLevel::Nominal
    }
}

/// Build publication constraints for a given evidence and regression state.
fn build_publication_constraints(
    evidence: &CertificateEvidence,
    regressions: &[RegressionRecord],
    tail: &TailRiskAssessment,
) -> Vec<PublicationConstraint> {
    let mut constraints = Vec::new();
    let mut caveats = Vec::new();

    // If there are regressions, must disclose and cap claims.
    let has_regressions = !regressions.is_empty();
    if has_regressions {
        caveats.push(format!("{} regression(s) detected", regressions.len(),));
    }

    // If tail risk is unacceptable, add caveat.
    if !tail.acceptable {
        caveats.push(format!(
            "tail-risk unacceptable: heaviness={}",
            tail.tail_heaviness,
        ));
    }

    // If budget was overrun, add caveat.
    if evidence.is_overrun() {
        caveats.push("budget overrun observed".to_string());
    }

    let must_disclose = has_regressions || !tail.acceptable || evidence.is_overrun();
    let max_claimable = if must_disclose {
        // Cap claimable improvement when disclosure is required.
        DEFAULT_MAX_CLAIMABLE_IMPROVEMENT / 2
    } else {
        DEFAULT_MAX_CLAIMABLE_IMPROVEMENT
    };

    constraints.push(PublicationConstraint {
        resource_kind: evidence.resource_kind,
        must_disclose,
        max_claimable_improvement: max_claimable,
        caveats,
    });

    constraints
}

/// Compute a receipt hash for a gate result.
fn compute_receipt_hash(
    verdict: GateVerdict,
    risk_level: RiskLevel,
    regressions: &[RegressionRecord],
    tail: &TailRiskAssessment,
    evidence: &CertificateEvidence,
) -> ContentHash {
    let mut h = Sha256::new();
    h.update(SCHEMA_VERSION.as_bytes());
    h.update(verdict.as_str().as_bytes());
    h.update(risk_level.as_str().as_bytes());
    h.update((regressions.len() as u64).to_le_bytes());
    h.update(tail.p99_fraction.to_le_bytes());
    h.update(tail.p999_fraction.to_le_bytes());
    h.update(evidence.epoch.as_u64().to_le_bytes());
    h.update(evidence.resource_kind.as_str().as_bytes());
    ContentHash::compute(&h.finalize())
}

/// Evaluate a single certificate evidence against an optional baseline.
///
/// If no baseline is provided, only tail-risk and budget-overrun checks
/// are performed (no regression detection).
pub fn evaluate(
    evidence: &CertificateEvidence,
    baseline: Option<&CertificateEvidence>,
    config: &GateConfig,
) -> GateResult {
    // Insufficient evidence check.
    if evidence.sample_count < config.min_sample_count {
        let tail = assess_tail_risk(evidence, config);
        let receipt_hash = compute_receipt_hash(
            GateVerdict::InsufficientEvidence,
            RiskLevel::Nominal,
            &[],
            &tail,
            evidence,
        );
        return GateResult {
            verdict: GateVerdict::InsufficientEvidence,
            risk_level: RiskLevel::Nominal,
            regressions: Vec::new(),
            tail_assessment: tail,
            publication_constraints: vec![PublicationConstraint {
                resource_kind: evidence.resource_kind,
                must_disclose: true,
                max_claimable_improvement: 0,
                caveats: vec![format!(
                    "insufficient samples: {} < {}",
                    evidence.sample_count, config.min_sample_count,
                )],
            }],
            receipt_hash,
        };
    }

    // Regression detection.
    let regressions = if let Some(base) = baseline {
        evaluate_regression(evidence, base, config)
    } else {
        Vec::new()
    };

    // Tail-risk assessment.
    let tail = assess_tail_risk(evidence, config);

    // Risk level.
    let risk_level = determine_risk_level(&regressions, &tail);

    // Publication constraints.
    let publication_constraints = build_publication_constraints(evidence, &regressions, &tail);

    // Verdict.
    let verdict = if !regressions.is_empty() && risk_level == RiskLevel::Critical {
        GateVerdict::Fail
    } else if !regressions.is_empty() || !tail.acceptable || evidence.is_overrun() {
        GateVerdict::ConditionalPass
    } else {
        GateVerdict::Pass
    };

    let receipt_hash = compute_receipt_hash(verdict, risk_level, &regressions, &tail, evidence);

    GateResult {
        verdict,
        risk_level,
        regressions,
        tail_assessment: tail,
        publication_constraints,
        receipt_hash,
    }
}

/// Evaluate a batch of evidence pairs and produce results plus a summary.
pub fn evaluate_batch(
    evidences: &[(CertificateEvidence, Option<CertificateEvidence>)],
    config: &GateConfig,
) -> (Vec<GateResult>, GateSummary) {
    let results: Vec<GateResult> = evidences
        .iter()
        .map(|(ev, base)| evaluate(ev, base.as_ref(), config))
        .collect();

    let total = results.len() as u64;
    let passed = results
        .iter()
        .filter(|r| r.verdict == GateVerdict::Pass)
        .count() as u64;
    let conditional = results
        .iter()
        .filter(|r| r.verdict == GateVerdict::ConditionalPass)
        .count() as u64;
    let failed = results
        .iter()
        .filter(|r| r.verdict == GateVerdict::Fail)
        .count() as u64;
    let insufficient = results
        .iter()
        .filter(|r| r.verdict == GateVerdict::InsufficientEvidence)
        .count() as u64;

    let passing = passed.saturating_add(conditional);
    let pass_rate = passing
        .saturating_mul(MILLION)
        .checked_div(total)
        .unwrap_or(0);

    let summary = GateSummary {
        total,
        passed,
        conditional,
        failed,
        insufficient,
        pass_rate,
    };

    (results, summary)
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

    fn default_config() -> GateConfig {
        GateConfig::default()
    }

    fn good_evidence(kind: ResourceKind) -> CertificateEvidence {
        CertificateEvidence {
            resource_kind: kind,
            budget_millionths: 1_000_000,
            consumed_millionths: 500_000,
            headroom_fraction: 500_000,
            tail_risk_fraction: 50_000,
            sample_count: 100,
            epoch: epoch(),
        }
    }

    fn baseline_evidence(kind: ResourceKind) -> CertificateEvidence {
        CertificateEvidence {
            resource_kind: kind,
            budget_millionths: 1_000_000,
            consumed_millionths: 400_000,
            headroom_fraction: 600_000,
            tail_risk_fraction: 40_000,
            sample_count: 200,
            epoch: SecurityEpoch::from_raw(999),
        }
    }

    fn overrun_evidence(kind: ResourceKind) -> CertificateEvidence {
        CertificateEvidence {
            resource_kind: kind,
            budget_millionths: 1_000_000,
            consumed_millionths: 1_200_000,
            headroom_fraction: 0,
            tail_risk_fraction: 300_000,
            sample_count: 100,
            epoch: epoch(),
        }
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
    }

    #[test]
    fn component_name() {
        assert_eq!(COMPONENT, "resource_certificate_governance_gate");
    }

    #[test]
    fn bead_id_format() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn policy_id_format() {
        assert!(POLICY_ID.starts_with("RGC-"));
    }

    // --- ResourceKind ---

    #[test]
    fn resource_kind_all_length() {
        assert_eq!(ResourceKind::ALL.len(), 6);
    }

    #[test]
    fn resource_kind_names_unique() {
        let names: std::collections::BTreeSet<&str> =
            ResourceKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), ResourceKind::ALL.len());
    }

    #[test]
    fn resource_kind_display() {
        for k in ResourceKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn resource_kind_serde_roundtrip() {
        for k in ResourceKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: ResourceKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- RiskLevel ---

    #[test]
    fn risk_level_all_length() {
        assert_eq!(RiskLevel::ALL.len(), 4);
    }

    #[test]
    fn risk_level_display() {
        for r in RiskLevel::ALL {
            assert_eq!(r.to_string(), r.as_str());
        }
    }

    #[test]
    fn risk_level_serde_roundtrip() {
        for r in RiskLevel::ALL {
            let json = serde_json::to_string(r).unwrap();
            let back: RiskLevel = serde_json::from_str(&json).unwrap();
            assert_eq!(*r, back);
        }
    }

    // --- GateVerdict ---

    #[test]
    fn verdict_all_length() {
        assert_eq!(GateVerdict::ALL.len(), 4);
    }

    #[test]
    fn verdict_is_passing() {
        assert!(GateVerdict::Pass.is_passing());
        assert!(GateVerdict::ConditionalPass.is_passing());
        assert!(!GateVerdict::Fail.is_passing());
        assert!(!GateVerdict::InsufficientEvidence.is_passing());
    }

    #[test]
    fn verdict_display() {
        for v in GateVerdict::ALL {
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in GateVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: GateVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- RegressionKind ---

    #[test]
    fn regression_kind_all_length() {
        assert_eq!(RegressionKind::ALL.len(), 5);
    }

    #[test]
    fn regression_kind_names_unique() {
        let names: std::collections::BTreeSet<&str> =
            RegressionKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), RegressionKind::ALL.len());
    }

    #[test]
    fn regression_kind_serde_roundtrip() {
        for k in RegressionKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: RegressionKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- CertificateEvidence ---

    #[test]
    fn evidence_utilisation_fraction() {
        let e = good_evidence(ResourceKind::CpuBudget);
        // 500_000 / 1_000_000 * 1_000_000 = 500_000
        assert_eq!(e.utilisation_fraction(), 500_000);
    }

    #[test]
    fn evidence_utilisation_zero_budget() {
        let mut e = good_evidence(ResourceKind::CpuBudget);
        e.budget_millionths = 0;
        assert_eq!(e.utilisation_fraction(), MILLION);
    }

    #[test]
    fn evidence_is_overrun() {
        let e = good_evidence(ResourceKind::CpuBudget);
        assert!(!e.is_overrun());
        let o = overrun_evidence(ResourceKind::CpuBudget);
        assert!(o.is_overrun());
    }

    #[test]
    fn evidence_content_hash_deterministic() {
        let e1 = good_evidence(ResourceKind::CpuBudget);
        let e2 = good_evidence(ResourceKind::CpuBudget);
        assert_eq!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn evidence_content_hash_varies_by_kind() {
        let e1 = good_evidence(ResourceKind::CpuBudget);
        let e2 = good_evidence(ResourceKind::MemoryBudget);
        assert_ne!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn evidence_serde_roundtrip() {
        let e = good_evidence(ResourceKind::IoBudget);
        let json = serde_json::to_string(&e).unwrap();
        let back: CertificateEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(e, back);
    }

    // --- evaluate_regression ---

    #[test]
    fn regression_none_when_same() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let base = ev.clone();
        let regs = evaluate_regression(&ev, &base, &config);
        assert!(regs.is_empty());
    }

    #[test]
    fn regression_detects_budget_overrun() {
        let config = default_config();
        let base = baseline_evidence(ResourceKind::CpuBudget);
        let ev = overrun_evidence(ResourceKind::CpuBudget);
        let regs = evaluate_regression(&ev, &base, &config);
        assert!(regs.iter().any(|r| r.kind == RegressionKind::BudgetOverrun));
    }

    #[test]
    fn regression_detects_tail_spike() {
        let config = default_config();
        let mut base = baseline_evidence(ResourceKind::CpuBudget);
        base.tail_risk_fraction = 10_000;
        let mut ev = good_evidence(ResourceKind::CpuBudget);
        ev.tail_risk_fraction = 100_000; // 10x baseline
        let regs = evaluate_regression(&ev, &base, &config);
        assert!(regs.iter().any(|r| r.kind == RegressionKind::TailSpike));
    }

    #[test]
    fn regression_effect_leak() {
        let config = default_config();
        let mut base = baseline_evidence(ResourceKind::EffectBudget);
        base.consumed_millionths = 100_000;
        let mut ev = good_evidence(ResourceKind::EffectBudget);
        ev.consumed_millionths = 200_000; // 2x, delta=100% > 5% overrun
        // This triggers BudgetOverrun first, so EffectLeak should not appear.
        let regs = evaluate_regression(&ev, &base, &config);
        assert!(regs.iter().any(|r| r.kind == RegressionKind::BudgetOverrun));
    }

    #[test]
    fn regression_allocation_burst() {
        let config = default_config();
        let mut base = baseline_evidence(ResourceKind::AllocationBudget);
        base.consumed_millionths = 100_000;
        let mut ev = good_evidence(ResourceKind::AllocationBudget);
        ev.consumed_millionths = 200_000;
        let regs = evaluate_regression(&ev, &base, &config);
        // BudgetOverrun triggers; AllocationBurst is suppressed.
        assert!(!regs.is_empty());
    }

    #[test]
    fn regression_latency_regression() {
        let config = default_config();
        let mut base = baseline_evidence(ResourceKind::LatencyBudget);
        base.consumed_millionths = 100_000;
        let mut ev = good_evidence(ResourceKind::LatencyBudget);
        ev.consumed_millionths = 180_000;
        let regs = evaluate_regression(&ev, &base, &config);
        assert!(!regs.is_empty());
    }

    #[test]
    fn regression_record_display() {
        let r = RegressionRecord {
            kind: RegressionKind::BudgetOverrun,
            resource_kind: ResourceKind::CpuBudget,
            baseline_millionths: 400_000,
            current_millionths: 900_000,
            delta_fraction: 1_250_000,
            severity: MILLION,
            epoch: epoch(),
        };
        let s = r.to_string();
        assert!(s.contains("budget_overrun"));
        assert!(s.contains("cpu_budget"));
    }

    // --- assess_tail_risk ---

    #[test]
    fn tail_risk_acceptable_low_risk() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let tail = assess_tail_risk(&ev, &config);
        assert!(tail.acceptable);
    }

    #[test]
    fn tail_risk_unacceptable_high_risk() {
        let config = default_config();
        let mut ev = good_evidence(ResourceKind::CpuBudget);
        ev.tail_risk_fraction = 5_000_000; // Very high
        ev.consumed_millionths = 900_000;
        let tail = assess_tail_risk(&ev, &config);
        assert!(!tail.acceptable);
    }

    #[test]
    fn tail_risk_heaviness_ratio() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let tail = assess_tail_risk(&ev, &config);
        // Heaviness = p999 / p99. Both derived from low tail_risk, so ratio ~ 1.x
        assert!(tail.tail_heaviness > 0);
    }

    #[test]
    fn tail_risk_display() {
        let t = TailRiskAssessment {
            p99_fraction: 800_000,
            p999_fraction: 900_000,
            max_observed: 950_000,
            tail_heaviness: 1_125_000,
            acceptable: false,
        };
        let s = t.to_string();
        assert!(s.contains("p99="));
        assert!(s.contains("acceptable=false"));
    }

    // --- evaluate ---

    #[test]
    fn evaluate_pass_no_baseline() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let result = evaluate(&ev, None, &config);
        assert_eq!(result.verdict, GateVerdict::Pass);
        assert_eq!(result.risk_level, RiskLevel::Nominal);
    }

    #[test]
    fn evaluate_pass_with_baseline() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let base = ev.clone();
        let result = evaluate(&ev, Some(&base), &config);
        assert_eq!(result.verdict, GateVerdict::Pass);
    }

    #[test]
    fn evaluate_conditional_with_regressions() {
        let config = default_config();
        let base = baseline_evidence(ResourceKind::CpuBudget);
        let mut ev = good_evidence(ResourceKind::CpuBudget);
        ev.consumed_millionths = 600_000; // 50% above baseline 400k
        let result = evaluate(&ev, Some(&base), &config);
        assert!(result.verdict.is_passing());
    }

    #[test]
    fn evaluate_conditional_with_overrun() {
        let config = default_config();
        let ev = overrun_evidence(ResourceKind::CpuBudget);
        let result = evaluate(&ev, None, &config);
        assert_eq!(result.verdict, GateVerdict::ConditionalPass);
    }

    #[test]
    fn evaluate_insufficient_evidence() {
        let config = default_config();
        let mut ev = good_evidence(ResourceKind::CpuBudget);
        ev.sample_count = 5; // Below min_sample_count=30
        let result = evaluate(&ev, None, &config);
        assert_eq!(result.verdict, GateVerdict::InsufficientEvidence);
        assert!(!result.publication_constraints.is_empty());
    }

    #[test]
    fn evaluate_receipt_hash_deterministic() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let r1 = evaluate(&ev, None, &config);
        let r2 = evaluate(&ev, None, &config);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn evaluate_publication_constraints_present() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let result = evaluate(&ev, None, &config);
        assert!(!result.publication_constraints.is_empty());
    }

    #[test]
    fn evaluate_disclosure_required_on_regression() {
        let config = default_config();
        let base = baseline_evidence(ResourceKind::CpuBudget);
        let ev = overrun_evidence(ResourceKind::CpuBudget);
        let result = evaluate(&ev, Some(&base), &config);
        let disc = result
            .publication_constraints
            .iter()
            .any(|c| c.must_disclose);
        assert!(disc);
    }

    #[test]
    fn evaluate_gate_result_display() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let result = evaluate(&ev, None, &config);
        let s = result.to_string();
        assert!(s.contains("pass"));
    }

    // --- evaluate_batch ---

    #[test]
    fn batch_empty() {
        let config = default_config();
        let (results, summary) = evaluate_batch(&[], &config);
        assert!(results.is_empty());
        assert_eq!(summary.total, 0);
        assert_eq!(summary.pass_rate, 0);
    }

    #[test]
    fn batch_all_pass() {
        let config = default_config();
        let items = vec![
            (good_evidence(ResourceKind::CpuBudget), None),
            (good_evidence(ResourceKind::MemoryBudget), None),
        ];
        let (results, summary) = evaluate_batch(&items, &config);
        assert_eq!(results.len(), 2);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.pass_rate, MILLION);
        assert!(summary.all_passing());
        assert!(!summary.has_failures());
    }

    #[test]
    fn batch_mixed_verdicts() {
        let config = default_config();
        let mut insufficient = good_evidence(ResourceKind::IoBudget);
        insufficient.sample_count = 1;
        let items = vec![
            (good_evidence(ResourceKind::CpuBudget), None),
            (insufficient, None),
        ];
        let (_, summary) = evaluate_batch(&items, &config);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.passed, 1);
        assert_eq!(summary.insufficient, 1);
        assert!(!summary.all_passing());
    }

    #[test]
    fn batch_summary_display() {
        let summary = GateSummary {
            total: 10,
            passed: 7,
            conditional: 2,
            failed: 1,
            insufficient: 0,
            pass_rate: 900_000,
        };
        let s = summary.to_string();
        assert!(s.contains("9/10"));
        assert!(s.contains("1 failed"));
    }

    // --- DecisionReceipt ---

    #[test]
    fn decision_receipt_from_result() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let result = evaluate(&ev, None, &config);
        let receipt = DecisionReceipt::from_result(&result, &ev);
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.verdict, GateVerdict::Pass);
        assert_eq!(receipt.epoch.as_u64(), 1000);
    }

    #[test]
    fn decision_receipt_deterministic() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let result = evaluate(&ev, None, &config);
        let r1 = DecisionReceipt::from_result(&result, &ev);
        let r2 = DecisionReceipt::from_result(&result, &ev);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn decision_receipt_display() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let result = evaluate(&ev, None, &config);
        let receipt = DecisionReceipt::from_result(&result, &ev);
        let s = receipt.to_string();
        assert!(s.contains("receipt["));
        assert!(s.contains("pass"));
    }

    #[test]
    fn decision_receipt_serde() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let result = evaluate(&ev, None, &config);
        let receipt = DecisionReceipt::from_result(&result, &ev);
        let json = serde_json::to_string(&receipt).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    // --- GateConfig ---

    #[test]
    fn config_default() {
        let c = GateConfig::default();
        assert_eq!(c.max_budget_overrun_fraction, DEFAULT_MAX_BUDGET_OVERRUN);
        assert_eq!(c.min_sample_count, DEFAULT_MIN_SAMPLE_COUNT);
    }

    #[test]
    fn config_strict_tighter_than_default() {
        let s = GateConfig::strict();
        let d = GateConfig::default();
        assert!(s.max_budget_overrun_fraction <= d.max_budget_overrun_fraction);
        assert!(s.regression_sensitivity <= d.regression_sensitivity);
        assert!(s.min_sample_count >= d.min_sample_count);
    }

    #[test]
    fn config_permissive_looser_than_default() {
        let p = GateConfig::permissive();
        let d = GateConfig::default();
        assert!(p.max_budget_overrun_fraction >= d.max_budget_overrun_fraction);
        assert!(p.regression_sensitivity >= d.regression_sensitivity);
        assert!(p.min_sample_count <= d.min_sample_count);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = GateConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- PublicationConstraint ---

    #[test]
    fn publication_constraint_display() {
        let c = PublicationConstraint {
            resource_kind: ResourceKind::CpuBudget,
            must_disclose: true,
            max_claimable_improvement: 50_000,
            caveats: vec!["budget overrun observed".into()],
        };
        let s = c.to_string();
        assert!(s.contains("cpu_budget"));
        assert!(s.contains("disclose=true"));
    }

    #[test]
    fn publication_constraint_serde() {
        let c = PublicationConstraint {
            resource_kind: ResourceKind::MemoryBudget,
            must_disclose: false,
            max_claimable_improvement: 100_000,
            caveats: Vec::new(),
        };
        let json = serde_json::to_string(&c).unwrap();
        let back: PublicationConstraint = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- Gate result ---

    #[test]
    fn gate_result_is_passing() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let r = evaluate(&ev, None, &config);
        assert!(r.is_passing());
        assert_eq!(r.regression_count(), 0);
    }

    #[test]
    fn gate_result_serde() {
        let config = default_config();
        let ev = good_evidence(ResourceKind::CpuBudget);
        let r = evaluate(&ev, None, &config);
        let json = serde_json::to_string(&r).unwrap();
        let back: GateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- Helpers / edge cases ---

    #[test]
    fn fractional_delta_zero_baseline() {
        assert_eq!(fractional_delta(0, 0), 0);
        assert_eq!(fractional_delta(0, 100), MILLION);
    }

    #[test]
    fn fractional_delta_no_change() {
        assert_eq!(fractional_delta(500_000, 500_000), 0);
    }

    #[test]
    fn fractional_delta_double() {
        // 400k -> 800k = 100% increase = 1_000_000 millionths.
        assert_eq!(fractional_delta(400_000, 800_000), MILLION);
    }

    #[test]
    fn severity_clamped() {
        assert_eq!(severity_from_delta(2 * MILLION), MILLION);
        assert_eq!(severity_from_delta(500_000), 500_000);
    }
}
