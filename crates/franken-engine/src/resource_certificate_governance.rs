//! Regression, tail-risk, and publication governance for resource certificates.
//!
//! Bead: bd-1lsy.7.25.3 [RGC-625C]
//!
//! Turns resource-bound certificates into regression, tail-risk, observability,
//! and publication gates so budgeted execution becomes part of the supremacy
//! story rather than a hidden side constraint.
//!
//! # Design
//!
//! - `ResourceDimension` classifies the bounded resource (time, memory, etc.).
//! - `CertificateEvidence` captures measured vs certified budget utilisation.
//! - `RegressionEntry` records budget regression between versions.
//! - `TailRiskEntry` records p99/p50 ratio drift on resource dimensions.
//! - `PublicationPolicy` configures thresholds for publishing resource claims.
//! - `GovernanceVerdict` is the top-level gate output.
//! - `GovernanceReceipt` is a content-hashed audit trail.
//!
//! All ratios use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-625C]

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.resource-certificate-governance.v1";

/// Component name.
pub const COMPONENT: &str = "resource_certificate_governance";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.25.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-625C";

/// One in fixed-point millionths.
pub const FIXED_ONE: u64 = 1_000_000;

/// Default maximum budget regression (millionths). 50_000 = 5%.
pub const DEFAULT_MAX_REGRESSION_MILLIONTHS: u64 = 50_000;

/// Default maximum tail-risk ratio increase (millionths). 100_000 = 10%.
pub const DEFAULT_MAX_TAIL_RISK_MILLIONTHS: u64 = 100_000;

/// Default minimum samples for statistical validity.
pub const DEFAULT_MIN_SAMPLES: u64 = 30;

/// Default minimum observability coverage (millionths). 800_000 = 80%.
pub const DEFAULT_MIN_OBSERVABILITY_COVERAGE: u64 = 800_000;

/// Default maximum budget utilisation before warning (millionths). 900_000 = 90%.
pub const DEFAULT_MAX_UTILISATION_MILLIONTHS: u64 = 900_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn append_str(buf: &mut Vec<u8>, val: &str) {
    let bytes = val.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn compute_digest(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// ResourceDimension
// ---------------------------------------------------------------------------

/// Classification of the bounded resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceDimension {
    /// CPU time budget.
    CpuTime,
    /// Wall-clock time budget.
    WallTime,
    /// Heap memory budget.
    HeapMemory,
    /// Stack depth budget.
    StackDepth,
    /// Allocation count budget.
    AllocationCount,
    /// IO operations budget.
    IoOperations,
    /// Network bandwidth budget.
    NetworkBandwidth,
    /// File descriptor budget.
    FileDescriptors,
    /// GC pause budget.
    GcPause,
    /// Instruction count budget.
    InstructionCount,
}

impl ResourceDimension {
    /// All dimensions.
    pub fn all() -> &'static [Self] {
        &[
            Self::CpuTime,
            Self::WallTime,
            Self::HeapMemory,
            Self::StackDepth,
            Self::AllocationCount,
            Self::IoOperations,
            Self::NetworkBandwidth,
            Self::FileDescriptors,
            Self::GcPause,
            Self::InstructionCount,
        ]
    }
}

impl fmt::Display for ResourceDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::CpuTime => "cpu_time",
            Self::WallTime => "wall_time",
            Self::HeapMemory => "heap_memory",
            Self::StackDepth => "stack_depth",
            Self::AllocationCount => "allocation_count",
            Self::IoOperations => "io_operations",
            Self::NetworkBandwidth => "network_bandwidth",
            Self::FileDescriptors => "file_descriptors",
            Self::GcPause => "gc_pause",
            Self::InstructionCount => "instruction_count",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// CertificateEvidence
// ---------------------------------------------------------------------------

/// Evidence of budget utilisation for one dimension on one workload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertificateEvidence {
    /// Resource dimension.
    pub dimension: ResourceDimension,
    /// Workload identifier.
    pub workload_id: String,
    /// Certified budget value (units depend on dimension).
    pub certified_budget: u64,
    /// Measured usage.
    pub measured_usage: u64,
    /// Utilisation in millionths.
    pub utilisation_millionths: u64,
    /// Whether utilisation is within the warning threshold.
    pub within_budget: bool,
    /// Sample count.
    pub sample_count: u64,
    /// Evidence hash.
    pub evidence_hash: ContentHash,
}

impl CertificateEvidence {
    /// Create with computed utilisation.
    pub fn new(
        dimension: ResourceDimension,
        workload_id: String,
        certified_budget: u64,
        measured_usage: u64,
        sample_count: u64,
        max_utilisation: u64,
    ) -> Self {
        let utilisation_millionths = measured_usage
            .saturating_mul(FIXED_ONE)
            .checked_div(certified_budget)
            .unwrap_or(if measured_usage == 0 { 0 } else { FIXED_ONE });
        let within_budget = utilisation_millionths <= max_utilisation;
        let mut buf = Vec::with_capacity(64);
        append_str(&mut buf, &dimension.to_string());
        append_str(&mut buf, &workload_id);
        append_u64(&mut buf, certified_budget);
        append_u64(&mut buf, measured_usage);
        append_u64(&mut buf, sample_count);
        let evidence_hash = compute_digest(&buf);
        Self {
            dimension,
            workload_id,
            certified_budget,
            measured_usage,
            utilisation_millionths,
            within_budget,
            sample_count,
            evidence_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// RegressionEntry
// ---------------------------------------------------------------------------

/// Budget regression between versions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionEntry {
    /// Resource dimension.
    pub dimension: ResourceDimension,
    /// Workload identifier.
    pub workload_id: String,
    /// Previous version usage.
    pub previous_usage: u64,
    /// Current version usage.
    pub current_usage: u64,
    /// Regression in millionths. Positive = regressed.
    pub regression_millionths: u64,
    /// Whether regression is within budget.
    pub within_budget: bool,
    /// Entry hash.
    pub entry_hash: ContentHash,
}

impl RegressionEntry {
    /// Create with computed regression.
    pub fn new(
        dimension: ResourceDimension,
        workload_id: String,
        previous_usage: u64,
        current_usage: u64,
        max_regression: u64,
    ) -> Self {
        let regression_millionths = current_usage
            .saturating_sub(previous_usage)
            .saturating_mul(FIXED_ONE)
            .checked_div(previous_usage)
            .unwrap_or(if current_usage == 0 { 0 } else { FIXED_ONE });
        let within_budget = regression_millionths <= max_regression;
        let mut buf = Vec::with_capacity(64);
        append_str(&mut buf, &dimension.to_string());
        append_str(&mut buf, &workload_id);
        append_u64(&mut buf, previous_usage);
        append_u64(&mut buf, current_usage);
        let entry_hash = compute_digest(&buf);
        Self {
            dimension,
            workload_id,
            previous_usage,
            current_usage,
            regression_millionths,
            within_budget,
            entry_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// TailRiskEntry
// ---------------------------------------------------------------------------

/// Tail-risk for resource usage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskEntry {
    /// Resource dimension.
    pub dimension: ResourceDimension,
    /// Workload identifier.
    pub workload_id: String,
    /// p99/p50 ratio in millionths.
    pub tail_ratio_millionths: u64,
    /// Baseline p99/p50 ratio in millionths.
    pub baseline_ratio_millionths: u64,
    /// Drift in millionths. Positive = worse tail.
    pub drift_millionths: u64,
    /// Whether drift is within budget.
    pub within_budget: bool,
    /// Entry hash.
    pub entry_hash: ContentHash,
}

impl TailRiskEntry {
    /// Create with computed drift.
    pub fn new(
        dimension: ResourceDimension,
        workload_id: String,
        tail_ratio_millionths: u64,
        baseline_ratio_millionths: u64,
        max_drift: u64,
    ) -> Self {
        let drift_millionths = tail_ratio_millionths.saturating_sub(baseline_ratio_millionths);
        let within_budget = drift_millionths <= max_drift;
        let mut buf = Vec::with_capacity(48);
        append_str(&mut buf, &dimension.to_string());
        append_str(&mut buf, &workload_id);
        append_u64(&mut buf, tail_ratio_millionths);
        append_u64(&mut buf, baseline_ratio_millionths);
        let entry_hash = compute_digest(&buf);
        Self {
            dimension,
            workload_id,
            tail_ratio_millionths,
            baseline_ratio_millionths,
            drift_millionths,
            within_budget,
            entry_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// PublicationPolicy
// ---------------------------------------------------------------------------

/// Configurable thresholds for publishing resource certificate claims.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicationPolicy {
    /// Maximum budget regression (millionths).
    pub max_regression_millionths: u64,
    /// Maximum tail-risk drift (millionths).
    pub max_tail_risk_millionths: u64,
    /// Maximum utilisation before warning (millionths).
    pub max_utilisation_millionths: u64,
    /// Minimum samples for validity.
    pub min_samples: u64,
    /// Minimum observability coverage (millionths).
    pub min_observability_coverage: u64,
    /// Required dimensions (empty = all).
    pub required_dimensions: BTreeSet<ResourceDimension>,
}

impl PublicationPolicy {
    /// Strict policy.
    pub fn strict() -> Self {
        Self {
            max_regression_millionths: 20_000,
            max_tail_risk_millionths: 50_000,
            max_utilisation_millionths: 800_000,
            min_samples: 100,
            min_observability_coverage: 950_000,
            required_dimensions: ResourceDimension::all().iter().copied().collect(),
        }
    }

    /// Relaxed policy.
    pub fn relaxed() -> Self {
        Self {
            max_regression_millionths: DEFAULT_MAX_REGRESSION_MILLIONTHS,
            max_tail_risk_millionths: DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
            max_utilisation_millionths: DEFAULT_MAX_UTILISATION_MILLIONTHS,
            min_samples: DEFAULT_MIN_SAMPLES,
            min_observability_coverage: DEFAULT_MIN_OBSERVABILITY_COVERAGE,
            required_dimensions: BTreeSet::new(),
        }
    }
}

impl Default for PublicationPolicy {
    fn default() -> Self {
        Self::relaxed()
    }
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

/// Top-level gate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceVerdict {
    /// All checks pass.
    Approved,
    /// Budget utilisation too high.
    UtilisationExceeded,
    /// Regression detected.
    RegressionDetected,
    /// Tail-risk drift too high.
    TailRiskExceeded,
    /// Required dimensions missing evidence.
    InsufficientCoverage,
    /// Insufficient samples.
    InsufficientSamples,
    /// Multiple issues.
    MultipleViolations,
}

impl GovernanceVerdict {
    /// Whether this verdict blocks publication.
    pub fn blocks_publication(self) -> bool {
        self != Self::Approved
    }
}

impl fmt::Display for GovernanceVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Approved => "approved",
            Self::UtilisationExceeded => "utilisation_exceeded",
            Self::RegressionDetected => "regression_detected",
            Self::TailRiskExceeded => "tail_risk_exceeded",
            Self::InsufficientCoverage => "insufficient_coverage",
            Self::InsufficientSamples => "insufficient_samples",
            Self::MultipleViolations => "multiple_violations",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// ViolationDetail
// ---------------------------------------------------------------------------

/// Detail about a single governance violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationDetail {
    /// Dimension affected.
    pub dimension: ResourceDimension,
    /// Workload.
    pub workload_id: String,
    /// Category.
    pub category: GovernanceVerdict,
    /// Summary.
    pub summary: String,
    /// Measured value (millionths).
    pub measured_millionths: u64,
    /// Threshold (millionths).
    pub threshold_millionths: u64,
}

// ---------------------------------------------------------------------------
// GovernanceReceipt
// ---------------------------------------------------------------------------

/// Content-hashed audit receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceReceipt {
    /// Overall verdict.
    pub verdict: GovernanceVerdict,
    /// Epoch at evaluation.
    pub epoch: SecurityEpoch,
    /// Dimensions evaluated.
    pub dimensions_evaluated: BTreeSet<ResourceDimension>,
    /// Dimensions missing evidence.
    pub dimensions_missing: BTreeSet<ResourceDimension>,
    /// Certificate evidence entries.
    pub certificates: Vec<CertificateEvidence>,
    /// Regression entries.
    pub regressions: Vec<RegressionEntry>,
    /// Tail-risk entries.
    pub tail_risks: Vec<TailRiskEntry>,
    /// All violations.
    pub violations: Vec<ViolationDetail>,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl GovernanceReceipt {
    fn compute_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(256);
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, &format!("{}", self.verdict));
        append_u64(&mut buf, self.epoch.as_u64());
        append_u64(&mut buf, self.dimensions_evaluated.len() as u64);
        for d in &self.dimensions_evaluated {
            append_str(&mut buf, &d.to_string());
        }
        append_u64(&mut buf, self.certificates.len() as u64);
        for c in &self.certificates {
            buf.extend_from_slice(c.evidence_hash.as_bytes());
        }
        append_u64(&mut buf, self.regressions.len() as u64);
        for r in &self.regressions {
            buf.extend_from_slice(r.entry_hash.as_bytes());
        }
        append_u64(&mut buf, self.violations.len() as u64);
        compute_digest(&buf)
    }
}

// ---------------------------------------------------------------------------
// GovernanceEvaluator
// ---------------------------------------------------------------------------

/// Evaluates resource certificate governance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceEvaluator {
    /// Configuration.
    pub policy: PublicationPolicy,
    /// Certificate evidence.
    pub certificates: Vec<CertificateEvidence>,
    /// Regression entries.
    pub regressions: Vec<RegressionEntry>,
    /// Tail-risk entries.
    pub tail_risks: Vec<TailRiskEntry>,
}

impl GovernanceEvaluator {
    /// Create with policy.
    pub fn new(policy: PublicationPolicy) -> Self {
        Self {
            policy,
            certificates: Vec::new(),
            regressions: Vec::new(),
            tail_risks: Vec::new(),
        }
    }

    /// Add certificate evidence.
    pub fn add_certificate(
        &mut self,
        dimension: ResourceDimension,
        workload_id: String,
        certified_budget: u64,
        measured_usage: u64,
        sample_count: u64,
    ) {
        let entry = CertificateEvidence::new(
            dimension,
            workload_id,
            certified_budget,
            measured_usage,
            sample_count,
            self.policy.max_utilisation_millionths,
        );
        self.certificates.push(entry);
    }

    /// Add regression entry.
    pub fn add_regression(
        &mut self,
        dimension: ResourceDimension,
        workload_id: String,
        previous_usage: u64,
        current_usage: u64,
    ) {
        let entry = RegressionEntry::new(
            dimension,
            workload_id,
            previous_usage,
            current_usage,
            self.policy.max_regression_millionths,
        );
        self.regressions.push(entry);
    }

    /// Add tail-risk entry.
    pub fn add_tail_risk(
        &mut self,
        dimension: ResourceDimension,
        workload_id: String,
        tail_ratio_millionths: u64,
        baseline_ratio_millionths: u64,
    ) {
        let entry = TailRiskEntry::new(
            dimension,
            workload_id,
            tail_ratio_millionths,
            baseline_ratio_millionths,
            self.policy.max_tail_risk_millionths,
        );
        self.tail_risks.push(entry);
    }

    /// Dimensions with evidence.
    fn covered_dimensions(&self) -> BTreeSet<ResourceDimension> {
        let mut dims = BTreeSet::new();
        for c in &self.certificates {
            dims.insert(c.dimension);
        }
        for r in &self.regressions {
            dims.insert(r.dimension);
        }
        for t in &self.tail_risks {
            dims.insert(t.dimension);
        }
        dims
    }

    /// Evaluate and produce receipt.
    pub fn evaluate(&self, epoch: SecurityEpoch) -> GovernanceReceipt {
        let covered = self.covered_dimensions();
        let mut violations = Vec::new();

        // Check required dimension coverage.
        let mut dims_missing = BTreeSet::new();
        for dim in &self.policy.required_dimensions {
            if !covered.contains(dim) {
                dims_missing.insert(*dim);
                violations.push(ViolationDetail {
                    dimension: *dim,
                    workload_id: String::new(),
                    category: GovernanceVerdict::InsufficientCoverage,
                    summary: format!("No evidence for required dimension {dim}"),
                    measured_millionths: 0,
                    threshold_millionths: 0,
                });
            }
        }

        // Check certificate utilisation.
        for c in &self.certificates {
            if !c.within_budget {
                violations.push(ViolationDetail {
                    dimension: c.dimension,
                    workload_id: c.workload_id.clone(),
                    category: GovernanceVerdict::UtilisationExceeded,
                    summary: format!(
                        "{} utilisation on {} = {} > {}",
                        c.dimension,
                        c.workload_id,
                        c.utilisation_millionths,
                        self.policy.max_utilisation_millionths
                    ),
                    measured_millionths: c.utilisation_millionths,
                    threshold_millionths: self.policy.max_utilisation_millionths,
                });
            }
            if c.sample_count < self.policy.min_samples {
                violations.push(ViolationDetail {
                    dimension: c.dimension,
                    workload_id: c.workload_id.clone(),
                    category: GovernanceVerdict::InsufficientSamples,
                    summary: format!(
                        "{} samples on {} = {} < {}",
                        c.dimension, c.workload_id, c.sample_count, self.policy.min_samples
                    ),
                    measured_millionths: c.sample_count,
                    threshold_millionths: self.policy.min_samples,
                });
            }
        }

        // Check regressions.
        for r in &self.regressions {
            if !r.within_budget {
                violations.push(ViolationDetail {
                    dimension: r.dimension,
                    workload_id: r.workload_id.clone(),
                    category: GovernanceVerdict::RegressionDetected,
                    summary: format!(
                        "{} regression on {} = {} > {}",
                        r.dimension,
                        r.workload_id,
                        r.regression_millionths,
                        self.policy.max_regression_millionths
                    ),
                    measured_millionths: r.regression_millionths,
                    threshold_millionths: self.policy.max_regression_millionths,
                });
            }
        }

        // Check tail-risk.
        for t in &self.tail_risks {
            if !t.within_budget {
                violations.push(ViolationDetail {
                    dimension: t.dimension,
                    workload_id: t.workload_id.clone(),
                    category: GovernanceVerdict::TailRiskExceeded,
                    summary: format!(
                        "{} tail-risk on {} = {} > {}",
                        t.dimension,
                        t.workload_id,
                        t.drift_millionths,
                        self.policy.max_tail_risk_millionths
                    ),
                    measured_millionths: t.drift_millionths,
                    threshold_millionths: self.policy.max_tail_risk_millionths,
                });
            }
        }

        let verdict = if violations.is_empty() {
            GovernanceVerdict::Approved
        } else {
            let categories: BTreeSet<GovernanceVerdict> =
                violations.iter().map(|v| v.category).collect();
            if categories.len() == 1 {
                *categories.iter().next().unwrap()
            } else {
                GovernanceVerdict::MultipleViolations
            }
        };

        let mut receipt = GovernanceReceipt {
            verdict,
            epoch,
            dimensions_evaluated: covered,
            dimensions_missing: dims_missing,
            certificates: self.certificates.clone(),
            regressions: self.regressions.clone(),
            tail_risks: self.tail_risks.clone(),
            violations,
            content_hash: ContentHash::compute(b"placeholder"),
        };
        receipt.content_hash = receipt.compute_hash();
        receipt
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("resource-certificate-governance"));
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "resource_certificate_governance");
    }

    #[test]
    fn test_bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.25.3");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-625C");
    }

    #[test]
    fn test_resource_dimension_all_count() {
        assert_eq!(ResourceDimension::all().len(), 10);
    }

    #[test]
    fn test_resource_dimension_ordering() {
        assert!(ResourceDimension::CpuTime < ResourceDimension::InstructionCount);
    }

    #[test]
    fn test_resource_dimension_display() {
        assert_eq!(ResourceDimension::HeapMemory.to_string(), "heap_memory");
    }

    #[test]
    fn test_certificate_within_budget() {
        let c = CertificateEvidence::new(
            ResourceDimension::CpuTime,
            "workload_a".into(),
            1000,
            800,
            50,
            DEFAULT_MAX_UTILISATION_MILLIONTHS,
        );
        assert!(c.within_budget);
        assert_eq!(c.utilisation_millionths, 800_000);
    }

    #[test]
    fn test_certificate_over_budget() {
        let c = CertificateEvidence::new(
            ResourceDimension::CpuTime,
            "workload_a".into(),
            1000,
            950,
            50,
            DEFAULT_MAX_UTILISATION_MILLIONTHS,
        );
        assert!(!c.within_budget);
    }

    #[test]
    fn test_certificate_zero_budget() {
        let c = CertificateEvidence::new(
            ResourceDimension::CpuTime,
            "workload_a".into(),
            0,
            100,
            50,
            DEFAULT_MAX_UTILISATION_MILLIONTHS,
        );
        assert_eq!(c.utilisation_millionths, FIXED_ONE);
    }

    #[test]
    fn test_certificate_hash_deterministic() {
        let a = CertificateEvidence::new(
            ResourceDimension::HeapMemory,
            "w1".into(),
            1000,
            500,
            50,
            DEFAULT_MAX_UTILISATION_MILLIONTHS,
        );
        let b = CertificateEvidence::new(
            ResourceDimension::HeapMemory,
            "w1".into(),
            1000,
            500,
            50,
            DEFAULT_MAX_UTILISATION_MILLIONTHS,
        );
        assert_eq!(a.evidence_hash, b.evidence_hash);
    }

    #[test]
    fn test_regression_within_budget() {
        let r = RegressionEntry::new(
            ResourceDimension::CpuTime,
            "workload_a".into(),
            1000,
            1020,
            DEFAULT_MAX_REGRESSION_MILLIONTHS,
        );
        assert!(r.within_budget);
        assert_eq!(r.regression_millionths, 20_000);
    }

    #[test]
    fn test_regression_exceeds_budget() {
        let r = RegressionEntry::new(
            ResourceDimension::CpuTime,
            "workload_a".into(),
            1000,
            1100,
            DEFAULT_MAX_REGRESSION_MILLIONTHS,
        );
        assert!(!r.within_budget);
    }

    #[test]
    fn test_regression_improvement() {
        let r = RegressionEntry::new(
            ResourceDimension::CpuTime,
            "workload_a".into(),
            1000,
            900,
            DEFAULT_MAX_REGRESSION_MILLIONTHS,
        );
        assert!(r.within_budget);
        assert_eq!(r.regression_millionths, 0);
    }

    #[test]
    fn test_tail_risk_within_budget() {
        let t = TailRiskEntry::new(
            ResourceDimension::HeapMemory,
            "workload_a".into(),
            2_100_000,
            2_050_000,
            DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
        );
        assert!(t.within_budget);
        assert_eq!(t.drift_millionths, 50_000);
    }

    #[test]
    fn test_tail_risk_exceeds() {
        let t = TailRiskEntry::new(
            ResourceDimension::HeapMemory,
            "workload_a".into(),
            3_000_000,
            2_000_000,
            DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
        );
        assert!(!t.within_budget);
    }

    #[test]
    fn test_policy_strict() {
        let p = PublicationPolicy::strict();
        assert_eq!(p.required_dimensions.len(), 10);
        assert_eq!(p.max_regression_millionths, 20_000);
    }

    #[test]
    fn test_policy_relaxed() {
        let p = PublicationPolicy::relaxed();
        assert!(p.required_dimensions.is_empty());
    }

    #[test]
    fn test_verdict_blocks_publication() {
        assert!(!GovernanceVerdict::Approved.blocks_publication());
        assert!(GovernanceVerdict::RegressionDetected.blocks_publication());
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(GovernanceVerdict::Approved.to_string(), "approved");
    }

    #[test]
    fn test_evaluator_empty_approved() {
        let eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn test_evaluator_certificate_pass() {
        let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
        eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn test_evaluator_certificate_fail() {
        let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
        eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 950, 50);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::UtilisationExceeded);
    }

    #[test]
    fn test_evaluator_regression_fail() {
        let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
        eval.add_regression(ResourceDimension::HeapMemory, "w1".into(), 1000, 1200);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::RegressionDetected);
    }

    #[test]
    fn test_evaluator_tail_risk_fail() {
        let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
        eval.add_tail_risk(
            ResourceDimension::CpuTime,
            "w1".into(),
            5_000_000,
            2_000_000,
        );
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::TailRiskExceeded);
    }

    #[test]
    fn test_evaluator_missing_required_dim() {
        let mut policy = PublicationPolicy::relaxed();
        policy
            .required_dimensions
            .insert(ResourceDimension::GcPause);
        let eval = GovernanceEvaluator::new(policy);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
    }

    #[test]
    fn test_evaluator_multiple_violations() {
        let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
        eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 950, 50);
        eval.add_regression(ResourceDimension::HeapMemory, "w1".into(), 1000, 1200);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
    }

    #[test]
    fn test_evaluator_insufficient_samples() {
        let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
        eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 5);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientSamples);
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
        eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
        let r1 = eval.evaluate(epoch());
        let r2 = eval.evaluate(epoch());
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_receipt_hash_changes() {
        let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
        let r1 = eval.evaluate(epoch());
        eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
        let r2 = eval.evaluate(epoch());
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_covered_dimensions() {
        let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
        eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
        eval.add_regression(ResourceDimension::HeapMemory, "w1".into(), 1000, 1000);
        let receipt = eval.evaluate(epoch());
        assert!(
            receipt
                .dimensions_evaluated
                .contains(&ResourceDimension::CpuTime)
        );
        assert!(
            receipt
                .dimensions_evaluated
                .contains(&ResourceDimension::HeapMemory)
        );
    }

    #[test]
    fn test_e2e_full_pass() {
        let mut eval = GovernanceEvaluator::new(PublicationPolicy::relaxed());
        eval.add_certificate(ResourceDimension::CpuTime, "w1".into(), 1000, 500, 50);
        eval.add_certificate(ResourceDimension::HeapMemory, "w1".into(), 2000, 1000, 50);
        eval.add_regression(ResourceDimension::CpuTime, "w1".into(), 1000, 1000);
        eval.add_tail_risk(
            ResourceDimension::CpuTime,
            "w1".into(),
            2_100_000,
            2_050_000,
        );
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn test_strict_requires_all_dimensions() {
        let eval = GovernanceEvaluator::new(PublicationPolicy::strict());
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
        assert_eq!(receipt.dimensions_missing.len(), 10);
    }
}
