#![forbid(unsafe_code)]

//! Sliding-window kernel-mean-embedding and MMD shift monitors for
//! benchmark versus live workload streams.
//!
//! Bead: bd-1lsy.8.6.1 [RGC-706A]
//!
//! Detects when the benchmark board no longer reflects actual production
//! workload distribution by comparing kernel-mean-embeddings over sliding
//! windows of workload features.
//!
//! # Design decisions
//!
//! - **Kernel-mean-embedding (KME)** — each window of workload observations
//!   is summarized by a mean-embedding in a reproducing kernel Hilbert space.
//! - **MMD (Maximum Mean Discrepancy)** — the distance between two KME
//!   summaries serves as a calibrated test statistic for distribution shift.
//! - **Sliding windows** — fixed-size non-overlapping windows ensure that
//!   the monitor operates on fresh data and does not dilute signals with
//!   stale history.
//! - **Multiple monitors** — each workload dimension (compute profile,
//!   allocation pattern, module-graph shape, etc.) gets its own monitor,
//!   combined via a structured aggregation policy.
//! - **Conservative false-alarm control** — the system prefers to miss a
//!   real shift rather than raise a false alarm that triggers unnecessary
//!   re-benchmarking or board expansion.
//! - **Explicit abstention** — if sample size, calibration, or evidence
//!   quality is insufficient the monitor abstains rather than guessing.
//! - All arithmetic uses fixed-point millionths (1_000_000 = 1.0).

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
pub const SCHEMA_VERSION: &str = "franken-engine.kernel-shift-monitor.v1";

/// Bead identifier.
pub const BEAD_ID: &str = "bd-1lsy.8.6.1";

/// Component name.
pub const COMPONENT: &str = "kernel_shift_monitor";

/// One million — unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

/// Default sliding window size (number of observations per window).
pub const DEFAULT_WINDOW_SIZE: usize = 256;

/// Minimum window size below which the monitor must abstain.
pub const MIN_WINDOW_SIZE: usize = 32;

/// Default MMD significance threshold (millionths).  MMD values above
/// this trigger a shift alert.
pub const DEFAULT_MMD_THRESHOLD: u64 = 100_000; // 10%

/// Maximum number of monitors that can be combined in a single aggregate.
pub const MAX_MONITORS: usize = 32;

/// Default false-alarm budget (millionths).  The system tries to keep
/// the false-alarm rate below this across all monitors.
pub const DEFAULT_FALSE_ALARM_BUDGET: u64 = 50_000; // 5%

// ---------------------------------------------------------------------------
// WorkloadDimension — what aspect of workload is being monitored
// ---------------------------------------------------------------------------

/// A workload feature dimension over which distribution shift is tracked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadDimension {
    /// CPU-bound computation intensity profile.
    ComputeIntensity,
    /// Heap allocation rate and object-size distribution.
    AllocationPattern,
    /// Module dependency graph shape and depth.
    ModuleGraphShape,
    /// Hostcall invocation frequency and type distribution.
    HostcallProfile,
    /// String operation density and encoding distribution.
    StringOperationProfile,
    /// Control flow complexity (branch counts, loop depths).
    ControlFlowComplexity,
    /// I/O wait and async scheduling patterns.
    IoSchedulingPattern,
    /// GC pressure and pause distribution.
    GcPressureProfile,
}

impl WorkloadDimension {
    /// All known dimensions in canonical order.
    pub const ALL: &[Self] = &[
        Self::ComputeIntensity,
        Self::AllocationPattern,
        Self::ModuleGraphShape,
        Self::HostcallProfile,
        Self::StringOperationProfile,
        Self::ControlFlowComplexity,
        Self::IoSchedulingPattern,
        Self::GcPressureProfile,
    ];

    /// Machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ComputeIntensity => "compute_intensity",
            Self::AllocationPattern => "allocation_pattern",
            Self::ModuleGraphShape => "module_graph_shape",
            Self::HostcallProfile => "hostcall_profile",
            Self::StringOperationProfile => "string_operation_profile",
            Self::ControlFlowComplexity => "control_flow_complexity",
            Self::IoSchedulingPattern => "io_scheduling_pattern",
            Self::GcPressureProfile => "gc_pressure_profile",
        }
    }
}

impl fmt::Display for WorkloadDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// KernelKind — the kernel function used for embedding
// ---------------------------------------------------------------------------

/// The reproducing kernel used to compute mean embeddings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KernelKind {
    /// Gaussian (RBF) kernel with bandwidth parameter.
    Gaussian,
    /// Laplacian kernel (exponential of L1 distance).
    Laplacian,
    /// Linear kernel (dot product — degenerate case for baseline).
    Linear,
    /// Polynomial kernel of fixed degree.
    Polynomial,
}

impl KernelKind {
    /// All kernel kinds.
    pub const ALL: &[Self] = &[
        Self::Gaussian,
        Self::Laplacian,
        Self::Linear,
        Self::Polynomial,
    ];

    /// Machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Gaussian => "gaussian",
            Self::Laplacian => "laplacian",
            Self::Linear => "linear",
            Self::Polynomial => "polynomial",
        }
    }

    /// Whether this kernel requires a bandwidth parameter.
    pub fn requires_bandwidth(&self) -> bool {
        matches!(self, Self::Gaussian | Self::Laplacian)
    }
}

impl fmt::Display for KernelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MonitorAbstention — why the monitor cannot produce a result
// ---------------------------------------------------------------------------

/// Reason why a shift monitor abstained from producing a verdict.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorAbstention {
    /// The window has fewer samples than the minimum.
    InsufficientSamples { available: usize, required: usize },
    /// The kernel bandwidth has not been calibrated.
    UncalibratedBandwidth,
    /// The reference (benchmark) distribution is empty.
    EmptyReferenceDistribution,
    /// The live stream has not yet filled a complete window.
    IncompleteWindow { filled: usize, window_size: usize },
    /// The monitor has been disabled by operator policy.
    DisabledByPolicy,
}

impl MonitorAbstention {
    /// Machine-readable tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::InsufficientSamples { .. } => "insufficient_samples",
            Self::UncalibratedBandwidth => "uncalibrated_bandwidth",
            Self::EmptyReferenceDistribution => "empty_reference_distribution",
            Self::IncompleteWindow { .. } => "incomplete_window",
            Self::DisabledByPolicy => "disabled_by_policy",
        }
    }
}

impl fmt::Display for MonitorAbstention {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InsufficientSamples {
                available,
                required,
            } => write!(f, "insufficient samples: {}/{}", available, required),
            Self::UncalibratedBandwidth => write!(f, "uncalibrated bandwidth"),
            Self::EmptyReferenceDistribution => write!(f, "empty reference distribution"),
            Self::IncompleteWindow {
                filled,
                window_size,
            } => write!(f, "incomplete window: {}/{}", filled, window_size),
            Self::DisabledByPolicy => write!(f, "disabled by policy"),
        }
    }
}

// ---------------------------------------------------------------------------
// ShiftVerdict — the outcome of a shift test
// ---------------------------------------------------------------------------

/// The outcome of a single shift test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShiftVerdict {
    /// No significant shift detected — the board is still representative.
    NoShift,
    /// Marginal shift detected — worth monitoring but not alarming.
    MarginalShift,
    /// Significant shift detected — the board should be re-evaluated.
    SignificantShift,
    /// Cannot determine — abstained due to data quality issues.
    Inconclusive,
}

impl ShiftVerdict {
    /// All verdicts.
    pub const ALL: &[Self] = &[
        Self::NoShift,
        Self::MarginalShift,
        Self::SignificantShift,
        Self::Inconclusive,
    ];

    /// Machine-readable label.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::NoShift => "no_shift",
            Self::MarginalShift => "marginal_shift",
            Self::SignificantShift => "significant_shift",
            Self::Inconclusive => "inconclusive",
        }
    }

    /// Whether this verdict recommends board re-evaluation.
    pub fn recommends_reevaluation(&self) -> bool {
        matches!(self, Self::SignificantShift)
    }

    /// Whether this verdict indicates potential concern.
    pub fn is_concerning(&self) -> bool {
        matches!(self, Self::MarginalShift | Self::SignificantShift)
    }
}

impl fmt::Display for ShiftVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MonitorConfig — per-dimension configuration
// ---------------------------------------------------------------------------

/// Configuration for a single workload shift monitor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorConfig {
    /// The workload dimension being monitored.
    pub dimension: WorkloadDimension,
    /// The kernel function to use.
    pub kernel: KernelKind,
    /// Bandwidth parameter for the kernel (in millionths).
    /// Ignored for kernels that do not require bandwidth.
    pub bandwidth_millionths: u64,
    /// Sliding window size (number of observations).
    pub window_size: usize,
    /// MMD significance threshold (millionths).
    pub mmd_threshold_millionths: u64,
    /// Marginal shift threshold (millionths) — values between marginal
    /// and significant thresholds receive `MarginalShift`.
    pub marginal_threshold_millionths: u64,
}

impl MonitorConfig {
    /// Build a default config for a dimension.
    pub fn default_for(dimension: WorkloadDimension) -> Self {
        Self {
            dimension,
            kernel: KernelKind::Gaussian,
            bandwidth_millionths: 500_000,
            window_size: DEFAULT_WINDOW_SIZE,
            mmd_threshold_millionths: DEFAULT_MMD_THRESHOLD,
            marginal_threshold_millionths: DEFAULT_MMD_THRESHOLD / 2,
        }
    }
}

// ---------------------------------------------------------------------------
// WindowSummary — the KME of a single window
// ---------------------------------------------------------------------------

/// Summary statistics of a sliding window, including the kernel-mean-embedding
/// fingerprint and sample metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowSummary {
    /// The window index (0-based, monotonically increasing).
    pub window_index: u64,
    /// Number of samples in this window.
    pub sample_count: usize,
    /// Mean feature value across the window (millionths).
    pub mean_millionths: u64,
    /// Variance of feature values (millionths-squared).
    pub variance_millionths: u64,
    /// Fingerprint of the KME for this window.
    pub embedding_fingerprint: String,
}

// ---------------------------------------------------------------------------
// MmdResult — the distance between two windows
// ---------------------------------------------------------------------------

/// Result of an MMD test between a reference window and a live window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmdResult {
    /// The workload dimension.
    pub dimension: WorkloadDimension,
    /// MMD estimate in millionths (0 = identical distributions).
    pub mmd_millionths: u64,
    /// The threshold used for this test (millionths).
    pub threshold_millionths: u64,
    /// The marginal threshold (millionths).
    pub marginal_threshold_millionths: u64,
    /// The kernel used.
    pub kernel: KernelKind,
    /// Number of reference samples.
    pub reference_sample_count: usize,
    /// Number of live samples.
    pub live_sample_count: usize,
    /// The shift verdict derived from the MMD value.
    pub verdict: ShiftVerdict,
}

impl MmdResult {
    /// Compute the verdict from MMD value and thresholds.
    pub fn compute(
        dimension: WorkloadDimension,
        mmd_millionths: u64,
        config: &MonitorConfig,
        reference_sample_count: usize,
        live_sample_count: usize,
    ) -> Self {
        let verdict = if mmd_millionths >= config.mmd_threshold_millionths {
            ShiftVerdict::SignificantShift
        } else if mmd_millionths >= config.marginal_threshold_millionths {
            ShiftVerdict::MarginalShift
        } else {
            ShiftVerdict::NoShift
        };

        Self {
            dimension,
            mmd_millionths,
            threshold_millionths: config.mmd_threshold_millionths,
            marginal_threshold_millionths: config.marginal_threshold_millionths,
            kernel: config.kernel,
            reference_sample_count,
            live_sample_count,
            verdict,
        }
    }

    /// Whether the MMD exceeds the significance threshold.
    pub fn is_significant(&self) -> bool {
        self.mmd_millionths >= self.threshold_millionths
    }

    /// Whether the MMD exceeds the marginal threshold.
    pub fn is_marginal(&self) -> bool {
        self.mmd_millionths >= self.marginal_threshold_millionths
    }
}

// ---------------------------------------------------------------------------
// MonitorResult — per-dimension result (scored or abstained)
// ---------------------------------------------------------------------------

/// Result of a single shift monitor: either an MMD measurement or an
/// abstention with a structured reason.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MonitorResult {
    /// The monitor produced an MMD measurement.
    Measured(MmdResult),
    /// The monitor abstained.
    Abstained {
        dimension: WorkloadDimension,
        reason: MonitorAbstention,
    },
}

impl MonitorResult {
    /// The workload dimension this result pertains to.
    pub fn dimension(&self) -> WorkloadDimension {
        match self {
            Self::Measured(m) => m.dimension,
            Self::Abstained { dimension, .. } => *dimension,
        }
    }

    /// Whether this result is a measurement (not an abstention).
    pub fn is_measured(&self) -> bool {
        matches!(self, Self::Measured(_))
    }

    /// Whether this result is an abstention.
    pub fn is_abstained(&self) -> bool {
        matches!(self, Self::Abstained { .. })
    }

    /// Extract the verdict if measured.
    pub fn verdict(&self) -> Option<ShiftVerdict> {
        match self {
            Self::Measured(m) => Some(m.verdict),
            Self::Abstained { .. } => None,
        }
    }

    /// Extract the MMD value if measured.
    pub fn mmd_millionths(&self) -> Option<u64> {
        match self {
            Self::Measured(m) => Some(m.mmd_millionths),
            Self::Abstained { .. } => None,
        }
    }
}

// ---------------------------------------------------------------------------
// AggregateShiftReport — combining all monitors
// ---------------------------------------------------------------------------

/// Aggregated shift report across all workload dimensions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateShiftReport {
    /// Schema version.
    pub schema_version: String,
    /// Security epoch at report time.
    pub epoch: SecurityEpoch,
    /// Per-dimension results.
    pub results: Vec<MonitorResult>,
    /// The aggregate verdict (most severe across all dimensions).
    pub aggregate_verdict: ShiftVerdict,
    /// Number of dimensions that detected significant shift.
    pub significant_count: usize,
    /// Number of dimensions that detected marginal shift.
    pub marginal_count: usize,
    /// Number of dimensions that abstained.
    pub abstained_count: usize,
    /// Content hash of the report.
    pub content_hash: ContentHash,
}

impl AggregateShiftReport {
    /// Build an aggregate report from per-dimension results.
    pub fn new(epoch: SecurityEpoch, results: Vec<MonitorResult>) -> Self {
        let significant_count = results
            .iter()
            .filter(|r| r.verdict() == Some(ShiftVerdict::SignificantShift))
            .count();
        let marginal_count = results
            .iter()
            .filter(|r| r.verdict() == Some(ShiftVerdict::MarginalShift))
            .count();
        let abstained_count = results.iter().filter(|r| r.is_abstained()).count();

        let aggregate_verdict = if significant_count > 0 {
            ShiftVerdict::SignificantShift
        } else if marginal_count > 0 {
            ShiftVerdict::MarginalShift
        } else if !results.is_empty() && abstained_count == results.len() {
            ShiftVerdict::Inconclusive
        } else {
            ShiftVerdict::NoShift
        };

        let mut hasher = Sha256::new();
        hasher.update(SCHEMA_VERSION.as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update((results.len() as u64).to_le_bytes());
        for r in &results {
            hasher.update(r.dimension().as_str().as_bytes());
            match r {
                MonitorResult::Measured(m) => {
                    hasher.update(b"measured");
                    hasher.update(m.mmd_millionths.to_le_bytes());
                    hasher.update(m.verdict.as_str().as_bytes());
                }
                MonitorResult::Abstained { reason, .. } => {
                    hasher.update(b"abstained");
                    hasher.update(reason.tag().as_bytes());
                }
            }
        }
        hasher.update(aggregate_verdict.as_str().as_bytes());
        let content_hash = ContentHash::compute(&hasher.finalize());

        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            epoch,
            results,
            aggregate_verdict,
            significant_count,
            marginal_count,
            abstained_count,
            content_hash,
        }
    }

    /// Total number of monitors in this report.
    pub fn monitor_count(&self) -> usize {
        self.results.len()
    }

    /// Number of monitors that produced a measurement.
    pub fn measured_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_measured()).count()
    }

    /// Coverage fraction (measured / total) in millionths.
    pub fn coverage_millionths(&self) -> u64 {
        if self.results.is_empty() {
            return 0;
        }
        let measured = self.measured_count() as u64;
        measured.saturating_mul(MILLION) / self.results.len() as u64
    }

    /// Whether the aggregate recommends board re-evaluation.
    pub fn recommends_reevaluation(&self) -> bool {
        self.aggregate_verdict.recommends_reevaluation()
    }

    /// Dimensions that detected significant shift.
    pub fn significantly_shifted_dimensions(&self) -> BTreeSet<WorkloadDimension> {
        self.results
            .iter()
            .filter(|r| r.verdict() == Some(ShiftVerdict::SignificantShift))
            .map(|r| r.dimension())
            .collect()
    }

    /// Result for a specific dimension.
    pub fn result_for(&self, dim: WorkloadDimension) -> Option<&MonitorResult> {
        self.results.iter().find(|r| r.dimension() == dim)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(55)
    }

    fn default_config(dim: WorkloadDimension) -> MonitorConfig {
        MonitorConfig::default_for(dim)
    }

    fn make_measured(dim: WorkloadDimension, mmd: u64) -> MonitorResult {
        let config = default_config(dim);
        MonitorResult::Measured(MmdResult::compute(dim, mmd, &config, 256, 256))
    }

    fn make_abstained(dim: WorkloadDimension) -> MonitorResult {
        MonitorResult::Abstained {
            dimension: dim,
            reason: MonitorAbstention::UncalibratedBandwidth,
        }
    }

    // --- WorkloadDimension tests ---

    #[test]
    fn dimension_all_count() {
        assert_eq!(WorkloadDimension::ALL.len(), 8);
    }

    #[test]
    fn dimension_names_unique() {
        let names: BTreeSet<&str> = WorkloadDimension::ALL.iter().map(|d| d.as_str()).collect();
        assert_eq!(names.len(), WorkloadDimension::ALL.len());
    }

    #[test]
    fn dimension_display_matches_as_str() {
        for d in WorkloadDimension::ALL {
            assert_eq!(d.to_string(), d.as_str());
        }
    }

    #[test]
    fn dimension_serde_roundtrip() {
        for d in WorkloadDimension::ALL {
            let json = serde_json::to_string(d).unwrap();
            let back: WorkloadDimension = serde_json::from_str(&json).unwrap();
            assert_eq!(*d, back);
        }
    }

    // --- KernelKind tests ---

    #[test]
    fn kernel_all_count() {
        assert_eq!(KernelKind::ALL.len(), 4);
    }

    #[test]
    fn kernel_names_unique() {
        let names: BTreeSet<&str> = KernelKind::ALL.iter().map(|k| k.as_str()).collect();
        assert_eq!(names.len(), KernelKind::ALL.len());
    }

    #[test]
    fn kernel_bandwidth_semantics() {
        assert!(KernelKind::Gaussian.requires_bandwidth());
        assert!(KernelKind::Laplacian.requires_bandwidth());
        assert!(!KernelKind::Linear.requires_bandwidth());
        assert!(!KernelKind::Polynomial.requires_bandwidth());
    }

    #[test]
    fn kernel_serde_roundtrip() {
        for k in KernelKind::ALL {
            let json = serde_json::to_string(k).unwrap();
            let back: KernelKind = serde_json::from_str(&json).unwrap();
            assert_eq!(*k, back);
        }
    }

    // --- MonitorAbstention tests ---

    #[test]
    fn abstention_tags_unique() {
        let reasons = [
            MonitorAbstention::InsufficientSamples {
                available: 10,
                required: 32,
            },
            MonitorAbstention::UncalibratedBandwidth,
            MonitorAbstention::EmptyReferenceDistribution,
            MonitorAbstention::IncompleteWindow {
                filled: 20,
                window_size: 256,
            },
            MonitorAbstention::DisabledByPolicy,
        ];
        let tags: BTreeSet<&str> = reasons.iter().map(|r| r.tag()).collect();
        assert_eq!(tags.len(), 5);
    }

    #[test]
    fn abstention_serde_roundtrip() {
        let r = MonitorAbstention::IncompleteWindow {
            filled: 50,
            window_size: 256,
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: MonitorAbstention = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    #[test]
    fn abstention_display() {
        let r = MonitorAbstention::InsufficientSamples {
            available: 5,
            required: 32,
        };
        let s = r.to_string();
        assert!(s.contains("5"));
        assert!(s.contains("32"));
    }

    // --- ShiftVerdict tests ---

    #[test]
    fn verdict_all_count() {
        assert_eq!(ShiftVerdict::ALL.len(), 4);
    }

    #[test]
    fn verdict_reevaluation_semantics() {
        assert!(!ShiftVerdict::NoShift.recommends_reevaluation());
        assert!(!ShiftVerdict::MarginalShift.recommends_reevaluation());
        assert!(ShiftVerdict::SignificantShift.recommends_reevaluation());
        assert!(!ShiftVerdict::Inconclusive.recommends_reevaluation());
    }

    #[test]
    fn verdict_concerning_semantics() {
        assert!(!ShiftVerdict::NoShift.is_concerning());
        assert!(ShiftVerdict::MarginalShift.is_concerning());
        assert!(ShiftVerdict::SignificantShift.is_concerning());
        assert!(!ShiftVerdict::Inconclusive.is_concerning());
    }

    #[test]
    fn verdict_serde_roundtrip() {
        for v in ShiftVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: ShiftVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- MonitorConfig tests ---

    #[test]
    fn config_default_values() {
        let c = MonitorConfig::default_for(WorkloadDimension::ComputeIntensity);
        assert_eq!(c.dimension, WorkloadDimension::ComputeIntensity);
        assert_eq!(c.kernel, KernelKind::Gaussian);
        assert_eq!(c.window_size, DEFAULT_WINDOW_SIZE);
        assert_eq!(c.mmd_threshold_millionths, DEFAULT_MMD_THRESHOLD);
        assert!(c.marginal_threshold_millionths < c.mmd_threshold_millionths);
    }

    #[test]
    fn config_serde_roundtrip() {
        let c = MonitorConfig::default_for(WorkloadDimension::AllocationPattern);
        let json = serde_json::to_string(&c).unwrap();
        let back: MonitorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // --- MmdResult tests ---

    #[test]
    fn mmd_no_shift() {
        let config = default_config(WorkloadDimension::ComputeIntensity);
        let r = MmdResult::compute(
            WorkloadDimension::ComputeIntensity,
            10_000, // 1%, well below threshold
            &config,
            256,
            256,
        );
        assert_eq!(r.verdict, ShiftVerdict::NoShift);
        assert!(!r.is_significant());
        assert!(!r.is_marginal());
    }

    #[test]
    fn mmd_marginal_shift() {
        let config = default_config(WorkloadDimension::ComputeIntensity);
        let r = MmdResult::compute(
            WorkloadDimension::ComputeIntensity,
            60_000, // 6%, between marginal (5%) and significant (10%)
            &config,
            256,
            256,
        );
        assert_eq!(r.verdict, ShiftVerdict::MarginalShift);
        assert!(!r.is_significant());
        assert!(r.is_marginal());
    }

    #[test]
    fn mmd_significant_shift() {
        let config = default_config(WorkloadDimension::ComputeIntensity);
        let r = MmdResult::compute(
            WorkloadDimension::ComputeIntensity,
            200_000, // 20%, above threshold
            &config,
            256,
            256,
        );
        assert_eq!(r.verdict, ShiftVerdict::SignificantShift);
        assert!(r.is_significant());
        assert!(r.is_marginal());
    }

    #[test]
    fn mmd_serde_roundtrip() {
        let config = default_config(WorkloadDimension::AllocationPattern);
        let r = MmdResult::compute(
            WorkloadDimension::AllocationPattern,
            75_000,
            &config,
            100,
            200,
        );
        let json = serde_json::to_string(&r).unwrap();
        let back: MmdResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, back);
    }

    // --- MonitorResult tests ---

    #[test]
    fn monitor_result_measured() {
        let r = make_measured(WorkloadDimension::ComputeIntensity, 5_000);
        assert!(r.is_measured());
        assert!(!r.is_abstained());
        assert_eq!(r.dimension(), WorkloadDimension::ComputeIntensity);
        assert!(r.verdict().is_some());
        assert!(r.mmd_millionths().is_some());
    }

    #[test]
    fn monitor_result_abstained() {
        let r = make_abstained(WorkloadDimension::GcPressureProfile);
        assert!(r.is_abstained());
        assert!(!r.is_measured());
        assert_eq!(r.dimension(), WorkloadDimension::GcPressureProfile);
        assert!(r.verdict().is_none());
        assert!(r.mmd_millionths().is_none());
    }

    #[test]
    fn monitor_result_serde_roundtrip() {
        let measured = make_measured(WorkloadDimension::HostcallProfile, 80_000);
        let json = serde_json::to_string(&measured).unwrap();
        let back: MonitorResult = serde_json::from_str(&json).unwrap();
        assert_eq!(measured, back);

        let abstained = make_abstained(WorkloadDimension::IoSchedulingPattern);
        let json2 = serde_json::to_string(&abstained).unwrap();
        let back2: MonitorResult = serde_json::from_str(&json2).unwrap();
        assert_eq!(abstained, back2);
    }

    // --- AggregateShiftReport tests ---

    #[test]
    fn aggregate_empty() {
        let report = AggregateShiftReport::new(test_epoch(), Vec::new());
        assert_eq!(report.monitor_count(), 0);
        assert_eq!(report.measured_count(), 0);
        assert_eq!(report.aggregate_verdict, ShiftVerdict::NoShift);
        assert_eq!(report.coverage_millionths(), 0);
        assert!(!report.recommends_reevaluation());
    }

    #[test]
    fn aggregate_all_no_shift() {
        let results: Vec<_> = WorkloadDimension::ALL
            .iter()
            .map(|d| make_measured(*d, 5_000))
            .collect();
        let report = AggregateShiftReport::new(test_epoch(), results);
        assert_eq!(report.aggregate_verdict, ShiftVerdict::NoShift);
        assert_eq!(report.significant_count, 0);
        assert_eq!(report.marginal_count, 0);
        assert!(!report.recommends_reevaluation());
        assert_eq!(report.coverage_millionths(), MILLION);
    }

    #[test]
    fn aggregate_one_significant() {
        let results = vec![
            make_measured(WorkloadDimension::ComputeIntensity, 5_000),
            make_measured(WorkloadDimension::AllocationPattern, 200_000), // significant
            make_measured(WorkloadDimension::ModuleGraphShape, 5_000),
        ];
        let report = AggregateShiftReport::new(test_epoch(), results);
        assert_eq!(report.aggregate_verdict, ShiftVerdict::SignificantShift);
        assert_eq!(report.significant_count, 1);
        assert!(report.recommends_reevaluation());
        let shifted = report.significantly_shifted_dimensions();
        assert!(shifted.contains(&WorkloadDimension::AllocationPattern));
    }

    #[test]
    fn aggregate_marginal_only() {
        let results = vec![
            make_measured(WorkloadDimension::ComputeIntensity, 5_000),
            make_measured(WorkloadDimension::AllocationPattern, 60_000), // marginal
        ];
        let report = AggregateShiftReport::new(test_epoch(), results);
        assert_eq!(report.aggregate_verdict, ShiftVerdict::MarginalShift);
        assert_eq!(report.marginal_count, 1);
        assert!(!report.recommends_reevaluation());
    }

    #[test]
    fn aggregate_all_abstained() {
        let results: Vec<_> = WorkloadDimension::ALL
            .iter()
            .map(|d| make_abstained(*d))
            .collect();
        let report = AggregateShiftReport::new(test_epoch(), results);
        assert_eq!(report.aggregate_verdict, ShiftVerdict::Inconclusive);
        assert_eq!(report.abstained_count, WorkloadDimension::ALL.len());
        assert_eq!(report.coverage_millionths(), 0);
    }

    #[test]
    fn aggregate_content_hash_deterministic() {
        let results1 = vec![make_measured(WorkloadDimension::ComputeIntensity, 50_000)];
        let results2 = vec![make_measured(WorkloadDimension::ComputeIntensity, 50_000)];
        let r1 = AggregateShiftReport::new(test_epoch(), results1);
        let r2 = AggregateShiftReport::new(test_epoch(), results2);
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn aggregate_result_for_lookup() {
        let results = vec![
            make_measured(WorkloadDimension::ComputeIntensity, 30_000),
            make_abstained(WorkloadDimension::GcPressureProfile),
        ];
        let report = AggregateShiftReport::new(test_epoch(), results);
        assert!(
            report
                .result_for(WorkloadDimension::ComputeIntensity)
                .is_some()
        );
        assert!(
            report
                .result_for(WorkloadDimension::GcPressureProfile)
                .is_some()
        );
        assert!(
            report
                .result_for(WorkloadDimension::IoSchedulingPattern)
                .is_none()
        );
    }

    #[test]
    fn aggregate_serde_roundtrip() {
        let results = vec![
            make_measured(WorkloadDimension::ComputeIntensity, 50_000),
            make_abstained(WorkloadDimension::AllocationPattern),
        ];
        let report = AggregateShiftReport::new(test_epoch(), results);
        let json = serde_json::to_string(&report).unwrap();
        let back: AggregateShiftReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // --- Constants tests ---

    #[test]
    fn constants_valid() {
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!COMPONENT.is_empty());
        let win = DEFAULT_WINDOW_SIZE;
        let min_win = MIN_WINDOW_SIZE;
        let mmd_thresh = DEFAULT_MMD_THRESHOLD;
        let max_mon = MAX_MONITORS;
        let fa_budget = DEFAULT_FALSE_ALARM_BUDGET;
        let mill = MILLION;
        assert!(win >= min_win);
        assert!(min_win > 0);
        assert!(mmd_thresh > 0);
        assert!(mmd_thresh <= mill);
        assert!(max_mon > 0);
        assert!(fa_budget > 0);
        assert!(fa_budget <= mill);
    }

    #[test]
    fn million_value() {
        assert_eq!(MILLION, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Deep enrichment tests (PearlTower 2026-03-18)
    // -----------------------------------------------------------------------

    #[test]
    fn mmd_exact_threshold_is_significant() {
        let config = default_config(WorkloadDimension::ComputeIntensity);
        let r = MmdResult::compute(
            WorkloadDimension::ComputeIntensity,
            config.mmd_threshold_millionths,
            &config,
            256,
            256,
        );
        assert_eq!(r.verdict, ShiftVerdict::SignificantShift);
    }

    #[test]
    fn mmd_just_below_threshold() {
        let config = default_config(WorkloadDimension::ComputeIntensity);
        let r = MmdResult::compute(
            WorkloadDimension::ComputeIntensity,
            config.mmd_threshold_millionths - 1,
            &config,
            256,
            256,
        );
        assert_ne!(r.verdict, ShiftVerdict::SignificantShift);
    }

    #[test]
    fn mmd_zero_is_no_shift() {
        let config = default_config(WorkloadDimension::ComputeIntensity);
        let r = MmdResult::compute(WorkloadDimension::ComputeIntensity, 0, &config, 256, 256);
        assert_eq!(r.verdict, ShiftVerdict::NoShift);
    }

    #[test]
    fn mmd_deterministic() {
        let config = default_config(WorkloadDimension::AllocationPattern);
        let r1 = MmdResult::compute(
            WorkloadDimension::AllocationPattern,
            75_000,
            &config,
            100,
            200,
        );
        let r2 = MmdResult::compute(
            WorkloadDimension::AllocationPattern,
            75_000,
            &config,
            100,
            200,
        );
        assert_eq!(r1, r2);
    }

    #[test]
    fn aggregate_mixed_measured_and_abstained() {
        let results = vec![
            make_measured(WorkloadDimension::ComputeIntensity, 5_000),
            make_abstained(WorkloadDimension::AllocationPattern),
            make_measured(WorkloadDimension::ModuleGraphShape, 200_000),
        ];
        let report = AggregateShiftReport::new(test_epoch(), results);
        assert_eq!(report.measured_count(), 2);
        assert_eq!(report.abstained_count, 1);
        assert_eq!(report.significant_count, 1);
    }

    #[test]
    fn aggregate_coverage_partial() {
        let results = vec![
            make_measured(WorkloadDimension::ComputeIntensity, 5_000),
            make_abstained(WorkloadDimension::AllocationPattern),
        ];
        let report = AggregateShiftReport::new(test_epoch(), results);
        // 1 measured out of 2 total = 500_000 millionths
        assert_eq!(report.coverage_millionths(), 500_000);
    }

    #[test]
    fn aggregate_significantly_shifted_empty_when_no_shift() {
        let results = vec![make_measured(WorkloadDimension::ComputeIntensity, 5_000)];
        let report = AggregateShiftReport::new(test_epoch(), results);
        assert!(report.significantly_shifted_dimensions().is_empty());
    }

    #[test]
    fn config_different_dimensions_same_structure() {
        let c1 = MonitorConfig::default_for(WorkloadDimension::ComputeIntensity);
        let c2 = MonitorConfig::default_for(WorkloadDimension::GcPressureProfile);
        // Same default structure, just different dimension
        assert_eq!(c1.kernel, c2.kernel);
        assert_eq!(c1.window_size, c2.window_size);
        assert_ne!(c1.dimension, c2.dimension);
    }

    #[test]
    fn kernel_display_matches_as_str() {
        for k in KernelKind::ALL {
            assert_eq!(k.to_string(), k.as_str());
        }
    }

    #[test]
    fn verdict_display_matches_as_str() {
        for v in ShiftVerdict::ALL {
            assert_eq!(v.to_string(), v.as_str());
        }
    }

    #[test]
    fn report_hash_changes_with_different_results() {
        let r1 = AggregateShiftReport::new(
            test_epoch(),
            vec![make_measured(WorkloadDimension::ComputeIntensity, 5_000)],
        );
        let r2 = AggregateShiftReport::new(
            test_epoch(),
            vec![make_measured(WorkloadDimension::ComputeIntensity, 200_000)],
        );
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn report_schema_version() {
        let report = AggregateShiftReport::new(test_epoch(), vec![]);
        assert_eq!(report.schema_version, SCHEMA_VERSION);
        assert_eq!(report.bead_id, BEAD_ID);
    }

    #[test]
    fn abstention_insufficient_samples_display() {
        let r = MonitorAbstention::InsufficientSamples {
            available: 10,
            required: 32,
        };
        let s = r.to_string();
        assert!(s.contains("10"));
        assert!(s.contains("32"));
    }

    #[test]
    fn abstention_disabled_by_policy_tag() {
        let r = MonitorAbstention::DisabledByPolicy;
        assert_eq!(r.tag(), "disabled_by_policy");
    }

    #[test]
    fn abstention_empty_reference_tag() {
        let r = MonitorAbstention::EmptyReferenceDistribution;
        assert_eq!(r.tag(), "empty_reference_distribution");
    }

    #[test]
    fn all_dimensions_have_default_configs() {
        for d in WorkloadDimension::ALL {
            let c = MonitorConfig::default_for(*d);
            assert_eq!(c.dimension, *d);
            assert!(c.window_size >= MIN_WINDOW_SIZE);
        }
    }

    #[test]
    fn mmd_result_display() {
        let config = default_config(WorkloadDimension::ComputeIntensity);
        let r = MmdResult::compute(
            WorkloadDimension::ComputeIntensity,
            50_000,
            &config,
            100,
            100,
        );
        let s = format!("{r}");
        assert!(!s.is_empty());
    }
}
