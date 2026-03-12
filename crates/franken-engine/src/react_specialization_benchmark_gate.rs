//! Bead: bd-1lsy.7.9.3 [RGC-609C]
//!
//! React specialization benchmark and parity governance gate.
//!
//! Measures and polices the React specialization lane with benchmark and
//! parity harnesses so React-specific wins become evidence-grade rather
//! than anecdotal.
//!
//! # Design
//!
//! The gate evaluates a benchmark matrix (domains x benchmark classes) and a
//! set of parity findings.  Each cell in the matrix aggregates samples,
//! computes regression evidence, and classifies severity.  The overall
//! verdict combines cell-level verdicts with the parity report to produce
//! an evidence-grade governance action.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-609C]

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version for react specialization benchmark gate artifacts.
pub const SCHEMA_VERSION: &str = "franken-engine.react-specialization-benchmark-gate.v1";

/// Component name for structured logging.
pub const COMPONENT: &str = "react_specialization_benchmark_gate";

/// Bead originating this module.
pub const BEAD_ID: &str = "bd-1lsy.7.9.3";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-609C";

/// Fixed-point unit: 1.0 in millionths.
const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// SpecializationDomain
// ---------------------------------------------------------------------------

/// The React specialization domain under measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpecializationDomain {
    /// Server-side rendering.
    SSR,
    /// Client-side entry / hydration bootstrap.
    ClientEntry,
    /// Hydration reconciliation.
    Hydration,
    /// Static site generation.
    StaticGeneration,
    /// Streaming SSR.
    StreamingSSR,
    /// Isomorphic bridge (shared client/server).
    IsomorphicBridge,
}

impl SpecializationDomain {
    /// All variants in declaration order.
    pub const ALL: &[Self] = &[
        Self::SSR,
        Self::ClientEntry,
        Self::Hydration,
        Self::StaticGeneration,
        Self::StreamingSSR,
        Self::IsomorphicBridge,
    ];

    /// String tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SSR => "ssr",
            Self::ClientEntry => "client_entry",
            Self::Hydration => "hydration",
            Self::StaticGeneration => "static_generation",
            Self::StreamingSSR => "streaming_ssr",
            Self::IsomorphicBridge => "isomorphic_bridge",
        }
    }
}

impl fmt::Display for SpecializationDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BenchmarkClass
// ---------------------------------------------------------------------------

/// Classification of benchmark measurement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkClass {
    /// Throughput (ops/sec or similar).
    Throughput,
    /// Latency (time per op).
    Latency,
    /// Memory overhead.
    MemoryOverhead,
    /// Output code size.
    CodeSize,
    /// Compile time.
    CompileTime,
    /// Cold startup time.
    StartupTime,
}

impl BenchmarkClass {
    /// All variants in declaration order.
    pub const ALL: &[Self] = &[
        Self::Throughput,
        Self::Latency,
        Self::MemoryOverhead,
        Self::CodeSize,
        Self::CompileTime,
        Self::StartupTime,
    ];

    /// String tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Throughput => "throughput",
            Self::Latency => "latency",
            Self::MemoryOverhead => "memory_overhead",
            Self::CodeSize => "code_size",
            Self::CompileTime => "compile_time",
            Self::StartupTime => "startup_time",
        }
    }
}

impl fmt::Display for BenchmarkClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ParityDimension
// ---------------------------------------------------------------------------

/// Dimension along which parity is evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityDimension {
    /// Outputs are byte-identical.
    OutputEquivalence,
    /// Diagnostic messages match.
    DiagnosticParity,
    /// Artifact shapes (files, bundles) match.
    ArtifactShapeParity,
    /// Performance characteristics are comparable.
    PerformanceParity,
    /// Semantic behaviour is equivalent.
    SemanticParity,
    /// Test/coverage scope is equivalent.
    CoverageParity,
}

impl ParityDimension {
    /// All variants.
    pub const ALL: &[Self] = &[
        Self::OutputEquivalence,
        Self::DiagnosticParity,
        Self::ArtifactShapeParity,
        Self::PerformanceParity,
        Self::SemanticParity,
        Self::CoverageParity,
    ];

    /// String tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OutputEquivalence => "output_equivalence",
            Self::DiagnosticParity => "diagnostic_parity",
            Self::ArtifactShapeParity => "artifact_shape_parity",
            Self::PerformanceParity => "performance_parity",
            Self::SemanticParity => "semantic_parity",
            Self::CoverageParity => "coverage_parity",
        }
    }
}

impl fmt::Display for ParityDimension {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RegressionSeverity
// ---------------------------------------------------------------------------

/// Severity classification of a detected regression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegressionSeverity {
    /// No regression detected.
    None,
    /// Minor regression within tolerance.
    Minor,
    /// Moderate regression approaching tolerance.
    Moderate,
    /// Major regression beyond tolerance.
    Major,
    /// Critical regression that must block rollout.
    Critical,
}

impl RegressionSeverity {
    /// String tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Minor => "minor",
            Self::Moderate => "moderate",
            Self::Major => "major",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for RegressionSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// Verdict from a single cell or the overall gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// All benchmarks pass.
    Pass,
    /// Pass with conditions (minor regressions).
    ConditionalPass,
    /// Minor regression detected.
    MinorRegression,
    /// Major regression detected.
    MajorRegression,
    /// Hard fail.
    Fail,
    /// Not enough evidence to decide.
    InsufficientEvidence,
}

impl GateVerdict {
    /// String tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::ConditionalPass => "conditional_pass",
            Self::MinorRegression => "minor_regression",
            Self::MajorRegression => "major_regression",
            Self::Fail => "fail",
            Self::InsufficientEvidence => "insufficient_evidence",
        }
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GovernanceAction
// ---------------------------------------------------------------------------

/// Action recommended by governance evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceAction {
    /// Rollout may proceed.
    AllowRollout,
    /// Rollout with conditions.
    ConditionalRollout,
    /// Block rollout.
    BlockRollout,
    /// Require fresh benchmark data.
    RequireFreshBenchmark,
    /// Downgrade specialization to generic path.
    DowngradeSpecialization,
    /// Require manual review.
    RequireManualReview,
}

impl GovernanceAction {
    /// String tag.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllowRollout => "allow_rollout",
            Self::ConditionalRollout => "conditional_rollout",
            Self::BlockRollout => "block_rollout",
            Self::RequireFreshBenchmark => "require_fresh_benchmark",
            Self::DowngradeSpecialization => "downgrade_specialization",
            Self::RequireManualReview => "require_manual_review",
        }
    }
}

impl fmt::Display for GovernanceAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BenchmarkSample
// ---------------------------------------------------------------------------

/// A single benchmark measurement sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSample {
    /// Specialization domain this sample belongs to.
    pub domain: SpecializationDomain,
    /// Class of benchmark.
    pub benchmark_class: BenchmarkClass,
    /// Baseline measurement in millionths.
    pub baseline_value_millionths: u64,
    /// Candidate measurement in millionths.
    pub candidate_value_millionths: u64,
    /// Number of sub-samples aggregated into this measurement.
    pub sample_count: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Content hash of the workload producing this sample.
    pub content_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// RegressionEvidence
// ---------------------------------------------------------------------------

/// Evidence of a regression detected in a benchmark cell.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegressionEvidence {
    /// Specialization domain.
    pub domain: SpecializationDomain,
    /// Benchmark class.
    pub benchmark_class: BenchmarkClass,
    /// Severity classification.
    pub severity: RegressionSeverity,
    /// Mean baseline value in millionths.
    pub baseline_mean_millionths: u64,
    /// Mean candidate value in millionths.
    pub candidate_mean_millionths: u64,
    /// Absolute delta in millionths (candidate - baseline, 0 if improvement).
    pub delta_millionths: u64,
    /// Relative delta in millionths (delta / baseline * MILLIONTHS).
    pub relative_delta_millionths: u64,
    /// Number of samples aggregated.
    pub sample_count: u64,
    /// Confidence in millionths.
    pub confidence_millionths: u64,
}

// ---------------------------------------------------------------------------
// ParityFinding
// ---------------------------------------------------------------------------

/// A single parity finding along one dimension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityFinding {
    /// Dimension being evaluated.
    pub dimension: ParityDimension,
    /// Domain tested.
    pub domain: SpecializationDomain,
    /// Whether parity was achieved.
    pub is_parity_achieved: bool,
    /// Number of divergences found.
    pub divergence_count: u64,
    /// Total comparisons made.
    pub total_comparisons: u64,
    /// Human-readable detail.
    pub detail: String,
}

// ---------------------------------------------------------------------------
// BenchmarkConfig
// ---------------------------------------------------------------------------

/// Configuration for the benchmark gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkConfig {
    /// Threshold for minor regression (millionths). Default 50_000 = 5%.
    pub minor_regression_threshold_millionths: u64,
    /// Threshold for major regression (millionths). Default 150_000 = 15%.
    pub major_regression_threshold_millionths: u64,
    /// Minimum sample count for statistical validity.
    pub min_sample_count: u64,
    /// Minimum confidence in millionths. Default 950_000 = 95%.
    pub min_confidence_millionths: u64,
    /// Required specialization domains.
    pub required_domains: BTreeSet<SpecializationDomain>,
    /// Required benchmark classes.
    pub required_classes: BTreeSet<BenchmarkClass>,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            minor_regression_threshold_millionths: 50_000,
            major_regression_threshold_millionths: 150_000,
            min_sample_count: 30,
            min_confidence_millionths: 950_000,
            required_domains: BTreeSet::new(),
            required_classes: BTreeSet::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// MatrixCell
// ---------------------------------------------------------------------------

/// A single cell in the benchmark matrix (domain x class).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatrixCell {
    /// Domain for this cell.
    pub domain: SpecializationDomain,
    /// Benchmark class for this cell.
    pub benchmark_class: BenchmarkClass,
    /// Samples aggregated in this cell.
    pub samples: Vec<BenchmarkSample>,
    /// Regression evidence, if any.
    pub regression: Option<RegressionEvidence>,
    /// Verdict for this cell.
    pub verdict: GateVerdict,
}

// ---------------------------------------------------------------------------
// ParityReport
// ---------------------------------------------------------------------------

/// Aggregated parity report over all findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityReport {
    /// Individual findings.
    pub findings: Vec<ParityFinding>,
    /// Whether overall parity was achieved.
    pub overall_parity_achieved: bool,
    /// Coverage in millionths (achieved / total comparisons).
    pub coverage_millionths: u64,
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Content-hashed receipt for a gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component name.
    pub component: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Hash of the input data.
    pub input_hash: ContentHash,
    /// Hash of the verdict.
    pub verdict_hash: ContentHash,
    /// Timestamp in microseconds since an arbitrary epoch.
    pub timestamp_micros: u64,
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

/// Full result of the benchmark gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Individual matrix cells.
    pub cells: Vec<MatrixCell>,
    /// Parity report.
    pub parity_report: ParityReport,
    /// Overall verdict.
    pub overall_verdict: GateVerdict,
    /// Recommended governance action.
    pub governance_action: GovernanceAction,
    /// Count of critical regressions.
    pub critical_regressions: usize,
    /// Count of major regressions.
    pub major_regressions: usize,
    /// Count of minor regressions.
    pub minor_regressions: usize,
    /// Decision receipt.
    pub receipt: DecisionReceipt,
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Classify a relative delta (in millionths) into a regression severity.
#[must_use]
pub fn classify_regression(
    relative_delta_millionths: u64,
    config: &BenchmarkConfig,
) -> RegressionSeverity {
    if relative_delta_millionths == 0 {
        RegressionSeverity::None
    } else if relative_delta_millionths < config.minor_regression_threshold_millionths {
        RegressionSeverity::Minor
    } else if relative_delta_millionths < config.major_regression_threshold_millionths {
        RegressionSeverity::Moderate
    } else if relative_delta_millionths
        < config
            .major_regression_threshold_millionths
            .saturating_mul(2)
    {
        RegressionSeverity::Major
    } else {
        RegressionSeverity::Critical
    }
}

/// Compute regression evidence from a set of benchmark samples.
///
/// Returns `None` if there are no samples or if the candidate does not
/// regress against the baseline.
#[must_use]
pub fn compute_regression(
    samples: &[BenchmarkSample],
    config: &BenchmarkConfig,
) -> Option<RegressionEvidence> {
    if samples.is_empty() {
        return None;
    }

    let total_count: u64 = samples.iter().map(|s| s.sample_count).sum();
    if total_count < config.min_sample_count {
        return None;
    }

    // Compute weighted means.
    let baseline_sum: u128 = samples
        .iter()
        .map(|s| u128::from(s.baseline_value_millionths) * u128::from(s.sample_count))
        .sum();
    let candidate_sum: u128 = samples
        .iter()
        .map(|s| u128::from(s.candidate_value_millionths) * u128::from(s.sample_count))
        .sum();

    let baseline_mean = (baseline_sum / u128::from(total_count)) as u64;
    let candidate_mean = (candidate_sum / u128::from(total_count)) as u64;

    // Regression = candidate worse than baseline (higher value).
    if candidate_mean <= baseline_mean {
        return None;
    }

    let delta = candidate_mean - baseline_mean;
    let relative_delta = if baseline_mean == 0 {
        MILLIONTHS // 100% regression if baseline is zero
    } else {
        (u128::from(delta) * u128::from(MILLIONTHS) / u128::from(baseline_mean)) as u64
    };

    // Simple confidence: ratio of total_count to min_sample_count, capped at
    // 1.0. More samples → higher confidence.
    let confidence = if total_count >= config.min_sample_count.saturating_mul(3) {
        MILLIONTHS
    } else {
        (u128::from(total_count) * u128::from(MILLIONTHS)
            / u128::from(config.min_sample_count.saturating_mul(3))) as u64
    };

    let severity = classify_regression(relative_delta, config);

    let domain = samples[0].domain;
    let benchmark_class = samples[0].benchmark_class;

    Some(RegressionEvidence {
        domain,
        benchmark_class,
        severity,
        baseline_mean_millionths: baseline_mean,
        candidate_mean_millionths: candidate_mean,
        delta_millionths: delta,
        relative_delta_millionths: relative_delta,
        sample_count: total_count,
        confidence_millionths: confidence,
    })
}

/// Evaluate a single matrix cell for a given domain and benchmark class.
#[must_use]
pub fn evaluate_cell(
    domain: SpecializationDomain,
    class: BenchmarkClass,
    samples: &[BenchmarkSample],
    config: &BenchmarkConfig,
) -> MatrixCell {
    let cell_samples: Vec<BenchmarkSample> = samples
        .iter()
        .filter(|s| s.domain == domain && s.benchmark_class == class)
        .cloned()
        .collect();

    if cell_samples.is_empty() {
        return MatrixCell {
            domain,
            benchmark_class: class,
            samples: cell_samples,
            regression: None,
            verdict: GateVerdict::InsufficientEvidence,
        };
    }

    let total_count: u64 = cell_samples.iter().map(|s| s.sample_count).sum();
    if total_count < config.min_sample_count {
        return MatrixCell {
            domain,
            benchmark_class: class,
            samples: cell_samples,
            regression: None,
            verdict: GateVerdict::InsufficientEvidence,
        };
    }

    let regression = compute_regression(&cell_samples, config);

    let verdict = match &regression {
        None => GateVerdict::Pass,
        Some(ev) => match ev.severity {
            RegressionSeverity::None => GateVerdict::Pass,
            RegressionSeverity::Minor => GateVerdict::ConditionalPass,
            RegressionSeverity::Moderate => GateVerdict::MinorRegression,
            RegressionSeverity::Major => GateVerdict::MajorRegression,
            RegressionSeverity::Critical => GateVerdict::Fail,
        },
    };

    MatrixCell {
        domain,
        benchmark_class: class,
        samples: cell_samples,
        regression,
        verdict,
    }
}

/// Build a parity report from individual findings.
#[must_use]
pub fn build_parity_report(findings: &[ParityFinding]) -> ParityReport {
    if findings.is_empty() {
        return ParityReport {
            findings: Vec::new(),
            overall_parity_achieved: true,
            coverage_millionths: 0,
        };
    }

    let overall_parity_achieved = findings.iter().all(|f| f.is_parity_achieved);

    let total_comparisons: u128 = findings
        .iter()
        .map(|f| u128::from(f.total_comparisons))
        .sum();
    let achieved_comparisons: u128 = findings
        .iter()
        .filter(|f| f.is_parity_achieved)
        .map(|f| u128::from(f.total_comparisons))
        .sum();

    let coverage_millionths = (achieved_comparisons * u128::from(MILLIONTHS))
        .checked_div(total_comparisons)
        .unwrap_or(0) as u64;

    ParityReport {
        findings: findings.to_vec(),
        overall_parity_achieved,
        coverage_millionths,
    }
}

/// Derive a governance action from the overall verdict and regression counts.
#[must_use]
pub fn derive_governance_action(
    verdict: &GateVerdict,
    critical_count: usize,
    major_count: usize,
) -> GovernanceAction {
    if critical_count > 0 {
        return GovernanceAction::DowngradeSpecialization;
    }
    match verdict {
        GateVerdict::Pass => GovernanceAction::AllowRollout,
        GateVerdict::ConditionalPass => GovernanceAction::ConditionalRollout,
        GateVerdict::MinorRegression => {
            if major_count > 0 {
                GovernanceAction::RequireManualReview
            } else {
                GovernanceAction::ConditionalRollout
            }
        }
        GateVerdict::MajorRegression => GovernanceAction::BlockRollout,
        GateVerdict::Fail => GovernanceAction::DowngradeSpecialization,
        GateVerdict::InsufficientEvidence => GovernanceAction::RequireFreshBenchmark,
    }
}

/// Compute a decision receipt for a gate evaluation.
#[must_use]
pub fn compute_receipt(
    input_hash: ContentHash,
    verdict: &GateVerdict,
    epoch: SecurityEpoch,
) -> DecisionReceipt {
    let mut h = Sha256::new();
    h.update(SCHEMA_VERSION.as_bytes());
    h.update(COMPONENT.as_bytes());
    h.update(BEAD_ID.as_bytes());
    h.update(POLICY_ID.as_bytes());
    h.update(epoch.as_u64().to_le_bytes());
    h.update(input_hash.as_bytes());
    h.update(verdict.as_str().as_bytes());
    let verdict_hash = ContentHash::compute(&h.finalize());

    // Deterministic timestamp: derive from epoch to maintain determinism.
    let timestamp_micros = epoch.as_u64().saturating_mul(1_000_000);

    DecisionReceipt {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: BEAD_ID.to_string(),
        policy_id: POLICY_ID.to_string(),
        epoch,
        input_hash,
        verdict_hash,
        timestamp_micros,
    }
}

/// Hash a collection of benchmark samples for receipt purposes.
fn hash_samples_and_findings(
    samples: &[BenchmarkSample],
    findings: &[ParityFinding],
) -> ContentHash {
    let mut h = Sha256::new();
    h.update(COMPONENT.as_bytes());
    h.update((samples.len() as u64).to_le_bytes());
    for s in samples {
        h.update(s.domain.as_str().as_bytes());
        h.update(s.benchmark_class.as_str().as_bytes());
        h.update(s.baseline_value_millionths.to_le_bytes());
        h.update(s.candidate_value_millionths.to_le_bytes());
        h.update(s.sample_count.to_le_bytes());
    }
    h.update((findings.len() as u64).to_le_bytes());
    for f in findings {
        h.update(f.dimension.as_str().as_bytes());
        h.update(f.domain.as_str().as_bytes());
        h.update(if f.is_parity_achieved { &[1u8] } else { &[0u8] });
        h.update(f.divergence_count.to_le_bytes());
        h.update(f.total_comparisons.to_le_bytes());
    }
    ContentHash::compute(&h.finalize())
}

/// Main entry point: evaluate the full benchmark matrix.
///
/// Aggregates benchmark samples into a domain x class matrix, computes
/// regression evidence for each cell, builds the parity report, and
/// produces an overall verdict with governance action and receipt.
#[must_use]
pub fn evaluate_benchmark_matrix(
    config: &BenchmarkConfig,
    samples: &[BenchmarkSample],
    parity_findings: &[ParityFinding],
    epoch: SecurityEpoch,
) -> GateResult {
    // Collect distinct domains and classes from samples.
    let domains: BTreeSet<SpecializationDomain> = samples.iter().map(|s| s.domain).collect();
    let classes: BTreeSet<BenchmarkClass> = samples.iter().map(|s| s.benchmark_class).collect();

    // Union with required domains/classes.
    let all_domains: BTreeSet<SpecializationDomain> =
        domains.union(&config.required_domains).copied().collect();
    let all_classes: BTreeSet<BenchmarkClass> =
        classes.union(&config.required_classes).copied().collect();

    // Evaluate each cell.
    let mut cells = Vec::new();
    for &domain in &all_domains {
        for &class in &all_classes {
            cells.push(evaluate_cell(domain, class, samples, config));
        }
    }

    // Build parity report.
    let parity_report = build_parity_report(parity_findings);

    // Count regressions.
    let mut critical_regressions = 0usize;
    let mut major_regressions = 0usize;
    let mut minor_regressions = 0usize;

    for cell in &cells {
        if let Some(ref ev) = cell.regression {
            match ev.severity {
                RegressionSeverity::Critical => critical_regressions += 1,
                RegressionSeverity::Major => major_regressions += 1,
                RegressionSeverity::Moderate => minor_regressions += 1,
                RegressionSeverity::Minor => minor_regressions += 1,
                RegressionSeverity::None => {}
            }
        }
    }

    // Derive overall verdict.
    let overall_verdict = if cells.is_empty() {
        GateVerdict::InsufficientEvidence
    } else if critical_regressions > 0 {
        GateVerdict::Fail
    } else if major_regressions > 0 {
        GateVerdict::MajorRegression
    } else if !parity_report.overall_parity_achieved {
        GateVerdict::MinorRegression
    } else if minor_regressions > 0 {
        GateVerdict::ConditionalPass
    } else {
        // Check if all cells have sufficient evidence.
        let all_have_evidence = cells
            .iter()
            .all(|c| c.verdict != GateVerdict::InsufficientEvidence);
        if all_have_evidence {
            GateVerdict::Pass
        } else {
            GateVerdict::InsufficientEvidence
        }
    };

    let governance_action =
        derive_governance_action(&overall_verdict, critical_regressions, major_regressions);

    let input_hash = hash_samples_and_findings(samples, parity_findings);
    let receipt = compute_receipt(input_hash, &overall_verdict, epoch);

    GateResult {
        cells,
        parity_report,
        overall_verdict,
        governance_action,
        critical_regressions,
        major_regressions,
        minor_regressions,
        receipt,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn sample(
        domain: SpecializationDomain,
        class: BenchmarkClass,
        baseline: u64,
        candidate: u64,
        count: u64,
    ) -> BenchmarkSample {
        BenchmarkSample {
            domain,
            benchmark_class: class,
            baseline_value_millionths: baseline,
            candidate_value_millionths: candidate,
            sample_count: count,
            epoch: epoch(1),
            content_hash: ContentHash::compute(b"test-workload"),
        }
    }

    fn parity_finding(
        dim: ParityDimension,
        domain: SpecializationDomain,
        achieved: bool,
        divergences: u64,
        total: u64,
    ) -> ParityFinding {
        ParityFinding {
            dimension: dim,
            domain,
            is_parity_achieved: achieved,
            divergence_count: divergences,
            total_comparisons: total,
            detail: if achieved {
                "parity achieved".into()
            } else {
                format!("{divergences} divergences found")
            },
        }
    }

    // -- Constants --

    #[test]
    fn test_schema_version() {
        assert_eq!(
            SCHEMA_VERSION,
            "franken-engine.react-specialization-benchmark-gate.v1"
        );
    }

    #[test]
    fn test_component_name() {
        assert_eq!(COMPONENT, "react_specialization_benchmark_gate");
    }

    #[test]
    fn test_bead_and_policy() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.9.3");
        assert_eq!(POLICY_ID, "RGC-609C");
    }

    #[test]
    fn test_millionths_constant() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -- Enum Display / as_str --

    #[test]
    fn test_specialization_domain_as_str() {
        assert_eq!(SpecializationDomain::SSR.as_str(), "ssr");
        assert_eq!(SpecializationDomain::ClientEntry.as_str(), "client_entry");
        assert_eq!(SpecializationDomain::Hydration.as_str(), "hydration");
        assert_eq!(
            SpecializationDomain::StaticGeneration.as_str(),
            "static_generation"
        );
        assert_eq!(SpecializationDomain::StreamingSSR.as_str(), "streaming_ssr");
        assert_eq!(
            SpecializationDomain::IsomorphicBridge.as_str(),
            "isomorphic_bridge"
        );
    }

    #[test]
    fn test_specialization_domain_display() {
        assert_eq!(format!("{}", SpecializationDomain::SSR), "ssr");
        assert_eq!(
            format!("{}", SpecializationDomain::IsomorphicBridge),
            "isomorphic_bridge"
        );
    }

    #[test]
    fn test_specialization_domain_all_count() {
        assert_eq!(SpecializationDomain::ALL.len(), 6);
    }

    #[test]
    fn test_benchmark_class_as_str() {
        assert_eq!(BenchmarkClass::Throughput.as_str(), "throughput");
        assert_eq!(BenchmarkClass::Latency.as_str(), "latency");
        assert_eq!(BenchmarkClass::MemoryOverhead.as_str(), "memory_overhead");
        assert_eq!(BenchmarkClass::CodeSize.as_str(), "code_size");
        assert_eq!(BenchmarkClass::CompileTime.as_str(), "compile_time");
        assert_eq!(BenchmarkClass::StartupTime.as_str(), "startup_time");
    }

    #[test]
    fn test_benchmark_class_display() {
        assert_eq!(format!("{}", BenchmarkClass::StartupTime), "startup_time");
    }

    #[test]
    fn test_parity_dimension_as_str() {
        assert_eq!(
            ParityDimension::OutputEquivalence.as_str(),
            "output_equivalence"
        );
        assert_eq!(
            ParityDimension::DiagnosticParity.as_str(),
            "diagnostic_parity"
        );
        assert_eq!(ParityDimension::CoverageParity.as_str(), "coverage_parity");
    }

    #[test]
    fn test_parity_dimension_all_count() {
        assert_eq!(ParityDimension::ALL.len(), 6);
    }

    #[test]
    fn test_regression_severity_as_str() {
        assert_eq!(RegressionSeverity::None.as_str(), "none");
        assert_eq!(RegressionSeverity::Minor.as_str(), "minor");
        assert_eq!(RegressionSeverity::Moderate.as_str(), "moderate");
        assert_eq!(RegressionSeverity::Major.as_str(), "major");
        assert_eq!(RegressionSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn test_gate_verdict_as_str() {
        assert_eq!(GateVerdict::Pass.as_str(), "pass");
        assert_eq!(GateVerdict::Fail.as_str(), "fail");
        assert_eq!(
            GateVerdict::InsufficientEvidence.as_str(),
            "insufficient_evidence"
        );
    }

    #[test]
    fn test_governance_action_as_str() {
        assert_eq!(GovernanceAction::AllowRollout.as_str(), "allow_rollout");
        assert_eq!(GovernanceAction::BlockRollout.as_str(), "block_rollout");
        assert_eq!(
            GovernanceAction::DowngradeSpecialization.as_str(),
            "downgrade_specialization"
        );
    }

    // -- Config defaults --

    #[test]
    fn test_config_defaults() {
        let cfg = BenchmarkConfig::default();
        assert_eq!(cfg.minor_regression_threshold_millionths, 50_000);
        assert_eq!(cfg.major_regression_threshold_millionths, 150_000);
        assert_eq!(cfg.min_sample_count, 30);
        assert_eq!(cfg.min_confidence_millionths, 950_000);
        assert!(cfg.required_domains.is_empty());
        assert!(cfg.required_classes.is_empty());
    }

    // -- classify_regression --

    #[test]
    fn test_classify_zero_delta_is_none() {
        let cfg = BenchmarkConfig::default();
        assert_eq!(classify_regression(0, &cfg), RegressionSeverity::None);
    }

    #[test]
    fn test_classify_below_minor_threshold() {
        let cfg = BenchmarkConfig::default();
        assert_eq!(classify_regression(49_999, &cfg), RegressionSeverity::Minor);
    }

    #[test]
    fn test_classify_at_minor_threshold_is_moderate() {
        let cfg = BenchmarkConfig::default();
        assert_eq!(
            classify_regression(50_000, &cfg),
            RegressionSeverity::Moderate
        );
    }

    #[test]
    fn test_classify_below_major_threshold() {
        let cfg = BenchmarkConfig::default();
        assert_eq!(
            classify_regression(149_999, &cfg),
            RegressionSeverity::Moderate
        );
    }

    #[test]
    fn test_classify_at_major_threshold_is_major() {
        let cfg = BenchmarkConfig::default();
        assert_eq!(
            classify_regression(150_000, &cfg),
            RegressionSeverity::Major
        );
    }

    #[test]
    fn test_classify_at_critical_boundary() {
        let cfg = BenchmarkConfig::default();
        // critical = >= 2 * major threshold = 300_000
        assert_eq!(
            classify_regression(299_999, &cfg),
            RegressionSeverity::Major
        );
        assert_eq!(
            classify_regression(300_000, &cfg),
            RegressionSeverity::Critical
        );
    }

    #[test]
    fn test_classify_well_above_critical() {
        let cfg = BenchmarkConfig::default();
        assert_eq!(
            classify_regression(1_000_000, &cfg),
            RegressionSeverity::Critical
        );
    }

    // -- compute_regression --

    #[test]
    fn test_compute_regression_empty_samples() {
        let cfg = BenchmarkConfig::default();
        assert!(compute_regression(&[], &cfg).is_none());
    }

    #[test]
    fn test_compute_regression_insufficient_samples() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_100_000,
            5, // below min_sample_count of 30
        )];
        assert!(compute_regression(&samples, &cfg).is_none());
    }

    #[test]
    fn test_compute_regression_no_regression_when_candidate_equal() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_000_000,
            30,
        )];
        assert!(compute_regression(&samples, &cfg).is_none());
    }

    #[test]
    fn test_compute_regression_no_regression_when_improvement() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            900_000, // improvement
            30,
        )];
        assert!(compute_regression(&samples, &cfg).is_none());
    }

    #[test]
    fn test_compute_regression_detects_regression() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_060_000, // 6% regression
            30,
        )];
        let ev = compute_regression(&samples, &cfg).unwrap();
        assert_eq!(ev.domain, SpecializationDomain::SSR);
        assert_eq!(ev.benchmark_class, BenchmarkClass::Latency);
        assert_eq!(ev.baseline_mean_millionths, 1_000_000);
        assert_eq!(ev.candidate_mean_millionths, 1_060_000);
        assert_eq!(ev.delta_millionths, 60_000);
        assert_eq!(ev.relative_delta_millionths, 60_000); // 6%
        assert_eq!(ev.severity, RegressionSeverity::Moderate);
    }

    #[test]
    fn test_compute_regression_weighted_mean() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![
            sample(
                SpecializationDomain::SSR,
                BenchmarkClass::Latency,
                1_000_000,
                1_100_000,
                20,
            ),
            sample(
                SpecializationDomain::SSR,
                BenchmarkClass::Latency,
                1_000_000,
                1_200_000,
                10,
            ),
        ];
        let ev = compute_regression(&samples, &cfg).unwrap();
        // weighted mean candidate = (1_100_000*20 + 1_200_000*10) / 30 = 1_133_333
        assert_eq!(ev.candidate_mean_millionths, 1_133_333);
        assert_eq!(ev.sample_count, 30);
    }

    #[test]
    fn test_compute_regression_zero_baseline() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Throughput,
            0,
            100_000,
            30,
        )];
        let ev = compute_regression(&samples, &cfg).unwrap();
        assert_eq!(ev.relative_delta_millionths, MILLIONTHS);
    }

    // -- evaluate_cell --

    #[test]
    fn test_evaluate_cell_no_samples() {
        let cfg = BenchmarkConfig::default();
        let cell = evaluate_cell(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            &[],
            &cfg,
        );
        assert_eq!(cell.verdict, GateVerdict::InsufficientEvidence);
        assert!(cell.regression.is_none());
        assert!(cell.samples.is_empty());
    }

    #[test]
    fn test_evaluate_cell_pass() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_000_000,
            30,
        )];
        let cell = evaluate_cell(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            &samples,
            &cfg,
        );
        assert_eq!(cell.verdict, GateVerdict::Pass);
        assert!(cell.regression.is_none());
    }

    #[test]
    fn test_evaluate_cell_conditional_pass_minor() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::Hydration,
            BenchmarkClass::CodeSize,
            1_000_000,
            1_020_000, // 2% = minor
            30,
        )];
        let cell = evaluate_cell(
            SpecializationDomain::Hydration,
            BenchmarkClass::CodeSize,
            &samples,
            &cfg,
        );
        assert_eq!(cell.verdict, GateVerdict::ConditionalPass);
    }

    #[test]
    fn test_evaluate_cell_major_regression() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_200_000, // 20% = major (>= 150_000, < 300_000)
            30,
        )];
        let cell = evaluate_cell(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            &samples,
            &cfg,
        );
        assert_eq!(cell.verdict, GateVerdict::MajorRegression);
    }

    #[test]
    fn test_evaluate_cell_fail_critical() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::StartupTime,
            1_000_000,
            1_500_000, // 50% = critical (>= 300_000)
            30,
        )];
        let cell = evaluate_cell(
            SpecializationDomain::SSR,
            BenchmarkClass::StartupTime,
            &samples,
            &cfg,
        );
        assert_eq!(cell.verdict, GateVerdict::Fail);
    }

    #[test]
    fn test_evaluate_cell_filters_by_domain_and_class() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![
            sample(
                SpecializationDomain::SSR,
                BenchmarkClass::Latency,
                1_000_000,
                1_000_000,
                30,
            ),
            sample(
                SpecializationDomain::Hydration,
                BenchmarkClass::Throughput,
                1_000_000,
                2_000_000,
                30,
            ),
        ];
        // Only SSR/Latency should be included
        let cell = evaluate_cell(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            &samples,
            &cfg,
        );
        assert_eq!(cell.samples.len(), 1);
        assert_eq!(cell.verdict, GateVerdict::Pass);
    }

    // -- build_parity_report --

    #[test]
    fn test_parity_report_empty() {
        let report = build_parity_report(&[]);
        assert!(report.overall_parity_achieved);
        assert_eq!(report.coverage_millionths, 0);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn test_parity_report_all_passing() {
        let findings = vec![
            parity_finding(
                ParityDimension::OutputEquivalence,
                SpecializationDomain::SSR,
                true,
                0,
                100,
            ),
            parity_finding(
                ParityDimension::SemanticParity,
                SpecializationDomain::SSR,
                true,
                0,
                200,
            ),
        ];
        let report = build_parity_report(&findings);
        assert!(report.overall_parity_achieved);
        assert_eq!(report.coverage_millionths, MILLIONTHS);
    }

    #[test]
    fn test_parity_report_with_divergences() {
        let findings = vec![
            parity_finding(
                ParityDimension::OutputEquivalence,
                SpecializationDomain::SSR,
                true,
                0,
                100,
            ),
            parity_finding(
                ParityDimension::DiagnosticParity,
                SpecializationDomain::SSR,
                false,
                5,
                100,
            ),
        ];
        let report = build_parity_report(&findings);
        assert!(!report.overall_parity_achieved);
        // coverage = 100 / 200 = 500_000
        assert_eq!(report.coverage_millionths, 500_000);
    }

    #[test]
    fn test_parity_report_partial_coverage() {
        let findings = vec![
            parity_finding(
                ParityDimension::OutputEquivalence,
                SpecializationDomain::SSR,
                true,
                0,
                300,
            ),
            parity_finding(
                ParityDimension::SemanticParity,
                SpecializationDomain::Hydration,
                false,
                10,
                100,
            ),
        ];
        let report = build_parity_report(&findings);
        assert!(!report.overall_parity_achieved);
        // coverage = 300 / 400 = 750_000
        assert_eq!(report.coverage_millionths, 750_000);
    }

    // -- derive_governance_action --

    #[test]
    fn test_governance_pass() {
        assert_eq!(
            derive_governance_action(&GateVerdict::Pass, 0, 0),
            GovernanceAction::AllowRollout
        );
    }

    #[test]
    fn test_governance_conditional_pass() {
        assert_eq!(
            derive_governance_action(&GateVerdict::ConditionalPass, 0, 0),
            GovernanceAction::ConditionalRollout
        );
    }

    #[test]
    fn test_governance_minor_regression_no_major() {
        assert_eq!(
            derive_governance_action(&GateVerdict::MinorRegression, 0, 0),
            GovernanceAction::ConditionalRollout
        );
    }

    #[test]
    fn test_governance_minor_regression_with_major() {
        assert_eq!(
            derive_governance_action(&GateVerdict::MinorRegression, 0, 1),
            GovernanceAction::RequireManualReview
        );
    }

    #[test]
    fn test_governance_major_regression() {
        assert_eq!(
            derive_governance_action(&GateVerdict::MajorRegression, 0, 1),
            GovernanceAction::BlockRollout
        );
    }

    #[test]
    fn test_governance_fail() {
        assert_eq!(
            derive_governance_action(&GateVerdict::Fail, 0, 0),
            GovernanceAction::DowngradeSpecialization
        );
    }

    #[test]
    fn test_governance_insufficient_evidence() {
        assert_eq!(
            derive_governance_action(&GateVerdict::InsufficientEvidence, 0, 0),
            GovernanceAction::RequireFreshBenchmark
        );
    }

    #[test]
    fn test_governance_critical_overrides_verdict() {
        // Critical count > 0 always yields DowngradeSpecialization.
        assert_eq!(
            derive_governance_action(&GateVerdict::ConditionalPass, 1, 0),
            GovernanceAction::DowngradeSpecialization
        );
    }

    // -- compute_receipt --

    #[test]
    fn test_receipt_determinism() {
        let hash = ContentHash::compute(b"test-input");
        let r1 = compute_receipt(hash, &GateVerdict::Pass, epoch(1));
        let r2 = compute_receipt(hash, &GateVerdict::Pass, epoch(1));
        assert_eq!(r1.verdict_hash, r2.verdict_hash);
        assert_eq!(r1.schema_version, SCHEMA_VERSION);
        assert_eq!(r1.component, COMPONENT);
        assert_eq!(r1.bead_id, BEAD_ID);
        assert_eq!(r1.policy_id, POLICY_ID);
    }

    #[test]
    fn test_receipt_different_verdicts_differ() {
        let hash = ContentHash::compute(b"test-input");
        let r1 = compute_receipt(hash, &GateVerdict::Pass, epoch(1));
        let r2 = compute_receipt(hash, &GateVerdict::Fail, epoch(1));
        assert_ne!(r1.verdict_hash, r2.verdict_hash);
    }

    #[test]
    fn test_receipt_different_epochs_differ() {
        let hash = ContentHash::compute(b"test-input");
        let r1 = compute_receipt(hash, &GateVerdict::Pass, epoch(1));
        let r2 = compute_receipt(hash, &GateVerdict::Pass, epoch(2));
        assert_ne!(r1.verdict_hash, r2.verdict_hash);
    }

    #[test]
    fn test_receipt_timestamp_from_epoch() {
        let r = compute_receipt(ContentHash::compute(b"x"), &GateVerdict::Pass, epoch(42));
        assert_eq!(r.timestamp_micros, 42_000_000);
    }

    // -- evaluate_benchmark_matrix (integration) --

    #[test]
    fn test_matrix_empty_samples() {
        let cfg = BenchmarkConfig::default();
        let result = evaluate_benchmark_matrix(&cfg, &[], &[], epoch(1));
        // No cells because no domains/classes and no required.
        assert!(result.cells.is_empty());
        assert_eq!(result.overall_verdict, GateVerdict::InsufficientEvidence);
        assert_eq!(
            result.governance_action,
            GovernanceAction::RequireFreshBenchmark
        );
    }

    #[test]
    fn test_matrix_all_pass() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_000_000,
            30,
        )];
        let findings = vec![parity_finding(
            ParityDimension::OutputEquivalence,
            SpecializationDomain::SSR,
            true,
            0,
            100,
        )];
        let result = evaluate_benchmark_matrix(&cfg, &samples, &findings, epoch(1));
        assert_eq!(result.overall_verdict, GateVerdict::Pass);
        assert_eq!(result.governance_action, GovernanceAction::AllowRollout);
        assert_eq!(result.critical_regressions, 0);
        assert_eq!(result.major_regressions, 0);
        assert_eq!(result.minor_regressions, 0);
    }

    #[test]
    fn test_matrix_minor_regression() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_030_000, // 3% = minor
            30,
        )];
        let findings = vec![parity_finding(
            ParityDimension::OutputEquivalence,
            SpecializationDomain::SSR,
            true,
            0,
            100,
        )];
        let result = evaluate_benchmark_matrix(&cfg, &samples, &findings, epoch(1));
        assert_eq!(result.overall_verdict, GateVerdict::ConditionalPass);
        assert_eq!(result.minor_regressions, 1);
    }

    #[test]
    fn test_matrix_major_regression_blocks() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_200_000, // 20% = major
            30,
        )];
        let result = evaluate_benchmark_matrix(&cfg, &samples, &[], epoch(1));
        assert_eq!(result.overall_verdict, GateVerdict::MajorRegression);
        assert_eq!(result.governance_action, GovernanceAction::BlockRollout);
        assert_eq!(result.major_regressions, 1);
    }

    #[test]
    fn test_matrix_critical_regression_downgrades() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_500_000, // 50% = critical
            30,
        )];
        let result = evaluate_benchmark_matrix(&cfg, &samples, &[], epoch(1));
        assert_eq!(result.overall_verdict, GateVerdict::Fail);
        assert_eq!(
            result.governance_action,
            GovernanceAction::DowngradeSpecialization
        );
        assert_eq!(result.critical_regressions, 1);
    }

    #[test]
    fn test_matrix_parity_failure_triggers_minor_regression() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_000_000, // no perf regression
            30,
        )];
        let findings = vec![parity_finding(
            ParityDimension::OutputEquivalence,
            SpecializationDomain::SSR,
            false,
            3,
            100,
        )];
        let result = evaluate_benchmark_matrix(&cfg, &samples, &findings, epoch(1));
        assert_eq!(result.overall_verdict, GateVerdict::MinorRegression);
        assert!(!result.parity_report.overall_parity_achieved);
    }

    #[test]
    fn test_matrix_multiple_domains() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![
            sample(
                SpecializationDomain::SSR,
                BenchmarkClass::Latency,
                1_000_000,
                1_000_000,
                30,
            ),
            sample(
                SpecializationDomain::Hydration,
                BenchmarkClass::Latency,
                1_000_000,
                1_000_000,
                30,
            ),
            sample(
                SpecializationDomain::ClientEntry,
                BenchmarkClass::Throughput,
                1_000_000,
                1_000_000,
                30,
            ),
        ];
        let result = evaluate_benchmark_matrix(&cfg, &samples, &[], epoch(1));
        // 3 distinct (domain, class) pairs = 3 cells (since no cross-product
        // is needed — we only evaluate cells for domains that appear)
        // Actually: domains = {SSR, Hydration, ClientEntry}, classes = {Latency, Throughput}
        // So 3 * 2 = 6 cells, but some have no samples -> InsufficientEvidence
        // This means not all have evidence -> InsufficientEvidence overall
        assert!(result.cells.len() >= 3);
    }

    #[test]
    fn test_matrix_required_domains_create_cells() {
        let mut cfg = BenchmarkConfig::default();
        cfg.required_domains
            .insert(SpecializationDomain::StreamingSSR);
        cfg.required_classes.insert(BenchmarkClass::CompileTime);
        let result = evaluate_benchmark_matrix(&cfg, &[], &[], epoch(1));
        assert_eq!(result.cells.len(), 1); // StreamingSSR x CompileTime
        assert_eq!(result.cells[0].verdict, GateVerdict::InsufficientEvidence);
    }

    #[test]
    fn test_matrix_improvement_is_pass() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            800_000, // 20% improvement
            30,
        )];
        let result = evaluate_benchmark_matrix(&cfg, &samples, &[], epoch(1));
        assert_eq!(result.cells[0].verdict, GateVerdict::Pass);
        assert!(result.cells[0].regression.is_none());
    }

    // -- BenchmarkSample construction --

    #[test]
    fn test_benchmark_sample_fields() {
        let s = sample(
            SpecializationDomain::Hydration,
            BenchmarkClass::MemoryOverhead,
            500_000,
            600_000,
            42,
        );
        assert_eq!(s.domain, SpecializationDomain::Hydration);
        assert_eq!(s.benchmark_class, BenchmarkClass::MemoryOverhead);
        assert_eq!(s.baseline_value_millionths, 500_000);
        assert_eq!(s.candidate_value_millionths, 600_000);
        assert_eq!(s.sample_count, 42);
    }

    // -- Edge cases --

    #[test]
    fn test_exactly_at_threshold_minor() {
        let cfg = BenchmarkConfig::default();
        // relative_delta = exactly 50_000 → Moderate (at threshold)
        assert_eq!(
            classify_regression(50_000, &cfg),
            RegressionSeverity::Moderate
        );
    }

    #[test]
    fn test_one_below_minor_threshold() {
        let cfg = BenchmarkConfig::default();
        assert_eq!(classify_regression(49_999, &cfg), RegressionSeverity::Minor);
    }

    #[test]
    fn test_large_sample_count_high_confidence() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_010_000,
            100, // >> 3 * 30 = 90
        )];
        let ev = compute_regression(&samples, &cfg).unwrap();
        assert_eq!(ev.confidence_millionths, MILLIONTHS);
    }

    #[test]
    fn test_moderate_sample_count_partial_confidence() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_010_000,
            45, // < 3 * 30 = 90
        )];
        let ev = compute_regression(&samples, &cfg).unwrap();
        // confidence = 45 * 1_000_000 / 90 = 500_000
        assert_eq!(ev.confidence_millionths, 500_000);
    }

    #[test]
    fn test_cell_insufficient_samples() {
        let cfg = BenchmarkConfig::default();
        let samples = vec![sample(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            1_000_000,
            1_100_000,
            5, // way below min 30
        )];
        let cell = evaluate_cell(
            SpecializationDomain::SSR,
            BenchmarkClass::Latency,
            &samples,
            &cfg,
        );
        assert_eq!(cell.verdict, GateVerdict::InsufficientEvidence);
    }

    #[test]
    fn test_regression_severity_display() {
        assert_eq!(format!("{}", RegressionSeverity::Critical), "critical");
    }

    #[test]
    fn test_governance_action_display() {
        assert_eq!(
            format!("{}", GovernanceAction::RequireManualReview),
            "require_manual_review"
        );
    }
}
