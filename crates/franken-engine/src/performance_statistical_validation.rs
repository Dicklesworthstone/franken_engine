//! Deterministic statistical validation pipeline for RGC-702 (`bd-1lsy.8.2`).
//!
//! The pipeline enforces variance/confidence guardrails for benchmark evidence so
//! promotion decisions fail closed when data is noisy or statistically weak.

use std::cmp::Ordering;
use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT: &str = "performance_statistical_validation";

const MILLION: u32 = 1_000_000;
const SQRT_2: f64 = std::f64::consts::SQRT_2;

const ERROR_INTEGRITY_MISSING_METADATA: &str = "FE-RGC-702-INTEGRITY-0001";
const ERROR_SAMPLE_INSUFFICIENT: &str = "FE-RGC-702-SAMPLE-0002";
const ERROR_VARIANCE_QUARANTINE: &str = "FE-RGC-702-VARIANCE-0003";
const ERROR_REGRESSION_FAIL: &str = "FE-RGC-702-REGRESSION-0004";
const ERROR_CONFIDENCE_QUARANTINE: &str = "FE-RGC-702-CONFIDENCE-0005";
const WARN_REGRESSION: &str = "WARN-RGC-702-REGRESSION-0001";
const ERROR_SERIALIZATION: &str = "FE-RGC-702-SERIALIZATION-0006";
const ERROR_REPORT_WRITE: &str = "FE-RGC-702-REPORT-0007";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatisticalValidationInput {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub workloads: Vec<WorkloadSamples>,
}

impl StatisticalValidationInput {
    pub fn new(
        trace_id: impl Into<String>,
        decision_id: impl Into<String>,
        policy_id: impl Into<String>,
        workloads: Vec<WorkloadSamples>,
    ) -> Self {
        Self {
            trace_id: trace_id.into(),
            decision_id: decision_id.into(),
            policy_id: policy_id.into(),
            workloads,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadSamples {
    pub workload_id: String,
    pub scenario_id: String,
    pub benchmark_metadata_hash: String,
    pub baseline_samples_ns: Vec<u64>,
    pub candidate_samples_ns: Vec<u64>,
}

impl WorkloadSamples {
    pub fn new(
        workload_id: impl Into<String>,
        scenario_id: impl Into<String>,
        benchmark_metadata_hash: impl Into<String>,
        baseline_samples_ns: Vec<u64>,
        candidate_samples_ns: Vec<u64>,
    ) -> Self {
        Self {
            workload_id: workload_id.into(),
            scenario_id: scenario_id.into(),
            benchmark_metadata_hash: benchmark_metadata_hash.into(),
            baseline_samples_ns,
            candidate_samples_ns,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatisticalValidationPolicy {
    pub warmup_drop_samples: usize,
    pub min_samples_after_filter: usize,
    pub outlier_policy: OutlierPolicy,
    pub thresholds: StatisticalThresholds,
}

impl Default for StatisticalValidationPolicy {
    fn default() -> Self {
        Self {
            warmup_drop_samples: 1,
            min_samples_after_filter: 8,
            outlier_policy: OutlierPolicy::default(),
            thresholds: StatisticalThresholds::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutlierPolicy {
    /// MAD multiplier in millionths (3.5 => 3_500_000).
    pub mad_multiplier_millionths: u32,
    /// Minimum retained samples after outlier filtering.
    pub min_retained_samples: usize,
}

impl Default for OutlierPolicy {
    fn default() -> Self {
        Self {
            mad_multiplier_millionths: 3_500_000,
            min_retained_samples: 8,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatisticalThresholds {
    /// Maximum coefficient of variation before automatic quarantine.
    pub max_cv_millionths: u32,
    /// Warning regression threshold in millionths of baseline mean.
    pub warning_regression_millionths: u32,
    /// Fail regression threshold in millionths of baseline mean.
    pub fail_regression_millionths: u32,
    /// Maximum acceptable two-sided p-value (millionths).
    pub max_p_value_millionths: u32,
    /// Minimum absolute effect size to enforce significance/quarantine logic.
    pub min_effect_size_millionths: u32,
    /// Confidence level for mean-delta confidence interval (millionths).
    pub confidence_level_millionths: u32,
}

impl Default for StatisticalThresholds {
    fn default() -> Self {
        Self {
            max_cv_millionths: 120_000,
            warning_regression_millionths: 10_000,
            fail_regression_millionths: 25_000,
            max_p_value_millionths: 50_000,
            min_effect_size_millionths: 5_000,
            confidence_level_millionths: 950_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadOutcome {
    Pass,
    Warn,
    Fail,
    Quarantine,
}

impl WorkloadOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Quarantine => "quarantine",
        }
    }
}

impl fmt::Display for WorkloadOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCode {
    MissingBenchmarkMetadata,
    InsufficientSamples,
    VarianceQuarantine,
    ConfidenceQuarantine,
    RegressionFail,
    RegressionWarn,
}

impl FindingCode {
    pub fn stable_code(self) -> &'static str {
        match self {
            Self::MissingBenchmarkMetadata => ERROR_INTEGRITY_MISSING_METADATA,
            Self::InsufficientSamples => ERROR_SAMPLE_INSUFFICIENT,
            Self::VarianceQuarantine => ERROR_VARIANCE_QUARANTINE,
            Self::ConfidenceQuarantine => ERROR_CONFIDENCE_QUARANTINE,
            Self::RegressionFail => ERROR_REGRESSION_FAIL,
            Self::RegressionWarn => WARN_REGRESSION,
        }
    }
}

impl fmt::Display for FindingCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.stable_code())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationFinding {
    pub code: FindingCode,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SampleStatsNs {
    pub sample_count: usize,
    pub mean_ns: u64,
    pub stddev_ns: u64,
    pub cv_millionths: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidenceIntervalNs {
    pub lower_ns: i64,
    pub upper_ns: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutlierSummary {
    pub baseline_removed: usize,
    pub candidate_removed: usize,
    pub method: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadValidationVerdict {
    pub workload_id: String,
    pub scenario_id: String,
    pub outcome: WorkloadOutcome,
    pub p_value_millionths: u32,
    pub effect_size_millionths: i64,
    pub confidence_interval_mean_delta_ns: ConfidenceIntervalNs,
    pub baseline: SampleStatsNs,
    pub candidate: SampleStatsNs,
    pub outliers: OutlierSummary,
    pub findings: Vec<ValidationFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatisticalValidationLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub scenario_id: String,
    pub workload_id: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatisticalValidationReport {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub promote_allowed: bool,
    pub failed_workloads: Vec<String>,
    pub quarantined_workloads: Vec<String>,
    pub warned_workloads: Vec<String>,
    pub verdicts: Vec<WorkloadValidationVerdict>,
    pub logs: Vec<StatisticalValidationLogEvent>,
}

#[derive(Debug, Error)]
pub enum StatisticalValidationError {
    #[error("serialization failed: {0}")]
    Serialization(String),
    #[error("report write failed for `{path}`: {source}")]
    ReportWrite {
        path: String,
        #[source]
        source: std::io::Error,
    },
}

impl StatisticalValidationError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::Serialization(_) => ERROR_SERIALIZATION,
            Self::ReportWrite { .. } => ERROR_REPORT_WRITE,
        }
    }
}

pub fn evaluate_statistical_validation(
    input: &StatisticalValidationInput,
    policy: &StatisticalValidationPolicy,
) -> StatisticalValidationReport {
    let mut workloads = input.workloads.clone();
    workloads.sort_by(|left, right| left.workload_id.cmp(&right.workload_id));

    let mut verdicts = Vec::with_capacity(workloads.len());
    let mut logs = Vec::new();
    let mut failed = BTreeSet::new();
    let mut quarantined = BTreeSet::new();
    let mut warned = BTreeSet::new();

    for workload in &workloads {
        let mut findings = Vec::new();
        let workload_id = workload.workload_id.clone();
        let scenario_id = workload.scenario_id.clone();

        let baseline_trimmed =
            trim_warmup(&workload.baseline_samples_ns, policy.warmup_drop_samples);
        let candidate_trimmed =
            trim_warmup(&workload.candidate_samples_ns, policy.warmup_drop_samples);

        let baseline_filtered = apply_mad_filter(&baseline_trimmed, &policy.outlier_policy);
        let candidate_filtered = apply_mad_filter(&candidate_trimmed, &policy.outlier_policy);

        if workload.benchmark_metadata_hash.trim().is_empty() {
            findings.push(ValidationFinding {
                code: FindingCode::MissingBenchmarkMetadata,
                message: "missing benchmark metadata hash".to_string(),
            });
        }

        if baseline_filtered.filtered.len() < policy.min_samples_after_filter
            || candidate_filtered.filtered.len() < policy.min_samples_after_filter
            || baseline_filtered.filtered.len() < policy.outlier_policy.min_retained_samples
            || candidate_filtered.filtered.len() < policy.outlier_policy.min_retained_samples
        {
            findings.push(ValidationFinding {
                code: FindingCode::InsufficientSamples,
                message: format!(
                    "insufficient retained samples after warmup/outlier filtering (baseline={}, candidate={}, min={})",
                    baseline_filtered.filtered.len(),
                    candidate_filtered.filtered.len(),
                    policy.min_samples_after_filter
                ),
            });
        }

        let baseline_stats = compute_stats(&baseline_filtered.filtered);
        let candidate_stats = compute_stats(&candidate_filtered.filtered);

        let mut outcome = WorkloadOutcome::Pass;
        let mut p_value_millionths = MILLION;
        let mut effect_size_millionths = 0_i64;
        let mut confidence_interval = ConfidenceIntervalNs {
            lower_ns: 0,
            upper_ns: 0,
        };

        if let (Some(base), Some(candidate)) = (&baseline_stats, &candidate_stats) {
            let baseline_mean = base.mean_ns as f64;
            let candidate_mean = candidate.mean_ns as f64;

            effect_size_millionths = regression_millionths(baseline_mean, candidate_mean);

            let stderr = standard_error(base, candidate);
            p_value_millionths =
                two_sided_p_value_millionths(candidate_mean - baseline_mean, stderr);
            confidence_interval = mean_delta_confidence_interval_ns(
                candidate_mean - baseline_mean,
                stderr,
                policy.thresholds.confidence_level_millionths,
            );

            if base.cv_millionths > policy.thresholds.max_cv_millionths
                || candidate.cv_millionths > policy.thresholds.max_cv_millionths
            {
                findings.push(ValidationFinding {
                    code: FindingCode::VarianceQuarantine,
                    message: format!(
                        "coefficient of variation exceeds policy (baseline_cv={}, candidate_cv={}, max={})",
                        base.cv_millionths,
                        candidate.cv_millionths,
                        policy.thresholds.max_cv_millionths
                    ),
                });
            }

            let absolute_effect = effect_size_millionths.unsigned_abs() as u32;
            if absolute_effect >= policy.thresholds.min_effect_size_millionths
                && p_value_millionths > policy.thresholds.max_p_value_millionths
            {
                findings.push(ValidationFinding {
                    code: FindingCode::ConfidenceQuarantine,
                    message: format!(
                        "p-value exceeds policy threshold (p={} > max={})",
                        p_value_millionths, policy.thresholds.max_p_value_millionths
                    ),
                });
            }

            if effect_size_millionths > i64::from(policy.thresholds.fail_regression_millionths)
                && p_value_millionths <= policy.thresholds.max_p_value_millionths
            {
                findings.push(ValidationFinding {
                    code: FindingCode::RegressionFail,
                    message: format!(
                        "regression exceeds fail threshold (regression={} > fail={})",
                        effect_size_millionths, policy.thresholds.fail_regression_millionths
                    ),
                });
            } else if effect_size_millionths
                > i64::from(policy.thresholds.warning_regression_millionths)
                && p_value_millionths <= policy.thresholds.max_p_value_millionths
            {
                findings.push(ValidationFinding {
                    code: FindingCode::RegressionWarn,
                    message: format!(
                        "regression exceeds warning threshold (regression={} > warning={})",
                        effect_size_millionths, policy.thresholds.warning_regression_millionths
                    ),
                });
            }
        }

        if findings
            .iter()
            .any(|finding| finding.code == FindingCode::RegressionFail)
            || findings
                .iter()
                .any(|finding| finding.code == FindingCode::MissingBenchmarkMetadata)
            || findings
                .iter()
                .any(|finding| finding.code == FindingCode::InsufficientSamples)
        {
            outcome = WorkloadOutcome::Fail;
            failed.insert(workload_id.clone());
        } else if findings
            .iter()
            .any(|finding| finding.code == FindingCode::VarianceQuarantine)
            || findings
                .iter()
                .any(|finding| finding.code == FindingCode::ConfidenceQuarantine)
        {
            outcome = WorkloadOutcome::Quarantine;
            quarantined.insert(workload_id.clone());
        } else if findings
            .iter()
            .any(|finding| finding.code == FindingCode::RegressionWarn)
        {
            outcome = WorkloadOutcome::Warn;
            warned.insert(workload_id.clone());
        }

        let baseline_fallback = baseline_stats.unwrap_or(SampleStatsNs {
            sample_count: baseline_filtered.filtered.len(),
            mean_ns: 0,
            stddev_ns: 0,
            cv_millionths: MILLION,
        });

        let candidate_fallback = candidate_stats.unwrap_or(SampleStatsNs {
            sample_count: candidate_filtered.filtered.len(),
            mean_ns: 0,
            stddev_ns: 0,
            cv_millionths: MILLION,
        });

        let error_code = if matches!(outcome, WorkloadOutcome::Pass) {
            None
        } else {
            findings
                .first()
                .map(|finding| finding.code.stable_code().to_string())
        };

        logs.push(StatisticalValidationLogEvent {
            trace_id: input.trace_id.clone(),
            decision_id: input.decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT.to_string(),
            event: "workload_evaluated".to_string(),
            scenario_id,
            workload_id: workload_id.clone(),
            outcome: outcome.to_string(),
            error_code,
        });

        verdicts.push(WorkloadValidationVerdict {
            workload_id,
            scenario_id: workload.scenario_id.clone(),
            outcome,
            p_value_millionths,
            effect_size_millionths,
            confidence_interval_mean_delta_ns: confidence_interval,
            baseline: baseline_fallback,
            candidate: candidate_fallback,
            outliers: OutlierSummary {
                baseline_removed: baseline_filtered.removed,
                candidate_removed: candidate_filtered.removed,
                method: "mad".to_string(),
            },
            findings,
        });
    }

    StatisticalValidationReport {
        trace_id: input.trace_id.clone(),
        decision_id: input.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT.to_string(),
        promote_allowed: failed.is_empty() && quarantined.is_empty(),
        failed_workloads: failed.into_iter().collect(),
        quarantined_workloads: quarantined.into_iter().collect(),
        warned_workloads: warned.into_iter().collect(),
        verdicts,
        logs,
    }
}

pub fn write_stats_verdict_report(
    report: &StatisticalValidationReport,
    path: impl AsRef<Path>,
) -> Result<(), StatisticalValidationError> {
    let report_json = serde_json::to_string_pretty(report)
        .map_err(|error| StatisticalValidationError::Serialization(error.to_string()))?;
    let output_path = path.as_ref();

    fs::write(output_path, report_json).map_err(|source| StatisticalValidationError::ReportWrite {
        path: output_path.display().to_string(),
        source,
    })
}

#[derive(Debug)]
struct FilteredSamples {
    filtered: Vec<u64>,
    removed: usize,
}

fn trim_warmup(samples: &[u64], warmup_drop_samples: usize) -> Vec<u64> {
    if warmup_drop_samples >= samples.len() {
        return Vec::new();
    }
    samples[warmup_drop_samples..].to_vec()
}

fn apply_mad_filter(samples: &[u64], policy: &OutlierPolicy) -> FilteredSamples {
    if samples.is_empty() {
        return FilteredSamples {
            filtered: Vec::new(),
            removed: 0,
        };
    }

    let median_value = median_u64(samples);
    let deviations: Vec<u64> = samples
        .iter()
        .map(|sample| sample.abs_diff(median_value))
        .collect();
    let mad = median_u64(&deviations);

    if mad == 0 {
        return FilteredSamples {
            filtered: samples.to_vec(),
            removed: 0,
        };
    }

    let threshold = ((mad as u128)
        .saturating_mul(policy.mad_multiplier_millionths as u128)
        .saturating_div(MILLION as u128)) as u64;

    let mut filtered = Vec::with_capacity(samples.len());
    for sample in samples {
        if sample.abs_diff(median_value) <= threshold {
            filtered.push(*sample);
        }
    }

    if filtered.len() < policy.min_retained_samples {
        // Revert to unfiltered samples but report how many WOULD have been
        // removed so callers know the filter was attempted.
        return FilteredSamples {
            removed: samples.len().saturating_sub(filtered.len()),
            filtered: samples.to_vec(),
        };
    }

    FilteredSamples {
        removed: samples.len().saturating_sub(filtered.len()),
        filtered,
    }
}

fn median_u64(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 1 {
        sorted[mid]
    } else {
        ((sorted[mid - 1] as u128 + sorted[mid] as u128) / 2) as u64
    }
}

fn compute_stats(samples: &[u64]) -> Option<SampleStatsNs> {
    if samples.is_empty() {
        return None;
    }

    let sample_count = samples.len();
    let sample_count_f64 = sample_count as f64;

    let mean = samples.iter().map(|sample| *sample as f64).sum::<f64>() / sample_count_f64;
    if mean <= 0.0 {
        return None;
    }

    // Use Bessel's correction (N-1) for unbiased sample variance.
    // For n=1, fall back to population variance (N) to avoid division by zero.
    let variance_divisor = if sample_count > 1 {
        (sample_count - 1) as f64
    } else {
        sample_count_f64
    };
    let variance = samples
        .iter()
        .map(|sample| {
            let delta = *sample as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / variance_divisor;

    let stddev = variance.sqrt();
    let cv_millionths = ((stddev / mean) * MILLION as f64).round();

    Some(SampleStatsNs {
        sample_count,
        mean_ns: mean.round() as u64,
        stddev_ns: stddev.round() as u64,
        cv_millionths: cv_millionths.clamp(0.0, MILLION as f64) as u32,
    })
}

fn standard_error(baseline: &SampleStatsNs, candidate: &SampleStatsNs) -> f64 {
    if baseline.sample_count == 0 || candidate.sample_count == 0 {
        return 0.0;
    }

    let baseline_var = (baseline.stddev_ns as f64).powi(2);
    let candidate_var = (candidate.stddev_ns as f64).powi(2);

    let stderr = (baseline_var / baseline.sample_count as f64
        + candidate_var / candidate.sample_count as f64)
        .sqrt();

    if stderr.is_finite() { stderr } else { 0.0 }
}

fn regression_millionths(baseline_mean_ns: f64, candidate_mean_ns: f64) -> i64 {
    if baseline_mean_ns <= 0.0 {
        return 0;
    }
    (((candidate_mean_ns - baseline_mean_ns) * MILLION as f64) / baseline_mean_ns).round() as i64
}

fn two_sided_p_value_millionths(mean_delta_ns: f64, stderr: f64) -> u32 {
    if stderr <= 0.0 {
        return if mean_delta_ns.abs() <= f64::EPSILON {
            MILLION
        } else {
            0
        };
    }

    let z_score = (mean_delta_ns.abs() / stderr).max(0.0);
    let cdf = normal_cdf(z_score);
    let mut p_value = 2.0 * (1.0 - cdf);
    if !p_value.is_finite() {
        p_value = 1.0;
    }

    let millionths = (p_value * MILLION as f64).round();
    millionths.clamp(0.0, MILLION as f64) as u32
}

fn mean_delta_confidence_interval_ns(
    mean_delta_ns: f64,
    stderr: f64,
    confidence_level_millionths: u32,
) -> ConfidenceIntervalNs {
    if stderr <= 0.0 {
        let point = mean_delta_ns.round() as i64;
        return ConfidenceIntervalNs {
            lower_ns: point,
            upper_ns: point,
        };
    }

    let clamped_confidence =
        confidence_level_millionths.clamp(500_000, 999_999) as f64 / MILLION as f64;
    let tail_probability = 1.0 - ((1.0 - clamped_confidence) / 2.0);
    let z_critical = inverse_normal_cdf(tail_probability);

    let lower = (mean_delta_ns - z_critical * stderr).round() as i64;
    let upper = (mean_delta_ns + z_critical * stderr).round() as i64;

    if lower <= upper {
        ConfidenceIntervalNs {
            lower_ns: lower,
            upper_ns: upper,
        }
    } else {
        ConfidenceIntervalNs {
            lower_ns: upper,
            upper_ns: lower,
        }
    }
}

fn inverse_normal_cdf(probability: f64) -> f64 {
    let p = probability.clamp(1e-12, 1.0 - 1e-12);
    let mut low = -8.0;
    let mut high = 8.0;

    for _ in 0..120 {
        let mid = (low + high) / 2.0;
        let mid_p = normal_cdf(mid);
        match mid_p.partial_cmp(&p).unwrap_or(Ordering::Equal) {
            Ordering::Less => low = mid,
            Ordering::Greater => high = mid,
            Ordering::Equal => return mid,
        }
    }

    (low + high) / 2.0
}

fn normal_cdf(value: f64) -> f64 {
    0.5 * (1.0 + erf_approx(value / SQRT_2))
}

fn erf_approx(value: f64) -> f64 {
    // Abramowitz & Stegun 7.1.26 approximation.
    let sign = if value < 0.0 { -1.0 } else { 1.0 };
    let x = value.abs();
    let t = 1.0 / (1.0 + 0.3275911 * x);
    let polynomial =
        (((1.061405429 * t - 1.453152027) * t + 1.421413741) * t - 0.284496736) * t + 0.254829592;
    let polynomial = polynomial * t;
    sign * (1.0 - polynomial * (-x * x).exp())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stable_policy() -> StatisticalValidationPolicy {
        StatisticalValidationPolicy {
            warmup_drop_samples: 0,
            min_samples_after_filter: 5,
            outlier_policy: OutlierPolicy {
                mad_multiplier_millionths: 3_000_000,
                min_retained_samples: 5,
            },
            thresholds: StatisticalThresholds {
                max_cv_millionths: 80_000,
                warning_regression_millionths: 10_000,
                fail_regression_millionths: 20_000,
                max_p_value_millionths: 50_000,
                min_effect_size_millionths: 3_000,
                confidence_level_millionths: 950_000,
            },
        }
    }

    fn low_noise_workload() -> WorkloadSamples {
        WorkloadSamples::new(
            "router_hot_path",
            "golden",
            "sha256:router-hot-path",
            vec![1000, 1002, 998, 1001, 999, 1000, 1001, 999, 1000],
            vec![1020, 1019, 1021, 1022, 1018, 1020, 1019, 1021, 1020],
        )
    }

    #[test]
    fn deterministic_report_for_identical_input() {
        let policy = stable_policy();
        let input = StatisticalValidationInput::new(
            "trace-a",
            "decision-a",
            "policy-a",
            vec![low_noise_workload()],
        );

        let report_a = evaluate_statistical_validation(&input, &policy);
        let report_b = evaluate_statistical_validation(&input, &policy);

        assert_eq!(report_a, report_b);
        assert_eq!(report_a.verdicts.len(), 1);
        assert_eq!(report_a.verdicts[0].outcome, report_b.verdicts[0].outcome);
    }

    #[test]
    fn high_variance_is_quarantined() {
        let policy = stable_policy();
        let workload = WorkloadSamples::new(
            "dom_commit_batch",
            "variance_path",
            "sha256:dom-commit",
            vec![900, 1300, 700, 1400, 600, 1500, 800, 1200, 500],
            vec![920, 1290, 680, 1420, 610, 1490, 820, 1210, 520],
        );

        let input = StatisticalValidationInput::new("trace", "decision", "policy", vec![workload]);
        let report = evaluate_statistical_validation(&input, &policy);

        assert!(!report.promote_allowed);
        assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Quarantine);
        assert!(
            report.verdicts[0]
                .findings
                .iter()
                .any(|f| f.code == FindingCode::VarianceQuarantine)
        );
    }

    #[test]
    fn low_confidence_regression_is_quarantined() {
        let policy = stable_policy();
        // Moderate noise, ~1.5% regression — above warn (1%) but below fail (2%).
        // Uniform +15 shift with noisy samples yields p > 0.05 → ConfidenceQuarantine.
        let workload = WorkloadSamples::new(
            "scheduler_path",
            "low_confidence",
            "sha256:scheduler",
            vec![980, 1000, 1020, 960, 1040, 1010, 990, 970, 1030],
            vec![995, 1015, 1035, 975, 1055, 1025, 1005, 985, 1045],
        );

        let input = StatisticalValidationInput::new("trace", "decision", "policy", vec![workload]);
        let report = evaluate_statistical_validation(&input, &policy);

        assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Quarantine);
        assert!(
            report.verdicts[0]
                .findings
                .iter()
                .any(|f| f.code == FindingCode::ConfidenceQuarantine)
        );
    }

    #[test]
    fn outlier_filter_removes_single_spike() {
        let policy = stable_policy();
        let workload = WorkloadSamples::new(
            "layout_workload",
            "outlier",
            "sha256:layout",
            vec![1000, 1001, 999, 1000, 1001, 1000, 1002, 1000, 1001],
            vec![1000, 1001, 999, 1000, 1001, 1000, 1002, 1000, 50_000],
        );

        let input = StatisticalValidationInput::new("trace", "decision", "policy", vec![workload]);
        let report = evaluate_statistical_validation(&input, &policy);

        assert_eq!(report.verdicts[0].outliers.candidate_removed, 1);
    }

    #[test]
    fn missing_metadata_fails_closed() {
        let policy = stable_policy();
        let mut workload = low_noise_workload();
        workload.benchmark_metadata_hash.clear();

        let input = StatisticalValidationInput::new("trace", "decision", "policy", vec![workload]);
        let report = evaluate_statistical_validation(&input, &policy);

        assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Fail);
        assert!(
            report.verdicts[0]
                .findings
                .iter()
                .any(|f| f.code == FindingCode::MissingBenchmarkMetadata)
        );
    }

    #[test]
    fn write_stats_report_writes_json() {
        let policy = stable_policy();
        let input = StatisticalValidationInput::new(
            "trace",
            "decision",
            "policy",
            vec![low_noise_workload()],
        );
        let report = evaluate_statistical_validation(&input, &policy);

        let temp_path = std::env::temp_dir().join("franken_engine_stats_validation_report.json");
        write_stats_verdict_report(&report, &temp_path).expect("report should write");

        let bytes = fs::read(&temp_path).expect("report should exist");
        assert!(!bytes.is_empty());

        let _ = fs::remove_file(temp_path);
    }

    #[test]
    fn confidence_interval_is_well_ordered() {
        let interval = mean_delta_confidence_interval_ns(100.0, 10.0, 950_000);
        assert!(interval.lower_ns <= interval.upper_ns);
    }

    // -- Helper function tests -----------------------------------------------

    #[test]
    fn median_u64_empty() {
        assert_eq!(median_u64(&[]), 0);
    }

    #[test]
    fn median_u64_single() {
        assert_eq!(median_u64(&[42]), 42);
    }

    #[test]
    fn median_u64_odd_count() {
        assert_eq!(median_u64(&[3, 1, 2]), 2);
    }

    #[test]
    fn median_u64_even_count() {
        assert_eq!(median_u64(&[1, 2, 3, 4]), 2); // (2+3)/2 = 2.5, truncated to 2
    }

    #[test]
    fn trim_warmup_drops_first_n() {
        let samples = vec![100, 200, 300, 400, 500];
        let trimmed = trim_warmup(&samples, 2);
        assert_eq!(trimmed, vec![300, 400, 500]);
    }

    #[test]
    fn trim_warmup_all_dropped() {
        let samples = vec![1, 2, 3];
        let trimmed = trim_warmup(&samples, 5);
        assert!(trimmed.is_empty());
    }

    #[test]
    fn trim_warmup_zero_drops_nothing() {
        let samples = vec![10, 20, 30];
        let trimmed = trim_warmup(&samples, 0);
        assert_eq!(trimmed, vec![10, 20, 30]);
    }

    #[test]
    fn compute_stats_empty() {
        assert!(compute_stats(&[]).is_none());
    }

    #[test]
    fn compute_stats_uniform() {
        let stats = compute_stats(&[1000, 1000, 1000, 1000, 1000]).unwrap();
        assert_eq!(stats.mean_ns, 1000);
        assert_eq!(stats.stddev_ns, 0);
        assert_eq!(stats.cv_millionths, 0);
        assert_eq!(stats.sample_count, 5);
    }

    #[test]
    fn compute_stats_nonzero_stddev() {
        let stats = compute_stats(&[900, 1000, 1100]).unwrap();
        assert_eq!(stats.mean_ns, 1000);
        assert!(stats.stddev_ns > 0);
        assert!(stats.cv_millionths > 0);
    }

    #[test]
    fn regression_millionths_positive() {
        // 10% regression: candidate = 1100, baseline = 1000
        let reg = regression_millionths(1000.0, 1100.0);
        assert_eq!(reg, 100_000); // 0.1 * 1M = 100k
    }

    #[test]
    fn regression_millionths_negative_improvement() {
        // 10% improvement: candidate = 900, baseline = 1000
        let reg = regression_millionths(1000.0, 900.0);
        assert_eq!(reg, -100_000);
    }

    #[test]
    fn regression_millionths_zero_baseline() {
        assert_eq!(regression_millionths(0.0, 100.0), 0);
    }

    #[test]
    fn normal_cdf_at_zero() {
        let cdf = normal_cdf(0.0);
        assert!((cdf - 0.5).abs() < 0.001, "normal_cdf(0) should be ~0.5");
    }

    #[test]
    fn normal_cdf_far_positive() {
        let cdf = normal_cdf(5.0);
        assert!(cdf > 0.999, "normal_cdf(5) should be ~1.0");
    }

    #[test]
    fn normal_cdf_far_negative() {
        let cdf = normal_cdf(-5.0);
        assert!(cdf < 0.001, "normal_cdf(-5) should be ~0.0");
    }

    #[test]
    fn erf_approx_zero() {
        let erf = erf_approx(0.0);
        assert!(erf.abs() < 0.001, "erf(0) should be ~0");
    }

    #[test]
    fn erf_approx_large() {
        let erf = erf_approx(3.0);
        assert!((erf - 1.0).abs() < 0.01, "erf(3) should be ~1");
    }

    #[test]
    fn p_value_identical_samples() {
        let p = two_sided_p_value_millionths(0.0, 10.0);
        assert_eq!(p, MILLION, "zero delta should give p=1.0");
    }

    #[test]
    fn p_value_large_delta() {
        let p = two_sided_p_value_millionths(100.0, 1.0);
        assert!(p < 50_000, "large z-score should give small p-value");
    }

    #[test]
    fn p_value_zero_stderr() {
        let p = two_sided_p_value_millionths(100.0, 0.0);
        assert_eq!(p, 0, "nonzero delta with zero stderr should give p=0");
    }

    #[test]
    fn p_value_zero_delta_zero_stderr() {
        let p = two_sided_p_value_millionths(0.0, 0.0);
        assert_eq!(p, MILLION);
    }

    // -- Policy and type tests -----------------------------------------------

    #[test]
    fn default_policy_has_sensible_values() {
        let policy = StatisticalValidationPolicy::default();
        assert!(policy.warmup_drop_samples > 0);
        assert!(policy.min_samples_after_filter > 0);
    }

    #[test]
    fn workload_outcome_as_str() {
        assert_eq!(WorkloadOutcome::Pass.as_str(), "pass");
        assert_eq!(WorkloadOutcome::Warn.as_str(), "warn");
        assert_eq!(WorkloadOutcome::Fail.as_str(), "fail");
        assert_eq!(WorkloadOutcome::Quarantine.as_str(), "quarantine");
    }

    #[test]
    fn workload_outcome_display() {
        assert_eq!(format!("{}", WorkloadOutcome::Pass), "pass");
        assert_eq!(format!("{}", WorkloadOutcome::Quarantine), "quarantine");
    }

    #[test]
    fn finding_code_stable_codes_are_distinct() {
        let codes = vec![
            FindingCode::MissingBenchmarkMetadata.stable_code(),
            FindingCode::InsufficientSamples.stable_code(),
            FindingCode::VarianceQuarantine.stable_code(),
            FindingCode::ConfidenceQuarantine.stable_code(),
            FindingCode::RegressionFail.stable_code(),
            FindingCode::RegressionWarn.stable_code(),
        ];
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(
            codes.len(),
            unique.len(),
            "all error codes should be distinct"
        );
    }

    #[test]
    fn finding_code_display_matches_stable_code() {
        let code = FindingCode::InsufficientSamples;
        assert_eq!(format!("{code}"), code.stable_code());
    }

    // -- MAD filter tests ----------------------------------------------------

    #[test]
    fn mad_filter_empty_input() {
        let policy = OutlierPolicy::default();
        let result = apply_mad_filter(&[], &policy);
        assert!(result.filtered.is_empty());
        assert_eq!(result.removed, 0);
    }

    #[test]
    fn mad_filter_uniform_keeps_all() {
        let policy = OutlierPolicy::default();
        let samples = vec![100, 100, 100, 100, 100, 100, 100, 100];
        let result = apply_mad_filter(&samples, &policy);
        assert_eq!(result.filtered.len(), 8);
        assert_eq!(result.removed, 0);
    }

    #[test]
    fn mad_filter_removes_extreme_outlier() {
        let policy = OutlierPolicy {
            mad_multiplier_millionths: 3_000_000,
            min_retained_samples: 5,
        };
        let samples = vec![100, 101, 99, 100, 102, 100, 101, 99, 100_000];
        let result = apply_mad_filter(&samples, &policy);
        assert!(result.removed > 0, "extreme outlier should be removed");
    }

    // -- Inverse normal CDF tests --------------------------------------------

    #[test]
    fn inverse_normal_cdf_at_half() {
        let z = inverse_normal_cdf(0.5);
        assert!(z.abs() < 0.01, "inverse_normal_cdf(0.5) should be ~0");
    }

    #[test]
    fn inverse_normal_cdf_at_975() {
        let z = inverse_normal_cdf(0.975);
        assert!(
            (z - 1.96).abs() < 0.05,
            "inverse_normal_cdf(0.975) should be ~1.96"
        );
    }

    // -- Standard error tests ------------------------------------------------

    #[test]
    fn standard_error_zero_samples() {
        let stats = SampleStatsNs {
            sample_count: 0,
            mean_ns: 0,
            stddev_ns: 0,
            cv_millionths: 0,
        };
        assert_eq!(standard_error(&stats, &stats), 0.0);
    }

    // -- Serde roundtrip tests -----------------------------------------------

    #[test]
    fn validation_input_serde_roundtrip() {
        let input = StatisticalValidationInput::new(
            "trace",
            "decision",
            "policy",
            vec![low_noise_workload()],
        );
        let json = serde_json::to_string(&input).unwrap();
        let restored: StatisticalValidationInput = serde_json::from_str(&json).unwrap();
        assert_eq!(input, restored);
    }

    #[test]
    fn validation_policy_serde_roundtrip() {
        let policy = stable_policy();
        let json = serde_json::to_string(&policy).unwrap();
        let restored: StatisticalValidationPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    #[test]
    fn validation_report_serde_roundtrip() {
        let policy = stable_policy();
        let input = StatisticalValidationInput::new(
            "trace",
            "decision",
            "policy",
            vec![low_noise_workload()],
        );
        let report = evaluate_statistical_validation(&input, &policy);
        let json = serde_json::to_string(&report).unwrap();
        let restored: StatisticalValidationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, restored);
    }

    // -- Promotion decision tests --------------------------------------------

    #[test]
    fn pass_allows_promotion() {
        let policy = StatisticalValidationPolicy {
            warmup_drop_samples: 0,
            min_samples_after_filter: 3,
            outlier_policy: OutlierPolicy {
                mad_multiplier_millionths: 10_000_000,
                min_retained_samples: 3,
            },
            thresholds: StatisticalThresholds {
                max_cv_millionths: 500_000, // generous
                warning_regression_millionths: 100_000,
                fail_regression_millionths: 200_000,
                max_p_value_millionths: 50_000,
                min_effect_size_millionths: 100_000,
                confidence_level_millionths: 950_000,
            },
        };
        let workload = WorkloadSamples::new(
            "fast_path",
            "stable",
            "sha256:fast",
            vec![1000, 1001, 999, 1000, 1001, 1000, 1002, 999, 1000],
            vec![1000, 1001, 999, 1000, 1001, 1000, 1002, 999, 1000],
        );
        let input = StatisticalValidationInput::new("t", "d", "p", vec![workload]);
        let report = evaluate_statistical_validation(&input, &policy);
        assert!(report.promote_allowed);
        assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Pass);
    }

    #[test]
    fn insufficient_samples_fails() {
        let policy = stable_policy();
        let workload = WorkloadSamples::new(
            "tiny",
            "test",
            "sha256:tiny",
            vec![100, 200],
            vec![100, 200],
        );
        let input = StatisticalValidationInput::new("t", "d", "p", vec![workload]);
        let report = evaluate_statistical_validation(&input, &policy);
        assert!(!report.promote_allowed);
        assert_eq!(report.verdicts[0].outcome, WorkloadOutcome::Fail);
        assert!(
            report.verdicts[0]
                .findings
                .iter()
                .any(|f| f.code == FindingCode::InsufficientSamples)
        );
    }

    #[test]
    fn multiple_workloads_independent_verdicts() {
        let policy = stable_policy();
        let good = low_noise_workload();
        let mut bad = low_noise_workload();
        bad.workload_id = "bad_workload".to_string();
        bad.benchmark_metadata_hash.clear(); // missing metadata

        let input = StatisticalValidationInput::new("t", "d", "p", vec![good, bad]);
        let report = evaluate_statistical_validation(&input, &policy);
        assert_eq!(report.verdicts.len(), 2);
        assert!(
            !report.promote_allowed,
            "one failure should block promotion"
        );
    }

    #[test]
    fn error_stable_codes() {
        let err = StatisticalValidationError::Serialization("test".into());
        assert_eq!(err.stable_code(), ERROR_SERIALIZATION);
    }

    #[test]
    fn workload_outcome_ordering() {
        assert!(WorkloadOutcome::Pass < WorkloadOutcome::Warn);
        assert!(WorkloadOutcome::Warn < WorkloadOutcome::Fail);
        assert!(WorkloadOutcome::Fail < WorkloadOutcome::Quarantine);
    }

    #[test]
    fn confidence_interval_zero_stderr() {
        let ci = mean_delta_confidence_interval_ns(50.0, 0.0, 950_000);
        assert_eq!(ci.lower_ns, 50);
        assert_eq!(ci.upper_ns, 50);
    }

    #[test]
    fn logs_contain_workload_events() {
        let policy = stable_policy();
        let input = StatisticalValidationInput::new(
            "trace",
            "decision",
            "policy",
            vec![low_noise_workload()],
        );
        let report = evaluate_statistical_validation(&input, &policy);
        assert!(!report.logs.is_empty());
        assert!(report.logs.iter().all(|l| l.event == "workload_evaluated"));
        assert!(
            report
                .logs
                .iter()
                .all(|l| l.component == PERFORMANCE_STATISTICAL_VALIDATION_COMPONENT)
        );
    }
}
