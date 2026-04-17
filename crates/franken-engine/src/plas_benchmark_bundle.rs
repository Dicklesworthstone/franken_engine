//! Deterministic PLAS benchmark-bundle publication for Section 10.15 (`bd-25b7`).
//!
//! Publishes machine-readable + operator-friendly benchmark summaries across
//! representative extension cohorts for:
//! - over-privilege ratio
//! - policy authoring-time reduction
//! - false-deny rates
//! - escrow-event rates

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const PLAS_BENCHMARK_BUNDLE_COMPONENT: &str = "plas_benchmark_bundle";
pub const PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION: &str = "franken-engine.plas-benchmark-bundle.v1";

const ERROR_INVALID_INPUT: &str = "FE-PLAS-BENCH-2001";
const ERROR_DUPLICATE_EXTENSION: &str = "FE-PLAS-BENCH-2002";
const ERROR_MISSING_COHORT: &str = "FE-PLAS-BENCH-2003";
const ERROR_THRESHOLD: &str = "FE-PLAS-BENCH-2004";
const ERROR_TREND_REGRESSION: &str = "FE-PLAS-BENCH-2005";

const MILLION: u128 = 1_000_000;
const NS_PER_HOUR: u128 = 3_600_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlasBenchmarkCohort {
    Simple,
    Complex,
    HighRisk,
    Boundary,
}

impl PlasBenchmarkCohort {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Simple => "simple",
            Self::Complex => "complex",
            Self::HighRisk => "high_risk",
            Self::Boundary => "boundary",
        }
    }

    pub fn all() -> [Self; 4] {
        [Self::Simple, Self::Complex, Self::HighRisk, Self::Boundary]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasBenchmarkExtensionSample {
    pub extension_id: String,
    pub cohort: PlasBenchmarkCohort,
    pub synthesized_capability_count: u32,
    pub empirically_required_capability_count: u32,
    pub manual_authoring_time_ms: u64,
    pub plas_authoring_time_ms: u64,
    pub benign_request_count: u64,
    pub benign_false_deny_count: u64,
    pub escrow_event_count: u64,
    pub observation_window_ns: u64,
    pub witness_present: bool,
}

impl PlasBenchmarkExtensionSample {
    fn validate(&self) -> Result<(), PlasBenchmarkBundleError> {
        if self.extension_id.trim().is_empty() {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "samples[].extension_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if self.synthesized_capability_count == 0 {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "samples[].synthesized_capability_count".to_string(),
                detail: "must be > 0".to_string(),
            });
        }
        if self.empirically_required_capability_count == 0 {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "samples[].empirically_required_capability_count".to_string(),
                detail: "must be > 0".to_string(),
            });
        }
        if self.manual_authoring_time_ms == 0 {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "samples[].manual_authoring_time_ms".to_string(),
                detail: "must be > 0".to_string(),
            });
        }
        if self.benign_request_count == 0 {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "samples[].benign_request_count".to_string(),
                detail: "must be > 0".to_string(),
            });
        }
        if self.benign_false_deny_count > self.benign_request_count {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "samples[].benign_false_deny_count".to_string(),
                detail: "must be <= benign_request_count".to_string(),
            });
        }
        if self.observation_window_ns == 0 {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "samples[].observation_window_ns".to_string(),
                detail: "must be > 0".to_string(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasBenchmarkThresholds {
    /// Success criterion target from the plan: <= 1.10.
    pub max_over_privilege_ratio_millionths: u64,
    /// Success criterion target from the plan: >= 70%.
    pub min_authoring_time_reduction_millionths: i64,
    /// Success criterion target from the plan: <= 0.5%.
    pub max_false_deny_rate_millionths: u64,
    /// Success criterion target from the plan: >= 90%.
    pub min_witness_coverage_millionths: u64,
    /// Optional operator threshold for escrow event pressure.
    pub max_escrow_event_rate_per_hour_millionths: Option<u64>,
    /// If true, publish gate fails on trend regression.
    pub fail_on_trend_regression: bool,
}

impl Default for PlasBenchmarkThresholds {
    fn default() -> Self {
        Self {
            max_over_privilege_ratio_millionths: 1_100_000,
            min_authoring_time_reduction_millionths: 700_000,
            max_false_deny_rate_millionths: 5_000,
            min_witness_coverage_millionths: 900_000,
            max_escrow_event_rate_per_hour_millionths: None,
            fail_on_trend_regression: false,
        }
    }
}

impl PlasBenchmarkThresholds {
    fn validate(&self) -> Result<(), PlasBenchmarkBundleError> {
        if self.max_over_privilege_ratio_millionths == 0 {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "thresholds.max_over_privilege_ratio_millionths".to_string(),
                detail: "must be > 0".to_string(),
            });
        }
        if self.max_false_deny_rate_millionths > 1_000_000 {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "thresholds.max_false_deny_rate_millionths".to_string(),
                detail: "must be <= 1_000_000".to_string(),
            });
        }
        if self.min_witness_coverage_millionths > 1_000_000 {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "thresholds.min_witness_coverage_millionths".to_string(),
                detail: "must be <= 1_000_000".to_string(),
            });
        }
        if let Some(limit) = self.max_escrow_event_rate_per_hour_millionths
            && limit == 0
        {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "thresholds.max_escrow_event_rate_per_hour_millionths".to_string(),
                detail: "must be > 0 when provided".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasBenchmarkTrendPoint {
    pub benchmark_run_id: String,
    pub generated_at_ns: u64,
    pub mean_over_privilege_ratio_millionths: u64,
    pub mean_authoring_time_reduction_millionths: i64,
    pub mean_false_deny_rate_millionths: u64,
    pub mean_escrow_event_rate_per_hour_millionths: u64,
    pub witness_coverage_millionths: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasBenchmarkBundleRequest {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub benchmark_run_id: String,
    pub generated_at_ns: u64,
    pub samples: Vec<PlasBenchmarkExtensionSample>,
    pub historical_runs: Vec<PlasBenchmarkTrendPoint>,
    pub thresholds: Option<PlasBenchmarkThresholds>,
}

impl PlasBenchmarkBundleRequest {
    fn validate(&self) -> Result<(), PlasBenchmarkBundleError> {
        if self.trace_id.trim().is_empty() {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "trace_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if self.decision_id.trim().is_empty() {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "decision_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if self.policy_id.trim().is_empty() {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "policy_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if self.benchmark_run_id.trim().is_empty() {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "benchmark_run_id".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        if self.samples.is_empty() {
            return Err(PlasBenchmarkBundleError::InvalidInput {
                field: "samples".to_string(),
                detail: "must not be empty".to_string(),
            });
        }
        for sample in &self.samples {
            sample.validate()?;
        }
        if let Some(thresholds) = &self.thresholds {
            thresholds.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasBenchmarkExtensionResult {
    pub extension_id: String,
    pub cohort: PlasBenchmarkCohort,
    pub over_privilege_ratio_millionths: u64,
    pub authoring_time_reduction_millionths: i64,
    pub false_deny_rate_millionths: u64,
    pub escrow_event_rate_per_hour_millionths: u64,
    pub witness_present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasBenchmarkCohortSummary {
    pub cohort: PlasBenchmarkCohort,
    pub extension_count: u64,
    pub mean_over_privilege_ratio_millionths: u64,
    pub mean_authoring_time_reduction_millionths: i64,
    pub mean_false_deny_rate_millionths: u64,
    pub mean_escrow_event_rate_per_hour_millionths: u64,
    pub witness_coverage_millionths: u64,
    pub over_privilege_ratio_threshold_pass: bool,
    pub authoring_time_reduction_threshold_pass: bool,
    pub false_deny_rate_threshold_pass: bool,
    pub witness_coverage_threshold_pass: bool,
    pub escrow_event_rate_threshold_pass: bool,
    pub pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasBenchmarkOverallSummary {
    pub extension_count: u64,
    pub cohorts_present: Vec<PlasBenchmarkCohort>,
    pub required_cohorts_present: bool,
    pub mean_over_privilege_ratio_millionths: u64,
    pub mean_authoring_time_reduction_millionths: i64,
    pub mean_false_deny_rate_millionths: u64,
    pub mean_escrow_event_rate_per_hour_millionths: u64,
    pub witness_coverage_millionths: u64,
    pub over_privilege_ratio_threshold_pass: bool,
    pub authoring_time_reduction_threshold_pass: bool,
    pub false_deny_rate_threshold_pass: bool,
    pub witness_coverage_threshold_pass: bool,
    pub escrow_event_rate_threshold_pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasBenchmarkBundleEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub cohort: Option<String>,
    pub extension_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlasBenchmarkBundleDecision {
    pub schema_version: String,
    pub bundle_id: String,
    pub benchmark_run_id: String,
    pub generated_at_ns: u64,
    pub publish_allowed: bool,
    pub blockers: Vec<String>,
    pub thresholds: PlasBenchmarkThresholds,
    pub extension_results: Vec<PlasBenchmarkExtensionResult>,
    pub cohort_summaries: Vec<PlasBenchmarkCohortSummary>,
    pub overall_summary: PlasBenchmarkOverallSummary,
    pub trend: Vec<PlasBenchmarkTrendPoint>,
    pub trend_regression_detected: bool,
    pub events: Vec<PlasBenchmarkBundleEvent>,
}

impl PlasBenchmarkBundleDecision {
    pub fn to_json_pretty(&self) -> Result<String, PlasBenchmarkBundleError> {
        serde_json::to_string_pretty(self)
            .map_err(|err| PlasBenchmarkBundleError::SerializationFailure(err.to_string()))
    }

    pub fn to_markdown_report(&self) -> String {
        let mut out = String::new();
        out.push_str("# PLAS Benchmark Bundle\n\n");
        out.push_str(&format!("- Bundle ID: `{}`\n", self.bundle_id));
        out.push_str(&format!("- Benchmark Run: `{}`\n", self.benchmark_run_id));
        out.push_str(&format!(
            "- Generated At (ns): `{}`\n",
            self.generated_at_ns
        ));
        out.push_str(&format!(
            "- Publication Gate: **{}**\n\n",
            if self.publish_allowed {
                "ALLOW"
            } else {
                "DENY"
            }
        ));

        if !self.blockers.is_empty() {
            out.push_str("## Blockers\n\n");
            for blocker in &self.blockers {
                out.push_str(&format!("- {blocker}\n"));
            }
            out.push('\n');
        }

        out.push_str("## Overall Metrics\n\n");
        out.push_str("| Metric | Value | Threshold | Pass |\n");
        out.push_str("|---|---:|---:|:---:|\n");
        out.push_str(&format!(
            "| Over-privilege ratio | {} | <= {} | {} |\n",
            format_ratio(self.overall_summary.mean_over_privilege_ratio_millionths),
            format_ratio(self.thresholds.max_over_privilege_ratio_millionths),
            pass_mark(self.overall_summary.over_privilege_ratio_threshold_pass),
        ));
        out.push_str(&format!(
            "| Authoring-time reduction | {} | >= {} | {} |\n",
            format_pct_signed(
                self.overall_summary
                    .mean_authoring_time_reduction_millionths
            ),
            format_pct_signed(self.thresholds.min_authoring_time_reduction_millionths),
            pass_mark(self.overall_summary.authoring_time_reduction_threshold_pass),
        ));
        out.push_str(&format!(
            "| False-deny rate | {} | <= {} | {} |\n",
            format_pct(self.overall_summary.mean_false_deny_rate_millionths),
            format_pct(self.thresholds.max_false_deny_rate_millionths),
            pass_mark(self.overall_summary.false_deny_rate_threshold_pass),
        ));
        out.push_str(&format!(
            "| Escrow-event rate (/hour) | {} | {} | {} |\n",
            format_scaled_rate(
                self.overall_summary
                    .mean_escrow_event_rate_per_hour_millionths
            ),
            self.thresholds
                .max_escrow_event_rate_per_hour_millionths
                .map(format_scaled_rate)
                .unwrap_or_else(|| "n/a".to_string()),
            pass_mark(self.overall_summary.escrow_event_rate_threshold_pass),
        ));
        out.push_str(&format!(
            "| Witness coverage | {} | >= {} | {} |\n\n",
            format_pct(self.overall_summary.witness_coverage_millionths),
            format_pct(self.thresholds.min_witness_coverage_millionths),
            pass_mark(self.overall_summary.witness_coverage_threshold_pass),
        ));

        out.push_str("## Cohort Summary\n\n");
        out.push_str("| Cohort | N | Over-Privilege | Authoring Reduction | False-Deny | Escrow Rate (/hour) | Witness Coverage | Pass |\n");
        out.push_str("|---|---:|---:|---:|---:|---:|---:|:---:|\n");
        for summary in &self.cohort_summaries {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                summary.cohort.as_str(),
                summary.extension_count,
                format_ratio(summary.mean_over_privilege_ratio_millionths),
                format_pct_signed(summary.mean_authoring_time_reduction_millionths),
                format_pct(summary.mean_false_deny_rate_millionths),
                format_scaled_rate(summary.mean_escrow_event_rate_per_hour_millionths),
                format_pct(summary.witness_coverage_millionths),
                pass_mark(summary.pass),
            ));
        }
        out.push('\n');

        out.push_str("## Extension Metrics\n\n");
        out.push_str("| Extension | Cohort | Over-Privilege | Authoring Reduction | False-Deny | Escrow Rate (/hour) | Witness |\n");
        out.push_str("|---|---|---:|---:|---:|---:|:---:|\n");
        for result in &self.extension_results {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                result.extension_id,
                result.cohort.as_str(),
                format_ratio(result.over_privilege_ratio_millionths),
                format_pct_signed(result.authoring_time_reduction_millionths),
                format_pct(result.false_deny_rate_millionths),
                format_scaled_rate(result.escrow_event_rate_per_hour_millionths),
                if result.witness_present { "yes" } else { "no" },
            ));
        }
        out.push('\n');

        out.push_str("## Trend\n\n");
        out.push_str("| Run | Timestamp (ns) | Over-Privilege | Authoring Reduction | False-Deny | Escrow Rate (/hour) | Witness Coverage |\n");
        out.push_str("|---|---:|---:|---:|---:|---:|---:|\n");
        for point in &self.trend {
            out.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} |\n",
                point.benchmark_run_id,
                point.generated_at_ns,
                format_ratio(point.mean_over_privilege_ratio_millionths),
                format_pct_signed(point.mean_authoring_time_reduction_millionths),
                format_pct(point.mean_false_deny_rate_millionths),
                format_scaled_rate(point.mean_escrow_event_rate_per_hour_millionths),
                format_pct(point.witness_coverage_millionths),
            ));
        }
        out.push('\n');

        out.push_str(&format!(
            "- Trend regression detected: **{}**\n",
            if self.trend_regression_detected {
                "yes"
            } else {
                "no"
            }
        ));

        out
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PlasBenchmarkBundleError {
    #[error("invalid input field `{field}`: {detail}")]
    InvalidInput { field: String, detail: String },
    #[error("duplicate extension_id `{extension_id}` in samples")]
    DuplicateExtensionId { extension_id: String },
    #[error("serialization failure: {0}")]
    SerializationFailure(String),
}

impl PlasBenchmarkBundleError {
    pub fn stable_code(&self) -> &'static str {
        match self {
            Self::InvalidInput { .. } => ERROR_INVALID_INPUT,
            Self::DuplicateExtensionId { .. } => ERROR_DUPLICATE_EXTENSION,
            Self::SerializationFailure(_) => ERROR_INVALID_INPUT,
        }
    }
}

pub fn build_plas_benchmark_bundle(
    request: &PlasBenchmarkBundleRequest,
) -> Result<PlasBenchmarkBundleDecision, PlasBenchmarkBundleError> {
    request.validate()?;

    let thresholds = request.thresholds.clone().unwrap_or_default();
    thresholds.validate()?;

    let mut events = vec![make_event(
        request,
        "plas_benchmark_bundle_started",
        "pass",
        None,
        None,
        None,
    )];

    let mut samples = request.samples.clone();
    samples.sort_by(|left, right| {
        left.extension_id
            .cmp(&right.extension_id)
            .then(left.cohort.cmp(&right.cohort))
    });

    let mut seen_extension_ids = BTreeSet::new();
    for sample in &samples {
        if !seen_extension_ids.insert(sample.extension_id.clone()) {
            return Err(PlasBenchmarkBundleError::DuplicateExtensionId {
                extension_id: sample.extension_id.clone(),
            });
        }
    }

    let extension_results: Vec<PlasBenchmarkExtensionResult> =
        samples.iter().map(sample_to_result).collect();

    let mut by_cohort: BTreeMap<PlasBenchmarkCohort, Vec<&PlasBenchmarkExtensionResult>> =
        BTreeMap::new();
    for result in &extension_results {
        by_cohort.entry(result.cohort).or_default().push(result);
    }

    let mut blockers = Vec::new();

    let mut missing_cohorts = Vec::new();
    for cohort in PlasBenchmarkCohort::all() {
        if !by_cohort.contains_key(&cohort) {
            missing_cohorts.push(cohort.as_str().to_string());
        }
    }

    if !missing_cohorts.is_empty() {
        blockers.push(format!(
            "missing representative cohort coverage: {}",
            missing_cohorts.join(", ")
        ));
        events.push(make_event(
            request,
            "cohort_coverage",
            "fail",
            Some(ERROR_MISSING_COHORT.to_string()),
            None,
            None,
        ));
    } else {
        events.push(make_event(
            request,
            "cohort_coverage",
            "pass",
            None,
            None,
            None,
        ));
    }

    let mut cohort_summaries = Vec::new();
    for cohort in PlasBenchmarkCohort::all() {
        if let Some(entries) = by_cohort.get(&cohort) {
            let summary = summarize_cohort(cohort, entries, &thresholds);
            if !summary.pass {
                blockers.extend(cohort_blockers(&summary, &thresholds));
            }
            events.push(make_event(
                request,
                "cohort_evaluated",
                if summary.pass { "pass" } else { "fail" },
                if summary.pass {
                    None
                } else {
                    Some(ERROR_THRESHOLD.to_string())
                },
                Some(summary.cohort.as_str().to_string()),
                None,
            ));
            cohort_summaries.push(summary);
        }
    }

    let overall_summary = summarize_overall(
        &extension_results,
        &thresholds,
        missing_cohorts.is_empty(),
        cohort_summaries
            .iter()
            .map(|summary| summary.cohort)
            .collect(),
    );

    if !overall_summary.over_privilege_ratio_threshold_pass {
        blockers.push(format!(
            "overall over-privilege ratio {} exceeds max {}",
            format_ratio(overall_summary.mean_over_privilege_ratio_millionths),
            format_ratio(thresholds.max_over_privilege_ratio_millionths),
        ));
    }
    if !overall_summary.authoring_time_reduction_threshold_pass {
        blockers.push(format!(
            "overall authoring-time reduction {} below min {}",
            format_pct_signed(overall_summary.mean_authoring_time_reduction_millionths),
            format_pct_signed(thresholds.min_authoring_time_reduction_millionths),
        ));
    }
    if !overall_summary.false_deny_rate_threshold_pass {
        blockers.push(format!(
            "overall false-deny rate {} exceeds max {}",
            format_pct(overall_summary.mean_false_deny_rate_millionths),
            format_pct(thresholds.max_false_deny_rate_millionths),
        ));
    }
    if !overall_summary.witness_coverage_threshold_pass {
        blockers.push(format!(
            "overall witness coverage {} below min {}",
            format_pct(overall_summary.witness_coverage_millionths),
            format_pct(thresholds.min_witness_coverage_millionths),
        ));
    }
    if !overall_summary.escrow_event_rate_threshold_pass
        && let Some(limit) = thresholds.max_escrow_event_rate_per_hour_millionths
    {
        blockers.push(format!(
            "overall escrow-event rate {} exceeds max {}",
            format_scaled_rate(overall_summary.mean_escrow_event_rate_per_hour_millionths),
            format_scaled_rate(limit),
        ));
    }

    let mut trend = request.historical_runs.clone();
    trend.sort_by(|left, right| {
        left.generated_at_ns
            .cmp(&right.generated_at_ns)
            .then(left.benchmark_run_id.cmp(&right.benchmark_run_id))
    });

    let current_point = PlasBenchmarkTrendPoint {
        benchmark_run_id: request.benchmark_run_id.clone(),
        generated_at_ns: request.generated_at_ns,
        mean_over_privilege_ratio_millionths: overall_summary.mean_over_privilege_ratio_millionths,
        mean_authoring_time_reduction_millionths: overall_summary
            .mean_authoring_time_reduction_millionths,
        mean_false_deny_rate_millionths: overall_summary.mean_false_deny_rate_millionths,
        mean_escrow_event_rate_per_hour_millionths: overall_summary
            .mean_escrow_event_rate_per_hour_millionths,
        witness_coverage_millionths: overall_summary.witness_coverage_millionths,
    };

    let trend_regression_detected = trend
        .last()
        .map(|previous| is_regression(previous, &current_point))
        .unwrap_or(false);

    if trend_regression_detected {
        events.push(make_event(
            request,
            "trend_regression_check",
            if thresholds.fail_on_trend_regression {
                "fail"
            } else {
                "warn"
            },
            Some(ERROR_TREND_REGRESSION.to_string()),
            None,
            None,
        ));
        if thresholds.fail_on_trend_regression {
            blockers.push(
                "trend regression detected versus previous benchmark run (fail_on_trend_regression=true)"
                    .to_string(),
            );
        }
    } else {
        events.push(make_event(
            request,
            "trend_regression_check",
            "pass",
            None,
            None,
            None,
        ));
    }

    trend.push(current_point);

    let publish_allowed = blockers.is_empty();
    events.push(make_event(
        request,
        "plas_benchmark_bundle_decision",
        if publish_allowed { "allow" } else { "deny" },
        if publish_allowed {
            None
        } else {
            Some(ERROR_THRESHOLD.to_string())
        },
        None,
        None,
    ));

    let bundle_id = compute_bundle_id(
        request,
        publish_allowed,
        &blockers,
        &thresholds,
        &extension_results,
        &cohort_summaries,
        &overall_summary,
        &trend,
        trend_regression_detected,
    )
    .map_err(PlasBenchmarkBundleError::SerializationFailure)?;

    Ok(PlasBenchmarkBundleDecision {
        schema_version: PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION.to_string(),
        bundle_id,
        benchmark_run_id: request.benchmark_run_id.clone(),
        generated_at_ns: request.generated_at_ns,
        publish_allowed,
        blockers,
        thresholds,
        extension_results,
        cohort_summaries,
        overall_summary,
        trend,
        trend_regression_detected,
        events,
    })
}

fn sample_to_result(sample: &PlasBenchmarkExtensionSample) -> PlasBenchmarkExtensionResult {
    PlasBenchmarkExtensionResult {
        extension_id: sample.extension_id.clone(),
        cohort: sample.cohort,
        over_privilege_ratio_millionths: ratio_millionths_ceil(
            sample.synthesized_capability_count as u64,
            sample.empirically_required_capability_count as u64,
        ),
        authoring_time_reduction_millionths: authoring_time_reduction_millionths(
            sample.manual_authoring_time_ms,
            sample.plas_authoring_time_ms,
        ),
        false_deny_rate_millionths: ratio_millionths_ceil(
            sample.benign_false_deny_count,
            sample.benign_request_count,
        ),
        escrow_event_rate_per_hour_millionths: escrow_event_rate_per_hour_millionths(
            sample.escrow_event_count,
            sample.observation_window_ns,
        ),
        witness_present: sample.witness_present,
    }
}

fn summarize_cohort(
    cohort: PlasBenchmarkCohort,
    entries: &[&PlasBenchmarkExtensionResult],
    thresholds: &PlasBenchmarkThresholds,
) -> PlasBenchmarkCohortSummary {
    let over_priv_values: Vec<u64> = entries
        .iter()
        .map(|entry| entry.over_privilege_ratio_millionths)
        .collect();
    let authoring_values: Vec<i64> = entries
        .iter()
        .map(|entry| entry.authoring_time_reduction_millionths)
        .collect();
    let false_deny_values: Vec<u64> = entries
        .iter()
        .map(|entry| entry.false_deny_rate_millionths)
        .collect();
    let escrow_values: Vec<u64> = entries
        .iter()
        .map(|entry| entry.escrow_event_rate_per_hour_millionths)
        .collect();

    let witness_count = entries.iter().filter(|entry| entry.witness_present).count() as u64;
    let extension_count = entries.len() as u64;

    let mean_over = mean_u64(&over_priv_values);
    let mean_authoring = mean_i64(&authoring_values);
    let mean_false_deny = mean_u64(&false_deny_values);
    let mean_escrow = mean_u64(&escrow_values);
    let witness_coverage = ratio_millionths_floor(witness_count, extension_count);

    let over_privilege_ratio_threshold_pass =
        mean_over <= thresholds.max_over_privilege_ratio_millionths;
    let authoring_time_reduction_threshold_pass =
        mean_authoring >= thresholds.min_authoring_time_reduction_millionths;
    let false_deny_rate_threshold_pass =
        mean_false_deny <= thresholds.max_false_deny_rate_millionths;
    let witness_coverage_threshold_pass =
        witness_coverage >= thresholds.min_witness_coverage_millionths;
    let escrow_event_rate_threshold_pass = thresholds
        .max_escrow_event_rate_per_hour_millionths
        .map(|limit| mean_escrow <= limit)
        .unwrap_or(true);

    let pass = over_privilege_ratio_threshold_pass
        && authoring_time_reduction_threshold_pass
        && false_deny_rate_threshold_pass
        && witness_coverage_threshold_pass
        && escrow_event_rate_threshold_pass;

    PlasBenchmarkCohortSummary {
        cohort,
        extension_count,
        mean_over_privilege_ratio_millionths: mean_over,
        mean_authoring_time_reduction_millionths: mean_authoring,
        mean_false_deny_rate_millionths: mean_false_deny,
        mean_escrow_event_rate_per_hour_millionths: mean_escrow,
        witness_coverage_millionths: witness_coverage,
        over_privilege_ratio_threshold_pass,
        authoring_time_reduction_threshold_pass,
        false_deny_rate_threshold_pass,
        witness_coverage_threshold_pass,
        escrow_event_rate_threshold_pass,
        pass,
    }
}

fn summarize_overall(
    extension_results: &[PlasBenchmarkExtensionResult],
    thresholds: &PlasBenchmarkThresholds,
    required_cohorts_present: bool,
    cohorts_present: Vec<PlasBenchmarkCohort>,
) -> PlasBenchmarkOverallSummary {
    let over_priv_values: Vec<u64> = extension_results
        .iter()
        .map(|entry| entry.over_privilege_ratio_millionths)
        .collect();
    let authoring_values: Vec<i64> = extension_results
        .iter()
        .map(|entry| entry.authoring_time_reduction_millionths)
        .collect();
    let false_deny_values: Vec<u64> = extension_results
        .iter()
        .map(|entry| entry.false_deny_rate_millionths)
        .collect();
    let escrow_values: Vec<u64> = extension_results
        .iter()
        .map(|entry| entry.escrow_event_rate_per_hour_millionths)
        .collect();

    let extension_count = extension_results.len() as u64;
    let witness_count = extension_results
        .iter()
        .filter(|entry| entry.witness_present)
        .count() as u64;

    let mean_over = mean_u64(&over_priv_values);
    let mean_authoring = mean_i64(&authoring_values);
    let mean_false_deny = mean_u64(&false_deny_values);
    let mean_escrow = mean_u64(&escrow_values);
    let witness_coverage = ratio_millionths_floor(witness_count, extension_count);

    let over_privilege_ratio_threshold_pass =
        mean_over <= thresholds.max_over_privilege_ratio_millionths;
    let authoring_time_reduction_threshold_pass =
        mean_authoring >= thresholds.min_authoring_time_reduction_millionths;
    let false_deny_rate_threshold_pass =
        mean_false_deny <= thresholds.max_false_deny_rate_millionths;
    let witness_coverage_threshold_pass =
        witness_coverage >= thresholds.min_witness_coverage_millionths;
    let escrow_event_rate_threshold_pass = thresholds
        .max_escrow_event_rate_per_hour_millionths
        .map(|limit| mean_escrow <= limit)
        .unwrap_or(true);

    PlasBenchmarkOverallSummary {
        extension_count,
        cohorts_present,
        required_cohorts_present,
        mean_over_privilege_ratio_millionths: mean_over,
        mean_authoring_time_reduction_millionths: mean_authoring,
        mean_false_deny_rate_millionths: mean_false_deny,
        mean_escrow_event_rate_per_hour_millionths: mean_escrow,
        witness_coverage_millionths: witness_coverage,
        over_privilege_ratio_threshold_pass,
        authoring_time_reduction_threshold_pass,
        false_deny_rate_threshold_pass,
        witness_coverage_threshold_pass,
        escrow_event_rate_threshold_pass,
    }
}

fn cohort_blockers(
    summary: &PlasBenchmarkCohortSummary,
    thresholds: &PlasBenchmarkThresholds,
) -> Vec<String> {
    let mut blockers = Vec::new();

    if !summary.over_privilege_ratio_threshold_pass {
        blockers.push(format!(
            "cohort `{}` over-privilege ratio {} exceeds max {}",
            summary.cohort.as_str(),
            format_ratio(summary.mean_over_privilege_ratio_millionths),
            format_ratio(thresholds.max_over_privilege_ratio_millionths),
        ));
    }
    if !summary.authoring_time_reduction_threshold_pass {
        blockers.push(format!(
            "cohort `{}` authoring-time reduction {} below min {}",
            summary.cohort.as_str(),
            format_pct_signed(summary.mean_authoring_time_reduction_millionths),
            format_pct_signed(thresholds.min_authoring_time_reduction_millionths),
        ));
    }
    if !summary.false_deny_rate_threshold_pass {
        blockers.push(format!(
            "cohort `{}` false-deny rate {} exceeds max {}",
            summary.cohort.as_str(),
            format_pct(summary.mean_false_deny_rate_millionths),
            format_pct(thresholds.max_false_deny_rate_millionths),
        ));
    }
    if !summary.witness_coverage_threshold_pass {
        blockers.push(format!(
            "cohort `{}` witness coverage {} below min {}",
            summary.cohort.as_str(),
            format_pct(summary.witness_coverage_millionths),
            format_pct(thresholds.min_witness_coverage_millionths),
        ));
    }
    if !summary.escrow_event_rate_threshold_pass
        && let Some(limit) = thresholds.max_escrow_event_rate_per_hour_millionths
    {
        blockers.push(format!(
            "cohort `{}` escrow-event rate {} exceeds max {}",
            summary.cohort.as_str(),
            format_scaled_rate(summary.mean_escrow_event_rate_per_hour_millionths),
            format_scaled_rate(limit),
        ));
    }

    blockers
}

fn make_event(
    request: &PlasBenchmarkBundleRequest,
    event: &str,
    outcome: &str,
    error_code: Option<String>,
    cohort: Option<String>,
    extension_id: Option<String>,
) -> PlasBenchmarkBundleEvent {
    PlasBenchmarkBundleEvent {
        trace_id: request.trace_id.clone(),
        decision_id: request.decision_id.clone(),
        policy_id: request.policy_id.clone(),
        component: PLAS_BENCHMARK_BUNDLE_COMPONENT.to_string(),
        event: event.to_string(),
        outcome: outcome.to_string(),
        error_code,
        cohort,
        extension_id,
    }
}

fn ratio_millionths_floor(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let scaled = (numerator as u128).saturating_mul(MILLION);
    clamp_u128_to_u64(scaled / denominator as u128)
}

fn ratio_millionths_ceil(numerator: u64, denominator: u64) -> u64 {
    if denominator == 0 {
        return u64::MAX;
    }
    let scaled = (numerator as u128).saturating_mul(MILLION);
    let value = scaled.div_ceil(denominator as u128);
    clamp_u128_to_u64(value)
}

fn escrow_event_rate_per_hour_millionths(event_count: u64, observation_window_ns: u64) -> u64 {
    if observation_window_ns == 0 {
        return u64::MAX;
    }

    let numerator = (event_count as u128)
        .saturating_mul(NS_PER_HOUR)
        .saturating_mul(MILLION);
    let value = numerator.div_ceil(observation_window_ns as u128);
    clamp_u128_to_u64(value)
}

fn authoring_time_reduction_millionths(manual_ms: u64, plas_ms: u64) -> i64 {
    if manual_ms == 0 {
        return i64::MIN;
    }
    let delta = manual_ms as i128 - plas_ms as i128;
    let scaled = delta.saturating_mul(MILLION as i128);
    let value = scaled / manual_ms as i128;
    value.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

fn mean_u64(values: &[u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let sum: u128 = values
        .iter()
        .fold(0u128, |acc, value| acc.saturating_add(*value as u128));
    clamp_u128_to_u64(sum / values.len() as u128)
}

fn mean_i64(values: &[i64]) -> i64 {
    if values.is_empty() {
        return 0;
    }
    let sum: i128 = values
        .iter()
        .fold(0i128, |acc, value| acc.saturating_add(*value as i128));
    let value = sum / values.len() as i128;
    value.clamp(i64::MIN as i128, i64::MAX as i128) as i64
}

fn clamp_u128_to_u64(value: u128) -> u64 {
    if value > u64::MAX as u128 {
        u64::MAX
    } else {
        value as u64
    }
}

fn is_regression(previous: &PlasBenchmarkTrendPoint, current: &PlasBenchmarkTrendPoint) -> bool {
    current.mean_over_privilege_ratio_millionths > previous.mean_over_privilege_ratio_millionths
        || current.mean_authoring_time_reduction_millionths
            < previous.mean_authoring_time_reduction_millionths
        || current.mean_false_deny_rate_millionths > previous.mean_false_deny_rate_millionths
        || current.witness_coverage_millionths < previous.witness_coverage_millionths
}

#[allow(clippy::too_many_arguments)]
fn compute_bundle_id(
    request: &PlasBenchmarkBundleRequest,
    publish_allowed: bool,
    blockers: &[String],
    thresholds: &PlasBenchmarkThresholds,
    extension_results: &[PlasBenchmarkExtensionResult],
    cohort_summaries: &[PlasBenchmarkCohortSummary],
    overall_summary: &PlasBenchmarkOverallSummary,
    trend: &[PlasBenchmarkTrendPoint],
    trend_regression_detected: bool,
) -> Result<String, String> {
    #[derive(Serialize)]
    struct HashView<'a> {
        schema_version: &'a str,
        trace_id: &'a str,
        decision_id: &'a str,
        policy_id: &'a str,
        benchmark_run_id: &'a str,
        generated_at_ns: u64,
        publish_allowed: bool,
        blockers: &'a [String],
        thresholds: &'a PlasBenchmarkThresholds,
        extension_results: &'a [PlasBenchmarkExtensionResult],
        cohort_summaries: &'a [PlasBenchmarkCohortSummary],
        overall_summary: &'a PlasBenchmarkOverallSummary,
        trend: &'a [PlasBenchmarkTrendPoint],
        trend_regression_detected: bool,
    }

    let view = HashView {
        schema_version: PLAS_BENCHMARK_BUNDLE_SCHEMA_VERSION,
        trace_id: &request.trace_id,
        decision_id: &request.decision_id,
        policy_id: &request.policy_id,
        benchmark_run_id: &request.benchmark_run_id,
        generated_at_ns: request.generated_at_ns,
        publish_allowed,
        blockers,
        thresholds,
        extension_results,
        cohort_summaries,
        overall_summary,
        trend,
        trend_regression_detected,
    };

    let bytes = serde_json::to_vec(&view).map_err(|err| err.to_string())?;
    let digest = Sha256::digest(bytes);
    Ok(format!("plas-bundle-{}", to_hex(&digest[..12])))
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn format_ratio(millionths: u64) -> String {
    format!("{:.3}x", millionths as f64 / 1_000_000.0)
}

fn format_pct(millionths: u64) -> String {
    format!("{:.3}%", millionths as f64 / 10_000.0)
}

fn format_pct_signed(millionths: i64) -> String {
    format!("{:.3}%", millionths as f64 / 10_000.0)
}

fn format_scaled_rate(millionths: u64) -> String {
    format!("{:.3}", millionths as f64 / 1_000_000.0)
}

fn pass_mark(pass: bool) -> &'static str {
    if pass { "yes" } else { "no" }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── helpers ──────────────────────────────────────────────────────

    fn sample(id: &str, cohort: PlasBenchmarkCohort) -> PlasBenchmarkExtensionSample {
        PlasBenchmarkExtensionSample {
            extension_id: id.to_string(),
            cohort,
            synthesized_capability_count: 5,
            empirically_required_capability_count: 5,
            manual_authoring_time_ms: 1000,
            plas_authoring_time_ms: 200,
            benign_request_count: 10000,
            benign_false_deny_count: 0,
            escrow_event_count: 10,
            observation_window_ns: 3_600_000_000_000, // 1 hour
            witness_present: true,
        }
    }

    fn all_cohort_samples() -> Vec<PlasBenchmarkExtensionSample> {
        vec![
            sample("ext-simple", PlasBenchmarkCohort::Simple),
            sample("ext-complex", PlasBenchmarkCohort::Complex),
            sample("ext-high-risk", PlasBenchmarkCohort::HighRisk),
            sample("ext-boundary", PlasBenchmarkCohort::Boundary),
        ]
    }

    fn make_request() -> PlasBenchmarkBundleRequest {
        PlasBenchmarkBundleRequest {
            trace_id: "t1".to_string(),
            decision_id: "d1".to_string(),
            policy_id: "p1".to_string(),
            benchmark_run_id: "run-1".to_string(),
            generated_at_ns: 1_000_000,
            samples: all_cohort_samples(),
            historical_runs: Vec::new(),
            thresholds: None,
        }
    }

    fn trend_point(
        run_id: &str,
        over_priv: u64,
        authoring: i64,
        false_deny: u64,
        witness: u64,
    ) -> PlasBenchmarkTrendPoint {
        PlasBenchmarkTrendPoint {
            benchmark_run_id: run_id.to_string(),
            generated_at_ns: 1_000_000,
            mean_over_privilege_ratio_millionths: over_priv,
            mean_authoring_time_reduction_millionths: authoring,
            mean_false_deny_rate_millionths: false_deny,
            mean_escrow_event_rate_per_hour_millionths: 0,
            witness_coverage_millionths: witness,
        }
    }

    // ── PlasBenchmarkCohort ─────────────────────────────────────────

    #[test]
    fn cohort_as_str() {
        assert_eq!(PlasBenchmarkCohort::Simple.as_str(), "simple");
        assert_eq!(PlasBenchmarkCohort::Complex.as_str(), "complex");
        assert_eq!(PlasBenchmarkCohort::HighRisk.as_str(), "high_risk");
        assert_eq!(PlasBenchmarkCohort::Boundary.as_str(), "boundary");
    }

    #[test]
    fn cohort_all() {
        let all = PlasBenchmarkCohort::all();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn cohort_ordering() {
        assert!(PlasBenchmarkCohort::Simple < PlasBenchmarkCohort::Complex);
        assert!(PlasBenchmarkCohort::Complex < PlasBenchmarkCohort::HighRisk);
        assert!(PlasBenchmarkCohort::HighRisk < PlasBenchmarkCohort::Boundary);
    }

    #[test]
    fn cohort_serde_roundtrip() {
        for variant in PlasBenchmarkCohort::all() {
            let json = serde_json::to_string(&variant).unwrap();
            let back: PlasBenchmarkCohort = serde_json::from_str(&json).unwrap();
            assert_eq!(variant, back);
        }
    }

    // ── PlasBenchmarkBundleError ────────────────────────────────────

    #[test]
    fn error_display_invalid_input() {
        let err = PlasBenchmarkBundleError::InvalidInput {
            field: "trace_id".to_string(),
            detail: "empty".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains("trace_id"));
        assert!(msg.contains("empty"));
    }

    #[test]
    fn error_display_duplicate() {
        let err = PlasBenchmarkBundleError::DuplicateExtensionId {
            extension_id: "ext-1".to_string(),
        };
        assert!(format!("{err}").contains("ext-1"));
    }

    #[test]
    fn error_stable_codes() {
        assert_eq!(
            PlasBenchmarkBundleError::InvalidInput {
                field: "x".to_string(),
                detail: "y".to_string()
            }
            .stable_code(),
            "FE-PLAS-BENCH-2001"
        );
        assert_eq!(
            PlasBenchmarkBundleError::DuplicateExtensionId {
                extension_id: "x".to_string()
            }
            .stable_code(),
            "FE-PLAS-BENCH-2002"
        );
        assert_eq!(
            PlasBenchmarkBundleError::SerializationFailure("x".to_string()).stable_code(),
            "FE-PLAS-BENCH-2001"
        );
    }

    // ── PlasBenchmarkThresholds ─────────────────────────────────────

    #[test]
    fn thresholds_default_values() {
        let t = PlasBenchmarkThresholds::default();
        assert_eq!(t.max_over_privilege_ratio_millionths, 1_100_000);
        assert_eq!(t.min_authoring_time_reduction_millionths, 700_000);
        assert_eq!(t.max_false_deny_rate_millionths, 5_000);
        assert_eq!(t.min_witness_coverage_millionths, 900_000);
        assert!(t.max_escrow_event_rate_per_hour_millionths.is_none());
        assert!(!t.fail_on_trend_regression);
    }

    #[test]
    fn thresholds_validate_zero_over_privilege() {
        let t = PlasBenchmarkThresholds {
            max_over_privilege_ratio_millionths: 0,
            ..PlasBenchmarkThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_validate_false_deny_over_million() {
        let t = PlasBenchmarkThresholds {
            max_false_deny_rate_millionths: 1_000_001,
            ..PlasBenchmarkThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_validate_witness_coverage_over_million() {
        let t = PlasBenchmarkThresholds {
            min_witness_coverage_millionths: 1_000_001,
            ..PlasBenchmarkThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_validate_escrow_rate_zero() {
        let t = PlasBenchmarkThresholds {
            max_escrow_event_rate_per_hour_millionths: Some(0),
            ..PlasBenchmarkThresholds::default()
        };
        assert!(t.validate().is_err());
    }

    #[test]
    fn thresholds_serde_roundtrip() {
        let t = PlasBenchmarkThresholds::default();
        let json = serde_json::to_string(&t).unwrap();
        let back: PlasBenchmarkThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    // ── PlasBenchmarkExtensionSample validation ─────────────────────

    #[test]
    fn sample_validate_empty_extension_id() {
        let mut s = sample("ext-1", PlasBenchmarkCohort::Simple);
        s.extension_id = "".to_string();
        assert!(s.validate().is_err());
    }

    #[test]
    fn sample_validate_zero_synth_count() {
        let mut s = sample("ext-1", PlasBenchmarkCohort::Simple);
        s.synthesized_capability_count = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn sample_validate_zero_empirical_count() {
        let mut s = sample("ext-1", PlasBenchmarkCohort::Simple);
        s.empirically_required_capability_count = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn sample_validate_zero_manual_time() {
        let mut s = sample("ext-1", PlasBenchmarkCohort::Simple);
        s.manual_authoring_time_ms = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn sample_validate_zero_benign_requests() {
        let mut s = sample("ext-1", PlasBenchmarkCohort::Simple);
        s.benign_request_count = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn sample_validate_false_deny_exceeds_requests() {
        let mut s = sample("ext-1", PlasBenchmarkCohort::Simple);
        s.benign_false_deny_count = 20000;
        assert!(s.validate().is_err());
    }

    #[test]
    fn sample_validate_zero_observation_window() {
        let mut s = sample("ext-1", PlasBenchmarkCohort::Simple);
        s.observation_window_ns = 0;
        assert!(s.validate().is_err());
    }

    #[test]
    fn sample_serde_roundtrip() {
        let s = sample("ext-1", PlasBenchmarkCohort::Simple);
        let json = serde_json::to_string(&s).unwrap();
        let back: PlasBenchmarkExtensionSample = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // ── PlasBenchmarkBundleRequest validation ───────────────────────

    #[test]
    fn request_validate_empty_trace_id() {
        let mut r = make_request();
        r.trace_id = "".to_string();
        assert!(build_plas_benchmark_bundle(&r).is_err());
    }

    #[test]
    fn request_validate_empty_decision_id() {
        let mut r = make_request();
        r.decision_id = "".to_string();
        assert!(build_plas_benchmark_bundle(&r).is_err());
    }

    #[test]
    fn request_validate_empty_policy_id() {
        let mut r = make_request();
        r.policy_id = "".to_string();
        assert!(build_plas_benchmark_bundle(&r).is_err());
    }

    #[test]
    fn request_validate_empty_benchmark_run_id() {
        let mut r = make_request();
        r.benchmark_run_id = "".to_string();
        assert!(build_plas_benchmark_bundle(&r).is_err());
    }

    #[test]
    fn request_validate_no_samples() {
        let mut r = make_request();
        r.samples = Vec::new();
        assert!(build_plas_benchmark_bundle(&r).is_err());
    }

    #[test]
    fn request_validate_duplicate_extension() {
        let mut r = make_request();
        r.samples
            .push(sample("ext-simple", PlasBenchmarkCohort::Simple));
        let err = build_plas_benchmark_bundle(&r).unwrap_err();
        assert!(matches!(
            err,
            PlasBenchmarkBundleError::DuplicateExtensionId { .. }
        ));
    }

    // ── Metric calculation helpers ──────────────────────────────────

    #[test]
    fn ratio_millionths_floor_basic() {
        assert_eq!(ratio_millionths_floor(1, 2), 500_000);
        assert_eq!(ratio_millionths_floor(5, 5), 1_000_000);
        assert_eq!(ratio_millionths_floor(0, 1), 0);
    }

    #[test]
    fn ratio_millionths_floor_zero_denominator() {
        assert_eq!(ratio_millionths_floor(1, 0), u64::MAX);
    }

    #[test]
    fn ratio_millionths_ceil_basic() {
        assert_eq!(ratio_millionths_ceil(5, 5), 1_000_000);
        assert_eq!(ratio_millionths_ceil(0, 1), 0);
    }

    #[test]
    fn ratio_millionths_ceil_rounds_up() {
        // 1/3 = 333333.33... → ceil = 333334
        assert_eq!(ratio_millionths_ceil(1, 3), 333_334);
    }

    #[test]
    fn authoring_time_reduction_basic() {
        // manual=1000, plas=200 → (1000-200)/1000 = 80% = 800_000 millionths
        assert_eq!(authoring_time_reduction_millionths(1000, 200), 800_000);
    }

    #[test]
    fn authoring_time_reduction_no_change() {
        assert_eq!(authoring_time_reduction_millionths(1000, 1000), 0);
    }

    #[test]
    fn authoring_time_reduction_negative() {
        // plas takes LONGER: manual=1000, plas=2000 → -100% = -1_000_000
        assert_eq!(authoring_time_reduction_millionths(1000, 2000), -1_000_000);
    }

    #[test]
    fn authoring_time_reduction_zero_manual() {
        assert_eq!(authoring_time_reduction_millionths(0, 100), i64::MIN);
    }

    #[test]
    fn escrow_event_rate_basic() {
        // 10 events in 1 hour = 10.0 events/hour = 10_000_000 millionths
        let one_hour = 3_600_000_000_000u64;
        assert_eq!(
            escrow_event_rate_per_hour_millionths(10, one_hour),
            10_000_000
        );
    }

    #[test]
    fn escrow_event_rate_zero_window() {
        assert_eq!(escrow_event_rate_per_hour_millionths(10, 0), u64::MAX);
    }

    #[test]
    fn mean_u64_basic() {
        assert_eq!(mean_u64(&[100, 200, 300]), 200);
    }

    #[test]
    fn mean_u64_empty() {
        assert_eq!(mean_u64(&[]), 0);
    }

    #[test]
    fn mean_i64_basic() {
        assert_eq!(mean_i64(&[-100, 0, 100]), 0);
    }

    #[test]
    fn mean_i64_empty() {
        assert_eq!(mean_i64(&[]), 0);
    }

    // ── is_regression ───────────────────────────────────────────────

    #[test]
    fn regression_detected_over_privilege_worse() {
        let prev = trend_point("run-0", 1_000_000, 800_000, 1_000, 1_000_000);
        let curr = trend_point("run-1", 1_100_000, 800_000, 1_000, 1_000_000);
        assert!(is_regression(&prev, &curr));
    }

    #[test]
    fn regression_detected_authoring_worse() {
        let prev = trend_point("run-0", 1_000_000, 800_000, 1_000, 1_000_000);
        let curr = trend_point("run-1", 1_000_000, 700_000, 1_000, 1_000_000);
        assert!(is_regression(&prev, &curr));
    }

    #[test]
    fn regression_detected_false_deny_worse() {
        let prev = trend_point("run-0", 1_000_000, 800_000, 1_000, 1_000_000);
        let curr = trend_point("run-1", 1_000_000, 800_000, 2_000, 1_000_000);
        assert!(is_regression(&prev, &curr));
    }

    #[test]
    fn regression_detected_witness_coverage_worse() {
        let prev = trend_point("run-0", 1_000_000, 800_000, 1_000, 1_000_000);
        let curr = trend_point("run-1", 1_000_000, 800_000, 1_000, 900_000);
        assert!(is_regression(&prev, &curr));
    }

    #[test]
    fn no_regression_when_same() {
        let prev = trend_point("run-0", 1_000_000, 800_000, 1_000, 1_000_000);
        let curr = trend_point("run-1", 1_000_000, 800_000, 1_000, 1_000_000);
        assert!(!is_regression(&prev, &curr));
    }

    #[test]
    fn no_regression_when_better() {
        let prev = trend_point("run-0", 1_100_000, 700_000, 2_000, 900_000);
        let curr = trend_point("run-1", 1_000_000, 800_000, 1_000, 1_000_000);
        assert!(!is_regression(&prev, &curr));
    }

    // ── build_plas_benchmark_bundle: passing case ───────────────────

    #[test]
    fn build_passing_bundle() {
        let r = make_request();
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(decision.publish_allowed);
        assert!(decision.blockers.is_empty());
        assert_eq!(decision.extension_results.len(), 4);
        assert_eq!(decision.cohort_summaries.len(), 4);
        assert_eq!(
            decision.schema_version,
            "franken-engine.plas-benchmark-bundle.v1"
        );
        assert!(!decision.trend_regression_detected);
    }

    #[test]
    fn build_passing_bundle_ids() {
        let r = make_request();
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert_eq!(decision.benchmark_run_id, "run-1");
        assert_eq!(decision.generated_at_ns, 1_000_000);
        assert!(decision.bundle_id.starts_with("plas-bundle-"));
    }

    #[test]
    fn build_bundle_deterministic() {
        let r = make_request();
        let d1 = build_plas_benchmark_bundle(&r).unwrap();
        let d2 = build_plas_benchmark_bundle(&r).unwrap();
        assert_eq!(d1.bundle_id, d2.bundle_id);
    }

    #[test]
    fn build_bundle_events_present() {
        let r = make_request();
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.event == "plas_benchmark_bundle_started")
        );
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.event == "plas_benchmark_bundle_decision")
        );
        assert!(
            decision
                .events
                .iter()
                .any(|e| e.event == "trend_regression_check")
        );
        assert!(
            decision
                .events
                .iter()
                .all(|e| e.component == "plas_benchmark_bundle")
        );
    }

    // ── build: missing cohort coverage ──────────────────────────────

    #[test]
    fn build_missing_cohorts_blocked() {
        let mut r = make_request();
        r.samples = vec![sample("ext-1", PlasBenchmarkCohort::Simple)];
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("missing representative cohort"))
        );
    }

    // ── build: over-privilege ratio failure ──────────────────────────

    #[test]
    fn build_over_privilege_ratio_fails() {
        let mut r = make_request();
        // Make all samples have over-privilege: synth=20, empirical=5 → ratio = 4.0
        for s in &mut r.samples {
            s.synthesized_capability_count = 20;
            s.empirically_required_capability_count = 5;
        }
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("over-privilege ratio"))
        );
    }

    // ── build: authoring time reduction failure ─────────────────────

    #[test]
    fn build_authoring_time_reduction_fails() {
        let mut r = make_request();
        // PLAS slower than manual
        for s in &mut r.samples {
            s.plas_authoring_time_ms = 2000;
            s.manual_authoring_time_ms = 1000;
        }
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("authoring-time reduction"))
        );
    }

    // ── build: false deny rate failure ──────────────────────────────

    #[test]
    fn build_false_deny_rate_fails() {
        let mut r = make_request();
        for s in &mut r.samples {
            s.benign_false_deny_count = 500; // 5% of 10000 = 50_000 millionths > 5_000
        }
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("false-deny rate"))
        );
    }

    // ── build: witness coverage failure ─────────────────────────────

    #[test]
    fn build_witness_coverage_fails() {
        let mut r = make_request();
        for s in &mut r.samples {
            s.witness_present = false;
        }
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("witness coverage"))
        );
    }

    // ── build: escrow event rate threshold ──────────────────────────

    #[test]
    fn build_escrow_rate_passes_when_no_threshold() {
        let r = make_request();
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(decision.overall_summary.escrow_event_rate_threshold_pass);
    }

    #[test]
    fn build_escrow_rate_fails_when_exceeded() {
        let mut r = make_request();
        r.thresholds = Some(PlasBenchmarkThresholds {
            max_escrow_event_rate_per_hour_millionths: Some(1), // basically 0
            ..PlasBenchmarkThresholds::default()
        });
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(!decision.overall_summary.escrow_event_rate_threshold_pass);
    }

    // ── build: trend regression ─────────────────────────────────────

    #[test]
    fn build_trend_regression_warn_no_block() {
        let mut r = make_request();
        // Previous run was better across the board
        r.historical_runs = vec![PlasBenchmarkTrendPoint {
            benchmark_run_id: "run-0".to_string(),
            generated_at_ns: 500_000,
            mean_over_privilege_ratio_millionths: 500_000, // better (lower)
            mean_authoring_time_reduction_millionths: 900_000, // better (higher)
            mean_false_deny_rate_millionths: 0,            // better (lower)
            mean_escrow_event_rate_per_hour_millionths: 0,
            witness_coverage_millionths: 1_000_000, // same
        }];
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(decision.trend_regression_detected);
        // Default fail_on_trend_regression = false, so should still pass
        assert!(decision.publish_allowed);
    }

    #[test]
    fn build_trend_regression_blocks_when_fail_on_regression() {
        let mut r = make_request();
        r.thresholds = Some(PlasBenchmarkThresholds {
            fail_on_trend_regression: true,
            ..PlasBenchmarkThresholds::default()
        });
        r.historical_runs = vec![PlasBenchmarkTrendPoint {
            benchmark_run_id: "run-0".to_string(),
            generated_at_ns: 500_000,
            mean_over_privilege_ratio_millionths: 500_000,
            mean_authoring_time_reduction_millionths: 900_000,
            mean_false_deny_rate_millionths: 0,
            mean_escrow_event_rate_per_hour_millionths: 0,
            witness_coverage_millionths: 1_000_000,
        }];
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(decision.trend_regression_detected);
        assert!(!decision.publish_allowed);
        assert!(
            decision
                .blockers
                .iter()
                .any(|b| b.contains("trend regression"))
        );
    }

    #[test]
    fn build_no_trend_regression_when_no_history() {
        let r = make_request();
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(!decision.trend_regression_detected);
    }

    // ── build: trend includes current point ─────────────────────────

    #[test]
    fn build_trend_includes_current_run() {
        let r = make_request();
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert_eq!(decision.trend.len(), 1);
        assert_eq!(decision.trend[0].benchmark_run_id, "run-1");
    }

    // ── markdown report ─────────────────────────────────────────────

    #[test]
    fn markdown_report_contains_key_sections() {
        let r = make_request();
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        let md = decision.to_markdown_report();
        assert!(md.contains("# PLAS Benchmark Bundle"));
        assert!(md.contains("## Overall Metrics"));
        assert!(md.contains("## Cohort Summary"));
        assert!(md.contains("## Extension Metrics"));
        assert!(md.contains("## Trend"));
        assert!(md.contains("ALLOW"));
    }

    #[test]
    fn markdown_report_deny_case() {
        let mut r = make_request();
        r.samples = vec![sample("ext-1", PlasBenchmarkCohort::Simple)];
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        let md = decision.to_markdown_report();
        assert!(md.contains("DENY"));
        assert!(md.contains("## Blockers"));
    }

    // ── to_json_pretty ──────────────────────────────────────────────

    #[test]
    fn to_json_pretty_roundtrips() {
        let r = make_request();
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        let json = decision.to_json_pretty().unwrap();
        let back: PlasBenchmarkBundleDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
    }

    // ── format helpers ──────────────────────────────────────────────

    #[test]
    fn format_ratio_basic() {
        assert_eq!(format_ratio(1_000_000), "1.000x");
        assert_eq!(format_ratio(1_100_000), "1.100x");
    }

    #[test]
    fn format_pct_basic() {
        assert_eq!(format_pct(1_000_000), "100.000%");
        assert_eq!(format_pct(5_000), "0.500%");
    }

    #[test]
    fn format_pct_signed_negative() {
        assert_eq!(format_pct_signed(-1_000_000), "-100.000%");
    }

    #[test]
    fn pass_mark_values() {
        assert_eq!(pass_mark(true), "yes");
        assert_eq!(pass_mark(false), "no");
    }

    // ── overall summary cohorts_present ─────────────────────────────

    #[test]
    fn overall_summary_cohorts_present() {
        let r = make_request();
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        assert!(decision.overall_summary.required_cohorts_present);
        assert_eq!(decision.overall_summary.cohorts_present.len(), 4);
    }

    // ── cohort summary pass/fail ────────────────────────────────────

    #[test]
    fn cohort_summary_all_pass() {
        let r = make_request();
        let decision = build_plas_benchmark_bundle(&r).unwrap();
        for summary in &decision.cohort_summaries {
            assert!(summary.pass);
        }
    }

    // ── extension results computed ──────────────────────────────────

    #[test]
    fn extension_result_over_privilege_ratio() {
        let s = sample("ext-1", PlasBenchmarkCohort::Simple);
        let result = sample_to_result(&s);
        // synth=5, empirical=5 → ratio = 1.0 = 1_000_000 millionths
        assert_eq!(result.over_privilege_ratio_millionths, 1_000_000);
    }

    #[test]
    fn extension_result_authoring_time_reduction() {
        let s = sample("ext-1", PlasBenchmarkCohort::Simple);
        let result = sample_to_result(&s);
        // manual=1000, plas=200 → (1000-200)/1000 = 80% = 800_000
        assert_eq!(result.authoring_time_reduction_millionths, 800_000);
    }

    #[test]
    fn extension_result_false_deny_rate_zero() {
        let s = sample("ext-1", PlasBenchmarkCohort::Simple);
        let result = sample_to_result(&s);
        assert_eq!(result.false_deny_rate_millionths, 0);
    }

    // -- Enrichment: PearlTower 2026-02-26 --

    #[test]
    fn plas_benchmark_cohort_serde_all_variants() {
        for v in PlasBenchmarkCohort::all() {
            let json = serde_json::to_string(&v).unwrap();
            let back: PlasBenchmarkCohort = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
        }
    }

    #[test]
    fn plas_benchmark_cohort_as_str_distinct() {
        let set: std::collections::BTreeSet<&str> = PlasBenchmarkCohort::all()
            .iter()
            .map(|c| c.as_str())
            .collect();
        assert_eq!(set.len(), 4);
    }

    #[test]
    fn plas_benchmark_cohort_ordering() {
        assert!(PlasBenchmarkCohort::Simple < PlasBenchmarkCohort::Complex);
        assert!(PlasBenchmarkCohort::Complex < PlasBenchmarkCohort::HighRisk);
        assert!(PlasBenchmarkCohort::HighRisk < PlasBenchmarkCohort::Boundary);
    }

    #[test]
    fn plas_benchmark_bundle_error_is_std_error() {
        let e = PlasBenchmarkBundleError::InvalidInput {
            field: "f".into(),
            detail: "d".into(),
        };
        let _: &dyn std::error::Error = &e;
    }

    #[test]
    fn plas_benchmark_bundle_error_display_distinct() {
        let variants: Vec<PlasBenchmarkBundleError> = vec![
            PlasBenchmarkBundleError::InvalidInput {
                field: "f".into(),
                detail: "d".into(),
            },
            PlasBenchmarkBundleError::DuplicateExtensionId {
                extension_id: "x".into(),
            },
            PlasBenchmarkBundleError::SerializationFailure("err".into()),
        ];
        let set: std::collections::BTreeSet<String> =
            variants.iter().map(|e| format!("{e}")).collect();
        assert_eq!(set.len(), variants.len());
    }
}
