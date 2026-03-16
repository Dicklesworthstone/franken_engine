//! Deterministic benchmark split gate for Section 10.13 item 17 (`bd-1rdj`).
//!
//! This module isolates control-plane integration overhead from VM hot-loop
//! behavior and enforces bounded regressions for:
//! - Cx threading
//! - decision contracts
//! - evidence emission
//! - full integration

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{self, CanonicalValue};
use crate::hash_tiers::ContentHash;

const CONTROL_PLANE_BENCHMARK_SPLIT_DOMAIN: &[u8] =
    b"FrankenEngine.ControlPlaneBenchmarkSplitGate.v1";
pub const CONTROL_PLANE_REAL_CONTEXT_OVERHEAD_REPORT_FILE: &str =
    "control_plane_real_context_overhead_report.json";
pub const BENCHMARK_SPLIT_DELTA_REPORT_FILE: &str = "benchmark_split_delta_report.json";
pub const CONTROL_PLANE_REAL_CONTEXT_OVERHEAD_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.control-plane-benchmark-split.real-context-overhead-report.v1";
pub const BENCHMARK_SPLIT_DELTA_REPORT_SCHEMA_VERSION: &str =
    "franken-engine.control-plane-benchmark-split.delta-report.v1";
pub const CONTROL_PLANE_BENCHMARK_SPLIT_REPORT_COMPONENT: &str =
    "control_plane_benchmark_split_gate";

static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    *ContentHash::compute(data).as_bytes()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Benchmark split phases for control-plane integration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BenchmarkSplit {
    Baseline,
    CxThreading,
    DecisionContracts,
    EvidenceEmission,
    FullIntegration,
}

impl BenchmarkSplit {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Baseline => "baseline",
            Self::CxThreading => "cx_threading",
            Self::DecisionContracts => "decision_contracts",
            Self::EvidenceEmission => "evidence_emission",
            Self::FullIntegration => "full_integration",
        }
    }

    fn all_required() -> BTreeSet<Self> {
        BTreeSet::from([
            Self::Baseline,
            Self::CxThreading,
            Self::DecisionContracts,
            Self::EvidenceEmission,
            Self::FullIntegration,
        ])
    }
}

impl fmt::Display for BenchmarkSplit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Deterministic latency summary in nanoseconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyStatsNs {
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
}

impl LatencyStatsNs {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert("p50_ns".to_string(), CanonicalValue::U64(self.p50_ns));
        map.insert("p95_ns".to_string(), CanonicalValue::U64(self.p95_ns));
        map.insert("p99_ns".to_string(), CanonicalValue::U64(self.p99_ns));
        CanonicalValue::Map(map)
    }
}

/// Benchmark metrics per split.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitBenchmarkMetrics {
    pub throughput_ops_per_sec: u64,
    pub latency_ns: LatencyStatsNs,
    /// Delta from baseline peak RSS in bytes.
    pub peak_rss_delta_bytes: u64,
}

impl SplitBenchmarkMetrics {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "throughput_ops_per_sec".to_string(),
            CanonicalValue::U64(self.throughput_ops_per_sec),
        );
        map.insert("latency_ns".to_string(), self.latency_ns.canonical_value());
        map.insert(
            "peak_rss_delta_bytes".to_string(),
            CanonicalValue::U64(self.peak_rss_delta_bytes),
        );
        CanonicalValue::Map(map)
    }
}

/// Deterministic snapshot for one benchmark run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitSnapshot {
    pub snapshot_id: String,
    pub benchmark_run_id: String,
    pub split_metrics: BTreeMap<BenchmarkSplit, SplitBenchmarkMetrics>,
    /// Baseline throughput samples used for CV stability checks.
    pub baseline_throughput_runs_ops_per_sec: Vec<u64>,
}

impl BenchmarkSplitSnapshot {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "snapshot_id".to_string(),
            CanonicalValue::String(self.snapshot_id.clone()),
        );
        map.insert(
            "benchmark_run_id".to_string(),
            CanonicalValue::String(self.benchmark_run_id.clone()),
        );

        let mut split_map = BTreeMap::new();
        for (split, metrics) in &self.split_metrics {
            split_map.insert(split.as_str().to_string(), metrics.canonical_value());
        }
        map.insert("split_metrics".to_string(), CanonicalValue::Map(split_map));

        let mut baseline_runs = self.baseline_throughput_runs_ops_per_sec.clone();
        baseline_runs.sort_unstable();
        map.insert(
            "baseline_throughput_runs_ops_per_sec".to_string(),
            CanonicalValue::Array(baseline_runs.into_iter().map(CanonicalValue::U64).collect()),
        );

        CanonicalValue::Map(map)
    }

    pub fn snapshot_hash(&self) -> [u8; 32] {
        hash_bytes(&deterministic_serde::encode_value(&self.canonical_value()))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitGateInput {
    pub trace_id: String,
    pub policy_id: String,
    pub previous_snapshot: BenchmarkSplitSnapshot,
    pub candidate_snapshot: BenchmarkSplitSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitThresholds {
    pub min_baseline_runs: usize,
    pub max_baseline_cv_millionths: u64,
    pub max_cx_throughput_regression_millionths: u64,
    pub max_decision_latency_regression_millionths: u64,
    pub max_evidence_throughput_regression_millionths: u64,
    pub max_full_integration_throughput_regression_millionths: u64,
    pub max_peak_rss_delta_bytes: BTreeMap<BenchmarkSplit, u64>,
    pub max_previous_run_throughput_regression_millionths: BTreeMap<BenchmarkSplit, u64>,
    pub max_previous_run_latency_regression_millionths: u64,
}

impl Default for BenchmarkSplitThresholds {
    fn default() -> Self {
        let mut max_peak_rss_delta_bytes = BTreeMap::new();
        max_peak_rss_delta_bytes.insert(BenchmarkSplit::Baseline, 0);
        max_peak_rss_delta_bytes.insert(BenchmarkSplit::CxThreading, 16 * 1024 * 1024);
        max_peak_rss_delta_bytes.insert(BenchmarkSplit::DecisionContracts, 32 * 1024 * 1024);
        max_peak_rss_delta_bytes.insert(BenchmarkSplit::EvidenceEmission, 48 * 1024 * 1024);
        max_peak_rss_delta_bytes.insert(BenchmarkSplit::FullIntegration, 64 * 1024 * 1024);

        let mut max_previous_run_throughput_regression_millionths = BTreeMap::new();
        max_previous_run_throughput_regression_millionths.insert(BenchmarkSplit::Baseline, 50_000);
        max_previous_run_throughput_regression_millionths
            .insert(BenchmarkSplit::CxThreading, 10_000);
        max_previous_run_throughput_regression_millionths
            .insert(BenchmarkSplit::DecisionContracts, 20_000);
        max_previous_run_throughput_regression_millionths
            .insert(BenchmarkSplit::EvidenceEmission, 20_000);
        max_previous_run_throughput_regression_millionths
            .insert(BenchmarkSplit::FullIntegration, 50_000);

        Self {
            min_baseline_runs: 10,
            max_baseline_cv_millionths: 50_000,
            max_cx_throughput_regression_millionths: 10_000,
            max_decision_latency_regression_millionths: 50_000,
            max_evidence_throughput_regression_millionths: 20_000,
            max_full_integration_throughput_regression_millionths: 50_000,
            max_peak_rss_delta_bytes,
            max_previous_run_throughput_regression_millionths,
            max_previous_run_latency_regression_millionths: 50_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BenchmarkSplitFailureCode {
    MissingSplitMetrics,
    InsufficientBaselineRuns,
    BaselineVarianceExceeded,
    InvalidMetric,
    ThroughputRegressionExceeded,
    LatencyRegressionExceeded,
    MemoryOverheadExceeded,
    PreviousRunRegressionExceeded,
}

impl fmt::Display for BenchmarkSplitFailureCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingSplitMetrics => f.write_str("missing_split_metrics"),
            Self::InsufficientBaselineRuns => f.write_str("insufficient_baseline_runs"),
            Self::BaselineVarianceExceeded => f.write_str("baseline_variance_exceeded"),
            Self::InvalidMetric => f.write_str("invalid_metric"),
            Self::ThroughputRegressionExceeded => f.write_str("throughput_regression_exceeded"),
            Self::LatencyRegressionExceeded => f.write_str("latency_regression_exceeded"),
            Self::MemoryOverheadExceeded => f.write_str("memory_overhead_exceeded"),
            Self::PreviousRunRegressionExceeded => f.write_str("previous_run_regression_exceeded"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitFinding {
    pub code: BenchmarkSplitFailureCode,
    pub split: Option<BenchmarkSplit>,
    pub metric: Option<String>,
    pub detail: String,
    pub observed_millionths: Option<u64>,
    pub threshold_millionths: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitBenchmarkEvaluation {
    pub split: BenchmarkSplit,
    pub previous_metrics: SplitBenchmarkMetrics,
    pub candidate_metrics: SplitBenchmarkMetrics,
    pub throughput_regression_vs_previous_millionths: u64,
    pub latency_p95_regression_vs_previous_millionths: u64,
    pub latency_p99_regression_vs_previous_millionths: u64,
    pub pass: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitLogEvent {
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    pub error_code: Option<String>,
    pub split: Option<String>,
    pub metric: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitGateDecision {
    pub decision_id: String,
    pub pass: bool,
    pub rollback_required: bool,
    pub previous_snapshot_hash: [u8; 32],
    pub candidate_snapshot_hash: [u8; 32],
    pub baseline_cv_millionths: Option<u64>,
    pub evaluations: Vec<SplitBenchmarkEvaluation>,
    pub findings: Vec<BenchmarkSplitFinding>,
    pub logs: Vec<BenchmarkSplitLogEvent>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkImpactVisibility {
    UserVisible,
    OperatorVisible,
    Mixed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkImpactSeverity {
    Transparent,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkImpactClass {
    Transparent,
    Noticeable,
    ActionRequired,
    ReleaseBlocking,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkDeltaReferenceKind {
    PreviousStage,
    ShortcutBaseline,
    PreviousSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkBaselineStabilityReport {
    pub observed_run_count: usize,
    pub required_run_count: usize,
    pub observed_cv_millionths: Option<u64>,
    pub max_cv_millionths: u64,
    pub pass: bool,
    pub severity: BenchmarkImpactSeverity,
    pub operator_impact_class: BenchmarkImpactClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitDeltaSummary {
    pub reference_kind: BenchmarkDeltaReferenceKind,
    pub reference_split: BenchmarkSplit,
    pub candidate_split: BenchmarkSplit,
    pub throughput_ops_per_sec_delta: i64,
    pub throughput_regression_millionths: u64,
    pub latency_p95_ns_delta: i64,
    pub latency_p95_regression_millionths: u64,
    pub latency_p99_ns_delta: i64,
    pub latency_p99_regression_millionths: u64,
    pub peak_rss_delta_bytes: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkOverheadComponentAttribution {
    pub component_id: String,
    pub visibility: BenchmarkImpactVisibility,
    pub reference_split: BenchmarkSplit,
    pub candidate_split: BenchmarkSplit,
    pub throughput_ops_per_sec_delta: i64,
    pub throughput_regression_millionths: u64,
    pub latency_p95_ns_delta: i64,
    pub latency_p95_regression_millionths: u64,
    pub latency_p99_ns_delta: i64,
    pub latency_p99_regression_millionths: u64,
    pub peak_rss_delta_bytes: i64,
    pub primary_threshold_metric: Option<String>,
    pub primary_threshold_millionths: Option<u64>,
    pub threshold_exceeded: bool,
    pub severity: BenchmarkImpactSeverity,
    pub impact_class: BenchmarkImpactClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneRealContextOverheadReport {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub previous_snapshot_id: String,
    pub candidate_snapshot_id: String,
    pub shortcut_reference_split: BenchmarkSplit,
    pub corrected_real_context_split: BenchmarkSplit,
    pub bounded_overhead: bool,
    pub rollback_required: bool,
    pub severity: BenchmarkImpactSeverity,
    pub user_impact_class: BenchmarkImpactClass,
    pub operator_impact_class: BenchmarkImpactClass,
    pub baseline_stability: BenchmarkBaselineStabilityReport,
    pub corrected_path_delta_vs_shortcut: BenchmarkSplitDeltaSummary,
    pub user_visible_delta: BenchmarkSplitDeltaSummary,
    pub operator_visible_delta: BenchmarkSplitDeltaSummary,
    pub corrected_path_components: Vec<BenchmarkOverheadComponentAttribution>,
    pub findings: Vec<BenchmarkSplitFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitDeltaEntry {
    pub reference_kind: BenchmarkDeltaReferenceKind,
    pub visibility: BenchmarkImpactVisibility,
    pub reference_split: BenchmarkSplit,
    pub candidate_split: BenchmarkSplit,
    pub throughput_ops_per_sec_delta: i64,
    pub throughput_regression_millionths: u64,
    pub latency_p95_ns_delta: i64,
    pub latency_p95_regression_millionths: u64,
    pub latency_p99_ns_delta: i64,
    pub latency_p99_regression_millionths: u64,
    pub peak_rss_delta_bytes: i64,
    pub severity: BenchmarkImpactSeverity,
    pub user_impact_class: BenchmarkImpactClass,
    pub operator_impact_class: BenchmarkImpactClass,
    pub finding_codes: Vec<BenchmarkSplitFailureCode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkSplitDeltaReport {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub bounded_overhead: bool,
    pub rollback_required: bool,
    pub severity: BenchmarkImpactSeverity,
    pub user_impact_class: BenchmarkImpactClass,
    pub operator_impact_class: BenchmarkImpactClass,
    pub previous_stage_deltas: Vec<BenchmarkSplitDeltaEntry>,
    pub shortcut_baseline_deltas: Vec<BenchmarkSplitDeltaEntry>,
    pub previous_snapshot_deltas: Vec<BenchmarkSplitDeltaEntry>,
    pub failing_findings: Vec<BenchmarkSplitFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneBenchmarkSplitReportArtifacts {
    pub out_dir: PathBuf,
    pub control_plane_real_context_overhead_report_path: PathBuf,
    pub benchmark_split_delta_report_path: PathBuf,
    pub decision_id: String,
    pub pass: bool,
    pub rollback_required: bool,
}

#[derive(Debug)]
pub enum ControlPlaneBenchmarkSplitReportWriteError {
    Io { path: PathBuf, source: io::Error },
    Json { path: PathBuf, reason: String },
}

impl fmt::Display for ControlPlaneBenchmarkSplitReportWriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => {
                write!(f, "I/O error for {}: {source}", path.display())
            }
            Self::Json { path, reason } => {
                write!(f, "failed to serialize {}: {reason}", path.display())
            }
        }
    }
}

impl std::error::Error for ControlPlaneBenchmarkSplitReportWriteError {}

fn throughput_regression_millionths(reference: u64, candidate: u64) -> u64 {
    if reference == 0 {
        return u64::MAX;
    }
    if candidate >= reference {
        return 0;
    }
    let delta = reference.saturating_sub(candidate);
    ((delta as u128 * 1_000_000) / reference as u128) as u64
}

fn latency_regression_millionths(reference: u64, candidate: u64) -> u64 {
    if reference == 0 {
        return u64::MAX;
    }
    if candidate <= reference {
        return 0;
    }
    let delta = candidate.saturating_sub(reference);
    ((delta as u128 * 1_000_000) / reference as u128) as u64
}

fn coefficient_of_variation_millionths(samples: &[u64]) -> Option<u64> {
    if samples.is_empty() {
        return None;
    }

    let len = samples.len() as f64;
    let mean = samples.iter().map(|value| *value as f64).sum::<f64>() / len;
    if mean == 0.0 {
        return None;
    }

    let variance = samples
        .iter()
        .map(|value| {
            let delta = *value as f64 - mean;
            delta * delta
        })
        .sum::<f64>()
        / len;
    let stddev = variance.sqrt();
    Some(((stddev / mean) * 1_000_000.0).round() as u64)
}

fn decision_canonical_value(
    input: &BenchmarkSplitGateInput,
    previous_hash: [u8; 32],
    candidate_hash: [u8; 32],
    pass: bool,
    baseline_cv_millionths: Option<u64>,
    evaluations: &[SplitBenchmarkEvaluation],
    findings: &[BenchmarkSplitFinding],
) -> CanonicalValue {
    let mut map = BTreeMap::new();
    map.insert(
        "trace_id".to_string(),
        CanonicalValue::String(input.trace_id.clone()),
    );
    map.insert(
        "policy_id".to_string(),
        CanonicalValue::String(input.policy_id.clone()),
    );
    map.insert("pass".to_string(), CanonicalValue::Bool(pass));
    map.insert(
        "previous_snapshot_hash".to_string(),
        CanonicalValue::Bytes(previous_hash.to_vec()),
    );
    map.insert(
        "candidate_snapshot_hash".to_string(),
        CanonicalValue::Bytes(candidate_hash.to_vec()),
    );
    map.insert(
        "baseline_cv_millionths".to_string(),
        match baseline_cv_millionths {
            Some(value) => CanonicalValue::U64(value),
            None => CanonicalValue::Null,
        },
    );

    map.insert(
        "evaluations".to_string(),
        CanonicalValue::Array(
            evaluations
                .iter()
                .map(|evaluation| {
                    let mut eval_map = BTreeMap::new();
                    eval_map.insert(
                        "split".to_string(),
                        CanonicalValue::String(evaluation.split.as_str().to_string()),
                    );
                    eval_map.insert("pass".to_string(), CanonicalValue::Bool(evaluation.pass));
                    eval_map.insert(
                        "throughput_regression_vs_previous_millionths".to_string(),
                        CanonicalValue::U64(
                            evaluation.throughput_regression_vs_previous_millionths,
                        ),
                    );
                    eval_map.insert(
                        "latency_p95_regression_vs_previous_millionths".to_string(),
                        CanonicalValue::U64(
                            evaluation.latency_p95_regression_vs_previous_millionths,
                        ),
                    );
                    eval_map.insert(
                        "latency_p99_regression_vs_previous_millionths".to_string(),
                        CanonicalValue::U64(
                            evaluation.latency_p99_regression_vs_previous_millionths,
                        ),
                    );
                    eval_map.insert(
                        "candidate_metrics".to_string(),
                        evaluation.candidate_metrics.canonical_value(),
                    );
                    eval_map.insert(
                        "previous_metrics".to_string(),
                        evaluation.previous_metrics.canonical_value(),
                    );
                    CanonicalValue::Map(eval_map)
                })
                .collect(),
        ),
    );

    map.insert(
        "findings".to_string(),
        CanonicalValue::Array(
            findings
                .iter()
                .map(|finding| {
                    let mut finding_map = BTreeMap::new();
                    finding_map.insert(
                        "code".to_string(),
                        CanonicalValue::String(finding.code.to_string()),
                    );
                    finding_map.insert(
                        "detail".to_string(),
                        CanonicalValue::String(finding.detail.clone()),
                    );
                    finding_map.insert(
                        "metric".to_string(),
                        match &finding.metric {
                            Some(metric) => CanonicalValue::String(metric.clone()),
                            None => CanonicalValue::Null,
                        },
                    );
                    finding_map.insert(
                        "split".to_string(),
                        match finding.split {
                            Some(split) => CanonicalValue::String(split.as_str().to_string()),
                            None => CanonicalValue::Null,
                        },
                    );
                    finding_map.insert(
                        "observed_millionths".to_string(),
                        match finding.observed_millionths {
                            Some(value) => CanonicalValue::U64(value),
                            None => CanonicalValue::Null,
                        },
                    );
                    finding_map.insert(
                        "threshold_millionths".to_string(),
                        match finding.threshold_millionths {
                            Some(value) => CanonicalValue::U64(value),
                            None => CanonicalValue::Null,
                        },
                    );
                    CanonicalValue::Map(finding_map)
                })
                .collect(),
        ),
    );

    CanonicalValue::Map(map)
}

/// Evaluate control-plane benchmark split inputs and produce deterministic gate output.
pub fn evaluate_control_plane_benchmark_split(
    input: &BenchmarkSplitGateInput,
    thresholds: &BenchmarkSplitThresholds,
) -> BenchmarkSplitGateDecision {
    let previous_hash = input.previous_snapshot.snapshot_hash();
    let candidate_hash = input.candidate_snapshot.snapshot_hash();

    let mut findings = Vec::new();
    let required_splits = BenchmarkSplit::all_required();

    for split in &required_splits {
        if !input.previous_snapshot.split_metrics.contains_key(split) {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::MissingSplitMetrics,
                split: Some(*split),
                metric: None,
                detail: format!("previous snapshot missing split `{split}`"),
                observed_millionths: None,
                threshold_millionths: None,
            });
        }
        if !input.candidate_snapshot.split_metrics.contains_key(split) {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::MissingSplitMetrics,
                split: Some(*split),
                metric: None,
                detail: format!("candidate snapshot missing split `{split}`"),
                observed_millionths: None,
                threshold_millionths: None,
            });
        }
    }

    let baseline_cv_millionths = if input
        .candidate_snapshot
        .baseline_throughput_runs_ops_per_sec
        .len()
        < thresholds.min_baseline_runs
    {
        findings.push(BenchmarkSplitFinding {
            code: BenchmarkSplitFailureCode::InsufficientBaselineRuns,
            split: Some(BenchmarkSplit::Baseline),
            metric: Some("baseline_cv".to_string()),
            detail: format!(
                "candidate baseline stability requires at least {} runs",
                thresholds.min_baseline_runs
            ),
            observed_millionths: Some(
                input
                    .candidate_snapshot
                    .baseline_throughput_runs_ops_per_sec
                    .len() as u64,
            ),
            threshold_millionths: Some(thresholds.min_baseline_runs as u64),
        });
        None
    } else {
        match coefficient_of_variation_millionths(
            &input
                .candidate_snapshot
                .baseline_throughput_runs_ops_per_sec,
        ) {
            Some(cv) => {
                if cv > thresholds.max_baseline_cv_millionths {
                    findings.push(BenchmarkSplitFinding {
                        code: BenchmarkSplitFailureCode::BaselineVarianceExceeded,
                        split: Some(BenchmarkSplit::Baseline),
                        metric: Some("baseline_cv".to_string()),
                        detail: format!(
                            "baseline coefficient of variation exceeded threshold (observed {} ppm, max {} ppm)",
                            cv, thresholds.max_baseline_cv_millionths
                        ),
                        observed_millionths: Some(cv),
                        threshold_millionths: Some(thresholds.max_baseline_cv_millionths),
                    });
                }
                Some(cv)
            }
            None => {
                findings.push(BenchmarkSplitFinding {
                    code: BenchmarkSplitFailureCode::InvalidMetric,
                    split: Some(BenchmarkSplit::Baseline),
                    metric: Some("baseline_cv".to_string()),
                    detail: "baseline coefficient of variation could not be computed".to_string(),
                    observed_millionths: None,
                    threshold_millionths: None,
                });
                None
            }
        }
    };

    let mut evaluations = Vec::new();
    for split in &required_splits {
        let previous_metrics = input.previous_snapshot.split_metrics.get(split);
        let candidate_metrics = input.candidate_snapshot.split_metrics.get(split);

        let (Some(previous_metrics), Some(candidate_metrics)) =
            (previous_metrics, candidate_metrics)
        else {
            continue;
        };

        if previous_metrics.throughput_ops_per_sec == 0
            || candidate_metrics.throughput_ops_per_sec == 0
        {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::InvalidMetric,
                split: Some(*split),
                metric: Some("throughput_ops_per_sec".to_string()),
                detail: "throughput must be non-zero for regression checks".to_string(),
                observed_millionths: None,
                threshold_millionths: None,
            });
        }

        let throughput_regression = throughput_regression_millionths(
            previous_metrics.throughput_ops_per_sec,
            candidate_metrics.throughput_ops_per_sec,
        );
        let latency_p95_regression = latency_regression_millionths(
            previous_metrics.latency_ns.p95_ns,
            candidate_metrics.latency_ns.p95_ns,
        );
        let latency_p99_regression = latency_regression_millionths(
            previous_metrics.latency_ns.p99_ns,
            candidate_metrics.latency_ns.p99_ns,
        );

        evaluations.push(SplitBenchmarkEvaluation {
            split: *split,
            previous_metrics: previous_metrics.clone(),
            candidate_metrics: candidate_metrics.clone(),
            throughput_regression_vs_previous_millionths: throughput_regression,
            latency_p95_regression_vs_previous_millionths: latency_p95_regression,
            latency_p99_regression_vs_previous_millionths: latency_p99_regression,
            pass: true,
        });
    }

    let candidate_baseline = input
        .candidate_snapshot
        .split_metrics
        .get(&BenchmarkSplit::Baseline);
    let candidate_cx = input
        .candidate_snapshot
        .split_metrics
        .get(&BenchmarkSplit::CxThreading);
    let candidate_decision = input
        .candidate_snapshot
        .split_metrics
        .get(&BenchmarkSplit::DecisionContracts);
    let candidate_evidence = input
        .candidate_snapshot
        .split_metrics
        .get(&BenchmarkSplit::EvidenceEmission);
    let candidate_full = input
        .candidate_snapshot
        .split_metrics
        .get(&BenchmarkSplit::FullIntegration);

    if let (Some(baseline), Some(cx)) = (candidate_baseline, candidate_cx) {
        let regression = throughput_regression_millionths(
            baseline.throughput_ops_per_sec,
            cx.throughput_ops_per_sec,
        );
        if regression > thresholds.max_cx_throughput_regression_millionths {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
                split: Some(BenchmarkSplit::CxThreading),
                metric: Some("throughput_ops_per_sec".to_string()),
                detail: format!(
                    "Cx threading throughput regression exceeded threshold (observed {} ppm, max {} ppm)",
                    regression, thresholds.max_cx_throughput_regression_millionths
                ),
                observed_millionths: Some(regression),
                threshold_millionths: Some(thresholds.max_cx_throughput_regression_millionths),
            });
        }
    }

    if let (Some(cx), Some(decision)) = (candidate_cx, candidate_decision) {
        let p95_regression =
            latency_regression_millionths(cx.latency_ns.p95_ns, decision.latency_ns.p95_ns);
        let p99_regression =
            latency_regression_millionths(cx.latency_ns.p99_ns, decision.latency_ns.p99_ns);
        let max_observed = p95_regression.max(p99_regression);
        if max_observed > thresholds.max_decision_latency_regression_millionths {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::LatencyRegressionExceeded,
                split: Some(BenchmarkSplit::DecisionContracts),
                metric: Some("latency_ns.p95_p99".to_string()),
                detail: format!(
                    "decision contract latency regression exceeded threshold (p95 {} ppm, p99 {} ppm, max {} ppm)",
                    p95_regression, p99_regression, thresholds.max_decision_latency_regression_millionths
                ),
                observed_millionths: Some(max_observed),
                threshold_millionths: Some(thresholds.max_decision_latency_regression_millionths),
            });
        }
    }

    if let (Some(baseline), Some(evidence)) = (candidate_baseline, candidate_evidence) {
        let regression = throughput_regression_millionths(
            baseline.throughput_ops_per_sec,
            evidence.throughput_ops_per_sec,
        );
        if regression > thresholds.max_evidence_throughput_regression_millionths {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
                split: Some(BenchmarkSplit::EvidenceEmission),
                metric: Some("throughput_ops_per_sec".to_string()),
                detail: format!(
                    "evidence emission throughput regression exceeded threshold (observed {} ppm, max {} ppm)",
                    regression, thresholds.max_evidence_throughput_regression_millionths
                ),
                observed_millionths: Some(regression),
                threshold_millionths: Some(thresholds.max_evidence_throughput_regression_millionths),
            });
        }
    }

    if let (Some(baseline), Some(full)) = (candidate_baseline, candidate_full) {
        let regression = throughput_regression_millionths(
            baseline.throughput_ops_per_sec,
            full.throughput_ops_per_sec,
        );
        if regression > thresholds.max_full_integration_throughput_regression_millionths {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
                split: Some(BenchmarkSplit::FullIntegration),
                metric: Some("throughput_ops_per_sec".to_string()),
                detail: format!(
                    "full integration throughput regression exceeded threshold (observed {} ppm, max {} ppm)",
                    regression, thresholds.max_full_integration_throughput_regression_millionths
                ),
                observed_millionths: Some(regression),
                threshold_millionths: Some(
                    thresholds.max_full_integration_throughput_regression_millionths,
                ),
            });
        }
    }

    for (split, metrics) in &input.candidate_snapshot.split_metrics {
        if let Some(limit) = thresholds.max_peak_rss_delta_bytes.get(split)
            && metrics.peak_rss_delta_bytes > *limit
        {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::MemoryOverheadExceeded,
                split: Some(*split),
                metric: Some("peak_rss_delta_bytes".to_string()),
                detail: format!(
                    "peak RSS delta exceeded threshold (observed {} bytes, max {} bytes)",
                    metrics.peak_rss_delta_bytes, limit
                ),
                observed_millionths: None,
                threshold_millionths: None,
            });
        }
    }

    for evaluation in &evaluations {
        if let Some(limit) = thresholds
            .max_previous_run_throughput_regression_millionths
            .get(&evaluation.split)
            && evaluation.throughput_regression_vs_previous_millionths > *limit
        {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
                split: Some(evaluation.split),
                metric: Some("throughput_ops_per_sec".to_string()),
                detail: format!(
                    "throughput regressed vs previous run (observed {} ppm, max {} ppm)",
                    evaluation.throughput_regression_vs_previous_millionths, limit
                ),
                observed_millionths: Some(evaluation.throughput_regression_vs_previous_millionths),
                threshold_millionths: Some(*limit),
            });
        }

        let max_latency_regression = evaluation
            .latency_p95_regression_vs_previous_millionths
            .max(evaluation.latency_p99_regression_vs_previous_millionths);
        if max_latency_regression > thresholds.max_previous_run_latency_regression_millionths {
            findings.push(BenchmarkSplitFinding {
                code: BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
                split: Some(evaluation.split),
                metric: Some("latency_ns.p95_p99".to_string()),
                detail: format!(
                    "latency regressed vs previous run (p95 {} ppm, p99 {} ppm, max {} ppm)",
                    evaluation.latency_p95_regression_vs_previous_millionths,
                    evaluation.latency_p99_regression_vs_previous_millionths,
                    thresholds.max_previous_run_latency_regression_millionths
                ),
                observed_millionths: Some(max_latency_regression),
                threshold_millionths: Some(
                    thresholds.max_previous_run_latency_regression_millionths,
                ),
            });
        }
    }

    for evaluation in &mut evaluations {
        evaluation.pass = !findings
            .iter()
            .any(|finding| finding.split == Some(evaluation.split));
    }

    let pass = findings.is_empty() && evaluations.iter().all(|evaluation| evaluation.pass);

    let decision_hash = hash_bytes(&deterministic_serde::encode_value(&CanonicalValue::Array(
        vec![
            CanonicalValue::Bytes(CONTROL_PLANE_BENCHMARK_SPLIT_DOMAIN.to_vec()),
            decision_canonical_value(
                input,
                previous_hash,
                candidate_hash,
                pass,
                baseline_cv_millionths,
                &evaluations,
                &findings,
            ),
        ],
    )));
    let decision_id = format!("cp-bench-split-{}", to_hex(&decision_hash[..16]));

    let mut logs = Vec::new();
    let stability_failure = findings.iter().find(|finding| {
        finding.split == Some(BenchmarkSplit::Baseline)
            && finding.metric.as_deref() == Some("baseline_cv")
    });
    logs.push(BenchmarkSplitLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: "control_plane_benchmark_split_gate".to_string(),
        event: "baseline_stability_check".to_string(),
        outcome: if stability_failure.is_none() {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: stability_failure.map(|finding| finding.code.to_string()),
        split: Some(BenchmarkSplit::Baseline.as_str().to_string()),
        metric: Some("baseline_cv".to_string()),
    });

    for evaluation in &evaluations {
        let failure = findings
            .iter()
            .find(|finding| finding.split == Some(evaluation.split));
        logs.push(BenchmarkSplitLogEvent {
            trace_id: input.trace_id.clone(),
            decision_id: decision_id.clone(),
            policy_id: input.policy_id.clone(),
            component: "control_plane_benchmark_split_gate".to_string(),
            event: "split_evaluation".to_string(),
            outcome: if evaluation.pass {
                "pass".to_string()
            } else {
                "fail".to_string()
            },
            error_code: failure.map(|finding| finding.code.to_string()),
            split: Some(evaluation.split.as_str().to_string()),
            metric: failure.and_then(|finding| finding.metric.clone()),
        });
    }

    logs.push(BenchmarkSplitLogEvent {
        trace_id: input.trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: input.policy_id.clone(),
        component: "control_plane_benchmark_split_gate".to_string(),
        event: "benchmark_split_decision".to_string(),
        outcome: if pass {
            "pass".to_string()
        } else {
            "fail".to_string()
        },
        error_code: if pass {
            None
        } else {
            Some("control_plane_benchmark_split_failed".to_string())
        },
        split: None,
        metric: None,
    });

    BenchmarkSplitGateDecision {
        decision_id,
        pass,
        rollback_required: !pass,
        previous_snapshot_hash: previous_hash,
        candidate_snapshot_hash: candidate_hash,
        baseline_cv_millionths,
        evaluations,
        findings,
        logs,
    }
}

/// Deterministic fixture used by the benchmark split suite to emit bead-specific
/// report artifacts without depending on non-deterministic local measurements.
pub fn control_plane_benchmark_split_report_fixture_input() -> BenchmarkSplitGateInput {
    let previous_snapshot = BenchmarkSplitSnapshot {
        snapshot_id: "report-fixture-previous-snapshot".to_string(),
        benchmark_run_id: "report-fixture-previous-run".to_string(),
        split_metrics: BTreeMap::from([
            (
                BenchmarkSplit::Baseline,
                SplitBenchmarkMetrics {
                    throughput_ops_per_sec: 1_002_000,
                    latency_ns: LatencyStatsNs {
                        p50_ns: 950_000,
                        p95_ns: 1_000_000,
                        p99_ns: 1_050_000,
                    },
                    peak_rss_delta_bytes: 0,
                },
            ),
            (
                BenchmarkSplit::CxThreading,
                SplitBenchmarkMetrics {
                    throughput_ops_per_sec: 997_000,
                    latency_ns: LatencyStatsNs {
                        p50_ns: 960_000,
                        p95_ns: 1_008_000,
                        p99_ns: 1_060_000,
                    },
                    peak_rss_delta_bytes: 8 * 1024 * 1024,
                },
            ),
            (
                BenchmarkSplit::DecisionContracts,
                SplitBenchmarkMetrics {
                    throughput_ops_per_sec: 994_000,
                    latency_ns: LatencyStatsNs {
                        p50_ns: 970_000,
                        p95_ns: 1_052_000,
                        p99_ns: 1_098_000,
                    },
                    peak_rss_delta_bytes: 16 * 1024 * 1024,
                },
            ),
            (
                BenchmarkSplit::EvidenceEmission,
                SplitBenchmarkMetrics {
                    throughput_ops_per_sec: 976_000,
                    latency_ns: LatencyStatsNs {
                        p50_ns: 980_000,
                        p95_ns: 1_068_000,
                        p99_ns: 1_116_000,
                    },
                    peak_rss_delta_bytes: 24 * 1024 * 1024,
                },
            ),
            (
                BenchmarkSplit::FullIntegration,
                SplitBenchmarkMetrics {
                    throughput_ops_per_sec: 958_000,
                    latency_ns: LatencyStatsNs {
                        p50_ns: 990_000,
                        p95_ns: 1_080_000,
                        p99_ns: 1_130_000,
                    },
                    peak_rss_delta_bytes: 30 * 1024 * 1024,
                },
            ),
        ]),
        baseline_throughput_runs_ops_per_sec: vec![
            1_000_100, 1_000_250, 999_950, 1_000_000, 1_000_150, 1_000_300, 999_975, 1_000_050,
            1_000_125, 1_000_225,
        ],
    };

    let candidate_snapshot = BenchmarkSplitSnapshot {
        snapshot_id: "report-fixture-candidate-snapshot".to_string(),
        benchmark_run_id: "report-fixture-candidate-run".to_string(),
        split_metrics: BTreeMap::from([
            (
                BenchmarkSplit::Baseline,
                SplitBenchmarkMetrics {
                    throughput_ops_per_sec: 1_000_000,
                    latency_ns: LatencyStatsNs {
                        p50_ns: 950_000,
                        p95_ns: 1_000_000,
                        p99_ns: 1_050_000,
                    },
                    peak_rss_delta_bytes: 0,
                },
            ),
            (
                BenchmarkSplit::CxThreading,
                SplitBenchmarkMetrics {
                    throughput_ops_per_sec: 995_000,
                    latency_ns: LatencyStatsNs {
                        p50_ns: 962_000,
                        p95_ns: 1_008_000,
                        p99_ns: 1_060_000,
                    },
                    peak_rss_delta_bytes: 8 * 1024 * 1024,
                },
            ),
            (
                BenchmarkSplit::DecisionContracts,
                SplitBenchmarkMetrics {
                    throughput_ops_per_sec: 993_500,
                    latency_ns: LatencyStatsNs {
                        p50_ns: 972_000,
                        p95_ns: 1_055_000,
                        p99_ns: 1_100_000,
                    },
                    peak_rss_delta_bytes: 16 * 1024 * 1024,
                },
            ),
            (
                BenchmarkSplit::EvidenceEmission,
                SplitBenchmarkMetrics {
                    throughput_ops_per_sec: 975_000,
                    latency_ns: LatencyStatsNs {
                        p50_ns: 980_000,
                        p95_ns: 1_068_000,
                        p99_ns: 1_115_000,
                    },
                    peak_rss_delta_bytes: 24 * 1024 * 1024,
                },
            ),
            (
                BenchmarkSplit::FullIntegration,
                SplitBenchmarkMetrics {
                    throughput_ops_per_sec: 955_000,
                    latency_ns: LatencyStatsNs {
                        p50_ns: 990_000,
                        p95_ns: 1_080_000,
                        p99_ns: 1_130_000,
                    },
                    peak_rss_delta_bytes: 30 * 1024 * 1024,
                },
            ),
        ]),
        baseline_throughput_runs_ops_per_sec: vec![
            1_000_100, 1_000_250, 999_950, 1_000_000, 1_000_150, 1_000_300, 999_975, 1_000_050,
            1_000_125, 1_000_225,
        ],
    };

    BenchmarkSplitGateInput {
        trace_id: "trace-bd-3nr-1-5-2-report-fixture".to_string(),
        policy_id: "policy-bd-3nr-1-5-2-report-fixture".to_string(),
        previous_snapshot,
        candidate_snapshot,
    }
}

pub fn build_control_plane_real_context_overhead_report(
    input: &BenchmarkSplitGateInput,
    thresholds: &BenchmarkSplitThresholds,
    decision: &BenchmarkSplitGateDecision,
) -> ControlPlaneRealContextOverheadReport {
    let baseline_stability = build_baseline_stability_report(input, thresholds, decision);
    let corrected_path_delta_vs_shortcut = build_delta_summary(
        BenchmarkDeltaReferenceKind::ShortcutBaseline,
        BenchmarkSplit::Baseline,
        BenchmarkSplit::FullIntegration,
        input,
    );
    let user_visible_delta = build_delta_summary(
        BenchmarkDeltaReferenceKind::ShortcutBaseline,
        BenchmarkSplit::Baseline,
        BenchmarkSplit::EvidenceEmission,
        input,
    );
    let operator_visible_delta = build_delta_summary(
        BenchmarkDeltaReferenceKind::PreviousStage,
        BenchmarkSplit::EvidenceEmission,
        BenchmarkSplit::FullIntegration,
        input,
    );

    let corrected_path_components = vec![
        build_component_attribution(
            "cx_threading",
            BenchmarkImpactVisibility::UserVisible,
            BenchmarkSplit::Baseline,
            BenchmarkSplit::CxThreading,
            input,
            thresholds,
            decision,
        ),
        build_component_attribution(
            "decision_contracts",
            BenchmarkImpactVisibility::UserVisible,
            BenchmarkSplit::CxThreading,
            BenchmarkSplit::DecisionContracts,
            input,
            thresholds,
            decision,
        ),
        build_component_attribution(
            "evidence_emission",
            BenchmarkImpactVisibility::UserVisible,
            BenchmarkSplit::DecisionContracts,
            BenchmarkSplit::EvidenceEmission,
            input,
            thresholds,
            decision,
        ),
        build_component_attribution(
            "full_integration_gate_runtime",
            BenchmarkImpactVisibility::OperatorVisible,
            BenchmarkSplit::EvidenceEmission,
            BenchmarkSplit::FullIntegration,
            input,
            thresholds,
            decision,
        ),
    ];

    let user_severity = corrected_path_components
        .iter()
        .filter(|component| {
            matches!(
                component.visibility,
                BenchmarkImpactVisibility::UserVisible | BenchmarkImpactVisibility::Mixed
            )
        })
        .fold(
            BenchmarkImpactSeverity::Transparent,
            |severity, component| severity.max(component.severity),
        );
    let operator_severity = corrected_path_components
        .iter()
        .filter(|component| {
            matches!(
                component.visibility,
                BenchmarkImpactVisibility::OperatorVisible | BenchmarkImpactVisibility::Mixed
            )
        })
        .fold(baseline_stability.severity, |severity, component| {
            severity.max(component.severity)
        });
    let severity = user_severity.max(operator_severity);

    ControlPlaneRealContextOverheadReport {
        schema_version: CONTROL_PLANE_REAL_CONTEXT_OVERHEAD_REPORT_SCHEMA_VERSION.to_string(),
        component: CONTROL_PLANE_BENCHMARK_SPLIT_REPORT_COMPONENT.to_string(),
        trace_id: input.trace_id.clone(),
        decision_id: decision.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        previous_snapshot_id: input.previous_snapshot.snapshot_id.clone(),
        candidate_snapshot_id: input.candidate_snapshot.snapshot_id.clone(),
        shortcut_reference_split: BenchmarkSplit::Baseline,
        corrected_real_context_split: BenchmarkSplit::FullIntegration,
        bounded_overhead: decision.pass,
        rollback_required: decision.rollback_required,
        severity,
        user_impact_class: impact_class_from_severity(user_severity),
        operator_impact_class: impact_class_from_severity(operator_severity),
        baseline_stability,
        corrected_path_delta_vs_shortcut,
        user_visible_delta,
        operator_visible_delta,
        corrected_path_components,
        findings: decision.findings.clone(),
    }
}

pub fn build_benchmark_split_delta_report(
    input: &BenchmarkSplitGateInput,
    decision: &BenchmarkSplitGateDecision,
) -> BenchmarkSplitDeltaReport {
    let previous_stage_deltas = vec![
        build_delta_entry(
            BenchmarkDeltaReferenceKind::PreviousStage,
            BenchmarkSplit::Baseline,
            BenchmarkSplit::CxThreading,
            input,
            decision,
        ),
        build_delta_entry(
            BenchmarkDeltaReferenceKind::PreviousStage,
            BenchmarkSplit::CxThreading,
            BenchmarkSplit::DecisionContracts,
            input,
            decision,
        ),
        build_delta_entry(
            BenchmarkDeltaReferenceKind::PreviousStage,
            BenchmarkSplit::DecisionContracts,
            BenchmarkSplit::EvidenceEmission,
            input,
            decision,
        ),
        build_delta_entry(
            BenchmarkDeltaReferenceKind::PreviousStage,
            BenchmarkSplit::EvidenceEmission,
            BenchmarkSplit::FullIntegration,
            input,
            decision,
        ),
    ];
    let shortcut_baseline_deltas = vec![
        build_delta_entry(
            BenchmarkDeltaReferenceKind::ShortcutBaseline,
            BenchmarkSplit::Baseline,
            BenchmarkSplit::CxThreading,
            input,
            decision,
        ),
        build_delta_entry(
            BenchmarkDeltaReferenceKind::ShortcutBaseline,
            BenchmarkSplit::Baseline,
            BenchmarkSplit::DecisionContracts,
            input,
            decision,
        ),
        build_delta_entry(
            BenchmarkDeltaReferenceKind::ShortcutBaseline,
            BenchmarkSplit::Baseline,
            BenchmarkSplit::EvidenceEmission,
            input,
            decision,
        ),
        build_delta_entry(
            BenchmarkDeltaReferenceKind::ShortcutBaseline,
            BenchmarkSplit::Baseline,
            BenchmarkSplit::FullIntegration,
            input,
            decision,
        ),
    ];
    let previous_snapshot_deltas = vec![
        build_delta_entry(
            BenchmarkDeltaReferenceKind::PreviousSnapshot,
            BenchmarkSplit::Baseline,
            BenchmarkSplit::Baseline,
            input,
            decision,
        ),
        build_delta_entry(
            BenchmarkDeltaReferenceKind::PreviousSnapshot,
            BenchmarkSplit::CxThreading,
            BenchmarkSplit::CxThreading,
            input,
            decision,
        ),
        build_delta_entry(
            BenchmarkDeltaReferenceKind::PreviousSnapshot,
            BenchmarkSplit::DecisionContracts,
            BenchmarkSplit::DecisionContracts,
            input,
            decision,
        ),
        build_delta_entry(
            BenchmarkDeltaReferenceKind::PreviousSnapshot,
            BenchmarkSplit::EvidenceEmission,
            BenchmarkSplit::EvidenceEmission,
            input,
            decision,
        ),
        build_delta_entry(
            BenchmarkDeltaReferenceKind::PreviousSnapshot,
            BenchmarkSplit::FullIntegration,
            BenchmarkSplit::FullIntegration,
            input,
            decision,
        ),
    ];

    let user_severity = previous_stage_deltas
        .iter()
        .filter(|delta| {
            matches!(
                delta.visibility,
                BenchmarkImpactVisibility::UserVisible | BenchmarkImpactVisibility::Mixed
            )
        })
        .fold(BenchmarkImpactSeverity::Transparent, |severity, delta| {
            severity.max(delta.severity)
        });
    let operator_severity = previous_stage_deltas
        .iter()
        .filter(|delta| {
            matches!(
                delta.visibility,
                BenchmarkImpactVisibility::OperatorVisible | BenchmarkImpactVisibility::Mixed
            )
        })
        .fold(BenchmarkImpactSeverity::Transparent, |severity, delta| {
            severity.max(delta.severity)
        });
    let severity = user_severity.max(operator_severity);

    BenchmarkSplitDeltaReport {
        schema_version: BENCHMARK_SPLIT_DELTA_REPORT_SCHEMA_VERSION.to_string(),
        component: CONTROL_PLANE_BENCHMARK_SPLIT_REPORT_COMPONENT.to_string(),
        trace_id: input.trace_id.clone(),
        decision_id: decision.decision_id.clone(),
        policy_id: input.policy_id.clone(),
        bounded_overhead: decision.pass,
        rollback_required: decision.rollback_required,
        severity,
        user_impact_class: impact_class_from_severity(user_severity),
        operator_impact_class: impact_class_from_severity(operator_severity),
        previous_stage_deltas,
        shortcut_baseline_deltas,
        previous_snapshot_deltas,
        failing_findings: decision.findings.clone(),
    }
}

pub fn write_control_plane_benchmark_split_reports(
    out_dir: &Path,
) -> Result<ControlPlaneBenchmarkSplitReportArtifacts, ControlPlaneBenchmarkSplitReportWriteError> {
    let input = control_plane_benchmark_split_report_fixture_input();
    let thresholds = BenchmarkSplitThresholds::default();
    let decision = evaluate_control_plane_benchmark_split(&input, &thresholds);
    let overhead_report =
        build_control_plane_real_context_overhead_report(&input, &thresholds, &decision);
    let delta_report = build_benchmark_split_delta_report(&input, &decision);

    let control_plane_real_context_overhead_report_path =
        out_dir.join(CONTROL_PLANE_REAL_CONTEXT_OVERHEAD_REPORT_FILE);
    let benchmark_split_delta_report_path = out_dir.join(BENCHMARK_SPLIT_DELTA_REPORT_FILE);
    let overhead_bytes = json_pretty_bytes(
        &overhead_report,
        &control_plane_real_context_overhead_report_path,
    )?;
    let delta_bytes = json_pretty_bytes(&delta_report, &benchmark_split_delta_report_path)?;

    write_atomic(
        &control_plane_real_context_overhead_report_path,
        &overhead_bytes,
    )?;
    write_atomic(&benchmark_split_delta_report_path, &delta_bytes)?;

    Ok(ControlPlaneBenchmarkSplitReportArtifacts {
        out_dir: out_dir.to_path_buf(),
        control_plane_real_context_overhead_report_path,
        benchmark_split_delta_report_path,
        decision_id: decision.decision_id,
        pass: decision.pass,
        rollback_required: decision.rollback_required,
    })
}

fn build_baseline_stability_report(
    input: &BenchmarkSplitGateInput,
    thresholds: &BenchmarkSplitThresholds,
    decision: &BenchmarkSplitGateDecision,
) -> BenchmarkBaselineStabilityReport {
    let observed_run_count = input
        .candidate_snapshot
        .baseline_throughput_runs_ops_per_sec
        .len();
    let threshold_exceeded = decision.findings.iter().any(|finding| {
        finding.split == Some(BenchmarkSplit::Baseline)
            && finding.metric.as_deref() == Some("baseline_cv")
    });
    let severity = if threshold_exceeded {
        if observed_run_count < thresholds.min_baseline_runs {
            BenchmarkImpactSeverity::Critical
        } else {
            BenchmarkImpactSeverity::High
        }
    } else {
        BenchmarkImpactSeverity::Transparent
    };

    BenchmarkBaselineStabilityReport {
        observed_run_count,
        required_run_count: thresholds.min_baseline_runs,
        observed_cv_millionths: decision.baseline_cv_millionths,
        max_cv_millionths: thresholds.max_baseline_cv_millionths,
        pass: !threshold_exceeded,
        severity,
        operator_impact_class: impact_class_from_severity(severity),
    }
}

fn build_component_attribution(
    component_id: &str,
    visibility: BenchmarkImpactVisibility,
    reference_split: BenchmarkSplit,
    candidate_split: BenchmarkSplit,
    input: &BenchmarkSplitGateInput,
    thresholds: &BenchmarkSplitThresholds,
    decision: &BenchmarkSplitGateDecision,
) -> BenchmarkOverheadComponentAttribution {
    let summary = build_delta_summary(
        BenchmarkDeltaReferenceKind::PreviousStage,
        reference_split,
        candidate_split,
        input,
    );
    let finding_codes = finding_codes_for_split(&decision.findings, candidate_split);
    let threshold_exceeded = !finding_codes.is_empty();
    let (primary_threshold_metric, primary_threshold_millionths) =
        component_threshold(candidate_split, thresholds);
    let primary_regression = match candidate_split {
        BenchmarkSplit::DecisionContracts => summary
            .latency_p95_regression_millionths
            .max(summary.latency_p99_regression_millionths),
        _ => summary.throughput_regression_millionths,
    };
    let severity = severity_from_regression(
        primary_regression,
        primary_threshold_millionths,
        threshold_exceeded,
    );

    BenchmarkOverheadComponentAttribution {
        component_id: component_id.to_string(),
        visibility,
        reference_split,
        candidate_split,
        throughput_ops_per_sec_delta: summary.throughput_ops_per_sec_delta,
        throughput_regression_millionths: summary.throughput_regression_millionths,
        latency_p95_ns_delta: summary.latency_p95_ns_delta,
        latency_p95_regression_millionths: summary.latency_p95_regression_millionths,
        latency_p99_ns_delta: summary.latency_p99_ns_delta,
        latency_p99_regression_millionths: summary.latency_p99_regression_millionths,
        peak_rss_delta_bytes: summary.peak_rss_delta_bytes,
        primary_threshold_metric: primary_threshold_metric.map(str::to_string),
        primary_threshold_millionths,
        threshold_exceeded,
        severity,
        impact_class: impact_class_from_severity(severity),
    }
}

fn build_delta_entry(
    reference_kind: BenchmarkDeltaReferenceKind,
    reference_split: BenchmarkSplit,
    candidate_split: BenchmarkSplit,
    input: &BenchmarkSplitGateInput,
    decision: &BenchmarkSplitGateDecision,
) -> BenchmarkSplitDeltaEntry {
    let summary = build_delta_summary(reference_kind, reference_split, candidate_split, input);
    let visibility = delta_visibility(reference_kind, candidate_split);
    let finding_codes = finding_codes_for_split(&decision.findings, candidate_split);
    let threshold_exceeded = !finding_codes.is_empty();
    let primary_regression = summary
        .throughput_regression_millionths
        .max(summary.latency_p95_regression_millionths)
        .max(summary.latency_p99_regression_millionths);
    let severity = severity_from_regression(primary_regression, None, threshold_exceeded);
    let user_impact_class = match visibility {
        BenchmarkImpactVisibility::OperatorVisible => BenchmarkImpactClass::Transparent,
        BenchmarkImpactVisibility::UserVisible | BenchmarkImpactVisibility::Mixed => {
            impact_class_from_severity(severity)
        }
    };
    let operator_impact_class = match visibility {
        BenchmarkImpactVisibility::UserVisible => BenchmarkImpactClass::Transparent,
        BenchmarkImpactVisibility::OperatorVisible | BenchmarkImpactVisibility::Mixed => {
            impact_class_from_severity(severity)
        }
    };

    BenchmarkSplitDeltaEntry {
        reference_kind,
        visibility,
        reference_split,
        candidate_split,
        throughput_ops_per_sec_delta: summary.throughput_ops_per_sec_delta,
        throughput_regression_millionths: summary.throughput_regression_millionths,
        latency_p95_ns_delta: summary.latency_p95_ns_delta,
        latency_p95_regression_millionths: summary.latency_p95_regression_millionths,
        latency_p99_ns_delta: summary.latency_p99_ns_delta,
        latency_p99_regression_millionths: summary.latency_p99_regression_millionths,
        peak_rss_delta_bytes: summary.peak_rss_delta_bytes,
        severity,
        user_impact_class,
        operator_impact_class,
        finding_codes,
    }
}

fn build_delta_summary(
    reference_kind: BenchmarkDeltaReferenceKind,
    reference_split: BenchmarkSplit,
    candidate_split: BenchmarkSplit,
    input: &BenchmarkSplitGateInput,
) -> BenchmarkSplitDeltaSummary {
    let (reference_metrics, candidate_metrics) = match reference_kind {
        BenchmarkDeltaReferenceKind::PreviousSnapshot => (
            input
                .previous_snapshot
                .split_metrics
                .get(&reference_split)
                .expect("previous snapshot split metrics"),
            input
                .candidate_snapshot
                .split_metrics
                .get(&candidate_split)
                .expect("candidate snapshot split metrics"),
        ),
        BenchmarkDeltaReferenceKind::PreviousStage
        | BenchmarkDeltaReferenceKind::ShortcutBaseline => (
            input
                .candidate_snapshot
                .split_metrics
                .get(&reference_split)
                .expect("candidate reference split metrics"),
            input
                .candidate_snapshot
                .split_metrics
                .get(&candidate_split)
                .expect("candidate split metrics"),
        ),
    };

    BenchmarkSplitDeltaSummary {
        reference_kind,
        reference_split,
        candidate_split,
        throughput_ops_per_sec_delta: signed_delta(
            reference_metrics.throughput_ops_per_sec,
            candidate_metrics.throughput_ops_per_sec,
        ),
        throughput_regression_millionths: throughput_regression_millionths(
            reference_metrics.throughput_ops_per_sec,
            candidate_metrics.throughput_ops_per_sec,
        ),
        latency_p95_ns_delta: signed_delta(
            reference_metrics.latency_ns.p95_ns,
            candidate_metrics.latency_ns.p95_ns,
        ),
        latency_p95_regression_millionths: latency_regression_millionths(
            reference_metrics.latency_ns.p95_ns,
            candidate_metrics.latency_ns.p95_ns,
        ),
        latency_p99_ns_delta: signed_delta(
            reference_metrics.latency_ns.p99_ns,
            candidate_metrics.latency_ns.p99_ns,
        ),
        latency_p99_regression_millionths: latency_regression_millionths(
            reference_metrics.latency_ns.p99_ns,
            candidate_metrics.latency_ns.p99_ns,
        ),
        peak_rss_delta_bytes: signed_delta(
            reference_metrics.peak_rss_delta_bytes,
            candidate_metrics.peak_rss_delta_bytes,
        ),
    }
}

fn component_threshold(
    candidate_split: BenchmarkSplit,
    thresholds: &BenchmarkSplitThresholds,
) -> (Option<&'static str>, Option<u64>) {
    match candidate_split {
        BenchmarkSplit::CxThreading => (
            Some("throughput_ops_per_sec"),
            Some(thresholds.max_cx_throughput_regression_millionths),
        ),
        BenchmarkSplit::DecisionContracts => (
            Some("latency_ns.p95_p99"),
            Some(thresholds.max_decision_latency_regression_millionths),
        ),
        BenchmarkSplit::EvidenceEmission => (
            Some("throughput_ops_per_sec"),
            Some(thresholds.max_evidence_throughput_regression_millionths),
        ),
        BenchmarkSplit::FullIntegration => (None, None),
        BenchmarkSplit::Baseline => (None, None),
    }
}

fn finding_codes_for_split(
    findings: &[BenchmarkSplitFinding],
    split: BenchmarkSplit,
) -> Vec<BenchmarkSplitFailureCode> {
    findings
        .iter()
        .filter(|finding| finding.split == Some(split))
        .map(|finding| finding.code)
        .collect()
}

fn delta_visibility(
    reference_kind: BenchmarkDeltaReferenceKind,
    candidate_split: BenchmarkSplit,
) -> BenchmarkImpactVisibility {
    match (reference_kind, candidate_split) {
        (BenchmarkDeltaReferenceKind::PreviousStage, BenchmarkSplit::FullIntegration) => {
            BenchmarkImpactVisibility::OperatorVisible
        }
        (BenchmarkDeltaReferenceKind::PreviousSnapshot, BenchmarkSplit::Baseline) => {
            BenchmarkImpactVisibility::OperatorVisible
        }
        (BenchmarkDeltaReferenceKind::PreviousSnapshot, BenchmarkSplit::FullIntegration)
        | (BenchmarkDeltaReferenceKind::ShortcutBaseline, BenchmarkSplit::FullIntegration) => {
            BenchmarkImpactVisibility::Mixed
        }
        _ => BenchmarkImpactVisibility::UserVisible,
    }
}

fn impact_class_from_severity(severity: BenchmarkImpactSeverity) -> BenchmarkImpactClass {
    match severity {
        BenchmarkImpactSeverity::Transparent => BenchmarkImpactClass::Transparent,
        BenchmarkImpactSeverity::Low | BenchmarkImpactSeverity::Medium => {
            BenchmarkImpactClass::Noticeable
        }
        BenchmarkImpactSeverity::High => BenchmarkImpactClass::ActionRequired,
        BenchmarkImpactSeverity::Critical => BenchmarkImpactClass::ReleaseBlocking,
    }
}

fn severity_from_regression(
    observed_millionths: u64,
    threshold_millionths: Option<u64>,
    threshold_exceeded: bool,
) -> BenchmarkImpactSeverity {
    if observed_millionths == 0 {
        return BenchmarkImpactSeverity::Transparent;
    }

    if threshold_exceeded {
        if let Some(threshold) = threshold_millionths
            && observed_millionths > threshold.saturating_mul(2)
        {
            return BenchmarkImpactSeverity::Critical;
        }
        return BenchmarkImpactSeverity::High;
    }

    match threshold_millionths {
        Some(threshold) if threshold > 0 => {
            if observed_millionths.saturating_mul(4) < threshold {
                BenchmarkImpactSeverity::Low
            } else {
                BenchmarkImpactSeverity::Medium
            }
        }
        _ if observed_millionths < 5_000 => BenchmarkImpactSeverity::Low,
        _ if observed_millionths < 20_000 => BenchmarkImpactSeverity::Medium,
        _ if observed_millionths < 50_000 => BenchmarkImpactSeverity::High,
        _ => BenchmarkImpactSeverity::Critical,
    }
}

fn signed_delta(reference: u64, candidate: u64) -> i64 {
    let delta = candidate as i128 - reference as i128;
    if delta > i64::MAX as i128 {
        i64::MAX
    } else if delta < i64::MIN as i128 {
        i64::MIN
    } else {
        delta as i64
    }
}

fn json_pretty_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, ControlPlaneBenchmarkSplitReportWriteError> {
    serde_json::to_vec_pretty(value).map_err(|error| {
        ControlPlaneBenchmarkSplitReportWriteError::Json {
            path: path.to_path_buf(),
            reason: error.to_string(),
        }
    })
}

fn write_atomic(
    path: &Path,
    bytes: &[u8],
) -> Result<(), ControlPlaneBenchmarkSplitReportWriteError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| {
            ControlPlaneBenchmarkSplitReportWriteError::Io {
                path: parent.to_path_buf(),
                source,
            }
        })?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| {
        ControlPlaneBenchmarkSplitReportWriteError::Io {
            path: temp_path.clone(),
            source,
        }
    })?;
    fs::rename(&temp_path, path).map_err(|source| ControlPlaneBenchmarkSplitReportWriteError::Io {
        path: path.to_path_buf(),
        source,
    })
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let sequence = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let mut temp_name = OsString::from(".");
    match path.file_name() {
        Some(file_name) => temp_name.push(file_name),
        None => temp_name.push("artifact"),
    }
    temp_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(temp_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metrics(
        throughput_ops_per_sec: u64,
        p50_ns: u64,
        p95_ns: u64,
        p99_ns: u64,
        peak_rss_delta_bytes: u64,
    ) -> SplitBenchmarkMetrics {
        SplitBenchmarkMetrics {
            throughput_ops_per_sec,
            latency_ns: LatencyStatsNs {
                p50_ns,
                p95_ns,
                p99_ns,
            },
            peak_rss_delta_bytes,
        }
    }

    fn previous_snapshot() -> BenchmarkSplitSnapshot {
        let split_metrics = BTreeMap::from([
            (
                BenchmarkSplit::Baseline,
                metrics(1_002_000, 950_000, 1_000_000, 1_050_000, 0),
            ),
            (
                BenchmarkSplit::CxThreading,
                metrics(997_000, 960_000, 1_008_000, 1_060_000, 8 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::DecisionContracts,
                metrics(994_000, 970_000, 1_052_000, 1_098_000, 16 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::EvidenceEmission,
                metrics(976_000, 980_000, 1_068_000, 1_116_000, 24 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::FullIntegration,
                metrics(958_000, 990_000, 1_080_000, 1_130_000, 30 * 1024 * 1024),
            ),
        ]);

        BenchmarkSplitSnapshot {
            snapshot_id: "previous-snapshot".to_string(),
            benchmark_run_id: "previous-run".to_string(),
            split_metrics,
            baseline_throughput_runs_ops_per_sec: vec![
                1_000_100, 1_000_300, 999_900, 1_000_200, 1_000_000, 1_000_250, 1_000_150,
                1_000_350, 999_950, 1_000_050,
            ],
        }
    }

    fn candidate_snapshot() -> BenchmarkSplitSnapshot {
        let split_metrics = BTreeMap::from([
            (
                BenchmarkSplit::Baseline,
                metrics(1_000_000, 950_000, 1_000_000, 1_050_000, 0),
            ),
            (
                BenchmarkSplit::CxThreading,
                metrics(995_000, 962_000, 1_008_000, 1_060_000, 8 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::DecisionContracts,
                metrics(993_500, 972_000, 1_055_000, 1_100_000, 16 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::EvidenceEmission,
                metrics(985_000, 980_000, 1_068_000, 1_115_000, 24 * 1024 * 1024),
            ),
            (
                BenchmarkSplit::FullIntegration,
                metrics(960_000, 990_000, 1_080_000, 1_130_000, 30 * 1024 * 1024),
            ),
        ]);

        BenchmarkSplitSnapshot {
            snapshot_id: "candidate-snapshot".to_string(),
            benchmark_run_id: "candidate-run".to_string(),
            split_metrics,
            baseline_throughput_runs_ops_per_sec: vec![
                1_000_100, 1_000_250, 999_950, 1_000_000, 1_000_150, 1_000_300, 999_975, 1_000_050,
                1_000_125, 1_000_225,
            ],
        }
    }

    fn input(
        previous: BenchmarkSplitSnapshot,
        candidate: BenchmarkSplitSnapshot,
    ) -> BenchmarkSplitGateInput {
        BenchmarkSplitGateInput {
            trace_id: "trace-cp-bench".to_string(),
            policy_id: "policy-cp-bench".to_string(),
            previous_snapshot: previous,
            candidate_snapshot: candidate,
        }
    }

    #[test]
    fn gate_passes_for_valid_split_inputs_and_emits_required_logs() {
        let decision = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate_snapshot()),
            &BenchmarkSplitThresholds::default(),
        );

        assert!(decision.pass);
        assert!(!decision.rollback_required);
        assert!(decision.findings.is_empty());
        assert_eq!(decision.evaluations.len(), 5);
        assert_eq!(
            decision.logs.last().map(|log| log.event.as_str()),
            Some("benchmark_split_decision")
        );
        assert!(decision.logs.iter().all(|log| {
            !log.trace_id.is_empty()
                && !log.decision_id.is_empty()
                && !log.policy_id.is_empty()
                && !log.component.is_empty()
                && !log.event.is_empty()
                && !log.outcome.is_empty()
        }));
    }

    #[test]
    fn gate_fails_when_baseline_variance_exceeds_threshold() {
        let mut candidate = candidate_snapshot();
        candidate.baseline_throughput_runs_ops_per_sec = vec![
            800_000, 1_200_000, 760_000, 1_240_000, 790_000, 1_210_000, 770_000, 1_250_000,
            810_000, 1_230_000,
        ];

        let decision = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );

        assert!(!decision.pass);
        assert!(decision.rollback_required);
        assert!(decision.findings.iter().any(|finding| {
            finding.code == BenchmarkSplitFailureCode::BaselineVarianceExceeded
                && finding.split == Some(BenchmarkSplit::Baseline)
        }));
    }

    #[test]
    fn gate_detects_adapter_sleep_regression() {
        let mut candidate = candidate_snapshot();
        let decision_metrics = candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::DecisionContracts)
            .expect("decision split present");
        decision_metrics.latency_ns.p95_ns = 1_300_000;
        decision_metrics.latency_ns.p99_ns = 1_380_000;

        let full_metrics = candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::FullIntegration)
            .expect("full split present");
        full_metrics.throughput_ops_per_sec = 900_000;

        let decision = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );

        assert!(!decision.pass);
        assert!(decision.rollback_required);
        assert!(decision.findings.iter().any(|finding| {
            finding.code == BenchmarkSplitFailureCode::LatencyRegressionExceeded
                && finding.split == Some(BenchmarkSplit::DecisionContracts)
        }));
    }

    #[test]
    fn split_isolation_without_evidence_matches_decision_throughput() {
        let mut candidate = candidate_snapshot();
        let decision_throughput = candidate
            .split_metrics
            .get(&BenchmarkSplit::DecisionContracts)
            .expect("decision split")
            .throughput_ops_per_sec;
        candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::EvidenceEmission)
            .expect("evidence split")
            .throughput_ops_per_sec = decision_throughput;
        candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::FullIntegration)
            .expect("full split")
            .throughput_ops_per_sec = decision_throughput;

        let decision = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );

        assert!(decision.pass);
        let evidence_eval = decision
            .evaluations
            .iter()
            .find(|evaluation| evaluation.split == BenchmarkSplit::EvidenceEmission)
            .expect("evidence evaluation");
        assert_eq!(
            evidence_eval.candidate_metrics.throughput_ops_per_sec,
            decision_throughput
        );
    }

    #[test]
    fn decision_id_is_stable_across_baseline_run_ordering() {
        let previous = previous_snapshot();

        let candidate_a = candidate_snapshot();
        let mut candidate_b = candidate_snapshot();
        candidate_b.baseline_throughput_runs_ops_per_sec.reverse();

        let decision_a = evaluate_control_plane_benchmark_split(
            &input(previous.clone(), candidate_a),
            &BenchmarkSplitThresholds::default(),
        );
        let decision_b = evaluate_control_plane_benchmark_split(
            &input(previous, candidate_b),
            &BenchmarkSplitThresholds::default(),
        );

        assert_eq!(decision_a.decision_id, decision_b.decision_id);
        assert_eq!(decision_a.pass, decision_b.pass);
        assert_eq!(decision_a.findings, decision_b.findings);
    }

    #[test]
    fn gate_fails_when_split_missing() {
        let previous = previous_snapshot();
        let mut candidate = candidate_snapshot();
        candidate
            .split_metrics
            .remove(&BenchmarkSplit::FullIntegration);

        let decision = evaluate_control_plane_benchmark_split(
            &input(previous, candidate),
            &BenchmarkSplitThresholds::default(),
        );

        assert!(!decision.pass);
        assert!(decision.rollback_required);
        assert!(decision.findings.iter().any(|finding| {
            finding.code == BenchmarkSplitFailureCode::MissingSplitMetrics
                && finding.split == Some(BenchmarkSplit::FullIntegration)
        }));
    }

    // ── BenchmarkSplit ───────────────────────────────────────────────

    #[test]
    fn benchmark_split_as_str_all() {
        assert_eq!(BenchmarkSplit::Baseline.as_str(), "baseline");
        assert_eq!(BenchmarkSplit::CxThreading.as_str(), "cx_threading");
        assert_eq!(
            BenchmarkSplit::DecisionContracts.as_str(),
            "decision_contracts"
        );
        assert_eq!(
            BenchmarkSplit::EvidenceEmission.as_str(),
            "evidence_emission"
        );
        assert_eq!(BenchmarkSplit::FullIntegration.as_str(), "full_integration");
    }

    #[test]
    fn benchmark_split_display() {
        assert_eq!(
            BenchmarkSplit::FullIntegration.to_string(),
            "full_integration"
        );
    }

    #[test]
    fn benchmark_split_ordering() {
        assert!(BenchmarkSplit::Baseline < BenchmarkSplit::FullIntegration);
    }

    #[test]
    fn benchmark_split_serde_roundtrip() {
        for split in [
            BenchmarkSplit::Baseline,
            BenchmarkSplit::CxThreading,
            BenchmarkSplit::DecisionContracts,
            BenchmarkSplit::EvidenceEmission,
            BenchmarkSplit::FullIntegration,
        ] {
            let json = serde_json::to_string(&split).unwrap();
            let back: BenchmarkSplit = serde_json::from_str(&json).unwrap();
            assert_eq!(back, split);
        }
    }

    // ── BenchmarkSplitFailureCode ────────────────────────────────────

    #[test]
    fn failure_code_display_all() {
        assert_eq!(
            BenchmarkSplitFailureCode::MissingSplitMetrics.to_string(),
            "missing_split_metrics"
        );
        assert_eq!(
            BenchmarkSplitFailureCode::InsufficientBaselineRuns.to_string(),
            "insufficient_baseline_runs"
        );
        assert_eq!(
            BenchmarkSplitFailureCode::BaselineVarianceExceeded.to_string(),
            "baseline_variance_exceeded"
        );
        assert_eq!(
            BenchmarkSplitFailureCode::InvalidMetric.to_string(),
            "invalid_metric"
        );
        assert_eq!(
            BenchmarkSplitFailureCode::ThroughputRegressionExceeded.to_string(),
            "throughput_regression_exceeded"
        );
        assert_eq!(
            BenchmarkSplitFailureCode::LatencyRegressionExceeded.to_string(),
            "latency_regression_exceeded"
        );
        assert_eq!(
            BenchmarkSplitFailureCode::MemoryOverheadExceeded.to_string(),
            "memory_overhead_exceeded"
        );
        assert_eq!(
            BenchmarkSplitFailureCode::PreviousRunRegressionExceeded.to_string(),
            "previous_run_regression_exceeded"
        );
    }

    #[test]
    fn failure_code_ordering() {
        assert!(
            BenchmarkSplitFailureCode::MissingSplitMetrics
                < BenchmarkSplitFailureCode::PreviousRunRegressionExceeded
        );
    }

    #[test]
    fn failure_code_serde_roundtrip() {
        for code in [
            BenchmarkSplitFailureCode::MissingSplitMetrics,
            BenchmarkSplitFailureCode::InsufficientBaselineRuns,
            BenchmarkSplitFailureCode::BaselineVarianceExceeded,
            BenchmarkSplitFailureCode::InvalidMetric,
            BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
            BenchmarkSplitFailureCode::LatencyRegressionExceeded,
            BenchmarkSplitFailureCode::MemoryOverheadExceeded,
            BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
        ] {
            let json = serde_json::to_string(&code).unwrap();
            let back: BenchmarkSplitFailureCode = serde_json::from_str(&json).unwrap();
            assert_eq!(back, code);
        }
    }

    // ── Thresholds ───────────────────────────────────────────────────

    #[test]
    fn thresholds_default_has_all_splits() {
        let t = BenchmarkSplitThresholds::default();
        assert_eq!(t.max_peak_rss_delta_bytes.len(), 5);
        assert_eq!(t.max_previous_run_throughput_regression_millionths.len(), 5);
        assert_eq!(t.min_baseline_runs, 10);
    }

    #[test]
    fn thresholds_serde_roundtrip() {
        let t = BenchmarkSplitThresholds::default();
        let json = serde_json::to_string(&t).unwrap();
        let back: BenchmarkSplitThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(back.min_baseline_runs, t.min_baseline_runs);
        assert_eq!(
            back.max_baseline_cv_millionths,
            t.max_baseline_cv_millionths
        );
    }

    // ── InsufficientBaselineRuns ──────────────────────────────────────

    #[test]
    fn gate_fails_when_insufficient_baseline_runs() {
        let mut candidate = candidate_snapshot();
        candidate.baseline_throughput_runs_ops_per_sec = vec![1_000_000; 3]; // < 10
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(!d.pass);
        assert!(
            d.findings
                .iter()
                .any(|f| { f.code == BenchmarkSplitFailureCode::InsufficientBaselineRuns })
        );
    }

    // ── InvalidMetric (zero throughput) ──────────────────────────────

    #[test]
    fn gate_finds_zero_throughput_invalid() {
        let mut candidate = candidate_snapshot();
        candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::Baseline)
            .unwrap()
            .throughput_ops_per_sec = 0;
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkSplitFailureCode::InvalidMetric
                && f.split == Some(BenchmarkSplit::Baseline)
        }));
    }

    // ── InvalidMetric (all-zero baseline runs) ───────────────────────

    #[test]
    fn gate_finds_invalid_baseline_cv() {
        let mut candidate = candidate_snapshot();
        candidate.baseline_throughput_runs_ops_per_sec = vec![0; 10];
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkSplitFailureCode::InvalidMetric
                && f.metric.as_deref() == Some("baseline_cv")
        }));
    }

    // ── CxThreading throughput regression ─────────────────────────────

    #[test]
    fn gate_detects_cx_threading_throughput_regression() {
        let mut candidate = candidate_snapshot();
        // Drop cx throughput significantly below baseline
        candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::CxThreading)
            .unwrap()
            .throughput_ops_per_sec = 800_000; // big drop from 1M baseline
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkSplitFailureCode::ThroughputRegressionExceeded
                && f.split == Some(BenchmarkSplit::CxThreading)
        }));
    }

    // ── Evidence throughput regression ────────────────────────────────

    #[test]
    fn gate_detects_evidence_throughput_regression() {
        let mut candidate = candidate_snapshot();
        // Drop evidence throughput well below decision contracts
        candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::EvidenceEmission)
            .unwrap()
            .throughput_ops_per_sec = 700_000;
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkSplitFailureCode::ThroughputRegressionExceeded
                && f.split == Some(BenchmarkSplit::EvidenceEmission)
        }));
    }

    // ── Full integration throughput regression ────────────────────────

    #[test]
    fn gate_detects_full_integration_throughput_regression() {
        let mut candidate = candidate_snapshot();
        candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::FullIntegration)
            .unwrap()
            .throughput_ops_per_sec = 800_000;
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkSplitFailureCode::ThroughputRegressionExceeded
                && f.split == Some(BenchmarkSplit::FullIntegration)
        }));
    }

    // ── Memory overhead exceeded ─────────────────────────────────────

    #[test]
    fn gate_detects_memory_overhead_exceeded() {
        let mut candidate = candidate_snapshot();
        candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::CxThreading)
            .unwrap()
            .peak_rss_delta_bytes = 100 * 1024 * 1024; // 100MB, limit is 16MB
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkSplitFailureCode::MemoryOverheadExceeded
                && f.split == Some(BenchmarkSplit::CxThreading)
        }));
    }

    // ── Previous run regression ──────────────────────────────────────

    #[test]
    fn gate_detects_previous_run_throughput_regression() {
        let mut candidate = candidate_snapshot();
        // Baseline throughput drops significantly vs previous
        candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::Baseline)
            .unwrap()
            .throughput_ops_per_sec = 800_000; // 20% drop
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkSplitFailureCode::PreviousRunRegressionExceeded
                && f.metric.as_deref() == Some("throughput_ops_per_sec")
        }));
    }

    #[test]
    fn gate_detects_previous_run_latency_regression() {
        let mut candidate = candidate_snapshot();
        // Latency balloons vs previous
        candidate
            .split_metrics
            .get_mut(&BenchmarkSplit::Baseline)
            .unwrap()
            .latency_ns
            .p95_ns = 2_000_000; // 100% increase
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkSplitFailureCode::PreviousRunRegressionExceeded
                && f.metric.as_deref() == Some("latency_ns.p95_p99")
        }));
    }

    // ── Helper functions ─────────────────────────────────────────────

    #[test]
    fn throughput_regression_no_drop() {
        assert_eq!(throughput_regression_millionths(1000, 1000), 0);
        assert_eq!(throughput_regression_millionths(1000, 1500), 0);
    }

    #[test]
    fn throughput_regression_50_percent() {
        assert_eq!(throughput_regression_millionths(1000, 500), 500_000);
    }

    #[test]
    fn throughput_regression_zero_reference() {
        assert_eq!(throughput_regression_millionths(0, 100), u64::MAX);
    }

    #[test]
    fn latency_regression_no_increase() {
        assert_eq!(latency_regression_millionths(1000, 1000), 0);
        assert_eq!(latency_regression_millionths(1000, 500), 0);
    }

    #[test]
    fn latency_regression_50_percent() {
        assert_eq!(latency_regression_millionths(1000, 1500), 500_000);
    }

    #[test]
    fn latency_regression_zero_reference() {
        assert_eq!(latency_regression_millionths(0, 100), u64::MAX);
    }

    #[test]
    fn coefficient_of_variation_empty() {
        assert_eq!(coefficient_of_variation_millionths(&[]), None);
    }

    #[test]
    fn coefficient_of_variation_all_zero() {
        assert_eq!(coefficient_of_variation_millionths(&[0, 0, 0]), None);
    }

    #[test]
    fn coefficient_of_variation_identical() {
        assert_eq!(
            coefficient_of_variation_millionths(&[100, 100, 100]),
            Some(0)
        );
    }

    #[test]
    fn coefficient_of_variation_normal() {
        let cv = coefficient_of_variation_millionths(&[100, 110, 90, 105, 95]).unwrap();
        assert!(cv > 0);
        assert!(cv < 100_000); // should be around 7%
    }

    // ── Snapshot hash ────────────────────────────────────────────────

    #[test]
    fn snapshot_hash_deterministic() {
        let s = candidate_snapshot();
        assert_eq!(s.snapshot_hash(), s.snapshot_hash());
    }

    #[test]
    fn snapshot_hash_changes_with_data() {
        assert_ne!(
            previous_snapshot().snapshot_hash(),
            candidate_snapshot().snapshot_hash()
        );
    }

    // ── Decision ID ──────────────────────────────────────────────────

    #[test]
    fn decision_id_prefix() {
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate_snapshot()),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(d.decision_id.starts_with("cp-bench-split-"));
    }

    #[test]
    fn decision_id_changes_with_trace() {
        let mut inp = input(previous_snapshot(), candidate_snapshot());
        let d1 = evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
        inp.trace_id = "different-trace".into();
        let d2 = evaluate_control_plane_benchmark_split(&inp, &BenchmarkSplitThresholds::default());
        assert_ne!(d1.decision_id, d2.decision_id);
    }

    // ── pass/rollback symmetry ───────────────────────────────────────

    #[test]
    fn pass_and_rollback_inverse() {
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate_snapshot()),
            &BenchmarkSplitThresholds::default(),
        );
        assert_eq!(d.pass, !d.rollback_required);
    }

    // ── Logs ─────────────────────────────────────────────────────────

    #[test]
    fn logs_carry_trace_and_policy() {
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate_snapshot()),
            &BenchmarkSplitThresholds::default(),
        );
        for log in &d.logs {
            assert_eq!(log.trace_id, "trace-cp-bench");
            assert_eq!(log.policy_id, "policy-cp-bench");
            assert_eq!(log.component, "control_plane_benchmark_split_gate");
        }
    }

    #[test]
    fn logs_final_event_passes_for_good_input() {
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate_snapshot()),
            &BenchmarkSplitThresholds::default(),
        );
        let last = d.logs.last().unwrap();
        assert_eq!(last.event, "benchmark_split_decision");
        assert_eq!(last.outcome, "pass");
        assert!(last.error_code.is_none());
    }

    #[test]
    fn logs_baseline_stability_check_present() {
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate_snapshot()),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(d.logs.iter().any(|l| l.event == "baseline_stability_check"));
    }

    // ── Serde roundtrips ─────────────────────────────────────────────

    #[test]
    fn decision_serde_roundtrip() {
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate_snapshot()),
            &BenchmarkSplitThresholds::default(),
        );
        let json = serde_json::to_string(&d).unwrap();
        let back: BenchmarkSplitGateDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(back.decision_id, d.decision_id);
        assert_eq!(back.pass, d.pass);
        assert_eq!(back.evaluations, d.evaluations);
    }

    #[test]
    fn finding_serde_roundtrip() {
        let f = BenchmarkSplitFinding {
            code: BenchmarkSplitFailureCode::MemoryOverheadExceeded,
            split: Some(BenchmarkSplit::CxThreading),
            metric: Some("peak_rss_delta_bytes".into()),
            detail: "test".into(),
            observed_millionths: Some(100),
            threshold_millionths: Some(50),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: BenchmarkSplitFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn log_event_serde_roundtrip() {
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate_snapshot()),
            &BenchmarkSplitThresholds::default(),
        );
        for log in &d.logs {
            let json = serde_json::to_string(log).unwrap();
            let back: BenchmarkSplitLogEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, log);
        }
    }

    #[test]
    fn evaluation_serde_roundtrip() {
        let d = evaluate_control_plane_benchmark_split(
            &input(previous_snapshot(), candidate_snapshot()),
            &BenchmarkSplitThresholds::default(),
        );
        for eval in &d.evaluations {
            let json = serde_json::to_string(eval).unwrap();
            let back: SplitBenchmarkEvaluation = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, eval);
        }
    }

    #[test]
    fn split_metrics_serde_roundtrip() {
        let m = metrics(1_000_000, 500_000, 800_000, 900_000, 1024);
        let json = serde_json::to_string(&m).unwrap();
        let back: SplitBenchmarkMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(back, m);
    }

    // ── Previous snapshot missing split ──────────────────────────────

    #[test]
    fn gate_fails_when_previous_missing_split() {
        let mut previous = previous_snapshot();
        previous.split_metrics.remove(&BenchmarkSplit::CxThreading);
        let d = evaluate_control_plane_benchmark_split(
            &input(previous, candidate_snapshot()),
            &BenchmarkSplitThresholds::default(),
        );
        assert!(!d.pass);
        assert!(d.findings.iter().any(|f| {
            f.code == BenchmarkSplitFailureCode::MissingSplitMetrics
                && f.split == Some(BenchmarkSplit::CxThreading)
                && f.detail.contains("previous")
        }));
    }

    // -----------------------------------------------------------------------
    // Enrichment batch — PearlTower 2026-02-25
    // -----------------------------------------------------------------------

    #[test]
    fn benchmark_split_display_uniqueness_btreeset() {
        let splits = [
            BenchmarkSplit::Baseline,
            BenchmarkSplit::CxThreading,
            BenchmarkSplit::DecisionContracts,
            BenchmarkSplit::EvidenceEmission,
            BenchmarkSplit::FullIntegration,
        ];
        let mut displays = BTreeSet::new();
        for s in &splits {
            displays.insert(s.to_string());
        }
        assert_eq!(
            displays.len(),
            5,
            "all BenchmarkSplit variants produce distinct Display strings"
        );
    }

    #[test]
    fn latency_stats_ns_serde_roundtrip() {
        let stats = LatencyStatsNs {
            p50_ns: 1_000,
            p95_ns: 2_000,
            p99_ns: 3_000,
        };
        let json = serde_json::to_string(&stats).unwrap();
        let back: LatencyStatsNs = serde_json::from_str(&json).unwrap();
        assert_eq!(stats, back);
    }

    #[test]
    fn split_benchmark_metrics_serde_roundtrip() {
        let m = metrics(500_000, 100, 200, 300, 1024);
        let json = serde_json::to_string(&m).unwrap();
        let back: SplitBenchmarkMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn benchmark_split_snapshot_serde_roundtrip() {
        let snap = previous_snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: BenchmarkSplitSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn benchmark_split_as_str_matches_display() {
        for s in [
            BenchmarkSplit::Baseline,
            BenchmarkSplit::CxThreading,
            BenchmarkSplit::DecisionContracts,
            BenchmarkSplit::EvidenceEmission,
            BenchmarkSplit::FullIntegration,
        ] {
            assert_eq!(s.as_str(), &s.to_string());
        }
    }

    #[test]
    fn enrichment_default_thresholds_have_sane_values() {
        let t = BenchmarkSplitThresholds::default();
        assert!(
            t.max_cx_throughput_regression_millionths > 0,
            "cx throughput regression threshold must be positive"
        );
        assert!(
            t.min_baseline_runs > 0,
            "min baseline runs must be positive"
        );
    }

    #[test]
    fn latency_stats_canonical_value_deterministic() {
        let stats = LatencyStatsNs {
            p50_ns: 500,
            p95_ns: 1000,
            p99_ns: 1500,
        };
        let v1 = stats.canonical_value();
        let v2 = stats.canonical_value();
        assert_eq!(v1, v2, "canonical_value must be deterministic");
    }

    // ── Enrichment: Copy semantics ──────────────────────────────────

    #[test]
    fn benchmark_split_copy_from_array() {
        let arr = [
            BenchmarkSplit::Baseline,
            BenchmarkSplit::CxThreading,
            BenchmarkSplit::DecisionContracts,
            BenchmarkSplit::EvidenceEmission,
            BenchmarkSplit::FullIntegration,
        ];
        let copied = arr[3];
        assert_eq!(copied, BenchmarkSplit::EvidenceEmission);
        assert_eq!(arr[3], BenchmarkSplit::EvidenceEmission);
    }

    #[test]
    fn failure_code_copy_from_array() {
        let arr = [
            BenchmarkSplitFailureCode::MissingSplitMetrics,
            BenchmarkSplitFailureCode::InsufficientBaselineRuns,
            BenchmarkSplitFailureCode::BaselineVarianceExceeded,
            BenchmarkSplitFailureCode::InvalidMetric,
            BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
            BenchmarkSplitFailureCode::LatencyRegressionExceeded,
            BenchmarkSplitFailureCode::MemoryOverheadExceeded,
            BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
        ];
        let copied = arr[5];
        assert_eq!(copied, BenchmarkSplitFailureCode::LatencyRegressionExceeded);
        assert_eq!(arr[5], BenchmarkSplitFailureCode::LatencyRegressionExceeded);
    }

    // ── Enrichment: Debug distinctness ──────────────────────────────

    #[test]
    fn benchmark_split_debug_all_distinct() {
        let dbgs: BTreeSet<String> = [
            BenchmarkSplit::Baseline,
            BenchmarkSplit::CxThreading,
            BenchmarkSplit::DecisionContracts,
            BenchmarkSplit::EvidenceEmission,
            BenchmarkSplit::FullIntegration,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(dbgs.len(), 5);
    }

    #[test]
    fn failure_code_debug_all_distinct() {
        let dbgs: BTreeSet<String> = [
            BenchmarkSplitFailureCode::MissingSplitMetrics,
            BenchmarkSplitFailureCode::InsufficientBaselineRuns,
            BenchmarkSplitFailureCode::BaselineVarianceExceeded,
            BenchmarkSplitFailureCode::InvalidMetric,
            BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
            BenchmarkSplitFailureCode::LatencyRegressionExceeded,
            BenchmarkSplitFailureCode::MemoryOverheadExceeded,
            BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
        ]
        .iter()
        .map(|v| format!("{v:?}"))
        .collect();
        assert_eq!(dbgs.len(), 8);
    }

    // ── Enrichment: Serde variant distinctness ──────────────────────

    #[test]
    fn benchmark_split_serde_variants_distinct() {
        let variants = [
            BenchmarkSplit::Baseline,
            BenchmarkSplit::CxThreading,
            BenchmarkSplit::DecisionContracts,
            BenchmarkSplit::EvidenceEmission,
            BenchmarkSplit::FullIntegration,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 5);
    }

    #[test]
    fn failure_code_serde_variants_distinct() {
        let variants = [
            BenchmarkSplitFailureCode::MissingSplitMetrics,
            BenchmarkSplitFailureCode::InsufficientBaselineRuns,
            BenchmarkSplitFailureCode::BaselineVarianceExceeded,
            BenchmarkSplitFailureCode::InvalidMetric,
            BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
            BenchmarkSplitFailureCode::LatencyRegressionExceeded,
            BenchmarkSplitFailureCode::MemoryOverheadExceeded,
            BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
        ];
        let jsons: BTreeSet<String> = variants
            .iter()
            .map(|v| serde_json::to_string(v).unwrap())
            .collect();
        assert_eq!(jsons.len(), 8);
    }

    // ── Enrichment: Clone independence ──────────────────────────────

    #[test]
    fn latency_stats_clone_independence() {
        let mut original = LatencyStatsNs {
            p50_ns: 100,
            p95_ns: 200,
            p99_ns: 300,
        };
        let cloned = original.clone();
        original.p99_ns = 999;
        assert_eq!(original.p99_ns, 999);
        assert_eq!(cloned.p99_ns, 300);
    }

    #[test]
    fn split_metrics_clone_independence() {
        let mut original = SplitBenchmarkMetrics {
            throughput_ops_per_sec: 1000,
            latency_ns: LatencyStatsNs {
                p50_ns: 10,
                p95_ns: 20,
                p99_ns: 30,
            },
            peak_rss_delta_bytes: 1024,
        };
        let cloned = original.clone();
        original.throughput_ops_per_sec = 0;
        assert_eq!(original.throughput_ops_per_sec, 0);
        assert_eq!(cloned.throughput_ops_per_sec, 1000);
    }

    #[test]
    fn finding_clone_independence() {
        let mut original = BenchmarkSplitFinding {
            code: BenchmarkSplitFailureCode::InvalidMetric,
            split: Some(BenchmarkSplit::Baseline),
            metric: Some("throughput".into()),
            detail: "original detail".into(),
            observed_millionths: Some(100_000),
            threshold_millionths: Some(50_000),
        };
        let cloned = original.clone();
        original.detail = "mutated".into();
        assert_eq!(cloned.detail, "original detail");
    }

    #[test]
    fn thresholds_clone_independence() {
        let mut original = BenchmarkSplitThresholds::default();
        let cloned = original.clone();
        original.min_baseline_runs = 999;
        assert_eq!(cloned.min_baseline_runs, 10);
    }

    // ── Enrichment: JSON field-name stability ───────────────────────

    #[test]
    fn latency_stats_json_field_names() {
        let stats = LatencyStatsNs {
            p50_ns: 100,
            p95_ns: 200,
            p99_ns: 300,
        };
        let val: serde_json::Value = serde_json::to_value(&stats).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("p50_ns"));
        assert!(obj.contains_key("p95_ns"));
        assert!(obj.contains_key("p99_ns"));
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn split_metrics_json_field_names() {
        let m = SplitBenchmarkMetrics {
            throughput_ops_per_sec: 1000,
            latency_ns: LatencyStatsNs {
                p50_ns: 10,
                p95_ns: 20,
                p99_ns: 30,
            },
            peak_rss_delta_bytes: 1024,
        };
        let val: serde_json::Value = serde_json::to_value(&m).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("throughput_ops_per_sec"));
        assert!(obj.contains_key("latency_ns"));
        assert!(obj.contains_key("peak_rss_delta_bytes"));
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn finding_json_field_names() {
        let f = BenchmarkSplitFinding {
            code: BenchmarkSplitFailureCode::InvalidMetric,
            split: None,
            metric: None,
            detail: "test".into(),
            observed_millionths: None,
            threshold_millionths: None,
        };
        let val: serde_json::Value = serde_json::to_value(&f).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("code"));
        assert!(obj.contains_key("split"));
        assert!(obj.contains_key("metric"));
        assert!(obj.contains_key("detail"));
        assert!(obj.contains_key("observed_millionths"));
        assert!(obj.contains_key("threshold_millionths"));
        assert_eq!(obj.len(), 6);
    }

    #[test]
    fn log_event_json_field_names() {
        let ev = BenchmarkSplitLogEvent {
            trace_id: "t".into(),
            decision_id: "d".into(),
            policy_id: "p".into(),
            component: "c".into(),
            event: "e".into(),
            outcome: "o".into(),
            error_code: None,
            split: None,
            metric: None,
        };
        let val: serde_json::Value = serde_json::to_value(&ev).unwrap();
        let obj = val.as_object().unwrap();
        assert!(obj.contains_key("trace_id"));
        assert!(obj.contains_key("decision_id"));
        assert!(obj.contains_key("policy_id"));
        assert!(obj.contains_key("component"));
        assert!(obj.contains_key("event"));
        assert!(obj.contains_key("outcome"));
        assert!(obj.contains_key("error_code"));
        assert!(obj.contains_key("split"));
        assert!(obj.contains_key("metric"));
        assert_eq!(obj.len(), 9);
    }

    // ── Enrichment: Display format ──────────────────────────────────

    #[test]
    fn benchmark_split_display_all_snake_case() {
        for s in [
            BenchmarkSplit::Baseline,
            BenchmarkSplit::CxThreading,
            BenchmarkSplit::DecisionContracts,
            BenchmarkSplit::EvidenceEmission,
            BenchmarkSplit::FullIntegration,
        ] {
            let display = s.to_string();
            assert!(!display.is_empty());
            assert!(display.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }

    #[test]
    fn failure_code_display_all_snake_case() {
        for c in [
            BenchmarkSplitFailureCode::MissingSplitMetrics,
            BenchmarkSplitFailureCode::InsufficientBaselineRuns,
            BenchmarkSplitFailureCode::BaselineVarianceExceeded,
            BenchmarkSplitFailureCode::InvalidMetric,
            BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
            BenchmarkSplitFailureCode::LatencyRegressionExceeded,
            BenchmarkSplitFailureCode::MemoryOverheadExceeded,
            BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
        ] {
            let display = c.to_string();
            assert!(!display.is_empty());
            assert!(
                display
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch == '_')
            );
        }
    }

    #[test]
    fn failure_code_display_all_distinct() {
        let displays: BTreeSet<String> = [
            BenchmarkSplitFailureCode::MissingSplitMetrics,
            BenchmarkSplitFailureCode::InsufficientBaselineRuns,
            BenchmarkSplitFailureCode::BaselineVarianceExceeded,
            BenchmarkSplitFailureCode::InvalidMetric,
            BenchmarkSplitFailureCode::ThroughputRegressionExceeded,
            BenchmarkSplitFailureCode::LatencyRegressionExceeded,
            BenchmarkSplitFailureCode::MemoryOverheadExceeded,
            BenchmarkSplitFailureCode::PreviousRunRegressionExceeded,
        ]
        .iter()
        .map(|v| v.to_string())
        .collect();
        assert_eq!(displays.len(), 8);
    }

    // ── Enrichment: Serde roundtrips ────────────────────────────────

    #[test]
    fn finding_serde_roundtrip_enrichment() {
        let f = BenchmarkSplitFinding {
            code: BenchmarkSplitFailureCode::MemoryOverheadExceeded,
            split: Some(BenchmarkSplit::FullIntegration),
            metric: Some("peak_rss_delta_bytes".into()),
            detail: "over limit".into(),
            observed_millionths: Some(200_000),
            threshold_millionths: Some(100_000),
        };
        let json = serde_json::to_string(&f).unwrap();
        let back: BenchmarkSplitFinding = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    #[test]
    fn log_event_serde_roundtrip_enrichment() {
        let ev = BenchmarkSplitLogEvent {
            trace_id: "trace-1".into(),
            decision_id: "dec-1".into(),
            policy_id: "pol-1".into(),
            component: "control_plane_benchmark_split_gate".into(),
            event: "evaluate".into(),
            outcome: "pass".into(),
            error_code: Some("E001".into()),
            split: Some("baseline".into()),
            metric: Some("throughput".into()),
        };
        let json = serde_json::to_string(&ev).unwrap();
        let back: BenchmarkSplitLogEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    #[test]
    fn thresholds_serde_roundtrip_enrichment() {
        let t = BenchmarkSplitThresholds::default();
        let json = serde_json::to_string(&t).unwrap();
        let back: BenchmarkSplitThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(t, back);
    }

    // ── Enrichment: Boundary/edge cases ─────────────────────────────

    #[test]
    fn throughput_regression_zero_reference_returns_max() {
        assert_eq!(throughput_regression_millionths(0, 1000), u64::MAX);
    }

    #[test]
    fn throughput_regression_candidate_exceeds_reference_returns_zero() {
        assert_eq!(throughput_regression_millionths(1000, 2000), 0);
    }

    #[test]
    fn throughput_regression_exact_half() {
        // 1000 -> 500 = 50% regression = 500_000 millionths
        assert_eq!(throughput_regression_millionths(1000, 500), 500_000);
    }

    #[test]
    fn latency_regression_zero_reference_returns_max() {
        assert_eq!(latency_regression_millionths(0, 1000), u64::MAX);
    }

    #[test]
    fn latency_regression_candidate_below_reference_returns_zero() {
        assert_eq!(latency_regression_millionths(1000, 500), 0);
    }

    #[test]
    fn latency_regression_double() {
        // 1000 -> 2000 = 100% regression = 1_000_000 millionths
        assert_eq!(latency_regression_millionths(1000, 2000), 1_000_000);
    }

    #[test]
    fn cv_empty_samples_returns_none() {
        assert_eq!(coefficient_of_variation_millionths(&[]), None);
    }

    #[test]
    fn cv_identical_samples_returns_zero() {
        assert_eq!(
            coefficient_of_variation_millionths(&[100, 100, 100]),
            Some(0)
        );
    }

    #[test]
    fn cv_zero_mean_returns_none() {
        assert_eq!(coefficient_of_variation_millionths(&[0, 0, 0]), None);
    }

    #[test]
    fn cv_single_sample_returns_zero() {
        assert_eq!(coefficient_of_variation_millionths(&[42]), Some(0));
    }

    #[test]
    fn benchmark_split_all_required_contains_five() {
        assert_eq!(BenchmarkSplit::all_required().len(), 5);
    }

    #[test]
    fn snapshot_hash_deterministic_enrichment() {
        let snap = previous_snapshot();
        let h1 = snap.snapshot_hash();
        let h2 = snap.snapshot_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn snapshot_hash_differs_for_different_ids() {
        let mut s1 = previous_snapshot();
        let mut s2 = previous_snapshot();
        s1.snapshot_id = "snap-A".into();
        s2.snapshot_id = "snap-B".into();
        assert_ne!(s1.snapshot_hash(), s2.snapshot_hash());
    }

    // ── Enrichment: Debug nonempty ──────────────────────────────────

    #[test]
    fn latency_stats_debug_nonempty() {
        let stats = LatencyStatsNs {
            p50_ns: 100,
            p95_ns: 200,
            p99_ns: 300,
        };
        let dbg = format!("{stats:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("LatencyStatsNs"));
    }

    #[test]
    fn gate_input_debug_nonempty() {
        let snap = previous_snapshot();
        let input = BenchmarkSplitGateInput {
            trace_id: "trace-1".into(),
            policy_id: "pol-1".into(),
            previous_snapshot: snap.clone(),
            candidate_snapshot: snap,
        };
        let dbg = format!("{input:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("BenchmarkSplitGateInput"));
    }

    #[test]
    fn thresholds_debug_nonempty() {
        let t = BenchmarkSplitThresholds::default();
        let dbg = format!("{t:?}");
        assert!(!dbg.is_empty());
        assert!(dbg.contains("BenchmarkSplitThresholds"));
    }
}
