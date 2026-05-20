#![forbid(unsafe_code)]

//! Throughput disruptive-floor metric gate with Node and Bun denominators.
//!
//! This child gate produces the `weighted_throughput_node_bun` metric
//! artifact consumed by `disruptive_floor_metric_gate`.

use serde::{Deserialize, Serialize};
// bd-pvr9h: BTreeMap, not HashMap — README.md L921 + AGENTS.md mission
// language require iteration order to be deterministic anywhere it can
// reach a content hash or a serde output, and the throughput gate
// outputs feed both the >=3x claim and the disruptive_floor_metric_gate
// aggregator. HashMap iteration order is unspecified, so its serde
// output is non-deterministic.
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use subtle::ConstantTimeEq;
use thiserror::Error;

use crate::disruptive_floor_metric_gate::{DisruptiveMetricId, MetricArtifact};

pub const SCHEMA_VERSION: &str = "franken-engine.throughput-disruptive-floor-metric-gate.v1";
pub const COMPONENT: &str = "throughput_disruptive_floor_metric_gate";
pub const BEAD_ID: &str = "bd-y6v8s";
pub const THROUGHPUT_SCALE_OPS_PER_SECOND: u64 = 1000;
pub const DEFAULT_FLOOR_RATIO_MILLIONTHS: u64 = 950_000; // 0.95 minimum ratio
pub const DEFAULT_MAX_FRESHNESS_DAYS: u64 = 14; // Default maximum age for evidence
pub const DEFAULT_MAX_BENCHMARK_DURATION_MS: u64 = 3_600_000; // 1 hour maximum

/// Baseline manifest file path relative to project root
pub const BASELINE_MANIFEST_PATH: &str = "docs/throughput_baseline_measurements_v1.json";

#[derive(Debug)]
struct ThroughputMetricClockAnchor {
    monotonic_origin: Instant,
    utc_origin: chrono::DateTime<chrono::Utc>,
}

static THROUGHPUT_METRIC_CLOCK_ANCHOR: OnceLock<ThroughputMetricClockAnchor> = OnceLock::new();

fn throughput_metric_clock_anchor() -> &'static ThroughputMetricClockAnchor {
    THROUGHPUT_METRIC_CLOCK_ANCHOR.get_or_init(|| ThroughputMetricClockAnchor {
        monotonic_origin: Instant::now(),
        utc_origin: chrono::Utc::now(),
    })
}

fn duration_as_nanos_saturating(duration: Duration) -> u64 {
    u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX)
}

/// Current process-relative monotonic timestamp in nanoseconds.
pub fn current_monotonic_ns() -> u64 {
    duration_as_nanos_saturating(throughput_metric_clock_anchor().monotonic_origin.elapsed())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineManifest {
    pub schema_version: String,
    pub generated_at: String,
    pub measurement_duration_ms: u64,
    pub workloads: Vec<String>,
    pub runtimes: BTreeMap<String, RuntimeBaseline>,
    pub has_live_measurements: bool,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeBaseline {
    pub version: String,
    pub baseline_ops_per_second: u64,
    pub workload_results: BTreeMap<String, u64>,
}

/// Load baseline manifest from file system or return error if unavailable
pub fn load_baseline_manifest() -> Result<BaselineManifest, String> {
    // First try to find the manifest relative to the project root
    let potential_paths = [
        BASELINE_MANIFEST_PATH,
        "../../docs/throughput_baseline_measurements_v1.json", // From crates/franken-engine/
        "../../../docs/throughput_baseline_measurements_v1.json", // From crates/franken-engine/target/
    ];

    for path in &potential_paths {
        if Path::new(path).exists() {
            let content = fs::read_to_string(path)
                .map_err(|e| format!("Failed to read baseline manifest {}: {}", path, e))?;

            let manifest: BaselineManifest = serde_json::from_str(&content)
                .map_err(|e| format!("Failed to parse baseline manifest {}: {}", path, e))?;

            return Ok(manifest);
        }
    }

    Err(format!(
        "Baseline manifest not found at any of: {}",
        potential_paths.join(", ")
    ))
}

/// Detect fake SHA256 hash patterns that indicate placeholder/test data rather than real measurements
pub fn is_fake_hash(hash: &str) -> bool {
    if !hash.starts_with("sha256:") {
        return false;
    }

    let hex_part = &hash[7..]; // Skip "sha256:" prefix
    if hex_part.len() != 64 {
        return false; // Not a valid SHA256 hex length
    }

    // Sequential hex pattern (0123456789abcdef...)
    let sequential_pattern = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    if hex_part == sequential_pattern {
        return true;
    }

    // All zeros
    if hex_part == "0".repeat(64) {
        return true;
    }

    // All the same character repeated
    if hex_part
        .chars()
        .all(|c| c == hex_part.chars().next().unwrap_or('x'))
    {
        return true;
    }

    // Common placeholder patterns
    let placeholder_patterns = [
        "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        "cafebabecafebabecafebabecafebabecafebabecafebabecafebabecafebabe",
        "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
    ];

    placeholder_patterns.contains(&hex_part)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThroughputMeasurementStatus {
    Verified,   // Real measurement with proper evidence and live baselines
    Targeted,   // Uses placeholder baselines or lacks complete evidence
    Unmeasured, // No measurement attempted
}

impl ThroughputMeasurementStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::Targeted => "targeted",
            Self::Unmeasured => "unmeasured",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeDenominator {
    Node,
    Bun,
}

impl RuntimeDenominator {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Bun => "bun",
        }
    }

    /// Get baseline operations per second, trying live measurements first, falling back to placeholders
    pub fn baseline_ops_per_second(self) -> u64 {
        if let Ok(manifest) = load_baseline_manifest()
            && manifest.has_live_measurements
            && let Some(runtime_baseline) = manifest.runtimes.get(self.as_str())
        {
            return runtime_baseline.baseline_ops_per_second;
        }

        // Fallback to placeholder values if manifest unavailable or no live measurements
        match self {
            Self::Node => 2500, // Placeholder baseline: Node.js ops/sec
            Self::Bun => 3200,  // Placeholder baseline: Bun ops/sec
        }
    }

    /// Check if current baseline is a placeholder (not from live measurements)
    pub fn is_placeholder_baseline(self) -> bool {
        if let Ok(manifest) = load_baseline_manifest()
            && manifest.has_live_measurements
            && manifest.runtimes.contains_key(self.as_str())
        {
            return false; // Has live measurements
        }

        // No live measurements available - using placeholder
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputEvidence {
    pub scenario_id: String,
    pub runtime_denominator: RuntimeDenominator,
    pub frankenengine_ops_per_second: u64,
    pub denominator_ops_per_second: u64,
    pub throughput_ratio_millionths: u64, // FrankenEngine/Denominator * 1_000_000
    pub benchmark_duration_ms: u64,
    pub request_count: u64,
    pub error_count: u64,
    pub success_rate_millionths: u64,
    pub scenario_path: String,
    pub output_path: String,
    pub output_hash: String,
    pub verification_command: String,
    pub benchmark_start_monotonic_ns: u64, // Monotonic timestamp for timing attack protection
    pub benchmark_window_seed: [u8; 32],   // Verifier-chosen seed for window pinning
    pub measurement_status: ThroughputMeasurementStatus,
    pub evidence_bead_id: Option<String>,
    pub evidence_commit_hash: Option<String>,
    pub evidence_test_name: Option<String>,
}

impl ThroughputEvidence {
    pub fn calculate_ratio_millionths(
        frankenengine_ops_per_second: u64,
        denominator_ops_per_second: u64,
    ) -> u64 {
        frankenengine_ops_per_second
            .saturating_mul(1_000_000)
            .checked_div(denominator_ops_per_second)
            .unwrap_or(0)
    }

    pub fn meets_floor_threshold(&self, floor_ratio_millionths: u64) -> bool {
        // Use constant-time comparison to prevent timing attacks on threshold checks
        let ratio_bytes = self.throughput_ratio_millionths.to_le_bytes();
        let threshold_bytes = floor_ratio_millionths.to_le_bytes();

        // Compare byte-by-byte in constant time, checking if ratio >= threshold
        constant_time_greater_or_equal(&ratio_bytes, &threshold_bytes)
    }
}

/// Constant-time comparison to check if `a >= b` for little-endian byte arrays.
/// Prevents timing attacks on threshold comparisons.
fn constant_time_greater_or_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut greater = 0u8;
    let mut equal = 1u8;

    // Compare from most significant byte to least significant (reverse for little-endian)
    for i in (0..a.len()).rev() {
        let a_byte = a[i];
        let b_byte = b[i];

        // If we haven't determined greater/less yet (equal == 1)
        let byte_greater = (a_byte > b_byte) as u8;
        // Update greater flag only if we're still equal
        greater |= equal & byte_greater;

        // Update equal flag - remains 1 only if all bytes so far are equal
        equal &= a_byte.ct_eq(&b_byte).unwrap_u8();
    }

    // Result is greater || equal (i.e., >=)
    (greater | equal) == 1
}

/// Validates monotonic timestamp to prevent clock manipulation attacks
pub fn validate_monotonic_timestamp(
    benchmark_start_ns: u64,
    current_monotonic_ns: u64,
    max_benchmark_duration_ns: u64,
) -> Result<(), String> {
    // Ensure benchmark started before current time
    if benchmark_start_ns > current_monotonic_ns {
        return Err(
            "Benchmark start time is in the future - possible clock manipulation".to_string(),
        );
    }

    // Ensure benchmark duration is reasonable
    let duration_ns = current_monotonic_ns - benchmark_start_ns;
    if duration_ns > max_benchmark_duration_ns {
        return Err(format!(
            "Benchmark duration {}ns exceeds maximum {}ns - possible timing attack",
            duration_ns, max_benchmark_duration_ns
        ));
    }

    Ok(())
}

/// Validates benchmark window pinning to prevent cherry-picking attacks
pub fn validate_benchmark_window_pinning(
    evidence: &[ThroughputEvidence],
    expected_seed: &[u8; 32],
) -> Result<(), String> {
    if evidence.is_empty() {
        return Err("No evidence provided for window validation".to_string());
    }

    for (i, ev) in evidence.iter().enumerate() {
        if &ev.benchmark_window_seed != expected_seed {
            return Err(format!(
                "Evidence {} has incorrect window seed - possible cherry-picking attack",
                i
            ));
        }
    }

    Ok(())
}

/// Generates a UTC report timestamp from a process monotonic clock anchor.
pub fn generate_secure_timestamp() -> String {
    let anchor = throughput_metric_clock_anchor();
    let generated_at = chrono::Duration::from_std(anchor.monotonic_origin.elapsed())
        .ok()
        .and_then(|elapsed| anchor.utc_origin.checked_add_signed(elapsed))
        .unwrap_or(anchor.utc_origin);

    generated_at.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

/// Validate evidence requirements for throughput measurement claims
pub fn validate_measurement_evidence(evidence: &ThroughputEvidence) -> bool {
    match evidence.measurement_status {
        ThroughputMeasurementStatus::Verified => {
            // Requires all evidence fields for verified measurements
            evidence
                .evidence_bead_id
                .as_ref()
                .is_some_and(|s| !s.trim().is_empty())
                && evidence
                    .evidence_commit_hash
                    .as_ref()
                    .is_some_and(|s| !s.trim().is_empty())
                && evidence
                    .evidence_test_name
                    .as_ref()
                    .is_some_and(|s| !s.trim().is_empty())
                && !evidence.runtime_denominator.is_placeholder_baseline() // Must use real baselines
        }
        ThroughputMeasurementStatus::Targeted | ThroughputMeasurementStatus::Unmeasured => {
            // Targeted/unmeasured don't require evidence (but may have partial evidence)
            true
        }
    }
}

/// Detect suspicious patterns in throughput measurements that suggest fake data
pub fn has_fake_measurement_data(evidence: &ThroughputEvidence) -> bool {
    // Check for fake hash patterns in output
    if is_fake_hash(&evidence.output_hash) {
        return true;
    }

    // Check for suspiciously round numbers that suggest placeholder data
    let suspicious_ops_values = [1000, 2500, 3200, 5000, 10000]; // Common fake values
    if suspicious_ops_values.contains(&evidence.frankenengine_ops_per_second)
        || suspicious_ops_values.contains(&evidence.denominator_ops_per_second)
    {
        return true;
    }

    // Check for perfect ratios that are unlikely in real measurements
    if evidence.throughput_ratio_millionths.is_multiple_of(100_000) {
        // Ratios that are exact multiples of 0.1 (100k millionths) are suspicious
        return true;
    }

    // Check for unrealistic success rates
    if evidence.success_rate_millionths == 1_000_000 && evidence.error_count > 0 {
        // Claims 100% success but has errors
        return true;
    }

    false
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputMetricInput {
    pub schema_version: String,
    pub bead_id: String,
    pub scenario_set: String,
    pub floor_ratio_millionths: u64,
    pub max_freshness_days: u64,
    pub evidence: Vec<ThroughputEvidence>,
    pub code_revision: String,
    pub generated_at_utc: String,
    pub benchmark_window_seed: [u8; 32], // Verifier-chosen seed for window pinning
    pub max_benchmark_duration_ms: u64,  // Maximum allowed benchmark duration
    pub evaluation_start_monotonic_ns: u64, // Monotonic timestamp for evaluation start
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThroughputMetricDecision {
    Pass,
    Targeted,
    FailClosed,
}

impl ThroughputMetricDecision {
    pub const fn as_outcome(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Targeted => "targeted",
            Self::FailClosed => "fail",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputMetricStructuredEvent {
    pub metric_id: DisruptiveMetricId,
    pub proof_manifest_id: String,
    pub command_id: String,
    pub scenario_id: String,
    pub runtime_denominator: Option<RuntimeDenominator>,
    pub measurement_status: Option<ThroughputMeasurementStatus>,
    pub throughput_ratio_millionths: u64,
    pub weighted_ratio_millionths: u64,
    pub threshold_millionths: u64,
    pub command: String,
    pub exit_code: i32,
    pub decision: String,
    pub reason: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ThroughputMetricGateError {
    #[error("evidence {evidence_index} contains fake measurement data patterns")]
    FakeMeasurementData {
        evidence_index: usize,
        scenario_id: String,
    },
    #[error("evidence {evidence_index} has insufficient evidence for claimed measurement status")]
    InsufficientMeasurementEvidence {
        evidence_index: usize,
        scenario_id: String,
    },
    #[error("ratio computation failed: {0}")]
    RatioComputation(String),
    #[error("clock error: {0}")]
    Clock(String),
    #[error("timestamp validation failed: {0}")]
    TimestampValidation(String),
    #[error("benchmark window validation failed: {0}")]
    BenchmarkWindowValidation(String),
}

impl ThroughputMetricGateError {
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::FakeMeasurementData { .. } => "fake_measurement_data_detected",
            Self::InsufficientMeasurementEvidence { .. } => "insufficient_measurement_evidence",
            Self::RatioComputation(_) => "ratio_computation_failed",
            Self::Clock(_) => "clock_error",
            Self::TimestampValidation(_) => "timestamp_validation_failed",
            Self::BenchmarkWindowValidation(_) => "benchmark_window_validation_failed",
        }
    }

    pub const fn remediation(&self) -> &'static str {
        match self {
            Self::FakeMeasurementData { .. } => {
                "replace placeholder throughput evidence with fresh measured output"
            }
            Self::InsufficientMeasurementEvidence { .. } => {
                "attach bead id, commit hash, and focused test evidence for verified measurements"
            }
            Self::RatioComputation(_) => {
                "provide at least one valid Node or Bun denominator throughput measurement"
            }
            Self::Clock(_) | Self::TimestampValidation(_) => {
                "rerun the metric gate with monotonic benchmark timestamps inside the allowed window"
            }
            Self::BenchmarkWindowValidation(_) => {
                "rerun the metric gate with the verifier-selected benchmark window seed"
            }
        }
    }

    fn scenario_id(&self) -> Option<&str> {
        match self {
            Self::FakeMeasurementData { scenario_id, .. }
            | Self::InsufficientMeasurementEvidence { scenario_id, .. } => Some(scenario_id),
            Self::RatioComputation(_)
            | Self::Clock(_)
            | Self::TimestampValidation(_)
            | Self::BenchmarkWindowValidation(_) => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputMetricReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub decision: ThroughputMetricDecision,
    pub reason: String,
    pub overall_outcome: String,        // "pass" | "fail" | "targeted"
    pub weighted_ratio_millionths: u64, // Geometric mean across denominators
    pub evidence_count: u64,
    pub passing_evidence_count: u64,
    pub node_evidence_count: u64,
    pub bun_evidence_count: u64,
    pub node_avg_ratio_millionths: u64,
    pub bun_avg_ratio_millionths: u64,
    pub verification_commands: Vec<String>,
    pub generated_at_utc: String,
    pub uses_placeholder_baselines: bool,
    pub baseline_warning: Option<String>,
    pub events: Vec<ThroughputMetricStructuredEvent>,
}

pub fn compute_weighted_throughput_ratio(evidence: &[ThroughputEvidence]) -> Result<u64, String> {
    if evidence.is_empty() {
        return Err("No throughput evidence provided".to_string());
    }

    let node_ratios: Vec<u64> = evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Node)
        .map(|e| e.throughput_ratio_millionths)
        .collect();

    let bun_ratios: Vec<u64> = evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Bun)
        .map(|e| e.throughput_ratio_millionths)
        .collect();

    if node_ratios.is_empty() && bun_ratios.is_empty() {
        return Err("No Node or Bun denominator evidence found".to_string());
    }

    // Compute geometric mean for each denominator
    let node_geomean = if node_ratios.is_empty() {
        0
    } else {
        geometric_mean(&node_ratios)?
    };

    let bun_geomean = if bun_ratios.is_empty() {
        0
    } else {
        geometric_mean(&bun_ratios)?
    };

    // Weight equally between Node and Bun if both present
    let weighted_ratio = if !node_ratios.is_empty() && !bun_ratios.is_empty() {
        (node_geomean + bun_geomean) / 2
    } else if !node_ratios.is_empty() {
        node_geomean
    } else {
        bun_geomean
    };

    Ok(weighted_ratio)
}

fn geometric_mean(values: &[u64]) -> Result<u64, String> {
    if values.is_empty() {
        return Err("Cannot compute geometric mean of empty values".to_string());
    }

    // Use log-space computation to avoid overflow
    let log_sum: f64 = values.iter().map(|&x| (x as f64).ln()).sum();

    let log_mean = log_sum / (values.len() as f64);
    let geomean = log_mean.exp();

    Ok(geomean as u64)
}

pub fn evaluate_throughput_metric(input: &ThroughputMetricInput) -> ThroughputMetricReport {
    match evaluate_throughput_metric_checked(input) {
        Ok(report) => report,
        Err(error) => fail_closed_throughput_report(input, error),
    }
}

pub fn evaluate_throughput_metric_checked(
    input: &ThroughputMetricInput,
) -> Result<ThroughputMetricReport, ThroughputMetricGateError> {
    // Validate evidence for fake data patterns and insufficient evidence
    for (i, evidence) in input.evidence.iter().enumerate() {
        if has_fake_measurement_data(evidence) {
            return Err(ThroughputMetricGateError::FakeMeasurementData {
                evidence_index: i,
                scenario_id: evidence.scenario_id.clone(),
            });
        }

        if !validate_measurement_evidence(evidence) {
            return Err(ThroughputMetricGateError::InsufficientMeasurementEvidence {
                evidence_index: i,
                scenario_id: evidence.scenario_id.clone(),
            });
        }
    }

    let weighted_ratio = compute_weighted_throughput_ratio(&input.evidence)
        .map_err(ThroughputMetricGateError::RatioComputation)?;

    let passing_count = input
        .evidence
        .iter()
        .filter(|e| e.meets_floor_threshold(input.floor_ratio_millionths))
        .count() as u64;

    let node_evidence: Vec<&ThroughputEvidence> = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Node)
        .collect();

    let bun_evidence: Vec<&ThroughputEvidence> = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Bun)
        .collect();

    let node_avg_ratio = if node_evidence.is_empty() {
        0
    } else {
        node_evidence
            .iter()
            .map(|e| e.throughput_ratio_millionths)
            .sum::<u64>()
            / node_evidence.len() as u64
    };

    let bun_avg_ratio = if bun_evidence.is_empty() {
        0
    } else {
        bun_evidence
            .iter()
            .map(|e| e.throughput_ratio_millionths)
            .sum::<u64>()
            / bun_evidence.len() as u64
    };

    // Check for placeholder baseline usage
    let uses_placeholder_node =
        !node_evidence.is_empty() && RuntimeDenominator::Node.is_placeholder_baseline();
    let uses_placeholder_bun =
        !bun_evidence.is_empty() && RuntimeDenominator::Bun.is_placeholder_baseline();
    let uses_placeholder_baselines = uses_placeholder_node || uses_placeholder_bun;

    // Validate timing attack protections before making pass/fail decision
    let current_ns = current_monotonic_ns();

    // Validate monotonic timestamp
    validate_monotonic_timestamp(
        input.evaluation_start_monotonic_ns,
        current_ns,
        input.max_benchmark_duration_ms * 1_000_000, // Convert ms to ns
    )
    .map_err(ThroughputMetricGateError::TimestampValidation)?;

    // Validate benchmark window pinning
    validate_benchmark_window_pinning(&input.evidence, &input.benchmark_window_seed)
        .map_err(ThroughputMetricGateError::BenchmarkWindowValidation)?;

    // Check if all evidence is verified (not targeted or unmeasured)
    let all_evidence_verified = input
        .evidence
        .iter()
        .all(|e| e.measurement_status == ThroughputMeasurementStatus::Verified);

    let (decision, reason, baseline_warning) = if uses_placeholder_baselines
        || !all_evidence_verified
    {
        let mut reasons = Vec::new();

        if uses_placeholder_baselines {
            reasons.push(format!(
                "placeholder baselines (Node: {}, Bun: {})",
                RuntimeDenominator::Node.baseline_ops_per_second(),
                RuntimeDenominator::Bun.baseline_ops_per_second()
            ));
        }

        let targeted_count = input
            .evidence
            .iter()
            .filter(|e| e.measurement_status == ThroughputMeasurementStatus::Targeted)
            .count();

        let unmeasured_count = input
            .evidence
            .iter()
            .filter(|e| e.measurement_status == ThroughputMeasurementStatus::Unmeasured)
            .count();

        if targeted_count > 0 {
            reasons.push(format!("{} targeted measurements", targeted_count));
        }

        if unmeasured_count > 0 {
            reasons.push(format!("{} unmeasured scenarios", unmeasured_count));
        }

        let warning = format!(
            "TARGETED performance claim: {}. Real ≥3x throughput claim requires verified measurements with live baseline comparison and complete evidence chain (bead_id + commit_hash + test_name).",
            reasons.join(", ")
        );
        (
            ThroughputMetricDecision::Targeted,
            "targeted_or_unverified_throughput_evidence".to_string(),
            Some(warning),
        )
    } else {
        // Use constant-time comparison to prevent timing attacks on pass/fail determination
        let ratio_bytes = weighted_ratio.to_le_bytes();
        let threshold_bytes = input.floor_ratio_millionths.to_le_bytes();
        let meets_threshold = constant_time_greater_or_equal(&ratio_bytes, &threshold_bytes);

        if meets_threshold {
            (
                ThroughputMetricDecision::Pass,
                "throughput_floor_verified".to_string(),
                None,
            )
        } else {
            (
                ThroughputMetricDecision::FailClosed,
                "throughput_ratio_below_floor".to_string(),
                None,
            )
        }
    };

    let verification_commands: Vec<String> = input
        .evidence
        .iter()
        .map(|e| e.verification_command.clone())
        .collect();

    Ok(ThroughputMetricReport {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: input.bead_id.clone(),
        decision,
        reason: reason.clone(),
        overall_outcome: decision.as_outcome().to_string(),
        weighted_ratio_millionths: weighted_ratio,
        evidence_count: input.evidence.len() as u64,
        passing_evidence_count: passing_count,
        node_evidence_count: node_evidence.len() as u64,
        bun_evidence_count: bun_evidence.len() as u64,
        node_avg_ratio_millionths: node_avg_ratio,
        bun_avg_ratio_millionths: bun_avg_ratio,
        verification_commands,
        generated_at_utc: generate_secure_timestamp(),
        uses_placeholder_baselines,
        baseline_warning,
        events: throughput_metric_events(input, weighted_ratio, decision, &reason),
    })
}

fn fail_closed_throughput_report(
    input: &ThroughputMetricInput,
    error: ThroughputMetricGateError,
) -> ThroughputMetricReport {
    let reason = format!("{}: {}", error.reason_code(), error);
    let verification_commands = input
        .evidence
        .iter()
        .map(|e| e.verification_command.clone())
        .collect();
    let node_evidence_count = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Node)
        .count() as u64;
    let bun_evidence_count = input
        .evidence
        .iter()
        .filter(|e| e.runtime_denominator == RuntimeDenominator::Bun)
        .count() as u64;
    let uses_placeholder_baselines = input
        .evidence
        .iter()
        .any(|e| e.runtime_denominator.is_placeholder_baseline());

    ThroughputMetricReport {
        schema_version: SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        bead_id: input.bead_id.clone(),
        decision: ThroughputMetricDecision::FailClosed,
        reason: reason.clone(),
        overall_outcome: ThroughputMetricDecision::FailClosed
            .as_outcome()
            .to_string(),
        weighted_ratio_millionths: 0,
        evidence_count: input.evidence.len() as u64,
        passing_evidence_count: 0,
        node_evidence_count,
        bun_evidence_count,
        node_avg_ratio_millionths: 0,
        bun_avg_ratio_millionths: 0,
        verification_commands,
        generated_at_utc: generate_secure_timestamp(),
        uses_placeholder_baselines,
        baseline_warning: Some(format!(
            "FAIL_CLOSED throughput metric gate: {}. {}.",
            reason,
            error.remediation()
        )),
        events: vec![throughput_metric_error_event(input, &error, &reason)],
    }
}

fn throughput_metric_events(
    input: &ThroughputMetricInput,
    weighted_ratio_millionths: u64,
    report_decision: ThroughputMetricDecision,
    report_reason: &str,
) -> Vec<ThroughputMetricStructuredEvent> {
    input
        .evidence
        .iter()
        .map(|evidence| {
            let meets_floor = evidence.meets_floor_threshold(input.floor_ratio_millionths);
            let reason = if report_decision == ThroughputMetricDecision::Targeted {
                "targeted_or_unverified_throughput_evidence"
            } else if meets_floor {
                "throughput_floor_met"
            } else {
                report_reason
            };
            ThroughputMetricStructuredEvent {
                metric_id: DisruptiveMetricId::WeightedThroughputNodeBun,
                proof_manifest_id: format!("{COMPONENT}:{}", input.scenario_set),
                command_id: format!("throughput:{}", evidence.scenario_id),
                scenario_id: evidence.scenario_id.clone(),
                runtime_denominator: Some(evidence.runtime_denominator),
                measurement_status: Some(evidence.measurement_status),
                throughput_ratio_millionths: evidence.throughput_ratio_millionths,
                weighted_ratio_millionths,
                threshold_millionths: input.floor_ratio_millionths,
                command: evidence.verification_command.clone(),
                exit_code: 0,
                decision: if meets_floor {
                    "meets_floor".to_string()
                } else {
                    "below_floor".to_string()
                },
                reason: reason.to_string(),
                remediation: if report_decision == ThroughputMetricDecision::Pass {
                    "none".to_string()
                } else {
                    "rerun the throughput gate with verified live Node and Bun denominator evidence"
                        .to_string()
                },
            }
        })
        .collect()
}

fn throughput_metric_error_event(
    input: &ThroughputMetricInput,
    error: &ThroughputMetricGateError,
    reason: &str,
) -> ThroughputMetricStructuredEvent {
    let evidence = error
        .scenario_id()
        .and_then(|scenario_id| input.evidence.iter().find(|e| e.scenario_id == scenario_id));

    ThroughputMetricStructuredEvent {
        metric_id: DisruptiveMetricId::WeightedThroughputNodeBun,
        proof_manifest_id: format!("{COMPONENT}:{}", input.scenario_set),
        command_id: evidence
            .map(|e| format!("throughput:{}", e.scenario_id))
            .unwrap_or_else(|| "throughput:input_validation".to_string()),
        scenario_id: evidence
            .map(|e| e.scenario_id.clone())
            .unwrap_or_else(|| "input_validation".to_string()),
        runtime_denominator: evidence.map(|e| e.runtime_denominator),
        measurement_status: evidence.map(|e| e.measurement_status),
        throughput_ratio_millionths: evidence.map_or(0, |e| e.throughput_ratio_millionths),
        weighted_ratio_millionths: 0,
        threshold_millionths: input.floor_ratio_millionths,
        command: evidence
            .map(|e| e.verification_command.clone())
            .unwrap_or_else(|| "evaluate_throughput_metric".to_string()),
        exit_code: 1,
        decision: "fail_closed".to_string(),
        reason: reason.to_string(),
        remediation: error.remediation().to_string(),
    }
}

pub fn create_throughput_metric_artifact(
    input: &ThroughputMetricInput,
    report: &ThroughputMetricReport,
    artifact_path: &str,
    artifact_hash: &str,
) -> MetricArtifact {
    MetricArtifact {
        metric_id: DisruptiveMetricId::WeightedThroughputNodeBun,
        threshold: input.floor_ratio_millionths,
        observed_value: report.weighted_ratio_millionths,
        unit: "ratio_millionths".to_string(),
        baseline: "node_bun_denominators".to_string(),
        candidate: "frankenengine".to_string(),
        denominator_id: "node_and_bun".to_string(),
        scenario_set: input.scenario_set.clone(),
        artifact_path: artifact_path.to_string(),
        artifact_hash: artifact_hash.to_string(),
        code_revision: input.code_revision.clone(),
        freshness_days: input.max_freshness_days,
        confidence_millionths: 950_000, // High confidence for deterministic measurement
        coverage_millionths: 900_000,   // Representative scenario coverage
        verification_command: format!(
            "./scripts/run_throughput_disruptive_floor_metric_gate.sh verify {}",
            artifact_path
        ),
        redaction_status: "none".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn recent_evaluation_start_ns() -> u64 {
        current_monotonic_ns().saturating_sub(500_000_000)
    }

    #[test]
    fn test_secure_timestamp_uses_monotonic_utc_anchor() {
        let first_monotonic_ns = current_monotonic_ns();
        let first_timestamp = generate_secure_timestamp();
        let second_timestamp = generate_secure_timestamp();
        let second_monotonic_ns = current_monotonic_ns();

        assert!(second_monotonic_ns >= first_monotonic_ns);
        assert!(first_timestamp.ends_with('Z'));
        assert!(second_timestamp.ends_with('Z'));

        let first_parsed = chrono::DateTime::parse_from_rfc3339(&first_timestamp)
            .expect("first timestamp should be RFC3339");
        let second_parsed = chrono::DateTime::parse_from_rfc3339(&second_timestamp)
            .expect("second timestamp should be RFC3339");
        assert!(second_parsed >= first_parsed);
    }

    #[test]
    fn test_calculate_ratio_millionths() {
        assert_eq!(
            ThroughputEvidence::calculate_ratio_millionths(3000, 2500),
            1_200_000 // 1.2x ratio
        );
        assert_eq!(
            ThroughputEvidence::calculate_ratio_millionths(2000, 2500),
            800_000 // 0.8x ratio
        );
        assert_eq!(
            ThroughputEvidence::calculate_ratio_millionths(100, 0),
            0 // Division by zero
        );
    }

    #[test]
    fn test_meets_floor_threshold() {
        let evidence = ThroughputEvidence {
            scenario_id: "test".to_string(),
            runtime_denominator: RuntimeDenominator::Node,
            frankenengine_ops_per_second: 3000,
            denominator_ops_per_second: 2500,
            throughput_ratio_millionths: 1_200_000,
            benchmark_duration_ms: 10_000,
            request_count: 30_000,
            error_count: 0,
            success_rate_millionths: 1_000_000,
            scenario_path: "test.json".to_string(),
            output_path: "output.json".to_string(),
            output_hash: "sha256:a4b2c8d6e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7"
                .to_string(),
            verification_command: "verify.sh".to_string(),
            benchmark_start_monotonic_ns: 1000000000,
            benchmark_window_seed: [1u8; 32],
            measurement_status: ThroughputMeasurementStatus::Targeted,
            evidence_bead_id: None,
            evidence_commit_hash: None,
            evidence_test_name: None,
        };

        assert!(evidence.meets_floor_threshold(950_000)); // 0.95 threshold
        assert!(evidence.meets_floor_threshold(1_200_000)); // Exact threshold
        assert!(!evidence.meets_floor_threshold(1_300_000)); // Above threshold
    }

    #[test]
    fn test_runtime_denominator_baselines() {
        // Test string conversion (const function)
        assert_eq!(RuntimeDenominator::Node.as_str(), "node");
        assert_eq!(RuntimeDenominator::Bun.as_str(), "bun");

        // Test baseline values (may use live measurements if available, otherwise placeholders)
        let node_baseline = RuntimeDenominator::Node.baseline_ops_per_second();
        let bun_baseline = RuntimeDenominator::Bun.baseline_ops_per_second();

        // Live measurements should be significantly higher than placeholders
        // If live measurements are available, Node should be ~442k, Bun should be ~1.2M
        // If placeholders, Node should be 2.5k, Bun should be 3.2k
        assert!(node_baseline > 0);
        assert!(bun_baseline > 0);

        // Bun should always be faster than Node (both in live and placeholder measurements)
        assert!(bun_baseline > node_baseline);
    }

    #[test]
    fn test_geometric_mean() {
        let equal_values = geometric_mean(&[1_000_000, 1_000_000]).unwrap();
        assert!((999_999..=1_000_000).contains(&equal_values));
        assert!(geometric_mean(&[]).is_err());

        // Approximate test for geometric mean of 800k and 1200k
        let result = geometric_mean(&[800_000, 1_200_000]).unwrap();
        assert!((970_000..=990_000).contains(&result)); // ~sqrt(800k * 1200k) ≈ 980k
    }

    #[test]
    fn test_compute_weighted_throughput_ratio() {
        let node_evidence = ThroughputEvidence {
            scenario_id: "node_test".to_string(),
            runtime_denominator: RuntimeDenominator::Node,
            frankenengine_ops_per_second: 3000,
            denominator_ops_per_second: 2500,
            throughput_ratio_millionths: 1_200_000,
            benchmark_duration_ms: 10_000,
            request_count: 30_000,
            error_count: 0,
            success_rate_millionths: 1_000_000,
            scenario_path: "node_test.json".to_string(),
            output_path: "node_output.json".to_string(),
            output_hash: "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
                .to_string(),
            verification_command: "verify_node.sh".to_string(),
            benchmark_start_monotonic_ns: 1000000000,
            benchmark_window_seed: [1u8; 32],
            measurement_status: ThroughputMeasurementStatus::Targeted,
            evidence_bead_id: None,
            evidence_commit_hash: None,
            evidence_test_name: None,
        };

        let bun_evidence = ThroughputEvidence {
            scenario_id: "bun_test".to_string(),
            runtime_denominator: RuntimeDenominator::Bun,
            frankenengine_ops_per_second: 3200,
            denominator_ops_per_second: 3200,
            throughput_ratio_millionths: 1_000_000,
            benchmark_duration_ms: 10_000,
            request_count: 32_000,
            error_count: 0,
            success_rate_millionths: 1_000_000,
            scenario_path: "bun_test.json".to_string(),
            output_path: "bun_output.json".to_string(),
            output_hash: "sha256:d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2"
                .to_string(),
            verification_command: "verify_bun.sh".to_string(),
            benchmark_start_monotonic_ns: 1000000000,
            benchmark_window_seed: [1u8; 32],
            measurement_status: ThroughputMeasurementStatus::Targeted,
            evidence_bead_id: None,
            evidence_commit_hash: None,
            evidence_test_name: None,
        };

        let evidence = vec![node_evidence, bun_evidence];
        let weighted_ratio = compute_weighted_throughput_ratio(&evidence).unwrap();

        // Should be average of 1.2M (Node) and 1.0M (Bun), allowing f64 truncation.
        assert!((1_099_999..=1_100_000).contains(&weighted_ratio));

        // Test with only Node evidence
        let node_only = vec![evidence[0].clone()];
        let node_ratio = compute_weighted_throughput_ratio(&node_only).unwrap();
        assert!((1_199_999..=1_200_000).contains(&node_ratio));

        // Test with empty evidence
        assert!(compute_weighted_throughput_ratio(&[]).is_err());
    }

    #[test]
    fn test_evaluate_throughput_metric() {
        let input = ThroughputMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "basic_throughput".to_string(),
            floor_ratio_millionths: 950_000,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![ThroughputEvidence {
                scenario_id: "passing_test".to_string(),
                runtime_denominator: RuntimeDenominator::Node,
                frankenengine_ops_per_second: 2534, // Non-round number to avoid fake data detection
                denominator_ops_per_second: 2487,   // Non-round number to avoid fake data detection
                throughput_ratio_millionths: 1_018_923, // Non-perfect ratio
                benchmark_duration_ms: 10_000,
                request_count: 25_340,
                error_count: 0,
                success_rate_millionths: 999_000, // Not perfect success rate
                scenario_path: "passing.json".to_string(),
                output_path: "passing_output.json".to_string(),
                output_hash:
                    "sha256:a4b2c8d6e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7"
                        .to_string(),
                verification_command: "verify_pass.sh".to_string(),
                benchmark_start_monotonic_ns: 1000000000,
                benchmark_window_seed: [2u8; 32],
                measurement_status: ThroughputMeasurementStatus::Targeted,
                evidence_bead_id: None,
                evidence_commit_hash: None,
                evidence_test_name: None,
            }],
            code_revision: "abc123def".to_string(),
            generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
            benchmark_window_seed: [2u8; 32],
            max_benchmark_duration_ms: DEFAULT_MAX_BENCHMARK_DURATION_MS,
            evaluation_start_monotonic_ns: recent_evaluation_start_ns(),
        };

        let report = evaluate_throughput_metric(&input);
        assert_eq!(report.decision, ThroughputMetricDecision::Targeted);
        assert_eq!(report.reason, "targeted_or_unverified_throughput_evidence");
        assert_eq!(report.overall_outcome, "targeted");
        assert_eq!(report.weighted_ratio_millionths, 1_018_923);
        assert_eq!(report.evidence_count, 1);
        assert_eq!(report.passing_evidence_count, 1);
        assert_eq!(report.node_evidence_count, 1);
        assert_eq!(report.bun_evidence_count, 0);
        let uses_placeholder_baseline = RuntimeDenominator::Node.is_placeholder_baseline();
        assert_eq!(report.uses_placeholder_baselines, uses_placeholder_baseline);
        assert!(report.baseline_warning.is_some());
        assert!(
            report
                .baseline_warning
                .as_ref()
                .unwrap()
                .contains("TARGETED performance claim")
        );
    }

    #[test]
    fn test_create_throughput_metric_artifact() {
        let input = ThroughputMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "test_scenario".to_string(),
            floor_ratio_millionths: 950_000,
            max_freshness_days: 14,
            evidence: vec![],
            code_revision: "test_rev".to_string(),
            generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
            benchmark_window_seed: [3u8; 32],
            max_benchmark_duration_ms: DEFAULT_MAX_BENCHMARK_DURATION_MS,
            evaluation_start_monotonic_ns: 1000000000,
        };

        let report = ThroughputMetricReport {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            decision: ThroughputMetricDecision::Targeted,
            reason: "targeted_or_unverified_throughput_evidence".to_string(),
            overall_outcome: "targeted".to_string(),
            weighted_ratio_millionths: 1_100_000,
            evidence_count: 2,
            passing_evidence_count: 2,
            node_evidence_count: 1,
            bun_evidence_count: 1,
            node_avg_ratio_millionths: 1_200_000,
            bun_avg_ratio_millionths: 1_000_000,
            verification_commands: vec!["verify.sh".to_string()],
            generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
            uses_placeholder_baselines: true,
            baseline_warning: Some("TARGETED performance claim".to_string()),
            events: vec![],
        };

        let artifact =
            create_throughput_metric_artifact(&input, &report, "test_artifact.json", "hash123");

        assert_eq!(
            artifact.metric_id,
            DisruptiveMetricId::WeightedThroughputNodeBun
        );
        assert_eq!(artifact.threshold, 950_000);
        assert_eq!(artifact.observed_value, 1_100_000);
        assert_eq!(artifact.unit, "ratio_millionths");
        assert_eq!(artifact.denominator_id, "node_and_bun");
        assert_eq!(artifact.scenario_set, "test_scenario");
        assert_eq!(artifact.artifact_hash, "hash123");
    }

    #[test]
    fn test_constant_time_greater_or_equal() {
        // Test equal values
        let a = 1_000_000u64.to_le_bytes();
        let b = 1_000_000u64.to_le_bytes();
        assert!(constant_time_greater_or_equal(&a, &b));

        // Test a > b
        let a = 1_200_000u64.to_le_bytes();
        let b = 1_000_000u64.to_le_bytes();
        assert!(constant_time_greater_or_equal(&a, &b));

        // Test a < b
        let a = 800_000u64.to_le_bytes();
        let b = 1_000_000u64.to_le_bytes();
        assert!(!constant_time_greater_or_equal(&a, &b));

        // Test edge cases
        let a = 0u64.to_le_bytes();
        let b = 0u64.to_le_bytes();
        assert!(constant_time_greater_or_equal(&a, &b));

        let a = u64::MAX.to_le_bytes();
        let b = 0u64.to_le_bytes();
        assert!(constant_time_greater_or_equal(&a, &b));

        let a = 0u64.to_le_bytes();
        let b = u64::MAX.to_le_bytes();
        assert!(!constant_time_greater_or_equal(&a, &b));
    }

    #[test]
    fn test_constant_time_threshold_comparison() {
        let evidence_pass = ThroughputEvidence {
            scenario_id: "timing_test_pass".to_string(),
            runtime_denominator: RuntimeDenominator::Node,
            frankenengine_ops_per_second: 2634,
            denominator_ops_per_second: 2531,
            throughput_ratio_millionths: 1_040_717, // Just above 0.95 threshold
            benchmark_duration_ms: 10_000,
            request_count: 26_340,
            error_count: 0,
            success_rate_millionths: 999_000,
            scenario_path: "timing_pass.json".to_string(),
            output_path: "timing_pass_output.json".to_string(),
            output_hash: "sha256:a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
                .to_string(),
            verification_command: "verify_timing_pass.sh".to_string(),
            benchmark_start_monotonic_ns: 1000000000,
            benchmark_window_seed: [4u8; 32],
            measurement_status: ThroughputMeasurementStatus::Targeted,
            evidence_bead_id: None,
            evidence_commit_hash: None,
            evidence_test_name: None,
        };

        let evidence_fail = ThroughputEvidence {
            scenario_id: "timing_test_fail".to_string(),
            runtime_denominator: RuntimeDenominator::Node,
            frankenengine_ops_per_second: 2341,
            denominator_ops_per_second: 2543,
            throughput_ratio_millionths: 920_568, // Below 0.95 threshold
            benchmark_duration_ms: 10_000,
            request_count: 23_410,
            error_count: 0,
            success_rate_millionths: 998_000,
            scenario_path: "timing_fail.json".to_string(),
            output_path: "timing_fail_output.json".to_string(),
            output_hash: "sha256:b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3"
                .to_string(),
            verification_command: "verify_timing_fail.sh".to_string(),
            benchmark_start_monotonic_ns: 1000000000,
            benchmark_window_seed: [4u8; 32],
            measurement_status: ThroughputMeasurementStatus::Targeted,
            evidence_bead_id: None,
            evidence_commit_hash: None,
            evidence_test_name: None,
        };

        // Both should use constant-time comparison internally
        assert!(evidence_pass.meets_floor_threshold(950_000));
        assert!(!evidence_fail.meets_floor_threshold(950_000));

        // Edge case: exactly at threshold
        let evidence_exact = ThroughputEvidence {
            scenario_id: "timing_test_exact".to_string(),
            runtime_denominator: RuntimeDenominator::Node,
            frankenengine_ops_per_second: 2375,
            denominator_ops_per_second: 2500,
            throughput_ratio_millionths: 950_000, // Exactly at threshold
            benchmark_duration_ms: 10_000,
            request_count: 23_750,
            error_count: 0,
            success_rate_millionths: 997_000,
            scenario_path: "timing_exact.json".to_string(),
            output_path: "timing_exact_output.json".to_string(),
            output_hash: "sha256:c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4"
                .to_string(),
            verification_command: "verify_timing_exact.sh".to_string(),
            benchmark_start_monotonic_ns: 1000000000,
            benchmark_window_seed: [4u8; 32],
            measurement_status: ThroughputMeasurementStatus::Targeted,
            evidence_bead_id: None,
            evidence_commit_hash: None,
            evidence_test_name: None,
        };

        assert!(evidence_exact.meets_floor_threshold(950_000));
    }

    #[test]
    fn test_validate_monotonic_timestamp() {
        let current_ns = 20_000_000_000u64; // 20 seconds
        let max_duration_ns = 10_000_000_000u64; // 10 seconds

        // Valid case: benchmark started before current time
        let start_ns = 15_000_000_000u64; // 15 seconds
        assert!(validate_monotonic_timestamp(start_ns, current_ns, max_duration_ns).is_ok());

        // Invalid case: benchmark start in future (clock manipulation)
        let future_start_ns = 21_000_000_000u64; // 21 seconds
        assert!(
            validate_monotonic_timestamp(future_start_ns, current_ns, max_duration_ns).is_err()
        );

        // Invalid case: benchmark duration too long (timing attack)
        let too_early_start_ns = 100_000_000u64; // Very early start
        let short_max_duration_ns = 100_000_000u64; // 0.1 second max
        assert!(
            validate_monotonic_timestamp(too_early_start_ns, current_ns, short_max_duration_ns)
                .is_err()
        );

        // Valid case: exactly at max duration
        let exact_start_ns = current_ns - max_duration_ns;
        assert!(validate_monotonic_timestamp(exact_start_ns, current_ns, max_duration_ns).is_ok());
    }

    #[test]
    fn test_validate_benchmark_window_pinning() {
        let seed = [42u8; 32];

        // Valid case: all evidence has correct seed
        let evidence = vec![
            ThroughputEvidence {
                scenario_id: "window_test_1".to_string(),
                runtime_denominator: RuntimeDenominator::Node,
                frankenengine_ops_per_second: 2534,
                denominator_ops_per_second: 2487,
                throughput_ratio_millionths: 1_018_923,
                benchmark_duration_ms: 10_000,
                request_count: 25_340,
                error_count: 0,
                success_rate_millionths: 999_000,
                scenario_path: "window1.json".to_string(),
                output_path: "window1_output.json".to_string(),
                output_hash:
                    "sha256:d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5"
                        .to_string(),
                verification_command: "verify_window1.sh".to_string(),
                benchmark_start_monotonic_ns: 1000000000,
                benchmark_window_seed: seed,
                measurement_status: ThroughputMeasurementStatus::Targeted,
                evidence_bead_id: None,
                evidence_commit_hash: None,
                evidence_test_name: None,
            },
            ThroughputEvidence {
                scenario_id: "window_test_2".to_string(),
                runtime_denominator: RuntimeDenominator::Bun,
                frankenengine_ops_per_second: 3241,
                denominator_ops_per_second: 3178,
                throughput_ratio_millionths: 1_019_825,
                benchmark_duration_ms: 10_000,
                request_count: 32_410,
                error_count: 0,
                success_rate_millionths: 998_000,
                scenario_path: "window2.json".to_string(),
                output_path: "window2_output.json".to_string(),
                output_hash:
                    "sha256:e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6"
                        .to_string(),
                verification_command: "verify_window2.sh".to_string(),
                benchmark_start_monotonic_ns: 1000000000,
                benchmark_window_seed: seed,
                measurement_status: ThroughputMeasurementStatus::Targeted,
                evidence_bead_id: None,
                evidence_commit_hash: None,
                evidence_test_name: None,
            },
        ];

        assert!(validate_benchmark_window_pinning(&evidence, &seed).is_ok());

        // Invalid case: mismatched seed (cherry-picking attack)
        let mut bad_evidence = evidence.clone();
        bad_evidence[1].benchmark_window_seed = [99u8; 32];

        assert!(validate_benchmark_window_pinning(&bad_evidence, &seed).is_err());

        // Edge case: empty evidence
        assert!(validate_benchmark_window_pinning(&[], &seed).is_err());
    }

    #[test]
    fn test_fake_hash_detection() {
        assert!(is_fake_hash(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ));
        assert!(is_fake_hash(
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        ));
        assert!(is_fake_hash(
            "sha256:deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        ));
        assert!(!is_fake_hash(
            "sha256:a4b2c8d6e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7"
        ));
        assert!(!is_fake_hash("not-sha256:0123456789abcdef"));
        assert!(!is_fake_hash("sha256:short"));
    }

    #[test]
    fn test_fake_measurement_data_detection() {
        let mut evidence = ThroughputEvidence {
            scenario_id: "test-scenario".to_string(),
            runtime_denominator: RuntimeDenominator::Node,
            frankenengine_ops_per_second: 2500, // Suspicious round number
            denominator_ops_per_second: 2500,   // Suspicious round number
            throughput_ratio_millionths: 1_000_000, // Perfect 1.0 ratio (suspicious)
            benchmark_duration_ms: 10_000,
            request_count: 25_000,
            error_count: 0,
            success_rate_millionths: 1_000_000,
            scenario_path: "test.json".to_string(),
            output_path: "test_output.json".to_string(),
            output_hash: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_string(), // Fake hash
            verification_command: "test-verify.sh".to_string(),
            benchmark_start_monotonic_ns: 1000000000,
            benchmark_window_seed: [1u8; 32],
            measurement_status: ThroughputMeasurementStatus::Targeted,
            evidence_bead_id: None,
            evidence_commit_hash: None,
            evidence_test_name: None,
        };

        assert!(has_fake_measurement_data(&evidence));

        // Change to non-suspicious values
        evidence.frankenengine_ops_per_second = 2534;
        evidence.denominator_ops_per_second = 2487;
        evidence.throughput_ratio_millionths = 1_018_923; // Non-round ratio
        evidence.output_hash =
            "sha256:a4b2c8d6e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7".to_string();
        assert!(!has_fake_measurement_data(&evidence));
    }

    #[test]
    fn test_measurement_evidence_validation() {
        let mut evidence = ThroughputEvidence {
            scenario_id: "evidence-test".to_string(),
            runtime_denominator: RuntimeDenominator::Node,
            frankenengine_ops_per_second: 2534,
            denominator_ops_per_second: 2487,
            throughput_ratio_millionths: 1_018_923,
            benchmark_duration_ms: 10_000,
            request_count: 25_340,
            error_count: 0,
            success_rate_millionths: 1_000_000,
            scenario_path: "evidence.json".to_string(),
            output_path: "evidence_output.json".to_string(),
            output_hash: "sha256:a4b2c8d6e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7"
                .to_string(),
            verification_command: "evidence-verify.sh".to_string(),
            benchmark_start_monotonic_ns: 1000000000,
            benchmark_window_seed: [1u8; 32],
            measurement_status: ThroughputMeasurementStatus::Verified,
            evidence_bead_id: Some("bd-1pq04".to_string()),
            evidence_commit_hash: Some("abc123".to_string()),
            evidence_test_name: Some("test_real_throughput_measurement".to_string()),
        };

        // Verified evidence is accepted only when live denominator baselines are available.
        assert_eq!(
            validate_measurement_evidence(&evidence),
            !RuntimeDenominator::Node.is_placeholder_baseline()
        );

        // Targeted status doesn't require evidence
        evidence.measurement_status = ThroughputMeasurementStatus::Targeted;
        evidence.evidence_bead_id = None;
        assert!(validate_measurement_evidence(&evidence));

        // Verified status still requires the complete evidence chain.
        evidence.measurement_status = ThroughputMeasurementStatus::Verified;
        assert!(!validate_measurement_evidence(&evidence));
    }

    #[test]
    fn test_fake_data_rejection_in_evaluation() {
        let input = ThroughputMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "fake_data_test".to_string(),
            floor_ratio_millionths: 950_000,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![ThroughputEvidence {
                scenario_id: "fake_data_scenario".to_string(),
                runtime_denominator: RuntimeDenominator::Node,
                frankenengine_ops_per_second: 2500, // Suspicious round number
                denominator_ops_per_second: 2500,   // Suspicious round number
                throughput_ratio_millionths: 1_000_000, // Perfect ratio
                benchmark_duration_ms: 10_000,
                request_count: 25_000,
                error_count: 0,
                success_rate_millionths: 1_000_000,
                scenario_path: "fake.json".to_string(),
                output_path: "fake_output.json".to_string(),
                output_hash:
                    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_string(),
                verification_command: "fake_verify.sh".to_string(),
                benchmark_start_monotonic_ns: 1000000000,
                benchmark_window_seed: [2u8; 32],
                measurement_status: ThroughputMeasurementStatus::Targeted,
                evidence_bead_id: None,
                evidence_commit_hash: None,
                evidence_test_name: None,
            }],
            code_revision: "fake_test_rev".to_string(),
            generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
            benchmark_window_seed: [2u8; 32],
            max_benchmark_duration_ms: DEFAULT_MAX_BENCHMARK_DURATION_MS,
            evaluation_start_monotonic_ns: 1000000000,
        };

        let result = evaluate_throughput_metric_checked(&input);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("fake measurement data patterns")
        );
        let report = evaluate_throughput_metric(&input);
        assert_eq!(report.decision, ThroughputMetricDecision::FailClosed);
        assert!(report.reason.contains("fake_measurement_data_detected"));
        assert_eq!(report.events[0].decision, "fail_closed");
    }

    #[test]
    fn test_insufficient_evidence_rejection() {
        let input = ThroughputMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "insufficient_evidence_test".to_string(),
            floor_ratio_millionths: 950_000,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![ThroughputEvidence {
                scenario_id: "insufficient_evidence_scenario".to_string(),
                runtime_denominator: RuntimeDenominator::Node,
                frankenengine_ops_per_second: 2534,
                denominator_ops_per_second: 2487,
                throughput_ratio_millionths: 1_018_923,
                benchmark_duration_ms: 10_000,
                request_count: 25_340,
                error_count: 0,
                success_rate_millionths: 999_000,
                scenario_path: "insufficient.json".to_string(),
                output_path: "insufficient_output.json".to_string(),
                output_hash:
                    "sha256:a4b2c8d6e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7"
                        .to_string(),
                verification_command: "insufficient_verify.sh".to_string(),
                benchmark_start_monotonic_ns: 1000000000,
                benchmark_window_seed: [3u8; 32],
                measurement_status: ThroughputMeasurementStatus::Verified, // Claims verified but missing evidence
                evidence_bead_id: None,                                    // Missing evidence
                evidence_commit_hash: None,
                evidence_test_name: None,
            }],
            code_revision: "insufficient_test_rev".to_string(),
            generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
            benchmark_window_seed: [3u8; 32],
            max_benchmark_duration_ms: DEFAULT_MAX_BENCHMARK_DURATION_MS,
            evaluation_start_monotonic_ns: 1000000000,
        };

        let result = evaluate_throughput_metric_checked(&input);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("insufficient evidence")
        );
        let report = evaluate_throughput_metric(&input);
        assert_eq!(report.decision, ThroughputMetricDecision::FailClosed);
        assert!(report.reason.contains("insufficient_measurement_evidence"));
    }

    #[test]
    fn test_targeted_status_with_placeholder_baselines() {
        let input = ThroughputMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "targeted_test".to_string(),
            floor_ratio_millionths: 950_000,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![ThroughputEvidence {
                scenario_id: "targeted_scenario".to_string(),
                runtime_denominator: RuntimeDenominator::Node,
                frankenengine_ops_per_second: 2534,
                denominator_ops_per_second: 2487,
                throughput_ratio_millionths: 1_018_923,
                benchmark_duration_ms: 10_000,
                request_count: 25_340,
                error_count: 0,
                success_rate_millionths: 999_000,
                scenario_path: "targeted.json".to_string(),
                output_path: "targeted_output.json".to_string(),
                output_hash:
                    "sha256:a4b2c8d6e9f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7"
                        .to_string(),
                verification_command: "targeted_verify.sh".to_string(),
                benchmark_start_monotonic_ns: 1000000000,
                benchmark_window_seed: [4u8; 32],
                measurement_status: ThroughputMeasurementStatus::Targeted,
                evidence_bead_id: Some("bd-1pq04".to_string()), // Has evidence but targeted status
                evidence_commit_hash: Some("def456".to_string()),
                evidence_test_name: Some("test_targeted_measurement".to_string()),
            }],
            code_revision: "targeted_test_rev".to_string(),
            generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
            benchmark_window_seed: [4u8; 32],
            max_benchmark_duration_ms: DEFAULT_MAX_BENCHMARK_DURATION_MS,
            evaluation_start_monotonic_ns: recent_evaluation_start_ns(),
        };

        let report = evaluate_throughput_metric(&input);
        assert_eq!(report.decision, ThroughputMetricDecision::Targeted);
        assert_eq!(report.overall_outcome, "targeted");
        assert!(report.baseline_warning.is_some());
        assert!(
            report
                .baseline_warning
                .as_ref()
                .unwrap()
                .contains("TARGETED performance claim")
        );
        let baseline_warning = report.baseline_warning.as_ref().unwrap();
        if RuntimeDenominator::Node.is_placeholder_baseline() {
            assert!(baseline_warning.contains("placeholder baselines"));
        } else {
            assert!(baseline_warning.contains("targeted measurements"));
        }
    }

    #[test]
    fn test_baseline_manifest_loading() {
        // Test loading the baseline manifest (may succeed or fail depending on test environment)
        match load_baseline_manifest() {
            Ok(manifest) => {
                // If manifest loads successfully, validate its structure
                assert_eq!(
                    manifest.schema_version,
                    "franken-engine.throughput-baselines.v1"
                );
                assert!(manifest.runtimes.contains_key("node"));
                assert!(manifest.runtimes.contains_key("bun"));
                assert!(manifest.runtimes.contains_key("frankenengine"));

                // Check that Node and Bun have reasonable baseline values
                if let Some(node_runtime) = manifest.runtimes.get("node") {
                    assert!(node_runtime.baseline_ops_per_second > 0);
                }
                if let Some(bun_runtime) = manifest.runtimes.get("bun") {
                    assert!(bun_runtime.baseline_ops_per_second > 0);
                }

                // If we have live measurements, they should be much higher than placeholders
                if manifest.has_live_measurements {
                    if let Some(node_runtime) = manifest.runtimes.get("node") {
                        // Live Node measurements should be significantly higher than 2500 placeholder
                        assert!(node_runtime.baseline_ops_per_second > 10_000);
                    }
                    if let Some(bun_runtime) = manifest.runtimes.get("bun") {
                        // Live Bun measurements should be significantly higher than 3200 placeholder
                        assert!(bun_runtime.baseline_ops_per_second > 10_000);
                    }
                }
            }
            Err(_) => {
                // If manifest can't be loaded, that's expected in some test environments
                // The function should gracefully fall back to placeholder values
                assert_eq!(RuntimeDenominator::Node.baseline_ops_per_second(), 2500);
                assert_eq!(RuntimeDenominator::Bun.baseline_ops_per_second(), 3200);
                assert!(RuntimeDenominator::Node.is_placeholder_baseline());
                assert!(RuntimeDenominator::Bun.is_placeholder_baseline());
            }
        }
    }

    #[test]
    fn test_placeholder_vs_live_baseline_detection() {
        // Test that placeholder detection works correctly
        let node_is_placeholder = RuntimeDenominator::Node.is_placeholder_baseline();
        let bun_is_placeholder = RuntimeDenominator::Bun.is_placeholder_baseline();

        // Both should have the same placeholder status (either both placeholder or both live)
        assert_eq!(node_is_placeholder, bun_is_placeholder);

        // If we can load a manifest with live measurements, placeholders should be false
        if let Ok(manifest) = load_baseline_manifest()
            && manifest.has_live_measurements
            && manifest.runtimes.contains_key("node")
            && manifest.runtimes.contains_key("bun")
        {
            assert!(
                !node_is_placeholder,
                "Should detect live measurements when manifest has them"
            );
            assert!(
                !bun_is_placeholder,
                "Should detect live measurements when manifest has them"
            );
        }
    }

    #[test]
    fn test_timing_attack_protection_in_evaluation() {
        let current_ns = current_monotonic_ns();

        let seed = [123u8; 32];

        let input = ThroughputMetricInput {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            scenario_set: "timing_attack_test".to_string(),
            floor_ratio_millionths: 950_000,
            max_freshness_days: DEFAULT_MAX_FRESHNESS_DAYS,
            evidence: vec![ThroughputEvidence {
                scenario_id: "secure_test".to_string(),
                runtime_denominator: RuntimeDenominator::Node,
                frankenengine_ops_per_second: 2534,
                denominator_ops_per_second: 2487,
                throughput_ratio_millionths: 1_018_923,
                benchmark_duration_ms: 10_000,
                request_count: 25_340,
                error_count: 0,
                success_rate_millionths: 999_000,
                scenario_path: "secure.json".to_string(),
                output_path: "secure_output.json".to_string(),
                output_hash:
                    "sha256:f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7"
                        .to_string(),
                verification_command: "verify_secure.sh".to_string(),
                benchmark_start_monotonic_ns: current_ns.saturating_sub(1_000_000_000),
                benchmark_window_seed: seed,
                measurement_status: ThroughputMeasurementStatus::Targeted,
                evidence_bead_id: None,
                evidence_commit_hash: None,
                evidence_test_name: None,
            }],
            code_revision: "secure_rev".to_string(),
            generated_at_utc: "2026-05-01T00:00:00Z".to_string(),
            benchmark_window_seed: seed,
            max_benchmark_duration_ms: DEFAULT_MAX_BENCHMARK_DURATION_MS,
            evaluation_start_monotonic_ns: current_ns.saturating_sub(500_000_000),
        };

        // Should succeed with valid timing protections
        let report = evaluate_throughput_metric(&input);
        assert_eq!(report.overall_outcome, "targeted"); // Uses placeholder baselines
        assert_eq!(report.weighted_ratio_millionths, 1_018_923);
    }
}
