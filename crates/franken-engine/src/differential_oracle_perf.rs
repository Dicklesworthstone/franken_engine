//! Performance arm of the differential oracle (E2.T4, bd-fqlfw.2.4).
//!
//! Measures steady-state throughput of the same JS corpus the correctness arm
//! compares, and emits a MEASURED Node/Bun denominator — the artifact
//! FE-CLAIM-010 requires before its ">= 3x" wording can ever promote.
//!
//! ## Measurement protocol (binding)
//!
//! * One subprocess per (case, external runtime). The subprocess runs a
//!   generated harness: the case source is compiled ONCE via `new Function`
//!   and invoked `warmup_iterations` times (discarded) then
//!   `measured_iterations` times, each timed with `process.hrtime.bigint()`.
//!   Process startup is therefore excluded by construction, and the external
//!   runtime gets full JIT warm-up — a deliberately *conservative* bias in
//!   favour of Node/Bun.
//! * The engine lane times `HybridRouter::eval` per iteration on a fresh
//!   router, so the engine pays its full parse → lower → execute pipeline on
//!   every measured iteration while Node/Bun amortize compilation. This bias
//!   is also conservative against FrankenEngine and is recorded in the
//!   fairness notes.
//! * Per-iteration nanosecond timings (warm-up and measured) are retained in
//!   the report and exported as `diffperf.iteration` events so a skeptic can
//!   re-derive every aggregate from raw data.
//!
//! ## Fairness rules (from PLAN sections 7.4–7.5)
//!
//! Identical hardware and corpus for all runtimes, pinned + recorded runtime
//! versions and resolved binary paths, a documented warm-up protocol, a full
//! environment manifest, and geometric-mean aggregation. A run that cannot
//! meet the rules emits a DEGRADED receipt instead of a number. One trap this
//! module checks explicitly: `node` on PATH may be Bun's `node` shim, which
//! would make the "Node" lane silently measure Bun (`node_genuine`).
//!
//! ## Honest outcome
//!
//! Cases are admitted into the denominator only when the correctness arm
//! reports structured-value consensus between Node, Bun, and FrankenEngine
//! ("output equivalence before throughput"). If the measured weighted
//! geometric mean is below the 3x floor, the result is still published with
//! `meets_3x_floor: false` — the number is surfaced, never massaged.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::differential_oracle::{
    DifferentialBackend, DifferentialComparisonMode, DifferentialComparisonVerdict,
    DifferentialHostFacts, DifferentialOracleInput, ExternalRuntimeSpec, VersionProbe,
    capture_external_version, capture_host_facts, current_unix_ns, run_command_with_timeout,
    run_differential_oracle, sha256_hex,
};
use crate::{HybridRouter, JsEngine};

pub const DIFFERENTIAL_PERF_SCHEMA_VERSION: &str = "franken-engine.differential-oracle-perf.v1";

/// FE-CLAIM-010 floor: ">= 3x weighted-geometric-mean throughput" in
/// fixed-point millionths (1_000_000 == 1.0x).
pub const DENOMINATOR_FLOOR_MILLIONTHS: u64 = 3_000_000;

/// Sentinel prefix the external harness prints before its timing payload.
pub const PERF_HARNESS_SENTINEL: &str = "__FE_PERF__";

const MILLIONTHS: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

/// One corpus case: an id plus the exact JS source every runtime evaluates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfCorpusCase {
    pub case_id: String,
    pub source: String,
}

impl PerfCorpusCase {
    pub fn new(case_id: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            case_id: case_id.into(),
            source: source.into(),
        }
    }
}

/// Tunable measurement policy. The defaults mirror the fairness policy pinned
/// in `benchmarks/runtime_comparison/manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfArmConfig {
    pub warmup_iterations: u32,
    pub measured_iterations: u32,
    /// Budget for one whole harness subprocess (all iterations of one case).
    pub case_timeout_ms: u64,
    /// Per-case coefficient-of-variation admission bar, in millionths
    /// (150_000 == 15%). Cases noisier than this are excluded from the
    /// denominator and the exclusion is recorded.
    pub max_cv_millionths: u32,
    pub node: ExternalRuntimeSpec,
    pub bun: ExternalRuntimeSpec,
}

impl Default for PerfArmConfig {
    fn default() -> Self {
        Self {
            warmup_iterations: 3,
            measured_iterations: 30,
            case_timeout_ms: 120_000,
            max_cv_millionths: 150_000,
            node: ExternalRuntimeSpec::node_default(),
            bun: ExternalRuntimeSpec::bun_default(),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-iteration evidence
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfPhase {
    Warmup,
    Measured,
}

/// One raw timing observation; serialized verbatim into `events.jsonl`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfIterationEvent {
    pub event: String,
    pub case_id: String,
    pub backend: DifferentialBackend,
    pub phase: PerfPhase,
    pub index: u32,
    pub duration_ns: u64,
}

// ---------------------------------------------------------------------------
// Aggregates
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfSampleStats {
    pub sample_count: usize,
    pub mean_ns: u64,
    pub stddev_ns: u64,
    /// stddev / mean in millionths.
    pub cv_millionths: u32,
    pub ci95_lower_ns: u64,
    pub ci95_upper_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfMeasurementStatus {
    Measured,
    Failed,
    Unavailable,
    Timeout,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfBackendCaseResult {
    pub backend: DifferentialBackend,
    pub status: PerfMeasurementStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resolved_program: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub warmup_ns: Vec<u64>,
    pub measured_ns: Vec<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<PerfSampleStats>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfCaseResult {
    pub case_id: String,
    pub source_sha256: String,
    /// Correctness-arm precondition: Node, Bun, and FrankenEngine produced
    /// the same canonical structured value for this source.
    pub behavior_equivalent: bool,
    pub equivalence_detail: String,
    pub engine: PerfBackendCaseResult,
    pub node: PerfBackendCaseResult,
    pub bun: PerfBackendCaseResult,
    /// node_mean / engine_mean in millionths (> 1_000_000 means the engine
    /// completed the workload faster than Node).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_over_engine_speedup_millionths: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bun_over_engine_speedup_millionths: Option<u64>,
    pub admitted: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclusion_reasons: Vec<String>,
}

// ---------------------------------------------------------------------------
// Environment + fairness
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfEnvironmentManifest {
    pub host: DifferentialHostFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_memory_kb: Option<u64>,
    /// 1-minute load average at run start, millionths (12_340_000 == 12.34).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_avg_1m_millionths: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_governor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_resolved_program: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_version: Option<String>,
    /// False when the `node` binary is actually Bun's node shim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_genuine: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bun_resolved_program: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bun_version: Option<String>,
    pub warmup_iterations: u32,
    pub measured_iterations: u32,
    pub corpus_case_count: usize,
    pub corpus_sha256: String,
    pub generated_unix_ns: u128,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfFairnessReport {
    pub compliant: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Denominator
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerfDenominatorStatus {
    /// Fairness rules met and enough cases admitted: the ratio is a number a
    /// skeptic can re-derive. Publication of CLAIM wording is still gated by
    /// the claim-to-proof matrix, not by this report.
    Published,
    /// Fairness rules unmet (or no admissible cases): the receipt documents
    /// why and carries no usable ratio.
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerfDenominator {
    pub baseline: String,
    pub admitted_cases: usize,
    pub excluded_cases: usize,
    /// Unweighted geometric mean of per-case speedups, millionths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geomean_speedup_millionths: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meets_3x_floor: Option<bool>,
    pub status: PerfDenominatorStatus,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degraded_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifferentialPerfReport {
    pub schema_version: String,
    pub generated_unix_ns: u128,
    pub environment: PerfEnvironmentManifest,
    pub fairness: PerfFairnessReport,
    pub cases: Vec<PerfCaseResult>,
    pub node_denominator: PerfDenominator,
    pub bun_denominator: PerfDenominator,
}

// ---------------------------------------------------------------------------
// Harness generation + parsing
// ---------------------------------------------------------------------------

/// Builds the JS harness an external runtime executes for one case.
///
/// The case source is embedded as a JSON string literal and compiled once via
/// `new Function`; `console.log` is replaced with an accumulator during the
/// timed loops so I/O cost does not dominate the workload being measured.
pub fn build_external_perf_harness(source: &str, warmup: u32, measured: u32) -> String {
    let escaped = serde_json::to_string(source).unwrap_or_else(|_| "\"\"".to_string());
    format!(
        "const __feSrc = {escaped};\n\
         const __feFn = new Function(__feSrc);\n\
         const __feRealLog = console.log;\n\
         let __feSink = 0;\n\
         console.log = function () {{ __feSink += arguments.length; }};\n\
         const __feWarm = [];\n\
         const __feMeas = [];\n\
         for (let i = 0; i < {warmup}; i += 1) {{\n\
           const t0 = process.hrtime.bigint();\n\
           __feFn();\n\
           const t1 = process.hrtime.bigint();\n\
           __feWarm.push(Number(t1 - t0));\n\
         }}\n\
         for (let i = 0; i < {measured}; i += 1) {{\n\
           const t0 = process.hrtime.bigint();\n\
           __feFn();\n\
           const t1 = process.hrtime.bigint();\n\
           __feMeas.push(Number(t1 - t0));\n\
         }}\n\
         console.log = __feRealLog;\n\
         console.log('{sentinel}' + JSON.stringify({{ warmup_ns: __feWarm, measured_ns: __feMeas, sink: __feSink }}));\n",
        sentinel = PERF_HARNESS_SENTINEL,
    )
}

#[derive(Debug, Deserialize)]
struct HarnessPayload {
    warmup_ns: Vec<u64>,
    measured_ns: Vec<u64>,
}

/// Extracts (warmup, measured) nanosecond vectors from harness stdout.
/// The LAST sentinel line wins so workload output cannot spoof the payload
/// unless it also runs after the harness completes.
pub fn parse_perf_harness_output(stdout: &str) -> Result<(Vec<u64>, Vec<u64>), String> {
    let payload_line = stdout
        .lines()
        .rev()
        .find_map(|line| line.trim().strip_prefix(PERF_HARNESS_SENTINEL))
        .ok_or_else(|| format!("no `{PERF_HARNESS_SENTINEL}` sentinel line in harness stdout"))?;
    let payload: HarnessPayload = serde_json::from_str(payload_line)
        .map_err(|error| format!("malformed harness timing payload: {error}"))?;
    Ok((payload.warmup_ns, payload.measured_ns))
}

// ---------------------------------------------------------------------------
// Statistics (integer-only, deterministic)
// ---------------------------------------------------------------------------

/// Deterministic integer square root (Newton's method) over u128.
fn isqrt_u128(value: u128) -> u128 {
    if value < 2 {
        return value;
    }
    let mut x = value;
    let mut y = x.div_ceil(2);
    while y < x {
        x = y;
        y = (x + value / x) / 2;
    }
    x
}

/// Computes deterministic sample statistics; `None` for empty input.
pub fn compute_sample_stats(samples: &[u64]) -> Option<PerfSampleStats> {
    if samples.is_empty() {
        return None;
    }
    let n = samples.len() as u128;
    let sum: u128 = samples.iter().map(|&s| u128::from(s)).sum();
    let mean = sum / n;
    let variance = if samples.len() < 2 {
        0
    } else {
        let sum_sq_dev: u128 = samples
            .iter()
            .map(|&s| {
                let d = u128::from(s).abs_diff(mean);
                d.saturating_mul(d)
            })
            .sum();
        sum_sq_dev / (n - 1)
    };
    let stddev = isqrt_u128(variance);
    let cv_millionths = if mean == 0 {
        0
    } else {
        u32::try_from(stddev.saturating_mul(u128::from(MILLIONTHS)) / mean).unwrap_or(u32::MAX)
    };
    // ci95 half-width = 1.96 * stddev / sqrt(n), computed in millionths so
    // sqrt(n) keeps six fractional digits of precision.
    let sqrt_n_millionths = isqrt_u128(n.saturating_mul(1_000_000_000_000));
    let ci_half = if sqrt_n_millionths == 0 {
        0
    } else {
        stddev.saturating_mul(1_960_000) / sqrt_n_millionths
    };
    let mean_u64 = u64::try_from(mean).unwrap_or(u64::MAX);
    let ci_half_u64 = u64::try_from(ci_half).unwrap_or(u64::MAX);
    Some(PerfSampleStats {
        sample_count: samples.len(),
        mean_ns: mean_u64,
        stddev_ns: u64::try_from(stddev).unwrap_or(u64::MAX),
        cv_millionths,
        ci95_lower_ns: mean_u64.saturating_sub(ci_half_u64),
        ci95_upper_ns: mean_u64.saturating_add(ci_half_u64),
        min_ns: samples.iter().copied().min().unwrap_or(0),
        max_ns: samples.iter().copied().max().unwrap_or(0),
    })
}

/// baseline_mean / engine_mean in millionths; `None` if either side is
/// missing or the engine mean is zero.
pub fn speedup_millionths(engine_mean_ns: u64, baseline_mean_ns: u64) -> Option<u64> {
    if engine_mean_ns == 0 {
        return None;
    }
    let value = u128::from(baseline_mean_ns).saturating_mul(u128::from(MILLIONTHS))
        / u128::from(engine_mean_ns);
    Some(u64::try_from(value).unwrap_or(u64::MAX))
}

/// Unweighted geometric mean of millionths-scaled ratios, in millionths.
///
/// Internally uses `f64::ln`/`exp` on report-only values (never hashed) and
/// rounds back to exact millionths, matching the precision convention used by
/// `benchmark_denominator::weighted_geometric_mean`.
pub fn geometric_mean_millionths(ratios: &[u64]) -> Option<u64> {
    if ratios.is_empty() {
        return None;
    }
    if ratios.iter().any(|&r| r == 0) {
        return None;
    }
    let log_sum: f64 = ratios
        .iter()
        .map(|&r| (r as f64 / MILLIONTHS as f64).ln())
        .sum();
    let gm = (log_sum / ratios.len() as f64).exp();
    let scaled = gm * MILLIONTHS as f64;
    if !scaled.is_finite() || scaled < 0.0 {
        return None;
    }
    Some(scaled.round() as u64)
}

/// Parses a decimal string like "12.34" into millionths (12_340_000) without
/// floating point. Returns `None` on malformed input.
pub fn parse_decimal_millionths(text: &str) -> Option<u64> {
    let trimmed = text.trim();
    let (whole, frac) = match trimmed.split_once('.') {
        Some((w, f)) => (w, f),
        None => (trimmed, ""),
    };
    if whole.is_empty() && frac.is_empty() {
        return None;
    }
    let whole_value: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let mut frac_value: u64 = 0;
    let mut scale: u64 = MILLIONTHS / 10;
    for ch in frac.chars().take(6) {
        let digit = ch.to_digit(10)? as u64;
        frac_value += digit * scale;
        scale /= 10;
    }
    whole_value
        .checked_mul(MILLIONTHS)
        .map(|w| w.saturating_add(frac_value))
}

// ---------------------------------------------------------------------------
// Environment capture + fairness evaluation
// ---------------------------------------------------------------------------

fn resolve_program_path(program: &str) -> Option<String> {
    let candidate = Path::new(program);
    if candidate.components().count() > 1 {
        return fs::canonicalize(candidate)
            .ok()
            .map(|p| p.display().to_string());
    }
    let path_var = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path_var) {
        let full = dir.join(program);
        if full.is_file() {
            return fs::canonicalize(&full)
                .ok()
                .map(|p| p.display().to_string())
                .or_else(|| Some(full.display().to_string()));
        }
    }
    None
}

/// True when the configured node binary is real Node.js rather than Bun's
/// `node` compatibility shim (`typeof Bun` is `"undefined"` on real Node).
fn detect_node_genuine(spec: &ExternalRuntimeSpec, timeout: Duration) -> Option<bool> {
    let args: Vec<&str> = spec
        .eval_args
        .iter()
        .map(String::as_str)
        .chain(["console.log(typeof Bun);"])
        .collect();
    let output = run_command_with_timeout(spec.program.as_str(), args, timeout).ok()?;
    if !output.status.success() || output.timed_out {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Some(stdout.trim() == "undefined")
}

fn read_total_memory_kb() -> Option<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    meminfo.lines().find_map(|line| {
        line.strip_prefix("MemTotal:").and_then(|rest| {
            rest.trim()
                .trim_end_matches(" kB")
                .trim()
                .parse::<u64>()
                .ok()
        })
    })
}

fn read_load_avg_1m_millionths() -> Option<u64> {
    let loadavg = fs::read_to_string("/proc/loadavg").ok()?;
    parse_decimal_millionths(loadavg.split_whitespace().next()?)
}

fn read_cpu_governor() -> Option<String> {
    fs::read_to_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn corpus_sha256(corpus: &[PerfCorpusCase]) -> String {
    // Length-prefix every variable-length field before mixing so distinct
    // corpora cannot collide on a shared byte stream.
    let mut bytes = Vec::new();
    for case in corpus {
        bytes.extend_from_slice(&(case.case_id.len() as u64).to_be_bytes());
        bytes.extend_from_slice(case.case_id.as_bytes());
        bytes.extend_from_slice(&(case.source.len() as u64).to_be_bytes());
        bytes.extend_from_slice(case.source.as_bytes());
    }
    sha256_hex(&bytes)
}

/// Captures the full environment manifest the fairness rules require.
pub fn capture_perf_environment(
    config: &PerfArmConfig,
    corpus: &[PerfCorpusCase],
) -> PerfEnvironmentManifest {
    let probe_timeout = Duration::from_millis(5_000);
    let node_version = match capture_external_version(&config.node, probe_timeout) {
        VersionProbe::Available(v) => Some(v),
        VersionProbe::Unavailable(_) => None,
    };
    let bun_version = match capture_external_version(&config.bun, probe_timeout) {
        VersionProbe::Available(v) => Some(v),
        VersionProbe::Unavailable(_) => None,
    };
    PerfEnvironmentManifest {
        host: capture_host_facts(),
        total_memory_kb: read_total_memory_kb(),
        load_avg_1m_millionths: read_load_avg_1m_millionths(),
        cpu_governor: read_cpu_governor(),
        node_resolved_program: resolve_program_path(config.node.program.as_str()),
        node_version,
        node_genuine: detect_node_genuine(&config.node, probe_timeout),
        bun_resolved_program: resolve_program_path(config.bun.program.as_str()),
        bun_version,
        warmup_iterations: config.warmup_iterations,
        measured_iterations: config.measured_iterations,
        corpus_case_count: corpus.len(),
        corpus_sha256: corpus_sha256(corpus),
        generated_unix_ns: current_unix_ns(),
    }
}

/// Applies the binding fairness rules to a captured environment.
pub fn evaluate_fairness(
    environment: &PerfEnvironmentManifest,
    config: &PerfArmConfig,
) -> PerfFairnessReport {
    let mut violations = Vec::new();
    let mut notes = Vec::new();

    if config.warmup_iterations == 0 {
        violations.push("warmup protocol requires at least one warmup iteration".to_string());
    }
    if config.measured_iterations < 10 {
        violations.push(format!(
            "measured_iterations={} is below the minimum sample floor of 10",
            config.measured_iterations
        ));
    }
    if environment.node_version.is_none() {
        violations.push("node runtime version could not be recorded".to_string());
    }
    if environment.bun_version.is_none() {
        violations.push("bun runtime version could not be recorded".to_string());
    }
    match environment.node_genuine {
        Some(true) => {}
        Some(false) => violations.push(
            "configured `node` binary is Bun's node shim, not real Node.js — \
             point --node-bin at a genuine Node installation"
                .to_string(),
        ),
        None => violations.push("could not verify the node binary is genuine Node.js".to_string()),
    }
    match environment.cpu_governor.as_deref() {
        Some("performance") => {}
        Some(other) => notes.push(format!(
            "cpu governor is `{other}` (not `performance`); host does not allow pinning"
        )),
        None => notes.push("cpu governor not readable on this host".to_string()),
    }
    if let Some(load) = environment.load_avg_1m_millionths {
        let cores = environment.host.cpu_cores_logical as u64;
        if cores > 0 && load > cores.saturating_mul(MILLIONTHS) / 2 {
            notes.push(format!(
                "1m load average {load_whole}.{load_frac:06} exceeds half the {cores} logical cores; \
                 expect elevated variance",
                load_whole = load / MILLIONTHS,
                load_frac = load % MILLIONTHS,
            ));
        }
    }
    notes.push(
        "engine lane pays full parse+lower+execute per iteration while node/bun compile once \
         and JIT-warm — conservative against FrankenEngine"
            .to_string(),
    );

    PerfFairnessReport {
        compliant: violations.is_empty(),
        violations,
        notes,
    }
}

// ---------------------------------------------------------------------------
// Per-case measurement
// ---------------------------------------------------------------------------

fn run_external_perf_case(
    spec: &ExternalRuntimeSpec,
    source: &str,
    config: &PerfArmConfig,
) -> PerfBackendCaseResult {
    let timeout = Duration::from_millis(config.case_timeout_ms.max(1));
    let version = match capture_external_version(spec, Duration::from_millis(5_000)) {
        VersionProbe::Available(v) => Some(v),
        VersionProbe::Unavailable(message) => {
            return PerfBackendCaseResult {
                backend: spec.runtime_id,
                status: PerfMeasurementStatus::Unavailable,
                resolved_program: resolve_program_path(spec.program.as_str()),
                version: None,
                warmup_ns: Vec::new(),
                measured_ns: Vec::new(),
                stats: None,
                diagnostics: vec![message],
            };
        }
    };
    let harness =
        build_external_perf_harness(source, config.warmup_iterations, config.measured_iterations);
    let args: Vec<&str> = spec
        .eval_args
        .iter()
        .map(String::as_str)
        .chain([harness.as_str()])
        .collect();
    match run_command_with_timeout(spec.program.as_str(), args, timeout) {
        Ok(output) if output.timed_out => PerfBackendCaseResult {
            backend: spec.runtime_id,
            status: PerfMeasurementStatus::Timeout,
            resolved_program: resolve_program_path(spec.program.as_str()),
            version,
            warmup_ns: Vec::new(),
            measured_ns: Vec::new(),
            stats: None,
            diagnostics: vec![format!(
                "perf harness exceeded {}ms timeout",
                timeout.as_millis()
            )],
        },
        Ok(output) if !output.status.success() => PerfBackendCaseResult {
            backend: spec.runtime_id,
            status: PerfMeasurementStatus::Failed,
            resolved_program: resolve_program_path(spec.program.as_str()),
            version,
            warmup_ns: Vec::new(),
            measured_ns: Vec::new(),
            stats: None,
            diagnostics: vec![format!(
                "perf harness exited with {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
                    .chars()
                    .take(400)
                    .collect::<String>()
            )],
        },
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            match parse_perf_harness_output(&stdout) {
                Ok((warmup_ns, measured_ns)) => {
                    let stats = compute_sample_stats(&measured_ns);
                    PerfBackendCaseResult {
                        backend: spec.runtime_id,
                        status: PerfMeasurementStatus::Measured,
                        resolved_program: resolve_program_path(spec.program.as_str()),
                        version,
                        warmup_ns,
                        measured_ns,
                        stats,
                        diagnostics: Vec::new(),
                    }
                }
                Err(message) => PerfBackendCaseResult {
                    backend: spec.runtime_id,
                    status: PerfMeasurementStatus::Failed,
                    resolved_program: resolve_program_path(spec.program.as_str()),
                    version,
                    warmup_ns: Vec::new(),
                    measured_ns: Vec::new(),
                    stats: None,
                    diagnostics: vec![message],
                },
            }
        }
        Err(error) => PerfBackendCaseResult {
            backend: spec.runtime_id,
            status: PerfMeasurementStatus::Unavailable,
            resolved_program: resolve_program_path(spec.program.as_str()),
            version,
            warmup_ns: Vec::new(),
            measured_ns: Vec::new(),
            stats: None,
            diagnostics: vec![format!("failed to spawn perf harness: {error}")],
        },
    }
}

fn run_engine_perf_case(source: &str, config: &PerfArmConfig) -> PerfBackendCaseResult {
    let mut warmup_ns = Vec::with_capacity(config.warmup_iterations as usize);
    let mut measured_ns = Vec::with_capacity(config.measured_iterations as usize);
    let mut diagnostics = Vec::new();
    let mut failed = false;

    for phase_measured in [false, true] {
        let count = if phase_measured {
            config.measured_iterations
        } else {
            config.warmup_iterations
        };
        for _ in 0..count {
            let mut router = HybridRouter::default();
            let started = Instant::now();
            let outcome = router.eval(source);
            let elapsed = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
            match outcome {
                Ok(_) => {
                    if phase_measured {
                        measured_ns.push(elapsed);
                    } else {
                        warmup_ns.push(elapsed);
                    }
                }
                Err(error) => {
                    diagnostics.push(format!("engine eval failed: {error}"));
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            break;
        }
    }

    if failed {
        return PerfBackendCaseResult {
            backend: DifferentialBackend::FrankenEngine,
            status: PerfMeasurementStatus::Failed,
            resolved_program: None,
            version: Some(env!("CARGO_PKG_VERSION").to_string()),
            warmup_ns: Vec::new(),
            measured_ns: Vec::new(),
            stats: None,
            diagnostics,
        };
    }
    let stats = compute_sample_stats(&measured_ns);
    PerfBackendCaseResult {
        backend: DifferentialBackend::FrankenEngine,
        status: PerfMeasurementStatus::Measured,
        resolved_program: None,
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
        warmup_ns,
        measured_ns,
        stats,
        diagnostics,
    }
}

/// Output-equivalence precondition via the correctness arm: Node, Bun, and
/// FrankenEngine must share one canonical structured-value group. FrankenCore
/// membership is ignored — the denominator claim is about Node and Bun.
fn check_behavior_equivalence(case: &PerfCorpusCase, config: &PerfArmConfig) -> (bool, String) {
    let mut input = DifferentialOracleInput::new(case.case_id.clone(), case.source.clone())
        .with_timeout_ms(config.case_timeout_ms.max(1));
    input.node = config.node.clone();
    input.bun = config.bun.clone();
    let report = run_differential_oracle(&input);
    let comparison = report
        .canonicalization
        .comparisons
        .iter()
        .find(|c| c.mode == DifferentialComparisonMode::StructuredValue);
    let Some(comparison) = comparison else {
        return (
            false,
            "correctness arm produced no structured-value comparison (fail-closed)".to_string(),
        );
    };
    if comparison.verdict == DifferentialComparisonVerdict::InsufficientData {
        return (
            false,
            "structured-value comparison had insufficient data (fail-closed)".to_string(),
        );
    }
    let required = [
        DifferentialBackend::NodeLts,
        DifferentialBackend::BunStable,
        DifferentialBackend::FrankenEngine,
    ];
    for group in &comparison.groups {
        if required.iter().all(|b| group.backends.contains(b)) {
            return (
                true,
                format!(
                    "node/bun/engine share structured-value group {}",
                    group.canonical_key_sha256
                ),
            );
        }
    }
    (
        false,
        "node/bun/engine did not share a structured-value group".to_string(),
    )
}

// ---------------------------------------------------------------------------
// Denominator assembly
// ---------------------------------------------------------------------------

fn case_speedup(engine: &PerfBackendCaseResult, baseline: &PerfBackendCaseResult) -> Option<u64> {
    let engine_mean = engine.stats.as_ref()?.mean_ns;
    let baseline_mean = baseline.stats.as_ref()?.mean_ns;
    speedup_millionths(engine_mean, baseline_mean)
}

/// Builds one baseline's denominator from per-case results.
pub fn build_denominator(
    cases: &[PerfCaseResult],
    baseline: DifferentialBackend,
    fairness: &PerfFairnessReport,
    config: &PerfArmConfig,
) -> PerfDenominator {
    let baseline_label = match baseline {
        DifferentialBackend::NodeLts => "node",
        DifferentialBackend::BunStable => "bun",
        other => other.stable_label(),
    };
    let mut admitted_ratios = Vec::new();
    let mut excluded = 0usize;
    for case in cases {
        let baseline_result = match baseline {
            DifferentialBackend::NodeLts => &case.node,
            DifferentialBackend::BunStable => &case.bun,
            _ => &case.node,
        };
        let ratio = match baseline {
            DifferentialBackend::NodeLts => case.node_over_engine_speedup_millionths,
            DifferentialBackend::BunStable => case.bun_over_engine_speedup_millionths,
            _ => None,
        };
        let cv_ok = |result: &PerfBackendCaseResult| {
            result
                .stats
                .as_ref()
                .is_some_and(|s| s.cv_millionths <= config.max_cv_millionths)
        };
        if case.behavior_equivalent
            && case.engine.status == PerfMeasurementStatus::Measured
            && baseline_result.status == PerfMeasurementStatus::Measured
            && cv_ok(&case.engine)
            && cv_ok(baseline_result)
            && ratio.is_some()
        {
            admitted_ratios.push(ratio.unwrap_or(0));
        } else {
            excluded = excluded.saturating_add(1);
        }
    }

    let geomean = geometric_mean_millionths(&admitted_ratios);
    let mut degraded_reasons = Vec::new();
    if !fairness.compliant {
        degraded_reasons.push("fairness rules unmet (see fairness.violations)".to_string());
    }
    if admitted_ratios.is_empty() {
        degraded_reasons.push("no case satisfied the admission preconditions".to_string());
    }
    let status = if degraded_reasons.is_empty() {
        PerfDenominatorStatus::Published
    } else {
        PerfDenominatorStatus::Degraded
    };
    let publishable = status == PerfDenominatorStatus::Published;
    PerfDenominator {
        baseline: baseline_label.to_string(),
        admitted_cases: admitted_ratios.len(),
        excluded_cases: excluded,
        geomean_speedup_millionths: if publishable { geomean } else { None },
        meets_3x_floor: if publishable {
            geomean.map(|g| g >= DENOMINATOR_FLOOR_MILLIONTHS)
        } else {
            None
        },
        status,
        degraded_reasons,
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

/// Runs the full performance arm over a corpus. Returns the report plus the
/// raw per-iteration event stream for `events.jsonl`.
pub fn run_differential_perf(
    corpus: &[PerfCorpusCase],
    config: &PerfArmConfig,
) -> (DifferentialPerfReport, Vec<PerfIterationEvent>) {
    let environment = capture_perf_environment(config, corpus);
    let fairness = evaluate_fairness(&environment, config);

    let mut events = Vec::new();
    let mut case_results = Vec::new();
    for case in corpus {
        let (behavior_equivalent, equivalence_detail) = check_behavior_equivalence(case, config);
        let engine = run_engine_perf_case(case.source.as_str(), config);
        let node = run_external_perf_case(&config.node, case.source.as_str(), config);
        let bun = run_external_perf_case(&config.bun, case.source.as_str(), config);

        for (backend_result, backend) in [
            (&engine, DifferentialBackend::FrankenEngine),
            (&node, DifferentialBackend::NodeLts),
            (&bun, DifferentialBackend::BunStable),
        ] {
            for (phase, samples) in [
                (PerfPhase::Warmup, &backend_result.warmup_ns),
                (PerfPhase::Measured, &backend_result.measured_ns),
            ] {
                for (index, &duration_ns) in samples.iter().enumerate() {
                    events.push(PerfIterationEvent {
                        event: "diffperf.iteration".to_string(),
                        case_id: case.case_id.clone(),
                        backend,
                        phase,
                        index: u32::try_from(index).unwrap_or(u32::MAX),
                        duration_ns,
                    });
                }
            }
        }

        let node_ratio = case_speedup(&engine, &node);
        let bun_ratio = case_speedup(&engine, &bun);
        let mut exclusion_reasons = Vec::new();
        if !behavior_equivalent {
            exclusion_reasons.push(equivalence_detail.clone());
        }
        for (label, result) in [("engine", &engine), ("node", &node), ("bun", &bun)] {
            if result.status != PerfMeasurementStatus::Measured {
                exclusion_reasons.push(format!(
                    "{label} lane status {:?} prevented measurement",
                    result.status
                ));
            } else if let Some(stats) = result.stats.as_ref()
                && stats.cv_millionths > config.max_cv_millionths
            {
                exclusion_reasons.push(format!(
                    "{label} lane cv {} millionths exceeds the {} millionths bar",
                    stats.cv_millionths, config.max_cv_millionths
                ));
            }
        }
        let admitted = exclusion_reasons.is_empty();
        case_results.push(PerfCaseResult {
            case_id: case.case_id.clone(),
            source_sha256: sha256_hex(case.source.as_bytes()),
            behavior_equivalent,
            equivalence_detail,
            engine,
            node,
            bun,
            node_over_engine_speedup_millionths: node_ratio,
            bun_over_engine_speedup_millionths: bun_ratio,
            admitted,
            exclusion_reasons,
        });
    }

    let node_denominator = build_denominator(
        &case_results,
        DifferentialBackend::NodeLts,
        &fairness,
        config,
    );
    let bun_denominator = build_denominator(
        &case_results,
        DifferentialBackend::BunStable,
        &fairness,
        config,
    );

    (
        DifferentialPerfReport {
            schema_version: DIFFERENTIAL_PERF_SCHEMA_VERSION.to_string(),
            generated_unix_ns: current_unix_ns(),
            environment,
            fairness,
            cases: case_results,
            node_denominator,
            bun_denominator,
        },
        events,
    )
}

// ---------------------------------------------------------------------------
// Corpus loading
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ComparisonManifestCase {
    benchmark_id: String,
    program_path: String,
}

#[derive(Debug, Deserialize)]
struct ComparisonManifest {
    cases: Vec<ComparisonManifestCase>,
}

/// Loads the `benchmarks/runtime_comparison/manifest.json` corpus: each case's
/// program file is read relative to the manifest's directory. Case ids are
/// returned in manifest order; duplicates are rejected.
pub fn load_runtime_comparison_corpus(manifest_path: &Path) -> Result<Vec<PerfCorpusCase>, String> {
    let manifest_text = fs::read_to_string(manifest_path).map_err(|error| {
        format!(
            "failed to read manifest {}: {error}",
            manifest_path.display()
        )
    })?;
    let manifest: ComparisonManifest = serde_json::from_str(&manifest_text)
        .map_err(|error| format!("malformed manifest {}: {error}", manifest_path.display()))?;
    let base = manifest_path.parent().unwrap_or_else(|| Path::new("."));
    let mut seen = BTreeMap::new();
    let mut corpus = Vec::with_capacity(manifest.cases.len());
    for case in manifest.cases {
        if seen.insert(case.benchmark_id.clone(), ()).is_some() {
            return Err(format!("duplicate benchmark_id `{}`", case.benchmark_id));
        }
        let program = base.join(&case.program_path);
        let source = fs::read_to_string(&program)
            .map_err(|error| format!("failed to read {}: {error}", program.display()))?;
        corpus.push(PerfCorpusCase::new(case.benchmark_id, source));
    }
    Ok(corpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measured_result(backend: DifferentialBackend, samples: &[u64]) -> PerfBackendCaseResult {
        PerfBackendCaseResult {
            backend,
            status: PerfMeasurementStatus::Measured,
            resolved_program: None,
            version: Some("test".to_string()),
            warmup_ns: Vec::new(),
            measured_ns: samples.to_vec(),
            stats: compute_sample_stats(samples),
            diagnostics: Vec::new(),
        }
    }

    fn equivalent_case(
        case_id: &str,
        engine_ns: &[u64],
        node_ns: &[u64],
        bun_ns: &[u64],
    ) -> PerfCaseResult {
        let engine = measured_result(DifferentialBackend::FrankenEngine, engine_ns);
        let node = measured_result(DifferentialBackend::NodeLts, node_ns);
        let bun = measured_result(DifferentialBackend::BunStable, bun_ns);
        let node_ratio = case_speedup(&engine, &node);
        let bun_ratio = case_speedup(&engine, &bun);
        PerfCaseResult {
            case_id: case_id.to_string(),
            source_sha256: sha256_hex(case_id.as_bytes()),
            behavior_equivalent: true,
            equivalence_detail: "test".to_string(),
            engine,
            node,
            bun,
            node_over_engine_speedup_millionths: node_ratio,
            bun_over_engine_speedup_millionths: bun_ratio,
            admitted: true,
            exclusion_reasons: Vec::new(),
        }
    }

    fn compliant_fairness() -> PerfFairnessReport {
        PerfFairnessReport {
            compliant: true,
            violations: Vec::new(),
            notes: Vec::new(),
        }
    }

    #[test]
    fn harness_contains_sentinel_and_iteration_counts() {
        let harness = build_external_perf_harness("console.log(1);", 2, 7);
        assert!(harness.contains(PERF_HARNESS_SENTINEL));
        assert!(harness.contains("i < 2"));
        assert!(harness.contains("i < 7"));
    }

    #[test]
    fn harness_json_escapes_source() {
        let harness = build_external_perf_harness("var s = \"quoted\";\nconsole.log(s);", 1, 1);
        assert!(harness.contains("\\\"quoted\\\""));
        assert!(harness.contains("\\n"));
    }

    #[test]
    fn harness_compiles_source_once() {
        let harness = build_external_perf_harness("1 + 1;", 1, 1);
        assert_eq!(harness.matches("new Function").count(), 1);
    }

    #[test]
    fn parse_harness_output_happy_path() {
        let stdout = format!(
            "workload noise\n{PERF_HARNESS_SENTINEL}{{\"warmup_ns\":[5],\"measured_ns\":[10,11],\"sink\":3}}\n"
        );
        let (warm, meas) = parse_perf_harness_output(&stdout).expect("parse");
        assert_eq!(warm, vec![5]);
        assert_eq!(meas, vec![10, 11]);
    }

    #[test]
    fn parse_harness_output_requires_sentinel() {
        let error = parse_perf_harness_output("no sentinel here").unwrap_err();
        assert!(error.contains("sentinel"));
    }

    #[test]
    fn parse_harness_output_rejects_malformed_json() {
        let stdout = format!("{PERF_HARNESS_SENTINEL}{{not json");
        let error = parse_perf_harness_output(&stdout).unwrap_err();
        assert!(error.contains("malformed"));
    }

    #[test]
    fn parse_harness_output_uses_last_sentinel_line() {
        let stdout = format!(
            "{PERF_HARNESS_SENTINEL}{{\"warmup_ns\":[1],\"measured_ns\":[1],\"sink\":0}}\n\
             {PERF_HARNESS_SENTINEL}{{\"warmup_ns\":[2],\"measured_ns\":[9],\"sink\":0}}\n"
        );
        let (warm, meas) = parse_perf_harness_output(&stdout).expect("parse");
        assert_eq!(warm, vec![2]);
        assert_eq!(meas, vec![9]);
    }

    #[test]
    fn stats_empty_input_is_none() {
        assert!(compute_sample_stats(&[]).is_none());
    }

    #[test]
    fn stats_single_sample_has_zero_spread() {
        let stats = compute_sample_stats(&[1_000]).expect("stats");
        assert_eq!(stats.mean_ns, 1_000);
        assert_eq!(stats.stddev_ns, 0);
        assert_eq!(stats.cv_millionths, 0);
        assert_eq!(stats.ci95_lower_ns, 1_000);
        assert_eq!(stats.ci95_upper_ns, 1_000);
    }

    #[test]
    fn stats_known_values() {
        // mean 200, sample variance ((100)^2 + 0 + (100)^2) / 2 = 10000 -> stddev 100.
        let stats = compute_sample_stats(&[100, 200, 300]).expect("stats");
        assert_eq!(stats.mean_ns, 200);
        assert_eq!(stats.stddev_ns, 100);
        assert_eq!(stats.cv_millionths, 500_000);
        assert_eq!(stats.min_ns, 100);
        assert_eq!(stats.max_ns, 300);
    }

    #[test]
    fn stats_ci_brackets_mean() {
        let stats = compute_sample_stats(&[90, 100, 110, 95, 105]).expect("stats");
        assert!(stats.ci95_lower_ns <= stats.mean_ns);
        assert!(stats.ci95_upper_ns >= stats.mean_ns);
        assert!(stats.ci95_lower_ns > 0);
    }

    #[test]
    fn isqrt_edge_cases() {
        assert_eq!(isqrt_u128(0), 0);
        assert_eq!(isqrt_u128(1), 1);
        assert_eq!(isqrt_u128(15), 3);
        assert_eq!(isqrt_u128(16), 4);
        assert_eq!(isqrt_u128(1_000_000_000_000), 1_000_000);
    }

    #[test]
    fn speedup_exact_two_x() {
        assert_eq!(speedup_millionths(100, 200), Some(2_000_000));
    }

    #[test]
    fn speedup_engine_slower_is_below_one() {
        assert_eq!(speedup_millionths(200, 100), Some(500_000));
    }

    #[test]
    fn speedup_zero_engine_mean_is_none() {
        assert_eq!(speedup_millionths(0, 100), None);
    }

    #[test]
    fn geomean_of_two_and_eight_is_four() {
        let gm = geometric_mean_millionths(&[2_000_000, 8_000_000]).expect("gm");
        assert!((gm as i64 - 4_000_000).abs() <= 1, "gm={gm}");
    }

    #[test]
    fn geomean_empty_is_none() {
        assert!(geometric_mean_millionths(&[]).is_none());
    }

    #[test]
    fn geomean_zero_ratio_is_none() {
        assert!(geometric_mean_millionths(&[0, 2_000_000]).is_none());
    }

    #[test]
    fn parse_decimal_millionths_variants() {
        assert_eq!(parse_decimal_millionths("12.34"), Some(12_340_000));
        assert_eq!(parse_decimal_millionths("0.5"), Some(500_000));
        assert_eq!(parse_decimal_millionths("7"), Some(7_000_000));
        assert_eq!(parse_decimal_millionths(""), None);
        assert_eq!(parse_decimal_millionths("not-a-number"), None);
    }

    #[test]
    fn denominator_publishes_and_checks_floor() {
        let cases = vec![
            equivalent_case("a", &[100; 12], &[400; 12], &[200; 12]),
            equivalent_case("b", &[100; 12], &[900; 12], &[400; 12]),
        ];
        let config = PerfArmConfig::default();
        let node = build_denominator(
            &cases,
            DifferentialBackend::NodeLts,
            &compliant_fairness(),
            &config,
        );
        assert_eq!(node.status, PerfDenominatorStatus::Published);
        assert_eq!(node.admitted_cases, 2);
        // geomean(4x, 9x) = 6x.
        assert_eq!(node.geomean_speedup_millionths, Some(6_000_000));
        assert_eq!(node.meets_3x_floor, Some(true));
    }

    #[test]
    fn denominator_honest_below_floor() {
        let cases = vec![equivalent_case("a", &[400; 12], &[200; 12], &[100; 12])];
        let config = PerfArmConfig::default();
        let node = build_denominator(
            &cases,
            DifferentialBackend::NodeLts,
            &compliant_fairness(),
            &config,
        );
        assert_eq!(node.status, PerfDenominatorStatus::Published);
        assert_eq!(node.geomean_speedup_millionths, Some(500_000));
        assert_eq!(node.meets_3x_floor, Some(false));
    }

    #[test]
    fn denominator_excludes_non_equivalent_case() {
        let mut case = equivalent_case("a", &[100; 12], &[400; 12], &[200; 12]);
        case.behavior_equivalent = false;
        let config = PerfArmConfig::default();
        let node = build_denominator(
            &[case],
            DifferentialBackend::NodeLts,
            &compliant_fairness(),
            &config,
        );
        assert_eq!(node.admitted_cases, 0);
        assert_eq!(node.excluded_cases, 1);
        assert_eq!(node.status, PerfDenominatorStatus::Degraded);
    }

    #[test]
    fn denominator_excludes_high_cv_case() {
        // Wildly bimodal engine samples blow through the 15% CV bar.
        let case = equivalent_case(
            "a",
            &[
                100, 10_000, 100, 10_000, 100, 10_000, 100, 10_000, 100, 10_000, 100, 10_000,
            ],
            &[400; 12],
            &[200; 12],
        );
        let config = PerfArmConfig::default();
        let node = build_denominator(
            &[case],
            DifferentialBackend::NodeLts,
            &compliant_fairness(),
            &config,
        );
        assert_eq!(node.admitted_cases, 0);
        assert_eq!(node.status, PerfDenominatorStatus::Degraded);
    }

    #[test]
    fn denominator_degraded_when_fairness_violated() {
        let cases = vec![equivalent_case("a", &[100; 12], &[400; 12], &[200; 12])];
        let fairness = PerfFairnessReport {
            compliant: false,
            violations: vec!["node binary is bun shim".to_string()],
            notes: Vec::new(),
        };
        let config = PerfArmConfig::default();
        let node = build_denominator(&cases, DifferentialBackend::NodeLts, &fairness, &config);
        assert_eq!(node.status, PerfDenominatorStatus::Degraded);
        assert_eq!(node.geomean_speedup_millionths, None);
        assert_eq!(node.meets_3x_floor, None);
    }

    #[test]
    fn fairness_flags_zero_warmup() {
        let config = PerfArmConfig {
            warmup_iterations: 0,
            ..PerfArmConfig::default()
        };
        let environment = test_environment();
        let report = evaluate_fairness(&environment, &config);
        assert!(!report.compliant);
        assert!(report.violations.iter().any(|v| v.contains("warmup")));
    }

    #[test]
    fn fairness_flags_bun_shim_node() {
        let config = PerfArmConfig::default();
        let mut environment = test_environment();
        environment.node_genuine = Some(false);
        let report = evaluate_fairness(&environment, &config);
        assert!(!report.compliant);
        assert!(report.violations.iter().any(|v| v.contains("shim")));
    }

    #[test]
    fn fairness_accepts_clean_environment() {
        let config = PerfArmConfig::default();
        let environment = test_environment();
        let report = evaluate_fairness(&environment, &config);
        assert!(report.compliant, "violations: {:?}", report.violations);
    }

    #[test]
    fn fairness_notes_engine_bias() {
        let report = evaluate_fairness(&test_environment(), &PerfArmConfig::default());
        assert!(report.notes.iter().any(|n| n.contains("conservative")));
    }

    #[test]
    fn corpus_sha_is_length_prefixed() {
        // ("ab","c") and ("a","bc") must hash differently.
        let one = corpus_sha256(&[PerfCorpusCase::new("ab", "c")]);
        let two = corpus_sha256(&[PerfCorpusCase::new("a", "bc")]);
        assert_ne!(one, two);
    }

    #[test]
    fn engine_perf_case_measures_simple_source() {
        let config = PerfArmConfig {
            warmup_iterations: 1,
            measured_iterations: 3,
            ..PerfArmConfig::default()
        };
        let result = run_engine_perf_case("1 + 1;", &config);
        assert_eq!(result.status, PerfMeasurementStatus::Measured);
        assert_eq!(result.warmup_ns.len(), 1);
        assert_eq!(result.measured_ns.len(), 3);
        assert!(result.stats.is_some());
    }

    #[test]
    fn engine_perf_case_reports_failure() {
        let config = PerfArmConfig {
            warmup_iterations: 1,
            measured_iterations: 2,
            ..PerfArmConfig::default()
        };
        let result = run_engine_perf_case("syntax error here (", &config);
        assert_eq!(result.status, PerfMeasurementStatus::Failed);
        assert!(result.stats.is_none());
        assert!(!result.diagnostics.is_empty());
    }

    #[test]
    fn corpus_loader_reads_manifest_relative_programs() {
        let dir =
            std::env::temp_dir().join(format!("fe_diffperf_corpus_test_{}", std::process::id()));
        let programs = dir.join("programs");
        fs::create_dir_all(&programs).expect("mkdir");
        fs::write(programs.join("one.js"), "console.log(1);").expect("write program");
        let manifest = dir.join("manifest.json");
        fs::write(
            &manifest,
            "{\"cases\":[{\"benchmark_id\":\"one\",\"program_path\":\"programs/one.js\"}]}",
        )
        .expect("write manifest");
        let corpus = load_runtime_comparison_corpus(&manifest).expect("load");
        assert_eq!(corpus.len(), 1);
        assert_eq!(corpus[0].case_id, "one");
        assert_eq!(corpus[0].source, "console.log(1);");
    }

    #[test]
    fn corpus_loader_rejects_duplicate_ids() {
        let dir = std::env::temp_dir().join(format!(
            "fe_diffperf_corpus_dup_test_{}",
            std::process::id()
        ));
        let programs = dir.join("programs");
        fs::create_dir_all(&programs).expect("mkdir");
        fs::write(programs.join("one.js"), "1;").expect("write program");
        let manifest = dir.join("manifest.json");
        fs::write(
            &manifest,
            "{\"cases\":[\
             {\"benchmark_id\":\"one\",\"program_path\":\"programs/one.js\"},\
             {\"benchmark_id\":\"one\",\"program_path\":\"programs/one.js\"}]}",
        )
        .expect("write manifest");
        let error = load_runtime_comparison_corpus(&manifest).unwrap_err();
        assert!(error.contains("duplicate"));
    }

    #[test]
    fn report_serde_round_trip() {
        let cases = vec![equivalent_case("a", &[100; 12], &[400; 12], &[200; 12])];
        let config = PerfArmConfig::default();
        let fairness = compliant_fairness();
        let node = build_denominator(&cases, DifferentialBackend::NodeLts, &fairness, &config);
        let bun = build_denominator(&cases, DifferentialBackend::BunStable, &fairness, &config);
        let report = DifferentialPerfReport {
            schema_version: DIFFERENTIAL_PERF_SCHEMA_VERSION.to_string(),
            generated_unix_ns: 42,
            environment: test_environment(),
            fairness,
            cases,
            node_denominator: node,
            bun_denominator: bun,
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: DifferentialPerfReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn iteration_event_serializes_snake_case_phase() {
        let event = PerfIterationEvent {
            event: "diffperf.iteration".to_string(),
            case_id: "a".to_string(),
            backend: DifferentialBackend::NodeLts,
            phase: PerfPhase::Measured,
            index: 0,
            duration_ns: 5,
        };
        let json = serde_json::to_string(&event).expect("serialize");
        assert!(json.contains("\"measured\""));
        assert!(json.contains("node_lts"));
    }

    fn test_environment() -> PerfEnvironmentManifest {
        PerfEnvironmentManifest {
            host: DifferentialHostFacts {
                os: "linux".to_string(),
                arch: "x86_64".to_string(),
                kernel: "test".to_string(),
                cpu_model: "test".to_string(),
                cpu_cores_logical: 8,
                franken_engine_version: "0.1.0".to_string(),
            },
            total_memory_kb: Some(1),
            load_avg_1m_millionths: Some(100_000),
            cpu_governor: Some("performance".to_string()),
            node_resolved_program: Some("/usr/bin/node".to_string()),
            node_version: Some("v22.2.0".to_string()),
            node_genuine: Some(true),
            bun_resolved_program: Some("/home/test/.bun/bin/bun".to_string()),
            bun_version: Some("1.3.14".to_string()),
            warmup_iterations: 3,
            measured_iterations: 30,
            corpus_case_count: 1,
            corpus_sha256: "0".repeat(64),
            generated_unix_ns: 42,
        }
    }
}
