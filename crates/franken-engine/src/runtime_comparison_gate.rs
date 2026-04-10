//! Release gate: Node/Bun comparison harness reproducibility and
//! publishability validation.
//!
//! Validates that the official runtime comparison harness (FrankenEngine
//! vs Node.js LTS vs Bun stable) meets the publishable-quality bar
//! required before credible performance claims can be attached to a
//! release.
//!
//! Key behaviors:
//! - Reproducibility audit: independent operator can replay full suite
//!   within stated tolerance band (CV < 3% across N runs).
//! - Methodology completeness check: benchmark selection rationale,
//!   warm-up policy, GC/JIT settling, statistical treatment documented.
//! - Artifact bundle validation: raw timing, environment fingerprint,
//!   run manifest, and replay script all present.
//! - Scorecard integration: output feeds disruption scorecard
//!   `performance_delta` dimension.
//! - No benchmark-sniffing: harness runs same binary/config as shipped.
//!
//! Plan reference: Section 10.9 item 1, bd-1ze.
//! Cross-refs: bd-6pk (disruption scorecard), bd-mhz4 (benchmark harness),
//! bd-3gsv (third-party verifier toolkit).

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const GATE_COMPONENT: &str = "runtime_comparison_gate";

/// Schema version for gate evidence.
pub const GATE_SCHEMA_VERSION: &str = "franken-engine.runtime-comparison-gate.v1";

/// Default maximum coefficient of variation (CV) in millionths.
/// 30_000 = 3%.
pub const DEFAULT_MAX_CV_MILLIONTHS: u64 = 30_000;

/// Default minimum runs per benchmark for statistical validity.
pub const DEFAULT_MIN_RUNS_PER_BENCHMARK: u64 = 30;

/// Required benchmark categories for a complete harness.
pub const REQUIRED_CATEGORIES: &[BenchmarkCategory] = &[
    BenchmarkCategory::Micro,
    BenchmarkCategory::Macro,
    BenchmarkCategory::Startup,
    BenchmarkCategory::Throughput,
    BenchmarkCategory::Memory,
];

// ---------------------------------------------------------------------------
// RuntimeId — identifies a runtime under comparison
// ---------------------------------------------------------------------------

/// Identifies a runtime being compared.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RuntimeId {
    /// FrankenEngine (the subject under test).
    FrankenEngine,
    /// Node.js LTS release.
    NodeLts,
    /// Bun stable release.
    BunStable,
}

impl RuntimeId {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FrankenEngine => "franken_engine",
            Self::NodeLts => "node_lts",
            Self::BunStable => "bun_stable",
        }
    }

    pub fn all() -> &'static [Self] {
        &[Self::FrankenEngine, Self::NodeLts, Self::BunStable]
    }
}

impl fmt::Display for RuntimeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BenchmarkCategory
// ---------------------------------------------------------------------------

/// Category of benchmark in the comparison corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BenchmarkCategory {
    /// Micro-benchmarks: tight loops, arithmetic, function calls.
    Micro,
    /// Macro-benchmarks: real-world application patterns.
    Macro,
    /// Startup time: cold start, module loading, initialization.
    Startup,
    /// Throughput: requests/sec, operations/sec under sustained load.
    Throughput,
    /// Memory: peak RSS, allocation rate, GC pressure.
    Memory,
}

impl BenchmarkCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Macro => "macro",
            Self::Startup => "startup",
            Self::Throughput => "throughput",
            Self::Memory => "memory",
        }
    }

    pub fn all() -> &'static [Self] {
        REQUIRED_CATEGORIES
    }
}

impl fmt::Display for BenchmarkCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BenchmarkResult
// ---------------------------------------------------------------------------

/// Result of a single benchmark on a single runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkResult {
    /// Unique benchmark identifier.
    pub benchmark_id: String,
    /// Category of this benchmark.
    pub category: BenchmarkCategory,
    /// Which runtime produced this result.
    pub runtime: RuntimeId,
    /// Wall-time in nanoseconds (median across runs).
    pub wall_time_ns: u64,
    /// Peak memory in bytes.
    pub memory_peak_bytes: u64,
    /// Number of runs (samples).
    pub run_count: u64,
    /// Coefficient of variation in millionths (1_000_000 = 100%).
    pub cv_millionths: u64,
}

// ---------------------------------------------------------------------------
// EnvironmentFingerprint
// ---------------------------------------------------------------------------

/// Captures the environment in which benchmarks were run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentFingerprint {
    /// CPU model string.
    pub cpu_model: String,
    /// Number of CPU cores.
    pub cpu_cores: u32,
    /// Total RAM in bytes.
    pub ram_bytes: u64,
    /// OS name and version.
    pub os_version: String,
    /// Kernel version.
    pub kernel_version: String,
    /// Runtime versions being compared.
    pub runtime_versions: BTreeMap<String, String>,
    /// Runtime flags/configuration.
    pub runtime_flags: BTreeMap<String, String>,
    /// Content hash of the full fingerprint.
    pub fingerprint_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// MethodologyDocument
// ---------------------------------------------------------------------------

/// Tracks presence and completeness of methodology documentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethodologyAudit {
    /// Benchmark selection rationale documented.
    pub selection_rationale: bool,
    /// Warm-up policy documented.
    pub warmup_policy: bool,
    /// GC/JIT settling strategy documented.
    pub gc_jit_settling: bool,
    /// Statistical treatment (confidence intervals, tests) documented.
    pub statistical_treatment: bool,
    /// Known limitations and caveats documented.
    pub known_limitations: bool,
    /// Peer review completed.
    pub peer_reviewed: bool,
    /// Reviewer identifiers (if reviewed).
    pub reviewer_ids: Vec<String>,
}

impl MethodologyAudit {
    /// Check if all required methodology sections are present.
    pub fn is_complete(&self) -> bool {
        self.selection_rationale
            && self.warmup_policy
            && self.gc_jit_settling
            && self.statistical_treatment
            && self.known_limitations
    }

    /// List missing methodology sections.
    pub fn missing_sections(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.selection_rationale {
            missing.push("selection_rationale");
        }
        if !self.warmup_policy {
            missing.push("warmup_policy");
        }
        if !self.gc_jit_settling {
            missing.push("gc_jit_settling");
        }
        if !self.statistical_treatment {
            missing.push("statistical_treatment");
        }
        if !self.known_limitations {
            missing.push("known_limitations");
        }
        missing
    }
}

// ---------------------------------------------------------------------------
// ArtifactBundle — tracks what artifacts are present
// ---------------------------------------------------------------------------

/// Tracks presence of required artifacts in the benchmark bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactBundleAudit {
    /// Raw timing data present.
    pub raw_timing_data: bool,
    /// Environment fingerprint present.
    pub environment_fingerprint: bool,
    /// Run manifest with reproducibility lock present.
    pub run_manifest: bool,
    /// One-command replay script present.
    pub replay_script: bool,
    /// Pinned dependency manifests present.
    pub dependency_manifests: bool,
    /// Content hash of the full bundle.
    pub bundle_hash: ContentHash,
}

impl ArtifactBundleAudit {
    /// Check if all required artifacts are present.
    pub fn is_complete(&self) -> bool {
        self.raw_timing_data
            && self.environment_fingerprint
            && self.run_manifest
            && self.replay_script
            && self.dependency_manifests
    }

    /// List missing artifacts.
    pub fn missing_artifacts(&self) -> Vec<&'static str> {
        let mut missing = Vec::new();
        if !self.raw_timing_data {
            missing.push("raw_timing_data");
        }
        if !self.environment_fingerprint {
            missing.push("environment_fingerprint");
        }
        if !self.run_manifest {
            missing.push("run_manifest");
        }
        if !self.replay_script {
            missing.push("replay_script");
        }
        if !self.dependency_manifests {
            missing.push("dependency_manifests");
        }
        missing
    }
}

// ---------------------------------------------------------------------------
// GateOutcome
// ---------------------------------------------------------------------------

/// Outcome of the comparison gate evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum GateOutcome {
    Pass,
    Fail,
}

impl GateOutcome {
    pub fn is_pass(self) -> bool {
        self == Self::Pass
    }
}

impl fmt::Display for GateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => f.write_str("PASS"),
            Self::Fail => f.write_str("FAIL"),
        }
    }
}

// ---------------------------------------------------------------------------
// GateBlocker
// ---------------------------------------------------------------------------

/// Specific reason why the gate failed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum GateBlocker {
    /// Missing benchmark category from the corpus.
    MissingCategory { category: String },
    /// Benchmark CV exceeds tolerance.
    ExcessiveVariance {
        benchmark_id: String,
        runtime: RuntimeId,
        cv_millionths: u64,
        max_cv_millionths: u64,
    },
    /// Insufficient runs for a benchmark.
    InsufficientRuns {
        benchmark_id: String,
        runtime: RuntimeId,
        run_count: u64,
        required: u64,
    },
    /// Missing methodology section.
    IncompleteMethodology { missing_sections: Vec<String> },
    /// Missing artifact in the bundle.
    IncompleteArtifactBundle { missing_artifacts: Vec<String> },
    /// Reproducibility replay failed — results outside tolerance.
    ReproducibilityFailed {
        benchmark_id: String,
        original_ns: u64,
        replay_ns: u64,
        deviation_millionths: u64,
    },
    /// Missing runtime from comparison set.
    MissingRuntime { runtime: RuntimeId },
    /// No benchmarks provided.
    NoBenchmarks,
    /// Benchmark-sniffing detected: harness config differs from ship config.
    BenchmarkSniffingDetected { detail: String },
}

impl fmt::Display for GateBlocker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCategory { category } => {
                write!(f, "missing benchmark category: {category}")
            }
            Self::ExcessiveVariance {
                benchmark_id,
                runtime,
                cv_millionths,
                max_cv_millionths,
            } => write!(
                f,
                "excessive variance: {benchmark_id} on {runtime} (CV {cv_millionths} > {max_cv_millionths})"
            ),
            Self::InsufficientRuns {
                benchmark_id,
                runtime,
                run_count,
                required,
            } => write!(
                f,
                "insufficient runs: {benchmark_id} on {runtime} ({run_count}/{required})"
            ),
            Self::IncompleteMethodology { missing_sections } => {
                write!(f, "incomplete methodology: missing {:?}", missing_sections)
            }
            Self::IncompleteArtifactBundle { missing_artifacts } => {
                write!(
                    f,
                    "incomplete artifact bundle: missing {:?}",
                    missing_artifacts
                )
            }
            Self::ReproducibilityFailed {
                benchmark_id,
                deviation_millionths,
                ..
            } => write!(
                f,
                "reproducibility failed: {benchmark_id} (deviation {deviation_millionths})"
            ),
            Self::MissingRuntime { runtime } => {
                write!(f, "missing runtime: {runtime}")
            }
            Self::NoBenchmarks => f.write_str("no benchmarks provided"),
            Self::BenchmarkSniffingDetected { detail } => {
                write!(f, "benchmark sniffing detected: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// PerformanceSummary
// ---------------------------------------------------------------------------

/// Per-category performance summary across runtimes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategorySummary {
    pub category: BenchmarkCategory,
    pub benchmark_count: u64,
    /// Mean wall-time delta: FrankenEngine vs Node.js (millionths).
    /// Positive = FrankenEngine is faster.
    pub vs_node_delta_millionths: i64,
    /// Mean wall-time delta: FrankenEngine vs Bun (millionths).
    pub vs_bun_delta_millionths: i64,
    /// Mean memory delta vs Node.js (millionths). Positive = less memory.
    pub vs_node_memory_delta_millionths: i64,
    /// Mean memory delta vs Bun (millionths).
    pub vs_bun_memory_delta_millionths: i64,
}

/// Overall performance summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PerformanceSummary {
    pub category_summaries: Vec<CategorySummary>,
    pub total_benchmarks: u64,
    /// Overall wall-time delta vs Node.js (millionths).
    pub overall_vs_node_delta_millionths: i64,
    /// Overall wall-time delta vs Bun (millionths).
    pub overall_vs_bun_delta_millionths: i64,
}

// ---------------------------------------------------------------------------
// ReproducibilityResult
// ---------------------------------------------------------------------------

/// Result of a reproducibility audit for one benchmark.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ReproducibilityResult {
    pub benchmark_id: String,
    pub runtime: RuntimeId,
    pub original_ns: u64,
    pub replay_ns: u64,
    /// Absolute deviation in millionths.
    pub deviation_millionths: u64,
    /// Whether within tolerance.
    pub within_tolerance: bool,
}

// ---------------------------------------------------------------------------
// GateEvidenceBundle
// ---------------------------------------------------------------------------

/// Complete evidence bundle from a gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvidenceBundle {
    pub schema_version: String,
    pub run_id: String,
    pub epoch: SecurityEpoch,
    pub outcome: GateOutcome,
    pub blockers: Vec<GateBlocker>,
    pub performance_summary: PerformanceSummary,
    pub methodology_audit: MethodologyAudit,
    pub artifact_audit: ArtifactBundleAudit,
    pub reproducibility_results: Vec<ReproducibilityResult>,
    pub environment: EnvironmentFingerprint,
    pub evidence_hash: ContentHash,
    pub total_benchmarks: u64,
}

// ---------------------------------------------------------------------------
// GateLogEntry
// ---------------------------------------------------------------------------

/// Structured log entry for gate events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateLogEntry {
    pub trace_id: String,
    pub component: String,
    pub benchmark_id: Option<String>,
    pub runtime: Option<RuntimeId>,
    pub variant: Option<String>,
    pub event: String,
    pub outcome: String,
    pub wall_time_ns: Option<u64>,
    pub memory_peak_bytes: Option<u64>,
    pub error_code: Option<String>,
}

// ---------------------------------------------------------------------------
// GateError
// ---------------------------------------------------------------------------

/// Errors during gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GateError {
    EmptyBenchmarks,
    InvalidFingerprint { detail: String },
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyBenchmarks => f.write_str("no benchmark results provided"),
            Self::InvalidFingerprint { detail } => {
                write!(f, "invalid environment fingerprint: {detail}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// GateInput
// ---------------------------------------------------------------------------

/// Input to the gate evaluation.
#[derive(Debug, Clone)]
pub struct GateInput<'a> {
    pub run_id: &'a str,
    pub trace_id: &'a str,
    pub epoch: SecurityEpoch,
    /// Benchmark results across all runtimes.
    pub results: &'a [BenchmarkResult],
    /// Methodology audit results.
    pub methodology: &'a MethodologyAudit,
    /// Artifact bundle audit results.
    pub artifacts: &'a ArtifactBundleAudit,
    /// Reproducibility replay results (if any).
    pub reproducibility: &'a [ReproducibilityResult],
    /// Environment fingerprint.
    pub environment: &'a EnvironmentFingerprint,
    /// Maximum CV in millionths.
    pub max_cv_millionths: u64,
    /// Minimum runs per benchmark.
    pub min_runs_per_benchmark: u64,
    /// Whether benchmark-sniffing check passed.
    pub benchmark_sniffing_check_passed: bool,
    /// Detail if benchmark-sniffing detected.
    pub benchmark_sniffing_detail: &'a str,
}

#[derive(Serialize)]
struct EvidenceHashInput<'a> {
    schema_version: &'a str,
    run_id: &'a str,
    epoch: SecurityEpoch,
    outcome: GateOutcome,
    blockers: &'a [GateBlocker],
    performance_summary: &'a PerformanceSummary,
    methodology_audit: &'a MethodologyAudit,
    artifact_audit: &'a ArtifactBundleAudit,
    reproducibility_results: &'a [ReproducibilityResult],
    environment: &'a EnvironmentFingerprint,
    total_benchmarks: u64,
}

// ---------------------------------------------------------------------------
// Core gate evaluation
// ---------------------------------------------------------------------------

/// Evaluate the runtime comparison gate.
pub fn evaluate_gate(input: &GateInput<'_>) -> Result<GateEvidenceBundle, GateError> {
    if input.results.is_empty() {
        return Err(GateError::EmptyBenchmarks);
    }

    let mut blockers = Vec::new();

    // Check benchmark-sniffing.
    if !input.benchmark_sniffing_check_passed {
        blockers.push(GateBlocker::BenchmarkSniffingDetected {
            detail: input.benchmark_sniffing_detail.to_string(),
        });
    }

    // Build index: (benchmark_id, runtime) -> result.
    let mut by_benchmark: BTreeMap<&str, BTreeMap<RuntimeId, &BenchmarkResult>> = BTreeMap::new();
    for r in input.results {
        by_benchmark
            .entry(r.benchmark_id.as_str())
            .or_default()
            .insert(r.runtime, r);
    }

    // Check all categories present.
    let mut categories_present: std::collections::BTreeSet<BenchmarkCategory> =
        std::collections::BTreeSet::new();
    for r in input.results {
        categories_present.insert(r.category);
    }
    for cat in REQUIRED_CATEGORIES {
        if !categories_present.contains(cat) {
            blockers.push(GateBlocker::MissingCategory {
                category: cat.as_str().to_string(),
            });
        }
    }

    // Check all runtimes present.
    let mut runtimes_present: std::collections::BTreeSet<RuntimeId> =
        std::collections::BTreeSet::new();
    for r in input.results {
        runtimes_present.insert(r.runtime);
    }
    for rt in RuntimeId::all() {
        if !runtimes_present.contains(rt) {
            blockers.push(GateBlocker::MissingRuntime { runtime: *rt });
        }
    }

    // Check per-benchmark per-runtime constraints.
    for r in input.results {
        if r.cv_millionths > input.max_cv_millionths {
            blockers.push(GateBlocker::ExcessiveVariance {
                benchmark_id: r.benchmark_id.clone(),
                runtime: r.runtime,
                cv_millionths: r.cv_millionths,
                max_cv_millionths: input.max_cv_millionths,
            });
        }
        if r.run_count < input.min_runs_per_benchmark {
            blockers.push(GateBlocker::InsufficientRuns {
                benchmark_id: r.benchmark_id.clone(),
                runtime: r.runtime,
                run_count: r.run_count,
                required: input.min_runs_per_benchmark,
            });
        }
    }

    // Check methodology completeness.
    if !input.methodology.is_complete() {
        blockers.push(GateBlocker::IncompleteMethodology {
            missing_sections: input
                .methodology
                .missing_sections()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        });
    }

    // Check artifact bundle completeness.
    if !input.artifacts.is_complete() {
        blockers.push(GateBlocker::IncompleteArtifactBundle {
            missing_artifacts: input
                .artifacts
                .missing_artifacts()
                .iter()
                .map(|s| s.to_string())
                .collect(),
        });
    }

    let mut reproducibility_results = input.reproducibility.to_vec();
    reproducibility_results.sort();

    // Check reproducibility results.
    for repro in &reproducibility_results {
        if !repro.within_tolerance {
            blockers.push(GateBlocker::ReproducibilityFailed {
                benchmark_id: repro.benchmark_id.clone(),
                original_ns: repro.original_ns,
                replay_ns: repro.replay_ns,
                deviation_millionths: repro.deviation_millionths,
            });
        }
    }

    blockers.sort();

    // Compute performance summaries.
    let category_summaries = compute_category_summaries(input.results);
    let total_benchmarks = by_benchmark.len() as u64;

    let (overall_vs_node, overall_vs_bun) = compute_overall_deltas(input.results);

    let performance_summary = PerformanceSummary {
        category_summaries,
        total_benchmarks,
        overall_vs_node_delta_millionths: overall_vs_node,
        overall_vs_bun_delta_millionths: overall_vs_bun,
    };

    let outcome = if blockers.is_empty() {
        GateOutcome::Pass
    } else {
        GateOutcome::Fail
    };

    let hash_input = serde_json::to_vec(&EvidenceHashInput {
        schema_version: GATE_SCHEMA_VERSION,
        run_id: input.run_id,
        epoch: input.epoch,
        outcome,
        blockers: &blockers,
        performance_summary: &performance_summary,
        methodology_audit: input.methodology,
        artifact_audit: input.artifacts,
        reproducibility_results: &reproducibility_results,
        environment: input.environment,
        total_benchmarks,
    })
    .unwrap();
    let evidence_hash = ContentHash::compute(&hash_input);

    Ok(GateEvidenceBundle {
        schema_version: GATE_SCHEMA_VERSION.to_string(),
        run_id: input.run_id.to_string(),
        epoch: input.epoch,
        outcome,
        blockers,
        performance_summary,
        methodology_audit: input.methodology.clone(),
        artifact_audit: input.artifacts.clone(),
        reproducibility_results,
        environment: input.environment.clone(),
        evidence_hash,
        total_benchmarks,
    })
}

/// Compute per-category performance summaries.
fn compute_category_summaries(results: &[BenchmarkResult]) -> Vec<CategorySummary> {
    let mut by_cat: BTreeMap<BenchmarkCategory, Vec<&BenchmarkResult>> = BTreeMap::new();
    for r in results {
        by_cat.entry(r.category).or_default().push(r);
    }

    let mut summaries = Vec::new();
    for (cat, cat_results) in &by_cat {
        // Group by benchmark_id.
        let mut by_bench: BTreeMap<&str, BTreeMap<RuntimeId, &BenchmarkResult>> = BTreeMap::new();
        for r in cat_results {
            by_bench
                .entry(r.benchmark_id.as_str())
                .or_default()
                .insert(r.runtime, r);
        }

        let mut node_deltas = Vec::new();
        let mut bun_deltas = Vec::new();
        let mut node_mem_deltas = Vec::new();
        let mut bun_mem_deltas = Vec::new();

        for runtimes in by_bench.values() {
            if let Some(franken) = runtimes.get(&RuntimeId::FrankenEngine) {
                if let Some(node) = runtimes.get(&RuntimeId::NodeLts) {
                    if node.wall_time_ns > 0 {
                        let delta = (node.wall_time_ns as i64 - franken.wall_time_ns as i64)
                            .saturating_mul(1_000_000)
                            / node.wall_time_ns as i64;
                        node_deltas.push(delta);
                    }
                    if node.memory_peak_bytes > 0 {
                        let delta = (node.memory_peak_bytes as i64
                            - franken.memory_peak_bytes as i64)
                            .saturating_mul(1_000_000)
                            / node.memory_peak_bytes as i64;
                        node_mem_deltas.push(delta);
                    }
                }
                if let Some(bun) = runtimes.get(&RuntimeId::BunStable) {
                    if bun.wall_time_ns > 0 {
                        let delta = (bun.wall_time_ns as i64 - franken.wall_time_ns as i64)
                            .saturating_mul(1_000_000)
                            / bun.wall_time_ns as i64;
                        bun_deltas.push(delta);
                    }
                    if bun.memory_peak_bytes > 0 {
                        let delta = (bun.memory_peak_bytes as i64
                            - franken.memory_peak_bytes as i64)
                            .saturating_mul(1_000_000)
                            / bun.memory_peak_bytes as i64;
                        bun_mem_deltas.push(delta);
                    }
                }
            }
        }

        let mean = |v: &[i64]| -> i64 {
            if v.is_empty() {
                0
            } else {
                v.iter().fold(0i64, |acc, x| acc.saturating_add(*x)) / v.len() as i64
            }
        };

        summaries.push(CategorySummary {
            category: *cat,
            benchmark_count: by_bench.len() as u64,
            vs_node_delta_millionths: mean(&node_deltas),
            vs_bun_delta_millionths: mean(&bun_deltas),
            vs_node_memory_delta_millionths: mean(&node_mem_deltas),
            vs_bun_memory_delta_millionths: mean(&bun_mem_deltas),
        });
    }

    summaries
}

/// Compute overall deltas across all categories.
fn compute_overall_deltas(results: &[BenchmarkResult]) -> (i64, i64) {
    let mut by_bench: BTreeMap<&str, BTreeMap<RuntimeId, &BenchmarkResult>> = BTreeMap::new();
    for r in results {
        by_bench
            .entry(r.benchmark_id.as_str())
            .or_default()
            .insert(r.runtime, r);
    }

    let mut node_deltas = Vec::new();
    let mut bun_deltas = Vec::new();

    for runtimes in by_bench.values() {
        if let Some(franken) = runtimes.get(&RuntimeId::FrankenEngine) {
            if let Some(node) = runtimes.get(&RuntimeId::NodeLts)
                && node.wall_time_ns > 0
            {
                let delta = (node.wall_time_ns as i64 - franken.wall_time_ns as i64)
                    .saturating_mul(1_000_000)
                    / node.wall_time_ns as i64;
                node_deltas.push(delta);
            }
            if let Some(bun) = runtimes.get(&RuntimeId::BunStable)
                && bun.wall_time_ns > 0
            {
                let delta = (bun.wall_time_ns as i64 - franken.wall_time_ns as i64)
                    .saturating_mul(1_000_000)
                    / bun.wall_time_ns as i64;
                bun_deltas.push(delta);
            }
        }
    }

    let mean = |v: &[i64]| -> i64 {
        if v.is_empty() {
            0
        } else {
            v.iter().fold(0i64, |acc, x| acc.saturating_add(*x)) / v.len() as i64
        }
    };

    (mean(&node_deltas), mean(&bun_deltas))
}

/// Check if a gate evidence bundle passes the release gate.
pub fn passes_release_gate(bundle: &GateEvidenceBundle) -> bool {
    bundle.outcome.is_pass()
}

/// Generate structured log entries for a gate evaluation.
pub fn generate_log_entries(trace_id: &str, bundle: &GateEvidenceBundle) -> Vec<GateLogEntry> {
    let mut entries = Vec::new();

    // Summary entry.
    entries.push(GateLogEntry {
        trace_id: trace_id.to_string(),
        component: GATE_COMPONENT.to_string(),
        benchmark_id: None,
        runtime: None,
        variant: None,
        event: "gate_evaluation_complete".to_string(),
        outcome: bundle.outcome.to_string(),
        wall_time_ns: None,
        memory_peak_bytes: None,
        error_code: if bundle.outcome.is_pass() {
            None
        } else {
            Some("GATE_FAILED".to_string())
        },
    });

    // Per-category entries.
    for cs in &bundle.performance_summary.category_summaries {
        entries.push(GateLogEntry {
            trace_id: trace_id.to_string(),
            component: GATE_COMPONENT.to_string(),
            benchmark_id: None,
            runtime: None,
            variant: Some(cs.category.as_str().to_string()),
            event: "category_summary".to_string(),
            outcome: format!(
                "vs_node={} vs_bun={}",
                cs.vs_node_delta_millionths, cs.vs_bun_delta_millionths
            ),
            wall_time_ns: None,
            memory_peak_bytes: None,
            error_code: None,
        });
    }

    entries
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_result(
        id: &str,
        cat: BenchmarkCategory,
        runtime: RuntimeId,
        wall_time_ns: u64,
        memory: u64,
    ) -> BenchmarkResult {
        BenchmarkResult {
            benchmark_id: id.to_string(),
            category: cat,
            runtime,
            wall_time_ns,
            memory_peak_bytes: memory,
            run_count: 30,
            cv_millionths: 20_000, // 2%
        }
    }

    fn passing_methodology() -> MethodologyAudit {
        MethodologyAudit {
            selection_rationale: true,
            warmup_policy: true,
            gc_jit_settling: true,
            statistical_treatment: true,
            known_limitations: true,
            peer_reviewed: true,
            reviewer_ids: vec!["reviewer-1".to_string()],
        }
    }

    fn passing_artifacts() -> ArtifactBundleAudit {
        ArtifactBundleAudit {
            raw_timing_data: true,
            environment_fingerprint: true,
            run_manifest: true,
            replay_script: true,
            dependency_manifests: true,
            bundle_hash: ContentHash::compute(b"test_bundle"),
        }
    }

    fn test_environment() -> EnvironmentFingerprint {
        let mut versions = BTreeMap::new();
        versions.insert("franken_engine".to_string(), "0.1.0".to_string());
        versions.insert("node".to_string(), "22.0.0".to_string());
        versions.insert("bun".to_string(), "1.2.0".to_string());
        EnvironmentFingerprint {
            cpu_model: "Test CPU".to_string(),
            cpu_cores: 8,
            ram_bytes: 16_000_000_000,
            os_version: "Linux 6.x".to_string(),
            kernel_version: "6.17.0".to_string(),
            runtime_versions: versions,
            runtime_flags: BTreeMap::new(),
            fingerprint_hash: ContentHash::compute(b"test_env"),
        }
    }

    fn passing_results() -> Vec<BenchmarkResult> {
        let mut results = Vec::new();
        let categories = BenchmarkCategory::all();
        for (i, cat) in categories.iter().enumerate() {
            let id = format!("bench_{}", cat.as_str());
            // FrankenEngine faster than both Node and Bun.
            results.push(make_result(
                &id,
                *cat,
                RuntimeId::FrankenEngine,
                800 + i as u64 * 10,
                4000,
            ));
            results.push(make_result(
                &id,
                *cat,
                RuntimeId::NodeLts,
                1000 + i as u64 * 10,
                5000,
            ));
            results.push(make_result(
                &id,
                *cat,
                RuntimeId::BunStable,
                900 + i as u64 * 10,
                4500,
            ));
        }
        results
    }

    fn make_passing_input<'a>(
        results: &'a [BenchmarkResult],
        methodology: &'a MethodologyAudit,
        artifacts: &'a ArtifactBundleAudit,
        reproducibility: &'a [ReproducibilityResult],
        environment: &'a EnvironmentFingerprint,
    ) -> GateInput<'a> {
        GateInput {
            run_id: "test-run-1",
            trace_id: "trace-001",
            epoch: SecurityEpoch::from_raw(1),
            results,
            methodology,
            artifacts,
            reproducibility,
            environment,
            max_cv_millionths: DEFAULT_MAX_CV_MILLIONTHS,
            min_runs_per_benchmark: DEFAULT_MIN_RUNS_PER_BENCHMARK,
            benchmark_sniffing_check_passed: true,
            benchmark_sniffing_detail: "",
        }
    }

    // -----------------------------------------------------------------------
    // RuntimeId
    // -----------------------------------------------------------------------

    #[test]
    fn runtime_id_as_str() {
        assert_eq!(RuntimeId::FrankenEngine.as_str(), "franken_engine");
        assert_eq!(RuntimeId::NodeLts.as_str(), "node_lts");
        assert_eq!(RuntimeId::BunStable.as_str(), "bun_stable");
    }

    #[test]
    fn runtime_id_all() {
        assert_eq!(RuntimeId::all().len(), 3);
    }

    #[test]
    fn runtime_id_display() {
        assert_eq!(format!("{}", RuntimeId::FrankenEngine), "franken_engine");
    }

    // -----------------------------------------------------------------------
    // BenchmarkCategory
    // -----------------------------------------------------------------------

    #[test]
    fn category_all() {
        assert_eq!(BenchmarkCategory::all().len(), 5);
    }

    #[test]
    fn category_as_str() {
        assert_eq!(BenchmarkCategory::Micro.as_str(), "micro");
        assert_eq!(BenchmarkCategory::Macro.as_str(), "macro");
        assert_eq!(BenchmarkCategory::Startup.as_str(), "startup");
        assert_eq!(BenchmarkCategory::Throughput.as_str(), "throughput");
        assert_eq!(BenchmarkCategory::Memory.as_str(), "memory");
    }

    // -----------------------------------------------------------------------
    // MethodologyAudit
    // -----------------------------------------------------------------------

    #[test]
    fn methodology_complete() {
        let m = passing_methodology();
        assert!(m.is_complete());
        assert!(m.missing_sections().is_empty());
    }

    #[test]
    fn methodology_incomplete() {
        let m = MethodologyAudit {
            selection_rationale: true,
            warmup_policy: false,
            gc_jit_settling: true,
            statistical_treatment: false,
            known_limitations: true,
            peer_reviewed: false,
            reviewer_ids: Vec::new(),
        };
        assert!(!m.is_complete());
        assert_eq!(m.missing_sections().len(), 2);
    }

    // -----------------------------------------------------------------------
    // ArtifactBundleAudit
    // -----------------------------------------------------------------------

    #[test]
    fn artifacts_complete() {
        let a = passing_artifacts();
        assert!(a.is_complete());
        assert!(a.missing_artifacts().is_empty());
    }

    #[test]
    fn artifacts_incomplete() {
        let mut a = passing_artifacts();
        a.replay_script = false;
        a.run_manifest = false;
        assert!(!a.is_complete());
        assert_eq!(a.missing_artifacts().len(), 2);
    }

    // -----------------------------------------------------------------------
    // GateOutcome
    // -----------------------------------------------------------------------

    #[test]
    fn outcome_pass() {
        assert!(GateOutcome::Pass.is_pass());
        assert!(!GateOutcome::Fail.is_pass());
    }

    #[test]
    fn outcome_display() {
        assert_eq!(format!("{}", GateOutcome::Pass), "PASS");
        assert_eq!(format!("{}", GateOutcome::Fail), "FAIL");
    }

    // -----------------------------------------------------------------------
    // evaluate_gate — passing
    // -----------------------------------------------------------------------

    #[test]
    fn gate_passes_all_criteria() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert!(bundle.outcome.is_pass());
        assert!(bundle.blockers.is_empty());
        assert_eq!(bundle.total_benchmarks, 5);
    }

    #[test]
    fn gate_evidence_hash_deterministic() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);

        let b1 = evaluate_gate(&input).unwrap();
        let b2 = evaluate_gate(&input).unwrap();
        assert_eq!(b1.evidence_hash, b2.evidence_hash);
    }

    #[test]
    fn gate_different_runs_different_hashes() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();

        let i1 = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let mut i2 = i1.clone();
        i2.run_id = "different-run";

        let b1 = evaluate_gate(&i1).unwrap();
        let b2 = evaluate_gate(&i2).unwrap();
        assert_ne!(b1.evidence_hash, b2.evidence_hash);
    }

    #[test]
    fn gate_hash_changes_when_blocker_details_change() {
        let mut results_low_runs = passing_results();
        results_low_runs[0].run_count = 5;
        let mut results_higher_runs = passing_results();
        results_higher_runs[0].run_count = 6;
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();

        let low_runs_input =
            make_passing_input(&results_low_runs, &methodology, &artifacts, &[], &env);
        let higher_runs_input =
            make_passing_input(&results_higher_runs, &methodology, &artifacts, &[], &env);

        let low_runs_bundle = evaluate_gate(&low_runs_input).unwrap();
        let higher_runs_bundle = evaluate_gate(&higher_runs_input).unwrap();

        assert_ne!(low_runs_bundle.blockers, higher_runs_bundle.blockers);
        assert_ne!(
            low_runs_bundle.evidence_hash,
            higher_runs_bundle.evidence_hash
        );
    }

    #[test]
    fn gate_hash_changes_when_reproducibility_results_change() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input_without_repro = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let repro = vec![ReproducibilityResult {
            benchmark_id: "bench_micro".to_string(),
            runtime: RuntimeId::FrankenEngine,
            original_ns: 1000,
            replay_ns: 1005,
            deviation_millionths: 5_000,
            within_tolerance: true,
        }];
        let input_with_repro = make_passing_input(&results, &methodology, &artifacts, &repro, &env);

        let bundle_without_repro = evaluate_gate(&input_without_repro).unwrap();
        let bundle_with_repro = evaluate_gate(&input_with_repro).unwrap();

        assert_ne!(
            bundle_without_repro.reproducibility_results,
            bundle_with_repro.reproducibility_results
        );
        assert_ne!(
            bundle_without_repro.evidence_hash,
            bundle_with_repro.evidence_hash
        );
    }

    #[test]
    fn gate_hash_stable_across_blocker_input_order() {
        let mut results = passing_results();
        for result in &mut results {
            result.run_count = 5;
        }
        let reversed_results = results.iter().cloned().rev().collect::<Vec<_>>();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();

        let forward_input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let reversed_input =
            make_passing_input(&reversed_results, &methodology, &artifacts, &[], &env);

        let forward_bundle = evaluate_gate(&forward_input).unwrap();
        let reversed_bundle = evaluate_gate(&reversed_input).unwrap();

        assert_eq!(forward_bundle.blockers, reversed_bundle.blockers);
        assert_eq!(forward_bundle.evidence_hash, reversed_bundle.evidence_hash);
    }

    #[test]
    fn gate_hash_stable_across_reproducibility_input_order() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let repro_forward = vec![
            ReproducibilityResult {
                benchmark_id: "bench_macro".to_string(),
                runtime: RuntimeId::BunStable,
                original_ns: 2000,
                replay_ns: 1998,
                deviation_millionths: 1_000,
                within_tolerance: true,
            },
            ReproducibilityResult {
                benchmark_id: "bench_micro".to_string(),
                runtime: RuntimeId::FrankenEngine,
                original_ns: 1000,
                replay_ns: 1005,
                deviation_millionths: 5_000,
                within_tolerance: true,
            },
        ];
        let repro_reversed = repro_forward.iter().cloned().rev().collect::<Vec<_>>();

        let forward_input =
            make_passing_input(&results, &methodology, &artifacts, &repro_forward, &env);
        let reversed_input =
            make_passing_input(&results, &methodology, &artifacts, &repro_reversed, &env);

        let forward_bundle = evaluate_gate(&forward_input).unwrap();
        let reversed_bundle = evaluate_gate(&reversed_input).unwrap();

        assert_eq!(
            forward_bundle.reproducibility_results,
            reversed_bundle.reproducibility_results
        );
        assert_eq!(forward_bundle.evidence_hash, reversed_bundle.evidence_hash);
    }

    // -----------------------------------------------------------------------
    // evaluate_gate — failures
    // -----------------------------------------------------------------------

    #[test]
    fn gate_fails_empty_benchmarks() {
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&[], &methodology, &artifacts, &[], &env);
        assert!(matches!(
            evaluate_gate(&input),
            Err(GateError::EmptyBenchmarks)
        ));
    }

    #[test]
    fn gate_fails_missing_category() {
        // Only provide 4 of 5 categories.
        let mut results = passing_results();
        results.retain(|r| r.category != BenchmarkCategory::Memory);
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert!(!bundle.outcome.is_pass());
        assert!(
            bundle
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::MissingCategory { .. }))
        );
    }

    #[test]
    fn gate_fails_missing_runtime() {
        // Remove all Bun results.
        let mut results = passing_results();
        results.retain(|r| r.runtime != RuntimeId::BunStable);
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert!(!bundle.outcome.is_pass());
        assert!(
            bundle
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::MissingRuntime { .. }))
        );
    }

    #[test]
    fn gate_fails_excessive_variance() {
        let mut results = passing_results();
        results[0].cv_millionths = 50_000; // 5% > 3% max
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert!(!bundle.outcome.is_pass());
        assert!(
            bundle
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::ExcessiveVariance { .. }))
        );
    }

    #[test]
    fn gate_fails_insufficient_runs() {
        let mut results = passing_results();
        results[0].run_count = 10; // < 30 min
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert!(!bundle.outcome.is_pass());
        assert!(
            bundle
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::InsufficientRuns { .. }))
        );
    }

    #[test]
    fn gate_fails_incomplete_methodology() {
        let results = passing_results();
        let mut methodology = passing_methodology();
        methodology.warmup_policy = false;
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert!(!bundle.outcome.is_pass());
        assert!(
            bundle
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::IncompleteMethodology { .. }))
        );
    }

    #[test]
    fn gate_fails_incomplete_artifacts() {
        let results = passing_results();
        let methodology = passing_methodology();
        let mut artifacts = passing_artifacts();
        artifacts.replay_script = false;
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert!(!bundle.outcome.is_pass());
        assert!(
            bundle
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::IncompleteArtifactBundle { .. }))
        );
    }

    #[test]
    fn gate_fails_reproducibility() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let repro = vec![ReproducibilityResult {
            benchmark_id: "bench_micro".to_string(),
            runtime: RuntimeId::FrankenEngine,
            original_ns: 1000,
            replay_ns: 1200,
            deviation_millionths: 200_000,
            within_tolerance: false,
        }];
        let input = make_passing_input(&results, &methodology, &artifacts, &repro, &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert!(!bundle.outcome.is_pass());
        assert!(
            bundle
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::ReproducibilityFailed { .. }))
        );
    }

    #[test]
    fn gate_fails_benchmark_sniffing() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let mut input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        input.benchmark_sniffing_check_passed = false;
        input.benchmark_sniffing_detail = "detected V8 flag in benchmark config";
        let bundle = evaluate_gate(&input).unwrap();

        assert!(!bundle.outcome.is_pass());
        assert!(
            bundle
                .blockers
                .iter()
                .any(|b| matches!(b, GateBlocker::BenchmarkSniffingDetected { .. }))
        );
    }

    // -----------------------------------------------------------------------
    // Performance summary
    // -----------------------------------------------------------------------

    #[test]
    fn performance_summary_all_categories() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert_eq!(bundle.performance_summary.category_summaries.len(), 5);
        assert_eq!(bundle.performance_summary.total_benchmarks, 5);
    }

    #[test]
    fn performance_summary_positive_deltas() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        // FrankenEngine is faster than both (800 vs 1000/900).
        assert!(bundle.performance_summary.overall_vs_node_delta_millionths > 0);
        assert!(bundle.performance_summary.overall_vs_bun_delta_millionths > 0);
    }

    #[test]
    fn performance_summary_negative_when_slower() {
        let mut results = passing_results();
        // Make FrankenEngine slower.
        for r in &mut results {
            if r.runtime == RuntimeId::FrankenEngine {
                r.wall_time_ns = 1500;
            }
        }
        let summaries = compute_category_summaries(&results);
        // All deltas should be negative since FrankenEngine is slower.
        for s in &summaries {
            assert!(s.vs_node_delta_millionths < 0);
            assert!(s.vs_bun_delta_millionths < 0);
        }
    }

    // -----------------------------------------------------------------------
    // passes_release_gate
    // -----------------------------------------------------------------------

    #[test]
    fn release_gate_pass() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();
        assert!(passes_release_gate(&bundle));
    }

    #[test]
    fn release_gate_fail() {
        let results = passing_results();
        let mut methodology = passing_methodology();
        methodology.warmup_policy = false;
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();
        assert!(!passes_release_gate(&bundle));
    }

    // -----------------------------------------------------------------------
    // generate_log_entries
    // -----------------------------------------------------------------------

    #[test]
    fn log_entries_include_summary() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();
        let entries = generate_log_entries("trace-1", &bundle);

        assert!(!entries.is_empty());
        assert_eq!(entries[0].event, "gate_evaluation_complete");
        assert_eq!(entries[0].outcome, "PASS");
    }

    #[test]
    fn log_entries_include_categories() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();
        let entries = generate_log_entries("trace-1", &bundle);

        let cat_entries: Vec<_> = entries
            .iter()
            .filter(|e| e.event == "category_summary")
            .collect();
        assert_eq!(cat_entries.len(), 5);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrips
    // -----------------------------------------------------------------------

    #[test]
    fn serde_runtime_id_roundtrip() {
        let val = RuntimeId::FrankenEngine;
        let json = serde_json::to_string(&val).unwrap();
        let back: RuntimeId = serde_json::from_str(&json).unwrap();
        assert_eq!(val, back);
    }

    #[test]
    fn serde_category_roundtrip() {
        let val = BenchmarkCategory::Throughput;
        let json = serde_json::to_string(&val).unwrap();
        let back: BenchmarkCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(val, back);
    }

    #[test]
    fn serde_evidence_bundle_roundtrip() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        let json = serde_json::to_string(&bundle).unwrap();
        let back: GateEvidenceBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, back);
    }

    #[test]
    fn serde_blocker_roundtrip() {
        let b = GateBlocker::ExcessiveVariance {
            benchmark_id: "b1".to_string(),
            runtime: RuntimeId::NodeLts,
            cv_millionths: 50_000,
            max_cv_millionths: 30_000,
        };
        let json = serde_json::to_string(&b).unwrap();
        let back: GateBlocker = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn serde_log_entry_roundtrip() {
        let entry = GateLogEntry {
            trace_id: "t1".to_string(),
            component: GATE_COMPONENT.to_string(),
            benchmark_id: Some("b1".to_string()),
            runtime: Some(RuntimeId::FrankenEngine),
            variant: None,
            event: "test".to_string(),
            outcome: "pass".to_string(),
            wall_time_ns: Some(1000),
            memory_peak_bytes: None,
            error_code: None,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let back: GateLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, back);
    }

    // -----------------------------------------------------------------------
    // GateBlocker Display
    // -----------------------------------------------------------------------

    #[test]
    fn blocker_display_missing_category() {
        let b = GateBlocker::MissingCategory {
            category: "memory".to_string(),
        };
        assert!(format!("{b}").contains("memory"));
    }

    #[test]
    fn blocker_display_excessive_variance() {
        let b = GateBlocker::ExcessiveVariance {
            benchmark_id: "b1".to_string(),
            runtime: RuntimeId::NodeLts,
            cv_millionths: 50_000,
            max_cv_millionths: 30_000,
        };
        let s = format!("{b}");
        assert!(s.contains("b1"));
        assert!(s.contains("50000"));
    }

    #[test]
    fn blocker_display_no_benchmarks() {
        assert_eq!(
            format!("{}", GateBlocker::NoBenchmarks),
            "no benchmarks provided"
        );
    }

    // -----------------------------------------------------------------------
    // GateError Display
    // -----------------------------------------------------------------------

    #[test]
    fn error_display_empty() {
        assert_eq!(
            format!("{}", GateError::EmptyBenchmarks),
            "no benchmark results provided"
        );
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn gate_with_extra_categories_passes() {
        let mut results = passing_results();
        // Add an extra benchmark in an existing category.
        results.push(make_result(
            "bench_extra",
            BenchmarkCategory::Micro,
            RuntimeId::FrankenEngine,
            700,
            3000,
        ));
        results.push(make_result(
            "bench_extra",
            BenchmarkCategory::Micro,
            RuntimeId::NodeLts,
            1000,
            5000,
        ));
        results.push(make_result(
            "bench_extra",
            BenchmarkCategory::Micro,
            RuntimeId::BunStable,
            900,
            4500,
        ));
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert!(bundle.outcome.is_pass());
        assert_eq!(bundle.total_benchmarks, 6); // 5 original + 1 extra
    }

    #[test]
    fn gate_multiple_blockers() {
        let mut results = passing_results();
        results.retain(|r| r.category != BenchmarkCategory::Memory);
        results[0].cv_millionths = 50_000;
        let mut methodology = passing_methodology();
        methodology.warmup_policy = false;
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert!(!bundle.outcome.is_pass());
        assert!(bundle.blockers.len() >= 3);
    }

    #[test]
    fn gate_schema_version() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();
        assert_eq!(bundle.schema_version, GATE_SCHEMA_VERSION);
    }

    #[test]
    fn reproducibility_pass_within_tolerance() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let repro = vec![ReproducibilityResult {
            benchmark_id: "bench_micro".to_string(),
            runtime: RuntimeId::FrankenEngine,
            original_ns: 1000,
            replay_ns: 1020,
            deviation_millionths: 20_000,
            within_tolerance: true,
        }];
        let input = make_passing_input(&results, &methodology, &artifacts, &repro, &env);
        let bundle = evaluate_gate(&input).unwrap();

        assert!(bundle.outcome.is_pass());
        assert_eq!(bundle.reproducibility_results.len(), 1);
    }

    // -- Enrichment: missing serde roundtrips, ordering, Display --

    #[test]
    fn benchmark_result_serde_roundtrip() {
        let r = BenchmarkResult {
            benchmark_id: "bench_micro".to_string(),
            category: BenchmarkCategory::Micro,
            runtime: RuntimeId::FrankenEngine,
            wall_time_ns: 5000,
            memory_peak_bytes: 1024,
            run_count: 30,
            cv_millionths: 15_000,
        };
        let json = serde_json::to_string(&r).unwrap();
        let restored: BenchmarkResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, restored);
    }

    #[test]
    fn environment_fingerprint_serde_roundtrip() {
        let fp = EnvironmentFingerprint {
            cpu_model: "AMD Ryzen 9".to_string(),
            cpu_cores: 16,
            ram_bytes: 64_000_000_000,
            os_version: "Ubuntu 24.04".to_string(),
            kernel_version: "6.8.0".to_string(),
            runtime_versions: BTreeMap::from([
                ("franken_engine".to_string(), "0.1.0".to_string()),
                ("node_lts".to_string(), "20.12.0".to_string()),
            ]),
            runtime_flags: BTreeMap::new(),
            fingerprint_hash: ContentHash::compute(b"fp-test"),
        };
        let json = serde_json::to_string(&fp).unwrap();
        let restored: EnvironmentFingerprint = serde_json::from_str(&json).unwrap();
        assert_eq!(fp, restored);
    }

    #[test]
    fn methodology_audit_serde_roundtrip() {
        let m = MethodologyAudit {
            selection_rationale: true,
            warmup_policy: true,
            gc_jit_settling: false,
            statistical_treatment: true,
            known_limitations: true,
            peer_reviewed: false,
            reviewer_ids: vec![],
        };
        let json = serde_json::to_string(&m).unwrap();
        let restored: MethodologyAudit = serde_json::from_str(&json).unwrap();
        assert_eq!(m, restored);
    }

    #[test]
    fn artifact_bundle_audit_serde_roundtrip() {
        let a = ArtifactBundleAudit {
            raw_timing_data: true,
            environment_fingerprint: true,
            run_manifest: true,
            replay_script: true,
            dependency_manifests: false,
            bundle_hash: ContentHash::compute(b"bundle-test"),
        };
        let json = serde_json::to_string(&a).unwrap();
        let restored: ArtifactBundleAudit = serde_json::from_str(&json).unwrap();
        assert_eq!(a, restored);
    }

    #[test]
    fn reproducibility_result_serde_roundtrip() {
        let r = ReproducibilityResult {
            benchmark_id: "bench_1".to_string(),
            runtime: RuntimeId::NodeLts,
            original_ns: 1000,
            replay_ns: 1050,
            deviation_millionths: 50_000,
            within_tolerance: true,
        };
        let json = serde_json::to_string(&r).unwrap();
        let restored: ReproducibilityResult = serde_json::from_str(&json).unwrap();
        assert_eq!(r, restored);
    }

    #[test]
    fn runtime_id_ordering() {
        assert!(RuntimeId::FrankenEngine < RuntimeId::NodeLts);
        assert!(RuntimeId::NodeLts < RuntimeId::BunStable);
    }

    #[test]
    fn benchmark_category_ordering() {
        assert!(BenchmarkCategory::Micro < BenchmarkCategory::Macro);
        assert!(BenchmarkCategory::Macro < BenchmarkCategory::Startup);
        assert!(BenchmarkCategory::Startup < BenchmarkCategory::Throughput);
        assert!(BenchmarkCategory::Throughput < BenchmarkCategory::Memory);
    }

    #[test]
    fn gate_outcome_ordering() {
        assert!(GateOutcome::Pass < GateOutcome::Fail);
    }

    #[test]
    fn gate_error_display_invalid_fingerprint() {
        let e = GateError::InvalidFingerprint {
            detail: "bad hash".to_string(),
        };
        assert!(e.to_string().contains("bad hash"));
    }

    #[test]
    fn gate_blocker_display_all_variants() {
        let blockers = [
            GateBlocker::MissingCategory {
                category: "micro".to_string(),
            },
            GateBlocker::ExcessiveVariance {
                benchmark_id: "b1".to_string(),
                runtime: RuntimeId::FrankenEngine,
                cv_millionths: 50_000,
                max_cv_millionths: 30_000,
            },
            GateBlocker::InsufficientRuns {
                benchmark_id: "b2".to_string(),
                runtime: RuntimeId::NodeLts,
                run_count: 5,
                required: 30,
            },
            GateBlocker::IncompleteMethodology {
                missing_sections: vec!["warmup_policy".to_string()],
            },
            GateBlocker::IncompleteArtifactBundle {
                missing_artifacts: vec!["replay_script".to_string()],
            },
            GateBlocker::ReproducibilityFailed {
                benchmark_id: "b3".to_string(),
                original_ns: 1000,
                replay_ns: 2000,
                deviation_millionths: 500_000,
            },
            GateBlocker::MissingRuntime {
                runtime: RuntimeId::BunStable,
            },
            GateBlocker::NoBenchmarks,
            GateBlocker::BenchmarkSniffingDetected {
                detail: "config mismatch".to_string(),
            },
        ];
        for b in &blockers {
            let s = format!("{b:?}");
            assert!(!s.is_empty());
        }
        assert_eq!(blockers.len(), 9);
    }

    // -----------------------------------------------------------------------
    // Enrichment: Display uniqueness, std::error, determinism, edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn gate_blocker_display_all_unique() {
        use std::collections::BTreeSet;
        let blockers = vec![
            GateBlocker::MissingCategory {
                category: "micro".to_string(),
            },
            GateBlocker::ExcessiveVariance {
                benchmark_id: "b1".to_string(),
                runtime: RuntimeId::FrankenEngine,
                cv_millionths: 50_000,
                max_cv_millionths: 30_000,
            },
            GateBlocker::InsufficientRuns {
                benchmark_id: "b2".to_string(),
                runtime: RuntimeId::NodeLts,
                run_count: 5,
                required: 30,
            },
            GateBlocker::IncompleteMethodology {
                missing_sections: vec!["warmup_policy".to_string()],
            },
            GateBlocker::IncompleteArtifactBundle {
                missing_artifacts: vec!["replay_script".to_string()],
            },
            GateBlocker::ReproducibilityFailed {
                benchmark_id: "b3".to_string(),
                original_ns: 1000,
                replay_ns: 2000,
                deviation_millionths: 500_000,
            },
            GateBlocker::MissingRuntime {
                runtime: RuntimeId::BunStable,
            },
            GateBlocker::NoBenchmarks,
            GateBlocker::BenchmarkSniffingDetected {
                detail: "config mismatch".to_string(),
            },
        ];
        let mut displays = BTreeSet::new();
        for b in &blockers {
            let msg = format!("{b}");
            assert!(!msg.is_empty());
            displays.insert(msg);
        }
        assert_eq!(
            displays.len(),
            blockers.len(),
            "all GateBlocker variants have unique Display"
        );
    }

    #[test]
    fn gate_error_display_is_nonempty() {
        let err = GateError::EmptyBenchmarks;
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn runtime_id_display_all_unique() {
        use std::collections::BTreeSet;
        let mut displays = BTreeSet::new();
        for id in [
            RuntimeId::FrankenEngine,
            RuntimeId::NodeLts,
            RuntimeId::BunStable,
        ] {
            displays.insert(format!("{id}"));
        }
        assert_eq!(
            displays.len(),
            3,
            "all RuntimeId variants have unique Display"
        );
    }

    #[test]
    fn benchmark_category_display_all_unique() {
        use std::collections::BTreeSet;
        let mut displays = BTreeSet::new();
        for cat in [
            BenchmarkCategory::Micro,
            BenchmarkCategory::Macro,
            BenchmarkCategory::Startup,
            BenchmarkCategory::Throughput,
            BenchmarkCategory::Memory,
        ] {
            displays.insert(format!("{cat}"));
        }
        assert_eq!(
            displays.len(),
            5,
            "all BenchmarkCategory variants have unique Display"
        );
    }

    #[test]
    fn gate_evidence_deterministic_json() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);

        let b1 = evaluate_gate(&input).unwrap();
        let b2 = evaluate_gate(&input).unwrap();
        let json1 = serde_json::to_string(&b1).unwrap();
        let json2 = serde_json::to_string(&b2).unwrap();
        assert_eq!(json1, json2, "identical inputs must produce identical JSON");
    }

    #[test]
    fn performance_summary_serde_roundtrip() {
        let results = passing_results();
        let methodology = passing_methodology();
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();

        let json = serde_json::to_string(&bundle.performance_summary).unwrap();
        let back: PerformanceSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle.performance_summary, back);
    }

    #[test]
    fn gate_error_serde_roundtrip_all_variants() {
        let errors = vec![
            GateError::EmptyBenchmarks,
            GateError::InvalidFingerprint {
                detail: "mismatch".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: GateError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    #[test]
    fn gate_outcome_display_all_unique() {
        use std::collections::BTreeSet;
        let mut displays = BTreeSet::new();
        displays.insert(GateOutcome::Pass.to_string());
        displays.insert(GateOutcome::Fail.to_string());
        assert_eq!(displays.len(), 2);
    }

    // -- Enrichment: PearlTower 2026-03-02 --

    #[test]
    fn gate_blocker_serde_all_9_variants() {
        let blockers = vec![
            GateBlocker::MissingCategory {
                category: "micro".to_string(),
            },
            GateBlocker::ExcessiveVariance {
                benchmark_id: "b1".to_string(),
                runtime: RuntimeId::FrankenEngine,
                cv_millionths: 50_000,
                max_cv_millionths: 30_000,
            },
            GateBlocker::InsufficientRuns {
                benchmark_id: "b2".to_string(),
                runtime: RuntimeId::NodeLts,
                run_count: 5,
                required: 30,
            },
            GateBlocker::IncompleteMethodology {
                missing_sections: vec!["warmup_policy".to_string()],
            },
            GateBlocker::IncompleteArtifactBundle {
                missing_artifacts: vec!["replay_script".to_string()],
            },
            GateBlocker::ReproducibilityFailed {
                benchmark_id: "b3".to_string(),
                original_ns: 1000,
                replay_ns: 2000,
                deviation_millionths: 500_000,
            },
            GateBlocker::MissingRuntime {
                runtime: RuntimeId::BunStable,
            },
            GateBlocker::NoBenchmarks,
            GateBlocker::BenchmarkSniffingDetected {
                detail: "config mismatch".to_string(),
            },
        ];
        for b in &blockers {
            let json = serde_json::to_string(b).unwrap();
            let back: GateBlocker = serde_json::from_str(&json).unwrap();
            assert_eq!(*b, back);
        }
    }

    #[test]
    fn methodology_all_missing_returns_five() {
        let m = MethodologyAudit {
            selection_rationale: false,
            warmup_policy: false,
            gc_jit_settling: false,
            statistical_treatment: false,
            known_limitations: false,
            peer_reviewed: false,
            reviewer_ids: Vec::new(),
        };
        assert!(!m.is_complete());
        assert_eq!(m.missing_sections().len(), 5);
    }

    #[test]
    fn artifacts_all_missing_returns_five() {
        let a = ArtifactBundleAudit {
            raw_timing_data: false,
            environment_fingerprint: false,
            run_manifest: false,
            replay_script: false,
            dependency_manifests: false,
            bundle_hash: ContentHash::compute(b"empty"),
        };
        assert!(!a.is_complete());
        assert_eq!(a.missing_artifacts().len(), 5);
    }

    #[test]
    fn log_entries_failed_gate_has_error_code() {
        let results = passing_results();
        let mut methodology = passing_methodology();
        methodology.warmup_policy = false;
        let artifacts = passing_artifacts();
        let env = test_environment();
        let input = make_passing_input(&results, &methodology, &artifacts, &[], &env);
        let bundle = evaluate_gate(&input).unwrap();
        assert!(!bundle.outcome.is_pass());

        let entries = generate_log_entries("trace-fail", &bundle);
        assert_eq!(entries[0].error_code.as_deref(), Some("GATE_FAILED"));
    }

    #[test]
    fn category_summary_serde_roundtrip() {
        let cs = CategorySummary {
            category: BenchmarkCategory::Micro,
            benchmark_count: 3,
            vs_node_delta_millionths: 200_000,
            vs_bun_delta_millionths: 100_000,
            vs_node_memory_delta_millionths: 50_000,
            vs_bun_memory_delta_millionths: -10_000,
        };
        let json = serde_json::to_string(&cs).unwrap();
        let back: CategorySummary = serde_json::from_str(&json).unwrap();
        assert_eq!(cs, back);
    }

    #[test]
    fn constants_sanity() {
        assert_eq!(DEFAULT_MAX_CV_MILLIONTHS, 30_000);
        assert_eq!(DEFAULT_MIN_RUNS_PER_BENCHMARK, 30);
        assert_eq!(REQUIRED_CATEGORIES.len(), 5);
        assert_eq!(GATE_COMPONENT, "runtime_comparison_gate");
    }

    #[test]
    fn category_display_all_match_as_str() {
        for cat in BenchmarkCategory::all() {
            assert_eq!(format!("{cat}"), cat.as_str());
        }
    }

    #[test]
    fn runtime_id_display_all_match_as_str() {
        for rt in RuntimeId::all() {
            assert_eq!(format!("{rt}"), rt.as_str());
        }
    }

    #[test]
    fn performance_summary_zero_deltas_with_equal_timing() {
        // FrankenEngine = Node = Bun => delta should be 0.
        let mut results = Vec::new();
        for cat in BenchmarkCategory::all() {
            let id = format!("bench_{}", cat.as_str());
            for rt in RuntimeId::all() {
                results.push(make_result(&id, *cat, *rt, 1000, 5000));
            }
        }
        let summaries = compute_category_summaries(&results);
        for s in &summaries {
            assert_eq!(s.vs_node_delta_millionths, 0);
            assert_eq!(s.vs_bun_delta_millionths, 0);
        }
    }
}
