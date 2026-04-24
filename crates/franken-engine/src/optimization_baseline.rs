//! Baseline + Profiling Infrastructure (FRX-06.1)
//!
//! Provides controlled benchmark environments, percentile-based instrumentation,
//! profiling pipeline integration, and opportunity-matrix scoring for
//! optimization selection.

use crate::engine_object_id::{EngineObjectId, ObjectDomain, SchemaId, derive_id};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn baseline_schema() -> SchemaId {
    SchemaId::from_definition(b"optimization_baseline-v1")
}

/// Fixed-point multiplier: 1_000_000 ≡ 1.0.
const MILLION: i64 = 1_000_000;

// ---------------------------------------------------------------------------
// Benchmark environment
// ---------------------------------------------------------------------------

/// Configuration for a controlled benchmark environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkEnvironment {
    pub env_id: String,
    /// Number of warm-up iterations before measurement.
    pub warmup_iterations: u32,
    /// Number of measurement iterations.
    pub measurement_iterations: u32,
    /// Maximum duration per iteration in microseconds.
    pub max_iteration_us: u64,
    /// Whether to pin to a single core.
    pub pin_to_core: bool,
    /// Whether to disable GC during measurement.
    pub disable_gc: bool,
    /// Tags for filtering/categorisation.
    pub tags: Vec<String>,
}

impl BenchmarkEnvironment {
    pub fn default_env(env_id: impl Into<String>) -> Self {
        Self {
            env_id: env_id.into(),
            warmup_iterations: 10,
            measurement_iterations: 100,
            max_iteration_us: 10_000_000, // 10s
            pin_to_core: false,
            disable_gc: false,
            tags: Vec::new(),
        }
    }

    /// Validate the environment configuration.
    pub fn validate(&self) -> Vec<String> {
        let mut errors = Vec::new();
        if self.env_id.is_empty() {
            errors.push("env_id must not be empty".to_string());
        }
        if self.measurement_iterations == 0 {
            errors.push("measurement_iterations must be > 0".to_string());
        }
        if self.max_iteration_us == 0 {
            errors.push("max_iteration_us must be > 0".to_string());
        }
        errors
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("env-{}", self.env_id);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "opt-baseline",
            &baseline_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

// ---------------------------------------------------------------------------
// Latency samples and percentile statistics
// ---------------------------------------------------------------------------

/// A single latency sample.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencySample {
    /// Latency in nanoseconds.
    pub latency_ns: u64,
    /// Iteration index.
    pub iteration: u32,
    /// Whether this was a warm-up iteration.
    pub is_warmup: bool,
}

/// Percentile statistics computed from latency samples.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PercentileStats {
    pub p50_ns: u64,
    pub p90_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub p999_ns: u64,
    pub min_ns: u64,
    pub max_ns: u64,
    pub mean_ns: u64,
    pub sample_count: u64,
}

impl PercentileStats {
    /// Compute percentile statistics from a set of latency samples.
    /// Only includes non-warmup samples.
    pub fn from_samples(samples: &[LatencySample]) -> Option<Self> {
        let mut values: Vec<u64> = samples
            .iter()
            .filter(|s| !s.is_warmup)
            .map(|s| s.latency_ns)
            .collect();

        if values.is_empty() {
            return None;
        }

        values.sort_unstable();
        let n = values.len();
        let sum: u64 = values.iter().fold(0u64, |acc, &x| acc.saturating_add(x));

        Some(Self {
            p50_ns: values[n * 50 / 100],
            p90_ns: values[(n * 90 / 100).min(n - 1)],
            p95_ns: values[(n * 95 / 100).min(n - 1)],
            p99_ns: values[(n * 99 / 100).min(n - 1)],
            p999_ns: values[(n * 999 / 1000).min(n - 1)],
            min_ns: values[0],
            max_ns: values[n - 1],
            mean_ns: sum / n as u64,
            sample_count: n as u64,
        })
    }

    /// Jitter: p99 - p50 in nanoseconds.
    pub fn jitter_ns(&self) -> u64 {
        self.p99_ns.saturating_sub(self.p50_ns)
    }

    /// Coefficient of variation in millionths (std_dev / mean).
    pub fn cv_millionths(&self) -> i64 {
        if self.mean_ns == 0 {
            return 0;
        }
        let jitter = self.jitter_ns() as i64;
        (jitter * MILLION) / self.mean_ns as i64
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!(
            "pstats-p50-{}-p99-{}-n-{}",
            self.p50_ns, self.p99_ns, self.sample_count
        );
        derive_id(
            ObjectDomain::EvidenceRecord,
            "opt-baseline",
            &baseline_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

// ---------------------------------------------------------------------------
// Throughput measurement
// ---------------------------------------------------------------------------

/// Throughput measurement for a benchmark.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputMeasurement {
    /// Operations per second (in millionths for precision).
    pub ops_per_sec_millionths: i64,
    /// Total operations completed.
    pub total_ops: u64,
    /// Duration in nanoseconds.
    pub duration_ns: u64,
    /// Bytes processed (if applicable).
    pub bytes_processed: Option<u64>,
}

impl ThroughputMeasurement {
    pub fn new(total_ops: u64, duration_ns: u64) -> Self {
        let ops_per_sec = if duration_ns == 0 {
            0
        } else {
            // ops_per_sec_millionths = ops * 1e6 * 1e9 / duration_ns
            // Use i128 to avoid overflow
            let wide = total_ops as i128 * 1_000_000_000i128 * MILLION as i128;
            (wide / duration_ns as i128) as i64
        };
        Self {
            ops_per_sec_millionths: ops_per_sec,
            total_ops,
            duration_ns,
            bytes_processed: None,
        }
    }

    pub fn with_bytes(mut self, bytes: u64) -> Self {
        self.bytes_processed = Some(bytes);
        self
    }

    /// Bytes per second in millionths (if bytes_processed set).
    pub fn bytes_per_sec_millionths(&self) -> Option<i64> {
        let bytes = self.bytes_processed?;
        if self.duration_ns == 0 {
            return Some(0);
        }
        let wide = bytes as i128 * 1_000_000_000i128 * MILLION as i128;
        Some((wide / self.duration_ns as i128) as i64)
    }
}

// ---------------------------------------------------------------------------
// Memory measurement
// ---------------------------------------------------------------------------

/// Memory usage snapshot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemorySnapshot {
    /// Heap allocated bytes.
    pub heap_bytes: u64,
    /// Stack usage bytes (estimated).
    pub stack_bytes: u64,
    /// Peak heap bytes.
    pub peak_heap_bytes: u64,
    /// Number of live allocations.
    pub live_allocations: u64,
    /// Total allocations during measurement.
    pub total_allocations: u64,
    /// Total deallocations during measurement.
    pub total_deallocations: u64,
}

impl MemorySnapshot {
    pub fn empty() -> Self {
        Self {
            heap_bytes: 0,
            stack_bytes: 0,
            peak_heap_bytes: 0,
            live_allocations: 0,
            total_allocations: 0,
            total_deallocations: 0,
        }
    }

    /// Net allocation churn (allocs - deallocs).
    pub fn allocation_churn(&self) -> i64 {
        self.total_allocations as i64 - self.total_deallocations as i64
    }

    /// Whether there's a potential memory leak (live > 0 after run).
    pub fn potential_leak(&self) -> bool {
        self.live_allocations > 0 && self.total_deallocations < self.total_allocations
    }
}

// ---------------------------------------------------------------------------
// Profiling pipeline
// ---------------------------------------------------------------------------

/// Profile data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ProfileKind {
    /// CPU flamegraph (sampled).
    CpuFlamegraph,
    /// Allocation flamegraph.
    AllocationFlamegraph,
    /// Syscall trace summary.
    SyscallTrace,
    /// Cache miss profile.
    CacheMissProfile,
    /// Branch misprediction profile.
    BranchMispredictionProfile,
}

impl ProfileKind {
    pub const ALL: [ProfileKind; 5] = [
        ProfileKind::CpuFlamegraph,
        ProfileKind::AllocationFlamegraph,
        ProfileKind::SyscallTrace,
        ProfileKind::CacheMissProfile,
        ProfileKind::BranchMispredictionProfile,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CpuFlamegraph => "cpu_flamegraph",
            Self::AllocationFlamegraph => "allocation_flamegraph",
            Self::SyscallTrace => "syscall_trace",
            Self::CacheMissProfile => "cache_miss_profile",
            Self::BranchMispredictionProfile => "branch_misprediction_profile",
        }
    }
}

/// A profiling artifact from a benchmark run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileArtifact {
    pub kind: ProfileKind,
    pub benchmark_id: String,
    /// Serialised profile data.
    pub data: Vec<u8>,
    /// Top hotspots extracted from the profile.
    pub hotspots: Vec<Hotspot>,
}

/// A hotspot identified in profiling data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hotspot {
    /// Function or symbol name.
    pub symbol: String,
    /// Percentage of total in millionths.
    pub percentage_millionths: i64,
    /// Sample count.
    pub samples: u64,
    /// Module or file path.
    pub module_path: String,
}

impl ProfileArtifact {
    pub fn new(kind: ProfileKind, benchmark_id: impl Into<String>) -> Self {
        Self {
            kind,
            benchmark_id: benchmark_id.into(),
            data: Vec::new(),
            hotspots: Vec::new(),
        }
    }

    pub fn with_hotspot(mut self, hotspot: Hotspot) -> Self {
        self.hotspots.push(hotspot);
        self
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("profile-{}-{}", self.kind.as_str(), self.benchmark_id);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "opt-baseline",
            &baseline_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

// ---------------------------------------------------------------------------
// Benchmark result
// ---------------------------------------------------------------------------

/// Complete result from a single benchmark run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub benchmark_id: String,
    pub environment: BenchmarkEnvironment,
    pub latency: Option<PercentileStats>,
    pub throughput: Option<ThroughputMeasurement>,
    pub memory: Option<MemorySnapshot>,
    pub profiles: Vec<ProfileArtifact>,
    pub metadata: BTreeMap<String, String>,
}

impl BenchmarkResult {
    pub fn new(benchmark_id: impl Into<String>, environment: BenchmarkEnvironment) -> Self {
        Self {
            benchmark_id: benchmark_id.into(),
            environment,
            latency: None,
            throughput: None,
            memory: None,
            profiles: Vec::new(),
            metadata: BTreeMap::new(),
        }
    }

    pub fn with_latency(mut self, stats: PercentileStats) -> Self {
        self.latency = Some(stats);
        self
    }

    pub fn with_throughput(mut self, throughput: ThroughputMeasurement) -> Self {
        self.throughput = Some(throughput);
        self
    }

    pub fn with_memory(mut self, memory: MemorySnapshot) -> Self {
        self.memory = Some(memory);
        self
    }

    pub fn add_profile(&mut self, profile: ProfileArtifact) {
        self.profiles.push(profile);
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("bench-result-{}", self.benchmark_id);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "opt-baseline",
            &baseline_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

// ---------------------------------------------------------------------------
// Baseline comparison
// ---------------------------------------------------------------------------

/// Direction of a metric comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ComparisonDirection {
    /// New is faster/better.
    Improvement,
    /// New is slower/worse.
    Regression,
    /// Within noise threshold.
    Neutral,
}

/// Comparison between baseline and candidate for a single metric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricComparison {
    pub metric_name: String,
    pub baseline_value: i64,
    pub candidate_value: i64,
    /// Change in millionths: (candidate - baseline) / baseline.
    pub change_millionths: i64,
    pub direction: ComparisonDirection,
}

/// Threshold for declaring a metric change significant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignificanceThreshold {
    /// Minimum change in millionths to be considered significant.
    pub min_change_millionths: i64,
    /// Minimum number of samples for statistical validity.
    pub min_samples: u64,
}

impl SignificanceThreshold {
    pub fn default_threshold() -> Self {
        Self {
            min_change_millionths: 50_000, // 5%
            min_samples: 30,
        }
    }
}

/// Compare two values and determine direction.
pub fn compare_metric(
    name: impl Into<String>,
    baseline: i64,
    candidate: i64,
    threshold: &SignificanceThreshold,
) -> MetricComparison {
    let change = if baseline == 0 {
        if candidate == 0 { 0 } else { MILLION }
    } else {
        ((candidate - baseline) * MILLION) / baseline
    };

    let direction = if change.abs() < threshold.min_change_millionths {
        ComparisonDirection::Neutral
    } else if change < 0 {
        ComparisonDirection::Improvement // lower is better for latency
    } else {
        ComparisonDirection::Regression
    };

    MetricComparison {
        metric_name: name.into(),
        baseline_value: baseline,
        candidate_value: candidate,
        change_millionths: change,
        direction,
    }
}

/// Full baseline comparison report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineComparison {
    pub baseline_id: String,
    pub candidate_id: String,
    pub comparisons: Vec<MetricComparison>,
    pub overall_direction: ComparisonDirection,
}

impl BaselineComparison {
    pub fn new(baseline_id: impl Into<String>, candidate_id: impl Into<String>) -> Self {
        Self {
            baseline_id: baseline_id.into(),
            candidate_id: candidate_id.into(),
            comparisons: Vec::new(),
            overall_direction: ComparisonDirection::Neutral,
        }
    }

    pub fn add_comparison(&mut self, comparison: MetricComparison) {
        self.comparisons.push(comparison);
        self.recompute_overall();
    }

    fn recompute_overall(&mut self) {
        let regressions = self
            .comparisons
            .iter()
            .filter(|c| c.direction == ComparisonDirection::Regression)
            .count();
        let improvements = self
            .comparisons
            .iter()
            .filter(|c| c.direction == ComparisonDirection::Improvement)
            .count();

        self.overall_direction = if regressions > improvements {
            ComparisonDirection::Regression
        } else if improvements > regressions {
            ComparisonDirection::Improvement
        } else {
            ComparisonDirection::Neutral
        };
    }

    /// Count of regressions detected.
    pub fn regression_count(&self) -> usize {
        self.comparisons
            .iter()
            .filter(|c| c.direction == ComparisonDirection::Regression)
            .count()
    }

    /// Count of improvements detected.
    pub fn improvement_count(&self) -> usize {
        self.comparisons
            .iter()
            .filter(|c| c.direction == ComparisonDirection::Improvement)
            .count()
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("comparison-{}-vs-{}", self.baseline_id, self.candidate_id);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "opt-baseline",
            &baseline_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

// ---------------------------------------------------------------------------
// Opportunity matrix
// ---------------------------------------------------------------------------

/// An optimisation opportunity identified from profiling data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OptimizationOpportunity {
    pub id: String,
    pub description: String,
    /// Which component this applies to.
    pub component: String,
    /// Estimated impact in millionths (0–MILLION scale).
    pub estimated_impact_millionths: i64,
    /// Implementation effort (1 = trivial, 5 = major).
    pub effort: u8,
    /// Risk level (1 = safe, 5 = dangerous).
    pub risk: u8,
    /// Profile evidence supporting this opportunity.
    pub evidence_profile_kinds: Vec<ProfileKind>,
    /// Current status.
    pub status: OpportunityStatus,
}

/// Status of an optimisation opportunity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum OpportunityStatus {
    /// Identified but not yet evaluated.
    Identified,
    /// Being actively evaluated.
    Evaluating,
    /// Approved for implementation.
    Approved,
    /// Implemented and verified.
    Implemented,
    /// Rejected (not worth pursuing).
    Rejected,
}

impl OpportunityStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Identified => "identified",
            Self::Evaluating => "evaluating",
            Self::Approved => "approved",
            Self::Implemented => "implemented",
            Self::Rejected => "rejected",
        }
    }
}

impl OptimizationOpportunity {
    /// Score: impact / (effort × risk). Higher is better.
    /// Returns score in millionths.
    pub fn score_millionths(&self) -> i64 {
        let denominator = (self.effort as i64).max(1) * (self.risk as i64).max(1);
        self.estimated_impact_millionths / denominator
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("opportunity-{}", self.id);
        derive_id(
            ObjectDomain::EvidenceRecord,
            "opt-baseline",
            &baseline_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

/// The opportunity matrix: a scored/prioritised list of optimization opportunities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpportunityMatrix {
    pub matrix_id: String,
    pub opportunities: Vec<OptimizationOpportunity>,
}

impl OpportunityMatrix {
    pub fn new(matrix_id: impl Into<String>) -> Self {
        Self {
            matrix_id: matrix_id.into(),
            opportunities: Vec::new(),
        }
    }

    pub fn add(&mut self, opportunity: OptimizationOpportunity) {
        self.opportunities.push(opportunity);
    }

    /// Return opportunities sorted by score (highest first).
    pub fn ranked(&self) -> Vec<&OptimizationOpportunity> {
        let mut ranked: Vec<_> = self.opportunities.iter().collect();
        ranked.sort_by_key(|o| std::cmp::Reverse(o.score_millionths()));
        ranked
    }

    /// Top N opportunities by score.
    pub fn top_n(&self, n: usize) -> Vec<&OptimizationOpportunity> {
        self.ranked().into_iter().take(n).collect()
    }

    /// Filter opportunities by status.
    pub fn by_status(&self, status: OpportunityStatus) -> Vec<&OptimizationOpportunity> {
        self.opportunities
            .iter()
            .filter(|o| o.status == status)
            .collect()
    }

    /// Total estimated impact of approved opportunities in millionths.
    pub fn approved_impact_millionths(&self) -> i64 {
        self.opportunities
            .iter()
            .filter(|o| o.status == OpportunityStatus::Approved)
            .map(|o| o.estimated_impact_millionths)
            .fold(0i64, |acc, x| acc.saturating_add(x))
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("matrix-{}-n-{}", self.matrix_id, self.opportunities.len());
        derive_id(
            ObjectDomain::EvidenceRecord,
            "opt-baseline",
            &baseline_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

// ---------------------------------------------------------------------------
// Baseline registry
// ---------------------------------------------------------------------------

/// Registry of baseline benchmark results for comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaselineRegistry {
    pub baselines: BTreeMap<String, BenchmarkResult>,
    pub comparison_threshold: SignificanceThreshold,
}

impl BaselineRegistry {
    pub fn new() -> Self {
        Self {
            baselines: BTreeMap::new(),
            comparison_threshold: SignificanceThreshold::default_threshold(),
        }
    }

    /// Register a baseline result.
    pub fn register(&mut self, result: BenchmarkResult) {
        self.baselines.insert(result.benchmark_id.clone(), result);
    }

    /// Get a baseline by ID.
    pub fn get(&self, benchmark_id: &str) -> Option<&BenchmarkResult> {
        self.baselines.get(benchmark_id)
    }

    /// Compare a candidate against a registered baseline.
    pub fn compare(
        &self,
        baseline_id: &str,
        candidate: &BenchmarkResult,
    ) -> Option<BaselineComparison> {
        let baseline = self.baselines.get(baseline_id)?;
        let mut comparison = BaselineComparison::new(baseline_id, &candidate.benchmark_id);

        // Compare latency p50
        if let (Some(bl), Some(cl)) = (&baseline.latency, &candidate.latency) {
            comparison.add_comparison(compare_metric(
                "latency_p50_ns",
                bl.p50_ns as i64,
                cl.p50_ns as i64,
                &self.comparison_threshold,
            ));
            comparison.add_comparison(compare_metric(
                "latency_p99_ns",
                bl.p99_ns as i64,
                cl.p99_ns as i64,
                &self.comparison_threshold,
            ));
        }

        // Compare throughput
        if let (Some(bt), Some(ct)) = (&baseline.throughput, &candidate.throughput) {
            // For throughput, higher is better — invert direction
            let mut thr_cmp = compare_metric(
                "throughput_ops_per_sec",
                bt.ops_per_sec_millionths,
                ct.ops_per_sec_millionths,
                &self.comparison_threshold,
            );
            // Flip: positive change = improvement for throughput
            thr_cmp.direction = match thr_cmp.direction {
                ComparisonDirection::Improvement => ComparisonDirection::Regression,
                ComparisonDirection::Regression => ComparisonDirection::Improvement,
                d => d,
            };
            comparison.add_comparison(thr_cmp);
        }

        // Compare memory
        if let (Some(bm), Some(cm)) = (&baseline.memory, &candidate.memory) {
            comparison.add_comparison(compare_metric(
                "heap_bytes",
                bm.heap_bytes as i64,
                cm.heap_bytes as i64,
                &self.comparison_threshold,
            ));
        }

        Some(comparison)
    }

    /// Number of registered baselines.
    pub fn count(&self) -> usize {
        self.baselines.len()
    }

    pub fn derive_id(&self) -> EngineObjectId {
        let canonical = format!("baseline-registry-n-{}", self.baselines.len());
        derive_id(
            ObjectDomain::EvidenceRecord,
            "opt-baseline",
            &baseline_schema(),
            canonical.as_bytes(),
        )
        .expect("serde deserialization should succeed")
    }
}

impl Default for BaselineRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- BenchmarkEnvironment --

    #[test]
    fn env_default_valid() {
        let env = BenchmarkEnvironment::default_env("test-bench");
        assert!(env.validate().is_empty());
    }

    #[test]
    fn env_empty_id_invalid() {
        let env = BenchmarkEnvironment::default_env("");
        let errors = env.validate();
        assert!(!errors.is_empty());
    }

    #[test]
    fn env_zero_iterations_invalid() {
        let mut env = BenchmarkEnvironment::default_env("test");
        env.measurement_iterations = 0;
        assert!(!env.validate().is_empty());
    }

    #[test]
    fn env_derive_id_stable() {
        let e1 = BenchmarkEnvironment::default_env("test");
        let e2 = BenchmarkEnvironment::default_env("test");
        assert_eq!(e1.derive_id(), e2.derive_id());
    }

    #[test]
    fn env_serde_roundtrip() {
        let env = BenchmarkEnvironment::default_env("test-bench");
        let json = serde_json::to_string(&env).expect("serde deserialization should succeed");
        let back: BenchmarkEnvironment =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(env, back);
    }

    // -- PercentileStats --

    #[test]
    fn pstats_empty_returns_none() {
        let stats = PercentileStats::from_samples(&[]);
        assert!(stats.is_none());
    }

    #[test]
    fn pstats_all_warmup_returns_none() {
        let samples = vec![LatencySample {
            latency_ns: 1000,
            iteration: 0,
            is_warmup: true,
        }];
        assert!(PercentileStats::from_samples(&samples).is_none());
    }

    #[test]
    fn pstats_single_sample() {
        let samples = vec![LatencySample {
            latency_ns: 5000,
            iteration: 0,
            is_warmup: false,
        }];
        let stats =
            PercentileStats::from_samples(&samples).expect("serde deserialization should succeed");
        assert_eq!(stats.p50_ns, 5000);
        assert_eq!(stats.min_ns, 5000);
        assert_eq!(stats.max_ns, 5000);
        assert_eq!(stats.sample_count, 1);
    }

    #[test]
    fn pstats_multiple_samples() {
        let samples: Vec<_> = (0..100)
            .map(|i| LatencySample {
                latency_ns: (i + 1) * 100,
                iteration: i as u32,
                is_warmup: false,
            })
            .collect();
        let stats =
            PercentileStats::from_samples(&samples).expect("serde deserialization should succeed");
        assert_eq!(stats.min_ns, 100);
        assert_eq!(stats.max_ns, 10000);
        assert_eq!(stats.sample_count, 100);
        assert!(stats.p50_ns <= stats.p90_ns);
        assert!(stats.p90_ns <= stats.p99_ns);
    }

    #[test]
    fn pstats_jitter() {
        let samples: Vec<_> = (0..100)
            .map(|i| LatencySample {
                latency_ns: (i + 1) * 100,
                iteration: i as u32,
                is_warmup: false,
            })
            .collect();
        let stats =
            PercentileStats::from_samples(&samples).expect("serde deserialization should succeed");
        assert!(stats.jitter_ns() > 0);
    }

    #[test]
    fn pstats_cv_millionths() {
        let samples: Vec<_> = (0..100)
            .map(|i| LatencySample {
                latency_ns: 1000 + i * 10,
                iteration: i as u32,
                is_warmup: false,
            })
            .collect();
        let stats =
            PercentileStats::from_samples(&samples).expect("serde deserialization should succeed");
        let cv = stats.cv_millionths();
        assert!(cv >= 0, "cv should be non-negative, got {cv}");
    }

    #[test]
    fn pstats_derive_id_stable() {
        let samples: Vec<_> = (0..10)
            .map(|i| LatencySample {
                latency_ns: 1000 + i * 100,
                iteration: i as u32,
                is_warmup: false,
            })
            .collect();
        let s1 =
            PercentileStats::from_samples(&samples).expect("serde deserialization should succeed");
        let s2 =
            PercentileStats::from_samples(&samples).expect("serde deserialization should succeed");
        assert_eq!(s1.derive_id(), s2.derive_id());
    }

    // -- ThroughputMeasurement --

    #[test]
    fn throughput_new() {
        let t = ThroughputMeasurement::new(1000, 1_000_000_000);
        assert!(t.ops_per_sec_millionths > 0);
        assert_eq!(t.total_ops, 1000);
    }

    #[test]
    fn throughput_zero_duration() {
        let t = ThroughputMeasurement::new(1000, 0);
        assert_eq!(t.ops_per_sec_millionths, 0);
    }

    #[test]
    fn throughput_with_bytes() {
        let t = ThroughputMeasurement::new(1000, 1_000_000_000).with_bytes(1_000_000);
        assert!(t.bytes_per_sec_millionths().is_some());
    }

    #[test]
    fn throughput_serde() {
        let t = ThroughputMeasurement::new(500, 2_000_000_000);
        let json = serde_json::to_string(&t).expect("serde deserialization should succeed");
        let back: ThroughputMeasurement =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(t, back);
    }

    // -- MemorySnapshot --

    #[test]
    fn memory_empty() {
        let m = MemorySnapshot::empty();
        assert_eq!(m.allocation_churn(), 0);
        assert!(!m.potential_leak());
    }

    #[test]
    fn memory_allocation_churn() {
        let m = MemorySnapshot {
            heap_bytes: 1024,
            stack_bytes: 512,
            peak_heap_bytes: 2048,
            live_allocations: 5,
            total_allocations: 100,
            total_deallocations: 95,
        };
        assert_eq!(m.allocation_churn(), 5);
        assert!(m.potential_leak());
    }

    #[test]
    fn memory_no_leak() {
        let m = MemorySnapshot {
            heap_bytes: 0,
            stack_bytes: 512,
            peak_heap_bytes: 2048,
            live_allocations: 0,
            total_allocations: 100,
            total_deallocations: 100,
        };
        assert!(!m.potential_leak());
    }

    // -- ProfileKind --

    #[test]
    fn profile_kind_as_str() {
        for k in &ProfileKind::ALL {
            assert!(!k.as_str().is_empty());
        }
    }

    #[test]
    fn profile_kind_serde() {
        for k in &ProfileKind::ALL {
            let json = serde_json::to_string(k).expect("serde deserialization should succeed");
            let back: ProfileKind =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(*k, back);
        }
    }

    // -- ProfileArtifact --

    #[test]
    fn profile_artifact_derive_id() {
        let p = ProfileArtifact::new(ProfileKind::CpuFlamegraph, "bench-1");
        let id1 = p.derive_id();
        let id2 = p.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn profile_artifact_with_hotspots() {
        let p = ProfileArtifact::new(ProfileKind::CpuFlamegraph, "bench-1").with_hotspot(Hotspot {
            symbol: "signal_graph::propagate".to_string(),
            percentage_millionths: 350_000,
            samples: 3500,
            module_path: "wasm_runtime_lane".to_string(),
        });
        assert_eq!(p.hotspots.len(), 1);
    }

    // -- BenchmarkResult --

    #[test]
    fn bench_result_derive_id() {
        let env = BenchmarkEnvironment::default_env("env-1");
        let r = BenchmarkResult::new("bench-1", env);
        let id1 = r.derive_id();
        let id2 = r.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn bench_result_serde() {
        let env = BenchmarkEnvironment::default_env("env-1");
        let r = BenchmarkResult::new("bench-1", env)
            .with_throughput(ThroughputMeasurement::new(1000, 1_000_000_000))
            .with_memory(MemorySnapshot::empty());
        let json = serde_json::to_string(&r).expect("serde deserialization should succeed");
        let back: BenchmarkResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(r, back);
    }

    // -- compare_metric --

    #[test]
    fn compare_metric_neutral() {
        let threshold = SignificanceThreshold::default_threshold();
        let cmp = compare_metric("test", 1000, 1010, &threshold);
        assert_eq!(cmp.direction, ComparisonDirection::Neutral);
    }

    #[test]
    fn compare_metric_improvement() {
        let threshold = SignificanceThreshold::default_threshold();
        let cmp = compare_metric("latency_ns", 1000, 800, &threshold);
        assert_eq!(cmp.direction, ComparisonDirection::Improvement);
    }

    #[test]
    fn compare_metric_regression() {
        let threshold = SignificanceThreshold::default_threshold();
        let cmp = compare_metric("latency_ns", 1000, 1200, &threshold);
        assert_eq!(cmp.direction, ComparisonDirection::Regression);
    }

    #[test]
    fn compare_metric_zero_baseline() {
        let threshold = SignificanceThreshold::default_threshold();
        let cmp = compare_metric("test", 0, 100, &threshold);
        assert_eq!(cmp.change_millionths, MILLION);
    }

    // -- BaselineComparison --

    #[test]
    fn baseline_comparison_new() {
        let bc = BaselineComparison::new("base", "candidate");
        assert_eq!(bc.regression_count(), 0);
        assert_eq!(bc.improvement_count(), 0);
    }

    #[test]
    fn baseline_comparison_overall() {
        let threshold = SignificanceThreshold::default_threshold();
        let mut bc = BaselineComparison::new("base", "candidate");
        bc.add_comparison(compare_metric("m1", 1000, 800, &threshold));
        bc.add_comparison(compare_metric("m2", 1000, 900, &threshold));
        assert_eq!(bc.overall_direction, ComparisonDirection::Improvement);
        assert_eq!(bc.improvement_count(), 2);
    }

    #[test]
    fn baseline_comparison_derive_id() {
        let bc = BaselineComparison::new("base", "cand");
        let id1 = bc.derive_id();
        let id2 = bc.derive_id();
        assert_eq!(id1, id2);
    }

    // -- OpportunityMatrix --

    #[test]
    fn opportunity_score() {
        let opp = OptimizationOpportunity {
            id: "opt-1".to_string(),
            description: "Inline hot function".to_string(),
            component: "signal_graph".to_string(),
            estimated_impact_millionths: 300_000,
            effort: 2,
            risk: 1,
            evidence_profile_kinds: vec![ProfileKind::CpuFlamegraph],
            status: OpportunityStatus::Identified,
        };
        assert_eq!(opp.score_millionths(), 150_000); // 300k / (2*1)
    }

    #[test]
    fn opportunity_derive_id() {
        let opp = OptimizationOpportunity {
            id: "opt-1".to_string(),
            description: "Test".to_string(),
            component: "test".to_string(),
            estimated_impact_millionths: 100_000,
            effort: 1,
            risk: 1,
            evidence_profile_kinds: vec![],
            status: OpportunityStatus::Identified,
        };
        let id1 = opp.derive_id();
        let id2 = opp.derive_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn matrix_ranked() {
        let mut matrix = OpportunityMatrix::new("m1");
        matrix.add(make_opportunity("low", 100_000, 3, 3));
        matrix.add(make_opportunity("high", 900_000, 1, 1));
        matrix.add(make_opportunity("mid", 500_000, 2, 1));
        let ranked = matrix.ranked();
        assert_eq!(ranked[0].id, "high");
        assert_eq!(ranked[1].id, "mid");
        assert_eq!(ranked[2].id, "low");
    }

    #[test]
    fn matrix_top_n() {
        let mut matrix = OpportunityMatrix::new("m1");
        matrix.add(make_opportunity("a", 100_000, 1, 1));
        matrix.add(make_opportunity("b", 200_000, 1, 1));
        matrix.add(make_opportunity("c", 300_000, 1, 1));
        let top = matrix.top_n(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].id, "c");
    }

    #[test]
    fn matrix_by_status() {
        let mut matrix = OpportunityMatrix::new("m1");
        let mut opp1 = make_opportunity("a", 100_000, 1, 1);
        opp1.status = OpportunityStatus::Approved;
        matrix.add(opp1);
        matrix.add(make_opportunity("b", 200_000, 1, 1));
        let approved = matrix.by_status(OpportunityStatus::Approved);
        assert_eq!(approved.len(), 1);
    }

    #[test]
    fn matrix_approved_impact() {
        let mut matrix = OpportunityMatrix::new("m1");
        let mut opp1 = make_opportunity("a", 300_000, 1, 1);
        opp1.status = OpportunityStatus::Approved;
        let mut opp2 = make_opportunity("b", 200_000, 1, 1);
        opp2.status = OpportunityStatus::Approved;
        matrix.add(opp1);
        matrix.add(opp2);
        matrix.add(make_opportunity("c", 500_000, 1, 1)); // not approved
        assert_eq!(matrix.approved_impact_millionths(), 500_000);
    }

    #[test]
    fn matrix_derive_id() {
        let m1 = OpportunityMatrix::new("m1");
        let m2 = OpportunityMatrix::new("m1");
        assert_eq!(m1.derive_id(), m2.derive_id());
    }

    #[test]
    fn matrix_serde() {
        let mut matrix = OpportunityMatrix::new("m1");
        matrix.add(make_opportunity("a", 100_000, 1, 1));
        let json = serde_json::to_string(&matrix).expect("serde deserialization should succeed");
        let back: OpportunityMatrix =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(matrix, back);
    }

    // -- BaselineRegistry --

    #[test]
    fn registry_new() {
        let reg = BaselineRegistry::new();
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn registry_register_and_get() {
        let mut reg = BaselineRegistry::new();
        let env = BenchmarkEnvironment::default_env("env-1");
        reg.register(BenchmarkResult::new("bench-1", env));
        assert_eq!(reg.count(), 1);
        assert!(reg.get("bench-1").is_some());
        assert!(reg.get("bench-2").is_none());
    }

    #[test]
    fn registry_compare_latency() {
        let mut reg = BaselineRegistry::new();
        let env = BenchmarkEnvironment::default_env("env-1");

        let samples_baseline: Vec<_> = (0..100)
            .map(|i| LatencySample {
                latency_ns: 1000 + i * 10,
                iteration: i as u32,
                is_warmup: false,
            })
            .collect();
        let baseline = BenchmarkResult::new("bench-1", env.clone()).with_latency(
            PercentileStats::from_samples(&samples_baseline)
                .expect("serde deserialization should succeed"),
        );
        reg.register(baseline);

        let samples_candidate: Vec<_> = (0..100)
            .map(|i| LatencySample {
                latency_ns: 800 + i * 8,
                iteration: i as u32,
                is_warmup: false,
            })
            .collect();
        let candidate = BenchmarkResult::new("bench-1-v2", env).with_latency(
            PercentileStats::from_samples(&samples_candidate)
                .expect("serde deserialization should succeed"),
        );

        let comparison = reg
            .compare("bench-1", &candidate)
            .expect("serde deserialization should succeed");
        assert!(comparison.improvement_count() > 0);
    }

    #[test]
    fn registry_compare_missing_baseline() {
        let reg = BaselineRegistry::new();
        let env = BenchmarkEnvironment::default_env("env-1");
        let candidate = BenchmarkResult::new("bench-1", env);
        assert!(reg.compare("nonexistent", &candidate).is_none());
    }

    #[test]
    fn registry_derive_id() {
        let r1 = BaselineRegistry::new();
        let r2 = BaselineRegistry::new();
        assert_eq!(r1.derive_id(), r2.derive_id());
    }

    #[test]
    fn registry_serde() {
        let mut reg = BaselineRegistry::new();
        let env = BenchmarkEnvironment::default_env("env-1");
        reg.register(BenchmarkResult::new("bench-1", env));
        let json = serde_json::to_string(&reg).expect("serde deserialization should succeed");
        let back: BaselineRegistry =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(reg, back);
    }

    // -- OpportunityStatus --

    #[test]
    fn opportunity_status_as_str() {
        let statuses = [
            OpportunityStatus::Identified,
            OpportunityStatus::Evaluating,
            OpportunityStatus::Approved,
            OpportunityStatus::Implemented,
            OpportunityStatus::Rejected,
        ];
        for s in &statuses {
            assert!(!s.as_str().is_empty());
        }
    }

    // -- E2E --

    #[test]
    fn e2e_full_pipeline() {
        // 1. Create environment
        let env = BenchmarkEnvironment::default_env("signal-graph-flush");

        // 2. Generate samples (simulating measurement)
        let samples: Vec<_> = (0..120)
            .map(|i| LatencySample {
                latency_ns: if i < 10 {
                    5000 + i * 200 // warmup
                } else {
                    2000 + (i % 20) * 50
                },
                iteration: i as u32,
                is_warmup: i < 10,
            })
            .collect();

        let stats =
            PercentileStats::from_samples(&samples).expect("serde deserialization should succeed");
        assert_eq!(stats.sample_count, 110); // 120 - 10 warmup

        // 3. Build benchmark result
        let mut result = BenchmarkResult::new("sg-flush-v1", env.clone())
            .with_latency(stats)
            .with_throughput(ThroughputMeasurement::new(10_000, 2_000_000_000))
            .with_memory(MemorySnapshot {
                heap_bytes: 1024 * 1024,
                stack_bytes: 64 * 1024,
                peak_heap_bytes: 2 * 1024 * 1024,
                live_allocations: 0,
                total_allocations: 50_000,
                total_deallocations: 50_000,
            });

        // 4. Add profile
        result.add_profile(
            ProfileArtifact::new(ProfileKind::CpuFlamegraph, "sg-flush-v1").with_hotspot(Hotspot {
                symbol: "WasmSignalGraph::propagate_dirty".to_string(),
                percentage_millionths: 420_000,
                samples: 4200,
                module_path: "wasm_runtime_lane".to_string(),
            }),
        );

        // 5. Register as baseline
        let mut registry = BaselineRegistry::new();
        registry.register(result);

        // 6. Identify opportunities
        let mut matrix = OpportunityMatrix::new("sg-flush-optimizations");
        matrix.add(OptimizationOpportunity {
            id: "batch-dirty-propagation".to_string(),
            description: "Batch dirty propagation into single pass".to_string(),
            component: "wasm_signal_graph".to_string(),
            estimated_impact_millionths: 350_000,
            effort: 2,
            risk: 1,
            evidence_profile_kinds: vec![ProfileKind::CpuFlamegraph],
            status: OpportunityStatus::Approved,
        });
        matrix.add(OptimizationOpportunity {
            id: "arena-allocator".to_string(),
            description: "Use arena allocator for signal nodes".to_string(),
            component: "wasm_signal_graph".to_string(),
            estimated_impact_millionths: 200_000,
            effort: 3,
            risk: 2,
            evidence_profile_kinds: vec![ProfileKind::AllocationFlamegraph],
            status: OpportunityStatus::Identified,
        });

        let ranked = matrix.ranked();
        assert_eq!(ranked[0].id, "batch-dirty-propagation"); // higher score
        assert_eq!(matrix.approved_impact_millionths(), 350_000);

        // 7. Simulate candidate run (improved)
        let candidate_samples: Vec<_> = (0..100)
            .map(|i| LatencySample {
                latency_ns: 1500 + (i % 20) * 30,
                iteration: i as u32,
                is_warmup: false,
            })
            .collect();
        let candidate = BenchmarkResult::new("sg-flush-v2", env)
            .with_latency(
                PercentileStats::from_samples(&candidate_samples)
                    .expect("serde deserialization should succeed"),
            )
            .with_throughput(ThroughputMeasurement::new(15_000, 2_000_000_000));

        let comparison = registry
            .compare("sg-flush-v1", &candidate)
            .expect("serde deserialization should succeed");
        // Latency should be improved
        assert!(comparison.improvement_count() > 0);
    }

    // -- Helpers --

    fn make_opportunity(id: &str, impact: i64, effort: u8, risk: u8) -> OptimizationOpportunity {
        OptimizationOpportunity {
            id: id.to_string(),
            description: format!("Opportunity {id}"),
            component: "test".to_string(),
            estimated_impact_millionths: impact,
            effort,
            risk,
            evidence_profile_kinds: vec![],
            status: OpportunityStatus::Identified,
        }
    }

    // -----------------------------------------------------------------------
    // Enrichment batch — PearlTower 2026-02-25
    // -----------------------------------------------------------------------

    #[test]
    fn comparison_direction_serde_roundtrip() {
        for d in [
            ComparisonDirection::Improvement,
            ComparisonDirection::Regression,
            ComparisonDirection::Neutral,
        ] {
            let json = serde_json::to_string(&d).expect("serde deserialization should succeed");
            let back: ComparisonDirection =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(d, back);
        }
    }

    #[test]
    fn opportunity_status_serde_roundtrip() {
        for s in [
            OpportunityStatus::Identified,
            OpportunityStatus::Evaluating,
            OpportunityStatus::Approved,
            OpportunityStatus::Implemented,
            OpportunityStatus::Rejected,
        ] {
            let json = serde_json::to_string(&s).expect("serde deserialization should succeed");
            let back: OpportunityStatus =
                serde_json::from_str(&json).expect("serde deserialization should succeed");
            assert_eq!(s, back);
        }
    }

    #[test]
    fn memory_snapshot_serde_roundtrip() {
        let snap = MemorySnapshot {
            heap_bytes: 1024,
            stack_bytes: 512,
            peak_heap_bytes: 2048,
            live_allocations: 10,
            total_allocations: 100,
            total_deallocations: 90,
        };
        let json = serde_json::to_string(&snap).expect("serde deserialization should succeed");
        let back: MemorySnapshot =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(snap, back);
    }

    #[test]
    fn hotspot_serde_roundtrip() {
        let hs = Hotspot {
            symbol: "my_func".to_string(),
            percentage_millionths: 250_000,
            samples: 500,
            module_path: "src/lib.rs".to_string(),
        };
        let json = serde_json::to_string(&hs).expect("serde deserialization should succeed");
        let back: Hotspot =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(hs, back);
    }

    #[test]
    fn significance_threshold_serde_roundtrip() {
        let t = SignificanceThreshold::default_threshold();
        let json = serde_json::to_string(&t).expect("serde deserialization should succeed");
        let back: SignificanceThreshold =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(t, back);
    }

    #[test]
    fn memory_snapshot_empty_has_no_leak() {
        let snap = MemorySnapshot::empty();
        assert!(!snap.potential_leak());
        assert_eq!(snap.allocation_churn(), 0);
    }

    #[test]
    fn memory_snapshot_potential_leak_detection() {
        let snap = MemorySnapshot {
            heap_bytes: 1024,
            stack_bytes: 0,
            peak_heap_bytes: 1024,
            live_allocations: 5,
            total_allocations: 100,
            total_deallocations: 95,
        };
        assert!(snap.potential_leak());
        assert_eq!(snap.allocation_churn(), 5);
    }

    #[test]
    fn profile_kind_as_str_all_distinct() {
        let mut displays = std::collections::BTreeSet::new();
        for kind in ProfileKind::ALL {
            displays.insert(kind.as_str());
        }
        assert_eq!(
            displays.len(),
            5,
            "all ProfileKind variants have distinct as_str values"
        );
    }

    // -----------------------------------------------------------------------
    // Enrichment batch 2 — PearlTower 2026-02-27
    // -----------------------------------------------------------------------

    // -- Copy semantics --

    #[test]
    fn profile_kind_copy_semantics() {
        let a = ProfileKind::CpuFlamegraph;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn comparison_direction_copy_semantics() {
        let a = ComparisonDirection::Improvement;
        let b = a;
        assert_eq!(a, b);
    }

    #[test]
    fn opportunity_status_copy_semantics() {
        let a = OpportunityStatus::Approved;
        let b = a;
        assert_eq!(a, b);
    }

    // -- Debug distinctness --

    #[test]
    fn profile_kind_debug_all_distinct() {
        let set: std::collections::BTreeSet<String> =
            ProfileKind::ALL.iter().map(|k| format!("{k:?}")).collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn comparison_direction_debug_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            ComparisonDirection::Improvement,
            ComparisonDirection::Regression,
            ComparisonDirection::Neutral,
        ]
        .iter()
        .map(|d| format!("{d:?}"))
        .collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn opportunity_status_debug_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            OpportunityStatus::Identified,
            OpportunityStatus::Evaluating,
            OpportunityStatus::Approved,
            OpportunityStatus::Implemented,
            OpportunityStatus::Rejected,
        ]
        .iter()
        .map(|s| format!("{s:?}"))
        .collect();
        assert_eq!(set.len(), 5);
    }

    // -- Serde variant distinctness --

    #[test]
    fn profile_kind_serde_all_distinct() {
        let set: std::collections::BTreeSet<String> = ProfileKind::ALL
            .iter()
            .map(|k| serde_json::to_string(k).expect("serde deserialization should succeed"))
            .collect();
        assert_eq!(set.len(), 5);
    }

    #[test]
    fn comparison_direction_serde_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            ComparisonDirection::Improvement,
            ComparisonDirection::Regression,
            ComparisonDirection::Neutral,
        ]
        .iter()
        .map(|d| serde_json::to_string(d).expect("serde deserialization should succeed"))
        .collect();
        assert_eq!(set.len(), 3);
    }

    #[test]
    fn opportunity_status_serde_all_distinct() {
        let set: std::collections::BTreeSet<String> = [
            OpportunityStatus::Identified,
            OpportunityStatus::Evaluating,
            OpportunityStatus::Approved,
            OpportunityStatus::Implemented,
            OpportunityStatus::Rejected,
        ]
        .iter()
        .map(|s| serde_json::to_string(s).expect("serde deserialization should succeed"))
        .collect();
        assert_eq!(set.len(), 5);
    }

    // -- Clone independence --

    #[test]
    fn benchmark_environment_clone_independence() {
        let env = BenchmarkEnvironment::default_env("test");
        let mut cloned = env.clone();
        cloned.warmup_iterations = 999;
        cloned.tags.push("new-tag".to_string());
        assert_eq!(env.warmup_iterations, 10);
        assert!(env.tags.is_empty());
    }

    #[test]
    fn percentile_stats_clone_independence() {
        let samples: Vec<_> = (0..10)
            .map(|i| LatencySample {
                latency_ns: 1000 + i * 100,
                iteration: i as u32,
                is_warmup: false,
            })
            .collect();
        let stats =
            PercentileStats::from_samples(&samples).expect("serde deserialization should succeed");
        let mut cloned = stats.clone();
        cloned.p50_ns = 999_999;
        assert_ne!(stats.p50_ns, 999_999);
        assert_eq!(cloned.p50_ns, 999_999);
    }

    #[test]
    fn memory_snapshot_clone_independence() {
        let snap = MemorySnapshot {
            heap_bytes: 1024,
            stack_bytes: 512,
            peak_heap_bytes: 2048,
            live_allocations: 5,
            total_allocations: 100,
            total_deallocations: 95,
        };
        let mut cloned = snap.clone();
        cloned.heap_bytes = 0;
        assert_eq!(snap.heap_bytes, 1024);
        assert_eq!(cloned.heap_bytes, 0);
    }

    #[test]
    fn baseline_comparison_clone_independence() {
        let threshold = SignificanceThreshold::default_threshold();
        let mut bc = BaselineComparison::new("base", "cand");
        bc.add_comparison(compare_metric("m1", 1000, 800, &threshold));
        let mut cloned = bc.clone();
        cloned.comparisons.clear();
        assert_eq!(bc.comparisons.len(), 1);
    }

    #[test]
    fn opportunity_matrix_clone_independence() {
        let mut matrix = OpportunityMatrix::new("m1");
        matrix.add(make_opportunity("a", 100_000, 1, 1));
        let mut cloned = matrix.clone();
        cloned.opportunities.clear();
        assert_eq!(matrix.opportunities.len(), 1);
    }

    // -- JSON field-name stability --

    #[test]
    fn benchmark_environment_json_field_names() {
        let env = BenchmarkEnvironment::default_env("test");
        let val: serde_json::Value =
            serde_json::to_value(&env).expect("serde deserialization should succeed");
        let obj = val
            .as_object()
            .expect("serde deserialization should succeed");
        for key in [
            "env_id",
            "warmup_iterations",
            "measurement_iterations",
            "max_iteration_us",
            "pin_to_core",
            "disable_gc",
            "tags",
        ] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 7);
    }

    #[test]
    fn latency_sample_json_field_names() {
        let sample = LatencySample {
            latency_ns: 1000,
            iteration: 0,
            is_warmup: false,
        };
        let val: serde_json::Value =
            serde_json::to_value(&sample).expect("serde deserialization should succeed");
        let obj = val
            .as_object()
            .expect("serde deserialization should succeed");
        for key in ["latency_ns", "iteration", "is_warmup"] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 3);
    }

    #[test]
    fn throughput_measurement_json_field_names() {
        let t = ThroughputMeasurement::new(100, 1_000_000);
        let val: serde_json::Value =
            serde_json::to_value(&t).expect("serde deserialization should succeed");
        let obj = val
            .as_object()
            .expect("serde deserialization should succeed");
        for key in [
            "ops_per_sec_millionths",
            "total_ops",
            "duration_ns",
            "bytes_processed",
        ] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 4);
    }

    #[test]
    fn memory_snapshot_json_field_names() {
        let m = MemorySnapshot::empty();
        let val: serde_json::Value =
            serde_json::to_value(&m).expect("serde deserialization should succeed");
        let obj = val
            .as_object()
            .expect("serde deserialization should succeed");
        for key in [
            "heap_bytes",
            "stack_bytes",
            "peak_heap_bytes",
            "live_allocations",
            "total_allocations",
            "total_deallocations",
        ] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 6);
    }

    #[test]
    fn hotspot_json_field_names() {
        let hs = Hotspot {
            symbol: "f".to_string(),
            percentage_millionths: 100_000,
            samples: 10,
            module_path: "m".to_string(),
        };
        let val: serde_json::Value =
            serde_json::to_value(&hs).expect("serde deserialization should succeed");
        let obj = val
            .as_object()
            .expect("serde deserialization should succeed");
        for key in ["symbol", "percentage_millionths", "samples", "module_path"] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 4);
    }

    #[test]
    fn metric_comparison_json_field_names() {
        let threshold = SignificanceThreshold::default_threshold();
        let cmp = compare_metric("test", 100, 200, &threshold);
        let val: serde_json::Value =
            serde_json::to_value(&cmp).expect("serde deserialization should succeed");
        let obj = val
            .as_object()
            .expect("serde deserialization should succeed");
        for key in [
            "metric_name",
            "baseline_value",
            "candidate_value",
            "change_millionths",
            "direction",
        ] {
            assert!(obj.contains_key(key), "missing field: {key}");
        }
        assert_eq!(obj.len(), 5);
    }

    // -- Hash consistency --

    #[test]
    fn profile_kind_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        ProfileKind::CpuFlamegraph.hash(&mut h1);
        ProfileKind::CpuFlamegraph.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn comparison_direction_hash_consistency() {
        use std::hash::{Hash, Hasher};
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        ComparisonDirection::Neutral.hash(&mut h1);
        ComparisonDirection::Neutral.hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    // -- Boundary/edge cases --

    #[test]
    fn throughput_zero_ops() {
        let t = ThroughputMeasurement::new(0, 1_000_000_000);
        assert_eq!(t.ops_per_sec_millionths, 0);
    }

    #[test]
    fn throughput_bytes_per_sec_none_when_unset() {
        let t = ThroughputMeasurement::new(100, 1_000_000);
        assert!(t.bytes_per_sec_millionths().is_none());
    }

    #[test]
    fn throughput_bytes_per_sec_zero_duration() {
        let t = ThroughputMeasurement::new(100, 0).with_bytes(1000);
        assert_eq!(t.bytes_per_sec_millionths(), Some(0));
    }

    #[test]
    fn memory_snapshot_max_values_serde_roundtrip() {
        let snap = MemorySnapshot {
            heap_bytes: u64::MAX,
            stack_bytes: u64::MAX,
            peak_heap_bytes: u64::MAX,
            live_allocations: u64::MAX,
            total_allocations: u64::MAX,
            total_deallocations: u64::MAX,
        };
        let json = serde_json::to_string(&snap).expect("serde deserialization should succeed");
        let back: MemorySnapshot =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(snap, back);
    }

    #[test]
    fn memory_snapshot_no_leak_when_allocs_equal_deallocs_but_live_nonzero() {
        let snap = MemorySnapshot {
            heap_bytes: 100,
            stack_bytes: 0,
            peak_heap_bytes: 100,
            live_allocations: 5,
            total_allocations: 50,
            total_deallocations: 50,
        };
        // live_allocations > 0 but total_deallocs == total_allocs → no leak
        assert!(!snap.potential_leak());
    }

    #[test]
    fn pstats_cv_millionths_zero_mean() {
        // All identical latencies → mean is nonzero, jitter is 0
        let samples: Vec<_> = (0..10)
            .map(|i| LatencySample {
                latency_ns: 5000,
                iteration: i as u32,
                is_warmup: false,
            })
            .collect();
        let stats =
            PercentileStats::from_samples(&samples).expect("serde deserialization should succeed");
        assert_eq!(stats.jitter_ns(), 0);
        assert_eq!(stats.cv_millionths(), 0);
    }

    #[test]
    fn pstats_filters_warmup_samples() {
        let samples = vec![
            LatencySample {
                latency_ns: 9999,
                iteration: 0,
                is_warmup: true,
            },
            LatencySample {
                latency_ns: 1000,
                iteration: 1,
                is_warmup: false,
            },
            LatencySample {
                latency_ns: 2000,
                iteration: 2,
                is_warmup: false,
            },
        ];
        let stats =
            PercentileStats::from_samples(&samples).expect("serde deserialization should succeed");
        assert_eq!(stats.sample_count, 2);
        assert_eq!(stats.min_ns, 1000);
        assert_eq!(stats.max_ns, 2000);
    }

    #[test]
    fn compare_metric_both_zero() {
        let threshold = SignificanceThreshold::default_threshold();
        let cmp = compare_metric("test", 0, 0, &threshold);
        assert_eq!(cmp.change_millionths, 0);
        assert_eq!(cmp.direction, ComparisonDirection::Neutral);
    }

    #[test]
    fn compare_metric_negative_improvement() {
        let threshold = SignificanceThreshold {
            min_change_millionths: 10_000, // 1%
            min_samples: 1,
        };
        let cmp = compare_metric("latency", 1000, 500, &threshold);
        assert_eq!(cmp.direction, ComparisonDirection::Improvement);
        assert!(cmp.change_millionths < 0);
    }

    #[test]
    fn env_zero_max_iteration_us_invalid() {
        let mut env = BenchmarkEnvironment::default_env("test");
        env.max_iteration_us = 0;
        let errors = env.validate();
        assert!(errors.iter().any(|e| e.contains("max_iteration_us")));
    }

    #[test]
    fn env_multiple_validation_errors() {
        let env = BenchmarkEnvironment {
            env_id: String::new(),
            warmup_iterations: 0,
            measurement_iterations: 0,
            max_iteration_us: 0,
            pin_to_core: false,
            disable_gc: false,
            tags: Vec::new(),
        };
        let errors = env.validate();
        assert!(
            errors.len() >= 2,
            "should have at least 2 errors, got {}",
            errors.len()
        );
    }

    #[test]
    fn opportunity_score_zero_effort_risk() {
        let opp = OptimizationOpportunity {
            id: "opt-z".to_string(),
            description: "Zero effort".to_string(),
            component: "test".to_string(),
            estimated_impact_millionths: 500_000,
            effort: 0,
            risk: 0,
            evidence_profile_kinds: vec![],
            status: OpportunityStatus::Identified,
        };
        // effort.max(1) * risk.max(1) = 1 * 1 = 1
        assert_eq!(opp.score_millionths(), 500_000);
    }

    #[test]
    fn baseline_comparison_equal_regressions_improvements_is_neutral() {
        let threshold = SignificanceThreshold::default_threshold();
        let mut bc = BaselineComparison::new("base", "cand");
        bc.add_comparison(compare_metric("m1", 1000, 800, &threshold)); // improvement
        bc.add_comparison(compare_metric("m2", 1000, 1300, &threshold)); // regression
        assert_eq!(bc.overall_direction, ComparisonDirection::Neutral);
    }

    // -- Serde roundtrips (complex) --

    #[test]
    fn profile_artifact_serde_roundtrip() {
        let p = ProfileArtifact::new(ProfileKind::AllocationFlamegraph, "bench-x").with_hotspot(
            Hotspot {
                symbol: "alloc_hot".to_string(),
                percentage_millionths: 600_000,
                samples: 6000,
                module_path: "alloc/mod.rs".to_string(),
            },
        );
        let json = serde_json::to_string(&p).expect("serde deserialization should succeed");
        let back: ProfileArtifact =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(p, back);
    }

    #[test]
    fn benchmark_result_full_serde_roundtrip() {
        let env = BenchmarkEnvironment::default_env("full-bench");
        let samples: Vec<_> = (0..50)
            .map(|i| LatencySample {
                latency_ns: 1000 + i * 20,
                iteration: i as u32,
                is_warmup: false,
            })
            .collect();
        let mut result = BenchmarkResult::new("full", env)
            .with_latency(
                PercentileStats::from_samples(&samples)
                    .expect("serde deserialization should succeed"),
            )
            .with_throughput(ThroughputMeasurement::new(5000, 1_000_000_000).with_bytes(500_000))
            .with_memory(MemorySnapshot {
                heap_bytes: 4096,
                stack_bytes: 1024,
                peak_heap_bytes: 8192,
                live_allocations: 2,
                total_allocations: 200,
                total_deallocations: 198,
            });
        result
            .metadata
            .insert("version".to_string(), "1.0".to_string());
        result.add_profile(ProfileArtifact::new(ProfileKind::SyscallTrace, "full"));

        let json = serde_json::to_string(&result).expect("serde deserialization should succeed");
        let back: BenchmarkResult =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(result, back);
    }

    #[test]
    fn baseline_comparison_serde_roundtrip() {
        let threshold = SignificanceThreshold::default_threshold();
        let mut bc = BaselineComparison::new("b1", "c1");
        bc.add_comparison(compare_metric("lat_p50", 1000, 900, &threshold));
        bc.add_comparison(compare_metric("lat_p99", 2000, 2500, &threshold));
        let json = serde_json::to_string(&bc).expect("serde deserialization should succeed");
        let back: BaselineComparison =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(bc, back);
    }

    #[test]
    fn metric_comparison_serde_roundtrip() {
        let threshold = SignificanceThreshold::default_threshold();
        let cmp = compare_metric("heap_bytes", 1_000_000, 900_000, &threshold);
        let json = serde_json::to_string(&cmp).expect("serde deserialization should succeed");
        let back: MetricComparison =
            serde_json::from_str(&json).expect("serde deserialization should succeed");
        assert_eq!(cmp, back);
    }

    // -- Debug nonempty --

    #[test]
    fn benchmark_environment_debug_nonempty() {
        let env = BenchmarkEnvironment::default_env("test");
        assert!(!format!("{env:?}").is_empty());
    }

    #[test]
    fn throughput_measurement_debug_nonempty() {
        let t = ThroughputMeasurement::new(100, 1_000);
        assert!(!format!("{t:?}").is_empty());
    }

    #[test]
    fn optimization_opportunity_debug_nonempty() {
        let opp = make_opportunity("dbg", 100_000, 1, 1);
        assert!(!format!("{opp:?}").is_empty());
    }

    // -- Derive ID stability across different types --

    #[test]
    fn env_derive_id_differs_for_different_ids() {
        let e1 = BenchmarkEnvironment::default_env("env-a");
        let e2 = BenchmarkEnvironment::default_env("env-b");
        assert_ne!(e1.derive_id(), e2.derive_id());
    }

    #[test]
    fn profile_artifact_derive_id_differs_for_different_kinds() {
        let p1 = ProfileArtifact::new(ProfileKind::CpuFlamegraph, "bench");
        let p2 = ProfileArtifact::new(ProfileKind::AllocationFlamegraph, "bench");
        assert_ne!(p1.derive_id(), p2.derive_id());
    }

    #[test]
    fn matrix_derive_id_changes_with_item_count() {
        let m1 = OpportunityMatrix::new("m");
        let mut m2 = OpportunityMatrix::new("m");
        m2.add(make_opportunity("x", 100_000, 1, 1));
        assert_ne!(m1.derive_id(), m2.derive_id());
    }

    // -- Registry compare with throughput inversion --

    #[test]
    fn registry_compare_throughput_inversion() {
        let mut reg = BaselineRegistry::new();
        let env = BenchmarkEnvironment::default_env("env-1");
        let baseline = BenchmarkResult::new("bench-1", env.clone())
            .with_throughput(ThroughputMeasurement::new(1000, 1_000_000_000));
        reg.register(baseline);

        // Candidate with higher throughput (improvement)
        let candidate = BenchmarkResult::new("bench-1-v2", env)
            .with_throughput(ThroughputMeasurement::new(2000, 1_000_000_000));
        let comparison = reg
            .compare("bench-1", &candidate)
            .expect("serde deserialization should succeed");
        // Higher throughput = improvement (direction inverted in compare())
        assert!(comparison.improvement_count() > 0);
    }

    // -- Top N edge cases --

    #[test]
    fn matrix_top_n_larger_than_size() {
        let mut matrix = OpportunityMatrix::new("m1");
        matrix.add(make_opportunity("only", 100_000, 1, 1));
        let top = matrix.top_n(10);
        assert_eq!(top.len(), 1);
    }

    #[test]
    fn matrix_top_n_zero() {
        let mut matrix = OpportunityMatrix::new("m1");
        matrix.add(make_opportunity("a", 100_000, 1, 1));
        let top = matrix.top_n(0);
        assert!(top.is_empty());
    }

    #[test]
    fn matrix_empty_ranked() {
        let matrix = OpportunityMatrix::new("empty");
        assert!(matrix.ranked().is_empty());
        assert_eq!(matrix.approved_impact_millionths(), 0);
    }

    #[test]
    fn registry_default_is_empty() {
        let reg = BaselineRegistry::default();
        assert_eq!(reg.count(), 0);
    }
}
