//! Publication-grade benchmark evidence bundles with provenance and parity verdicts.
//!
//! Implements [RGC-704C]: packages benchmark runs into reproducible evidence
//! bundles with environment capture, workload provenance, and parity verdicts
//! so external reviewers can reproduce claims without tribal knowledge.
//!
//! # Design
//!
//! - `BenchmarkRun` captures a single benchmark execution with environment and timing.
//! - `WorkloadProvenance` records the origin and integrity of the workload corpus.
//! - `ParityVerdict` records whether the benchmark exhibited parity with a baseline.
//! - `EvidenceBundle` aggregates runs, provenance, and parity into a publication unit.
//! - `BundleConfig` controls thresholds for bundle acceptance.
//! - `BundleVerdict` is the pass/fail/incomplete gate result.
//!
//! All timing values use microseconds (u64). All ratios use fixed-point
//! millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-704C]

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.benchmark-evidence-bundle.v1";

/// Component name.
pub const COMPONENT: &str = "benchmark_evidence_bundle";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.8.4.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-704C";

/// Minimum runs per workload before a bundle can pass.
pub const MIN_RUNS_PER_WORKLOAD: usize = 5;

/// Maximum acceptable coefficient-of-variation (millionths). 100_000 = 10%.
pub const MAX_CV_MILLIONTHS: u64 = 100_000;

/// Default minimum parity ratio for a workload to be considered equivalent (millionths).
/// 950_000 = 95%.
pub const DEFAULT_MIN_PARITY_RATIO: u64 = 950_000;

/// Maximum allowed environment drift entries before bundle is suspect.
pub const MAX_ENVIRONMENT_DRIFT: usize = 3;

// ---------------------------------------------------------------------------
// EnvironmentSnapshot
// ---------------------------------------------------------------------------

/// Captured environment state at benchmark time.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct EnvironmentSnapshot {
    /// OS identifier.
    pub os: String,
    /// CPU model string.
    pub cpu_model: String,
    /// Number of logical cores.
    pub logical_cores: u32,
    /// Total system memory in bytes.
    pub memory_bytes: u64,
    /// Runtime version (e.g., "node 22.1.0").
    pub runtime_version: String,
    /// Engine version.
    pub engine_version: String,
    /// Additional key-value metadata.
    pub extra: BTreeMap<String, String>,
    /// Hash of the snapshot for integrity checks.
    pub snapshot_hash: ContentHash,
}

impl EnvironmentSnapshot {
    /// Create a new snapshot and compute its hash.
    pub fn new(
        os: String,
        cpu_model: String,
        logical_cores: u32,
        memory_bytes: u64,
        runtime_version: String,
        engine_version: String,
        extra: BTreeMap<String, String>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(os.as_bytes());
        hasher.update(cpu_model.as_bytes());
        hasher.update(logical_cores.to_le_bytes());
        hasher.update(memory_bytes.to_le_bytes());
        hasher.update(runtime_version.as_bytes());
        hasher.update(engine_version.as_bytes());
        for (k, v) in &extra {
            hasher.update(k.as_bytes());
            hasher.update(v.as_bytes());
        }
        let snapshot_hash = ContentHash::compute(&hasher.finalize());
        Self {
            os,
            cpu_model,
            logical_cores,
            memory_bytes,
            runtime_version,
            engine_version,
            extra,
            snapshot_hash,
        }
    }

    /// Compute drift entries against another snapshot.
    pub fn drift_from(&self, other: &Self) -> Vec<String> {
        let mut drifts = Vec::new();
        if self.os != other.os {
            drifts.push(format!("os: {} vs {}", self.os, other.os));
        }
        if self.cpu_model != other.cpu_model {
            drifts.push(format!("cpu: {} vs {}", self.cpu_model, other.cpu_model));
        }
        if self.logical_cores != other.logical_cores {
            drifts.push(format!(
                "cores: {} vs {}",
                self.logical_cores, other.logical_cores
            ));
        }
        if self.memory_bytes != other.memory_bytes {
            drifts.push(format!(
                "memory: {} vs {}",
                self.memory_bytes, other.memory_bytes
            ));
        }
        if self.runtime_version != other.runtime_version {
            drifts.push(format!(
                "runtime: {} vs {}",
                self.runtime_version, other.runtime_version
            ));
        }
        if self.engine_version != other.engine_version {
            drifts.push(format!(
                "engine: {} vs {}",
                self.engine_version, other.engine_version
            ));
        }
        drifts
    }
}

// ---------------------------------------------------------------------------
// WorkloadCategory
// ---------------------------------------------------------------------------

/// Classification of a benchmark workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadCategory {
    /// Micro-benchmark (single function or loop).
    Micro,
    /// Application-level benchmark (realistic app pattern).
    Application,
    /// Framework-level benchmark (e.g., React rendering).
    Framework,
    /// Startup / cold-start measurement.
    ColdStart,
    /// Memory pressure and allocation benchmark.
    Memory,
    /// I/O or event-loop throughput benchmark.
    IoThroughput,
}

impl WorkloadCategory {
    pub const ALL: &[Self] = &[
        Self::Micro,
        Self::Application,
        Self::Framework,
        Self::ColdStart,
        Self::Memory,
        Self::IoThroughput,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Micro => "micro",
            Self::Application => "application",
            Self::Framework => "framework",
            Self::ColdStart => "cold_start",
            Self::Memory => "memory",
            Self::IoThroughput => "io_throughput",
        }
    }
}

impl fmt::Display for WorkloadCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// WorkloadProvenance
// ---------------------------------------------------------------------------

/// Records the origin and integrity of a benchmark workload.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkloadProvenance {
    /// Unique identifier for this workload.
    pub workload_id: String,
    /// Human-readable name.
    pub name: String,
    /// Category classification.
    pub category: WorkloadCategory,
    /// Source repository or corpus path.
    pub source: String,
    /// Git commit or corpus version pinning the workload.
    pub pinned_version: String,
    /// Content hash of the workload script/binary.
    pub content_hash: ContentHash,
    /// Epoch when provenance was established.
    pub provenance_epoch: SecurityEpoch,
    /// Tags for filtering.
    pub tags: BTreeSet<String>,
}

// ---------------------------------------------------------------------------
// BenchmarkRun
// ---------------------------------------------------------------------------

/// A single benchmark execution record.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BenchmarkRun {
    /// Run identifier.
    pub run_id: String,
    /// Which workload was run.
    pub workload_id: String,
    /// Execution time in microseconds.
    pub duration_us: u64,
    /// Memory peak in bytes (0 if not measured).
    pub peak_memory_bytes: u64,
    /// GC pause total in microseconds (0 if not measured).
    pub gc_pause_us: u64,
    /// Whether this run was a warmup (excluded from stats).
    pub is_warmup: bool,
    /// Iteration number within the workload.
    pub iteration: u32,
    /// Environment snapshot for this run.
    pub environment: EnvironmentSnapshot,
    /// Epoch when the run was performed.
    pub run_epoch: SecurityEpoch,
}

// ---------------------------------------------------------------------------
// ParityTarget
// ---------------------------------------------------------------------------

/// External runtime against which parity is checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityTarget {
    /// Node.js baseline.
    NodeJs,
    /// Bun baseline.
    Bun,
    /// Deno baseline.
    Deno,
    /// V8 isolate baseline.
    V8Isolate,
}

impl ParityTarget {
    pub const ALL: &[Self] = &[Self::NodeJs, Self::Bun, Self::Deno, Self::V8Isolate];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeJs => "node_js",
            Self::Bun => "bun",
            Self::Deno => "deno",
            Self::V8Isolate => "v8_isolate",
        }
    }
}

impl fmt::Display for ParityTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ParityVerdict
// ---------------------------------------------------------------------------

/// Result of comparing benchmark behavior against a baseline.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ParityVerdict {
    /// Workload being compared.
    pub workload_id: String,
    /// Comparison target.
    pub target: ParityTarget,
    /// Whether output was semantically equivalent.
    pub output_equivalent: bool,
    /// Performance ratio (millionths). 1_000_000 = same speed.
    /// > 1_000_000 means we're faster.
    pub performance_ratio_millionths: u64,
    /// Number of behavioral differences detected.
    pub behavioral_differences: usize,
    /// Description of differences (empty if equivalent).
    pub difference_details: Vec<String>,
    /// Evidence hash.
    pub evidence_hash: ContentHash,
}

impl ParityVerdict {
    /// Whether this verdict represents acceptable parity.
    pub fn is_acceptable(&self, min_parity_ratio: u64) -> bool {
        self.output_equivalent && self.performance_ratio_millionths >= min_parity_ratio
    }
}

// ---------------------------------------------------------------------------
// BundleStatus
// ---------------------------------------------------------------------------

/// Status of an evidence bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleStatus {
    /// Bundle is still being assembled.
    Assembling,
    /// Bundle is complete and sealed.
    Sealed,
    /// Bundle has been published.
    Published,
    /// Bundle was rejected during review.
    Rejected,
    /// Bundle was superseded by a newer one.
    Superseded,
}

impl BundleStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Assembling => "assembling",
            Self::Sealed => "sealed",
            Self::Published => "published",
            Self::Rejected => "rejected",
            Self::Superseded => "superseded",
        }
    }
}

impl fmt::Display for BundleStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// EvidenceBundle
// ---------------------------------------------------------------------------

/// A complete benchmark evidence bundle ready for publication.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    /// Bundle identifier.
    pub bundle_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Status.
    pub status: BundleStatus,
    /// Epoch when the bundle was created.
    pub created_epoch: SecurityEpoch,
    /// Workload provenance records.
    pub provenances: Vec<WorkloadProvenance>,
    /// Benchmark run records (non-warmup).
    pub runs: Vec<BenchmarkRun>,
    /// Parity verdicts.
    pub parity_verdicts: Vec<ParityVerdict>,
    /// Reference environment (first run's environment).
    pub reference_environment: Option<EnvironmentSnapshot>,
    /// Environment drift entries detected across runs.
    pub environment_drifts: Vec<String>,
    /// Bundle content hash.
    pub bundle_hash: ContentHash,
}

impl EvidenceBundle {
    /// Create a new empty bundle.
    pub fn new(bundle_id: String, epoch: SecurityEpoch) -> Self {
        Self {
            bundle_id,
            schema_version: SCHEMA_VERSION.to_string(),
            status: BundleStatus::Assembling,
            created_epoch: epoch,
            provenances: Vec::new(),
            runs: Vec::new(),
            parity_verdicts: Vec::new(),
            reference_environment: None,
            environment_drifts: Vec::new(),
            bundle_hash: ContentHash::compute(b"empty"),
        }
    }

    /// Add a workload provenance record.
    pub fn add_provenance(&mut self, prov: WorkloadProvenance) -> Result<(), BundleError> {
        if self.status != BundleStatus::Assembling {
            return Err(BundleError::BundleSealed {
                bundle_id: self.bundle_id.clone(),
            });
        }
        if self
            .provenances
            .iter()
            .any(|p| p.workload_id == prov.workload_id)
        {
            return Err(BundleError::DuplicateWorkload {
                workload_id: prov.workload_id,
            });
        }
        self.provenances.push(prov);
        self.recompute_hash();
        Ok(())
    }

    /// Add a benchmark run.
    pub fn add_run(&mut self, run: BenchmarkRun) -> Result<(), BundleError> {
        if self.status != BundleStatus::Assembling {
            return Err(BundleError::BundleSealed {
                bundle_id: self.bundle_id.clone(),
            });
        }
        // Check provenance exists for this workload.
        if !self
            .provenances
            .iter()
            .any(|p| p.workload_id == run.workload_id)
        {
            return Err(BundleError::MissingProvenance {
                workload_id: run.workload_id,
            });
        }
        // Track environment drift.
        if let Some(ref env) = self.reference_environment {
            let drifts = env.drift_from(&run.environment);
            for d in drifts {
                if !self.environment_drifts.contains(&d) {
                    self.environment_drifts.push(d);
                }
            }
        } else {
            self.reference_environment = Some(run.environment.clone());
        }
        self.runs.push(run);
        self.recompute_hash();
        Ok(())
    }

    /// Add a parity verdict.
    pub fn add_parity_verdict(&mut self, verdict: ParityVerdict) -> Result<(), BundleError> {
        if self.status != BundleStatus::Assembling {
            return Err(BundleError::BundleSealed {
                bundle_id: self.bundle_id.clone(),
            });
        }
        self.parity_verdicts.push(verdict);
        self.recompute_hash();
        Ok(())
    }

    /// Seal the bundle, preventing further modifications.
    pub fn seal(&mut self) -> Result<(), BundleError> {
        if self.status != BundleStatus::Assembling {
            return Err(BundleError::BundleSealed {
                bundle_id: self.bundle_id.clone(),
            });
        }
        self.status = BundleStatus::Sealed;
        self.recompute_hash();
        Ok(())
    }

    /// Mark as published.
    pub fn publish(&mut self) -> Result<(), BundleError> {
        if self.status != BundleStatus::Sealed {
            return Err(BundleError::InvalidTransition {
                from: self.status,
                to: BundleStatus::Published,
            });
        }
        self.status = BundleStatus::Published;
        Ok(())
    }

    /// Mark as rejected.
    pub fn reject(&mut self) -> Result<(), BundleError> {
        if self.status != BundleStatus::Sealed {
            return Err(BundleError::InvalidTransition {
                from: self.status,
                to: BundleStatus::Rejected,
            });
        }
        self.status = BundleStatus::Rejected;
        Ok(())
    }

    /// Non-warmup runs.
    pub fn effective_runs(&self) -> Vec<&BenchmarkRun> {
        self.runs.iter().filter(|r| !r.is_warmup).collect()
    }

    /// Effective runs for a specific workload.
    pub fn runs_for_workload(&self, workload_id: &str) -> Vec<&BenchmarkRun> {
        self.effective_runs()
            .into_iter()
            .filter(|r| r.workload_id == workload_id)
            .collect()
    }

    /// Workload IDs with provenance.
    pub fn workload_ids(&self) -> Vec<&str> {
        self.provenances
            .iter()
            .map(|p| p.workload_id.as_str())
            .collect()
    }

    /// Categories covered.
    pub fn categories(&self) -> BTreeSet<WorkloadCategory> {
        self.provenances.iter().map(|p| p.category).collect()
    }

    /// Compute per-workload timing statistics.
    pub fn workload_stats(&self, workload_id: &str) -> Option<TimingStats> {
        let runs = self.runs_for_workload(workload_id);
        if runs.is_empty() {
            return None;
        }
        let durations: Vec<u64> = runs.iter().map(|r| r.duration_us).collect();
        Some(TimingStats::from_durations(&durations))
    }

    /// Parity verdicts for a specific workload.
    pub fn parity_for_workload(&self, workload_id: &str) -> Vec<&ParityVerdict> {
        self.parity_verdicts
            .iter()
            .filter(|v| v.workload_id == workload_id)
            .collect()
    }

    /// Recompute the bundle content hash.
    fn recompute_hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(self.bundle_id.as_bytes());
        hasher.update(self.schema_version.as_bytes());
        hasher.update(self.created_epoch.as_u64().to_le_bytes());
        let mut prov_hashes: Vec<ContentHash> =
            self.provenances.iter().map(|p| p.content_hash).collect();
        prov_hashes.sort();
        for h in &prov_hashes {
            hasher.update(h.as_bytes());
        }
        let mut run_ids: Vec<&String> = self.runs.iter().map(|r| &r.run_id).collect();
        run_ids.sort();
        for id in &run_ids {
            hasher.update(id.as_bytes());
        }
        let mut verdict_hashes: Vec<ContentHash> = self
            .parity_verdicts
            .iter()
            .map(|v| v.evidence_hash)
            .collect();
        verdict_hashes.sort();
        for h in &verdict_hashes {
            hasher.update(h.as_bytes());
        }
        self.bundle_hash = ContentHash::compute(&hasher.finalize());
    }
}

// ---------------------------------------------------------------------------
// TimingStats
// ---------------------------------------------------------------------------

/// Statistical summary of timing measurements.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimingStats {
    /// Number of measurements.
    pub count: usize,
    /// Minimum duration in microseconds.
    pub min_us: u64,
    /// Maximum duration in microseconds.
    pub max_us: u64,
    /// Mean duration in microseconds.
    pub mean_us: u64,
    /// Median duration in microseconds.
    pub median_us: u64,
    /// Standard deviation in microseconds.
    pub stddev_us: u64,
    /// Coefficient of variation (millionths). 100_000 = 10%.
    pub cv_millionths: u64,
    /// p95 duration in microseconds.
    pub p95_us: u64,
    /// p99 duration in microseconds.
    pub p99_us: u64,
}

impl TimingStats {
    /// Compute statistics from a slice of durations (microseconds).
    pub fn from_durations(durations: &[u64]) -> Self {
        if durations.is_empty() {
            return Self {
                count: 0,
                min_us: 0,
                max_us: 0,
                mean_us: 0,
                median_us: 0,
                stddev_us: 0,
                cv_millionths: 0,
                p95_us: 0,
                p99_us: 0,
            };
        }

        let mut sorted = durations.to_vec();
        sorted.sort_unstable();

        let count = sorted.len();
        let min_us = sorted[0];
        let max_us = sorted[count - 1];
        let sum: u64 = sorted.iter().sum();
        let mean_us = sum / count as u64;
        let median_us = if count.is_multiple_of(2) {
            (sorted[count / 2 - 1] + sorted[count / 2]) / 2
        } else {
            sorted[count / 2]
        };

        // Variance in microseconds^2.
        let variance: u64 = if count > 1 {
            sorted
                .iter()
                .map(|&d| {
                    let diff = d.abs_diff(mean_us);
                    diff.saturating_mul(diff)
                })
                .sum::<u64>()
                / (count as u64 - 1)
        } else {
            0
        };

        // Integer square root approximation for stddev.
        let stddev_us = isqrt(variance);

        // CV in millionths.
        let cv_millionths = stddev_us
            .saturating_mul(1_000_000)
            .checked_div(mean_us)
            .unwrap_or(0);

        // Percentiles.
        let p95_idx = ((count as u64 * 95) / 100) as usize;
        let p99_idx = ((count as u64 * 99) / 100) as usize;
        let p95_us = sorted[p95_idx.min(count - 1)];
        let p99_us = sorted[p99_idx.min(count - 1)];

        Self {
            count,
            min_us,
            max_us,
            mean_us,
            median_us,
            stddev_us,
            cv_millionths,
            p95_us,
            p99_us,
        }
    }

    /// Whether the CV is within acceptable bounds.
    pub fn is_stable(&self, max_cv: u64) -> bool {
        self.cv_millionths <= max_cv
    }
}

// ---------------------------------------------------------------------------
// BundleConfig
// ---------------------------------------------------------------------------

/// Configuration for bundle acceptance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleConfig {
    /// Minimum runs per workload to consider the workload sufficiently sampled.
    pub min_runs_per_workload: usize,
    /// Maximum CV (millionths) for any workload's timing.
    pub max_cv_millionths: u64,
    /// Minimum parity ratio (millionths) for parity to be acceptable.
    pub min_parity_ratio: u64,
    /// Maximum environment drift entries allowed.
    pub max_environment_drift: usize,
    /// Required workload categories (empty = no requirement).
    pub required_categories: BTreeSet<WorkloadCategory>,
    /// Required parity targets (empty = no requirement).
    pub required_parity_targets: BTreeSet<ParityTarget>,
    /// Minimum verification epoch.
    pub min_verification_epoch: SecurityEpoch,
}

impl Default for BundleConfig {
    fn default() -> Self {
        Self {
            min_runs_per_workload: MIN_RUNS_PER_WORKLOAD,
            max_cv_millionths: MAX_CV_MILLIONTHS,
            min_parity_ratio: DEFAULT_MIN_PARITY_RATIO,
            max_environment_drift: MAX_ENVIRONMENT_DRIFT,
            required_categories: BTreeSet::new(),
            required_parity_targets: BTreeSet::new(),
            min_verification_epoch: SecurityEpoch::from_raw(1),
        }
    }
}

// ---------------------------------------------------------------------------
// BundleVerdict
// ---------------------------------------------------------------------------

/// Result of evaluating a bundle against acceptance criteria.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[serde(tag = "verdict")]
pub enum BundleVerdict {
    /// Bundle meets all acceptance criteria.
    Pass {
        /// Number of workloads in the bundle.
        workload_count: usize,
        /// Total effective runs.
        total_runs: usize,
        /// Categories covered.
        categories: BTreeSet<WorkloadCategory>,
    },
    /// Bundle fails one or more acceptance criteria.
    Fail {
        /// Reasons for failure.
        reasons: Vec<String>,
    },
    /// Bundle is incomplete — missing required information.
    Incomplete {
        /// What is missing.
        missing: Vec<String>,
    },
}

// ---------------------------------------------------------------------------
// BundleReport
// ---------------------------------------------------------------------------

/// High-level report of a bundle for dashboards and evidence records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleReport {
    /// Schema version.
    pub schema_version: String,
    /// Bundle ID.
    pub bundle_id: String,
    /// Bundle status.
    pub status: BundleStatus,
    /// Bundle epoch.
    pub epoch: SecurityEpoch,
    /// Total workloads.
    pub total_workloads: usize,
    /// Total effective runs.
    pub total_effective_runs: usize,
    /// Total warmup runs.
    pub total_warmup_runs: usize,
    /// Per-workload stats.
    pub workload_stats: Vec<WorkloadStatEntry>,
    /// Parity verdict count.
    pub parity_verdict_count: usize,
    /// Parity pass count.
    pub parity_pass_count: usize,
    /// Environment drift entries.
    pub environment_drift_count: usize,
    /// Categories covered.
    pub categories: BTreeSet<WorkloadCategory>,
    /// Gate verdict.
    pub verdict: BundleVerdict,
    /// Report hash.
    pub report_hash: ContentHash,
}

/// Per-workload entry in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadStatEntry {
    /// Workload ID.
    pub workload_id: String,
    /// Workload category.
    pub category: WorkloadCategory,
    /// Timing stats.
    pub stats: TimingStats,
    /// Number of parity verdicts.
    pub parity_verdicts: usize,
    /// All parity passed.
    pub all_parity_passed: bool,
}

// ---------------------------------------------------------------------------
// BundleError
// ---------------------------------------------------------------------------

/// Errors from evidence bundle operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BundleError {
    /// Bundle is already sealed.
    BundleSealed { bundle_id: String },
    /// Duplicate workload provenance.
    DuplicateWorkload { workload_id: String },
    /// Run references a workload with no provenance.
    MissingProvenance { workload_id: String },
    /// Invalid status transition.
    InvalidTransition {
        from: BundleStatus,
        to: BundleStatus,
    },
    /// Configuration is invalid.
    InvalidConfig { reason: String },
    /// Evidence too stale for the requested gate.
    StaleEvidence {
        bundle_epoch: u64,
        required_epoch: u64,
    },
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BundleSealed { bundle_id } => {
                write!(f, "bundle already sealed: {bundle_id}")
            }
            Self::DuplicateWorkload { workload_id } => {
                write!(f, "duplicate workload provenance: {workload_id}")
            }
            Self::MissingProvenance { workload_id } => {
                write!(f, "no provenance for workload: {workload_id}")
            }
            Self::InvalidTransition { from, to } => {
                write!(f, "invalid transition: {from} -> {to}")
            }
            Self::InvalidConfig { reason } => {
                write!(f, "invalid config: {reason}")
            }
            Self::StaleEvidence {
                bundle_epoch,
                required_epoch,
            } => {
                write!(
                    f,
                    "stale evidence: bundle epoch {bundle_epoch} < required {required_epoch}"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/// Evaluate a bundle against the acceptance gate.
pub fn evaluate_bundle(bundle: &EvidenceBundle, config: &BundleConfig) -> BundleVerdict {
    let mut reasons = Vec::new();
    let mut missing = Vec::new();

    // Check stale epoch.
    if bundle.created_epoch.as_u64() < config.min_verification_epoch.as_u64() {
        reasons.push(format!(
            "bundle epoch {} < required {}",
            bundle.created_epoch.as_u64(),
            config.min_verification_epoch.as_u64()
        ));
    }

    // Check empty bundle.
    if bundle.provenances.is_empty() {
        missing.push("no workload provenances".to_string());
    }

    // Check required categories.
    let covered_cats = bundle.categories();
    for cat in &config.required_categories {
        if !covered_cats.contains(cat) {
            missing.push(format!("missing required category: {cat}"));
        }
    }

    // Check required parity targets.
    let covered_targets: BTreeSet<ParityTarget> =
        bundle.parity_verdicts.iter().map(|v| v.target).collect();
    for target in &config.required_parity_targets {
        if !covered_targets.contains(target) {
            missing.push(format!("missing required parity target: {target}"));
        }
    }

    if !missing.is_empty() {
        return BundleVerdict::Incomplete { missing };
    }

    // Check per-workload constraints.
    for prov in &bundle.provenances {
        let runs = bundle.runs_for_workload(&prov.workload_id);
        if runs.len() < config.min_runs_per_workload {
            reasons.push(format!(
                "workload {}: {} runs < minimum {}",
                prov.workload_id,
                runs.len(),
                config.min_runs_per_workload
            ));
        }

        if let Some(stats) = bundle.workload_stats(&prov.workload_id)
            && stats.cv_millionths > config.max_cv_millionths
        {
            reasons.push(format!(
                "workload {}: CV {} > max {}",
                prov.workload_id, stats.cv_millionths, config.max_cv_millionths
            ));
        }
    }

    // Check parity verdicts.
    for verdict in &bundle.parity_verdicts {
        if !verdict.is_acceptable(config.min_parity_ratio) {
            reasons.push(format!(
                "parity fail: workload {} vs {}: ratio={}, eq={}",
                verdict.workload_id,
                verdict.target,
                verdict.performance_ratio_millionths,
                verdict.output_equivalent,
            ));
        }
    }

    // Check environment drift.
    if bundle.environment_drifts.len() > config.max_environment_drift {
        reasons.push(format!(
            "environment drift: {} entries > max {}",
            bundle.environment_drifts.len(),
            config.max_environment_drift
        ));
    }

    if reasons.is_empty() {
        BundleVerdict::Pass {
            workload_count: bundle.provenances.len(),
            total_runs: bundle.effective_runs().len(),
            categories: covered_cats,
        }
    } else {
        BundleVerdict::Fail { reasons }
    }
}

/// Generate a report for a bundle.
pub fn generate_report(bundle: &EvidenceBundle, config: &BundleConfig) -> BundleReport {
    let verdict = evaluate_bundle(bundle, config);

    let workload_stats: Vec<WorkloadStatEntry> = bundle
        .provenances
        .iter()
        .map(|prov| {
            let stats = bundle
                .workload_stats(&prov.workload_id)
                .unwrap_or(TimingStats::from_durations(&[]));
            let parity = bundle.parity_for_workload(&prov.workload_id);
            let all_passed = !parity.is_empty()
                && parity
                    .iter()
                    .all(|v| v.is_acceptable(config.min_parity_ratio));
            WorkloadStatEntry {
                workload_id: prov.workload_id.clone(),
                category: prov.category,
                stats,
                parity_verdicts: parity.len(),
                all_parity_passed: all_passed,
            }
        })
        .collect();

    let parity_pass = bundle
        .parity_verdicts
        .iter()
        .filter(|v| v.is_acceptable(config.min_parity_ratio))
        .count();

    let warmup_count = bundle.runs.iter().filter(|r| r.is_warmup).count();

    let mut hasher = Sha256::new();
    hasher.update(bundle.bundle_id.as_bytes());
    hasher.update(bundle.bundle_hash.as_bytes());
    hasher.update(SCHEMA_VERSION.as_bytes());
    let report_hash = ContentHash::compute(&hasher.finalize());

    BundleReport {
        schema_version: SCHEMA_VERSION.to_string(),
        bundle_id: bundle.bundle_id.clone(),
        status: bundle.status,
        epoch: bundle.created_epoch,
        total_workloads: bundle.provenances.len(),
        total_effective_runs: bundle.effective_runs().len(),
        total_warmup_runs: warmup_count,
        workload_stats,
        parity_verdict_count: bundle.parity_verdicts.len(),
        parity_pass_count: parity_pass,
        environment_drift_count: bundle.environment_drifts.len(),
        categories: bundle.categories(),
        verdict,
        report_hash,
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Integer square root via Newton's method.
fn isqrt(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    #[allow(clippy::manual_div_ceil)]
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn test_env() -> EnvironmentSnapshot {
        EnvironmentSnapshot::new(
            "linux".to_string(),
            "x86_64".to_string(),
            16,
            64_000_000_000,
            "node 22.1.0".to_string(),
            "franken 0.1.0".to_string(),
            BTreeMap::new(),
        )
    }

    fn test_prov(id: &str, cat: WorkloadCategory) -> WorkloadProvenance {
        WorkloadProvenance {
            workload_id: id.to_string(),
            name: format!("Workload {id}"),
            category: cat,
            source: "test-corpus".to_string(),
            pinned_version: "abc123".to_string(),
            content_hash: ContentHash::compute(id.as_bytes()),
            provenance_epoch: epoch(1),
            tags: BTreeSet::new(),
        }
    }

    fn test_run(id: &str, workload_id: &str, duration_us: u64, iteration: u32) -> BenchmarkRun {
        BenchmarkRun {
            run_id: id.to_string(),
            workload_id: workload_id.to_string(),
            duration_us,
            peak_memory_bytes: 1024,
            gc_pause_us: 0,
            is_warmup: false,
            iteration,
            environment: test_env(),
            run_epoch: epoch(1),
        }
    }

    fn test_parity(workload_id: &str, target: ParityTarget, ratio: u64) -> ParityVerdict {
        ParityVerdict {
            workload_id: workload_id.to_string(),
            target,
            output_equivalent: true,
            performance_ratio_millionths: ratio,
            behavioral_differences: 0,
            difference_details: Vec::new(),
            evidence_hash: ContentHash::compute(workload_id.as_bytes()),
        }
    }

    fn default_config() -> BundleConfig {
        BundleConfig::default()
    }

    fn populated_bundle() -> EvidenceBundle {
        let mut bundle = EvidenceBundle::new("test-bundle".to_string(), epoch(5));
        bundle
            .add_provenance(test_prov("wk-1", WorkloadCategory::Micro))
            .unwrap();
        for i in 0..6 {
            bundle
                .add_run(test_run(&format!("r-{i}"), "wk-1", 1000 + i * 10, i as u32))
                .unwrap();
        }
        bundle
            .add_parity_verdict(test_parity("wk-1", ParityTarget::NodeJs, 1_050_000))
            .unwrap();
        bundle
    }

    // -- Constants --

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SCHEMA_VERSION.ends_with(".v1"));
    }

    #[test]
    fn component_name_matches() {
        assert_eq!(COMPONENT, "benchmark_evidence_bundle");
    }

    #[test]
    fn bead_id_matches() {
        assert_eq!(BEAD_ID, "bd-1lsy.8.4.3");
    }

    #[test]
    fn policy_id_matches() {
        assert_eq!(POLICY_ID, "RGC-704C");
    }

    // -- WorkloadCategory --

    #[test]
    fn workload_category_all_variants() {
        assert_eq!(WorkloadCategory::ALL.len(), 6);
    }

    #[test]
    fn workload_category_as_str_roundtrip() {
        for &cat in WorkloadCategory::ALL {
            let s = cat.as_str();
            assert!(!s.is_empty());
            assert_eq!(cat.to_string(), s);
        }
    }

    #[test]
    fn workload_category_ordering() {
        assert!(WorkloadCategory::Micro < WorkloadCategory::Application);
        assert!(WorkloadCategory::Application < WorkloadCategory::Framework);
    }

    #[test]
    fn workload_category_serde_roundtrip() {
        for &cat in WorkloadCategory::ALL {
            let json = serde_json::to_string(&cat).unwrap();
            let back: WorkloadCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }
    }

    // -- ParityTarget --

    #[test]
    fn parity_target_all_variants() {
        assert_eq!(ParityTarget::ALL.len(), 4);
    }

    #[test]
    fn parity_target_as_str() {
        assert_eq!(ParityTarget::NodeJs.as_str(), "node_js");
        assert_eq!(ParityTarget::Bun.as_str(), "bun");
        assert_eq!(ParityTarget::Deno.as_str(), "deno");
        assert_eq!(ParityTarget::V8Isolate.as_str(), "v8_isolate");
    }

    #[test]
    fn parity_target_display() {
        assert_eq!(ParityTarget::NodeJs.to_string(), "node_js");
    }

    // -- BundleStatus --

    #[test]
    fn bundle_status_as_str() {
        assert_eq!(BundleStatus::Assembling.as_str(), "assembling");
        assert_eq!(BundleStatus::Sealed.as_str(), "sealed");
        assert_eq!(BundleStatus::Published.as_str(), "published");
        assert_eq!(BundleStatus::Rejected.as_str(), "rejected");
        assert_eq!(BundleStatus::Superseded.as_str(), "superseded");
    }

    #[test]
    fn bundle_status_display() {
        assert_eq!(BundleStatus::Published.to_string(), "published");
    }

    // -- EnvironmentSnapshot --

    #[test]
    fn environment_snapshot_hash_deterministic() {
        let e1 = test_env();
        let e2 = test_env();
        assert_eq!(e1.snapshot_hash, e2.snapshot_hash);
    }

    #[test]
    fn environment_drift_detection() {
        let e1 = test_env();
        let mut e2 = test_env();
        e2.os = "macos".to_string();
        e2.logical_cores = 8;
        let drifts = e1.drift_from(&e2);
        assert_eq!(drifts.len(), 2);
    }

    #[test]
    fn environment_no_drift_for_identical() {
        let e1 = test_env();
        let e2 = test_env();
        let drifts = e1.drift_from(&e2);
        assert!(drifts.is_empty());
    }

    // -- EvidenceBundle CRUD --

    #[test]
    fn new_bundle_is_assembling() {
        let bundle = EvidenceBundle::new("b1".to_string(), epoch(1));
        assert_eq!(bundle.status, BundleStatus::Assembling);
        assert!(bundle.provenances.is_empty());
        assert!(bundle.runs.is_empty());
    }

    #[test]
    fn add_provenance_success() {
        let mut bundle = EvidenceBundle::new("b1".to_string(), epoch(1));
        let result = bundle.add_provenance(test_prov("w1", WorkloadCategory::Micro));
        assert!(result.is_ok());
        assert_eq!(bundle.provenances.len(), 1);
    }

    #[test]
    fn add_duplicate_provenance_fails() {
        let mut bundle = EvidenceBundle::new("b1".to_string(), epoch(1));
        bundle
            .add_provenance(test_prov("w1", WorkloadCategory::Micro))
            .unwrap();
        let result = bundle.add_provenance(test_prov("w1", WorkloadCategory::Application));
        assert!(matches!(result, Err(BundleError::DuplicateWorkload { .. })));
    }

    #[test]
    fn add_run_requires_provenance() {
        let mut bundle = EvidenceBundle::new("b1".to_string(), epoch(1));
        let result = bundle.add_run(test_run("r1", "w1", 100, 0));
        assert!(matches!(result, Err(BundleError::MissingProvenance { .. })));
    }

    #[test]
    fn add_run_success_with_provenance() {
        let mut bundle = EvidenceBundle::new("b1".to_string(), epoch(1));
        bundle
            .add_provenance(test_prov("w1", WorkloadCategory::Micro))
            .unwrap();
        let result = bundle.add_run(test_run("r1", "w1", 100, 0));
        assert!(result.is_ok());
        assert_eq!(bundle.runs.len(), 1);
    }

    #[test]
    fn seal_and_no_further_adds() {
        let mut bundle = populated_bundle();
        bundle.seal().unwrap();
        assert_eq!(bundle.status, BundleStatus::Sealed);
        let result = bundle.add_provenance(test_prov("w2", WorkloadCategory::Application));
        assert!(matches!(result, Err(BundleError::BundleSealed { .. })));
    }

    #[test]
    fn publish_requires_sealed() {
        let mut bundle = populated_bundle();
        let result = bundle.publish();
        assert!(matches!(result, Err(BundleError::InvalidTransition { .. })));
        bundle.seal().unwrap();
        assert!(bundle.publish().is_ok());
        assert_eq!(bundle.status, BundleStatus::Published);
    }

    #[test]
    fn reject_requires_sealed() {
        let mut bundle = populated_bundle();
        bundle.seal().unwrap();
        assert!(bundle.reject().is_ok());
        assert_eq!(bundle.status, BundleStatus::Rejected);
    }

    // -- Warmup filtering --

    #[test]
    fn effective_runs_excludes_warmup() {
        let mut bundle = EvidenceBundle::new("b1".to_string(), epoch(1));
        bundle
            .add_provenance(test_prov("w1", WorkloadCategory::Micro))
            .unwrap();
        let mut warmup = test_run("r0", "w1", 2000, 0);
        warmup.is_warmup = true;
        bundle.add_run(warmup).unwrap();
        bundle.add_run(test_run("r1", "w1", 1000, 1)).unwrap();
        assert_eq!(bundle.effective_runs().len(), 1);
        assert_eq!(bundle.runs.len(), 2);
    }

    // -- Workload queries --

    #[test]
    fn workload_ids_from_provenances() {
        let bundle = populated_bundle();
        assert_eq!(bundle.workload_ids(), vec!["wk-1"]);
    }

    #[test]
    fn categories_from_provenances() {
        let bundle = populated_bundle();
        assert!(bundle.categories().contains(&WorkloadCategory::Micro));
    }

    #[test]
    fn runs_for_workload_filters() {
        let bundle = populated_bundle();
        assert_eq!(bundle.runs_for_workload("wk-1").len(), 6);
        assert_eq!(bundle.runs_for_workload("wk-nonexist").len(), 0);
    }

    // -- TimingStats --

    #[test]
    fn timing_stats_empty() {
        let stats = TimingStats::from_durations(&[]);
        assert_eq!(stats.count, 0);
        assert_eq!(stats.mean_us, 0);
    }

    #[test]
    fn timing_stats_single() {
        let stats = TimingStats::from_durations(&[500]);
        assert_eq!(stats.count, 1);
        assert_eq!(stats.min_us, 500);
        assert_eq!(stats.max_us, 500);
        assert_eq!(stats.mean_us, 500);
        assert_eq!(stats.median_us, 500);
    }

    #[test]
    fn timing_stats_multiple() {
        let stats = TimingStats::from_durations(&[100, 200, 300, 400, 500]);
        assert_eq!(stats.count, 5);
        assert_eq!(stats.min_us, 100);
        assert_eq!(stats.max_us, 500);
        assert_eq!(stats.mean_us, 300);
        assert_eq!(stats.median_us, 300);
    }

    #[test]
    fn timing_stats_even_count_median() {
        let stats = TimingStats::from_durations(&[100, 200, 300, 400]);
        assert_eq!(stats.median_us, 250);
    }

    #[test]
    fn timing_stats_cv_zero_for_constant() {
        let stats = TimingStats::from_durations(&[100, 100, 100, 100, 100]);
        assert_eq!(stats.cv_millionths, 0);
    }

    #[test]
    fn timing_stats_stability_check() {
        let stats = TimingStats::from_durations(&[100, 100, 100, 100, 100]);
        assert!(stats.is_stable(MAX_CV_MILLIONTHS));
    }

    #[test]
    fn timing_stats_percentiles() {
        let durations: Vec<u64> = (1..=100).collect();
        let stats = TimingStats::from_durations(&durations);
        // p95_idx = (100*95)/100 = 95 → sorted[95] = 96
        assert_eq!(stats.p95_us, 96);
        // p99_idx = (100*99)/100 = 99 → sorted[99] = 100
        assert_eq!(stats.p99_us, 100);
    }

    // -- ParityVerdict --

    #[test]
    fn parity_verdict_acceptable() {
        let v = test_parity("w1", ParityTarget::NodeJs, 1_050_000);
        assert!(v.is_acceptable(DEFAULT_MIN_PARITY_RATIO));
    }

    #[test]
    fn parity_verdict_unacceptable_low_ratio() {
        let v = test_parity("w1", ParityTarget::NodeJs, 800_000);
        assert!(!v.is_acceptable(DEFAULT_MIN_PARITY_RATIO));
    }

    #[test]
    fn parity_verdict_unacceptable_not_equivalent() {
        let mut v = test_parity("w1", ParityTarget::NodeJs, 1_100_000);
        v.output_equivalent = false;
        assert!(!v.is_acceptable(DEFAULT_MIN_PARITY_RATIO));
    }

    // -- Evaluation --

    #[test]
    fn evaluate_pass_basic() {
        let bundle = populated_bundle();
        let config = default_config();
        let verdict = evaluate_bundle(&bundle, &config);
        assert!(matches!(verdict, BundleVerdict::Pass { .. }));
    }

    #[test]
    fn evaluate_fail_insufficient_runs() {
        let mut bundle = EvidenceBundle::new("b1".to_string(), epoch(5));
        bundle
            .add_provenance(test_prov("w1", WorkloadCategory::Micro))
            .unwrap();
        bundle.add_run(test_run("r1", "w1", 100, 0)).unwrap();
        let config = default_config();
        let verdict = evaluate_bundle(&bundle, &config);
        assert!(matches!(verdict, BundleVerdict::Fail { .. }));
    }

    #[test]
    fn evaluate_incomplete_missing_category() {
        let bundle = populated_bundle();
        let mut config = default_config();
        config
            .required_categories
            .insert(WorkloadCategory::Application);
        let verdict = evaluate_bundle(&bundle, &config);
        assert!(matches!(verdict, BundleVerdict::Incomplete { .. }));
    }

    #[test]
    fn evaluate_incomplete_missing_parity_target() {
        let bundle = populated_bundle();
        let mut config = default_config();
        config.required_parity_targets.insert(ParityTarget::Bun);
        let verdict = evaluate_bundle(&bundle, &config);
        assert!(matches!(verdict, BundleVerdict::Incomplete { .. }));
    }

    #[test]
    fn evaluate_fail_stale_epoch() {
        let bundle = populated_bundle();
        let mut config = default_config();
        config.min_verification_epoch = epoch(10);
        let verdict = evaluate_bundle(&bundle, &config);
        assert!(matches!(verdict, BundleVerdict::Fail { .. }));
    }

    #[test]
    fn evaluate_incomplete_no_provenances() {
        let bundle = EvidenceBundle::new("b1".to_string(), epoch(5));
        let config = default_config();
        let verdict = evaluate_bundle(&bundle, &config);
        assert!(matches!(verdict, BundleVerdict::Incomplete { .. }));
    }

    #[test]
    fn evaluate_fail_parity_failure() {
        let mut bundle = populated_bundle();
        let bad_parity = ParityVerdict {
            workload_id: "wk-1".to_string(),
            target: ParityTarget::Bun,
            output_equivalent: false,
            performance_ratio_millionths: 500_000,
            behavioral_differences: 3,
            difference_details: vec!["diff 1".to_string()],
            evidence_hash: ContentHash::compute(b"bad"),
        };
        bundle.add_parity_verdict(bad_parity).unwrap();
        let config = default_config();
        let verdict = evaluate_bundle(&bundle, &config);
        assert!(matches!(verdict, BundleVerdict::Fail { .. }));
    }

    #[test]
    fn evaluate_fail_environment_drift() {
        let mut bundle = EvidenceBundle::new("b1".to_string(), epoch(5));
        bundle
            .add_provenance(test_prov("w1", WorkloadCategory::Micro))
            .unwrap();
        // Add runs with different environments to cause drift.
        for i in 0..6 {
            let mut run = test_run(&format!("r-{i}"), "w1", 1000, i as u32);
            if i >= 1 {
                run.environment = EnvironmentSnapshot::new(
                    format!("os-{i}"),
                    format!("cpu-{i}"),
                    (16 + i) as u32,
                    64_000_000_000 + i as u64 * 1000,
                    "node 22.1.0".to_string(),
                    "franken 0.1.0".to_string(),
                    BTreeMap::new(),
                );
            }
            bundle.add_run(run).unwrap();
        }
        let config = default_config();
        let verdict = evaluate_bundle(&bundle, &config);
        assert!(matches!(verdict, BundleVerdict::Fail { .. }));
    }

    // -- Report --

    #[test]
    fn report_basic() {
        let bundle = populated_bundle();
        let config = default_config();
        let report = generate_report(&bundle, &config);
        assert_eq!(report.bundle_id, "test-bundle");
        assert_eq!(report.total_workloads, 1);
        assert_eq!(report.total_effective_runs, 6);
        assert!(matches!(report.verdict, BundleVerdict::Pass { .. }));
    }

    #[test]
    fn report_includes_workload_stats() {
        let bundle = populated_bundle();
        let config = default_config();
        let report = generate_report(&bundle, &config);
        assert_eq!(report.workload_stats.len(), 1);
        assert_eq!(report.workload_stats[0].workload_id, "wk-1");
        assert_eq!(report.workload_stats[0].stats.count, 6);
    }

    #[test]
    fn report_hash_deterministic() {
        let bundle = populated_bundle();
        let config = default_config();
        let r1 = generate_report(&bundle, &config);
        let r2 = generate_report(&bundle, &config);
        assert_eq!(r1.report_hash, r2.report_hash);
    }

    // -- BundleError Display --

    #[test]
    fn error_display_sealed() {
        let err = BundleError::BundleSealed {
            bundle_id: "b1".to_string(),
        };
        assert!(err.to_string().contains("sealed"));
    }

    #[test]
    fn error_display_missing_provenance() {
        let err = BundleError::MissingProvenance {
            workload_id: "w1".to_string(),
        };
        assert!(err.to_string().contains("provenance"));
    }

    #[test]
    fn error_display_stale() {
        let err = BundleError::StaleEvidence {
            bundle_epoch: 1,
            required_epoch: 5,
        };
        assert!(err.to_string().contains("stale"));
    }

    // -- Serde roundtrips --

    #[test]
    fn bundle_serde_roundtrip() {
        let bundle = populated_bundle();
        let json = serde_json::to_string(&bundle).unwrap();
        let back: EvidenceBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle.bundle_id, back.bundle_id);
        assert_eq!(bundle.runs.len(), back.runs.len());
    }

    #[test]
    fn config_serde_roundtrip() {
        let config = default_config();
        let json = serde_json::to_string(&config).unwrap();
        let back: BundleConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, back);
    }

    #[test]
    fn report_serde_roundtrip() {
        let bundle = populated_bundle();
        let config = default_config();
        let report = generate_report(&bundle, &config);
        let json = serde_json::to_string(&report).unwrap();
        let back: BundleReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.bundle_id, back.bundle_id);
    }

    #[test]
    fn verdict_serde_roundtrip() {
        let verdict = BundleVerdict::Pass {
            workload_count: 3,
            total_runs: 15,
            categories: BTreeSet::new(),
        };
        let json = serde_json::to_string(&verdict).unwrap();
        let back: BundleVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(verdict, back);
    }

    // -- Hash integrity --

    #[test]
    fn bundle_hash_changes_on_add() {
        let mut bundle = EvidenceBundle::new("b1".to_string(), epoch(1));
        let h1 = bundle.bundle_hash;
        bundle
            .add_provenance(test_prov("w1", WorkloadCategory::Micro))
            .unwrap();
        assert_ne!(h1, bundle.bundle_hash);
    }

    #[test]
    fn bundle_hash_changes_on_run() {
        let mut bundle = EvidenceBundle::new("b1".to_string(), epoch(1));
        bundle
            .add_provenance(test_prov("w1", WorkloadCategory::Micro))
            .unwrap();
        let h1 = bundle.bundle_hash;
        bundle.add_run(test_run("r1", "w1", 100, 0)).unwrap();
        assert_ne!(h1, bundle.bundle_hash);
    }

    // -- isqrt --

    #[test]
    fn isqrt_basic_values() {
        assert_eq!(isqrt(0), 0);
        assert_eq!(isqrt(1), 1);
        assert_eq!(isqrt(4), 2);
        assert_eq!(isqrt(9), 3);
        assert_eq!(isqrt(100), 10);
        assert_eq!(isqrt(10000), 100);
    }

    #[test]
    fn isqrt_non_perfect_squares() {
        assert_eq!(isqrt(2), 1);
        assert_eq!(isqrt(5), 2);
        assert_eq!(isqrt(8), 2);
        assert_eq!(isqrt(99), 9);
    }

    // -- Environment hash --

    #[test]
    fn environment_extra_metadata_affects_hash() {
        let e1 = test_env();
        let mut extra = BTreeMap::new();
        extra.insert("turbo".to_string(), "on".to_string());
        let e2 = EnvironmentSnapshot::new(
            "linux".to_string(),
            "x86_64".to_string(),
            16,
            64_000_000_000,
            "node 22.1.0".to_string(),
            "franken 0.1.0".to_string(),
            extra,
        );
        assert_ne!(e1.snapshot_hash, e2.snapshot_hash);
    }

    // -- Multiple workloads --

    #[test]
    fn multi_workload_bundle() {
        let mut bundle = EvidenceBundle::new("b1".to_string(), epoch(5));
        bundle
            .add_provenance(test_prov("w1", WorkloadCategory::Micro))
            .unwrap();
        bundle
            .add_provenance(test_prov("w2", WorkloadCategory::Application))
            .unwrap();
        for i in 0..6 {
            bundle
                .add_run(test_run(&format!("r1-{i}"), "w1", 100, i as u32))
                .unwrap();
            bundle
                .add_run(test_run(&format!("r2-{i}"), "w2", 200, i as u32))
                .unwrap();
        }
        assert_eq!(bundle.workload_ids().len(), 2);
        assert_eq!(bundle.categories().len(), 2);
    }

    #[test]
    fn parity_for_workload_filters() {
        let mut bundle = populated_bundle();
        bundle
            .add_parity_verdict(test_parity("wk-1", ParityTarget::Bun, 980_000))
            .unwrap();
        assert_eq!(bundle.parity_for_workload("wk-1").len(), 2);
        assert_eq!(bundle.parity_for_workload("wk-nonexist").len(), 0);
    }
}
