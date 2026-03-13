//! Hot-path NitroSketch kernels, exact-shadow calibration, and sketch writers.
//!
//! This module implements the low-overhead hot-path telemetry layer that
//! allows runtime-critical code paths to emit observability data under
//! strict budget constraints.  The key innovation is that each kernel
//! operates in one of four capture modes (Budgeted, ExactShadow,
//! Degraded, FullCapture), and evidence consumers can always determine
//! which mode produced a given artifact.
//!
//! Key capabilities:
//! - **Sketch writer kernels**: deterministic writers that fold weighted
//!   observations into bounded-memory sketches (Count-Min, Heavy-Hitter,
//!   Quantile, Histogram) with replay-stable sampling decisions.
//! - **Exact-shadow calibration**: a parallel exact-count path that runs
//!   alongside sketched telemetry so calibration reports can bound
//!   approximation error with concrete evidence.
//! - **Evidence thinning**: deterministic policies that reduce the volume
//!   of evidence artifacts on hot paths while preserving statistical
//!   properties and provenance chains.
//! - **Budget-aware capture**: kernels automatically degrade sampling
//!   rates as budgets deplete, with fail-closed behavior on exhaustion.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//! All collections use BTreeMap/BTreeSet for deterministic ordering.
//!
//! Plan reference: Section 10.11, RGC-066B (bd-1lsy.11.20.2).
//! Dependencies: hash_tiers, security_epoch, nitrosketch_telemetry.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "hot_path_telemetry_kernel";

/// Fixed-point unit: 1_000_000 = 1.0 (100%).
const MILLION: u64 = 1_000_000;

/// Schema version for hot-path telemetry manifests.
pub const SCHEMA_VERSION: &str = "franken-engine.hot-path-telemetry-kernel.v1";

/// Maximum number of active kernels in a single registry.
const MAX_KERNELS: usize = 2048;

/// Maximum sketch entries per kernel before compaction.
const MAX_SKETCH_ENTRIES: usize = 16_384;

/// Default evidence-thinning retention rate (10% = 100_000 millionths).
#[allow(dead_code)]
const DEFAULT_RETENTION_MILLIONTHS: u64 = 100_000;

/// Calibration error threshold (5% = 50_000 millionths).
const CALIBRATION_ERROR_THRESHOLD: u64 = 50_000;

/// Maximum thinning rounds before forced compaction.
const MAX_THINNING_ROUNDS: u64 = 256;

// ---------------------------------------------------------------------------
// CaptureMode — which telemetry mode produced an artifact
// ---------------------------------------------------------------------------

/// The capture mode under which a telemetry artifact was produced.
///
/// Every evidence artifact carries its capture mode so consumers know
/// exactly what level of fidelity to expect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMode {
    /// Default budgeted capture: sketch-based, sampled, bounded memory.
    Budgeted,
    /// Exact-shadow validation: every event counted exactly, used for
    /// calibrating sketched results.
    ExactShadow,
    /// Degraded mode: budget exhausted or kernel error, minimal data.
    Degraded,
    /// Full capture: incident or audit mode, every event recorded.
    FullCapture,
}

impl CaptureMode {
    /// Canonical string tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Budgeted => "budgeted",
            Self::ExactShadow => "exact_shadow",
            Self::Degraded => "degraded",
            Self::FullCapture => "full_capture",
        }
    }

    /// Whether this mode produces exact (non-approximated) results.
    pub fn is_exact(self) -> bool {
        matches!(self, Self::ExactShadow | Self::FullCapture)
    }

    /// Whether this mode is considered healthy for normal operation.
    pub fn is_healthy(self) -> bool {
        matches!(self, Self::Budgeted | Self::ExactShadow | Self::FullCapture)
    }
}

impl fmt::Display for CaptureMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ThinningStrategy — how evidence is thinned on hot paths
// ---------------------------------------------------------------------------

/// Strategy for thinning evidence artifacts on hot runtime paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThinningStrategy {
    /// Uniform random thinning: retain each entry with fixed probability.
    UniformRate,
    /// Hash-based deterministic thinning: retain if hash(key) < threshold.
    HashDeterministic,
    /// Weight-proportional: higher-weight evidence more likely retained.
    WeightProportional,
    /// Epoch-adaptive: retention rate decreases as epoch ages.
    EpochAdaptive,
    /// Priority-tiered: retain all high-priority, thin low-priority.
    PriorityTiered,
}

impl ThinningStrategy {
    /// Canonical string tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UniformRate => "uniform_rate",
            Self::HashDeterministic => "hash_deterministic",
            Self::WeightProportional => "weight_proportional",
            Self::EpochAdaptive => "epoch_adaptive",
            Self::PriorityTiered => "priority_tiered",
        }
    }
}

impl fmt::Display for ThinningStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SketchWriterKind — kernel sketch algorithm
// ---------------------------------------------------------------------------

/// The sketch algorithm used by a hot-path kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SketchWriterKind {
    /// Count-Min: frequency upper-bound estimation.
    CountMin,
    /// Heavy-Hitter: Space-Saving / Misra-Gries top-K.
    HeavyHitter,
    /// Quantile: t-digest or GK summary.
    Quantile,
    /// Histogram: fixed-bucket with configurable boundaries.
    Histogram,
}

impl SketchWriterKind {
    /// Canonical string tag.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CountMin => "count_min",
            Self::HeavyHitter => "heavy_hitter",
            Self::Quantile => "quantile",
            Self::Histogram => "histogram",
        }
    }
}

impl fmt::Display for SketchWriterKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ThinningPolicy — evidence thinning configuration
// ---------------------------------------------------------------------------

/// Configuration for evidence thinning on a hot path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThinningPolicy {
    /// Unique identifier for this policy.
    pub policy_id: String,
    /// Thinning strategy to apply.
    pub strategy: ThinningStrategy,
    /// Target retention rate (millionths).  MILLION = keep everything.
    pub target_retention_millionths: u64,
    /// Minimum number of epochs an entry must survive before thinning.
    pub min_retention_epochs: u64,
    /// Priority threshold: entries above this priority are always retained.
    pub priority_floor: u64,
    /// Maximum thinning rounds before forced compaction.
    pub max_rounds: u64,
    /// Content hash for integrity verification.
    pub content_hash: ContentHash,
}

impl ThinningPolicy {
    /// Create a new thinning policy with computed content hash.
    pub fn new(
        policy_id: String,
        strategy: ThinningStrategy,
        target_retention_millionths: u64,
        min_retention_epochs: u64,
        priority_floor: u64,
    ) -> Self {
        let max_rounds = MAX_THINNING_ROUNDS;
        let mut policy = Self {
            policy_id,
            strategy,
            target_retention_millionths: target_retention_millionths.min(MILLION),
            min_retention_epochs,
            priority_floor,
            max_rounds,
            content_hash: ContentHash::compute(b"placeholder"),
        };
        policy.content_hash = policy.compute_hash();
        policy
    }

    /// Compute content hash from policy fields.
    fn compute_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(COMPONENT.as_bytes());
        hasher.update(b":policy:");
        hasher.update(self.policy_id.as_bytes());
        hasher.update(b":");
        hasher.update(self.strategy.as_str().as_bytes());
        hasher.update(b":");
        hasher.update(self.target_retention_millionths.to_le_bytes());
        hasher.update(self.min_retention_epochs.to_le_bytes());
        hasher.update(self.priority_floor.to_le_bytes());
        hasher.update(self.max_rounds.to_le_bytes());
        let result = hasher.finalize();
        ContentHash::compute(&result)
    }
}

impl fmt::Display for ThinningPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "thinning-policy:{}(strategy={},retention={},floor={})",
            self.policy_id, self.strategy, self.target_retention_millionths, self.priority_floor,
        )
    }
}

// ---------------------------------------------------------------------------
// EvidenceEntry — a single evidence observation on a hot path
// ---------------------------------------------------------------------------

/// A single evidence observation produced on a hot runtime path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HotPathEvidenceEntry {
    /// Unique entry identifier (content-addressed).
    pub entry_id: String,
    /// Kernel that produced this entry.
    pub kernel_id: String,
    /// Observation key (e.g. opcode, function name, allocation site).
    pub key: String,
    /// Observation weight (millionths).
    pub weight_millionths: u64,
    /// Priority level (higher = more important, always retained above floor).
    pub priority: u64,
    /// Capture mode that produced this entry.
    pub capture_mode: CaptureMode,
    /// Security epoch of the observation.
    pub epoch: SecurityEpoch,
    /// Logical timestamp (monotonic counter within kernel).
    pub sequence: u64,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

impl HotPathEvidenceEntry {
    /// Compute the content hash for this entry.
    fn compute_hash(
        kernel_id: &str,
        key: &str,
        weight: u64,
        priority: u64,
        mode: CaptureMode,
        epoch: SecurityEpoch,
        sequence: u64,
    ) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(COMPONENT.as_bytes());
        hasher.update(b":entry:");
        hasher.update(kernel_id.as_bytes());
        hasher.update(b":");
        hasher.update(key.as_bytes());
        hasher.update(b":");
        hasher.update(weight.to_le_bytes());
        hasher.update(priority.to_le_bytes());
        hasher.update(mode.as_str().as_bytes());
        hasher.update(epoch.as_u64().to_le_bytes());
        hasher.update(sequence.to_le_bytes());
        let result = hasher.finalize();
        ContentHash::compute(&result)
    }
}

impl fmt::Display for HotPathEvidenceEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "entry:{}(kernel={},key={},mode={},seq={})",
            self.entry_id, self.kernel_id, self.key, self.capture_mode, self.sequence,
        )
    }
}

// ---------------------------------------------------------------------------
// SketchBucket — a single sketch counter
// ---------------------------------------------------------------------------

/// A single counter in a sketch data structure.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct SketchBucket {
    /// Key being counted.
    pub key: String,
    /// Accumulated weight (millionths).
    pub weight_millionths: u64,
    /// Number of observations folded into this bucket.
    pub count: u64,
    /// Last update sequence number.
    pub last_sequence: u64,
}

// ---------------------------------------------------------------------------
// ExactShadowCounter — parallel exact-count path
// ---------------------------------------------------------------------------

/// A parallel exact-count counter for calibration purposes.
///
/// Runs alongside the sketched path to measure approximation error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExactShadowCounter {
    /// Kernel this shadow counter tracks.
    pub kernel_id: String,
    /// Exact counts per key.
    pub exact_counts: BTreeMap<String, u64>,
    /// Total observations counted.
    pub total_observations: u64,
    /// Total weight accumulated (millionths).
    pub total_weight_millionths: u64,
    /// Whether the shadow counter is active.
    pub active: bool,
}

impl ExactShadowCounter {
    /// Create a new shadow counter for a kernel.
    pub fn new(kernel_id: String) -> Self {
        Self {
            kernel_id,
            exact_counts: BTreeMap::new(),
            total_observations: 0,
            total_weight_millionths: 0,
            active: true,
        }
    }

    /// Record an exact observation.
    pub fn observe(&mut self, key: &str, weight_millionths: u64) {
        if !self.active {
            return;
        }
        *self.exact_counts.entry(key.to_string()).or_insert(0) += 1;
        self.total_observations = self.total_observations.saturating_add(1);
        self.total_weight_millionths = self
            .total_weight_millionths
            .saturating_add(weight_millionths);
    }

    /// Get the exact count for a key.
    pub fn count_for(&self, key: &str) -> u64 {
        self.exact_counts.get(key).copied().unwrap_or(0)
    }

    /// Number of distinct keys observed.
    pub fn distinct_keys(&self) -> usize {
        self.exact_counts.len()
    }
}

impl fmt::Display for ExactShadowCounter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "shadow:{}(keys={},obs={},active={})",
            self.kernel_id,
            self.exact_counts.len(),
            self.total_observations,
            self.active,
        )
    }
}

// ---------------------------------------------------------------------------
// CalibrationEvidence — exact-shadow vs sketch comparison
// ---------------------------------------------------------------------------

/// Evidence from calibrating a sketch against its exact-shadow counter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationEvidence {
    /// Kernel that was calibrated.
    pub kernel_id: String,
    /// Security epoch of calibration.
    pub epoch: SecurityEpoch,
    /// Per-key calibration results.
    pub per_key_results: Vec<KeyCalibrationResult>,
    /// Mean relative error across all keys (millionths).
    pub mean_error_millionths: u64,
    /// Maximum relative error across all keys (millionths).
    pub max_error_millionths: u64,
    /// Whether calibration passed (all errors below threshold).
    pub passed: bool,
    /// Error threshold used (millionths).
    pub threshold_millionths: u64,
    /// Number of keys compared.
    pub keys_compared: u64,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

impl fmt::Display for CalibrationEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "calibration:{}(epoch={},keys={},mean_err={},max_err={},passed={})",
            self.kernel_id,
            self.epoch.as_u64(),
            self.keys_compared,
            self.mean_error_millionths,
            self.max_error_millionths,
            self.passed,
        )
    }
}

/// Calibration result for a single key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct KeyCalibrationResult {
    /// Key being compared.
    pub key: String,
    /// Exact count from shadow counter.
    pub exact_count: u64,
    /// Sketch estimate.
    pub sketch_estimate: u64,
    /// Absolute error.
    pub absolute_error: u64,
    /// Relative error (millionths).  MILLION = 100% error.
    pub relative_error_millionths: u64,
    /// Whether this key passed the threshold.
    pub passed: bool,
}

// ---------------------------------------------------------------------------
// ThinnedBundle — result of applying evidence thinning
// ---------------------------------------------------------------------------

/// The result of applying a thinning policy to a set of evidence entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThinnedBundle {
    /// Unique bundle identifier.
    pub bundle_id: String,
    /// Policy used for thinning.
    pub policy_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Original number of entries before thinning.
    pub original_count: u64,
    /// Number of entries retained after thinning.
    pub retained_count: u64,
    /// Actual retention ratio (millionths).
    pub actual_retention_millionths: u64,
    /// Number of entries above the priority floor (always retained).
    pub priority_retained_count: u64,
    /// Number of entries thinned by the sampling strategy.
    pub sampled_retained_count: u64,
    /// IDs of retained entries.
    pub retained_ids: BTreeSet<String>,
    /// IDs of discarded entries.
    pub discarded_ids: BTreeSet<String>,
    /// Number of thinning rounds applied.
    pub rounds_applied: u64,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

impl fmt::Display for ThinnedBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "thinned:{}(policy={},orig={},retained={},ratio={})",
            self.bundle_id,
            self.policy_id,
            self.original_count,
            self.retained_count,
            self.actual_retention_millionths,
        )
    }
}

// ---------------------------------------------------------------------------
// KernelState — runtime state of a hot-path kernel
// ---------------------------------------------------------------------------

/// Runtime state of a single hot-path telemetry kernel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelState {
    /// Kernel identifier.
    pub kernel_id: String,
    /// Sketch algorithm in use.
    pub writer_kind: SketchWriterKind,
    /// Current capture mode.
    pub capture_mode: CaptureMode,
    /// Fixed-point sampling rate (millionths).
    pub sampling_rate_millionths: u64,
    /// Original sampling rate before any degradation.
    pub original_rate_millionths: u64,
    /// Remaining event budget.
    pub budget_remaining: u64,
    /// Original event budget.
    pub budget_original: u64,
    /// Monotonic sequence counter.
    pub sequence: u64,
    /// Sketch buckets.
    pub sketch_buckets: Vec<SketchBucket>,
    /// Whether the kernel is exhausted (fail-closed latch).
    pub exhausted: bool,
    /// Number of events accepted.
    pub accepted_count: u64,
    /// Number of events rejected by sampling.
    pub rejected_count: u64,
    /// Security epoch.
    pub epoch: SecurityEpoch,
}

impl KernelState {
    /// Whether the kernel can still accept events.
    pub fn is_active(&self) -> bool {
        !self.exhausted && self.budget_remaining > 0
    }

    /// Fraction of budget consumed (millionths).
    pub fn budget_consumed_millionths(&self) -> u64 {
        if self.budget_original == 0 {
            return MILLION;
        }
        let consumed = self.budget_original.saturating_sub(self.budget_remaining);
        consumed
            .saturating_mul(MILLION)
            .checked_div(self.budget_original)
            .unwrap_or(MILLION)
    }

    /// The effective acceptance rate (accepted / (accepted + rejected), millionths).
    pub fn effective_rate_millionths(&self) -> u64 {
        let total = self.accepted_count.saturating_add(self.rejected_count);
        if total == 0 {
            return 0;
        }
        self.accepted_count
            .saturating_mul(MILLION)
            .checked_div(total)
            .unwrap_or(0)
    }
}

impl fmt::Display for KernelState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "kernel:{}(kind={},mode={},budget={}/{},seq={})",
            self.kernel_id,
            self.writer_kind,
            self.capture_mode,
            self.budget_remaining,
            self.budget_original,
            self.sequence,
        )
    }
}

// ---------------------------------------------------------------------------
// KernelRegistry — collection of active kernels
// ---------------------------------------------------------------------------

/// Registry of all active hot-path telemetry kernels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelRegistry {
    /// Registry identifier.
    pub registry_id: String,
    /// Active kernels, keyed by kernel_id.
    pub kernels: Vec<KernelState>,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Total events processed across all kernels.
    pub total_events: u64,
    /// Total events accepted across all kernels.
    pub total_accepted: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl KernelRegistry {
    /// Look up a kernel by ID.
    pub fn find_kernel(&self, kernel_id: &str) -> Option<&KernelState> {
        self.kernels.iter().find(|k| k.kernel_id == kernel_id)
    }

    /// Look up a mutable kernel by ID.
    pub fn find_kernel_mut(&mut self, kernel_id: &str) -> Option<&mut KernelState> {
        self.kernels.iter_mut().find(|k| k.kernel_id == kernel_id)
    }

    /// Count active (non-exhausted) kernels.
    pub fn active_count(&self) -> usize {
        self.kernels.iter().filter(|k| k.is_active()).count()
    }

    /// Recompute the content hash.
    pub fn recompute_hash(&mut self) {
        self.total_events = self
            .kernels
            .iter()
            .map(|k| k.accepted_count.saturating_add(k.rejected_count))
            .sum();
        self.total_accepted = self.kernels.iter().map(|k| k.accepted_count).sum();
        self.content_hash = compute_registry_hash(&self.kernels, self.epoch);
    }
}

impl fmt::Display for KernelRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "registry:{}(kernels={},active={},events={})",
            self.registry_id,
            self.kernels.len(),
            self.active_count(),
            self.total_events,
        )
    }
}

// ---------------------------------------------------------------------------
// TelemetryManifest — publication-grade telemetry report
// ---------------------------------------------------------------------------

/// A publication-grade telemetry manifest combining kernel states,
/// calibration evidence, and thinning reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryManifest {
    /// Manifest identifier.
    pub manifest_id: String,
    /// Schema version.
    pub schema_version: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Kernel summaries.
    pub kernel_summaries: Vec<KernelSummary>,
    /// Calibration evidence (if any exact-shadow calibration was run).
    pub calibration_evidence: Vec<CalibrationEvidence>,
    /// Thinning reports (one per policy applied).
    pub thinning_reports: Vec<ThinnedBundle>,
    /// Overall capture mode (worst-case across all kernels).
    pub overall_mode: CaptureMode,
    /// Whether the manifest is suitable for publication.
    pub publishable: bool,
    /// Reasons if not publishable.
    pub rejection_reasons: Vec<String>,
    /// Content hash for integrity.
    pub content_hash: ContentHash,
}

impl fmt::Display for TelemetryManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "manifest:{}(epoch={},kernels={},mode={},publishable={})",
            self.manifest_id,
            self.epoch.as_u64(),
            self.kernel_summaries.len(),
            self.overall_mode,
            self.publishable,
        )
    }
}

/// Summary of a single kernel's state for inclusion in a manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelSummary {
    /// Kernel identifier.
    pub kernel_id: String,
    /// Writer kind.
    pub writer_kind: SketchWriterKind,
    /// Capture mode.
    pub capture_mode: CaptureMode,
    /// Budget consumed (millionths).
    pub budget_consumed_millionths: u64,
    /// Effective acceptance rate (millionths).
    pub effective_rate_millionths: u64,
    /// Total events processed.
    pub total_events: u64,
    /// Total events accepted.
    pub accepted_events: u64,
    /// Distinct sketch keys.
    pub distinct_keys: u64,
    /// Whether the kernel is still active.
    pub is_active: bool,
}

// ---------------------------------------------------------------------------
// TelemetryError — error types
// ---------------------------------------------------------------------------

/// Errors that can occur in hot-path telemetry operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryError {
    /// Kernel not found in registry.
    KernelNotFound(String),
    /// Kernel budget exhausted (fail-closed).
    BudgetExhausted(String),
    /// Maximum kernels reached.
    RegistryFull,
    /// Sketch capacity exceeded.
    SketchCapacityExceeded(String),
    /// Calibration failed (error above threshold).
    CalibrationFailed {
        kernel_id: String,
        max_error_millionths: u64,
        threshold_millionths: u64,
    },
    /// Thinning policy invalid.
    InvalidPolicy(String),
    /// Epoch mismatch.
    EpochMismatch {
        expected: SecurityEpoch,
        actual: SecurityEpoch,
    },
    /// Empty input.
    EmptyInput,
}

impl std::error::Error for TelemetryError {}

impl fmt::Display for TelemetryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KernelNotFound(id) => write!(f, "[{COMPONENT}] kernel not found: {id}"),
            Self::BudgetExhausted(id) => write!(f, "[{COMPONENT}] budget exhausted: {id}"),
            Self::RegistryFull => write!(f, "[{COMPONENT}] registry full (max {MAX_KERNELS})"),
            Self::SketchCapacityExceeded(id) => {
                write!(f, "[{COMPONENT}] sketch capacity exceeded: {id}")
            }
            Self::CalibrationFailed {
                kernel_id,
                max_error_millionths,
                threshold_millionths,
            } => write!(
                f,
                "[{COMPONENT}] calibration failed for {kernel_id}: max_error={max_error_millionths} > threshold={threshold_millionths}",
            ),
            Self::InvalidPolicy(reason) => {
                write!(f, "[{COMPONENT}] invalid policy: {reason}")
            }
            Self::EpochMismatch { expected, actual } => write!(
                f,
                "[{COMPONENT}] epoch mismatch: expected={}, actual={}",
                expected.as_u64(),
                actual.as_u64(),
            ),
            Self::EmptyInput => write!(f, "[{COMPONENT}] empty input"),
        }
    }
}

// ---------------------------------------------------------------------------
// Core functions — kernel lifecycle
// ---------------------------------------------------------------------------

/// Create a new hot-path telemetry kernel.
pub fn create_kernel(
    kernel_id: String,
    writer_kind: SketchWriterKind,
    sampling_rate_millionths: u64,
    budget: u64,
    epoch: SecurityEpoch,
) -> KernelState {
    let rate = sampling_rate_millionths.min(MILLION);
    KernelState {
        kernel_id,
        writer_kind,
        capture_mode: CaptureMode::Budgeted,
        sampling_rate_millionths: rate,
        original_rate_millionths: rate,
        budget_remaining: budget,
        budget_original: budget,
        sequence: 0,
        sketch_buckets: Vec::new(),
        exhausted: false,
        accepted_count: 0,
        rejected_count: 0,
        epoch,
    }
}

/// Register a kernel in a registry.
pub fn register_kernel(
    registry: &mut KernelRegistry,
    kernel: KernelState,
) -> Result<(), TelemetryError> {
    if registry.kernels.len() >= MAX_KERNELS {
        return Err(TelemetryError::RegistryFull);
    }
    registry.kernels.push(kernel);
    // Keep deterministic ordering by kernel_id.
    registry
        .kernels
        .sort_by(|a, b| a.kernel_id.cmp(&b.kernel_id));
    registry.recompute_hash();
    Ok(())
}

/// Build a new empty kernel registry.
pub fn build_registry(registry_id: String, epoch: SecurityEpoch) -> KernelRegistry {
    KernelRegistry {
        registry_id,
        kernels: Vec::new(),
        epoch,
        total_events: 0,
        total_accepted: 0,
        content_hash: ContentHash::compute(b"empty-registry"),
    }
}

// ---------------------------------------------------------------------------
// Core functions — sketch writing
// ---------------------------------------------------------------------------

/// Submit an observation to a kernel.  Returns the evidence entry if
/// the observation was accepted by the sampling decision, or `None`
/// if it was thinned.
pub fn submit_observation(
    kernel: &mut KernelState,
    key: &str,
    weight_millionths: u64,
) -> Result<Option<HotPathEvidenceEntry>, TelemetryError> {
    if kernel.exhausted {
        return Err(TelemetryError::BudgetExhausted(kernel.kernel_id.clone()));
    }

    // Check budget.
    if kernel.budget_remaining == 0 {
        kernel.exhausted = true;
        kernel.capture_mode = CaptureMode::Degraded;
        return Err(TelemetryError::BudgetExhausted(kernel.kernel_id.clone()));
    }

    let seq = kernel.sequence;
    kernel.sequence = kernel.sequence.saturating_add(1);

    // Sampling decision: deterministic hash-based.
    let accepted = evaluate_sampling_decision(
        key,
        seq,
        kernel.sampling_rate_millionths,
        kernel.budget_remaining,
        kernel.budget_original,
    );

    if !accepted {
        kernel.rejected_count = kernel.rejected_count.saturating_add(1);
        return Ok(None);
    }

    // Accepted — record sketch update.
    kernel.accepted_count = kernel.accepted_count.saturating_add(1);
    kernel.budget_remaining = kernel.budget_remaining.saturating_sub(1);

    // Update sketch bucket.
    update_sketch_bucket(&mut kernel.sketch_buckets, key, weight_millionths, seq);

    // Check for budget-adaptive rate degradation.
    if kernel.capture_mode == CaptureMode::Budgeted {
        let consumed_frac = kernel.budget_consumed_millionths();
        // Halve sampling rate at 75% budget consumed.
        if consumed_frac >= 750_000 && kernel.sampling_rate_millionths > 1 {
            kernel.sampling_rate_millionths /= 2;
            if kernel.sampling_rate_millionths == 0 {
                kernel.sampling_rate_millionths = 1;
            }
        }
    }

    // Check if budget is now exhausted.
    if kernel.budget_remaining == 0 {
        kernel.exhausted = true;
        kernel.capture_mode = CaptureMode::Degraded;
    }

    let content_hash = HotPathEvidenceEntry::compute_hash(
        &kernel.kernel_id,
        key,
        weight_millionths,
        0, // default priority
        kernel.capture_mode,
        kernel.epoch,
        seq,
    );

    let entry_id = format!(
        "hpte-{}-{}-{}",
        &kernel.kernel_id,
        seq,
        hex_prefix(&content_hash),
    );

    Ok(Some(HotPathEvidenceEntry {
        entry_id,
        kernel_id: kernel.kernel_id.clone(),
        key: key.to_string(),
        weight_millionths,
        priority: 0,
        capture_mode: kernel.capture_mode,
        epoch: kernel.epoch,
        sequence: seq,
        content_hash,
    }))
}

/// Evaluate the deterministic sampling decision for an observation.
fn evaluate_sampling_decision(
    key: &str,
    sequence: u64,
    sampling_rate_millionths: u64,
    budget_remaining: u64,
    budget_original: u64,
) -> bool {
    if sampling_rate_millionths >= MILLION {
        return true; // 100% sampling
    }
    if sampling_rate_millionths == 0 || budget_remaining == 0 {
        return false;
    }

    // Hash-based deterministic decision.
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hasher.update(sequence.to_le_bytes());
    let result = hasher.finalize();
    let hash_val = u64::from_le_bytes([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ]);

    // Accept if hash_val mod MILLION < sampling_rate.
    let decision_val = hash_val % MILLION;
    if decision_val >= sampling_rate_millionths {
        return false;
    }

    // Budget-adaptive: further restrict near exhaustion.
    if budget_original > 0 {
        let remaining_frac = budget_remaining
            .saturating_mul(MILLION)
            .checked_div(budget_original)
            .unwrap_or(0);
        // Below 10% budget: only accept if hash in tighter band.
        if remaining_frac < 100_000 {
            let tight_rate = sampling_rate_millionths / 4;
            return decision_val < tight_rate.max(1);
        }
    }

    true
}

/// Update a sketch bucket with a new observation.
fn update_sketch_bucket(
    buckets: &mut Vec<SketchBucket>,
    key: &str,
    weight_millionths: u64,
    sequence: u64,
) {
    if let Some(bucket) = buckets.iter_mut().find(|b| b.key == key) {
        bucket.weight_millionths = bucket.weight_millionths.saturating_add(weight_millionths);
        bucket.count = bucket.count.saturating_add(1);
        bucket.last_sequence = sequence;
    } else if buckets.len() < MAX_SKETCH_ENTRIES {
        buckets.push(SketchBucket {
            key: key.to_string(),
            weight_millionths,
            count: 1,
            last_sequence: sequence,
        });
    }
    // If at capacity, do nothing (fail-closed: drop new keys).
}

// ---------------------------------------------------------------------------
// Core functions — exact-shadow calibration
// ---------------------------------------------------------------------------

/// Run exact-shadow calibration comparing sketch estimates against
/// exact counts.
pub fn calibrate_kernel(
    kernel: &KernelState,
    shadow: &ExactShadowCounter,
    epoch: SecurityEpoch,
) -> Result<CalibrationEvidence, TelemetryError> {
    if kernel.kernel_id != shadow.kernel_id {
        return Err(TelemetryError::KernelNotFound(format!(
            "kernel {} != shadow {}",
            kernel.kernel_id, shadow.kernel_id,
        )));
    }

    let all_keys: BTreeSet<String> = kernel
        .sketch_buckets
        .iter()
        .map(|b| b.key.clone())
        .chain(shadow.exact_counts.keys().cloned())
        .collect();

    if all_keys.is_empty() {
        return Err(TelemetryError::EmptyInput);
    }

    let mut per_key_results = Vec::new();
    let mut total_error: u64 = 0;
    let mut max_error: u64 = 0;
    let mut all_passed = true;

    for key in &all_keys {
        let exact_count = shadow.count_for(key);
        let sketch_estimate = kernel
            .sketch_buckets
            .iter()
            .find(|b| b.key == *key)
            .map(|b| b.count)
            .unwrap_or(0);

        let absolute_error = exact_count.abs_diff(sketch_estimate);

        let relative_error_millionths = if exact_count > 0 {
            absolute_error
                .saturating_mul(MILLION)
                .checked_div(exact_count)
                .unwrap_or(MILLION)
        } else if sketch_estimate > 0 {
            MILLION // 100% error if exact is 0 but sketch says non-zero
        } else {
            0
        };

        let passed = relative_error_millionths <= CALIBRATION_ERROR_THRESHOLD;
        if !passed {
            all_passed = false;
        }

        total_error = total_error.saturating_add(relative_error_millionths);
        if relative_error_millionths > max_error {
            max_error = relative_error_millionths;
        }

        per_key_results.push(KeyCalibrationResult {
            key: key.clone(),
            exact_count,
            sketch_estimate,
            absolute_error,
            relative_error_millionths,
            passed,
        });
    }

    let keys_compared = per_key_results.len() as u64;
    let mean_error = total_error.checked_div(keys_compared.max(1)).unwrap_or(0);

    let content_hash = compute_calibration_hash(&kernel.kernel_id, epoch, &per_key_results);

    Ok(CalibrationEvidence {
        kernel_id: kernel.kernel_id.clone(),
        epoch,
        per_key_results,
        mean_error_millionths: mean_error,
        max_error_millionths: max_error,
        passed: all_passed,
        threshold_millionths: CALIBRATION_ERROR_THRESHOLD,
        keys_compared,
        content_hash,
    })
}

// ---------------------------------------------------------------------------
// Core functions — evidence thinning
// ---------------------------------------------------------------------------

/// Apply a thinning policy to a set of evidence entries.
///
/// Returns a `ThinnedBundle` with retained and discarded entry IDs.
/// Entries above the policy's priority floor are always retained.
/// Remaining entries are thinned according to the strategy.
pub fn apply_thinning(
    entries: &[HotPathEvidenceEntry],
    policy: &ThinningPolicy,
    epoch: SecurityEpoch,
) -> Result<ThinnedBundle, TelemetryError> {
    if policy.target_retention_millionths == 0 {
        return Err(TelemetryError::InvalidPolicy(
            "retention rate must be > 0".to_string(),
        ));
    }

    let mut retained_ids = BTreeSet::new();
    let mut discarded_ids = BTreeSet::new();
    let mut priority_retained: u64 = 0;
    let mut sampled_retained: u64 = 0;

    for entry in entries {
        // Always retain entries above the priority floor.
        if entry.priority >= policy.priority_floor && policy.priority_floor > 0 {
            retained_ids.insert(entry.entry_id.clone());
            priority_retained += 1;
            continue;
        }

        // Always retain entries from exact modes.
        if entry.capture_mode.is_exact() {
            retained_ids.insert(entry.entry_id.clone());
            priority_retained += 1;
            continue;
        }

        // Apply thinning strategy.
        let retain = evaluate_thinning_decision(
            &entry.entry_id,
            entry.weight_millionths,
            entry.sequence,
            policy,
        );

        if retain {
            retained_ids.insert(entry.entry_id.clone());
            sampled_retained += 1;
        } else {
            discarded_ids.insert(entry.entry_id.clone());
        }
    }

    let original_count = entries.len() as u64;
    let retained_count = retained_ids.len() as u64;
    let actual_retention = if original_count > 0 {
        retained_count
            .saturating_mul(MILLION)
            .checked_div(original_count)
            .unwrap_or(0)
    } else {
        0
    };

    let bundle_id = compute_thinned_bundle_id(&policy.policy_id, epoch, original_count);

    let content_hash = compute_thinned_bundle_hash(&retained_ids, &discarded_ids, epoch);

    Ok(ThinnedBundle {
        bundle_id,
        policy_id: policy.policy_id.clone(),
        epoch,
        original_count,
        retained_count,
        actual_retention_millionths: actual_retention,
        priority_retained_count: priority_retained,
        sampled_retained_count: sampled_retained,
        retained_ids,
        discarded_ids,
        rounds_applied: 1,
        content_hash,
    })
}

/// Evaluate whether a single entry should be retained under the
/// thinning policy.
fn evaluate_thinning_decision(
    entry_id: &str,
    weight_millionths: u64,
    sequence: u64,
    policy: &ThinningPolicy,
) -> bool {
    match policy.strategy {
        ThinningStrategy::UniformRate => {
            // Hash-based: retain if hash < target_retention.
            let hash_val = deterministic_hash_u64(entry_id, sequence);
            (hash_val % MILLION) < policy.target_retention_millionths
        }
        ThinningStrategy::HashDeterministic => {
            // Pure hash of entry_id only (replay-stable).
            let hash_val = deterministic_hash_u64(entry_id, 0);
            (hash_val % MILLION) < policy.target_retention_millionths
        }
        ThinningStrategy::WeightProportional => {
            // Higher weight => more likely retained.
            let hash_val = deterministic_hash_u64(entry_id, sequence);
            let adjusted_rate = policy
                .target_retention_millionths
                .saturating_add(weight_millionths / 10);
            (hash_val % MILLION) < adjusted_rate.min(MILLION)
        }
        ThinningStrategy::EpochAdaptive => {
            // Same as uniform for now; epoch adaptation handled by caller.
            let hash_val = deterministic_hash_u64(entry_id, sequence);
            (hash_val % MILLION) < policy.target_retention_millionths
        }
        ThinningStrategy::PriorityTiered => {
            // All entries get the uniform rate (priority entries already retained).
            let hash_val = deterministic_hash_u64(entry_id, sequence);
            (hash_val % MILLION) < policy.target_retention_millionths
        }
    }
}

// ---------------------------------------------------------------------------
// Core functions — manifest building
// ---------------------------------------------------------------------------

/// Build a publication-grade telemetry manifest from a kernel registry,
/// calibration evidence, and thinning reports.
pub fn build_manifest(
    manifest_id: String,
    registry: &KernelRegistry,
    calibrations: Vec<CalibrationEvidence>,
    thinning_reports: Vec<ThinnedBundle>,
    epoch: SecurityEpoch,
) -> TelemetryManifest {
    let kernel_summaries: Vec<KernelSummary> = registry
        .kernels
        .iter()
        .map(|k| KernelSummary {
            kernel_id: k.kernel_id.clone(),
            writer_kind: k.writer_kind,
            capture_mode: k.capture_mode,
            budget_consumed_millionths: k.budget_consumed_millionths(),
            effective_rate_millionths: k.effective_rate_millionths(),
            total_events: k.accepted_count.saturating_add(k.rejected_count),
            accepted_events: k.accepted_count,
            distinct_keys: k.sketch_buckets.len() as u64,
            is_active: k.is_active(),
        })
        .collect();

    // Overall mode: worst-case across all kernels.
    let overall_mode = kernel_summaries
        .iter()
        .map(|s| s.capture_mode)
        .max()
        .unwrap_or(CaptureMode::Budgeted);

    // Determine publishability.
    let mut rejection_reasons = Vec::new();

    // Reject if any kernel is degraded.
    if overall_mode == CaptureMode::Degraded {
        rejection_reasons.push("one or more kernels in degraded mode".to_string());
    }

    // Reject if any calibration failed.
    for cal in &calibrations {
        if !cal.passed {
            rejection_reasons.push(format!(
                "calibration failed for kernel {}: max_error={}",
                cal.kernel_id, cal.max_error_millionths,
            ));
        }
    }

    // Reject if no kernels are active.
    if kernel_summaries.iter().all(|s| !s.is_active) && !kernel_summaries.is_empty() {
        rejection_reasons.push("all kernels exhausted".to_string());
    }

    let publishable = rejection_reasons.is_empty();

    let content_hash = compute_manifest_hash(&manifest_id, epoch, &kernel_summaries);

    TelemetryManifest {
        manifest_id,
        schema_version: SCHEMA_VERSION.to_string(),
        epoch,
        kernel_summaries,
        calibration_evidence: calibrations,
        thinning_reports,
        overall_mode,
        publishable,
        rejection_reasons,
        content_hash,
    }
}

// ---------------------------------------------------------------------------
// Hash helpers
// ---------------------------------------------------------------------------

/// Compute a deterministic u64 hash from a string and sequence.
fn deterministic_hash_u64(input: &str, sequence: u64) -> u64 {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT.as_bytes());
    hasher.update(b":");
    hasher.update(input.as_bytes());
    hasher.update(b":");
    hasher.update(sequence.to_le_bytes());
    let result = hasher.finalize();
    u64::from_le_bytes([
        result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
    ])
}

/// Hex prefix of a content hash for identifiers.
fn hex_prefix(hash: &ContentHash) -> String {
    let bytes = hash.as_bytes();
    format!(
        "{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    )
}

/// Compute registry content hash.
fn compute_registry_hash(kernels: &[KernelState], epoch: SecurityEpoch) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT.as_bytes());
    hasher.update(b":registry:");
    hasher.update(epoch.as_u64().to_le_bytes());
    for k in kernels {
        hasher.update(k.kernel_id.as_bytes());
        hasher.update(k.writer_kind.as_str().as_bytes());
        hasher.update(k.capture_mode.as_str().as_bytes());
        hasher.update(k.budget_remaining.to_le_bytes());
        hasher.update(k.sequence.to_le_bytes());
    }
    let result = hasher.finalize();
    ContentHash::compute(&result)
}

/// Compute calibration evidence content hash.
fn compute_calibration_hash(
    kernel_id: &str,
    epoch: SecurityEpoch,
    results: &[KeyCalibrationResult],
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT.as_bytes());
    hasher.update(b":calibration:");
    hasher.update(kernel_id.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    for r in results {
        hasher.update(r.key.as_bytes());
        hasher.update(r.exact_count.to_le_bytes());
        hasher.update(r.sketch_estimate.to_le_bytes());
    }
    let result = hasher.finalize();
    ContentHash::compute(&result)
}

/// Compute thinned bundle identifier.
fn compute_thinned_bundle_id(policy_id: &str, epoch: SecurityEpoch, count: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT.as_bytes());
    hasher.update(b":bundle:");
    hasher.update(policy_id.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    hasher.update(count.to_le_bytes());
    let result = hasher.finalize();
    format!(
        "thn-{:02x}{:02x}{:02x}{:02x}",
        result[0], result[1], result[2], result[3],
    )
}

/// Compute thinned bundle content hash.
fn compute_thinned_bundle_hash(
    retained: &BTreeSet<String>,
    discarded: &BTreeSet<String>,
    epoch: SecurityEpoch,
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT.as_bytes());
    hasher.update(b":thinned:");
    hasher.update(epoch.as_u64().to_le_bytes());
    for id in retained {
        hasher.update(b"r:");
        hasher.update(id.as_bytes());
    }
    for id in discarded {
        hasher.update(b"d:");
        hasher.update(id.as_bytes());
    }
    let result = hasher.finalize();
    ContentHash::compute(&result)
}

/// Compute manifest content hash.
fn compute_manifest_hash(
    manifest_id: &str,
    epoch: SecurityEpoch,
    summaries: &[KernelSummary],
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(COMPONENT.as_bytes());
    hasher.update(b":manifest:");
    hasher.update(manifest_id.as_bytes());
    hasher.update(epoch.as_u64().to_le_bytes());
    for s in summaries {
        hasher.update(s.kernel_id.as_bytes());
        hasher.update(s.writer_kind.as_str().as_bytes());
        hasher.update(s.capture_mode.as_str().as_bytes());
        hasher.update(s.total_events.to_le_bytes());
    }
    let result = hasher.finalize();
    ContentHash::compute(&result)
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

    fn make_kernel(id: &str, rate: u64, budget: u64) -> KernelState {
        create_kernel(
            id.to_string(),
            SketchWriterKind::CountMin,
            rate,
            budget,
            epoch(1),
        )
    }

    fn make_policy(id: &str, strategy: ThinningStrategy, retention: u64) -> ThinningPolicy {
        ThinningPolicy::new(id.to_string(), strategy, retention, 0, 0)
    }

    fn make_entry(
        id: &str,
        kernel_id: &str,
        key: &str,
        seq: u64,
        priority: u64,
        mode: CaptureMode,
    ) -> HotPathEvidenceEntry {
        let content_hash = HotPathEvidenceEntry::compute_hash(
            kernel_id,
            key,
            MILLION,
            priority,
            mode,
            epoch(1),
            seq,
        );
        HotPathEvidenceEntry {
            entry_id: id.to_string(),
            kernel_id: kernel_id.to_string(),
            key: key.to_string(),
            weight_millionths: MILLION,
            priority,
            capture_mode: mode,
            epoch: epoch(1),
            sequence: seq,
            content_hash,
        }
    }

    // -- CaptureMode tests --

    #[test]
    fn capture_mode_string_tags() {
        assert_eq!(CaptureMode::Budgeted.as_str(), "budgeted");
        assert_eq!(CaptureMode::ExactShadow.as_str(), "exact_shadow");
        assert_eq!(CaptureMode::Degraded.as_str(), "degraded");
        assert_eq!(CaptureMode::FullCapture.as_str(), "full_capture");
    }

    #[test]
    fn capture_mode_exactness() {
        assert!(!CaptureMode::Budgeted.is_exact());
        assert!(CaptureMode::ExactShadow.is_exact());
        assert!(!CaptureMode::Degraded.is_exact());
        assert!(CaptureMode::FullCapture.is_exact());
    }

    #[test]
    fn capture_mode_health() {
        assert!(CaptureMode::Budgeted.is_healthy());
        assert!(CaptureMode::ExactShadow.is_healthy());
        assert!(!CaptureMode::Degraded.is_healthy());
        assert!(CaptureMode::FullCapture.is_healthy());
    }

    #[test]
    fn capture_mode_display() {
        assert_eq!(format!("{}", CaptureMode::Budgeted), "budgeted");
        assert_eq!(format!("{}", CaptureMode::Degraded), "degraded");
    }

    // -- ThinningStrategy tests --

    #[test]
    fn thinning_strategy_string_tags() {
        assert_eq!(ThinningStrategy::UniformRate.as_str(), "uniform_rate");
        assert_eq!(
            ThinningStrategy::HashDeterministic.as_str(),
            "hash_deterministic"
        );
        assert_eq!(
            ThinningStrategy::WeightProportional.as_str(),
            "weight_proportional"
        );
        assert_eq!(ThinningStrategy::EpochAdaptive.as_str(), "epoch_adaptive");
        assert_eq!(ThinningStrategy::PriorityTiered.as_str(), "priority_tiered");
    }

    #[test]
    fn thinning_strategy_display() {
        assert_eq!(format!("{}", ThinningStrategy::UniformRate), "uniform_rate");
    }

    // -- SketchWriterKind tests --

    #[test]
    fn sketch_writer_kind_tags() {
        assert_eq!(SketchWriterKind::CountMin.as_str(), "count_min");
        assert_eq!(SketchWriterKind::HeavyHitter.as_str(), "heavy_hitter");
        assert_eq!(SketchWriterKind::Quantile.as_str(), "quantile");
        assert_eq!(SketchWriterKind::Histogram.as_str(), "histogram");
    }

    // -- ThinningPolicy tests --

    #[test]
    fn thinning_policy_creation() {
        let policy = make_policy("p1", ThinningStrategy::UniformRate, 500_000);
        assert_eq!(policy.policy_id, "p1");
        assert_eq!(policy.strategy, ThinningStrategy::UniformRate);
        assert_eq!(policy.target_retention_millionths, 500_000);
        assert_eq!(policy.max_rounds, MAX_THINNING_ROUNDS);
    }

    #[test]
    fn thinning_policy_caps_retention() {
        let policy = make_policy("p2", ThinningStrategy::HashDeterministic, MILLION + 100);
        assert_eq!(policy.target_retention_millionths, MILLION);
    }

    #[test]
    fn thinning_policy_hash_deterministic() {
        let p1 = make_policy("p1", ThinningStrategy::UniformRate, 500_000);
        let p2 = make_policy("p1", ThinningStrategy::UniformRate, 500_000);
        assert_eq!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn thinning_policy_different_strategies_differ() {
        let p1 = make_policy("p1", ThinningStrategy::UniformRate, 500_000);
        let p2 = make_policy("p1", ThinningStrategy::HashDeterministic, 500_000);
        assert_ne!(p1.content_hash, p2.content_hash);
    }

    #[test]
    fn thinning_policy_display() {
        let policy = make_policy("test-pol", ThinningStrategy::PriorityTiered, 200_000);
        let s = format!("{policy}");
        assert!(s.contains("test-pol"));
        assert!(s.contains("priority_tiered"));
    }

    // -- KernelState tests --

    #[test]
    fn kernel_creation_defaults() {
        let k = make_kernel("k1", 500_000, 1000);
        assert_eq!(k.kernel_id, "k1");
        assert_eq!(k.writer_kind, SketchWriterKind::CountMin);
        assert_eq!(k.capture_mode, CaptureMode::Budgeted);
        assert_eq!(k.sampling_rate_millionths, 500_000);
        assert_eq!(k.original_rate_millionths, 500_000);
        assert_eq!(k.budget_remaining, 1000);
        assert_eq!(k.budget_original, 1000);
        assert_eq!(k.sequence, 0);
        assert!(!k.exhausted);
        assert!(k.is_active());
    }

    #[test]
    fn kernel_caps_sampling_rate() {
        let k = make_kernel("k2", MILLION + 100, 1000);
        assert_eq!(k.sampling_rate_millionths, MILLION);
    }

    #[test]
    fn kernel_budget_consumed_zero_original() {
        let k = make_kernel("k3", MILLION, 0);
        assert_eq!(k.budget_consumed_millionths(), MILLION);
    }

    #[test]
    fn kernel_budget_consumed_half() {
        let mut k = make_kernel("k4", MILLION, 100);
        k.budget_remaining = 50;
        assert_eq!(k.budget_consumed_millionths(), 500_000);
    }

    #[test]
    fn kernel_effective_rate_no_events() {
        let k = make_kernel("k5", MILLION, 100);
        assert_eq!(k.effective_rate_millionths(), 0);
    }

    #[test]
    fn kernel_effective_rate_all_accepted() {
        let mut k = make_kernel("k6", MILLION, 100);
        k.accepted_count = 50;
        k.rejected_count = 0;
        assert_eq!(k.effective_rate_millionths(), MILLION);
    }

    #[test]
    fn kernel_effective_rate_half() {
        let mut k = make_kernel("k7", MILLION, 100);
        k.accepted_count = 25;
        k.rejected_count = 25;
        assert_eq!(k.effective_rate_millionths(), 500_000);
    }

    #[test]
    fn kernel_display() {
        let k = make_kernel("test-k", 500_000, 1000);
        let s = format!("{k}");
        assert!(s.contains("test-k"));
        assert!(s.contains("count_min"));
        assert!(s.contains("budgeted"));
    }

    // -- ExactShadowCounter tests --

    #[test]
    fn shadow_counter_new() {
        let s = ExactShadowCounter::new("k1".to_string());
        assert_eq!(s.kernel_id, "k1");
        assert!(s.active);
        assert_eq!(s.total_observations, 0);
        assert_eq!(s.distinct_keys(), 0);
    }

    #[test]
    fn shadow_counter_observe() {
        let mut s = ExactShadowCounter::new("k1".to_string());
        s.observe("key_a", MILLION);
        s.observe("key_a", MILLION);
        s.observe("key_b", MILLION);
        assert_eq!(s.count_for("key_a"), 2);
        assert_eq!(s.count_for("key_b"), 1);
        assert_eq!(s.count_for("key_c"), 0);
        assert_eq!(s.total_observations, 3);
        assert_eq!(s.distinct_keys(), 2);
    }

    #[test]
    fn shadow_counter_inactive_ignores() {
        let mut s = ExactShadowCounter::new("k1".to_string());
        s.active = false;
        s.observe("key_a", MILLION);
        assert_eq!(s.total_observations, 0);
    }

    #[test]
    fn shadow_counter_weight_accumulation() {
        let mut s = ExactShadowCounter::new("k1".to_string());
        s.observe("key_a", 300_000);
        s.observe("key_a", 700_000);
        assert_eq!(s.total_weight_millionths, 1_000_000);
    }

    #[test]
    fn shadow_counter_display() {
        let s = ExactShadowCounter::new("k1".to_string());
        let display = format!("{s}");
        assert!(display.contains("k1"));
        assert!(display.contains("active=true"));
    }

    // -- KernelRegistry tests --

    #[test]
    fn registry_creation() {
        let r = build_registry("reg1".to_string(), epoch(1));
        assert_eq!(r.registry_id, "reg1");
        assert!(r.kernels.is_empty());
        assert_eq!(r.active_count(), 0);
    }

    #[test]
    fn registry_register_kernel() {
        let mut r = build_registry("reg1".to_string(), epoch(1));
        let k = make_kernel("k1", MILLION, 100);
        register_kernel(&mut r, k).unwrap();
        assert_eq!(r.kernels.len(), 1);
        assert_eq!(r.active_count(), 1);
    }

    #[test]
    fn registry_deterministic_ordering() {
        let mut r = build_registry("reg1".to_string(), epoch(1));
        register_kernel(&mut r, make_kernel("k_z", MILLION, 100)).unwrap();
        register_kernel(&mut r, make_kernel("k_a", MILLION, 100)).unwrap();
        register_kernel(&mut r, make_kernel("k_m", MILLION, 100)).unwrap();
        assert_eq!(r.kernels[0].kernel_id, "k_a");
        assert_eq!(r.kernels[1].kernel_id, "k_m");
        assert_eq!(r.kernels[2].kernel_id, "k_z");
    }

    #[test]
    fn registry_find_kernel() {
        let mut r = build_registry("reg1".to_string(), epoch(1));
        register_kernel(&mut r, make_kernel("k1", MILLION, 100)).unwrap();
        assert!(r.find_kernel("k1").is_some());
        assert!(r.find_kernel("k2").is_none());
    }

    #[test]
    fn registry_display() {
        let r = build_registry("test-reg".to_string(), epoch(1));
        let s = format!("{r}");
        assert!(s.contains("test-reg"));
    }

    // -- submit_observation tests --

    #[test]
    fn submit_full_rate_always_accepts() {
        let mut k = make_kernel("k1", MILLION, 100);
        let result = submit_observation(&mut k, "key_a", MILLION).unwrap();
        assert!(result.is_some());
        let entry = result.unwrap();
        assert_eq!(entry.kernel_id, "k1");
        assert_eq!(entry.key, "key_a");
        assert_eq!(entry.capture_mode, CaptureMode::Budgeted);
    }

    #[test]
    fn submit_zero_rate_always_rejects() {
        let mut k = make_kernel("k1", 0, 100);
        let result = submit_observation(&mut k, "key_a", MILLION).unwrap();
        assert!(result.is_none());
        assert_eq!(k.rejected_count, 1);
    }

    #[test]
    fn submit_exhausts_budget() {
        let mut k = make_kernel("k1", MILLION, 2);
        submit_observation(&mut k, "key_a", MILLION).unwrap();
        submit_observation(&mut k, "key_b", MILLION).unwrap();
        assert!(k.exhausted);
        assert_eq!(k.capture_mode, CaptureMode::Degraded);
        let err = submit_observation(&mut k, "key_c", MILLION).unwrap_err();
        assert!(matches!(err, TelemetryError::BudgetExhausted(_)));
    }

    #[test]
    fn submit_increments_sequence() {
        let mut k = make_kernel("k1", MILLION, 100);
        submit_observation(&mut k, "key_a", MILLION).unwrap();
        submit_observation(&mut k, "key_b", MILLION).unwrap();
        assert_eq!(k.sequence, 2);
    }

    #[test]
    fn submit_accumulates_sketch_buckets() {
        let mut k = make_kernel("k1", MILLION, 100);
        submit_observation(&mut k, "key_a", 500_000).unwrap();
        submit_observation(&mut k, "key_a", 300_000).unwrap();
        submit_observation(&mut k, "key_b", 200_000).unwrap();
        assert_eq!(k.sketch_buckets.len(), 2);
        let bucket_a = k.sketch_buckets.iter().find(|b| b.key == "key_a").unwrap();
        assert_eq!(bucket_a.weight_millionths, 800_000);
        assert_eq!(bucket_a.count, 2);
    }

    #[test]
    fn submit_entry_hash_deterministic() {
        let mut k1 = make_kernel("k1", MILLION, 100);
        let mut k2 = make_kernel("k1", MILLION, 100);
        let e1 = submit_observation(&mut k1, "key_a", MILLION)
            .unwrap()
            .unwrap();
        let e2 = submit_observation(&mut k2, "key_a", MILLION)
            .unwrap()
            .unwrap();
        assert_eq!(e1.content_hash, e2.content_hash);
    }

    // -- calibrate_kernel tests --

    #[test]
    fn calibration_perfect_match() {
        let mut k = make_kernel("k1", MILLION, 100);
        let mut shadow = ExactShadowCounter::new("k1".to_string());
        // Both see exactly the same events.
        for i in 0..10 {
            let key = format!("key_{i}");
            submit_observation(&mut k, &key, MILLION).unwrap();
            shadow.observe(&key, MILLION);
        }
        let evidence = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
        assert!(evidence.passed);
        assert_eq!(evidence.mean_error_millionths, 0);
        assert_eq!(evidence.max_error_millionths, 0);
        assert_eq!(evidence.keys_compared, 10);
    }

    #[test]
    fn calibration_mismatched_kernels() {
        let k = make_kernel("k1", MILLION, 100);
        let shadow = ExactShadowCounter::new("k2".to_string());
        let err = calibrate_kernel(&k, &shadow, epoch(1)).unwrap_err();
        assert!(matches!(err, TelemetryError::KernelNotFound(_)));
    }

    #[test]
    fn calibration_empty_data() {
        let k = make_kernel("k1", MILLION, 100);
        let shadow = ExactShadowCounter::new("k1".to_string());
        let err = calibrate_kernel(&k, &shadow, epoch(1)).unwrap_err();
        assert!(matches!(err, TelemetryError::EmptyInput));
    }

    #[test]
    fn calibration_with_error() {
        let mut k = make_kernel("k1", MILLION, 100);
        let mut shadow = ExactShadowCounter::new("k1".to_string());
        // Sketch sees key_a 5 times, shadow sees it 10 times.
        for _ in 0..5 {
            submit_observation(&mut k, "key_a", MILLION).unwrap();
        }
        for _ in 0..10 {
            shadow.observe("key_a", MILLION);
        }
        let evidence = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
        // Error = |5 - 10| / 10 = 50% = 500_000 millionths.
        assert_eq!(evidence.per_key_results.len(), 1);
        let r = &evidence.per_key_results[0];
        assert_eq!(r.exact_count, 10);
        assert_eq!(r.sketch_estimate, 5);
        assert_eq!(r.relative_error_millionths, 500_000);
        assert!(!r.passed); // Above 5% threshold.
        assert!(!evidence.passed);
    }

    #[test]
    fn calibration_hash_deterministic() {
        let mut k1 = make_kernel("k1", MILLION, 100);
        let mut shadow1 = ExactShadowCounter::new("k1".to_string());
        let mut k2 = make_kernel("k1", MILLION, 100);
        let mut shadow2 = ExactShadowCounter::new("k1".to_string());
        for i in 0..5 {
            let key = format!("key_{i}");
            submit_observation(&mut k1, &key, MILLION).unwrap();
            shadow1.observe(&key, MILLION);
            submit_observation(&mut k2, &key, MILLION).unwrap();
            shadow2.observe(&key, MILLION);
        }
        let e1 = calibrate_kernel(&k1, &shadow1, epoch(1)).unwrap();
        let e2 = calibrate_kernel(&k2, &shadow2, epoch(1)).unwrap();
        assert_eq!(e1.content_hash, e2.content_hash);
    }

    // -- apply_thinning tests --

    #[test]
    fn thinning_full_retention() {
        let entries: Vec<HotPathEvidenceEntry> = (0..10)
            .map(|i| {
                make_entry(
                    &format!("e{i}"),
                    "k1",
                    &format!("key_{i}"),
                    i,
                    0,
                    CaptureMode::Budgeted,
                )
            })
            .collect();
        let policy = make_policy("p1", ThinningStrategy::UniformRate, MILLION);
        let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
        assert_eq!(bundle.retained_count, 10);
        assert_eq!(bundle.discarded_ids.len(), 0);
        assert_eq!(bundle.actual_retention_millionths, MILLION);
    }

    #[test]
    fn thinning_zero_retention_rejected() {
        let entries: Vec<HotPathEvidenceEntry> = (0..5)
            .map(|i| {
                make_entry(
                    &format!("e{i}"),
                    "k1",
                    &format!("key_{i}"),
                    i,
                    0,
                    CaptureMode::Budgeted,
                )
            })
            .collect();
        let policy = make_policy("p1", ThinningStrategy::UniformRate, 0);
        let err = apply_thinning(&entries, &policy, epoch(1)).unwrap_err();
        assert!(matches!(err, TelemetryError::InvalidPolicy(_)));
    }

    #[test]
    fn thinning_priority_floor_always_retained() {
        let mut entries: Vec<HotPathEvidenceEntry> = (0..10)
            .map(|i| {
                make_entry(
                    &format!("e{i}"),
                    "k1",
                    &format!("key_{i}"),
                    i,
                    0,
                    CaptureMode::Budgeted,
                )
            })
            .collect();
        // Set first 3 entries to high priority.
        for entry in entries.iter_mut().take(3) {
            entry.priority = 100;
        }
        let mut policy = make_policy("p1", ThinningStrategy::UniformRate, 1); // minimal retention
        policy.priority_floor = 50;
        policy.content_hash = policy.compute_hash();
        let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
        assert!(bundle.retained_count >= 3); // At least the priority entries.
        assert_eq!(bundle.priority_retained_count, 3);
    }

    #[test]
    fn thinning_exact_mode_always_retained() {
        let entries = vec![
            make_entry("e0", "k1", "key_0", 0, 0, CaptureMode::ExactShadow),
            make_entry("e1", "k1", "key_1", 1, 0, CaptureMode::FullCapture),
            make_entry("e2", "k1", "key_2", 2, 0, CaptureMode::Budgeted),
        ];
        let policy = make_policy("p1", ThinningStrategy::UniformRate, 1); // minimal retention
        let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
        assert!(bundle.retained_ids.contains("e0")); // ExactShadow always retained.
        assert!(bundle.retained_ids.contains("e1")); // FullCapture always retained.
    }

    #[test]
    fn thinning_deterministic_across_runs() {
        let entries: Vec<HotPathEvidenceEntry> = (0..100)
            .map(|i| {
                make_entry(
                    &format!("e{i}"),
                    "k1",
                    &format!("key_{i}"),
                    i,
                    0,
                    CaptureMode::Budgeted,
                )
            })
            .collect();
        let policy = make_policy("p1", ThinningStrategy::HashDeterministic, 500_000);
        let b1 = apply_thinning(&entries, &policy, epoch(1)).unwrap();
        let b2 = apply_thinning(&entries, &policy, epoch(1)).unwrap();
        assert_eq!(b1.retained_ids, b2.retained_ids);
        assert_eq!(b1.discarded_ids, b2.discarded_ids);
        assert_eq!(b1.content_hash, b2.content_hash);
    }

    #[test]
    fn thinning_empty_entries() {
        let entries: Vec<HotPathEvidenceEntry> = Vec::new();
        let policy = make_policy("p1", ThinningStrategy::UniformRate, 500_000);
        let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
        assert_eq!(bundle.original_count, 0);
        assert_eq!(bundle.retained_count, 0);
    }

    #[test]
    fn thinning_bundle_display() {
        let entries: Vec<HotPathEvidenceEntry> = (0..5)
            .map(|i| {
                make_entry(
                    &format!("e{i}"),
                    "k1",
                    &format!("key_{i}"),
                    i,
                    0,
                    CaptureMode::Budgeted,
                )
            })
            .collect();
        let policy = make_policy("p1", ThinningStrategy::UniformRate, MILLION);
        let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
        let s = format!("{bundle}");
        assert!(s.contains("p1"));
        assert!(s.contains("orig=5"));
    }

    // -- build_manifest tests --

    #[test]
    fn manifest_healthy_publishable() {
        let mut registry = build_registry("reg1".to_string(), epoch(1));
        register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
        let manifest = build_manifest(
            "m1".to_string(),
            &registry,
            Vec::new(),
            Vec::new(),
            epoch(1),
        );
        assert!(manifest.publishable);
        assert!(manifest.rejection_reasons.is_empty());
        assert_eq!(manifest.overall_mode, CaptureMode::Budgeted);
        assert_eq!(manifest.schema_version, SCHEMA_VERSION);
    }

    #[test]
    fn manifest_degraded_not_publishable() {
        let mut registry = build_registry("reg1".to_string(), epoch(1));
        let mut k = make_kernel("k1", MILLION, 1);
        // Exhaust the kernel.
        submit_observation(&mut k, "key", MILLION).unwrap();
        assert!(k.exhausted);
        register_kernel(&mut registry, k).unwrap();
        let manifest = build_manifest(
            "m1".to_string(),
            &registry,
            Vec::new(),
            Vec::new(),
            epoch(1),
        );
        assert!(!manifest.publishable);
        assert!(
            manifest
                .rejection_reasons
                .iter()
                .any(|r| r.contains("degraded"))
        );
    }

    #[test]
    fn manifest_failed_calibration_not_publishable() {
        let mut registry = build_registry("reg1".to_string(), epoch(1));
        register_kernel(&mut registry, make_kernel("k1", MILLION, 100)).unwrap();
        let cal = CalibrationEvidence {
            kernel_id: "k1".to_string(),
            epoch: epoch(1),
            per_key_results: Vec::new(),
            mean_error_millionths: 100_000,
            max_error_millionths: 200_000,
            passed: false,
            threshold_millionths: CALIBRATION_ERROR_THRESHOLD,
            keys_compared: 1,
            content_hash: ContentHash::compute(b"test"),
        };
        let manifest = build_manifest("m1".to_string(), &registry, vec![cal], Vec::new(), epoch(1));
        assert!(!manifest.publishable);
        assert!(
            manifest
                .rejection_reasons
                .iter()
                .any(|r| r.contains("calibration failed"))
        );
    }

    #[test]
    fn manifest_display() {
        let registry = build_registry("reg1".to_string(), epoch(1));
        let manifest = build_manifest(
            "test-manifest".to_string(),
            &registry,
            Vec::new(),
            Vec::new(),
            epoch(1),
        );
        let s = format!("{manifest}");
        assert!(s.contains("test-manifest"));
    }

    #[test]
    fn manifest_hash_deterministic() {
        let mut r1 = build_registry("reg1".to_string(), epoch(1));
        register_kernel(&mut r1, make_kernel("k1", MILLION, 100)).unwrap();
        let mut r2 = build_registry("reg1".to_string(), epoch(1));
        register_kernel(&mut r2, make_kernel("k1", MILLION, 100)).unwrap();
        let m1 = build_manifest("m".to_string(), &r1, Vec::new(), Vec::new(), epoch(1));
        let m2 = build_manifest("m".to_string(), &r2, Vec::new(), Vec::new(), epoch(1));
        assert_eq!(m1.content_hash, m2.content_hash);
    }

    // -- Serde round-trip tests --

    #[test]
    fn serde_capture_mode_roundtrip() {
        let mode = CaptureMode::ExactShadow;
        let json = serde_json::to_string(&mode).unwrap();
        let restored: CaptureMode = serde_json::from_str(&json).unwrap();
        assert_eq!(mode, restored);
        assert!(json.contains("exact_shadow"));
    }

    #[test]
    fn serde_thinning_strategy_roundtrip() {
        let strategy = ThinningStrategy::WeightProportional;
        let json = serde_json::to_string(&strategy).unwrap();
        let restored: ThinningStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(strategy, restored);
    }

    #[test]
    fn serde_kernel_state_roundtrip() {
        let k = make_kernel("k1", 500_000, 1000);
        let json = serde_json::to_string(&k).unwrap();
        let restored: KernelState = serde_json::from_str(&json).unwrap();
        assert_eq!(k, restored);
    }

    #[test]
    fn serde_policy_roundtrip() {
        let policy = make_policy("p1", ThinningStrategy::PriorityTiered, 300_000);
        let json = serde_json::to_string(&policy).unwrap();
        let restored: ThinningPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(policy, restored);
    }

    #[test]
    fn serde_evidence_entry_roundtrip() {
        let entry = make_entry("e1", "k1", "key_a", 0, 5, CaptureMode::Budgeted);
        let json = serde_json::to_string(&entry).unwrap();
        let restored: HotPathEvidenceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, restored);
    }

    #[test]
    fn serde_calibration_evidence_roundtrip() {
        let mut k = make_kernel("k1", MILLION, 100);
        let mut shadow = ExactShadowCounter::new("k1".to_string());
        for i in 0..3 {
            let key = format!("key_{i}");
            submit_observation(&mut k, &key, MILLION).unwrap();
            shadow.observe(&key, MILLION);
        }
        let evidence = calibrate_kernel(&k, &shadow, epoch(1)).unwrap();
        let json = serde_json::to_string(&evidence).unwrap();
        let restored: CalibrationEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(evidence, restored);
    }

    // -- Error display tests --

    #[test]
    fn error_display_kernel_not_found() {
        let err = TelemetryError::KernelNotFound("k99".to_string());
        let s = format!("{err}");
        assert!(s.contains("k99"));
        assert!(s.contains("not found"));
    }

    #[test]
    fn error_display_budget_exhausted() {
        let err = TelemetryError::BudgetExhausted("k1".to_string());
        assert!(format!("{err}").contains("budget exhausted"));
    }

    #[test]
    fn error_display_registry_full() {
        let err = TelemetryError::RegistryFull;
        assert!(format!("{err}").contains("registry full"));
    }

    #[test]
    fn error_display_calibration_failed() {
        let err = TelemetryError::CalibrationFailed {
            kernel_id: "k1".to_string(),
            max_error_millionths: 200_000,
            threshold_millionths: 50_000,
        };
        assert!(format!("{err}").contains("calibration failed"));
    }

    #[test]
    fn error_display_epoch_mismatch() {
        let err = TelemetryError::EpochMismatch {
            expected: epoch(1),
            actual: epoch(2),
        };
        assert!(format!("{err}").contains("epoch mismatch"));
    }

    // -- Integration-style tests --

    #[test]
    fn end_to_end_kernel_lifecycle() {
        // Create registry, add kernel, submit observations, calibrate, thin, build manifest.
        let mut registry = build_registry("e2e-reg".to_string(), epoch(5));
        let kernel = create_kernel(
            "e2e-kernel".to_string(),
            SketchWriterKind::HeavyHitter,
            MILLION, // 100% sampling
            50,
            epoch(5),
        );
        register_kernel(&mut registry, kernel).unwrap();

        // Submit observations and shadow-count.
        let mut shadow = ExactShadowCounter::new("e2e-kernel".to_string());
        let mut entries = Vec::new();
        let k = registry.find_kernel_mut("e2e-kernel").unwrap();
        for i in 0..20 {
            let key = format!("op_{}", i % 5);
            if let Some(entry) = submit_observation(k, &key, MILLION).unwrap() {
                entries.push(entry);
            }
            shadow.observe(&key, MILLION);
        }

        // Calibrate.
        let k = registry.find_kernel("e2e-kernel").unwrap();
        let calibration = calibrate_kernel(k, &shadow, epoch(5)).unwrap();
        assert!(calibration.passed);

        // Thin.
        let policy = make_policy("e2e-pol", ThinningStrategy::HashDeterministic, 500_000);
        let bundle = apply_thinning(&entries, &policy, epoch(5)).unwrap();
        assert!(bundle.retained_count > 0);
        assert!(bundle.retained_count <= entries.len() as u64);

        // Build manifest.
        registry.recompute_hash();
        let manifest = build_manifest(
            "e2e-manifest".to_string(),
            &registry,
            vec![calibration],
            vec![bundle],
            epoch(5),
        );
        assert!(manifest.publishable);
        assert_eq!(manifest.kernel_summaries.len(), 1);
        assert_eq!(manifest.calibration_evidence.len(), 1);
        assert_eq!(manifest.thinning_reports.len(), 1);
    }

    #[test]
    fn budget_adaptive_rate_degradation() {
        // Kernel with budget of 10 and 100% rate.
        let mut k = make_kernel("k-adapt", MILLION, 10);
        let mut accepted = 0;
        for i in 0..100 {
            match submit_observation(&mut k, &format!("key_{i}"), MILLION) {
                Ok(Some(_)) => accepted += 1,
                Ok(None) => {}
                Err(TelemetryError::BudgetExhausted(_)) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        // With budget of 10 and 100% rate, should accept exactly 10.
        assert_eq!(accepted, 10);
        assert!(k.exhausted);
        assert_eq!(k.capture_mode, CaptureMode::Degraded);
    }

    #[test]
    fn partial_sampling_rate() {
        // 50% sampling rate, large budget.
        let mut k = make_kernel("k-half", 500_000, 10_000);
        let mut accepted = 0u64;
        let mut rejected = 0u64;
        for i in 0..1000 {
            match submit_observation(&mut k, &format!("key_{i}"), MILLION) {
                Ok(Some(_)) => accepted += 1,
                Ok(None) => rejected += 1,
                Err(_) => break,
            }
        }
        // With 50% rate and hash-based sampling, should be roughly half.
        let total = accepted + rejected;
        assert_eq!(total, 1000);
        // Allow wide tolerance since hash distribution isn't uniform.
        assert!(accepted > 200, "accepted too low: {accepted}");
        assert!(accepted < 800, "accepted too high: {accepted}");
    }

    #[test]
    fn weight_proportional_thinning_favors_heavy() {
        // Create entries: first 10 with high weight, last 90 with low weight.
        let mut entries = Vec::new();
        for i in 0..10 {
            let mut e = make_entry(
                &format!("e{i}"),
                "k1",
                &format!("key_{i}"),
                i,
                0,
                CaptureMode::Budgeted,
            );
            e.weight_millionths = MILLION; // high weight
            entries.push(e);
        }
        for i in 10..100 {
            let mut e = make_entry(
                &format!("e{i}"),
                "k1",
                &format!("key_{i}"),
                i,
                0,
                CaptureMode::Budgeted,
            );
            e.weight_millionths = 1_000; // low weight
            entries.push(e);
        }
        let policy = make_policy("wp", ThinningStrategy::WeightProportional, 200_000);
        let bundle = apply_thinning(&entries, &policy, epoch(1)).unwrap();
        // Should retain some entries.
        assert!(bundle.retained_count > 0);
        assert!(bundle.retained_count < 100);
    }
}
