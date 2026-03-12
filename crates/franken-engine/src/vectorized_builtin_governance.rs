//! Parity, skew, and cold-start governance for vectorized builtin lanes.
//!
//! Bead: bd-1lsy.7.24.3 [RGC-624C]
//!
//! Gates vectorized builtins on parity, skew, tail-risk, cold-start, and
//! observability evidence so the lane remains an advantage instead of a
//! benchmark-only curiosity.
//!
//! # Design
//!
//! - `VectorizedLane` classifies which builtin surface is vectorized.
//! - `ParityAxis` enumerates parity dimensions (semantic, performance, etc.).
//! - `ParityResult` records the parity measurement for one axis.
//! - `SkewEntry` captures distribution skew between scalar and vectorized paths.
//! - `ColdStartEntry` records cold-start overhead for a vectorized lane.
//! - `GovernanceConfig` configures thresholds for publication.
//! - `GovernanceVerdict` is the top-level gate output.
//! - `GovernanceReceipt` is a content-hashed audit trail.
//!
//! All ratios use fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-624C]

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.vectorized-builtin-governance.v1";

/// Component name.
pub const COMPONENT: &str = "vectorized_builtin_governance";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.24.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-624C";

/// One in fixed-point millionths.
pub const FIXED_ONE: u64 = 1_000_000;

/// Default minimum parity ratio (millionths). 950_000 = 95%.
pub const DEFAULT_MIN_PARITY_MILLIONTHS: u64 = 950_000;

/// Default maximum skew (millionths). 100_000 = 10%.
pub const DEFAULT_MAX_SKEW_MILLIONTHS: u64 = 100_000;

/// Default maximum cold-start overhead (millionths). 200_000 = 20%.
pub const DEFAULT_MAX_COLD_START_OVERHEAD: u64 = 200_000;

/// Default minimum samples for statistical validity.
pub const DEFAULT_MIN_SAMPLES: u64 = 30;

/// Default maximum tail-risk regression (millionths). 50_000 = 5%.
pub const DEFAULT_MAX_TAIL_RISK_MILLIONTHS: u64 = 50_000;

/// Default minimum observability coverage (millionths). 800_000 = 80%.
pub const DEFAULT_MIN_OBSERVABILITY_COVERAGE: u64 = 800_000;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u64(buf: &mut Vec<u8>, val: u64) {
    buf.extend_from_slice(&val.to_be_bytes());
}

fn append_str(buf: &mut Vec<u8>, val: &str) {
    let bytes = val.as_bytes();
    buf.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn compute_digest(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// VectorizedLane
// ---------------------------------------------------------------------------

/// Which builtin surface has been vectorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VectorizedLane {
    /// Array.prototype.map / filter / reduce.
    ArrayHigherOrder,
    /// String search and replace.
    StringSearch,
    /// JSON parse / stringify.
    JsonCodec,
    /// TypedArray bulk operations.
    TypedArrayBulk,
    /// RegExp matching.
    RegexpMatch,
    /// Object.keys / values / entries.
    ObjectEnumeration,
    /// Set / Map iteration.
    CollectionIteration,
    /// Buffer / ArrayBuffer operations.
    BufferOps,
    /// Promise.all / Promise.allSettled.
    PromiseCombinator,
    /// Math builtins (floor, ceil, sqrt batch).
    MathBatch,
}

impl VectorizedLane {
    /// All lanes in declaration order.
    pub fn all() -> &'static [Self] {
        &[
            Self::ArrayHigherOrder,
            Self::StringSearch,
            Self::JsonCodec,
            Self::TypedArrayBulk,
            Self::RegexpMatch,
            Self::ObjectEnumeration,
            Self::CollectionIteration,
            Self::BufferOps,
            Self::PromiseCombinator,
            Self::MathBatch,
        ]
    }
}

impl fmt::Display for VectorizedLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ArrayHigherOrder => write!(f, "array_higher_order"),
            Self::StringSearch => write!(f, "string_search"),
            Self::JsonCodec => write!(f, "json_codec"),
            Self::TypedArrayBulk => write!(f, "typed_array_bulk"),
            Self::RegexpMatch => write!(f, "regexp_match"),
            Self::ObjectEnumeration => write!(f, "object_enumeration"),
            Self::CollectionIteration => write!(f, "collection_iteration"),
            Self::BufferOps => write!(f, "buffer_ops"),
            Self::PromiseCombinator => write!(f, "promise_combinator"),
            Self::MathBatch => write!(f, "math_batch"),
        }
    }
}

// ---------------------------------------------------------------------------
// ParityAxis
// ---------------------------------------------------------------------------

/// Dimension along which parity is measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityAxis {
    /// Semantic equivalence: same outputs for same inputs.
    Semantic,
    /// Performance parity: vectorized path is not slower overall.
    Performance,
    /// Memory parity: no excessive memory overhead.
    Memory,
    /// Error-path parity: exceptions/errors match scalar path.
    ErrorPath,
    /// Observable side-effect parity (e.g., getter calls, proxy traps).
    SideEffect,
    /// GC pressure parity.
    GcPressure,
}

impl fmt::Display for ParityAxis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Semantic => "semantic",
            Self::Performance => "performance",
            Self::Memory => "memory",
            Self::ErrorPath => "error_path",
            Self::SideEffect => "side_effect",
            Self::GcPressure => "gc_pressure",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// ParityResult
// ---------------------------------------------------------------------------

/// Measurement of parity on a single axis for a single lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityResult {
    /// Lane under test.
    pub lane: VectorizedLane,
    /// Axis measured.
    pub axis: ParityAxis,
    /// Parity ratio in millionths. 1_000_000 = perfect parity.
    pub parity_millionths: u64,
    /// Number of test samples.
    pub sample_count: u64,
    /// Whether this axis passes the configured threshold.
    pub passes: bool,
    /// Hash of the measurement evidence.
    pub evidence_hash: ContentHash,
}

impl ParityResult {
    /// Compute the evidence hash from measurement data.
    pub fn new(
        lane: VectorizedLane,
        axis: ParityAxis,
        parity_millionths: u64,
        sample_count: u64,
        min_parity: u64,
        min_samples: u64,
    ) -> Self {
        let passes = parity_millionths >= min_parity && sample_count >= min_samples;
        let mut buf = Vec::with_capacity(64);
        append_str(&mut buf, &lane.to_string());
        append_str(&mut buf, &axis.to_string());
        append_u64(&mut buf, parity_millionths);
        append_u64(&mut buf, sample_count);
        let evidence_hash = compute_digest(&buf);
        Self {
            lane,
            axis,
            parity_millionths,
            sample_count,
            passes,
            evidence_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// SkewEntry
// ---------------------------------------------------------------------------

/// Distribution skew between scalar and vectorized execution times.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkewEntry {
    /// Lane under test.
    pub lane: VectorizedLane,
    /// Skew magnitude in millionths. 0 = no skew.
    pub skew_millionths: u64,
    /// p50 scalar execution (ns).
    pub scalar_p50_ns: u64,
    /// p50 vectorized execution (ns).
    pub vectorized_p50_ns: u64,
    /// p99 scalar execution (ns).
    pub scalar_p99_ns: u64,
    /// p99 vectorized execution (ns).
    pub vectorized_p99_ns: u64,
    /// Sample count.
    pub sample_count: u64,
    /// Whether skew is within budget.
    pub within_budget: bool,
    /// Evidence hash.
    pub entry_hash: ContentHash,
}

impl SkewEntry {
    /// Create and compute hash.
    pub fn new(
        lane: VectorizedLane,
        skew_millionths: u64,
        scalar_p50_ns: u64,
        vectorized_p50_ns: u64,
        scalar_p99_ns: u64,
        vectorized_p99_ns: u64,
        sample_count: u64,
        max_skew: u64,
    ) -> Self {
        let within_budget = skew_millionths <= max_skew;
        let mut buf = Vec::with_capacity(80);
        append_str(&mut buf, &lane.to_string());
        append_u64(&mut buf, skew_millionths);
        append_u64(&mut buf, scalar_p50_ns);
        append_u64(&mut buf, vectorized_p50_ns);
        append_u64(&mut buf, scalar_p99_ns);
        append_u64(&mut buf, vectorized_p99_ns);
        append_u64(&mut buf, sample_count);
        let entry_hash = compute_digest(&buf);
        Self {
            lane,
            skew_millionths,
            scalar_p50_ns,
            vectorized_p50_ns,
            scalar_p99_ns,
            vectorized_p99_ns,
            sample_count,
            within_budget,
            entry_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// ColdStartEntry
// ---------------------------------------------------------------------------

/// Cold-start overhead measurement for a vectorized lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartEntry {
    /// Lane under test.
    pub lane: VectorizedLane,
    /// Cold-start time (ns).
    pub cold_ns: u64,
    /// Warm-start time (ns).
    pub warm_ns: u64,
    /// Overhead in millionths relative to warm.
    pub overhead_millionths: u64,
    /// Whether overhead is within budget.
    pub within_budget: bool,
    /// Evidence hash.
    pub entry_hash: ContentHash,
}

impl ColdStartEntry {
    /// Create with computed overhead.
    pub fn new(lane: VectorizedLane, cold_ns: u64, warm_ns: u64, max_overhead: u64) -> Self {
        let overhead_millionths = if warm_ns == 0 {
            if cold_ns == 0 { 0 } else { FIXED_ONE }
        } else {
            cold_ns.saturating_sub(warm_ns).saturating_mul(FIXED_ONE) / warm_ns
        };
        let within_budget = overhead_millionths <= max_overhead;
        let mut buf = Vec::with_capacity(40);
        append_str(&mut buf, &lane.to_string());
        append_u64(&mut buf, cold_ns);
        append_u64(&mut buf, warm_ns);
        let entry_hash = compute_digest(&buf);
        Self {
            lane,
            cold_ns,
            warm_ns,
            overhead_millionths,
            within_budget,
            entry_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// TailRiskEntry
// ---------------------------------------------------------------------------

/// Tail-risk assessment for a vectorized lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskEntry {
    /// Lane under test.
    pub lane: VectorizedLane,
    /// p99/p50 ratio in millionths for vectorized path.
    pub tail_ratio_millionths: u64,
    /// p99/p50 ratio in millionths for scalar baseline.
    pub baseline_tail_ratio_millionths: u64,
    /// Regression: how much worse is vectorized tail vs baseline tail (millionths).
    pub regression_millionths: u64,
    /// Whether regression is within budget.
    pub within_budget: bool,
    /// Sample count.
    pub sample_count: u64,
    /// Evidence hash.
    pub entry_hash: ContentHash,
}

impl TailRiskEntry {
    /// Create with computed regression.
    pub fn new(
        lane: VectorizedLane,
        tail_ratio_millionths: u64,
        baseline_tail_ratio_millionths: u64,
        sample_count: u64,
        max_regression: u64,
    ) -> Self {
        let regression_millionths =
            tail_ratio_millionths.saturating_sub(baseline_tail_ratio_millionths);
        let within_budget = regression_millionths <= max_regression;
        let mut buf = Vec::with_capacity(48);
        append_str(&mut buf, &lane.to_string());
        append_u64(&mut buf, tail_ratio_millionths);
        append_u64(&mut buf, baseline_tail_ratio_millionths);
        append_u64(&mut buf, sample_count);
        let entry_hash = compute_digest(&buf);
        Self {
            lane,
            tail_ratio_millionths,
            baseline_tail_ratio_millionths,
            regression_millionths,
            within_budget,
            sample_count,
            entry_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// ObservabilityCoverage
// ---------------------------------------------------------------------------

/// Observability coverage for a vectorized lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservabilityCoverage {
    /// Lane under test.
    pub lane: VectorizedLane,
    /// How many observable hooks are instrumented (millionths of total).
    pub coverage_millionths: u64,
    /// Total hooks.
    pub total_hooks: u64,
    /// Instrumented hooks.
    pub instrumented_hooks: u64,
    /// Whether coverage meets minimum.
    pub adequate: bool,
}

impl ObservabilityCoverage {
    /// Create with computed coverage.
    pub fn new(
        lane: VectorizedLane,
        total_hooks: u64,
        instrumented_hooks: u64,
        min_coverage: u64,
    ) -> Self {
        let coverage_millionths = if total_hooks == 0 {
            FIXED_ONE
        } else {
            instrumented_hooks.saturating_mul(FIXED_ONE) / total_hooks
        };
        let adequate = coverage_millionths >= min_coverage;
        Self {
            lane,
            coverage_millionths,
            total_hooks,
            instrumented_hooks,
            adequate,
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceConfig
// ---------------------------------------------------------------------------

/// Configurable thresholds for the vectorized builtin gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Minimum parity ratio (millionths).
    pub min_parity_millionths: u64,
    /// Maximum skew (millionths).
    pub max_skew_millionths: u64,
    /// Maximum cold-start overhead (millionths).
    pub max_cold_start_overhead: u64,
    /// Minimum samples for statistical validity.
    pub min_samples: u64,
    /// Maximum tail-risk regression (millionths).
    pub max_tail_risk_millionths: u64,
    /// Minimum observability coverage (millionths).
    pub min_observability_coverage: u64,
    /// Required lanes (empty = all).
    pub required_lanes: BTreeSet<VectorizedLane>,
    /// Required parity axes (empty = all).
    pub required_axes: BTreeSet<ParityAxis>,
}

impl GovernanceConfig {
    /// Strict configuration — no compromises.
    pub fn strict() -> Self {
        Self {
            min_parity_millionths: FIXED_ONE,
            max_skew_millionths: 50_000,
            max_cold_start_overhead: 100_000,
            min_samples: 100,
            max_tail_risk_millionths: 20_000,
            min_observability_coverage: 950_000,
            required_lanes: VectorizedLane::all().iter().copied().collect(),
            required_axes: BTreeSet::new(),
        }
    }

    /// Relaxed configuration — suitable for early development.
    pub fn relaxed() -> Self {
        Self {
            min_parity_millionths: DEFAULT_MIN_PARITY_MILLIONTHS,
            max_skew_millionths: DEFAULT_MAX_SKEW_MILLIONTHS,
            max_cold_start_overhead: DEFAULT_MAX_COLD_START_OVERHEAD,
            min_samples: DEFAULT_MIN_SAMPLES,
            max_tail_risk_millionths: DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
            min_observability_coverage: DEFAULT_MIN_OBSERVABILITY_COVERAGE,
            required_lanes: BTreeSet::new(),
            required_axes: BTreeSet::new(),
        }
    }
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self::relaxed()
    }
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

/// Top-level gate verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceVerdict {
    /// All checks pass — lane may be published.
    Approved,
    /// Parity violations detected.
    ParityViolation,
    /// Skew exceeds budget.
    SkewExceeded,
    /// Cold-start overhead too high.
    ColdStartExceeded,
    /// Tail-risk regression too high.
    TailRiskExceeded,
    /// Observability coverage insufficient.
    ObservabilityInsufficient,
    /// Required lanes missing evidence.
    InsufficientCoverage,
    /// Multiple issues detected.
    MultipleViolations,
}

impl GovernanceVerdict {
    /// Whether this verdict blocks publication.
    pub fn blocks_publication(self) -> bool {
        self != Self::Approved
    }
}

impl fmt::Display for GovernanceVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Approved => "approved",
            Self::ParityViolation => "parity_violation",
            Self::SkewExceeded => "skew_exceeded",
            Self::ColdStartExceeded => "cold_start_exceeded",
            Self::TailRiskExceeded => "tail_risk_exceeded",
            Self::ObservabilityInsufficient => "observability_insufficient",
            Self::InsufficientCoverage => "insufficient_coverage",
            Self::MultipleViolations => "multiple_violations",
        };
        write!(f, "{s}")
    }
}

// ---------------------------------------------------------------------------
// ViolationDetail
// ---------------------------------------------------------------------------

/// Detail about a single governance violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViolationDetail {
    /// Lane affected.
    pub lane: VectorizedLane,
    /// Category of violation.
    pub category: GovernanceVerdict,
    /// Human-readable summary.
    pub summary: String,
    /// Measured value (millionths).
    pub measured_millionths: u64,
    /// Threshold that was exceeded (millionths).
    pub threshold_millionths: u64,
}

// ---------------------------------------------------------------------------
// GovernanceReceipt
// ---------------------------------------------------------------------------

/// Content-hashed audit receipt for a governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceReceipt {
    /// Overall verdict.
    pub verdict: GovernanceVerdict,
    /// Epoch at evaluation time.
    pub epoch: SecurityEpoch,
    /// Lanes evaluated.
    pub lanes_evaluated: BTreeSet<VectorizedLane>,
    /// Lanes missing evidence.
    pub lanes_missing: BTreeSet<VectorizedLane>,
    /// Parity results.
    pub parity_results: Vec<ParityResult>,
    /// Skew entries.
    pub skew_entries: Vec<SkewEntry>,
    /// Cold-start entries.
    pub cold_start_entries: Vec<ColdStartEntry>,
    /// Tail-risk entries.
    pub tail_risk_entries: Vec<TailRiskEntry>,
    /// Observability coverage entries.
    pub observability_entries: Vec<ObservabilityCoverage>,
    /// All violations found.
    pub violations: Vec<ViolationDetail>,
    /// Content hash of the receipt.
    pub content_hash: ContentHash,
}

impl GovernanceReceipt {
    /// Compute the content hash from all receipt data.
    fn compute_hash(&self) -> ContentHash {
        let mut buf = Vec::with_capacity(256);
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, &format!("{}", self.verdict));
        append_u64(&mut buf, self.epoch.as_u64());
        append_u64(&mut buf, self.lanes_evaluated.len() as u64);
        for lane in &self.lanes_evaluated {
            append_str(&mut buf, &lane.to_string());
        }
        append_u64(&mut buf, self.parity_results.len() as u64);
        for p in &self.parity_results {
            buf.extend_from_slice(p.evidence_hash.as_bytes());
        }
        append_u64(&mut buf, self.skew_entries.len() as u64);
        for s in &self.skew_entries {
            buf.extend_from_slice(s.entry_hash.as_bytes());
        }
        append_u64(&mut buf, self.violations.len() as u64);
        compute_digest(&buf)
    }
}

// ---------------------------------------------------------------------------
// GovernanceEvaluator
// ---------------------------------------------------------------------------

/// Evaluates vectorized builtin governance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceEvaluator {
    /// Configuration.
    pub config: GovernanceConfig,
    /// Collected parity results.
    pub parity_results: Vec<ParityResult>,
    /// Collected skew entries.
    pub skew_entries: Vec<SkewEntry>,
    /// Collected cold-start entries.
    pub cold_start_entries: Vec<ColdStartEntry>,
    /// Collected tail-risk entries.
    pub tail_risk_entries: Vec<TailRiskEntry>,
    /// Collected observability entries.
    pub observability_entries: Vec<ObservabilityCoverage>,
}

impl GovernanceEvaluator {
    /// Create with default config.
    pub fn new(config: GovernanceConfig) -> Self {
        Self {
            config,
            parity_results: Vec::new(),
            skew_entries: Vec::new(),
            cold_start_entries: Vec::new(),
            tail_risk_entries: Vec::new(),
            observability_entries: Vec::new(),
        }
    }

    /// Add a parity result.
    pub fn add_parity(
        &mut self,
        lane: VectorizedLane,
        axis: ParityAxis,
        parity_millionths: u64,
        sample_count: u64,
    ) {
        let result = ParityResult::new(
            lane,
            axis,
            parity_millionths,
            sample_count,
            self.config.min_parity_millionths,
            self.config.min_samples,
        );
        self.parity_results.push(result);
    }

    /// Add a skew measurement.
    pub fn add_skew(
        &mut self,
        lane: VectorizedLane,
        skew_millionths: u64,
        scalar_p50_ns: u64,
        vectorized_p50_ns: u64,
        scalar_p99_ns: u64,
        vectorized_p99_ns: u64,
        sample_count: u64,
    ) {
        let entry = SkewEntry::new(
            lane,
            skew_millionths,
            scalar_p50_ns,
            vectorized_p50_ns,
            scalar_p99_ns,
            vectorized_p99_ns,
            sample_count,
            self.config.max_skew_millionths,
        );
        self.skew_entries.push(entry);
    }

    /// Add a cold-start measurement.
    pub fn add_cold_start(&mut self, lane: VectorizedLane, cold_ns: u64, warm_ns: u64) {
        let entry =
            ColdStartEntry::new(lane, cold_ns, warm_ns, self.config.max_cold_start_overhead);
        self.cold_start_entries.push(entry);
    }

    /// Add a tail-risk measurement.
    pub fn add_tail_risk(
        &mut self,
        lane: VectorizedLane,
        tail_ratio_millionths: u64,
        baseline_tail_ratio_millionths: u64,
        sample_count: u64,
    ) {
        let entry = TailRiskEntry::new(
            lane,
            tail_ratio_millionths,
            baseline_tail_ratio_millionths,
            sample_count,
            self.config.max_tail_risk_millionths,
        );
        self.tail_risk_entries.push(entry);
    }

    /// Add observability coverage.
    pub fn add_observability(
        &mut self,
        lane: VectorizedLane,
        total_hooks: u64,
        instrumented_hooks: u64,
    ) {
        let entry = ObservabilityCoverage::new(
            lane,
            total_hooks,
            instrumented_hooks,
            self.config.min_observability_coverage,
        );
        self.observability_entries.push(entry);
    }

    /// Which lanes have evidence.
    fn covered_lanes(&self) -> BTreeSet<VectorizedLane> {
        let mut lanes = BTreeSet::new();
        for p in &self.parity_results {
            lanes.insert(p.lane);
        }
        for s in &self.skew_entries {
            lanes.insert(s.lane);
        }
        for c in &self.cold_start_entries {
            lanes.insert(c.lane);
        }
        for t in &self.tail_risk_entries {
            lanes.insert(t.lane);
        }
        for o in &self.observability_entries {
            lanes.insert(o.lane);
        }
        lanes
    }

    /// Evaluate and produce a receipt.
    pub fn evaluate(&self, epoch: SecurityEpoch) -> GovernanceReceipt {
        let covered = self.covered_lanes();
        let mut violations = Vec::new();

        // Check required lane coverage.
        let mut lanes_missing = BTreeSet::new();
        for lane in &self.config.required_lanes {
            if !covered.contains(lane) {
                lanes_missing.insert(*lane);
                violations.push(ViolationDetail {
                    lane: *lane,
                    category: GovernanceVerdict::InsufficientCoverage,
                    summary: format!("No evidence for required lane {lane}"),
                    measured_millionths: 0,
                    threshold_millionths: 0,
                });
            }
        }

        // Check parity.
        for p in &self.parity_results {
            if !p.passes {
                violations.push(ViolationDetail {
                    lane: p.lane,
                    category: GovernanceVerdict::ParityViolation,
                    summary: format!(
                        "{} parity on {} = {} < {}",
                        p.axis, p.lane, p.parity_millionths, self.config.min_parity_millionths
                    ),
                    measured_millionths: p.parity_millionths,
                    threshold_millionths: self.config.min_parity_millionths,
                });
            }
        }

        // Check skew.
        for s in &self.skew_entries {
            if !s.within_budget {
                violations.push(ViolationDetail {
                    lane: s.lane,
                    category: GovernanceVerdict::SkewExceeded,
                    summary: format!(
                        "Skew on {} = {} > {}",
                        s.lane, s.skew_millionths, self.config.max_skew_millionths
                    ),
                    measured_millionths: s.skew_millionths,
                    threshold_millionths: self.config.max_skew_millionths,
                });
            }
        }

        // Check cold-start.
        for c in &self.cold_start_entries {
            if !c.within_budget {
                violations.push(ViolationDetail {
                    lane: c.lane,
                    category: GovernanceVerdict::ColdStartExceeded,
                    summary: format!(
                        "Cold-start overhead on {} = {} > {}",
                        c.lane, c.overhead_millionths, self.config.max_cold_start_overhead
                    ),
                    measured_millionths: c.overhead_millionths,
                    threshold_millionths: self.config.max_cold_start_overhead,
                });
            }
        }

        // Check tail-risk.
        for t in &self.tail_risk_entries {
            if !t.within_budget {
                violations.push(ViolationDetail {
                    lane: t.lane,
                    category: GovernanceVerdict::TailRiskExceeded,
                    summary: format!(
                        "Tail-risk regression on {} = {} > {}",
                        t.lane, t.regression_millionths, self.config.max_tail_risk_millionths
                    ),
                    measured_millionths: t.regression_millionths,
                    threshold_millionths: self.config.max_tail_risk_millionths,
                });
            }
        }

        // Check observability.
        for o in &self.observability_entries {
            if !o.adequate {
                violations.push(ViolationDetail {
                    lane: o.lane,
                    category: GovernanceVerdict::ObservabilityInsufficient,
                    summary: format!(
                        "Observability on {} = {} < {}",
                        o.lane, o.coverage_millionths, self.config.min_observability_coverage
                    ),
                    measured_millionths: o.coverage_millionths,
                    threshold_millionths: self.config.min_observability_coverage,
                });
            }
        }

        // Determine verdict.
        let verdict = if violations.is_empty() {
            GovernanceVerdict::Approved
        } else {
            let categories: BTreeSet<GovernanceVerdict> =
                violations.iter().map(|v| v.category).collect();
            if categories.len() == 1 {
                *categories.iter().next().unwrap()
            } else {
                GovernanceVerdict::MultipleViolations
            }
        };

        let mut receipt = GovernanceReceipt {
            verdict,
            epoch,
            lanes_evaluated: covered,
            lanes_missing,
            parity_results: self.parity_results.clone(),
            skew_entries: self.skew_entries.clone(),
            cold_start_entries: self.cold_start_entries.clone(),
            tail_risk_entries: self.tail_risk_entries.clone(),
            observability_entries: self.observability_entries.clone(),
            violations,
            content_hash: ContentHash::compute(b"placeholder"),
        };
        receipt.content_hash = receipt.compute_hash();
        receipt
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(42)
    }

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("vectorized-builtin-governance"));
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "vectorized_builtin_governance");
    }

    #[test]
    fn test_bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.24.3");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-624C");
    }

    #[test]
    fn test_vectorized_lane_all_count() {
        assert_eq!(VectorizedLane::all().len(), 10);
    }

    #[test]
    fn test_vectorized_lane_ordering() {
        assert!(VectorizedLane::ArrayHigherOrder < VectorizedLane::MathBatch);
    }

    #[test]
    fn test_vectorized_lane_display() {
        assert_eq!(VectorizedLane::JsonCodec.to_string(), "json_codec");
    }

    #[test]
    fn test_parity_axis_display() {
        assert_eq!(ParityAxis::Semantic.to_string(), "semantic");
        assert_eq!(ParityAxis::GcPressure.to_string(), "gc_pressure");
    }

    #[test]
    fn test_parity_result_passes() {
        let r = ParityResult::new(
            VectorizedLane::ArrayHigherOrder,
            ParityAxis::Semantic,
            FIXED_ONE,
            50,
            DEFAULT_MIN_PARITY_MILLIONTHS,
            DEFAULT_MIN_SAMPLES,
        );
        assert!(r.passes);
    }

    #[test]
    fn test_parity_result_fails_low_parity() {
        let r = ParityResult::new(
            VectorizedLane::ArrayHigherOrder,
            ParityAxis::Semantic,
            900_000,
            50,
            DEFAULT_MIN_PARITY_MILLIONTHS,
            DEFAULT_MIN_SAMPLES,
        );
        assert!(!r.passes);
    }

    #[test]
    fn test_parity_result_fails_low_samples() {
        let r = ParityResult::new(
            VectorizedLane::ArrayHigherOrder,
            ParityAxis::Semantic,
            FIXED_ONE,
            10,
            DEFAULT_MIN_PARITY_MILLIONTHS,
            DEFAULT_MIN_SAMPLES,
        );
        assert!(!r.passes);
    }

    #[test]
    fn test_parity_result_hash_deterministic() {
        let a = ParityResult::new(
            VectorizedLane::StringSearch,
            ParityAxis::Performance,
            980_000,
            100,
            DEFAULT_MIN_PARITY_MILLIONTHS,
            DEFAULT_MIN_SAMPLES,
        );
        let b = ParityResult::new(
            VectorizedLane::StringSearch,
            ParityAxis::Performance,
            980_000,
            100,
            DEFAULT_MIN_PARITY_MILLIONTHS,
            DEFAULT_MIN_SAMPLES,
        );
        assert_eq!(a.evidence_hash, b.evidence_hash);
    }

    #[test]
    fn test_skew_within_budget() {
        let s = SkewEntry::new(
            VectorizedLane::JsonCodec,
            50_000,
            1000,
            900,
            3000,
            2800,
            100,
            DEFAULT_MAX_SKEW_MILLIONTHS,
        );
        assert!(s.within_budget);
    }

    #[test]
    fn test_skew_exceeds_budget() {
        let s = SkewEntry::new(
            VectorizedLane::JsonCodec,
            200_000,
            1000,
            900,
            3000,
            2800,
            100,
            DEFAULT_MAX_SKEW_MILLIONTHS,
        );
        assert!(!s.within_budget);
    }

    #[test]
    fn test_cold_start_within_budget() {
        let c = ColdStartEntry::new(
            VectorizedLane::TypedArrayBulk,
            1200,
            1000,
            DEFAULT_MAX_COLD_START_OVERHEAD,
        );
        assert!(c.within_budget);
        assert_eq!(c.overhead_millionths, 200_000);
    }

    #[test]
    fn test_cold_start_exceeds_budget() {
        let c = ColdStartEntry::new(
            VectorizedLane::TypedArrayBulk,
            2000,
            1000,
            DEFAULT_MAX_COLD_START_OVERHEAD,
        );
        assert!(!c.within_budget);
    }

    #[test]
    fn test_cold_start_zero_warm() {
        let c = ColdStartEntry::new(
            VectorizedLane::TypedArrayBulk,
            100,
            0,
            DEFAULT_MAX_COLD_START_OVERHEAD,
        );
        assert_eq!(c.overhead_millionths, FIXED_ONE);
    }

    #[test]
    fn test_cold_start_both_zero() {
        let c = ColdStartEntry::new(
            VectorizedLane::TypedArrayBulk,
            0,
            0,
            DEFAULT_MAX_COLD_START_OVERHEAD,
        );
        assert_eq!(c.overhead_millionths, 0);
    }

    #[test]
    fn test_tail_risk_within_budget() {
        let t = TailRiskEntry::new(
            VectorizedLane::RegexpMatch,
            2_500_000,
            2_400_000,
            100,
            DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
        );
        assert!(t.within_budget);
        assert_eq!(t.regression_millionths, 100_000);
    }

    #[test]
    fn test_tail_risk_exceeds() {
        let t = TailRiskEntry::new(
            VectorizedLane::RegexpMatch,
            3_000_000,
            2_400_000,
            100,
            DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
        );
        assert!(!t.within_budget);
    }

    #[test]
    fn test_tail_risk_no_regression() {
        let t = TailRiskEntry::new(
            VectorizedLane::RegexpMatch,
            2_000_000,
            2_400_000,
            100,
            DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
        );
        assert!(t.within_budget);
        assert_eq!(t.regression_millionths, 0);
    }

    #[test]
    fn test_observability_adequate() {
        let o = ObservabilityCoverage::new(
            VectorizedLane::BufferOps,
            100,
            90,
            DEFAULT_MIN_OBSERVABILITY_COVERAGE,
        );
        assert!(o.adequate);
        assert_eq!(o.coverage_millionths, 900_000);
    }

    #[test]
    fn test_observability_inadequate() {
        let o = ObservabilityCoverage::new(
            VectorizedLane::BufferOps,
            100,
            50,
            DEFAULT_MIN_OBSERVABILITY_COVERAGE,
        );
        assert!(!o.adequate);
    }

    #[test]
    fn test_observability_zero_hooks() {
        let o = ObservabilityCoverage::new(
            VectorizedLane::BufferOps,
            0,
            0,
            DEFAULT_MIN_OBSERVABILITY_COVERAGE,
        );
        assert!(o.adequate);
        assert_eq!(o.coverage_millionths, FIXED_ONE);
    }

    #[test]
    fn test_config_strict() {
        let c = GovernanceConfig::strict();
        assert_eq!(c.min_parity_millionths, FIXED_ONE);
        assert_eq!(c.required_lanes.len(), 10);
    }

    #[test]
    fn test_config_relaxed() {
        let c = GovernanceConfig::relaxed();
        assert!(c.min_parity_millionths < FIXED_ONE);
        assert!(c.required_lanes.is_empty());
    }

    #[test]
    fn test_verdict_blocks_publication() {
        assert!(!GovernanceVerdict::Approved.blocks_publication());
        assert!(GovernanceVerdict::ParityViolation.blocks_publication());
        assert!(GovernanceVerdict::MultipleViolations.blocks_publication());
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(GovernanceVerdict::Approved.to_string(), "approved");
        assert_eq!(GovernanceVerdict::SkewExceeded.to_string(), "skew_exceeded");
    }

    #[test]
    fn test_evaluator_empty_approved() {
        let eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
        assert!(receipt.violations.is_empty());
    }

    #[test]
    fn test_evaluator_all_passing() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_parity(
            VectorizedLane::ArrayHigherOrder,
            ParityAxis::Semantic,
            980_000,
            50,
        );
        eval.add_skew(
            VectorizedLane::ArrayHigherOrder,
            30_000,
            1000,
            900,
            3000,
            2800,
            50,
        );
        eval.add_cold_start(VectorizedLane::ArrayHigherOrder, 1100, 1000);
        eval.add_tail_risk(VectorizedLane::ArrayHigherOrder, 2_100_000, 2_100_000, 50);
        eval.add_observability(VectorizedLane::ArrayHigherOrder, 10, 9);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
    }

    #[test]
    fn test_evaluator_parity_violation() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_parity(
            VectorizedLane::StringSearch,
            ParityAxis::Semantic,
            800_000,
            50,
        );
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::ParityViolation);
        assert_eq!(receipt.violations.len(), 1);
    }

    #[test]
    fn test_evaluator_skew_violation() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_skew(
            VectorizedLane::JsonCodec,
            200_000,
            1000,
            900,
            3000,
            2800,
            50,
        );
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::SkewExceeded);
    }

    #[test]
    fn test_evaluator_multiple_violations() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_parity(
            VectorizedLane::StringSearch,
            ParityAxis::Semantic,
            800_000,
            50,
        );
        eval.add_skew(
            VectorizedLane::JsonCodec,
            200_000,
            1000,
            900,
            3000,
            2800,
            50,
        );
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
    }

    #[test]
    fn test_evaluator_missing_required_lanes() {
        let mut config = GovernanceConfig::relaxed();
        config.required_lanes.insert(VectorizedLane::MathBatch);
        let eval = GovernanceEvaluator::new(config);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
        assert!(receipt.lanes_missing.contains(&VectorizedLane::MathBatch));
    }

    #[test]
    fn test_evaluator_covered_lanes() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_parity(
            VectorizedLane::ArrayHigherOrder,
            ParityAxis::Semantic,
            FIXED_ONE,
            50,
        );
        eval.add_skew(
            VectorizedLane::StringSearch,
            10_000,
            500,
            400,
            1500,
            1400,
            50,
        );
        let receipt = eval.evaluate(epoch());
        assert!(
            receipt
                .lanes_evaluated
                .contains(&VectorizedLane::ArrayHigherOrder)
        );
        assert!(
            receipt
                .lanes_evaluated
                .contains(&VectorizedLane::StringSearch)
        );
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_parity(
            VectorizedLane::ArrayHigherOrder,
            ParityAxis::Semantic,
            FIXED_ONE,
            50,
        );
        let r1 = eval.evaluate(epoch());
        let r2 = eval.evaluate(epoch());
        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_receipt_hash_changes_with_data() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        let r1 = eval.evaluate(epoch());
        eval.add_parity(
            VectorizedLane::ArrayHigherOrder,
            ParityAxis::Semantic,
            FIXED_ONE,
            50,
        );
        let r2 = eval.evaluate(epoch());
        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_cold_start_violation() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_cold_start(VectorizedLane::RegexpMatch, 5000, 1000);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::ColdStartExceeded);
    }

    #[test]
    fn test_tail_risk_violation() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_tail_risk(
            VectorizedLane::CollectionIteration,
            3_000_000,
            2_000_000,
            50,
        );
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::TailRiskExceeded);
    }

    #[test]
    fn test_observability_violation() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_observability(VectorizedLane::PromiseCombinator, 100, 20);
        let receipt = eval.evaluate(epoch());
        assert_eq!(
            receipt.verdict,
            GovernanceVerdict::ObservabilityInsufficient
        );
    }

    #[test]
    fn test_strict_config_requires_all_lanes() {
        let config = GovernanceConfig::strict();
        let eval = GovernanceEvaluator::new(config);
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::InsufficientCoverage);
        assert_eq!(receipt.lanes_missing.len(), 10);
    }

    #[test]
    fn test_e2e_full_pass_relaxed() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        for lane in VectorizedLane::all() {
            eval.add_parity(*lane, ParityAxis::Semantic, 960_000, 50);
            eval.add_parity(*lane, ParityAxis::Performance, 970_000, 50);
            eval.add_skew(*lane, 30_000, 1000, 900, 3000, 2800, 50);
            eval.add_cold_start(*lane, 1100, 1000);
            eval.add_tail_risk(*lane, 2_100_000, 2_100_000, 50);
            eval.add_observability(*lane, 10, 9);
        }
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::Approved);
        assert!(receipt.violations.is_empty());
        assert_eq!(receipt.lanes_evaluated.len(), 10);
    }

    #[test]
    fn test_e2e_mixed_pass_fail() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        // One lane passes, another fails parity
        eval.add_parity(
            VectorizedLane::ArrayHigherOrder,
            ParityAxis::Semantic,
            FIXED_ONE,
            100,
        );
        eval.add_parity(
            VectorizedLane::StringSearch,
            ParityAxis::Semantic,
            500_000,
            100,
        );
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.verdict, GovernanceVerdict::ParityViolation);
        assert_eq!(receipt.violations.len(), 1);
        assert_eq!(receipt.violations[0].lane, VectorizedLane::StringSearch);
    }

    #[test]
    fn test_violation_detail_contents() {
        let mut eval = GovernanceEvaluator::new(GovernanceConfig::relaxed());
        eval.add_skew(
            VectorizedLane::MathBatch,
            150_000,
            1000,
            900,
            3000,
            2800,
            50,
        );
        let receipt = eval.evaluate(epoch());
        assert_eq!(receipt.violations.len(), 1);
        let v = &receipt.violations[0];
        assert_eq!(v.lane, VectorizedLane::MathBatch);
        assert_eq!(v.category, GovernanceVerdict::SkewExceeded);
        assert_eq!(v.measured_millionths, 150_000);
        assert_eq!(v.threshold_millionths, DEFAULT_MAX_SKEW_MILLIONTHS);
    }
}
