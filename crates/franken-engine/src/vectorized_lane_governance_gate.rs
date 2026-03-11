#![forbid(unsafe_code)]

//! Parity, skew, cold-start, and tail-risk governance gate for vectorized
//! builtin lanes.
//!
//! Implements [RGC-624C] (bead bd-1lsy.7.24.3): gates vectorized builtins on
//! parity evidence, skew measurements, tail-risk profiles, cold-start penalty,
//! and observability so the lane remains a production advantage rather than a
//! benchmark-only curiosity.
//!
//! # Design
//!
//! - `ParityEvidence` carries scalar-vs-vectorized throughput measurements.
//! - `SkewRecord` captures input-dependent performance asymmetries.
//! - `ColdStartRecord` quantifies warm-up cost.
//! - `TailRiskRecord` quantifies latency tail behaviour.
//! - `evaluate` combines all evidence into a `GateResult` with a `LaneVerdict`.
//! - `evaluate_batch` processes multiple builtin families and produces a
//!   `GateSummary` with pass-rate statistics.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-624C]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.vectorized-lane-governance-gate.v1";

/// Component name.
pub const COMPONENT: &str = "vectorized_lane_governance_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.7.24.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-624C";

/// One million — the unit for fixed-point millionths arithmetic.
const MILLION: u64 = 1_000_000;

/// Default minimum speedup fraction (millionths).
/// 1.05x = 1_050_000 means vectorized must be at least 5% faster.
const DEFAULT_MIN_SPEEDUP: u64 = 1_050_000;

/// Default maximum parity violations before rejection.
const DEFAULT_MAX_PARITY_VIOLATIONS: u64 = 5;

/// Default maximum skew fraction before flagging (millionths).
/// 200_000 = 20%.
const DEFAULT_MAX_SKEW: u64 = 200_000;

/// Default maximum cold-start penalty fraction (millionths).
/// 500_000 = 50%.
const DEFAULT_MAX_COLD_PENALTY: u64 = 500_000;

/// Default maximum tail ratio (p99/p50, millionths).
/// 3_000_000 = 3.0x.
const DEFAULT_MAX_TAIL_RATIO: u64 = 3_000_000;

/// Default minimum sample count.
const DEFAULT_MIN_SAMPLE_COUNT: u64 = 30;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn compute_content_hash(data: &[u8]) -> ContentHash {
    ContentHash::compute(data)
}

// ---------------------------------------------------------------------------
// BuiltinFamily
// ---------------------------------------------------------------------------

/// Builtin function families eligible for vectorized lane governance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinFamily {
    /// `Array.prototype.map`
    ArrayMap,
    /// `Array.prototype.filter`
    ArrayFilter,
    /// `Array.prototype.reduce` / `reduceRight`
    ArrayReduce,
    /// `String.prototype.concat`
    StringConcat,
    /// `String.prototype.search` / `includes` / `indexOf`
    StringSearch,
    /// `JSON.parse`
    JsonParse,
    /// `JSON.stringify`
    JsonStringify,
    /// `Set` operations (add, delete, has, union, intersection)
    SetOperation,
    /// `Map` operations (get, set, delete, forEach)
    MapOperation,
}

impl BuiltinFamily {
    /// All variants in declaration order.
    pub const ALL: &[Self] = &[
        Self::ArrayMap,
        Self::ArrayFilter,
        Self::ArrayReduce,
        Self::StringConcat,
        Self::StringSearch,
        Self::JsonParse,
        Self::JsonStringify,
        Self::SetOperation,
        Self::MapOperation,
    ];

    /// String tag for this family.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ArrayMap => "array_map",
            Self::ArrayFilter => "array_filter",
            Self::ArrayReduce => "array_reduce",
            Self::StringConcat => "string_concat",
            Self::StringSearch => "string_search",
            Self::JsonParse => "json_parse",
            Self::JsonStringify => "json_stringify",
            Self::SetOperation => "set_operation",
            Self::MapOperation => "map_operation",
        }
    }
}

impl fmt::Display for BuiltinFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// LaneVerdict
// ---------------------------------------------------------------------------

/// Verdict from the governance gate for a vectorized lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaneVerdict {
    /// Lane is approved for production use.
    Approved,
    /// Lane is conditionally approved (minor issues present).
    ConditionalApproval,
    /// Lane is rejected — must not be used.
    Rejected,
    /// Fallback to scalar path required.
    FallbackRequired,
}

impl LaneVerdict {
    pub const ALL: &[Self] = &[
        Self::Approved,
        Self::ConditionalApproval,
        Self::Rejected,
        Self::FallbackRequired,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::ConditionalApproval => "conditional_approval",
            Self::Rejected => "rejected",
            Self::FallbackRequired => "fallback_required",
        }
    }

    /// Whether this verdict allows the lane to be used at all.
    pub const fn allows_lane(self) -> bool {
        matches!(self, Self::Approved | Self::ConditionalApproval)
    }
}

impl fmt::Display for LaneVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SkewKind
// ---------------------------------------------------------------------------

/// Kind of performance skew observed between scalar and vectorized paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkewKind {
    /// Skew depends on input array size.
    InputSize,
    /// Skew depends on element types encountered.
    ElementType,
    /// Skew depends on data density (sparseness).
    Density,
    /// Skew depends on value distribution (e.g. sorted vs random).
    Distribution,
    /// Skew depends on memory alignment of input buffers.
    Alignment,
}

impl SkewKind {
    pub const ALL: &[Self] = &[
        Self::InputSize,
        Self::ElementType,
        Self::Density,
        Self::Distribution,
        Self::Alignment,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InputSize => "input_size",
            Self::ElementType => "element_type",
            Self::Density => "density",
            Self::Distribution => "distribution",
            Self::Alignment => "alignment",
        }
    }
}

impl fmt::Display for SkewKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ColdStartImpact
// ---------------------------------------------------------------------------

/// Impact classification for cold-start penalty.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColdStartImpact {
    /// Cold-start penalty is negligible (< 10%).
    Negligible,
    /// Cold-start penalty is moderate (10–30%).
    Moderate,
    /// Cold-start penalty is severe (30–60%).
    Severe,
    /// Cold-start penalty is prohibitive (> 60%).
    Prohibitive,
}

impl ColdStartImpact {
    pub const ALL: &[Self] = &[
        Self::Negligible,
        Self::Moderate,
        Self::Severe,
        Self::Prohibitive,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Negligible => "negligible",
            Self::Moderate => "moderate",
            Self::Severe => "severe",
            Self::Prohibitive => "prohibitive",
        }
    }

    /// Whether this impact level is acceptable for production use.
    pub const fn is_acceptable(self) -> bool {
        matches!(self, Self::Negligible | Self::Moderate)
    }
}

impl fmt::Display for ColdStartImpact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ParityEvidence
// ---------------------------------------------------------------------------

/// Evidence comparing scalar and vectorized throughput for a builtin family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityEvidence {
    /// Which builtin family was benchmarked.
    pub builtin_family: BuiltinFamily,
    /// Scalar path throughput (ops/sec, millionths).
    pub scalar_throughput: u64,
    /// Vectorized path throughput (ops/sec, millionths).
    pub vectorized_throughput: u64,
    /// Speedup fraction: vectorized / scalar (millionths).
    /// A value of 1_500_000 means 1.5x speedup.
    pub speedup_fraction: u64,
    /// Number of parity violations detected during testing.
    pub parity_violations: u64,
    /// Number of benchmark samples collected.
    pub sample_count: u64,
    /// Security epoch when evidence was collected.
    pub epoch: SecurityEpoch,
}

impl ParityEvidence {
    /// Compute speedup fraction from throughput values.
    pub fn computed_speedup(&self) -> u64 {
        if self.scalar_throughput == 0 {
            return 0;
        }
        self.vectorized_throughput
            .saturating_mul(MILLION)
            .checked_div(self.scalar_throughput)
            .unwrap_or(0)
    }

    /// Whether vectorized path is actually faster than scalar.
    pub fn is_faster(&self) -> bool {
        self.vectorized_throughput > self.scalar_throughput
    }
}

impl fmt::Display for ParityEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: speedup={} violations={} samples={}",
            self.builtin_family, self.speedup_fraction, self.parity_violations, self.sample_count
        )
    }
}

// ---------------------------------------------------------------------------
// SkewRecord
// ---------------------------------------------------------------------------

/// A measured performance skew between scalar and vectorized paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkewRecord {
    /// What kind of skew this is.
    pub kind: SkewKind,
    /// Measured skew magnitude (millionths). 0 = no skew; 1_000_000 = 100%.
    pub measured_skew: u64,
    /// Threshold above which this skew is considered problematic (millionths).
    pub threshold: u64,
    /// Human-readable explanation of the skew.
    pub explanation: String,
}

impl SkewRecord {
    /// Whether the measured skew exceeds the threshold.
    pub fn is_failing(&self) -> bool {
        self.measured_skew > self.threshold
    }
}

impl fmt::Display for SkewRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: measured={} threshold={} {}",
            self.kind,
            self.measured_skew,
            self.threshold,
            if self.is_failing() { "FAIL" } else { "ok" }
        )
    }
}

// ---------------------------------------------------------------------------
// ColdStartRecord
// ---------------------------------------------------------------------------

/// Record of cold-start penalty for a vectorized builtin lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ColdStartRecord {
    /// Which builtin family.
    pub builtin_family: BuiltinFamily,
    /// Number of iterations required to warm up the vectorized path.
    pub warmup_iterations: u64,
    /// Penalty as a fraction of steady-state throughput (millionths).
    /// 300_000 = 30% slower during cold start.
    pub cold_penalty_fraction: u64,
    /// Classified impact.
    pub impact: ColdStartImpact,
    /// Security epoch when measured.
    pub epoch: SecurityEpoch,
}

impl fmt::Display for ColdStartRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: warmup={} penalty={} impact={}",
            self.builtin_family, self.warmup_iterations, self.cold_penalty_fraction, self.impact
        )
    }
}

// ---------------------------------------------------------------------------
// TailRiskRecord
// ---------------------------------------------------------------------------

/// Tail latency profile for a vectorized builtin lane.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskRecord {
    /// p50 latency (nanoseconds).
    pub p50: u64,
    /// p99 latency (nanoseconds).
    pub p99: u64,
    /// p99.9 latency (nanoseconds).
    pub p999: u64,
    /// Maximum observed latency (nanoseconds).
    pub max: u64,
    /// Tail ratio: p99 / p50 (millionths). 2_000_000 = 2.0x.
    pub tail_ratio: u64,
}

impl TailRiskRecord {
    /// Compute tail ratio from p50 and p99.
    pub fn computed_tail_ratio(&self) -> u64 {
        if self.p50 == 0 {
            return 0;
        }
        self.p99
            .saturating_mul(MILLION)
            .checked_div(self.p50)
            .unwrap_or(0)
    }

    /// Whether the tail is within acceptable bounds.
    pub fn is_acceptable(&self, max_ratio: u64) -> bool {
        self.tail_ratio <= max_ratio
    }
}

impl fmt::Display for TailRiskRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "p50={} p99={} p999={} max={} ratio={}",
            self.p50, self.p99, self.p999, self.max, self.tail_ratio
        )
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the vectorized lane governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum speedup fraction required for approval (millionths).
    pub min_speedup_fraction: u64,
    /// Maximum parity violations before rejection.
    pub max_parity_violations: u64,
    /// Maximum skew fraction before flagging (millionths).
    pub max_skew_fraction: u64,
    /// Maximum cold-start penalty fraction (millionths).
    pub max_cold_penalty: u64,
    /// Maximum tail ratio (p99/p50, millionths).
    pub max_tail_ratio: u64,
    /// Minimum sample count for evidence to be considered valid.
    pub min_sample_count: u64,
}

impl GateConfig {
    /// Create a permissive configuration that approves everything.
    pub fn permissive() -> Self {
        Self {
            min_speedup_fraction: 0,
            max_parity_violations: u64::MAX,
            max_skew_fraction: u64::MAX,
            max_cold_penalty: u64::MAX,
            max_tail_ratio: u64::MAX,
            min_sample_count: 0,
        }
    }

    /// Create a strict configuration.
    pub fn strict() -> Self {
        Self {
            min_speedup_fraction: 1_200_000, // 1.2x minimum
            max_parity_violations: 0,
            max_skew_fraction: 100_000, // 10%
            max_cold_penalty: 200_000,  // 20%
            max_tail_ratio: 2_000_000,  // 2.0x
            min_sample_count: 100,
        }
    }
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_speedup_fraction: DEFAULT_MIN_SPEEDUP,
            max_parity_violations: DEFAULT_MAX_PARITY_VIOLATIONS,
            max_skew_fraction: DEFAULT_MAX_SKEW,
            max_cold_penalty: DEFAULT_MAX_COLD_PENALTY,
            max_tail_ratio: DEFAULT_MAX_TAIL_RATIO,
            min_sample_count: DEFAULT_MIN_SAMPLE_COUNT,
        }
    }
}

impl fmt::Display for GateConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GateConfig(speedup>={} violations<={} skew<={} cold<={} tail<={} samples>={})",
            self.min_speedup_fraction,
            self.max_parity_violations,
            self.max_skew_fraction,
            self.max_cold_penalty,
            self.max_tail_ratio,
            self.min_sample_count
        )
    }
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

/// Result of evaluating a single vectorized lane through the governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Overall verdict.
    pub verdict: LaneVerdict,
    /// Whether parity evidence passed.
    pub parity_ok: bool,
    /// Skew records that failed their thresholds.
    pub skew_records: Vec<SkewRecord>,
    /// Cold-start assessment (if available).
    pub cold_start: Option<ColdStartImpact>,
    /// Tail-risk assessment (if available).
    pub tail_risk: Option<TailRiskRecord>,
    /// Blocking reasons preventing approval.
    pub blocking_reasons: Vec<String>,
    /// Content hash of this result.
    pub receipt_hash: ContentHash,
}

impl GateResult {
    /// Whether the lane is approved (fully or conditionally).
    pub fn is_approved(&self) -> bool {
        self.verdict.allows_lane()
    }

    /// Whether the result has any blocking reasons.
    pub fn has_blockers(&self) -> bool {
        !self.blocking_reasons.is_empty()
    }
}

impl fmt::Display for GateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} parity={} skews={} blockers={}",
            self.verdict,
            if self.parity_ok { "ok" } else { "FAIL" },
            self.skew_records.len(),
            self.blocking_reasons.len()
        )
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Immutable receipt recording a governance gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Hash of this receipt.
    pub receipt_hash: ContentHash,
    /// Component that produced this receipt.
    pub component: String,
    /// Security epoch at decision time.
    pub epoch: SecurityEpoch,
    /// Verdict rendered.
    pub verdict: LaneVerdict,
    /// Hash of the underlying evidence.
    pub evidence_hash: ContentHash,
}

impl DecisionReceipt {
    /// Create a new receipt from gate evaluation artifacts.
    pub fn new(epoch: SecurityEpoch, verdict: LaneVerdict, evidence_hash: ContentHash) -> Self {
        let mut h = Sha256::new();
        h.update(COMPONENT.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(verdict.as_str().as_bytes());
        h.update(evidence_hash.as_bytes());
        let receipt_hash = compute_content_hash(&h.finalize());

        Self {
            receipt_hash,
            component: COMPONENT.to_string(),
            epoch,
            verdict,
            evidence_hash,
        }
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Receipt({} epoch={} verdict={})",
            hex_encode(&self.receipt_hash.as_bytes()[..8]),
            self.epoch.as_u64(),
            self.verdict
        )
    }
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

/// Summary statistics from a batch governance gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Total number of lanes evaluated.
    pub total: usize,
    /// Number approved outright.
    pub approved: usize,
    /// Number conditionally approved.
    pub conditional: usize,
    /// Number rejected.
    pub rejected: usize,
    /// Number requiring fallback.
    pub fallback: usize,
    /// Pass rate (approved + conditional) / total (millionths).
    pub pass_rate: u64,
}

impl GateSummary {
    /// Whether all lanes passed (approved or conditional).
    pub fn all_passed(&self) -> bool {
        self.total > 0 && self.rejected == 0 && self.fallback == 0
    }

    /// Whether any lanes were rejected.
    pub fn has_rejections(&self) -> bool {
        self.rejected > 0
    }
}

impl fmt::Display for GateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Summary(total={} approved={} conditional={} rejected={} fallback={} rate={})",
            self.total,
            self.approved,
            self.conditional,
            self.rejected,
            self.fallback,
            self.pass_rate
        )
    }
}

// ---------------------------------------------------------------------------
// Core evaluation functions
// ---------------------------------------------------------------------------

/// Evaluate parity evidence against gate configuration.
///
/// Returns `true` if parity is acceptable.
pub fn evaluate_parity(evidence: &ParityEvidence, config: &GateConfig) -> bool {
    // Must have enough samples.
    if evidence.sample_count < config.min_sample_count {
        return false;
    }
    // Must not exceed parity violation limit.
    if evidence.parity_violations > config.max_parity_violations {
        return false;
    }
    // Speedup must meet minimum threshold.
    if evidence.speedup_fraction < config.min_speedup_fraction {
        return false;
    }
    true
}

/// Evaluate skew records against gate configuration.
///
/// Returns the subset of `skew_records` that fail their thresholds
/// or exceed the global max skew fraction.
pub fn evaluate_skew(
    evidence: &ParityEvidence,
    skew_records: &[SkewRecord],
    config: &GateConfig,
) -> Vec<SkewRecord> {
    let _ = evidence; // used for context in future extensions
    skew_records
        .iter()
        .filter(|r| r.measured_skew > config.max_skew_fraction || r.is_failing())
        .cloned()
        .collect()
}

/// Evaluate cold-start penalty and classify its impact.
///
/// Returns the classified impact based on penalty fraction thresholds.
pub fn evaluate_cold_start(record: &ColdStartRecord, config: &GateConfig) -> ColdStartImpact {
    let penalty = record.cold_penalty_fraction;
    if penalty > config.max_cold_penalty {
        // If exceeds the configured max, it's at least severe.
        if penalty > 600_000 {
            ColdStartImpact::Prohibitive
        } else {
            ColdStartImpact::Severe
        }
    } else if penalty > 300_000 {
        ColdStartImpact::Severe
    } else if penalty > 100_000 {
        ColdStartImpact::Moderate
    } else {
        ColdStartImpact::Negligible
    }
}

/// Evaluate all evidence for a single vectorized lane and produce a gate result.
pub fn evaluate(
    parity: &ParityEvidence,
    skews: &[SkewRecord],
    cold_start: Option<&ColdStartRecord>,
    tail: Option<&TailRiskRecord>,
    config: &GateConfig,
) -> GateResult {
    let mut blocking_reasons: Vec<String> = Vec::new();

    // 1. Parity check.
    let parity_ok = evaluate_parity(parity, config);
    if !parity_ok {
        if parity.sample_count < config.min_sample_count {
            blocking_reasons.push(format!(
                "insufficient samples: {} < {}",
                parity.sample_count, config.min_sample_count
            ));
        }
        if parity.parity_violations > config.max_parity_violations {
            blocking_reasons.push(format!(
                "too many parity violations: {} > {}",
                parity.parity_violations, config.max_parity_violations
            ));
        }
        if parity.speedup_fraction < config.min_speedup_fraction {
            blocking_reasons.push(format!(
                "speedup too low: {} < {}",
                parity.speedup_fraction, config.min_speedup_fraction
            ));
        }
    }

    // 2. Skew check.
    let failing_skews = evaluate_skew(parity, skews, config);
    for s in &failing_skews {
        blocking_reasons.push(format!(
            "skew {} exceeds threshold: {}",
            s.kind, s.measured_skew
        ));
    }

    // 3. Cold-start check.
    let cold_impact = cold_start.map(|cs| evaluate_cold_start(cs, config));
    if let Some(impact) = cold_impact {
        if !impact.is_acceptable() {
            blocking_reasons.push(format!("cold-start impact: {impact}"));
        }
    }

    // 4. Tail-risk check.
    if let Some(t) = tail {
        if t.tail_ratio > config.max_tail_ratio {
            blocking_reasons.push(format!(
                "tail ratio {} > max {}",
                t.tail_ratio, config.max_tail_ratio
            ));
        }
    }

    // Determine verdict.
    let verdict = if blocking_reasons.is_empty() {
        LaneVerdict::Approved
    } else if !parity_ok && parity.speedup_fraction < MILLION {
        // Vectorized is actually slower — force fallback.
        LaneVerdict::FallbackRequired
    } else if blocking_reasons.len() == 1 && failing_skews.len() <= 1 && parity_ok {
        // Minor issue: conditional approval.
        LaneVerdict::ConditionalApproval
    } else if !parity_ok {
        LaneVerdict::Rejected
    } else {
        // Multiple issues but parity is ok — conditional or rejected.
        if blocking_reasons.len() <= 2 {
            LaneVerdict::ConditionalApproval
        } else {
            LaneVerdict::Rejected
        }
    };

    // Compute receipt hash.
    let mut h = Sha256::new();
    h.update(COMPONENT.as_bytes());
    h.update(parity.builtin_family.as_str().as_bytes());
    h.update(parity.epoch.as_u64().to_le_bytes());
    h.update(verdict.as_str().as_bytes());
    h.update((blocking_reasons.len() as u64).to_le_bytes());
    for r in &blocking_reasons {
        h.update(r.as_bytes());
    }
    let receipt_hash = compute_content_hash(&h.finalize());

    GateResult {
        verdict,
        parity_ok,
        skew_records: failing_skews,
        cold_start: cold_impact,
        tail_risk: tail.cloned(),
        blocking_reasons,
        receipt_hash,
    }
}

/// Evaluate a batch of vectorized lanes and produce results with summary.
pub fn evaluate_batch(
    items: &[(
        ParityEvidence,
        Vec<SkewRecord>,
        Option<ColdStartRecord>,
        Option<TailRiskRecord>,
    )],
    config: &GateConfig,
) -> (Vec<GateResult>, GateSummary) {
    let results: Vec<GateResult> = items
        .iter()
        .map(|(parity, skews, cold, tail)| {
            evaluate(parity, skews, cold.as_ref(), tail.as_ref(), config)
        })
        .collect();

    let mut approved = 0usize;
    let mut conditional = 0usize;
    let mut rejected = 0usize;
    let mut fallback = 0usize;

    for r in &results {
        match r.verdict {
            LaneVerdict::Approved => approved += 1,
            LaneVerdict::ConditionalApproval => conditional += 1,
            LaneVerdict::Rejected => rejected += 1,
            LaneVerdict::FallbackRequired => fallback += 1,
        }
    }

    let total = results.len();
    let pass_rate = (approved as u64 + conditional as u64)
        .saturating_mul(MILLION)
        .checked_div(total as u64)
        .unwrap_or(0);

    let summary = GateSummary {
        total,
        approved,
        conditional,
        rejected,
        fallback,
        pass_rate,
    };

    (results, summary)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(700)
    }

    fn good_parity() -> ParityEvidence {
        ParityEvidence {
            builtin_family: BuiltinFamily::ArrayMap,
            scalar_throughput: 1_000_000,
            vectorized_throughput: 1_500_000,
            speedup_fraction: 1_500_000, // 1.5x
            parity_violations: 0,
            sample_count: 100,
            epoch: epoch(),
        }
    }

    fn marginal_parity() -> ParityEvidence {
        ParityEvidence {
            builtin_family: BuiltinFamily::StringConcat,
            scalar_throughput: 1_000_000,
            vectorized_throughput: 1_060_000,
            speedup_fraction: 1_060_000, // 1.06x — just above default
            parity_violations: 3,
            sample_count: 50,
            epoch: epoch(),
        }
    }

    fn slow_parity() -> ParityEvidence {
        ParityEvidence {
            builtin_family: BuiltinFamily::JsonParse,
            scalar_throughput: 1_000_000,
            vectorized_throughput: 800_000,
            speedup_fraction: 800_000, // 0.8x — slower
            parity_violations: 10,
            sample_count: 100,
            epoch: epoch(),
        }
    }

    fn clean_skew() -> SkewRecord {
        SkewRecord {
            kind: SkewKind::InputSize,
            measured_skew: 50_000, // 5%
            threshold: 200_000,
            explanation: "minor input size skew".into(),
        }
    }

    fn bad_skew() -> SkewRecord {
        SkewRecord {
            kind: SkewKind::Distribution,
            measured_skew: 350_000, // 35%
            threshold: 200_000,
            explanation: "severe distribution skew".into(),
        }
    }

    fn mild_cold_start() -> ColdStartRecord {
        ColdStartRecord {
            builtin_family: BuiltinFamily::ArrayMap,
            warmup_iterations: 10,
            cold_penalty_fraction: 80_000, // 8%
            impact: ColdStartImpact::Negligible,
            epoch: epoch(),
        }
    }

    fn severe_cold_start() -> ColdStartRecord {
        ColdStartRecord {
            builtin_family: BuiltinFamily::JsonStringify,
            warmup_iterations: 500,
            cold_penalty_fraction: 550_000, // 55%
            impact: ColdStartImpact::Severe,
            epoch: epoch(),
        }
    }

    fn good_tail() -> TailRiskRecord {
        TailRiskRecord {
            p50: 100,
            p99: 200,
            p999: 400,
            max: 800,
            tail_ratio: 2_000_000, // 2.0x
        }
    }

    fn bad_tail() -> TailRiskRecord {
        TailRiskRecord {
            p50: 100,
            p99: 500,
            p999: 2_000,
            max: 10_000,
            tail_ratio: 5_000_000, // 5.0x
        }
    }

    // --- Constants ---

    #[test]
    fn schema_version_format() {
        assert!(SCHEMA_VERSION.starts_with("franken-engine."));
        assert!(SCHEMA_VERSION.contains("vectorized-lane-governance-gate"));
    }

    #[test]
    fn component_not_empty() {
        assert!(!COMPONENT.is_empty());
        assert_eq!(COMPONENT, "vectorized_lane_governance_gate");
    }

    #[test]
    fn bead_and_policy_ids() {
        assert_eq!(BEAD_ID, "bd-1lsy.7.24.3");
        assert_eq!(POLICY_ID, "RGC-624C");
    }

    #[test]
    fn million_constant() {
        assert_eq!(MILLION, 1_000_000);
    }

    // --- BuiltinFamily ---

    #[test]
    fn builtin_family_all_count() {
        assert_eq!(BuiltinFamily::ALL.len(), 9);
    }

    #[test]
    fn builtin_family_round_trip_str() {
        for family in BuiltinFamily::ALL {
            let s = family.as_str();
            assert!(!s.is_empty());
            assert_eq!(family.to_string(), s);
        }
    }

    #[test]
    fn builtin_family_serde_round_trip() {
        for family in BuiltinFamily::ALL {
            let json = serde_json::to_string(family).unwrap();
            let back: BuiltinFamily = serde_json::from_str(&json).unwrap();
            assert_eq!(*family, back);
        }
    }

    // --- LaneVerdict ---

    #[test]
    fn lane_verdict_all_count() {
        assert_eq!(LaneVerdict::ALL.len(), 4);
    }

    #[test]
    fn lane_verdict_allows_lane() {
        assert!(LaneVerdict::Approved.allows_lane());
        assert!(LaneVerdict::ConditionalApproval.allows_lane());
        assert!(!LaneVerdict::Rejected.allows_lane());
        assert!(!LaneVerdict::FallbackRequired.allows_lane());
    }

    #[test]
    fn lane_verdict_display() {
        assert_eq!(LaneVerdict::Approved.to_string(), "approved");
        assert_eq!(LaneVerdict::Rejected.to_string(), "rejected");
    }

    #[test]
    fn lane_verdict_serde_round_trip() {
        for v in LaneVerdict::ALL {
            let json = serde_json::to_string(v).unwrap();
            let back: LaneVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(*v, back);
        }
    }

    // --- SkewKind ---

    #[test]
    fn skew_kind_all_count() {
        assert_eq!(SkewKind::ALL.len(), 5);
    }

    #[test]
    fn skew_kind_display() {
        assert_eq!(SkewKind::InputSize.to_string(), "input_size");
        assert_eq!(SkewKind::Alignment.to_string(), "alignment");
    }

    // --- ColdStartImpact ---

    #[test]
    fn cold_start_impact_all_count() {
        assert_eq!(ColdStartImpact::ALL.len(), 4);
    }

    #[test]
    fn cold_start_impact_acceptability() {
        assert!(ColdStartImpact::Negligible.is_acceptable());
        assert!(ColdStartImpact::Moderate.is_acceptable());
        assert!(!ColdStartImpact::Severe.is_acceptable());
        assert!(!ColdStartImpact::Prohibitive.is_acceptable());
    }

    #[test]
    fn cold_start_impact_serde_round_trip() {
        for impact in ColdStartImpact::ALL {
            let json = serde_json::to_string(impact).unwrap();
            let back: ColdStartImpact = serde_json::from_str(&json).unwrap();
            assert_eq!(*impact, back);
        }
    }

    // --- ParityEvidence ---

    #[test]
    fn parity_evidence_computed_speedup() {
        let ev = good_parity();
        assert_eq!(ev.computed_speedup(), 1_500_000);
    }

    #[test]
    fn parity_evidence_computed_speedup_zero_scalar() {
        let mut ev = good_parity();
        ev.scalar_throughput = 0;
        assert_eq!(ev.computed_speedup(), 0);
    }

    #[test]
    fn parity_evidence_is_faster() {
        assert!(good_parity().is_faster());
        assert!(!slow_parity().is_faster());
    }

    #[test]
    fn parity_evidence_display() {
        let d = good_parity().to_string();
        assert!(d.contains("array_map"));
        assert!(d.contains("1500000"));
    }

    #[test]
    fn parity_evidence_serde_round_trip() {
        let ev = good_parity();
        let json = serde_json::to_string(&ev).unwrap();
        let back: ParityEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(ev, back);
    }

    // --- SkewRecord ---

    #[test]
    fn skew_record_is_failing() {
        assert!(!clean_skew().is_failing());
        assert!(bad_skew().is_failing());
    }

    #[test]
    fn skew_record_display() {
        let d = bad_skew().to_string();
        assert!(d.contains("FAIL"));
        let d2 = clean_skew().to_string();
        assert!(d2.contains("ok"));
    }

    // --- ColdStartRecord ---

    #[test]
    fn cold_start_record_display() {
        let d = mild_cold_start().to_string();
        assert!(d.contains("array_map"));
        assert!(d.contains("negligible"));
    }

    // --- TailRiskRecord ---

    #[test]
    fn tail_risk_computed_ratio() {
        let t = good_tail();
        assert_eq!(t.computed_tail_ratio(), 2_000_000);
    }

    #[test]
    fn tail_risk_computed_ratio_zero_p50() {
        let mut t = good_tail();
        t.p50 = 0;
        assert_eq!(t.computed_tail_ratio(), 0);
    }

    #[test]
    fn tail_risk_acceptable() {
        assert!(good_tail().is_acceptable(3_000_000));
        assert!(!bad_tail().is_acceptable(3_000_000));
    }

    #[test]
    fn tail_risk_display() {
        let d = good_tail().to_string();
        assert!(d.contains("p50=100"));
        assert!(d.contains("p99=200"));
    }

    // --- GateConfig ---

    #[test]
    fn gate_config_default() {
        let cfg = GateConfig::default();
        assert_eq!(cfg.min_speedup_fraction, DEFAULT_MIN_SPEEDUP);
        assert_eq!(cfg.max_parity_violations, DEFAULT_MAX_PARITY_VIOLATIONS);
        assert_eq!(cfg.max_skew_fraction, DEFAULT_MAX_SKEW);
        assert_eq!(cfg.max_cold_penalty, DEFAULT_MAX_COLD_PENALTY);
        assert_eq!(cfg.max_tail_ratio, DEFAULT_MAX_TAIL_RATIO);
        assert_eq!(cfg.min_sample_count, DEFAULT_MIN_SAMPLE_COUNT);
    }

    #[test]
    fn gate_config_permissive() {
        let cfg = GateConfig::permissive();
        assert_eq!(cfg.min_speedup_fraction, 0);
        assert_eq!(cfg.max_parity_violations, u64::MAX);
    }

    #[test]
    fn gate_config_strict() {
        let cfg = GateConfig::strict();
        assert!(cfg.min_speedup_fraction > DEFAULT_MIN_SPEEDUP);
        assert_eq!(cfg.max_parity_violations, 0);
    }

    #[test]
    fn gate_config_display() {
        let d = GateConfig::default().to_string();
        assert!(d.contains("GateConfig"));
        assert!(d.contains(&DEFAULT_MIN_SPEEDUP.to_string()));
    }

    // --- evaluate_parity ---

    #[test]
    fn evaluate_parity_good() {
        let cfg = GateConfig::default();
        assert!(evaluate_parity(&good_parity(), &cfg));
    }

    #[test]
    fn evaluate_parity_low_samples() {
        let cfg = GateConfig::default();
        let mut ev = good_parity();
        ev.sample_count = 5; // below 30
        assert!(!evaluate_parity(&ev, &cfg));
    }

    #[test]
    fn evaluate_parity_too_many_violations() {
        let cfg = GateConfig::default();
        let mut ev = good_parity();
        ev.parity_violations = 10;
        assert!(!evaluate_parity(&ev, &cfg));
    }

    #[test]
    fn evaluate_parity_low_speedup() {
        let cfg = GateConfig::default();
        let mut ev = good_parity();
        ev.speedup_fraction = 1_000_000; // 1.0x — no speedup
        assert!(!evaluate_parity(&ev, &cfg));
    }

    #[test]
    fn evaluate_parity_marginal() {
        let cfg = GateConfig::default();
        assert!(evaluate_parity(&marginal_parity(), &cfg));
    }

    // --- evaluate_skew ---

    #[test]
    fn evaluate_skew_no_failures() {
        let cfg = GateConfig::default();
        let failing = evaluate_skew(&good_parity(), &[clean_skew()], &cfg);
        assert!(failing.is_empty());
    }

    #[test]
    fn evaluate_skew_with_failure() {
        let cfg = GateConfig::default();
        let failing = evaluate_skew(&good_parity(), &[clean_skew(), bad_skew()], &cfg);
        assert_eq!(failing.len(), 1);
        assert_eq!(failing[0].kind, SkewKind::Distribution);
    }

    #[test]
    fn evaluate_skew_empty_records() {
        let cfg = GateConfig::default();
        let failing = evaluate_skew(&good_parity(), &[], &cfg);
        assert!(failing.is_empty());
    }

    // --- evaluate_cold_start ---

    #[test]
    fn evaluate_cold_start_negligible() {
        let cfg = GateConfig::default();
        let impact = evaluate_cold_start(&mild_cold_start(), &cfg);
        assert_eq!(impact, ColdStartImpact::Negligible);
    }

    #[test]
    fn evaluate_cold_start_severe() {
        let cfg = GateConfig::default();
        let impact = evaluate_cold_start(&severe_cold_start(), &cfg);
        assert_eq!(impact, ColdStartImpact::Severe);
    }

    #[test]
    fn evaluate_cold_start_moderate() {
        let cfg = GateConfig::default();
        let cs = ColdStartRecord {
            builtin_family: BuiltinFamily::ArrayFilter,
            warmup_iterations: 50,
            cold_penalty_fraction: 150_000, // 15%
            impact: ColdStartImpact::Moderate,
            epoch: epoch(),
        };
        assert_eq!(evaluate_cold_start(&cs, &cfg), ColdStartImpact::Moderate);
    }

    #[test]
    fn evaluate_cold_start_prohibitive() {
        let cfg = GateConfig::default();
        let cs = ColdStartRecord {
            builtin_family: BuiltinFamily::SetOperation,
            warmup_iterations: 1000,
            cold_penalty_fraction: 700_000, // 70%
            impact: ColdStartImpact::Prohibitive,
            epoch: epoch(),
        };
        assert_eq!(evaluate_cold_start(&cs, &cfg), ColdStartImpact::Prohibitive);
    }

    // --- evaluate (full) ---

    #[test]
    fn evaluate_all_clean_approved() {
        let cfg = GateConfig::default();
        let result = evaluate(
            &good_parity(),
            &[clean_skew()],
            Some(&mild_cold_start()),
            Some(&good_tail()),
            &cfg,
        );
        assert_eq!(result.verdict, LaneVerdict::Approved);
        assert!(result.parity_ok);
        assert!(result.skew_records.is_empty());
        assert!(result.blocking_reasons.is_empty());
    }

    #[test]
    fn evaluate_no_optional_evidence() {
        let cfg = GateConfig::default();
        let result = evaluate(&good_parity(), &[], None, None, &cfg);
        assert_eq!(result.verdict, LaneVerdict::Approved);
        assert!(result.cold_start.is_none());
        assert!(result.tail_risk.is_none());
    }

    #[test]
    fn evaluate_slow_parity_fallback() {
        let cfg = GateConfig::default();
        let result = evaluate(&slow_parity(), &[], None, None, &cfg);
        assert_eq!(result.verdict, LaneVerdict::FallbackRequired);
        assert!(!result.parity_ok);
        assert!(!result.blocking_reasons.is_empty());
    }

    #[test]
    fn evaluate_single_skew_conditional() {
        let cfg = GateConfig::default();
        let result = evaluate(&good_parity(), &[bad_skew()], None, None, &cfg);
        assert_eq!(result.verdict, LaneVerdict::ConditionalApproval);
        assert!(result.parity_ok);
        assert_eq!(result.skew_records.len(), 1);
    }

    #[test]
    fn evaluate_bad_tail_conditional() {
        let cfg = GateConfig::default();
        let result = evaluate(&good_parity(), &[], None, Some(&bad_tail()), &cfg);
        assert_eq!(result.verdict, LaneVerdict::ConditionalApproval);
        assert!(result.parity_ok);
        assert_eq!(result.blocking_reasons.len(), 1);
    }

    #[test]
    fn evaluate_multiple_issues_rejected() {
        let cfg = GateConfig::default();
        let result = evaluate(
            &good_parity(),
            &[bad_skew()],
            Some(&severe_cold_start()),
            Some(&bad_tail()),
            &cfg,
        );
        assert_eq!(result.verdict, LaneVerdict::Rejected);
        assert!(result.blocking_reasons.len() >= 3);
    }

    #[test]
    fn evaluate_receipt_hash_deterministic() {
        let cfg = GateConfig::default();
        let r1 = evaluate(&good_parity(), &[], None, None, &cfg);
        let r2 = evaluate(&good_parity(), &[], None, None, &cfg);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn evaluate_receipt_hash_changes_with_verdict() {
        let cfg = GateConfig::default();
        let r1 = evaluate(&good_parity(), &[], None, None, &cfg);
        let r2 = evaluate(&slow_parity(), &[], None, None, &cfg);
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn gate_result_is_approved() {
        let cfg = GateConfig::default();
        let r = evaluate(&good_parity(), &[], None, None, &cfg);
        assert!(r.is_approved());
        assert!(!r.has_blockers());
    }

    #[test]
    fn gate_result_display() {
        let cfg = GateConfig::default();
        let r = evaluate(&good_parity(), &[], None, None, &cfg);
        let d = r.to_string();
        assert!(d.contains("approved"));
        assert!(d.contains("parity=ok"));
    }

    // --- evaluate_batch ---

    #[test]
    fn evaluate_batch_all_approved() {
        let cfg = GateConfig::default();
        let items = vec![
            (
                good_parity(),
                vec![clean_skew()],
                Some(mild_cold_start()),
                Some(good_tail()),
            ),
            (marginal_parity(), vec![], None, None),
        ];
        let (results, summary) = evaluate_batch(&items, &cfg);
        assert_eq!(results.len(), 2);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.approved, 2);
        assert_eq!(summary.rejected, 0);
        assert!(summary.all_passed());
        assert_eq!(summary.pass_rate, MILLION); // 100%
    }

    #[test]
    fn evaluate_batch_mixed() {
        let cfg = GateConfig::default();
        let items = vec![
            (good_parity(), vec![], None, None),
            (slow_parity(), vec![], None, None),
        ];
        let (results, summary) = evaluate_batch(&items, &cfg);
        assert_eq!(results.len(), 2);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.approved, 1);
        assert!(summary.fallback >= 1);
        assert!(summary.has_rejections() || summary.fallback > 0);
        assert!(!summary.all_passed());
    }

    #[test]
    fn evaluate_batch_empty() {
        let cfg = GateConfig::default();
        let (results, summary) = evaluate_batch(&[], &cfg);
        assert!(results.is_empty());
        assert_eq!(summary.total, 0);
        assert_eq!(summary.pass_rate, 0);
        assert!(!summary.all_passed());
    }

    #[test]
    fn evaluate_batch_pass_rate_half() {
        let cfg = GateConfig::default();
        let items = vec![
            (good_parity(), vec![], None, None),
            (
                slow_parity(),
                vec![bad_skew()],
                Some(severe_cold_start()),
                Some(bad_tail()),
            ),
        ];
        let (_, summary) = evaluate_batch(&items, &cfg);
        assert_eq!(summary.total, 2);
        // One approved, one not => 500_000
        assert_eq!(summary.pass_rate, 500_000);
    }

    #[test]
    fn gate_summary_display() {
        let cfg = GateConfig::default();
        let (_, summary) = evaluate_batch(&[(good_parity(), vec![], None, None)], &cfg);
        let d = summary.to_string();
        assert!(d.contains("Summary"));
        assert!(d.contains("total=1"));
    }

    // --- DecisionReceipt ---

    #[test]
    fn decision_receipt_creation() {
        let evidence_hash = compute_content_hash(b"test-evidence");
        let receipt = DecisionReceipt::new(epoch(), LaneVerdict::Approved, evidence_hash);
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.verdict, LaneVerdict::Approved);
        assert_eq!(receipt.epoch, epoch());
    }

    #[test]
    fn decision_receipt_deterministic() {
        let evidence_hash = compute_content_hash(b"test-evidence");
        let r1 = DecisionReceipt::new(epoch(), LaneVerdict::Approved, evidence_hash.clone());
        let r2 = DecisionReceipt::new(epoch(), LaneVerdict::Approved, evidence_hash);
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn decision_receipt_differs_by_verdict() {
        let evidence_hash = compute_content_hash(b"test-evidence");
        let r1 = DecisionReceipt::new(epoch(), LaneVerdict::Approved, evidence_hash.clone());
        let r2 = DecisionReceipt::new(epoch(), LaneVerdict::Rejected, evidence_hash);
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn decision_receipt_display() {
        let evidence_hash = compute_content_hash(b"test-evidence");
        let receipt = DecisionReceipt::new(epoch(), LaneVerdict::Approved, evidence_hash);
        let d = receipt.to_string();
        assert!(d.contains("Receipt"));
        assert!(d.contains("700"));
        assert!(d.contains("approved"));
    }

    #[test]
    fn decision_receipt_serde_round_trip() {
        let evidence_hash = compute_content_hash(b"test-evidence");
        let receipt = DecisionReceipt::new(epoch(), LaneVerdict::Approved, evidence_hash);
        let json = serde_json::to_string(&receipt).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    // --- Hex encode ---

    #[test]
    fn hex_encode_empty() {
        assert_eq!(hex_encode(&[]), "");
    }

    #[test]
    fn hex_encode_bytes() {
        assert_eq!(hex_encode(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
