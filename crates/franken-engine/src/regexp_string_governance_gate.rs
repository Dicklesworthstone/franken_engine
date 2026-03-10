#![forbid(unsafe_code)]

//! String/RegExp parity, Unicode, and benchmark governance gate.
//!
//! Bead: bd-1lsy.4.12.3 [RGC-312C]
//!
//! Gates string and RegExp support on parity, Unicode, tail-risk, benchmark,
//! and observability evidence so the runtime never publishes a fake win on
//! one of the most workload-dominant surfaces.
//!
//! # Design
//!
//! - `StringSurface` / `RegExpSurface` enumerate the API surfaces under governance.
//! - `StringParityEvidence` / `RegExpParityEvidence` carry per-surface test evidence.
//! - `BenchmarkEvidence` carries throughput and speedup measurements.
//! - `TailRiskRecord` captures latency tail risk (p99, p999, max).
//! - `evaluate` merges all evidence channels into a single `GateResult`.
//!
//! All arithmetic uses fixed-point millionths (1_000_000 = 1.0).
//!
//! Reference: [RGC-312C]

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.regexp-string-governance-gate.v1";

/// Component name.
pub const COMPONENT: &str = "regexp_string_governance_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.4.12.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-312C";

/// Fixed-point one (1.0 = 1_000_000).
pub const FIXED_ONE: u64 = 1_000_000;

/// Default minimum parity fraction (95% = 950_000).
pub const DEFAULT_MIN_PARITY_FRACTION: u64 = 950_000;

/// Default maximum tail ratio (2.0 = 2_000_000).
pub const DEFAULT_MAX_TAIL_RATIO: u64 = 2_000_000;

/// Default minimum test count per surface.
pub const DEFAULT_MIN_TEST_COUNT: u64 = 100;

/// Default minimum speedup to make a shipped claim (5% = 50_000).
pub const DEFAULT_MIN_SPEEDUP_FOR_CLAIM: u64 = 50_000;

/// Default maximum known gaps before blocking.
pub const DEFAULT_MAX_KNOWN_GAPS: usize = 3;

// ---------------------------------------------------------------------------
// StringSurface
// ---------------------------------------------------------------------------

/// String API surface under governance.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum StringSurface {
    /// String concatenation.
    Concat,
    /// Substring / slice.
    Slice,
    /// String search (indexOf, includes, startsWith, endsWith).
    Search,
    /// String replace / replaceAll.
    Replace,
    /// String split.
    Split,
    /// Template literal interpolation.
    Template,
    /// Unicode normalization (NFC, NFD, NFKC, NFKD).
    Normalize,
    /// Locale-aware comparison (localeCompare).
    Compare,
}

impl StringSurface {
    pub const ALL: &[Self] = &[
        Self::Concat,
        Self::Slice,
        Self::Search,
        Self::Replace,
        Self::Split,
        Self::Template,
        Self::Normalize,
        Self::Compare,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Concat => "concat",
            Self::Slice => "slice",
            Self::Search => "search",
            Self::Replace => "replace",
            Self::Split => "split",
            Self::Template => "template",
            Self::Normalize => "normalize",
            Self::Compare => "compare",
        }
    }
}

impl fmt::Display for StringSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RegExpSurface
// ---------------------------------------------------------------------------

/// RegExp feature surface under governance.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RegExpSurface {
    /// Literal character matching.
    Literal,
    /// Character classes ([a-z], \d, \w, etc.).
    CharClass,
    /// Quantifiers (*, +, ?, {n,m}).
    Quantifier,
    /// Back-references (\1, \2).
    Backreference,
    /// Lookahead assertions (?=...), (?!...).
    Lookahead,
    /// Lookbehind assertions (?<=...), (?<!...).
    Lookbehind,
    /// Unicode property escapes (\p{...}).
    UnicodeProperty,
    /// Named capture groups (?<name>...).
    NamedGroup,
}

impl RegExpSurface {
    pub const ALL: &[Self] = &[
        Self::Literal,
        Self::CharClass,
        Self::Quantifier,
        Self::Backreference,
        Self::Lookahead,
        Self::Lookbehind,
        Self::UnicodeProperty,
        Self::NamedGroup,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::CharClass => "char_class",
            Self::Quantifier => "quantifier",
            Self::Backreference => "backreference",
            Self::Lookahead => "lookahead",
            Self::Lookbehind => "lookbehind",
            Self::UnicodeProperty => "unicode_property",
            Self::NamedGroup => "named_group",
        }
    }
}

impl fmt::Display for RegExpSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ParityVerdict
// ---------------------------------------------------------------------------

/// Verdict on parity between engine and reference implementation.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum ParityVerdict {
    /// Every test passed — full behavioral parity.
    FullParity,
    /// Most tests pass but minor gaps remain.
    PartialParity,
    /// Known semantic gaps that may affect workloads.
    KnownGap,
    /// Insufficient evidence to make a parity claim.
    FailOpen,
}

impl ParityVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullParity => "full_parity",
            Self::PartialParity => "partial_parity",
            Self::KnownGap => "known_gap",
            Self::FailOpen => "fail_open",
        }
    }

    /// Whether this verdict allows shipping.
    pub const fn allows_ship(self) -> bool {
        matches!(self, Self::FullParity | Self::PartialParity)
    }
}

impl fmt::Display for ParityVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// UnicodeCompliance
// ---------------------------------------------------------------------------

/// Level of Unicode compliance for a RegExp surface.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum UnicodeCompliance {
    /// Full Unicode support including supplementary planes.
    FullCompliant,
    /// Basic Multilingual Plane only (U+0000..U+FFFF).
    Bmp,
    /// ASCII only (U+0000..U+007F).
    AsciiOnly,
    /// Non-compliant — known Unicode bugs.
    NonCompliant,
}

impl UnicodeCompliance {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FullCompliant => "full_compliant",
            Self::Bmp => "bmp",
            Self::AsciiOnly => "ascii_only",
            Self::NonCompliant => "non_compliant",
        }
    }

    /// Numeric rank for comparison (higher = better).
    pub const fn rank(self) -> u8 {
        match self {
            Self::FullCompliant => 3,
            Self::Bmp => 2,
            Self::AsciiOnly => 1,
            Self::NonCompliant => 0,
        }
    }

    /// Whether this compliance level meets a minimum requirement.
    pub fn meets_minimum(self, minimum: Self) -> bool {
        self.rank() >= minimum.rank()
    }
}

impl fmt::Display for UnicodeCompliance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateDecision
// ---------------------------------------------------------------------------

/// Decision from the governance gate.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    /// Evidence supports shipping this lane.
    Ship,
    /// Ship with conditions (e.g., known gaps documented).
    ConditionalShip,
    /// Block shipping — evidence is insufficient or negative.
    Block,
    /// Need more evidence before a decision can be made.
    RequireEvidence,
}

impl GateDecision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ship => "ship",
            Self::ConditionalShip => "conditional_ship",
            Self::Block => "block",
            Self::RequireEvidence => "require_evidence",
        }
    }

    /// Whether this decision allows the lane to proceed.
    pub const fn allows_proceed(self) -> bool {
        matches!(self, Self::Ship | Self::ConditionalShip)
    }
}

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// StringParityEvidence
// ---------------------------------------------------------------------------

/// Evidence for string surface parity between engine and reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringParityEvidence {
    /// Which string surface this evidence covers.
    pub surface: StringSurface,
    /// Total number of parity tests executed.
    pub test_count: u64,
    /// Number of tests that passed.
    pub pass_count: u64,
    /// Parity fraction (millionths, pass_count / test_count).
    pub parity_fraction: u64,
    /// Known semantic gaps.
    pub known_gaps: Vec<String>,
    /// Epoch when evidence was collected.
    pub epoch: SecurityEpoch,
}

impl StringParityEvidence {
    /// Create new evidence, computing parity fraction from counts.
    pub fn new(
        surface: StringSurface,
        test_count: u64,
        pass_count: u64,
        known_gaps: Vec<String>,
        epoch: SecurityEpoch,
    ) -> Self {
        let parity_fraction = if test_count == 0 {
            0
        } else {
            pass_count.saturating_mul(FIXED_ONE) / test_count
        };
        Self {
            surface,
            test_count,
            pass_count,
            parity_fraction,
            known_gaps,
            epoch,
        }
    }
}

impl fmt::Display for StringParityEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "string[{}]: {}/{} parity={} gaps={}",
            self.surface,
            self.pass_count,
            self.test_count,
            self.parity_fraction,
            self.known_gaps.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// RegExpParityEvidence
// ---------------------------------------------------------------------------

/// Evidence for RegExp surface parity between engine and reference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegExpParityEvidence {
    /// Which RegExp surface this evidence covers.
    pub surface: RegExpSurface,
    /// Total number of parity tests executed.
    pub test_count: u64,
    /// Number of tests that passed.
    pub pass_count: u64,
    /// Parity fraction (millionths).
    pub parity_fraction: u64,
    /// Number of automata states exercised.
    pub automata_states_tested: u64,
    /// Unicode compliance level observed.
    pub unicode_coverage: UnicodeCompliance,
    /// Epoch when evidence was collected.
    pub epoch: SecurityEpoch,
}

impl RegExpParityEvidence {
    /// Create new evidence, computing parity fraction from counts.
    pub fn new(
        surface: RegExpSurface,
        test_count: u64,
        pass_count: u64,
        automata_states_tested: u64,
        unicode_coverage: UnicodeCompliance,
        epoch: SecurityEpoch,
    ) -> Self {
        let parity_fraction = if test_count == 0 {
            0
        } else {
            pass_count.saturating_mul(FIXED_ONE) / test_count
        };
        Self {
            surface,
            test_count,
            pass_count,
            parity_fraction,
            automata_states_tested,
            unicode_coverage,
            epoch,
        }
    }
}

impl fmt::Display for RegExpParityEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "regexp[{}]: {}/{} parity={} states={} unicode={}",
            self.surface,
            self.pass_count,
            self.test_count,
            self.parity_fraction,
            self.automata_states_tested,
            self.unicode_coverage,
        )
    }
}

// ---------------------------------------------------------------------------
// BenchmarkEvidence
// ---------------------------------------------------------------------------

/// Benchmark throughput and speedup evidence for a surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkEvidence {
    /// Surface name (free-form, maps to StringSurface or RegExpSurface).
    pub surface_name: String,
    /// Measured throughput (millionths, ops/sec scaled).
    pub throughput_millionths: u64,
    /// Baseline throughput for comparison.
    pub baseline_throughput: u64,
    /// Speedup fraction (millionths, throughput / baseline - 1.0).
    pub speedup_fraction: u64,
    /// Tail risk fraction (millionths, p99/median ratio).
    pub tail_risk_fraction: u64,
    /// Number of benchmark samples.
    pub sample_count: u64,
    /// Epoch when benchmark was run.
    pub epoch: SecurityEpoch,
}

impl BenchmarkEvidence {
    /// Create new benchmark evidence.
    pub fn new(
        surface_name: impl Into<String>,
        throughput_millionths: u64,
        baseline_throughput: u64,
        speedup_fraction: u64,
        tail_risk_fraction: u64,
        sample_count: u64,
        epoch: SecurityEpoch,
    ) -> Self {
        Self {
            surface_name: surface_name.into(),
            throughput_millionths,
            baseline_throughput,
            speedup_fraction,
            tail_risk_fraction,
            sample_count,
            epoch,
        }
    }

    /// Whether the benchmark claims a speedup over baseline.
    pub fn claims_speedup(&self) -> bool {
        self.speedup_fraction > 0
    }
}

impl fmt::Display for BenchmarkEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "bench[{}]: throughput={} baseline={} speedup={} tail_risk={} n={}",
            self.surface_name,
            self.throughput_millionths,
            self.baseline_throughput,
            self.speedup_fraction,
            self.tail_risk_fraction,
            self.sample_count,
        )
    }
}

// ---------------------------------------------------------------------------
// TailRiskRecord
// ---------------------------------------------------------------------------

/// Tail-latency risk record for a surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskRecord {
    /// Surface name.
    pub surface_name: String,
    /// p99 latency (microseconds).
    pub p99_latency: u64,
    /// p99.9 latency (microseconds).
    pub p999_latency: u64,
    /// Maximum observed latency (microseconds).
    pub max_latency: u64,
    /// Tail ratio (millionths, p999 / p99).
    pub tail_ratio: u64,
    /// Whether this tail risk is acceptable.
    pub acceptable: bool,
}

impl TailRiskRecord {
    /// Create a new tail risk record.
    pub fn new(
        surface_name: impl Into<String>,
        p99_latency: u64,
        p999_latency: u64,
        max_latency: u64,
    ) -> Self {
        let tail_ratio = if p99_latency == 0 {
            0
        } else {
            p999_latency.saturating_mul(FIXED_ONE) / p99_latency
        };
        let acceptable = tail_ratio <= DEFAULT_MAX_TAIL_RATIO;
        Self {
            surface_name: surface_name.into(),
            p99_latency,
            p999_latency,
            max_latency,
            tail_ratio,
            acceptable,
        }
    }

    /// Whether tail ratio is within the given limit.
    pub fn within_limit(&self, max_ratio: u64) -> bool {
        self.tail_ratio <= max_ratio
    }
}

impl fmt::Display for TailRiskRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tail[{}]: p99={} p999={} max={} ratio={} ok={}",
            self.surface_name,
            self.p99_latency,
            self.p999_latency,
            self.max_latency,
            self.tail_ratio,
            self.acceptable,
        )
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the string/RegExp governance gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum parity fraction to allow shipping (millionths).
    pub min_parity_fraction: u64,
    /// Minimum Unicode compliance level.
    pub min_unicode_compliance: UnicodeCompliance,
    /// Maximum allowed tail ratio (millionths).
    pub max_tail_ratio: u64,
    /// Minimum test count per surface.
    pub min_test_count: u64,
    /// Minimum speedup fraction to accept a benchmark claim (millionths).
    pub min_speedup_for_claim: u64,
    /// Maximum number of known gaps before blocking.
    pub max_known_gaps: usize,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_parity_fraction: DEFAULT_MIN_PARITY_FRACTION,
            min_unicode_compliance: UnicodeCompliance::Bmp,
            max_tail_ratio: DEFAULT_MAX_TAIL_RATIO,
            min_test_count: DEFAULT_MIN_TEST_COUNT,
            min_speedup_for_claim: DEFAULT_MIN_SPEEDUP_FOR_CLAIM,
            max_known_gaps: DEFAULT_MAX_KNOWN_GAPS,
        }
    }
}

impl GateConfig {
    /// Strict configuration: full compliance, tight thresholds.
    pub fn strict() -> Self {
        Self {
            min_parity_fraction: 990_000, // 99%
            min_unicode_compliance: UnicodeCompliance::FullCompliant,
            max_tail_ratio: 1_500_000, // 1.5x
            min_test_count: 500,
            min_speedup_for_claim: 100_000, // 10%
            max_known_gaps: 0,
        }
    }

    /// Permissive configuration for development/testing.
    pub fn permissive() -> Self {
        Self {
            min_parity_fraction: 0,
            min_unicode_compliance: UnicodeCompliance::NonCompliant,
            max_tail_ratio: u64::MAX,
            min_test_count: 0,
            min_speedup_for_claim: 0,
            max_known_gaps: usize::MAX,
        }
    }
}

// ---------------------------------------------------------------------------
// GateResult
// ---------------------------------------------------------------------------

/// Result of the governance gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateResult {
    /// Overall decision.
    pub decision: GateDecision,
    /// Aggregate parity verdict.
    pub parity_verdict: ParityVerdict,
    /// Aggregate Unicode compliance.
    pub unicode_compliance: UnicodeCompliance,
    /// Whether tail risk is within limits.
    pub tail_risk_ok: bool,
    /// Reasons that contributed to a non-Ship decision.
    pub blocking_reasons: Vec<String>,
    /// Content hash of the evaluation inputs.
    pub receipt_hash: ContentHash,
}

impl GateResult {
    /// Whether the gate allows proceeding.
    pub fn allows_proceed(&self) -> bool {
        self.decision.allows_proceed()
    }
}

impl fmt::Display for GateResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "gate={} parity={} unicode={} tail_ok={} reasons={}",
            self.decision,
            self.parity_verdict,
            self.unicode_compliance,
            self.tail_risk_ok,
            self.blocking_reasons.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// DecisionReceipt
// ---------------------------------------------------------------------------

/// Signed receipt of a gate decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionReceipt {
    /// Content hash of the receipt.
    pub receipt_hash: ContentHash,
    /// Component that produced this receipt.
    pub component: String,
    /// Epoch at which the decision was made.
    pub epoch: SecurityEpoch,
    /// The decision rendered.
    pub decision: GateDecision,
    /// Hash of the evidence that was evaluated.
    pub evidence_hash: ContentHash,
}

impl DecisionReceipt {
    /// Create a receipt from a gate result.
    pub fn from_result(result: &GateResult, epoch: SecurityEpoch) -> Self {
        let mut h = Sha256::new();
        h.update(SCHEMA_VERSION.as_bytes());
        h.update(COMPONENT.as_bytes());
        h.update(epoch.as_u64().to_le_bytes());
        h.update(result.decision.as_str().as_bytes());
        h.update(result.receipt_hash.as_bytes());
        let receipt_hash = ContentHash::compute(&h.finalize());

        Self {
            receipt_hash,
            component: COMPONENT.to_string(),
            epoch,
            decision: result.decision,
            evidence_hash: result.receipt_hash.clone(),
        }
    }
}

impl fmt::Display for DecisionReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "receipt[{}] epoch={} decision={}",
            self.component,
            self.epoch.as_u64(),
            self.decision,
        )
    }
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

/// Summary statistics from a batch of gate evaluations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Total evaluations.
    pub total: u64,
    /// Count of Ship decisions.
    pub shipped: u64,
    /// Count of ConditionalShip decisions.
    pub conditional: u64,
    /// Count of Block decisions.
    pub blocked: u64,
    /// Count of RequireEvidence decisions.
    pub insufficient: u64,
    /// Pass rate (millionths, (shipped + conditional) / total).
    pub pass_rate: u64,
}

impl GateSummary {
    /// Compute a summary from a list of gate results.
    pub fn from_results(results: &[GateResult]) -> Self {
        let total = results.len() as u64;
        let mut shipped = 0u64;
        let mut conditional = 0u64;
        let mut blocked = 0u64;
        let mut insufficient = 0u64;

        for r in results {
            match r.decision {
                GateDecision::Ship => shipped += 1,
                GateDecision::ConditionalShip => conditional += 1,
                GateDecision::Block => blocked += 1,
                GateDecision::RequireEvidence => insufficient += 1,
            }
        }

        let pass_rate = if total == 0 {
            0
        } else {
            (shipped + conditional).saturating_mul(FIXED_ONE) / total
        };

        Self {
            total,
            shipped,
            conditional,
            blocked,
            insufficient,
            pass_rate,
        }
    }
}

impl fmt::Display for GateSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "summary: total={} ship={} cond={} block={} insuff={} rate={}",
            self.total,
            self.shipped,
            self.conditional,
            self.blocked,
            self.insufficient,
            self.pass_rate,
        )
    }
}

// ---------------------------------------------------------------------------
// Core evaluation functions
// ---------------------------------------------------------------------------

/// Evaluate string parity evidence against the gate configuration.
pub fn evaluate_string_parity(
    evidence: &StringParityEvidence,
    config: &GateConfig,
) -> ParityVerdict {
    // Insufficient test count => fail open.
    if evidence.test_count < config.min_test_count {
        return ParityVerdict::FailOpen;
    }

    // Too many known gaps => KnownGap.
    if evidence.known_gaps.len() > config.max_known_gaps {
        return ParityVerdict::KnownGap;
    }

    // Full parity if fraction meets threshold and no gaps.
    if evidence.parity_fraction >= config.min_parity_fraction
        && evidence.known_gaps.is_empty()
    {
        return ParityVerdict::FullParity;
    }

    // Partial parity if fraction meets threshold but gaps exist.
    if evidence.parity_fraction >= config.min_parity_fraction {
        return ParityVerdict::PartialParity;
    }

    // Below parity threshold with gaps.
    if !evidence.known_gaps.is_empty() {
        return ParityVerdict::KnownGap;
    }

    // Below parity threshold, no gaps — still partial if close.
    let close_threshold = config.min_parity_fraction.saturating_sub(50_000); // within 5%
    if evidence.parity_fraction >= close_threshold {
        ParityVerdict::PartialParity
    } else {
        ParityVerdict::KnownGap
    }
}

/// Evaluate RegExp parity evidence against the gate configuration.
pub fn evaluate_regexp_parity(
    evidence: &RegExpParityEvidence,
    config: &GateConfig,
) -> ParityVerdict {
    if evidence.test_count < config.min_test_count {
        return ParityVerdict::FailOpen;
    }

    if evidence.parity_fraction >= config.min_parity_fraction
        && evidence.unicode_coverage.meets_minimum(config.min_unicode_compliance)
    {
        return ParityVerdict::FullParity;
    }

    if evidence.parity_fraction >= config.min_parity_fraction {
        return ParityVerdict::PartialParity;
    }

    let close_threshold = config.min_parity_fraction.saturating_sub(50_000);
    if evidence.parity_fraction >= close_threshold {
        ParityVerdict::PartialParity
    } else {
        ParityVerdict::KnownGap
    }
}

/// Evaluate Unicode compliance from RegExp evidence.
pub fn evaluate_unicode(
    evidence: &RegExpParityEvidence,
    config: &GateConfig,
) -> UnicodeCompliance {
    if evidence.unicode_coverage.meets_minimum(config.min_unicode_compliance) {
        evidence.unicode_coverage
    } else {
        evidence.unicode_coverage
    }
}

/// Main gate evaluation: merge all evidence channels into a single result.
pub fn evaluate(
    string_ev: &[StringParityEvidence],
    regexp_ev: &[RegExpParityEvidence],
    bench_ev: &[BenchmarkEvidence],
    tail_ev: &[TailRiskRecord],
    config: &GateConfig,
) -> GateResult {
    let mut blocking_reasons: Vec<String> = Vec::new();

    // --- Parity evaluation ---
    let mut worst_string_parity = ParityVerdict::FullParity;
    for ev in string_ev {
        let verdict = evaluate_string_parity(ev, config);
        if verdict as u8 > worst_string_parity as u8 {
            worst_string_parity = verdict;
        }
        match verdict {
            ParityVerdict::KnownGap => {
                blocking_reasons.push(format!(
                    "string surface {} has known gaps",
                    ev.surface
                ));
            }
            ParityVerdict::FailOpen => {
                blocking_reasons.push(format!(
                    "string surface {} has insufficient tests ({})",
                    ev.surface, ev.test_count
                ));
            }
            _ => {}
        }
    }

    let mut worst_regexp_parity = ParityVerdict::FullParity;
    for ev in regexp_ev {
        let verdict = evaluate_regexp_parity(ev, config);
        if verdict as u8 > worst_regexp_parity as u8 {
            worst_regexp_parity = verdict;
        }
        match verdict {
            ParityVerdict::KnownGap => {
                blocking_reasons.push(format!(
                    "regexp surface {} has parity gap",
                    ev.surface
                ));
            }
            ParityVerdict::FailOpen => {
                blocking_reasons.push(format!(
                    "regexp surface {} has insufficient tests ({})",
                    ev.surface, ev.test_count
                ));
            }
            _ => {}
        }
    }

    // Merge parity verdicts: take the worse of the two.
    let parity_verdict = if worst_string_parity as u8 > worst_regexp_parity as u8 {
        worst_string_parity
    } else {
        worst_regexp_parity
    };

    // --- Unicode evaluation ---
    let mut worst_unicode = UnicodeCompliance::FullCompliant;
    for ev in regexp_ev {
        let uc = evaluate_unicode(ev, config);
        if uc.rank() < worst_unicode.rank() {
            worst_unicode = uc;
        }
    }
    let unicode_compliance = worst_unicode;

    if !unicode_compliance.meets_minimum(config.min_unicode_compliance) {
        blocking_reasons.push(format!(
            "unicode compliance {} below minimum {}",
            unicode_compliance, config.min_unicode_compliance
        ));
    }

    // --- Benchmark evaluation ---
    for ev in bench_ev {
        if ev.claims_speedup() && ev.speedup_fraction < config.min_speedup_for_claim {
            blocking_reasons.push(format!(
                "benchmark {} claims speedup {} below minimum {}",
                ev.surface_name, ev.speedup_fraction, config.min_speedup_for_claim
            ));
        }
    }

    // --- Tail risk evaluation ---
    let mut tail_risk_ok = true;
    for tr in tail_ev {
        if !tr.within_limit(config.max_tail_ratio) {
            tail_risk_ok = false;
            blocking_reasons.push(format!(
                "tail risk {} exceeds limit: ratio {} > {}",
                tr.surface_name, tr.tail_ratio, config.max_tail_ratio
            ));
        }
    }

    // --- Compute receipt hash ---
    let mut h = Sha256::new();
    h.update(SCHEMA_VERSION.as_bytes());
    h.update(COMPONENT.as_bytes());
    h.update((string_ev.len() as u64).to_le_bytes());
    for ev in string_ev {
        h.update(ev.surface.as_str().as_bytes());
        h.update(ev.parity_fraction.to_le_bytes());
    }
    h.update((regexp_ev.len() as u64).to_le_bytes());
    for ev in regexp_ev {
        h.update(ev.surface.as_str().as_bytes());
        h.update(ev.parity_fraction.to_le_bytes());
    }
    h.update((bench_ev.len() as u64).to_le_bytes());
    for ev in bench_ev {
        h.update(ev.surface_name.as_bytes());
        h.update(ev.speedup_fraction.to_le_bytes());
    }
    h.update((tail_ev.len() as u64).to_le_bytes());
    for tr in tail_ev {
        h.update(tr.surface_name.as_bytes());
        h.update(tr.tail_ratio.to_le_bytes());
    }
    let receipt_hash = ContentHash::compute(&h.finalize());

    // --- Determine decision ---
    let decision = if blocking_reasons.is_empty() {
        // No issues at all: check if we have enough evidence.
        if string_ev.is_empty() && regexp_ev.is_empty() {
            GateDecision::RequireEvidence
        } else {
            GateDecision::Ship
        }
    } else if parity_verdict == ParityVerdict::FailOpen {
        GateDecision::RequireEvidence
    } else if parity_verdict == ParityVerdict::KnownGap || !tail_risk_ok {
        GateDecision::Block
    } else {
        // Partial parity or minor benchmark issues.
        GateDecision::ConditionalShip
    };

    GateResult {
        decision,
        parity_verdict,
        unicode_compliance,
        tail_risk_ok,
        blocking_reasons,
        receipt_hash,
    }
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

    fn default_config() -> GateConfig {
        GateConfig::default()
    }

    // -- StringSurface --

    #[test]
    fn string_surface_all_count() {
        assert_eq!(StringSurface::ALL.len(), 8);
    }

    #[test]
    fn string_surface_as_str_roundtrip() {
        for s in StringSurface::ALL {
            assert!(!s.as_str().is_empty());
            assert_eq!(format!("{s}"), s.as_str());
        }
    }

    // -- RegExpSurface --

    #[test]
    fn regexp_surface_all_count() {
        assert_eq!(RegExpSurface::ALL.len(), 8);
    }

    #[test]
    fn regexp_surface_as_str_roundtrip() {
        for s in RegExpSurface::ALL {
            assert!(!s.as_str().is_empty());
            assert_eq!(format!("{s}"), s.as_str());
        }
    }

    // -- ParityVerdict --

    #[test]
    fn parity_verdict_allows_ship() {
        assert!(ParityVerdict::FullParity.allows_ship());
        assert!(ParityVerdict::PartialParity.allows_ship());
        assert!(!ParityVerdict::KnownGap.allows_ship());
        assert!(!ParityVerdict::FailOpen.allows_ship());
    }

    #[test]
    fn parity_verdict_display() {
        assert_eq!(ParityVerdict::FullParity.to_string(), "full_parity");
        assert_eq!(ParityVerdict::KnownGap.to_string(), "known_gap");
    }

    // -- UnicodeCompliance --

    #[test]
    fn unicode_compliance_rank_ordering() {
        assert!(UnicodeCompliance::FullCompliant.rank() > UnicodeCompliance::Bmp.rank());
        assert!(UnicodeCompliance::Bmp.rank() > UnicodeCompliance::AsciiOnly.rank());
        assert!(UnicodeCompliance::AsciiOnly.rank() > UnicodeCompliance::NonCompliant.rank());
    }

    #[test]
    fn unicode_compliance_meets_minimum() {
        assert!(UnicodeCompliance::FullCompliant.meets_minimum(UnicodeCompliance::Bmp));
        assert!(UnicodeCompliance::Bmp.meets_minimum(UnicodeCompliance::Bmp));
        assert!(!UnicodeCompliance::AsciiOnly.meets_minimum(UnicodeCompliance::Bmp));
        assert!(!UnicodeCompliance::NonCompliant.meets_minimum(UnicodeCompliance::AsciiOnly));
    }

    #[test]
    fn unicode_compliance_display() {
        assert_eq!(UnicodeCompliance::FullCompliant.to_string(), "full_compliant");
        assert_eq!(UnicodeCompliance::Bmp.to_string(), "bmp");
    }

    // -- GateDecision --

    #[test]
    fn gate_decision_allows_proceed() {
        assert!(GateDecision::Ship.allows_proceed());
        assert!(GateDecision::ConditionalShip.allows_proceed());
        assert!(!GateDecision::Block.allows_proceed());
        assert!(!GateDecision::RequireEvidence.allows_proceed());
    }

    #[test]
    fn gate_decision_display() {
        assert_eq!(GateDecision::Ship.to_string(), "ship");
        assert_eq!(GateDecision::Block.to_string(), "block");
    }

    // -- StringParityEvidence --

    #[test]
    fn string_parity_evidence_computes_fraction() {
        let ev = StringParityEvidence::new(
            StringSurface::Concat,
            200,
            190,
            vec![],
            epoch(1),
        );
        assert_eq!(ev.parity_fraction, 950_000);
    }

    #[test]
    fn string_parity_evidence_zero_tests() {
        let ev = StringParityEvidence::new(
            StringSurface::Slice,
            0,
            0,
            vec![],
            epoch(1),
        );
        assert_eq!(ev.parity_fraction, 0);
    }

    #[test]
    fn string_parity_evidence_display() {
        let ev = StringParityEvidence::new(
            StringSurface::Search,
            100,
            95,
            vec!["gap1".into()],
            epoch(1),
        );
        let s = ev.to_string();
        assert!(s.contains("search"));
        assert!(s.contains("95"));
    }

    // -- RegExpParityEvidence --

    #[test]
    fn regexp_parity_evidence_computes_fraction() {
        let ev = RegExpParityEvidence::new(
            RegExpSurface::Literal,
            1000,
            980,
            500,
            UnicodeCompliance::FullCompliant,
            epoch(2),
        );
        assert_eq!(ev.parity_fraction, 980_000);
    }

    #[test]
    fn regexp_parity_evidence_zero_tests() {
        let ev = RegExpParityEvidence::new(
            RegExpSurface::CharClass,
            0,
            0,
            0,
            UnicodeCompliance::NonCompliant,
            epoch(1),
        );
        assert_eq!(ev.parity_fraction, 0);
    }

    #[test]
    fn regexp_parity_evidence_display() {
        let ev = RegExpParityEvidence::new(
            RegExpSurface::Quantifier,
            200,
            198,
            150,
            UnicodeCompliance::Bmp,
            epoch(3),
        );
        let s = ev.to_string();
        assert!(s.contains("quantifier"));
        assert!(s.contains("bmp"));
    }

    // -- BenchmarkEvidence --

    #[test]
    fn benchmark_evidence_claims_speedup() {
        let ev = BenchmarkEvidence::new("concat", 2_000_000, 1_000_000, 100_000, 1_500_000, 1000, epoch(1));
        assert!(ev.claims_speedup());
    }

    #[test]
    fn benchmark_evidence_no_speedup() {
        let ev = BenchmarkEvidence::new("concat", 1_000_000, 1_000_000, 0, 1_200_000, 500, epoch(1));
        assert!(!ev.claims_speedup());
    }

    #[test]
    fn benchmark_evidence_display() {
        let ev = BenchmarkEvidence::new("search", 1_500_000, 1_000_000, 500_000, 1_100_000, 100, epoch(1));
        let s = ev.to_string();
        assert!(s.contains("search"));
        assert!(s.contains("1500000"));
    }

    // -- TailRiskRecord --

    #[test]
    fn tail_risk_computes_ratio() {
        let tr = TailRiskRecord::new("concat", 100, 200, 500);
        assert_eq!(tr.tail_ratio, 2_000_000); // 2.0x
    }

    #[test]
    fn tail_risk_zero_p99() {
        let tr = TailRiskRecord::new("slice", 0, 100, 200);
        assert_eq!(tr.tail_ratio, 0);
    }

    #[test]
    fn tail_risk_acceptable_at_limit() {
        let tr = TailRiskRecord::new("search", 100, 200, 300);
        assert!(tr.acceptable); // 2.0x == DEFAULT_MAX_TAIL_RATIO
    }

    #[test]
    fn tail_risk_unacceptable_over_limit() {
        let tr = TailRiskRecord::new("replace", 100, 201, 400);
        assert!(!tr.acceptable); // 2.01x > DEFAULT_MAX_TAIL_RATIO
    }

    #[test]
    fn tail_risk_within_limit() {
        let tr = TailRiskRecord::new("split", 100, 150, 200);
        assert!(tr.within_limit(2_000_000));
        assert!(!tr.within_limit(1_000_000));
    }

    #[test]
    fn tail_risk_display() {
        let tr = TailRiskRecord::new("template", 50, 80, 120);
        let s = tr.to_string();
        assert!(s.contains("template"));
    }

    // -- GateConfig --

    #[test]
    fn gate_config_default_values() {
        let c = GateConfig::default();
        assert_eq!(c.min_parity_fraction, DEFAULT_MIN_PARITY_FRACTION);
        assert_eq!(c.min_unicode_compliance, UnicodeCompliance::Bmp);
        assert_eq!(c.max_tail_ratio, DEFAULT_MAX_TAIL_RATIO);
        assert_eq!(c.min_test_count, DEFAULT_MIN_TEST_COUNT);
        assert_eq!(c.min_speedup_for_claim, DEFAULT_MIN_SPEEDUP_FOR_CLAIM);
        assert_eq!(c.max_known_gaps, DEFAULT_MAX_KNOWN_GAPS);
    }

    #[test]
    fn gate_config_strict() {
        let c = GateConfig::strict();
        assert_eq!(c.min_parity_fraction, 990_000);
        assert_eq!(c.min_unicode_compliance, UnicodeCompliance::FullCompliant);
        assert_eq!(c.max_known_gaps, 0);
    }

    #[test]
    fn gate_config_permissive() {
        let c = GateConfig::permissive();
        assert_eq!(c.min_parity_fraction, 0);
        assert_eq!(c.max_known_gaps, usize::MAX);
    }

    // -- evaluate_string_parity --

    #[test]
    fn string_parity_full_parity() {
        let ev = StringParityEvidence::new(
            StringSurface::Concat,
            200,
            200,
            vec![],
            epoch(1),
        );
        let v = evaluate_string_parity(&ev, &default_config());
        assert_eq!(v, ParityVerdict::FullParity);
    }

    #[test]
    fn string_parity_partial_with_gaps() {
        let ev = StringParityEvidence::new(
            StringSurface::Replace,
            200,
            196,
            vec!["minor-gap".into()],
            epoch(1),
        );
        let v = evaluate_string_parity(&ev, &default_config());
        assert_eq!(v, ParityVerdict::PartialParity);
    }

    #[test]
    fn string_parity_known_gap_too_many_gaps() {
        let ev = StringParityEvidence::new(
            StringSurface::Split,
            200,
            200,
            vec!["g1".into(), "g2".into(), "g3".into(), "g4".into()],
            epoch(1),
        );
        let v = evaluate_string_parity(&ev, &default_config());
        assert_eq!(v, ParityVerdict::KnownGap);
    }

    #[test]
    fn string_parity_fail_open_low_tests() {
        let ev = StringParityEvidence::new(
            StringSurface::Template,
            50,
            50,
            vec![],
            epoch(1),
        );
        let v = evaluate_string_parity(&ev, &default_config());
        assert_eq!(v, ParityVerdict::FailOpen);
    }

    #[test]
    fn string_parity_below_threshold_no_gaps() {
        let ev = StringParityEvidence::new(
            StringSurface::Normalize,
            200,
            180,
            vec![],
            epoch(1),
        );
        let v = evaluate_string_parity(&ev, &default_config());
        // 180/200 = 900_000, threshold=950_000, close_threshold=900_000
        assert_eq!(v, ParityVerdict::PartialParity);
    }

    #[test]
    fn string_parity_well_below_threshold() {
        let ev = StringParityEvidence::new(
            StringSurface::Compare,
            200,
            100,
            vec![],
            epoch(1),
        );
        let v = evaluate_string_parity(&ev, &default_config());
        // 100/200 = 500_000, well below threshold
        assert_eq!(v, ParityVerdict::KnownGap);
    }

    // -- evaluate_regexp_parity --

    #[test]
    fn regexp_parity_full_with_unicode() {
        let ev = RegExpParityEvidence::new(
            RegExpSurface::Literal,
            200,
            200,
            100,
            UnicodeCompliance::FullCompliant,
            epoch(1),
        );
        let v = evaluate_regexp_parity(&ev, &default_config());
        assert_eq!(v, ParityVerdict::FullParity);
    }

    #[test]
    fn regexp_parity_partial_bad_unicode() {
        let ev = RegExpParityEvidence::new(
            RegExpSurface::UnicodeProperty,
            200,
            198,
            100,
            UnicodeCompliance::AsciiOnly,
            epoch(1),
        );
        let v = evaluate_regexp_parity(&ev, &default_config());
        // parity is high but unicode doesn't meet Bmp minimum
        assert_eq!(v, ParityVerdict::PartialParity);
    }

    #[test]
    fn regexp_parity_fail_open_few_tests() {
        let ev = RegExpParityEvidence::new(
            RegExpSurface::Backreference,
            10,
            10,
            5,
            UnicodeCompliance::FullCompliant,
            epoch(1),
        );
        let v = evaluate_regexp_parity(&ev, &default_config());
        assert_eq!(v, ParityVerdict::FailOpen);
    }

    // -- evaluate_unicode --

    #[test]
    fn unicode_eval_returns_evidence_compliance() {
        let ev = RegExpParityEvidence::new(
            RegExpSurface::UnicodeProperty,
            200,
            200,
            100,
            UnicodeCompliance::Bmp,
            epoch(1),
        );
        let uc = evaluate_unicode(&ev, &default_config());
        assert_eq!(uc, UnicodeCompliance::Bmp);
    }

    #[test]
    fn unicode_eval_non_compliant() {
        let ev = RegExpParityEvidence::new(
            RegExpSurface::Literal,
            200,
            200,
            50,
            UnicodeCompliance::NonCompliant,
            epoch(1),
        );
        let uc = evaluate_unicode(&ev, &default_config());
        assert_eq!(uc, UnicodeCompliance::NonCompliant);
    }

    // -- evaluate (main gate) --

    #[test]
    fn evaluate_all_good_ships() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
        ];
        let regexp_ev = vec![
            RegExpParityEvidence::new(
                RegExpSurface::Literal,
                200,
                200,
                100,
                UnicodeCompliance::FullCompliant,
                epoch(1),
            ),
        ];
        let bench_ev = vec![
            BenchmarkEvidence::new("concat", 2_000_000, 1_000_000, 100_000, 1_500_000, 500, epoch(1)),
        ];
        let tail_ev = vec![
            TailRiskRecord::new("concat", 100, 150, 200),
        ];

        let result = evaluate(&string_ev, &regexp_ev, &bench_ev, &tail_ev, &default_config());
        assert_eq!(result.decision, GateDecision::Ship);
        assert!(result.blocking_reasons.is_empty());
        assert!(result.tail_risk_ok);
    }

    #[test]
    fn evaluate_no_evidence_requires_evidence() {
        let result = evaluate(&[], &[], &[], &[], &default_config());
        assert_eq!(result.decision, GateDecision::RequireEvidence);
    }

    #[test]
    fn evaluate_string_known_gap_blocks() {
        let string_ev = vec![
            StringParityEvidence::new(
                StringSurface::Replace,
                200,
                100,
                vec!["big-gap".into()],
                epoch(1),
            ),
        ];
        let result = evaluate(&string_ev, &[], &[], &[], &default_config());
        assert_eq!(result.decision, GateDecision::Block);
        assert_eq!(result.parity_verdict, ParityVerdict::KnownGap);
    }

    #[test]
    fn evaluate_tail_risk_blocks() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
        ];
        let tail_ev = vec![
            TailRiskRecord::new("concat", 100, 300, 500), // ratio = 3.0x, above 2.0x limit
        ];
        let result = evaluate(&string_ev, &[], &[], &tail_ev, &default_config());
        assert!(!result.tail_risk_ok);
        assert_eq!(result.decision, GateDecision::Block);
    }

    #[test]
    fn evaluate_benchmark_below_speedup_conditional() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
        ];
        let bench_ev = vec![
            BenchmarkEvidence::new("concat", 1_050_000, 1_000_000, 10_000, 1_200_000, 500, epoch(1)),
        ];
        let result = evaluate(&string_ev, &[], &bench_ev, &[], &default_config());
        // speedup_fraction=10_000 < min_speedup_for_claim=50_000 => blocking reason
        // but parity is full so not Block, should be ConditionalShip
        assert_eq!(result.decision, GateDecision::ConditionalShip);
    }

    #[test]
    fn evaluate_fail_open_requires_evidence() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 10, 10, vec![], epoch(1)),
        ];
        let result = evaluate(&string_ev, &[], &[], &[], &default_config());
        assert_eq!(result.decision, GateDecision::RequireEvidence);
        assert_eq!(result.parity_verdict, ParityVerdict::FailOpen);
    }

    #[test]
    fn evaluate_regexp_low_unicode_blocking() {
        let regexp_ev = vec![
            RegExpParityEvidence::new(
                RegExpSurface::UnicodeProperty,
                200,
                200,
                100,
                UnicodeCompliance::AsciiOnly,
                epoch(1),
            ),
        ];
        let config = GateConfig {
            min_unicode_compliance: UnicodeCompliance::FullCompliant,
            ..GateConfig::default()
        };
        let result = evaluate(&[], &regexp_ev, &[], &[], &config);
        assert!(!result.blocking_reasons.is_empty());
    }

    #[test]
    fn evaluate_receipt_hash_stable() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
        ];
        let r1 = evaluate(&string_ev, &[], &[], &[], &default_config());
        let r2 = evaluate(&string_ev, &[], &[], &[], &default_config());
        assert_eq!(r1.receipt_hash, r2.receipt_hash);
    }

    #[test]
    fn evaluate_receipt_hash_changes_with_input() {
        let ev1 = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
        ];
        let ev2 = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 190, vec![], epoch(1)),
        ];
        let r1 = evaluate(&ev1, &[], &[], &[], &default_config());
        let r2 = evaluate(&ev2, &[], &[], &[], &default_config());
        assert_ne!(r1.receipt_hash, r2.receipt_hash);
    }

    // -- GateResult --

    #[test]
    fn gate_result_allows_proceed() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
        ];
        let result = evaluate(&string_ev, &[], &[], &[], &default_config());
        assert!(result.allows_proceed());
    }

    #[test]
    fn gate_result_display() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
        ];
        let result = evaluate(&string_ev, &[], &[], &[], &default_config());
        let s = result.to_string();
        assert!(s.contains("gate="));
        assert!(s.contains("parity="));
    }

    // -- DecisionReceipt --

    #[test]
    fn decision_receipt_from_result() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(5)),
        ];
        let result = evaluate(&string_ev, &[], &[], &[], &default_config());
        let receipt = DecisionReceipt::from_result(&result, epoch(5));
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.epoch, epoch(5));
        assert_eq!(receipt.decision, result.decision);
        assert_eq!(receipt.evidence_hash, result.receipt_hash);
    }

    #[test]
    fn decision_receipt_display() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(3)),
        ];
        let result = evaluate(&string_ev, &[], &[], &[], &default_config());
        let receipt = DecisionReceipt::from_result(&result, epoch(3));
        let s = receipt.to_string();
        assert!(s.contains("receipt"));
        assert!(s.contains("epoch=3"));
    }

    // -- GateSummary --

    #[test]
    fn gate_summary_empty() {
        let summary = GateSummary::from_results(&[]);
        assert_eq!(summary.total, 0);
        assert_eq!(summary.pass_rate, 0);
    }

    #[test]
    fn gate_summary_all_ship() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
        ];
        let r1 = evaluate(&string_ev, &[], &[], &[], &default_config());
        let r2 = evaluate(&string_ev, &[], &[], &[], &default_config());
        let summary = GateSummary::from_results(&[r1, r2]);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.shipped, 2);
        assert_eq!(summary.pass_rate, FIXED_ONE);
    }

    #[test]
    fn gate_summary_mixed() {
        let good = evaluate(
            &[StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1))],
            &[],
            &[],
            &[],
            &default_config(),
        );
        let bad = evaluate(
            &[StringParityEvidence::new(StringSurface::Replace, 200, 50, vec!["g".into()], epoch(1))],
            &[],
            &[],
            &[],
            &default_config(),
        );
        let summary = GateSummary::from_results(&[good, bad]);
        assert_eq!(summary.total, 2);
        assert_eq!(summary.shipped, 1);
        assert_eq!(summary.blocked, 1);
        assert_eq!(summary.pass_rate, 500_000); // 50%
    }

    #[test]
    fn gate_summary_display() {
        let summary = GateSummary::from_results(&[]);
        let s = summary.to_string();
        assert!(s.contains("summary:"));
        assert!(s.contains("total=0"));
    }

    // -- Constants --

    #[test]
    fn constants_sanity() {
        assert_eq!(FIXED_ONE, 1_000_000);
        assert!(!SCHEMA_VERSION.is_empty());
        assert!(!COMPONENT.is_empty());
        assert!(!BEAD_ID.is_empty());
        assert!(!POLICY_ID.is_empty());
    }

    #[test]
    fn schema_version_matches_component() {
        assert!(SCHEMA_VERSION.contains("regexp-string-governance-gate"));
    }

    // -- Serde roundtrip --

    #[test]
    fn serde_string_surface_roundtrip() {
        let s = StringSurface::Concat;
        let json = serde_json::to_string(&s).unwrap();
        let back: StringSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn serde_regexp_surface_roundtrip() {
        let s = RegExpSurface::Lookahead;
        let json = serde_json::to_string(&s).unwrap();
        let back: RegExpSurface = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn serde_parity_verdict_roundtrip() {
        let v = ParityVerdict::PartialParity;
        let json = serde_json::to_string(&v).unwrap();
        let back: ParityVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    #[test]
    fn serde_gate_config_roundtrip() {
        let c = GateConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn serde_gate_result_roundtrip() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
        ];
        let result = evaluate(&string_ev, &[], &[], &[], &default_config());
        let json = serde_json::to_string(&result).unwrap();
        let back: GateResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, back);
    }

    #[test]
    fn serde_decision_receipt_roundtrip() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
        ];
        let result = evaluate(&string_ev, &[], &[], &[], &default_config());
        let receipt = DecisionReceipt::from_result(&result, epoch(1));
        let json = serde_json::to_string(&receipt).unwrap();
        let back: DecisionReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn serde_gate_summary_roundtrip() {
        let summary = GateSummary::from_results(&[]);
        let json = serde_json::to_string(&summary).unwrap();
        let back: GateSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    // -- Edge cases --

    #[test]
    fn multiple_surfaces_worst_wins() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
            StringParityEvidence::new(StringSurface::Replace, 200, 50, vec!["gap".into()], epoch(1)),
        ];
        let result = evaluate(&string_ev, &[], &[], &[], &default_config());
        assert_eq!(result.parity_verdict, ParityVerdict::KnownGap);
        assert_eq!(result.decision, GateDecision::Block);
    }

    #[test]
    fn multiple_regexp_surfaces() {
        let regexp_ev = vec![
            RegExpParityEvidence::new(
                RegExpSurface::Literal, 200, 200, 100,
                UnicodeCompliance::FullCompliant, epoch(1),
            ),
            RegExpParityEvidence::new(
                RegExpSurface::Backreference, 200, 200, 50,
                UnicodeCompliance::AsciiOnly, epoch(1),
            ),
        ];
        let result = evaluate(&[], &regexp_ev, &[], &[], &default_config());
        // worst unicode is AsciiOnly
        assert_eq!(result.unicode_compliance, UnicodeCompliance::AsciiOnly);
    }

    #[test]
    fn multiple_tail_risks_one_bad() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 200, 200, vec![], epoch(1)),
        ];
        let tail_ev = vec![
            TailRiskRecord::new("concat", 100, 150, 200),  // ok
            TailRiskRecord::new("search", 100, 500, 1000), // bad: ratio=5.0x
        ];
        let result = evaluate(&string_ev, &[], &[], &tail_ev, &default_config());
        assert!(!result.tail_risk_ok);
    }

    #[test]
    fn permissive_config_ships_everything() {
        let string_ev = vec![
            StringParityEvidence::new(StringSurface::Concat, 1, 0, vec!["gap".into()], epoch(1)),
        ];
        let result = evaluate(&string_ev, &[], &[], &[], &GateConfig::permissive());
        assert_eq!(result.decision, GateDecision::Ship);
    }
}
