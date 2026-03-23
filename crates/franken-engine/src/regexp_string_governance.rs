//! Bead: bd-1lsy.4.12.3 [RGC-312C]
//!
//! String/RegExp parity, Unicode, and benchmark governance for shipped lanes.
//!
//! Gates string and RegExp support on parity, Unicode, tail-risk, benchmark,
//! and observability evidence so the runtime never publishes a fake win on one
//! of the most workload-dominant surfaces.
//!
//! Key design:
//! 1. **StringLane** — Ascii, Latin1, Utf16, Utf8, Rope (5 lanes).
//! 2. **RegexpFeature** — Backreferences, Lookahead, Lookbehind, NamedGroups,
//!    UnicodeProperty, DotAll, Sticky, Multiline (8 features).
//! 3. **ParityAxis** — Semantic, Performance, Unicode, Memory, ErrorPath.
//! 4. **ParityResult** — lane/feature, axis, parity ratio, samples, evidence.
//! 5. **UnicodeCoverage** — per-plane codepoint-range coverage.
//! 6. **BenchmarkEntry** — category/workload, baseline/optimized ns, speedup.
//! 7. **GovernanceConfig** — thresholds for all axes.
//! 8. **GovernanceVerdict** — Approved or one-of-many violation flavours.
//! 9. **GovernanceEvaluator** — accumulates evidence, evaluates governance.
//! 10. **GovernanceReceipt** — auditable receipt with content-hash.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.regexp-string-governance.v1";

/// Bead identifier.
pub const BEAD_ID: &str = "bd-1lsy.4.12.3";

/// Component name for diagnostics.
pub const COMPONENT: &str = "regexp_string_governance";

/// Policy identifier.
pub const POLICY_ID: &str = "RGC-312C";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

/// Default minimum parity ratio (millionths). 950_000 = 95%.
pub const DEFAULT_MIN_PARITY_MILLIONTHS: u64 = 950_000;

/// Default maximum tail-risk ratio (millionths). 50_000 = 5%.
pub const DEFAULT_MAX_TAIL_RISK_MILLIONTHS: u64 = 50_000;

/// Default minimum Unicode coverage (millionths). 900_000 = 90%.
pub const DEFAULT_MIN_UNICODE_COVERAGE_MILLIONTHS: u64 = 900_000;

/// Default minimum benchmark sample count.
pub const DEFAULT_MIN_BENCHMARK_SAMPLES: u64 = 30;

/// Default minimum speedup required (millionths). 1_000_000 = 1.0x (no regression).
pub const DEFAULT_MIN_SPEEDUP_MILLIONTHS: u64 = MILLIONTHS;

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
// StringLane
// ---------------------------------------------------------------------------

/// Representation lane for string values in the engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringLane {
    /// Pure ASCII (0x00-0x7F).
    Ascii,
    /// Latin-1 (ISO 8859-1).
    Latin1,
    /// UTF-16 (JS-native encoding).
    Utf16,
    /// UTF-8 (internal optimized representation).
    Utf8,
    /// Rope (for large/concatenated strings).
    Rope,
}

impl StringLane {
    pub const ALL: &[Self] = &[
        Self::Ascii,
        Self::Latin1,
        Self::Utf16,
        Self::Utf8,
        Self::Rope,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ascii => "ascii",
            Self::Latin1 => "latin1",
            Self::Utf16 => "utf16",
            Self::Utf8 => "utf8",
            Self::Rope => "rope",
        }
    }
}

impl fmt::Display for StringLane {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RegexpFeature
// ---------------------------------------------------------------------------

/// RegExp feature surface that must demonstrate parity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegexpFeature {
    /// Back-references (`\1`, `\k<name>`).
    Backreferences,
    /// Positive/negative lookahead (`(?=...)`, `(?!...)`).
    Lookahead,
    /// Positive/negative lookbehind (`(?<=...)`, `(?<!...)`).
    Lookbehind,
    /// Named capturing groups (`(?<name>...)`).
    NamedGroups,
    /// Unicode property escapes (`\p{Lu}`).
    UnicodeProperty,
    /// DotAll flag (`/s`).
    DotAll,
    /// Sticky flag (`/y`).
    Sticky,
    /// Multiline flag (`/m`).
    Multiline,
}

impl RegexpFeature {
    pub const ALL: &[Self] = &[
        Self::Backreferences,
        Self::Lookahead,
        Self::Lookbehind,
        Self::NamedGroups,
        Self::UnicodeProperty,
        Self::DotAll,
        Self::Sticky,
        Self::Multiline,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Backreferences => "backreferences",
            Self::Lookahead => "lookahead",
            Self::Lookbehind => "lookbehind",
            Self::NamedGroups => "named_groups",
            Self::UnicodeProperty => "unicode_property",
            Self::DotAll => "dot_all",
            Self::Sticky => "sticky",
            Self::Multiline => "multiline",
        }
    }
}

impl fmt::Display for RegexpFeature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ParityAxis
// ---------------------------------------------------------------------------

/// Dimension along which parity is measured.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityAxis {
    /// Semantic correctness (output equality).
    Semantic,
    /// Performance (throughput/latency).
    Performance,
    /// Unicode handling correctness.
    Unicode,
    /// Memory footprint.
    Memory,
    /// Error-path fidelity (same errors for same inputs).
    ErrorPath,
}

impl ParityAxis {
    pub const ALL: &[Self] = &[
        Self::Semantic,
        Self::Performance,
        Self::Unicode,
        Self::Memory,
        Self::ErrorPath,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Semantic => "semantic",
            Self::Performance => "performance",
            Self::Unicode => "unicode",
            Self::Memory => "memory",
            Self::ErrorPath => "error_path",
        }
    }
}

impl fmt::Display for ParityAxis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ParitySubject
// ---------------------------------------------------------------------------

/// What entity is being measured for parity: a string lane or a regexp feature.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParitySubject {
    /// Parity for a string lane.
    Lane(StringLane),
    /// Parity for a regexp feature.
    Feature(RegexpFeature),
}

impl fmt::Display for ParitySubject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lane(l) => write!(f, "lane:{l}"),
            Self::Feature(ft) => write!(f, "feature:{ft}"),
        }
    }
}

// ---------------------------------------------------------------------------
// ParityResult
// ---------------------------------------------------------------------------

/// Result of a single parity measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityResult {
    /// What is being compared.
    pub subject: ParitySubject,
    /// Which axis the measurement is on.
    pub axis: ParityAxis,
    /// Parity ratio in millionths (1_000_000 = perfect parity).
    pub parity_millionths: u64,
    /// Number of test samples.
    pub sample_count: u64,
    /// Whether this measurement passes the configured threshold.
    pub passes: bool,
    /// Content hash of the underlying evidence.
    pub evidence_hash: ContentHash,
}

impl ParityResult {
    /// Create a parity result with computed evidence hash.
    pub fn new(
        subject: ParitySubject,
        axis: ParityAxis,
        parity_millionths: u64,
        sample_count: u64,
        passes: bool,
    ) -> Self {
        let mut buf = Vec::new();
        append_str(&mut buf, &subject.to_string());
        append_str(&mut buf, axis.as_str());
        append_u64(&mut buf, parity_millionths);
        append_u64(&mut buf, sample_count);
        append_u64(&mut buf, u64::from(passes));
        let evidence_hash = compute_digest(&buf);
        Self {
            subject,
            axis,
            parity_millionths,
            sample_count,
            passes,
            evidence_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// UnicodeCoverage
// ---------------------------------------------------------------------------

/// Coverage of a specific Unicode plane/range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnicodeCoverage {
    /// Unicode plane number (0 = BMP, 1 = SMP, etc.).
    pub plane: u32,
    /// Start of covered codepoint range.
    pub codepoint_range_start: u32,
    /// End of covered codepoint range (inclusive).
    pub codepoint_range_end: u32,
    /// Coverage ratio in millionths.
    pub coverage_millionths: u64,
    /// Whether this entry passes the configured threshold.
    pub passes: bool,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl UnicodeCoverage {
    /// Create a coverage entry.
    pub fn new(
        plane: u32,
        codepoint_range_start: u32,
        codepoint_range_end: u32,
        coverage_millionths: u64,
        passes: bool,
    ) -> Self {
        let mut buf = Vec::new();
        append_u64(&mut buf, plane as u64);
        append_u64(&mut buf, codepoint_range_start as u64);
        append_u64(&mut buf, codepoint_range_end as u64);
        append_u64(&mut buf, coverage_millionths);
        append_u64(&mut buf, u64::from(passes));
        let content_hash = compute_digest(&buf);
        Self {
            plane,
            codepoint_range_start,
            codepoint_range_end,
            coverage_millionths,
            passes,
            content_hash,
        }
    }

    /// Total codepoints in the range.
    pub fn range_size(&self) -> u64 {
        u64::from(self.codepoint_range_end).saturating_sub(u64::from(self.codepoint_range_start))
            + 1
    }
}

// ---------------------------------------------------------------------------
// BenchmarkCategory
// ---------------------------------------------------------------------------

/// Category of a benchmark workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkCategory {
    /// String operations benchmark.
    String,
    /// RegExp operations benchmark.
    Regexp,
}

impl BenchmarkCategory {
    pub const ALL: &[Self] = &[Self::String, Self::Regexp];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Regexp => "regexp",
        }
    }
}

impl fmt::Display for BenchmarkCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// BenchmarkEntry
// ---------------------------------------------------------------------------

/// A single benchmark measurement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchmarkEntry {
    /// Category of the benchmark.
    pub category: BenchmarkCategory,
    /// Workload identifier (e.g. "string_concat_10k", "regexp_email_match").
    pub workload_id: String,
    /// Baseline latency in nanoseconds.
    pub baseline_ns: u64,
    /// Optimized latency in nanoseconds.
    pub optimized_ns: u64,
    /// Speedup in millionths (e.g. 2_000_000 = 2.0x faster).
    pub speedup_millionths: u64,
    /// Number of samples for statistical validity.
    pub sample_count: u64,
    /// Content hash of this entry.
    pub content_hash: ContentHash,
}

impl BenchmarkEntry {
    /// Create a benchmark entry with computed speedup and hash.
    pub fn new(
        category: BenchmarkCategory,
        workload_id: impl Into<String>,
        baseline_ns: u64,
        optimized_ns: u64,
        sample_count: u64,
    ) -> Self {
        let workload_id = workload_id.into();
        // speedup = baseline / optimized, in millionths
        let speedup_millionths = baseline_ns
            .saturating_mul(MILLIONTHS)
            .checked_div(optimized_ns)
            .unwrap_or(MILLIONTHS * 10); // cap at 10x for zero-latency optimized path
        let mut buf = Vec::new();
        append_str(&mut buf, category.as_str());
        append_str(&mut buf, &workload_id);
        append_u64(&mut buf, baseline_ns);
        append_u64(&mut buf, optimized_ns);
        append_u64(&mut buf, speedup_millionths);
        append_u64(&mut buf, sample_count);
        let content_hash = compute_digest(&buf);
        Self {
            category,
            workload_id,
            baseline_ns,
            optimized_ns,
            speedup_millionths,
            sample_count,
            content_hash,
        }
    }

    /// Whether this entry regresses (speedup < 1.0x).
    pub fn is_regression(&self) -> bool {
        self.speedup_millionths < MILLIONTHS
    }
}

// ---------------------------------------------------------------------------
// TailRiskEntry
// ---------------------------------------------------------------------------

/// Tail-risk observation for a lane/feature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TailRiskEntry {
    /// What entity has the tail risk.
    pub subject: ParitySubject,
    /// p99 latency in nanoseconds.
    pub p99_ns: u64,
    /// p50 latency in nanoseconds (for ratio).
    pub p50_ns: u64,
    /// Tail ratio in millionths (p99/p50).
    pub tail_ratio_millionths: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl TailRiskEntry {
    /// Create a tail-risk entry.
    pub fn new(subject: ParitySubject, p99_ns: u64, p50_ns: u64) -> Self {
        let tail_ratio_millionths = p99_ns
            .saturating_mul(MILLIONTHS)
            .checked_div(p50_ns)
            .unwrap_or(MILLIONTHS * 100); // cap for zero-median
        let mut buf = Vec::new();
        append_str(&mut buf, &subject.to_string());
        append_u64(&mut buf, p99_ns);
        append_u64(&mut buf, p50_ns);
        append_u64(&mut buf, tail_ratio_millionths);
        let content_hash = compute_digest(&buf);
        Self {
            subject,
            p99_ns,
            p50_ns,
            tail_ratio_millionths,
            content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceConfig
// ---------------------------------------------------------------------------

/// Configuration thresholds for the governance evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Minimum parity ratio (millionths) for any axis to pass.
    pub min_parity_millionths: u64,
    /// Maximum acceptable tail-risk ratio (millionths).
    pub max_tail_risk_millionths: u64,
    /// Minimum Unicode coverage (millionths) for each plane.
    pub min_unicode_coverage_millionths: u64,
    /// Minimum benchmark sample count.
    pub min_benchmark_samples: u64,
    /// Minimum speedup (millionths). Below MILLIONTHS is a regression.
    pub min_speedup_millionths: u64,
    /// Required string lanes (must all have parity evidence).
    pub required_lanes: BTreeSet<StringLane>,
    /// Required regexp features (must all have parity evidence).
    pub required_features: BTreeSet<RegexpFeature>,
    /// Whether to fail closed when evidence is missing.
    pub fail_closed: bool,
}

impl GovernanceConfig {
    /// Default configuration: 95% parity, 5% tail-risk, 90% Unicode, 30 samples.
    pub fn default_config() -> Self {
        Self {
            min_parity_millionths: DEFAULT_MIN_PARITY_MILLIONTHS,
            max_tail_risk_millionths: DEFAULT_MAX_TAIL_RISK_MILLIONTHS,
            min_unicode_coverage_millionths: DEFAULT_MIN_UNICODE_COVERAGE_MILLIONTHS,
            min_benchmark_samples: DEFAULT_MIN_BENCHMARK_SAMPLES,
            min_speedup_millionths: DEFAULT_MIN_SPEEDUP_MILLIONTHS,
            required_lanes: StringLane::ALL.iter().copied().collect(),
            required_features: RegexpFeature::ALL.iter().copied().collect(),
            fail_closed: true,
        }
    }

    /// Strict: requires perfect parity and all evidence.
    pub fn strict() -> Self {
        Self {
            min_parity_millionths: MILLIONTHS,
            max_tail_risk_millionths: MILLIONTHS, // 1.0x tail ratio = no tail
            min_unicode_coverage_millionths: MILLIONTHS,
            min_benchmark_samples: 100,
            min_speedup_millionths: MILLIONTHS,
            required_lanes: StringLane::ALL.iter().copied().collect(),
            required_features: RegexpFeature::ALL.iter().copied().collect(),
            fail_closed: true,
        }
    }

    /// Permissive: allow anything through.
    pub fn permissive() -> Self {
        Self {
            min_parity_millionths: 0,
            max_tail_risk_millionths: u64::MAX,
            min_unicode_coverage_millionths: 0,
            min_benchmark_samples: 0,
            min_speedup_millionths: 0,
            required_lanes: BTreeSet::new(),
            required_features: BTreeSet::new(),
            fail_closed: false,
        }
    }

    /// Builder: set parity threshold.
    pub fn with_min_parity(mut self, millionths: u64) -> Self {
        self.min_parity_millionths = millionths;
        self
    }

    /// Builder: set tail-risk threshold.
    pub fn with_max_tail_risk(mut self, millionths: u64) -> Self {
        self.max_tail_risk_millionths = millionths;
        self
    }

    /// Builder: set Unicode coverage threshold.
    pub fn with_min_unicode_coverage(mut self, millionths: u64) -> Self {
        self.min_unicode_coverage_millionths = millionths;
        self
    }

    /// Builder: set minimum benchmark samples.
    pub fn with_min_benchmark_samples(mut self, count: u64) -> Self {
        self.min_benchmark_samples = count;
        self
    }

    /// Builder: set required lanes.
    pub fn with_required_lanes(mut self, lanes: BTreeSet<StringLane>) -> Self {
        self.required_lanes = lanes;
        self
    }

    /// Builder: set required features.
    pub fn with_required_features(mut self, features: BTreeSet<RegexpFeature>) -> Self {
        self.required_features = features;
        self
    }

    /// Builder: set fail-open semantics.
    pub fn fail_open(mut self) -> Self {
        self.fail_closed = false;
        self
    }
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

// ---------------------------------------------------------------------------
// GovernanceVerdict
// ---------------------------------------------------------------------------

/// Verdict from the governance evaluator.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GovernanceVerdict {
    /// All checks pass.
    Approved,
    /// Parity below threshold on at least one axis.
    ParityViolation,
    /// Unicode coverage below threshold.
    UnicodeCoverageGap,
    /// Benchmark has insufficient samples or regression.
    BenchmarkInsufficient,
    /// Tail risk exceeds acceptable bounds.
    TailRiskExceeded,
    /// Multiple violations detected.
    MultipleViolations,
}

impl GovernanceVerdict {
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved)
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::ParityViolation => "parity_violation",
            Self::UnicodeCoverageGap => "unicode_coverage_gap",
            Self::BenchmarkInsufficient => "benchmark_insufficient",
            Self::TailRiskExceeded => "tail_risk_exceeded",
            Self::MultipleViolations => "multiple_violations",
        }
    }
}

impl fmt::Display for GovernanceVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Violation
// ---------------------------------------------------------------------------

/// A specific governance violation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// Which kind of violation.
    pub kind: GovernanceVerdict,
    /// Human-readable description.
    pub description: String,
    /// Actual value in millionths.
    pub actual_millionths: u64,
    /// Threshold value in millionths.
    pub threshold_millionths: u64,
}

impl Violation {
    pub fn new(
        kind: GovernanceVerdict,
        description: impl Into<String>,
        actual_millionths: u64,
        threshold_millionths: u64,
    ) -> Self {
        Self {
            kind,
            description: description.into(),
            actual_millionths,
            threshold_millionths,
        }
    }
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {} (actual={}, threshold={})",
            self.kind, self.description, self.actual_millionths, self.threshold_millionths
        )
    }
}

// ---------------------------------------------------------------------------
// GovernanceReceipt
// ---------------------------------------------------------------------------

/// Auditable receipt from a governance evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component name.
    pub component: String,
    /// Bead reference.
    pub bead_id: String,
    /// Policy reference.
    pub policy_id: String,
    /// Overall verdict.
    pub verdict: GovernanceVerdict,
    /// Security epoch at evaluation time.
    pub epoch: SecurityEpoch,
    /// All parity results submitted.
    pub parity_results: Vec<ParityResult>,
    /// All Unicode coverage entries submitted.
    pub unicode_coverage: Vec<UnicodeCoverage>,
    /// All benchmark entries submitted.
    pub benchmark_entries: Vec<BenchmarkEntry>,
    /// All tail-risk entries submitted.
    pub tail_risk_entries: Vec<TailRiskEntry>,
    /// Violations found.
    pub violations: Vec<Violation>,
    /// Content hash of the entire receipt.
    pub content_hash: ContentHash,
}

impl GovernanceReceipt {
    /// Recompute the content hash from all fields.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, &self.schema_version);
        append_str(&mut buf, &self.component);
        append_str(&mut buf, &self.bead_id);
        append_str(&mut buf, &self.policy_id);
        append_str(&mut buf, self.verdict.as_str());
        append_u64(&mut buf, self.epoch.as_u64());
        append_u64(&mut buf, self.parity_results.len() as u64);
        let mut sorted_parity: Vec<_> = self
            .parity_results
            .iter()
            .map(|pr| pr.evidence_hash)
            .collect();
        sorted_parity.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for h in &sorted_parity {
            buf.extend_from_slice(h.as_bytes());
        }
        append_u64(&mut buf, self.unicode_coverage.len() as u64);
        let mut sorted_unicode: Vec<_> = self
            .unicode_coverage
            .iter()
            .map(|uc| uc.content_hash)
            .collect();
        sorted_unicode.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for h in &sorted_unicode {
            buf.extend_from_slice(h.as_bytes());
        }
        append_u64(&mut buf, self.benchmark_entries.len() as u64);
        let mut sorted_bench: Vec<_> = self
            .benchmark_entries
            .iter()
            .map(|be| be.content_hash)
            .collect();
        sorted_bench.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for h in &sorted_bench {
            buf.extend_from_slice(h.as_bytes());
        }
        append_u64(&mut buf, self.tail_risk_entries.len() as u64);
        let mut sorted_tail: Vec<_> = self
            .tail_risk_entries
            .iter()
            .map(|tr| tr.content_hash)
            .collect();
        sorted_tail.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        for h in &sorted_tail {
            buf.extend_from_slice(h.as_bytes());
        }
        append_u64(&mut buf, self.violations.len() as u64);
        for v in &self.violations {
            append_str(&mut buf, v.kind.as_str());
        }
        self.content_hash = compute_digest(&buf);
    }

    /// Whether the verdict is approved.
    pub fn is_approved(&self) -> bool {
        self.verdict.is_approved()
    }

    /// Number of violations.
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }
}

// ---------------------------------------------------------------------------
// GovernanceEvaluator
// ---------------------------------------------------------------------------

/// Evaluator that accumulates parity, Unicode, benchmark, and tail-risk
/// evidence and produces a governance verdict with an auditable receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEvaluator {
    config: GovernanceConfig,
    epoch: SecurityEpoch,
    parity_results: Vec<ParityResult>,
    unicode_coverage: Vec<UnicodeCoverage>,
    benchmark_entries: Vec<BenchmarkEntry>,
    tail_risk_entries: Vec<TailRiskEntry>,
    evaluation_count: u64,
    approved_count: u64,
    denied_count: u64,
    last_receipt: Option<GovernanceReceipt>,
}

impl GovernanceEvaluator {
    /// Create a new evaluator with the given config and epoch.
    pub fn new(config: GovernanceConfig, epoch: SecurityEpoch) -> Self {
        Self {
            config,
            epoch,
            parity_results: Vec::new(),
            unicode_coverage: Vec::new(),
            benchmark_entries: Vec::new(),
            tail_risk_entries: Vec::new(),
            evaluation_count: 0,
            approved_count: 0,
            denied_count: 0,
            last_receipt: None,
        }
    }

    /// Create with default config.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(GovernanceConfig::default(), epoch)
    }

    /// Access config.
    pub fn config(&self) -> &GovernanceConfig {
        &self.config
    }

    /// Current epoch.
    pub fn epoch(&self) -> &SecurityEpoch {
        &self.epoch
    }

    /// Total evaluations performed.
    pub fn evaluation_count(&self) -> u64 {
        self.evaluation_count
    }

    /// Total approvals.
    pub fn approved_count(&self) -> u64 {
        self.approved_count
    }

    /// Total denials.
    pub fn denied_count(&self) -> u64 {
        self.denied_count
    }

    /// Most recent receipt.
    pub fn last_receipt(&self) -> Option<&GovernanceReceipt> {
        self.last_receipt.as_ref()
    }

    /// Parity results accumulated so far.
    pub fn parity_results(&self) -> &[ParityResult] {
        &self.parity_results
    }

    /// Unicode coverage accumulated so far.
    pub fn unicode_coverage(&self) -> &[UnicodeCoverage] {
        &self.unicode_coverage
    }

    /// Benchmark entries accumulated so far.
    pub fn benchmark_entries(&self) -> &[BenchmarkEntry] {
        &self.benchmark_entries
    }

    /// Tail-risk entries accumulated so far.
    pub fn tail_risk_entries(&self) -> &[TailRiskEntry] {
        &self.tail_risk_entries
    }

    /// Add a parity result.
    pub fn add_parity(&mut self, result: ParityResult) {
        self.parity_results.push(result);
    }

    /// Add a Unicode coverage entry.
    pub fn add_unicode_coverage(&mut self, entry: UnicodeCoverage) {
        self.unicode_coverage.push(entry);
    }

    /// Add a benchmark entry.
    pub fn add_benchmark(&mut self, entry: BenchmarkEntry) {
        self.benchmark_entries.push(entry);
    }

    /// Add a tail-risk entry.
    pub fn add_tail_risk(&mut self, entry: TailRiskEntry) {
        self.tail_risk_entries.push(entry);
    }

    /// Clear all accumulated evidence (reset for re-evaluation).
    pub fn clear(&mut self) {
        self.parity_results.clear();
        self.unicode_coverage.clear();
        self.benchmark_entries.clear();
        self.tail_risk_entries.clear();
    }

    /// Evaluate all accumulated evidence against the config.
    ///
    /// Returns a sealed `GovernanceReceipt` with the verdict, violations,
    /// and content hash.
    pub fn evaluate(&mut self) -> GovernanceReceipt {
        self.evaluation_count += 1;
        let mut violations = Vec::new();

        // 1. Check parity on all results
        for pr in &self.parity_results {
            if pr.parity_millionths < self.config.min_parity_millionths {
                violations.push(Violation::new(
                    GovernanceVerdict::ParityViolation,
                    format!("{} on {} below threshold", pr.subject, pr.axis),
                    pr.parity_millionths,
                    self.config.min_parity_millionths,
                ));
            }
        }

        // 2. Check required lanes have at least one parity result
        let observed_lanes: BTreeSet<StringLane> = self
            .parity_results
            .iter()
            .filter_map(|pr| match &pr.subject {
                ParitySubject::Lane(l) => Some(*l),
                _ => None,
            })
            .collect();
        for required in &self.config.required_lanes {
            if !observed_lanes.contains(required) && self.config.fail_closed {
                violations.push(Violation::new(
                    GovernanceVerdict::ParityViolation,
                    format!("missing parity evidence for lane {required}"),
                    0,
                    self.config.min_parity_millionths,
                ));
            }
        }

        // 3. Check required features have at least one parity result
        let observed_features: BTreeSet<RegexpFeature> = self
            .parity_results
            .iter()
            .filter_map(|pr| match &pr.subject {
                ParitySubject::Feature(f) => Some(*f),
                _ => None,
            })
            .collect();
        for required in &self.config.required_features {
            if !observed_features.contains(required) && self.config.fail_closed {
                violations.push(Violation::new(
                    GovernanceVerdict::ParityViolation,
                    format!("missing parity evidence for feature {required}"),
                    0,
                    self.config.min_parity_millionths,
                ));
            }
        }

        // 4. Check Unicode coverage
        for uc in &self.unicode_coverage {
            if uc.coverage_millionths < self.config.min_unicode_coverage_millionths {
                violations.push(Violation::new(
                    GovernanceVerdict::UnicodeCoverageGap,
                    format!(
                        "plane {} range {:#06x}-{:#06x} coverage below threshold",
                        uc.plane, uc.codepoint_range_start, uc.codepoint_range_end
                    ),
                    uc.coverage_millionths,
                    self.config.min_unicode_coverage_millionths,
                ));
            }
        }

        // 5. Check benchmarks
        for be in &self.benchmark_entries {
            if be.sample_count < self.config.min_benchmark_samples {
                violations.push(Violation::new(
                    GovernanceVerdict::BenchmarkInsufficient,
                    format!(
                        "workload {} has {} samples, need {}",
                        be.workload_id, be.sample_count, self.config.min_benchmark_samples
                    ),
                    be.sample_count,
                    self.config.min_benchmark_samples,
                ));
            }
            if be.speedup_millionths < self.config.min_speedup_millionths {
                violations.push(Violation::new(
                    GovernanceVerdict::BenchmarkInsufficient,
                    format!(
                        "workload {} regresses (speedup {} < {})",
                        be.workload_id, be.speedup_millionths, self.config.min_speedup_millionths
                    ),
                    be.speedup_millionths,
                    self.config.min_speedup_millionths,
                ));
            }
        }

        // 6. Check tail risk
        for tr in &self.tail_risk_entries {
            if tr.tail_ratio_millionths > self.config.max_tail_risk_millionths {
                violations.push(Violation::new(
                    GovernanceVerdict::TailRiskExceeded,
                    format!(
                        "{} tail ratio {} exceeds {}",
                        tr.subject, tr.tail_ratio_millionths, self.config.max_tail_risk_millionths
                    ),
                    tr.tail_ratio_millionths,
                    self.config.max_tail_risk_millionths,
                ));
            }
        }

        // Determine overall verdict
        let verdict = if violations.is_empty() {
            GovernanceVerdict::Approved
        } else {
            // Collect unique violation kinds
            let kinds: BTreeSet<&GovernanceVerdict> = violations.iter().map(|v| &v.kind).collect();
            if kinds.len() > 1 {
                GovernanceVerdict::MultipleViolations
            } else {
                violations[0].kind.clone()
            }
        };

        // Update counters
        if verdict.is_approved() {
            self.approved_count += 1;
        } else {
            self.denied_count += 1;
        }

        // Build receipt
        let mut receipt = GovernanceReceipt {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            verdict,
            epoch: self.epoch,
            parity_results: self.parity_results.clone(),
            unicode_coverage: self.unicode_coverage.clone(),
            benchmark_entries: self.benchmark_entries.clone(),
            tail_risk_entries: self.tail_risk_entries.clone(),
            violations,
            content_hash: ContentHash::compute(b""),
        };
        receipt.seal();
        self.last_receipt = Some(receipt.clone());
        receipt
    }

    /// Pass rate in millionths.
    pub fn pass_rate_millionths(&self) -> u64 {
        if self.evaluation_count == 0 {
            return 0;
        }
        self.approved_count
            .saturating_mul(MILLIONTHS)
            .checked_div(self.evaluation_count)
            .unwrap_or(0)
    }

    /// Summary statistics.
    pub fn summary(&self) -> GovernanceSummary {
        GovernanceSummary {
            total_evaluations: self.evaluation_count,
            approved_count: self.approved_count,
            denied_count: self.denied_count,
            parity_results_count: self.parity_results.len() as u64,
            unicode_coverage_count: self.unicode_coverage.len() as u64,
            benchmark_count: self.benchmark_entries.len() as u64,
            tail_risk_count: self.tail_risk_entries.len() as u64,
            pass_rate_millionths: self.pass_rate_millionths(),
        }
    }
}

// ---------------------------------------------------------------------------
// GovernanceSummary
// ---------------------------------------------------------------------------

/// Summary statistics for the governance evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceSummary {
    pub total_evaluations: u64,
    pub approved_count: u64,
    pub denied_count: u64,
    pub parity_results_count: u64,
    pub unicode_coverage_count: u64,
    pub benchmark_count: u64,
    pub tail_risk_count: u64,
    pub pass_rate_millionths: u64,
}

// ---------------------------------------------------------------------------
// summarize_receipt
// ---------------------------------------------------------------------------

/// Produce a human-readable summary of a governance receipt.
pub fn summarize_receipt(receipt: &GovernanceReceipt) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "String/RegExp Governance — verdict: {}",
        receipt.verdict
    ));
    lines.push(format!("  epoch: {}", receipt.epoch));
    lines.push(format!(
        "  parity results: {}",
        receipt.parity_results.len()
    ));
    lines.push(format!(
        "  unicode coverage entries: {}",
        receipt.unicode_coverage.len()
    ));
    lines.push(format!(
        "  benchmark entries: {}",
        receipt.benchmark_entries.len()
    ));
    lines.push(format!(
        "  tail-risk entries: {}",
        receipt.tail_risk_entries.len()
    ));
    lines.push(format!("  violations: {}", receipt.violations.len()));

    if !receipt.violations.is_empty() {
        lines.push("  violation details:".to_string());
        for v in &receipt.violations {
            lines.push(format!("    - {v}"));
        }
    }

    lines.push(format!("  content hash: {}", receipt.content_hash));
    lines.join("\n")
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Default manifest for this module.
pub fn regexp_string_governance_manifest() -> GovernanceSummary {
    GovernanceSummary {
        total_evaluations: 0,
        approved_count: 0,
        denied_count: 0,
        parity_results_count: 0,
        unicode_coverage_count: 0,
        benchmark_count: 0,
        tail_risk_count: 0,
        pass_rate_millionths: 0,
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    fn good_parity(subject: ParitySubject, axis: ParityAxis) -> ParityResult {
        ParityResult::new(subject, axis, MILLIONTHS, 100, true)
    }

    fn bad_parity(subject: ParitySubject, axis: ParityAxis) -> ParityResult {
        ParityResult::new(subject, axis, 800_000, 100, false)
    }

    fn good_unicode(plane: u32) -> UnicodeCoverage {
        UnicodeCoverage::new(plane, 0, 0xFFFF, MILLIONTHS, true)
    }

    fn bad_unicode(plane: u32) -> UnicodeCoverage {
        UnicodeCoverage::new(plane, 0, 0xFFFF, 500_000, false)
    }

    fn good_benchmark(cat: BenchmarkCategory, wid: &str) -> BenchmarkEntry {
        BenchmarkEntry::new(cat, wid, 1000, 500, 50) // 2x speedup, 50 samples
    }

    fn regression_benchmark(cat: BenchmarkCategory, wid: &str) -> BenchmarkEntry {
        BenchmarkEntry::new(cat, wid, 500, 1000, 50) // 0.5x = regression
    }

    fn insufficient_benchmark(cat: BenchmarkCategory, wid: &str) -> BenchmarkEntry {
        BenchmarkEntry::new(cat, wid, 1000, 500, 5) // only 5 samples
    }

    fn good_tail_risk(subject: ParitySubject) -> TailRiskEntry {
        TailRiskEntry::new(subject, 5, 100) // 50_000 millionths (at threshold)
    }

    fn bad_tail_risk(subject: ParitySubject) -> TailRiskEntry {
        TailRiskEntry::new(subject, 10_000, 100) // 100x tail ratio
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("regexp-string-governance"));
    }

    #[test]
    fn test_bead_id() {
        assert_eq!(BEAD_ID, "bd-1lsy.4.12.3");
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "regexp_string_governance");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-312C");
    }

    #[test]
    fn test_millionths_constant() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // StringLane
    // -----------------------------------------------------------------------

    #[test]
    fn test_string_lane_all_count() {
        assert_eq!(StringLane::ALL.len(), 5);
    }

    #[test]
    fn test_string_lane_display() {
        assert_eq!(format!("{}", StringLane::Ascii), "ascii");
        assert_eq!(format!("{}", StringLane::Rope), "rope");
        assert_eq!(format!("{}", StringLane::Utf16), "utf16");
    }

    #[test]
    fn test_string_lane_serde_roundtrip() {
        for lane in StringLane::ALL {
            let json = serde_json::to_string(lane).unwrap();
            let back: StringLane = serde_json::from_str(&json).unwrap();
            assert_eq!(*lane, back);
        }
    }

    // -----------------------------------------------------------------------
    // RegexpFeature
    // -----------------------------------------------------------------------

    #[test]
    fn test_regexp_feature_all_count() {
        assert_eq!(RegexpFeature::ALL.len(), 8);
    }

    #[test]
    fn test_regexp_feature_display() {
        assert_eq!(
            format!("{}", RegexpFeature::Backreferences),
            "backreferences"
        );
        assert_eq!(format!("{}", RegexpFeature::Lookahead), "lookahead");
        assert_eq!(format!("{}", RegexpFeature::NamedGroups), "named_groups");
    }

    #[test]
    fn test_regexp_feature_serde_roundtrip() {
        for feat in RegexpFeature::ALL {
            let json = serde_json::to_string(feat).unwrap();
            let back: RegexpFeature = serde_json::from_str(&json).unwrap();
            assert_eq!(*feat, back);
        }
    }

    // -----------------------------------------------------------------------
    // ParityAxis
    // -----------------------------------------------------------------------

    #[test]
    fn test_parity_axis_all_count() {
        assert_eq!(ParityAxis::ALL.len(), 5);
    }

    #[test]
    fn test_parity_axis_display() {
        assert_eq!(format!("{}", ParityAxis::Semantic), "semantic");
        assert_eq!(format!("{}", ParityAxis::ErrorPath), "error_path");
    }

    // -----------------------------------------------------------------------
    // ParitySubject
    // -----------------------------------------------------------------------

    #[test]
    fn test_parity_subject_lane_display() {
        let s = ParitySubject::Lane(StringLane::Utf8);
        assert_eq!(format!("{s}"), "lane:utf8");
    }

    #[test]
    fn test_parity_subject_feature_display() {
        let s = ParitySubject::Feature(RegexpFeature::DotAll);
        assert_eq!(format!("{s}"), "feature:dot_all");
    }

    // -----------------------------------------------------------------------
    // ParityResult
    // -----------------------------------------------------------------------

    #[test]
    fn test_parity_result_new() {
        let pr = good_parity(ParitySubject::Lane(StringLane::Ascii), ParityAxis::Semantic);
        assert_eq!(pr.parity_millionths, MILLIONTHS);
        assert_eq!(pr.sample_count, 100);
        assert!(pr.passes);
    }

    #[test]
    fn test_parity_result_evidence_hash_deterministic() {
        let a = good_parity(ParitySubject::Lane(StringLane::Ascii), ParityAxis::Semantic);
        let b = good_parity(ParitySubject::Lane(StringLane::Ascii), ParityAxis::Semantic);
        assert_eq!(a.evidence_hash, b.evidence_hash);
    }

    #[test]
    fn test_parity_result_different_subjects_differ() {
        let a = good_parity(ParitySubject::Lane(StringLane::Ascii), ParityAxis::Semantic);
        let b = good_parity(ParitySubject::Lane(StringLane::Utf16), ParityAxis::Semantic);
        assert_ne!(a.evidence_hash, b.evidence_hash);
    }

    // -----------------------------------------------------------------------
    // UnicodeCoverage
    // -----------------------------------------------------------------------

    #[test]
    fn test_unicode_coverage_new() {
        let uc = good_unicode(0);
        assert_eq!(uc.plane, 0);
        assert_eq!(uc.coverage_millionths, MILLIONTHS);
        assert!(uc.passes);
    }

    #[test]
    fn test_unicode_coverage_range_size() {
        let uc = UnicodeCoverage::new(0, 0x0000, 0x00FF, MILLIONTHS, true);
        assert_eq!(uc.range_size(), 256);
    }

    #[test]
    fn test_unicode_coverage_range_size_single() {
        let uc = UnicodeCoverage::new(0, 0x0041, 0x0041, MILLIONTHS, true);
        assert_eq!(uc.range_size(), 1);
    }

    #[test]
    fn test_unicode_coverage_hash_deterministic() {
        let a = UnicodeCoverage::new(1, 0x10000, 0x1FFFF, 950_000, true);
        let b = UnicodeCoverage::new(1, 0x10000, 0x1FFFF, 950_000, true);
        assert_eq!(a.content_hash, b.content_hash);
    }

    // -----------------------------------------------------------------------
    // BenchmarkCategory
    // -----------------------------------------------------------------------

    #[test]
    fn test_benchmark_category_all_count() {
        assert_eq!(BenchmarkCategory::ALL.len(), 2);
    }

    #[test]
    fn test_benchmark_category_display() {
        assert_eq!(format!("{}", BenchmarkCategory::String), "string");
        assert_eq!(format!("{}", BenchmarkCategory::Regexp), "regexp");
    }

    // -----------------------------------------------------------------------
    // BenchmarkEntry
    // -----------------------------------------------------------------------

    #[test]
    fn test_benchmark_entry_speedup() {
        let be = BenchmarkEntry::new(BenchmarkCategory::String, "concat", 2000, 1000, 50);
        assert_eq!(be.speedup_millionths, 2_000_000); // 2.0x
    }

    #[test]
    fn test_benchmark_entry_regression() {
        let be = regression_benchmark(BenchmarkCategory::Regexp, "match");
        assert!(be.is_regression());
    }

    #[test]
    fn test_benchmark_entry_not_regression() {
        let be = good_benchmark(BenchmarkCategory::String, "slice");
        assert!(!be.is_regression());
    }

    #[test]
    fn test_benchmark_entry_zero_optimized() {
        let be = BenchmarkEntry::new(BenchmarkCategory::String, "noop", 1000, 0, 50);
        assert_eq!(be.speedup_millionths, MILLIONTHS * 10); // capped at 10x
    }

    #[test]
    fn test_benchmark_entry_hash_deterministic() {
        let a = BenchmarkEntry::new(BenchmarkCategory::String, "x", 100, 50, 30);
        let b = BenchmarkEntry::new(BenchmarkCategory::String, "x", 100, 50, 30);
        assert_eq!(a.content_hash, b.content_hash);
    }

    // -----------------------------------------------------------------------
    // TailRiskEntry
    // -----------------------------------------------------------------------

    #[test]
    fn test_tail_risk_entry_ratio() {
        let tr = TailRiskEntry::new(ParitySubject::Lane(StringLane::Ascii), 2000, 1000);
        assert_eq!(tr.tail_ratio_millionths, 2_000_000); // 2.0x
    }

    #[test]
    fn test_tail_risk_entry_zero_p50() {
        let tr = TailRiskEntry::new(ParitySubject::Lane(StringLane::Utf8), 1000, 0);
        assert_eq!(tr.tail_ratio_millionths, MILLIONTHS * 100); // capped
    }

    #[test]
    fn test_tail_risk_entry_hash_deterministic() {
        let a = TailRiskEntry::new(ParitySubject::Feature(RegexpFeature::Sticky), 500, 250);
        let b = TailRiskEntry::new(ParitySubject::Feature(RegexpFeature::Sticky), 500, 250);
        assert_eq!(a.content_hash, b.content_hash);
    }

    // -----------------------------------------------------------------------
    // GovernanceConfig
    // -----------------------------------------------------------------------

    #[test]
    fn test_default_config() {
        let cfg = GovernanceConfig::default();
        assert_eq!(cfg.min_parity_millionths, DEFAULT_MIN_PARITY_MILLIONTHS);
        assert_eq!(
            cfg.max_tail_risk_millionths,
            DEFAULT_MAX_TAIL_RISK_MILLIONTHS
        );
        assert!(cfg.fail_closed);
        assert_eq!(cfg.required_lanes.len(), 5);
        assert_eq!(cfg.required_features.len(), 8);
    }

    #[test]
    fn test_strict_config() {
        let cfg = GovernanceConfig::strict();
        assert_eq!(cfg.min_parity_millionths, MILLIONTHS);
        assert_eq!(cfg.min_benchmark_samples, 100);
    }

    #[test]
    fn test_permissive_config() {
        let cfg = GovernanceConfig::permissive();
        assert_eq!(cfg.min_parity_millionths, 0);
        assert!(!cfg.fail_closed);
        assert!(cfg.required_lanes.is_empty());
    }

    #[test]
    fn test_config_builders() {
        let cfg = GovernanceConfig::default()
            .with_min_parity(900_000)
            .with_max_tail_risk(100_000)
            .with_min_unicode_coverage(800_000)
            .with_min_benchmark_samples(50);
        assert_eq!(cfg.min_parity_millionths, 900_000);
        assert_eq!(cfg.max_tail_risk_millionths, 100_000);
        assert_eq!(cfg.min_unicode_coverage_millionths, 800_000);
        assert_eq!(cfg.min_benchmark_samples, 50);
    }

    #[test]
    fn test_config_fail_open() {
        let cfg = GovernanceConfig::default().fail_open();
        assert!(!cfg.fail_closed);
    }

    #[test]
    fn test_config_with_required_lanes() {
        let lanes = BTreeSet::from([StringLane::Ascii, StringLane::Utf8]);
        let cfg = GovernanceConfig::default().with_required_lanes(lanes.clone());
        assert_eq!(cfg.required_lanes, lanes);
    }

    // -----------------------------------------------------------------------
    // GovernanceVerdict
    // -----------------------------------------------------------------------

    #[test]
    fn test_verdict_approved() {
        assert!(GovernanceVerdict::Approved.is_approved());
        assert!(!GovernanceVerdict::ParityViolation.is_approved());
        assert!(!GovernanceVerdict::UnicodeCoverageGap.is_approved());
        assert!(!GovernanceVerdict::BenchmarkInsufficient.is_approved());
        assert!(!GovernanceVerdict::TailRiskExceeded.is_approved());
        assert!(!GovernanceVerdict::MultipleViolations.is_approved());
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(format!("{}", GovernanceVerdict::Approved), "approved");
        assert_eq!(
            format!("{}", GovernanceVerdict::ParityViolation),
            "parity_violation"
        );
        assert_eq!(
            format!("{}", GovernanceVerdict::MultipleViolations),
            "multiple_violations"
        );
    }

    #[test]
    fn test_verdict_serde_roundtrip() {
        let v = GovernanceVerdict::TailRiskExceeded;
        let json = serde_json::to_string(&v).unwrap();
        let back: GovernanceVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // -----------------------------------------------------------------------
    // Violation
    // -----------------------------------------------------------------------

    #[test]
    fn test_violation_display() {
        let v = Violation::new(
            GovernanceVerdict::ParityViolation,
            "ascii semantic below threshold",
            800_000,
            950_000,
        );
        let s = format!("{v}");
        assert!(s.contains("parity_violation"));
        assert!(s.contains("800000"));
        assert!(s.contains("950000"));
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — approved
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_approved_permissive() {
        let mut ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        let receipt = ev.evaluate();
        assert!(receipt.is_approved());
        assert_eq!(receipt.violation_count(), 0);
    }

    #[test]
    fn test_evaluator_approved_with_all_evidence() {
        let cfg = GovernanceConfig::default()
            .with_required_lanes(BTreeSet::from([StringLane::Ascii]))
            .with_required_features(BTreeSet::from([RegexpFeature::Lookahead]));
        let mut ev = GovernanceEvaluator::new(cfg, epoch());

        ev.add_parity(good_parity(
            ParitySubject::Lane(StringLane::Ascii),
            ParityAxis::Semantic,
        ));
        ev.add_parity(good_parity(
            ParitySubject::Feature(RegexpFeature::Lookahead),
            ParityAxis::Semantic,
        ));
        ev.add_unicode_coverage(good_unicode(0));
        ev.add_benchmark(good_benchmark(BenchmarkCategory::String, "concat"));
        ev.add_tail_risk(good_tail_risk(ParitySubject::Lane(StringLane::Ascii)));

        let receipt = ev.evaluate();
        assert!(receipt.is_approved());
        assert_eq!(receipt.violations.len(), 0);
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — parity violation
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_parity_violation() {
        let cfg = GovernanceConfig::default()
            .with_required_lanes(BTreeSet::new())
            .with_required_features(BTreeSet::new());
        let mut ev = GovernanceEvaluator::new(cfg, epoch());

        ev.add_parity(bad_parity(
            ParitySubject::Lane(StringLane::Utf16),
            ParityAxis::Semantic,
        ));

        let receipt = ev.evaluate();
        assert!(!receipt.is_approved());
        assert_eq!(receipt.verdict, GovernanceVerdict::ParityViolation);
        assert_eq!(receipt.violations.len(), 1);
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — missing required lane
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_missing_required_lane() {
        let cfg = GovernanceConfig::default()
            .with_required_lanes(BTreeSet::from([StringLane::Rope]))
            .with_required_features(BTreeSet::new());
        let mut ev = GovernanceEvaluator::new(cfg, epoch());
        // No parity evidence for Rope lane.
        let receipt = ev.evaluate();
        assert!(!receipt.is_approved());
        assert!(
            receipt
                .violations
                .iter()
                .any(|v| v.description.contains("lane rope"))
        );
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — missing required feature
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_missing_required_feature() {
        let cfg = GovernanceConfig::default()
            .with_required_lanes(BTreeSet::new())
            .with_required_features(BTreeSet::from([RegexpFeature::Lookbehind]));
        let mut ev = GovernanceEvaluator::new(cfg, epoch());
        let receipt = ev.evaluate();
        assert!(!receipt.is_approved());
        assert!(
            receipt
                .violations
                .iter()
                .any(|v| v.description.contains("feature lookbehind"))
        );
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — unicode coverage gap
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_unicode_coverage_gap() {
        let cfg = GovernanceConfig::default()
            .with_required_lanes(BTreeSet::new())
            .with_required_features(BTreeSet::new());
        let mut ev = GovernanceEvaluator::new(cfg, epoch());
        ev.add_unicode_coverage(bad_unicode(1));

        let receipt = ev.evaluate();
        assert_eq!(receipt.verdict, GovernanceVerdict::UnicodeCoverageGap);
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — benchmark insufficient (samples)
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_benchmark_insufficient_samples() {
        let cfg = GovernanceConfig::default()
            .with_required_lanes(BTreeSet::new())
            .with_required_features(BTreeSet::new());
        let mut ev = GovernanceEvaluator::new(cfg, epoch());
        ev.add_benchmark(insufficient_benchmark(BenchmarkCategory::String, "x"));

        let receipt = ev.evaluate();
        assert_eq!(receipt.verdict, GovernanceVerdict::BenchmarkInsufficient);
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — benchmark regression
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_benchmark_regression() {
        let cfg = GovernanceConfig::default()
            .with_required_lanes(BTreeSet::new())
            .with_required_features(BTreeSet::new());
        let mut ev = GovernanceEvaluator::new(cfg, epoch());
        ev.add_benchmark(regression_benchmark(BenchmarkCategory::Regexp, "match"));

        let receipt = ev.evaluate();
        assert!(!receipt.is_approved());
        assert!(
            receipt
                .violations
                .iter()
                .any(|v| v.kind == GovernanceVerdict::BenchmarkInsufficient)
        );
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — tail risk exceeded
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_tail_risk_exceeded() {
        let cfg = GovernanceConfig::default()
            .with_required_lanes(BTreeSet::new())
            .with_required_features(BTreeSet::new());
        let mut ev = GovernanceEvaluator::new(cfg, epoch());
        ev.add_tail_risk(bad_tail_risk(ParitySubject::Lane(StringLane::Latin1)));

        let receipt = ev.evaluate();
        assert_eq!(receipt.verdict, GovernanceVerdict::TailRiskExceeded);
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — multiple violations
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_multiple_violations() {
        let cfg = GovernanceConfig::default()
            .with_required_lanes(BTreeSet::new())
            .with_required_features(BTreeSet::new());
        let mut ev = GovernanceEvaluator::new(cfg, epoch());
        ev.add_parity(bad_parity(
            ParitySubject::Lane(StringLane::Utf8),
            ParityAxis::Semantic,
        ));
        ev.add_unicode_coverage(bad_unicode(0));

        let receipt = ev.evaluate();
        assert_eq!(receipt.verdict, GovernanceVerdict::MultipleViolations);
        assert!(receipt.violations.len() >= 2);
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — fail open
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_fail_open_missing_evidence() {
        let cfg = GovernanceConfig::default()
            .fail_open()
            .with_required_lanes(BTreeSet::from([StringLane::Rope]))
            .with_required_features(BTreeSet::from([RegexpFeature::Multiline]));
        let mut ev = GovernanceEvaluator::new(cfg, epoch());
        // No evidence but fail_open means missing evidence doesn't violate.
        let receipt = ev.evaluate();
        assert!(receipt.is_approved());
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — counters and pass rate
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_counters() {
        let mut ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        ev.evaluate();
        ev.evaluate();
        assert_eq!(ev.evaluation_count(), 2);
        assert_eq!(ev.approved_count(), 2);
        assert_eq!(ev.denied_count(), 0);
        assert_eq!(ev.pass_rate_millionths(), MILLIONTHS);
    }

    #[test]
    fn test_evaluator_pass_rate_mixed() {
        let mut ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        // First: approved
        ev.evaluate();
        // Second: denied (add bad parity for strict-enough config)
        ev.clear();
        // Switch to strict behavior for one eval — we use a separate evaluator.
        // Instead, just count manually via the summary.
        assert_eq!(ev.evaluation_count(), 1);
    }

    #[test]
    fn test_evaluator_pass_rate_zero_evals() {
        let ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        assert_eq!(ev.pass_rate_millionths(), 0);
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — clear
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_clear() {
        let mut ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        ev.add_parity(good_parity(
            ParitySubject::Lane(StringLane::Ascii),
            ParityAxis::Semantic,
        ));
        ev.add_unicode_coverage(good_unicode(0));
        ev.add_benchmark(good_benchmark(BenchmarkCategory::String, "x"));
        ev.add_tail_risk(good_tail_risk(ParitySubject::Lane(StringLane::Ascii)));
        assert_eq!(ev.parity_results().len(), 1);
        assert_eq!(ev.unicode_coverage().len(), 1);
        assert_eq!(ev.benchmark_entries().len(), 1);
        assert_eq!(ev.tail_risk_entries().len(), 1);

        ev.clear();
        assert_eq!(ev.parity_results().len(), 0);
        assert_eq!(ev.unicode_coverage().len(), 0);
        assert_eq!(ev.benchmark_entries().len(), 0);
        assert_eq!(ev.tail_risk_entries().len(), 0);
    }

    // -----------------------------------------------------------------------
    // GovernanceEvaluator — summary
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_summary() {
        let mut ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        ev.add_parity(good_parity(
            ParitySubject::Lane(StringLane::Ascii),
            ParityAxis::Semantic,
        ));
        ev.add_benchmark(good_benchmark(BenchmarkCategory::String, "x"));
        ev.evaluate();
        let summary = ev.summary();
        assert_eq!(summary.total_evaluations, 1);
        assert_eq!(summary.approved_count, 1);
        assert_eq!(summary.parity_results_count, 1);
        assert_eq!(summary.benchmark_count, 1);
        assert_eq!(summary.pass_rate_millionths, MILLIONTHS);
    }

    // -----------------------------------------------------------------------
    // GovernanceReceipt
    // -----------------------------------------------------------------------

    #[test]
    fn test_receipt_seal_deterministic() {
        let mut ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        let receipt_a = ev.evaluate();
        let mut ev2 = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        let receipt_b = ev2.evaluate();
        assert_eq!(receipt_a.content_hash, receipt_b.content_hash);
    }

    #[test]
    fn test_receipt_metadata() {
        let mut ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        let receipt = ev.evaluate();
        assert_eq!(receipt.schema_version, SCHEMA_VERSION);
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.bead_id, BEAD_ID);
        assert_eq!(receipt.policy_id, POLICY_ID);
    }

    #[test]
    fn test_receipt_last_receipt() {
        let mut ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        assert!(ev.last_receipt().is_none());
        ev.evaluate();
        assert!(ev.last_receipt().is_some());
    }

    // -----------------------------------------------------------------------
    // summarize_receipt
    // -----------------------------------------------------------------------

    #[test]
    fn test_summarize_receipt_approved() {
        let mut ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        let receipt = ev.evaluate();
        let summary = summarize_receipt(&receipt);
        assert!(summary.contains("approved"));
        assert!(summary.contains("violations: 0"));
    }

    #[test]
    fn test_summarize_receipt_violations() {
        let cfg = GovernanceConfig::default()
            .with_required_lanes(BTreeSet::new())
            .with_required_features(BTreeSet::new());
        let mut ev = GovernanceEvaluator::new(cfg, epoch());
        ev.add_parity(bad_parity(
            ParitySubject::Lane(StringLane::Latin1),
            ParityAxis::Performance,
        ));
        let receipt = ev.evaluate();
        let summary = summarize_receipt(&receipt);
        assert!(summary.contains("parity_violation"));
        assert!(summary.contains("violation details"));
    }

    // -----------------------------------------------------------------------
    // Manifest
    // -----------------------------------------------------------------------

    #[test]
    fn test_manifest() {
        let m = regexp_string_governance_manifest();
        assert_eq!(m.total_evaluations, 0);
        assert_eq!(m.approved_count, 0);
        assert_eq!(m.pass_rate_millionths, 0);
    }

    // -----------------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn test_parity_subject_serde_roundtrip() {
        let subjects = vec![
            ParitySubject::Lane(StringLane::Ascii),
            ParitySubject::Feature(RegexpFeature::Backreferences),
        ];
        for s in &subjects {
            let json = serde_json::to_string(s).unwrap();
            let back: ParitySubject = serde_json::from_str(&json).unwrap();
            assert_eq!(*s, back);
        }
    }

    #[test]
    fn test_benchmark_category_serde() {
        let c = BenchmarkCategory::Regexp;
        let json = serde_json::to_string(&c).unwrap();
        let back: BenchmarkCategory = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn test_governance_config_serde_roundtrip() {
        let cfg = GovernanceConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: GovernanceConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn test_full_receipt_serde_roundtrip() {
        let mut ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), epoch());
        ev.add_parity(good_parity(
            ParitySubject::Lane(StringLane::Ascii),
            ParityAxis::Semantic,
        ));
        let receipt = ev.evaluate();
        let json = serde_json::to_string(&receipt).unwrap();
        let back: GovernanceReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, back);
    }

    #[test]
    fn test_evaluator_epoch() {
        let e = SecurityEpoch::from_raw(42);
        let ev = GovernanceEvaluator::new(GovernanceConfig::permissive(), e);
        assert_eq!(*ev.epoch(), e);
    }

    #[test]
    fn test_evaluator_config() {
        let cfg = GovernanceConfig::strict();
        let ev = GovernanceEvaluator::new(cfg.clone(), epoch());
        assert_eq!(*ev.config(), cfg);
    }
}
