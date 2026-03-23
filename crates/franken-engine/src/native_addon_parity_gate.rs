//! Bead: bd-1lsy.5.9.3 [RGC-407C]
//!
//! Parity, security, throughput, and support-surface gates for native-addon
//! cohorts.
//!
//! Ensures compatibility progress across native-addon cohorts is
//! evidence-backed rather than anecdotal.  Each cohort (Crypto,
//! ImageProcessing, Compression, etc.) is evaluated along five axes:
//!
//! 1. **Parity** — behavioral equivalence between native and membrane paths.
//! 2. **Security** — known vulnerability findings (buffer overflow, UAF, etc.).
//! 3. **Throughput** — overhead of the membrane path vs raw native.
//! 4. **SupportSurface** — API coverage within each cohort.
//! 5. **MemorySafety** — additional memory-safety gate for native code.
//!
//! A `GateEvaluator` accumulates evidence entries and produces a
//! `GateReceipt` with an auditable verdict and content hash.
//!
//! All fractional values use fixed-point millionths (1_000_000 = 1.0).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.native-addon-parity-gate.v1";

/// Component name.
pub const COMPONENT: &str = "native_addon_parity_gate";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.5.9.3";

/// Policy reference.
pub const POLICY_ID: &str = "RGC-407C";

/// Fixed-point unit: 1.0 in millionths.
pub const MILLIONTHS: u64 = 1_000_000;

/// Default minimum parity ratio (millionths). 950_000 = 95%.
pub const DEFAULT_MIN_PARITY_MILLIONTHS: u64 = 950_000;

/// Default maximum throughput overhead (millionths). 100_000 = 10%.
pub const DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS: u64 = 100_000;

/// Default maximum critical/high security findings before blocking.
pub const DEFAULT_MAX_SECURITY_FINDINGS: usize = 0;

/// Default minimum support-surface coverage (millionths). 800_000 = 80%.
pub const DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS: u64 = 800_000;

/// Default minimum sample count for parity evidence.
pub const DEFAULT_MIN_SAMPLE_COUNT: u64 = 30;

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
// AddonCohort
// ---------------------------------------------------------------------------

/// Native-addon cohort — a functional domain grouping addons by purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddonCohort {
    /// Cryptographic operations (hashing, encryption, signing).
    Crypto,
    /// Image processing (resize, transcode, filter).
    ImageProcessing,
    /// Compression / decompression (zlib, brotli, zstd).
    Compression,
    /// Database drivers and connection pools.
    Database,
    /// Machine-learning inference and model loading.
    MachineLearning,
    /// System integration (OS APIs, IPC, signals).
    SystemIntegration,
    /// Media codecs (audio/video encode/decode).
    MediaCodec,
    /// Networking (TLS, HTTP/2, QUIC).
    Networking,
}

impl AddonCohort {
    /// All cohort variants.
    pub const ALL: &[Self] = &[
        Self::Crypto,
        Self::ImageProcessing,
        Self::Compression,
        Self::Database,
        Self::MachineLearning,
        Self::SystemIntegration,
        Self::MediaCodec,
        Self::Networking,
    ];

    /// String label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Crypto => "crypto",
            Self::ImageProcessing => "image_processing",
            Self::Compression => "compression",
            Self::Database => "database",
            Self::MachineLearning => "machine_learning",
            Self::SystemIntegration => "system_integration",
            Self::MediaCodec => "media_codec",
            Self::Networking => "networking",
        }
    }
}

impl fmt::Display for AddonCohort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// GateAxis
// ---------------------------------------------------------------------------

/// Evaluation axis for the native-addon gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateAxis {
    /// Behavioral parity between native and membrane paths.
    Parity,
    /// Known security vulnerabilities.
    Security,
    /// Throughput overhead of the membrane path.
    Throughput,
    /// API coverage within a cohort.
    SupportSurface,
    /// Memory-safety gate for native code.
    MemorySafety,
}

impl GateAxis {
    /// All axis variants.
    pub const ALL: &[Self] = &[
        Self::Parity,
        Self::Security,
        Self::Throughput,
        Self::SupportSurface,
        Self::MemorySafety,
    ];

    /// String label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Parity => "parity",
            Self::Security => "security",
            Self::Throughput => "throughput",
            Self::SupportSurface => "support_surface",
            Self::MemorySafety => "memory_safety",
        }
    }
}

impl fmt::Display for GateAxis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// FindingSeverity
// ---------------------------------------------------------------------------

/// Severity of a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    /// Exploitable remotely with no user interaction.
    Critical,
    /// Significant impact, likely exploitable.
    High,
    /// Moderate impact, limited exploitability.
    Medium,
    /// Informational or low impact.
    Low,
}

impl FindingSeverity {
    /// All severity variants.
    pub const ALL: &[Self] = &[Self::Critical, Self::High, Self::Medium, Self::Low];

    /// String label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Whether this severity is blocking (Critical or High).
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Critical | Self::High)
    }
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// FindingCategory
// ---------------------------------------------------------------------------

/// Category of a security finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    /// Out-of-bounds read or write.
    BufferOverflow,
    /// Access to freed memory.
    UseAfterFree,
    /// Type confusion leading to memory corruption.
    TypeConfusion,
    /// Injection (command, SQL, path traversal, etc.).
    Injection,
    /// Information leakage (side-channel, heap spray, etc.).
    InfoLeak,
}

impl FindingCategory {
    /// All category variants.
    pub const ALL: &[Self] = &[
        Self::BufferOverflow,
        Self::UseAfterFree,
        Self::TypeConfusion,
        Self::Injection,
        Self::InfoLeak,
    ];

    /// String label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BufferOverflow => "buffer_overflow",
            Self::UseAfterFree => "use_after_free",
            Self::TypeConfusion => "type_confusion",
            Self::Injection => "injection",
            Self::InfoLeak => "info_leak",
        }
    }
}

impl fmt::Display for FindingCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SecurityFinding
// ---------------------------------------------------------------------------

/// A security finding against a native addon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityFinding {
    /// Severity of the finding.
    pub severity: FindingSeverity,
    /// Category of the vulnerability.
    pub category: FindingCategory,
    /// Name of the addon where the finding was discovered.
    pub addon_name: String,
    /// Human-readable description.
    pub description: String,
    /// Content hash of the finding.
    pub content_hash: ContentHash,
}

impl SecurityFinding {
    /// Create a new security finding with computed content hash.
    pub fn new(
        severity: FindingSeverity,
        category: FindingCategory,
        addon_name: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        let addon_name = addon_name.into();
        let description = description.into();
        let mut buf = Vec::new();
        append_str(&mut buf, severity.as_str());
        append_str(&mut buf, category.as_str());
        append_str(&mut buf, &addon_name);
        append_str(&mut buf, &description);
        let content_hash = compute_digest(&buf);
        Self {
            severity,
            category,
            addon_name,
            description,
            content_hash,
        }
    }

    /// Whether this finding is blocking (Critical or High severity).
    pub fn is_blocking(&self) -> bool {
        self.severity.is_blocking()
    }
}

// ---------------------------------------------------------------------------
// ThroughputEntry
// ---------------------------------------------------------------------------

/// Throughput measurement for a single addon within a cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThroughputEntry {
    /// Cohort the addon belongs to.
    pub cohort: AddonCohort,
    /// Name of the addon measured.
    pub addon_name: String,
    /// Native (raw) throughput in operations per second.
    pub native_throughput_ops: u64,
    /// Membrane-mediated throughput in operations per second.
    pub membrane_throughput_ops: u64,
    /// Overhead in millionths: (native - membrane) / native * 1_000_000.
    pub overhead_millionths: u64,
    /// Whether the overhead is within the configured budget.
    pub within_budget: bool,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl ThroughputEntry {
    /// Create a new throughput entry with computed overhead and content hash.
    pub fn new(
        cohort: AddonCohort,
        addon_name: impl Into<String>,
        native_throughput_ops: u64,
        membrane_throughput_ops: u64,
        max_overhead_millionths: u64,
    ) -> Self {
        let addon_name = addon_name.into();
        let overhead_millionths = if native_throughput_ops == 0 {
            0
        } else {
            native_throughput_ops
                .saturating_sub(membrane_throughput_ops)
                .saturating_mul(MILLIONTHS)
                .checked_div(native_throughput_ops)
                .unwrap_or(0)
        };
        let within_budget = overhead_millionths <= max_overhead_millionths;
        let mut buf = Vec::new();
        append_str(&mut buf, cohort.as_str());
        append_str(&mut buf, &addon_name);
        append_u64(&mut buf, native_throughput_ops);
        append_u64(&mut buf, membrane_throughput_ops);
        append_u64(&mut buf, overhead_millionths);
        let content_hash = compute_digest(&buf);
        Self {
            cohort,
            addon_name,
            native_throughput_ops,
            membrane_throughput_ops,
            overhead_millionths,
            within_budget,
            content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// ParityEntry
// ---------------------------------------------------------------------------

/// Parity measurement for a single addon on a specific axis.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParityEntry {
    /// Cohort the addon belongs to.
    pub cohort: AddonCohort,
    /// Name of the addon measured.
    pub addon_name: String,
    /// Axis being measured.
    pub axis: GateAxis,
    /// Parity ratio in millionths (1_000_000 = 100% parity).
    pub parity_millionths: u64,
    /// Number of samples used in the measurement.
    pub sample_count: u64,
    /// Whether parity meets the configured minimum.
    pub passes: bool,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl ParityEntry {
    /// Create a new parity entry with computed content hash.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        cohort: AddonCohort,
        addon_name: impl Into<String>,
        axis: GateAxis,
        parity_millionths: u64,
        sample_count: u64,
        min_parity_millionths: u64,
        min_sample_count: u64,
    ) -> Self {
        let addon_name = addon_name.into();
        let passes = parity_millionths >= min_parity_millionths && sample_count >= min_sample_count;
        let mut buf = Vec::new();
        append_str(&mut buf, cohort.as_str());
        append_str(&mut buf, &addon_name);
        append_str(&mut buf, axis.as_str());
        append_u64(&mut buf, parity_millionths);
        append_u64(&mut buf, sample_count);
        let content_hash = compute_digest(&buf);
        Self {
            cohort,
            addon_name,
            axis,
            parity_millionths,
            sample_count,
            passes,
            content_hash,
        }
    }
}

// ---------------------------------------------------------------------------
// SupportSurfaceEntry
// ---------------------------------------------------------------------------

/// API coverage measurement for a cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportSurfaceEntry {
    /// Cohort being measured.
    pub cohort: AddonCohort,
    /// Number of APIs supported through the membrane.
    pub supported_apis: u64,
    /// Total number of APIs in the cohort.
    pub total_apis: u64,
    /// Coverage in millionths (supported / total * 1_000_000).
    pub coverage_millionths: u64,
    /// Content hash.
    pub content_hash: ContentHash,
}

impl SupportSurfaceEntry {
    /// Create a new support-surface entry with computed coverage.
    pub fn new(cohort: AddonCohort, supported_apis: u64, total_apis: u64) -> Self {
        let coverage_millionths = if total_apis == 0 {
            0
        } else {
            supported_apis
                .saturating_mul(MILLIONTHS)
                .checked_div(total_apis)
                .unwrap_or(0)
        };
        let mut buf = Vec::new();
        append_str(&mut buf, cohort.as_str());
        append_u64(&mut buf, supported_apis);
        append_u64(&mut buf, total_apis);
        let content_hash = compute_digest(&buf);
        Self {
            cohort,
            supported_apis,
            total_apis,
            coverage_millionths,
            content_hash,
        }
    }

    /// Whether the coverage meets the given minimum.
    pub fn meets_minimum(&self, min_coverage_millionths: u64) -> bool {
        self.coverage_millionths >= min_coverage_millionths
    }
}

// ---------------------------------------------------------------------------
// GateConfig
// ---------------------------------------------------------------------------

/// Configuration for the native-addon parity gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateConfig {
    /// Minimum parity ratio (millionths) across all axes.
    pub min_parity_millionths: u64,
    /// Maximum throughput overhead (millionths) before blocking.
    pub max_throughput_overhead_millionths: u64,
    /// Maximum number of blocking (Critical/High) security findings.
    pub max_security_findings: usize,
    /// Minimum support-surface coverage (millionths).
    pub min_support_coverage_millionths: u64,
    /// Minimum sample count for parity evidence.
    pub min_sample_count: u64,
    /// Set of cohorts that must be present for approval.
    pub required_cohorts: BTreeSet<AddonCohort>,
    /// Whether to fail closed (deny) on missing evidence.
    pub fail_closed: bool,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            min_parity_millionths: DEFAULT_MIN_PARITY_MILLIONTHS,
            max_throughput_overhead_millionths: DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS,
            max_security_findings: DEFAULT_MAX_SECURITY_FINDINGS,
            min_support_coverage_millionths: DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS,
            min_sample_count: DEFAULT_MIN_SAMPLE_COUNT,
            required_cohorts: BTreeSet::new(),
            fail_closed: true,
        }
    }
}

impl GateConfig {
    /// Set the minimum parity threshold.
    pub fn with_min_parity(mut self, millionths: u64) -> Self {
        self.min_parity_millionths = millionths;
        self
    }

    /// Set the maximum throughput overhead.
    pub fn with_max_overhead(mut self, millionths: u64) -> Self {
        self.max_throughput_overhead_millionths = millionths;
        self
    }

    /// Set the maximum blocking security findings.
    pub fn with_max_security_findings(mut self, max: usize) -> Self {
        self.max_security_findings = max;
        self
    }

    /// Set the minimum support-surface coverage.
    pub fn with_min_support_coverage(mut self, millionths: u64) -> Self {
        self.min_support_coverage_millionths = millionths;
        self
    }

    /// Set the minimum sample count.
    pub fn with_min_samples(mut self, count: u64) -> Self {
        self.min_sample_count = count;
        self
    }

    /// Add a required cohort.
    pub fn with_required_cohort(mut self, cohort: AddonCohort) -> Self {
        self.required_cohorts.insert(cohort);
        self
    }

    /// Use fail-open semantics.
    pub fn fail_open(mut self) -> Self {
        self.fail_closed = false;
        self
    }

    /// Strict configuration: zero tolerance for security, 99% parity.
    pub fn strict() -> Self {
        let mut required = BTreeSet::new();
        for c in AddonCohort::ALL {
            required.insert(*c);
        }
        Self {
            min_parity_millionths: 990_000,
            max_throughput_overhead_millionths: 50_000,
            max_security_findings: 0,
            min_support_coverage_millionths: 900_000,
            min_sample_count: 50,
            required_cohorts: required,
            fail_closed: true,
        }
    }

    /// Permissive configuration for development.
    pub fn permissive() -> Self {
        Self {
            min_parity_millionths: 0,
            max_throughput_overhead_millionths: MILLIONTHS,
            max_security_findings: usize::MAX,
            min_support_coverage_millionths: 0,
            min_sample_count: 0,
            required_cohorts: BTreeSet::new(),
            fail_closed: false,
        }
    }
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// Overall verdict from the native-addon parity gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// All axes pass within budget.
    Approved,
    /// One or more parity entries failed.
    ParityViolation,
    /// Blocking security findings exceed the threshold.
    SecurityBlocking,
    /// Throughput overhead exceeds the budget.
    ThroughputExceeded,
    /// Support-surface coverage is insufficient.
    SupportInsufficient,
    /// Multiple axes violated simultaneously.
    MultipleViolations,
}

impl GateVerdict {
    /// String label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::ParityViolation => "parity_violation",
            Self::SecurityBlocking => "security_blocking",
            Self::ThroughputExceeded => "throughput_exceeded",
            Self::SupportInsufficient => "support_insufficient",
            Self::MultipleViolations => "multiple_violations",
        }
    }

    /// Whether the gate approved.
    #[must_use]
    pub const fn is_approved(self) -> bool {
        matches!(self, Self::Approved)
    }

    /// Whether the gate blocked.
    #[must_use]
    pub const fn is_blocking(self) -> bool {
        !matches!(self, Self::Approved)
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Violation
// ---------------------------------------------------------------------------

/// A specific violation detected during gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    /// Which axis was violated.
    pub axis: GateAxis,
    /// Cohort involved (if applicable).
    pub cohort: Option<AddonCohort>,
    /// Human-readable description of the violation.
    pub description: String,
}

impl Violation {
    /// Create a new violation.
    pub fn new(
        axis: GateAxis,
        cohort: Option<AddonCohort>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            axis,
            cohort,
            description: description.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// GateReceipt
// ---------------------------------------------------------------------------

/// Auditable receipt from a gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReceipt {
    /// Schema version.
    pub schema_version: String,
    /// Component name.
    pub component: String,
    /// Bead identifier.
    pub bead_id: String,
    /// Policy identifier.
    pub policy_id: String,
    /// Security epoch.
    pub epoch: SecurityEpoch,
    /// Overall verdict.
    pub verdict: GateVerdict,
    /// Parity entries evaluated.
    pub parity_entries: Vec<ParityEntry>,
    /// Security findings evaluated.
    pub security_findings: Vec<SecurityFinding>,
    /// Throughput entries evaluated.
    pub throughput_entries: Vec<ThroughputEntry>,
    /// Support-surface entries evaluated.
    pub support_surface_entries: Vec<SupportSurfaceEntry>,
    /// Violations that caused a non-approved verdict.
    pub violations: Vec<Violation>,
    /// Cohorts observed in the evidence.
    pub observed_cohorts: BTreeSet<AddonCohort>,
    /// Missing required cohorts.
    pub missing_cohorts: BTreeSet<AddonCohort>,
    /// Content hash over the entire receipt.
    pub content_hash: ContentHash,
}

impl GateReceipt {
    /// Whether the gate approved.
    pub fn is_approved(&self) -> bool {
        self.verdict.is_approved()
    }

    /// Number of violations.
    pub fn violation_count(&self) -> usize {
        self.violations.len()
    }

    /// Number of blocking security findings.
    pub fn blocking_finding_count(&self) -> usize {
        self.security_findings
            .iter()
            .filter(|f| f.is_blocking())
            .count()
    }

    /// Recompute the content hash.
    pub fn seal(&mut self) {
        let mut buf = Vec::new();
        append_str(&mut buf, SCHEMA_VERSION);
        append_str(&mut buf, COMPONENT);
        append_str(&mut buf, BEAD_ID);
        append_str(&mut buf, POLICY_ID);
        append_u64(&mut buf, self.epoch.as_u64());
        append_str(&mut buf, self.verdict.as_str());
        append_u64(&mut buf, self.parity_entries.len() as u64);
        {
            let mut sorted: Vec<&[u8; 32]> = self
                .parity_entries
                .iter()
                .map(|p| p.content_hash.as_bytes())
                .collect();
            sorted.sort();
            for h in &sorted {
                buf.extend_from_slice(*h);
            }
        }
        append_u64(&mut buf, self.security_findings.len() as u64);
        {
            let mut sorted: Vec<&[u8; 32]> = self
                .security_findings
                .iter()
                .map(|f| f.content_hash.as_bytes())
                .collect();
            sorted.sort();
            for h in &sorted {
                buf.extend_from_slice(*h);
            }
        }
        append_u64(&mut buf, self.throughput_entries.len() as u64);
        {
            let mut sorted: Vec<&[u8; 32]> = self
                .throughput_entries
                .iter()
                .map(|t| t.content_hash.as_bytes())
                .collect();
            sorted.sort();
            for h in &sorted {
                buf.extend_from_slice(*h);
            }
        }
        append_u64(&mut buf, self.support_surface_entries.len() as u64);
        {
            let mut sorted: Vec<&[u8; 32]> = self
                .support_surface_entries
                .iter()
                .map(|s| s.content_hash.as_bytes())
                .collect();
            sorted.sort();
            for h in &sorted {
                buf.extend_from_slice(*h);
            }
        }
        append_u64(&mut buf, self.violations.len() as u64);
        for v in &self.violations {
            append_str(&mut buf, v.axis.as_str());
            append_str(&mut buf, &v.description);
        }
        self.content_hash = compute_digest(&buf);
    }
}

// ---------------------------------------------------------------------------
// GateEvaluator
// ---------------------------------------------------------------------------

/// Evaluator for the native-addon parity gate.
///
/// Accumulates evidence entries across all axes and produces a `GateReceipt`
/// via `evaluate()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateEvaluator {
    /// Gate configuration.
    config: GateConfig,
    /// Security epoch.
    epoch: SecurityEpoch,
    /// Accumulated parity entries.
    parity_entries: Vec<ParityEntry>,
    /// Accumulated security findings.
    security_findings: Vec<SecurityFinding>,
    /// Accumulated throughput entries.
    throughput_entries: Vec<ThroughputEntry>,
    /// Accumulated support-surface entries.
    support_surface_entries: Vec<SupportSurfaceEntry>,
    /// Total evaluations.
    evaluation_count: u64,
    /// Total approvals.
    approved_count: u64,
    /// Total denials.
    denied_count: u64,
    /// Most recent receipt.
    last_receipt: Option<GateReceipt>,
}

impl GateEvaluator {
    /// Create a new evaluator.
    pub fn new(config: GateConfig, epoch: SecurityEpoch) -> Self {
        Self {
            config,
            epoch,
            parity_entries: Vec::new(),
            security_findings: Vec::new(),
            throughput_entries: Vec::new(),
            support_surface_entries: Vec::new(),
            evaluation_count: 0,
            approved_count: 0,
            denied_count: 0,
            last_receipt: None,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults(epoch: SecurityEpoch) -> Self {
        Self::new(GateConfig::default(), epoch)
    }

    /// Access configuration.
    pub fn config(&self) -> &GateConfig {
        &self.config
    }

    /// Current epoch.
    pub fn epoch(&self) -> &SecurityEpoch {
        &self.epoch
    }

    /// Total evaluations.
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
    pub fn last_receipt(&self) -> Option<&GateReceipt> {
        self.last_receipt.as_ref()
    }

    /// Number of accumulated parity entries.
    pub fn parity_entry_count(&self) -> usize {
        self.parity_entries.len()
    }

    /// Number of accumulated security findings.
    pub fn security_finding_count(&self) -> usize {
        self.security_findings.len()
    }

    /// Number of accumulated throughput entries.
    pub fn throughput_entry_count(&self) -> usize {
        self.throughput_entries.len()
    }

    /// Number of accumulated support-surface entries.
    pub fn support_surface_entry_count(&self) -> usize {
        self.support_surface_entries.len()
    }

    /// Add a parity entry.
    pub fn add_parity(
        &mut self,
        cohort: AddonCohort,
        addon_name: &str,
        axis: GateAxis,
        parity_millionths: u64,
        sample_count: u64,
    ) {
        let entry = ParityEntry::new(
            cohort,
            addon_name,
            axis,
            parity_millionths,
            sample_count,
            self.config.min_parity_millionths,
            self.config.min_sample_count,
        );
        self.parity_entries.push(entry);
    }

    /// Add a security finding.
    pub fn add_security_finding(
        &mut self,
        severity: FindingSeverity,
        category: FindingCategory,
        addon_name: &str,
        description: &str,
    ) {
        let finding = SecurityFinding::new(severity, category, addon_name, description);
        self.security_findings.push(finding);
    }

    /// Add a throughput entry.
    pub fn add_throughput(
        &mut self,
        cohort: AddonCohort,
        addon_name: &str,
        native_throughput_ops: u64,
        membrane_throughput_ops: u64,
    ) {
        let entry = ThroughputEntry::new(
            cohort,
            addon_name,
            native_throughput_ops,
            membrane_throughput_ops,
            self.config.max_throughput_overhead_millionths,
        );
        self.throughput_entries.push(entry);
    }

    /// Add a support-surface entry.
    pub fn add_support_surface(
        &mut self,
        cohort: AddonCohort,
        supported_apis: u64,
        total_apis: u64,
    ) {
        let entry = SupportSurfaceEntry::new(cohort, supported_apis, total_apis);
        self.support_surface_entries.push(entry);
    }

    /// Clear all accumulated evidence (for re-evaluation).
    pub fn clear(&mut self) {
        self.parity_entries.clear();
        self.security_findings.clear();
        self.throughput_entries.clear();
        self.support_surface_entries.clear();
    }

    /// Evaluate all accumulated evidence and produce a receipt.
    pub fn evaluate(&mut self) -> GateReceipt {
        self.evaluation_count += 1;
        let mut violations = Vec::new();

        // --- Parity axis ---
        for entry in &self.parity_entries {
            if !entry.passes {
                if entry.sample_count < self.config.min_sample_count {
                    violations.push(Violation::new(
                        GateAxis::Parity,
                        Some(entry.cohort),
                        format!(
                            "addon '{}' has insufficient samples: {} < {}",
                            entry.addon_name, entry.sample_count, self.config.min_sample_count
                        ),
                    ));
                } else {
                    violations.push(Violation::new(
                        GateAxis::Parity,
                        Some(entry.cohort),
                        format!(
                            "addon '{}' parity {}/1000000 below minimum {}/1000000",
                            entry.addon_name,
                            entry.parity_millionths,
                            self.config.min_parity_millionths
                        ),
                    ));
                }
            }
        }

        // --- Security axis ---
        let blocking_count = self
            .security_findings
            .iter()
            .filter(|f| f.is_blocking())
            .count();
        if blocking_count > self.config.max_security_findings {
            violations.push(Violation::new(
                GateAxis::Security,
                None,
                format!(
                    "{} blocking findings exceed maximum {}",
                    blocking_count, self.config.max_security_findings
                ),
            ));
        }

        // --- Throughput axis ---
        for entry in &self.throughput_entries {
            if !entry.within_budget {
                violations.push(Violation::new(
                    GateAxis::Throughput,
                    Some(entry.cohort),
                    format!(
                        "addon '{}' overhead {}/1000000 exceeds budget {}/1000000",
                        entry.addon_name,
                        entry.overhead_millionths,
                        self.config.max_throughput_overhead_millionths
                    ),
                ));
            }
        }

        // --- Support-surface axis ---
        for entry in &self.support_surface_entries {
            if !entry.meets_minimum(self.config.min_support_coverage_millionths) {
                violations.push(Violation::new(
                    GateAxis::SupportSurface,
                    Some(entry.cohort),
                    format!(
                        "cohort '{}' coverage {}/1000000 below minimum {}/1000000",
                        entry.cohort,
                        entry.coverage_millionths,
                        self.config.min_support_coverage_millionths
                    ),
                ));
            }
        }

        // --- Required cohorts ---
        let mut observed_cohorts = BTreeSet::new();
        for entry in &self.parity_entries {
            observed_cohorts.insert(entry.cohort);
        }
        for entry in &self.throughput_entries {
            observed_cohorts.insert(entry.cohort);
        }
        for entry in &self.support_surface_entries {
            observed_cohorts.insert(entry.cohort);
        }

        let missing_cohorts: BTreeSet<AddonCohort> = self
            .config
            .required_cohorts
            .iter()
            .filter(|c| !observed_cohorts.contains(c))
            .copied()
            .collect();

        if !missing_cohorts.is_empty() && self.config.fail_closed {
            for cohort in &missing_cohorts {
                violations.push(Violation::new(
                    GateAxis::SupportSurface,
                    Some(*cohort),
                    format!("required cohort '{}' has no evidence", cohort),
                ));
            }
        }

        // --- Determine verdict ---
        let verdict = if violations.is_empty() {
            GateVerdict::Approved
        } else {
            // Collect which axes were violated.
            let violated_axes: BTreeSet<GateAxis> = violations.iter().map(|v| v.axis).collect();
            if violated_axes.len() > 1 {
                GateVerdict::MultipleViolations
            } else {
                match violated_axes.iter().next().unwrap() {
                    GateAxis::Parity => GateVerdict::ParityViolation,
                    GateAxis::Security => GateVerdict::SecurityBlocking,
                    GateAxis::Throughput => GateVerdict::ThroughputExceeded,
                    GateAxis::SupportSurface => GateVerdict::SupportInsufficient,
                    GateAxis::MemorySafety => GateVerdict::MultipleViolations,
                }
            }
        };

        // Update counters.
        if verdict.is_approved() {
            self.approved_count += 1;
        } else {
            self.denied_count += 1;
        }

        // Build receipt.
        let mut receipt = GateReceipt {
            schema_version: SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            policy_id: POLICY_ID.to_string(),
            epoch: self.epoch,
            verdict,
            parity_entries: self.parity_entries.clone(),
            security_findings: self.security_findings.clone(),
            throughput_entries: self.throughput_entries.clone(),
            support_surface_entries: self.support_surface_entries.clone(),
            violations,
            observed_cohorts,
            missing_cohorts,
            content_hash: ContentHash::compute(b""),
        };
        receipt.seal();
        self.last_receipt = Some(receipt.clone());

        receipt
    }

    /// Approval rate in millionths.
    pub fn approval_rate_millionths(&self) -> u64 {
        if self.evaluation_count == 0 {
            return 0;
        }
        self.approved_count
            .saturating_mul(MILLIONTHS)
            .checked_div(self.evaluation_count)
            .unwrap_or(0)
    }

    /// Summary statistics.
    pub fn summary(&self) -> GateSummary {
        GateSummary {
            total_evaluations: self.evaluation_count,
            approved_count: self.approved_count,
            denied_count: self.denied_count,
            parity_entries: self.parity_entries.len() as u64,
            security_findings: self.security_findings.len() as u64,
            throughput_entries: self.throughput_entries.len() as u64,
            support_surface_entries: self.support_surface_entries.len() as u64,
            approval_rate_millionths: self.approval_rate_millionths(),
        }
    }
}

// ---------------------------------------------------------------------------
// GateSummary
// ---------------------------------------------------------------------------

/// Summary statistics for the gate evaluator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateSummary {
    /// Total evaluations performed.
    pub total_evaluations: u64,
    /// Total approvals.
    pub approved_count: u64,
    /// Total denials.
    pub denied_count: u64,
    /// Accumulated parity entries.
    pub parity_entries: u64,
    /// Accumulated security findings.
    pub security_findings: u64,
    /// Accumulated throughput entries.
    pub throughput_entries: u64,
    /// Accumulated support-surface entries.
    pub support_surface_entries: u64,
    /// Approval rate in millionths.
    pub approval_rate_millionths: u64,
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/// Default manifest for this module.
pub fn native_addon_parity_gate_manifest() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("schema_version".to_string(), SCHEMA_VERSION.to_string());
    m.insert("component".to_string(), COMPONENT.to_string());
    m.insert("bead_id".to_string(), BEAD_ID.to_string());
    m.insert("policy_id".to_string(), POLICY_ID.to_string());
    m
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch() -> SecurityEpoch {
        SecurityEpoch::from_raw(1)
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_schema_version() {
        assert!(SCHEMA_VERSION.contains("native-addon-parity-gate"));
    }

    #[test]
    fn test_bead_id() {
        assert!(BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn test_component() {
        assert_eq!(COMPONENT, "native_addon_parity_gate");
    }

    #[test]
    fn test_policy_id() {
        assert_eq!(POLICY_ID, "RGC-407C");
    }

    #[test]
    fn test_millionths() {
        assert_eq!(MILLIONTHS, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // AddonCohort
    // -----------------------------------------------------------------------

    #[test]
    fn test_addon_cohort_all_count() {
        assert_eq!(AddonCohort::ALL.len(), 8);
    }

    #[test]
    fn test_addon_cohort_display() {
        assert_eq!(format!("{}", AddonCohort::Crypto), "crypto");
        assert_eq!(
            format!("{}", AddonCohort::ImageProcessing),
            "image_processing"
        );
        assert_eq!(
            format!("{}", AddonCohort::MachineLearning),
            "machine_learning"
        );
    }

    #[test]
    fn test_addon_cohort_serde_roundtrip() {
        let c = AddonCohort::Compression;
        let json = serde_json::to_string(&c).unwrap();
        let back: AddonCohort = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn test_addon_cohort_as_str_all() {
        for c in AddonCohort::ALL {
            assert!(!c.as_str().is_empty());
        }
    }

    // -----------------------------------------------------------------------
    // GateAxis
    // -----------------------------------------------------------------------

    #[test]
    fn test_gate_axis_all_count() {
        assert_eq!(GateAxis::ALL.len(), 5);
    }

    #[test]
    fn test_gate_axis_display() {
        assert_eq!(format!("{}", GateAxis::Parity), "parity");
        assert_eq!(format!("{}", GateAxis::Throughput), "throughput");
        assert_eq!(format!("{}", GateAxis::MemorySafety), "memory_safety");
    }

    #[test]
    fn test_gate_axis_serde_roundtrip() {
        let a = GateAxis::Security;
        let json = serde_json::to_string(&a).unwrap();
        let back: GateAxis = serde_json::from_str(&json).unwrap();
        assert_eq!(a, back);
    }

    // -----------------------------------------------------------------------
    // FindingSeverity
    // -----------------------------------------------------------------------

    #[test]
    fn test_finding_severity_blocking() {
        assert!(FindingSeverity::Critical.is_blocking());
        assert!(FindingSeverity::High.is_blocking());
        assert!(!FindingSeverity::Medium.is_blocking());
        assert!(!FindingSeverity::Low.is_blocking());
    }

    #[test]
    fn test_finding_severity_display() {
        assert_eq!(format!("{}", FindingSeverity::Critical), "critical");
        assert_eq!(format!("{}", FindingSeverity::Low), "low");
    }

    #[test]
    fn test_finding_severity_serde() {
        let s = FindingSeverity::High;
        let json = serde_json::to_string(&s).unwrap();
        let back: FindingSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -----------------------------------------------------------------------
    // FindingCategory
    // -----------------------------------------------------------------------

    #[test]
    fn test_finding_category_all_count() {
        assert_eq!(FindingCategory::ALL.len(), 5);
    }

    #[test]
    fn test_finding_category_display() {
        assert_eq!(
            format!("{}", FindingCategory::BufferOverflow),
            "buffer_overflow"
        );
        assert_eq!(format!("{}", FindingCategory::InfoLeak), "info_leak");
    }

    // -----------------------------------------------------------------------
    // SecurityFinding
    // -----------------------------------------------------------------------

    #[test]
    fn test_security_finding_new() {
        let f = SecurityFinding::new(
            FindingSeverity::Critical,
            FindingCategory::BufferOverflow,
            "sharp-crypto",
            "heap overflow in decrypt",
        );
        assert_eq!(f.addon_name, "sharp-crypto");
        assert!(f.is_blocking());
        assert_ne!(f.content_hash, ContentHash::compute(b""));
    }

    #[test]
    fn test_security_finding_non_blocking() {
        let f = SecurityFinding::new(
            FindingSeverity::Low,
            FindingCategory::InfoLeak,
            "some-addon",
            "minor timing leak",
        );
        assert!(!f.is_blocking());
    }

    #[test]
    fn test_security_finding_deterministic_hash() {
        let a = SecurityFinding::new(
            FindingSeverity::High,
            FindingCategory::UseAfterFree,
            "addon-a",
            "uaf in callback",
        );
        let b = SecurityFinding::new(
            FindingSeverity::High,
            FindingCategory::UseAfterFree,
            "addon-a",
            "uaf in callback",
        );
        assert_eq!(a.content_hash, b.content_hash);
    }

    // -----------------------------------------------------------------------
    // ThroughputEntry
    // -----------------------------------------------------------------------

    #[test]
    fn test_throughput_entry_no_overhead() {
        let e = ThroughputEntry::new(
            AddonCohort::Crypto,
            "fast-hash",
            1_000_000,
            1_000_000,
            DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS,
        );
        assert_eq!(e.overhead_millionths, 0);
        assert!(e.within_budget);
    }

    #[test]
    fn test_throughput_entry_some_overhead() {
        let e = ThroughputEntry::new(
            AddonCohort::Compression,
            "zstd-addon",
            1_000_000,
            900_000,
            DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS,
        );
        assert_eq!(e.overhead_millionths, 100_000); // 10%
        assert!(e.within_budget); // exactly at budget
    }

    #[test]
    fn test_throughput_entry_over_budget() {
        let e = ThroughputEntry::new(
            AddonCohort::Database,
            "pg-driver",
            1_000_000,
            800_000,
            DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS,
        );
        assert_eq!(e.overhead_millionths, 200_000); // 20%
        assert!(!e.within_budget);
    }

    #[test]
    fn test_throughput_entry_zero_native() {
        let e = ThroughputEntry::new(
            AddonCohort::Networking,
            "tls-addon",
            0,
            100,
            DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS,
        );
        assert_eq!(e.overhead_millionths, 0);
        assert!(e.within_budget);
    }

    #[test]
    fn test_throughput_entry_deterministic() {
        let a = ThroughputEntry::new(AddonCohort::Crypto, "x", 1000, 900, 100_000);
        let b = ThroughputEntry::new(AddonCohort::Crypto, "x", 1000, 900, 100_000);
        assert_eq!(a.content_hash, b.content_hash);
    }

    // -----------------------------------------------------------------------
    // ParityEntry
    // -----------------------------------------------------------------------

    #[test]
    fn test_parity_entry_passes() {
        let e = ParityEntry::new(
            AddonCohort::Crypto,
            "aes-addon",
            GateAxis::Parity,
            MILLIONTHS, // 100%
            50,
            DEFAULT_MIN_PARITY_MILLIONTHS,
            DEFAULT_MIN_SAMPLE_COUNT,
        );
        assert!(e.passes);
    }

    #[test]
    fn test_parity_entry_fails_low_parity() {
        let e = ParityEntry::new(
            AddonCohort::Crypto,
            "aes-addon",
            GateAxis::Parity,
            900_000, // 90%, below 95%
            50,
            DEFAULT_MIN_PARITY_MILLIONTHS,
            DEFAULT_MIN_SAMPLE_COUNT,
        );
        assert!(!e.passes);
    }

    #[test]
    fn test_parity_entry_fails_low_samples() {
        let e = ParityEntry::new(
            AddonCohort::Crypto,
            "aes-addon",
            GateAxis::Parity,
            MILLIONTHS,
            5, // below min 30
            DEFAULT_MIN_PARITY_MILLIONTHS,
            DEFAULT_MIN_SAMPLE_COUNT,
        );
        assert!(!e.passes);
    }

    #[test]
    fn test_parity_entry_deterministic() {
        let a = ParityEntry::new(
            AddonCohort::Compression,
            "zlib",
            GateAxis::Parity,
            MILLIONTHS,
            100,
            DEFAULT_MIN_PARITY_MILLIONTHS,
            DEFAULT_MIN_SAMPLE_COUNT,
        );
        let b = ParityEntry::new(
            AddonCohort::Compression,
            "zlib",
            GateAxis::Parity,
            MILLIONTHS,
            100,
            DEFAULT_MIN_PARITY_MILLIONTHS,
            DEFAULT_MIN_SAMPLE_COUNT,
        );
        assert_eq!(a.content_hash, b.content_hash);
    }

    // -----------------------------------------------------------------------
    // SupportSurfaceEntry
    // -----------------------------------------------------------------------

    #[test]
    fn test_support_surface_full_coverage() {
        let e = SupportSurfaceEntry::new(AddonCohort::MediaCodec, 100, 100);
        assert_eq!(e.coverage_millionths, MILLIONTHS);
        assert!(e.meets_minimum(DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS));
    }

    #[test]
    fn test_support_surface_half_coverage() {
        let e = SupportSurfaceEntry::new(AddonCohort::Database, 50, 100);
        assert_eq!(e.coverage_millionths, 500_000);
        assert!(!e.meets_minimum(DEFAULT_MIN_SUPPORT_COVERAGE_MILLIONTHS));
    }

    #[test]
    fn test_support_surface_zero_total() {
        let e = SupportSurfaceEntry::new(AddonCohort::Networking, 0, 0);
        assert_eq!(e.coverage_millionths, 0);
    }

    #[test]
    fn test_support_surface_deterministic() {
        let a = SupportSurfaceEntry::new(AddonCohort::Crypto, 80, 100);
        let b = SupportSurfaceEntry::new(AddonCohort::Crypto, 80, 100);
        assert_eq!(a.content_hash, b.content_hash);
    }

    // -----------------------------------------------------------------------
    // GateConfig
    // -----------------------------------------------------------------------

    #[test]
    fn test_config_default() {
        let c = GateConfig::default();
        assert_eq!(c.min_parity_millionths, DEFAULT_MIN_PARITY_MILLIONTHS);
        assert_eq!(
            c.max_throughput_overhead_millionths,
            DEFAULT_MAX_THROUGHPUT_OVERHEAD_MILLIONTHS
        );
        assert_eq!(c.max_security_findings, DEFAULT_MAX_SECURITY_FINDINGS);
        assert!(c.fail_closed);
        assert!(c.required_cohorts.is_empty());
    }

    #[test]
    fn test_config_strict() {
        let c = GateConfig::strict();
        assert_eq!(c.min_parity_millionths, 990_000);
        assert_eq!(c.required_cohorts.len(), 8);
    }

    #[test]
    fn test_config_permissive() {
        let c = GateConfig::permissive();
        assert_eq!(c.min_parity_millionths, 0);
        assert!(!c.fail_closed);
    }

    #[test]
    fn test_config_builders() {
        let c = GateConfig::default()
            .with_min_parity(980_000)
            .with_max_overhead(50_000)
            .with_max_security_findings(2)
            .with_min_support_coverage(900_000)
            .with_min_samples(100)
            .with_required_cohort(AddonCohort::Crypto)
            .fail_open();
        assert_eq!(c.min_parity_millionths, 980_000);
        assert_eq!(c.max_throughput_overhead_millionths, 50_000);
        assert_eq!(c.max_security_findings, 2);
        assert_eq!(c.min_support_coverage_millionths, 900_000);
        assert_eq!(c.min_sample_count, 100);
        assert!(c.required_cohorts.contains(&AddonCohort::Crypto));
        assert!(!c.fail_closed);
    }

    #[test]
    fn test_config_serde() {
        let c = GateConfig::default();
        let json = serde_json::to_string(&c).unwrap();
        let back: GateConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    // -----------------------------------------------------------------------
    // GateVerdict
    // -----------------------------------------------------------------------

    #[test]
    fn test_verdict_approved() {
        assert!(GateVerdict::Approved.is_approved());
        assert!(!GateVerdict::ParityViolation.is_approved());
        assert!(!GateVerdict::SecurityBlocking.is_approved());
        assert!(!GateVerdict::ThroughputExceeded.is_approved());
        assert!(!GateVerdict::SupportInsufficient.is_approved());
        assert!(!GateVerdict::MultipleViolations.is_approved());
    }

    #[test]
    fn test_verdict_blocking() {
        assert!(!GateVerdict::Approved.is_blocking());
        assert!(GateVerdict::ParityViolation.is_blocking());
        assert!(GateVerdict::MultipleViolations.is_blocking());
    }

    #[test]
    fn test_verdict_display() {
        assert_eq!(format!("{}", GateVerdict::Approved), "approved");
        assert_eq!(
            format!("{}", GateVerdict::SecurityBlocking),
            "security_blocking"
        );
    }

    #[test]
    fn test_verdict_serde() {
        let v = GateVerdict::ThroughputExceeded;
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — construction
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_new() {
        let g = GateEvaluator::with_defaults(epoch());
        assert_eq!(g.evaluation_count(), 0);
        assert_eq!(g.approved_count(), 0);
        assert_eq!(g.denied_count(), 0);
        assert!(g.last_receipt().is_none());
    }

    #[test]
    fn test_evaluator_epoch() {
        let g = GateEvaluator::with_defaults(SecurityEpoch::from_raw(42));
        assert_eq!(g.epoch().as_u64(), 42);
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — add entries
    // -----------------------------------------------------------------------

    #[test]
    fn test_add_parity() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        assert_eq!(g.parity_entry_count(), 1);
    }

    #[test]
    fn test_add_security_finding() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_security_finding(
            FindingSeverity::Critical,
            FindingCategory::BufferOverflow,
            "addon-x",
            "heap overflow",
        );
        assert_eq!(g.security_finding_count(), 1);
    }

    #[test]
    fn test_add_throughput() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_throughput(AddonCohort::Compression, "zstd", 1_000_000, 950_000);
        assert_eq!(g.throughput_entry_count(), 1);
    }

    #[test]
    fn test_add_support_surface() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_support_surface(AddonCohort::MediaCodec, 90, 100);
        assert_eq!(g.support_surface_entry_count(), 1);
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — evaluate: approved
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_approved_all_pass() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        g.add_throughput(AddonCohort::Crypto, "aes", 1_000_000, 950_000);
        g.add_support_surface(AddonCohort::Crypto, 90, 100);
        let receipt = g.evaluate();
        assert_eq!(receipt.verdict, GateVerdict::Approved);
        assert!(receipt.violations.is_empty());
        assert_eq!(g.approved_count(), 1);
    }

    #[test]
    fn test_evaluate_approved_empty_evidence() {
        let mut g = GateEvaluator::with_defaults(epoch());
        let receipt = g.evaluate();
        // No evidence, no required cohorts -> approved
        assert_eq!(receipt.verdict, GateVerdict::Approved);
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — evaluate: parity violation
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_parity_violation() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_parity(
            AddonCohort::Crypto,
            "aes",
            GateAxis::Parity,
            900_000, // 90%, below 95%
            50,
        );
        let receipt = g.evaluate();
        assert_eq!(receipt.verdict, GateVerdict::ParityViolation);
        assert_eq!(receipt.violations.len(), 1);
        assert_eq!(receipt.violations[0].axis, GateAxis::Parity);
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — evaluate: security blocking
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_security_blocking() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_security_finding(
            FindingSeverity::Critical,
            FindingCategory::BufferOverflow,
            "addon-vuln",
            "remote code execution",
        );
        let receipt = g.evaluate();
        assert_eq!(receipt.verdict, GateVerdict::SecurityBlocking);
        assert_eq!(receipt.blocking_finding_count(), 1);
    }

    #[test]
    fn test_evaluate_security_non_blocking_findings() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_security_finding(
            FindingSeverity::Low,
            FindingCategory::InfoLeak,
            "addon-ok",
            "minor timing side-channel",
        );
        let receipt = g.evaluate();
        assert_eq!(receipt.verdict, GateVerdict::Approved);
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — evaluate: throughput exceeded
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_throughput_exceeded() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_throughput(
            AddonCohort::Database,
            "pg-driver",
            1_000_000,
            700_000, // 30% overhead
        );
        let receipt = g.evaluate();
        assert_eq!(receipt.verdict, GateVerdict::ThroughputExceeded);
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — evaluate: support insufficient
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_support_insufficient() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_support_surface(AddonCohort::MediaCodec, 30, 100); // 30%
        let receipt = g.evaluate();
        assert_eq!(receipt.verdict, GateVerdict::SupportInsufficient);
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — evaluate: multiple violations
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_multiple_violations() {
        let mut g = GateEvaluator::with_defaults(epoch());
        // Parity violation
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, 800_000, 50);
        // Throughput violation
        g.add_throughput(AddonCohort::Crypto, "aes", 1_000_000, 700_000);
        let receipt = g.evaluate();
        assert_eq!(receipt.verdict, GateVerdict::MultipleViolations);
        assert!(receipt.violations.len() >= 2);
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — evaluate: required cohorts
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_missing_required_cohort() {
        let config = GateConfig::default()
            .with_required_cohort(AddonCohort::Crypto)
            .with_required_cohort(AddonCohort::Compression);
        let mut g = GateEvaluator::new(config, epoch());
        // Only provide crypto evidence
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        let receipt = g.evaluate();
        assert!(!receipt.is_approved());
        assert!(receipt.missing_cohorts.contains(&AddonCohort::Compression));
    }

    #[test]
    fn test_evaluate_all_required_cohorts_present() {
        let config = GateConfig::default().with_required_cohort(AddonCohort::Crypto);
        let mut g = GateEvaluator::new(config, epoch());
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        let receipt = g.evaluate();
        assert!(receipt.is_approved());
        assert!(receipt.missing_cohorts.is_empty());
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — evaluate: counters and rate
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_counters() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.evaluate();
        assert_eq!(g.evaluation_count(), 1);
        assert_eq!(g.approved_count(), 1);
        assert_eq!(g.denied_count(), 0);
    }

    #[test]
    fn test_approval_rate_empty() {
        let g = GateEvaluator::with_defaults(epoch());
        assert_eq!(g.approval_rate_millionths(), 0);
    }

    #[test]
    fn test_approval_rate_all_approved() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.evaluate();
        g.clear();
        g.evaluate();
        assert_eq!(g.approval_rate_millionths(), MILLIONTHS);
    }

    #[test]
    fn test_approval_rate_half() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.evaluate(); // approved (empty)
        g.clear();
        g.add_parity(AddonCohort::Crypto, "x", GateAxis::Parity, 100_000, 50);
        g.evaluate(); // denied (low parity)
        assert_eq!(g.approval_rate_millionths(), 500_000);
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — clear
    // -----------------------------------------------------------------------

    #[test]
    fn test_clear() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        g.add_security_finding(FindingSeverity::Low, FindingCategory::InfoLeak, "x", "y");
        g.add_throughput(AddonCohort::Crypto, "aes", 1000, 900);
        g.add_support_surface(AddonCohort::Crypto, 80, 100);
        g.clear();
        assert_eq!(g.parity_entry_count(), 0);
        assert_eq!(g.security_finding_count(), 0);
        assert_eq!(g.throughput_entry_count(), 0);
        assert_eq!(g.support_surface_entry_count(), 0);
    }

    // -----------------------------------------------------------------------
    // GateReceipt
    // -----------------------------------------------------------------------

    #[test]
    fn test_receipt_fields() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        let receipt = g.evaluate();
        assert_eq!(receipt.schema_version, SCHEMA_VERSION);
        assert_eq!(receipt.component, COMPONENT);
        assert_eq!(receipt.bead_id, BEAD_ID);
        assert_eq!(receipt.policy_id, POLICY_ID);
        assert_eq!(receipt.epoch.as_u64(), 1);
    }

    #[test]
    fn test_receipt_hash_deterministic() {
        let mut g1 = GateEvaluator::with_defaults(epoch());
        g1.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        let r1 = g1.evaluate();

        let mut g2 = GateEvaluator::with_defaults(epoch());
        g2.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        let r2 = g2.evaluate();

        assert_eq!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_receipt_hash_differs_on_change() {
        let mut g1 = GateEvaluator::with_defaults(epoch());
        g1.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        let r1 = g1.evaluate();

        let mut g2 = GateEvaluator::with_defaults(epoch());
        g2.add_parity(
            AddonCohort::Crypto,
            "aes",
            GateAxis::Parity,
            900_000, // different parity
            50,
        );
        let r2 = g2.evaluate();

        assert_ne!(r1.content_hash, r2.content_hash);
    }

    #[test]
    fn test_receipt_observed_cohorts() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        g.add_throughput(AddonCohort::Compression, "zstd", 1000, 950);
        let receipt = g.evaluate();
        assert!(receipt.observed_cohorts.contains(&AddonCohort::Crypto));
        assert!(receipt.observed_cohorts.contains(&AddonCohort::Compression));
    }

    #[test]
    fn test_receipt_last_receipt() {
        let mut g = GateEvaluator::with_defaults(epoch());
        assert!(g.last_receipt().is_none());
        g.evaluate();
        assert!(g.last_receipt().is_some());
    }

    // -----------------------------------------------------------------------
    // GateSummary
    // -----------------------------------------------------------------------

    #[test]
    fn test_summary() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        g.add_security_finding(FindingSeverity::Low, FindingCategory::InfoLeak, "x", "y");
        g.evaluate();
        let s = g.summary();
        assert_eq!(s.total_evaluations, 1);
        assert_eq!(s.approved_count, 1);
        assert_eq!(s.parity_entries, 1);
        assert_eq!(s.security_findings, 1);
    }

    #[test]
    fn test_summary_serde() {
        let s = GateSummary {
            total_evaluations: 5,
            approved_count: 3,
            denied_count: 2,
            parity_entries: 10,
            security_findings: 1,
            throughput_entries: 5,
            support_surface_entries: 3,
            approval_rate_millionths: 600_000,
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: GateSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    // -----------------------------------------------------------------------
    // Violation
    // -----------------------------------------------------------------------

    #[test]
    fn test_violation_new() {
        let v = Violation::new(GateAxis::Security, Some(AddonCohort::Crypto), "found CVE");
        assert_eq!(v.axis, GateAxis::Security);
        assert_eq!(v.cohort, Some(AddonCohort::Crypto));
    }

    #[test]
    fn test_violation_serde() {
        let v = Violation::new(GateAxis::Throughput, None, "too slow");
        let json = serde_json::to_string(&v).unwrap();
        let back: Violation = serde_json::from_str(&json).unwrap();
        assert_eq!(v, back);
    }

    // -----------------------------------------------------------------------
    // Manifest
    // -----------------------------------------------------------------------

    #[test]
    fn test_manifest() {
        let m = native_addon_parity_gate_manifest();
        assert_eq!(m.get("schema_version").unwrap(), SCHEMA_VERSION);
        assert_eq!(m.get("component").unwrap(), COMPONENT);
        assert_eq!(m.get("bead_id").unwrap(), BEAD_ID);
        assert_eq!(m.get("policy_id").unwrap(), POLICY_ID);
    }

    // -----------------------------------------------------------------------
    // GateEvaluator — serde
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluator_serde() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        g.evaluate();
        let json = serde_json::to_string(&g).unwrap();
        let back: GateEvaluator = serde_json::from_str(&json).unwrap();
        assert_eq!(back.evaluation_count(), 1);
        assert_eq!(back.approved_count(), 1);
    }

    // -----------------------------------------------------------------------
    // Parity insufficient samples
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_parity_insufficient_samples() {
        let mut g = GateEvaluator::with_defaults(epoch());
        g.add_parity(
            AddonCohort::Compression,
            "brotli",
            GateAxis::Parity,
            MILLIONTHS,
            5, // below min 30
        );
        let receipt = g.evaluate();
        assert_eq!(receipt.verdict, GateVerdict::ParityViolation);
        assert!(receipt.violations[0].description.contains("insufficient"));
    }

    // -----------------------------------------------------------------------
    // Security with allowed findings
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_security_within_allowed() {
        let config = GateConfig::default().with_max_security_findings(1);
        let mut g = GateEvaluator::new(config, epoch());
        g.add_security_finding(
            FindingSeverity::High,
            FindingCategory::TypeConfusion,
            "x",
            "type confusion",
        );
        let receipt = g.evaluate();
        // 1 blocking finding <= max 1 -> approved
        assert_eq!(receipt.verdict, GateVerdict::Approved);
    }

    // -----------------------------------------------------------------------
    // Multiple cohorts evidence gathering
    // -----------------------------------------------------------------------

    #[test]
    fn test_evaluate_multi_cohort_approved() {
        let config = GateConfig::default()
            .with_required_cohort(AddonCohort::Crypto)
            .with_required_cohort(AddonCohort::Compression);
        let mut g = GateEvaluator::new(config, epoch());
        g.add_parity(AddonCohort::Crypto, "aes", GateAxis::Parity, MILLIONTHS, 50);
        g.add_parity(
            AddonCohort::Compression,
            "zstd",
            GateAxis::Parity,
            MILLIONTHS,
            50,
        );
        g.add_throughput(AddonCohort::Crypto, "aes", 1_000_000, 950_000);
        g.add_throughput(AddonCohort::Compression, "zstd", 1_000_000, 960_000);
        g.add_support_surface(AddonCohort::Crypto, 95, 100);
        g.add_support_surface(AddonCohort::Compression, 85, 100);
        let receipt = g.evaluate();
        assert_eq!(receipt.verdict, GateVerdict::Approved);
        assert_eq!(receipt.observed_cohorts.len(), 2);
        assert!(receipt.missing_cohorts.is_empty());
    }
}
