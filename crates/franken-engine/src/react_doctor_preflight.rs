#![forbid(unsafe_code)]

//! React-aware doctor, preflight, and support-bundle guidance.
//!
//! Consumes the `react_mismatch_catalog` module to produce immediate,
//! actionable guidance when user-facing React failures occur, instead of
//! generic JS/TS error messages.
//!
//! Plan references: Section 10.12 (RGC-912B), bead bd-1lsy.10.12.2.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::react_mismatch_catalog::{
    ComparisonTarget, MismatchDomain, MismatchEntry, MismatchSeverity, RemediationStatus,
};
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

/// Schema version for the react doctor preflight module.
pub const DOCTOR_PREFLIGHT_SCHEMA_VERSION: &str = "franken-engine.react-doctor-preflight.v1";

/// Bead identifier originating this module.
pub const DOCTOR_PREFLIGHT_BEAD_ID: &str = "bd-1lsy.10.12.2";

/// Policy ID binding.
pub const DOCTOR_PREFLIGHT_POLICY_ID: &str = "RGC-912B";

/// Component name for evidence linkage.
pub const COMPONENT: &str = "react_doctor_preflight";

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLIONTHS: u64 = 1_000_000;

/// Maximum number of checks in a single doctor run.
const MAX_CHECKS: usize = 10_000;

/// Maximum guidance text length.
const MAX_GUIDANCE_LEN: usize = 8192;

/// Maximum support bundle entries.
const MAX_BUNDLE_ENTRIES: usize = 5_000;

// ---------------------------------------------------------------------------
// CheckCategory
// ---------------------------------------------------------------------------

/// Category of a doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckCategory {
    /// Package presence and health (react, react-dom, etc.).
    PackageHealth,
    /// Version compatibility between React packages.
    VersionCompat,
    /// JSX transform mode (classic vs automatic).
    JsxTransform,
    /// Hook ordering and rules-of-hooks compliance.
    HookOrdering,
    /// Server-side rendering configuration.
    SsrConfig,
    /// Module format (ESM, CJS, dual).
    ModuleFormat,
    /// Bundle structure and chunk boundaries.
    BundleStructure,
    /// TypeScript configuration and compatibility.
    TypeScript,
}

impl CheckCategory {
    /// Short identifier for hash derivation and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PackageHealth => "package_health",
            Self::VersionCompat => "version_compat",
            Self::JsxTransform => "jsx_transform",
            Self::HookOrdering => "hook_ordering",
            Self::SsrConfig => "ssr_config",
            Self::ModuleFormat => "module_format",
            Self::BundleStructure => "bundle_structure",
            Self::TypeScript => "typescript",
        }
    }

    /// Fixed-point priority weight (millionths). Higher = more important.
    pub const fn priority_weight(self) -> u64 {
        match self {
            Self::PackageHealth => MILLIONTHS,
            Self::VersionCompat => 900_000,
            Self::JsxTransform => 700_000,
            Self::HookOrdering => 800_000,
            Self::SsrConfig => 600_000,
            Self::ModuleFormat => 500_000,
            Self::BundleStructure => 400_000,
            Self::TypeScript => 600_000,
        }
    }
}

impl fmt::Display for CheckCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// All check category variants for exhaustive iteration.
pub const ALL_CATEGORIES: &[CheckCategory] = &[
    CheckCategory::PackageHealth,
    CheckCategory::VersionCompat,
    CheckCategory::JsxTransform,
    CheckCategory::HookOrdering,
    CheckCategory::SsrConfig,
    CheckCategory::ModuleFormat,
    CheckCategory::BundleStructure,
    CheckCategory::TypeScript,
];

// ---------------------------------------------------------------------------
// CheckSeverity
// ---------------------------------------------------------------------------

/// Severity of a doctor check result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckSeverity {
    /// Check passed without issues.
    Pass,
    /// Advisory note, no action required.
    Advisory,
    /// Warning: potential issue that may cause problems.
    Warning,
    /// Error: confirmed issue that will cause failures.
    Error,
    /// Critical: issue that will cause data loss or security problems.
    Critical,
}

impl CheckSeverity {
    /// Short identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Advisory => "advisory",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// Numeric weight for aggregation (fixed-point millionths).
    pub const fn weight(self) -> u64 {
        match self {
            Self::Pass => 0,
            Self::Advisory => 50_000,     // 0.05
            Self::Warning => 300_000,     // 0.3
            Self::Error => 700_000,       // 0.7
            Self::Critical => MILLIONTHS, // 1.0
        }
    }

    /// Whether this severity blocks a preflight.
    pub const fn is_blocking(self) -> bool {
        matches!(self, Self::Error | Self::Critical)
    }
}

impl fmt::Display for CheckSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DoctorCheck
// ---------------------------------------------------------------------------

/// An individual doctor check result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    /// Unique check identifier (e.g., "pkg-react-present").
    pub check_id: String,
    /// Category of this check.
    pub category: CheckCategory,
    /// Severity of the finding.
    pub severity: CheckSeverity,
    /// Human-readable message describing the finding.
    pub message: String,
    /// Actionable remediation guidance.
    pub remediation: String,
    /// IDs of mismatch entries that triggered this check.
    pub related_mismatch_ids: Vec<String>,
    /// Tags for filtering.
    pub tags: BTreeSet<String>,
}

impl DoctorCheck {
    /// Compute a deterministic content hash.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(DOCTOR_PREFLIGHT_SCHEMA_VERSION.as_bytes());
        hasher.update(self.check_id.as_bytes());
        hasher.update(self.category.as_str().as_bytes());
        hasher.update(self.severity.as_str().as_bytes());
        hasher.update(self.message.as_bytes());
        ContentHash::compute(&hasher.finalize())
    }

    /// Whether this check result is blocking.
    pub fn is_blocking(&self) -> bool {
        self.severity.is_blocking()
    }

    /// Whether this check passed.
    pub fn is_pass(&self) -> bool {
        self.severity == CheckSeverity::Pass
    }
}

// ---------------------------------------------------------------------------
// DoctorConfig
// ---------------------------------------------------------------------------

/// Configuration for what doctor checks to run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorConfig {
    /// Categories to include. If empty, all categories are included.
    pub include_categories: BTreeSet<CheckCategory>,
    /// Categories to exclude.
    pub exclude_categories: BTreeSet<CheckCategory>,
    /// Minimum mismatch severity to consider.
    pub min_mismatch_severity: MismatchSeverity,
    /// Whether to include resolved mismatches.
    pub include_resolved: bool,
    /// Comparison targets to focus on. If empty, all targets.
    pub focus_targets: BTreeSet<ComparisonTarget>,
    /// Maximum number of checks to emit.
    pub max_checks: usize,
    /// Security epoch for freshness validation.
    pub current_epoch: SecurityEpoch,
    /// Maximum age in epochs before a mismatch is considered stale.
    pub max_stale_epochs: u64,
}

impl Default for DoctorConfig {
    fn default() -> Self {
        Self {
            include_categories: BTreeSet::new(),
            exclude_categories: BTreeSet::new(),
            min_mismatch_severity: MismatchSeverity::Info,
            include_resolved: false,
            focus_targets: BTreeSet::new(),
            max_checks: MAX_CHECKS,
            current_epoch: SecurityEpoch::from_raw(1),
            max_stale_epochs: 10,
        }
    }
}

impl DoctorConfig {
    /// Whether a given category is enabled by this config.
    pub fn is_category_enabled(&self, cat: CheckCategory) -> bool {
        if self.exclude_categories.contains(&cat) {
            return false;
        }
        if self.include_categories.is_empty() {
            return true;
        }
        self.include_categories.contains(&cat)
    }

    /// Whether an entry passes the target focus filter.
    pub fn is_target_included(&self, target: ComparisonTarget) -> bool {
        if self.focus_targets.is_empty() {
            return true;
        }
        self.focus_targets.contains(&target)
    }

    /// Whether a mismatch entry is relevant under this config.
    pub fn is_entry_relevant(&self, entry: &MismatchEntry) -> bool {
        if entry.severity < self.min_mismatch_severity {
            return false;
        }
        if !self.include_resolved && !entry.is_open() {
            return false;
        }
        self.is_target_included(entry.target)
    }
}

// ---------------------------------------------------------------------------
// DoctorSummary
// ---------------------------------------------------------------------------

/// High-level summary of a doctor report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorSummary {
    /// Total checks performed.
    pub total_checks: usize,
    /// Checks that passed.
    pub pass_count: usize,
    /// Advisory findings.
    pub advisory_count: usize,
    /// Warning findings.
    pub warning_count: usize,
    /// Error findings.
    pub error_count: usize,
    /// Critical findings.
    pub critical_count: usize,
    /// Per-category breakdown.
    pub by_category: BTreeMap<String, usize>,
    /// Overall readiness flag.
    pub is_ready: bool,
    /// Aggregate severity score (millionths).
    pub aggregate_score: u64,
}

// ---------------------------------------------------------------------------
// DoctorReport
// ---------------------------------------------------------------------------

/// Full report from running all doctor checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID.
    pub bead_id: String,
    /// Policy ID.
    pub policy_id: String,
    /// Epoch at which this report was generated.
    pub epoch: SecurityEpoch,
    /// All individual check results.
    pub checks: Vec<DoctorCheck>,
    /// Content hash of this report.
    pub report_hash: ContentHash,
}

impl DoctorReport {
    /// Create a new empty report.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            schema_version: DOCTOR_PREFLIGHT_SCHEMA_VERSION.to_string(),
            bead_id: DOCTOR_PREFLIGHT_BEAD_ID.to_string(),
            policy_id: DOCTOR_PREFLIGHT_POLICY_ID.to_string(),
            epoch,
            checks: Vec::new(),
            report_hash: ContentHash::compute(b"empty-doctor"),
        }
    }

    /// Add a check to the report.
    fn add_check(&mut self, check: DoctorCheck) {
        self.checks.push(check);
        self.recompute_hash();
    }

    /// Recompute the report content hash.
    fn recompute_hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(DOCTOR_PREFLIGHT_SCHEMA_VERSION.as_bytes());
        hasher.update(self.epoch.as_u64().to_le_bytes());
        for check in &self.checks {
            hasher.update(check.content_hash().as_bytes());
        }
        self.report_hash = ContentHash::compute(&hasher.finalize());
    }

    /// Number of checks.
    pub fn len(&self) -> usize {
        self.checks.len()
    }

    /// Whether the report has no checks.
    pub fn is_empty(&self) -> bool {
        self.checks.is_empty()
    }

    /// Count of blocking checks (Error or Critical).
    pub fn blocking_count(&self) -> usize {
        self.checks.iter().filter(|c| c.is_blocking()).count()
    }

    /// Count of checks with a specific severity.
    pub fn count_by_severity(&self, severity: CheckSeverity) -> usize {
        self.checks
            .iter()
            .filter(|c| c.severity == severity)
            .count()
    }

    /// Count of checks in a specific category.
    pub fn count_by_category(&self, cat: CheckCategory) -> usize {
        self.checks.iter().filter(|c| c.category == cat).count()
    }

    /// All blocking checks.
    pub fn blocking_checks(&self) -> Vec<&DoctorCheck> {
        self.checks.iter().filter(|c| c.is_blocking()).collect()
    }

    /// Checks in a specific category.
    pub fn checks_by_category(&self, cat: CheckCategory) -> Vec<&DoctorCheck> {
        self.checks.iter().filter(|c| c.category == cat).collect()
    }

    /// Aggregate severity score (millionths).
    pub fn aggregate_score(&self) -> u64 {
        self.checks.iter().map(|c| c.severity.weight()).sum()
    }
}

// ---------------------------------------------------------------------------
// PreflightResult
// ---------------------------------------------------------------------------

/// Result of a preflight validation before React compile/build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreflightResult {
    /// Whether the preflight passed (no blocking issues).
    pub passed: bool,
    /// Blocking issues that prevent proceeding.
    pub blockers: Vec<DoctorCheck>,
    /// Non-blocking warnings and advisories.
    pub advisories: Vec<DoctorCheck>,
    /// Total entries analyzed.
    pub entries_analyzed: usize,
    /// Epoch of the preflight.
    pub epoch: SecurityEpoch,
    /// Content hash.
    pub result_hash: ContentHash,
}

impl PreflightResult {
    /// Number of blockers.
    pub fn blocker_count(&self) -> usize {
        self.blockers.len()
    }

    /// Number of advisories.
    pub fn advisory_count(&self) -> usize {
        self.advisories.len()
    }

    /// Total findings (blockers + advisories).
    pub fn total_findings(&self) -> usize {
        self.blockers.len() + self.advisories.len()
    }
}

// ---------------------------------------------------------------------------
// GuidanceEntry
// ---------------------------------------------------------------------------

/// Actionable remediation guidance mapped from doctor findings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuidanceEntry {
    /// Unique guidance identifier.
    pub guidance_id: String,
    /// Priority (1 = highest). Derived from severity and category weight.
    pub priority: u32,
    /// Category of the originating check.
    pub category: CheckCategory,
    /// Severity of the originating check.
    pub severity: CheckSeverity,
    /// Short title for the guidance.
    pub title: String,
    /// Detailed remediation steps.
    pub steps: Vec<String>,
    /// IDs of checks that produced this guidance.
    pub originating_check_ids: Vec<String>,
    /// Content hash.
    pub guidance_hash: ContentHash,
}

impl GuidanceEntry {
    /// Compute content hash.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(DOCTOR_PREFLIGHT_SCHEMA_VERSION.as_bytes());
        hasher.update(self.guidance_id.as_bytes());
        hasher.update(self.title.as_bytes());
        for step in &self.steps {
            hasher.update(step.as_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// SupportBundleEntry
// ---------------------------------------------------------------------------

/// A single entry within a support bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundleEntry {
    /// Entry key (e.g., "doctor_checks", "mismatch_summary").
    pub key: String,
    /// Serialized diagnostic data.
    pub value: String,
    /// Category for grouping.
    pub category: String,
}

// ---------------------------------------------------------------------------
// SupportBundle
// ---------------------------------------------------------------------------

/// Collected diagnostics for support reporting.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportBundle {
    /// Schema version.
    pub schema_version: String,
    /// When this bundle was generated (epoch).
    pub epoch: SecurityEpoch,
    /// Bundle entries.
    pub entries: Vec<SupportBundleEntry>,
    /// Doctor report summary.
    pub summary: DoctorSummary,
    /// Guidance entries.
    pub guidance: Vec<GuidanceEntry>,
    /// Content hash of the bundle.
    pub bundle_hash: ContentHash,
}

impl SupportBundle {
    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the bundle is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Entries by category.
    pub fn entries_by_category(&self, cat: &str) -> Vec<&SupportBundleEntry> {
        self.entries.iter().filter(|e| e.category == cat).collect()
    }
}

// ---------------------------------------------------------------------------
// DoctorError
// ---------------------------------------------------------------------------

/// Errors from doctor and preflight operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DoctorError {
    /// Too many checks generated.
    CheckCapacityExceeded { current: usize, max: usize },
    /// Guidance text too long.
    GuidanceTooLong { guidance_id: String, len: usize },
    /// Support bundle too large.
    BundleTooLarge { current: usize, max: usize },
    /// No entries to analyze.
    EmptyInput,
    /// Invalid configuration.
    InvalidConfig { reason: String },
    /// Stale data detected.
    StaleData { entry_id: String, epoch_gap: u64 },
}

impl fmt::Display for DoctorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CheckCapacityExceeded { current, max } => {
                write!(f, "check capacity exceeded: {current}/{max}")
            }
            Self::GuidanceTooLong { guidance_id, len } => {
                write!(
                    f,
                    "guidance too long for {guidance_id}: {len} > {MAX_GUIDANCE_LEN}"
                )
            }
            Self::BundleTooLarge { current, max } => {
                write!(f, "support bundle too large: {current}/{max}")
            }
            Self::EmptyInput => write!(f, "no mismatch entries to analyze"),
            Self::InvalidConfig { reason } => {
                write!(f, "invalid doctor configuration: {reason}")
            }
            Self::StaleData {
                entry_id,
                epoch_gap,
            } => {
                write!(
                    f,
                    "stale data for entry {entry_id}: {epoch_gap} epochs behind"
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Mapping: MismatchDomain -> CheckCategory
// ---------------------------------------------------------------------------

/// Map a mismatch domain to the most relevant doctor check category.
fn domain_to_category(domain: MismatchDomain) -> CheckCategory {
    match domain {
        MismatchDomain::CompileOutput => CheckCategory::JsxTransform,
        MismatchDomain::Diagnostics => CheckCategory::PackageHealth,
        MismatchDomain::SourceMap => CheckCategory::BundleStructure,
        MismatchDomain::ServerSideRender => CheckCategory::SsrConfig,
        MismatchDomain::ClientEntry => CheckCategory::SsrConfig,
        MismatchDomain::ArtifactShape => CheckCategory::BundleStructure,
        MismatchDomain::ModuleGraph => CheckCategory::ModuleFormat,
        MismatchDomain::HookSemantics => CheckCategory::HookOrdering,
        MismatchDomain::SuspenseBoundary => CheckCategory::SsrConfig,
        MismatchDomain::ErrorBoundary => CheckCategory::PackageHealth,
    }
}

/// Map a mismatch severity to a check severity.
fn mismatch_severity_to_check(sev: MismatchSeverity) -> CheckSeverity {
    match sev {
        MismatchSeverity::Info => CheckSeverity::Advisory,
        MismatchSeverity::Warning => CheckSeverity::Warning,
        MismatchSeverity::Error => CheckSeverity::Error,
        MismatchSeverity::Critical => CheckSeverity::Critical,
    }
}

// ---------------------------------------------------------------------------
// Check generation from mismatch entries
// ---------------------------------------------------------------------------

/// Generate a doctor check from a single mismatch entry.
fn check_from_entry(entry: &MismatchEntry, check_num: usize) -> DoctorCheck {
    let category = domain_to_category(entry.domain);
    let severity = mismatch_severity_to_check(entry.severity);

    let remediation = match entry.remediation {
        RemediationStatus::None => format!(
            "No remediation available yet for {}. Monitor for updates.",
            entry.domain.as_str()
        ),
        RemediationStatus::Workaround => format!(
            "Workaround available: {}. Apply the documented workaround.",
            entry.advisory
        ),
        RemediationStatus::InProgress => format!(
            "Fix in progress for {}. Temporary workaround: check advisory.",
            entry.domain.as_str()
        ),
        RemediationStatus::Shipped => format!(
            "Fix shipped for {}. Update to the latest version to resolve.",
            entry.domain.as_str()
        ),
        RemediationStatus::Resolved => {
            format!(
                "Issue resolved for {}. No action needed.",
                entry.domain.as_str()
            )
        }
        RemediationStatus::Accepted => format!(
            "Known limitation in {}. See advisory for details.",
            entry.domain.as_str()
        ),
    };

    let mut tags: BTreeSet<String> = entry.tags.clone();
    tags.insert(category.as_str().to_string());
    tags.insert("doctor".to_string());

    DoctorCheck {
        check_id: format!("dc-{check_num:04}-{}", entry.entry_id),
        category,
        severity,
        message: format!(
            "[{}] {}: {}",
            entry.target.as_str(),
            entry.domain.as_str(),
            entry.summary
        ),
        remediation,
        related_mismatch_ids: vec![entry.entry_id.clone()],
        tags,
    }
}

/// Generate a staleness check for an entry.
fn staleness_check(
    entry: &MismatchEntry,
    current_epoch: SecurityEpoch,
    check_num: usize,
) -> Option<DoctorCheck> {
    let epoch_gap = current_epoch
        .as_u64()
        .saturating_sub(entry.verified_epoch.as_u64());
    if epoch_gap > 5 {
        let severity = if epoch_gap > 20 {
            CheckSeverity::Error
        } else if epoch_gap > 10 {
            CheckSeverity::Warning
        } else {
            CheckSeverity::Advisory
        };
        Some(DoctorCheck {
            check_id: format!("dc-stale-{check_num:04}-{}", entry.entry_id),
            category: domain_to_category(entry.domain),
            severity,
            message: format!(
                "Stale mismatch data for {}: last verified {} epochs ago",
                entry.entry_id, epoch_gap
            ),
            remediation: format!(
                "Re-verify mismatch {} against current React version. Data is {} epochs stale.",
                entry.entry_id, epoch_gap
            ),
            related_mismatch_ids: vec![entry.entry_id.clone()],
            tags: ["stale", "doctor"].iter().map(|s| s.to_string()).collect(),
        })
    } else {
        None
    }
}

/// Generate version compatibility checks from a set of entries.
fn version_compat_checks(entries: &[&MismatchEntry], check_num_start: usize) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    let mut version_ranges: BTreeMap<String, Vec<&MismatchEntry>> = BTreeMap::new();

    for entry in entries {
        version_ranges
            .entry(entry.react_version_range.clone())
            .or_default()
            .push(entry);
    }

    let mut num = check_num_start;
    for (range, range_entries) in &version_ranges {
        let max_sev = range_entries
            .iter()
            .map(|e| e.severity)
            .max()
            .unwrap_or(MismatchSeverity::Info);

        if range_entries.len() > 1 {
            let ids: Vec<String> = range_entries.iter().map(|e| e.entry_id.clone()).collect();
            checks.push(DoctorCheck {
                check_id: format!("dc-vc-{num:04}"),
                category: CheckCategory::VersionCompat,
                severity: mismatch_severity_to_check(max_sev),
                message: format!(
                    "{} mismatches affect React version range {range}",
                    range_entries.len()
                ),
                remediation: format!(
                    "Review version range {range}: {} entries have known issues. Consider pinning to a verified version.",
                    range_entries.len()
                ),
                related_mismatch_ids: ids,
                tags: ["version_compat", "doctor"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            });
            num += 1;
        }
    }
    checks
}

/// Generate package health checks by analyzing diagnostics and error boundary entries.
fn package_health_checks(entries: &[&MismatchEntry], check_num_start: usize) -> Vec<DoctorCheck> {
    let mut checks = Vec::new();
    let mut num = check_num_start;

    let diag_entries: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.domain == MismatchDomain::Diagnostics || e.domain == MismatchDomain::ErrorBoundary
        })
        .collect();

    if !diag_entries.is_empty() {
        let critical_count = diag_entries
            .iter()
            .filter(|e| e.severity == MismatchSeverity::Critical)
            .count();
        let error_count = diag_entries
            .iter()
            .filter(|e| e.severity == MismatchSeverity::Error)
            .count();

        let severity = if critical_count > 0 {
            CheckSeverity::Critical
        } else if error_count > 0 {
            CheckSeverity::Error
        } else {
            CheckSeverity::Warning
        };

        let ids: Vec<String> = diag_entries.iter().map(|e| e.entry_id.clone()).collect();

        checks.push(DoctorCheck {
            check_id: format!("dc-pkg-{num:04}"),
            category: CheckCategory::PackageHealth,
            severity,
            message: format!(
                "Package health: {} diagnostic issues ({} critical, {} errors)",
                diag_entries.len(),
                critical_count,
                error_count
            ),
            remediation: "Verify react and react-dom packages are installed correctly. Run npm ls react to check for duplicate or conflicting versions.".to_string(),
            related_mismatch_ids: ids,
            tags: ["package_health", "doctor"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        });
        num += 1;
    }

    // Per-target health check
    let mut by_target: BTreeMap<ComparisonTarget, Vec<&&MismatchEntry>> = BTreeMap::new();
    for entry in &diag_entries {
        by_target.entry(entry.target).or_default().push(entry);
    }
    for (target, t_entries) in &by_target {
        if t_entries.len() > 2 {
            checks.push(DoctorCheck {
                check_id: format!("dc-pkg-tgt-{num:04}"),
                category: CheckCategory::PackageHealth,
                severity: CheckSeverity::Warning,
                message: format!(
                    "Multiple diagnostic issues ({}) against {}",
                    t_entries.len(),
                    target.as_str()
                ),
                remediation: format!(
                    "Check compatibility with {} runtime. {} diagnostic mismatches detected.",
                    target.as_str(),
                    t_entries.len()
                ),
                related_mismatch_ids: t_entries.iter().map(|e| e.entry_id.clone()).collect(),
                tags: ["package_health", "target_specific", "doctor"]
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
            });
            num += 1;
        }
    }

    checks
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Run all doctor checks against a set of mismatch entries.
///
/// Returns a `DoctorReport` with all findings, or an error if config/input
/// is invalid.
pub fn run_doctor(
    config: &DoctorConfig,
    entries: &[MismatchEntry],
) -> Result<DoctorReport, DoctorError> {
    if config.max_checks == 0 {
        return Err(DoctorError::InvalidConfig {
            reason: "max_checks must be > 0".to_string(),
        });
    }

    let mut report = DoctorReport::new(config.current_epoch);

    // Filter relevant entries
    let relevant: Vec<&MismatchEntry> = entries
        .iter()
        .filter(|e| config.is_entry_relevant(e))
        .collect();

    let mut check_num: usize = 0;

    // 1. Generate per-entry checks
    for entry in &relevant {
        let category = domain_to_category(entry.domain);
        if !config.is_category_enabled(category) {
            continue;
        }
        if check_num >= config.max_checks {
            break;
        }
        let check = check_from_entry(entry, check_num);
        report.add_check(check);
        check_num += 1;

        // Staleness check
        if check_num < config.max_checks
            && let Some(stale) = staleness_check(entry, config.current_epoch, check_num)
        {
            report.add_check(stale);
            check_num += 1;
        }
    }

    // 2. Version compatibility checks
    if config.is_category_enabled(CheckCategory::VersionCompat) && check_num < config.max_checks {
        let vc_checks = version_compat_checks(&relevant, check_num);
        for vc in vc_checks {
            if check_num >= config.max_checks {
                break;
            }
            report.add_check(vc);
            check_num += 1;
        }
    }

    // 3. Package health checks
    if config.is_category_enabled(CheckCategory::PackageHealth) && check_num < config.max_checks {
        let ph_checks = package_health_checks(&relevant, check_num);
        for ph in ph_checks {
            if check_num >= config.max_checks {
                break;
            }
            report.add_check(ph);
            check_num += 1;
        }
    }

    Ok(report)
}

/// Run preflight validation before React compile/build.
///
/// Returns a `PreflightResult` indicating whether the build can proceed.
pub fn run_preflight(
    config: &DoctorConfig,
    entries: &[MismatchEntry],
) -> Result<PreflightResult, DoctorError> {
    let report = run_doctor(config, entries)?;

    let mut blockers = Vec::new();
    let mut advisories = Vec::new();

    for check in &report.checks {
        if check.is_blocking() {
            blockers.push(check.clone());
        } else if check.severity != CheckSeverity::Pass {
            advisories.push(check.clone());
        }
    }

    let passed = blockers.is_empty();

    let mut hasher = Sha256::new();
    hasher.update(DOCTOR_PREFLIGHT_SCHEMA_VERSION.as_bytes());
    hasher.update(if passed { b"pass" } else { b"fail" });
    hasher.update(report.report_hash.as_bytes());
    let result_hash = ContentHash::compute(&hasher.finalize());

    Ok(PreflightResult {
        passed,
        blockers,
        advisories,
        entries_analyzed: entries.len(),
        epoch: config.current_epoch,
        result_hash,
    })
}

/// Build a support bundle from a doctor report.
pub fn build_support_bundle(report: &DoctorReport) -> Result<SupportBundle, DoctorError> {
    let summary = summarize(report);
    let guidance = generate_guidance(report)?;

    let mut bundle_entries = Vec::new();

    // Add check summaries
    for check in &report.checks {
        if bundle_entries.len() >= MAX_BUNDLE_ENTRIES {
            break;
        }
        bundle_entries.push(SupportBundleEntry {
            key: check.check_id.clone(),
            value: format!(
                "[{}] {}: {}",
                check.severity.as_str(),
                check.category.as_str(),
                check.message
            ),
            category: "doctor_checks".to_string(),
        });
    }

    // Add severity breakdown
    for sev in [
        CheckSeverity::Critical,
        CheckSeverity::Error,
        CheckSeverity::Warning,
        CheckSeverity::Advisory,
        CheckSeverity::Pass,
    ] {
        let count = report.count_by_severity(sev);
        if count > 0 && bundle_entries.len() < MAX_BUNDLE_ENTRIES {
            bundle_entries.push(SupportBundleEntry {
                key: format!("severity_{}", sev.as_str()),
                value: format!("{count}"),
                category: "severity_breakdown".to_string(),
            });
        }
    }

    // Add category breakdown
    for cat in ALL_CATEGORIES {
        let count = report.count_by_category(*cat);
        if count > 0 && bundle_entries.len() < MAX_BUNDLE_ENTRIES {
            bundle_entries.push(SupportBundleEntry {
                key: format!("category_{}", cat.as_str()),
                value: format!("{count}"),
                category: "category_breakdown".to_string(),
            });
        }
    }

    // Add guidance entries
    for g in &guidance {
        if bundle_entries.len() >= MAX_BUNDLE_ENTRIES {
            break;
        }
        bundle_entries.push(SupportBundleEntry {
            key: g.guidance_id.clone(),
            value: g.title.clone(),
            category: "guidance".to_string(),
        });
    }

    let mut hasher = Sha256::new();
    hasher.update(DOCTOR_PREFLIGHT_SCHEMA_VERSION.as_bytes());
    hasher.update(report.epoch.as_u64().to_le_bytes());
    for entry in &bundle_entries {
        hasher.update(entry.key.as_bytes());
        hasher.update(entry.value.as_bytes());
    }
    let bundle_hash = ContentHash::compute(&hasher.finalize());

    Ok(SupportBundle {
        schema_version: DOCTOR_PREFLIGHT_SCHEMA_VERSION.to_string(),
        epoch: report.epoch,
        entries: bundle_entries,
        summary,
        guidance,
        bundle_hash,
    })
}

/// Generate actionable remediation guidance from a doctor report.
pub fn generate_guidance(report: &DoctorReport) -> Result<Vec<GuidanceEntry>, DoctorError> {
    let mut guidance = Vec::new();
    let mut guidance_num: usize = 0;

    // Group checks by category for consolidated guidance
    let mut by_category: BTreeMap<CheckCategory, Vec<&DoctorCheck>> = BTreeMap::new();
    for check in &report.checks {
        if check.severity != CheckSeverity::Pass {
            by_category.entry(check.category).or_default().push(check);
        }
    }

    // Sort categories by priority weight (descending)
    let mut sorted_cats: Vec<_> = by_category.keys().copied().collect();
    sorted_cats.sort_by_key(|b| std::cmp::Reverse(b.priority_weight()));

    for cat in sorted_cats {
        if let Some(checks) = by_category.get(&cat) {
            let max_severity = checks
                .iter()
                .map(|c| c.severity)
                .max()
                .unwrap_or(CheckSeverity::Advisory);

            // Compute priority: lower number = higher priority
            let priority = match max_severity {
                CheckSeverity::Critical => 1,
                CheckSeverity::Error => 2,
                CheckSeverity::Warning => 3,
                CheckSeverity::Advisory => 4,
                CheckSeverity::Pass => 5,
            };

            let mut steps: Vec<String> = Vec::new();
            let mut check_ids: Vec<String> = Vec::new();

            for check in checks {
                check_ids.push(check.check_id.clone());
                if !check.remediation.is_empty()
                    && !steps.contains(&check.remediation)
                    && steps.len() < 10
                {
                    steps.push(check.remediation.clone());
                }
            }

            let title = format!(
                "{}: {} issue(s) detected (max severity: {})",
                cat.as_str(),
                checks.len(),
                max_severity.as_str()
            );

            if title.len() > MAX_GUIDANCE_LEN {
                return Err(DoctorError::GuidanceTooLong {
                    guidance_id: format!("gd-{guidance_num:04}"),
                    len: title.len(),
                });
            }

            let mut hasher = Sha256::new();
            hasher.update(format!("gd-{guidance_num:04}").as_bytes());
            hasher.update(title.as_bytes());
            let guidance_hash = ContentHash::compute(&hasher.finalize());

            guidance.push(GuidanceEntry {
                guidance_id: format!("gd-{guidance_num:04}"),
                priority,
                category: cat,
                severity: max_severity,
                title,
                steps,
                originating_check_ids: check_ids,
                guidance_hash,
            });
            guidance_num += 1;
        }
    }

    // Sort by priority
    guidance.sort_by_key(|a| a.priority);

    Ok(guidance)
}

/// Quick pass/fail: whether the report indicates React-readiness.
pub fn is_react_ready(report: &DoctorReport) -> bool {
    report.blocking_count() == 0
}

/// High-level summary of a doctor report.
pub fn summarize(report: &DoctorReport) -> DoctorSummary {
    let mut by_category = BTreeMap::new();
    for cat in ALL_CATEGORIES {
        let count = report.count_by_category(*cat);
        if count > 0 {
            by_category.insert(cat.as_str().to_string(), count);
        }
    }

    DoctorSummary {
        total_checks: report.len(),
        pass_count: report.count_by_severity(CheckSeverity::Pass),
        advisory_count: report.count_by_severity(CheckSeverity::Advisory),
        warning_count: report.count_by_severity(CheckSeverity::Warning),
        error_count: report.count_by_severity(CheckSeverity::Error),
        critical_count: report.count_by_severity(CheckSeverity::Critical),
        by_category,
        is_ready: is_react_ready(report),
        aggregate_score: report.aggregate_score(),
    }
}

/// Compute a readiness score in fixed-point millionths (1_000_000 = fully ready).
/// Decreases as more issues are found.
pub fn readiness_score(report: &DoctorReport) -> u64 {
    if report.is_empty() {
        return MILLIONTHS;
    }
    let agg = report.aggregate_score();
    let max_possible = report.len() as u64 * MILLIONTHS;
    if max_possible == 0 {
        return MILLIONTHS;
    }
    let ratio = (agg * MILLIONTHS) / max_possible;
    MILLIONTHS.saturating_sub(ratio)
}

/// Collect all unique mismatch IDs referenced in a report.
pub fn referenced_mismatch_ids(report: &DoctorReport) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for check in &report.checks {
        for id in &check.related_mismatch_ids {
            ids.insert(id.clone());
        }
    }
    ids
}

/// Filter report checks to only those in the given categories.
pub fn filter_by_categories(
    report: &DoctorReport,
    categories: &BTreeSet<CheckCategory>,
) -> Vec<DoctorCheck> {
    report
        .checks
        .iter()
        .filter(|c| categories.contains(&c.category))
        .cloned()
        .collect()
}

/// Count open mismatch entries per domain for a quick triage view.
pub fn domain_triage(entries: &[MismatchEntry]) -> BTreeMap<String, usize> {
    let mut triage = BTreeMap::new();
    for entry in entries {
        if entry.is_open() {
            *triage.entry(entry.domain.as_str().to_string()).or_insert(0) += 1;
        }
    }
    triage
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash_tiers::ContentHash;
    use crate::react_mismatch_catalog::{
        ComparisonTarget, MismatchDomain, MismatchEntry, MismatchSeverity, RemediationStatus,
    };
    use crate::security_epoch::SecurityEpoch;

    fn epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn make_entry(id: &str, domain: MismatchDomain, severity: MismatchSeverity) -> MismatchEntry {
        MismatchEntry {
            entry_id: id.to_string(),
            domain,
            severity,
            target: ComparisonTarget::NodeJs,
            summary: format!("Mismatch {id}"),
            expected_behavior: "expected".to_string(),
            actual_behavior: "actual".to_string(),
            reproduction: "test fixture".to_string(),
            remediation: RemediationStatus::None,
            advisory: "advisory text".to_string(),
            react_version_range: ">=18.0.0".to_string(),
            evidence_hash: ContentHash::compute(id.as_bytes()),
            detected_epoch: epoch(1),
            verified_epoch: epoch(2),
            tags: ["react", "test"].iter().map(|s| s.to_string()).collect(),
        }
    }

    fn make_entry_full(
        id: &str,
        domain: MismatchDomain,
        severity: MismatchSeverity,
        target: ComparisonTarget,
        remediation: RemediationStatus,
    ) -> MismatchEntry {
        let mut e = make_entry(id, domain, severity);
        e.target = target;
        e.remediation = remediation;
        e
    }

    fn default_config() -> DoctorConfig {
        DoctorConfig::default()
    }

    // -- CheckCategory tests --

    #[test]
    fn check_category_as_str_all_variants() {
        assert_eq!(CheckCategory::PackageHealth.as_str(), "package_health");
        assert_eq!(CheckCategory::VersionCompat.as_str(), "version_compat");
        assert_eq!(CheckCategory::JsxTransform.as_str(), "jsx_transform");
        assert_eq!(CheckCategory::HookOrdering.as_str(), "hook_ordering");
        assert_eq!(CheckCategory::SsrConfig.as_str(), "ssr_config");
        assert_eq!(CheckCategory::ModuleFormat.as_str(), "module_format");
        assert_eq!(CheckCategory::BundleStructure.as_str(), "bundle_structure");
        assert_eq!(CheckCategory::TypeScript.as_str(), "typescript");
    }

    #[test]
    fn check_category_display() {
        assert_eq!(
            format!("{}", CheckCategory::PackageHealth),
            "package_health"
        );
        assert_eq!(format!("{}", CheckCategory::TypeScript), "typescript");
    }

    #[test]
    fn check_category_priority_weights_are_positive() {
        for cat in ALL_CATEGORIES {
            assert!(cat.priority_weight() > 0, "{cat:?} has zero weight");
        }
    }

    #[test]
    fn check_category_ordering_deterministic() {
        let mut cats: Vec<CheckCategory> = ALL_CATEGORIES.to_vec();
        let original = cats.clone();
        cats.sort();
        // BTreeSet ordering should be stable
        let set: BTreeSet<CheckCategory> = cats.iter().copied().collect();
        let from_set: Vec<CheckCategory> = set.into_iter().collect();
        assert_eq!(from_set.len(), original.len());
    }

    #[test]
    fn all_categories_count() {
        assert_eq!(ALL_CATEGORIES.len(), 8);
    }

    // -- CheckSeverity tests --

    #[test]
    fn check_severity_as_str_all_variants() {
        assert_eq!(CheckSeverity::Pass.as_str(), "pass");
        assert_eq!(CheckSeverity::Advisory.as_str(), "advisory");
        assert_eq!(CheckSeverity::Warning.as_str(), "warning");
        assert_eq!(CheckSeverity::Error.as_str(), "error");
        assert_eq!(CheckSeverity::Critical.as_str(), "critical");
    }

    #[test]
    fn check_severity_weights_monotonically_increase() {
        let severities = [
            CheckSeverity::Pass,
            CheckSeverity::Advisory,
            CheckSeverity::Warning,
            CheckSeverity::Error,
            CheckSeverity::Critical,
        ];
        for window in severities.windows(2) {
            assert!(
                window[0].weight() <= window[1].weight(),
                "{:?} weight {} > {:?} weight {}",
                window[0],
                window[0].weight(),
                window[1],
                window[1].weight()
            );
        }
    }

    #[test]
    fn check_severity_blocking_only_error_and_critical() {
        assert!(!CheckSeverity::Pass.is_blocking());
        assert!(!CheckSeverity::Advisory.is_blocking());
        assert!(!CheckSeverity::Warning.is_blocking());
        assert!(CheckSeverity::Error.is_blocking());
        assert!(CheckSeverity::Critical.is_blocking());
    }

    #[test]
    fn check_severity_display() {
        assert_eq!(format!("{}", CheckSeverity::Critical), "critical");
    }

    // -- DoctorCheck tests --

    #[test]
    fn doctor_check_content_hash_deterministic() {
        let check = DoctorCheck {
            check_id: "dc-0001".to_string(),
            category: CheckCategory::PackageHealth,
            severity: CheckSeverity::Warning,
            message: "test message".to_string(),
            remediation: "fix it".to_string(),
            related_mismatch_ids: vec!["m-1".to_string()],
            tags: BTreeSet::new(),
        };
        let h1 = check.content_hash();
        let h2 = check.content_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn doctor_check_is_blocking() {
        let mut check = DoctorCheck {
            check_id: "dc-0001".to_string(),
            category: CheckCategory::PackageHealth,
            severity: CheckSeverity::Warning,
            message: "test".to_string(),
            remediation: "fix".to_string(),
            related_mismatch_ids: vec![],
            tags: BTreeSet::new(),
        };
        assert!(!check.is_blocking());
        check.severity = CheckSeverity::Error;
        assert!(check.is_blocking());
    }

    #[test]
    fn doctor_check_is_pass() {
        let check = DoctorCheck {
            check_id: "dc-0001".to_string(),
            category: CheckCategory::PackageHealth,
            severity: CheckSeverity::Pass,
            message: "ok".to_string(),
            remediation: String::new(),
            related_mismatch_ids: vec![],
            tags: BTreeSet::new(),
        };
        assert!(check.is_pass());
    }

    // -- DoctorConfig tests --

    #[test]
    fn doctor_config_default_includes_all_categories() {
        let cfg = DoctorConfig::default();
        for cat in ALL_CATEGORIES {
            assert!(
                cfg.is_category_enabled(*cat),
                "default should include {cat:?}"
            );
        }
    }

    #[test]
    fn doctor_config_exclude_overrides_include() {
        let mut cfg = DoctorConfig::default();
        cfg.include_categories.insert(CheckCategory::PackageHealth);
        cfg.exclude_categories.insert(CheckCategory::PackageHealth);
        assert!(!cfg.is_category_enabled(CheckCategory::PackageHealth));
    }

    #[test]
    fn doctor_config_include_restricts() {
        let mut cfg = DoctorConfig::default();
        cfg.include_categories.insert(CheckCategory::SsrConfig);
        assert!(cfg.is_category_enabled(CheckCategory::SsrConfig));
        assert!(!cfg.is_category_enabled(CheckCategory::TypeScript));
    }

    #[test]
    fn doctor_config_target_focus_empty_includes_all() {
        let cfg = DoctorConfig::default();
        assert!(cfg.is_target_included(ComparisonTarget::NodeJs));
        assert!(cfg.is_target_included(ComparisonTarget::Bun));
        assert!(cfg.is_target_included(ComparisonTarget::Deno));
    }

    #[test]
    fn doctor_config_target_focus_restricts() {
        let mut cfg = DoctorConfig::default();
        cfg.focus_targets.insert(ComparisonTarget::NodeJs);
        assert!(cfg.is_target_included(ComparisonTarget::NodeJs));
        assert!(!cfg.is_target_included(ComparisonTarget::Bun));
    }

    #[test]
    fn doctor_config_is_entry_relevant_severity_filter() {
        let mut cfg = DoctorConfig::default();
        cfg.min_mismatch_severity = MismatchSeverity::Warning;
        let info = make_entry(
            "info-1",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Info,
        );
        let warn = make_entry(
            "warn-1",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
        );
        assert!(!cfg.is_entry_relevant(&info));
        assert!(cfg.is_entry_relevant(&warn));
    }

    #[test]
    fn doctor_config_is_entry_relevant_resolved_filter() {
        let cfg = DoctorConfig::default();
        let resolved = make_entry_full(
            "r-1",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        );
        assert!(!cfg.is_entry_relevant(&resolved));

        let mut cfg2 = DoctorConfig::default();
        cfg2.include_resolved = true;
        assert!(cfg2.is_entry_relevant(&resolved));
    }

    // -- DoctorReport tests --

    #[test]
    fn doctor_report_new_is_empty() {
        let report = DoctorReport::new(epoch(1));
        assert!(report.is_empty());
        assert_eq!(report.len(), 0);
        assert_eq!(report.blocking_count(), 0);
    }

    #[test]
    fn doctor_report_schema_constants() {
        let report = DoctorReport::new(epoch(1));
        assert_eq!(report.schema_version, DOCTOR_PREFLIGHT_SCHEMA_VERSION);
        assert_eq!(report.bead_id, DOCTOR_PREFLIGHT_BEAD_ID);
        assert_eq!(report.policy_id, DOCTOR_PREFLIGHT_POLICY_ID);
    }

    #[test]
    fn doctor_report_aggregate_score() {
        let entries = vec![
            make_entry(
                "e-1",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Warning,
            ),
            make_entry("e-2", MismatchDomain::Diagnostics, MismatchSeverity::Error),
        ];
        let report = run_doctor(&default_config(), &entries).unwrap();
        assert!(report.aggregate_score() > 0);
    }

    // -- run_doctor tests --

    #[test]
    fn run_doctor_empty_entries_returns_empty_report() {
        let report = run_doctor(&default_config(), &[]).unwrap();
        assert!(report.is_empty());
    }

    #[test]
    fn run_doctor_single_info_entry() {
        let entries = vec![make_entry(
            "info-1",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Info,
        )];
        let report = run_doctor(&default_config(), &entries).unwrap();
        assert!(!report.is_empty());
        assert_eq!(report.blocking_count(), 0);
    }

    #[test]
    fn run_doctor_critical_entry_produces_blocking() {
        let entries = vec![make_entry(
            "crit-1",
            MismatchDomain::ServerSideRender,
            MismatchSeverity::Critical,
        )];
        let report = run_doctor(&default_config(), &entries).unwrap();
        assert!(report.blocking_count() > 0);
    }

    #[test]
    fn run_doctor_respects_category_exclusion() {
        let mut cfg = default_config();
        cfg.exclude_categories.insert(CheckCategory::SsrConfig);
        let entries = vec![make_entry(
            "ssr-1",
            MismatchDomain::ServerSideRender,
            MismatchSeverity::Error,
        )];
        let report = run_doctor(&cfg, &entries).unwrap();
        let ssr_checks = report.checks_by_category(CheckCategory::SsrConfig);
        assert!(ssr_checks.is_empty());
    }

    #[test]
    fn run_doctor_respects_max_checks() {
        let mut cfg = default_config();
        cfg.max_checks = 2;
        let entries: Vec<_> = (0..10)
            .map(|i| {
                make_entry(
                    &format!("e-{i}"),
                    MismatchDomain::Diagnostics,
                    MismatchSeverity::Warning,
                )
            })
            .collect();
        let report = run_doctor(&cfg, &entries).unwrap();
        assert!(report.len() <= 2);
    }

    #[test]
    fn run_doctor_invalid_config_zero_max_checks() {
        let mut cfg = default_config();
        cfg.max_checks = 0;
        let result = run_doctor(&cfg, &[]);
        assert!(result.is_err());
        if let Err(DoctorError::InvalidConfig { reason }) = result {
            assert!(reason.contains("max_checks"));
        }
    }

    #[test]
    fn run_doctor_filters_resolved_by_default() {
        let entries = vec![make_entry_full(
            "resolved-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        )];
        let report = run_doctor(&default_config(), &entries).unwrap();
        assert!(report.is_empty());
    }

    #[test]
    fn run_doctor_includes_resolved_when_configured() {
        let mut cfg = default_config();
        cfg.include_resolved = true;
        let entries = vec![make_entry_full(
            "resolved-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        )];
        let report = run_doctor(&cfg, &entries).unwrap();
        assert!(!report.is_empty());
    }

    #[test]
    fn run_doctor_multiple_domains() {
        let entries = vec![
            make_entry(
                "e-1",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Warning,
            ),
            make_entry(
                "e-2",
                MismatchDomain::HookSemantics,
                MismatchSeverity::Error,
            ),
            make_entry("e-3", MismatchDomain::ModuleGraph, MismatchSeverity::Info),
        ];
        let report = run_doctor(&default_config(), &entries).unwrap();
        assert!(report.len() >= 3);
    }

    #[test]
    fn run_doctor_staleness_detection() {
        let mut cfg = default_config();
        cfg.current_epoch = epoch(50);
        let mut e = make_entry(
            "stale-1",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
        );
        e.verified_epoch = epoch(5); // 45 epochs behind
        let report = run_doctor(&cfg, &[e]).unwrap();
        let stale: Vec<_> = report
            .checks
            .iter()
            .filter(|c| c.check_id.contains("stale"))
            .collect();
        assert!(!stale.is_empty());
    }

    // -- run_preflight tests --

    #[test]
    fn preflight_passes_on_empty() {
        let result = run_preflight(&default_config(), &[]).unwrap();
        assert!(result.passed);
        assert_eq!(result.blocker_count(), 0);
    }

    #[test]
    fn preflight_passes_on_warnings_only() {
        let entries = vec![make_entry(
            "warn-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        )];
        let result = run_preflight(&default_config(), &entries).unwrap();
        assert!(result.passed);
        assert!(result.advisory_count() > 0);
    }

    #[test]
    fn preflight_fails_on_errors() {
        let entries = vec![make_entry(
            "err-1",
            MismatchDomain::ServerSideRender,
            MismatchSeverity::Error,
        )];
        let result = run_preflight(&default_config(), &entries).unwrap();
        assert!(!result.passed);
        assert!(result.blocker_count() > 0);
    }

    #[test]
    fn preflight_fails_on_critical() {
        let entries = vec![make_entry(
            "crit-1",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Critical,
        )];
        let result = run_preflight(&default_config(), &entries).unwrap();
        assert!(!result.passed);
    }

    #[test]
    fn preflight_entries_analyzed_count() {
        let entries = vec![
            make_entry("e-1", MismatchDomain::CompileOutput, MismatchSeverity::Info),
            make_entry("e-2", MismatchDomain::Diagnostics, MismatchSeverity::Info),
        ];
        let result = run_preflight(&default_config(), &entries).unwrap();
        assert_eq!(result.entries_analyzed, 2);
    }

    #[test]
    fn preflight_total_findings() {
        let entries = vec![
            make_entry(
                "e-1",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Warning,
            ),
            make_entry("e-2", MismatchDomain::Diagnostics, MismatchSeverity::Error),
        ];
        let result = run_preflight(&default_config(), &entries).unwrap();
        assert!(result.total_findings() > 0);
    }

    // -- build_support_bundle tests --

    #[test]
    fn support_bundle_from_empty_report() {
        let report = DoctorReport::new(epoch(1));
        let bundle = build_support_bundle(&report).unwrap();
        assert!(bundle.is_empty());
        assert_eq!(bundle.schema_version, DOCTOR_PREFLIGHT_SCHEMA_VERSION);
    }

    #[test]
    fn support_bundle_has_entries_for_checks() {
        let entries = vec![
            make_entry(
                "e-1",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Warning,
            ),
            make_entry(
                "e-2",
                MismatchDomain::HookSemantics,
                MismatchSeverity::Error,
            ),
        ];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let bundle = build_support_bundle(&report).unwrap();
        assert!(!bundle.is_empty());
        let doctor_checks = bundle.entries_by_category("doctor_checks");
        assert!(!doctor_checks.is_empty());
    }

    #[test]
    fn support_bundle_contains_severity_breakdown() {
        let entries = vec![make_entry(
            "e-1",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
        )];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let bundle = build_support_bundle(&report).unwrap();
        let severity = bundle.entries_by_category("severity_breakdown");
        assert!(!severity.is_empty());
    }

    #[test]
    fn support_bundle_contains_guidance() {
        let entries = vec![make_entry(
            "e-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        )];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let bundle = build_support_bundle(&report).unwrap();
        let guidance = bundle.entries_by_category("guidance");
        assert!(!guidance.is_empty());
    }

    // -- generate_guidance tests --

    #[test]
    fn guidance_empty_report() {
        let report = DoctorReport::new(epoch(1));
        let guidance = generate_guidance(&report).unwrap();
        assert!(guidance.is_empty());
    }

    #[test]
    fn guidance_groups_by_category() {
        let entries = vec![
            make_entry(
                "e-1",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Warning,
            ),
            make_entry(
                "e-2",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Error,
            ),
        ];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let guidance = generate_guidance(&report).unwrap();
        // Both map to JsxTransform, should be consolidated
        let jsx_guidance: Vec<_> = guidance
            .iter()
            .filter(|g| g.category == CheckCategory::JsxTransform)
            .collect();
        assert!(!jsx_guidance.is_empty());
    }

    #[test]
    fn guidance_sorted_by_priority() {
        let entries = vec![
            make_entry(
                "e-1",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Warning,
            ),
            make_entry(
                "e-2",
                MismatchDomain::HookSemantics,
                MismatchSeverity::Critical,
            ),
        ];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let guidance = generate_guidance(&report).unwrap();
        if guidance.len() >= 2 {
            assert!(guidance[0].priority <= guidance[1].priority);
        }
    }

    #[test]
    fn guidance_has_steps() {
        let entries = vec![make_entry(
            "e-1",
            MismatchDomain::ServerSideRender,
            MismatchSeverity::Error,
        )];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let guidance = generate_guidance(&report).unwrap();
        assert!(!guidance.is_empty());
        assert!(!guidance[0].steps.is_empty());
    }

    #[test]
    fn guidance_content_hash_deterministic() {
        let entries = vec![make_entry(
            "e-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        )];
        let r1 = run_doctor(&default_config(), &entries).unwrap();
        let r2 = run_doctor(&default_config(), &entries).unwrap();
        let g1 = generate_guidance(&r1).unwrap();
        let g2 = generate_guidance(&r2).unwrap();
        assert_eq!(g1.len(), g2.len());
        for (a, b) in g1.iter().zip(g2.iter()) {
            assert_eq!(a.content_hash(), b.content_hash());
        }
    }

    // -- is_react_ready tests --

    #[test]
    fn is_react_ready_empty_report() {
        let report = DoctorReport::new(epoch(1));
        assert!(is_react_ready(&report));
    }

    #[test]
    fn is_react_ready_with_blocking() {
        let entries = vec![make_entry(
            "e-1",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Critical,
        )];
        let report = run_doctor(&default_config(), &entries).unwrap();
        assert!(!is_react_ready(&report));
    }

    // -- summarize tests --

    #[test]
    fn summarize_empty_report() {
        let report = DoctorReport::new(epoch(1));
        let summary = summarize(&report);
        assert_eq!(summary.total_checks, 0);
        assert!(summary.is_ready);
        assert_eq!(summary.aggregate_score, 0);
    }

    #[test]
    fn summarize_counts_match() {
        let entries = vec![
            make_entry(
                "e-1",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Warning,
            ),
            make_entry(
                "e-2",
                MismatchDomain::HookSemantics,
                MismatchSeverity::Error,
            ),
            make_entry("e-3", MismatchDomain::Diagnostics, MismatchSeverity::Info),
        ];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let summary = summarize(&report);
        assert_eq!(
            summary.total_checks,
            summary.pass_count
                + summary.advisory_count
                + summary.warning_count
                + summary.error_count
                + summary.critical_count
        );
    }

    #[test]
    fn summarize_not_ready_with_errors() {
        let entries = vec![make_entry(
            "e-1",
            MismatchDomain::ModuleGraph,
            MismatchSeverity::Error,
        )];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let summary = summarize(&report);
        assert!(!summary.is_ready);
    }

    // -- readiness_score tests --

    #[test]
    fn readiness_score_empty_is_max() {
        let report = DoctorReport::new(epoch(1));
        assert_eq!(readiness_score(&report), MILLIONTHS);
    }

    #[test]
    fn readiness_score_decreases_with_issues() {
        let entries_light = vec![make_entry(
            "e-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Info,
        )];
        let entries_heavy = vec![
            make_entry(
                "e-1",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Critical,
            ),
            make_entry(
                "e-2",
                MismatchDomain::HookSemantics,
                MismatchSeverity::Critical,
            ),
        ];
        let r_light = run_doctor(&default_config(), &entries_light).unwrap();
        let r_heavy = run_doctor(&default_config(), &entries_heavy).unwrap();
        assert!(readiness_score(&r_light) > readiness_score(&r_heavy));
    }

    // -- referenced_mismatch_ids tests --

    #[test]
    fn referenced_mismatch_ids_collects_all() {
        let entries = vec![
            make_entry(
                "e-1",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Warning,
            ),
            make_entry("e-2", MismatchDomain::Diagnostics, MismatchSeverity::Error),
        ];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let ids = referenced_mismatch_ids(&report);
        assert!(ids.contains("e-1"));
        assert!(ids.contains("e-2"));
    }

    // -- filter_by_categories tests --

    #[test]
    fn filter_by_categories_restricts() {
        let entries = vec![
            make_entry(
                "e-1",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Warning,
            ),
            make_entry(
                "e-2",
                MismatchDomain::HookSemantics,
                MismatchSeverity::Error,
            ),
        ];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let cats: BTreeSet<_> = [CheckCategory::HookOrdering].into_iter().collect();
        let filtered = filter_by_categories(&report, &cats);
        for c in &filtered {
            assert_eq!(c.category, CheckCategory::HookOrdering);
        }
    }

    // -- domain_triage tests --

    #[test]
    fn domain_triage_counts_open_only() {
        let entries = vec![
            make_entry(
                "e-1",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Warning,
            ),
            make_entry_full(
                "e-2",
                MismatchDomain::CompileOutput,
                MismatchSeverity::Error,
                ComparisonTarget::NodeJs,
                RemediationStatus::Resolved,
            ),
        ];
        let triage = domain_triage(&entries);
        assert_eq!(triage.get("compile_output"), Some(&1));
    }

    #[test]
    fn domain_triage_empty() {
        let triage = domain_triage(&[]);
        assert!(triage.is_empty());
    }

    // -- domain_to_category mapping tests --

    #[test]
    fn domain_to_category_coverage() {
        // Ensure all domains map to some category
        let domains = [
            MismatchDomain::CompileOutput,
            MismatchDomain::Diagnostics,
            MismatchDomain::SourceMap,
            MismatchDomain::ServerSideRender,
            MismatchDomain::ClientEntry,
            MismatchDomain::ArtifactShape,
            MismatchDomain::ModuleGraph,
            MismatchDomain::HookSemantics,
            MismatchDomain::SuspenseBoundary,
            MismatchDomain::ErrorBoundary,
        ];
        for d in domains {
            let _ = domain_to_category(d);
        }
    }

    // -- Serde roundtrip tests --

    #[test]
    fn serde_roundtrip_check_category() {
        for cat in ALL_CATEGORIES {
            let json = serde_json::to_string(cat).unwrap();
            let back: CheckCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(*cat, back);
        }
    }

    #[test]
    fn serde_roundtrip_check_severity() {
        for sev in [
            CheckSeverity::Pass,
            CheckSeverity::Advisory,
            CheckSeverity::Warning,
            CheckSeverity::Error,
            CheckSeverity::Critical,
        ] {
            let json = serde_json::to_string(&sev).unwrap();
            let back: CheckSeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn serde_roundtrip_doctor_report() {
        let entries = vec![make_entry(
            "e-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        )];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let back: DoctorReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report.len(), back.len());
        assert_eq!(report.report_hash, back.report_hash);
    }

    #[test]
    fn serde_roundtrip_preflight_result() {
        let entries = vec![make_entry(
            "e-1",
            MismatchDomain::HookSemantics,
            MismatchSeverity::Error,
        )];
        let result = run_preflight(&default_config(), &entries).unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let back: PreflightResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result.passed, back.passed);
        assert_eq!(result.blocker_count(), back.blocker_count());
    }

    #[test]
    fn serde_roundtrip_guidance_entry() {
        let entries = vec![make_entry(
            "e-1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        )];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let guidance = generate_guidance(&report).unwrap();
        for g in &guidance {
            let json = serde_json::to_string(g).unwrap();
            let back: GuidanceEntry = serde_json::from_str(&json).unwrap();
            assert_eq!(g.guidance_id, back.guidance_id);
        }
    }

    #[test]
    fn serde_roundtrip_support_bundle() {
        let entries = vec![make_entry(
            "e-1",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
        )];
        let report = run_doctor(&default_config(), &entries).unwrap();
        let bundle = build_support_bundle(&report).unwrap();
        let json = serde_json::to_string(&bundle).unwrap();
        let back: SupportBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle.len(), back.len());
    }

    #[test]
    fn serde_roundtrip_doctor_config() {
        let cfg = DoctorConfig::default();
        let json = serde_json::to_string(&cfg).unwrap();
        let back: DoctorConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn serde_roundtrip_doctor_error() {
        let err = DoctorError::EmptyInput;
        let json = serde_json::to_string(&err).unwrap();
        let back: DoctorError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
    }

    // -- DoctorError Display tests --

    #[test]
    fn doctor_error_display_capacity() {
        let err = DoctorError::CheckCapacityExceeded {
            current: 100,
            max: 50,
        };
        let s = format!("{err}");
        assert!(s.contains("100"));
        assert!(s.contains("50"));
    }

    #[test]
    fn doctor_error_display_empty_input() {
        let err = DoctorError::EmptyInput;
        assert_eq!(format!("{err}"), "no mismatch entries to analyze");
    }

    #[test]
    fn doctor_error_display_stale_data() {
        let err = DoctorError::StaleData {
            entry_id: "e-1".to_string(),
            epoch_gap: 42,
        };
        let s = format!("{err}");
        assert!(s.contains("e-1"));
        assert!(s.contains("42"));
    }

    // -- Schema constant tests --

    #[test]
    fn schema_constants_non_empty() {
        assert!(!DOCTOR_PREFLIGHT_SCHEMA_VERSION.is_empty());
        assert!(!DOCTOR_PREFLIGHT_BEAD_ID.is_empty());
        assert!(!DOCTOR_PREFLIGHT_POLICY_ID.is_empty());
        assert!(!COMPONENT.is_empty());
    }

    #[test]
    fn bead_id_format() {
        assert!(DOCTOR_PREFLIGHT_BEAD_ID.starts_with("bd-"));
    }

    #[test]
    fn policy_id_format() {
        assert!(DOCTOR_PREFLIGHT_POLICY_ID.starts_with("RGC-"));
    }
}
