#![forbid(unsafe_code)]

//! React mismatch catalog for docs, advisories, and benchmark gates.
//!
//! Aggregates React mismatches across compile outputs, diagnostics, SSR,
//! client-entry, and artifact shapes into a machine-readable catalog.
//! Downstream consumers (docs generators, advisory publishers, benchmark
//! gates, and rollout gates) consume the catalog without manual
//! interpretation.
//!
//! Plan references: Section 9.7 (RGC-807C), bead bd-1lsy.9.7.3.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

/// Schema version for the react mismatch catalog.
pub const MISMATCH_CATALOG_SCHEMA_VERSION: &str = "franken-engine.react-mismatch-catalog.v1";

/// Bead identifier originating this module.
pub const MISMATCH_CATALOG_BEAD_ID: &str = "bd-1lsy.9.7.3";

/// Policy ID binding.
pub const MISMATCH_CATALOG_POLICY_ID: &str = "RGC-807C";

/// Component name for evidence linkage.
pub const COMPONENT: &str = "react_mismatch_catalog";

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLIONTHS: u64 = 1_000_000;

/// Maximum entries in a single catalog batch.
const MAX_CATALOG_ENTRIES: usize = 10_000;

/// Maximum advisory text length.
const MAX_ADVISORY_LEN: usize = 4096;

// ---------------------------------------------------------------------------
// MismatchDomain
// ---------------------------------------------------------------------------

/// The domain in which a React mismatch was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchDomain {
    /// Compile output differences (emitted JS, JSX transform mode).
    CompileOutput,
    /// Diagnostic differences (warnings, errors, suggestions).
    Diagnostics,
    /// Source-map behavior differences.
    SourceMap,
    /// Server-side rendering behavior.
    ServerSideRender,
    /// Client-entry hydration behavior.
    ClientEntry,
    /// Artifact shape (bundle structure, chunk boundaries).
    ArtifactShape,
    /// Module graph topology differences.
    ModuleGraph,
    /// Hook execution ordering or semantics.
    HookSemantics,
    /// Suspense boundary behavior.
    SuspenseBoundary,
    /// Error boundary propagation.
    ErrorBoundary,
}

impl MismatchDomain {
    /// Short identifier for hash derivation and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CompileOutput => "compile_output",
            Self::Diagnostics => "diagnostics",
            Self::SourceMap => "source_map",
            Self::ServerSideRender => "server_side_render",
            Self::ClientEntry => "client_entry",
            Self::ArtifactShape => "artifact_shape",
            Self::ModuleGraph => "module_graph",
            Self::HookSemantics => "hook_semantics",
            Self::SuspenseBoundary => "suspense_boundary",
            Self::ErrorBoundary => "error_boundary",
        }
    }
}

impl fmt::Display for MismatchDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// All domain variants for exhaustive iteration.
pub const ALL_DOMAINS: &[MismatchDomain] = &[
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

// ---------------------------------------------------------------------------
// MismatchSeverity
// ---------------------------------------------------------------------------

/// Severity classification for a mismatch entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MismatchSeverity {
    /// Informational: no behavioral impact observed.
    Info,
    /// Warning: potential behavioral impact under specific conditions.
    Warning,
    /// Error: confirmed behavioral divergence.
    Error,
    /// Critical: divergence that could cause data loss or security issues.
    Critical,
}

impl MismatchSeverity {
    /// Short identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    /// Numeric weight for aggregation (fixed-point millionths).
    pub const fn weight(self) -> u64 {
        match self {
            Self::Info => 100_000,       // 0.1
            Self::Warning => 300_000,    // 0.3
            Self::Error => 700_000,      // 0.7
            Self::Critical => 1_000_000, // 1.0
        }
    }
}

impl fmt::Display for MismatchSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// RemediationStatus
// ---------------------------------------------------------------------------

/// Status of the remediation for a mismatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStatus {
    /// No remediation available yet.
    None,
    /// Workaround documented.
    Workaround,
    /// Fix in progress.
    InProgress,
    /// Fix shipped, awaiting verification.
    Shipped,
    /// Fix verified and closed.
    Resolved,
    /// Mismatch accepted as known limitation.
    Accepted,
}

impl RemediationStatus {
    /// Short identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Workaround => "workaround",
            Self::InProgress => "in_progress",
            Self::Shipped => "shipped",
            Self::Resolved => "resolved",
            Self::Accepted => "accepted",
        }
    }

    /// Whether this status counts as open (not yet resolved or accepted).
    pub const fn is_open(self) -> bool {
        matches!(
            self,
            Self::None | Self::Workaround | Self::InProgress | Self::Shipped
        )
    }
}

impl fmt::Display for RemediationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ComparisonTarget
// ---------------------------------------------------------------------------

/// The runtime or tool being compared against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComparisonTarget {
    /// Node.js runtime.
    NodeJs,
    /// Bun runtime.
    Bun,
    /// Deno runtime.
    Deno,
    /// Reference V8 behavior.
    V8Reference,
}

impl ComparisonTarget {
    /// Short identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NodeJs => "nodejs",
            Self::Bun => "bun",
            Self::Deno => "deno",
            Self::V8Reference => "v8_reference",
        }
    }
}

impl fmt::Display for ComparisonTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// MismatchEntry
// ---------------------------------------------------------------------------

/// A single mismatch catalog entry with full provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MismatchEntry {
    /// Unique identifier for this mismatch.
    pub entry_id: String,
    /// Domain of the mismatch.
    pub domain: MismatchDomain,
    /// Severity classification.
    pub severity: MismatchSeverity,
    /// Runtime or tool being compared against.
    pub target: ComparisonTarget,
    /// Human-readable summary of the mismatch.
    pub summary: String,
    /// Detailed description of the expected behavior.
    pub expected_behavior: String,
    /// Detailed description of the actual behavior.
    pub actual_behavior: String,
    /// Minimal reproduction steps or test case identifier.
    pub reproduction: String,
    /// Current remediation status.
    pub remediation: RemediationStatus,
    /// Advisory text for operators and users.
    pub advisory: String,
    /// React version range affected (semver-like).
    pub react_version_range: String,
    /// Content hash of the evidence bundle.
    pub evidence_hash: ContentHash,
    /// Epoch at which this mismatch was first detected.
    pub detected_epoch: SecurityEpoch,
    /// Epoch of the most recent verification.
    pub verified_epoch: SecurityEpoch,
    /// Tags for filtering and grouping.
    pub tags: BTreeSet<String>,
}

impl MismatchEntry {
    /// Compute a deterministic content hash for this entry.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(MISMATCH_CATALOG_SCHEMA_VERSION.as_bytes());
        hasher.update(self.entry_id.as_bytes());
        hasher.update(self.domain.as_str().as_bytes());
        hasher.update(self.severity.as_str().as_bytes());
        hasher.update(self.target.as_str().as_bytes());
        hasher.update(self.summary.as_bytes());
        hasher.update(self.expected_behavior.as_bytes());
        hasher.update(self.actual_behavior.as_bytes());
        hasher.update(self.reproduction.as_bytes());
        hasher.update(self.remediation.as_str().as_bytes());
        hasher.update(self.advisory.as_bytes());
        hasher.update(self.react_version_range.as_bytes());
        hasher.update(self.evidence_hash.as_bytes());
        hasher.update(self.detected_epoch.as_u64().to_le_bytes());
        hasher.update(self.verified_epoch.as_u64().to_le_bytes());
        for tag in &self.tags {
            hasher.update((tag.len() as u64).to_le_bytes());
            hasher.update(tag.as_bytes());
        }
        ContentHash::compute(&hasher.finalize())
    }

    /// Whether this entry is still open (not resolved or accepted).
    pub fn is_open(&self) -> bool {
        self.remediation.is_open()
    }

    /// Weighted severity score in fixed-point millionths.
    pub fn weighted_score(&self) -> u64 {
        self.severity.weight()
    }
}

// ---------------------------------------------------------------------------
// CatalogConfig
// ---------------------------------------------------------------------------

/// Configuration for catalog construction and gating.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogConfig {
    /// Maximum number of open critical entries before gate blocks.
    pub max_open_critical: usize,
    /// Maximum number of open error entries before gate blocks.
    pub max_open_errors: usize,
    /// Maximum aggregate weighted score (millionths) before gate blocks.
    pub max_aggregate_score: u64,
    /// Domains that must be covered for a catalog to be complete.
    pub required_domains: BTreeSet<MismatchDomain>,
    /// Comparison targets that must be covered.
    pub required_targets: BTreeSet<ComparisonTarget>,
    /// Minimum verification epoch for entries to be considered current.
    pub min_verification_epoch: SecurityEpoch,
}

impl Default for CatalogConfig {
    fn default() -> Self {
        Self {
            max_open_critical: 0,
            max_open_errors: 5,
            max_aggregate_score: 3_000_000, // 3.0
            required_domains: ALL_DOMAINS.iter().copied().collect(),
            required_targets: [ComparisonTarget::NodeJs, ComparisonTarget::Bun]
                .into_iter()
                .collect(),
            min_verification_epoch: SecurityEpoch::from_raw(0),
        }
    }
}

// ---------------------------------------------------------------------------
// DomainSummary
// ---------------------------------------------------------------------------

/// Per-domain aggregation summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainSummary {
    /// The domain.
    pub domain: MismatchDomain,
    /// Total entries in this domain.
    pub total_entries: usize,
    /// Number of open entries.
    pub open_entries: usize,
    /// Number of resolved entries.
    pub resolved_entries: usize,
    /// Count by severity.
    pub by_severity: BTreeMap<String, usize>,
    /// Aggregate weighted score (millionths).
    pub aggregate_score: u64,
}

// ---------------------------------------------------------------------------
// TargetSummary
// ---------------------------------------------------------------------------

/// Per-target aggregation summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSummary {
    /// The comparison target.
    pub target: ComparisonTarget,
    /// Total entries against this target.
    pub total_entries: usize,
    /// Number of open entries.
    pub open_entries: usize,
    /// Aggregate weighted score (millionths).
    pub aggregate_score: u64,
}

// ---------------------------------------------------------------------------
// GateVerdict
// ---------------------------------------------------------------------------

/// Verdict from evaluating the catalog against a gate configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateVerdict {
    /// Catalog passes all gate checks.
    Pass,
    /// Catalog fails one or more gate checks.
    Fail {
        /// Reasons for failure.
        reasons: Vec<String>,
    },
    /// Catalog is incomplete (missing required domains or targets).
    Incomplete {
        /// Missing domains.
        missing_domains: Vec<MismatchDomain>,
        /// Missing targets.
        missing_targets: Vec<ComparisonTarget>,
    },
}

impl GateVerdict {
    /// Whether this verdict allows proceeding.
    pub fn is_pass(&self) -> bool {
        matches!(self, Self::Pass)
    }
}

impl fmt::Display for GateVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "PASS"),
            Self::Fail { reasons } => write!(f, "FAIL: {}", reasons.join("; ")),
            Self::Incomplete {
                missing_domains,
                missing_targets,
            } => {
                write!(f, "INCOMPLETE: ")?;
                if !missing_domains.is_empty() {
                    write!(
                        f,
                        "missing domains: {}",
                        missing_domains
                            .iter()
                            .map(|d| d.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )?;
                }
                if !missing_targets.is_empty() {
                    if !missing_domains.is_empty() {
                        write!(f, "; ")?;
                    }
                    write!(
                        f,
                        "missing targets: {}",
                        missing_targets
                            .iter()
                            .map(|t| t.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )?;
                }
                Ok(())
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CatalogError
// ---------------------------------------------------------------------------

/// Errors from catalog operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CatalogError {
    /// Catalog capacity exceeded.
    CapacityExceeded { current: usize, max: usize },
    /// Duplicate entry ID.
    DuplicateEntry { entry_id: String },
    /// Advisory text too long.
    AdvisoryTooLong { entry_id: String, len: usize },
    /// Entry not found.
    EntryNotFound { entry_id: String },
    /// Invalid epoch.
    InvalidEpoch { entry_id: String, reason: String },
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExceeded { current, max } => {
                write!(f, "catalog capacity exceeded: {current}/{max}")
            }
            Self::DuplicateEntry { entry_id } => {
                write!(f, "duplicate entry: {entry_id}")
            }
            Self::AdvisoryTooLong { entry_id, len } => {
                write!(
                    f,
                    "advisory too long for {entry_id}: {len} > {MAX_ADVISORY_LEN}"
                )
            }
            Self::EntryNotFound { entry_id } => {
                write!(f, "entry not found: {entry_id}")
            }
            Self::InvalidEpoch { entry_id, reason } => {
                write!(f, "invalid epoch for {entry_id}: {reason}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// MismatchCatalog
// ---------------------------------------------------------------------------

/// Machine-readable catalog of React mismatches with full provenance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MismatchCatalog {
    /// Schema version.
    pub schema_version: String,
    /// Bead ID that produced this catalog.
    pub bead_id: String,
    /// Policy ID binding.
    pub policy_id: String,
    /// Security epoch of this catalog snapshot.
    pub epoch: SecurityEpoch,
    /// All mismatch entries indexed by entry_id.
    entries: Vec<MismatchEntry>,
    /// Content hash of the catalog itself.
    pub catalog_hash: ContentHash,
}

impl MismatchCatalog {
    /// Create a new empty catalog at the given epoch.
    pub fn new(epoch: SecurityEpoch) -> Self {
        Self {
            schema_version: MISMATCH_CATALOG_SCHEMA_VERSION.to_string(),
            bead_id: MISMATCH_CATALOG_BEAD_ID.to_string(),
            policy_id: MISMATCH_CATALOG_POLICY_ID.to_string(),
            epoch,
            entries: Vec::new(),
            catalog_hash: ContentHash::compute(b"empty"),
        }
    }

    /// Add an entry to the catalog.
    pub fn add_entry(&mut self, entry: MismatchEntry) -> Result<(), CatalogError> {
        if self.entries.len() >= MAX_CATALOG_ENTRIES {
            return Err(CatalogError::CapacityExceeded {
                current: self.entries.len(),
                max: MAX_CATALOG_ENTRIES,
            });
        }
        if self.entries.iter().any(|e| e.entry_id == entry.entry_id) {
            return Err(CatalogError::DuplicateEntry {
                entry_id: entry.entry_id,
            });
        }
        if entry.advisory.len() > MAX_ADVISORY_LEN {
            return Err(CatalogError::AdvisoryTooLong {
                entry_id: entry.entry_id,
                len: entry.advisory.len(),
            });
        }
        if entry.verified_epoch.as_u64() < entry.detected_epoch.as_u64() {
            return Err(CatalogError::InvalidEpoch {
                entry_id: entry.entry_id,
                reason: "verified_epoch < detected_epoch".to_string(),
            });
        }
        self.entries.push(entry);
        self.recompute_hash();
        Ok(())
    }

    /// Remove an entry by ID.
    pub fn remove_entry(&mut self, entry_id: &str) -> Result<MismatchEntry, CatalogError> {
        let pos = self
            .entries
            .iter()
            .position(|e| e.entry_id == entry_id)
            .ok_or_else(|| CatalogError::EntryNotFound {
                entry_id: entry_id.to_string(),
            })?;
        let entry = self.entries.remove(pos);
        self.recompute_hash();
        Ok(entry)
    }

    /// Update the remediation status of an entry.
    pub fn update_remediation(
        &mut self,
        entry_id: &str,
        status: RemediationStatus,
    ) -> Result<(), CatalogError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.entry_id == entry_id)
            .ok_or_else(|| CatalogError::EntryNotFound {
                entry_id: entry_id.to_string(),
            })?;
        entry.remediation = status;
        self.recompute_hash();
        Ok(())
    }

    /// Get a reference to an entry by ID.
    pub fn get_entry(&self, entry_id: &str) -> Option<&MismatchEntry> {
        self.entries.iter().find(|e| e.entry_id == entry_id)
    }

    /// All entries in the catalog.
    pub fn entries(&self) -> &[MismatchEntry] {
        &self.entries
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the catalog is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Count of open entries (not resolved or accepted).
    pub fn open_count(&self) -> usize {
        self.entries.iter().filter(|e| e.is_open()).count()
    }

    /// Count of entries by severity.
    pub fn count_by_severity(&self, severity: MismatchSeverity) -> usize {
        self.entries
            .iter()
            .filter(|e| e.severity == severity)
            .count()
    }

    /// Count of open entries by severity.
    pub fn open_count_by_severity(&self, severity: MismatchSeverity) -> usize {
        self.entries
            .iter()
            .filter(|e| e.is_open() && e.severity == severity)
            .count()
    }

    /// Aggregate weighted score of all open entries (millionths).
    pub fn aggregate_open_score(&self) -> u64 {
        self.entries
            .iter()
            .filter(|e| e.is_open())
            .map(|e| e.weighted_score())
            .sum()
    }

    /// Domains covered by at least one entry.
    pub fn covered_domains(&self) -> BTreeSet<MismatchDomain> {
        self.entries.iter().map(|e| e.domain).collect()
    }

    /// Targets covered by at least one entry.
    pub fn covered_targets(&self) -> BTreeSet<ComparisonTarget> {
        self.entries.iter().map(|e| e.target).collect()
    }

    /// Filter entries by domain.
    pub fn entries_by_domain(&self, domain: MismatchDomain) -> Vec<&MismatchEntry> {
        self.entries.iter().filter(|e| e.domain == domain).collect()
    }

    /// Filter entries by target.
    pub fn entries_by_target(&self, target: ComparisonTarget) -> Vec<&MismatchEntry> {
        self.entries.iter().filter(|e| e.target == target).collect()
    }

    /// Filter entries by severity.
    pub fn entries_by_severity(&self, severity: MismatchSeverity) -> Vec<&MismatchEntry> {
        self.entries
            .iter()
            .filter(|e| e.severity == severity)
            .collect()
    }

    /// Filter entries by tag.
    pub fn entries_by_tag(&self, tag: &str) -> Vec<&MismatchEntry> {
        self.entries
            .iter()
            .filter(|e| e.tags.contains(tag))
            .collect()
    }

    /// Produce a per-domain summary.
    pub fn domain_summary(&self) -> Vec<DomainSummary> {
        ALL_DOMAINS
            .iter()
            .map(|&domain| {
                let entries: Vec<_> = self.entries.iter().filter(|e| e.domain == domain).collect();
                let mut by_severity = BTreeMap::new();
                for sev in [
                    MismatchSeverity::Info,
                    MismatchSeverity::Warning,
                    MismatchSeverity::Error,
                    MismatchSeverity::Critical,
                ] {
                    let count = entries.iter().filter(|e| e.severity == sev).count();
                    if count > 0 {
                        by_severity.insert(sev.as_str().to_string(), count);
                    }
                }
                DomainSummary {
                    domain,
                    total_entries: entries.len(),
                    open_entries: entries.iter().filter(|e| e.is_open()).count(),
                    resolved_entries: entries.iter().filter(|e| !e.is_open()).count(),
                    by_severity,
                    aggregate_score: entries
                        .iter()
                        .filter(|e| e.is_open())
                        .map(|e| e.weighted_score())
                        .sum(),
                }
            })
            .collect()
    }

    /// Produce a per-target summary.
    pub fn target_summary(&self) -> Vec<TargetSummary> {
        let targets: BTreeSet<_> = self.entries.iter().map(|e| e.target).collect();
        targets
            .into_iter()
            .map(|target| {
                let entries: Vec<_> = self.entries.iter().filter(|e| e.target == target).collect();
                TargetSummary {
                    target,
                    total_entries: entries.len(),
                    open_entries: entries.iter().filter(|e| e.is_open()).count(),
                    aggregate_score: entries
                        .iter()
                        .filter(|e| e.is_open())
                        .map(|e| e.weighted_score())
                        .sum(),
                }
            })
            .collect()
    }

    /// Evaluate the catalog against gate configuration.
    pub fn evaluate(&self, config: &CatalogConfig) -> GateVerdict {
        // Check completeness first.
        let covered_d = self.covered_domains();
        let covered_t = self.covered_targets();
        let missing_domains: Vec<_> = config
            .required_domains
            .iter()
            .filter(|d| !covered_d.contains(d))
            .copied()
            .collect();
        let missing_targets: Vec<_> = config
            .required_targets
            .iter()
            .filter(|t| !covered_t.contains(t))
            .copied()
            .collect();

        if !missing_domains.is_empty() || !missing_targets.is_empty() {
            return GateVerdict::Incomplete {
                missing_domains,
                missing_targets,
            };
        }

        // Check gate thresholds.
        let mut reasons = Vec::new();

        let open_critical = self.open_count_by_severity(MismatchSeverity::Critical);
        if open_critical > config.max_open_critical {
            reasons.push(format!(
                "open critical entries: {open_critical} > {}",
                config.max_open_critical
            ));
        }

        let open_errors = self.open_count_by_severity(MismatchSeverity::Error);
        if open_errors > config.max_open_errors {
            reasons.push(format!(
                "open error entries: {open_errors} > {}",
                config.max_open_errors
            ));
        }

        let score = self.aggregate_open_score();
        if score > config.max_aggregate_score {
            reasons.push(format!(
                "aggregate score: {} > {} (millionths)",
                score, config.max_aggregate_score
            ));
        }

        // Check stale entries.
        let stale_count = self
            .entries
            .iter()
            .filter(|e| {
                e.is_open() && e.verified_epoch.as_u64() < config.min_verification_epoch.as_u64()
            })
            .count();
        if stale_count > 0 {
            reasons.push(format!(
                "stale entries (verified before epoch {}): {stale_count}",
                config.min_verification_epoch.as_u64()
            ));
        }

        if reasons.is_empty() {
            GateVerdict::Pass
        } else {
            GateVerdict::Fail { reasons }
        }
    }

    /// Produce a high-level catalog report.
    pub fn report(&self) -> CatalogReport {
        CatalogReport {
            schema_version: self.schema_version.clone(),
            epoch: self.epoch,
            total_entries: self.entries.len(),
            open_entries: self.open_count(),
            critical_count: self.count_by_severity(MismatchSeverity::Critical),
            error_count: self.count_by_severity(MismatchSeverity::Error),
            warning_count: self.count_by_severity(MismatchSeverity::Warning),
            info_count: self.count_by_severity(MismatchSeverity::Info),
            aggregate_open_score: self.aggregate_open_score(),
            domains_covered: self.covered_domains().len(),
            targets_covered: self.covered_targets().len(),
            domain_summaries: self.domain_summary(),
            target_summaries: self.target_summary(),
            catalog_hash: self.catalog_hash,
        }
    }

    /// Recompute the catalog content hash.
    fn recompute_hash(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(MISMATCH_CATALOG_SCHEMA_VERSION.as_bytes());
        hasher.update(self.epoch.as_u64().to_le_bytes());
        for entry in &self.entries {
            hasher.update(entry.content_hash().as_bytes());
        }
        self.catalog_hash = ContentHash::compute(&hasher.finalize());
    }
}

// ---------------------------------------------------------------------------
// CatalogReport
// ---------------------------------------------------------------------------

/// High-level report of catalog state for dashboards and evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogReport {
    /// Schema version.
    pub schema_version: String,
    /// Catalog epoch.
    pub epoch: SecurityEpoch,
    /// Total mismatch entries.
    pub total_entries: usize,
    /// Open (unresolved) entries.
    pub open_entries: usize,
    /// Critical severity count.
    pub critical_count: usize,
    /// Error severity count.
    pub error_count: usize,
    /// Warning severity count.
    pub warning_count: usize,
    /// Info severity count.
    pub info_count: usize,
    /// Aggregate weighted open score (millionths).
    pub aggregate_open_score: u64,
    /// Number of domains with coverage.
    pub domains_covered: usize,
    /// Number of targets with coverage.
    pub targets_covered: usize,
    /// Per-domain breakdown.
    pub domain_summaries: Vec<DomainSummary>,
    /// Per-target breakdown.
    pub target_summaries: Vec<TargetSummary>,
    /// Content hash of the catalog.
    pub catalog_hash: ContentHash,
}

// ---------------------------------------------------------------------------
// Advisory generation
// ---------------------------------------------------------------------------

/// A generated advisory document for a set of mismatches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MismatchAdvisory {
    /// Advisory identifier.
    pub advisory_id: String,
    /// Domain(s) covered.
    pub domains: BTreeSet<MismatchDomain>,
    /// Target(s) covered.
    pub targets: BTreeSet<ComparisonTarget>,
    /// Highest severity in this advisory.
    pub max_severity: MismatchSeverity,
    /// Number of entries summarized.
    pub entry_count: usize,
    /// Entry IDs included.
    pub entry_ids: Vec<String>,
    /// Summary text for operators.
    pub summary: String,
    /// Content hash of this advisory.
    pub advisory_hash: ContentHash,
}

/// Generate advisories grouped by domain from a catalog.
pub fn generate_advisories(catalog: &MismatchCatalog) -> Vec<MismatchAdvisory> {
    let mut advisories = Vec::new();
    let mut advisory_num = 0u64;

    for &domain in ALL_DOMAINS {
        let entries = catalog.entries_by_domain(domain);
        let open_entries: Vec<_> = entries.iter().filter(|e| e.is_open()).collect();
        if open_entries.is_empty() {
            continue;
        }

        advisory_num += 1;
        let max_severity = open_entries
            .iter()
            .map(|e| e.severity)
            .max()
            .unwrap_or(MismatchSeverity::Info);
        let targets: BTreeSet<_> = open_entries.iter().map(|e| e.target).collect();
        let entry_ids: Vec<_> = open_entries.iter().map(|e| e.entry_id.clone()).collect();

        let summary = format!(
            "{} open {} mismatch(es) in {} domain against {}",
            open_entries.len(),
            max_severity.as_str(),
            domain.as_str(),
            targets
                .iter()
                .map(|t| t.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );

        let mut hasher = Sha256::new();
        hasher.update(format!("advisory-{advisory_num}").as_bytes());
        hasher.update(domain.as_str().as_bytes());
        for id in &entry_ids {
            hasher.update(id.as_bytes());
        }
        let hash = ContentHash::compute(&hasher.finalize());

        advisories.push(MismatchAdvisory {
            advisory_id: format!("ADV-{:04}", advisory_num),
            domains: [domain].into_iter().collect(),
            targets,
            max_severity,
            entry_count: open_entries.len(),
            entry_ids,
            summary,
            advisory_hash: hash,
        });
    }

    advisories
}

/// Compute domain coverage ratio in fixed-point millionths.
pub fn domain_coverage(catalog: &MismatchCatalog) -> u64 {
    let covered = catalog.covered_domains().len() as u64;
    let total = ALL_DOMAINS.len() as u64;
    if total == 0 {
        return MILLIONTHS;
    }
    covered.saturating_mul(MILLIONTHS) / total
}

/// Compute resolution ratio in fixed-point millionths: resolved / total.
pub fn resolution_ratio(catalog: &MismatchCatalog) -> u64 {
    let total = catalog.len() as u64;
    if total == 0 {
        return MILLIONTHS;
    }
    let resolved = catalog.entries().iter().filter(|e| !e.is_open()).count() as u64;
    resolved.saturating_mul(MILLIONTHS) / total
}

/// Collect all unique tags across catalog entries.
pub fn all_tags(catalog: &MismatchCatalog) -> BTreeSet<String> {
    catalog
        .entries()
        .iter()
        .flat_map(|e| e.tags.iter().cloned())
        .collect()
}

/// Filter catalog entries by a predicate, returning matching entry IDs.
pub fn filter_entry_ids<F>(catalog: &MismatchCatalog, pred: F) -> Vec<String>
where
    F: Fn(&MismatchEntry) -> bool,
{
    catalog
        .entries()
        .iter()
        .filter(|e| pred(e))
        .map(|e| e.entry_id.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_epoch(n: u64) -> SecurityEpoch {
        SecurityEpoch::from_raw(n)
    }

    fn test_entry(id: &str, domain: MismatchDomain, severity: MismatchSeverity) -> MismatchEntry {
        MismatchEntry {
            entry_id: id.to_string(),
            domain,
            severity,
            target: ComparisonTarget::NodeJs,
            summary: format!("Test mismatch {id}"),
            expected_behavior: "expected".to_string(),
            actual_behavior: "actual".to_string(),
            reproduction: "test case".to_string(),
            remediation: RemediationStatus::None,
            advisory: "advisory text".to_string(),
            react_version_range: ">=18.0.0".to_string(),
            evidence_hash: ContentHash::compute(id.as_bytes()),
            detected_epoch: test_epoch(1),
            verified_epoch: test_epoch(2),
            tags: ["react", "test"].iter().map(|s| s.to_string()).collect(),
        }
    }

    fn test_entry_full(
        id: &str,
        domain: MismatchDomain,
        severity: MismatchSeverity,
        target: ComparisonTarget,
        remediation: RemediationStatus,
    ) -> MismatchEntry {
        let mut e = test_entry(id, domain, severity);
        e.target = target;
        e.remediation = remediation;
        e
    }

    #[test]
    fn test_domain_as_str() {
        assert_eq!(MismatchDomain::CompileOutput.as_str(), "compile_output");
        assert_eq!(
            MismatchDomain::ServerSideRender.as_str(),
            "server_side_render"
        );
        assert_eq!(MismatchDomain::HookSemantics.as_str(), "hook_semantics");
    }

    #[test]
    fn test_domain_display() {
        assert_eq!(format!("{}", MismatchDomain::SourceMap), "source_map");
        assert_eq!(
            format!("{}", MismatchDomain::ErrorBoundary),
            "error_boundary"
        );
    }

    #[test]
    fn test_all_domains_count() {
        assert_eq!(ALL_DOMAINS.len(), 10);
    }

    #[test]
    fn test_severity_weight() {
        assert_eq!(MismatchSeverity::Info.weight(), 100_000);
        assert_eq!(MismatchSeverity::Warning.weight(), 300_000);
        assert_eq!(MismatchSeverity::Error.weight(), 700_000);
        assert_eq!(MismatchSeverity::Critical.weight(), 1_000_000);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", MismatchSeverity::Critical), "critical");
    }

    #[test]
    fn test_remediation_is_open() {
        assert!(RemediationStatus::None.is_open());
        assert!(RemediationStatus::Workaround.is_open());
        assert!(RemediationStatus::InProgress.is_open());
        assert!(RemediationStatus::Shipped.is_open());
        assert!(!RemediationStatus::Resolved.is_open());
        assert!(!RemediationStatus::Accepted.is_open());
    }

    #[test]
    fn test_comparison_target_as_str() {
        assert_eq!(ComparisonTarget::NodeJs.as_str(), "nodejs");
        assert_eq!(ComparisonTarget::Bun.as_str(), "bun");
        assert_eq!(ComparisonTarget::Deno.as_str(), "deno");
        assert_eq!(ComparisonTarget::V8Reference.as_str(), "v8_reference");
    }

    #[test]
    fn test_empty_catalog() {
        let cat = MismatchCatalog::new(test_epoch(1));
        assert!(cat.is_empty());
        assert_eq!(cat.len(), 0);
        assert_eq!(cat.open_count(), 0);
    }

    #[test]
    fn test_add_entry() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        let e = test_entry("m1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
        assert!(cat.add_entry(e).is_ok());
        assert_eq!(cat.len(), 1);
        assert_eq!(cat.open_count(), 1);
    }

    #[test]
    fn test_duplicate_entry_rejected() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        let e1 = test_entry("m1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
        let e2 = test_entry("m1", MismatchDomain::Diagnostics, MismatchSeverity::Warning);
        cat.add_entry(e1).unwrap();
        let err = cat.add_entry(e2).unwrap_err();
        assert!(matches!(err, CatalogError::DuplicateEntry { .. }));
    }

    #[test]
    fn test_advisory_too_long() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        let mut e = test_entry("m1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
        e.advisory = "x".repeat(MAX_ADVISORY_LEN + 1);
        let err = cat.add_entry(e).unwrap_err();
        assert!(matches!(err, CatalogError::AdvisoryTooLong { .. }));
    }

    #[test]
    fn test_invalid_epoch_rejected() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        let mut e = test_entry("m1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
        e.detected_epoch = test_epoch(10);
        e.verified_epoch = test_epoch(5);
        let err = cat.add_entry(e).unwrap_err();
        assert!(matches!(err, CatalogError::InvalidEpoch { .. }));
    }

    #[test]
    fn test_remove_entry() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        let e = test_entry("m1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
        cat.add_entry(e).unwrap();
        assert_eq!(cat.len(), 1);
        let removed = cat.remove_entry("m1").unwrap();
        assert_eq!(removed.entry_id, "m1");
        assert!(cat.is_empty());
    }

    #[test]
    fn test_remove_entry_not_found() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        let err = cat.remove_entry("nonexistent").unwrap_err();
        assert!(matches!(err, CatalogError::EntryNotFound { .. }));
    }

    #[test]
    fn test_update_remediation() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        let e = test_entry("m1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
        cat.add_entry(e).unwrap();
        assert_eq!(cat.open_count(), 1);
        cat.update_remediation("m1", RemediationStatus::Resolved)
            .unwrap();
        assert_eq!(cat.open_count(), 0);
    }

    #[test]
    fn test_update_remediation_not_found() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        let err = cat
            .update_remediation("nonexistent", RemediationStatus::Resolved)
            .unwrap_err();
        assert!(matches!(err, CatalogError::EntryNotFound { .. }));
    }

    #[test]
    fn test_get_entry() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        assert!(cat.get_entry("m1").is_some());
        assert!(cat.get_entry("m2").is_none());
    }

    #[test]
    fn test_count_by_severity() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Error,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m3",
            MismatchDomain::SourceMap,
            MismatchSeverity::Warning,
        ))
        .unwrap();
        assert_eq!(cat.count_by_severity(MismatchSeverity::Error), 2);
        assert_eq!(cat.count_by_severity(MismatchSeverity::Warning), 1);
        assert_eq!(cat.count_by_severity(MismatchSeverity::Critical), 0);
    }

    #[test]
    fn test_aggregate_open_score() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
        ))
        .unwrap();
        // Error(700_000) + Warning(300_000) = 1_000_000
        assert_eq!(cat.aggregate_open_score(), 1_000_000);
    }

    #[test]
    fn test_aggregate_score_excludes_resolved() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry_full(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
        ))
        .unwrap();
        assert_eq!(cat.aggregate_open_score(), 300_000);
    }

    #[test]
    fn test_covered_domains() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m2",
            MismatchDomain::SourceMap,
            MismatchSeverity::Info,
        ))
        .unwrap();
        let covered = cat.covered_domains();
        assert_eq!(covered.len(), 2);
        assert!(covered.contains(&MismatchDomain::CompileOutput));
        assert!(covered.contains(&MismatchDomain::SourceMap));
    }

    #[test]
    fn test_covered_targets() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry_full(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::None,
        ))
        .unwrap();
        cat.add_entry(test_entry_full(
            "m2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
            ComparisonTarget::Bun,
            RemediationStatus::None,
        ))
        .unwrap();
        let targets = cat.covered_targets();
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_entries_by_domain() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m2",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m3",
            MismatchDomain::SourceMap,
            MismatchSeverity::Info,
        ))
        .unwrap();
        assert_eq!(
            cat.entries_by_domain(MismatchDomain::CompileOutput).len(),
            2
        );
        assert_eq!(cat.entries_by_domain(MismatchDomain::SourceMap).len(), 1);
    }

    #[test]
    fn test_entries_by_target() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry_full(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::None,
        ))
        .unwrap();
        cat.add_entry(test_entry_full(
            "m2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
            ComparisonTarget::Bun,
            RemediationStatus::None,
        ))
        .unwrap();
        assert_eq!(cat.entries_by_target(ComparisonTarget::NodeJs).len(), 1);
        assert_eq!(cat.entries_by_target(ComparisonTarget::Bun).len(), 1);
    }

    #[test]
    fn test_entries_by_severity() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Error,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m3",
            MismatchDomain::SourceMap,
            MismatchSeverity::Warning,
        ))
        .unwrap();
        assert_eq!(cat.entries_by_severity(MismatchSeverity::Error).len(), 2);
    }

    #[test]
    fn test_entries_by_tag() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        assert_eq!(cat.entries_by_tag("react").len(), 1);
        assert_eq!(cat.entries_by_tag("nonexistent").len(), 0);
    }

    #[test]
    fn test_domain_summary() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        cat.add_entry(test_entry_full(
            "m2",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        ))
        .unwrap();
        let summaries = cat.domain_summary();
        let co_summary = summaries
            .iter()
            .find(|s| s.domain == MismatchDomain::CompileOutput)
            .unwrap();
        assert_eq!(co_summary.total_entries, 2);
        assert_eq!(co_summary.open_entries, 1);
        assert_eq!(co_summary.resolved_entries, 1);
        assert_eq!(co_summary.aggregate_score, 700_000);
    }

    #[test]
    fn test_target_summary() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry_full(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::None,
        ))
        .unwrap();
        cat.add_entry(test_entry_full(
            "m2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
            ComparisonTarget::NodeJs,
            RemediationStatus::None,
        ))
        .unwrap();
        let summaries = cat.target_summary();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].total_entries, 2);
        assert_eq!(summaries[0].aggregate_score, 1_000_000);
    }

    #[test]
    fn test_gate_verdict_pass() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        // Add entries for all domains and required targets.
        for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
            let target = if i.is_multiple_of(2) {
                ComparisonTarget::NodeJs
            } else {
                ComparisonTarget::Bun
            };
            cat.add_entry(test_entry_full(
                &format!("m{i}"),
                domain,
                MismatchSeverity::Info,
                target,
                RemediationStatus::Resolved,
            ))
            .unwrap();
        }
        let config = CatalogConfig::default();
        let verdict = cat.evaluate(&config);
        assert!(verdict.is_pass());
    }

    #[test]
    fn test_gate_verdict_incomplete() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Info,
        ))
        .unwrap();
        let config = CatalogConfig::default();
        let verdict = cat.evaluate(&config);
        assert!(matches!(verdict, GateVerdict::Incomplete { .. }));
    }

    #[test]
    fn test_gate_verdict_fail_critical() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
            let target = if i.is_multiple_of(2) {
                ComparisonTarget::NodeJs
            } else {
                ComparisonTarget::Bun
            };
            let severity = if i == 0 {
                MismatchSeverity::Critical
            } else {
                MismatchSeverity::Info
            };
            cat.add_entry(test_entry_full(
                &format!("m{i}"),
                domain,
                severity,
                target,
                RemediationStatus::None,
            ))
            .unwrap();
        }
        let config = CatalogConfig::default();
        let verdict = cat.evaluate(&config);
        assert!(matches!(verdict, GateVerdict::Fail { .. }));
    }

    #[test]
    fn test_gate_verdict_fail_aggregate_score() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
            let target = if i.is_multiple_of(2) {
                ComparisonTarget::NodeJs
            } else {
                ComparisonTarget::Bun
            };
            cat.add_entry(test_entry_full(
                &format!("m{i}"),
                domain,
                MismatchSeverity::Error,
                target,
                RemediationStatus::None,
            ))
            .unwrap();
        }
        let config = CatalogConfig {
            max_open_errors: 100, // relax error count
            ..CatalogConfig::default()
        };
        let verdict = cat.evaluate(&config);
        assert!(matches!(verdict, GateVerdict::Fail { .. }));
    }

    #[test]
    fn test_gate_verdict_display() {
        let pass = GateVerdict::Pass;
        assert_eq!(format!("{pass}"), "PASS");

        let fail = GateVerdict::Fail {
            reasons: vec!["too many errors".to_string()],
        };
        assert!(format!("{fail}").starts_with("FAIL:"));

        let incomplete = GateVerdict::Incomplete {
            missing_domains: vec![MismatchDomain::SourceMap],
            missing_targets: vec![],
        };
        assert!(format!("{incomplete}").contains("INCOMPLETE"));
    }

    #[test]
    fn test_catalog_report() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
        ))
        .unwrap();
        let report = cat.report();
        assert_eq!(report.total_entries, 2);
        assert_eq!(report.open_entries, 2);
        assert_eq!(report.error_count, 1);
        assert_eq!(report.warning_count, 1);
        assert_eq!(report.aggregate_open_score, 1_000_000);
    }

    #[test]
    fn test_generate_advisories() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m2",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Warning,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m3",
            MismatchDomain::SourceMap,
            MismatchSeverity::Info,
        ))
        .unwrap();
        let advisories = generate_advisories(&cat);
        assert_eq!(advisories.len(), 2); // compile_output + source_map
        let co_adv = advisories
            .iter()
            .find(|a| a.domains.contains(&MismatchDomain::CompileOutput))
            .unwrap();
        assert_eq!(co_adv.entry_count, 2);
        assert_eq!(co_adv.max_severity, MismatchSeverity::Error);
    }

    #[test]
    fn test_generate_advisories_skips_resolved() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry_full(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        ))
        .unwrap();
        let advisories = generate_advisories(&cat);
        assert!(advisories.is_empty());
    }

    #[test]
    fn test_domain_coverage() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        let coverage = domain_coverage(&cat);
        // 1/10 = 100_000
        assert_eq!(coverage, 100_000);
    }

    #[test]
    fn test_domain_coverage_full() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
            cat.add_entry(test_entry(&format!("m{i}"), domain, MismatchSeverity::Info))
                .unwrap();
        }
        assert_eq!(domain_coverage(&cat), MILLIONTHS);
    }

    #[test]
    fn test_resolution_ratio_empty() {
        let cat = MismatchCatalog::new(test_epoch(1));
        assert_eq!(resolution_ratio(&cat), MILLIONTHS);
    }

    #[test]
    fn test_resolution_ratio_partial() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry_full(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
        ))
        .unwrap();
        // 1/2 = 500_000
        assert_eq!(resolution_ratio(&cat), 500_000);
    }

    #[test]
    fn test_all_tags() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        let tags = all_tags(&cat);
        assert!(tags.contains("react"));
        assert!(tags.contains("test"));
    }

    #[test]
    fn test_filter_entry_ids() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        cat.add_entry(test_entry(
            "m2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Warning,
        ))
        .unwrap();
        let errors = filter_entry_ids(&cat, |e| e.severity == MismatchSeverity::Error);
        assert_eq!(errors, vec!["m1"]);
    }

    #[test]
    fn test_content_hash_deterministic() {
        let e1 = test_entry("m1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
        let e2 = test_entry("m1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
        assert_eq!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn test_content_hash_varies() {
        let e1 = test_entry("m1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
        let e2 = test_entry("m2", MismatchDomain::CompileOutput, MismatchSeverity::Error);
        assert_ne!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn test_content_hash_changes_on_remediation_update() {
        let e1 = test_entry_full(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::None,
        );
        let e2 = test_entry_full(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        );
        assert_ne!(e1.content_hash(), e2.content_hash());
    }

    #[test]
    fn test_catalog_hash_changes_on_add() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        let h1 = cat.catalog_hash;
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        assert_ne!(cat.catalog_hash, h1);
    }

    #[test]
    fn test_catalog_hash_changes_on_remove() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        let h1 = cat.catalog_hash;
        cat.remove_entry("m1").unwrap();
        assert_ne!(cat.catalog_hash, h1);
    }

    #[test]
    fn test_serde_roundtrip_entry() {
        let e = test_entry("m1", MismatchDomain::CompileOutput, MismatchSeverity::Error);
        let json = serde_json::to_string(&e).unwrap();
        let parsed: MismatchEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(e, parsed);
    }

    #[test]
    fn test_serde_roundtrip_catalog() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        let json = serde_json::to_string(&cat).unwrap();
        let parsed: MismatchCatalog = serde_json::from_str(&json).unwrap();
        assert_eq!(cat, parsed);
    }

    #[test]
    fn test_serde_roundtrip_config() {
        let config = CatalogConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: CatalogConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_serde_roundtrip_verdict() {
        let v = GateVerdict::Fail {
            reasons: vec!["test".to_string()],
        };
        let json = serde_json::to_string(&v).unwrap();
        let parsed: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(v, parsed);
    }

    #[test]
    fn test_serde_roundtrip_report() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        let report = cat.report();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: CatalogReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
    }

    #[test]
    fn test_serde_roundtrip_advisory() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        let advisories = generate_advisories(&cat);
        let json = serde_json::to_string(&advisories[0]).unwrap();
        let parsed: MismatchAdvisory = serde_json::from_str(&json).unwrap();
        assert_eq!(advisories[0], parsed);
    }

    #[test]
    fn test_catalog_error_display() {
        let e = CatalogError::CapacityExceeded {
            current: 100,
            max: 50,
        };
        assert!(format!("{e}").contains("capacity exceeded"));

        let e2 = CatalogError::DuplicateEntry {
            entry_id: "m1".to_string(),
        };
        assert!(format!("{e2}").contains("duplicate"));
    }

    #[test]
    fn test_stale_entries_fail_gate() {
        let mut cat = MismatchCatalog::new(test_epoch(10));
        for (i, &domain) in ALL_DOMAINS.iter().enumerate() {
            let target = if i.is_multiple_of(2) {
                ComparisonTarget::NodeJs
            } else {
                ComparisonTarget::Bun
            };
            let mut e = test_entry_full(
                &format!("m{i}"),
                domain,
                MismatchSeverity::Info,
                target,
                RemediationStatus::None,
            );
            e.verified_epoch = test_epoch(3);
            e.detected_epoch = test_epoch(1);
            cat.add_entry(e).unwrap();
        }
        let config = CatalogConfig {
            min_verification_epoch: test_epoch(5),
            ..CatalogConfig::default()
        };
        let verdict = cat.evaluate(&config);
        assert!(matches!(verdict, GateVerdict::Fail { .. }));
        if let GateVerdict::Fail { reasons } = &verdict {
            assert!(reasons.iter().any(|r| r.contains("stale")));
        }
    }

    #[test]
    fn test_open_count_by_severity() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry_full(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Critical,
            ComparisonTarget::NodeJs,
            RemediationStatus::None,
        ))
        .unwrap();
        cat.add_entry(test_entry_full(
            "m2",
            MismatchDomain::Diagnostics,
            MismatchSeverity::Critical,
            ComparisonTarget::NodeJs,
            RemediationStatus::Resolved,
        ))
        .unwrap();
        assert_eq!(cat.open_count_by_severity(MismatchSeverity::Critical), 1);
    }

    #[test]
    fn test_entry_weighted_score() {
        let e = test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Critical,
        );
        assert_eq!(e.weighted_score(), 1_000_000);
    }

    #[test]
    fn test_multiple_targets_in_catalog() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        for (i, target) in [
            ComparisonTarget::NodeJs,
            ComparisonTarget::Bun,
            ComparisonTarget::Deno,
            ComparisonTarget::V8Reference,
        ]
        .iter()
        .enumerate()
        {
            cat.add_entry(test_entry_full(
                &format!("m{i}"),
                MismatchDomain::CompileOutput,
                MismatchSeverity::Info,
                *target,
                RemediationStatus::None,
            ))
            .unwrap();
        }
        assert_eq!(cat.covered_targets().len(), 4);
    }

    #[test]
    fn test_schema_constants() {
        assert!(!MISMATCH_CATALOG_SCHEMA_VERSION.is_empty());
        assert!(!MISMATCH_CATALOG_BEAD_ID.is_empty());
        assert!(!MISMATCH_CATALOG_POLICY_ID.is_empty());
        assert!(!COMPONENT.is_empty());
    }

    #[test]
    fn test_advisory_has_correct_id_format() {
        let mut cat = MismatchCatalog::new(test_epoch(1));
        cat.add_entry(test_entry(
            "m1",
            MismatchDomain::CompileOutput,
            MismatchSeverity::Error,
        ))
        .unwrap();
        let advisories = generate_advisories(&cat);
        assert!(advisories[0].advisory_id.starts_with("ADV-"));
    }

    #[test]
    fn test_domain_summary_empty_domain() {
        let cat = MismatchCatalog::new(test_epoch(1));
        let summaries = cat.domain_summary();
        assert_eq!(summaries.len(), ALL_DOMAINS.len());
        for s in &summaries {
            assert_eq!(s.total_entries, 0);
        }
    }

    #[test]
    fn test_target_summary_empty() {
        let cat = MismatchCatalog::new(test_epoch(1));
        assert!(cat.target_summary().is_empty());
    }
}
