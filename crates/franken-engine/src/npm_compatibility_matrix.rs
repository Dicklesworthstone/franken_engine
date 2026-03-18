//! npm package compatibility matrix and cohort unblocking framework.
//!
//! Defines and executes compatibility campaigns over prioritized package
//! cohorts. Each incompatibility produces a minimized repro, owner
//! assignment, and deterministic remediation tracking.
//!
//! ## Design
//!
//! - **Cohort tiers**: packages are bucketed by criticality (download count,
//!   ecosystem role, dependency fanout).
//! - **Incompatibility records**: each divergence carries a minimized repro,
//!   root-cause taxonomy, severity classification, and remediation state.
//! - **Deterministic hashing**: matrix snapshots are content-addressed for
//!   evidence-ledger integration.
//!
//! `BTreeMap`/`BTreeSet` for deterministic ordering.
//! `#![forbid(unsafe_code)]` — no unsafe anywhere.
//!
//! Plan reference: Section 10.4, bd-1lsy.5.4.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::deterministic_serde::{CanonicalValue, encode_value};
use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Component name for structured logging.
pub const COMPONENT: &str = "npm_compatibility_matrix";

/// Schema version.
pub const SCHEMA_VERSION: &str = "franken-engine.npm-compatibility-matrix.v1";

/// Bead reference.
pub const BEAD_ID: &str = "bd-1lsy.5.4";

/// Maximum packages per cohort for bounded analysis.
pub const MAX_PACKAGES_PER_COHORT: usize = 500;

/// Maximum incompatibility records per package before overflow guard.
pub const MAX_INCOMPATIBILITIES_PER_PACKAGE: usize = 100;

// ---------------------------------------------------------------------------
// Cohort tier classification
// ---------------------------------------------------------------------------

/// Tier of a package cohort by criticality.
///
/// Tier 1 packages must be unblocked before any beta milestone.
/// Tier 2 packages must be unblocked before GA.
/// Tier 3 are best-effort ecosystem expansion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CohortTier {
    /// Critical infrastructure: runtime deps, bundlers, test frameworks.
    Tier1Critical,
    /// Popular ecosystem: widely-used libraries with >1M weekly downloads.
    Tier2Popular,
    /// Long-tail: niche packages, infrequently maintained, or deprecated.
    Tier3LongTail,
}

impl CohortTier {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Tier1Critical => "tier_1_critical",
            Self::Tier2Popular => "tier_2_popular",
            Self::Tier3LongTail => "tier_3_long_tail",
        }
    }

    /// Minimum compatibility percentage required for the cohort to be
    /// considered unblocked.
    pub const fn unblock_threshold_millionths(self) -> u64 {
        match self {
            Self::Tier1Critical => 950_000, // 95%
            Self::Tier2Popular => 900_000,  // 90%
            Self::Tier3LongTail => 750_000, // 75%
        }
    }
}

impl fmt::Display for CohortTier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Package category
// ---------------------------------------------------------------------------

/// Functional category of a package within the ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageCategory {
    /// Build tooling: bundlers, transpilers, compilers.
    BuildTool,
    /// Test framework: mocha, jest, vitest, ava.
    TestFramework,
    /// HTTP/networking: express, fastify, axios, node-fetch.
    HttpNetworking,
    /// Database/ORM: prisma, sequelize, mongoose, knex.
    DatabaseOrm,
    /// CLI tooling: commander, yargs, chalk, ora.
    CliTool,
    /// Utility library: lodash, ramda, date-fns, uuid.
    UtilityLibrary,
    /// Crypto/security: bcrypt, jsonwebtoken, helmet.
    CryptoSecurity,
    /// File system: fs-extra, glob, chokidar.
    FileSystem,
    /// Stream/buffer: through2, concat-stream, readable-stream.
    StreamBuffer,
    /// Framework: next, nuxt, remix, astro.
    Framework,
    /// Other / uncategorized.
    Other,
}

impl PackageCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BuildTool => "build_tool",
            Self::TestFramework => "test_framework",
            Self::HttpNetworking => "http_networking",
            Self::DatabaseOrm => "database_orm",
            Self::CliTool => "cli_tool",
            Self::UtilityLibrary => "utility_library",
            Self::CryptoSecurity => "crypto_security",
            Self::FileSystem => "file_system",
            Self::StreamBuffer => "stream_buffer",
            Self::Framework => "framework",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for PackageCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Module system requirement
// ---------------------------------------------------------------------------

/// Module system a package requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleSystemReq {
    EsmOnly,
    CjsOnly,
    DualEsmCjs,
    Unknown,
}

impl ModuleSystemReq {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EsmOnly => "esm_only",
            Self::CjsOnly => "cjs_only",
            Self::DualEsmCjs => "dual_esm_cjs",
            Self::Unknown => "unknown",
        }
    }
}

// ---------------------------------------------------------------------------
// Package record
// ---------------------------------------------------------------------------

/// A package registered in the compatibility matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageRecord {
    /// npm package name (e.g. "express", "@types/node").
    pub name: String,
    /// Pinned version used for testing.
    pub version: String,
    /// Cohort tier classification.
    pub tier: CohortTier,
    /// Functional category.
    pub category: PackageCategory,
    /// Module system requirement.
    pub module_system: ModuleSystemReq,
    /// Estimated weekly download count (for priority ranking).
    pub weekly_downloads: u64,
    /// Dependency fanout (number of transitive deps).
    pub dependency_fanout: u32,
    /// Node API surfaces this package depends on.
    pub node_api_deps: BTreeSet<String>,
    /// Whether this package is a type-only package.
    pub types_only: bool,
}

impl PackageRecord {
    fn normalize(&mut self) {
        self.name = self.name.trim().to_string();
        self.version = self.version.trim().to_string();
        let mut normalized_deps = BTreeSet::new();
        for dep in &self.node_api_deps {
            let trimmed = dep.trim().to_string();
            if !trimmed.is_empty() {
                normalized_deps.insert(trimmed);
            }
        }
        self.node_api_deps = normalized_deps;
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "name".to_string(),
            CanonicalValue::String(self.name.clone()),
        );
        map.insert(
            "version".to_string(),
            CanonicalValue::String(self.version.clone()),
        );
        map.insert(
            "tier".to_string(),
            CanonicalValue::String(self.tier.as_str().to_string()),
        );
        map.insert(
            "category".to_string(),
            CanonicalValue::String(self.category.as_str().to_string()),
        );
        map.insert(
            "module_system".to_string(),
            CanonicalValue::String(self.module_system.as_str().to_string()),
        );
        map.insert(
            "weekly_downloads".to_string(),
            CanonicalValue::I64(self.weekly_downloads as i64),
        );
        map.insert(
            "dependency_fanout".to_string(),
            CanonicalValue::I64(i64::from(self.dependency_fanout)),
        );
        map.insert(
            "node_api_deps".to_string(),
            CanonicalValue::Array(
                self.node_api_deps
                    .iter()
                    .map(|d| CanonicalValue::String(d.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "types_only".to_string(),
            CanonicalValue::Bool(self.types_only),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Incompatibility taxonomy
// ---------------------------------------------------------------------------

/// Root cause of an incompatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompatibilityRootCause {
    /// Missing Node API surface (fs, path, crypto, etc.).
    MissingNodeApi,
    /// CJS `require()` semantics divergence.
    CjsRequireDivergence,
    /// ESM import resolution divergence.
    EsmResolutionDivergence,
    /// package.json `exports`/`imports` map handling divergence.
    ExportsMapDivergence,
    /// Native addon dependency (N-API / node-gyp).
    NativeAddon,
    /// V8-specific API usage (vm, inspector, etc.).
    V8SpecificApi,
    /// Process/env/globals divergence.
    ProcessGlobalsDivergence,
    /// Child process / worker thread semantics.
    ChildProcessDivergence,
    /// Stream/Buffer API divergence.
    StreamBufferDivergence,
    /// TypeScript-specific compilation issue.
    TypeScriptCompilation,
    /// Package-internal assumption about runtime identity.
    RuntimeIdentityCheck,
    /// Other / uncategorized root cause.
    Other,
}

impl IncompatibilityRootCause {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingNodeApi => "missing_node_api",
            Self::CjsRequireDivergence => "cjs_require_divergence",
            Self::EsmResolutionDivergence => "esm_resolution_divergence",
            Self::ExportsMapDivergence => "exports_map_divergence",
            Self::NativeAddon => "native_addon",
            Self::V8SpecificApi => "v8_specific_api",
            Self::ProcessGlobalsDivergence => "process_globals_divergence",
            Self::ChildProcessDivergence => "child_process_divergence",
            Self::StreamBufferDivergence => "stream_buffer_divergence",
            Self::TypeScriptCompilation => "typescript_compilation",
            Self::RuntimeIdentityCheck => "runtime_identity_check",
            Self::Other => "other",
        }
    }
}

impl fmt::Display for IncompatibilityRootCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Severity classification
// ---------------------------------------------------------------------------

/// Severity of an incompatibility for prioritization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncompatibilitySeverity {
    /// Package is completely unusable.
    Blocker,
    /// Major functionality broken but workarounds exist.
    Major,
    /// Minor functionality affected, polyfill/shim available.
    Minor,
    /// Cosmetic divergence, no functional impact.
    Cosmetic,
}

impl IncompatibilitySeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Blocker => "blocker",
            Self::Major => "major",
            Self::Minor => "minor",
            Self::Cosmetic => "cosmetic",
        }
    }

    /// Weight for weighted compatibility scoring (millionths).
    pub const fn weight_millionths(self) -> u64 {
        match self {
            Self::Blocker => 1_000_000,
            Self::Major => 500_000,
            Self::Minor => 100_000,
            Self::Cosmetic => 10_000,
        }
    }
}

impl fmt::Display for IncompatibilitySeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Remediation state machine
// ---------------------------------------------------------------------------

/// Remediation lifecycle state for an incompatibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationState {
    /// Just discovered, not yet triaged.
    Discovered,
    /// Triaged and root-cause assigned.
    Triaged,
    /// Fix in progress.
    InProgress,
    /// Fix landed but not yet verified against the package.
    FixLanded,
    /// Verified compatible after fix.
    Verified,
    /// Deferred / won't fix with documented reason.
    WontFix,
}

impl RemediationState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovered => "discovered",
            Self::Triaged => "triaged",
            Self::InProgress => "in_progress",
            Self::FixLanded => "fix_landed",
            Self::Verified => "verified",
            Self::WontFix => "wont_fix",
        }
    }

    /// Whether this state counts as "resolved" for compatibility scoring.
    pub const fn is_resolved(self) -> bool {
        matches!(self, Self::Verified | Self::WontFix)
    }
}

impl fmt::Display for RemediationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// Incompatibility record
// ---------------------------------------------------------------------------

/// A single incompatibility record for a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncompatibilityRecord {
    /// Unique incompatibility id within the matrix (e.g. "INC-express-001").
    pub incompatibility_id: String,
    /// Package this applies to.
    pub package_name: String,
    /// Root cause taxonomy.
    pub root_cause: IncompatibilityRootCause,
    /// Severity classification.
    pub severity: IncompatibilitySeverity,
    /// One-line description of the issue.
    pub summary: String,
    /// Minimized reproduction script/code.
    pub minimized_repro: String,
    /// Expected behavior (what Node/Bun does).
    pub expected_behavior: String,
    /// Actual behavior (what FrankenEngine does).
    pub actual_behavior: String,
    /// Remediation state.
    pub remediation_state: RemediationState,
    /// Assigned owner (agent or team).
    pub owner: String,
    /// Related bead IDs for tracking.
    pub related_beads: BTreeSet<String>,
    /// Epoch when this was discovered.
    pub discovered_epoch: u64,
    /// Epoch when remediation was last updated.
    pub last_updated_epoch: u64,
}

impl IncompatibilityRecord {
    fn normalize(&mut self) {
        self.incompatibility_id = self.incompatibility_id.trim().to_string();
        self.package_name = self.package_name.trim().to_string();
        self.summary = self.summary.trim().to_string();
        self.minimized_repro = self.minimized_repro.trim().to_string();
        self.expected_behavior = self.expected_behavior.trim().to_string();
        self.actual_behavior = self.actual_behavior.trim().to_string();
        self.owner = self.owner.trim().to_string();
        let mut normalized = BTreeSet::new();
        for bead in &self.related_beads {
            let trimmed = bead.trim().to_string();
            if !trimmed.is_empty() {
                normalized.insert(trimmed);
            }
        }
        self.related_beads = normalized;
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "incompatibility_id".to_string(),
            CanonicalValue::String(self.incompatibility_id.clone()),
        );
        map.insert(
            "package_name".to_string(),
            CanonicalValue::String(self.package_name.clone()),
        );
        map.insert(
            "root_cause".to_string(),
            CanonicalValue::String(self.root_cause.as_str().to_string()),
        );
        map.insert(
            "severity".to_string(),
            CanonicalValue::String(self.severity.as_str().to_string()),
        );
        map.insert(
            "summary".to_string(),
            CanonicalValue::String(self.summary.clone()),
        );
        map.insert(
            "minimized_repro".to_string(),
            CanonicalValue::String(self.minimized_repro.clone()),
        );
        map.insert(
            "expected_behavior".to_string(),
            CanonicalValue::String(self.expected_behavior.clone()),
        );
        map.insert(
            "actual_behavior".to_string(),
            CanonicalValue::String(self.actual_behavior.clone()),
        );
        map.insert(
            "remediation_state".to_string(),
            CanonicalValue::String(self.remediation_state.as_str().to_string()),
        );
        map.insert(
            "owner".to_string(),
            CanonicalValue::String(self.owner.clone()),
        );
        map.insert(
            "related_beads".to_string(),
            CanonicalValue::Array(
                self.related_beads
                    .iter()
                    .map(|b| CanonicalValue::String(b.clone()))
                    .collect(),
            ),
        );
        map.insert(
            "discovered_epoch".to_string(),
            CanonicalValue::I64(self.discovered_epoch as i64),
        );
        map.insert(
            "last_updated_epoch".to_string(),
            CanonicalValue::I64(self.last_updated_epoch as i64),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Test result for a package
// ---------------------------------------------------------------------------

/// Outcome of a compatibility test run for a single package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageTestOutcome {
    /// Fully compatible — all tests pass.
    Compatible,
    /// Partially compatible — some tests fail.
    PartiallyCompatible,
    /// Incompatible — cannot load or run.
    Incompatible,
    /// Skipped — not testable (native addon, etc.).
    Skipped,
    /// Not yet tested.
    Untested,
}

impl PackageTestOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Compatible => "compatible",
            Self::PartiallyCompatible => "partially_compatible",
            Self::Incompatible => "incompatible",
            Self::Skipped => "skipped",
            Self::Untested => "untested",
        }
    }

    /// Whether this outcome counts positively toward compatibility score.
    pub const fn counts_as_compatible(self) -> bool {
        matches!(self, Self::Compatible)
    }
}

impl fmt::Display for PackageTestOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Full test result for a package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageTestResult {
    pub package_name: String,
    pub version: String,
    pub outcome: PackageTestOutcome,
    pub total_tests: u32,
    pub passed_tests: u32,
    pub failed_tests: u32,
    pub skipped_tests: u32,
    /// Content hash of the test output for evidence.
    pub output_hash: Option<String>,
    /// Epoch of the test run.
    pub test_epoch: u64,
}

impl PackageTestResult {
    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "package_name".to_string(),
            CanonicalValue::String(self.package_name.clone()),
        );
        map.insert(
            "version".to_string(),
            CanonicalValue::String(self.version.clone()),
        );
        map.insert(
            "outcome".to_string(),
            CanonicalValue::String(self.outcome.as_str().to_string()),
        );
        map.insert(
            "total_tests".to_string(),
            CanonicalValue::I64(i64::from(self.total_tests)),
        );
        map.insert(
            "passed_tests".to_string(),
            CanonicalValue::I64(i64::from(self.passed_tests)),
        );
        map.insert(
            "failed_tests".to_string(),
            CanonicalValue::I64(i64::from(self.failed_tests)),
        );
        map.insert(
            "skipped_tests".to_string(),
            CanonicalValue::I64(i64::from(self.skipped_tests)),
        );
        let hash_val = match &self.output_hash {
            Some(h) => CanonicalValue::String(h.clone()),
            None => CanonicalValue::Null,
        };
        map.insert("output_hash".to_string(), hash_val);
        map.insert(
            "test_epoch".to_string(),
            CanonicalValue::I64(self.test_epoch as i64),
        );
        CanonicalValue::Map(map)
    }

    /// Pass rate in millionths (1_000_000 = 100%).
    pub fn pass_rate_millionths(&self) -> u64 {
        if self.total_tests == 0 {
            return 0;
        }
        (u64::from(self.passed_tests) * 1_000_000) / u64::from(self.total_tests)
    }
}

// ---------------------------------------------------------------------------
// Cohort summary
// ---------------------------------------------------------------------------

/// Summary statistics for a package cohort.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortSummary {
    pub tier: CohortTier,
    pub total_packages: u32,
    pub compatible_count: u32,
    pub partially_compatible_count: u32,
    pub incompatible_count: u32,
    pub skipped_count: u32,
    pub untested_count: u32,
    /// Compatibility rate in millionths.
    pub compatibility_rate_millionths: u64,
    /// Unblock threshold in millionths.
    pub unblock_threshold_millionths: u64,
    /// Whether this cohort meets its unblock threshold.
    pub unblocked: bool,
    /// Total open incompatibilities (not resolved).
    pub open_incompatibilities: u32,
    /// Blocker-severity incompatibilities.
    pub blocker_count: u32,
}

impl CohortSummary {
    /// Canonical value for deterministic hashing.
    pub fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "tier".to_string(),
            CanonicalValue::String(self.tier.as_str().to_string()),
        );
        map.insert(
            "total_packages".to_string(),
            CanonicalValue::I64(i64::from(self.total_packages)),
        );
        map.insert(
            "compatible_count".to_string(),
            CanonicalValue::I64(i64::from(self.compatible_count)),
        );
        map.insert(
            "partially_compatible_count".to_string(),
            CanonicalValue::I64(i64::from(self.partially_compatible_count)),
        );
        map.insert(
            "incompatible_count".to_string(),
            CanonicalValue::I64(i64::from(self.incompatible_count)),
        );
        map.insert(
            "skipped_count".to_string(),
            CanonicalValue::I64(i64::from(self.skipped_count)),
        );
        map.insert(
            "untested_count".to_string(),
            CanonicalValue::I64(i64::from(self.untested_count)),
        );
        map.insert(
            "compatibility_rate_millionths".to_string(),
            CanonicalValue::I64(self.compatibility_rate_millionths as i64),
        );
        map.insert(
            "unblock_threshold_millionths".to_string(),
            CanonicalValue::I64(self.unblock_threshold_millionths as i64),
        );
        map.insert(
            "unblocked".to_string(),
            CanonicalValue::Bool(self.unblocked),
        );
        map.insert(
            "open_incompatibilities".to_string(),
            CanonicalValue::I64(i64::from(self.open_incompatibilities)),
        );
        map.insert(
            "blocker_count".to_string(),
            CanonicalValue::I64(i64::from(self.blocker_count)),
        );
        CanonicalValue::Map(map)
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors from npm compatibility matrix operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NpmCompatibilityError {
    /// Duplicate package name in the matrix.
    DuplicatePackage { name: String },
    /// Duplicate incompatibility id.
    DuplicateIncompatibility { id: String },
    /// Package not found.
    PackageNotFound { name: String },
    /// Incompatibility not found.
    IncompatibilityNotFound { id: String },
    /// Cohort size overflow.
    CohortOverflow { tier: CohortTier, count: usize },
    /// Incompatibility overflow for a package.
    IncompatibilityOverflow { package: String, count: usize },
    /// Invalid state transition.
    InvalidStateTransition {
        id: String,
        from: RemediationState,
        to: RemediationState,
    },
    /// Content hash mismatch on snapshot verify.
    SnapshotHashMismatch { expected: String, actual: String },
}

impl fmt::Display for NpmCompatibilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicatePackage { name } => {
                write!(f, "duplicate package in matrix: {name}")
            }
            Self::DuplicateIncompatibility { id } => {
                write!(f, "duplicate incompatibility id: {id}")
            }
            Self::PackageNotFound { name } => {
                write!(f, "package not found: {name}")
            }
            Self::IncompatibilityNotFound { id } => {
                write!(f, "incompatibility not found: {id}")
            }
            Self::CohortOverflow { tier, count } => {
                write!(
                    f,
                    "cohort {tier} overflow: {count} > {MAX_PACKAGES_PER_COHORT}"
                )
            }
            Self::IncompatibilityOverflow { package, count } => {
                write!(
                    f,
                    "incompatibility overflow for {package}: {count} > {MAX_INCOMPATIBILITIES_PER_PACKAGE}"
                )
            }
            Self::InvalidStateTransition { id, from, to } => {
                write!(
                    f,
                    "invalid remediation state transition for {id}: {from} -> {to}"
                )
            }
            Self::SnapshotHashMismatch { expected, actual } => {
                write!(
                    f,
                    "snapshot hash mismatch: expected {expected}, got {actual}"
                )
            }
        }
    }
}

pub type NpmCompatibilityResult<T> = Result<T, Box<NpmCompatibilityError>>;

// ---------------------------------------------------------------------------
// Matrix verdict
// ---------------------------------------------------------------------------

/// Overall verdict for the compatibility matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatrixVerdict {
    /// All cohort tiers meet their unblock thresholds.
    AllCohortsUnblocked,
    /// Some cohorts meet thresholds but not all.
    PartiallyUnblocked,
    /// No cohort meets its threshold.
    Blocked,
    /// Insufficient data to determine (>50% untested).
    InsufficientData,
}

impl MatrixVerdict {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AllCohortsUnblocked => "all_cohorts_unblocked",
            Self::PartiallyUnblocked => "partially_unblocked",
            Self::Blocked => "blocked",
            Self::InsufficientData => "insufficient_data",
        }
    }
}

impl fmt::Display for MatrixVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// NpmCompatibilityMatrix
// ---------------------------------------------------------------------------

/// The core npm compatibility matrix.
///
/// Tracks packages, their test results, and incompatibility records.
/// All collections use `BTreeMap`/`BTreeSet` for deterministic ordering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NpmCompatibilityMatrix {
    /// Schema version.
    pub schema_version: String,
    /// Bead reference.
    pub bead_id: String,
    /// All registered packages keyed by name.
    pub packages: Vec<PackageRecord>,
    /// Latest test result per package.
    pub test_results: Vec<PackageTestResult>,
    /// All incompatibility records.
    pub incompatibilities: Vec<IncompatibilityRecord>,
    /// Snapshot epoch for evidence linkage.
    pub snapshot_epoch: u64,
}

impl Default for NpmCompatibilityMatrix {
    fn default() -> Self {
        Self::new()
    }
}

impl NpmCompatibilityMatrix {
    pub fn new() -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            bead_id: BEAD_ID.to_string(),
            packages: Vec::new(),
            test_results: Vec::new(),
            incompatibilities: Vec::new(),
            snapshot_epoch: 0,
        }
    }

    /// Register a package in the matrix.
    pub fn add_package(&mut self, mut record: PackageRecord) -> NpmCompatibilityResult<()> {
        record.normalize();
        if self.packages.iter().any(|p| p.name == record.name) {
            return Err(Box::new(NpmCompatibilityError::DuplicatePackage {
                name: record.name,
            }));
        }
        let tier = record.tier;
        let tier_count = self.packages.iter().filter(|p| p.tier == tier).count();
        if tier_count >= MAX_PACKAGES_PER_COHORT {
            return Err(Box::new(NpmCompatibilityError::CohortOverflow {
                tier,
                count: tier_count + 1,
            }));
        }
        self.packages.push(record);
        self.packages.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(())
    }

    /// Record a test result for a package.
    pub fn record_test_result(&mut self, result: PackageTestResult) -> NpmCompatibilityResult<()> {
        if !self.packages.iter().any(|p| p.name == result.package_name) {
            return Err(Box::new(NpmCompatibilityError::PackageNotFound {
                name: result.package_name,
            }));
        }
        // Replace existing result for this package if any.
        self.test_results
            .retain(|r| r.package_name != result.package_name);
        self.test_results.push(result);
        self.test_results
            .sort_by(|a, b| a.package_name.cmp(&b.package_name));
        Ok(())
    }

    /// Add an incompatibility record.
    pub fn add_incompatibility(
        &mut self,
        mut record: IncompatibilityRecord,
    ) -> NpmCompatibilityResult<()> {
        record.normalize();
        if self
            .incompatibilities
            .iter()
            .any(|i| i.incompatibility_id == record.incompatibility_id)
        {
            return Err(Box::new(NpmCompatibilityError::DuplicateIncompatibility {
                id: record.incompatibility_id,
            }));
        }
        let pkg_count = self
            .incompatibilities
            .iter()
            .filter(|i| i.package_name == record.package_name)
            .count();
        if pkg_count >= MAX_INCOMPATIBILITIES_PER_PACKAGE {
            return Err(Box::new(NpmCompatibilityError::IncompatibilityOverflow {
                package: record.package_name,
                count: pkg_count + 1,
            }));
        }
        self.incompatibilities.push(record);
        self.incompatibilities
            .sort_by(|a, b| a.incompatibility_id.cmp(&b.incompatibility_id));
        Ok(())
    }

    /// Transition remediation state for an incompatibility.
    pub fn transition_remediation(
        &mut self,
        incompatibility_id: &str,
        new_state: RemediationState,
        epoch: u64,
    ) -> NpmCompatibilityResult<()> {
        let record = self
            .incompatibilities
            .iter_mut()
            .find(|i| i.incompatibility_id == incompatibility_id)
            .ok_or_else(|| {
                Box::new(NpmCompatibilityError::IncompatibilityNotFound {
                    id: incompatibility_id.to_string(),
                })
            })?;
        // Validate state transition.
        let valid = matches!(
            (record.remediation_state, new_state),
            (RemediationState::Discovered, RemediationState::Triaged)
                | (RemediationState::Triaged, RemediationState::InProgress)
                | (RemediationState::Triaged, RemediationState::WontFix)
                | (RemediationState::InProgress, RemediationState::FixLanded)
                | (RemediationState::InProgress, RemediationState::WontFix)
                | (RemediationState::FixLanded, RemediationState::Verified)
                | (RemediationState::FixLanded, RemediationState::InProgress)
        );
        if !valid {
            return Err(Box::new(NpmCompatibilityError::InvalidStateTransition {
                id: incompatibility_id.to_string(),
                from: record.remediation_state,
                to: new_state,
            }));
        }
        record.remediation_state = new_state;
        record.last_updated_epoch = epoch;
        Ok(())
    }

    /// Get test result for a package.
    pub fn get_test_result(&self, package_name: &str) -> Option<&PackageTestResult> {
        self.test_results
            .iter()
            .find(|r| r.package_name == package_name)
    }

    /// Get all incompatibilities for a package.
    pub fn incompatibilities_for_package(&self, package_name: &str) -> Vec<&IncompatibilityRecord> {
        self.incompatibilities
            .iter()
            .filter(|i| i.package_name == package_name)
            .collect()
    }

    /// Get open (unresolved) incompatibilities.
    pub fn open_incompatibilities(&self) -> Vec<&IncompatibilityRecord> {
        self.incompatibilities
            .iter()
            .filter(|i| !i.remediation_state.is_resolved())
            .collect()
    }

    /// Get incompatibilities by root cause.
    pub fn incompatibilities_by_root_cause(
        &self,
        root_cause: IncompatibilityRootCause,
    ) -> Vec<&IncompatibilityRecord> {
        self.incompatibilities
            .iter()
            .filter(|i| i.root_cause == root_cause)
            .collect()
    }

    /// Compute cohort summary for a given tier.
    pub fn cohort_summary(&self, tier: CohortTier) -> CohortSummary {
        let tier_packages: Vec<&PackageRecord> =
            self.packages.iter().filter(|p| p.tier == tier).collect();
        let total = tier_packages.len() as u32;

        let mut compatible = 0u32;
        let mut partially = 0u32;
        let mut incompatible = 0u32;
        let mut skipped = 0u32;
        let mut untested = 0u32;

        for pkg in &tier_packages {
            match self.get_test_result(&pkg.name) {
                Some(r) => match r.outcome {
                    PackageTestOutcome::Compatible => compatible += 1,
                    PackageTestOutcome::PartiallyCompatible => partially += 1,
                    PackageTestOutcome::Incompatible => incompatible += 1,
                    PackageTestOutcome::Skipped => skipped += 1,
                    PackageTestOutcome::Untested => untested += 1,
                },
                None => untested += 1,
            }
        }

        let testable = total.saturating_sub(skipped);
        let rate = if testable == 0 {
            0
        } else {
            (u64::from(compatible) * 1_000_000) / u64::from(testable)
        };
        let threshold = tier.unblock_threshold_millionths();
        let unblocked = rate >= threshold;

        let open_incompat = self
            .incompatibilities
            .iter()
            .filter(|i| {
                !i.remediation_state.is_resolved()
                    && tier_packages.iter().any(|p| p.name == i.package_name)
            })
            .count() as u32;

        let blockers = self
            .incompatibilities
            .iter()
            .filter(|i| {
                i.severity == IncompatibilitySeverity::Blocker
                    && !i.remediation_state.is_resolved()
                    && tier_packages.iter().any(|p| p.name == i.package_name)
            })
            .count() as u32;

        CohortSummary {
            tier,
            total_packages: total,
            compatible_count: compatible,
            partially_compatible_count: partially,
            incompatible_count: incompatible,
            skipped_count: skipped,
            untested_count: untested,
            compatibility_rate_millionths: rate,
            unblock_threshold_millionths: threshold,
            unblocked,
            open_incompatibilities: open_incompat,
            blocker_count: blockers,
        }
    }

    /// Compute overall matrix verdict.
    pub fn verdict(&self) -> MatrixVerdict {
        let tiers = [
            CohortTier::Tier1Critical,
            CohortTier::Tier2Popular,
            CohortTier::Tier3LongTail,
        ];
        let summaries: Vec<CohortSummary> = tiers.iter().map(|t| self.cohort_summary(*t)).collect();

        // Check for insufficient data (>50% untested in any tier with packages).
        for s in &summaries {
            if s.total_packages > 0 && s.untested_count * 2 > s.total_packages {
                return MatrixVerdict::InsufficientData;
            }
        }

        let active_summaries: Vec<&CohortSummary> =
            summaries.iter().filter(|s| s.total_packages > 0).collect();
        if active_summaries.is_empty() {
            return MatrixVerdict::InsufficientData;
        }

        let all_unblocked = active_summaries.iter().all(|s| s.unblocked);
        let any_unblocked = active_summaries.iter().any(|s| s.unblocked);

        if all_unblocked {
            MatrixVerdict::AllCohortsUnblocked
        } else if any_unblocked {
            MatrixVerdict::PartiallyUnblocked
        } else {
            MatrixVerdict::Blocked
        }
    }

    /// Root-cause distribution: count of open incompatibilities by root cause.
    pub fn root_cause_distribution(&self) -> BTreeMap<IncompatibilityRootCause, u32> {
        let mut dist = BTreeMap::new();
        for inc in &self.incompatibilities {
            if !inc.remediation_state.is_resolved() {
                *dist.entry(inc.root_cause).or_insert(0) += 1;
            }
        }
        dist
    }

    /// Top blockers: packages sorted by severity-weighted incompatibility count.
    pub fn top_blockers(&self, limit: usize) -> Vec<(String, u64)> {
        let mut scores: BTreeMap<String, u64> = BTreeMap::new();
        for inc in &self.incompatibilities {
            if !inc.remediation_state.is_resolved() {
                *scores.entry(inc.package_name.clone()).or_insert(0) +=
                    inc.severity.weight_millionths();
            }
        }
        let mut sorted: Vec<(String, u64)> = scores.into_iter().collect();
        sorted.sort_by_key(|entry| (std::cmp::Reverse(entry.1), entry.0.clone()));
        sorted.truncate(limit);
        sorted
    }

    /// Normalize all records and compute content hash.
    pub fn normalize_and_hash(&mut self) -> ContentHash {
        for pkg in &mut self.packages {
            pkg.normalize();
        }
        self.packages.sort_by(|a, b| a.name.cmp(&b.name));

        for inc in &mut self.incompatibilities {
            inc.normalize();
        }
        self.incompatibilities
            .sort_by(|a, b| a.incompatibility_id.cmp(&b.incompatibility_id));

        self.test_results
            .sort_by(|a, b| a.package_name.cmp(&b.package_name));

        let canonical = self.canonical_value();
        let encoded = encode_value(&canonical);
        ContentHash::compute(&encoded)
    }

    fn canonical_value(&self) -> CanonicalValue {
        let mut map = BTreeMap::new();
        map.insert(
            "schema_version".to_string(),
            CanonicalValue::String(self.schema_version.clone()),
        );
        map.insert(
            "bead_id".to_string(),
            CanonicalValue::String(self.bead_id.clone()),
        );
        map.insert(
            "packages".to_string(),
            CanonicalValue::Array(self.packages.iter().map(|p| p.canonical_value()).collect()),
        );
        map.insert(
            "test_results".to_string(),
            CanonicalValue::Array(
                self.test_results
                    .iter()
                    .map(|r| r.canonical_value())
                    .collect(),
            ),
        );
        map.insert(
            "incompatibilities".to_string(),
            CanonicalValue::Array(
                self.incompatibilities
                    .iter()
                    .map(|i| i.canonical_value())
                    .collect(),
            ),
        );
        map.insert(
            "snapshot_epoch".to_string(),
            CanonicalValue::I64(self.snapshot_epoch as i64),
        );
        CanonicalValue::Map(map)
    }

    /// Packages in a specific tier.
    pub fn packages_in_tier(&self, tier: CohortTier) -> Vec<&PackageRecord> {
        self.packages.iter().filter(|p| p.tier == tier).collect()
    }

    /// Packages sorted by weekly downloads (descending).
    pub fn packages_by_downloads(&self) -> Vec<&PackageRecord> {
        let mut sorted: Vec<&PackageRecord> = self.packages.iter().collect();
        sorted.sort_by_key(|p| std::cmp::Reverse(p.weekly_downloads));
        sorted
    }

    /// Total package count.
    pub fn total_packages(&self) -> usize {
        self.packages.len()
    }

    /// Total incompatibility count.
    pub fn total_incompatibilities(&self) -> usize {
        self.incompatibilities.len()
    }

    /// Packages requiring a specific Node API surface.
    pub fn packages_requiring_api(&self, api: &str) -> Vec<&PackageRecord> {
        self.packages
            .iter()
            .filter(|p| p.node_api_deps.contains(api))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Seed cohort builder
// ---------------------------------------------------------------------------

/// Builder for the default Tier 1 critical package cohort.
///
/// Provides a curated list of packages that are critical infrastructure
/// for the Node.js ecosystem.
pub fn seed_tier1_critical_packages() -> Vec<PackageRecord> {
    let packages = [
        (
            "express",
            "4.21.0",
            PackageCategory::HttpNetworking,
            ModuleSystemReq::CjsOnly,
            30_000_000,
            30,
            &["http", "path", "fs", "stream", "events"][..],
        ),
        (
            "typescript",
            "5.6.3",
            PackageCategory::BuildTool,
            ModuleSystemReq::CjsOnly,
            50_000_000,
            0,
            &["fs", "path", "os"][..],
        ),
        (
            "lodash",
            "4.17.21",
            PackageCategory::UtilityLibrary,
            ModuleSystemReq::CjsOnly,
            50_000_000,
            0,
            &[][..],
        ),
        (
            "axios",
            "1.7.7",
            PackageCategory::HttpNetworking,
            ModuleSystemReq::DualEsmCjs,
            45_000_000,
            8,
            &["http", "https", "stream", "url", "zlib"][..],
        ),
        (
            "chalk",
            "5.3.0",
            PackageCategory::CliTool,
            ModuleSystemReq::EsmOnly,
            25_000_000,
            0,
            &[][..],
        ),
        (
            "uuid",
            "10.0.0",
            PackageCategory::UtilityLibrary,
            ModuleSystemReq::DualEsmCjs,
            20_000_000,
            0,
            &["crypto"][..],
        ),
        (
            "commander",
            "12.1.0",
            PackageCategory::CliTool,
            ModuleSystemReq::DualEsmCjs,
            15_000_000,
            2,
            &["process", "events"][..],
        ),
        (
            "dotenv",
            "16.4.5",
            PackageCategory::UtilityLibrary,
            ModuleSystemReq::CjsOnly,
            25_000_000,
            0,
            &["fs", "path", "os", "crypto"][..],
        ),
        (
            "zod",
            "3.23.8",
            PackageCategory::UtilityLibrary,
            ModuleSystemReq::DualEsmCjs,
            12_000_000,
            0,
            &[][..],
        ),
        (
            "date-fns",
            "4.1.0",
            PackageCategory::UtilityLibrary,
            ModuleSystemReq::EsmOnly,
            15_000_000,
            0,
            &[][..],
        ),
    ];

    packages
        .into_iter()
        .map(
            |(name, version, category, module_system, downloads, fanout, apis)| PackageRecord {
                name: name.to_string(),
                version: version.to_string(),
                tier: CohortTier::Tier1Critical,
                category,
                module_system,
                weekly_downloads: downloads,
                dependency_fanout: fanout,
                node_api_deps: apis.iter().map(|s| (*s).to_string()).collect(),
                types_only: false,
            },
        )
        .collect()
}

/// Builder for the default Tier 2 popular package cohort.
pub fn seed_tier2_popular_packages() -> Vec<PackageRecord> {
    let packages = [
        (
            "fastify",
            "5.0.0",
            PackageCategory::HttpNetworking,
            ModuleSystemReq::DualEsmCjs,
            2_500_000,
            45,
            &["http", "https", "stream", "events"][..],
        ),
        (
            "vitest",
            "2.1.0",
            PackageCategory::TestFramework,
            ModuleSystemReq::EsmOnly,
            5_000_000,
            60,
            &["fs", "path", "process", "worker_threads"][..],
        ),
        (
            "prisma",
            "5.20.0",
            PackageCategory::DatabaseOrm,
            ModuleSystemReq::CjsOnly,
            3_000_000,
            15,
            &["fs", "path", "child_process", "crypto"][..],
        ),
        (
            "glob",
            "11.0.0",
            PackageCategory::FileSystem,
            ModuleSystemReq::DualEsmCjs,
            8_000_000,
            3,
            &["fs", "path"][..],
        ),
        (
            "ora",
            "8.1.0",
            PackageCategory::CliTool,
            ModuleSystemReq::EsmOnly,
            4_000_000,
            5,
            &["process"][..],
        ),
        (
            "jsonwebtoken",
            "9.0.2",
            PackageCategory::CryptoSecurity,
            ModuleSystemReq::CjsOnly,
            10_000_000,
            4,
            &["crypto", "buffer"][..],
        ),
        (
            "ws",
            "8.18.0",
            PackageCategory::HttpNetworking,
            ModuleSystemReq::CjsOnly,
            12_000_000,
            0,
            &["http", "https", "net", "tls", "stream", "events", "crypto"][..],
        ),
        (
            "yargs",
            "17.7.2",
            PackageCategory::CliTool,
            ModuleSystemReq::CjsOnly,
            8_000_000,
            10,
            &["path", "process"][..],
        ),
        (
            "chokidar",
            "4.0.0",
            PackageCategory::FileSystem,
            ModuleSystemReq::EsmOnly,
            6_000_000,
            2,
            &["fs", "path", "events"][..],
        ),
        (
            "pino",
            "9.4.0",
            PackageCategory::UtilityLibrary,
            ModuleSystemReq::DualEsmCjs,
            4_000_000,
            8,
            &["os", "stream", "worker_threads"][..],
        ),
    ];

    packages
        .into_iter()
        .map(
            |(name, version, category, module_system, downloads, fanout, apis)| PackageRecord {
                name: name.to_string(),
                version: version.to_string(),
                tier: CohortTier::Tier2Popular,
                category,
                module_system,
                weekly_downloads: downloads,
                dependency_fanout: fanout,
                node_api_deps: apis.iter().map(|s| (*s).to_string()).collect(),
                types_only: false,
            },
        )
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_package(name: &str, tier: CohortTier) -> PackageRecord {
        PackageRecord {
            name: name.to_string(),
            version: "1.0.0".to_string(),
            tier,
            category: PackageCategory::UtilityLibrary,
            module_system: ModuleSystemReq::DualEsmCjs,
            weekly_downloads: 1_000_000,
            dependency_fanout: 5,
            node_api_deps: BTreeSet::new(),
            types_only: false,
        }
    }

    fn sample_test_result(
        name: &str,
        outcome: PackageTestOutcome,
        total: u32,
        passed: u32,
    ) -> PackageTestResult {
        PackageTestResult {
            package_name: name.to_string(),
            version: "1.0.0".to_string(),
            outcome,
            total_tests: total,
            passed_tests: passed,
            failed_tests: total.saturating_sub(passed),
            skipped_tests: 0,
            output_hash: None,
            test_epoch: 1,
        }
    }

    fn sample_incompatibility(
        id: &str,
        package: &str,
        severity: IncompatibilitySeverity,
    ) -> IncompatibilityRecord {
        IncompatibilityRecord {
            incompatibility_id: id.to_string(),
            package_name: package.to_string(),
            root_cause: IncompatibilityRootCause::MissingNodeApi,
            severity,
            summary: format!("issue in {package}"),
            minimized_repro: "require('missing')".to_string(),
            expected_behavior: "works".to_string(),
            actual_behavior: "throws".to_string(),
            remediation_state: RemediationState::Discovered,
            owner: String::new(),
            related_beads: BTreeSet::new(),
            discovered_epoch: 1,
            last_updated_epoch: 1,
        }
    }

    #[test]
    fn new_matrix_is_empty() {
        let m = NpmCompatibilityMatrix::new();
        assert_eq!(m.total_packages(), 0);
        assert_eq!(m.total_incompatibilities(), 0);
        assert_eq!(m.schema_version, SCHEMA_VERSION);
        assert_eq!(m.bead_id, BEAD_ID);
    }

    #[test]
    fn add_package_and_retrieve() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("lodash", CohortTier::Tier1Critical))
            .unwrap();
        assert_eq!(m.total_packages(), 1);
        assert_eq!(m.packages_in_tier(CohortTier::Tier1Critical).len(), 1);
        assert_eq!(m.packages_in_tier(CohortTier::Tier2Popular).len(), 0);
    }

    #[test]
    fn duplicate_package_rejected() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("lodash", CohortTier::Tier1Critical))
            .unwrap();
        let err = m
            .add_package(sample_package("lodash", CohortTier::Tier1Critical))
            .unwrap_err();
        assert!(matches!(
            *err,
            NpmCompatibilityError::DuplicatePackage { .. }
        ));
    }

    #[test]
    fn test_result_for_unknown_package_fails() {
        let mut m = NpmCompatibilityMatrix::new();
        let result = m.record_test_result(sample_test_result(
            "nonexistent",
            PackageTestOutcome::Compatible,
            10,
            10,
        ));
        assert!(result.is_err());
    }

    #[test]
    fn record_and_retrieve_test_result() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("lodash", CohortTier::Tier1Critical))
            .unwrap();
        m.record_test_result(sample_test_result(
            "lodash",
            PackageTestOutcome::Compatible,
            100,
            100,
        ))
        .unwrap();
        let result = m.get_test_result("lodash").unwrap();
        assert_eq!(result.outcome, PackageTestOutcome::Compatible);
        assert_eq!(result.pass_rate_millionths(), 1_000_000);
    }

    #[test]
    fn test_result_replacement() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("lodash", CohortTier::Tier1Critical))
            .unwrap();
        m.record_test_result(sample_test_result(
            "lodash",
            PackageTestOutcome::Incompatible,
            10,
            0,
        ))
        .unwrap();
        m.record_test_result(sample_test_result(
            "lodash",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        let result = m.get_test_result("lodash").unwrap();
        assert_eq!(result.outcome, PackageTestOutcome::Compatible);
    }

    #[test]
    fn pass_rate_zero_total() {
        let result = sample_test_result("x", PackageTestOutcome::Skipped, 0, 0);
        assert_eq!(result.pass_rate_millionths(), 0);
    }

    #[test]
    fn add_and_retrieve_incompatibility() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("express", CohortTier::Tier1Critical))
            .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-express-001",
            "express",
            IncompatibilitySeverity::Blocker,
        ))
        .unwrap();
        assert_eq!(m.total_incompatibilities(), 1);
        assert_eq!(m.incompatibilities_for_package("express").len(), 1);
        assert_eq!(m.open_incompatibilities().len(), 1);
    }

    #[test]
    fn duplicate_incompatibility_rejected() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        let err = m
            .add_incompatibility(sample_incompatibility(
                "INC-001",
                "foo",
                IncompatibilitySeverity::Minor,
            ))
            .unwrap_err();
        assert!(matches!(
            *err,
            NpmCompatibilityError::DuplicateIncompatibility { .. }
        ));
    }

    #[test]
    fn remediation_state_transitions() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Blocker,
        ))
        .unwrap();
        m.transition_remediation("INC-001", RemediationState::Triaged, 2)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::InProgress, 3)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::FixLanded, 4)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::Verified, 5)
            .unwrap();
        assert!(m.open_incompatibilities().is_empty());
    }

    #[test]
    fn invalid_remediation_transition_rejected() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        let err = m
            .transition_remediation("INC-001", RemediationState::Verified, 2)
            .unwrap_err();
        assert!(matches!(
            *err,
            NpmCompatibilityError::InvalidStateTransition { .. }
        ));
    }

    #[test]
    fn cohort_summary_computation() {
        let mut m = NpmCompatibilityMatrix::new();
        for i in 0..10 {
            m.add_package(sample_package(
                &format!("pkg-{i}"),
                CohortTier::Tier1Critical,
            ))
            .unwrap();
        }
        // 8 compatible, 1 incompatible, 1 untested
        for i in 0..8 {
            m.record_test_result(sample_test_result(
                &format!("pkg-{i}"),
                PackageTestOutcome::Compatible,
                10,
                10,
            ))
            .unwrap();
        }
        m.record_test_result(sample_test_result(
            "pkg-8",
            PackageTestOutcome::Incompatible,
            10,
            0,
        ))
        .unwrap();

        let summary = m.cohort_summary(CohortTier::Tier1Critical);
        assert_eq!(summary.total_packages, 10);
        assert_eq!(summary.compatible_count, 8);
        assert_eq!(summary.incompatible_count, 1);
        assert_eq!(summary.untested_count, 1);
        // 8/10 = 800_000 millionths
        assert_eq!(summary.compatibility_rate_millionths, 800_000);
        assert!(!summary.unblocked); // threshold is 950_000
    }

    #[test]
    fn verdict_insufficient_data() {
        let mut m = NpmCompatibilityMatrix::new();
        for i in 0..10 {
            m.add_package(sample_package(
                &format!("pkg-{i}"),
                CohortTier::Tier1Critical,
            ))
            .unwrap();
        }
        // Only 2 tested = 80% untested > 50%
        m.record_test_result(sample_test_result(
            "pkg-0",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        m.record_test_result(sample_test_result(
            "pkg-1",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        assert_eq!(m.verdict(), MatrixVerdict::InsufficientData);
    }

    #[test]
    fn verdict_all_unblocked() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        m.record_test_result(sample_test_result(
            "a",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        m.add_package(sample_package("b", CohortTier::Tier2Popular))
            .unwrap();
        m.record_test_result(sample_test_result(
            "b",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        assert_eq!(m.verdict(), MatrixVerdict::AllCohortsUnblocked);
    }

    #[test]
    fn verdict_blocked() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        m.record_test_result(sample_test_result(
            "a",
            PackageTestOutcome::Incompatible,
            10,
            0,
        ))
        .unwrap();
        assert_eq!(m.verdict(), MatrixVerdict::Blocked);
    }

    #[test]
    fn root_cause_distribution() {
        let mut m = NpmCompatibilityMatrix::new();
        let mut inc1 = sample_incompatibility("INC-001", "a", IncompatibilitySeverity::Blocker);
        inc1.root_cause = IncompatibilityRootCause::MissingNodeApi;
        m.add_incompatibility(inc1).unwrap();

        let mut inc2 = sample_incompatibility("INC-002", "b", IncompatibilitySeverity::Major);
        inc2.root_cause = IncompatibilityRootCause::MissingNodeApi;
        m.add_incompatibility(inc2).unwrap();

        let mut inc3 = sample_incompatibility("INC-003", "c", IncompatibilitySeverity::Minor);
        inc3.root_cause = IncompatibilityRootCause::CjsRequireDivergence;
        m.add_incompatibility(inc3).unwrap();

        let dist = m.root_cause_distribution();
        assert_eq!(dist[&IncompatibilityRootCause::MissingNodeApi], 2);
        assert_eq!(dist[&IncompatibilityRootCause::CjsRequireDivergence], 1);
    }

    #[test]
    fn top_blockers_ranking() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "a",
            IncompatibilitySeverity::Blocker,
        ))
        .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-002",
            "a",
            IncompatibilitySeverity::Major,
        ))
        .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-003",
            "b",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();

        let top = m.top_blockers(10);
        assert_eq!(top[0].0, "a");
        assert_eq!(top[1].0, "b");
    }

    #[test]
    fn normalize_and_hash_deterministic() {
        let mut m1 = NpmCompatibilityMatrix::new();
        m1.add_package(sample_package("b", CohortTier::Tier1Critical))
            .unwrap();
        m1.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();

        let mut m2 = NpmCompatibilityMatrix::new();
        m2.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        m2.add_package(sample_package("b", CohortTier::Tier1Critical))
            .unwrap();

        let h1 = m1.normalize_and_hash();
        let h2 = m2.normalize_and_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn seed_tier1_packages_valid() {
        let packages = seed_tier1_critical_packages();
        assert!(!packages.is_empty());
        for pkg in &packages {
            assert_eq!(pkg.tier, CohortTier::Tier1Critical);
            assert!(!pkg.name.is_empty());
            assert!(!pkg.version.is_empty());
        }
    }

    #[test]
    fn seed_tier2_packages_valid() {
        let packages = seed_tier2_popular_packages();
        assert!(!packages.is_empty());
        for pkg in &packages {
            assert_eq!(pkg.tier, CohortTier::Tier2Popular);
            assert!(!pkg.name.is_empty());
            assert!(!pkg.version.is_empty());
        }
    }

    #[test]
    fn seed_packages_unique_names() {
        let t1 = seed_tier1_critical_packages();
        let t2 = seed_tier2_popular_packages();
        let mut names = BTreeSet::new();
        for pkg in t1.iter().chain(t2.iter()) {
            assert!(names.insert(&pkg.name), "duplicate: {}", pkg.name);
        }
    }

    #[test]
    fn packages_by_downloads_sorted_descending() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(PackageRecord {
            weekly_downloads: 100,
            ..sample_package("low", CohortTier::Tier1Critical)
        })
        .unwrap();
        m.add_package(PackageRecord {
            weekly_downloads: 10_000,
            ..sample_package("high", CohortTier::Tier1Critical)
        })
        .unwrap();
        let sorted = m.packages_by_downloads();
        assert_eq!(sorted[0].name, "high");
        assert_eq!(sorted[1].name, "low");
    }

    #[test]
    fn packages_requiring_api() {
        let mut m = NpmCompatibilityMatrix::new();
        let mut pkg1 = sample_package("a", CohortTier::Tier1Critical);
        pkg1.node_api_deps.insert("fs".to_string());
        pkg1.node_api_deps.insert("path".to_string());
        m.add_package(pkg1).unwrap();

        let mut pkg2 = sample_package("b", CohortTier::Tier1Critical);
        pkg2.node_api_deps.insert("crypto".to_string());
        m.add_package(pkg2).unwrap();

        assert_eq!(m.packages_requiring_api("fs").len(), 1);
        assert_eq!(m.packages_requiring_api("crypto").len(), 1);
        assert_eq!(m.packages_requiring_api("http").len(), 0);
    }

    #[test]
    fn wont_fix_counts_as_resolved() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        m.transition_remediation("INC-001", RemediationState::Triaged, 2)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::WontFix, 3)
            .unwrap();
        assert!(m.open_incompatibilities().is_empty());
    }

    #[test]
    fn fix_landed_to_in_progress_regression() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Major,
        ))
        .unwrap();
        m.transition_remediation("INC-001", RemediationState::Triaged, 2)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::InProgress, 3)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::FixLanded, 4)
            .unwrap();
        // Regression: go back to in-progress
        m.transition_remediation("INC-001", RemediationState::InProgress, 5)
            .unwrap();
        assert_eq!(m.open_incompatibilities().len(), 1);
    }

    #[test]
    fn cohort_threshold_values() {
        assert_eq!(
            CohortTier::Tier1Critical.unblock_threshold_millionths(),
            950_000
        );
        assert_eq!(
            CohortTier::Tier2Popular.unblock_threshold_millionths(),
            900_000
        );
        assert_eq!(
            CohortTier::Tier3LongTail.unblock_threshold_millionths(),
            750_000
        );
    }

    #[test]
    fn severity_weights_ordered() {
        assert!(
            IncompatibilitySeverity::Blocker.weight_millionths()
                > IncompatibilitySeverity::Major.weight_millionths()
        );
        assert!(
            IncompatibilitySeverity::Major.weight_millionths()
                > IncompatibilitySeverity::Minor.weight_millionths()
        );
        assert!(
            IncompatibilitySeverity::Minor.weight_millionths()
                > IncompatibilitySeverity::Cosmetic.weight_millionths()
        );
    }

    #[test]
    fn serde_round_trip_matrix() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("express", CohortTier::Tier1Critical))
            .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "express",
            IncompatibilitySeverity::Blocker,
        ))
        .unwrap();
        m.record_test_result(sample_test_result(
            "express",
            PackageTestOutcome::Incompatible,
            50,
            10,
        ))
        .unwrap();

        let json = serde_json::to_string(&m).unwrap();
        let deserialized: NpmCompatibilityMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m, deserialized);
    }

    #[test]
    fn serde_round_trip_all_enums() {
        let tiers = [
            CohortTier::Tier1Critical,
            CohortTier::Tier2Popular,
            CohortTier::Tier3LongTail,
        ];
        for tier in tiers {
            let json = serde_json::to_string(&tier).unwrap();
            let back: CohortTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, back);
        }

        let categories = [
            PackageCategory::BuildTool,
            PackageCategory::TestFramework,
            PackageCategory::HttpNetworking,
            PackageCategory::DatabaseOrm,
            PackageCategory::CliTool,
            PackageCategory::UtilityLibrary,
            PackageCategory::CryptoSecurity,
            PackageCategory::FileSystem,
            PackageCategory::StreamBuffer,
            PackageCategory::Framework,
            PackageCategory::Other,
        ];
        for cat in categories {
            let json = serde_json::to_string(&cat).unwrap();
            let back: PackageCategory = serde_json::from_str(&json).unwrap();
            assert_eq!(cat, back);
        }

        let severities = [
            IncompatibilitySeverity::Blocker,
            IncompatibilitySeverity::Major,
            IncompatibilitySeverity::Minor,
            IncompatibilitySeverity::Cosmetic,
        ];
        for sev in severities {
            let json = serde_json::to_string(&sev).unwrap();
            let back: IncompatibilitySeverity = serde_json::from_str(&json).unwrap();
            assert_eq!(sev, back);
        }
    }

    #[test]
    fn display_impls_match_as_str() {
        assert_eq!(format!("{}", CohortTier::Tier1Critical), "tier_1_critical");
        assert_eq!(format!("{}", PackageCategory::BuildTool), "build_tool");
        assert_eq!(format!("{}", IncompatibilitySeverity::Blocker), "blocker");
        assert_eq!(
            format!("{}", IncompatibilityRootCause::MissingNodeApi),
            "missing_node_api"
        );
        assert_eq!(format!("{}", RemediationState::InProgress), "in_progress");
        assert_eq!(format!("{}", PackageTestOutcome::Compatible), "compatible");
        assert_eq!(format!("{}", MatrixVerdict::Blocked), "blocked");
    }

    #[test]
    fn default_matrix_equals_new() {
        let d = NpmCompatibilityMatrix::default();
        let n = NpmCompatibilityMatrix::new();
        assert_eq!(d, n);
    }

    #[test]
    fn empty_matrix_verdict_insufficient() {
        let m = NpmCompatibilityMatrix::new();
        assert_eq!(m.verdict(), MatrixVerdict::InsufficientData);
    }

    #[test]
    fn nonexistent_incompatibility_transition_fails() {
        let mut m = NpmCompatibilityMatrix::new();
        let err = m
            .transition_remediation("INC-999", RemediationState::Triaged, 1)
            .unwrap_err();
        assert!(matches!(
            *err,
            NpmCompatibilityError::IncompatibilityNotFound { .. }
        ));
    }

    #[test]
    fn skipped_packages_excluded_from_rate() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        m.add_package(sample_package("b", CohortTier::Tier1Critical))
            .unwrap();

        m.record_test_result(sample_test_result(
            "a",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        m.record_test_result(sample_test_result("b", PackageTestOutcome::Skipped, 0, 0))
            .unwrap();

        let summary = m.cohort_summary(CohortTier::Tier1Critical);
        // 1 compatible / 1 testable = 100%
        assert_eq!(summary.compatibility_rate_millionths, 1_000_000);
    }

    // -----------------------------------------------------------------------
    // Deep enrichment tests (PearlTower 2026-03-18)
    // -----------------------------------------------------------------------

    #[test]
    fn verdict_partially_unblocked() {
        let mut m = NpmCompatibilityMatrix::new();
        // Tier1: 1 compatible (100%) -> unblocked
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        m.record_test_result(sample_test_result(
            "a",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        // Tier2: 1 incompatible (0%) -> blocked
        m.add_package(sample_package("b", CohortTier::Tier2Popular))
            .unwrap();
        m.record_test_result(sample_test_result(
            "b",
            PackageTestOutcome::Incompatible,
            10,
            0,
        ))
        .unwrap();
        assert_eq!(m.verdict(), MatrixVerdict::PartiallyUnblocked);
    }

    #[test]
    fn package_normalization_trims_whitespace() {
        let mut m = NpmCompatibilityMatrix::new();
        let mut pkg = sample_package("  lodash  ", CohortTier::Tier1Critical);
        pkg.version = "  1.0.0  ".to_string();
        pkg.node_api_deps.insert("  fs  ".to_string());
        pkg.node_api_deps.insert("".to_string());
        m.add_package(pkg).unwrap();
        assert_eq!(m.packages[0].name, "lodash");
        assert_eq!(m.packages[0].version, "1.0.0");
        assert!(m.packages[0].node_api_deps.contains("fs"));
        assert!(!m.packages[0].node_api_deps.contains(""));
    }

    #[test]
    fn incompatibility_normalization_trims_whitespace() {
        let mut m = NpmCompatibilityMatrix::new();
        let mut inc =
            sample_incompatibility("  INC-001  ", "  foo  ", IncompatibilitySeverity::Minor);
        inc.summary = "  summary  ".to_string();
        inc.owner = "  agent  ".to_string();
        inc.related_beads.insert("  bd-123  ".to_string());
        inc.related_beads.insert("".to_string());
        m.add_incompatibility(inc).unwrap();
        assert_eq!(m.incompatibilities[0].incompatibility_id, "INC-001");
        assert_eq!(m.incompatibilities[0].package_name, "foo");
        assert_eq!(m.incompatibilities[0].summary, "summary");
        assert_eq!(m.incompatibilities[0].owner, "agent");
        assert!(m.incompatibilities[0].related_beads.contains("bd-123"));
        assert!(!m.incompatibilities[0].related_beads.contains(""));
    }

    #[test]
    fn types_only_package_field() {
        let mut pkg = sample_package("types-node", CohortTier::Tier1Critical);
        pkg.types_only = true;
        let json = serde_json::to_string(&pkg).unwrap();
        let back: PackageRecord = serde_json::from_str(&json).unwrap();
        assert!(back.types_only);
    }

    #[test]
    fn all_module_system_variants_serde() {
        let variants = [
            ModuleSystemReq::EsmOnly,
            ModuleSystemReq::CjsOnly,
            ModuleSystemReq::DualEsmCjs,
            ModuleSystemReq::Unknown,
        ];
        for v in variants {
            let json = serde_json::to_string(&v).unwrap();
            let back: ModuleSystemReq = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
            assert!(!v.as_str().is_empty());
        }
    }

    #[test]
    fn all_remediation_states_serde() {
        let states = [
            RemediationState::Discovered,
            RemediationState::Triaged,
            RemediationState::InProgress,
            RemediationState::FixLanded,
            RemediationState::Verified,
            RemediationState::WontFix,
        ];
        for s in states {
            let json = serde_json::to_string(&s).unwrap();
            let back: RemediationState = serde_json::from_str(&json).unwrap();
            assert_eq!(s, back);
        }
    }

    #[test]
    fn all_test_outcomes_serde_and_compat_flag() {
        let outcomes = [
            (PackageTestOutcome::Compatible, true),
            (PackageTestOutcome::PartiallyCompatible, false),
            (PackageTestOutcome::Incompatible, false),
            (PackageTestOutcome::Skipped, false),
            (PackageTestOutcome::Untested, false),
        ];
        for (outcome, expected_compat) in outcomes {
            let json = serde_json::to_string(&outcome).unwrap();
            let back: PackageTestOutcome = serde_json::from_str(&json).unwrap();
            assert_eq!(outcome, back);
            assert_eq!(outcome.counts_as_compatible(), expected_compat);
        }
    }

    #[test]
    fn all_root_causes_serde() {
        let causes = [
            IncompatibilityRootCause::MissingNodeApi,
            IncompatibilityRootCause::CjsRequireDivergence,
            IncompatibilityRootCause::EsmResolutionDivergence,
            IncompatibilityRootCause::ExportsMapDivergence,
            IncompatibilityRootCause::NativeAddon,
            IncompatibilityRootCause::V8SpecificApi,
            IncompatibilityRootCause::ProcessGlobalsDivergence,
            IncompatibilityRootCause::ChildProcessDivergence,
            IncompatibilityRootCause::StreamBufferDivergence,
            IncompatibilityRootCause::TypeScriptCompilation,
            IncompatibilityRootCause::RuntimeIdentityCheck,
            IncompatibilityRootCause::Other,
        ];
        for cause in causes {
            let json = serde_json::to_string(&cause).unwrap();
            let back: IncompatibilityRootCause = serde_json::from_str(&json).unwrap();
            assert_eq!(cause, back);
            assert!(!cause.as_str().is_empty());
        }
    }

    #[test]
    fn all_verdicts_serde_and_display() {
        let verdicts = [
            MatrixVerdict::AllCohortsUnblocked,
            MatrixVerdict::PartiallyUnblocked,
            MatrixVerdict::Blocked,
            MatrixVerdict::InsufficientData,
        ];
        for v in verdicts {
            let json = serde_json::to_string(&v).unwrap();
            let back: MatrixVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, back);
            assert_eq!(format!("{v}"), v.as_str());
        }
    }

    #[test]
    fn pass_rate_partial_fraction() {
        let result = sample_test_result("x", PackageTestOutcome::PartiallyCompatible, 3, 1);
        // 1/3 = 333_333
        assert_eq!(result.pass_rate_millionths(), 333_333);
    }

    #[test]
    fn pass_rate_half() {
        let result = sample_test_result("x", PackageTestOutcome::PartiallyCompatible, 100, 50);
        assert_eq!(result.pass_rate_millionths(), 500_000);
    }

    #[test]
    fn cohort_summary_empty_tier_zero_rate() {
        let m = NpmCompatibilityMatrix::new();
        let summary = m.cohort_summary(CohortTier::Tier3LongTail);
        assert_eq!(summary.total_packages, 0);
        assert_eq!(summary.compatibility_rate_millionths, 0);
        assert!(!summary.unblocked);
    }

    #[test]
    fn cohort_summary_all_skipped_zero_rate() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        m.add_package(sample_package("b", CohortTier::Tier1Critical))
            .unwrap();
        m.record_test_result(sample_test_result("a", PackageTestOutcome::Skipped, 0, 0))
            .unwrap();
        m.record_test_result(sample_test_result("b", PackageTestOutcome::Skipped, 0, 0))
            .unwrap();
        let summary = m.cohort_summary(CohortTier::Tier1Critical);
        assert_eq!(summary.skipped_count, 2);
        // testable = 0, so rate = 0
        assert_eq!(summary.compatibility_rate_millionths, 0);
    }

    #[test]
    fn cohort_summary_blocker_count_filters_resolved() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "a",
            IncompatibilitySeverity::Blocker,
        ))
        .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-002",
            "a",
            IncompatibilitySeverity::Blocker,
        ))
        .unwrap();
        // Resolve one
        m.transition_remediation("INC-001", RemediationState::Triaged, 2)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::WontFix, 3)
            .unwrap();
        let summary = m.cohort_summary(CohortTier::Tier1Critical);
        assert_eq!(summary.blocker_count, 1);
        assert_eq!(summary.open_incompatibilities, 1);
    }

    #[test]
    fn in_progress_to_wont_fix_transition() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        m.transition_remediation("INC-001", RemediationState::Triaged, 2)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::InProgress, 3)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::WontFix, 4)
            .unwrap();
        assert!(m.open_incompatibilities().is_empty());
    }

    #[test]
    fn discovered_to_in_progress_invalid() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        let err = m
            .transition_remediation("INC-001", RemediationState::InProgress, 2)
            .unwrap_err();
        assert!(matches!(
            *err,
            NpmCompatibilityError::InvalidStateTransition { .. }
        ));
    }

    #[test]
    fn verified_to_anything_invalid() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        m.transition_remediation("INC-001", RemediationState::Triaged, 2)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::InProgress, 3)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::FixLanded, 4)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::Verified, 5)
            .unwrap();
        // Verified is terminal — can't transition further
        let err = m
            .transition_remediation("INC-001", RemediationState::InProgress, 6)
            .unwrap_err();
        assert!(matches!(
            *err,
            NpmCompatibilityError::InvalidStateTransition { .. }
        ));
    }

    #[test]
    fn error_display_all_variants() {
        let errors: Vec<NpmCompatibilityError> = vec![
            NpmCompatibilityError::DuplicatePackage {
                name: "lodash".to_string(),
            },
            NpmCompatibilityError::DuplicateIncompatibility {
                id: "INC-001".to_string(),
            },
            NpmCompatibilityError::PackageNotFound {
                name: "missing".to_string(),
            },
            NpmCompatibilityError::IncompatibilityNotFound {
                id: "INC-999".to_string(),
            },
            NpmCompatibilityError::CohortOverflow {
                tier: CohortTier::Tier1Critical,
                count: 501,
            },
            NpmCompatibilityError::IncompatibilityOverflow {
                package: "express".to_string(),
                count: 101,
            },
            NpmCompatibilityError::InvalidStateTransition {
                id: "INC-001".to_string(),
                from: RemediationState::Discovered,
                to: RemediationState::Verified,
            },
            NpmCompatibilityError::SnapshotHashMismatch {
                expected: "abc".to_string(),
                actual: "def".to_string(),
            },
        ];
        for e in &errors {
            let msg = format!("{e}");
            assert!(!msg.is_empty(), "empty display for {e:?}");
        }
    }

    #[test]
    fn top_blockers_ignores_resolved() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "a",
            IncompatibilitySeverity::Blocker,
        ))
        .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-002",
            "b",
            IncompatibilitySeverity::Blocker,
        ))
        .unwrap();
        // Resolve the "a" blocker
        m.transition_remediation("INC-001", RemediationState::Triaged, 2)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::WontFix, 3)
            .unwrap();
        let top = m.top_blockers(10);
        assert_eq!(top.len(), 1);
        assert_eq!(top[0].0, "b");
    }

    #[test]
    fn top_blockers_respects_limit() {
        let mut m = NpmCompatibilityMatrix::new();
        for i in 0..10 {
            m.add_incompatibility(sample_incompatibility(
                &format!("INC-{i:03}"),
                &format!("pkg-{i}"),
                IncompatibilitySeverity::Minor,
            ))
            .unwrap();
        }
        let top = m.top_blockers(3);
        assert_eq!(top.len(), 3);
    }

    #[test]
    fn top_blockers_empty_matrix() {
        let m = NpmCompatibilityMatrix::new();
        let top = m.top_blockers(10);
        assert!(top.is_empty());
    }

    #[test]
    fn root_cause_distribution_excludes_resolved() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "a",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        m.transition_remediation("INC-001", RemediationState::Triaged, 2)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::WontFix, 3)
            .unwrap();
        let dist = m.root_cause_distribution();
        assert!(dist.is_empty());
    }

    #[test]
    fn seed_tier1_into_matrix() {
        let mut m = NpmCompatibilityMatrix::new();
        for pkg in seed_tier1_critical_packages() {
            m.add_package(pkg).unwrap();
        }
        assert_eq!(m.packages_in_tier(CohortTier::Tier1Critical).len(), 10);
        // All should be tier 1
        for pkg in &m.packages {
            assert_eq!(pkg.tier, CohortTier::Tier1Critical);
        }
    }

    #[test]
    fn seed_tier2_into_matrix() {
        let mut m = NpmCompatibilityMatrix::new();
        for pkg in seed_tier2_popular_packages() {
            m.add_package(pkg).unwrap();
        }
        assert_eq!(m.packages_in_tier(CohortTier::Tier2Popular).len(), 10);
    }

    #[test]
    fn seed_both_tiers_no_overlap() {
        let mut m = NpmCompatibilityMatrix::new();
        for pkg in seed_tier1_critical_packages() {
            m.add_package(pkg).unwrap();
        }
        for pkg in seed_tier2_popular_packages() {
            m.add_package(pkg).unwrap();
        }
        assert_eq!(m.total_packages(), 20);
    }

    #[test]
    fn canonical_value_package_includes_all_fields() {
        let mut pkg = sample_package("test-pkg", CohortTier::Tier2Popular);
        pkg.node_api_deps.insert("fs".to_string());
        let cv = pkg.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(map.contains_key("name"));
            assert!(map.contains_key("version"));
            assert!(map.contains_key("tier"));
            assert!(map.contains_key("category"));
            assert!(map.contains_key("module_system"));
            assert!(map.contains_key("weekly_downloads"));
            assert!(map.contains_key("dependency_fanout"));
            assert!(map.contains_key("node_api_deps"));
            assert!(map.contains_key("types_only"));
            assert_eq!(map.len(), 9);
        } else {
            panic!("expected Map canonical value");
        }
    }

    #[test]
    fn canonical_value_incompatibility_includes_all_fields() {
        let inc = sample_incompatibility("INC-001", "foo", IncompatibilitySeverity::Blocker);
        let cv = inc.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(map.contains_key("incompatibility_id"));
            assert!(map.contains_key("package_name"));
            assert!(map.contains_key("root_cause"));
            assert!(map.contains_key("severity"));
            assert!(map.contains_key("summary"));
            assert!(map.contains_key("minimized_repro"));
            assert!(map.contains_key("expected_behavior"));
            assert!(map.contains_key("actual_behavior"));
            assert!(map.contains_key("remediation_state"));
            assert!(map.contains_key("owner"));
            assert!(map.contains_key("related_beads"));
            assert!(map.contains_key("discovered_epoch"));
            assert!(map.contains_key("last_updated_epoch"));
            assert_eq!(map.len(), 13);
        } else {
            panic!("expected Map canonical value");
        }
    }

    #[test]
    fn canonical_value_test_result_null_hash() {
        let result = sample_test_result("x", PackageTestOutcome::Compatible, 10, 10);
        let cv = result.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(matches!(map["output_hash"], CanonicalValue::Null));
        } else {
            panic!("expected Map canonical value");
        }
    }

    #[test]
    fn canonical_value_test_result_with_hash() {
        let mut result = sample_test_result("x", PackageTestOutcome::Compatible, 10, 10);
        result.output_hash = Some("abc123".to_string());
        let cv = result.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(matches!(&map["output_hash"], CanonicalValue::String(s) if s == "abc123"));
        } else {
            panic!("expected Map canonical value");
        }
    }

    #[test]
    fn normalize_and_hash_idempotent() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "a",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        let h1 = m.normalize_and_hash();
        let h2 = m.normalize_and_hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn packages_sorted_after_add() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("zlib", CohortTier::Tier1Critical))
            .unwrap();
        m.add_package(sample_package("axios", CohortTier::Tier1Critical))
            .unwrap();
        m.add_package(sample_package("express", CohortTier::Tier1Critical))
            .unwrap();
        assert_eq!(m.packages[0].name, "axios");
        assert_eq!(m.packages[1].name, "express");
        assert_eq!(m.packages[2].name, "zlib");
    }

    #[test]
    fn incompatibilities_sorted_after_add() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-003",
            "c",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "a",
            IncompatibilitySeverity::Blocker,
        ))
        .unwrap();
        assert_eq!(m.incompatibilities[0].incompatibility_id, "INC-001");
        assert_eq!(m.incompatibilities[1].incompatibility_id, "INC-003");
    }

    #[test]
    fn test_results_sorted_after_record() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("z", CohortTier::Tier1Critical))
            .unwrap();
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        m.record_test_result(sample_test_result(
            "z",
            PackageTestOutcome::Compatible,
            5,
            5,
        ))
        .unwrap();
        m.record_test_result(sample_test_result(
            "a",
            PackageTestOutcome::Compatible,
            5,
            5,
        ))
        .unwrap();
        assert_eq!(m.test_results[0].package_name, "a");
        assert_eq!(m.test_results[1].package_name, "z");
    }

    #[test]
    fn incompatibilities_for_nonexistent_package_empty() {
        let m = NpmCompatibilityMatrix::new();
        assert!(m.incompatibilities_for_package("nothing").is_empty());
    }

    #[test]
    fn get_test_result_nonexistent_returns_none() {
        let m = NpmCompatibilityMatrix::new();
        assert!(m.get_test_result("nothing").is_none());
    }

    #[test]
    fn remediation_epoch_updated_on_transition() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        assert_eq!(m.incompatibilities[0].last_updated_epoch, 1);
        m.transition_remediation("INC-001", RemediationState::Triaged, 42)
            .unwrap();
        assert_eq!(m.incompatibilities[0].last_updated_epoch, 42);
    }

    #[test]
    fn remediation_is_resolved_logic() {
        assert!(!RemediationState::Discovered.is_resolved());
        assert!(!RemediationState::Triaged.is_resolved());
        assert!(!RemediationState::InProgress.is_resolved());
        assert!(!RemediationState::FixLanded.is_resolved());
        assert!(RemediationState::Verified.is_resolved());
        assert!(RemediationState::WontFix.is_resolved());
    }

    #[test]
    fn cohort_summary_canonical_value_has_all_fields() {
        let summary = CohortSummary {
            tier: CohortTier::Tier1Critical,
            total_packages: 10,
            compatible_count: 8,
            partially_compatible_count: 1,
            incompatible_count: 1,
            skipped_count: 0,
            untested_count: 0,
            compatibility_rate_millionths: 800_000,
            unblock_threshold_millionths: 950_000,
            unblocked: false,
            open_incompatibilities: 2,
            blocker_count: 1,
        };
        let cv = summary.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert_eq!(map.len(), 12);
            assert!(map.contains_key("tier"));
            assert!(map.contains_key("blocker_count"));
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn multiple_incompatibilities_same_package_filtered() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("express", CohortTier::Tier1Critical))
            .unwrap();
        for i in 0..5 {
            let mut inc = sample_incompatibility(
                &format!("INC-express-{i:03}"),
                "express",
                IncompatibilitySeverity::Minor,
            );
            inc.root_cause = if i % 2 == 0 {
                IncompatibilityRootCause::MissingNodeApi
            } else {
                IncompatibilityRootCause::CjsRequireDivergence
            };
            m.add_incompatibility(inc).unwrap();
        }
        assert_eq!(m.incompatibilities_for_package("express").len(), 5);
        assert_eq!(
            m.incompatibilities_by_root_cause(IncompatibilityRootCause::MissingNodeApi)
                .len(),
            3
        );
        assert_eq!(
            m.incompatibilities_by_root_cause(IncompatibilityRootCause::CjsRequireDivergence)
                .len(),
            2
        );
    }

    #[test]
    fn verdict_with_tier3_only() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("niche-pkg", CohortTier::Tier3LongTail))
            .unwrap();
        m.record_test_result(sample_test_result(
            "niche-pkg",
            PackageTestOutcome::Compatible,
            5,
            5,
        ))
        .unwrap();
        assert_eq!(m.verdict(), MatrixVerdict::AllCohortsUnblocked);
    }

    #[test]
    fn cohort_tier_as_str_values() {
        assert_eq!(CohortTier::Tier1Critical.as_str(), "tier_1_critical");
        assert_eq!(CohortTier::Tier2Popular.as_str(), "tier_2_popular");
        assert_eq!(CohortTier::Tier3LongTail.as_str(), "tier_3_long_tail");
    }

    #[test]
    fn package_category_as_str_exhaustive() {
        let categories = [
            (PackageCategory::BuildTool, "build_tool"),
            (PackageCategory::TestFramework, "test_framework"),
            (PackageCategory::HttpNetworking, "http_networking"),
            (PackageCategory::DatabaseOrm, "database_orm"),
            (PackageCategory::CliTool, "cli_tool"),
            (PackageCategory::UtilityLibrary, "utility_library"),
            (PackageCategory::CryptoSecurity, "crypto_security"),
            (PackageCategory::FileSystem, "file_system"),
            (PackageCategory::StreamBuffer, "stream_buffer"),
            (PackageCategory::Framework, "framework"),
            (PackageCategory::Other, "other"),
        ];
        for (cat, expected) in categories {
            assert_eq!(cat.as_str(), expected);
        }
    }

    #[test]
    fn constants_sanity() {
        assert_eq!(COMPONENT, "npm_compatibility_matrix");
        assert!(SCHEMA_VERSION.contains("npm-compatibility-matrix"));
        assert!(MAX_PACKAGES_PER_COHORT > 0);
        assert!(MAX_INCOMPATIBILITIES_PER_PACKAGE > 0);
    }

    // -----------------------------------------------------------------------
    // Additional enrichment tests (PearlTower 2026-03-18, batch 2)
    // -----------------------------------------------------------------------

    #[test]
    fn hash_changes_when_content_differs() {
        let mut m1 = NpmCompatibilityMatrix::new();
        m1.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        let h1 = m1.normalize_and_hash();

        let mut m2 = NpmCompatibilityMatrix::new();
        m2.add_package(sample_package("b", CohortTier::Tier1Critical))
            .unwrap();
        let h2 = m2.normalize_and_hash();

        assert_ne!(h1, h2, "different content must produce different hashes");
    }

    #[test]
    fn hash_changes_when_incompatibility_added() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        let h_before = m.normalize_and_hash();

        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "a",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        let h_after = m.normalize_and_hash();

        assert_ne!(h_before, h_after);
    }

    #[test]
    fn hash_changes_when_test_result_recorded() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        let h_before = m.normalize_and_hash();

        m.record_test_result(sample_test_result(
            "a",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        let h_after = m.normalize_and_hash();

        assert_ne!(h_before, h_after);
    }

    #[test]
    fn hash_changes_when_snapshot_epoch_differs() {
        let mut m1 = NpmCompatibilityMatrix::new();
        m1.snapshot_epoch = 100;
        let h1 = m1.normalize_and_hash();

        let mut m2 = NpmCompatibilityMatrix::new();
        m2.snapshot_epoch = 200;
        let h2 = m2.normalize_and_hash();

        assert_ne!(h1, h2);
    }

    #[test]
    fn serde_round_trip_full_matrix_with_all_fields() {
        let mut m = NpmCompatibilityMatrix::new();
        m.snapshot_epoch = 42;

        let mut pkg = sample_package("express", CohortTier::Tier1Critical);
        pkg.category = PackageCategory::HttpNetworking;
        pkg.module_system = ModuleSystemReq::CjsOnly;
        pkg.weekly_downloads = 30_000_000;
        pkg.dependency_fanout = 30;
        pkg.node_api_deps.insert("http".to_string());
        pkg.node_api_deps.insert("path".to_string());
        pkg.types_only = false;
        m.add_package(pkg).unwrap();

        let mut result =
            sample_test_result("express", PackageTestOutcome::PartiallyCompatible, 100, 75);
        result.output_hash = Some("sha256:abcdef".to_string());
        result.test_epoch = 99;
        m.record_test_result(result).unwrap();

        let mut inc = sample_incompatibility(
            "INC-express-001",
            "express",
            IncompatibilitySeverity::Blocker,
        );
        inc.root_cause = IncompatibilityRootCause::CjsRequireDivergence;
        inc.owner = "PearlTower".to_string();
        inc.related_beads.insert("bd-1lsy.5.4".to_string());
        inc.discovered_epoch = 10;
        inc.last_updated_epoch = 20;
        m.add_incompatibility(inc).unwrap();

        let json = serde_json::to_string_pretty(&m).unwrap();
        let back: NpmCompatibilityMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(m, back);
        assert_eq!(back.snapshot_epoch, 42);
        assert_eq!(back.packages[0].node_api_deps.len(), 2);
        assert_eq!(back.incompatibilities[0].owner, "PearlTower");
        assert!(
            back.incompatibilities[0]
                .related_beads
                .contains("bd-1lsy.5.4")
        );
    }

    #[test]
    fn serde_round_trip_cohort_summary() {
        let summary = CohortSummary {
            tier: CohortTier::Tier2Popular,
            total_packages: 50,
            compatible_count: 40,
            partially_compatible_count: 5,
            incompatible_count: 3,
            skipped_count: 1,
            untested_count: 1,
            compatibility_rate_millionths: 816_326,
            unblock_threshold_millionths: 900_000,
            unblocked: false,
            open_incompatibilities: 8,
            blocker_count: 2,
        };
        let json = serde_json::to_string(&summary).unwrap();
        let back: CohortSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(summary, back);
    }

    #[test]
    fn serde_round_trip_error_all_variants() {
        let errors = vec![
            NpmCompatibilityError::DuplicatePackage {
                name: "x".to_string(),
            },
            NpmCompatibilityError::DuplicateIncompatibility {
                id: "y".to_string(),
            },
            NpmCompatibilityError::PackageNotFound {
                name: "z".to_string(),
            },
            NpmCompatibilityError::IncompatibilityNotFound {
                id: "w".to_string(),
            },
            NpmCompatibilityError::CohortOverflow {
                tier: CohortTier::Tier3LongTail,
                count: 600,
            },
            NpmCompatibilityError::IncompatibilityOverflow {
                package: "big".to_string(),
                count: 200,
            },
            NpmCompatibilityError::InvalidStateTransition {
                id: "INC-001".to_string(),
                from: RemediationState::Discovered,
                to: RemediationState::Verified,
            },
            NpmCompatibilityError::SnapshotHashMismatch {
                expected: "aaa".to_string(),
                actual: "bbb".to_string(),
            },
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: NpmCompatibilityError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    #[test]
    fn pass_rate_all_pass() {
        let result = sample_test_result("x", PackageTestOutcome::Compatible, 1000, 1000);
        assert_eq!(result.pass_rate_millionths(), 1_000_000);
    }

    #[test]
    fn pass_rate_none_pass() {
        let result = sample_test_result("x", PackageTestOutcome::Incompatible, 50, 0);
        assert_eq!(result.pass_rate_millionths(), 0);
    }

    #[test]
    fn pass_rate_single_test_pass() {
        let result = sample_test_result("x", PackageTestOutcome::Compatible, 1, 1);
        assert_eq!(result.pass_rate_millionths(), 1_000_000);
    }

    #[test]
    fn pass_rate_single_test_fail() {
        let result = sample_test_result("x", PackageTestOutcome::Incompatible, 1, 0);
        assert_eq!(result.pass_rate_millionths(), 0);
    }

    #[test]
    fn cohort_summary_partially_compatible_counted_separately() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("a", CohortTier::Tier2Popular))
            .unwrap();
        m.add_package(sample_package("b", CohortTier::Tier2Popular))
            .unwrap();
        m.add_package(sample_package("c", CohortTier::Tier2Popular))
            .unwrap();
        m.record_test_result(sample_test_result(
            "a",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        m.record_test_result(sample_test_result(
            "b",
            PackageTestOutcome::PartiallyCompatible,
            10,
            5,
        ))
        .unwrap();
        m.record_test_result(sample_test_result(
            "c",
            PackageTestOutcome::Incompatible,
            10,
            0,
        ))
        .unwrap();

        let summary = m.cohort_summary(CohortTier::Tier2Popular);
        assert_eq!(summary.compatible_count, 1);
        assert_eq!(summary.partially_compatible_count, 1);
        assert_eq!(summary.incompatible_count, 1);
        // Only Compatible counts: 1/3 = 333_333
        assert_eq!(summary.compatibility_rate_millionths, 333_333);
        assert!(!summary.unblocked);
    }

    #[test]
    fn verdict_exactly_at_threshold_is_unblocked() {
        // Tier3LongTail threshold is 750_000 (75%).
        // 3 compatible out of 4 = 750_000 exactly.
        let mut m = NpmCompatibilityMatrix::new();
        for name in &["a", "b", "c", "d"] {
            m.add_package(sample_package(name, CohortTier::Tier3LongTail))
                .unwrap();
        }
        for name in &["a", "b", "c"] {
            m.record_test_result(sample_test_result(
                name,
                PackageTestOutcome::Compatible,
                10,
                10,
            ))
            .unwrap();
        }
        m.record_test_result(sample_test_result(
            "d",
            PackageTestOutcome::Incompatible,
            10,
            0,
        ))
        .unwrap();
        let summary = m.cohort_summary(CohortTier::Tier3LongTail);
        assert_eq!(summary.compatibility_rate_millionths, 750_000);
        assert!(summary.unblocked, "rate equal to threshold should unblock");
    }

    #[test]
    fn verdict_just_below_threshold_is_blocked() {
        // Tier1 threshold is 950_000 (95%).
        // 19 compatible + 2 incompatible out of 21 = 904_761 < 950_000.
        let mut m = NpmCompatibilityMatrix::new();
        for i in 0..21 {
            m.add_package(sample_package(
                &format!("pkg-{i:03}"),
                CohortTier::Tier1Critical,
            ))
            .unwrap();
        }
        for i in 0..19 {
            m.record_test_result(sample_test_result(
                &format!("pkg-{i:03}"),
                PackageTestOutcome::Compatible,
                10,
                10,
            ))
            .unwrap();
        }
        for i in 19..21 {
            m.record_test_result(sample_test_result(
                &format!("pkg-{i:03}"),
                PackageTestOutcome::Incompatible,
                10,
                0,
            ))
            .unwrap();
        }
        let summary = m.cohort_summary(CohortTier::Tier1Critical);
        assert!(summary.compatibility_rate_millionths < 950_000);
        assert!(!summary.unblocked);
    }

    #[test]
    fn verdict_insufficient_data_exactly_half_untested() {
        // >50% untested means insufficient. Exactly 50% is NOT insufficient.
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        m.add_package(sample_package("b", CohortTier::Tier1Critical))
            .unwrap();
        m.record_test_result(sample_test_result(
            "a",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        // b is untested: 1 untested out of 2 = 50%, which is NOT >50%
        // untested_count * 2 > total_packages => 1*2 > 2 => false
        let verdict = m.verdict();
        assert_ne!(
            verdict,
            MatrixVerdict::InsufficientData,
            "exactly 50% untested should not be insufficient"
        );
    }

    #[test]
    fn top_blockers_severity_weighted_scoring() {
        let mut m = NpmCompatibilityMatrix::new();
        // Package "minor-many" has 3 Minor incompatibilities: 3 * 100_000 = 300_000
        for i in 0..3 {
            m.add_incompatibility(sample_incompatibility(
                &format!("INC-minor-{i}"),
                "minor-many",
                IncompatibilitySeverity::Minor,
            ))
            .unwrap();
        }
        // Package "blocker-one" has 1 Blocker: 1_000_000
        m.add_incompatibility(sample_incompatibility(
            "INC-blocker-0",
            "blocker-one",
            IncompatibilitySeverity::Blocker,
        ))
        .unwrap();
        // Package "cosmetic-many" has 5 Cosmetic: 5 * 10_000 = 50_000
        for i in 0..5 {
            m.add_incompatibility(sample_incompatibility(
                &format!("INC-cosmetic-{i}"),
                "cosmetic-many",
                IncompatibilitySeverity::Cosmetic,
            ))
            .unwrap();
        }

        let top = m.top_blockers(10);
        assert_eq!(top.len(), 3);
        assert_eq!(top[0].0, "blocker-one");
        assert_eq!(top[0].1, 1_000_000);
        assert_eq!(top[1].0, "minor-many");
        assert_eq!(top[1].1, 300_000);
        assert_eq!(top[2].0, "cosmetic-many");
        assert_eq!(top[2].1, 50_000);
    }

    #[test]
    fn packages_by_downloads_empty_matrix() {
        let m = NpmCompatibilityMatrix::new();
        assert!(m.packages_by_downloads().is_empty());
    }

    #[test]
    fn packages_by_downloads_same_count_stable() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(PackageRecord {
            weekly_downloads: 5000,
            ..sample_package("alpha", CohortTier::Tier1Critical)
        })
        .unwrap();
        m.add_package(PackageRecord {
            weekly_downloads: 5000,
            ..sample_package("beta", CohortTier::Tier1Critical)
        })
        .unwrap();
        let sorted = m.packages_by_downloads();
        assert_eq!(sorted.len(), 2);
        // Both have the same download count; just verify both are present
        let names: BTreeSet<&str> = sorted.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains("alpha"));
        assert!(names.contains("beta"));
    }

    #[test]
    fn cohort_summary_cross_tier_isolation() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("t1", CohortTier::Tier1Critical))
            .unwrap();
        m.add_package(sample_package("t2", CohortTier::Tier2Popular))
            .unwrap();
        m.record_test_result(sample_test_result(
            "t1",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        m.record_test_result(sample_test_result(
            "t2",
            PackageTestOutcome::Incompatible,
            10,
            0,
        ))
        .unwrap();

        let s1 = m.cohort_summary(CohortTier::Tier1Critical);
        assert_eq!(s1.compatible_count, 1);
        assert_eq!(s1.incompatible_count, 0);

        let s2 = m.cohort_summary(CohortTier::Tier2Popular);
        assert_eq!(s2.compatible_count, 0);
        assert_eq!(s2.incompatible_count, 1);
    }

    #[test]
    fn cohort_summary_open_incompatibilities_cross_tier() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("t1-pkg", CohortTier::Tier1Critical))
            .unwrap();
        m.add_package(sample_package("t2-pkg", CohortTier::Tier2Popular))
            .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-t1",
            "t1-pkg",
            IncompatibilitySeverity::Blocker,
        ))
        .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-t2",
            "t2-pkg",
            IncompatibilitySeverity::Major,
        ))
        .unwrap();

        let s1 = m.cohort_summary(CohortTier::Tier1Critical);
        assert_eq!(s1.open_incompatibilities, 1);
        assert_eq!(s1.blocker_count, 1);

        let s2 = m.cohort_summary(CohortTier::Tier2Popular);
        assert_eq!(s2.open_incompatibilities, 1);
        assert_eq!(s2.blocker_count, 0);
    }

    #[test]
    fn wont_fix_to_anything_invalid() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        m.transition_remediation("INC-001", RemediationState::Triaged, 2)
            .unwrap();
        m.transition_remediation("INC-001", RemediationState::WontFix, 3)
            .unwrap();
        // WontFix is terminal
        let err = m
            .transition_remediation("INC-001", RemediationState::Discovered, 4)
            .unwrap_err();
        assert!(matches!(
            *err,
            NpmCompatibilityError::InvalidStateTransition { .. }
        ));
    }

    #[test]
    fn discovered_to_discovered_invalid() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        let err = m
            .transition_remediation("INC-001", RemediationState::Discovered, 2)
            .unwrap_err();
        assert!(matches!(
            *err,
            NpmCompatibilityError::InvalidStateTransition { .. }
        ));
    }

    #[test]
    fn triaged_to_discovered_invalid() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "foo",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        m.transition_remediation("INC-001", RemediationState::Triaged, 2)
            .unwrap();
        let err = m
            .transition_remediation("INC-001", RemediationState::Discovered, 3)
            .unwrap_err();
        assert!(matches!(
            *err,
            NpmCompatibilityError::InvalidStateTransition { .. }
        ));
    }

    #[test]
    fn error_display_contains_relevant_details() {
        let err = NpmCompatibilityError::CohortOverflow {
            tier: CohortTier::Tier2Popular,
            count: 501,
        };
        let msg = format!("{err}");
        assert!(msg.contains("tier_2_popular"));
        assert!(msg.contains("501"));

        let err2 = NpmCompatibilityError::InvalidStateTransition {
            id: "INC-xyz".to_string(),
            from: RemediationState::Discovered,
            to: RemediationState::Verified,
        };
        let msg2 = format!("{err2}");
        assert!(msg2.contains("INC-xyz"));
        assert!(msg2.contains("discovered"));
        assert!(msg2.contains("verified"));
    }

    #[test]
    fn seed_tier1_has_expected_packages() {
        let packages = seed_tier1_critical_packages();
        let names: BTreeSet<String> = packages.iter().map(|p| p.name.clone()).collect();
        assert!(names.contains("express"));
        assert!(names.contains("typescript"));
        assert!(names.contains("lodash"));
        assert!(names.contains("axios"));
        assert!(names.contains("chalk"));
        assert!(names.contains("uuid"));
        assert!(names.contains("commander"));
        assert!(names.contains("dotenv"));
        assert!(names.contains("zod"));
        assert!(names.contains("date-fns"));
        assert_eq!(packages.len(), 10);
    }

    #[test]
    fn seed_tier1_express_has_node_api_deps() {
        let packages = seed_tier1_critical_packages();
        let express = packages.iter().find(|p| p.name == "express").unwrap();
        assert!(express.node_api_deps.contains("http"));
        assert!(express.node_api_deps.contains("path"));
        assert!(express.node_api_deps.contains("fs"));
        assert!(express.node_api_deps.contains("stream"));
        assert!(express.node_api_deps.contains("events"));
        assert_eq!(express.category, PackageCategory::HttpNetworking);
        assert_eq!(express.module_system, ModuleSystemReq::CjsOnly);
    }

    #[test]
    fn seed_tier2_has_expected_packages() {
        let packages = seed_tier2_popular_packages();
        let names: BTreeSet<String> = packages.iter().map(|p| p.name.clone()).collect();
        assert!(names.contains("fastify"));
        assert!(names.contains("vitest"));
        assert!(names.contains("prisma"));
        assert!(names.contains("ws"));
        assert_eq!(packages.len(), 10);
    }

    #[test]
    fn packages_requiring_api_across_tiers() {
        let mut m = NpmCompatibilityMatrix::new();
        for pkg in seed_tier1_critical_packages() {
            m.add_package(pkg).unwrap();
        }
        for pkg in seed_tier2_popular_packages() {
            m.add_package(pkg).unwrap();
        }
        // "fs" is used by many packages across both tiers
        let fs_pkgs = m.packages_requiring_api("fs");
        assert!(
            fs_pkgs.len() >= 2,
            "expected at least 2 packages needing fs, got {}",
            fs_pkgs.len()
        );
        // "crypto" is used by at least uuid (tier1) and jsonwebtoken (tier2)
        let crypto_pkgs = m.packages_requiring_api("crypto");
        assert!(
            crypto_pkgs.len() >= 2,
            "expected at least 2 packages needing crypto"
        );
        // Nonexistent API returns empty
        assert!(m.packages_requiring_api("imaginary_api").is_empty());
    }

    #[test]
    fn matrix_clone_equality() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_package(sample_package("a", CohortTier::Tier1Critical))
            .unwrap();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "a",
            IncompatibilitySeverity::Major,
        ))
        .unwrap();
        m.record_test_result(sample_test_result(
            "a",
            PackageTestOutcome::Compatible,
            10,
            10,
        ))
        .unwrap();
        let cloned = m.clone();
        assert_eq!(m, cloned);
    }

    #[test]
    fn incompatibilities_by_root_cause_empty_for_unused_cause() {
        let mut m = NpmCompatibilityMatrix::new();
        m.add_incompatibility(sample_incompatibility(
            "INC-001",
            "a",
            IncompatibilitySeverity::Minor,
        ))
        .unwrap();
        // Default root cause is MissingNodeApi
        assert!(
            m.incompatibilities_by_root_cause(IncompatibilityRootCause::NativeAddon)
                .is_empty()
        );
        assert!(
            m.incompatibilities_by_root_cause(IncompatibilityRootCause::V8SpecificApi)
                .is_empty()
        );
        assert_eq!(
            m.incompatibilities_by_root_cause(IncompatibilityRootCause::MissingNodeApi)
                .len(),
            1
        );
    }

    #[test]
    fn severity_weight_exact_values() {
        assert_eq!(
            IncompatibilitySeverity::Blocker.weight_millionths(),
            1_000_000
        );
        assert_eq!(IncompatibilitySeverity::Major.weight_millionths(), 500_000);
        assert_eq!(IncompatibilitySeverity::Minor.weight_millionths(), 100_000);
        assert_eq!(
            IncompatibilitySeverity::Cosmetic.weight_millionths(),
            10_000
        );
    }

    #[test]
    fn test_result_skipped_tests_field() {
        let mut result = sample_test_result("x", PackageTestOutcome::Compatible, 20, 15);
        result.skipped_tests = 3;
        // failed_tests was set by sample helper as 20-15=5
        assert_eq!(result.failed_tests, 5);
        assert_eq!(result.skipped_tests, 3);
        // pass_rate is still based on passed/total
        assert_eq!(result.pass_rate_millionths(), 750_000);
    }

    #[test]
    fn canonical_value_cohort_summary_field_values() {
        let summary = CohortSummary {
            tier: CohortTier::Tier3LongTail,
            total_packages: 3,
            compatible_count: 2,
            partially_compatible_count: 0,
            incompatible_count: 1,
            skipped_count: 0,
            untested_count: 0,
            compatibility_rate_millionths: 666_666,
            unblock_threshold_millionths: 750_000,
            unblocked: false,
            open_incompatibilities: 1,
            blocker_count: 0,
        };
        let cv = summary.canonical_value();
        if let CanonicalValue::Map(map) = cv {
            assert!(matches!(
                &map["tier"],
                CanonicalValue::String(s) if s == "tier_3_long_tail"
            ));
            assert!(matches!(map["total_packages"], CanonicalValue::I64(3)));
            assert!(matches!(map["unblocked"], CanonicalValue::Bool(false)));
        } else {
            panic!("expected Map");
        }
    }

    #[test]
    fn cohort_tier_ord_ordering() {
        assert!(CohortTier::Tier1Critical < CohortTier::Tier2Popular);
        assert!(CohortTier::Tier2Popular < CohortTier::Tier3LongTail);
    }

    #[test]
    fn incompatibility_severity_ord_ordering() {
        assert!(IncompatibilitySeverity::Blocker < IncompatibilitySeverity::Major);
        assert!(IncompatibilitySeverity::Major < IncompatibilitySeverity::Minor);
        assert!(IncompatibilitySeverity::Minor < IncompatibilitySeverity::Cosmetic);
    }

    #[test]
    fn remediation_state_ord_ordering() {
        assert!(RemediationState::Discovered < RemediationState::Triaged);
        assert!(RemediationState::Triaged < RemediationState::InProgress);
        assert!(RemediationState::InProgress < RemediationState::FixLanded);
        assert!(RemediationState::FixLanded < RemediationState::Verified);
        assert!(RemediationState::Verified < RemediationState::WontFix);
    }

    #[test]
    fn matrix_verdict_ord_ordering() {
        assert!(MatrixVerdict::AllCohortsUnblocked < MatrixVerdict::PartiallyUnblocked);
        assert!(MatrixVerdict::PartiallyUnblocked < MatrixVerdict::Blocked);
        assert!(MatrixVerdict::Blocked < MatrixVerdict::InsufficientData);
    }
}
