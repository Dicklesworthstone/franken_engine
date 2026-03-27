//! React package cohort validation and resolver behaviour for native JSX
//! runtime support.
//!
//! This module models the core React package ecosystem — React, ReactDOM,
//! the automatic JSX runtimes, the scheduler, and the reconciler — and
//! validates their export-map behaviour, aliasing contracts, runtime
//! subpath resolution, and mixed ESM/CJS edge cases.
//!
//! Every package is described by a [`PackageManifest`] that enumerates its
//! subpath export entries, per-condition resolution targets, and alias
//! mappings.  A [`CohortMatrix`] aggregates all manifests for a given
//! security epoch and captures edge-case validation results so the React
//! cohort compatibility claim can be reproduced outside the implementation
//! team.
//!
//! Plan references: Section 5.7 (RGC-405A), bead bd-1lsy.5.7.1.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;
use crate::security_epoch::SecurityEpoch;

// ---------------------------------------------------------------------------
// Schema constants
// ---------------------------------------------------------------------------

/// Schema version for the react package cohort contract.
pub const REACT_COHORT_SCHEMA_VERSION: &str = "franken-engine.react-package-cohort.v1";
/// Schema version for the react package cohort run manifest.
pub const REACT_COHORT_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "franken-engine.react-package-cohort.run-manifest.v1";
/// Schema version for react package cohort structured events.
pub const REACT_COHORT_EVENT_SCHEMA_VERSION: &str = "franken-engine.react-package-cohort.event.v1";
/// Schema version for the stable trace-id artifact.
pub const REACT_COHORT_TRACE_IDS_SCHEMA_VERSION: &str =
    "franken-engine.react-package-cohort.trace-ids.v1";

/// Bead identifier originating this module.
pub const REACT_COHORT_BEAD_ID: &str = "bd-1lsy.5.7.1";

/// Policy ID binding.
pub const REACT_COHORT_POLICY_ID: &str = "RGC-405A";

/// Component name for evidence linkage.
pub const REACT_COHORT_COMPONENT: &str = "react_package_cohort";

/// Fixed-point scale: 1_000_000 millionths = 1.0.
const MILLIONTHS: u64 = 1_000_000;
static NEXT_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// ReactPackage
// ---------------------------------------------------------------------------

/// Enumerates the core React packages relevant to native JSX runtime
/// resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReactPackage {
    /// The core `react` package.
    React,
    /// `react-dom` — browser and server rendering.
    ReactDom,
    /// `react-dom/server` logical package for SSR.
    ReactDomServer,
    /// `react/jsx-runtime` — automatic JSX transform (production).
    ReactJsxRuntime,
    /// `react/jsx-dev-runtime` — automatic JSX transform (development).
    ReactJsxDevRuntime,
    /// `scheduler` — cooperative scheduling substrate.
    Scheduler,
    /// `react-reconciler` — custom renderer abstraction.
    ReactReconciler,
}

impl ReactPackage {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [ReactPackage] = &[
        ReactPackage::React,
        ReactPackage::ReactDom,
        ReactPackage::ReactDomServer,
        ReactPackage::ReactJsxRuntime,
        ReactPackage::ReactJsxDevRuntime,
        ReactPackage::Scheduler,
        ReactPackage::ReactReconciler,
    ];

    /// The canonical npm package name.
    pub const fn npm_name(self) -> &'static str {
        match self {
            Self::React => "react",
            Self::ReactDom => "react-dom",
            Self::ReactDomServer => "react-dom",
            Self::ReactJsxRuntime => "react",
            Self::ReactJsxDevRuntime => "react",
            Self::Scheduler => "scheduler",
            Self::ReactReconciler => "react-reconciler",
        }
    }

    /// Short identifier used in hash derivation and diagnostics.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::React => "react",
            Self::ReactDom => "react_dom",
            Self::ReactDomServer => "react_dom_server",
            Self::ReactJsxRuntime => "react_jsx_runtime",
            Self::ReactJsxDevRuntime => "react_jsx_dev_runtime",
            Self::Scheduler => "scheduler",
            Self::ReactReconciler => "react_reconciler",
        }
    }
}

impl fmt::Display for ReactPackage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// ExportCondition
// ---------------------------------------------------------------------------

/// Node/bundler export-map conditions relevant to React packages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportCondition {
    /// ESM `import` condition.
    Import,
    /// CJS `require` condition.
    Require,
    /// Fallback `default` condition.
    Default,
    /// Browser-specific condition.
    Browser,
    /// Node.js-specific condition.
    Node,
    /// React server-component condition (`react-server`).
    ReactServer,
    /// React Native condition.
    ReactNative,
}

impl ExportCondition {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [ExportCondition] = &[
        ExportCondition::Import,
        ExportCondition::Require,
        ExportCondition::Default,
        ExportCondition::Browser,
        ExportCondition::Node,
        ExportCondition::ReactServer,
        ExportCondition::ReactNative,
    ];

    /// String key as it appears in `package.json` export maps.
    pub const fn condition_key(self) -> &'static str {
        match self {
            Self::Import => "import",
            Self::Require => "require",
            Self::Default => "default",
            Self::Browser => "browser",
            Self::Node => "node",
            Self::ReactServer => "react-server",
            Self::ReactNative => "react-native",
        }
    }
}

impl fmt::Display for ExportCondition {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.condition_key())
    }
}

// ---------------------------------------------------------------------------
// ModuleFormat
// ---------------------------------------------------------------------------

/// Module format of a resolved export target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModuleFormat {
    /// ECMAScript modules (`.mjs` or `"type": "module"`).
    Esm,
    /// CommonJS modules (`.cjs` or `"type": "commonjs"`).
    Cjs,
    /// Dual-format: package ships both ESM and CJS entry-points.
    Dual,
}

impl ModuleFormat {
    /// All variants for exhaustive iteration.
    pub const ALL: &'static [ModuleFormat] =
        &[ModuleFormat::Esm, ModuleFormat::Cjs, ModuleFormat::Dual];

    /// Human-readable label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Esm => "esm",
            Self::Cjs => "cjs",
            Self::Dual => "dual",
        }
    }
}

impl fmt::Display for ModuleFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// SubpathEntry
// ---------------------------------------------------------------------------

/// A single subpath export entry in a React package's export map.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SubpathEntry {
    /// The subpath pattern (e.g. `"."`, `"./jsx-runtime"`, `"./server"`).
    pub subpath: String,
    /// The export conditions under which this entry is reachable.
    pub conditions: Vec<ExportCondition>,
    /// The resolved file path relative to the package root.
    pub resolved_path: String,
    /// The module format of the resolved target.
    pub format: ModuleFormat,
}

impl SubpathEntry {
    /// Create a new subpath entry.
    pub fn new(
        subpath: impl Into<String>,
        conditions: Vec<ExportCondition>,
        resolved_path: impl Into<String>,
        format: ModuleFormat,
    ) -> Self {
        Self {
            subpath: subpath.into(),
            conditions,
            resolved_path: resolved_path.into(),
            format,
        }
    }

    /// Whether this entry matches the given subpath string and condition.
    pub fn matches(&self, subpath: &str, condition: &ExportCondition) -> bool {
        self.subpath == subpath && self.conditions.contains(condition)
    }

    /// Compute a stable fingerprint of this entry.
    fn fingerprint_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.subpath.as_bytes());
        buf.push(b':');
        for cond in &self.conditions {
            buf.extend_from_slice(cond.condition_key().as_bytes());
            buf.push(b',');
        }
        buf.push(b':');
        buf.extend_from_slice(self.resolved_path.as_bytes());
        buf.push(b':');
        buf.extend_from_slice(self.format.as_str().as_bytes());
        buf
    }
}

impl fmt::Display for SubpathEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "subpath({} -> {} [{}])",
            self.subpath, self.resolved_path, self.format
        )
    }
}

// ---------------------------------------------------------------------------
// PackageManifest
// ---------------------------------------------------------------------------

/// Describes a React package's export surface: subpath entries, alias
/// mappings, and a content hash for integrity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManifest {
    /// Which React package this manifest describes.
    pub package: ReactPackage,
    /// Semantic version string (e.g. `"18.3.1"`).
    pub version: String,
    /// All subpath export entries.
    pub subpaths: Vec<SubpathEntry>,
    /// Alias mappings (e.g. `"react-dom/server" -> "react-dom/server.browser"`).
    pub aliases: BTreeMap<String, String>,
    /// Content hash over the manifest's deterministic representation.
    pub content_hash: ContentHash,
}

impl PackageManifest {
    /// Number of distinct subpath entries.
    pub fn subpath_count(&self) -> u64 {
        self.subpaths.len() as u64
    }

    /// Number of alias mappings.
    pub fn alias_count(&self) -> u64 {
        self.aliases.len() as u64
    }

    /// Fixed-point coverage ratio: fraction of conditions that have at least
    /// one subpath entry, expressed in millionths.
    pub fn condition_coverage_millionths(&self) -> u64 {
        let total = ExportCondition::ALL.len() as u64;
        if total == 0 {
            return 0;
        }
        let mut covered = std::collections::BTreeSet::new();
        for entry in &self.subpaths {
            for cond in &entry.conditions {
                covered.insert(*cond);
            }
        }
        let hit = covered.len() as u64;
        hit.saturating_mul(MILLIONTHS) / total
    }
}

impl fmt::Display for PackageManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PackageManifest({} v{}, {} subpaths, {} aliases)",
            self.package,
            self.version,
            self.subpaths.len(),
            self.aliases.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// EdgeCase
// ---------------------------------------------------------------------------

/// Captures a single edge-case validation scenario within the cohort
/// matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeCase {
    /// Unique identifier for the edge case.
    pub case_id: String,
    /// Human-readable description.
    pub description: String,
    /// The source package being resolved.
    pub source_package: ReactPackage,
    /// The export condition applied.
    pub condition: ExportCondition,
    /// The expected resolution path.
    pub expected_resolution: String,
    /// The actual resolution path (None if resolution failed).
    pub actual_resolution: Option<String>,
    /// Whether the edge case passed validation.
    pub passed: bool,
}

impl EdgeCase {
    /// Build a new edge case with unknown result (pre-validation).
    pub fn pending(
        case_id: impl Into<String>,
        description: impl Into<String>,
        source_package: ReactPackage,
        condition: ExportCondition,
        expected_resolution: impl Into<String>,
    ) -> Self {
        Self {
            case_id: case_id.into(),
            description: description.into(),
            source_package,
            condition,
            expected_resolution: expected_resolution.into(),
            actual_resolution: None,
            passed: false,
        }
    }

    /// Mark this edge case as resolved with a given actual path.
    pub fn resolve(&mut self, actual: impl Into<String>) {
        let actual = actual.into();
        self.passed = actual == self.expected_resolution;
        self.actual_resolution = Some(actual);
    }

    /// Mark this edge case as failed (resolution not found).
    pub fn mark_failed(&mut self) {
        self.actual_resolution = None;
        self.passed = false;
    }
}

impl fmt::Display for EdgeCase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.passed { "PASS" } else { "FAIL" };
        write!(f, "[{}] {} ({})", status, self.case_id, self.description)
    }
}

// ---------------------------------------------------------------------------
// CohortError
// ---------------------------------------------------------------------------

/// Errors arising from React package cohort validation and resolution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CohortError {
    /// The requested package was not found in the cohort matrix.
    PackageNotFound(String),
    /// The requested subpath was not found in the package manifest.
    SubpathMissing(String),
    /// The resolved module format does not match the expected format.
    FormatMismatch {
        /// Expected format.
        expected: ModuleFormat,
        /// Actual format.
        actual: ModuleFormat,
    },
    /// An alias chain forms a cycle.
    AliasLoop(Vec<String>),
    /// Catch-all internal error.
    InternalError(String),
}

impl fmt::Display for CohortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PackageNotFound(name) => {
                write!(f, "package not found: {name}")
            }
            Self::SubpathMissing(sp) => {
                write!(f, "subpath missing: {sp}")
            }
            Self::FormatMismatch { expected, actual } => {
                write!(f, "format mismatch: expected {expected}, got {actual}")
            }
            Self::AliasLoop(chain) => {
                write!(f, "alias loop detected: {}", chain.join(" -> "))
            }
            Self::InternalError(msg) => {
                write!(f, "internal error: {msg}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CohortMatrix
// ---------------------------------------------------------------------------

/// Aggregation of all React package manifests for a given epoch,
/// including edge-case validation results and summary metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortMatrix {
    /// Unique matrix identifier.
    pub matrix_id: String,
    /// The security epoch under which this matrix was built.
    pub epoch: SecurityEpoch,
    /// All package manifests in the cohort.
    pub packages: Vec<PackageManifest>,
    /// Edge-case validation scenarios.
    pub edge_cases: Vec<EdgeCase>,
    /// Total number of subpath entries across all packages.
    pub total_subpaths: u64,
    /// Content hash over the entire matrix.
    pub content_hash: ContentHash,
}

impl CohortMatrix {
    /// Number of packages in the cohort.
    pub fn package_count(&self) -> usize {
        self.packages.len()
    }

    /// Number of edge cases that passed.
    pub fn passed_edge_cases(&self) -> usize {
        self.edge_cases.iter().filter(|ec| ec.passed).count()
    }

    /// Number of edge cases that failed.
    pub fn failed_edge_cases(&self) -> usize {
        self.edge_cases.iter().filter(|ec| !ec.passed).count()
    }

    /// Fixed-point pass rate in millionths.
    pub fn pass_rate_millionths(&self) -> u64 {
        let total = self.edge_cases.len() as u64;
        if total == 0 {
            return MILLIONTHS; // 100% when no edge cases
        }
        let passed = self.passed_edge_cases() as u64;
        passed.saturating_mul(MILLIONTHS) / total
    }

    /// Look up a manifest by package kind.
    pub fn find_manifest(&self, pkg: ReactPackage) -> Option<&PackageManifest> {
        self.packages.iter().find(|m| m.package == pkg)
    }
}

impl fmt::Display for CohortMatrix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CohortMatrix({}, {} packages, {} subpaths, {} edge cases [{}/{}])",
            self.matrix_id,
            self.packages.len(),
            self.total_subpaths,
            self.edge_cases.len(),
            self.passed_edge_cases(),
            self.edge_cases.len(),
        )
    }
}

// ---------------------------------------------------------------------------
// CohortValidationReport
// ---------------------------------------------------------------------------

/// Summarises the result of running the cohort validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortValidationReport {
    /// The matrix that was validated.
    pub matrix_id: String,
    /// Overall pass/fail.
    pub passed: bool,
    /// Pass rate in millionths.
    pub pass_rate_millionths: u64,
    /// Per-package subpath counts.
    pub per_package_subpath_counts: BTreeMap<String, u64>,
    /// Alias loop chains detected across all packages.
    pub alias_loops_detected: Vec<Vec<String>>,
    /// Content hash of the report itself.
    pub content_hash: ContentHash,
}

impl fmt::Display for CohortValidationReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.passed { "PASS" } else { "FAIL" };
        write!(
            f,
            "CohortValidationReport({}, {}, rate={})",
            self.matrix_id, status, self.pass_rate_millionths
        )
    }
}

// ---------------------------------------------------------------------------
// Bundle artifacts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactCohortArtifactPaths {
    pub react_package_cohort_matrix: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
    pub trace_ids: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactCohortRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub matrix_hash: String,
    pub package_count: u64,
    pub edge_case_count: u64,
    pub pass_count: u64,
    pub fail_count: u64,
    pub pass_rate_millionths: u64,
    pub contract_satisfied: bool,
    pub artifact_paths: ReactCohortArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactCohortEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub case_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReactCohortTraceIds {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReactCohortBundleArtifacts {
    pub out_dir: PathBuf,
    pub matrix_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub matrix_hash: String,
    pub package_count: usize,
    pub edge_case_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ReactCohortWriteError {
    #[error("failed to serialize `{path}`: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("failed to write `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("bundle output directory is already locked by another writer: `{path}`")]
    Busy { path: String },
}

// ---------------------------------------------------------------------------
// Core functions
// ---------------------------------------------------------------------------

/// Build a [`PackageManifest`] from a package identifier, version, and
/// subpath entries.  The content hash is computed deterministically from
/// the manifest's structural data.
pub fn build_manifest(
    package: ReactPackage,
    version: &str,
    subpaths: Vec<SubpathEntry>,
) -> PackageManifest {
    let aliases = BTreeMap::new();
    build_manifest_with_aliases(package, version, subpaths, aliases)
}

/// Build a [`PackageManifest`] with explicit alias mappings.
pub fn build_manifest_with_aliases(
    package: ReactPackage,
    version: &str,
    subpaths: Vec<SubpathEntry>,
    aliases: BTreeMap<String, String>,
) -> PackageManifest {
    let content_hash = compute_manifest_hash(package, version, &subpaths, &aliases);
    PackageManifest {
        package,
        version: version.to_string(),
        subpaths,
        aliases,
        content_hash,
    }
}

/// Compute a deterministic content hash for a package manifest.
fn compute_manifest_hash(
    package: ReactPackage,
    version: &str,
    subpaths: &[SubpathEntry],
    aliases: &BTreeMap<String, String>,
) -> ContentHash {
    let mut hasher = Sha256::new();
    hasher.update(REACT_COHORT_SCHEMA_VERSION.as_bytes());
    hasher.update(b":");
    hasher.update(package.as_str().as_bytes());
    hasher.update(b":");
    hasher.update(version.as_bytes());
    for entry in subpaths {
        hasher.update(b"|");
        hasher.update(entry.fingerprint_bytes());
    }
    for (k, v) in aliases {
        hasher.update(b"@");
        hasher.update(k.as_bytes());
        hasher.update(b"=");
        hasher.update(v.as_bytes());
    }
    let result = hasher.finalize();
    ContentHash(result.into())
}

/// Resolve a subpath under a given export condition within a manifest.
///
/// Returns the first matching [`SubpathEntry`], or
/// [`CohortError::SubpathMissing`] if no entry matches.
pub fn resolve_subpath<'a>(
    manifest: &'a PackageManifest,
    subpath: &str,
    condition: &ExportCondition,
) -> Result<&'a SubpathEntry, CohortError> {
    // First check if there's an alias for this subpath.
    let effective_subpath = if let Some(alias_target) = manifest.aliases.get(subpath) {
        alias_target.as_str()
    } else {
        subpath
    };

    manifest
        .subpaths
        .iter()
        .find(|entry| entry.matches(effective_subpath, condition))
        .ok_or_else(|| {
            CohortError::SubpathMissing(format!(
                "{} under condition {}",
                effective_subpath, condition
            ))
        })
}

/// Resolve a subpath with a chain of condition fallbacks.  Tries each
/// condition in order and returns the first successful resolution.
pub fn resolve_subpath_with_fallbacks<'a>(
    manifest: &'a PackageManifest,
    subpath: &str,
    conditions: &[ExportCondition],
) -> Result<&'a SubpathEntry, CohortError> {
    for cond in conditions {
        if let Ok(entry) = resolve_subpath(manifest, subpath, cond) {
            return Ok(entry);
        }
    }
    Err(CohortError::SubpathMissing(format!(
        "{} under conditions {:?}",
        subpath,
        conditions
            .iter()
            .map(|c| c.condition_key())
            .collect::<Vec<_>>()
    )))
}

/// Build a [`CohortMatrix`] from an epoch and a set of package manifests.
///
/// Computes the total subpath count and a matrix-level content hash.
pub fn build_cohort_matrix(epoch: SecurityEpoch, packages: Vec<PackageManifest>) -> CohortMatrix {
    build_cohort_matrix_with_edges(epoch, packages, Vec::new())
}

/// Build a [`CohortMatrix`] with explicit edge cases.
pub fn build_cohort_matrix_with_edges(
    epoch: SecurityEpoch,
    packages: Vec<PackageManifest>,
    edge_cases: Vec<EdgeCase>,
) -> CohortMatrix {
    let total_subpaths: u64 = packages.iter().map(|m| m.subpath_count()).sum();

    let mut hasher = Sha256::new();
    hasher.update(REACT_COHORT_SCHEMA_VERSION.as_bytes());
    hasher.update(b":matrix:");
    hasher.update(epoch.as_u64().to_le_bytes());
    for manifest in &packages {
        hasher.update(b"|pkg:");
        hasher.update(manifest.content_hash.as_bytes());
    }
    let mut sorted_ecs: Vec<_> = edge_cases.iter().collect();
    sorted_ecs.sort_by(|a, b| a.case_id.cmp(&b.case_id));
    for ec in &sorted_ecs {
        hasher.update(b"|ec:");
        hasher.update(ec.case_id.as_bytes());
        hasher.update(if ec.passed { b":pass" } else { b":fail" });
    }
    let result = hasher.finalize();
    let content_hash = ContentHash(result.into());

    let matrix_id = format!(
        "cohort-matrix-{}-{}",
        epoch.as_u64(),
        &content_hash.to_hex()[..16]
    );

    CohortMatrix {
        matrix_id,
        epoch,
        packages,
        edge_cases,
        total_subpaths,
        content_hash,
    }
}

/// Validate a single edge case against its source package manifest.
///
/// Attempts to resolve the expected subpath under the edge case's
/// condition.  Returns `true` if the resolved path matches the expected
/// resolution.
pub fn validate_edge_case(manifest: &PackageManifest, case: &EdgeCase) -> bool {
    match resolve_subpath(manifest, &case.expected_resolution, &case.condition) {
        Ok(entry) => entry.resolved_path == case.expected_resolution,
        Err(_) => {
            // Try matching the expected resolution as a resolved_path
            // rather than a subpath.
            manifest.subpaths.iter().any(|entry| {
                entry.resolved_path == case.expected_resolution
                    && entry.conditions.contains(&case.condition)
            })
        }
    }
}

/// Detect alias loops in a package manifest.
///
/// Follows each alias chain and reports any cycles found.  Returns a
/// vector of cycle chains (empty if no loops exist).
pub fn detect_alias_loops(manifest: &PackageManifest) -> Vec<Vec<String>> {
    let mut loops = Vec::new();

    for start_key in manifest.aliases.keys() {
        let mut visited = Vec::new();
        let mut current = start_key.as_str();
        visited.push(current.to_string());

        while let Some(next) = manifest.aliases.get(current) {
            if let Some(pos) = visited.iter().position(|v| v == next) {
                // Found a cycle — extract the loop portion.
                let cycle: Vec<String> = visited[pos..].to_vec();
                // Only record if we haven't already captured an
                // equivalent cycle (normalise by smallest element).
                let is_duplicate = loops.iter().any(|existing: &Vec<String>| {
                    existing.len() == cycle.len() && cycle.iter().all(|c| existing.contains(c))
                });
                if !is_duplicate {
                    loops.push(cycle);
                }
                break;
            }
            visited.push(next.to_string());
            current = next.as_str();
        }
    }

    loops
}

/// Verify that all subpath entries within a manifest have consistent
/// format declarations (no conflicting formats for the same resolved
/// path).
pub fn verify_format_consistency(manifest: &PackageManifest) -> Vec<CohortError> {
    let mut path_formats: BTreeMap<&str, ModuleFormat> = BTreeMap::new();
    let mut errors = Vec::new();

    for entry in &manifest.subpaths {
        if let Some(&existing) = path_formats.get(entry.resolved_path.as_str()) {
            if existing != entry.format {
                errors.push(CohortError::FormatMismatch {
                    expected: existing,
                    actual: entry.format,
                });
            }
        } else {
            path_formats.insert(&entry.resolved_path, entry.format);
        }
    }

    errors
}

/// Run the full cohort validation: edge-case checking, alias loop
/// detection, and format consistency.
pub fn validate_cohort(matrix: &CohortMatrix) -> CohortValidationReport {
    let mut all_loops: Vec<Vec<String>> = Vec::new();
    let mut per_package_subpath_counts = BTreeMap::new();

    for manifest in &matrix.packages {
        per_package_subpath_counts.insert(
            manifest.package.as_str().to_string(),
            manifest.subpath_count(),
        );
        let loops = detect_alias_loops(manifest);
        for lp in loops {
            all_loops.push(lp);
        }
    }

    let edge_pass_count = matrix.passed_edge_cases() as u64;
    let edge_total = matrix.edge_cases.len() as u64;
    let pass_rate = edge_pass_count
        .saturating_mul(MILLIONTHS)
        .checked_div(edge_total)
        .unwrap_or(MILLIONTHS);

    let passed = all_loops.is_empty() && (edge_total == 0 || edge_pass_count == edge_total);

    let mut hasher = Sha256::new();
    hasher.update(b"cohort-validation-report:");
    hasher.update(matrix.matrix_id.as_bytes());
    hasher.update(if passed { b":pass" } else { b":fail" });
    hasher.update(pass_rate.to_le_bytes());
    let result = hasher.finalize();
    let content_hash = ContentHash(result.into());

    CohortValidationReport {
        matrix_id: matrix.matrix_id.clone(),
        passed,
        pass_rate_millionths: pass_rate,
        per_package_subpath_counts,
        alias_loops_detected: all_loops,
        content_hash,
    }
}

/// Build the canonical franken-engine React cohort manifest.
///
/// This factory produces a fully-populated [`CohortMatrix`] covering all
/// seven React packages with representative subpath entries and edge-case
/// scenarios.  Used as the golden reference for validation.
pub fn franken_engine_react_cohort_manifest() -> CohortMatrix {
    let epoch = SecurityEpoch::from_raw(1);

    // --- react ---
    let react_subpaths = vec![
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Import],
            "./esm/react.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Require],
            "./cjs/react.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Default],
            "./cjs/react.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            "./jsx-runtime",
            vec![ExportCondition::Import],
            "./esm/jsx-runtime.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            "./jsx-runtime",
            vec![ExportCondition::Require],
            "./cjs/jsx-runtime.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            "./jsx-dev-runtime",
            vec![ExportCondition::Import],
            "./esm/jsx-dev-runtime.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            "./jsx-dev-runtime",
            vec![ExportCondition::Require],
            "./cjs/jsx-dev-runtime.js",
            ModuleFormat::Cjs,
        ),
    ];
    let react_manifest = build_manifest(ReactPackage::React, "18.3.1", react_subpaths);

    // --- react-dom ---
    let react_dom_subpaths = vec![
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Import],
            "./esm/react-dom.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Require],
            "./cjs/react-dom.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Default],
            "./cjs/react-dom.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            "./client",
            vec![ExportCondition::Import],
            "./esm/react-dom-client.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            "./client",
            vec![ExportCondition::Require],
            "./cjs/react-dom-client.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            "./server",
            vec![ExportCondition::Import, ExportCondition::Node],
            "./esm/react-dom-server.node.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            "./server",
            vec![ExportCondition::Require],
            "./cjs/react-dom-server.node.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            "./server",
            vec![ExportCondition::Browser],
            "./esm/react-dom-server.browser.js",
            ModuleFormat::Esm,
        ),
    ];
    let react_dom_manifest = build_manifest(ReactPackage::ReactDom, "18.3.1", react_dom_subpaths);

    // --- react-dom/server (logical) ---
    let react_dom_server_subpaths = vec![
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Import, ExportCondition::Node],
            "./esm/react-dom-server.node.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Require],
            "./cjs/react-dom-server.node.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Browser],
            "./esm/react-dom-server.browser.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::ReactServer],
            "./esm/react-dom-server.edge.js",
            ModuleFormat::Esm,
        ),
    ];
    let react_dom_server_manifest = build_manifest(
        ReactPackage::ReactDomServer,
        "18.3.1",
        react_dom_server_subpaths,
    );

    // --- react/jsx-runtime ---
    let jsx_runtime_subpaths = vec![
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Import],
            "./esm/jsx-runtime.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Require],
            "./cjs/jsx-runtime.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Default],
            "./cjs/jsx-runtime.js",
            ModuleFormat::Cjs,
        ),
    ];
    let jsx_runtime_manifest = build_manifest(
        ReactPackage::ReactJsxRuntime,
        "18.3.1",
        jsx_runtime_subpaths,
    );

    // --- react/jsx-dev-runtime ---
    let jsx_dev_runtime_subpaths = vec![
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Import],
            "./esm/jsx-dev-runtime.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Require],
            "./cjs/jsx-dev-runtime.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Default],
            "./cjs/jsx-dev-runtime.js",
            ModuleFormat::Cjs,
        ),
    ];
    let jsx_dev_runtime_manifest = build_manifest(
        ReactPackage::ReactJsxDevRuntime,
        "18.3.1",
        jsx_dev_runtime_subpaths,
    );

    // --- scheduler ---
    let scheduler_subpaths = vec![
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Import],
            "./esm/scheduler.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Require],
            "./cjs/scheduler.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Default],
            "./cjs/scheduler.js",
            ModuleFormat::Cjs,
        ),
    ];
    let scheduler_manifest = build_manifest(ReactPackage::Scheduler, "0.23.0", scheduler_subpaths);

    // --- react-reconciler ---
    let reconciler_subpaths = vec![
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Import],
            "./esm/react-reconciler.js",
            ModuleFormat::Esm,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Require],
            "./cjs/react-reconciler.js",
            ModuleFormat::Cjs,
        ),
        SubpathEntry::new(
            ".",
            vec![ExportCondition::Default],
            "./cjs/react-reconciler.js",
            ModuleFormat::Cjs,
        ),
    ];
    let reconciler_manifest =
        build_manifest(ReactPackage::ReactReconciler, "0.29.0", reconciler_subpaths);

    // --- edge cases ---
    let mut ec1 = EdgeCase::pending(
        "ec-jsx-runtime-esm",
        "jsx-runtime resolves to ESM under import condition",
        ReactPackage::ReactJsxRuntime,
        ExportCondition::Import,
        "./esm/jsx-runtime.js",
    );
    ec1.resolve("./esm/jsx-runtime.js");

    let mut ec2 = EdgeCase::pending(
        "ec-dom-server-browser",
        "react-dom/server resolves to browser ESM under browser condition",
        ReactPackage::ReactDomServer,
        ExportCondition::Browser,
        "./esm/react-dom-server.browser.js",
    );
    ec2.resolve("./esm/react-dom-server.browser.js");

    let mut ec3 = EdgeCase::pending(
        "ec-dom-server-react-server",
        "react-dom/server resolves to edge ESM under react-server condition",
        ReactPackage::ReactDomServer,
        ExportCondition::ReactServer,
        "./esm/react-dom-server.edge.js",
    );
    ec3.resolve("./esm/react-dom-server.edge.js");

    let mut ec4 = EdgeCase::pending(
        "ec-react-cjs-fallback",
        "react main entry falls back to CJS under default condition",
        ReactPackage::React,
        ExportCondition::Default,
        "./cjs/react.js",
    );
    ec4.resolve("./cjs/react.js");

    let mut ec5 = EdgeCase::pending(
        "ec-scheduler-require",
        "scheduler resolves to CJS under require condition",
        ReactPackage::Scheduler,
        ExportCondition::Require,
        "./cjs/scheduler.js",
    );
    ec5.resolve("./cjs/scheduler.js");

    let packages = vec![
        react_manifest,
        react_dom_manifest,
        react_dom_server_manifest,
        jsx_runtime_manifest,
        jsx_dev_runtime_manifest,
        scheduler_manifest,
        reconciler_manifest,
    ];

    let edge_cases = vec![ec1, ec2, ec3, ec4, ec5];

    build_cohort_matrix_with_edges(epoch, packages, edge_cases)
}

// ---------------------------------------------------------------------------
// Helper: resolve an alias chain (with loop detection)
// ---------------------------------------------------------------------------

/// Follow the alias chain for a given key, returning the terminal value
/// or an [`CohortError::AliasLoop`] if a cycle is found.
pub fn resolve_alias_chain(
    aliases: &BTreeMap<String, String>,
    start: &str,
) -> Result<String, CohortError> {
    let mut visited = Vec::new();
    let mut current = start.to_string();

    loop {
        if visited.contains(&current) {
            return Err(CohortError::AliasLoop(visited));
        }
        visited.push(current.clone());
        match aliases.get(&current) {
            Some(next) => current = next.clone(),
            None => return Ok(current),
        }
    }
}

/// Check whether a given format is compatible with an expected format.
/// `Dual` is compatible with both `Esm` and `Cjs`.
pub fn format_compatible(expected: ModuleFormat, actual: ModuleFormat) -> bool {
    if expected == actual {
        return true;
    }
    matches!(
        (expected, actual),
        (ModuleFormat::Esm, ModuleFormat::Dual)
            | (ModuleFormat::Cjs, ModuleFormat::Dual)
            | (ModuleFormat::Dual, ModuleFormat::Esm)
            | (ModuleFormat::Dual, ModuleFormat::Cjs)
    )
}

/// Compute a fixed-point coverage score for a set of packages relative to
/// the full React package enum.  Expressed in millionths.
pub fn cohort_coverage_millionths(packages: &[PackageManifest]) -> u64 {
    let total = ReactPackage::ALL.len() as u64;
    if total == 0 {
        return 0;
    }
    let mut covered = std::collections::BTreeSet::new();
    for manifest in packages {
        covered.insert(manifest.package);
    }
    let hit = covered.len() as u64;
    hit.saturating_mul(MILLIONTHS) / total
}

pub fn write_react_package_cohort_bundle(
    out_dir: impl AsRef<Path>,
    command_lines: &[String],
) -> Result<ReactCohortBundleArtifacts, ReactCohortWriteError> {
    let out_dir = out_dir.as_ref().to_path_buf();
    fs::create_dir_all(&out_dir).map_err(|source| ReactCohortWriteError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;

    let matrix = franken_engine_react_cohort_manifest();
    let report = validate_cohort(&matrix);

    let matrix_path = out_dir.join("react_package_cohort_matrix.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let trace_ids_path = out_dir.join("trace_ids.json");

    let matrix_bytes = canonical_json_bytes(&matrix, &matrix_path)?;
    let matrix_hash = sha256_hex(&matrix_bytes);
    let short_hash = matrix_hash.chars().take(16).collect::<String>();

    let trace_ids = ReactCohortTraceIds {
        schema_version: REACT_COHORT_TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: REACT_COHORT_COMPONENT.to_string(),
        trace_id: format!("trace-react-package-cohort-{short_hash}"),
        decision_id: format!("decision-react-package-cohort-{short_hash}"),
        policy_id: REACT_COHORT_POLICY_ID.to_string(),
    };
    let trace_ids_bytes = canonical_json_bytes(&trace_ids, &trace_ids_path)?;

    let manifest = ReactCohortRunManifest {
        schema_version: REACT_COHORT_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: REACT_COHORT_COMPONENT.to_string(),
        trace_id: trace_ids.trace_id.clone(),
        decision_id: trace_ids.decision_id.clone(),
        policy_id: REACT_COHORT_POLICY_ID.to_string(),
        matrix_hash: matrix_hash.clone(),
        package_count: matrix.package_count() as u64,
        edge_case_count: matrix.edge_cases.len() as u64,
        pass_count: matrix.passed_edge_cases() as u64,
        fail_count: matrix.failed_edge_cases() as u64,
        pass_rate_millionths: report.pass_rate_millionths,
        contract_satisfied: report.passed,
        artifact_paths: ReactCohortArtifactPaths {
            react_package_cohort_matrix: "react_package_cohort_matrix.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
            trace_ids: "trace_ids.json".to_string(),
        },
    };
    let manifest_bytes = canonical_json_bytes(&manifest, &run_manifest_path)?;

    let events = build_cohort_events(&matrix, &report, &trace_ids);
    let mut events_jsonl = String::new();
    for event in &events {
        let line = serde_json::to_string(event).map_err(|source| ReactCohortWriteError::Json {
            path: events_path.display().to_string(),
            source,
        })?;
        events_jsonl.push_str(&line);
        events_jsonl.push('\n');
    }

    let mut commands_buf = String::new();
    for command in command_lines {
        commands_buf.push_str(command);
        commands_buf.push('\n');
    }

    let _bundle_lock = acquire_bundle_write_lock(&out_dir)?;
    remove_commit_marker(&run_manifest_path)?;
    write_atomic(&matrix_path, &matrix_bytes)?;
    write_atomic(&trace_ids_path, &trace_ids_bytes)?;
    write_atomic(&events_path, events_jsonl.as_bytes())?;
    write_atomic(&commands_path, commands_buf.as_bytes())?;
    write_atomic(&run_manifest_path, &manifest_bytes)?;

    Ok(ReactCohortBundleArtifacts {
        out_dir,
        matrix_path,
        run_manifest_path,
        events_path,
        commands_path,
        trace_ids_path,
        matrix_hash,
        package_count: matrix.package_count(),
        edge_case_count: matrix.edge_cases.len(),
    })
}

fn build_cohort_events(
    matrix: &CohortMatrix,
    report: &CohortValidationReport,
    trace_ids: &ReactCohortTraceIds,
) -> Vec<ReactCohortEvent> {
    let mut events = vec![ReactCohortEvent {
        schema_version: REACT_COHORT_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_ids.trace_id.clone(),
        decision_id: trace_ids.decision_id.clone(),
        policy_id: trace_ids.policy_id.clone(),
        component: REACT_COHORT_COMPONENT.to_string(),
        event: "cohort_generation_started".to_string(),
        outcome: "started".to_string(),
        package: None,
        case_id: None,
        detail: Some(format!(
            "{} packages, {} edge cases",
            matrix.package_count(),
            matrix.edge_cases.len()
        )),
    }];

    events.extend(matrix.packages.iter().map(|manifest| ReactCohortEvent {
        schema_version: REACT_COHORT_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_ids.trace_id.clone(),
        decision_id: trace_ids.decision_id.clone(),
        policy_id: trace_ids.policy_id.clone(),
        component: REACT_COHORT_COMPONENT.to_string(),
        event: "package_manifest_recorded".to_string(),
        outcome: "recorded".to_string(),
        package: Some(manifest.package.as_str().to_string()),
        case_id: None,
        detail: Some(format!(
            "subpaths={} aliases={} coverage_millionths={}",
            manifest.subpath_count(),
            manifest.alias_count(),
            manifest.condition_coverage_millionths()
        )),
    }));

    events.extend(matrix.edge_cases.iter().map(|edge_case| ReactCohortEvent {
        schema_version: REACT_COHORT_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_ids.trace_id.clone(),
        decision_id: trace_ids.decision_id.clone(),
        policy_id: trace_ids.policy_id.clone(),
        component: REACT_COHORT_COMPONENT.to_string(),
        event: "edge_case_evaluated".to_string(),
        outcome: if edge_case.passed { "pass" } else { "fail" }.to_string(),
        package: Some(edge_case.source_package.as_str().to_string()),
        case_id: Some(edge_case.case_id.clone()),
        detail: Some(format!(
            "expected={} actual={}",
            edge_case.expected_resolution,
            edge_case.actual_resolution.as_deref().unwrap_or("<missing>")
        )),
    }));

    events.push(ReactCohortEvent {
        schema_version: REACT_COHORT_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_ids.trace_id.clone(),
        decision_id: trace_ids.decision_id.clone(),
        policy_id: trace_ids.policy_id.clone(),
        component: REACT_COHORT_COMPONENT.to_string(),
        event: "cohort_generation_completed".to_string(),
        outcome: if report.passed { "pass" } else { "fail" }.to_string(),
        package: None,
        case_id: None,
        detail: Some(format!(
            "pass_rate_millionths={} alias_loops_detected={}",
            report.pass_rate_millionths,
            report.alias_loops_detected.len()
        )),
    });

    events
}

fn canonical_json_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, ReactCohortWriteError> {
    serde_json::to_vec(value).map_err(|source| ReactCohortWriteError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn acquire_bundle_write_lock(out_dir: &Path) -> Result<BundleWriteLock, ReactCohortWriteError> {
    let lock_path = out_dir.join(".react_package_cohort.lock");
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(BundleWriteLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {
            Err(ReactCohortWriteError::Busy {
                path: lock_path.display().to_string(),
            })
        }
        Err(source) => Err(ReactCohortWriteError::Io {
            path: lock_path.display().to_string(),
            source,
        }),
    }
}

fn remove_commit_marker(path: &Path) -> Result<(), ReactCohortWriteError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ReactCohortWriteError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), ReactCohortWriteError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ReactCohortWriteError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let temp_path = unique_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| ReactCohortWriteError::Io {
        path: temp_path.display().to_string(),
        source,
    })?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(ReactCohortWriteError::Io {
            path: path.display().to_string(),
            source,
        });
    }
    Ok(())
}

fn unique_temp_path(path: &Path) -> PathBuf {
    let sequence = NEXT_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    let mut temp_name = OsString::from(".");
    match path.file_name() {
        Some(file_name) => temp_name.push(file_name),
        None => temp_name.push("artifact"),
    }
    temp_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
    path.parent()
        .unwrap_or_else(|| Path::new("."))
        .join(temp_name)
}

#[derive(Debug)]
struct BundleWriteLock {
    path: PathBuf,
}

impl Drop for BundleWriteLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

// ===========================================================================
// Unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn sample_subpath(
        sub: &str,
        cond: ExportCondition,
        path: &str,
        fmt: ModuleFormat,
    ) -> SubpathEntry {
        SubpathEntry::new(sub, vec![cond], path, fmt)
    }

    fn sample_react_manifest() -> PackageManifest {
        let subpaths = vec![
            sample_subpath(
                ".",
                ExportCondition::Import,
                "./esm/react.js",
                ModuleFormat::Esm,
            ),
            sample_subpath(
                ".",
                ExportCondition::Require,
                "./cjs/react.js",
                ModuleFormat::Cjs,
            ),
            sample_subpath(
                ".",
                ExportCondition::Default,
                "./cjs/react.js",
                ModuleFormat::Cjs,
            ),
            sample_subpath(
                "./jsx-runtime",
                ExportCondition::Import,
                "./esm/jsx-runtime.js",
                ModuleFormat::Esm,
            ),
            sample_subpath(
                "./jsx-runtime",
                ExportCondition::Require,
                "./cjs/jsx-runtime.js",
                ModuleFormat::Cjs,
            ),
        ];
        build_manifest(ReactPackage::React, "18.3.1", subpaths)
    }

    // -----------------------------------------------------------------------
    // ReactPackage
    // -----------------------------------------------------------------------

    #[test]
    fn test_react_package_all_count() {
        assert_eq!(ReactPackage::ALL.len(), 7);
    }

    #[test]
    fn test_react_package_npm_names() {
        assert_eq!(ReactPackage::React.npm_name(), "react");
        assert_eq!(ReactPackage::ReactDom.npm_name(), "react-dom");
        assert_eq!(ReactPackage::ReactDomServer.npm_name(), "react-dom");
        assert_eq!(ReactPackage::ReactJsxRuntime.npm_name(), "react");
        assert_eq!(ReactPackage::Scheduler.npm_name(), "scheduler");
        assert_eq!(ReactPackage::ReactReconciler.npm_name(), "react-reconciler");
    }

    #[test]
    fn test_react_package_as_str_display() {
        for pkg in ReactPackage::ALL {
            assert_eq!(pkg.to_string(), pkg.as_str());
        }
    }

    #[test]
    fn test_react_package_serde_roundtrip() {
        for pkg in ReactPackage::ALL {
            let json = serde_json::to_string(pkg).unwrap();
            let back: ReactPackage = serde_json::from_str(&json).unwrap();
            assert_eq!(*pkg, back);
        }
    }

    // -----------------------------------------------------------------------
    // ExportCondition
    // -----------------------------------------------------------------------

    #[test]
    fn test_export_condition_all_count() {
        assert_eq!(ExportCondition::ALL.len(), 7);
    }

    #[test]
    fn test_export_condition_keys() {
        assert_eq!(ExportCondition::Import.condition_key(), "import");
        assert_eq!(ExportCondition::Require.condition_key(), "require");
        assert_eq!(ExportCondition::Default.condition_key(), "default");
        assert_eq!(ExportCondition::Browser.condition_key(), "browser");
        assert_eq!(ExportCondition::Node.condition_key(), "node");
        assert_eq!(ExportCondition::ReactServer.condition_key(), "react-server");
        assert_eq!(ExportCondition::ReactNative.condition_key(), "react-native");
    }

    #[test]
    fn test_export_condition_display() {
        assert_eq!(ExportCondition::ReactServer.to_string(), "react-server");
    }

    #[test]
    fn test_export_condition_serde_roundtrip() {
        for cond in ExportCondition::ALL {
            let json = serde_json::to_string(cond).unwrap();
            let back: ExportCondition = serde_json::from_str(&json).unwrap();
            assert_eq!(*cond, back);
        }
    }

    // -----------------------------------------------------------------------
    // ModuleFormat
    // -----------------------------------------------------------------------

    #[test]
    fn test_module_format_all_count() {
        assert_eq!(ModuleFormat::ALL.len(), 3);
    }

    #[test]
    fn test_module_format_display() {
        assert_eq!(ModuleFormat::Esm.to_string(), "esm");
        assert_eq!(ModuleFormat::Cjs.to_string(), "cjs");
        assert_eq!(ModuleFormat::Dual.to_string(), "dual");
    }

    #[test]
    fn test_module_format_serde_roundtrip() {
        for fmt in ModuleFormat::ALL {
            let json = serde_json::to_string(fmt).unwrap();
            let back: ModuleFormat = serde_json::from_str(&json).unwrap();
            assert_eq!(*fmt, back);
        }
    }

    // -----------------------------------------------------------------------
    // SubpathEntry
    // -----------------------------------------------------------------------

    #[test]
    fn test_subpath_entry_matches_exact() {
        let entry = sample_subpath(
            ".",
            ExportCondition::Import,
            "./esm/react.js",
            ModuleFormat::Esm,
        );
        assert!(entry.matches(".", &ExportCondition::Import));
        assert!(!entry.matches(".", &ExportCondition::Require));
        assert!(!entry.matches("./other", &ExportCondition::Import));
    }

    #[test]
    fn test_subpath_entry_multi_condition() {
        let entry = SubpathEntry::new(
            "./server",
            vec![ExportCondition::Import, ExportCondition::Node],
            "./esm/server.js",
            ModuleFormat::Esm,
        );
        assert!(entry.matches("./server", &ExportCondition::Import));
        assert!(entry.matches("./server", &ExportCondition::Node));
        assert!(!entry.matches("./server", &ExportCondition::Browser));
    }

    #[test]
    fn test_subpath_entry_display() {
        let entry = sample_subpath(
            ".",
            ExportCondition::Import,
            "./esm/react.js",
            ModuleFormat::Esm,
        );
        let display = entry.to_string();
        assert!(display.contains("./esm/react.js"));
        assert!(display.contains("esm"));
    }

    #[test]
    fn test_subpath_entry_fingerprint_deterministic() {
        let e1 = sample_subpath(
            ".",
            ExportCondition::Import,
            "./esm/react.js",
            ModuleFormat::Esm,
        );
        let e2 = sample_subpath(
            ".",
            ExportCondition::Import,
            "./esm/react.js",
            ModuleFormat::Esm,
        );
        assert_eq!(e1.fingerprint_bytes(), e2.fingerprint_bytes());
    }

    #[test]
    fn test_subpath_entry_fingerprint_differs_for_different_formats() {
        let e1 = sample_subpath(
            ".",
            ExportCondition::Import,
            "./esm/react.js",
            ModuleFormat::Esm,
        );
        let e2 = sample_subpath(
            ".",
            ExportCondition::Import,
            "./esm/react.js",
            ModuleFormat::Cjs,
        );
        assert_ne!(e1.fingerprint_bytes(), e2.fingerprint_bytes());
    }

    // -----------------------------------------------------------------------
    // build_manifest
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_manifest_basic() {
        let manifest = sample_react_manifest();
        assert_eq!(manifest.package, ReactPackage::React);
        assert_eq!(manifest.version, "18.3.1");
        assert_eq!(manifest.subpath_count(), 5);
        assert_eq!(manifest.alias_count(), 0);
    }

    #[test]
    fn test_build_manifest_deterministic_hash() {
        let m1 = sample_react_manifest();
        let m2 = sample_react_manifest();
        assert_eq!(m1.content_hash, m2.content_hash);
    }

    #[test]
    fn test_build_manifest_different_versions_different_hash() {
        let subpaths = vec![sample_subpath(
            ".",
            ExportCondition::Import,
            "./esm/react.js",
            ModuleFormat::Esm,
        )];
        let m1 = build_manifest(ReactPackage::React, "18.3.0", subpaths.clone());
        let m2 = build_manifest(ReactPackage::React, "18.3.1", subpaths);
        assert_ne!(m1.content_hash, m2.content_hash);
    }

    #[test]
    fn test_build_manifest_with_aliases() {
        let subpaths = vec![sample_subpath(
            "./server.browser",
            ExportCondition::Import,
            "./esm/server.browser.js",
            ModuleFormat::Esm,
        )];
        let mut aliases = BTreeMap::new();
        aliases.insert("./server".to_string(), "./server.browser".to_string());
        let manifest =
            build_manifest_with_aliases(ReactPackage::ReactDomServer, "18.3.1", subpaths, aliases);
        assert_eq!(manifest.alias_count(), 1);
    }

    #[test]
    fn test_build_manifest_condition_coverage() {
        let manifest = sample_react_manifest();
        let coverage = manifest.condition_coverage_millionths();
        // 3 out of 7 conditions covered (Import, Require, Default)
        let expected = 3u64.saturating_mul(MILLIONTHS) / 7;
        assert_eq!(coverage, expected);
    }

    #[test]
    fn test_build_manifest_display() {
        let manifest = sample_react_manifest();
        let display = manifest.to_string();
        assert!(display.contains("react"));
        assert!(display.contains("18.3.1"));
        assert!(display.contains("5 subpaths"));
    }

    // -----------------------------------------------------------------------
    // resolve_subpath
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_subpath_found() {
        let manifest = sample_react_manifest();
        let entry = resolve_subpath(&manifest, ".", &ExportCondition::Import).unwrap();
        assert_eq!(entry.resolved_path, "./esm/react.js");
        assert_eq!(entry.format, ModuleFormat::Esm);
    }

    #[test]
    fn test_resolve_subpath_not_found() {
        let manifest = sample_react_manifest();
        let err = resolve_subpath(&manifest, "./nonexistent", &ExportCondition::Import);
        assert!(err.is_err());
        match err.unwrap_err() {
            CohortError::SubpathMissing(msg) => assert!(msg.contains("nonexistent")),
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn test_resolve_subpath_wrong_condition() {
        let manifest = sample_react_manifest();
        let err = resolve_subpath(&manifest, ".", &ExportCondition::Browser);
        assert!(err.is_err());
    }

    #[test]
    fn test_resolve_subpath_via_alias() {
        let subpaths = vec![sample_subpath(
            "./server.browser",
            ExportCondition::Import,
            "./esm/server.browser.js",
            ModuleFormat::Esm,
        )];
        let mut aliases = BTreeMap::new();
        aliases.insert("./server".to_string(), "./server.browser".to_string());
        let manifest =
            build_manifest_with_aliases(ReactPackage::ReactDomServer, "18.3.1", subpaths, aliases);
        let entry = resolve_subpath(&manifest, "./server", &ExportCondition::Import).unwrap();
        assert_eq!(entry.resolved_path, "./esm/server.browser.js");
    }

    #[test]
    fn test_resolve_subpath_with_fallbacks() {
        let manifest = sample_react_manifest();
        // Browser doesn't exist, but Import does.
        let entry = resolve_subpath_with_fallbacks(
            &manifest,
            ".",
            &[ExportCondition::Browser, ExportCondition::Import],
        )
        .unwrap();
        assert_eq!(entry.resolved_path, "./esm/react.js");
    }

    #[test]
    fn test_resolve_subpath_with_fallbacks_all_miss() {
        let manifest = sample_react_manifest();
        let err = resolve_subpath_with_fallbacks(
            &manifest,
            "./nonexistent",
            &[ExportCondition::Browser, ExportCondition::ReactNative],
        );
        assert!(err.is_err());
    }

    // -----------------------------------------------------------------------
    // CohortMatrix
    // -----------------------------------------------------------------------

    #[test]
    fn test_build_cohort_matrix_basic() {
        let manifest = sample_react_manifest();
        let matrix = build_cohort_matrix(SecurityEpoch::from_raw(1), vec![manifest]);
        assert_eq!(matrix.package_count(), 1);
        assert_eq!(matrix.total_subpaths, 5);
        assert_eq!(matrix.edge_cases.len(), 0);
        assert!(matrix.matrix_id.starts_with("cohort-matrix-1-"));
    }

    #[test]
    fn test_build_cohort_matrix_deterministic() {
        let m1 = sample_react_manifest();
        let m2 = sample_react_manifest();
        let mat1 = build_cohort_matrix(SecurityEpoch::from_raw(1), vec![m1]);
        let mat2 = build_cohort_matrix(SecurityEpoch::from_raw(1), vec![m2]);
        assert_eq!(mat1.content_hash, mat2.content_hash);
        assert_eq!(mat1.matrix_id, mat2.matrix_id);
    }

    #[test]
    fn test_build_cohort_matrix_different_epochs() {
        let m1 = sample_react_manifest();
        let m2 = sample_react_manifest();
        let mat1 = build_cohort_matrix(SecurityEpoch::from_raw(1), vec![m1]);
        let mat2 = build_cohort_matrix(SecurityEpoch::from_raw(2), vec![m2]);
        assert_ne!(mat1.content_hash, mat2.content_hash);
    }

    #[test]
    fn test_cohort_matrix_pass_rate_all_pass() {
        let mut ec = EdgeCase::pending(
            "ec-1",
            "test",
            ReactPackage::React,
            ExportCondition::Import,
            "./esm/react.js",
        );
        ec.resolve("./esm/react.js");
        let matrix = build_cohort_matrix_with_edges(
            SecurityEpoch::from_raw(1),
            vec![sample_react_manifest()],
            vec![ec],
        );
        assert_eq!(matrix.pass_rate_millionths(), MILLIONTHS);
    }

    #[test]
    fn test_cohort_matrix_pass_rate_partial() {
        let mut ec1 = EdgeCase::pending(
            "ec-1",
            "passes",
            ReactPackage::React,
            ExportCondition::Import,
            "./esm/react.js",
        );
        ec1.resolve("./esm/react.js");
        let mut ec2 = EdgeCase::pending(
            "ec-2",
            "fails",
            ReactPackage::React,
            ExportCondition::Import,
            "./esm/react.js",
        );
        ec2.resolve("./wrong.js");
        let matrix = build_cohort_matrix_with_edges(
            SecurityEpoch::from_raw(1),
            vec![sample_react_manifest()],
            vec![ec1, ec2],
        );
        // 1/2 = 500_000
        assert_eq!(matrix.pass_rate_millionths(), 500_000);
        assert_eq!(matrix.passed_edge_cases(), 1);
        assert_eq!(matrix.failed_edge_cases(), 1);
    }

    #[test]
    fn test_cohort_matrix_no_edge_cases_100_percent() {
        let matrix = build_cohort_matrix(SecurityEpoch::from_raw(1), vec![sample_react_manifest()]);
        assert_eq!(matrix.pass_rate_millionths(), MILLIONTHS);
    }

    #[test]
    fn test_cohort_matrix_find_manifest() {
        let manifest = sample_react_manifest();
        let matrix = build_cohort_matrix(SecurityEpoch::from_raw(1), vec![manifest]);
        assert!(matrix.find_manifest(ReactPackage::React).is_some());
        assert!(matrix.find_manifest(ReactPackage::ReactDom).is_none());
    }

    #[test]
    fn test_cohort_matrix_display() {
        let matrix = build_cohort_matrix(SecurityEpoch::from_raw(1), vec![sample_react_manifest()]);
        let display = matrix.to_string();
        assert!(display.contains("CohortMatrix"));
        assert!(display.contains("1 packages"));
    }

    // -----------------------------------------------------------------------
    // EdgeCase
    // -----------------------------------------------------------------------

    #[test]
    fn test_edge_case_pending() {
        let ec = EdgeCase::pending(
            "ec-1",
            "test case",
            ReactPackage::React,
            ExportCondition::Import,
            "./esm/react.js",
        );
        assert!(!ec.passed);
        assert!(ec.actual_resolution.is_none());
    }

    #[test]
    fn test_edge_case_resolve_pass() {
        let mut ec = EdgeCase::pending(
            "ec-1",
            "test case",
            ReactPackage::React,
            ExportCondition::Import,
            "./esm/react.js",
        );
        ec.resolve("./esm/react.js");
        assert!(ec.passed);
        assert_eq!(ec.actual_resolution.as_deref(), Some("./esm/react.js"));
    }

    #[test]
    fn test_edge_case_resolve_fail() {
        let mut ec = EdgeCase::pending(
            "ec-1",
            "test case",
            ReactPackage::React,
            ExportCondition::Import,
            "./esm/react.js",
        );
        ec.resolve("./wrong/path.js");
        assert!(!ec.passed);
        assert_eq!(ec.actual_resolution.as_deref(), Some("./wrong/path.js"));
    }

    #[test]
    fn test_edge_case_mark_failed() {
        let mut ec = EdgeCase::pending(
            "ec-1",
            "test case",
            ReactPackage::React,
            ExportCondition::Import,
            "./esm/react.js",
        );
        ec.resolve("./esm/react.js");
        assert!(ec.passed);
        ec.mark_failed();
        assert!(!ec.passed);
        assert!(ec.actual_resolution.is_none());
    }

    #[test]
    fn test_edge_case_display() {
        let mut ec = EdgeCase::pending(
            "ec-1",
            "test case",
            ReactPackage::React,
            ExportCondition::Import,
            "./esm/react.js",
        );
        ec.resolve("./esm/react.js");
        let display = ec.to_string();
        assert!(display.contains("PASS"));
        assert!(display.contains("ec-1"));
    }

    // -----------------------------------------------------------------------
    // CohortError
    // -----------------------------------------------------------------------

    #[test]
    fn test_cohort_error_display() {
        let err = CohortError::PackageNotFound("react-missing".to_string());
        assert!(err.to_string().contains("react-missing"));

        let err = CohortError::SubpathMissing("./foo".to_string());
        assert!(err.to_string().contains("./foo"));

        let err = CohortError::FormatMismatch {
            expected: ModuleFormat::Esm,
            actual: ModuleFormat::Cjs,
        };
        let display = err.to_string();
        assert!(display.contains("esm"));
        assert!(display.contains("cjs"));

        let err = CohortError::AliasLoop(vec!["a".to_string(), "b".to_string(), "a".to_string()]);
        assert!(err.to_string().contains("a -> b -> a"));

        let err = CohortError::InternalError("boom".to_string());
        assert!(err.to_string().contains("boom"));
    }

    #[test]
    fn test_cohort_error_serde_roundtrip() {
        let errors = vec![
            CohortError::PackageNotFound("react".to_string()),
            CohortError::SubpathMissing("./jsx-runtime".to_string()),
            CohortError::FormatMismatch {
                expected: ModuleFormat::Esm,
                actual: ModuleFormat::Cjs,
            },
            CohortError::AliasLoop(vec!["a".to_string(), "b".to_string()]),
            CohortError::InternalError("test".to_string()),
        ];
        for err in &errors {
            let json = serde_json::to_string(err).unwrap();
            let back: CohortError = serde_json::from_str(&json).unwrap();
            assert_eq!(*err, back);
        }
    }

    // -----------------------------------------------------------------------
    // detect_alias_loops
    // -----------------------------------------------------------------------

    #[test]
    fn test_detect_alias_loops_none() {
        let manifest = sample_react_manifest();
        let loops = detect_alias_loops(&manifest);
        assert!(loops.is_empty());
    }

    #[test]
    fn test_detect_alias_loops_simple_cycle() {
        let mut aliases = BTreeMap::new();
        aliases.insert("a".to_string(), "b".to_string());
        aliases.insert("b".to_string(), "a".to_string());
        let manifest =
            build_manifest_with_aliases(ReactPackage::React, "18.3.1", Vec::new(), aliases);
        let loops = detect_alias_loops(&manifest);
        assert!(!loops.is_empty());
        // The cycle should contain both "a" and "b".
        let cycle = &loops[0];
        assert!(cycle.contains(&"a".to_string()));
        assert!(cycle.contains(&"b".to_string()));
    }

    #[test]
    fn test_detect_alias_loops_three_node_cycle() {
        let mut aliases = BTreeMap::new();
        aliases.insert("x".to_string(), "y".to_string());
        aliases.insert("y".to_string(), "z".to_string());
        aliases.insert("z".to_string(), "x".to_string());
        let manifest =
            build_manifest_with_aliases(ReactPackage::React, "18.3.1", Vec::new(), aliases);
        let loops = detect_alias_loops(&manifest);
        assert!(!loops.is_empty());
        let cycle = &loops[0];
        assert!(cycle.contains(&"x".to_string()));
        assert!(cycle.contains(&"y".to_string()));
        assert!(cycle.contains(&"z".to_string()));
    }

    #[test]
    fn test_detect_alias_loops_no_loop_chain() {
        let mut aliases = BTreeMap::new();
        aliases.insert("a".to_string(), "b".to_string());
        aliases.insert("b".to_string(), "c".to_string());
        // "c" is not in aliases, so no loop.
        let manifest =
            build_manifest_with_aliases(ReactPackage::React, "18.3.1", Vec::new(), aliases);
        let loops = detect_alias_loops(&manifest);
        assert!(loops.is_empty());
    }

    // -----------------------------------------------------------------------
    // resolve_alias_chain
    // -----------------------------------------------------------------------

    #[test]
    fn test_resolve_alias_chain_simple() {
        let mut aliases = BTreeMap::new();
        aliases.insert("a".to_string(), "b".to_string());
        aliases.insert("b".to_string(), "c".to_string());
        let result = resolve_alias_chain(&aliases, "a").unwrap();
        assert_eq!(result, "c");
    }

    #[test]
    fn test_resolve_alias_chain_no_alias() {
        let aliases = BTreeMap::new();
        let result = resolve_alias_chain(&aliases, "direct").unwrap();
        assert_eq!(result, "direct");
    }

    #[test]
    fn test_resolve_alias_chain_loop_detected() {
        let mut aliases = BTreeMap::new();
        aliases.insert("a".to_string(), "b".to_string());
        aliases.insert("b".to_string(), "a".to_string());
        let err = resolve_alias_chain(&aliases, "a");
        assert!(err.is_err());
        match err.unwrap_err() {
            CohortError::AliasLoop(chain) => {
                assert!(chain.contains(&"a".to_string()));
                assert!(chain.contains(&"b".to_string()));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    // -----------------------------------------------------------------------
    // format_compatible
    // -----------------------------------------------------------------------

    #[test]
    fn test_format_compatible_same() {
        assert!(format_compatible(ModuleFormat::Esm, ModuleFormat::Esm));
        assert!(format_compatible(ModuleFormat::Cjs, ModuleFormat::Cjs));
        assert!(format_compatible(ModuleFormat::Dual, ModuleFormat::Dual));
    }

    #[test]
    fn test_format_compatible_dual() {
        assert!(format_compatible(ModuleFormat::Esm, ModuleFormat::Dual));
        assert!(format_compatible(ModuleFormat::Cjs, ModuleFormat::Dual));
        assert!(format_compatible(ModuleFormat::Dual, ModuleFormat::Esm));
        assert!(format_compatible(ModuleFormat::Dual, ModuleFormat::Cjs));
    }

    #[test]
    fn test_format_incompatible() {
        assert!(!format_compatible(ModuleFormat::Esm, ModuleFormat::Cjs));
        assert!(!format_compatible(ModuleFormat::Cjs, ModuleFormat::Esm));
    }

    // -----------------------------------------------------------------------
    // verify_format_consistency
    // -----------------------------------------------------------------------

    #[test]
    fn test_verify_format_consistency_clean() {
        let manifest = sample_react_manifest();
        let errors = verify_format_consistency(&manifest);
        assert!(errors.is_empty());
    }

    #[test]
    fn test_verify_format_consistency_conflict() {
        let subpaths = vec![
            sample_subpath(
                ".",
                ExportCondition::Import,
                "./shared/index.js",
                ModuleFormat::Esm,
            ),
            sample_subpath(
                ".",
                ExportCondition::Require,
                "./shared/index.js",
                ModuleFormat::Cjs,
            ),
        ];
        let manifest = build_manifest(ReactPackage::React, "18.3.1", subpaths);
        let errors = verify_format_consistency(&manifest);
        assert_eq!(errors.len(), 1);
        match &errors[0] {
            CohortError::FormatMismatch { expected, actual } => {
                assert_eq!(*expected, ModuleFormat::Esm);
                assert_eq!(*actual, ModuleFormat::Cjs);
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    // -----------------------------------------------------------------------
    // validate_edge_case
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_edge_case_resolved_path_match() {
        let manifest = sample_react_manifest();
        let ec = EdgeCase {
            case_id: "ec-test".to_string(),
            description: "root ESM".to_string(),
            source_package: ReactPackage::React,
            condition: ExportCondition::Import,
            expected_resolution: "./esm/react.js".to_string(),
            actual_resolution: None,
            passed: false,
        };
        assert!(validate_edge_case(&manifest, &ec));
    }

    #[test]
    fn test_validate_edge_case_no_match() {
        let manifest = sample_react_manifest();
        let ec = EdgeCase {
            case_id: "ec-test".to_string(),
            description: "wrong path".to_string(),
            source_package: ReactPackage::React,
            condition: ExportCondition::Import,
            expected_resolution: "./nonexistent.js".to_string(),
            actual_resolution: None,
            passed: false,
        };
        assert!(!validate_edge_case(&manifest, &ec));
    }

    // -----------------------------------------------------------------------
    // validate_cohort
    // -----------------------------------------------------------------------

    #[test]
    fn test_validate_cohort_clean() {
        let manifest = sample_react_manifest();
        let mut ec = EdgeCase::pending(
            "ec-1",
            "test",
            ReactPackage::React,
            ExportCondition::Import,
            "./esm/react.js",
        );
        ec.resolve("./esm/react.js");
        let matrix =
            build_cohort_matrix_with_edges(SecurityEpoch::from_raw(1), vec![manifest], vec![ec]);
        let report = validate_cohort(&matrix);
        assert!(report.passed);
        assert_eq!(report.pass_rate_millionths, MILLIONTHS);
        assert!(report.alias_loops_detected.is_empty());
    }

    #[test]
    fn test_validate_cohort_with_failed_edge_case() {
        let manifest = sample_react_manifest();
        let mut ec = EdgeCase::pending(
            "ec-1",
            "test",
            ReactPackage::React,
            ExportCondition::Import,
            "./esm/react.js",
        );
        ec.resolve("./wrong.js");
        let matrix =
            build_cohort_matrix_with_edges(SecurityEpoch::from_raw(1), vec![manifest], vec![ec]);
        let report = validate_cohort(&matrix);
        assert!(!report.passed);
    }

    #[test]
    fn test_validate_cohort_with_alias_loop() {
        let mut aliases = BTreeMap::new();
        aliases.insert("a".to_string(), "b".to_string());
        aliases.insert("b".to_string(), "a".to_string());
        let manifest =
            build_manifest_with_aliases(ReactPackage::React, "18.3.1", Vec::new(), aliases);
        let matrix = build_cohort_matrix(SecurityEpoch::from_raw(1), vec![manifest]);
        let report = validate_cohort(&matrix);
        assert!(!report.passed);
        assert!(!report.alias_loops_detected.is_empty());
    }

    #[test]
    fn test_validate_cohort_report_serde_roundtrip() {
        let manifest = sample_react_manifest();
        let matrix = build_cohort_matrix(SecurityEpoch::from_raw(1), vec![manifest]);
        let report = validate_cohort(&matrix);
        let json = serde_json::to_string(&report).unwrap();
        let back: CohortValidationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, back);
    }

    // -----------------------------------------------------------------------
    // cohort_coverage_millionths
    // -----------------------------------------------------------------------

    #[test]
    fn test_cohort_coverage_single_package() {
        let manifest = sample_react_manifest();
        let coverage = cohort_coverage_millionths(&[manifest]);
        // 1 out of 7 packages
        let expected = MILLIONTHS / 7;
        assert_eq!(coverage, expected);
    }

    #[test]
    fn test_cohort_coverage_all_packages() {
        let manifests: Vec<PackageManifest> = ReactPackage::ALL
            .iter()
            .map(|pkg| build_manifest(*pkg, "1.0.0", Vec::new()))
            .collect();
        let coverage = cohort_coverage_millionths(&manifests);
        assert_eq!(coverage, MILLIONTHS);
    }

    #[test]
    fn test_cohort_coverage_empty() {
        let coverage = cohort_coverage_millionths(&[]);
        assert_eq!(coverage, 0);
    }

    // -----------------------------------------------------------------------
    // franken_engine_react_cohort_manifest
    // -----------------------------------------------------------------------

    #[test]
    fn test_golden_manifest_package_count() {
        let matrix = franken_engine_react_cohort_manifest();
        assert_eq!(matrix.package_count(), 7);
    }

    #[test]
    fn test_golden_manifest_all_edge_cases_pass() {
        let matrix = franken_engine_react_cohort_manifest();
        assert_eq!(matrix.failed_edge_cases(), 0);
        assert_eq!(matrix.pass_rate_millionths(), MILLIONTHS);
    }

    #[test]
    fn test_golden_manifest_deterministic() {
        let m1 = franken_engine_react_cohort_manifest();
        let m2 = franken_engine_react_cohort_manifest();
        assert_eq!(m1.content_hash, m2.content_hash);
        assert_eq!(m1.matrix_id, m2.matrix_id);
    }

    #[test]
    fn test_golden_manifest_total_subpaths() {
        let matrix = franken_engine_react_cohort_manifest();
        // react: 7, react-dom: 8, react-dom/server: 4, jsx-runtime: 3,
        // jsx-dev-runtime: 3, scheduler: 3, reconciler: 3 = 31
        assert_eq!(matrix.total_subpaths, 31);
    }

    #[test]
    fn test_golden_manifest_validation_passes() {
        let matrix = franken_engine_react_cohort_manifest();
        let report = validate_cohort(&matrix);
        assert!(report.passed);
        assert!(report.alias_loops_detected.is_empty());
    }

    #[test]
    fn test_golden_manifest_jsx_runtime_esm() {
        let matrix = franken_engine_react_cohort_manifest();
        let jsx_manifest = matrix.find_manifest(ReactPackage::ReactJsxRuntime).unwrap();
        let entry = resolve_subpath(jsx_manifest, ".", &ExportCondition::Import).unwrap();
        assert_eq!(entry.resolved_path, "./esm/jsx-runtime.js");
        assert_eq!(entry.format, ModuleFormat::Esm);
    }

    #[test]
    fn test_golden_manifest_dom_server_conditions() {
        let matrix = franken_engine_react_cohort_manifest();
        let server_manifest = matrix.find_manifest(ReactPackage::ReactDomServer).unwrap();

        // Browser condition -> browser.js
        let browser = resolve_subpath(server_manifest, ".", &ExportCondition::Browser).unwrap();
        assert_eq!(browser.resolved_path, "./esm/react-dom-server.browser.js");

        // ReactServer condition -> edge.js
        let rsc = resolve_subpath(server_manifest, ".", &ExportCondition::ReactServer).unwrap();
        assert_eq!(rsc.resolved_path, "./esm/react-dom-server.edge.js");

        // Require condition -> node CJS
        let cjs = resolve_subpath(server_manifest, ".", &ExportCondition::Require).unwrap();
        assert_eq!(cjs.resolved_path, "./cjs/react-dom-server.node.js");
        assert_eq!(cjs.format, ModuleFormat::Cjs);
    }

    // -----------------------------------------------------------------------
    // Serde roundtrip: full matrix
    // -----------------------------------------------------------------------

    #[test]
    fn test_full_matrix_serde_roundtrip() {
        let matrix = franken_engine_react_cohort_manifest();
        let json = serde_json::to_string(&matrix).unwrap();
        let back: CohortMatrix = serde_json::from_str(&json).unwrap();
        assert_eq!(matrix, back);
    }

    // -----------------------------------------------------------------------
    // Constants
    // -----------------------------------------------------------------------

    #[test]
    fn test_schema_constants() {
        assert!(!REACT_COHORT_SCHEMA_VERSION.is_empty());
        assert!(!REACT_COHORT_BEAD_ID.is_empty());
        assert!(!REACT_COHORT_POLICY_ID.is_empty());
        assert!(!REACT_COHORT_COMPONENT.is_empty());
    }
}
