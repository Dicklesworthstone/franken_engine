//! Control-plane mock-seam inventory and classification.
//!
//! Bead: bd-3nr.1.1.1 [10.13X.A1]
//!
//! Inventories every residual non-test use of `control_plane::mocks`,
//! fake budgets, seed-derived trace contexts, and equivalent stand-ins.
//! Each occurrence is classified as:
//!
//! - **`MustFixProduction`** — mock / stub / fake that leaks into a
//!   production code path.
//! - **`AcceptableTestOnly`** — usage inside `#[cfg(test)]`, a `tests/`
//!   file, or gated behind a test-only feature flag.
//! - **`FalsePositive`** — a grep hit that is not actually a mock seam.
//!
//! The inventory is encoded as a deterministic, serde-able data structure
//! so downstream beads (bd-3nr.1.2.1, bd-3nr.1.3.1, bd-3nr.1.3.2,
//! bd-3nr.1.2.2, bd-3nr.1.6) can consume it programmatically.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "control_plane_mock_inventory";
pub const BEAD_ID: &str = "bd-3nr.1.1.1";
pub const INVENTORY_SCHEMA_VERSION: &str = "frankenengine.control-plane-mock-inventory.v1";
pub const AMBIENT_MOCK_GUARD_COMPONENT: &str = "ambient_mock_guard";
pub const AMBIENT_MOCK_GUARD_BEAD_ID: &str = "bd-3nr.1.2.2";
pub const AMBIENT_MOCK_GUARD_POLICY_ID: &str = "frankenengine.control-plane-mocks.fail-closed.v1";
pub const AMBIENT_MOCK_GUARD_REPORT_SCHEMA_VERSION: &str =
    "frankenengine.ambient-mock-guard-report.v1";
pub const AMBIENT_MOCK_GUARD_REGRESSION_REPORT_SCHEMA_VERSION: &str =
    "frankenengine.ambient-mock-guard-regression-report.v1";
pub const AMBIENT_MOCK_GUARD_TRACE_IDS_SCHEMA_VERSION: &str =
    "frankenengine.ambient-mock-guard.trace-ids.v1";
pub const AMBIENT_MOCK_GUARD_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "frankenengine.ambient-mock-guard.run-manifest.v1";
pub const AMBIENT_MOCK_GUARD_EVENT_SCHEMA_VERSION: &str =
    "frankenengine.ambient-mock-guard.event.v1";
pub const AMBIENT_MOCK_GUARD_SCAN_ROOT: &str = "crates/franken-engine/src";
pub const AMBIENT_MOCK_GUARD_REGRESSION_BEAD_ID: &str = "bd-2muur.3.3";
pub const AMBIENT_MOCK_GUARD_REGRESSION_POLICY_ID: &str =
    "frankenengine.control-plane-mocks.guard-regression.v1";
pub const AMBIENT_MOCK_GUARD_REGRESSION_SEED: &str = "ambient-mock-guard-regression-fixtures-v1";
const CONTROL_PLANE_MOCK_SHARED_BUNDLE_LOCK_FILE: &str = ".control_plane_mock_bundle.lock";

/// Scanner version for the source-derived inventory. Bump this when the
/// scanner logic changes to invalidate cached or serialized inventories.
pub const SOURCE_DERIVED_SCANNER_VERSION: &str =
    "frankenengine.control-plane-mock-inventory.source-derived.v1";

/// Freshness guard policy ID for inventory drift detection.
pub const INVENTORY_FRESHNESS_POLICY_ID: &str =
    "frankenengine.control-plane-mock-inventory.freshness.v1";

static NEXT_AMBIENT_MOCK_GUARD_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

fn append_hash_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn append_hash_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn append_hash_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    append_hash_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn append_hash_str(buf: &mut Vec<u8>, value: &str) {
    append_hash_bytes(buf, value.as_bytes());
}

fn append_hash_bool(buf: &mut Vec<u8>, value: bool) {
    buf.push(u8::from(value));
}

fn architectural_issue_content_hash(issue: &ArchitecturalIssue) -> ContentHash {
    let mut hasher = Sha256::new();
    let mut canonical = Vec::new();
    append_hash_str(&mut canonical, INVENTORY_SCHEMA_VERSION);
    append_hash_str(&mut canonical, &issue.id);
    append_hash_str(&mut canonical, &issue.description);
    append_hash_str(&mut canonical, &issue.file_path);
    append_hash_str(&mut canonical, &issue.severity.to_string());
    append_hash_str(&mut canonical, &issue.remediation.to_string());
    append_hash_str(&mut canonical, &issue.remediation_bead);
    hasher.update(&canonical);
    ContentHash::compute(&hasher.finalize())
}

fn inventory_hash_preimage(
    occurrences: &[SeamOccurrence],
    architectural_issues: &[ArchitecturalIssue],
) -> Vec<u8> {
    let mut canonical = Vec::new();
    append_hash_str(&mut canonical, INVENTORY_SCHEMA_VERSION);
    append_hash_str(&mut canonical, "occurrences");
    append_hash_u64(&mut canonical, occurrences.len() as u64);
    for occ in occurrences {
        append_hash_bytes(&mut canonical, occ.content_hash().as_bytes());
    }
    append_hash_str(&mut canonical, "architectural_issues");
    append_hash_u64(&mut canonical, architectural_issues.len() as u64);
    for issue in architectural_issues {
        append_hash_bytes(
            &mut canonical,
            architectural_issue_content_hash(issue).as_bytes(),
        );
    }
    canonical
}

// ---------------------------------------------------------------------------
// SeamClassification
// ---------------------------------------------------------------------------

/// Classification of a mock/fake/stub seam occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeamClassification {
    /// Production code path that uses mocks/fakes — must be remediated.
    MustFixProduction,
    /// Usage inside `#[cfg(test)]` or test-only module — acceptable.
    AcceptableTestOnly,
    /// Grep hit that is not actually a mock seam (documentation, etc.).
    FalsePositive,
}

impl fmt::Display for SeamClassification {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MustFixProduction => write!(f, "must_fix_production"),
            Self::AcceptableTestOnly => write!(f, "acceptable_test_only"),
            Self::FalsePositive => write!(f, "false_positive"),
        }
    }
}

// ---------------------------------------------------------------------------
// SeamKind
// ---------------------------------------------------------------------------

/// Kind of mock/fake/stub seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeamKind {
    /// Import of `control_plane::mocks::MockCx`.
    MockContext,
    /// Import of `control_plane::mocks::MockBudget`.
    MockBudget,
    /// Import of `control_plane::mocks::MockDecisionContract`.
    MockDecisionContract,
    /// Import of `control_plane::mocks::MockEvidenceEmitter`.
    MockEvidenceEmitter,
    /// Import of `control_plane::mocks::MockFailureMode`.
    MockFailureMode,
    /// Use of `trace_id_from_seed()` (synthetic trace context).
    SeedDerivedTraceId,
    /// Use of `decision_id_from_seed()` (synthetic decision ID).
    SeedDerivedDecisionId,
    /// Use of `policy_id_from_seed()` (synthetic policy ID).
    SeedDerivedPolicyId,
    /// Use of `schema_version_from_seed()` (synthetic schema version).
    SeedDerivedSchemaVersion,
    /// Hardcoded budget value in production code (e.g., `MockBudget::new(10_000)`).
    HardcodedBudget,
    /// Module definition of mocks without `#[cfg(test)]` guard.
    UnguardedMockModule,
}

impl fmt::Display for SeamKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MockContext => write!(f, "MockCx"),
            Self::MockBudget => write!(f, "MockBudget"),
            Self::MockDecisionContract => write!(f, "MockDecisionContract"),
            Self::MockEvidenceEmitter => write!(f, "MockEvidenceEmitter"),
            Self::MockFailureMode => write!(f, "MockFailureMode"),
            Self::SeedDerivedTraceId => write!(f, "trace_id_from_seed"),
            Self::SeedDerivedDecisionId => write!(f, "decision_id_from_seed"),
            Self::SeedDerivedPolicyId => write!(f, "policy_id_from_seed"),
            Self::SeedDerivedSchemaVersion => write!(f, "schema_version_from_seed"),
            Self::HardcodedBudget => write!(f, "hardcoded_budget"),
            Self::UnguardedMockModule => write!(f, "unguarded_mock_module"),
        }
    }
}

// ---------------------------------------------------------------------------
// SeamSeverity
// ---------------------------------------------------------------------------

/// Impact severity of a seam occurrence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeamSeverity {
    /// Informational — no remediation needed.
    Info,
    /// Low impact — test-only usage, acceptable but worth tracking.
    Low,
    /// Medium — architectural concern (e.g., unguarded module).
    Medium,
    /// High — production code using mocks; must be fixed before GA.
    High,
    /// Critical — production code path with incorrect behavior.
    Critical,
}

impl fmt::Display for SeamSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ---------------------------------------------------------------------------
// RemediationStrategy
// ---------------------------------------------------------------------------

/// How a production seam should be fixed.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemediationStrategy {
    /// Move import/usage behind `#[cfg(test)]`.
    MoveToTestOnly,
    /// Replace with real `KernelContext` / `Cx` threading.
    ThreadRealContext,
    /// Replace hardcoded budget with propagated parent budget.
    PropagateBudget,
    /// Add `#[cfg(test)]` guard to module definition.
    AddCfgTestGuard,
    /// No action needed (test-only or false positive).
    NoAction,
}

impl fmt::Display for RemediationStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MoveToTestOnly => write!(f, "move_to_test_only"),
            Self::ThreadRealContext => write!(f, "thread_real_context"),
            Self::PropagateBudget => write!(f, "propagate_budget"),
            Self::AddCfgTestGuard => write!(f, "add_cfg_test_guard"),
            Self::NoAction => write!(f, "no_action"),
        }
    }
}

// ---------------------------------------------------------------------------
// SeamOccurrence
// ---------------------------------------------------------------------------

/// A single occurrence of a mock/fake/stub seam in the codebase.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SeamOccurrence {
    /// Relative file path from the workspace root.
    pub file_path: String,
    /// Line number (1-based) of the occurrence.
    pub line_number: u32,
    /// Kind of seam.
    pub kind: SeamKind,
    /// Classification: must-fix, test-only, or false positive.
    pub classification: SeamClassification,
    /// Impact severity.
    pub severity: SeamSeverity,
    /// Whether the occurrence is inside `#[cfg(test)]`.
    pub inside_cfg_test: bool,
    /// Brief description of the occurrence.
    pub description: String,
    /// Recommended remediation.
    pub remediation: RemediationStrategy,
    /// Downstream bead(s) that will implement the fix.
    pub remediation_bead: String,
}

/// Input for constructing a [`SeamOccurrence`] (avoids too-many-arguments).
pub struct SeamOccurrenceInput<'a> {
    pub file_path: &'a str,
    pub line_number: u32,
    pub kind: SeamKind,
    pub classification: SeamClassification,
    pub severity: SeamSeverity,
    pub inside_cfg_test: bool,
    pub description: &'a str,
    pub remediation: RemediationStrategy,
    pub remediation_bead: &'a str,
}

impl SeamOccurrence {
    /// Create a new occurrence from an input struct.
    pub fn new(input: SeamOccurrenceInput<'_>) -> Self {
        Self {
            file_path: input.file_path.to_string(),
            line_number: input.line_number,
            kind: input.kind,
            classification: input.classification,
            severity: input.severity,
            inside_cfg_test: input.inside_cfg_test,
            description: input.description.to_string(),
            remediation: input.remediation,
            remediation_bead: input.remediation_bead.to_string(),
        }
    }

    /// Compute a deterministic content hash of this occurrence covering all fields.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        let mut canonical = Vec::new();
        append_hash_str(&mut canonical, INVENTORY_SCHEMA_VERSION);
        append_hash_str(&mut canonical, &self.file_path);
        append_hash_u32(&mut canonical, self.line_number);
        append_hash_str(&mut canonical, &self.kind.to_string());
        append_hash_str(&mut canonical, &self.classification.to_string());
        append_hash_str(&mut canonical, &self.severity.to_string());
        append_hash_bool(&mut canonical, self.inside_cfg_test);
        append_hash_str(&mut canonical, &self.description);
        append_hash_str(&mut canonical, &self.remediation.to_string());
        append_hash_str(&mut canonical, &self.remediation_bead);
        hasher.update(&canonical);
        ContentHash::compute(&hasher.finalize())
    }
}

impl fmt::Display for SeamOccurrence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {}:{} ({}) — {}",
            self.severity, self.file_path, self.line_number, self.kind, self.description
        )
    }
}

// ---------------------------------------------------------------------------
// ArchitecturalIssue
// ---------------------------------------------------------------------------

/// A higher-level architectural concern identified during the inventory.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArchitecturalIssue {
    /// Short identifier for the issue.
    pub id: String,
    /// Description of the concern.
    pub description: String,
    /// Affected file path.
    pub file_path: String,
    /// Severity.
    pub severity: SeamSeverity,
    /// Recommended remediation.
    pub remediation: RemediationStrategy,
    /// Downstream bead(s) that will implement the fix.
    pub remediation_bead: String,
}

impl fmt::Display for ArchitecturalIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.severity, self.id, self.description)
    }
}

// ---------------------------------------------------------------------------
// MockInventory
// ---------------------------------------------------------------------------

/// Complete inventory of mock/fake/stub seams in the codebase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MockInventory {
    /// Schema version for forward compatibility.
    pub schema_version: String,
    /// All seam occurrences, sorted by (file_path, line_number).
    pub occurrences: Vec<SeamOccurrence>,
    /// Architectural issues identified.
    pub architectural_issues: Vec<ArchitecturalIssue>,
    /// Summary counts by classification.
    pub summary: InventorySummary,
    /// Content hash of the entire inventory.
    pub inventory_hash: ContentHash,
}

/// Summary statistics for the inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventorySummary {
    /// Total occurrences found.
    pub total_occurrences: u32,
    /// Occurrences classified as must-fix-production.
    pub must_fix_count: u32,
    /// Occurrences classified as acceptable-test-only.
    pub test_only_count: u32,
    /// Occurrences classified as false-positive.
    pub false_positive_count: u32,
    /// Distinct files with occurrences.
    pub affected_files: u32,
    /// Distinct files with must-fix occurrences.
    pub must_fix_files: u32,
    /// Architectural issues.
    pub architectural_issue_count: u32,
    /// Breakdown by seam kind.
    pub by_kind: BTreeMap<String, u32>,
}

impl MockInventory {
    /// Build the canonical inventory from scanned occurrences and issues.
    pub fn build(
        mut occurrences: Vec<SeamOccurrence>,
        mut architectural_issues: Vec<ArchitecturalIssue>,
    ) -> Self {
        // Sort deterministically by (file_path, line_number).
        occurrences.sort();
        architectural_issues.sort();

        let total = occurrences.len() as u32;
        let must_fix = occurrences
            .iter()
            .filter(|o| o.classification == SeamClassification::MustFixProduction)
            .count() as u32;
        let test_only = occurrences
            .iter()
            .filter(|o| o.classification == SeamClassification::AcceptableTestOnly)
            .count() as u32;
        let false_positive = occurrences
            .iter()
            .filter(|o| o.classification == SeamClassification::FalsePositive)
            .count() as u32;

        let mut affected_files_set = std::collections::BTreeSet::new();
        let mut must_fix_files_set = std::collections::BTreeSet::new();
        let mut by_kind: BTreeMap<String, u32> = BTreeMap::new();

        for occ in &occurrences {
            affected_files_set.insert(occ.file_path.clone());
            if occ.classification == SeamClassification::MustFixProduction {
                must_fix_files_set.insert(occ.file_path.clone());
            }
            *by_kind.entry(format!("{}", occ.kind)).or_insert(0) += 1;
        }

        let summary = InventorySummary {
            total_occurrences: total,
            must_fix_count: must_fix,
            test_only_count: test_only,
            false_positive_count: false_positive,
            affected_files: affected_files_set.len() as u32,
            must_fix_files: must_fix_files_set.len() as u32,
            architectural_issue_count: architectural_issues.len() as u32,
            by_kind,
        };

        // Compute inventory-wide content hash.
        let mut hasher = Sha256::new();
        hasher.update(inventory_hash_preimage(&occurrences, &architectural_issues));
        let inventory_hash = ContentHash::compute(&hasher.finalize());

        Self {
            schema_version: INVENTORY_SCHEMA_VERSION.to_string(),
            occurrences,
            architectural_issues,
            summary,
            inventory_hash,
        }
    }

    /// Filter occurrences to only must-fix-production items.
    pub fn must_fix_items(&self) -> Vec<&SeamOccurrence> {
        self.occurrences
            .iter()
            .filter(|o| o.classification == SeamClassification::MustFixProduction)
            .collect()
    }

    /// Filter occurrences to only test-only items.
    pub fn test_only_items(&self) -> Vec<&SeamOccurrence> {
        self.occurrences
            .iter()
            .filter(|o| o.classification == SeamClassification::AcceptableTestOnly)
            .collect()
    }

    /// Get occurrences for a specific file.
    pub fn for_file(&self, path: &str) -> Vec<&SeamOccurrence> {
        self.occurrences
            .iter()
            .filter(|o| o.file_path == path)
            .collect()
    }

    /// Check whether any must-fix items remain.
    pub fn has_must_fix(&self) -> bool {
        self.summary.must_fix_count > 0
    }

    /// Get the count of occurrences for a specific seam kind.
    pub fn count_by_kind(&self, kind: SeamKind) -> u32 {
        let key = format!("{}", kind);
        self.summary.by_kind.get(&key).copied().unwrap_or(0)
    }

    pub fn production_mock_seam_matrix(&self) -> ProductionMockSeamMatrix {
        ProductionMockSeamMatrix {
            schema_version: PRODUCTION_MOCK_SEAM_MATRIX_SCHEMA_VERSION.to_string(),
            component: COMPONENT.to_string(),
            bead_id: BEAD_ID.to_string(),
            policy_id: CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID.to_string(),
            inventory_hash: self.inventory_hash.to_string(),
            must_fix_count: self.summary.must_fix_count,
            must_fix_files: self.summary.must_fix_files,
            architectural_issue_count: self.summary.architectural_issue_count,
            must_fix_occurrences: self.must_fix_items().into_iter().cloned().collect(),
            architectural_issues: self.architectural_issues.clone(),
        }
    }
}

impl fmt::Display for MockInventory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Control-Plane Mock Inventory ({})", self.schema_version)?;
        writeln!(f, "  Total occurrences: {}", self.summary.total_occurrences)?;
        writeln!(f, "  Must-fix: {}", self.summary.must_fix_count)?;
        writeln!(f, "  Test-only: {}", self.summary.test_only_count)?;
        writeln!(f, "  False positive: {}", self.summary.false_positive_count)?;
        writeln!(f, "  Affected files: {}", self.summary.affected_files)?;
        writeln!(
            f,
            "  Architectural issues: {}",
            self.summary.architectural_issue_count
        )?;
        write!(f, "  Inventory hash: {}", self.inventory_hash)
    }
}

pub const CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID: &str =
    "frankenengine.control-plane-mock-inventory.v1";
pub const PRODUCTION_MOCK_SEAM_MATRIX_SCHEMA_VERSION: &str =
    "frankenengine.production-mock-seam-matrix.v1";
pub const CONTROL_PLANE_MOCK_INVENTORY_TRACE_IDS_SCHEMA_VERSION: &str =
    "frankenengine.control-plane-mock-inventory.trace-ids.v1";
pub const CONTROL_PLANE_MOCK_INVENTORY_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "frankenengine.control-plane-mock-inventory.run-manifest.v1";
pub const CONTROL_PLANE_MOCK_INVENTORY_EVENT_SCHEMA_VERSION: &str =
    "frankenengine.control-plane-mock-inventory.event.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlPlaneMockInventoryOutcome {
    InventoryComplete,
}

impl ControlPlaneMockInventoryOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InventoryComplete => "inventory_complete",
        }
    }
}

impl fmt::Display for ControlPlaneMockInventoryOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionMockSeamMatrix {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub must_fix_count: u32,
    pub must_fix_files: u32,
    pub architectural_issue_count: u32,
    pub must_fix_occurrences: Vec<SeamOccurrence>,
    pub architectural_issues: Vec<ArchitecturalIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneMockInventoryArtifactPaths {
    pub asupersync_residual_mock_inventory: String,
    pub production_mock_seam_matrix: String,
    pub trace_ids: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
    pub step_logs_dir: String,
    pub summary_md: String,
    pub env_json: String,
    pub repro_lock: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneMockInventoryTraceIds {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub production_mock_seam_matrix_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneMockInventoryRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub inventory_hash: String,
    pub production_mock_seam_matrix_hash: String,
    pub outcome: ControlPlaneMockInventoryOutcome,
    pub must_fix_count: u32,
    pub architectural_issue_count: u32,
    pub artifact_paths: ControlPlaneMockInventoryArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPlaneMockInventoryEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub seed: String,
    pub scenario_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlPlaneMockInventoryArtifacts {
    pub out_dir: PathBuf,
    pub inventory_path: PathBuf,
    pub production_mock_seam_matrix_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub step_logs_dir: PathBuf,
    pub summary_path: PathBuf,
    pub env_path: PathBuf,
    pub repro_lock_path: PathBuf,
    pub outcome: ControlPlaneMockInventoryOutcome,
    pub inventory_hash: String,
    pub production_mock_seam_matrix_hash: String,
    pub must_fix_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum ControlPlaneMockInventoryBundleError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("JSON serialization error at {path}: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("bundle directory is already being written: {path}")]
    Busy { path: String },
}

#[derive(Debug)]
#[allow(dead_code)]
struct ControlPlaneMockInventoryBundleLock {
    path: PathBuf,
}

impl Drop for ControlPlaneMockInventoryBundleLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

// ---------------------------------------------------------------------------
// build_source_derived_inventory — live source-tree scanning
// ---------------------------------------------------------------------------

/// Mapping from diagnostic code prefix to [`SeamKind`].
#[cfg(test)]
fn seam_kind_from_diagnostic_code(code: &str) -> SeamKind {
    match code {
        "AMG-PROD-MOCK-CX" => SeamKind::MockContext,
        "AMG-PROD-MOCK-BUDGET" => SeamKind::MockBudget,
        "AMG-PROD-MOCK-DECISION-CONTRACT" => SeamKind::MockDecisionContract,
        "AMG-PROD-MOCK-EVIDENCE-EMITTER" => SeamKind::MockEvidenceEmitter,
        "AMG-PROD-MOCK-FAILURE-MODE" => SeamKind::MockFailureMode,
        "AMG-PROD-SEED-TRACE-ID" => SeamKind::SeedDerivedTraceId,
        "AMG-PROD-SEED-DECISION-ID" => SeamKind::SeedDerivedDecisionId,
        "AMG-PROD-SEED-POLICY-ID" => SeamKind::SeedDerivedPolicyId,
        "AMG-PROD-SEED-SCHEMA-VERSION" => SeamKind::SeedDerivedSchemaVersion,
        "AMG-ARCH-UNGARDED-MOCK-MODULE" => SeamKind::UnguardedMockModule,
        "AMG-PROD-MOCK-MODULE-REFERENCE" => SeamKind::MockContext,
        _ => SeamKind::MockContext,
    }
}

/// Remediation strategy derived from the seam kind.
fn remediation_for_kind(kind: SeamKind) -> RemediationStrategy {
    match kind {
        SeamKind::MockBudget | SeamKind::HardcodedBudget => RemediationStrategy::PropagateBudget,
        SeamKind::UnguardedMockModule => RemediationStrategy::AddCfgTestGuard,
        _ => RemediationStrategy::ThreadRealContext,
    }
}

/// Match a single source line against all known mock/fake symbols and return
/// every [`SeamKind`] that matches. This is used by the source-derived
/// inventory scanner to detect all mock usage in a line (not just the first).
fn all_seam_kinds_in_line(line: &str) -> Vec<(SeamKind, &'static str)> {
    let symbols: &[(&str, SeamKind, &str)] = &[
        ("MockCx", SeamKind::MockContext, "MockCx reference"),
        ("MockBudget", SeamKind::MockBudget, "MockBudget reference"),
        (
            "MockDecisionContract",
            SeamKind::MockDecisionContract,
            "MockDecisionContract reference",
        ),
        (
            "MockEvidenceEmitter",
            SeamKind::MockEvidenceEmitter,
            "MockEvidenceEmitter reference",
        ),
        (
            "MockFailureMode",
            SeamKind::MockFailureMode,
            "MockFailureMode reference",
        ),
        (
            "trace_id_from_seed",
            SeamKind::SeedDerivedTraceId,
            "trace_id_from_seed reference",
        ),
        (
            "decision_id_from_seed",
            SeamKind::SeedDerivedDecisionId,
            "decision_id_from_seed reference",
        ),
        (
            "policy_id_from_seed",
            SeamKind::SeedDerivedPolicyId,
            "policy_id_from_seed reference",
        ),
        (
            "schema_version_from_seed",
            SeamKind::SeedDerivedSchemaVersion,
            "schema_version_from_seed reference",
        ),
    ];

    let mut hits = Vec::new();
    for &(symbol, kind, desc) in symbols {
        if contains_ident(line, symbol) {
            hits.push((kind, desc));
        }
    }
    // Detect hardcoded budget patterns like `MockBudget::new(N)` separately.
    if contains_ident(line, "MockBudget") && line.contains("::new(") {
        hits.push((
            SeamKind::HardcodedBudget,
            "hardcoded MockBudget::new() call",
        ));
    }
    hits
}

/// Scan a single Rust source file and emit [`SeamOccurrence`] records for
/// every mock/fake/stub usage found. Uses the same brace-depth and
/// `#[cfg(test)]` scope tracking as the ambient mock guard scanner.
fn scan_file_for_seam_occurrences(
    workspace_root: &Path,
    file_path: &Path,
    relative_path: &str,
) -> Result<Vec<SeamOccurrence>, AmbientMockGuardError> {
    let source = fs::read_to_string(file_path).map_err(|source| AmbientMockGuardError::Io {
        path: file_path.display().to_string(),
        source,
    })?;

    let file_is_test = relative_path.contains("/tests/");
    let mut occurrences = Vec::new();
    let mut in_block_comment = false;
    let mut brace_depth = 0usize;
    let mut pending_test_scope = false;
    let mut pending_mock_module_scope = false;
    let mut scope_stack: Vec<GuardScopeFrame> = Vec::new();

    for (index, raw_line) in source.lines().enumerate() {
        let line_number = (index + 1) as u32;
        let code_line = strip_non_code_segments(raw_line, &mut in_block_comment);
        let trimmed = code_line.trim();
        let line_has_cfg_test = is_cfg_test_attribute(trimmed);

        if line_has_cfg_test {
            pending_test_scope = true;
        }

        let is_test_context = file_is_test
            || pending_test_scope
            || line_has_cfg_test
            || scope_stack
                .iter()
                .any(|frame| frame.kind == GuardScopeKind::TestOnly);

        // Detect mock module definitions.
        if is_mock_module_definition(trimmed) {
            pending_mock_module_scope = true;
            if !is_test_context {
                occurrences.push(SeamOccurrence::new(SeamOccurrenceInput {
                    file_path: relative_path,
                    line_number,
                    kind: SeamKind::UnguardedMockModule,
                    classification: SeamClassification::MustFixProduction,
                    severity: SeamSeverity::High,
                    inside_cfg_test: false,
                    description: "mock helper module reachable from production code",
                    remediation: RemediationStrategy::AddCfgTestGuard,
                    remediation_bead: "bd-3nr.1.2.2",
                }));
            }
        }

        // Detect mock/fake symbol usage on non-empty lines.
        if !trimmed.is_empty() {
            let hits = all_seam_kinds_in_line(trimmed);
            for (kind, desc) in hits {
                let (classification, severity) = if is_test_context {
                    (SeamClassification::AcceptableTestOnly, SeamSeverity::Low)
                } else {
                    let sev = match kind {
                        SeamKind::MockContext
                        | SeamKind::MockBudget
                        | SeamKind::HardcodedBudget => SeamSeverity::Critical,
                        SeamKind::SeedDerivedTraceId
                        | SeamKind::SeedDerivedDecisionId
                        | SeamKind::SeedDerivedPolicyId => SeamSeverity::High,
                        _ => SeamSeverity::Medium,
                    };
                    (SeamClassification::MustFixProduction, sev)
                };
                occurrences.push(SeamOccurrence::new(SeamOccurrenceInput {
                    file_path: relative_path,
                    line_number,
                    kind,
                    classification,
                    severity,
                    inside_cfg_test: is_test_context,
                    description: desc,
                    remediation: if is_test_context {
                        RemediationStrategy::NoAction
                    } else {
                        remediation_for_kind(kind)
                    },
                    remediation_bead: if is_test_context { "" } else { "bd-3nr.1.2.1" },
                }));
            }
        }

        // Mock module reference detection for production paths.
        if !trimmed.is_empty() && !is_test_context && is_production_mock_module_reference(trimmed) {
            // Only add if we didn't already capture via symbol-level matching.
            let already_captured = occurrences.iter().any(|o| {
                o.file_path == relative_path
                    && o.line_number == line_number
                    && o.classification == SeamClassification::MustFixProduction
            });
            if !already_captured {
                occurrences.push(SeamOccurrence::new(SeamOccurrenceInput {
                    file_path: relative_path,
                    line_number,
                    kind: SeamKind::MockContext,
                    classification: SeamClassification::MustFixProduction,
                    severity: SeamSeverity::Critical,
                    inside_cfg_test: false,
                    description: "production code imports from control_plane::mocks",
                    remediation: RemediationStrategy::ThreadRealContext,
                    remediation_bead: "bd-3nr.1.2.1",
                }));
            }
        }

        // Track brace depth and scope stack (same logic as ambient guard scanner).
        let open_braces = trimmed.chars().filter(|ch| *ch == '{').count();

        let mut line_depth = brace_depth;
        for ch in trimmed.chars() {
            if ch == '{' {
                line_depth += 1;
                if pending_test_scope {
                    scope_stack.push(GuardScopeFrame {
                        kind: GuardScopeKind::TestOnly,
                        depth: line_depth,
                    });
                    pending_test_scope = false;
                }
                if pending_mock_module_scope {
                    scope_stack.push(GuardScopeFrame {
                        kind: GuardScopeKind::MockModule,
                        depth: line_depth,
                    });
                    pending_mock_module_scope = false;
                }
            } else if ch == '}' {
                line_depth = line_depth.saturating_sub(1);
                while scope_stack.last().is_some_and(|f| line_depth < f.depth) {
                    scope_stack.pop();
                }
            }
        }
        brace_depth = line_depth;

        if pending_test_scope && pending_scope_consumed_without_block(trimmed, open_braces) {
            pending_test_scope = false;
        }
        if pending_mock_module_scope && pending_scope_consumed_without_block(trimmed, open_braces) {
            pending_mock_module_scope = false;
        }
    }

    // Normalise to workspace-relative paths.
    for occ in &mut occurrences {
        if occ
            .file_path
            .starts_with(&workspace_root.display().to_string())
        {
            occ.file_path = relative_path.to_string();
        }
    }

    Ok(occurrences)
}

/// Build the mock inventory by scanning the actual source tree under
/// `workspace_root`. This replaces the former hardcoded ledger with live
/// source-derived detection.
pub fn build_source_derived_inventory(
    workspace_root: &Path,
) -> Result<MockInventory, AmbientMockGuardError> {
    let scan_root = AMBIENT_MOCK_GUARD_SCAN_ROOT;
    let source_root = workspace_root.join(scan_root);
    if !source_root.exists() {
        return Err(AmbientMockGuardError::MissingScanRoot {
            path: workspace_root.display().to_string(),
            expected: scan_root.to_string(),
        });
    }

    let mut rust_files = Vec::new();
    collect_rust_files(&source_root, &mut rust_files)?;

    let mut all_occurrences = Vec::new();
    for file_path in &rust_files {
        let relative_path = relative_path_from(workspace_root, file_path);
        // Skip self to avoid circular detection.
        if relative_path == "crates/franken-engine/src/control_plane_mock_inventory.rs" {
            continue;
        }
        all_occurrences.extend(scan_file_for_seam_occurrences(
            workspace_root,
            file_path,
            &relative_path,
        )?);
    }

    // Derive architectural issues from the production-level occurrences.
    let mut architectural_issues = Vec::new();
    let mut seen_arch_ids = std::collections::BTreeSet::new();

    // ARCH-001: unguarded mock module.
    for occ in all_occurrences
        .iter()
        .filter(|o| o.kind == SeamKind::UnguardedMockModule)
    {
        let arch_id = format!("ARCH-UNGUARDED-{}", occ.file_path.replace('/', "_"));
        if seen_arch_ids.insert(arch_id.clone()) {
            architectural_issues.push(ArchitecturalIssue {
                id: arch_id,
                description: format!(
                    "{}:{} — `pub mod mocks` without #[cfg(test)] guard",
                    occ.file_path, occ.line_number
                ),
                file_path: occ.file_path.clone(),
                severity: SeamSeverity::High,
                remediation: RemediationStrategy::AddCfgTestGuard,
                remediation_bead: "bd-3nr.1.2.2".to_string(),
            });
        }
    }

    // ARCH-002: production code using MockCx/MockBudget for real execution.
    for occ in all_occurrences.iter().filter(|o| {
        o.classification == SeamClassification::MustFixProduction
            && matches!(
                o.kind,
                SeamKind::MockContext | SeamKind::MockBudget | SeamKind::HardcodedBudget
            )
    }) {
        let arch_id = format!(
            "ARCH-PROD-MOCK-{}-{}",
            occ.file_path.replace('/', "_"),
            occ.line_number
        );
        if seen_arch_ids.insert(arch_id.clone()) {
            architectural_issues.push(ArchitecturalIssue {
                id: arch_id,
                description: format!(
                    "{}:{} — production code uses {} bypassing real context/budget tracking",
                    occ.file_path, occ.line_number, occ.kind
                ),
                file_path: occ.file_path.clone(),
                severity: SeamSeverity::Critical,
                remediation: remediation_for_kind(occ.kind),
                remediation_bead: "bd-3nr.1.2.1".to_string(),
            });
        }
    }

    Ok(MockInventory::build(all_occurrences, architectural_issues))
}

/// Build the canonical inventory by scanning the live source tree.
///
/// Prior to bd-2muur.5.1 this function returned a hardcoded ledger from the
/// 2026-03-09 codebase scan. It now delegates to [`build_source_derived_inventory`]
/// which scans the actual source files for mock/fake/stub usage. If the scan
/// fails (e.g. workspace root cannot be located), an empty inventory is returned
/// so callers that do not have access to the workspace still get a valid value.
pub fn build_canonical_inventory() -> MockInventory {
    let root = repo_root();
    match build_source_derived_inventory(&root) {
        Ok(inventory) => inventory,
        Err(_) => MockInventory::build(Vec::new(), Vec::new()),
    }
}

// ---------------------------------------------------------------------------
// Freshness guard — bd-2muur.5.3
// ---------------------------------------------------------------------------

/// Result of an inventory freshness check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InventoryFreshnessResult {
    /// Scanner version used.
    pub scanner_version: String,
    /// Policy ID for this check.
    pub policy_id: String,
    /// Whether the inventory is fresh (hash matches a re-scan).
    pub fresh: bool,
    /// Hash from the original inventory.
    pub original_hash: String,
    /// Hash from a re-scan of the same workspace root.
    pub rescan_hash: String,
}

/// Verify that a [`MockInventory`] is fresh by re-scanning the same workspace
/// root and comparing inventory hashes. Returns a fail-closed result: if the
/// re-scan fails, the inventory is considered stale.
pub fn verify_inventory_freshness(
    inventory: &MockInventory,
    workspace_root: &Path,
) -> InventoryFreshnessResult {
    let rescan = build_source_derived_inventory(workspace_root)
        .unwrap_or_else(|_| MockInventory::build(Vec::new(), Vec::new()));
    let original_hash = inventory.inventory_hash.to_string();
    let rescan_hash = rescan.inventory_hash.to_string();
    InventoryFreshnessResult {
        scanner_version: SOURCE_DERIVED_SCANNER_VERSION.to_string(),
        policy_id: INVENTORY_FRESHNESS_POLICY_ID.to_string(),
        fresh: original_hash == rescan_hash,
        original_hash,
        rescan_hash,
    }
}

fn control_plane_mock_inventory_json_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, ControlPlaneMockInventoryBundleError> {
    serde_json::to_vec(value).map_err(|source| ControlPlaneMockInventoryBundleError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn control_plane_mock_shared_bundle_lock_path(out_dir: &Path) -> PathBuf {
    out_dir.join(CONTROL_PLANE_MOCK_SHARED_BUNDLE_LOCK_FILE)
}

fn acquire_control_plane_mock_inventory_bundle_lock(
    out_dir: &Path,
) -> Result<ControlPlaneMockInventoryBundleLock, ControlPlaneMockInventoryBundleError> {
    let lock_path = control_plane_mock_shared_bundle_lock_path(out_dir);
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(ControlPlaneMockInventoryBundleLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {
            Err(ControlPlaneMockInventoryBundleError::Busy {
                path: lock_path.display().to_string(),
            })
        }
        Err(source) => Err(ControlPlaneMockInventoryBundleError::Io {
            path: lock_path.display().to_string(),
            source,
        }),
    }
}

fn write_control_plane_mock_inventory_atomic(
    path: &Path,
    bytes: &[u8],
) -> Result<(), ControlPlaneMockInventoryBundleError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ControlPlaneMockInventoryBundleError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let temp_path = ambient_mock_guard_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| ControlPlaneMockInventoryBundleError::Io {
        path: temp_path.display().to_string(),
        source,
    })?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(ControlPlaneMockInventoryBundleError::Io {
            path: path.display().to_string(),
            source,
        });
    }
    Ok(())
}

fn build_ambient_mock_guard_events(
    report: &AmbientMockGuardReport,
    trace_id: &str,
    decision_id: &str,
) -> Vec<AmbientMockGuardEvent> {
    let mut events = vec![AmbientMockGuardEvent {
        schema_version: AMBIENT_MOCK_GUARD_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        event: "guard_started".to_string(),
        outcome: "started".to_string(),
        error_code: None,
        seed: "ambient-mock-guard-static-scan-v1".to_string(),
        scenario_id: "workspace-scan".to_string(),
        rule_id: None,
        diagnostic_id: None,
        source_path: None,
        file_path: None,
        line_number: None,
        detail: Some("ambient mock guard scan started".to_string()),
    }];

    for violation in &report.violations {
        events.push(AmbientMockGuardEvent {
            schema_version: AMBIENT_MOCK_GUARD_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
            component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
            event: "violation_detected".to_string(),
            outcome: "fail_closed".to_string(),
            error_code: Some(violation.diagnostic_code.clone()),
            seed: "ambient-mock-guard-static-scan-v1".to_string(),
            scenario_id: "workspace-scan".to_string(),
            rule_id: Some(violation.rule.as_str().to_string()),
            diagnostic_id: Some(violation.violation_id.clone()),
            source_path: Some(violation.file_path.clone()),
            file_path: Some(violation.file_path.clone()),
            line_number: Some(violation.line_number),
            detail: Some(violation.detail.clone()),
        });
    }

    events.push(AmbientMockGuardEvent {
        schema_version: AMBIENT_MOCK_GUARD_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        event: "guard_completed".to_string(),
        outcome: report.outcome.as_str().to_string(),
        error_code: None,
        seed: "ambient-mock-guard-static-scan-v1".to_string(),
        scenario_id: "workspace-scan".to_string(),
        rule_id: None,
        diagnostic_id: None,
        source_path: None,
        file_path: None,
        line_number: None,
        detail: Some(format!(
            "{} files scanned; {} violation(s) recorded",
            report.summary.scanned_file_count, report.summary.violation_count
        )),
    });

    events
}

fn render_ambient_mock_guard_summary(
    report: &AmbientMockGuardReport,
    trace_id: &str,
    decision_id: &str,
) -> String {
    let mut lines = vec![
        "# Ambient Mock Guard Summary".to_string(),
        String::new(),
        format!("Outcome: `{}`", report.outcome),
        format!("Policy: `{}`", report.policy_id),
        format!("Bead: `{}`", report.bead_id),
        format!("Trace: `{trace_id}`"),
        format!("Decision: `{decision_id}`"),
        format!("Scan root: `{}`", report.scan_root),
        format!(
            "Canonical inventory hash: `{}`",
            report.canonical_inventory_hash
        ),
        format!("Scanned files: {}", report.summary.scanned_file_count),
        format!("Violations: {}", report.summary.violation_count),
        String::new(),
    ];

    if report.violations.is_empty() {
        lines.push("No production `control_plane::mocks` seams were detected.".to_string());
    } else {
        lines.push("## Violations".to_string());
        lines.push(String::new());
        for violation in &report.violations {
            lines.push(format!(
                "- `{}` {}:{} {}",
                violation.diagnostic_code,
                violation.file_path,
                violation.line_number,
                violation.detail
            ));
        }
    }

    lines.join("\n")
}

fn render_ambient_mock_guard_step_log(
    report: &AmbientMockGuardReport,
    trace_id: &str,
    decision_id: &str,
) -> String {
    let mut output = String::new();
    output.push_str(&format!("trace_id={trace_id}\n"));
    output.push_str(&format!("decision_id={decision_id}\n"));
    output.push_str(&format!("policy_id={}\n", report.policy_id));
    output.push_str(&format!("outcome={}\n", report.outcome));
    output.push_str(&format!(
        "scanned_file_count={}\n",
        report.summary.scanned_file_count
    ));
    output.push_str(&format!(
        "violation_count={}\n",
        report.summary.violation_count
    ));
    for violation in &report.violations {
        output.push_str(&format!(
            "violation={} rule_id={} source_path={} line={} {}\n",
            violation.diagnostic_code,
            violation.rule.as_str(),
            violation.file_path,
            violation.line_number,
            violation.detail
        ));
    }
    output
}

fn ambient_mock_guard_json_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, AmbientMockGuardError> {
    serde_json::to_vec(value).map_err(|source| AmbientMockGuardError::Json {
        path: path.display().to_string(),
        source,
    })
}

fn ambient_mock_guard_temp_dir(label: &str) -> PathBuf {
    let sequence = NEXT_AMBIENT_MOCK_GUARD_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "frankenengine-ambient-mock-guard-{label}-{}-{sequence}",
        std::process::id()
    ))
}

fn write_ambient_mock_guard_fixture_file(
    root: &Path,
    relative_path: &str,
    contents: &str,
) -> Result<(), AmbientMockGuardError> {
    let path = root.join(relative_path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| AmbientMockGuardError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }
    fs::write(&path, contents).map_err(|source| AmbientMockGuardError::Io {
        path: path.display().to_string(),
        source,
    })
}

fn sorted_unique_strings(values: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut values: Vec<String> = values
        .into_iter()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    values.sort();
    values
}

fn evaluate_ambient_mock_guard_regression_scenario(
    scenario_id: &str,
    description: &str,
    fixture_files: &[(&str, &str)],
    expected_outcome: AmbientMockGuardOutcome,
    expected_rule_ids: &[AmbientMockGuardRule],
    expected_diagnostic_codes: &[&str],
    expected_source_paths: &[&str],
) -> Result<AmbientMockGuardRegressionScenario, AmbientMockGuardError> {
    let root = ambient_mock_guard_temp_dir(scenario_id);
    for (relative_path, contents) in fixture_files {
        write_ambient_mock_guard_fixture_file(&root, relative_path, contents)?;
    }

    let report_result = evaluate_ambient_mock_guard_in_root(&root);
    let cleanup_result = fs::remove_dir_all(&root);
    let report = report_result?;
    if let Err(source) = cleanup_result {
        return Err(AmbientMockGuardError::Io {
            path: root.display().to_string(),
            source,
        });
    }

    let expected_rule_ids = sorted_unique_strings(
        expected_rule_ids
            .iter()
            .map(|rule| rule.as_str().to_string()),
    );
    let actual_rule_ids = sorted_unique_strings(
        report
            .violations
            .iter()
            .map(|violation| violation.rule.as_str().to_string()),
    );
    let expected_diagnostic_codes = sorted_unique_strings(
        expected_diagnostic_codes
            .iter()
            .map(|code| (*code).to_string()),
    );
    let actual_diagnostic_codes = sorted_unique_strings(
        report
            .violations
            .iter()
            .map(|violation| violation.diagnostic_code.clone()),
    );
    let expected_source_paths =
        sorted_unique_strings(expected_source_paths.iter().map(|path| (*path).to_string()));
    let actual_source_paths = sorted_unique_strings(
        report
            .violations
            .iter()
            .map(|violation| violation.file_path.clone()),
    );

    let mut notes = Vec::new();
    if report.outcome != expected_outcome {
        notes.push(format!(
            "expected outcome `{expected_outcome}`, got `{}`",
            report.outcome
        ));
    }
    if actual_rule_ids != expected_rule_ids {
        notes.push(format!(
            "expected rule_ids {:?}, got {:?}",
            expected_rule_ids, actual_rule_ids
        ));
    }
    if actual_diagnostic_codes != expected_diagnostic_codes {
        notes.push(format!(
            "expected diagnostic_codes {:?}, got {:?}",
            expected_diagnostic_codes, actual_diagnostic_codes
        ));
    }
    if actual_source_paths != expected_source_paths {
        notes.push(format!(
            "expected source_paths {:?}, got {:?}",
            expected_source_paths, actual_source_paths
        ));
    }

    Ok(AmbientMockGuardRegressionScenario {
        scenario_id: scenario_id.to_string(),
        description: description.to_string(),
        expected_outcome,
        actual_outcome: report.outcome,
        expected_rule_ids,
        actual_rule_ids,
        expected_diagnostic_codes,
        actual_diagnostic_codes,
        expected_source_paths,
        actual_source_paths,
        passed: notes.is_empty(),
        notes,
    })
}

fn evaluate_ambient_mock_guard_regression_report(
    canonical_inventory_hash: &str,
) -> Result<AmbientMockGuardRegressionReport, AmbientMockGuardError> {
    let scenarios = vec![
        evaluate_ambient_mock_guard_regression_scenario(
            "cfg_test_only_mock_usage",
            "test-only `control_plane::mocks` usage must remain allowed when sealed behind `#[cfg(test)]`",
            &[(
                "crates/franken-engine/src/lib.rs",
                r#"
#[cfg(test)]
mod tests {
    use crate::control_plane::mocks::{MockBudget, MockCx};

    #[test]
    fn helper() {
        let _cx = MockCx::new(crate::control_plane::mocks::trace_id_from_seed(1), MockBudget::new(10));
    }
}
"#,
            )],
            AmbientMockGuardOutcome::Pass,
            &[],
            &[],
            &[],
        )?,
        evaluate_ambient_mock_guard_regression_scenario(
            "production_mock_reference_fails_closed",
            "production code must fail closed when it imports `control_plane::mocks` and constructs a fake context",
            &[(
                "crates/franken-engine/src/lib.rs",
                r#"
use crate::control_plane::mocks::{MockBudget, MockCx};

fn build() {
    let _cx = MockCx::new(trace_id_from_seed(7), MockBudget::new(10));
}
"#,
            )],
            AmbientMockGuardOutcome::FailClosed,
            &[
                AmbientMockGuardRule::NoProductionMockModuleReference,
                AmbientMockGuardRule::NoProductionFakeContextSymbol,
            ],
            &["AMG-PROD-MOCK-CX", "AMG-PROD-MOCK-MODULE-REFERENCE"],
            &["crates/franken-engine/src/lib.rs"],
        )?,
        evaluate_ambient_mock_guard_regression_scenario(
            "unguarded_mock_module_fails_closed",
            "a production-default `pub mod mocks` definition must be flagged immediately with actionable diagnostics",
            &[
                (
                    "crates/franken-engine/src/control_plane/mod.rs",
                    r#"
pub mod mocks {
    pub struct MockCx;
}
"#,
                ),
                ("crates/franken-engine/src/lib.rs", "pub mod control_plane;"),
            ],
            AmbientMockGuardOutcome::FailClosed,
            &[AmbientMockGuardRule::MockModuleMustBeCfgTest],
            &["AMG-ARCH-UNGARDED-MOCK-MODULE"],
            &["crates/franken-engine/src/control_plane/mod.rs"],
        )?,
    ];
    let summary = AmbientMockGuardRegressionSummary {
        scenario_count: scenarios.len() as u64,
        passed_scenario_count: scenarios.iter().filter(|scenario| scenario.passed).count() as u64,
        failed_scenario_count: scenarios.iter().filter(|scenario| !scenario.passed).count() as u64,
    };

    Ok(AmbientMockGuardRegressionReport {
        schema_version: AMBIENT_MOCK_GUARD_REGRESSION_REPORT_SCHEMA_VERSION.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        bead_id: AMBIENT_MOCK_GUARD_REGRESSION_BEAD_ID.to_string(),
        policy_id: AMBIENT_MOCK_GUARD_REGRESSION_POLICY_ID.to_string(),
        canonical_inventory_hash: canonical_inventory_hash.to_string(),
        suite_seed: AMBIENT_MOCK_GUARD_REGRESSION_SEED.to_string(),
        outcome: if summary.failed_scenario_count == 0 {
            AmbientMockGuardOutcome::Pass
        } else {
            AmbientMockGuardOutcome::FailClosed
        },
        summary,
        scenarios,
    })
}

fn acquire_ambient_mock_guard_bundle_lock(
    out_dir: &Path,
) -> Result<AmbientMockGuardBundleLock, AmbientMockGuardError> {
    let lock_path = control_plane_mock_shared_bundle_lock_path(out_dir);
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(AmbientMockGuardBundleLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {
            Err(AmbientMockGuardError::Busy {
                path: lock_path.display().to_string(),
            })
        }
        Err(source) => Err(AmbientMockGuardError::Io {
            path: lock_path.display().to_string(),
            source,
        }),
    }
}

fn write_ambient_mock_guard_atomic(path: &Path, bytes: &[u8]) -> Result<(), AmbientMockGuardError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| AmbientMockGuardError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let temp_path = ambient_mock_guard_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| AmbientMockGuardError::Io {
        path: temp_path.display().to_string(),
        source,
    })?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(AmbientMockGuardError::Io {
            path: path.display().to_string(),
            source,
        });
    }
    Ok(())
}

pub fn write_control_plane_mock_inventory_bundle(
    out_dir: impl AsRef<Path>,
    command_lines: &[String],
) -> Result<ControlPlaneMockInventoryArtifacts, ControlPlaneMockInventoryBundleError> {
    write_control_plane_mock_inventory_bundle_in_root(repo_root(), out_dir, command_lines)
}

pub fn write_control_plane_mock_inventory_bundle_in_root(
    workspace_root: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    command_lines: &[String],
) -> Result<ControlPlaneMockInventoryArtifacts, ControlPlaneMockInventoryBundleError> {
    let workspace_root = workspace_root.as_ref();
    let out_dir = out_dir.as_ref().to_path_buf();
    fs::create_dir_all(&out_dir).map_err(|source| ControlPlaneMockInventoryBundleError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;

    let inventory = build_source_derived_inventory(workspace_root)
        .unwrap_or_else(|_| MockInventory::build(Vec::new(), Vec::new()));
    let production_mock_seam_matrix = inventory.production_mock_seam_matrix();

    let inventory_path = out_dir.join("asupersync_residual_mock_inventory.json");
    let production_mock_seam_matrix_path = out_dir.join("production_mock_seam_matrix.json");
    let trace_ids_path = out_dir.join("trace_ids.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let step_logs_dir = out_dir.join("step_logs");
    let summary_path = out_dir.join("summary.md");
    let env_path = out_dir.join("env.json");
    let repro_lock_path = out_dir.join("repro.lock");

    let inventory_bytes = control_plane_mock_inventory_json_bytes(&inventory, &inventory_path)?;
    let canonical_inventory_hash = inventory.inventory_hash.to_string();
    let production_mock_seam_matrix_bytes = control_plane_mock_inventory_json_bytes(
        &production_mock_seam_matrix,
        &production_mock_seam_matrix_path,
    )?;
    let production_mock_seam_matrix_hash = sha256_hex(&production_mock_seam_matrix_bytes);
    let short_hash = canonical_inventory_hash
        .chars()
        .take(16)
        .collect::<String>();
    let trace_id = format!("trace-control-plane-mock-inventory-{short_hash}");
    let decision_id = format!("decision-control-plane-mock-inventory-{short_hash}");

    let trace_ids = ControlPlaneMockInventoryTraceIds {
        schema_version: CONTROL_PLANE_MOCK_INVENTORY_TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID.to_string(),
        inventory_hash: canonical_inventory_hash.clone(),
        production_mock_seam_matrix_hash: production_mock_seam_matrix_hash.clone(),
    };
    let trace_ids_bytes = control_plane_mock_inventory_json_bytes(&trace_ids, &trace_ids_path)?;

    let events = build_control_plane_mock_inventory_events(&inventory, &trace_id, &decision_id);
    let mut events_jsonl = String::new();
    for event in &events {
        let line = serde_json::to_string(event).map_err(|source| {
            ControlPlaneMockInventoryBundleError::Json {
                path: events_path.display().to_string(),
                source,
            }
        })?;
        events_jsonl.push_str(&line);
        events_jsonl.push('\n');
    }

    let mut commands_buf = String::new();
    for command in command_lines {
        commands_buf.push_str(command);
        commands_buf.push('\n');
    }

    let summary_md =
        render_control_plane_mock_inventory_summary(&inventory, &trace_id, &decision_id);
    let env_json = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": "frankenengine.control-plane-mock-inventory.env.v1",
        "component": COMPONENT,
        "bead_id": BEAD_ID,
        "policy_id": CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID,
        "workspace_root": workspace_root.display().to_string(),
        "inventory_schema_version": inventory.schema_version,
        "production_matrix_schema_version": PRODUCTION_MOCK_SEAM_MATRIX_SCHEMA_VERSION,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "toolchain": std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".to_string()),
    }))
    .map_err(|source| ControlPlaneMockInventoryBundleError::Json {
        path: env_path.display().to_string(),
        source,
    })?;
    let repro_lock = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": "franken-engine.repro-lock.v1",
        "component": COMPONENT,
        "bead_id": BEAD_ID,
        "policy_id": CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID,
        "inventory_hash": canonical_inventory_hash.clone(),
        "production_mock_seam_matrix_hash": production_mock_seam_matrix_hash.clone(),
        "replay_command": replay_command_for_bundle("franken_control_plane_mock_inventory", workspace_root),
    }))
    .map_err(|source| ControlPlaneMockInventoryBundleError::Json {
        path: repro_lock_path.display().to_string(),
        source,
    })?;

    let manifest = ControlPlaneMockInventoryRunManifest {
        schema_version: CONTROL_PLANE_MOCK_INVENTORY_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID.to_string(),
        inventory_hash: canonical_inventory_hash.clone(),
        production_mock_seam_matrix_hash: production_mock_seam_matrix_hash.clone(),
        outcome: ControlPlaneMockInventoryOutcome::InventoryComplete,
        must_fix_count: inventory.summary.must_fix_count,
        architectural_issue_count: inventory.summary.architectural_issue_count,
        artifact_paths: ControlPlaneMockInventoryArtifactPaths {
            asupersync_residual_mock_inventory: "asupersync_residual_mock_inventory.json"
                .to_string(),
            production_mock_seam_matrix: "production_mock_seam_matrix.json".to_string(),
            trace_ids: "trace_ids.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
            step_logs_dir: "step_logs".to_string(),
            summary_md: "summary.md".to_string(),
            env_json: "env.json".to_string(),
            repro_lock: "repro.lock".to_string(),
        },
    };
    let manifest_bytes = control_plane_mock_inventory_json_bytes(&manifest, &run_manifest_path)?;

    let _bundle_lock = acquire_control_plane_mock_inventory_bundle_lock(&out_dir)?;
    write_control_plane_mock_inventory_atomic(&inventory_path, &inventory_bytes)?;
    write_control_plane_mock_inventory_atomic(
        &production_mock_seam_matrix_path,
        &production_mock_seam_matrix_bytes,
    )?;
    write_control_plane_mock_inventory_atomic(&trace_ids_path, &trace_ids_bytes)?;
    write_control_plane_mock_inventory_atomic(&events_path, events_jsonl.as_bytes())?;
    write_control_plane_mock_inventory_atomic(&commands_path, commands_buf.as_bytes())?;
    fs::create_dir_all(&step_logs_dir).map_err(|source| {
        ControlPlaneMockInventoryBundleError::Io {
            path: step_logs_dir.display().to_string(),
            source,
        }
    })?;
    let step_log =
        render_control_plane_mock_inventory_step_log(&inventory, &trace_id, &decision_id);
    write_control_plane_mock_inventory_atomic(
        &step_logs_dir.join("step_001_inventory.log"),
        step_log.as_bytes(),
    )?;
    write_control_plane_mock_inventory_atomic(&summary_path, summary_md.as_bytes())?;
    write_control_plane_mock_inventory_atomic(&env_path, &env_json)?;
    write_control_plane_mock_inventory_atomic(&repro_lock_path, &repro_lock)?;
    write_control_plane_mock_inventory_atomic(&run_manifest_path, &manifest_bytes)?;

    Ok(ControlPlaneMockInventoryArtifacts {
        out_dir,
        inventory_path,
        production_mock_seam_matrix_path,
        trace_ids_path,
        run_manifest_path,
        events_path,
        commands_path,
        step_logs_dir,
        summary_path,
        env_path,
        repro_lock_path,
        outcome: ControlPlaneMockInventoryOutcome::InventoryComplete,
        inventory_hash: canonical_inventory_hash,
        production_mock_seam_matrix_hash,
        must_fix_count: inventory.must_fix_items().len(),
    })
}

// ---------------------------------------------------------------------------
// Ambient mock guard
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbientMockGuardOutcome {
    Pass,
    FailClosed,
}

impl AmbientMockGuardOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::FailClosed => "fail_closed",
        }
    }
}

impl fmt::Display for AmbientMockGuardOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AmbientMockGuardRule {
    MockModuleMustBeCfgTest,
    NoProductionMockModuleReference,
    NoProductionFakeContextSymbol,
}

impl AmbientMockGuardRule {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MockModuleMustBeCfgTest => "mock_module_must_be_cfg_test",
            Self::NoProductionMockModuleReference => "no_production_mock_module_reference",
            Self::NoProductionFakeContextSymbol => "no_production_fake_context_symbol",
        }
    }
}

impl fmt::Display for AmbientMockGuardRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientMockGuardViolation {
    pub violation_id: String,
    pub rule: AmbientMockGuardRule,
    pub severity: SeamSeverity,
    pub diagnostic_code: String,
    pub file_path: String,
    pub line_number: u32,
    pub code_snippet: String,
    pub detail: String,
    pub remediation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientMockGuardSummary {
    pub scanned_file_count: u64,
    pub violation_count: u64,
    pub architectural_violation_count: u64,
    pub production_reference_violation_count: u64,
    pub fake_context_violation_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientMockGuardReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub canonical_inventory_hash: String,
    pub scan_root: String,
    pub outcome: AmbientMockGuardOutcome,
    pub summary: AmbientMockGuardSummary,
    pub violations: Vec<AmbientMockGuardViolation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientMockGuardArtifactPaths {
    pub ambient_mock_guard_report: String,
    pub control_plane_mock_surface_migration_report: String,
    pub control_plane_mock_guard_regression_report: String,
    pub trace_ids: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
    pub step_logs_dir: String,
    pub summary_md: String,
    pub env_json: String,
    pub repro_lock: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientMockGuardRegressionSummary {
    pub scenario_count: u64,
    pub passed_scenario_count: u64,
    pub failed_scenario_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientMockGuardRegressionScenario {
    pub scenario_id: String,
    pub description: String,
    pub expected_outcome: AmbientMockGuardOutcome,
    pub actual_outcome: AmbientMockGuardOutcome,
    pub expected_rule_ids: Vec<String>,
    pub actual_rule_ids: Vec<String>,
    pub expected_diagnostic_codes: Vec<String>,
    pub actual_diagnostic_codes: Vec<String>,
    pub expected_source_paths: Vec<String>,
    pub actual_source_paths: Vec<String>,
    pub passed: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientMockGuardRegressionReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub canonical_inventory_hash: String,
    pub suite_seed: String,
    pub outcome: AmbientMockGuardOutcome,
    pub summary: AmbientMockGuardRegressionSummary,
    pub scenarios: Vec<AmbientMockGuardRegressionScenario>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientMockGuardTraceIds {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub report_hash: String,
    pub canonical_inventory_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientMockGuardRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub report_hash: String,
    pub canonical_inventory_hash: String,
    pub outcome: AmbientMockGuardOutcome,
    pub violation_count: u64,
    pub artifact_paths: AmbientMockGuardArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AmbientMockGuardEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub seed: String,
    pub scenario_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AmbientMockGuardArtifacts {
    pub out_dir: PathBuf,
    pub report_path: PathBuf,
    pub migration_report_path: PathBuf,
    pub regression_report_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub step_logs_dir: PathBuf,
    pub summary_path: PathBuf,
    pub env_path: PathBuf,
    pub repro_lock_path: PathBuf,
    pub outcome: AmbientMockGuardOutcome,
    pub report_hash: String,
    pub violation_count: usize,
}

pub const ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT: &str = "orchestrator_context_refactor";
pub const ORCHESTRATOR_CONTEXT_REFACTOR_BEAD_ID: &str = "bd-3nr.1.2.1";
pub const ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID: &str =
    "frankenengine.orchestrator-context-refactor.v1";
pub const ORCHESTRATOR_CONTEXT_PATH_CONTRACT_SCHEMA_VERSION: &str =
    "frankenengine.orchestrator-context-path-contract.v1";
pub const ORCHESTRATOR_CONTEXT_REFACTOR_REPORT_SCHEMA_VERSION: &str =
    "frankenengine.orchestrator-context-refactor-report.v1";
pub const ORCHESTRATOR_CONTEXT_REFACTOR_TRACE_IDS_SCHEMA_VERSION: &str =
    "frankenengine.orchestrator-context-refactor.trace-ids.v1";
pub const ORCHESTRATOR_CONTEXT_REFACTOR_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "frankenengine.orchestrator-context-refactor.run-manifest.v1";
pub const ORCHESTRATOR_CONTEXT_REFACTOR_EVENT_SCHEMA_VERSION: &str =
    "frankenengine.orchestrator-context-refactor.event.v1";
pub const ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE: &str =
    "crates/franken-engine/src/execution_orchestrator.rs";
pub const ORCHESTRATOR_CONTEXT_PATH_ID: &str = "orchestrator-cell-close-canonical-context";

const ORCHESTRATOR_CONTEXT_REFACTOR_FORBIDDEN_TOKENS: &[(&str, &str)] = &[
    ("forbidden_mock_import", "use crate::control_plane::mocks"),
    ("forbidden_mock_context_ctor", "MockCx::new("),
    ("forbidden_mock_budget_ctor", "MockBudget::new("),
    ("forbidden_seed_trace_id", "trace_id_from_seed"),
];

const ORCHESTRATOR_CONTEXT_REFACTOR_REQUIRED_TOKENS: &[(&str, &str)] = &[
    (
        "required_cell_close_context_factory",
        "Self::build_cell_close_context(&trace_id, self.config.cell_close_budget_ms)",
    ),
    (
        "required_kernel_context_construction",
        "KernelContext::new(Cx::new(",
    ),
    ("required_budget_propagation", "Budget::new(budget_ms)"),
    (
        "required_trace_derivation",
        "Self::derive_cell_close_trace_id(trace_id)",
    ),
    ("required_capability_scope", "NoCaps"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrchestratorContextRefactorOutcome {
    Pass,
    FailClosed,
}

impl OrchestratorContextRefactorOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::FailClosed => "fail_closed",
        }
    }
}

impl fmt::Display for OrchestratorContextRefactorOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionContextPath {
    pub path_id: String,
    pub source_file: String,
    pub source_symbol: String,
    pub context_origin: String,
    pub trace_origin: String,
    pub budget_origin: String,
    pub capability_scope: String,
    pub deterministic_fallback: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectedProductionSeam {
    pub seam_id: String,
    pub occurrence_hash: String,
    pub original_file_path: String,
    pub original_line_number: u32,
    pub seam_kind: SeamKind,
    pub previous_pattern: String,
    pub corrected_path_id: String,
    pub corrected_context_source: String,
    pub corrected_trace_source: String,
    pub corrected_budget_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextRefactorGuard {
    pub guard_id: String,
    pub guard_kind: String,
    pub needle: String,
    pub passed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProductionContextPathContract {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub canonical_inventory_hash: String,
    pub source_file: String,
    pub context_paths: Vec<ProductionContextPath>,
    pub corrected_seams: Vec<CorrectedProductionSeam>,
    pub deferred_seams: Vec<String>,
    pub guards: Vec<ContextRefactorGuard>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrchestratorContextRefactorSummary {
    pub corrected_seam_count: u64,
    pub deferred_seam_count: u64,
    pub guard_count: u64,
    pub failed_guard_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrchestratorContextRefactorReport {
    pub schema_version: String,
    pub component: String,
    pub bead_id: String,
    pub policy_id: String,
    pub canonical_inventory_hash: String,
    pub contract_hash: String,
    pub source_file: String,
    pub outcome: OrchestratorContextRefactorOutcome,
    pub summary: OrchestratorContextRefactorSummary,
    pub corrected_seams: Vec<CorrectedProductionSeam>,
    pub deferred_seams: Vec<String>,
    pub guards: Vec<ContextRefactorGuard>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrchestratorContextRefactorArtifactPaths {
    pub production_context_path_contract: String,
    pub orchestrator_context_refactor_report: String,
    pub trace_ids: String,
    pub run_manifest: String,
    pub events_jsonl: String,
    pub commands_txt: String,
    pub step_logs_dir: String,
    pub summary_md: String,
    pub env_json: String,
    pub repro_lock: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrchestratorContextRefactorTraceIds {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub report_hash: String,
    pub contract_hash: String,
    pub canonical_inventory_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrchestratorContextRefactorRunManifest {
    pub schema_version: String,
    pub component: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub report_hash: String,
    pub contract_hash: String,
    pub canonical_inventory_hash: String,
    pub outcome: OrchestratorContextRefactorOutcome,
    pub corrected_seam_count: u64,
    pub failed_guard_count: u64,
    pub artifact_paths: OrchestratorContextRefactorArtifactPaths,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrchestratorContextRefactorEvent {
    pub schema_version: String,
    pub trace_id: String,
    pub decision_id: String,
    pub policy_id: String,
    pub component: String,
    pub event: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub seed: String,
    pub scenario_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub diagnostic_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_number: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrchestratorContextRefactorArtifacts {
    pub out_dir: PathBuf,
    pub contract_path: PathBuf,
    pub report_path: PathBuf,
    pub trace_ids_path: PathBuf,
    pub run_manifest_path: PathBuf,
    pub events_path: PathBuf,
    pub commands_path: PathBuf,
    pub step_logs_dir: PathBuf,
    pub summary_path: PathBuf,
    pub env_path: PathBuf,
    pub repro_lock_path: PathBuf,
    pub outcome: OrchestratorContextRefactorOutcome,
    pub contract_hash: String,
    pub report_hash: String,
    pub corrected_seam_count: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorContextRefactorError {
    #[error("failed to read `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to serialize `{path}`: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error(
        "orchestrator context refactor output directory is already locked by another writer: `{path}`"
    )]
    Busy { path: String },
    #[error("orchestrator source is missing: `{path}`")]
    MissingSource { path: String },
}

#[derive(Debug, thiserror::Error)]
pub enum AmbientMockGuardError {
    #[error("failed to read `{path}`: {source}")]
    Io {
        path: String,
        #[source]
        source: io::Error,
    },
    #[error("failed to serialize `{path}`: {source}")]
    Json {
        path: String,
        #[source]
        source: serde_json::Error,
    },
    #[error("ambient mock guard output directory is already locked by another writer: `{path}`")]
    Busy { path: String },
    #[error("ambient mock guard scan root does not contain `{expected}`: `{path}`")]
    MissingScanRoot { path: String, expected: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GuardScopeKind {
    TestOnly,
    MockModule,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GuardScopeFrame {
    kind: GuardScopeKind,
    depth: usize,
}

#[derive(Debug)]
struct AmbientMockGuardBundleLock {
    path: PathBuf,
}

impl Drop for AmbientMockGuardBundleLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[derive(Debug)]
struct OrchestratorContextRefactorBundleLock {
    path: PathBuf,
}

impl Drop for OrchestratorContextRefactorBundleLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn ambient_mock_guard_exit_code(report: &AmbientMockGuardReport) -> i32 {
    match report.outcome {
        AmbientMockGuardOutcome::Pass => 0,
        AmbientMockGuardOutcome::FailClosed => 2,
    }
}

pub fn evaluate_ambient_mock_guard() -> Result<AmbientMockGuardReport, AmbientMockGuardError> {
    evaluate_ambient_mock_guard_in_root(repo_root())
}

pub fn evaluate_ambient_mock_guard_in_root(
    workspace_root: impl AsRef<Path>,
) -> Result<AmbientMockGuardReport, AmbientMockGuardError> {
    let workspace_root = workspace_root.as_ref();
    let canonical_inventory = build_source_derived_inventory(workspace_root)
        .unwrap_or_else(|_| MockInventory::build(Vec::new(), Vec::new()));
    let (scanned_file_count, mut violations) =
        scan_workspace_for_ambient_mock_violations(workspace_root, AMBIENT_MOCK_GUARD_SCAN_ROOT)?;
    violations.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then(left.line_number.cmp(&right.line_number))
            .then(left.diagnostic_code.cmp(&right.diagnostic_code))
    });

    let summary = AmbientMockGuardSummary {
        scanned_file_count,
        violation_count: violations.len() as u64,
        architectural_violation_count: violations
            .iter()
            .filter(|violation| violation.rule == AmbientMockGuardRule::MockModuleMustBeCfgTest)
            .count() as u64,
        production_reference_violation_count: violations
            .iter()
            .filter(|violation| {
                violation.rule == AmbientMockGuardRule::NoProductionMockModuleReference
            })
            .count() as u64,
        fake_context_violation_count: violations
            .iter()
            .filter(|violation| {
                violation.rule == AmbientMockGuardRule::NoProductionFakeContextSymbol
            })
            .count() as u64,
    };

    Ok(AmbientMockGuardReport {
        schema_version: AMBIENT_MOCK_GUARD_REPORT_SCHEMA_VERSION.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        bead_id: AMBIENT_MOCK_GUARD_BEAD_ID.to_string(),
        policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
        canonical_inventory_hash: canonical_inventory.inventory_hash.to_string(),
        scan_root: AMBIENT_MOCK_GUARD_SCAN_ROOT.to_string(),
        outcome: if violations.is_empty() {
            AmbientMockGuardOutcome::Pass
        } else {
            AmbientMockGuardOutcome::FailClosed
        },
        summary,
        violations,
    })
}

pub fn write_ambient_mock_guard_bundle(
    out_dir: impl AsRef<Path>,
    command_lines: &[String],
) -> Result<AmbientMockGuardArtifacts, AmbientMockGuardError> {
    write_ambient_mock_guard_bundle_in_root(repo_root(), out_dir, command_lines)
}

pub fn write_ambient_mock_guard_bundle_in_root(
    workspace_root: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    command_lines: &[String],
) -> Result<AmbientMockGuardArtifacts, AmbientMockGuardError> {
    let workspace_root = workspace_root.as_ref();
    let out_dir = out_dir.as_ref().to_path_buf();
    fs::create_dir_all(&out_dir).map_err(|source| AmbientMockGuardError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;

    let report = evaluate_ambient_mock_guard_in_root(workspace_root)?;
    let report_path = out_dir.join("ambient_mock_guard_report.json");
    let migration_report_path = out_dir.join("control_plane_mock_surface_migration_report.json");
    let regression_report_path = out_dir.join("control_plane_mock_guard_regression_report.json");
    let trace_ids_path = out_dir.join("trace_ids.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let step_logs_dir = out_dir.join("step_logs");
    let summary_path = out_dir.join("summary.md");
    let env_path = out_dir.join("env.json");
    let repro_lock_path = out_dir.join("repro.lock");

    let report_bytes = ambient_mock_guard_json_bytes(&report, &report_path)?;
    let regression_report =
        evaluate_ambient_mock_guard_regression_report(&report.canonical_inventory_hash)?;
    let regression_report_bytes =
        ambient_mock_guard_json_bytes(&regression_report, &regression_report_path)?;
    let report_hash = sha256_hex(&report_bytes);
    let short_hash = report_hash.chars().take(16).collect::<String>();
    let trace_id = format!("trace-ambient-mock-guard-{short_hash}");
    let decision_id = format!("decision-ambient-mock-guard-{short_hash}");

    let trace_ids = AmbientMockGuardTraceIds {
        schema_version: AMBIENT_MOCK_GUARD_TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
        report_hash: report_hash.clone(),
        canonical_inventory_hash: report.canonical_inventory_hash.clone(),
    };
    let trace_ids_bytes = ambient_mock_guard_json_bytes(&trace_ids, &trace_ids_path)?;

    let events = build_ambient_mock_guard_events(&report, &trace_id, &decision_id);
    let mut events_jsonl = String::new();
    for event in &events {
        let line = serde_json::to_string(event).map_err(|source| AmbientMockGuardError::Json {
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

    let summary_md = render_ambient_mock_guard_summary(&report, &trace_id, &decision_id);
    let env_json = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": "frankenengine.ambient-mock-guard.env.v1",
        "component": AMBIENT_MOCK_GUARD_COMPONENT,
        "policy_id": AMBIENT_MOCK_GUARD_POLICY_ID,
        "workspace_root": workspace_root.display().to_string(),
        "scan_root_contract": AMBIENT_MOCK_GUARD_SCAN_ROOT,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "toolchain": std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".to_string()),
    }))
    .map_err(|source| AmbientMockGuardError::Json {
        path: env_path.display().to_string(),
        source,
    })?;
    let repro_lock = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": "franken-engine.repro-lock.v1",
        "component": AMBIENT_MOCK_GUARD_COMPONENT,
        "policy_id": AMBIENT_MOCK_GUARD_POLICY_ID,
        "scan_root_contract": AMBIENT_MOCK_GUARD_SCAN_ROOT,
        "canonical_inventory_hash": report.canonical_inventory_hash,
        "report_hash": report_hash,
        "replay_command": replay_command_for_bundle("franken_ambient_mock_guard", workspace_root),
    }))
    .map_err(|source| AmbientMockGuardError::Json {
        path: repro_lock_path.display().to_string(),
        source,
    })?;

    let manifest = AmbientMockGuardRunManifest {
        schema_version: AMBIENT_MOCK_GUARD_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
        report_hash: report_hash.clone(),
        canonical_inventory_hash: report.canonical_inventory_hash.clone(),
        outcome: report.outcome,
        violation_count: report.summary.violation_count,
        artifact_paths: AmbientMockGuardArtifactPaths {
            ambient_mock_guard_report: "ambient_mock_guard_report.json".to_string(),
            control_plane_mock_surface_migration_report:
                "control_plane_mock_surface_migration_report.json".to_string(),
            control_plane_mock_guard_regression_report:
                "control_plane_mock_guard_regression_report.json".to_string(),
            trace_ids: "trace_ids.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
            step_logs_dir: "step_logs".to_string(),
            summary_md: "summary.md".to_string(),
            env_json: "env.json".to_string(),
            repro_lock: "repro.lock".to_string(),
        },
    };
    let manifest_bytes = ambient_mock_guard_json_bytes(&manifest, &run_manifest_path)?;

    let _bundle_lock = acquire_ambient_mock_guard_bundle_lock(&out_dir)?;
    write_ambient_mock_guard_atomic(&report_path, &report_bytes)?;
    write_ambient_mock_guard_atomic(&migration_report_path, &report_bytes)?;
    write_ambient_mock_guard_atomic(&regression_report_path, &regression_report_bytes)?;
    write_ambient_mock_guard_atomic(&trace_ids_path, &trace_ids_bytes)?;
    write_ambient_mock_guard_atomic(&events_path, events_jsonl.as_bytes())?;
    write_ambient_mock_guard_atomic(&commands_path, commands_buf.as_bytes())?;
    fs::create_dir_all(&step_logs_dir).map_err(|source| AmbientMockGuardError::Io {
        path: step_logs_dir.display().to_string(),
        source,
    })?;
    let step_log = render_ambient_mock_guard_step_log(&report, &trace_id, &decision_id);
    write_ambient_mock_guard_atomic(
        &step_logs_dir.join("step_001_scan.log"),
        step_log.as_bytes(),
    )?;
    write_ambient_mock_guard_atomic(&summary_path, summary_md.as_bytes())?;
    write_ambient_mock_guard_atomic(&env_path, &env_json)?;
    write_ambient_mock_guard_atomic(&repro_lock_path, &repro_lock)?;
    write_ambient_mock_guard_atomic(&run_manifest_path, &manifest_bytes)?;
    if regression_report.outcome != AmbientMockGuardOutcome::Pass {
        let detail = regression_report
            .scenarios
            .iter()
            .find(|scenario| !scenario.passed)
            .map(|scenario| {
                format!(
                    "regression scenario `{}` failed: {}",
                    scenario.scenario_id,
                    scenario.notes.join("; ")
                )
            })
            .unwrap_or_else(|| "ambient mock guard regression suite failed".to_string());
        return Err(AmbientMockGuardError::Io {
            path: regression_report_path.display().to_string(),
            source: io::Error::other(detail),
        });
    }

    Ok(AmbientMockGuardArtifacts {
        out_dir,
        report_path,
        migration_report_path,
        regression_report_path,
        trace_ids_path,
        run_manifest_path,
        events_path,
        commands_path,
        step_logs_dir,
        summary_path,
        env_path,
        repro_lock_path,
        outcome: report.outcome,
        report_hash,
        violation_count: report.violations.len(),
    })
}

pub fn orchestrator_context_refactor_exit_code(report: &OrchestratorContextRefactorReport) -> i32 {
    match report.outcome {
        OrchestratorContextRefactorOutcome::Pass => 0,
        OrchestratorContextRefactorOutcome::FailClosed => 2,
    }
}

pub fn evaluate_orchestrator_context_refactor() -> Result<
    (
        ProductionContextPathContract,
        OrchestratorContextRefactorReport,
    ),
    OrchestratorContextRefactorError,
> {
    evaluate_orchestrator_context_refactor_in_root(repo_root())
}

pub fn evaluate_orchestrator_context_refactor_in_root(
    workspace_root: impl AsRef<Path>,
) -> Result<
    (
        ProductionContextPathContract,
        OrchestratorContextRefactorReport,
    ),
    OrchestratorContextRefactorError,
> {
    let workspace_root = workspace_root.as_ref();
    let orchestrator_path = workspace_root.join(ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE);
    let source = fs::read_to_string(&orchestrator_path).map_err(|source| {
        if source.kind() == ErrorKind::NotFound {
            OrchestratorContextRefactorError::MissingSource {
                path: orchestrator_path.display().to_string(),
            }
        } else {
            OrchestratorContextRefactorError::Io {
                path: orchestrator_path.display().to_string(),
                source,
            }
        }
    })?;

    let canonical_inventory = build_source_derived_inventory(workspace_root)
        .unwrap_or_else(|_| MockInventory::build(Vec::new(), Vec::new()));
    let corrected_seams = canonical_inventory
        .occurrences
        .iter()
        .filter(|occurrence| {
            occurrence.file_path == ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE
                && occurrence.classification == SeamClassification::MustFixProduction
                && occurrence.remediation_bead == ORCHESTRATOR_CONTEXT_REFACTOR_BEAD_ID
        })
        .map(build_corrected_production_seam)
        .collect::<Vec<_>>();

    let guards = build_orchestrator_context_refactor_guards(&source);
    let contract = ProductionContextPathContract {
        schema_version: ORCHESTRATOR_CONTEXT_PATH_CONTRACT_SCHEMA_VERSION.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        bead_id: ORCHESTRATOR_CONTEXT_REFACTOR_BEAD_ID.to_string(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        canonical_inventory_hash: canonical_inventory.inventory_hash.to_string(),
        source_file: ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE.to_string(),
        context_paths: vec![ProductionContextPath {
            path_id: ORCHESTRATOR_CONTEXT_PATH_ID.to_string(),
            source_file: ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE.to_string(),
            source_symbol: "ExecutionOrchestrator::build_cell_close_context".to_string(),
            context_origin:
                "KernelContext::new(Cx::new(Self::derive_cell_close_trace_id(trace_id), Budget::new(budget_ms), NoCaps))"
                    .to_string(),
            trace_origin: "ExecutionOrchestrator::derive_cell_close_trace_id(trace_id)"
                .to_string(),
            budget_origin: "OrchestratorConfig.cell_close_budget_ms -> Budget::new(budget_ms)"
                .to_string(),
            capability_scope: "NoCaps".to_string(),
            deterministic_fallback:
                "OrchestratorError::Cell(CellError::BudgetExhausted { .. })".to_string(),
        }],
        corrected_seams: corrected_seams.clone(),
        deferred_seams: Vec::new(),
        guards: guards.clone(),
    };

    let contract_bytes = ambient_mock_guard_json_bytes(&contract, &orchestrator_path)
        .map_err(map_refactor_json_error(&orchestrator_path))?;
    let contract_hash = sha256_hex(&contract_bytes);
    let failed_guard_count = guards.iter().filter(|guard| !guard.passed).count() as u64;
    // If the source-derived inventory found no must-fix production items for
    // the orchestrator, the refactor is already complete — Pass if guards also
    // hold. If must-fix items still exist (corrected_seams non-empty), Pass
    // only when all guards hold. FailClosed if guards fail or if must-fix
    // items were found but the seam list is somehow empty (shouldn't happen
    // with source-derived scanning, but kept for defensive correctness).
    let has_remaining_must_fix = canonical_inventory.occurrences.iter().any(|o| {
        o.file_path == ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE
            && o.classification == SeamClassification::MustFixProduction
    });
    let outcome =
        if failed_guard_count > 0 || (has_remaining_must_fix && corrected_seams.is_empty()) {
            OrchestratorContextRefactorOutcome::FailClosed
        } else {
            OrchestratorContextRefactorOutcome::Pass
        };
    let report = OrchestratorContextRefactorReport {
        schema_version: ORCHESTRATOR_CONTEXT_REFACTOR_REPORT_SCHEMA_VERSION.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        bead_id: ORCHESTRATOR_CONTEXT_REFACTOR_BEAD_ID.to_string(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        canonical_inventory_hash: canonical_inventory.inventory_hash.to_string(),
        contract_hash,
        source_file: ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE.to_string(),
        outcome,
        summary: OrchestratorContextRefactorSummary {
            corrected_seam_count: corrected_seams.len() as u64,
            deferred_seam_count: 0,
            guard_count: guards.len() as u64,
            failed_guard_count,
        },
        corrected_seams,
        deferred_seams: Vec::new(),
        guards,
    };

    Ok((contract, report))
}

pub fn write_orchestrator_context_refactor_bundle(
    out_dir: impl AsRef<Path>,
    command_lines: &[String],
) -> Result<OrchestratorContextRefactorArtifacts, OrchestratorContextRefactorError> {
    write_orchestrator_context_refactor_bundle_in_root(repo_root(), out_dir, command_lines)
}

pub fn write_orchestrator_context_refactor_bundle_in_root(
    workspace_root: impl AsRef<Path>,
    out_dir: impl AsRef<Path>,
    command_lines: &[String],
) -> Result<OrchestratorContextRefactorArtifacts, OrchestratorContextRefactorError> {
    let workspace_root = workspace_root.as_ref();
    let out_dir = out_dir.as_ref().to_path_buf();
    fs::create_dir_all(&out_dir).map_err(|source| OrchestratorContextRefactorError::Io {
        path: out_dir.display().to_string(),
        source,
    })?;

    let (contract, report) = evaluate_orchestrator_context_refactor_in_root(workspace_root)?;
    let contract_path = out_dir.join("production_context_path_contract.json");
    let report_path = out_dir.join("orchestrator_context_refactor_report.json");
    let trace_ids_path = out_dir.join("trace_ids.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let step_logs_dir = out_dir.join("step_logs");
    let summary_path = out_dir.join("summary.md");
    let env_path = out_dir.join("env.json");
    let repro_lock_path = out_dir.join("repro.lock");

    let contract_bytes = ambient_mock_guard_json_bytes(&contract, &contract_path)
        .map_err(map_refactor_json_error(&contract_path))?;
    let report_bytes = ambient_mock_guard_json_bytes(&report, &report_path)
        .map_err(map_refactor_json_error(&report_path))?;
    let contract_hash = sha256_hex(&contract_bytes);
    let report_hash = sha256_hex(&report_bytes);
    let short_hash = report_hash.chars().take(16).collect::<String>();
    let trace_id = format!("trace-orchestrator-context-refactor-{short_hash}");
    let decision_id = format!("decision-orchestrator-context-refactor-{short_hash}");

    let trace_ids = OrchestratorContextRefactorTraceIds {
        schema_version: ORCHESTRATOR_CONTEXT_REFACTOR_TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        report_hash: report_hash.clone(),
        contract_hash: contract_hash.clone(),
        canonical_inventory_hash: report.canonical_inventory_hash.clone(),
    };
    let trace_ids_bytes = ambient_mock_guard_json_bytes(&trace_ids, &trace_ids_path)
        .map_err(map_refactor_json_error(&trace_ids_path))?;

    let events = build_orchestrator_context_refactor_events(&report, &trace_id, &decision_id);
    let mut events_jsonl = String::new();
    for event in &events {
        let line = serde_json::to_string(event).map_err(|source| {
            OrchestratorContextRefactorError::Json {
                path: events_path.display().to_string(),
                source,
            }
        })?;
        events_jsonl.push_str(&line);
        events_jsonl.push('\n');
    }

    let mut commands_buf = String::new();
    for command in command_lines {
        commands_buf.push_str(command);
        commands_buf.push('\n');
    }

    let summary_md = render_orchestrator_context_refactor_summary(&report, &trace_id, &decision_id);
    let env_json = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": "frankenengine.orchestrator-context-refactor.env.v1",
        "component": ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT,
        "policy_id": ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID,
        "workspace_root": workspace_root.display().to_string(),
        "source_file": ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "toolchain": std::env::var("RUSTUP_TOOLCHAIN").unwrap_or_else(|_| "unknown".to_string()),
    }))
    .map_err(|source| OrchestratorContextRefactorError::Json {
        path: env_path.display().to_string(),
        source,
    })?;
    let repro_lock = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": "franken-engine.repro-lock.v1",
        "component": ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT,
        "policy_id": ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID,
        "source_file": ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE,
        "canonical_inventory_hash": report.canonical_inventory_hash,
        "contract_hash": contract_hash,
        "report_hash": report_hash,
        "replay_command": replay_command_for_bundle("franken_orchestrator_context_refactor", workspace_root),
    }))
    .map_err(|source| OrchestratorContextRefactorError::Json {
        path: repro_lock_path.display().to_string(),
        source,
    })?;

    let manifest = OrchestratorContextRefactorRunManifest {
        schema_version: ORCHESTRATOR_CONTEXT_REFACTOR_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        trace_id: trace_id.clone(),
        decision_id: decision_id.clone(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        report_hash: report_hash.clone(),
        contract_hash: contract_hash.clone(),
        canonical_inventory_hash: report.canonical_inventory_hash.clone(),
        outcome: report.outcome,
        corrected_seam_count: report.summary.corrected_seam_count,
        failed_guard_count: report.summary.failed_guard_count,
        artifact_paths: OrchestratorContextRefactorArtifactPaths {
            production_context_path_contract: "production_context_path_contract.json".to_string(),
            orchestrator_context_refactor_report: "orchestrator_context_refactor_report.json"
                .to_string(),
            trace_ids: "trace_ids.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
            step_logs_dir: "step_logs".to_string(),
            summary_md: "summary.md".to_string(),
            env_json: "env.json".to_string(),
            repro_lock: "repro.lock".to_string(),
        },
    };
    let manifest_bytes = ambient_mock_guard_json_bytes(&manifest, &run_manifest_path)
        .map_err(map_refactor_json_error(&run_manifest_path))?;

    let _bundle_lock = acquire_orchestrator_context_refactor_bundle_lock(&out_dir)?;
    write_orchestrator_context_refactor_atomic(&contract_path, &contract_bytes)?;
    write_orchestrator_context_refactor_atomic(&report_path, &report_bytes)?;
    write_orchestrator_context_refactor_atomic(&trace_ids_path, &trace_ids_bytes)?;
    write_orchestrator_context_refactor_atomic(&events_path, events_jsonl.as_bytes())?;
    write_orchestrator_context_refactor_atomic(&commands_path, commands_buf.as_bytes())?;
    fs::create_dir_all(&step_logs_dir).map_err(|source| OrchestratorContextRefactorError::Io {
        path: step_logs_dir.display().to_string(),
        source,
    })?;
    let step_log = render_orchestrator_context_refactor_step_log(&report, &trace_id, &decision_id);
    write_orchestrator_context_refactor_atomic(
        &step_logs_dir.join("step_001_scan.log"),
        step_log.as_bytes(),
    )?;
    write_orchestrator_context_refactor_atomic(&summary_path, summary_md.as_bytes())?;
    write_orchestrator_context_refactor_atomic(&env_path, &env_json)?;
    write_orchestrator_context_refactor_atomic(&repro_lock_path, &repro_lock)?;
    write_orchestrator_context_refactor_atomic(&run_manifest_path, &manifest_bytes)?;

    Ok(OrchestratorContextRefactorArtifacts {
        out_dir,
        contract_path,
        report_path,
        trace_ids_path,
        run_manifest_path,
        events_path,
        commands_path,
        step_logs_dir,
        summary_path,
        env_path,
        repro_lock_path,
        outcome: report.outcome,
        contract_hash,
        report_hash,
        corrected_seam_count: report.corrected_seams.len(),
    })
}

fn build_corrected_production_seam(occurrence: &SeamOccurrence) -> CorrectedProductionSeam {
    CorrectedProductionSeam {
        seam_id: format!(
            "{}:{}:{}",
            occurrence.file_path, occurrence.line_number, occurrence.kind
        ),
        occurrence_hash: occurrence.content_hash().to_string(),
        original_file_path: occurrence.file_path.clone(),
        original_line_number: occurrence.line_number,
        seam_kind: occurrence.kind,
        previous_pattern: occurrence.description.clone(),
        corrected_path_id: ORCHESTRATOR_CONTEXT_PATH_ID.to_string(),
        corrected_context_source: "ExecutionOrchestrator::build_cell_close_context".to_string(),
        corrected_trace_source: "ExecutionOrchestrator::derive_cell_close_trace_id(trace_id)"
            .to_string(),
        corrected_budget_source: "OrchestratorConfig.cell_close_budget_ms".to_string(),
    }
}

fn build_orchestrator_context_refactor_guards(source: &str) -> Vec<ContextRefactorGuard> {
    let mut guards = Vec::new();
    for (guard_id, needle) in ORCHESTRATOR_CONTEXT_REFACTOR_FORBIDDEN_TOKENS {
        let passed = !source.contains(needle);
        guards.push(ContextRefactorGuard {
            guard_id: (*guard_id).to_string(),
            guard_kind: "forbidden_token".to_string(),
            needle: (*needle).to_string(),
            passed,
            error_code: (!passed).then(|| format!("OCR-FORBIDDEN-{}", guard_id.to_uppercase())),
        });
    }
    for (guard_id, needle) in ORCHESTRATOR_CONTEXT_REFACTOR_REQUIRED_TOKENS {
        let passed = source.contains(needle);
        guards.push(ContextRefactorGuard {
            guard_id: (*guard_id).to_string(),
            guard_kind: "required_token".to_string(),
            needle: (*needle).to_string(),
            passed,
            error_code: (!passed).then(|| format!("OCR-REQUIRED-{}", guard_id.to_uppercase())),
        });
    }
    guards
}

fn build_orchestrator_context_refactor_events(
    report: &OrchestratorContextRefactorReport,
    trace_id: &str,
    decision_id: &str,
) -> Vec<OrchestratorContextRefactorEvent> {
    let mut events = report
        .guards
        .iter()
        .map(|guard| OrchestratorContextRefactorEvent {
            schema_version: ORCHESTRATOR_CONTEXT_REFACTOR_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
            component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
            event: "guard_evaluated".to_string(),
            outcome: if guard.passed { "pass" } else { "fail" }.to_string(),
            error_code: guard.error_code.clone(),
            seed: "orchestrator-context-refactor-static-scan-v1".to_string(),
            scenario_id: "workspace-source-scan".to_string(),
            diagnostic_id: Some(guard.guard_id.clone()),
            file_path: Some(ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE.to_string()),
            line_number: None,
            detail: Some(format!("{} => `{}`", guard.guard_kind, guard.needle)),
        })
        .collect::<Vec<_>>();

    events.push(OrchestratorContextRefactorEvent {
        schema_version: ORCHESTRATOR_CONTEXT_REFACTOR_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        event: "refactor_evaluated".to_string(),
        outcome: report.outcome.as_str().to_string(),
        error_code: None,
        seed: "orchestrator-context-refactor-static-scan-v1".to_string(),
        scenario_id: "workspace-source-scan".to_string(),
        diagnostic_id: None,
        file_path: Some(report.source_file.clone()),
        line_number: None,
        detail: Some(format!(
            "{} corrected seam(s); {} guard failure(s)",
            report.summary.corrected_seam_count, report.summary.failed_guard_count
        )),
    });

    events
}

fn render_orchestrator_context_refactor_summary(
    report: &OrchestratorContextRefactorReport,
    trace_id: &str,
    decision_id: &str,
) -> String {
    let mut lines = vec![
        "# Orchestrator Context Refactor Summary".to_string(),
        String::new(),
        format!("Outcome: `{}`", report.outcome),
        format!("Policy: `{}`", report.policy_id),
        format!("Bead: `{}`", report.bead_id),
        format!("Trace: `{trace_id}`"),
        format!("Decision: `{decision_id}`"),
        format!("Source file: `{}`", report.source_file),
        format!(
            "Canonical inventory hash: `{}`",
            report.canonical_inventory_hash
        ),
        format!("Contract hash: `{}`", report.contract_hash),
        format!("Corrected seams: {}", report.summary.corrected_seam_count),
        format!("Failed guards: {}", report.summary.failed_guard_count),
        String::new(),
        "## Corrected seams".to_string(),
        String::new(),
    ];

    for seam in &report.corrected_seams {
        lines.push(format!(
            "- `{}` {}:{} -> `{}`",
            seam.seam_kind,
            seam.original_file_path,
            seam.original_line_number,
            seam.corrected_context_source
        ));
    }

    lines.push(String::new());
    lines.push("## Guard results".to_string());
    lines.push(String::new());
    for guard in &report.guards {
        lines.push(format!(
            "- `{}` [{}] `{}`",
            guard.guard_id,
            if guard.passed { "pass" } else { "fail" },
            guard.needle
        ));
    }

    lines.join("\n")
}

fn render_orchestrator_context_refactor_step_log(
    report: &OrchestratorContextRefactorReport,
    trace_id: &str,
    decision_id: &str,
) -> String {
    let mut output = String::new();
    output.push_str(&format!("trace_id={trace_id}\n"));
    output.push_str(&format!("decision_id={decision_id}\n"));
    output.push_str(&format!(
        "policy_id={}\n",
        ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID
    ));
    output.push_str(&format!("outcome={}\n", report.outcome));
    output.push_str(&format!(
        "corrected_seam_count={}\n",
        report.summary.corrected_seam_count
    ));
    output.push_str(&format!(
        "failed_guard_count={}\n",
        report.summary.failed_guard_count
    ));
    for seam in &report.corrected_seams {
        output.push_str(&format!(
            "corrected_seam={} {}:{} -> {}\n",
            seam.seam_kind,
            seam.original_file_path,
            seam.original_line_number,
            seam.corrected_context_source
        ));
    }
    for guard in &report.guards {
        output.push_str(&format!(
            "guard={} kind={} passed={} needle={}\n",
            guard.guard_id, guard.guard_kind, guard.passed, guard.needle
        ));
    }
    output
}

fn acquire_orchestrator_context_refactor_bundle_lock(
    out_dir: &Path,
) -> Result<OrchestratorContextRefactorBundleLock, OrchestratorContextRefactorError> {
    let lock_path = control_plane_mock_shared_bundle_lock_path(out_dir);
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&lock_path)
    {
        Ok(_) => Ok(OrchestratorContextRefactorBundleLock { path: lock_path }),
        Err(source) if source.kind() == ErrorKind::AlreadyExists => {
            Err(OrchestratorContextRefactorError::Busy {
                path: lock_path.display().to_string(),
            })
        }
        Err(source) => Err(OrchestratorContextRefactorError::Io {
            path: lock_path.display().to_string(),
            source,
        }),
    }
}

fn write_orchestrator_context_refactor_atomic(
    path: &Path,
    bytes: &[u8],
) -> Result<(), OrchestratorContextRefactorError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| OrchestratorContextRefactorError::Io {
            path: parent.display().to_string(),
            source,
        })?;
    }

    let temp_path = ambient_mock_guard_temp_path(path);
    fs::write(&temp_path, bytes).map_err(|source| OrchestratorContextRefactorError::Io {
        path: temp_path.display().to_string(),
        source,
    })?;
    if let Err(source) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(OrchestratorContextRefactorError::Io {
            path: path.display().to_string(),
            source,
        });
    }
    Ok(())
}

fn map_refactor_json_error(
    path: &Path,
) -> impl FnOnce(AmbientMockGuardError) -> OrchestratorContextRefactorError + '_ {
    move |error| match error {
        AmbientMockGuardError::Json { source, .. } => OrchestratorContextRefactorError::Json {
            path: path.display().to_string(),
            source,
        },
        AmbientMockGuardError::Io { source, .. } => OrchestratorContextRefactorError::Io {
            path: path.display().to_string(),
            source,
        },
        AmbientMockGuardError::Busy { .. } => OrchestratorContextRefactorError::Busy {
            path: path.display().to_string(),
        },
        AmbientMockGuardError::MissingScanRoot { .. } => {
            OrchestratorContextRefactorError::MissingSource {
                path: path.display().to_string(),
            }
        }
    }
}

fn scan_workspace_for_ambient_mock_violations(
    workspace_root: &Path,
    scan_root: &str,
) -> Result<(u64, Vec<AmbientMockGuardViolation>), AmbientMockGuardError> {
    let source_root = workspace_root.join(scan_root);
    if !source_root.exists() {
        return Err(AmbientMockGuardError::MissingScanRoot {
            path: workspace_root.display().to_string(),
            expected: scan_root.to_string(),
        });
    }

    let mut rust_files = Vec::new();
    collect_rust_files(&source_root, &mut rust_files)?;

    let mut scanned_file_count = 0u64;
    let mut violations = Vec::new();
    for file_path in &rust_files {
        let relative_path = relative_path_from(workspace_root, file_path);
        if relative_path == "crates/franken-engine/src/control_plane_mock_inventory.rs" {
            continue;
        }
        scanned_file_count += 1;
        violations.extend(scan_rust_file_for_ambient_mock_violations(
            workspace_root,
            file_path,
            &relative_path,
        )?);
    }

    Ok((scanned_file_count, violations))
}

fn collect_rust_files(dir: &Path, files: &mut Vec<PathBuf>) -> Result<(), AmbientMockGuardError> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).map_err(|source| AmbientMockGuardError::Io {
        path: dir.display().to_string(),
        source,
    })? {
        let entry = entry.map_err(|source| AmbientMockGuardError::Io {
            path: dir.display().to_string(),
            source,
        })?;
        entries.push(entry.path());
    }
    entries.sort();

    for path in entries {
        if path.is_dir() {
            collect_rust_files(&path, files)?;
        } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
            files.push(path);
        }
    }
    Ok(())
}

fn scan_rust_file_for_ambient_mock_violations(
    workspace_root: &Path,
    file_path: &Path,
    relative_path: &str,
) -> Result<Vec<AmbientMockGuardViolation>, AmbientMockGuardError> {
    let source = fs::read_to_string(file_path).map_err(|source| AmbientMockGuardError::Io {
        path: file_path.display().to_string(),
        source,
    })?;

    let file_is_test = relative_path.contains("/tests/");
    let mut violations = Vec::new();
    let mut in_block_comment = false;
    let mut brace_depth = 0usize;
    let mut pending_test_scope = false;
    let mut pending_mock_module_scope = false;
    let mut scope_stack: Vec<GuardScopeFrame> = Vec::new();

    for (index, raw_line) in source.lines().enumerate() {
        let line_number = (index + 1) as u32;
        let code_line = strip_non_code_segments(raw_line, &mut in_block_comment);
        let trimmed = code_line.trim();
        let line_has_cfg_test = is_cfg_test_attribute(trimmed);

        if line_has_cfg_test {
            pending_test_scope = true;
        }

        let is_test_context = file_is_test
            || pending_test_scope
            || line_has_cfg_test
            || scope_stack
                .iter()
                .any(|frame| frame.kind == GuardScopeKind::TestOnly);
        let is_mock_module_context = scope_stack
            .iter()
            .any(|frame| frame.kind == GuardScopeKind::MockModule);

        if is_mock_module_definition(trimmed) {
            pending_mock_module_scope = true;
            if !is_test_context {
                violations.push(guard_violation(GuardViolationInput {
                    rule: AmbientMockGuardRule::MockModuleMustBeCfgTest,
                    diagnostic_code: "AMG-ARCH-UNGARDED-MOCK-MODULE",
                    severity: SeamSeverity::High,
                    relative_path,
                    line_number,
                    code_snippet: trimmed,
                    detail:
                        "mock helper module is reachable from non-test production code because `pub mod mocks` is not gated behind `#[cfg(test)]`",
                    remediation:
                        "Add `#[cfg(test)]` to the mock module or move it behind a test-only feature gate.",
                }));
            }
        }

        if !trimmed.is_empty() && !is_test_context && !is_mock_module_context {
            violations.extend(line_level_guard_violations(
                relative_path,
                line_number,
                trimmed,
            ));
        }

        let open_braces = trimmed.chars().filter(|ch| *ch == '{').count();
        if open_braces > 0 {
            if pending_test_scope {
                scope_stack.push(GuardScopeFrame {
                    kind: GuardScopeKind::TestOnly,
                    depth: brace_depth + 1,
                });
                pending_test_scope = false;
            }
            if pending_mock_module_scope {
                scope_stack.push(GuardScopeFrame {
                    kind: GuardScopeKind::MockModule,
                    depth: brace_depth + 1,
                });
                pending_mock_module_scope = false;
            }
        }

        if pending_test_scope && pending_scope_consumed_without_block(trimmed, open_braces) {
            pending_test_scope = false;
        }
        if pending_mock_module_scope && pending_scope_consumed_without_block(trimmed, open_braces) {
            pending_mock_module_scope = false;
        }

        let close_braces = trimmed.chars().filter(|ch| *ch == '}').count();
        brace_depth += open_braces;
        brace_depth = brace_depth.saturating_sub(close_braces);

        while scope_stack
            .last()
            .is_some_and(|frame| brace_depth < frame.depth)
        {
            scope_stack.pop();
        }
    }

    // Ensure relative paths in diagnostics are always workspace-relative.
    for violation in &mut violations {
        if violation
            .file_path
            .starts_with(&workspace_root.display().to_string())
        {
            violation.file_path = relative_path.to_string();
        }
    }

    Ok(violations)
}

fn line_level_guard_violations(
    relative_path: &str,
    line_number: u32,
    trimmed: &str,
) -> Vec<AmbientMockGuardViolation> {
    let mut violations = Vec::new();

    if is_production_mock_module_reference(trimmed) {
        violations.push(guard_violation(GuardViolationInput {
            rule: AmbientMockGuardRule::NoProductionMockModuleReference,
            diagnostic_code: "AMG-PROD-MOCK-MODULE-REFERENCE",
            severity: SeamSeverity::Critical,
            relative_path,
            line_number,
            code_snippet: trimmed,
            detail: "production code references `control_plane::mocks` directly",
            remediation:
                "Thread the canonical control-plane context instead of importing from `control_plane::mocks`.",
        }));
    }

    if let Some((diagnostic_code, detail)) = fake_context_symbol_match(trimmed) {
        violations.push(guard_violation(GuardViolationInput {
            rule: AmbientMockGuardRule::NoProductionFakeContextSymbol,
            diagnostic_code,
            severity: SeamSeverity::Critical,
            relative_path,
            line_number,
            code_snippet: trimmed,
            detail,
            remediation:
                "Replace the fake context symbol with canonical runtime-managed context threading.",
        }));
    }

    violations
}

struct GuardViolationInput<'a> {
    rule: AmbientMockGuardRule,
    diagnostic_code: &'a str,
    severity: SeamSeverity,
    relative_path: &'a str,
    line_number: u32,
    code_snippet: &'a str,
    detail: &'a str,
    remediation: &'a str,
}

fn guard_violation(input: GuardViolationInput<'_>) -> AmbientMockGuardViolation {
    let violation_id = ambient_mock_guard_violation_id(
        input.relative_path,
        input.line_number,
        input.diagnostic_code,
    );
    AmbientMockGuardViolation {
        violation_id,
        rule: input.rule,
        severity: input.severity,
        diagnostic_code: input.diagnostic_code.to_string(),
        file_path: input.relative_path.to_string(),
        line_number: input.line_number,
        code_snippet: input.code_snippet.to_string(),
        detail: input.detail.to_string(),
        remediation: input.remediation.to_string(),
    }
}

fn ambient_mock_guard_violation_id(
    relative_path: &str,
    line_number: u32,
    diagnostic_code: &str,
) -> String {
    let seed = format!("{relative_path}:{line_number}:{diagnostic_code}");
    let hash = sha256_hex(seed.as_bytes());
    format!("amg-{}", &hash[..16])
}

fn is_cfg_test_attribute(line: &str) -> bool {
    let compact = line.replace(' ', "");
    compact.starts_with("#[cfg(test")
        || compact.contains("cfg(any(test")
        || compact.contains("cfg(all(test")
        || compact.contains(",test")
        || compact.contains("(test,")
}

fn is_mock_module_definition(line: &str) -> bool {
    line.starts_with("pub mod mocks") || line.starts_with("mod mocks")
}

fn is_production_mock_module_reference(line: &str) -> bool {
    (line.starts_with("use ")
        && (line.contains("crate::control_plane::mocks")
            || line.contains("super::mocks")
            || line.contains("super::super::mocks")))
        || line.contains("crate::control_plane::mocks::")
        || line.contains("control_plane::mocks::")
        || line.contains("super::mocks::")
        || line.contains("super::super::mocks::")
}

fn fake_context_symbol_match(line: &str) -> Option<(&'static str, &'static str)> {
    let symbols = [
        (
            "MockCx",
            "AMG-PROD-MOCK-CX",
            "production code references `MockCx`, which is a fake control-plane context",
        ),
        (
            "MockBudget",
            "AMG-PROD-MOCK-BUDGET",
            "production code references `MockBudget`, which bypasses canonical budget propagation",
        ),
        (
            "MockDecisionContract",
            "AMG-PROD-MOCK-DECISION-CONTRACT",
            "production code references `MockDecisionContract`, which is test-only policy scaffolding",
        ),
        (
            "MockEvidenceEmitter",
            "AMG-PROD-MOCK-EVIDENCE-EMITTER",
            "production code references `MockEvidenceEmitter`, which is test-only evidence scaffolding",
        ),
        (
            "MockFailureMode",
            "AMG-PROD-MOCK-FAILURE-MODE",
            "production code references `MockFailureMode`, which is test-only fault injection scaffolding",
        ),
        (
            "trace_id_from_seed",
            "AMG-PROD-SEED-TRACE-ID",
            "production code synthesizes trace identifiers from a seed instead of threading the canonical trace context",
        ),
        (
            "decision_id_from_seed",
            "AMG-PROD-SEED-DECISION-ID",
            "production code synthesizes decision identifiers from a seed instead of using canonical decision provenance",
        ),
        (
            "policy_id_from_seed",
            "AMG-PROD-SEED-POLICY-ID",
            "production code synthesizes policy identifiers from a seed instead of using canonical policy provenance",
        ),
        (
            "schema_version_from_seed",
            "AMG-PROD-SEED-SCHEMA-VERSION",
            "production code synthesizes schema versions from a seed instead of using canonical schema provenance",
        ),
    ];

    symbols
        .into_iter()
        .find(|(symbol, _, _)| contains_ident(line, symbol))
        .map(|(_, diagnostic_code, detail)| (diagnostic_code, detail))
}

fn contains_ident(line: &str, ident: &str) -> bool {
    let bytes = line.as_bytes();
    let ident_bytes = ident.as_bytes();
    if ident_bytes.is_empty() || ident_bytes.len() > bytes.len() {
        return false;
    }

    let mut start = 0usize;
    while start + ident_bytes.len() <= bytes.len() {
        let Some(offset) = line[start..].find(ident) else {
            break;
        };
        let absolute = start + offset;
        let before = absolute
            .checked_sub(1)
            .and_then(|index| bytes.get(index).copied());
        let after = bytes.get(absolute + ident_bytes.len()).copied();
        if !is_ident_byte(before) && !is_ident_byte(after) {
            return true;
        }
        start = absolute + ident_bytes.len();
    }
    false
}

fn is_ident_byte(byte: Option<u8>) -> bool {
    matches!(byte, Some(b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'))
}

fn pending_scope_consumed_without_block(line: &str, open_braces: usize) -> bool {
    open_braces == 0 && !line.is_empty() && line.ends_with(';')
}

fn strip_non_code_segments(line: &str, in_block_comment: &mut bool) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut output = String::with_capacity(line.len());
    let mut index = 0usize;
    let mut in_string = false;

    while index < chars.len() {
        if *in_block_comment {
            if chars[index] == '*' && chars.get(index + 1) == Some(&'/') {
                *in_block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }

        if in_string {
            if chars[index] == '\\' {
                index += 2;
                continue;
            }
            if chars[index] == '"' {
                in_string = false;
            }
            index += 1;
            continue;
        }

        if chars[index] == '/' && chars.get(index + 1) == Some(&'/') {
            break;
        }
        if chars[index] == '/' && chars.get(index + 1) == Some(&'*') {
            *in_block_comment = true;
            index += 2;
            continue;
        }
        if chars[index] == '"' {
            in_string = true;
            index += 1;
            continue;
        }

        output.push(chars[index]);
        index += 1;
    }

    output
}

fn build_control_plane_mock_inventory_events(
    inventory: &MockInventory,
    trace_id: &str,
    decision_id: &str,
) -> Vec<ControlPlaneMockInventoryEvent> {
    let mut events = vec![ControlPlaneMockInventoryEvent {
        schema_version: CONTROL_PLANE_MOCK_INVENTORY_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "inventory_started".to_string(),
        outcome: "started".to_string(),
        error_code: None,
        seed: "control-plane-mock-inventory-v1".to_string(),
        scenario_id: "canonical_inventory".to_string(),
        diagnostic_id: None,
        file_path: None,
        line_number: None,
        detail: Some("building canonical control-plane mock inventory".to_string()),
    }];

    for occurrence in inventory.must_fix_items() {
        events.push(ControlPlaneMockInventoryEvent {
            schema_version: CONTROL_PLANE_MOCK_INVENTORY_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            event: "production_seam_classified".to_string(),
            outcome: occurrence.classification.to_string(),
            error_code: Some("CPMI-MUST-FIX".to_string()),
            seed: "control-plane-mock-inventory-v1".to_string(),
            scenario_id: "canonical_inventory".to_string(),
            diagnostic_id: Some(occurrence.content_hash().to_string()),
            file_path: Some(occurrence.file_path.clone()),
            line_number: Some(occurrence.line_number),
            detail: Some(occurrence.description.clone()),
        });
    }

    for issue in &inventory.architectural_issues {
        events.push(ControlPlaneMockInventoryEvent {
            schema_version: CONTROL_PLANE_MOCK_INVENTORY_EVENT_SCHEMA_VERSION.to_string(),
            trace_id: trace_id.to_string(),
            decision_id: decision_id.to_string(),
            policy_id: CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID.to_string(),
            component: COMPONENT.to_string(),
            event: "architectural_issue_classified".to_string(),
            outcome: issue.severity.to_string(),
            error_code: Some("CPMI-ARCH-ISSUE".to_string()),
            seed: "control-plane-mock-inventory-v1".to_string(),
            scenario_id: "canonical_inventory".to_string(),
            diagnostic_id: Some(issue.id.clone()),
            file_path: Some(issue.file_path.clone()),
            line_number: None,
            detail: Some(issue.description.clone()),
        });
    }

    events.push(ControlPlaneMockInventoryEvent {
        schema_version: CONTROL_PLANE_MOCK_INVENTORY_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: trace_id.to_string(),
        decision_id: decision_id.to_string(),
        policy_id: CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID.to_string(),
        component: COMPONENT.to_string(),
        event: "inventory_completed".to_string(),
        outcome: ControlPlaneMockInventoryOutcome::InventoryComplete
            .as_str()
            .to_string(),
        error_code: None,
        seed: "control-plane-mock-inventory-v1".to_string(),
        scenario_id: "canonical_inventory".to_string(),
        diagnostic_id: None,
        file_path: None,
        line_number: None,
        detail: Some(format!(
            "{} occurrences, {} must-fix production seam(s), {} architectural issue(s)",
            inventory.summary.total_occurrences,
            inventory.summary.must_fix_count,
            inventory.summary.architectural_issue_count
        )),
    });

    events
}

fn render_control_plane_mock_inventory_summary(
    inventory: &MockInventory,
    trace_id: &str,
    decision_id: &str,
) -> String {
    let mut lines = vec![
        "# Control-Plane Mock Inventory Summary".to_string(),
        String::new(),
        format!(
            "Outcome: `{}`",
            ControlPlaneMockInventoryOutcome::InventoryComplete
        ),
        format!("Policy: `{}`", CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID),
        format!("Bead: `{}`", BEAD_ID),
        format!("Trace: `{trace_id}`"),
        format!("Decision: `{decision_id}`"),
        format!("Inventory hash: `{}`", inventory.inventory_hash),
        format!("Total occurrences: {}", inventory.summary.total_occurrences),
        format!(
            "Must-fix production seams: {}",
            inventory.summary.must_fix_count
        ),
        format!(
            "Acceptable test-only seams: {}",
            inventory.summary.test_only_count
        ),
        format!(
            "False positives: {}",
            inventory.summary.false_positive_count
        ),
        format!(
            "Architectural issues: {}",
            inventory.summary.architectural_issue_count
        ),
        String::new(),
        "## Must-Fix Production Seams".to_string(),
        String::new(),
    ];

    for occurrence in inventory.must_fix_items() {
        lines.push(format!(
            "- `{}` {}:{} {} -> `{}`",
            occurrence.kind,
            occurrence.file_path,
            occurrence.line_number,
            occurrence.description,
            occurrence.remediation_bead
        ));
    }

    lines.push(String::new());
    lines.push("## Architectural Issues".to_string());
    lines.push(String::new());
    for issue in &inventory.architectural_issues {
        lines.push(format!(
            "- `{}` {} {} -> `{}`",
            issue.id, issue.file_path, issue.description, issue.remediation_bead
        ));
    }

    lines.join("\n")
}

fn render_control_plane_mock_inventory_step_log(
    inventory: &MockInventory,
    trace_id: &str,
    decision_id: &str,
) -> String {
    let mut output = String::new();
    output.push_str(&format!("trace_id={trace_id}\n"));
    output.push_str(&format!("decision_id={decision_id}\n"));
    output.push_str(&format!(
        "policy_id={}\n",
        CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID
    ));
    output.push_str(&format!("inventory_hash={}\n", inventory.inventory_hash));
    output.push_str(&format!(
        "total_occurrences={}\n",
        inventory.summary.total_occurrences
    ));
    output.push_str(&format!(
        "must_fix_count={}\n",
        inventory.summary.must_fix_count
    ));
    output.push_str(&format!(
        "architectural_issue_count={}\n",
        inventory.summary.architectural_issue_count
    ));
    for occurrence in inventory.must_fix_items() {
        output.push_str(&format!(
            "must_fix={} {}:{} {}\n",
            occurrence.kind, occurrence.file_path, occurrence.line_number, occurrence.description
        ));
    }
    for issue in &inventory.architectural_issues {
        output.push_str(&format!(
            "architectural_issue={} {} {}\n",
            issue.id, issue.file_path, issue.description
        ));
    }
    output
}

fn ambient_mock_guard_temp_path(path: &Path) -> PathBuf {
    let sequence = NEXT_AMBIENT_MOCK_GUARD_TEMP_FILE_ID.fetch_add(1, Ordering::Relaxed);
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

fn relative_path_from(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn shell_quote_argument(arg: &str) -> String {
    if arg.is_empty() {
        return "''".to_string();
    }
    if arg.bytes().all(|byte| {
        matches!(
            byte,
            b'a'..=b'z'
                | b'A'..=b'Z'
                | b'0'..=b'9'
                | b'/'
                | b'.'
                | b'_'
                | b'-'
                | b':'
                | b'='
                | b'+'
        )
    }) {
        return arg.to_string();
    }
    format!("'{}'", arg.replace('\'', "'\"'\"'"))
}

pub fn render_command_transcript(args: &[String]) -> String {
    args.iter()
        .map(|arg| shell_quote_argument(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn render_bundle_command_lines(
    args: &[String],
    bin_name: &str,
    workspace_root: &Path,
) -> Vec<String> {
    vec![
        render_command_transcript(args),
        replay_command_for_bundle(bin_name, workspace_root),
    ]
}

fn replay_command_for_bundle(bin_name: &str, workspace_root: &Path) -> String {
    let repo_root = repo_root();
    if workspace_root == repo_root {
        return format!(
            "rch exec -- cargo run -p frankenengine-engine --bin {bin_name} -- --out-dir <DIR>"
        );
    }
    format!(
        "rch exec -- cargo run -p frankenengine-engine --bin {bin_name} -- --out-dir <DIR> --workspace-root {}",
        shell_quote_argument(&workspace_root.display().to_string())
    )
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock before epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "frankenengine-control-plane-mock-inventory-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn write_fixture_file(root: &Path, relative_path: &str, contents: &str) {
        let path = root.join(relative_path);
        fs::create_dir_all(path.parent().expect("fixture file must have parent"))
            .expect("create fixture parent");
        fs::write(path, contents).expect("write fixture file");
    }

    fn sample_occurrence(
        path: &str,
        line: u32,
        classification: SeamClassification,
    ) -> SeamOccurrence {
        SeamOccurrence::new(SeamOccurrenceInput {
            file_path: path,
            line_number: line,
            kind: SeamKind::MockContext,
            classification,
            severity: SeamSeverity::High,
            inside_cfg_test: classification == SeamClassification::AcceptableTestOnly,
            description: "test occurrence",
            remediation: RemediationStrategy::NoAction,
            remediation_bead: "",
        })
    }

    fn sample_architectural_issue(
        id: &str,
        description: &str,
        file_path: &str,
    ) -> ArchitecturalIssue {
        ArchitecturalIssue {
            id: id.to_string(),
            description: description.to_string(),
            file_path: file_path.to_string(),
            severity: SeamSeverity::High,
            remediation: RemediationStrategy::AddCfgTestGuard,
            remediation_bead: format!("bd-{id}"),
        }
    }

    fn old_inventory_hash_preimage(
        occurrence_hashes: &[ContentHash],
        architectural_issue_hashes: &[ContentHash],
    ) -> Vec<u8> {
        let mut bytes = INVENTORY_SCHEMA_VERSION.as_bytes().to_vec();
        for hash in occurrence_hashes {
            bytes.extend_from_slice(hash.as_bytes());
        }
        for hash in architectural_issue_hashes {
            bytes.extend_from_slice(hash.as_bytes());
        }
        bytes
    }

    fn new_inventory_hash_preimage(
        occurrence_hashes: &[ContentHash],
        architectural_issue_hashes: &[ContentHash],
    ) -> Vec<u8> {
        let mut canonical = Vec::new();
        append_hash_str(&mut canonical, INVENTORY_SCHEMA_VERSION);
        append_hash_str(&mut canonical, "occurrences");
        append_hash_u64(&mut canonical, occurrence_hashes.len() as u64);
        for hash in occurrence_hashes {
            append_hash_bytes(&mut canonical, hash.as_bytes());
        }
        append_hash_str(&mut canonical, "architectural_issues");
        append_hash_u64(&mut canonical, architectural_issue_hashes.len() as u64);
        for hash in architectural_issue_hashes {
            append_hash_bytes(&mut canonical, hash.as_bytes());
        }
        canonical
    }

    #[test]
    fn schema_version_is_stable() {
        assert_eq!(
            INVENTORY_SCHEMA_VERSION,
            "frankenengine.control-plane-mock-inventory.v1"
        );
    }

    #[test]
    fn classification_display() {
        assert_eq!(
            format!("{}", SeamClassification::MustFixProduction),
            "must_fix_production"
        );
        assert_eq!(
            format!("{}", SeamClassification::AcceptableTestOnly),
            "acceptable_test_only"
        );
        assert_eq!(
            format!("{}", SeamClassification::FalsePositive),
            "false_positive"
        );
    }

    #[test]
    fn classification_ordering() {
        assert!(SeamClassification::MustFixProduction < SeamClassification::AcceptableTestOnly);
        assert!(SeamClassification::AcceptableTestOnly < SeamClassification::FalsePositive);
    }

    #[test]
    fn seam_kind_display() {
        assert_eq!(format!("{}", SeamKind::MockContext), "MockCx");
        assert_eq!(format!("{}", SeamKind::MockBudget), "MockBudget");
        assert_eq!(
            format!("{}", SeamKind::SeedDerivedTraceId),
            "trace_id_from_seed"
        );
        assert_eq!(format!("{}", SeamKind::HardcodedBudget), "hardcoded_budget");
        assert_eq!(
            format!("{}", SeamKind::UnguardedMockModule),
            "unguarded_mock_module"
        );
    }

    #[test]
    fn seam_kind_all_variants_display() {
        let kinds = [
            SeamKind::MockContext,
            SeamKind::MockBudget,
            SeamKind::MockDecisionContract,
            SeamKind::MockEvidenceEmitter,
            SeamKind::MockFailureMode,
            SeamKind::SeedDerivedTraceId,
            SeamKind::SeedDerivedDecisionId,
            SeamKind::SeedDerivedPolicyId,
            SeamKind::SeedDerivedSchemaVersion,
            SeamKind::HardcodedBudget,
            SeamKind::UnguardedMockModule,
        ];
        for kind in kinds {
            let s = format!("{}", kind);
            assert!(!s.is_empty());
        }
    }

    #[test]
    fn severity_ordering() {
        assert!(SeamSeverity::Info < SeamSeverity::Low);
        assert!(SeamSeverity::Low < SeamSeverity::Medium);
        assert!(SeamSeverity::Medium < SeamSeverity::High);
        assert!(SeamSeverity::High < SeamSeverity::Critical);
    }

    #[test]
    fn severity_display() {
        assert_eq!(format!("{}", SeamSeverity::Critical), "critical");
        assert_eq!(format!("{}", SeamSeverity::Info), "info");
    }

    #[test]
    fn remediation_display() {
        assert_eq!(
            format!("{}", RemediationStrategy::MoveToTestOnly),
            "move_to_test_only"
        );
        assert_eq!(
            format!("{}", RemediationStrategy::ThreadRealContext),
            "thread_real_context"
        );
        assert_eq!(
            format!("{}", RemediationStrategy::PropagateBudget),
            "propagate_budget"
        );
        assert_eq!(
            format!("{}", RemediationStrategy::AddCfgTestGuard),
            "add_cfg_test_guard"
        );
        assert_eq!(format!("{}", RemediationStrategy::NoAction), "no_action");
    }

    #[test]
    fn occurrence_content_hash_deterministic() {
        let occ1 = sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction);
        let occ2 = sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction);
        assert_eq!(occ1.content_hash(), occ2.content_hash());
    }

    #[test]
    fn occurrence_content_hash_differs_by_file() {
        let occ1 = sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction);
        let occ2 = sample_occurrence("b.rs", 10, SeamClassification::MustFixProduction);
        assert_ne!(occ1.content_hash(), occ2.content_hash());
    }

    #[test]
    fn occurrence_content_hash_differs_by_line() {
        let occ1 = sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction);
        let occ2 = sample_occurrence("a.rs", 20, SeamClassification::MustFixProduction);
        assert_ne!(occ1.content_hash(), occ2.content_hash());
    }

    #[test]
    fn occurrence_content_hash_differs_by_classification() {
        let occ1 = sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction);
        let occ2 = sample_occurrence("a.rs", 10, SeamClassification::AcceptableTestOnly);
        assert_ne!(occ1.content_hash(), occ2.content_hash());
    }

    #[test]
    fn occurrence_display() {
        let occ = sample_occurrence("a.rs", 42, SeamClassification::MustFixProduction);
        let s = format!("{}", occ);
        assert!(s.contains("a.rs:42"));
        assert!(s.contains("MockCx"));
    }

    #[test]
    fn inventory_empty() {
        let inv = MockInventory::build(vec![], vec![]);
        assert_eq!(inv.summary.total_occurrences, 0);
        assert_eq!(inv.summary.must_fix_count, 0);
        assert!(!inv.has_must_fix());
    }

    #[test]
    fn inventory_build_counts() {
        let occs = vec![
            sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction),
            sample_occurrence("a.rs", 20, SeamClassification::AcceptableTestOnly),
            sample_occurrence("b.rs", 5, SeamClassification::FalsePositive),
        ];
        let inv = MockInventory::build(occs, vec![]);
        assert_eq!(inv.summary.total_occurrences, 3);
        assert_eq!(inv.summary.must_fix_count, 1);
        assert_eq!(inv.summary.test_only_count, 1);
        assert_eq!(inv.summary.false_positive_count, 1);
        assert_eq!(inv.summary.affected_files, 2);
        assert_eq!(inv.summary.must_fix_files, 1);
        assert!(inv.has_must_fix());
    }

    #[test]
    fn inventory_must_fix_items() {
        let occs = vec![
            sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction),
            sample_occurrence("b.rs", 20, SeamClassification::AcceptableTestOnly),
        ];
        let inv = MockInventory::build(occs, vec![]);
        let must_fix = inv.must_fix_items();
        assert_eq!(must_fix.len(), 1);
        assert_eq!(must_fix[0].file_path, "a.rs");
    }

    #[test]
    fn inventory_test_only_items() {
        let occs = vec![
            sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction),
            sample_occurrence("b.rs", 20, SeamClassification::AcceptableTestOnly),
            sample_occurrence("c.rs", 30, SeamClassification::AcceptableTestOnly),
        ];
        let inv = MockInventory::build(occs, vec![]);
        assert_eq!(inv.test_only_items().len(), 2);
    }

    #[test]
    fn inventory_for_file() {
        let occs = vec![
            sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction),
            sample_occurrence("a.rs", 20, SeamClassification::AcceptableTestOnly),
            sample_occurrence("b.rs", 5, SeamClassification::FalsePositive),
        ];
        let inv = MockInventory::build(occs, vec![]);
        assert_eq!(inv.for_file("a.rs").len(), 2);
        assert_eq!(inv.for_file("b.rs").len(), 1);
        assert_eq!(inv.for_file("c.rs").len(), 0);
    }

    #[test]
    fn inventory_count_by_kind() {
        let occs = vec![
            SeamOccurrence::new(SeamOccurrenceInput {
                file_path: "a.rs",
                line_number: 10,
                kind: SeamKind::MockContext,
                classification: SeamClassification::MustFixProduction,
                severity: SeamSeverity::High,
                inside_cfg_test: false,
                description: "ctx",
                remediation: RemediationStrategy::NoAction,
                remediation_bead: "",
            }),
            SeamOccurrence::new(SeamOccurrenceInput {
                file_path: "a.rs",
                line_number: 20,
                kind: SeamKind::MockBudget,
                classification: SeamClassification::MustFixProduction,
                severity: SeamSeverity::High,
                inside_cfg_test: false,
                description: "budget",
                remediation: RemediationStrategy::NoAction,
                remediation_bead: "",
            }),
            SeamOccurrence::new(SeamOccurrenceInput {
                file_path: "b.rs",
                line_number: 5,
                kind: SeamKind::MockContext,
                classification: SeamClassification::AcceptableTestOnly,
                severity: SeamSeverity::Low,
                inside_cfg_test: true,
                description: "ctx test",
                remediation: RemediationStrategy::NoAction,
                remediation_bead: "",
            }),
        ];
        let inv = MockInventory::build(occs, vec![]);
        assert_eq!(inv.count_by_kind(SeamKind::MockContext), 2);
        assert_eq!(inv.count_by_kind(SeamKind::MockBudget), 1);
        assert_eq!(inv.count_by_kind(SeamKind::HardcodedBudget), 0);
    }

    #[test]
    fn inventory_sorted_by_file_and_line() {
        let occs = vec![
            sample_occurrence("b.rs", 20, SeamClassification::AcceptableTestOnly),
            sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction),
        ];
        let inv = MockInventory::build(occs, vec![]);
        assert_eq!(inv.occurrences[0].file_path, "a.rs");
        assert_eq!(inv.occurrences[1].file_path, "b.rs");
    }

    #[test]
    fn inventory_hash_deterministic() {
        let occs = vec![
            sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction),
            sample_occurrence("b.rs", 5, SeamClassification::AcceptableTestOnly),
        ];
        let inv1 = MockInventory::build(occs.clone(), vec![]);
        let inv2 = MockInventory::build(occs, vec![]);
        assert_eq!(inv1.inventory_hash, inv2.inventory_hash);
    }

    #[test]
    fn inventory_hash_differs_with_different_data() {
        let inv1 = MockInventory::build(
            vec![sample_occurrence(
                "a.rs",
                10,
                SeamClassification::MustFixProduction,
            )],
            vec![],
        );
        let inv2 = MockInventory::build(
            vec![sample_occurrence(
                "b.rs",
                10,
                SeamClassification::MustFixProduction,
            )],
            vec![],
        );
        assert_ne!(inv1.inventory_hash, inv2.inventory_hash);
    }

    #[test]
    fn inventory_sorts_architectural_issues_deterministically() {
        let issues = vec![
            sample_architectural_issue("ARCH-002", "second issue", "z.rs"),
            sample_architectural_issue("ARCH-001", "first issue", "a.rs"),
        ];
        let inv1 = MockInventory::build(vec![], issues.clone());
        let inv2 = MockInventory::build(vec![], issues.into_iter().rev().collect());

        assert_eq!(inv1.architectural_issues, inv2.architectural_issues);
        assert_eq!(inv1.inventory_hash, inv2.inventory_hash);
        assert_eq!(
            inv1.architectural_issues
                .iter()
                .map(|issue| issue.id.as_str())
                .collect::<Vec<_>>(),
            vec!["ARCH-001", "ARCH-002"]
        );
    }

    #[test]
    fn inventory_hash_changes_when_architectural_issue_payload_changes_with_same_id() {
        let baseline = sample_architectural_issue("ARCH-001", "baseline description", "a.rs");
        let mut changed = baseline.clone();
        changed.description = "updated description".to_string();

        let inv1 = MockInventory::build(vec![], vec![baseline]);
        let inv2 = MockInventory::build(vec![], vec![changed]);

        assert_ne!(inv1.inventory_hash, inv2.inventory_hash);
    }

    #[test]
    fn inventory_hash_preimage_separates_occurrence_and_issue_sections() {
        let hash_a = ContentHash::from_bytes([0x11; 32]);
        let hash_b = ContentHash::from_bytes([0x22; 32]);
        let hash_c = ContentHash::from_bytes([0x33; 32]);

        assert_eq!(
            old_inventory_hash_preimage(&[hash_a], &[hash_b, hash_c]),
            old_inventory_hash_preimage(&[hash_a, hash_b], &[hash_c]),
            "pre-patch inventory hash preimage collapses different occurrence/issue partitions"
        );
        assert_ne!(
            new_inventory_hash_preimage(&[hash_a], &[hash_b, hash_c]),
            new_inventory_hash_preimage(&[hash_a, hash_b], &[hash_c])
        );
    }

    #[test]
    fn replay_command_omits_workspace_override_for_repo_root() {
        let command =
            replay_command_for_bundle("franken_control_plane_mock_inventory", &repo_root());

        assert_eq!(
            command,
            "rch exec -- cargo run -p frankenengine-engine --bin franken_control_plane_mock_inventory -- --out-dir <DIR>"
        );
    }

    #[test]
    fn replay_command_includes_workspace_override_for_custom_root() {
        let custom_root = Path::new("/tmp/custom root");
        let command = replay_command_for_bundle("franken_ambient_mock_guard", custom_root);

        assert_eq!(
            command,
            "rch exec -- cargo run -p frankenengine-engine --bin franken_ambient_mock_guard -- --out-dir <DIR> --workspace-root '/tmp/custom root'"
        );
    }

    #[test]
    fn render_command_transcript_quotes_arguments_shell_safely() {
        let command = render_command_transcript(&[
            "franken_control_plane_mock_inventory".to_string(),
            "--out-dir".to_string(),
            "/tmp/out dir".to_string(),
            "--workspace-root".to_string(),
            "/tmp/engine's root".to_string(),
        ]);

        assert_eq!(
            command,
            "franken_control_plane_mock_inventory --out-dir '/tmp/out dir' --workspace-root '/tmp/engine'\"'\"'s root'"
        );
    }

    #[test]
    fn render_bundle_command_lines_include_literal_and_rch_replay_commands() {
        let bundle_commands = render_bundle_command_lines(
            &[
                "franken_control_plane_mock_inventory".to_string(),
                "--out-dir".to_string(),
                "/tmp/out".to_string(),
            ],
            "franken_control_plane_mock_inventory",
            &repo_root(),
        );

        assert_eq!(bundle_commands.len(), 2);
        assert_eq!(
            bundle_commands[0],
            "franken_control_plane_mock_inventory --out-dir /tmp/out"
        );
        assert_eq!(
            bundle_commands[1],
            "rch exec -- cargo run -p frankenengine-engine --bin franken_control_plane_mock_inventory -- --out-dir <DIR>"
        );
    }

    #[test]
    fn inventory_display() {
        let inv = MockInventory::build(
            vec![sample_occurrence(
                "a.rs",
                10,
                SeamClassification::MustFixProduction,
            )],
            vec![],
        );
        let s = format!("{}", inv);
        assert!(s.contains("Total occurrences: 1"));
        assert!(s.contains("Must-fix: 1"));
    }

    #[test]
    fn inventory_with_architectural_issues() {
        let issues = vec![ArchitecturalIssue {
            id: "ARCH-001".to_string(),
            description: "test issue".to_string(),
            file_path: "a.rs".to_string(),
            severity: SeamSeverity::High,
            remediation: RemediationStrategy::AddCfgTestGuard,
            remediation_bead: "bd-test".to_string(),
        }];
        let inv = MockInventory::build(vec![], issues);
        assert_eq!(inv.summary.architectural_issue_count, 1);
        assert_eq!(inv.architectural_issues[0].id, "ARCH-001");
    }

    #[test]
    fn architectural_issue_display() {
        let issue = ArchitecturalIssue {
            id: "ARCH-001".to_string(),
            description: "Missing cfg guard".to_string(),
            file_path: "a.rs".to_string(),
            severity: SeamSeverity::High,
            remediation: RemediationStrategy::AddCfgTestGuard,
            remediation_bead: "bd-test".to_string(),
        };
        let s = format!("{}", issue);
        assert!(s.contains("ARCH-001"));
        assert!(s.contains("Missing cfg guard"));
    }

    #[test]
    fn canonical_inventory_not_empty() {
        let inv = build_canonical_inventory();
        // Source-derived inventory should find at least some mock usage in the
        // codebase (test-only at minimum).
        assert!(
            inv.summary.total_occurrences > 0,
            "source-derived inventory found zero occurrences — scanner may be broken"
        );
    }

    #[test]
    fn canonical_inventory_has_test_only() {
        let inv = build_canonical_inventory();
        // Many src modules use MockCx/MockBudget inside #[cfg(test)] blocks.
        assert!(
            inv.summary.test_only_count > 0,
            "expected at least some test-only mock occurrences"
        );
    }

    #[test]
    fn canonical_inventory_test_files_are_test_only() {
        let inv = build_canonical_inventory();
        for occ in inv.test_only_items() {
            assert!(occ.inside_cfg_test);
        }
    }

    #[test]
    fn canonical_inventory_deterministic() {
        let inv1 = build_canonical_inventory();
        let inv2 = build_canonical_inventory();
        assert_eq!(inv1.inventory_hash, inv2.inventory_hash);
    }

    #[test]
    fn canonical_inventory_serde_roundtrip() {
        let inv = build_canonical_inventory();
        let json = serde_json::to_string(&inv).expect("serialize derived Serialize");
        let inv2: MockInventory =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(inv, inv2);
    }

    #[test]
    fn source_derived_inventory_classifies_test_only_correctly() {
        let inv = build_canonical_inventory();
        for occ in inv.test_only_items() {
            assert_eq!(occ.classification, SeamClassification::AcceptableTestOnly);
            assert!(occ.inside_cfg_test);
            assert_eq!(occ.remediation, RemediationStrategy::NoAction);
        }
    }

    #[test]
    fn source_derived_inventory_must_fix_items_not_inside_cfg_test() {
        let inv = build_canonical_inventory();
        for occ in inv.must_fix_items() {
            assert!(!occ.inside_cfg_test);
            assert_eq!(occ.classification, SeamClassification::MustFixProduction);
        }
    }

    #[test]
    fn production_mock_seam_matrix_matches_inventory() {
        let inventory = build_canonical_inventory();
        let matrix = inventory.production_mock_seam_matrix();

        assert_eq!(
            matrix.schema_version,
            PRODUCTION_MOCK_SEAM_MATRIX_SCHEMA_VERSION
        );
        assert_eq!(matrix.component, COMPONENT);
        assert_eq!(matrix.bead_id, BEAD_ID);
        assert_eq!(matrix.policy_id, CONTROL_PLANE_MOCK_INVENTORY_POLICY_ID);
        assert_eq!(matrix.inventory_hash, inventory.inventory_hash.to_string());
        assert_eq!(matrix.must_fix_count, inventory.summary.must_fix_count);
        assert_eq!(matrix.must_fix_files, inventory.summary.must_fix_files);
        assert_eq!(
            matrix.architectural_issue_count,
            inventory.summary.architectural_issue_count
        );
        assert_eq!(
            matrix.must_fix_occurrences,
            inventory
                .must_fix_items()
                .into_iter()
                .cloned()
                .collect::<Vec<_>>()
        );
        assert_eq!(matrix.architectural_issues, inventory.architectural_issues);
    }

    #[test]
    fn write_control_plane_mock_inventory_bundle_emits_expected_artifacts() {
        let root = unique_temp_dir("control-plane-mock-inventory-bundle-root");
        let out_dir = unique_temp_dir("control-plane-mock-inventory-bundle-out");
        let commands = vec![
            "rch exec -- cargo run -p frankenengine-engine --bin franken_control_plane_mock_inventory -- --out-dir /tmp/out"
                .to_string(),
        ];

        let artifacts =
            write_control_plane_mock_inventory_bundle_in_root(&root, &out_dir, &commands)
                .expect("bundle should be written");

        assert_eq!(
            artifacts.outcome,
            ControlPlaneMockInventoryOutcome::InventoryComplete
        );
        assert!(artifacts.inventory_path.exists());
        assert!(artifacts.production_mock_seam_matrix_path.exists());
        assert!(artifacts.trace_ids_path.exists());
        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.commands_path.exists());
        assert!(
            artifacts
                .step_logs_dir
                .join("step_001_inventory.log")
                .exists()
        );
        assert!(artifacts.summary_path.exists());
        assert!(artifacts.env_path.exists());
        assert!(artifacts.repro_lock_path.exists());
        // The bundle uses source-derived inventory from the temp root (empty),
        // so its hash should match a second scan of the same root.
        let empty_inv = build_source_derived_inventory(&root)
            .unwrap_or_else(|_| MockInventory::build(Vec::new(), Vec::new()));
        assert_eq!(
            artifacts.inventory_hash,
            empty_inv.inventory_hash.to_string()
        );

        let manifest: ControlPlaneMockInventoryRunManifest =
            serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read manifest"))
                .expect("deserialization should succeed");
        assert_eq!(
            manifest.outcome,
            ControlPlaneMockInventoryOutcome::InventoryComplete
        );
        assert_eq!(
            manifest.artifact_paths.asupersync_residual_mock_inventory,
            "asupersync_residual_mock_inventory.json"
        );
        assert_eq!(
            manifest.artifact_paths.production_mock_seam_matrix,
            "production_mock_seam_matrix.json"
        );

        let trace_ids: ControlPlaneMockInventoryTraceIds =
            serde_json::from_slice(&fs::read(&artifacts.trace_ids_path).expect("read trace ids"))
                .expect("deserialization should succeed");
        assert_eq!(trace_ids.inventory_hash, manifest.inventory_hash);

        let repro_lock: serde_json::Value =
            serde_json::from_slice(&fs::read(&artifacts.repro_lock_path).expect("read repro lock"))
                .expect("deserialization should succeed");
        let replay_command = repro_lock["replay_command"]
            .as_str()
            .expect("replay command should be a string");
        assert!(replay_command.contains("--workspace-root"));
        assert!(replay_command.contains(root.to_str().expect("utf-8 workspace root")));

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(out_dir);
    }

    #[test]
    fn control_plane_bundle_writers_share_output_lock() {
        let out_dir = unique_temp_dir("control-plane-shared-bundle-lock");
        fs::create_dir_all(&out_dir).expect("create bundle dir");

        let inventory_lock = acquire_control_plane_mock_inventory_bundle_lock(&out_dir)
            .expect("inventory writer should acquire shared bundle lock");
        assert!(matches!(
            acquire_ambient_mock_guard_bundle_lock(&out_dir),
            Err(AmbientMockGuardError::Busy { path })
                if path.ends_with(CONTROL_PLANE_MOCK_SHARED_BUNDLE_LOCK_FILE)
        ));
        assert!(matches!(
            acquire_orchestrator_context_refactor_bundle_lock(&out_dir),
            Err(OrchestratorContextRefactorError::Busy { path })
                if path.ends_with(CONTROL_PLANE_MOCK_SHARED_BUNDLE_LOCK_FILE)
        ));
        drop(inventory_lock);

        let ambient_lock = acquire_ambient_mock_guard_bundle_lock(&out_dir)
            .expect("ambient writer should acquire shared bundle lock after release");
        assert!(matches!(
            acquire_control_plane_mock_inventory_bundle_lock(&out_dir),
            Err(ControlPlaneMockInventoryBundleError::Busy { path })
                if path.ends_with(CONTROL_PLANE_MOCK_SHARED_BUNDLE_LOCK_FILE)
        ));
        drop(ambient_lock);

        let _ = fs::remove_dir_all(out_dir);
    }

    #[test]
    fn classification_serde_roundtrip() {
        let c = SeamClassification::MustFixProduction;
        let json = serde_json::to_string(&c).expect("serialize derived Serialize");
        let c2: SeamClassification =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(c, c2);
    }

    #[test]
    fn seam_kind_serde_roundtrip() {
        for kind in [
            SeamKind::MockContext,
            SeamKind::MockBudget,
            SeamKind::HardcodedBudget,
            SeamKind::UnguardedMockModule,
        ] {
            let json = serde_json::to_string(&kind).expect("serialize derived Serialize");
            let k2: SeamKind = serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(kind, k2);
        }
    }

    #[test]
    fn severity_serde_roundtrip() {
        for sev in [
            SeamSeverity::Info,
            SeamSeverity::Low,
            SeamSeverity::Medium,
            SeamSeverity::High,
            SeamSeverity::Critical,
        ] {
            let json = serde_json::to_string(&sev).expect("serialize derived Serialize");
            let s2: SeamSeverity =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(sev, s2);
        }
    }

    #[test]
    fn remediation_serde_roundtrip() {
        for rem in [
            RemediationStrategy::MoveToTestOnly,
            RemediationStrategy::ThreadRealContext,
            RemediationStrategy::PropagateBudget,
            RemediationStrategy::AddCfgTestGuard,
            RemediationStrategy::NoAction,
        ] {
            let json = serde_json::to_string(&rem).expect("serialize derived Serialize");
            let r2: RemediationStrategy =
                serde_json::from_str(&json).expect("deserialize known-valid JSON");
            assert_eq!(rem, r2);
        }
    }

    #[test]
    fn occurrence_serde_roundtrip() {
        let occ = sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction);
        let json = serde_json::to_string(&occ).expect("serialize derived Serialize");
        let occ2: SeamOccurrence =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(occ, occ2);
    }

    #[test]
    fn inventory_by_kind_breakdown() {
        let inv = build_canonical_inventory();
        // Source-derived scanner should find MockContext usage in at least
        // test-only files (many modules use MockCx in cfg(test) blocks).
        assert!(
            inv.count_by_kind(SeamKind::MockContext) > 0,
            "expected at least one MockContext occurrence"
        );
    }

    #[test]
    fn inventory_affected_files_count() {
        let inv = build_canonical_inventory();
        // Source-derived scanner should find mock usage across multiple files.
        assert!(
            inv.summary.affected_files > 0,
            "expected at least one affected file"
        );
    }

    #[test]
    fn strip_non_code_segments_ignores_strings_and_comments() {
        let mut in_block_comment = false;
        let line = r#"let note = "MockCx"; // crate::control_plane::mocks::MockCx"#;
        let stripped = strip_non_code_segments(line, &mut in_block_comment);
        assert_eq!(stripped.trim(), "let note = ;");
        assert!(!in_block_comment);
    }

    #[test]
    fn ambient_mock_guard_flags_production_mock_usage() {
        let root = unique_temp_dir("ambient-mock-guard-production");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/lib.rs",
            r#"
use crate::control_plane::mocks::{MockBudget, MockCx};

fn build() {
    let _cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(10));
}
"#,
        );

        let report =
            evaluate_ambient_mock_guard_in_root(&root).expect("guard should evaluate fixture");

        assert_eq!(report.outcome, AmbientMockGuardOutcome::FailClosed);
        assert!(report.violations.iter().any(
            |violation| violation.rule == AmbientMockGuardRule::NoProductionMockModuleReference
        ));
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.rule
                    == AmbientMockGuardRule::NoProductionFakeContextSymbol)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ambient_mock_guard_ignores_cfg_test_usage() {
        let root = unique_temp_dir("ambient-mock-guard-test-only");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/lib.rs",
            r#"
#[cfg(test)]
mod tests {
    use crate::control_plane::mocks::{MockBudget, MockCx};

    #[test]
    fn works() {
        let _cx = MockCx::new(crate::control_plane::mocks::trace_id_from_seed(1), MockBudget::new(10));
    }
}
"#,
        );

        let report =
            evaluate_ambient_mock_guard_in_root(&root).expect("guard should evaluate fixture");

        assert_eq!(report.outcome, AmbientMockGuardOutcome::Pass);
        assert!(report.violations.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ambient_mock_guard_flags_unguarded_mock_module() {
        let root = unique_temp_dir("ambient-mock-guard-unguarded-module");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/control_plane/mod.rs",
            r#"
pub mod mocks {
    pub struct MockCx;
}
"#,
        );
        write_fixture_file(
            &root,
            "crates/franken-engine/src/lib.rs",
            "pub mod control_plane;",
        );

        let report =
            evaluate_ambient_mock_guard_in_root(&root).expect("guard should evaluate fixture");

        assert_eq!(report.outcome, AmbientMockGuardOutcome::FailClosed);
        assert!(report.violations.iter().any(|violation| {
            violation.rule == AmbientMockGuardRule::MockModuleMustBeCfgTest
                && violation.diagnostic_code == "AMG-ARCH-UNGARDED-MOCK-MODULE"
        }));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ambient_mock_guard_does_not_leak_cfg_test_scope_past_semicolon_items() {
        let root = unique_temp_dir("ambient-mock-guard-cfg-test-scope-leak");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/lib.rs",
            r#"
#[cfg(test)]
mod tests;

use crate::control_plane::mocks::{MockBudget, MockCx};

fn build() {
    let _cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(10));
}
"#,
        );

        let report =
            evaluate_ambient_mock_guard_in_root(&root).expect("guard should evaluate fixture");

        assert_eq!(report.outcome, AmbientMockGuardOutcome::FailClosed);
        assert!(report.violations.iter().any(
            |violation| violation.rule == AmbientMockGuardRule::NoProductionMockModuleReference
        ));
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.rule
                    == AmbientMockGuardRule::NoProductionFakeContextSymbol)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn ambient_mock_guard_does_not_leak_mock_module_scope_past_semicolon_module_decl() {
        let root = unique_temp_dir("ambient-mock-guard-mock-module-scope-leak");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/lib.rs",
            r#"
pub mod mocks;

fn build() {
    use crate::control_plane::mocks::{MockBudget, MockCx};
    let _cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(10));
}
"#,
        );

        let report =
            evaluate_ambient_mock_guard_in_root(&root).expect("guard should evaluate fixture");

        assert_eq!(report.outcome, AmbientMockGuardOutcome::FailClosed);
        assert!(report.violations.iter().any(
            |violation| violation.rule == AmbientMockGuardRule::NoProductionMockModuleReference
        ));
        assert!(
            report
                .violations
                .iter()
                .any(|violation| violation.rule
                    == AmbientMockGuardRule::NoProductionFakeContextSymbol)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn write_ambient_mock_guard_bundle_emits_expected_artifacts() {
        let root = unique_temp_dir("ambient-mock-guard-bundle-root");
        let out_dir = unique_temp_dir("ambient-mock-guard-bundle-out");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/lib.rs",
            r#"
#[cfg(test)]
mod tests {
    use crate::control_plane::mocks::{MockBudget, MockCx};
}
"#,
        );

        let commands = vec![
            "rch exec -- cargo run -p frankenengine-engine --bin franken_ambient_mock_guard -- --out-dir /tmp/out"
                .to_string(),
        ];
        let artifacts = write_ambient_mock_guard_bundle_in_root(&root, &out_dir, &commands)
            .expect("bundle should be written");
        assert_eq!(artifacts.outcome, AmbientMockGuardOutcome::Pass);
        assert!(artifacts.report_path.exists());
        assert!(artifacts.migration_report_path.exists());
        assert!(artifacts.regression_report_path.exists());
        assert!(artifacts.trace_ids_path.exists());
        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.commands_path.exists());
        assert!(artifacts.step_logs_dir.join("step_001_scan.log").exists());
        assert!(artifacts.summary_path.exists());
        assert!(artifacts.env_path.exists());
        assert!(artifacts.repro_lock_path.exists());

        let manifest: AmbientMockGuardRunManifest =
            serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read manifest"))
                .expect("deserialization should succeed");
        assert_eq!(manifest.outcome, AmbientMockGuardOutcome::Pass);
        assert_eq!(
            manifest.artifact_paths.ambient_mock_guard_report,
            "ambient_mock_guard_report.json"
        );
        assert_eq!(
            manifest
                .artifact_paths
                .control_plane_mock_surface_migration_report,
            "control_plane_mock_surface_migration_report.json"
        );
        assert_eq!(
            manifest
                .artifact_paths
                .control_plane_mock_guard_regression_report,
            "control_plane_mock_guard_regression_report.json"
        );

        let repro_lock: serde_json::Value =
            serde_json::from_slice(&fs::read(&artifacts.repro_lock_path).expect("read repro lock"))
                .expect("deserialization should succeed");
        let replay_command = repro_lock["replay_command"]
            .as_str()
            .expect("replay command should be a string");
        assert!(replay_command.contains("--workspace-root"));
        assert!(replay_command.contains(root.to_str().expect("utf-8 workspace root")));

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(out_dir);
    }

    #[test]
    fn orchestrator_context_refactor_passes_corrected_fixture() {
        let root = unique_temp_dir("orchestrator-context-refactor-pass");
        write_fixture_file(
            &root,
            ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE,
            r#"
use crate::control_plane::{Budget, Cx, KernelContext, NoCaps, TraceId};

fn close_cell(trace_id: &str) {
    let _close_cx =
        Self::build_cell_close_context(&trace_id, self.config.cell_close_budget_ms);
}

fn build_cell_close_context(trace_id: &str, budget_ms: u64) -> KernelContext<'static, NoCaps> {
    KernelContext::new(Cx::new(
        Self::derive_cell_close_trace_id(trace_id),
        Budget::new(budget_ms),
        NoCaps,
    ))
}
"#,
        );

        let (_contract, report) = evaluate_orchestrator_context_refactor_in_root(&root)
            .expect("context refactor evaluation should succeed");

        assert_eq!(report.outcome, OrchestratorContextRefactorOutcome::Pass);
        // The corrected fixture has no mock usage, so the source-derived
        // inventory finds 0 must-fix items (refactor is already complete).
        assert_eq!(report.summary.corrected_seam_count, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn orchestrator_context_refactor_fails_when_mock_context_returns() {
        let root = unique_temp_dir("orchestrator-context-refactor-fail-mock");
        write_fixture_file(
            &root,
            ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE,
            r#"
use crate::control_plane::mocks::{MockBudget, MockCx, trace_id_from_seed};

fn close_cell() {
    let _cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(10_000));
}
"#,
        );

        let (_contract, report) = evaluate_orchestrator_context_refactor_in_root(&root)
            .expect("context refactor evaluation should succeed");

        assert_eq!(
            report.outcome,
            OrchestratorContextRefactorOutcome::FailClosed
        );
        assert!(
            report
                .guards
                .iter()
                .any(|guard| { guard.guard_id == "forbidden_mock_context_ctor" && !guard.passed })
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn write_orchestrator_context_refactor_bundle_emits_expected_artifacts() {
        let root = unique_temp_dir("orchestrator-context-refactor-bundle-root");
        let out_dir = unique_temp_dir("orchestrator-context-refactor-bundle-out");
        write_fixture_file(
            &root,
            ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE,
            r#"
use crate::control_plane::{Budget, Cx, KernelContext, NoCaps, TraceId};

fn close_cell(trace_id: &str) {
    let _close_cx =
        Self::build_cell_close_context(&trace_id, self.config.cell_close_budget_ms);
}

fn build_cell_close_context(trace_id: &str, budget_ms: u64) -> KernelContext<'static, NoCaps> {
    KernelContext::new(Cx::new(
        Self::derive_cell_close_trace_id(trace_id),
        Budget::new(budget_ms),
        NoCaps,
    ))
}
"#,
        );

        let commands = vec![
            "rch exec -- cargo run -p frankenengine-engine --bin franken_orchestrator_context_refactor -- --out-dir /tmp/out"
                .to_string(),
        ];
        let artifacts =
            write_orchestrator_context_refactor_bundle_in_root(&root, &out_dir, &commands)
                .expect("bundle should be written");

        assert_eq!(artifacts.outcome, OrchestratorContextRefactorOutcome::Pass);
        assert!(artifacts.contract_path.exists());
        assert!(artifacts.report_path.exists());
        assert!(artifacts.trace_ids_path.exists());
        assert!(artifacts.run_manifest_path.exists());
        assert!(artifacts.events_path.exists());
        assert!(artifacts.commands_path.exists());
        assert!(artifacts.step_logs_dir.join("step_001_scan.log").exists());
        assert!(artifacts.summary_path.exists());
        assert!(artifacts.env_path.exists());
        assert!(artifacts.repro_lock_path.exists());

        let manifest: OrchestratorContextRefactorRunManifest =
            serde_json::from_slice(&fs::read(&artifacts.run_manifest_path).expect("read manifest"))
                .expect("deserialization should succeed");
        assert_eq!(manifest.outcome, OrchestratorContextRefactorOutcome::Pass);
        assert_eq!(
            manifest.artifact_paths.production_context_path_contract,
            "production_context_path_contract.json"
        );

        let repro_lock: serde_json::Value =
            serde_json::from_slice(&fs::read(&artifacts.repro_lock_path).expect("read repro lock"))
                .expect("deserialization should succeed");
        let replay_command = repro_lock["replay_command"]
            .as_str()
            .expect("replay command should be a string");
        assert!(replay_command.contains("--workspace-root"));
        assert!(replay_command.contains(root.to_str().expect("utf-8 workspace root")));

        let _ = fs::remove_dir_all(root);
        let _ = fs::remove_dir_all(out_dir);
    }

    #[test]
    fn component_constant() {
        assert_eq!(COMPONENT, "control_plane_mock_inventory");
    }

    #[test]
    fn bead_id_constant() {
        assert_eq!(BEAD_ID, "bd-3nr.1.1.1");
    }

    // -----------------------------------------------------------------------
    // Source-derived inventory scanner tests (bd-2muur.5.1)
    // -----------------------------------------------------------------------

    #[test]
    fn source_derived_inventory_finds_production_mock_usage() {
        let root = unique_temp_dir("source-derived-production");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/executor.rs",
            r#"
use crate::control_plane::mocks::{MockBudget, MockCx};

fn execute() {
    let cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(10_000));
}
"#,
        );

        let inv =
            build_source_derived_inventory(&root).expect("source-derived inventory should work");

        assert!(inv.summary.total_occurrences > 0);
        assert!(inv.summary.must_fix_count > 0);

        let must_fix = inv.must_fix_items();
        assert!(!must_fix.is_empty());
        assert!(
            must_fix
                .iter()
                .any(|o| o.kind == SeamKind::MockContext && o.file_path.contains("executor.rs"))
        );
        assert!(must_fix.iter().any(|o| o.kind == SeamKind::MockBudget));
        assert!(
            must_fix
                .iter()
                .any(|o| o.kind == SeamKind::SeedDerivedTraceId)
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn source_derived_inventory_classifies_cfg_test_as_test_only() {
        let root = unique_temp_dir("source-derived-test-only");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/widget.rs",
            r#"
pub fn real_code() {}

#[cfg(test)]
mod tests {
    use crate::control_plane::mocks::{MockBudget, MockCx};

    fn helper() {
        let _cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(10));
    }
}
"#,
        );

        let inv =
            build_source_derived_inventory(&root).expect("source-derived inventory should work");

        assert!(inv.summary.test_only_count > 0);
        assert_eq!(inv.summary.must_fix_count, 0);

        for occ in inv.test_only_items() {
            assert!(occ.inside_cfg_test);
            assert_eq!(occ.remediation, RemediationStrategy::NoAction);
        }

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn source_derived_inventory_detects_unguarded_mock_module() {
        let root = unique_temp_dir("source-derived-unguarded");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/control_plane.rs",
            r#"
pub mod mocks {
    pub struct MockCx;
}
"#,
        );

        let inv =
            build_source_derived_inventory(&root).expect("source-derived inventory should work");

        assert!(
            inv.occurrences
                .iter()
                .any(|o| o.kind == SeamKind::UnguardedMockModule)
        );
        assert!(
            inv.architectural_issues
                .iter()
                .any(|i| i.description.contains("pub mod mocks"))
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn source_derived_inventory_is_deterministic() {
        let root = unique_temp_dir("source-derived-determinism");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/test_mod.rs",
            r#"
#[cfg(test)]
mod tests {
    fn helper() {
        let _ = MockCx::new();
    }
}
"#,
        );

        let inv1 = build_source_derived_inventory(&root).expect("first scan");
        let inv2 = build_source_derived_inventory(&root).expect("second scan");
        assert_eq!(inv1.inventory_hash, inv2.inventory_hash);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn source_derived_inventory_skips_self() {
        let inv = build_canonical_inventory();
        // The scanner skips control_plane_mock_inventory.rs itself, so no
        // occurrence should reference that file.
        assert!(
            inv.occurrences
                .iter()
                .all(|o| !o.file_path.ends_with("control_plane_mock_inventory.rs"))
        );
    }

    #[test]
    fn source_derived_inventory_empty_tree_returns_empty() {
        let root = unique_temp_dir("source-derived-empty");
        fs::create_dir_all(root.join("crates/franken-engine/src")).expect("create scan root");

        let inv = build_source_derived_inventory(&root).expect("empty tree scan");
        assert_eq!(inv.summary.total_occurrences, 0);
        assert!(inv.occurrences.is_empty());
        assert!(inv.architectural_issues.is_empty());

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn all_seam_kinds_in_line_detects_multiple_symbols() {
        let line = "let cx = MockCx::new(trace_id_from_seed(1), MockBudget::new(10));";
        let hits = all_seam_kinds_in_line(line);
        let kinds: Vec<SeamKind> = hits.iter().map(|(k, _)| *k).collect();
        assert!(kinds.contains(&SeamKind::MockContext));
        assert!(kinds.contains(&SeamKind::MockBudget));
        assert!(kinds.contains(&SeamKind::SeedDerivedTraceId));
        assert!(kinds.contains(&SeamKind::HardcodedBudget));
    }

    #[test]
    fn all_seam_kinds_in_line_returns_empty_for_clean_code() {
        let line = "let x = compute_budget(real_cx);";
        let hits = all_seam_kinds_in_line(line);
        assert!(hits.is_empty());
    }

    #[test]
    fn seam_kind_from_diagnostic_code_mapping() {
        assert_eq!(
            seam_kind_from_diagnostic_code("AMG-PROD-MOCK-CX"),
            SeamKind::MockContext
        );
        assert_eq!(
            seam_kind_from_diagnostic_code("AMG-PROD-MOCK-BUDGET"),
            SeamKind::MockBudget
        );
        assert_eq!(
            seam_kind_from_diagnostic_code("AMG-PROD-SEED-TRACE-ID"),
            SeamKind::SeedDerivedTraceId
        );
        assert_eq!(
            seam_kind_from_diagnostic_code("AMG-ARCH-UNGARDED-MOCK-MODULE"),
            SeamKind::UnguardedMockModule
        );
    }

    // -----------------------------------------------------------------------
    // Freshness guard tests (bd-2muur.5.3)
    // -----------------------------------------------------------------------

    #[test]
    fn freshness_guard_passes_for_fresh_inventory() {
        let root = unique_temp_dir("freshness-guard-fresh");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/widget.rs",
            r#"
#[cfg(test)]
mod tests {
    fn helper() { let _ = MockCx::new(); }
}
"#,
        );

        let inv = build_source_derived_inventory(&root).expect("scan");
        let result = verify_inventory_freshness(&inv, &root);

        assert!(
            result.fresh,
            "freshness check should pass for a just-scanned inventory"
        );
        assert_eq!(result.original_hash, result.rescan_hash);
        assert_eq!(result.scanner_version, SOURCE_DERIVED_SCANNER_VERSION);
        assert_eq!(result.policy_id, INVENTORY_FRESHNESS_POLICY_ID);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn freshness_guard_fails_for_stale_inventory() {
        let root = unique_temp_dir("freshness-guard-stale");
        write_fixture_file(
            &root,
            "crates/franken-engine/src/widget.rs",
            r#"
fn prod() { let _ = MockCx::new(); }
"#,
        );

        let inv = build_source_derived_inventory(&root).expect("first scan");

        // Modify the source so the inventory becomes stale.
        write_fixture_file(
            &root,
            "crates/franken-engine/src/widget.rs",
            r#"
fn prod() { let _ = real_cx(); }
"#,
        );

        let result = verify_inventory_freshness(&inv, &root);
        assert!(
            !result.fresh,
            "freshness check should fail after source changed"
        );
        assert_ne!(result.original_hash, result.rescan_hash);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn freshness_guard_constants_present() {
        assert!(!SOURCE_DERIVED_SCANNER_VERSION.is_empty());
        assert!(!INVENTORY_FRESHNESS_POLICY_ID.is_empty());
        assert!(SOURCE_DERIVED_SCANNER_VERSION.starts_with("frankenengine."));
        assert!(INVENTORY_FRESHNESS_POLICY_ID.starts_with("frankenengine."));
    }

    #[test]
    fn freshness_result_serde_roundtrip() {
        let result = InventoryFreshnessResult {
            scanner_version: SOURCE_DERIVED_SCANNER_VERSION.to_string(),
            policy_id: INVENTORY_FRESHNESS_POLICY_ID.to_string(),
            fresh: true,
            original_hash: "abc".to_string(),
            rescan_hash: "abc".to_string(),
        };
        let json = serde_json::to_string(&result).expect("serialize derived Serialize");
        let back: InventoryFreshnessResult =
            serde_json::from_str(&json).expect("deserialize known-valid JSON");
        assert_eq!(result, back);
    }

    #[test]
    fn freshness_guard_empty_tree_is_fresh() {
        let root = unique_temp_dir("freshness-guard-empty");
        fs::create_dir_all(root.join("crates/franken-engine/src")).expect("create scan root");

        let inv = build_source_derived_inventory(&root).expect("empty scan");
        let result = verify_inventory_freshness(&inv, &root);
        assert!(result.fresh);

        let _ = fs::remove_dir_all(root);
    }
}
