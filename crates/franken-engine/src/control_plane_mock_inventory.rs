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
pub const AMBIENT_MOCK_GUARD_TRACE_IDS_SCHEMA_VERSION: &str =
    "frankenengine.ambient-mock-guard.trace-ids.v1";
pub const AMBIENT_MOCK_GUARD_RUN_MANIFEST_SCHEMA_VERSION: &str =
    "frankenengine.ambient-mock-guard.run-manifest.v1";
pub const AMBIENT_MOCK_GUARD_EVENT_SCHEMA_VERSION: &str =
    "frankenengine.ambient-mock-guard.event.v1";
pub const AMBIENT_MOCK_GUARD_SCAN_ROOT: &str = "crates/franken-engine/src";

static NEXT_AMBIENT_MOCK_GUARD_TEMP_FILE_ID: AtomicU64 = AtomicU64::new(0);

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

    /// Compute a deterministic content hash of this occurrence.
    pub fn content_hash(&self) -> ContentHash {
        let mut hasher = Sha256::new();
        hasher.update(INVENTORY_SCHEMA_VERSION.as_bytes());
        hasher.update(self.file_path.as_bytes());
        hasher.update(self.line_number.to_le_bytes());
        hasher.update(format!("{}", self.kind).as_bytes());
        hasher.update(format!("{}", self.classification).as_bytes());
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
        architectural_issues: Vec<ArchitecturalIssue>,
    ) -> Self {
        // Sort deterministically by (file_path, line_number).
        occurrences.sort();

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
        hasher.update(INVENTORY_SCHEMA_VERSION.as_bytes());
        for occ in &occurrences {
            hasher.update(occ.content_hash().as_bytes());
        }
        for issue in &architectural_issues {
            hasher.update(issue.id.as_bytes());
        }
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

// ---------------------------------------------------------------------------
// build_canonical_inventory — the actual 2026-03-09 scan results
// ---------------------------------------------------------------------------

/// Build the canonical inventory from the 2026-03-09 codebase scan.
///
/// This encodes every occurrence found by the automated grep + manual
/// classification pass as structured, versioned data.
pub fn build_canonical_inventory() -> MockInventory {
    fn must_fix(
        file_path: &str,
        line: u32,
        kind: SeamKind,
        sev: SeamSeverity,
        desc: &str,
        rem: RemediationStrategy,
    ) -> SeamOccurrence {
        SeamOccurrence::new(SeamOccurrenceInput {
            file_path,
            line_number: line,
            kind,
            classification: SeamClassification::MustFixProduction,
            severity: sev,
            inside_cfg_test: false,
            description: desc,
            remediation: rem,
            remediation_bead: "bd-3nr.1.2.1",
        })
    }
    fn test_only(file_path: &str, line: u32, desc: &str) -> SeamOccurrence {
        SeamOccurrence::new(SeamOccurrenceInput {
            file_path,
            line_number: line,
            kind: SeamKind::MockContext,
            classification: SeamClassification::AcceptableTestOnly,
            severity: SeamSeverity::Low,
            inside_cfg_test: true,
            description: desc,
            remediation: RemediationStrategy::NoAction,
            remediation_bead: "",
        })
    }

    let orch = "crates/franken-engine/src/execution_orchestrator.rs";
    let occurrences = vec![
        // === MUST-FIX PRODUCTION ===
        must_fix(
            orch,
            30,
            SeamKind::MockContext,
            SeamSeverity::Critical,
            "Unconditional top-level import of MockCx, MockBudget, trace_id_from_seed in production module",
            RemediationStrategy::ThreadRealContext,
        ),
        must_fix(
            orch,
            30,
            SeamKind::MockBudget,
            SeamSeverity::Critical,
            "Unconditional top-level import of MockBudget in production module",
            RemediationStrategy::PropagateBudget,
        ),
        must_fix(
            orch,
            30,
            SeamKind::SeedDerivedTraceId,
            SeamSeverity::High,
            "Unconditional import of trace_id_from_seed in production module",
            RemediationStrategy::ThreadRealContext,
        ),
        must_fix(
            orch,
            519,
            SeamKind::MockContext,
            SeamSeverity::Critical,
            "MockCx::new() called in execute() production path for cell.close()",
            RemediationStrategy::ThreadRealContext,
        ),
        must_fix(
            orch,
            519,
            SeamKind::HardcodedBudget,
            SeamSeverity::Critical,
            "Hardcoded MockBudget::new(10_000) in production execute() path",
            RemediationStrategy::PropagateBudget,
        ),
        // === ACCEPTABLE TEST-ONLY ===
        test_only(
            "crates/franken-engine/src/obligation_integration.rs",
            640,
            "MockCx/MockBudget/trace_id_from_seed inside #[cfg(test)] mod tests",
        ),
        test_only(
            "crates/franken-engine/src/frankenlab_extension_lifecycle.rs",
            546,
            "MockCx/MockBudget/trace_id_from_seed inside #[cfg(test)] mod tests",
        ),
        test_only(
            "crates/franken-engine/src/frankenlab_release_gate.rs",
            620,
            "MockCx/MockBudget/trace_id_from_seed inside #[cfg(test)] mod tests",
        ),
        test_only(
            "crates/franken-engine/src/extension_host_lifecycle.rs",
            694,
            "MockCx/MockBudget/trace_id_from_seed inside #[cfg(test)] mod tests",
        ),
        test_only(
            "crates/franken-engine/src/safety_decision_router.rs",
            749,
            "MockCx/MockBudget/decision_id_from_seed/policy_id_from_seed inside #[cfg(test)]",
        ),
        test_only(
            "crates/franken-engine/src/safe_mode_fallback.rs",
            1321,
            "MockCx/MockBudget/MockDecisionContract/MockFailureMode inside #[cfg(test)]",
        ),
        test_only(
            "crates/franken-engine/src/evidence_replay_checker.rs",
            932,
            "MockCx/MockBudget/decision_id_from_seed/policy_id_from_seed inside #[cfg(test)]",
        ),
        test_only(
            "crates/franken-engine/src/evidence_emission.rs",
            569,
            "MockCx/MockBudget/decision_id_from_seed/policy_id_from_seed inside #[cfg(test)]",
        ),
        test_only(
            "crates/franken-engine/src/execution_cell.rs",
            990,
            "MockCx/MockBudget inside #[cfg(test)]",
        ),
        test_only(
            "crates/franken-engine/src/release_gate.rs",
            768,
            "MockCx/MockBudget inside #[cfg(test)]",
        ),
        test_only(
            "crates/franken-engine/src/migration_compatibility.rs",
            1639,
            "MockCx/MockBudget/decision_id_from_seed/policy_id_from_seed inside #[cfg(test)]",
        ),
        test_only(
            "crates/franken-engine/src/cancellation_lifecycle.rs",
            589,
            "MockCx/MockBudget inside #[cfg(test)]",
        ),
        test_only(
            "crates/franken-engine/src/cx_threading.rs",
            933,
            "MockCx/MockBudget/trace_id_from_seed inside #[cfg(test)]",
        ),
    ];

    let architectural_issues = vec![
        ArchitecturalIssue {
            id: "ARCH-001".to_string(),
            description: "control_plane/mod.rs line 284: pub mod mocks {{ }} has no #[cfg(test)] guard despite being documented as 'Test helper mock types'".to_string(),
            file_path: "crates/franken-engine/src/control_plane/mod.rs".to_string(),
            severity: SeamSeverity::High,
            remediation: RemediationStrategy::AddCfgTestGuard,
            remediation_bead: "bd-3nr.1.2.2".to_string(),
        },
        ArchitecturalIssue {
            id: "ARCH-002".to_string(),
            description: "execution_orchestrator.rs execute() uses MockCx for cell.close() — all extension executions bypass real budget/context tracking".to_string(),
            file_path: "crates/franken-engine/src/execution_orchestrator.rs".to_string(),
            severity: SeamSeverity::Critical,
            remediation: RemediationStrategy::ThreadRealContext,
            remediation_bead: "bd-3nr.1.2.1".to_string(),
        },
    ];

    MockInventory::build(occurrences, architectural_issues)
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
    pub diagnostic_id: Option<String>,
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
    let canonical_inventory = build_canonical_inventory();
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
    let trace_ids_path = out_dir.join("trace_ids.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let step_logs_dir = out_dir.join("step_logs");
    let summary_path = out_dir.join("summary.md");
    let env_path = out_dir.join("env.json");
    let repro_lock_path = out_dir.join("repro.lock");

    let report_bytes = ambient_mock_guard_json_bytes(&report, &report_path)?;
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
        "replay_command": "cargo run -p frankenengine-engine --bin franken_ambient_mock_guard -- --out-dir <DIR>",
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

    Ok(AmbientMockGuardArtifacts {
        out_dir,
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
        report_hash,
        violation_count: report.violations.len(),
    })
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
            .starts_with(workspace_root.display().to_string().as_str())
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
        diagnostic_id: None,
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
            diagnostic_id: Some(violation.violation_id.clone()),
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
        diagnostic_id: None,
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
            "violation={} {}:{} {}\n",
            violation.diagnostic_code, violation.file_path, violation.line_number, violation.detail
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

fn acquire_ambient_mock_guard_bundle_lock(
    out_dir: &Path,
) -> Result<AmbientMockGuardBundleLock, AmbientMockGuardError> {
    let lock_path = out_dir.join(".ambient_mock_guard.lock");
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
        assert!(inv.summary.total_occurrences > 0);
    }

    #[test]
    fn canonical_inventory_has_must_fix() {
        let inv = build_canonical_inventory();
        assert!(inv.has_must_fix());
        assert!(inv.summary.must_fix_count >= 5);
    }

    #[test]
    fn canonical_inventory_has_test_only() {
        let inv = build_canonical_inventory();
        assert!(inv.summary.test_only_count >= 13);
    }

    #[test]
    fn canonical_inventory_has_architectural_issues() {
        let inv = build_canonical_inventory();
        assert_eq!(inv.summary.architectural_issue_count, 2);
    }

    #[test]
    fn canonical_inventory_orchestrator_must_fix() {
        let inv = build_canonical_inventory();
        let orch_items = inv.for_file("crates/franken-engine/src/execution_orchestrator.rs");
        assert!(!orch_items.is_empty());
        assert!(
            orch_items
                .iter()
                .all(|o| o.classification == SeamClassification::MustFixProduction)
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
        let json = serde_json::to_string(&inv).unwrap();
        let inv2: MockInventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, inv2);
    }

    #[test]
    fn classification_serde_roundtrip() {
        let c = SeamClassification::MustFixProduction;
        let json = serde_json::to_string(&c).unwrap();
        let c2: SeamClassification = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(&kind).unwrap();
            let k2: SeamKind = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(&sev).unwrap();
            let s2: SeamSeverity = serde_json::from_str(&json).unwrap();
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
            let json = serde_json::to_string(&rem).unwrap();
            let r2: RemediationStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(rem, r2);
        }
    }

    #[test]
    fn occurrence_serde_roundtrip() {
        let occ = sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction);
        let json = serde_json::to_string(&occ).unwrap();
        let occ2: SeamOccurrence = serde_json::from_str(&json).unwrap();
        assert_eq!(occ, occ2);
    }

    #[test]
    fn inventory_by_kind_breakdown() {
        let inv = build_canonical_inventory();
        assert!(inv.count_by_kind(SeamKind::MockContext) > 0);
        assert!(inv.count_by_kind(SeamKind::MockBudget) > 0);
    }

    #[test]
    fn inventory_affected_files_count() {
        let inv = build_canonical_inventory();
        // At least 14 distinct files (1 production + 13 test)
        assert!(inv.summary.affected_files >= 14);
    }

    #[test]
    fn inventory_must_fix_files_count() {
        let inv = build_canonical_inventory();
        // Only execution_orchestrator.rs has must-fix items
        assert_eq!(inv.summary.must_fix_files, 1);
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
            "cargo run -p frankenengine-engine --bin franken_ambient_mock_guard -- --out-dir /tmp/out"
                .to_string(),
        ];
        let artifacts = write_ambient_mock_guard_bundle_in_root(&root, &out_dir, &commands)
            .expect("bundle should be written");
        assert_eq!(artifacts.outcome, AmbientMockGuardOutcome::Pass);
        assert!(artifacts.report_path.exists());
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
                .expect("manifest should deserialize");
        assert_eq!(manifest.outcome, AmbientMockGuardOutcome::Pass);
        assert_eq!(
            manifest.artifact_paths.ambient_mock_guard_report,
            "ambient_mock_guard_report.json"
        );

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
}
