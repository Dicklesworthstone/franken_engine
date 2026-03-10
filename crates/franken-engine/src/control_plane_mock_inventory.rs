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
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::hash_tiers::ContentHash;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const COMPONENT: &str = "control_plane_mock_inventory";
pub const BEAD_ID: &str = "bd-3nr.1.1.1";
pub const INVENTORY_SCHEMA_VERSION: &str = "frankenengine.control-plane-mock-inventory.v1";

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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
    fn component_constant() {
        assert_eq!(COMPONENT, "control_plane_mock_inventory");
    }

    #[test]
    fn bead_id_constant() {
        assert_eq!(BEAD_ID, "bd-3nr.1.1.1");
    }
}
