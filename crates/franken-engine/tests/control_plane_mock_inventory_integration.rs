//! Integration tests for the `control_plane_mock_inventory` module.

#![allow(
    clippy::field_reassign_with_default,
    clippy::assertions_on_constants,
    clippy::useless_vec,
    clippy::clone_on_copy,
    clippy::unnecessary_get_then_check,
    clippy::len_zero,
    clippy::needless_borrows_for_generic_args,
    clippy::too_many_arguments,
    clippy::identity_op,
    clippy::manual_abs_diff
)]

use frankenengine_engine::control_plane_mock_inventory::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_occurrence(path: &str, line: u32, classification: SeamClassification) -> SeamOccurrence {
    SeamOccurrence::new(SeamOccurrenceInput {
        file_path: path,
        line_number: line,
        kind: SeamKind::MockContext,
        classification,
        severity: SeamSeverity::High,
        inside_cfg_test: classification == SeamClassification::AcceptableTestOnly,
        description: "integration test occurrence",
        remediation: RemediationStrategy::NoAction,
        remediation_bead: "",
    })
}

fn occurrence_with_kind(
    path: &str,
    line: u32,
    kind: SeamKind,
    classification: SeamClassification,
) -> SeamOccurrence {
    SeamOccurrence::new(SeamOccurrenceInput {
        file_path: path,
        line_number: line,
        kind,
        classification,
        severity: SeamSeverity::Medium,
        inside_cfg_test: false,
        description: "kind-specific occurrence",
        remediation: RemediationStrategy::MoveToTestOnly,
        remediation_bead: "bd-test",
    })
}

// ---------------------------------------------------------------------------
// SeamClassification Display / serde
// ---------------------------------------------------------------------------

#[test]
fn classification_must_fix_display() {
    assert_eq!(
        format!("{}", SeamClassification::MustFixProduction),
        "must_fix_production"
    );
}

#[test]
fn classification_test_only_display() {
    assert_eq!(
        format!("{}", SeamClassification::AcceptableTestOnly),
        "acceptable_test_only"
    );
}

#[test]
fn classification_false_positive_display() {
    assert_eq!(
        format!("{}", SeamClassification::FalsePositive),
        "false_positive"
    );
}

#[test]
fn classification_serde_roundtrip_all_variants() {
    for c in [
        SeamClassification::MustFixProduction,
        SeamClassification::AcceptableTestOnly,
        SeamClassification::FalsePositive,
    ] {
        let json = serde_json::to_string(&c).unwrap();
        let back: SeamClassification = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }
}

#[test]
fn classification_ordering() {
    assert!(SeamClassification::MustFixProduction < SeamClassification::AcceptableTestOnly);
    assert!(SeamClassification::AcceptableTestOnly < SeamClassification::FalsePositive);
}

// ---------------------------------------------------------------------------
// SeamKind Display / serde
// ---------------------------------------------------------------------------

#[test]
fn seam_kind_display_all_variants() {
    let expected = [
        (SeamKind::MockContext, "MockCx"),
        (SeamKind::MockBudget, "MockBudget"),
        (SeamKind::MockDecisionContract, "MockDecisionContract"),
        (SeamKind::MockEvidenceEmitter, "MockEvidenceEmitter"),
        (SeamKind::MockFailureMode, "MockFailureMode"),
        (SeamKind::SeedDerivedTraceId, "trace_id_from_seed"),
        (SeamKind::SeedDerivedDecisionId, "decision_id_from_seed"),
        (SeamKind::SeedDerivedPolicyId, "policy_id_from_seed"),
        (
            SeamKind::SeedDerivedSchemaVersion,
            "schema_version_from_seed",
        ),
        (SeamKind::HardcodedBudget, "hardcoded_budget"),
        (SeamKind::UnguardedMockModule, "unguarded_mock_module"),
    ];
    for (kind, display) in expected {
        assert_eq!(format!("{}", kind), display);
    }
}

#[test]
fn seam_kind_serde_roundtrip_all_variants() {
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
        let json = serde_json::to_string(&kind).unwrap();
        let back: SeamKind = serde_json::from_str(&json).unwrap();
        assert_eq!(kind, back);
    }
}

// ---------------------------------------------------------------------------
// SeamSeverity Display / serde
// ---------------------------------------------------------------------------

#[test]
fn severity_display_all_variants() {
    assert_eq!(format!("{}", SeamSeverity::Info), "info");
    assert_eq!(format!("{}", SeamSeverity::Low), "low");
    assert_eq!(format!("{}", SeamSeverity::Medium), "medium");
    assert_eq!(format!("{}", SeamSeverity::High), "high");
    assert_eq!(format!("{}", SeamSeverity::Critical), "critical");
}

#[test]
fn severity_serde_roundtrip_all_variants() {
    for sev in [
        SeamSeverity::Info,
        SeamSeverity::Low,
        SeamSeverity::Medium,
        SeamSeverity::High,
        SeamSeverity::Critical,
    ] {
        let json = serde_json::to_string(&sev).unwrap();
        let back: SeamSeverity = serde_json::from_str(&json).unwrap();
        assert_eq!(sev, back);
    }
}

#[test]
fn severity_ordering() {
    assert!(SeamSeverity::Info < SeamSeverity::Low);
    assert!(SeamSeverity::Low < SeamSeverity::Medium);
    assert!(SeamSeverity::Medium < SeamSeverity::High);
    assert!(SeamSeverity::High < SeamSeverity::Critical);
}

// ---------------------------------------------------------------------------
// RemediationStrategy Display / serde
// ---------------------------------------------------------------------------

#[test]
fn remediation_display_all_variants() {
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
fn remediation_serde_roundtrip_all_variants() {
    for rem in [
        RemediationStrategy::MoveToTestOnly,
        RemediationStrategy::ThreadRealContext,
        RemediationStrategy::PropagateBudget,
        RemediationStrategy::AddCfgTestGuard,
        RemediationStrategy::NoAction,
    ] {
        let json = serde_json::to_string(&rem).unwrap();
        let back: RemediationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(rem, back);
    }
}

// ---------------------------------------------------------------------------
// SeamOccurrence construction, content_hash, Display
// ---------------------------------------------------------------------------

#[test]
fn occurrence_new_sets_fields() {
    let occ = SeamOccurrence::new(SeamOccurrenceInput {
        file_path: "src/foo.rs",
        line_number: 42,
        kind: SeamKind::MockBudget,
        classification: SeamClassification::MustFixProduction,
        severity: SeamSeverity::Critical,
        inside_cfg_test: false,
        description: "hardcoded budget",
        remediation: RemediationStrategy::PropagateBudget,
        remediation_bead: "bd-fix",
    });
    assert_eq!(occ.file_path, "src/foo.rs");
    assert_eq!(occ.line_number, 42);
    assert_eq!(occ.kind, SeamKind::MockBudget);
    assert_eq!(occ.classification, SeamClassification::MustFixProduction);
    assert_eq!(occ.severity, SeamSeverity::Critical);
    assert!(!occ.inside_cfg_test);
    assert_eq!(occ.description, "hardcoded budget");
    assert_eq!(occ.remediation, RemediationStrategy::PropagateBudget);
    assert_eq!(occ.remediation_bead, "bd-fix");
}

#[test]
fn occurrence_content_hash_deterministic() {
    let a = sample_occurrence("x.rs", 10, SeamClassification::MustFixProduction);
    let b = sample_occurrence("x.rs", 10, SeamClassification::MustFixProduction);
    assert_eq!(a.content_hash(), b.content_hash());
}

#[test]
fn occurrence_content_hash_differs_by_file() {
    let a = sample_occurrence("x.rs", 10, SeamClassification::MustFixProduction);
    let b = sample_occurrence("y.rs", 10, SeamClassification::MustFixProduction);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn occurrence_content_hash_differs_by_line() {
    let a = sample_occurrence("x.rs", 10, SeamClassification::MustFixProduction);
    let b = sample_occurrence("x.rs", 11, SeamClassification::MustFixProduction);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn occurrence_content_hash_differs_by_classification() {
    let a = sample_occurrence("x.rs", 10, SeamClassification::MustFixProduction);
    let b = sample_occurrence("x.rs", 10, SeamClassification::FalsePositive);
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn occurrence_display_contains_file_line_kind() {
    let occ = sample_occurrence("src/lib.rs", 99, SeamClassification::MustFixProduction);
    let s = format!("{}", occ);
    assert!(s.contains("src/lib.rs:99"));
    assert!(s.contains("MockCx"));
    assert!(s.contains("high"));
}

#[test]
fn occurrence_serde_roundtrip() {
    let occ = SeamOccurrence::new(SeamOccurrenceInput {
        file_path: "test.rs",
        line_number: 5,
        kind: SeamKind::HardcodedBudget,
        classification: SeamClassification::AcceptableTestOnly,
        severity: SeamSeverity::Low,
        inside_cfg_test: true,
        description: "test-only budget",
        remediation: RemediationStrategy::NoAction,
        remediation_bead: "",
    });
    let json = serde_json::to_string(&occ).unwrap();
    let back: SeamOccurrence = serde_json::from_str(&json).unwrap();
    assert_eq!(occ, back);
}

// ---------------------------------------------------------------------------
// ArchitecturalIssue Display
// ---------------------------------------------------------------------------

#[test]
fn architectural_issue_display() {
    let issue = ArchitecturalIssue {
        id: "ARCH-001".to_string(),
        description: "Missing cfg guard".to_string(),
        file_path: "mod.rs".to_string(),
        severity: SeamSeverity::High,
        remediation: RemediationStrategy::AddCfgTestGuard,
        remediation_bead: "bd-fix".to_string(),
    };
    let s = format!("{}", issue);
    assert!(s.contains("ARCH-001"));
    assert!(s.contains("Missing cfg guard"));
    assert!(s.contains("high"));
}

#[test]
fn architectural_issue_serde_roundtrip() {
    let issue = ArchitecturalIssue {
        id: "ARCH-TEST".to_string(),
        description: "Test concern".to_string(),
        file_path: "test.rs".to_string(),
        severity: SeamSeverity::Medium,
        remediation: RemediationStrategy::ThreadRealContext,
        remediation_bead: "bd-x".to_string(),
    };
    let json = serde_json::to_string(&issue).unwrap();
    let back: ArchitecturalIssue = serde_json::from_str(&json).unwrap();
    assert_eq!(issue, back);
}

// ---------------------------------------------------------------------------
// MockInventory::build with mixed classifications
// ---------------------------------------------------------------------------

#[test]
fn inventory_build_mixed_classifications() {
    let occs = vec![
        sample_occurrence("a.rs", 1, SeamClassification::MustFixProduction),
        sample_occurrence("b.rs", 2, SeamClassification::AcceptableTestOnly),
        sample_occurrence("c.rs", 3, SeamClassification::FalsePositive),
        sample_occurrence("a.rs", 10, SeamClassification::MustFixProduction),
    ];
    let inv = MockInventory::build(occs, vec![]);
    assert_eq!(inv.summary.total_occurrences, 4);
    assert_eq!(inv.summary.must_fix_count, 2);
    assert_eq!(inv.summary.test_only_count, 1);
    assert_eq!(inv.summary.false_positive_count, 1);
    assert_eq!(inv.summary.affected_files, 3);
    assert_eq!(inv.summary.must_fix_files, 1);
}

#[test]
fn inventory_build_sorted_by_file_then_line() {
    let occs = vec![
        sample_occurrence("z.rs", 50, SeamClassification::AcceptableTestOnly),
        sample_occurrence("a.rs", 20, SeamClassification::MustFixProduction),
        sample_occurrence("a.rs", 5, SeamClassification::FalsePositive),
    ];
    let inv = MockInventory::build(occs, vec![]);
    assert_eq!(inv.occurrences[0].file_path, "a.rs");
    assert_eq!(inv.occurrences[0].line_number, 5);
    assert_eq!(inv.occurrences[1].file_path, "a.rs");
    assert_eq!(inv.occurrences[1].line_number, 20);
    assert_eq!(inv.occurrences[2].file_path, "z.rs");
}

// ---------------------------------------------------------------------------
// MockInventory filters (must_fix_items, test_only_items)
// ---------------------------------------------------------------------------

#[test]
fn inventory_must_fix_items_filter() {
    let occs = vec![
        sample_occurrence("a.rs", 1, SeamClassification::MustFixProduction),
        sample_occurrence("b.rs", 2, SeamClassification::AcceptableTestOnly),
        sample_occurrence("c.rs", 3, SeamClassification::MustFixProduction),
    ];
    let inv = MockInventory::build(occs, vec![]);
    let must_fix = inv.must_fix_items();
    assert_eq!(must_fix.len(), 2);
    assert!(
        must_fix
            .iter()
            .all(|o| o.classification == SeamClassification::MustFixProduction)
    );
}

#[test]
fn inventory_test_only_items_filter() {
    let occs = vec![
        sample_occurrence("a.rs", 1, SeamClassification::AcceptableTestOnly),
        sample_occurrence("b.rs", 2, SeamClassification::MustFixProduction),
        sample_occurrence("c.rs", 3, SeamClassification::AcceptableTestOnly),
        sample_occurrence("d.rs", 4, SeamClassification::FalsePositive),
    ];
    let inv = MockInventory::build(occs, vec![]);
    let test_only = inv.test_only_items();
    assert_eq!(test_only.len(), 2);
    assert!(
        test_only
            .iter()
            .all(|o| o.classification == SeamClassification::AcceptableTestOnly)
    );
}

#[test]
fn inventory_for_file_returns_matching() {
    let occs = vec![
        sample_occurrence("a.rs", 1, SeamClassification::MustFixProduction),
        sample_occurrence("a.rs", 10, SeamClassification::AcceptableTestOnly),
        sample_occurrence("b.rs", 5, SeamClassification::FalsePositive),
    ];
    let inv = MockInventory::build(occs, vec![]);
    assert_eq!(inv.for_file("a.rs").len(), 2);
    assert_eq!(inv.for_file("b.rs").len(), 1);
    assert_eq!(inv.for_file("nonexistent.rs").len(), 0);
}

#[test]
fn inventory_has_must_fix_true() {
    let occs = vec![sample_occurrence(
        "a.rs",
        1,
        SeamClassification::MustFixProduction,
    )];
    let inv = MockInventory::build(occs, vec![]);
    assert!(inv.has_must_fix());
}

#[test]
fn inventory_has_must_fix_false() {
    let occs = vec![sample_occurrence(
        "a.rs",
        1,
        SeamClassification::AcceptableTestOnly,
    )];
    let inv = MockInventory::build(occs, vec![]);
    assert!(!inv.has_must_fix());
}

#[test]
fn inventory_count_by_kind() {
    let occs = vec![
        occurrence_with_kind(
            "a.rs",
            1,
            SeamKind::MockContext,
            SeamClassification::MustFixProduction,
        ),
        occurrence_with_kind(
            "b.rs",
            2,
            SeamKind::MockBudget,
            SeamClassification::AcceptableTestOnly,
        ),
        occurrence_with_kind(
            "c.rs",
            3,
            SeamKind::MockContext,
            SeamClassification::FalsePositive,
        ),
        occurrence_with_kind(
            "d.rs",
            4,
            SeamKind::HardcodedBudget,
            SeamClassification::MustFixProduction,
        ),
    ];
    let inv = MockInventory::build(occs, vec![]);
    assert_eq!(inv.count_by_kind(SeamKind::MockContext), 2);
    assert_eq!(inv.count_by_kind(SeamKind::MockBudget), 1);
    assert_eq!(inv.count_by_kind(SeamKind::HardcodedBudget), 1);
    assert_eq!(inv.count_by_kind(SeamKind::UnguardedMockModule), 0);
}

// ---------------------------------------------------------------------------
// InventorySummary field correctness
// ---------------------------------------------------------------------------

#[test]
fn inventory_summary_by_kind_map() {
    let occs = vec![
        occurrence_with_kind(
            "a.rs",
            1,
            SeamKind::MockContext,
            SeamClassification::MustFixProduction,
        ),
        occurrence_with_kind(
            "b.rs",
            2,
            SeamKind::MockContext,
            SeamClassification::AcceptableTestOnly,
        ),
        occurrence_with_kind(
            "c.rs",
            3,
            SeamKind::SeedDerivedTraceId,
            SeamClassification::FalsePositive,
        ),
    ];
    let inv = MockInventory::build(occs, vec![]);
    assert_eq!(*inv.summary.by_kind.get("MockCx").unwrap(), 2);
    assert_eq!(*inv.summary.by_kind.get("trace_id_from_seed").unwrap(), 1);
    assert!(inv.summary.by_kind.get("MockBudget").is_none());
}

#[test]
fn inventory_summary_architectural_issue_count() {
    let issues = vec![
        ArchitecturalIssue {
            id: "A1".to_string(),
            description: "issue 1".to_string(),
            file_path: "x.rs".to_string(),
            severity: SeamSeverity::High,
            remediation: RemediationStrategy::AddCfgTestGuard,
            remediation_bead: "bd-1".to_string(),
        },
        ArchitecturalIssue {
            id: "A2".to_string(),
            description: "issue 2".to_string(),
            file_path: "y.rs".to_string(),
            severity: SeamSeverity::Critical,
            remediation: RemediationStrategy::ThreadRealContext,
            remediation_bead: "bd-2".to_string(),
        },
    ];
    let inv = MockInventory::build(vec![], issues);
    assert_eq!(inv.summary.architectural_issue_count, 2);
    assert_eq!(inv.architectural_issues.len(), 2);
}

// ---------------------------------------------------------------------------
// Inventory hash determinism
// ---------------------------------------------------------------------------

#[test]
fn inventory_hash_deterministic_same_data() {
    let occs = vec![
        sample_occurrence("a.rs", 1, SeamClassification::MustFixProduction),
        sample_occurrence("b.rs", 2, SeamClassification::AcceptableTestOnly),
    ];
    let inv1 = MockInventory::build(occs.clone(), vec![]);
    let inv2 = MockInventory::build(occs, vec![]);
    assert_eq!(inv1.inventory_hash, inv2.inventory_hash);
}

#[test]
fn inventory_hash_differs_with_different_occurrences() {
    let inv1 = MockInventory::build(
        vec![sample_occurrence(
            "a.rs",
            1,
            SeamClassification::MustFixProduction,
        )],
        vec![],
    );
    let inv2 = MockInventory::build(
        vec![sample_occurrence(
            "b.rs",
            1,
            SeamClassification::MustFixProduction,
        )],
        vec![],
    );
    assert_ne!(inv1.inventory_hash, inv2.inventory_hash);
}

#[test]
fn inventory_hash_differs_with_architectural_issues() {
    let occs = vec![sample_occurrence(
        "a.rs",
        1,
        SeamClassification::MustFixProduction,
    )];
    let inv1 = MockInventory::build(occs.clone(), vec![]);
    let inv2 = MockInventory::build(
        occs,
        vec![ArchitecturalIssue {
            id: "ARCH-X".to_string(),
            description: "extra issue".to_string(),
            file_path: "a.rs".to_string(),
            severity: SeamSeverity::High,
            remediation: RemediationStrategy::NoAction,
            remediation_bead: "".to_string(),
        }],
    );
    assert_ne!(inv1.inventory_hash, inv2.inventory_hash);
}

#[test]
fn inventory_hash_independent_of_insertion_order() {
    let a = sample_occurrence("a.rs", 1, SeamClassification::MustFixProduction);
    let b = sample_occurrence("b.rs", 2, SeamClassification::AcceptableTestOnly);
    // build() sorts by (file_path, line_number), so order should not matter
    let inv1 = MockInventory::build(vec![a.clone(), b.clone()], vec![]);
    let inv2 = MockInventory::build(vec![b, a], vec![]);
    assert_eq!(inv1.inventory_hash, inv2.inventory_hash);
}

// ---------------------------------------------------------------------------
// Edge cases: empty inventory
// ---------------------------------------------------------------------------

#[test]
fn empty_inventory_summary() {
    let inv = MockInventory::build(vec![], vec![]);
    assert_eq!(inv.summary.total_occurrences, 0);
    assert_eq!(inv.summary.must_fix_count, 0);
    assert_eq!(inv.summary.test_only_count, 0);
    assert_eq!(inv.summary.false_positive_count, 0);
    assert_eq!(inv.summary.affected_files, 0);
    assert_eq!(inv.summary.must_fix_files, 0);
    assert_eq!(inv.summary.architectural_issue_count, 0);
    assert!(inv.summary.by_kind.is_empty());
    assert!(!inv.has_must_fix());
}

#[test]
fn empty_inventory_filters_return_empty() {
    let inv = MockInventory::build(vec![], vec![]);
    assert!(inv.must_fix_items().is_empty());
    assert!(inv.test_only_items().is_empty());
    assert!(inv.for_file("any.rs").is_empty());
}

// ---------------------------------------------------------------------------
// Edge cases: all same classification
// ---------------------------------------------------------------------------

#[test]
fn all_must_fix_inventory() {
    let occs = vec![
        sample_occurrence("a.rs", 1, SeamClassification::MustFixProduction),
        sample_occurrence("b.rs", 2, SeamClassification::MustFixProduction),
        sample_occurrence("c.rs", 3, SeamClassification::MustFixProduction),
    ];
    let inv = MockInventory::build(occs, vec![]);
    assert_eq!(inv.summary.must_fix_count, 3);
    assert_eq!(inv.summary.test_only_count, 0);
    assert_eq!(inv.summary.false_positive_count, 0);
    assert_eq!(inv.must_fix_items().len(), 3);
    assert!(inv.test_only_items().is_empty());
}

#[test]
fn all_test_only_inventory() {
    let occs = vec![
        sample_occurrence("a.rs", 1, SeamClassification::AcceptableTestOnly),
        sample_occurrence("b.rs", 2, SeamClassification::AcceptableTestOnly),
    ];
    let inv = MockInventory::build(occs, vec![]);
    assert_eq!(inv.summary.test_only_count, 2);
    assert_eq!(inv.summary.must_fix_count, 0);
    assert!(!inv.has_must_fix());
    assert_eq!(inv.test_only_items().len(), 2);
}

// ---------------------------------------------------------------------------
// MockInventory serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn inventory_serde_roundtrip() {
    let occs = vec![
        sample_occurrence("a.rs", 1, SeamClassification::MustFixProduction),
        sample_occurrence("b.rs", 2, SeamClassification::AcceptableTestOnly),
    ];
    let issues = vec![ArchitecturalIssue {
        id: "ARCH-1".to_string(),
        description: "test".to_string(),
        file_path: "a.rs".to_string(),
        severity: SeamSeverity::High,
        remediation: RemediationStrategy::AddCfgTestGuard,
        remediation_bead: "bd-1".to_string(),
    }];
    let inv = MockInventory::build(occs, issues);
    let json = serde_json::to_string(&inv).unwrap();
    let back: MockInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// ---------------------------------------------------------------------------
// MockInventory Display
// ---------------------------------------------------------------------------

#[test]
fn inventory_display_contains_summary() {
    let occs = vec![
        sample_occurrence("a.rs", 1, SeamClassification::MustFixProduction),
        sample_occurrence("b.rs", 2, SeamClassification::AcceptableTestOnly),
    ];
    let inv = MockInventory::build(occs, vec![]);
    let s = format!("{}", inv);
    assert!(s.contains("Total occurrences: 2"));
    assert!(s.contains("Must-fix: 1"));
    assert!(s.contains("Test-only: 1"));
    assert!(s.contains("False positive: 0"));
    assert!(s.contains("Affected files: 2"));
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

#[test]
fn component_constant() {
    assert_eq!(COMPONENT, "control_plane_mock_inventory");
}

#[test]
fn bead_id_constant() {
    assert_eq!(BEAD_ID, "bd-3nr.1.1.1");
}

#[test]
fn schema_version_constant() {
    assert_eq!(
        INVENTORY_SCHEMA_VERSION,
        "frankenengine.control-plane-mock-inventory.v1"
    );
}

// ---------------------------------------------------------------------------
// Canonical inventory integration
// ---------------------------------------------------------------------------

#[test]
fn canonical_inventory_builds_successfully() {
    let inv = build_canonical_inventory();
    assert!(inv.summary.total_occurrences > 0);
    assert!(inv.has_must_fix());
}

#[test]
fn canonical_inventory_schema_version() {
    let inv = build_canonical_inventory();
    assert_eq!(inv.schema_version, INVENTORY_SCHEMA_VERSION);
}

#[test]
fn canonical_inventory_deterministic_hash() {
    let inv1 = build_canonical_inventory();
    let inv2 = build_canonical_inventory();
    assert_eq!(inv1.inventory_hash, inv2.inventory_hash);
    assert_eq!(inv1, inv2);
}

#[test]
fn canonical_inventory_serde_roundtrip() {
    let inv = build_canonical_inventory();
    let json = serde_json::to_string(&inv).unwrap();
    let back: MockInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(inv, back);
}

// ---------------------------------------------------------------------------
// Additional edge cases
// ---------------------------------------------------------------------------

#[test]
fn occurrence_content_hash_differs_by_kind() {
    let a = SeamOccurrence::new(SeamOccurrenceInput {
        file_path: "x.rs",
        line_number: 10,
        kind: SeamKind::MockContext,
        classification: SeamClassification::MustFixProduction,
        severity: SeamSeverity::High,
        inside_cfg_test: false,
        description: "desc",
        remediation: RemediationStrategy::NoAction,
        remediation_bead: "",
    });
    let b = SeamOccurrence::new(SeamOccurrenceInput {
        file_path: "x.rs",
        line_number: 10,
        kind: SeamKind::MockBudget,
        classification: SeamClassification::MustFixProduction,
        severity: SeamSeverity::High,
        inside_cfg_test: false,
        description: "desc",
        remediation: RemediationStrategy::NoAction,
        remediation_bead: "",
    });
    assert_ne!(a.content_hash(), b.content_hash());
}

#[test]
fn inventory_multiple_occurrences_same_file() {
    let occs = vec![
        sample_occurrence("f.rs", 1, SeamClassification::MustFixProduction),
        sample_occurrence("f.rs", 5, SeamClassification::AcceptableTestOnly),
        sample_occurrence("f.rs", 10, SeamClassification::FalsePositive),
    ];
    let inv = MockInventory::build(occs, vec![]);
    assert_eq!(inv.summary.affected_files, 1);
    assert_eq!(inv.summary.must_fix_files, 1);
    assert_eq!(inv.for_file("f.rs").len(), 3);
}

#[test]
fn inventory_must_fix_files_only_counts_must_fix() {
    let occs = vec![
        sample_occurrence("a.rs", 1, SeamClassification::AcceptableTestOnly),
        sample_occurrence("b.rs", 2, SeamClassification::FalsePositive),
    ];
    let inv = MockInventory::build(occs, vec![]);
    assert_eq!(inv.summary.must_fix_files, 0);
    assert_eq!(inv.summary.affected_files, 2);
}

// ---------------------------------------------------------------------------
// AmbientMockGuardOutcome — Display, as_str, serde
// ---------------------------------------------------------------------------

#[test]
fn ambient_mock_guard_outcome_display_pass() {
    assert_eq!(format!("{}", AmbientMockGuardOutcome::Pass), "pass");
}

#[test]
fn ambient_mock_guard_outcome_display_fail_closed() {
    assert_eq!(
        format!("{}", AmbientMockGuardOutcome::FailClosed),
        "fail_closed"
    );
}

#[test]
fn ambient_mock_guard_outcome_as_str() {
    assert_eq!(AmbientMockGuardOutcome::Pass.as_str(), "pass");
    assert_eq!(AmbientMockGuardOutcome::FailClosed.as_str(), "fail_closed");
}

#[test]
fn ambient_mock_guard_outcome_serde_roundtrip() {
    for outcome in [
        AmbientMockGuardOutcome::Pass,
        AmbientMockGuardOutcome::FailClosed,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: AmbientMockGuardOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }
}

// ---------------------------------------------------------------------------
// AmbientMockGuardRule — Display, as_str, serde
// ---------------------------------------------------------------------------

#[test]
fn ambient_mock_guard_rule_display_all() {
    assert_eq!(
        format!("{}", AmbientMockGuardRule::MockModuleMustBeCfgTest),
        "mock_module_must_be_cfg_test"
    );
    assert_eq!(
        format!("{}", AmbientMockGuardRule::NoProductionMockModuleReference),
        "no_production_mock_module_reference"
    );
    assert_eq!(
        format!("{}", AmbientMockGuardRule::NoProductionFakeContextSymbol),
        "no_production_fake_context_symbol"
    );
}

#[test]
fn ambient_mock_guard_rule_as_str_all() {
    assert_eq!(
        AmbientMockGuardRule::MockModuleMustBeCfgTest.as_str(),
        "mock_module_must_be_cfg_test"
    );
    assert_eq!(
        AmbientMockGuardRule::NoProductionMockModuleReference.as_str(),
        "no_production_mock_module_reference"
    );
    assert_eq!(
        AmbientMockGuardRule::NoProductionFakeContextSymbol.as_str(),
        "no_production_fake_context_symbol"
    );
}

#[test]
fn ambient_mock_guard_rule_serde_roundtrip() {
    for rule in [
        AmbientMockGuardRule::MockModuleMustBeCfgTest,
        AmbientMockGuardRule::NoProductionMockModuleReference,
        AmbientMockGuardRule::NoProductionFakeContextSymbol,
    ] {
        let json = serde_json::to_string(&rule).unwrap();
        let back: AmbientMockGuardRule = serde_json::from_str(&json).unwrap();
        assert_eq!(rule, back);
    }
}

// ---------------------------------------------------------------------------
// AmbientMockGuardViolation serde
// ---------------------------------------------------------------------------

#[test]
fn ambient_mock_guard_violation_serde_roundtrip() {
    let v = AmbientMockGuardViolation {
        violation_id: "v-001".to_string(),
        rule: AmbientMockGuardRule::MockModuleMustBeCfgTest,
        severity: SeamSeverity::High,
        diagnostic_code: "AMG-001".to_string(),
        file_path: "src/control_plane/mod.rs".to_string(),
        line_number: 284,
        code_snippet: "pub mod mocks {".to_string(),
        detail: "Module lacks #[cfg(test)] guard".to_string(),
        remediation: "Add #[cfg(test)] above module definition".to_string(),
    };
    let json = serde_json::to_string(&v).unwrap();
    let back: AmbientMockGuardViolation = serde_json::from_str(&json).unwrap();
    assert_eq!(v, back);
}

// ---------------------------------------------------------------------------
// AmbientMockGuardSummary serde
// ---------------------------------------------------------------------------

#[test]
fn ambient_mock_guard_summary_serde_roundtrip() {
    let s = AmbientMockGuardSummary {
        scanned_file_count: 42,
        violation_count: 3,
        architectural_violation_count: 1,
        production_reference_violation_count: 1,
        fake_context_violation_count: 1,
    };
    let json = serde_json::to_string(&s).unwrap();
    let back: AmbientMockGuardSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(s, back);
}

// ---------------------------------------------------------------------------
// AmbientMockGuardReport serde
// ---------------------------------------------------------------------------

#[test]
fn ambient_mock_guard_report_serde_roundtrip() {
    let report = AmbientMockGuardReport {
        schema_version: AMBIENT_MOCK_GUARD_REPORT_SCHEMA_VERSION.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        bead_id: AMBIENT_MOCK_GUARD_BEAD_ID.to_string(),
        policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
        canonical_inventory_hash: "abc123".to_string(),
        scan_root: AMBIENT_MOCK_GUARD_SCAN_ROOT.to_string(),
        outcome: AmbientMockGuardOutcome::Pass,
        summary: AmbientMockGuardSummary {
            scanned_file_count: 10,
            violation_count: 0,
            architectural_violation_count: 0,
            production_reference_violation_count: 0,
            fake_context_violation_count: 0,
        },
        violations: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: AmbientMockGuardReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// AmbientMockGuardTraceIds serde
// ---------------------------------------------------------------------------

#[test]
fn ambient_mock_guard_trace_ids_serde_roundtrip() {
    let ids = AmbientMockGuardTraceIds {
        schema_version: AMBIENT_MOCK_GUARD_TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        trace_id: "trace-abc".to_string(),
        decision_id: "decision-abc".to_string(),
        policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
        report_hash: "deadbeef".to_string(),
        canonical_inventory_hash: "abc123".to_string(),
    };
    let json = serde_json::to_string(&ids).unwrap();
    let back: AmbientMockGuardTraceIds = serde_json::from_str(&json).unwrap();
    assert_eq!(ids, back);
}

// ---------------------------------------------------------------------------
// AmbientMockGuardArtifactPaths serde
// ---------------------------------------------------------------------------

#[test]
fn ambient_mock_guard_artifact_paths_serde_roundtrip() {
    let paths = AmbientMockGuardArtifactPaths {
        ambient_mock_guard_report: "report.json".to_string(),
        trace_ids: "trace_ids.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
        step_logs_dir: "step_logs".to_string(),
        summary_md: "summary.md".to_string(),
        env_json: "env.json".to_string(),
        repro_lock: "repro.lock".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: AmbientMockGuardArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

// ---------------------------------------------------------------------------
// AmbientMockGuardRunManifest serde
// ---------------------------------------------------------------------------

#[test]
fn ambient_mock_guard_run_manifest_serde_roundtrip() {
    let manifest = AmbientMockGuardRunManifest {
        schema_version: AMBIENT_MOCK_GUARD_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
        report_hash: "aabb".to_string(),
        canonical_inventory_hash: "ccdd".to_string(),
        outcome: AmbientMockGuardOutcome::FailClosed,
        violation_count: 5,
        artifact_paths: AmbientMockGuardArtifactPaths {
            ambient_mock_guard_report: "report.json".to_string(),
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
    let json = serde_json::to_string(&manifest).unwrap();
    let back: AmbientMockGuardRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ---------------------------------------------------------------------------
// AmbientMockGuardEvent serde (with optional fields)
// ---------------------------------------------------------------------------

#[test]
fn ambient_mock_guard_event_serde_with_all_fields() {
    let event = AmbientMockGuardEvent {
        schema_version: AMBIENT_MOCK_GUARD_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        event: "violation_detected".to_string(),
        outcome: "fail_closed".to_string(),
        error_code: Some("AMG-001".to_string()),
        seed: "seed-abc".to_string(),
        scenario_id: "scenario-1".to_string(),
        diagnostic_id: Some("diag-1".to_string()),
        file_path: Some("src/foo.rs".to_string()),
        line_number: Some(42),
        detail: Some("detail info".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: AmbientMockGuardEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn ambient_mock_guard_event_serde_with_no_optional_fields() {
    let event = AmbientMockGuardEvent {
        schema_version: AMBIENT_MOCK_GUARD_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-2".to_string(),
        decision_id: "decision-2".to_string(),
        policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        event: "scan_complete".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        seed: "seed-xyz".to_string(),
        scenario_id: "scenario-2".to_string(),
        diagnostic_id: None,
        file_path: None,
        line_number: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    // Optional None fields should be absent from JSON
    assert!(!json.contains("error_code"));
    assert!(!json.contains("diagnostic_id"));
    assert!(!json.contains("file_path"));
    assert!(!json.contains("line_number"));
    assert!(!json.contains("detail"));
    let back: AmbientMockGuardEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// OrchestratorContextRefactorOutcome — Display, as_str, serde
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_outcome_display() {
    assert_eq!(
        format!("{}", OrchestratorContextRefactorOutcome::Pass),
        "pass"
    );
    assert_eq!(
        format!("{}", OrchestratorContextRefactorOutcome::FailClosed),
        "fail_closed"
    );
}

#[test]
fn orchestrator_outcome_as_str() {
    assert_eq!(OrchestratorContextRefactorOutcome::Pass.as_str(), "pass");
    assert_eq!(
        OrchestratorContextRefactorOutcome::FailClosed.as_str(),
        "fail_closed"
    );
}

#[test]
fn orchestrator_outcome_serde_roundtrip() {
    for outcome in [
        OrchestratorContextRefactorOutcome::Pass,
        OrchestratorContextRefactorOutcome::FailClosed,
    ] {
        let json = serde_json::to_string(&outcome).unwrap();
        let back: OrchestratorContextRefactorOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(outcome, back);
    }
}

// ---------------------------------------------------------------------------
// ProductionContextPath serde
// ---------------------------------------------------------------------------

#[test]
fn production_context_path_serde_roundtrip() {
    let path = ProductionContextPath {
        path_id: "path-1".to_string(),
        source_file: "src/orch.rs".to_string(),
        source_symbol: "build_context".to_string(),
        context_origin: "KernelContext::new(...)".to_string(),
        trace_origin: "derive_trace_id".to_string(),
        budget_origin: "Budget::new(100)".to_string(),
        capability_scope: "NoCaps".to_string(),
        deterministic_fallback: "BudgetExhausted".to_string(),
    };
    let json = serde_json::to_string(&path).unwrap();
    let back: ProductionContextPath = serde_json::from_str(&json).unwrap();
    assert_eq!(path, back);
}

// ---------------------------------------------------------------------------
// CorrectedProductionSeam serde
// ---------------------------------------------------------------------------

#[test]
fn corrected_production_seam_serde_roundtrip() {
    let seam = CorrectedProductionSeam {
        seam_id: "seam-1".to_string(),
        occurrence_hash: "hash-abc".to_string(),
        original_file_path: "src/orch.rs".to_string(),
        original_line_number: 30,
        seam_kind: SeamKind::MockContext,
        previous_pattern: "MockCx::new()".to_string(),
        corrected_path_id: "path-1".to_string(),
        corrected_context_source: "KernelContext".to_string(),
        corrected_trace_source: "derive_trace_id".to_string(),
        corrected_budget_source: "Budget::new".to_string(),
    };
    let json = serde_json::to_string(&seam).unwrap();
    let back: CorrectedProductionSeam = serde_json::from_str(&json).unwrap();
    assert_eq!(seam, back);
}

// ---------------------------------------------------------------------------
// ContextRefactorGuard serde (with and without optional error_code)
// ---------------------------------------------------------------------------

#[test]
fn context_refactor_guard_serde_with_error_code() {
    let guard = ContextRefactorGuard {
        guard_id: "guard-1".to_string(),
        guard_kind: "forbidden_token".to_string(),
        needle: "MockCx::new(".to_string(),
        passed: false,
        error_code: Some("CRG-001".to_string()),
    };
    let json = serde_json::to_string(&guard).unwrap();
    let back: ContextRefactorGuard = serde_json::from_str(&json).unwrap();
    assert_eq!(guard, back);
}

#[test]
fn context_refactor_guard_serde_without_error_code() {
    let guard = ContextRefactorGuard {
        guard_id: "guard-2".to_string(),
        guard_kind: "required_token".to_string(),
        needle: "KernelContext::new".to_string(),
        passed: true,
        error_code: None,
    };
    let json = serde_json::to_string(&guard).unwrap();
    assert!(!json.contains("error_code"));
    let back: ContextRefactorGuard = serde_json::from_str(&json).unwrap();
    assert_eq!(guard, back);
}

// ---------------------------------------------------------------------------
// ProductionContextPathContract serde
// ---------------------------------------------------------------------------

#[test]
fn production_context_path_contract_serde_roundtrip() {
    let contract = ProductionContextPathContract {
        schema_version: ORCHESTRATOR_CONTEXT_PATH_CONTRACT_SCHEMA_VERSION.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        bead_id: ORCHESTRATOR_CONTEXT_REFACTOR_BEAD_ID.to_string(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        canonical_inventory_hash: "inv-hash".to_string(),
        source_file: ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE.to_string(),
        context_paths: vec![],
        corrected_seams: vec![],
        deferred_seams: vec![],
        guards: vec![],
    };
    let json = serde_json::to_string(&contract).unwrap();
    let back: ProductionContextPathContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

// ---------------------------------------------------------------------------
// OrchestratorContextRefactorSummary serde
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_context_refactor_summary_serde_roundtrip() {
    let summary = OrchestratorContextRefactorSummary {
        corrected_seam_count: 5,
        deferred_seam_count: 0,
        guard_count: 9,
        failed_guard_count: 2,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: OrchestratorContextRefactorSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(summary, back);
}

// ---------------------------------------------------------------------------
// OrchestratorContextRefactorReport serde
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_context_refactor_report_serde_roundtrip() {
    let report = OrchestratorContextRefactorReport {
        schema_version: ORCHESTRATOR_CONTEXT_REFACTOR_REPORT_SCHEMA_VERSION.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        bead_id: ORCHESTRATOR_CONTEXT_REFACTOR_BEAD_ID.to_string(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        canonical_inventory_hash: "inv-hash".to_string(),
        contract_hash: "contract-hash".to_string(),
        source_file: ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE.to_string(),
        outcome: OrchestratorContextRefactorOutcome::Pass,
        summary: OrchestratorContextRefactorSummary {
            corrected_seam_count: 3,
            deferred_seam_count: 0,
            guard_count: 4,
            failed_guard_count: 0,
        },
        corrected_seams: vec![],
        deferred_seams: vec![],
        guards: vec![],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: OrchestratorContextRefactorReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
}

// ---------------------------------------------------------------------------
// OrchestratorContextRefactorArtifactPaths serde
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_artifact_paths_serde_roundtrip() {
    let paths = OrchestratorContextRefactorArtifactPaths {
        production_context_path_contract: "contract.json".to_string(),
        orchestrator_context_refactor_report: "report.json".to_string(),
        trace_ids: "trace_ids.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
        step_logs_dir: "step_logs".to_string(),
        summary_md: "summary.md".to_string(),
        env_json: "env.json".to_string(),
        repro_lock: "repro.lock".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: OrchestratorContextRefactorArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(paths, back);
}

// ---------------------------------------------------------------------------
// OrchestratorContextRefactorTraceIds serde
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_trace_ids_serde_roundtrip() {
    let ids = OrchestratorContextRefactorTraceIds {
        schema_version: ORCHESTRATOR_CONTEXT_REFACTOR_TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        trace_id: "trace-orch".to_string(),
        decision_id: "decision-orch".to_string(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        report_hash: "rephash".to_string(),
        contract_hash: "conhash".to_string(),
        canonical_inventory_hash: "invhash".to_string(),
    };
    let json = serde_json::to_string(&ids).unwrap();
    let back: OrchestratorContextRefactorTraceIds = serde_json::from_str(&json).unwrap();
    assert_eq!(ids, back);
}

// ---------------------------------------------------------------------------
// OrchestratorContextRefactorRunManifest serde
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_run_manifest_serde_roundtrip() {
    let manifest = OrchestratorContextRefactorRunManifest {
        schema_version: ORCHESTRATOR_CONTEXT_REFACTOR_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        report_hash: "rhash".to_string(),
        contract_hash: "chash".to_string(),
        canonical_inventory_hash: "ihash".to_string(),
        outcome: OrchestratorContextRefactorOutcome::FailClosed,
        corrected_seam_count: 0,
        failed_guard_count: 3,
        artifact_paths: OrchestratorContextRefactorArtifactPaths {
            production_context_path_contract: "contract.json".to_string(),
            orchestrator_context_refactor_report: "report.json".to_string(),
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
    let json = serde_json::to_string(&manifest).unwrap();
    let back: OrchestratorContextRefactorRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(manifest, back);
}

// ---------------------------------------------------------------------------
// OrchestratorContextRefactorEvent serde (with optional fields)
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_event_serde_all_fields() {
    let event = OrchestratorContextRefactorEvent {
        schema_version: ORCHESTRATOR_CONTEXT_REFACTOR_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        event: "guard_check".to_string(),
        outcome: "fail_closed".to_string(),
        error_code: Some("CRG-001".to_string()),
        seed: "seed-1".to_string(),
        scenario_id: "scenario-1".to_string(),
        diagnostic_id: Some("diag-1".to_string()),
        file_path: Some("src/orch.rs".to_string()),
        line_number: Some(519),
        detail: Some("MockCx found in production path".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: OrchestratorContextRefactorEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

#[test]
fn orchestrator_event_serde_no_optional_fields() {
    let event = OrchestratorContextRefactorEvent {
        schema_version: ORCHESTRATOR_CONTEXT_REFACTOR_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-2".to_string(),
        decision_id: "decision-2".to_string(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        event: "scan_complete".to_string(),
        outcome: "pass".to_string(),
        error_code: None,
        seed: "seed-2".to_string(),
        scenario_id: "scenario-2".to_string(),
        diagnostic_id: None,
        file_path: None,
        line_number: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(!json.contains("error_code"));
    let back: OrchestratorContextRefactorEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(event, back);
}

// ---------------------------------------------------------------------------
// Exit code functions
// ---------------------------------------------------------------------------

#[test]
fn ambient_mock_guard_exit_code_pass() {
    let report = AmbientMockGuardReport {
        schema_version: "v1".to_string(),
        component: "test".to_string(),
        bead_id: "bd-test".to_string(),
        policy_id: "p1".to_string(),
        canonical_inventory_hash: "h".to_string(),
        scan_root: "src".to_string(),
        outcome: AmbientMockGuardOutcome::Pass,
        summary: AmbientMockGuardSummary {
            scanned_file_count: 0,
            violation_count: 0,
            architectural_violation_count: 0,
            production_reference_violation_count: 0,
            fake_context_violation_count: 0,
        },
        violations: vec![],
    };
    assert_eq!(ambient_mock_guard_exit_code(&report), 0);
}

#[test]
fn ambient_mock_guard_exit_code_fail_closed() {
    let report = AmbientMockGuardReport {
        schema_version: "v1".to_string(),
        component: "test".to_string(),
        bead_id: "bd-test".to_string(),
        policy_id: "p1".to_string(),
        canonical_inventory_hash: "h".to_string(),
        scan_root: "src".to_string(),
        outcome: AmbientMockGuardOutcome::FailClosed,
        summary: AmbientMockGuardSummary {
            scanned_file_count: 0,
            violation_count: 1,
            architectural_violation_count: 1,
            production_reference_violation_count: 0,
            fake_context_violation_count: 0,
        },
        violations: vec![],
    };
    assert_eq!(ambient_mock_guard_exit_code(&report), 2);
}

#[test]
fn orchestrator_exit_code_pass() {
    let report = OrchestratorContextRefactorReport {
        schema_version: "v1".to_string(),
        component: "test".to_string(),
        bead_id: "bd-test".to_string(),
        policy_id: "p1".to_string(),
        canonical_inventory_hash: "h".to_string(),
        contract_hash: "ch".to_string(),
        source_file: "src/orch.rs".to_string(),
        outcome: OrchestratorContextRefactorOutcome::Pass,
        summary: OrchestratorContextRefactorSummary {
            corrected_seam_count: 0,
            deferred_seam_count: 0,
            guard_count: 0,
            failed_guard_count: 0,
        },
        corrected_seams: vec![],
        deferred_seams: vec![],
        guards: vec![],
    };
    assert_eq!(orchestrator_context_refactor_exit_code(&report), 0);
}

#[test]
fn orchestrator_exit_code_fail_closed() {
    let report = OrchestratorContextRefactorReport {
        schema_version: "v1".to_string(),
        component: "test".to_string(),
        bead_id: "bd-test".to_string(),
        policy_id: "p1".to_string(),
        canonical_inventory_hash: "h".to_string(),
        contract_hash: "ch".to_string(),
        source_file: "src/orch.rs".to_string(),
        outcome: OrchestratorContextRefactorOutcome::FailClosed,
        summary: OrchestratorContextRefactorSummary {
            corrected_seam_count: 0,
            deferred_seam_count: 0,
            guard_count: 1,
            failed_guard_count: 1,
        },
        corrected_seams: vec![],
        deferred_seams: vec![],
        guards: vec![],
    };
    assert_eq!(orchestrator_context_refactor_exit_code(&report), 2);
}

// ---------------------------------------------------------------------------
// Additional ambient mock guard constants
// ---------------------------------------------------------------------------

#[test]
fn ambient_mock_guard_constants_nonempty() {
    assert!(!AMBIENT_MOCK_GUARD_COMPONENT.is_empty());
    assert!(!AMBIENT_MOCK_GUARD_BEAD_ID.is_empty());
    assert!(!AMBIENT_MOCK_GUARD_POLICY_ID.is_empty());
    assert!(!AMBIENT_MOCK_GUARD_REPORT_SCHEMA_VERSION.is_empty());
    assert!(!AMBIENT_MOCK_GUARD_TRACE_IDS_SCHEMA_VERSION.is_empty());
    assert!(!AMBIENT_MOCK_GUARD_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!AMBIENT_MOCK_GUARD_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!AMBIENT_MOCK_GUARD_SCAN_ROOT.is_empty());
}

// ---------------------------------------------------------------------------
// Orchestrator context refactor constants
// ---------------------------------------------------------------------------

#[test]
fn orchestrator_context_refactor_constants_nonempty() {
    assert!(!ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.is_empty());
    assert!(!ORCHESTRATOR_CONTEXT_REFACTOR_BEAD_ID.is_empty());
    assert!(!ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.is_empty());
    assert!(!ORCHESTRATOR_CONTEXT_PATH_CONTRACT_SCHEMA_VERSION.is_empty());
    assert!(!ORCHESTRATOR_CONTEXT_REFACTOR_REPORT_SCHEMA_VERSION.is_empty());
    assert!(!ORCHESTRATOR_CONTEXT_REFACTOR_TRACE_IDS_SCHEMA_VERSION.is_empty());
    assert!(!ORCHESTRATOR_CONTEXT_REFACTOR_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!ORCHESTRATOR_CONTEXT_REFACTOR_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE.is_empty());
    assert!(!ORCHESTRATOR_CONTEXT_PATH_ID.is_empty());
}

// ---------------------------------------------------------------------------
// InventorySummary serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn inventory_summary_serde_roundtrip() {
    let occs = vec![
        sample_occurrence("a.rs", 1, SeamClassification::MustFixProduction),
        sample_occurrence("b.rs", 2, SeamClassification::AcceptableTestOnly),
    ];
    let inv = MockInventory::build(occs, vec![]);
    let json = serde_json::to_string(&inv.summary).unwrap();
    let back: InventorySummary = serde_json::from_str(&json).unwrap();
    assert_eq!(inv.summary, back);
}

// ---------------------------------------------------------------------------
// Canonical inventory structure
// ---------------------------------------------------------------------------

#[test]
fn canonical_inventory_has_must_fix_and_test_only() {
    let inv = build_canonical_inventory();
    assert!(inv.summary.must_fix_count > 0, "should have must-fix items");
    assert!(
        inv.summary.test_only_count > 0,
        "should have test-only items"
    );
}

#[test]
fn canonical_inventory_has_architectural_issues() {
    let inv = build_canonical_inventory();
    assert!(
        inv.summary.architectural_issue_count > 0,
        "should have architectural issues"
    );
    assert!(!inv.architectural_issues.is_empty());
}

#[test]
fn canonical_inventory_must_fix_all_from_orchestrator() {
    let inv = build_canonical_inventory();
    let must_fix = inv.must_fix_items();
    for occ in &must_fix {
        assert!(
            occ.file_path.contains("execution_orchestrator"),
            "must-fix should be from orchestrator, got: {}",
            occ.file_path
        );
    }
}

// ---------------------------------------------------------------------------
// Inventory with architectural issues only (no occurrences)
// ---------------------------------------------------------------------------

#[test]
fn inventory_arch_issues_only() {
    let issues = vec![ArchitecturalIssue {
        id: "ARCH-X".to_string(),
        description: "lone issue".to_string(),
        file_path: "x.rs".to_string(),
        severity: SeamSeverity::Medium,
        remediation: RemediationStrategy::NoAction,
        remediation_bead: "".to_string(),
    }];
    let inv = MockInventory::build(vec![], issues);
    assert_eq!(inv.summary.total_occurrences, 0);
    assert_eq!(inv.summary.architectural_issue_count, 1);
    assert!(!inv.has_must_fix());
}

// ---------------------------------------------------------------------------
// Content hash uniqueness across all SeamKind variants
// ---------------------------------------------------------------------------

#[test]
fn all_seam_kinds_produce_unique_hashes() {
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
    let mut hashes = std::collections::BTreeSet::new();
    for kind in &kinds {
        let occ = occurrence_with_kind("same.rs", 1, *kind, SeamClassification::MustFixProduction);
        hashes.insert(occ.content_hash().as_bytes().to_vec());
    }
    assert_eq!(
        hashes.len(),
        kinds.len(),
        "each SeamKind should produce a unique hash"
    );
}

// ---------------------------------------------------------------------------
// Multiple seam kinds get distinct by_kind entries
// ---------------------------------------------------------------------------

#[test]
fn multiple_seam_kinds_get_distinct_by_kind() {
    let occs = vec![
        occurrence_with_kind(
            "a.rs",
            1,
            SeamKind::MockContext,
            SeamClassification::MustFixProduction,
        ),
        occurrence_with_kind(
            "b.rs",
            2,
            SeamKind::MockBudget,
            SeamClassification::AcceptableTestOnly,
        ),
        occurrence_with_kind(
            "c.rs",
            3,
            SeamKind::SeedDerivedTraceId,
            SeamClassification::FalsePositive,
        ),
        occurrence_with_kind(
            "d.rs",
            4,
            SeamKind::HardcodedBudget,
            SeamClassification::MustFixProduction,
        ),
        occurrence_with_kind(
            "e.rs",
            5,
            SeamKind::UnguardedMockModule,
            SeamClassification::MustFixProduction,
        ),
    ];
    let inv = MockInventory::build(occs, vec![]);
    assert_eq!(inv.summary.by_kind.len(), 5);
    assert_eq!(*inv.summary.by_kind.get("MockCx").unwrap(), 1);
    assert_eq!(*inv.summary.by_kind.get("MockBudget").unwrap(), 1);
    assert_eq!(*inv.summary.by_kind.get("trace_id_from_seed").unwrap(), 1);
    assert_eq!(*inv.summary.by_kind.get("hardcoded_budget").unwrap(), 1);
    assert_eq!(
        *inv.summary.by_kind.get("unguarded_mock_module").unwrap(),
        1
    );
}

// ---------------------------------------------------------------------------
// Remediation ordering
// ---------------------------------------------------------------------------

#[test]
fn remediation_ordering() {
    assert!(RemediationStrategy::MoveToTestOnly < RemediationStrategy::ThreadRealContext);
    assert!(RemediationStrategy::ThreadRealContext < RemediationStrategy::PropagateBudget);
    assert!(RemediationStrategy::PropagateBudget < RemediationStrategy::AddCfgTestGuard);
    assert!(RemediationStrategy::AddCfgTestGuard < RemediationStrategy::NoAction);
}

// ---------------------------------------------------------------------------
// SeamKind ordering
// ---------------------------------------------------------------------------

#[test]
fn seam_kind_ordering() {
    assert!(SeamKind::MockContext < SeamKind::MockBudget);
    assert!(SeamKind::MockBudget < SeamKind::MockDecisionContract);
}
