//! Integration tests for the `control_plane_mock_inventory` module.

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
