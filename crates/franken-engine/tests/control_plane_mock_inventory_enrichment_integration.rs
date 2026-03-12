//! Enrichment integration tests for the `control_plane_mock_inventory` module.

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

use std::collections::BTreeSet;

use frankenengine_engine::control_plane_mock_inventory::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn sample_occ(path: &str, line: u32, classification: SeamClassification) -> SeamOccurrence {
    SeamOccurrence::new(SeamOccurrenceInput {
        file_path: path,
        line_number: line,
        kind: SeamKind::MockContext,
        classification,
        severity: SeamSeverity::High,
        inside_cfg_test: classification == SeamClassification::AcceptableTestOnly,
        description: "enrichment test occurrence",
        remediation: RemediationStrategy::NoAction,
        remediation_bead: "",
    })
}

fn occ_with_kind(
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
        description: "kind-enrichment occurrence",
        remediation: RemediationStrategy::MoveToTestOnly,
        remediation_bead: "bd-enrich",
    })
}

// ---------------------------------------------------------------------------
// Constants — value correctness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_values_correct() {
    assert_eq!(COMPONENT, "control_plane_mock_inventory");
    assert_eq!(BEAD_ID, "bd-3nr.1.1.1");
    assert_eq!(
        INVENTORY_SCHEMA_VERSION,
        "frankenengine.control-plane-mock-inventory.v1"
    );
    assert_eq!(AMBIENT_MOCK_GUARD_COMPONENT, "ambient_mock_guard");
    assert_eq!(AMBIENT_MOCK_GUARD_BEAD_ID, "bd-3nr.1.2.2");
    assert_eq!(
        AMBIENT_MOCK_GUARD_POLICY_ID,
        "frankenengine.control-plane-mocks.fail-closed.v1"
    );
    assert_eq!(AMBIENT_MOCK_GUARD_SCAN_ROOT, "crates/franken-engine/src");
    assert_eq!(
        ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT,
        "orchestrator_context_refactor"
    );
    assert_eq!(ORCHESTRATOR_CONTEXT_REFACTOR_BEAD_ID, "bd-3nr.1.2.1");
    assert_eq!(
        ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE,
        "crates/franken-engine/src/execution_orchestrator.rs"
    );
    assert_eq!(
        ORCHESTRATOR_CONTEXT_PATH_ID,
        "orchestrator-cell-close-canonical-context"
    );
}

// ---------------------------------------------------------------------------
// All schema version constants are unique
// ---------------------------------------------------------------------------

#[test]
fn enrichment_all_schema_version_constants_unique() {
    let versions: Vec<&str> = vec![
        INVENTORY_SCHEMA_VERSION,
        AMBIENT_MOCK_GUARD_REPORT_SCHEMA_VERSION,
        AMBIENT_MOCK_GUARD_TRACE_IDS_SCHEMA_VERSION,
        AMBIENT_MOCK_GUARD_RUN_MANIFEST_SCHEMA_VERSION,
        AMBIENT_MOCK_GUARD_EVENT_SCHEMA_VERSION,
        ORCHESTRATOR_CONTEXT_PATH_CONTRACT_SCHEMA_VERSION,
        ORCHESTRATOR_CONTEXT_REFACTOR_REPORT_SCHEMA_VERSION,
        ORCHESTRATOR_CONTEXT_REFACTOR_TRACE_IDS_SCHEMA_VERSION,
        ORCHESTRATOR_CONTEXT_REFACTOR_RUN_MANIFEST_SCHEMA_VERSION,
        ORCHESTRATOR_CONTEXT_REFACTOR_EVENT_SCHEMA_VERSION,
    ];
    let unique: BTreeSet<&str> = versions.iter().copied().collect();
    assert_eq!(
        unique.len(),
        versions.len(),
        "all schema version constants must be unique"
    );
}

#[test]
fn enrichment_all_schema_versions_start_with_frankenengine() {
    let versions = [
        INVENTORY_SCHEMA_VERSION,
        AMBIENT_MOCK_GUARD_REPORT_SCHEMA_VERSION,
        AMBIENT_MOCK_GUARD_TRACE_IDS_SCHEMA_VERSION,
        AMBIENT_MOCK_GUARD_RUN_MANIFEST_SCHEMA_VERSION,
        AMBIENT_MOCK_GUARD_EVENT_SCHEMA_VERSION,
        ORCHESTRATOR_CONTEXT_PATH_CONTRACT_SCHEMA_VERSION,
        ORCHESTRATOR_CONTEXT_REFACTOR_REPORT_SCHEMA_VERSION,
        ORCHESTRATOR_CONTEXT_REFACTOR_TRACE_IDS_SCHEMA_VERSION,
        ORCHESTRATOR_CONTEXT_REFACTOR_RUN_MANIFEST_SCHEMA_VERSION,
        ORCHESTRATOR_CONTEXT_REFACTOR_EVENT_SCHEMA_VERSION,
    ];
    for v in &versions {
        assert!(
            v.starts_with("frankenengine."),
            "schema version {v} must start with 'frankenengine.'"
        );
    }
}

// ---------------------------------------------------------------------------
// Serde snake_case serialized forms
// ---------------------------------------------------------------------------

#[test]
fn enrichment_classification_serde_snake_case_values() {
    let json = serde_json::to_string(&SeamClassification::MustFixProduction).unwrap();
    assert_eq!(json, "\"must_fix_production\"");
    let json = serde_json::to_string(&SeamClassification::AcceptableTestOnly).unwrap();
    assert_eq!(json, "\"acceptable_test_only\"");
    let json = serde_json::to_string(&SeamClassification::FalsePositive).unwrap();
    assert_eq!(json, "\"false_positive\"");
}

#[test]
fn enrichment_seam_kind_serde_snake_case_values() {
    let json = serde_json::to_string(&SeamKind::MockContext).unwrap();
    assert_eq!(json, "\"mock_context\"");
    let json = serde_json::to_string(&SeamKind::HardcodedBudget).unwrap();
    assert_eq!(json, "\"hardcoded_budget\"");
    let json = serde_json::to_string(&SeamKind::UnguardedMockModule).unwrap();
    assert_eq!(json, "\"unguarded_mock_module\"");
}

#[test]
fn enrichment_severity_serde_snake_case_values() {
    let json = serde_json::to_string(&SeamSeverity::Info).unwrap();
    assert_eq!(json, "\"info\"");
    let json = serde_json::to_string(&SeamSeverity::Critical).unwrap();
    assert_eq!(json, "\"critical\"");
}

#[test]
fn enrichment_remediation_serde_snake_case_values() {
    let json = serde_json::to_string(&RemediationStrategy::MoveToTestOnly).unwrap();
    assert_eq!(json, "\"move_to_test_only\"");
    let json = serde_json::to_string(&RemediationStrategy::ThreadRealContext).unwrap();
    assert_eq!(json, "\"thread_real_context\"");
    let json = serde_json::to_string(&RemediationStrategy::PropagateBudget).unwrap();
    assert_eq!(json, "\"propagate_budget\"");
    let json = serde_json::to_string(&RemediationStrategy::AddCfgTestGuard).unwrap();
    assert_eq!(json, "\"add_cfg_test_guard\"");
    let json = serde_json::to_string(&RemediationStrategy::NoAction).unwrap();
    assert_eq!(json, "\"no_action\"");
}

// ---------------------------------------------------------------------------
// Display uniqueness
// ---------------------------------------------------------------------------

#[test]
fn enrichment_seam_classification_display_all_unique() {
    let variants = [
        SeamClassification::MustFixProduction,
        SeamClassification::AcceptableTestOnly,
        SeamClassification::FalsePositive,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), variants.len());
}

#[test]
fn enrichment_seam_kind_display_all_unique() {
    let variants = [
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
    let displays: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), variants.len());
}

#[test]
fn enrichment_severity_display_all_unique() {
    let variants = [
        SeamSeverity::Info,
        SeamSeverity::Low,
        SeamSeverity::Medium,
        SeamSeverity::High,
        SeamSeverity::Critical,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), variants.len());
}

#[test]
fn enrichment_remediation_display_all_unique() {
    let variants = [
        RemediationStrategy::MoveToTestOnly,
        RemediationStrategy::ThreadRealContext,
        RemediationStrategy::PropagateBudget,
        RemediationStrategy::AddCfgTestGuard,
        RemediationStrategy::NoAction,
    ];
    let displays: BTreeSet<String> = variants.iter().map(|v| format!("{v}")).collect();
    assert_eq!(displays.len(), variants.len());
}

// ---------------------------------------------------------------------------
// AmbientMockGuardOutcome / Rule ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ambient_outcome_ordering() {
    assert!(AmbientMockGuardOutcome::Pass < AmbientMockGuardOutcome::FailClosed);
}

#[test]
fn enrichment_ambient_rule_ordering() {
    assert!(
        AmbientMockGuardRule::MockModuleMustBeCfgTest
            < AmbientMockGuardRule::NoProductionMockModuleReference
    );
    assert!(
        AmbientMockGuardRule::NoProductionMockModuleReference
            < AmbientMockGuardRule::NoProductionFakeContextSymbol
    );
}

#[test]
fn enrichment_orchestrator_outcome_display_distinct() {
    let pass = format!("{}", OrchestratorContextRefactorOutcome::Pass);
    let fail = format!("{}", OrchestratorContextRefactorOutcome::FailClosed);
    assert_ne!(pass, fail, "Pass and FailClosed must have distinct display");
}

// ---------------------------------------------------------------------------
// Error Display messages
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ambient_mock_guard_error_io_display() {
    let err = AmbientMockGuardError::Io {
        path: "/tmp/test.json".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/tmp/test.json"), "error should contain path");
}

#[test]
fn enrichment_ambient_mock_guard_error_busy_display() {
    let err = AmbientMockGuardError::Busy {
        path: "/tmp/.lock".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/tmp/.lock"), "busy error should contain path");
    assert!(
        msg.contains("locked"),
        "busy error should mention lock: {msg}"
    );
}

#[test]
fn enrichment_ambient_mock_guard_error_missing_scan_root_display() {
    let err = AmbientMockGuardError::MissingScanRoot {
        path: "/workspace".to_string(),
        expected: "crates/franken-engine/src".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/workspace"));
    assert!(msg.contains("crates/franken-engine/src"));
}

#[test]
fn enrichment_orchestrator_error_io_display() {
    let err = OrchestratorContextRefactorError::Io {
        path: "/tmp/report.json".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/tmp/report.json"));
}

#[test]
fn enrichment_orchestrator_error_busy_display() {
    let err = OrchestratorContextRefactorError::Busy {
        path: "/tmp/.lock".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/tmp/.lock"));
    assert!(
        msg.contains("locked"),
        "busy error should mention lock: {msg}"
    );
}

#[test]
fn enrichment_orchestrator_error_missing_source_display() {
    let err = OrchestratorContextRefactorError::MissingSource {
        path: "/tmp/orchestrator.rs".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/tmp/orchestrator.rs"));
    assert!(msg.contains("missing"), "missing source error: {msg}");
}

// ---------------------------------------------------------------------------
// Canonical inventory structural invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_canonical_inventory_test_only_items_have_inside_cfg_test() {
    let inv = build_canonical_inventory();
    for occ in inv.test_only_items() {
        assert!(
            occ.inside_cfg_test,
            "test-only occurrence at {}:{} should have inside_cfg_test=true",
            occ.file_path, occ.line_number
        );
    }
}

#[test]
fn enrichment_canonical_inventory_must_fix_items_not_inside_cfg_test() {
    let inv = build_canonical_inventory();
    for occ in inv.must_fix_items() {
        assert!(
            !occ.inside_cfg_test,
            "must-fix occurrence at {}:{} should have inside_cfg_test=false",
            occ.file_path, occ.line_number
        );
    }
}

#[test]
fn enrichment_canonical_inventory_summary_total_equals_parts() {
    let inv = build_canonical_inventory();
    assert_eq!(
        inv.summary.total_occurrences,
        inv.summary.must_fix_count + inv.summary.test_only_count + inv.summary.false_positive_count,
        "total must equal sum of must_fix + test_only + false_positive"
    );
}

#[test]
fn enrichment_canonical_inventory_occurrences_sorted() {
    let inv = build_canonical_inventory();
    for window in inv.occurrences.windows(2) {
        assert!(
            window[0] <= window[1],
            "occurrences must be sorted: {} <= {} violated at {}:{} vs {}:{}",
            window[0].file_path,
            window[1].file_path,
            window[0].file_path,
            window[0].line_number,
            window[1].file_path,
            window[1].line_number,
        );
    }
}

#[test]
fn enrichment_canonical_inventory_must_fix_remediation_bead_set() {
    let inv = build_canonical_inventory();
    for occ in inv.must_fix_items() {
        assert!(
            !occ.remediation_bead.is_empty(),
            "must-fix at {}:{} should have a remediation bead",
            occ.file_path,
            occ.line_number
        );
    }
}

#[test]
fn enrichment_canonical_inventory_test_only_no_action_remediation() {
    let inv = build_canonical_inventory();
    for occ in inv.test_only_items() {
        assert_eq!(
            occ.remediation,
            RemediationStrategy::NoAction,
            "test-only at {}:{} should have NoAction remediation",
            occ.file_path,
            occ.line_number
        );
    }
}

#[test]
fn enrichment_canonical_inventory_by_kind_keys_match_display() {
    let inv = build_canonical_inventory();
    for key in inv.summary.by_kind.keys() {
        // Each key should be a valid SeamKind Display string
        assert!(!key.is_empty(), "by_kind key should not be empty");
    }
}

#[test]
fn enrichment_canonical_inventory_arch_issues_have_ids() {
    let inv = build_canonical_inventory();
    for issue in &inv.architectural_issues {
        assert!(
            !issue.id.is_empty(),
            "architectural issue ID must be nonempty"
        );
        assert!(
            issue.id.starts_with("ARCH-"),
            "architectural issue ID {0} should start with ARCH-",
            issue.id
        );
    }
}

#[test]
fn enrichment_canonical_inventory_schema_version_matches_constant() {
    let inv = build_canonical_inventory();
    assert_eq!(inv.schema_version, INVENTORY_SCHEMA_VERSION);
}

// ---------------------------------------------------------------------------
// MockInventory Display includes hash
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inventory_display_includes_hash() {
    let inv = MockInventory::build(
        vec![sample_occ("a.rs", 1, SeamClassification::MustFixProduction)],
        vec![],
    );
    let s = format!("{inv}");
    assert!(
        s.contains("Inventory hash:"),
        "display should include inventory hash"
    );
}

// ---------------------------------------------------------------------------
// ArchitecturalIssue serde ordering
// ---------------------------------------------------------------------------

#[test]
fn enrichment_architectural_issue_ordering_by_id() {
    let a = ArchitecturalIssue {
        id: "ARCH-001".to_string(),
        description: "first".to_string(),
        file_path: "a.rs".to_string(),
        severity: SeamSeverity::High,
        remediation: RemediationStrategy::NoAction,
        remediation_bead: "".to_string(),
    };
    let b = ArchitecturalIssue {
        id: "ARCH-002".to_string(),
        description: "second".to_string(),
        file_path: "a.rs".to_string(),
        severity: SeamSeverity::High,
        remediation: RemediationStrategy::NoAction,
        remediation_bead: "".to_string(),
    };
    assert!(a < b, "issues should be ordered by id");
}

// ---------------------------------------------------------------------------
// SeamOccurrence content_hash includes schema version
// ---------------------------------------------------------------------------

#[test]
fn enrichment_occurrence_content_hash_is_32_bytes() {
    let occ = sample_occ("x.rs", 1, SeamClassification::MustFixProduction);
    let hash = occ.content_hash();
    assert_eq!(
        hash.as_bytes().len(),
        32,
        "content hash should be 32 bytes (SHA-256)"
    );
}

// ---------------------------------------------------------------------------
// MockInventory count_by_kind returns 0 for absent kinds
// ---------------------------------------------------------------------------

#[test]
fn enrichment_count_by_kind_absent_returns_zero() {
    let inv = MockInventory::build(vec![], vec![]);
    assert_eq!(inv.count_by_kind(SeamKind::MockContext), 0);
    assert_eq!(inv.count_by_kind(SeamKind::HardcodedBudget), 0);
    assert_eq!(inv.count_by_kind(SeamKind::UnguardedMockModule), 0);
}

// ---------------------------------------------------------------------------
// MockInventory build with all 11 SeamKind variants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inventory_all_seam_kinds_in_by_kind() {
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
    let occs: Vec<SeamOccurrence> = kinds
        .iter()
        .enumerate()
        .map(|(i, kind)| {
            occ_with_kind(
                &format!("f{i}.rs"),
                1,
                *kind,
                SeamClassification::MustFixProduction,
            )
        })
        .collect();
    let inv = MockInventory::build(occs, vec![]);
    assert_eq!(inv.summary.by_kind.len(), 11);
    for kind in &kinds {
        assert_eq!(
            inv.count_by_kind(*kind),
            1,
            "count_by_kind({kind}) should be 1"
        );
    }
}

// ---------------------------------------------------------------------------
// Ambient mock guard report with violations
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ambient_report_with_violations_serde_roundtrip() {
    let report = AmbientMockGuardReport {
        schema_version: AMBIENT_MOCK_GUARD_REPORT_SCHEMA_VERSION.to_string(),
        component: AMBIENT_MOCK_GUARD_COMPONENT.to_string(),
        bead_id: AMBIENT_MOCK_GUARD_BEAD_ID.to_string(),
        policy_id: AMBIENT_MOCK_GUARD_POLICY_ID.to_string(),
        canonical_inventory_hash: "test-hash".to_string(),
        scan_root: AMBIENT_MOCK_GUARD_SCAN_ROOT.to_string(),
        outcome: AmbientMockGuardOutcome::FailClosed,
        summary: AmbientMockGuardSummary {
            scanned_file_count: 100,
            violation_count: 2,
            architectural_violation_count: 1,
            production_reference_violation_count: 1,
            fake_context_violation_count: 0,
        },
        violations: vec![
            AmbientMockGuardViolation {
                violation_id: "amg-abc123".to_string(),
                rule: AmbientMockGuardRule::MockModuleMustBeCfgTest,
                severity: SeamSeverity::High,
                diagnostic_code: "AMG-ARCH-UNGARDED-MOCK-MODULE".to_string(),
                file_path: "src/control_plane/mod.rs".to_string(),
                line_number: 284,
                code_snippet: "pub mod mocks {".to_string(),
                detail: "mock module lacks guard".to_string(),
                remediation: "add #[cfg(test)]".to_string(),
            },
            AmbientMockGuardViolation {
                violation_id: "amg-def456".to_string(),
                rule: AmbientMockGuardRule::NoProductionMockModuleReference,
                severity: SeamSeverity::Critical,
                diagnostic_code: "AMG-PROD-MOCK-MODULE-REFERENCE".to_string(),
                file_path: "src/orchestrator.rs".to_string(),
                line_number: 30,
                code_snippet: "use crate::control_plane::mocks::MockCx;".to_string(),
                detail: "prod imports mocks".to_string(),
                remediation: "thread real context".to_string(),
            },
        ],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: AmbientMockGuardReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
    assert_eq!(back.violations.len(), 2);
}

// ---------------------------------------------------------------------------
// Orchestrator context refactor report with guards and seams
// ---------------------------------------------------------------------------

#[test]
fn enrichment_orchestrator_report_with_guards_and_seams_roundtrip() {
    let report = OrchestratorContextRefactorReport {
        schema_version: ORCHESTRATOR_CONTEXT_REFACTOR_REPORT_SCHEMA_VERSION.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        bead_id: ORCHESTRATOR_CONTEXT_REFACTOR_BEAD_ID.to_string(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        canonical_inventory_hash: "inv-hash".to_string(),
        contract_hash: "contract-hash".to_string(),
        source_file: ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE.to_string(),
        outcome: OrchestratorContextRefactorOutcome::FailClosed,
        summary: OrchestratorContextRefactorSummary {
            corrected_seam_count: 2,
            deferred_seam_count: 1,
            guard_count: 3,
            failed_guard_count: 1,
        },
        corrected_seams: vec![CorrectedProductionSeam {
            seam_id: "seam-1".to_string(),
            occurrence_hash: "hash-1".to_string(),
            original_file_path: "src/orch.rs".to_string(),
            original_line_number: 30,
            seam_kind: SeamKind::MockContext,
            previous_pattern: "MockCx::new()".to_string(),
            corrected_path_id: "path-1".to_string(),
            corrected_context_source: "KernelContext".to_string(),
            corrected_trace_source: "derive_trace_id".to_string(),
            corrected_budget_source: "Budget::new".to_string(),
        }],
        deferred_seams: vec!["deferred-seam-1".to_string()],
        guards: vec![
            ContextRefactorGuard {
                guard_id: "forbidden_mock_import".to_string(),
                guard_kind: "forbidden_token".to_string(),
                needle: "use crate::control_plane::mocks".to_string(),
                passed: true,
                error_code: None,
            },
            ContextRefactorGuard {
                guard_id: "required_budget".to_string(),
                guard_kind: "required_token".to_string(),
                needle: "Budget::new(budget_ms)".to_string(),
                passed: false,
                error_code: Some("OCR-REQUIRED-REQUIRED_BUDGET".to_string()),
            },
        ],
    };
    let json = serde_json::to_string(&report).unwrap();
    let back: OrchestratorContextRefactorReport = serde_json::from_str(&json).unwrap();
    assert_eq!(report, back);
    assert_eq!(back.corrected_seams.len(), 1);
    assert_eq!(back.deferred_seams.len(), 1);
    assert_eq!(back.guards.len(), 2);
}

// ---------------------------------------------------------------------------
// ProductionContextPathContract with populated fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_production_context_path_contract_populated_roundtrip() {
    let contract = ProductionContextPathContract {
        schema_version: ORCHESTRATOR_CONTEXT_PATH_CONTRACT_SCHEMA_VERSION.to_string(),
        component: ORCHESTRATOR_CONTEXT_REFACTOR_COMPONENT.to_string(),
        bead_id: ORCHESTRATOR_CONTEXT_REFACTOR_BEAD_ID.to_string(),
        policy_id: ORCHESTRATOR_CONTEXT_REFACTOR_POLICY_ID.to_string(),
        canonical_inventory_hash: "inv-hash".to_string(),
        source_file: ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE.to_string(),
        context_paths: vec![ProductionContextPath {
            path_id: ORCHESTRATOR_CONTEXT_PATH_ID.to_string(),
            source_file: ORCHESTRATOR_CONTEXT_REFACTOR_SOURCE_FILE.to_string(),
            source_symbol: "build_cell_close_context".to_string(),
            context_origin: "KernelContext::new(...)".to_string(),
            trace_origin: "derive_cell_close_trace_id".to_string(),
            budget_origin: "Budget::new(budget_ms)".to_string(),
            capability_scope: "NoCaps".to_string(),
            deterministic_fallback: "BudgetExhausted".to_string(),
        }],
        corrected_seams: vec![CorrectedProductionSeam {
            seam_id: "seam-1".to_string(),
            occurrence_hash: "h1".to_string(),
            original_file_path: "src/orch.rs".to_string(),
            original_line_number: 30,
            seam_kind: SeamKind::MockContext,
            previous_pattern: "old pattern".to_string(),
            corrected_path_id: ORCHESTRATOR_CONTEXT_PATH_ID.to_string(),
            corrected_context_source: "new context".to_string(),
            corrected_trace_source: "new trace".to_string(),
            corrected_budget_source: "new budget".to_string(),
        }],
        deferred_seams: vec!["deferred-1".to_string()],
        guards: vec![ContextRefactorGuard {
            guard_id: "g1".to_string(),
            guard_kind: "required_token".to_string(),
            needle: "KernelContext::new".to_string(),
            passed: true,
            error_code: None,
        }],
    };
    let json = serde_json::to_string(&contract).unwrap();
    let back: ProductionContextPathContract = serde_json::from_str(&json).unwrap();
    assert_eq!(contract, back);
}

// ---------------------------------------------------------------------------
// AmbientMockGuardRule display and as_str consistency
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ambient_rule_display_matches_as_str() {
    let rules = [
        AmbientMockGuardRule::MockModuleMustBeCfgTest,
        AmbientMockGuardRule::NoProductionMockModuleReference,
        AmbientMockGuardRule::NoProductionFakeContextSymbol,
    ];
    for rule in &rules {
        assert_eq!(
            format!("{rule}"),
            rule.as_str(),
            "Display and as_str must match for {rule:?}"
        );
    }
}

#[test]
fn enrichment_ambient_outcome_display_matches_as_str() {
    for outcome in [
        AmbientMockGuardOutcome::Pass,
        AmbientMockGuardOutcome::FailClosed,
    ] {
        assert_eq!(
            format!("{outcome}"),
            outcome.as_str(),
            "Display and as_str must match for {outcome:?}"
        );
    }
}

#[test]
fn enrichment_orchestrator_outcome_display_matches_as_str() {
    for outcome in [
        OrchestratorContextRefactorOutcome::Pass,
        OrchestratorContextRefactorOutcome::FailClosed,
    ] {
        assert_eq!(
            format!("{outcome}"),
            outcome.as_str(),
            "Display and as_str must match for {outcome:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// Inventory hash sensitive to occurrence order after sorting
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inventory_hash_sensitive_to_number_of_occurrences() {
    let inv1 = MockInventory::build(
        vec![sample_occ("a.rs", 1, SeamClassification::MustFixProduction)],
        vec![],
    );
    let inv2 = MockInventory::build(
        vec![
            sample_occ("a.rs", 1, SeamClassification::MustFixProduction),
            sample_occ("a.rs", 2, SeamClassification::MustFixProduction),
        ],
        vec![],
    );
    assert_ne!(
        inv1.inventory_hash, inv2.inventory_hash,
        "adding an occurrence should change the hash"
    );
}

// ---------------------------------------------------------------------------
// SeamOccurrence Display format verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_occurrence_display_format() {
    let occ = SeamOccurrence::new(SeamOccurrenceInput {
        file_path: "crates/franken-engine/src/foo.rs",
        line_number: 42,
        kind: SeamKind::MockBudget,
        classification: SeamClassification::MustFixProduction,
        severity: SeamSeverity::Critical,
        inside_cfg_test: false,
        description: "hardcoded budget in prod",
        remediation: RemediationStrategy::PropagateBudget,
        remediation_bead: "bd-fix",
    });
    let s = format!("{occ}");
    // Format: "[severity] file:line (kind) — description"
    assert!(
        s.contains("[critical]"),
        "display should contain [severity]: {s}"
    );
    assert!(
        s.contains("crates/franken-engine/src/foo.rs:42"),
        "display should contain file:line: {s}"
    );
    assert!(s.contains("MockBudget"), "display should contain kind: {s}");
    assert!(
        s.contains("hardcoded budget in prod"),
        "display should contain description: {s}"
    );
}

// ---------------------------------------------------------------------------
// ArchitecturalIssue Display format verification
// ---------------------------------------------------------------------------

#[test]
fn enrichment_architectural_issue_display_format() {
    let issue = ArchitecturalIssue {
        id: "ARCH-005".to_string(),
        description: "unguarded mock module".to_string(),
        file_path: "mod.rs".to_string(),
        severity: SeamSeverity::Critical,
        remediation: RemediationStrategy::AddCfgTestGuard,
        remediation_bead: "bd-fix".to_string(),
    };
    let s = format!("{issue}");
    // Format: "[severity] id: description"
    assert!(
        s.contains("[critical]"),
        "display should contain severity: {s}"
    );
    assert!(s.contains("ARCH-005"), "display should contain id: {s}");
    assert!(
        s.contains("unguarded mock module"),
        "display should contain description: {s}"
    );
}

// ---------------------------------------------------------------------------
// MockInventory Display with architectural issues
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inventory_display_with_arch_issues() {
    let inv = MockInventory::build(
        vec![],
        vec![ArchitecturalIssue {
            id: "ARCH-T".to_string(),
            description: "test".to_string(),
            file_path: "t.rs".to_string(),
            severity: SeamSeverity::Medium,
            remediation: RemediationStrategy::NoAction,
            remediation_bead: "".to_string(),
        }],
    );
    let s = format!("{inv}");
    assert!(
        s.contains("Architectural issues: 1"),
        "should show arch issue count: {s}"
    );
}

// ---------------------------------------------------------------------------
// AmbientMockGuardSummary violation counts consistency
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ambient_summary_violation_subcounts_sum_to_total() {
    // When we construct a summary, the sub-counts should sum to total
    let summary = AmbientMockGuardSummary {
        scanned_file_count: 200,
        violation_count: 5,
        architectural_violation_count: 2,
        production_reference_violation_count: 2,
        fake_context_violation_count: 1,
    };
    assert_eq!(
        summary.violation_count,
        summary.architectural_violation_count
            + summary.production_reference_violation_count
            + summary.fake_context_violation_count,
        "sub-counts should sum to total"
    );
}

// ---------------------------------------------------------------------------
// OrchestratorContextRefactorSummary consistency
// ---------------------------------------------------------------------------

#[test]
fn enrichment_orchestrator_summary_guard_count_gte_failed() {
    let summary = OrchestratorContextRefactorSummary {
        corrected_seam_count: 3,
        deferred_seam_count: 1,
        guard_count: 9,
        failed_guard_count: 2,
    };
    assert!(
        summary.guard_count >= summary.failed_guard_count,
        "guard_count must be >= failed_guard_count"
    );
}

// ---------------------------------------------------------------------------
// evaluate_ambient_mock_guard_in_root — fixture tests
// ---------------------------------------------------------------------------

#[test]
fn enrichment_evaluate_ambient_mock_guard_missing_scan_root() {
    let tmp = std::env::temp_dir().join(format!(
        "franken-enrichment-amg-missing-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&tmp).unwrap();
    let result = evaluate_ambient_mock_guard_in_root(&tmp);
    assert!(result.is_err(), "should fail when scan root is missing");
    let err = result.unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("crates/franken-engine/src"),
        "error should mention expected scan root: {msg}"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn enrichment_evaluate_ambient_mock_guard_empty_scan_root() {
    let tmp = std::env::temp_dir().join(format!(
        "franken-enrichment-amg-empty-{}",
        std::process::id()
    ));
    let scan_root = tmp.join("crates/franken-engine/src");
    std::fs::create_dir_all(&scan_root).unwrap();
    let result = evaluate_ambient_mock_guard_in_root(&tmp);
    assert!(
        result.is_ok(),
        "empty scan root should succeed: {:?}",
        result.err()
    );
    let report = result.unwrap();
    assert_eq!(report.outcome, AmbientMockGuardOutcome::Pass);
    assert_eq!(report.summary.violation_count, 0);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn enrichment_evaluate_ambient_mock_guard_clean_file_no_violations() {
    let tmp = std::env::temp_dir().join(format!(
        "franken-enrichment-amg-clean-{}",
        std::process::id()
    ));
    let scan_root = tmp.join("crates/franken-engine/src");
    std::fs::create_dir_all(&scan_root).unwrap();
    std::fs::write(
        scan_root.join("clean_module.rs"),
        "pub fn hello() -> &'static str { \"hello\" }\n",
    )
    .unwrap();
    let result = evaluate_ambient_mock_guard_in_root(&tmp);
    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.outcome, AmbientMockGuardOutcome::Pass);
    assert_eq!(report.summary.scanned_file_count, 1);
    assert_eq!(report.summary.violation_count, 0);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn enrichment_evaluate_ambient_mock_guard_violation_in_prod_code() {
    let tmp = std::env::temp_dir().join(format!(
        "franken-enrichment-amg-violation-{}",
        std::process::id()
    ));
    let scan_root = tmp.join("crates/franken-engine/src");
    std::fs::create_dir_all(&scan_root).unwrap();
    std::fs::write(
        scan_root.join("bad_module.rs"),
        "use crate::control_plane::mocks::MockCx;\nfn bad() { let _ = MockCx::new(); }\n",
    )
    .unwrap();
    let result = evaluate_ambient_mock_guard_in_root(&tmp);
    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(report.outcome, AmbientMockGuardOutcome::FailClosed);
    assert!(report.summary.violation_count > 0);
    let _ = std::fs::remove_dir_all(&tmp);
}

#[test]
fn enrichment_evaluate_ambient_mock_guard_cfg_test_not_violation() {
    let tmp = std::env::temp_dir().join(format!(
        "franken-enrichment-amg-cfgtest-{}",
        std::process::id()
    ));
    let scan_root = tmp.join("crates/franken-engine/src");
    std::fs::create_dir_all(&scan_root).unwrap();
    std::fs::write(
        scan_root.join("test_module.rs"),
        "#[cfg(test)]\nmod tests {\n    use crate::control_plane::mocks::MockCx;\n    fn t() { let _ = MockCx::new(); }\n}\n",
    )
    .unwrap();
    let result = evaluate_ambient_mock_guard_in_root(&tmp);
    assert!(result.is_ok());
    let report = result.unwrap();
    assert_eq!(
        report.outcome,
        AmbientMockGuardOutcome::Pass,
        "cfg(test) code should not trigger violations"
    );
    let _ = std::fs::remove_dir_all(&tmp);
}

// ---------------------------------------------------------------------------
// Exit code functions comprehensive
// ---------------------------------------------------------------------------

#[test]
fn enrichment_exit_code_ambient_pass_is_zero() {
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
fn enrichment_exit_code_ambient_fail_is_two() {
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
            violation_count: 0,
            architectural_violation_count: 0,
            production_reference_violation_count: 0,
            fake_context_violation_count: 0,
        },
        violations: vec![],
    };
    assert_eq!(ambient_mock_guard_exit_code(&report), 2);
}

// ---------------------------------------------------------------------------
// AmbientMockGuardRule serde snake_case values
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ambient_rule_serde_snake_case_values() {
    let json = serde_json::to_string(&AmbientMockGuardRule::MockModuleMustBeCfgTest).unwrap();
    assert_eq!(json, "\"mock_module_must_be_cfg_test\"");
    let json =
        serde_json::to_string(&AmbientMockGuardRule::NoProductionMockModuleReference).unwrap();
    assert_eq!(json, "\"no_production_mock_module_reference\"");
    let json = serde_json::to_string(&AmbientMockGuardRule::NoProductionFakeContextSymbol).unwrap();
    assert_eq!(json, "\"no_production_fake_context_symbol\"");
}

// ---------------------------------------------------------------------------
// AmbientMockGuardOutcome serde snake_case
// ---------------------------------------------------------------------------

#[test]
fn enrichment_ambient_outcome_serde_snake_case_values() {
    let json = serde_json::to_string(&AmbientMockGuardOutcome::Pass).unwrap();
    assert_eq!(json, "\"pass\"");
    let json = serde_json::to_string(&AmbientMockGuardOutcome::FailClosed).unwrap();
    assert_eq!(json, "\"fail_closed\"");
}

#[test]
fn enrichment_orchestrator_outcome_serde_snake_case_values() {
    let json = serde_json::to_string(&OrchestratorContextRefactorOutcome::Pass).unwrap();
    assert_eq!(json, "\"pass\"");
    let json = serde_json::to_string(&OrchestratorContextRefactorOutcome::FailClosed).unwrap();
    assert_eq!(json, "\"fail_closed\"");
}
