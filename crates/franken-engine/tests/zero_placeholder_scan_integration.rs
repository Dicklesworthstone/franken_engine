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

use frankenengine_engine::zero_placeholder_scan::{
    ZERO_PLACEHOLDER_SCAN_COMPONENT, ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION,
    ZERO_PLACEHOLDER_SCAN_FINDING_COUNT, ZERO_PLACEHOLDER_SCAN_POLICY_ID,
    ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION, ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION,
    ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION, ZeroPlaceholderFinding,
    ZeroPlaceholderInventory, ZeroPlaceholderScanArtifactPaths, ZeroPlaceholderScanEvent,
    ZeroPlaceholderScanRunManifest, ZeroPlaceholderScanTraceIds, ZeroPlaceholderSeverity,
    ZeroPlaceholderStatus, ZeroPlaceholderSubsystem, ZeroPlaceholderSubsystemSummary,
    zero_placeholder_scan_inventory,
};

// ---------------------------------------------------------------------------
// Helper builders
// ---------------------------------------------------------------------------

fn make_finding(
    id: &str,
    subsystem: ZeroPlaceholderSubsystem,
    status: ZeroPlaceholderStatus,
    severity: ZeroPlaceholderSeverity,
) -> ZeroPlaceholderFinding {
    ZeroPlaceholderFinding {
        finding_id: id.to_string(),
        subsystem,
        status,
        severity,
        owner: "test_owner".to_string(),
        owner_bead_id: "bd-test-0".to_string(),
        subject_area: "test.area".to_string(),
        source_reference: "src/test.rs::fn_test".to_string(),
        observed_behavior: "placeholder returned".to_string(),
        required_behavior: "real value returned".to_string(),
        diagnostic_code: None,
    }
}

fn make_inventory(findings: Vec<ZeroPlaceholderFinding>) -> ZeroPlaceholderInventory {
    ZeroPlaceholderInventory {
        schema_version: ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        findings,
    }
}

// ---------------------------------------------------------------------------
// 1. Public constants
// ---------------------------------------------------------------------------

#[test]
fn schema_version_constant_has_expected_prefix() {
    assert!(
        ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.starts_with("franken-engine."),
        "schema version should start with 'franken-engine.'"
    );
}

#[test]
fn schema_version_constant_is_non_empty() {
    assert!(!ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION.is_empty());
}

#[test]
fn trace_ids_schema_version_is_non_empty() {
    assert!(!ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION.is_empty());
}

#[test]
fn run_manifest_schema_version_is_non_empty() {
    assert!(!ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
}

#[test]
fn event_schema_version_is_non_empty() {
    assert!(!ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.is_empty());
}

#[test]
fn component_constant_matches_module_name() {
    assert_eq!(ZERO_PLACEHOLDER_SCAN_COMPONENT, "zero_placeholder_scan");
}

#[test]
fn policy_id_constant_contains_policy_keyword() {
    assert!(
        ZERO_PLACEHOLDER_SCAN_POLICY_ID.contains("policy"),
        "policy ID should contain 'policy'"
    );
}

#[test]
fn finding_count_constant_is_positive() {
    assert!(ZERO_PLACEHOLDER_SCAN_FINDING_COUNT > 0);
}

#[test]
fn finding_count_constant_matches_inventory_length() {
    let inventory = zero_placeholder_scan_inventory();
    assert_eq!(
        inventory.findings.len(),
        ZERO_PLACEHOLDER_SCAN_FINDING_COUNT
    );
}

#[test]
fn all_schema_versions_are_distinct() {
    let versions = [
        ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION,
        ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION,
        ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION,
        ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION,
    ];
    let unique: std::collections::BTreeSet<&&str> = versions.iter().collect();
    assert_eq!(
        unique.len(),
        versions.len(),
        "all schema version strings must be distinct"
    );
}

// ---------------------------------------------------------------------------
// 2. ZeroPlaceholderSubsystem
// ---------------------------------------------------------------------------

#[test]
fn subsystem_all_array_has_four_entries() {
    assert_eq!(ZeroPlaceholderSubsystem::ALL.len(), 4);
}

#[test]
fn subsystem_all_contains_parser() {
    assert!(ZeroPlaceholderSubsystem::ALL.contains(&ZeroPlaceholderSubsystem::Parser));
}

#[test]
fn subsystem_all_contains_lowering() {
    assert!(ZeroPlaceholderSubsystem::ALL.contains(&ZeroPlaceholderSubsystem::Lowering));
}

#[test]
fn subsystem_all_contains_runtime() {
    assert!(ZeroPlaceholderSubsystem::ALL.contains(&ZeroPlaceholderSubsystem::Runtime));
}

#[test]
fn subsystem_all_contains_cli_docs() {
    assert!(ZeroPlaceholderSubsystem::ALL.contains(&ZeroPlaceholderSubsystem::CliDocs));
}

#[test]
fn subsystem_as_str_parser() {
    assert_eq!(ZeroPlaceholderSubsystem::Parser.as_str(), "parser");
}

#[test]
fn subsystem_as_str_lowering() {
    assert_eq!(ZeroPlaceholderSubsystem::Lowering.as_str(), "lowering");
}

#[test]
fn subsystem_as_str_runtime() {
    assert_eq!(ZeroPlaceholderSubsystem::Runtime.as_str(), "runtime");
}

#[test]
fn subsystem_as_str_cli_docs() {
    assert_eq!(ZeroPlaceholderSubsystem::CliDocs.as_str(), "cli_docs");
}

#[test]
fn subsystem_serde_roundtrip_parser() {
    let v = ZeroPlaceholderSubsystem::Parser;
    let json = serde_json::to_string(&v).unwrap();
    let back: ZeroPlaceholderSubsystem = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn subsystem_serde_roundtrip_lowering() {
    let v = ZeroPlaceholderSubsystem::Lowering;
    let json = serde_json::to_string(&v).unwrap();
    let back: ZeroPlaceholderSubsystem = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn subsystem_serde_roundtrip_runtime() {
    let v = ZeroPlaceholderSubsystem::Runtime;
    let json = serde_json::to_string(&v).unwrap();
    let back: ZeroPlaceholderSubsystem = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn subsystem_serde_roundtrip_cli_docs() {
    let v = ZeroPlaceholderSubsystem::CliDocs;
    let json = serde_json::to_string(&v).unwrap();
    let back: ZeroPlaceholderSubsystem = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn subsystem_as_str_values_are_unique() {
    let strs: std::collections::BTreeSet<&str> = ZeroPlaceholderSubsystem::ALL
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert_eq!(strs.len(), ZeroPlaceholderSubsystem::ALL.len());
}

#[test]
fn subsystem_serde_produces_snake_case_json() {
    // CliDocs should serialize as "cli_docs", not "CliDocs"
    let json = serde_json::to_string(&ZeroPlaceholderSubsystem::CliDocs).unwrap();
    assert_eq!(json, "\"cli_docs\"");
}

#[test]
fn subsystem_ordering_is_stable() {
    // ALL is [Parser, Lowering, Runtime, CliDocs]
    assert_eq!(
        ZeroPlaceholderSubsystem::ALL[0],
        ZeroPlaceholderSubsystem::Parser
    );
    assert_eq!(
        ZeroPlaceholderSubsystem::ALL[1],
        ZeroPlaceholderSubsystem::Lowering
    );
    assert_eq!(
        ZeroPlaceholderSubsystem::ALL[2],
        ZeroPlaceholderSubsystem::Runtime
    );
    assert_eq!(
        ZeroPlaceholderSubsystem::ALL[3],
        ZeroPlaceholderSubsystem::CliDocs
    );
}

// ---------------------------------------------------------------------------
// 3. ZeroPlaceholderStatus
// ---------------------------------------------------------------------------

#[test]
fn status_as_str_open_placeholder() {
    assert_eq!(
        ZeroPlaceholderStatus::OpenPlaceholder.as_str(),
        "open_placeholder"
    );
}

#[test]
fn status_as_str_fail_closed() {
    assert_eq!(ZeroPlaceholderStatus::FailClosed.as_str(), "fail_closed");
}

#[test]
fn status_as_str_resolved() {
    assert_eq!(ZeroPlaceholderStatus::Resolved.as_str(), "resolved");
}

#[test]
fn status_serde_roundtrip_open_placeholder() {
    let v = ZeroPlaceholderStatus::OpenPlaceholder;
    let json = serde_json::to_string(&v).unwrap();
    let back: ZeroPlaceholderStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn status_serde_roundtrip_fail_closed() {
    let v = ZeroPlaceholderStatus::FailClosed;
    let json = serde_json::to_string(&v).unwrap();
    let back: ZeroPlaceholderStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn status_serde_roundtrip_resolved() {
    let v = ZeroPlaceholderStatus::Resolved;
    let json = serde_json::to_string(&v).unwrap();
    let back: ZeroPlaceholderStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn status_serde_produces_snake_case_open_placeholder() {
    let json = serde_json::to_string(&ZeroPlaceholderStatus::OpenPlaceholder).unwrap();
    assert_eq!(json, "\"open_placeholder\"");
}

#[test]
fn status_serde_produces_snake_case_fail_closed() {
    let json = serde_json::to_string(&ZeroPlaceholderStatus::FailClosed).unwrap();
    assert_eq!(json, "\"fail_closed\"");
}

// ---------------------------------------------------------------------------
// 4. ZeroPlaceholderSeverity
// ---------------------------------------------------------------------------

#[test]
fn severity_as_str_high() {
    assert_eq!(ZeroPlaceholderSeverity::High.as_str(), "high");
}

#[test]
fn severity_as_str_medium() {
    assert_eq!(ZeroPlaceholderSeverity::Medium.as_str(), "medium");
}

#[test]
fn severity_as_str_low() {
    assert_eq!(ZeroPlaceholderSeverity::Low.as_str(), "low");
}

#[test]
fn severity_serde_roundtrip_high() {
    let v = ZeroPlaceholderSeverity::High;
    let json = serde_json::to_string(&v).unwrap();
    let back: ZeroPlaceholderSeverity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn severity_serde_roundtrip_medium() {
    let v = ZeroPlaceholderSeverity::Medium;
    let json = serde_json::to_string(&v).unwrap();
    let back: ZeroPlaceholderSeverity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

#[test]
fn severity_serde_roundtrip_low() {
    let v = ZeroPlaceholderSeverity::Low;
    let json = serde_json::to_string(&v).unwrap();
    let back: ZeroPlaceholderSeverity = serde_json::from_str(&json).unwrap();
    assert_eq!(back, v);
}

// ---------------------------------------------------------------------------
// 5. ZeroPlaceholderFinding
// ---------------------------------------------------------------------------

#[test]
fn finding_construction_and_field_access() {
    let f = make_finding(
        "runtime::test",
        ZeroPlaceholderSubsystem::Runtime,
        ZeroPlaceholderStatus::OpenPlaceholder,
        ZeroPlaceholderSeverity::High,
    );
    assert_eq!(f.finding_id, "runtime::test");
    assert_eq!(f.subsystem, ZeroPlaceholderSubsystem::Runtime);
    assert_eq!(f.status, ZeroPlaceholderStatus::OpenPlaceholder);
    assert_eq!(f.severity, ZeroPlaceholderSeverity::High);
    assert_eq!(f.owner, "test_owner");
    assert!(f.diagnostic_code.is_none());
}

#[test]
fn finding_serde_roundtrip_with_diagnostic_code() {
    let f = ZeroPlaceholderFinding {
        finding_id: "parser::export_named".to_string(),
        subsystem: ZeroPlaceholderSubsystem::Parser,
        status: ZeroPlaceholderStatus::FailClosed,
        severity: ZeroPlaceholderSeverity::Medium,
        owner: "parser_team".to_string(),
        owner_bead_id: "bd-1lsy.4.7.2".to_string(),
        subject_area: "export_named_clause".to_string(),
        source_reference: "src/parser.rs::parse_export".to_string(),
        observed_behavior: "returns UnsupportedSyntax".to_string(),
        required_behavior: "parses fully".to_string(),
        diagnostic_code: Some("FE-PARSE-0042".to_string()),
    };
    let json = serde_json::to_string(&f).unwrap();
    let back: ZeroPlaceholderFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back, f);
    assert_eq!(back.diagnostic_code, Some("FE-PARSE-0042".to_string()));
}

#[test]
fn finding_serde_roundtrip_without_diagnostic_code() {
    let f = make_finding(
        "runtime::json_parse",
        ZeroPlaceholderSubsystem::Runtime,
        ZeroPlaceholderStatus::OpenPlaceholder,
        ZeroPlaceholderSeverity::High,
    );
    let json = serde_json::to_string(&f).unwrap();
    let back: ZeroPlaceholderFinding = serde_json::from_str(&json).unwrap();
    assert_eq!(back, f);
    assert!(back.diagnostic_code.is_none());
}

#[test]
fn finding_none_diagnostic_code_skipped_in_serialization() {
    let f = make_finding(
        "runtime::no_diag",
        ZeroPlaceholderSubsystem::Runtime,
        ZeroPlaceholderStatus::OpenPlaceholder,
        ZeroPlaceholderSeverity::High,
    );
    let json = serde_json::to_string(&f).unwrap();
    assert!(
        !json.contains("diagnostic_code"),
        "None diagnostic_code should be absent from JSON"
    );
}

#[test]
fn finding_clone_equality() {
    let f = make_finding(
        "lowering::for_in",
        ZeroPlaceholderSubsystem::Lowering,
        ZeroPlaceholderStatus::Resolved,
        ZeroPlaceholderSeverity::Low,
    );
    let cloned = f.clone();
    assert_eq!(f, cloned);
}

// ---------------------------------------------------------------------------
// 6. ZeroPlaceholderInventory counting methods
// ---------------------------------------------------------------------------

#[test]
fn empty_inventory_counts_are_zero() {
    let inv = make_inventory(vec![]);
    assert_eq!(inv.open_placeholder_finding_count(), 0);
    assert_eq!(inv.fail_closed_finding_count(), 0);
    assert_eq!(inv.resolved_finding_count(), 0);
}

#[test]
fn inventory_counts_open_placeholders_correctly() {
    let findings = vec![
        make_finding(
            "a",
            ZeroPlaceholderSubsystem::Parser,
            ZeroPlaceholderStatus::OpenPlaceholder,
            ZeroPlaceholderSeverity::High,
        ),
        make_finding(
            "b",
            ZeroPlaceholderSubsystem::Runtime,
            ZeroPlaceholderStatus::OpenPlaceholder,
            ZeroPlaceholderSeverity::High,
        ),
        make_finding(
            "c",
            ZeroPlaceholderSubsystem::Lowering,
            ZeroPlaceholderStatus::Resolved,
            ZeroPlaceholderSeverity::Low,
        ),
    ];
    let inv = make_inventory(findings);
    assert_eq!(inv.open_placeholder_finding_count(), 2);
    assert_eq!(inv.fail_closed_finding_count(), 0);
    assert_eq!(inv.resolved_finding_count(), 1);
}

#[test]
fn inventory_counts_fail_closed_correctly() {
    let findings = vec![
        make_finding(
            "a",
            ZeroPlaceholderSubsystem::Parser,
            ZeroPlaceholderStatus::FailClosed,
            ZeroPlaceholderSeverity::Medium,
        ),
        make_finding(
            "b",
            ZeroPlaceholderSubsystem::Lowering,
            ZeroPlaceholderStatus::FailClosed,
            ZeroPlaceholderSeverity::Medium,
        ),
        make_finding(
            "c",
            ZeroPlaceholderSubsystem::CliDocs,
            ZeroPlaceholderStatus::Resolved,
            ZeroPlaceholderSeverity::Low,
        ),
    ];
    let inv = make_inventory(findings);
    assert_eq!(inv.open_placeholder_finding_count(), 0);
    assert_eq!(inv.fail_closed_finding_count(), 2);
    assert_eq!(inv.resolved_finding_count(), 1);
}

#[test]
fn inventory_counts_resolved_correctly() {
    let findings = vec![
        make_finding(
            "x",
            ZeroPlaceholderSubsystem::Parser,
            ZeroPlaceholderStatus::Resolved,
            ZeroPlaceholderSeverity::Low,
        ),
        make_finding(
            "y",
            ZeroPlaceholderSubsystem::Lowering,
            ZeroPlaceholderStatus::Resolved,
            ZeroPlaceholderSeverity::Low,
        ),
        make_finding(
            "z",
            ZeroPlaceholderSubsystem::Runtime,
            ZeroPlaceholderStatus::Resolved,
            ZeroPlaceholderSeverity::Low,
        ),
    ];
    let inv = make_inventory(findings);
    assert_eq!(inv.resolved_finding_count(), 3);
    assert_eq!(inv.open_placeholder_finding_count(), 0);
    assert_eq!(inv.fail_closed_finding_count(), 0);
}

#[test]
fn inventory_count_sum_equals_findings_len() {
    let inv = zero_placeholder_scan_inventory();
    let sum = inv.open_placeholder_finding_count()
        + inv.fail_closed_finding_count()
        + inv.resolved_finding_count();
    assert_eq!(sum, inv.findings.len());
}

#[test]
fn inventory_subsystem_summaries_returns_all_four_subsystems() {
    let inv = make_inventory(vec![]);
    let summaries = inv.subsystem_summaries();
    assert_eq!(summaries.len(), 4);
}

#[test]
fn inventory_subsystem_summaries_cover_every_subsystem_variant() {
    let inv = make_inventory(vec![]);
    let summaries = inv.subsystem_summaries();
    let subsystems: std::collections::BTreeSet<_> = summaries.iter().map(|s| s.subsystem).collect();
    for variant in ZeroPlaceholderSubsystem::ALL {
        assert!(subsystems.contains(&variant));
    }
}

#[test]
fn inventory_subsystem_summaries_counts_add_up_per_subsystem() {
    let findings = vec![
        make_finding(
            "p1",
            ZeroPlaceholderSubsystem::Parser,
            ZeroPlaceholderStatus::OpenPlaceholder,
            ZeroPlaceholderSeverity::High,
        ),
        make_finding(
            "p2",
            ZeroPlaceholderSubsystem::Parser,
            ZeroPlaceholderStatus::FailClosed,
            ZeroPlaceholderSeverity::Medium,
        ),
        make_finding(
            "l1",
            ZeroPlaceholderSubsystem::Lowering,
            ZeroPlaceholderStatus::Resolved,
            ZeroPlaceholderSeverity::Low,
        ),
    ];
    let inv = make_inventory(findings);
    let summaries = inv.subsystem_summaries();

    let parser_summary = summaries
        .iter()
        .find(|s| s.subsystem == ZeroPlaceholderSubsystem::Parser)
        .unwrap();
    assert_eq!(parser_summary.finding_count, 2);
    assert_eq!(parser_summary.open_placeholder_finding_count, 1);
    assert_eq!(parser_summary.fail_closed_finding_count, 1);
    assert_eq!(parser_summary.resolved_finding_count, 0);

    let lowering_summary = summaries
        .iter()
        .find(|s| s.subsystem == ZeroPlaceholderSubsystem::Lowering)
        .unwrap();
    assert_eq!(lowering_summary.finding_count, 1);
    assert_eq!(lowering_summary.resolved_finding_count, 1);
}

#[test]
fn inventory_subsystem_summaries_total_equals_findings_len() {
    let inv = zero_placeholder_scan_inventory();
    let summaries = inv.subsystem_summaries();
    let total: u64 = summaries.iter().map(|s| s.finding_count).sum();
    assert_eq!(total as usize, inv.findings.len());
}

#[test]
fn inventory_subsystem_summary_internal_counts_consistent() {
    let inv = zero_placeholder_scan_inventory();
    for summary in inv.subsystem_summaries() {
        assert_eq!(
            summary.finding_count,
            summary.open_placeholder_finding_count
                + summary.fail_closed_finding_count
                + summary.resolved_finding_count,
            "subsystem {:?}: internal count mismatch",
            summary.subsystem
        );
    }
}

// ---------------------------------------------------------------------------
// 7. zero_placeholder_scan_inventory() function
// ---------------------------------------------------------------------------

#[test]
fn scan_inventory_returns_correct_total_finding_count() {
    let inv = zero_placeholder_scan_inventory();
    assert_eq!(inv.findings.len(), ZERO_PLACEHOLDER_SCAN_FINDING_COUNT);
}

#[test]
fn scan_inventory_schema_version_matches_constant() {
    let inv = zero_placeholder_scan_inventory();
    assert_eq!(inv.schema_version, ZERO_PLACEHOLDER_SCAN_SCHEMA_VERSION);
}

#[test]
fn scan_inventory_component_matches_constant() {
    let inv = zero_placeholder_scan_inventory();
    assert_eq!(inv.component, ZERO_PLACEHOLDER_SCAN_COMPONENT);
}

#[test]
fn scan_inventory_finding_ids_are_all_unique() {
    let inv = zero_placeholder_scan_inventory();
    let ids: std::collections::BTreeSet<&str> =
        inv.findings.iter().map(|f| f.finding_id.as_str()).collect();
    assert_eq!(
        ids.len(),
        inv.findings.len(),
        "all finding IDs must be unique"
    );
}

#[test]
fn scan_inventory_has_parser_findings() {
    let inv = zero_placeholder_scan_inventory();
    let count = inv
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::Parser)
        .count();
    assert!(count > 0, "must have at least one parser finding");
}

#[test]
fn scan_inventory_has_lowering_findings() {
    let inv = zero_placeholder_scan_inventory();
    let count = inv
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::Lowering)
        .count();
    assert!(count > 0, "must have at least one lowering finding");
}

#[test]
fn scan_inventory_has_runtime_findings() {
    let inv = zero_placeholder_scan_inventory();
    let count = inv
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::Runtime)
        .count();
    assert_eq!(count, 3, "exactly 3 runtime findings expected");
}

#[test]
fn scan_inventory_has_cli_docs_finding() {
    let inv = zero_placeholder_scan_inventory();
    let count = inv
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::CliDocs)
        .count();
    assert_eq!(count, 1, "exactly 1 cli_docs finding expected");
}

#[test]
fn scan_inventory_runtime_findings_match_expected_status_and_severity_split() {
    let inv = zero_placeholder_scan_inventory();
    let runtime_findings: Vec<_> = inv
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::Runtime)
        .collect();
    assert_eq!(runtime_findings.len(), 3);
    assert_eq!(
        runtime_findings
            .iter()
            .filter(|finding| finding.status == ZeroPlaceholderStatus::OpenPlaceholder)
            .count(),
        2
    );
    assert_eq!(
        runtime_findings
            .iter()
            .filter(|finding| finding.severity == ZeroPlaceholderSeverity::High)
            .count(),
        2
    );

    let iterator_finding = runtime_findings
        .iter()
        .find(|finding| finding.finding_id == "runtime::iterator_ir3_placeholder_execution")
        .expect("iterator runtime finding");
    assert_eq!(iterator_finding.status, ZeroPlaceholderStatus::Resolved);
    assert_eq!(iterator_finding.severity, ZeroPlaceholderSeverity::Low);
}

#[test]
fn scan_inventory_all_findings_have_non_empty_owner() {
    let inv = zero_placeholder_scan_inventory();
    for finding in &inv.findings {
        assert!(
            !finding.owner.is_empty(),
            "finding {} has empty owner",
            finding.finding_id
        );
    }
}

#[test]
fn scan_inventory_all_findings_have_non_empty_owner_bead_id() {
    let inv = zero_placeholder_scan_inventory();
    for finding in &inv.findings {
        assert!(
            !finding.owner_bead_id.is_empty(),
            "finding {} has empty owner_bead_id",
            finding.finding_id
        );
    }
}

#[test]
fn scan_inventory_all_findings_have_non_empty_subject_area() {
    let inv = zero_placeholder_scan_inventory();
    for finding in &inv.findings {
        assert!(
            !finding.subject_area.is_empty(),
            "finding {} has empty subject_area",
            finding.finding_id
        );
    }
}

#[test]
fn scan_inventory_all_findings_have_non_empty_observed_behavior() {
    let inv = zero_placeholder_scan_inventory();
    for finding in &inv.findings {
        assert!(
            !finding.observed_behavior.is_empty(),
            "finding {} has empty observed_behavior",
            finding.finding_id
        );
    }
}

#[test]
fn scan_inventory_all_findings_have_non_empty_required_behavior() {
    let inv = zero_placeholder_scan_inventory();
    for finding in &inv.findings {
        assert!(
            !finding.required_behavior.is_empty(),
            "finding {} has empty required_behavior",
            finding.finding_id
        );
    }
}

#[test]
fn scan_inventory_parser_finding_ids_prefixed_correctly() {
    let inv = zero_placeholder_scan_inventory();
    for finding in inv
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::Parser)
    {
        assert!(
            finding.finding_id.starts_with("parser::"),
            "parser finding ID '{}' should start with 'parser::'",
            finding.finding_id
        );
    }
}

#[test]
fn scan_inventory_lowering_finding_ids_prefixed_correctly() {
    let inv = zero_placeholder_scan_inventory();
    for finding in inv
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::Lowering)
    {
        assert!(
            finding.finding_id.starts_with("lowering::"),
            "lowering finding ID '{}' should start with 'lowering::'",
            finding.finding_id
        );
    }
}

#[test]
fn scan_inventory_runtime_finding_ids_prefixed_correctly() {
    let inv = zero_placeholder_scan_inventory();
    for finding in inv
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::Runtime)
    {
        assert!(
            finding.finding_id.starts_with("runtime::"),
            "runtime finding ID '{}' should start with 'runtime::'",
            finding.finding_id
        );
    }
}

#[test]
fn scan_inventory_cli_docs_finding_id_prefixed_correctly() {
    let inv = zero_placeholder_scan_inventory();
    for finding in inv
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::CliDocs)
    {
        assert!(
            finding.finding_id.starts_with("cli_docs::"),
            "cli_docs finding ID '{}' should start with 'cli_docs::'",
            finding.finding_id
        );
    }
}

#[test]
fn scan_inventory_is_deterministic() {
    let inv1 = zero_placeholder_scan_inventory();
    let inv2 = zero_placeholder_scan_inventory();
    // Finding IDs and subsystems must be stable across calls
    let ids1: Vec<&str> = inv1
        .findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();
    let ids2: Vec<&str> = inv2
        .findings
        .iter()
        .map(|f| f.finding_id.as_str())
        .collect();
    assert_eq!(ids1, ids2, "inventory must be deterministic across calls");
}

#[test]
fn scan_inventory_open_placeholder_count_tracks_remaining_runtime_gaps() {
    // Two runtime gaps remain open; iterator execution is now resolved.
    let inv = zero_placeholder_scan_inventory();
    assert_eq!(inv.open_placeholder_finding_count(), 2);
}

#[test]
fn scan_inventory_routes_iterator_runtime_gap_to_iteration_bead() {
    let inv = zero_placeholder_scan_inventory();
    let finding = inv
        .findings
        .iter()
        .find(|finding| finding.finding_id == "runtime::iterator_ir3_placeholder_execution")
        .expect("iterator runtime finding");
    assert_eq!(finding.subsystem, ZeroPlaceholderSubsystem::Runtime);
    assert_eq!(finding.owner_bead_id, "bd-1lsy.4.8");
    assert_eq!(finding.status, ZeroPlaceholderStatus::Resolved);
    assert_eq!(finding.severity, ZeroPlaceholderSeverity::Low);
    assert!(finding.source_reference.contains("lowering_pipeline"));
    assert!(finding.source_reference.contains("baseline_interpreter"));
}

// ---------------------------------------------------------------------------
// 8. ZeroPlaceholderSubsystemSummary — serde roundtrip
// ---------------------------------------------------------------------------

#[test]
fn subsystem_summary_serde_roundtrip() {
    let summary = ZeroPlaceholderSubsystemSummary {
        subsystem: ZeroPlaceholderSubsystem::Parser,
        finding_count: 6,
        open_placeholder_finding_count: 2,
        fail_closed_finding_count: 3,
        resolved_finding_count: 1,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: ZeroPlaceholderSubsystemSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back, summary);
}

#[test]
fn subsystem_summary_zero_counts_serde_roundtrip() {
    let summary = ZeroPlaceholderSubsystemSummary {
        subsystem: ZeroPlaceholderSubsystem::Runtime,
        finding_count: 0,
        open_placeholder_finding_count: 0,
        fail_closed_finding_count: 0,
        resolved_finding_count: 0,
    };
    let json = serde_json::to_string(&summary).unwrap();
    let back: ZeroPlaceholderSubsystemSummary = serde_json::from_str(&json).unwrap();
    assert_eq!(back.finding_count, 0);
    assert_eq!(back.subsystem, ZeroPlaceholderSubsystem::Runtime);
}

#[test]
fn subsystem_summary_clone_equality() {
    let summary = ZeroPlaceholderSubsystemSummary {
        subsystem: ZeroPlaceholderSubsystem::Lowering,
        finding_count: 4,
        open_placeholder_finding_count: 1,
        fail_closed_finding_count: 2,
        resolved_finding_count: 1,
    };
    assert_eq!(summary.clone(), summary);
}

// ---------------------------------------------------------------------------
// 9. ZeroPlaceholderScanTraceIds, ZeroPlaceholderScanRunManifest, ZeroPlaceholderScanEvent
// ---------------------------------------------------------------------------

#[test]
fn trace_ids_construction_and_serde_roundtrip() {
    let trace_ids = ZeroPlaceholderScanTraceIds {
        schema_version: ZERO_PLACEHOLDER_SCAN_TRACE_IDS_SCHEMA_VERSION.to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        trace_id: "trace-abc123".to_string(),
        decision_id: "decision-abc123".to_string(),
        policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
        inventory_hash: "deadbeefdeadbeef".to_string(),
    };
    let json = serde_json::to_string(&trace_ids).unwrap();
    let back: ZeroPlaceholderScanTraceIds = serde_json::from_str(&json).unwrap();
    assert_eq!(back, trace_ids);
}

#[test]
fn trace_ids_fields_accessible() {
    let trace_ids = ZeroPlaceholderScanTraceIds {
        schema_version: "v1".to_string(),
        component: "comp".to_string(),
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: "p1".to_string(),
        inventory_hash: "h1".to_string(),
    };
    assert_eq!(trace_ids.trace_id, "t1");
    assert_eq!(trace_ids.decision_id, "d1");
    assert_eq!(trace_ids.inventory_hash, "h1");
}

#[test]
fn run_manifest_construction_and_serde_roundtrip() {
    let inv = zero_placeholder_scan_inventory();
    let summaries = inv.subsystem_summaries();
    let manifest = ZeroPlaceholderScanRunManifest {
        schema_version: ZERO_PLACEHOLDER_SCAN_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        trace_id: "trace-xyz".to_string(),
        decision_id: "decision-xyz".to_string(),
        policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
        inventory_hash: "cafebabecafebabe".to_string(),
        finding_count: inv.findings.len() as u64,
        open_placeholder_finding_count: inv.open_placeholder_finding_count() as u64,
        fail_closed_finding_count: inv.fail_closed_finding_count() as u64,
        resolved_finding_count: inv.resolved_finding_count() as u64,
        subsystem_summaries: summaries,
        artifact_paths: ZeroPlaceholderScanArtifactPaths {
            zero_placeholder_inventory: "zero_placeholder_inventory.json".to_string(),
            trace_ids: "trace_ids.json".to_string(),
            run_manifest: "run_manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ZeroPlaceholderScanRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, manifest);
}

#[test]
fn run_manifest_finding_count_matches_sum() {
    let inv = zero_placeholder_scan_inventory();
    let total = inv.open_placeholder_finding_count() as u64
        + inv.fail_closed_finding_count() as u64
        + inv.resolved_finding_count() as u64;
    assert_eq!(total, inv.findings.len() as u64);
}

#[test]
fn scan_event_construction_with_optional_fields_none() {
    let event = ZeroPlaceholderScanEvent {
        schema_version: ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        event: "inventory_started".to_string(),
        outcome: "started".to_string(),
        subsystem: None,
        finding_id: None,
        detail: None,
    };
    assert!(event.subsystem.is_none());
    assert!(event.finding_id.is_none());
    assert!(event.detail.is_none());
}

#[test]
fn scan_event_serde_roundtrip_all_fields_present() {
    let event = ZeroPlaceholderScanEvent {
        schema_version: ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-2".to_string(),
        decision_id: "decision-2".to_string(),
        policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        event: "finding_recorded".to_string(),
        outcome: "open_placeholder".to_string(),
        subsystem: Some(ZeroPlaceholderSubsystem::Runtime),
        finding_id: Some("runtime::json_parse_compound_placeholder".to_string()),
        detail: Some("returns descriptor instead of heap value".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ZeroPlaceholderScanEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn scan_event_none_optional_fields_absent_in_json() {
    let event = ZeroPlaceholderScanEvent {
        schema_version: ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "inventory_started".to_string(),
        outcome: "started".to_string(),
        subsystem: None,
        finding_id: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    assert!(
        !json.contains("\"subsystem\""),
        "None subsystem should be absent from JSON"
    );
    assert!(
        !json.contains("\"finding_id\""),
        "None finding_id should be absent from JSON"
    );
    assert!(
        !json.contains("\"detail\""),
        "None detail should be absent from JSON"
    );
}

#[test]
fn scan_event_clone_equality() {
    let event = ZeroPlaceholderScanEvent {
        schema_version: "v1".to_string(),
        trace_id: "t".to_string(),
        decision_id: "d".to_string(),
        policy_id: "p".to_string(),
        component: "c".to_string(),
        event: "finding_recorded".to_string(),
        outcome: "resolved".to_string(),
        subsystem: Some(ZeroPlaceholderSubsystem::Lowering),
        finding_id: Some("lowering::for_of".to_string()),
        detail: None,
    };
    assert_eq!(event.clone(), event);
}

// ---------------------------------------------------------------------------
// 10. ZeroPlaceholderScanArtifactPaths
// ---------------------------------------------------------------------------

#[test]
fn artifact_paths_construction_and_serde_roundtrip() {
    let paths = ZeroPlaceholderScanArtifactPaths {
        zero_placeholder_inventory: "zero_placeholder_inventory.json".to_string(),
        trace_ids: "trace_ids.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: ZeroPlaceholderScanArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(back, paths);
}

#[test]
fn artifact_paths_fields_have_expected_filenames() {
    let paths = ZeroPlaceholderScanArtifactPaths {
        zero_placeholder_inventory: "zero_placeholder_inventory.json".to_string(),
        trace_ids: "trace_ids.json".to_string(),
        run_manifest: "run_manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    };
    assert!(paths.zero_placeholder_inventory.ends_with(".json"));
    assert!(paths.trace_ids.ends_with(".json"));
    assert!(paths.run_manifest.ends_with(".json"));
    assert!(paths.events_jsonl.ends_with(".jsonl"));
    assert!(paths.commands_txt.ends_with(".txt"));
}

#[test]
fn artifact_paths_clone_equality() {
    let paths = ZeroPlaceholderScanArtifactPaths {
        zero_placeholder_inventory: "a.json".to_string(),
        trace_ids: "b.json".to_string(),
        run_manifest: "c.json".to_string(),
        events_jsonl: "d.jsonl".to_string(),
        commands_txt: "e.txt".to_string(),
    };
    assert_eq!(paths.clone(), paths);
}

// ---------------------------------------------------------------------------
// Additional cross-cutting tests
// ---------------------------------------------------------------------------

#[test]
fn inventory_serde_roundtrip() {
    let inv = zero_placeholder_scan_inventory();
    let json = serde_json::to_string(&inv).unwrap();
    let back: ZeroPlaceholderInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(back.schema_version, inv.schema_version);
    assert_eq!(back.component, inv.component);
    assert_eq!(back.findings.len(), inv.findings.len());
}

#[test]
fn all_subsystem_as_str_values_are_non_empty() {
    for variant in ZeroPlaceholderSubsystem::ALL {
        assert!(!variant.as_str().is_empty());
    }
}

#[test]
fn all_status_as_str_values_are_non_empty() {
    for status in [
        ZeroPlaceholderStatus::OpenPlaceholder,
        ZeroPlaceholderStatus::FailClosed,
        ZeroPlaceholderStatus::Resolved,
    ] {
        assert!(!status.as_str().is_empty());
    }
}

#[test]
fn all_severity_as_str_values_are_non_empty() {
    for severity in [
        ZeroPlaceholderSeverity::High,
        ZeroPlaceholderSeverity::Medium,
        ZeroPlaceholderSeverity::Low,
    ] {
        assert!(!severity.as_str().is_empty());
    }
}

#[test]
fn inventory_parser_count_plus_lowering_count_is_twelve() {
    let inv = zero_placeholder_scan_inventory();
    let parser_count = inv
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::Parser)
        .count();
    let lowering_count = inv
        .findings
        .iter()
        .filter(|f| f.subsystem == ZeroPlaceholderSubsystem::Lowering)
        .count();
    assert_eq!(
        parser_count + lowering_count,
        12,
        "parser (6) + lowering (6) = 12"
    );
}

#[test]
fn scan_event_with_lowering_subsystem_serde_roundtrip() {
    let event = ZeroPlaceholderScanEvent {
        schema_version: ZERO_PLACEHOLDER_SCAN_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-lowering".to_string(),
        decision_id: "decision-lowering".to_string(),
        policy_id: ZERO_PLACEHOLDER_SCAN_POLICY_ID.to_string(),
        component: ZERO_PLACEHOLDER_SCAN_COMPONENT.to_string(),
        event: "finding_recorded".to_string(),
        outcome: "fail_closed".to_string(),
        subsystem: Some(ZeroPlaceholderSubsystem::Lowering),
        finding_id: Some("lowering::statement.for_in".to_string()),
        detail: Some("emits UnsupportedSyntax IR3 node".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ZeroPlaceholderScanEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back.subsystem, Some(ZeroPlaceholderSubsystem::Lowering));
    assert_eq!(back.outcome, "fail_closed");
}
