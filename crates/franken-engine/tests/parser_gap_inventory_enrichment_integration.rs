#![forbid(unsafe_code)]

//! Enrichment integration tests for the `parser_gap_inventory` module.

use std::collections::BTreeSet;

use frankenengine_engine::ast::SourceSpan;
use frankenengine_engine::parser_gap_inventory::*;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn span() -> SourceSpan {
    SourceSpan {
        start_line: 10,
        start_column: 5,
        end_line: 10,
        end_column: 25,
        start_offset: 100,
        end_offset: 120,
    }
}

fn span2() -> SourceSpan {
    SourceSpan {
        start_line: 42,
        start_column: 1,
        end_line: 42,
        end_column: 30,
        start_offset: 500,
        end_offset: 529,
    }
}

// ===========================================================================
// ParserGapStage
// ===========================================================================

#[test]
fn enrichment_parser_gap_stage_as_str_ir0_to_ir1() {
    assert_eq!(ParserGapStage::Ir0ToIr1.as_str(), "ir0_to_ir1");
}

#[test]
fn enrichment_parser_gap_stage_as_str_ir1_to_ir3() {
    assert_eq!(ParserGapStage::Ir1ToIr3.as_str(), "ir1_to_ir3");
}

#[test]
fn enrichment_parser_gap_stage_serde_roundtrip_all() {
    for stage in [ParserGapStage::Ir0ToIr1, ParserGapStage::Ir1ToIr3] {
        let json = serde_json::to_string(&stage).unwrap();
        let back: ParserGapStage = serde_json::from_str(&json).unwrap();
        assert_eq!(back, stage);
    }
}

#[test]
fn enrichment_parser_gap_stage_as_str_values_unique() {
    let strs: BTreeSet<&str> = [ParserGapStage::Ir0ToIr1, ParserGapStage::Ir1ToIr3]
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert_eq!(strs.len(), 2);
}

#[test]
fn enrichment_parser_gap_stage_ord_ir0_before_ir1() {
    assert!(ParserGapStage::Ir0ToIr1 < ParserGapStage::Ir1ToIr3);
}

#[test]
fn enrichment_parser_gap_stage_clone_eq() {
    let s = ParserGapStage::Ir0ToIr1;
    let s2 = s;
    assert_eq!(s, s2);
}

#[test]
fn enrichment_parser_gap_stage_debug_not_empty() {
    assert!(!format!("{:?}", ParserGapStage::Ir0ToIr1).is_empty());
    assert!(!format!("{:?}", ParserGapStage::Ir1ToIr3).is_empty());
}

// ===========================================================================
// ParserGapRemediationStatus
// ===========================================================================

#[test]
fn enrichment_remediation_status_as_str_fail_closed() {
    assert_eq!(
        ParserGapRemediationStatus::FailClosed.as_str(),
        "fail_closed"
    );
}

#[test]
fn enrichment_remediation_status_as_str_open_placeholder() {
    assert_eq!(
        ParserGapRemediationStatus::OpenPlaceholder.as_str(),
        "open_placeholder"
    );
}

#[test]
fn enrichment_remediation_status_as_str_resolved() {
    assert_eq!(ParserGapRemediationStatus::Resolved.as_str(), "resolved");
}

#[test]
fn enrichment_remediation_status_serde_roundtrip_all() {
    for status in [
        ParserGapRemediationStatus::FailClosed,
        ParserGapRemediationStatus::OpenPlaceholder,
        ParserGapRemediationStatus::Resolved,
    ] {
        let json = serde_json::to_string(&status).unwrap();
        let back: ParserGapRemediationStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(back, status);
    }
}

#[test]
fn enrichment_remediation_status_all_as_str_unique() {
    let strs: BTreeSet<&str> = [
        ParserGapRemediationStatus::FailClosed,
        ParserGapRemediationStatus::OpenPlaceholder,
        ParserGapRemediationStatus::Resolved,
    ]
    .iter()
    .map(|s| s.as_str())
    .collect();
    assert_eq!(strs.len(), 3);
}

#[test]
fn enrichment_remediation_status_ord() {
    assert!(ParserGapRemediationStatus::FailClosed < ParserGapRemediationStatus::OpenPlaceholder);
    assert!(ParserGapRemediationStatus::OpenPlaceholder < ParserGapRemediationStatus::Resolved);
}

// ===========================================================================
// ParserGapSiteId — basic const methods
// ===========================================================================

#[test]
fn enrichment_site_id_all_has_six_entries() {
    assert_eq!(ParserGapSiteId::ALL.len(), 6);
}

#[test]
fn enrichment_site_id_all_as_str_unique() {
    let strs: BTreeSet<&str> = ParserGapSiteId::ALL.iter().map(|s| s.as_str()).collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn enrichment_site_id_all_diagnostic_codes_unique() {
    let codes: BTreeSet<&str> = ParserGapSiteId::ALL
        .iter()
        .map(|s| s.diagnostic_code())
        .collect();
    assert_eq!(codes.len(), 6);
}

#[test]
fn enrichment_site_id_diagnostic_code_prefix() {
    for site in ParserGapSiteId::ALL {
        assert!(
            site.diagnostic_code().starts_with("FE-PARSER-GAP-"),
            "diagnostic code {:?} should start with FE-PARSER-GAP-",
            site.diagnostic_code()
        );
    }
}

#[test]
fn enrichment_site_id_for_in_stage_is_ir0_to_ir1() {
    assert_eq!(
        ParserGapSiteId::ForInStatementPlaceholder.stage(),
        ParserGapStage::Ir0ToIr1
    );
}

#[test]
fn enrichment_site_id_for_of_stage_is_ir0_to_ir1() {
    assert_eq!(
        ParserGapSiteId::ForOfStatementPlaceholder.stage(),
        ParserGapStage::Ir0ToIr1
    );
}

#[test]
fn enrichment_site_id_new_expression_stage_is_ir0_to_ir1() {
    assert_eq!(
        ParserGapSiteId::NewExpressionCallPlaceholder.stage(),
        ParserGapStage::Ir0ToIr1
    );
}

#[test]
fn enrichment_site_id_template_literal_stage_is_ir0_to_ir1() {
    assert_eq!(
        ParserGapSiteId::TemplateLiteralRawPlaceholder.stage(),
        ParserGapStage::Ir0ToIr1
    );
}

#[test]
fn enrichment_site_id_binary_non_arith_stage_is_ir1_to_ir3() {
    assert_eq!(
        ParserGapSiteId::BinaryNonArithmeticAddPlaceholder.stage(),
        ParserGapStage::Ir1ToIr3
    );
}

#[test]
fn enrichment_site_id_non_ident_assign_stage_is_ir0_to_ir1() {
    assert_eq!(
        ParserGapSiteId::NonIdentifierAssignmentNopPlaceholder.stage(),
        ParserGapStage::Ir0ToIr1
    );
}

#[test]
fn enrichment_site_id_stage_distribution() {
    let ir0_count = ParserGapSiteId::ALL
        .iter()
        .filter(|s| s.stage() == ParserGapStage::Ir0ToIr1)
        .count();
    let ir3_count = ParserGapSiteId::ALL
        .iter()
        .filter(|s| s.stage() == ParserGapStage::Ir1ToIr3)
        .count();
    assert_eq!(ir0_count, 5);
    assert_eq!(ir3_count, 1);
    assert_eq!(ir0_count + ir3_count, 6);
}

#[test]
fn enrichment_site_id_all_resolved() {
    for site in ParserGapSiteId::ALL {
        assert_eq!(
            site.remediation_status(),
            ParserGapRemediationStatus::Resolved
        );
    }
}

#[test]
fn enrichment_site_id_owner_always_lowering_pipeline() {
    for site in ParserGapSiteId::ALL {
        assert_eq!(site.owner(), "lowering_pipeline");
    }
}

#[test]
fn enrichment_site_id_feature_families_all_distinct() {
    let families: BTreeSet<&str> = ParserGapSiteId::ALL
        .iter()
        .map(|s| s.feature_family())
        .collect();
    assert_eq!(families.len(), 6);
}

#[test]
fn enrichment_site_id_api_surface_all_non_empty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.api_surface().is_empty());
    }
}

#[test]
fn enrichment_site_id_api_surface_values() {
    let surfaces: BTreeSet<&str> = ParserGapSiteId::ALL
        .iter()
        .map(|s| s.api_surface())
        .collect();
    assert!(surfaces.contains("lower_ir0_to_ir1"));
    assert!(surfaces.contains("lower_ir1_to_ir3"));
}

#[test]
fn enrichment_site_id_syntax_shape_all_non_empty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.syntax_shape().is_empty());
    }
}

#[test]
fn enrichment_site_id_observed_fallback_all_non_empty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.observed_fallback_behavior().is_empty());
    }
}

#[test]
fn enrichment_site_id_required_fail_closed_all_non_empty() {
    for site in ParserGapSiteId::ALL {
        assert!(
            !site.required_fail_closed_contract().is_empty(),
            "required_fail_closed_contract empty for {:?}",
            site
        );
    }
}

#[test]
fn enrichment_site_id_source_reference_all_contain_lowering() {
    for site in ParserGapSiteId::ALL {
        assert!(
            site.source_reference().contains("lowering_pipeline"),
            "source_reference {:?} should mention lowering_pipeline",
            site.source_reference()
        );
    }
}

#[test]
fn enrichment_site_id_message_template_all_non_empty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.message_template().is_empty());
    }
}

#[test]
fn enrichment_site_id_message_template_mentions_fail_closed() {
    for site in ParserGapSiteId::ALL {
        assert!(
            site.message_template().contains("fail-closed"),
            "message_template for {:?} should mention fail-closed",
            site
        );
    }
}

#[test]
fn enrichment_site_id_blocking_workloads_all_have_two() {
    for site in ParserGapSiteId::ALL {
        assert_eq!(
            site.blocking_workloads().len(),
            2,
            "site {:?} should have exactly 2 blocking workloads",
            site
        );
    }
}

#[test]
fn enrichment_site_id_blocking_workloads_all_non_empty_strings() {
    for site in ParserGapSiteId::ALL {
        for w in site.blocking_workloads() {
            assert!(!w.is_empty());
        }
    }
}

#[test]
fn enrichment_site_id_serde_roundtrip_all() {
    for site in ParserGapSiteId::ALL {
        let json = serde_json::to_string(&site).unwrap();
        let back: ParserGapSiteId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, site);
    }
}

// ===========================================================================
// ParserGapSiteDescriptor
// ===========================================================================

#[test]
fn enrichment_site_descriptor_from_each_site() {
    for site in ParserGapSiteId::ALL {
        let desc = ParserGapSiteDescriptor::from_site(site);
        assert_eq!(desc.site_id, site.as_str());
        assert_eq!(desc.stage, site.stage());
        assert_eq!(desc.remediation_status, site.remediation_status());
        assert_eq!(desc.owner, site.owner());
        assert_eq!(desc.feature_family, site.feature_family());
        assert_eq!(desc.api_surface, site.api_surface());
        assert_eq!(desc.syntax_shape, site.syntax_shape());
        assert_eq!(
            desc.observed_fallback_behavior,
            site.observed_fallback_behavior()
        );
        assert_eq!(
            desc.required_fail_closed_contract,
            site.required_fail_closed_contract()
        );
        assert_eq!(desc.desired_diagnostic_code, site.diagnostic_code());
        assert_eq!(
            desc.blocking_workloads.len(),
            site.blocking_workloads().len()
        );
        assert_eq!(desc.source_reference, site.source_reference());
    }
}

#[test]
fn enrichment_site_descriptor_serde_roundtrip() {
    for site in ParserGapSiteId::ALL {
        let desc = ParserGapSiteDescriptor::from_site(site);
        let json = serde_json::to_string(&desc).unwrap();
        let back: ParserGapSiteDescriptor = serde_json::from_str(&json).unwrap();
        assert_eq!(back, desc);
    }
}

#[test]
fn enrichment_site_descriptor_blocking_workloads_match_original() {
    let site = ParserGapSiteId::ForInStatementPlaceholder;
    let desc = ParserGapSiteDescriptor::from_site(site);
    for (i, workload) in site.blocking_workloads().iter().enumerate() {
        assert_eq!(desc.blocking_workloads[i], *workload);
    }
}

// ===========================================================================
// ParserGapInventory
// ===========================================================================

#[test]
fn enrichment_parser_gap_inventory_has_six_sites() {
    let inv = parser_gap_inventory();
    assert_eq!(inv.sites.len(), 6);
}

#[test]
fn enrichment_parser_gap_inventory_schema_version() {
    let inv = parser_gap_inventory();
    assert_eq!(inv.schema_version, PARSER_GAP_INVENTORY_SCHEMA_VERSION);
}

#[test]
fn enrichment_parser_gap_inventory_diagnostic_schema() {
    let inv = parser_gap_inventory();
    assert_eq!(
        inv.diagnostic_schema_version,
        UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION
    );
}

#[test]
fn enrichment_parser_gap_inventory_component() {
    let inv = parser_gap_inventory();
    assert_eq!(inv.component, PARSER_GAP_COMPONENT);
}

#[test]
fn enrichment_parser_gap_inventory_fail_closed_count_zero() {
    let inv = parser_gap_inventory();
    assert_eq!(inv.fail_closed_site_count(), 0);
}

#[test]
fn enrichment_parser_gap_inventory_open_placeholder_count_zero() {
    let inv = parser_gap_inventory();
    assert_eq!(inv.open_placeholder_site_count(), 0);
}

#[test]
fn enrichment_parser_gap_inventory_serde_roundtrip() {
    let inv = parser_gap_inventory();
    let json = serde_json::to_string(&inv).unwrap();
    let back: ParserGapInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(back, inv);
}

#[test]
fn enrichment_parser_gap_inventory_unique_site_ids() {
    let inv = parser_gap_inventory();
    let ids: BTreeSet<&str> = inv.sites.iter().map(|s| s.site_id.as_str()).collect();
    assert_eq!(ids.len(), inv.sites.len());
}

#[test]
fn enrichment_parser_gap_inventory_unique_diagnostic_codes() {
    let inv = parser_gap_inventory();
    let codes: BTreeSet<&str> = inv
        .sites
        .iter()
        .map(|s| s.desired_diagnostic_code.as_str())
        .collect();
    assert_eq!(codes.len(), inv.sites.len());
}

#[test]
fn enrichment_parser_gap_inventory_deterministic() {
    let inv1 = parser_gap_inventory();
    let inv2 = parser_gap_inventory();
    assert_eq!(inv1, inv2);
    let json1 = serde_json::to_string(&inv1).unwrap();
    let json2 = serde_json::to_string(&inv2).unwrap();
    assert_eq!(json1, json2);
}

// ===========================================================================
// UnsupportedSyntaxDiagnostic
// ===========================================================================

#[test]
fn enrichment_unsupported_syntax_diagnostic_from_each_site() {
    for site in ParserGapSiteId::ALL {
        let diag = UnsupportedSyntaxDiagnostic::from_site(site, "test_src", Some(span()));
        assert_eq!(
            diag.schema_version,
            UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION
        );
        assert_eq!(diag.diagnostic_code, site.diagnostic_code());
        assert_eq!(diag.site_id, site.as_str());
        assert_eq!(diag.stage, site.stage());
        assert_eq!(diag.owner, site.owner());
        assert_eq!(diag.feature_family, site.feature_family());
        assert_eq!(diag.api_surface, site.api_surface());
        assert_eq!(diag.source_label, "test_src");
        assert_eq!(diag.span, Some(span()));
    }
}

#[test]
fn enrichment_unsupported_syntax_diagnostic_without_span() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::NewExpressionCallPlaceholder,
        "no_span_src",
        None,
    );
    assert!(diag.span.is_none());
    assert_eq!(diag.source_label, "no_span_src");
}

#[test]
fn enrichment_unsupported_syntax_diagnostic_serde_roundtrip_with_span() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForOfStatementPlaceholder,
        "serde_src",
        Some(span()),
    );
    let json = serde_json::to_string(&diag).unwrap();
    let back: UnsupportedSyntaxDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(back, diag);
}

#[test]
fn enrichment_unsupported_syntax_diagnostic_serde_roundtrip_without_span() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::TemplateLiteralRawPlaceholder,
        "no_span",
        None,
    );
    let json = serde_json::to_string(&diag).unwrap();
    let back: UnsupportedSyntaxDiagnostic = serde_json::from_str(&json).unwrap();
    assert_eq!(back, diag);
    // span should not appear in JSON when None
    assert!(!json.contains("\"span\""));
}

#[test]
fn enrichment_unsupported_syntax_diagnostic_display_with_span() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForInStatementPlaceholder,
        "my_module",
        Some(span()),
    );
    let display = format!("{diag}");
    assert!(display.contains("FE-PARSER-GAP-FOR-IN-0001"));
    assert!(display.contains("my_module"));
    assert!(display.contains("at 10:5"));
}

#[test]
fn enrichment_unsupported_syntax_diagnostic_display_without_span() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::BinaryNonArithmeticAddPlaceholder,
        "binary_src",
        None,
    );
    let display = format!("{diag}");
    assert!(display.contains("FE-PARSER-GAP-BINARY-0001"));
    assert!(display.contains("binary_src"));
    assert!(!display.contains("at "));
}

#[test]
fn enrichment_unsupported_syntax_diagnostic_display_different_span() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::NonIdentifierAssignmentNopPlaceholder,
        "assign_src",
        Some(span2()),
    );
    let display = format!("{diag}");
    assert!(display.contains("at 42:1"));
}

// ===========================================================================
// Canonical value and hash
// ===========================================================================

#[test]
fn enrichment_canonical_value_is_map_with_16_keys() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForInStatementPlaceholder,
        "test",
        Some(span()),
    );
    let cv = diag.canonical_value();
    if let frankenengine_engine::deterministic_serde::CanonicalValue::Map(map) = &cv {
        assert_eq!(map.len(), 16);
    } else {
        panic!("canonical_value should be a Map");
    }
}

#[test]
fn enrichment_canonical_value_null_span_when_none() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForOfStatementPlaceholder,
        "test",
        None,
    );
    let cv = diag.canonical_value();
    if let frankenengine_engine::deterministic_serde::CanonicalValue::Map(map) = &cv {
        assert!(matches!(
            map.get("span"),
            Some(frankenengine_engine::deterministic_serde::CanonicalValue::Null)
        ));
    } else {
        panic!("canonical_value should be a Map");
    }
}

#[test]
fn enrichment_canonical_hash_deterministic() {
    let diag1 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::TemplateLiteralRawPlaceholder,
        "det_src",
        Some(span()),
    );
    let diag2 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::TemplateLiteralRawPlaceholder,
        "det_src",
        Some(span()),
    );
    assert_eq!(diag1.canonical_hash(), diag2.canonical_hash());
}

#[test]
fn enrichment_canonical_hash_changes_with_source_label() {
    let diag1 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForInStatementPlaceholder,
        "label_a",
        Some(span()),
    );
    let diag2 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForInStatementPlaceholder,
        "label_b",
        Some(span()),
    );
    assert_ne!(diag1.canonical_hash(), diag2.canonical_hash());
}

#[test]
fn enrichment_canonical_hash_changes_with_site() {
    let diag1 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForInStatementPlaceholder,
        "same",
        None,
    );
    let diag2 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForOfStatementPlaceholder,
        "same",
        None,
    );
    assert_ne!(diag1.canonical_hash(), diag2.canonical_hash());
}

#[test]
fn enrichment_canonical_hash_changes_with_span_presence() {
    let diag1 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::NewExpressionCallPlaceholder,
        "src",
        Some(span()),
    );
    let diag2 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::NewExpressionCallPlaceholder,
        "src",
        None,
    );
    assert_ne!(diag1.canonical_hash(), diag2.canonical_hash());
}

#[test]
fn enrichment_canonical_hash_has_prefix() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForInStatementPlaceholder,
        "src",
        None,
    );
    let hash = diag.canonical_hash();
    assert!(hash.starts_with(&diag.hash_prefix));
    assert!(hash.len() > diag.hash_prefix.len());
}

#[test]
fn enrichment_canonical_hash_all_sites_distinct() {
    let hashes: BTreeSet<String> = ParserGapSiteId::ALL
        .iter()
        .map(|site| {
            UnsupportedSyntaxDiagnostic::from_site(*site, "common_label", Some(span()))
                .canonical_hash()
        })
        .collect();
    assert_eq!(hashes.len(), 6);
}

// ===========================================================================
// ParseDiagnosticEnvelope projection
// ===========================================================================

#[test]
fn enrichment_parse_diagnostic_envelope_fields() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForInStatementPlaceholder,
        "envelope_src",
        Some(span()),
    );
    let envelope = diag.parse_diagnostic_envelope();
    assert_eq!(
        envelope.parse_error_code,
        frankenengine_engine::parser::ParseErrorCode::UnsupportedSyntax
    );
    assert_eq!(envelope.diagnostic_code, "FE-PARSER-GAP-FOR-IN-0001");
    assert_eq!(
        envelope.category,
        frankenengine_engine::parser::ParseDiagnosticCategory::Syntax
    );
    assert_eq!(
        envelope.severity,
        frankenengine_engine::parser::ParseDiagnosticSeverity::Error
    );
    assert_eq!(envelope.span, Some(span()));
    assert!(envelope.budget_kind.is_none());
    assert!(envelope.witness.is_none());
}

#[test]
fn enrichment_parse_diagnostic_envelope_no_span() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForOfStatementPlaceholder,
        "no_span",
        None,
    );
    let envelope = diag.parse_diagnostic_envelope();
    assert!(envelope.span.is_none());
}

#[test]
fn enrichment_parse_diagnostic_envelope_from_each_site() {
    for site in ParserGapSiteId::ALL {
        let diag = UnsupportedSyntaxDiagnostic::from_site(site, "each", None);
        let envelope = diag.parse_diagnostic_envelope();
        assert_eq!(envelope.diagnostic_code, site.diagnostic_code());
        assert_eq!(envelope.message_template, site.message_template());
    }
}

// ===========================================================================
// Schema version constants
// ===========================================================================

#[test]
fn enrichment_schema_version_constants_all_non_empty() {
    assert!(!UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_GAP_INVENTORY_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_GAP_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_GAP_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_GAP_COMPONENT.is_empty());
    assert!(!PARSER_GAP_POLICY_ID.is_empty());
}

#[test]
fn enrichment_schema_version_constants_contain_franken() {
    assert!(UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION.contains("franken"));
    assert!(PARSER_GAP_INVENTORY_SCHEMA_VERSION.contains("franken"));
    assert!(PARSER_GAP_RUN_MANIFEST_SCHEMA_VERSION.contains("franken"));
    assert!(PARSER_GAP_EVENT_SCHEMA_VERSION.contains("franken"));
}

#[test]
fn enrichment_parser_gap_component_value() {
    assert_eq!(PARSER_GAP_COMPONENT, "parser_gap_inventory");
}

// ===========================================================================
// ParserGapInventoryArtifactPaths
// ===========================================================================

#[test]
fn enrichment_artifact_paths_serde_roundtrip() {
    let paths = ParserGapInventoryArtifactPaths {
        parser_gap_inventory: "inventory.json".to_string(),
        run_manifest: "manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    };
    let json = serde_json::to_string(&paths).unwrap();
    let back: ParserGapInventoryArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(back, paths);
}

// ===========================================================================
// ParserGapInventoryRunManifest
// ===========================================================================

#[test]
fn enrichment_run_manifest_serde_roundtrip() {
    let manifest = ParserGapInventoryRunManifest {
        schema_version: PARSER_GAP_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: PARSER_GAP_COMPONENT.to_string(),
        trace_id: "trace-abc".to_string(),
        decision_id: "decision-abc".to_string(),
        policy_id: PARSER_GAP_POLICY_ID.to_string(),
        inventory_hash: "deadbeef".to_string(),
        site_count: 6,
        fail_closed_site_count: 0,
        open_placeholder_site_count: 0,
        diagnostic_schema_version: UNSUPPORTED_SYNTAX_DIAGNOSTIC_SCHEMA_VERSION.to_string(),
        artifact_paths: ParserGapInventoryArtifactPaths {
            parser_gap_inventory: "inventory.json".to_string(),
            run_manifest: "manifest.json".to_string(),
            events_jsonl: "events.jsonl".to_string(),
            commands_txt: "commands.txt".to_string(),
        },
    };
    let json = serde_json::to_string(&manifest).unwrap();
    let back: ParserGapInventoryRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(back, manifest);
}

// ===========================================================================
// ParserGapInventoryEvent
// ===========================================================================

#[test]
fn enrichment_inventory_event_serde_roundtrip_with_optionals() {
    let event = ParserGapInventoryEvent {
        schema_version: PARSER_GAP_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-1".to_string(),
        decision_id: "decision-1".to_string(),
        policy_id: PARSER_GAP_POLICY_ID.to_string(),
        component: PARSER_GAP_COMPONENT.to_string(),
        event: "gap_site_recorded".to_string(),
        outcome: "resolved".to_string(),
        site_id: Some("test_site".to_string()),
        diagnostic_code: Some("FE-TEST-0001".to_string()),
        detail: Some("detail here".to_string()),
    };
    let json = serde_json::to_string(&event).unwrap();
    let back: ParserGapInventoryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

#[test]
fn enrichment_inventory_event_serde_roundtrip_without_optionals() {
    let event = ParserGapInventoryEvent {
        schema_version: PARSER_GAP_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-2".to_string(),
        decision_id: "decision-2".to_string(),
        policy_id: PARSER_GAP_POLICY_ID.to_string(),
        component: PARSER_GAP_COMPONENT.to_string(),
        event: "inventory_started".to_string(),
        outcome: "started".to_string(),
        site_id: None,
        diagnostic_code: None,
        detail: None,
    };
    let json = serde_json::to_string(&event).unwrap();
    // None fields should be skipped
    assert!(!json.contains("\"site_id\""));
    assert!(!json.contains("\"diagnostic_code\""));
    let back: ParserGapInventoryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(back, event);
}

// ===========================================================================
// ParserGapInventoryWriteError
// ===========================================================================

#[test]
fn enrichment_write_error_display_json() {
    let err = ParserGapInventoryWriteError::Json {
        path: "/tmp/test.json".to_string(),
        source: serde_json::from_str::<String>("not json").unwrap_err(),
    };
    let display = format!("{err}");
    assert!(display.contains("/tmp/test.json"));
    assert!(display.contains("serialize"));
}

#[test]
fn enrichment_write_error_display_busy() {
    let err = ParserGapInventoryWriteError::Busy {
        path: "/tmp/.lock".to_string(),
    };
    let display = format!("{err}");
    assert!(display.contains("/tmp/.lock"));
    assert!(display.contains("locked"));
}

#[test]
fn enrichment_write_error_display_io() {
    let err = ParserGapInventoryWriteError::Io {
        path: "/tmp/missing".to_string(),
        source: std::io::Error::new(std::io::ErrorKind::NotFound, "not found"),
    };
    let display = format!("{err}");
    assert!(display.contains("/tmp/missing"));
}

// ===========================================================================
// write_parser_gap_inventory_bundle (integration)
// ===========================================================================

#[test]
fn enrichment_write_bundle_creates_all_files() {
    let out_dir = std::env::temp_dir().join(format!(
        "frankenengine-pgap-enrichment-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let commands = vec!["test_command --flag".to_string()];
    let artifacts = write_parser_gap_inventory_bundle(&out_dir, &commands).unwrap();

    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
    assert_eq!(artifacts.site_count, 6);
    assert!(!artifacts.inventory_hash.is_empty());

    // Lock should be cleaned up
    assert!(!out_dir.join(".parser_gap_inventory.lock").exists());

    // Cleanup
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn enrichment_write_bundle_inventory_json_valid() {
    let out_dir = std::env::temp_dir().join(format!(
        "frankenengine-pgap-inv-valid-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let artifacts = write_parser_gap_inventory_bundle(&out_dir, &[]).unwrap();
    let bytes = std::fs::read(&artifacts.inventory_path).unwrap();
    let inv: ParserGapInventory = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(inv.sites.len(), 6);
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn enrichment_write_bundle_manifest_matches_inventory() {
    let out_dir = std::env::temp_dir().join(format!(
        "frankenengine-pgap-manifest-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let artifacts = write_parser_gap_inventory_bundle(&out_dir, &[]).unwrap();
    let manifest: ParserGapInventoryRunManifest =
        serde_json::from_slice(&std::fs::read(&artifacts.run_manifest_path).unwrap()).unwrap();
    assert_eq!(manifest.site_count, 6);
    assert_eq!(manifest.fail_closed_site_count, 0);
    assert_eq!(manifest.open_placeholder_site_count, 0);
    assert_eq!(manifest.inventory_hash, artifacts.inventory_hash);
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn enrichment_write_bundle_events_line_count() {
    let out_dir = std::env::temp_dir().join(format!(
        "frankenengine-pgap-events-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let artifacts = write_parser_gap_inventory_bundle(&out_dir, &[]).unwrap();
    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    // 1 started + 6 sites + 1 completed = 8 lines
    assert_eq!(events_text.lines().count(), 8);
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn enrichment_write_bundle_events_parseable_jsonl() {
    let out_dir = std::env::temp_dir().join(format!(
        "frankenengine-pgap-jsonl-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let artifacts = write_parser_gap_inventory_bundle(&out_dir, &[]).unwrap();
    let events_text = std::fs::read_to_string(&artifacts.events_path).unwrap();
    for line in events_text.lines() {
        let event: ParserGapInventoryEvent = serde_json::from_str(line).unwrap();
        assert!(!event.event.is_empty());
    }
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn enrichment_write_bundle_commands_written() {
    let out_dir = std::env::temp_dir().join(format!(
        "frankenengine-pgap-cmds-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let commands = vec!["cmd1 --arg".to_string(), "cmd2 --flag".to_string()];
    let artifacts = write_parser_gap_inventory_bundle(&out_dir, &commands).unwrap();
    let cmds = std::fs::read_to_string(&artifacts.commands_path).unwrap();
    assert!(cmds.contains("cmd1 --arg"));
    assert!(cmds.contains("cmd2 --flag"));
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn enrichment_write_bundle_hash_deterministic() {
    let out_dir1 = std::env::temp_dir().join(format!(
        "frankenengine-pgap-det1-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let out_dir2 = std::env::temp_dir().join(format!(
        "frankenengine-pgap-det2-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            + 1
    ));
    let a1 = write_parser_gap_inventory_bundle(&out_dir1, &[]).unwrap();
    let a2 = write_parser_gap_inventory_bundle(&out_dir2, &[]).unwrap();
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
    let _ = std::fs::remove_dir_all(&out_dir1);
    let _ = std::fs::remove_dir_all(&out_dir2);
}

#[test]
fn enrichment_write_bundle_rewrite_replaces_old_files() {
    let out_dir = std::env::temp_dir().join(format!(
        "frankenengine-pgap-rewrite-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let a1 = write_parser_gap_inventory_bundle(&out_dir, &["first".to_string()]).unwrap();
    let a2 = write_parser_gap_inventory_bundle(&out_dir, &["second".to_string()]).unwrap();
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
    let cmds = std::fs::read_to_string(&a2.commands_path).unwrap();
    assert!(cmds.contains("second"));
    let _ = std::fs::remove_dir_all(&out_dir);
}

// ===========================================================================
// Cross-cutting: diagnostic_code ↔ required_fail_closed_contract alignment
// ===========================================================================

#[test]
fn enrichment_fail_closed_contract_mentions_diagnostic_code() {
    for site in ParserGapSiteId::ALL {
        let contract = site.required_fail_closed_contract();
        let code = site.diagnostic_code();
        assert!(
            contract.contains(code),
            "fail-closed contract for {:?} should mention diagnostic code {code}",
            site
        );
    }
}

#[test]
fn enrichment_source_reference_contains_crates_prefix() {
    for site in ParserGapSiteId::ALL {
        assert!(
            site.source_reference().starts_with("crates/"),
            "source_reference for {:?} should start with crates/",
            site
        );
    }
}

#[test]
fn enrichment_for_in_specific_values() {
    let site = ParserGapSiteId::ForInStatementPlaceholder;
    assert_eq!(site.diagnostic_code(), "FE-PARSER-GAP-FOR-IN-0001");
    assert_eq!(site.feature_family(), "for_in_statement");
    assert!(site.syntax_shape().contains("for"));
    assert!(site.syntax_shape().contains("in"));
}

#[test]
fn enrichment_for_of_specific_values() {
    let site = ParserGapSiteId::ForOfStatementPlaceholder;
    assert_eq!(site.diagnostic_code(), "FE-PARSER-GAP-FOR-OF-0001");
    assert_eq!(site.feature_family(), "for_of_statement");
    assert!(site.syntax_shape().contains("for"));
    assert!(site.syntax_shape().contains("of"));
}

#[test]
fn enrichment_new_expression_specific_values() {
    let site = ParserGapSiteId::NewExpressionCallPlaceholder;
    assert_eq!(site.diagnostic_code(), "FE-PARSER-GAP-NEW-0001");
    assert_eq!(site.feature_family(), "new_expression");
    assert!(site.syntax_shape().contains("new"));
}

#[test]
fn enrichment_template_literal_specific_values() {
    let site = ParserGapSiteId::TemplateLiteralRawPlaceholder;
    assert_eq!(site.diagnostic_code(), "FE-PARSER-GAP-TEMPLATE-0001");
    assert_eq!(site.feature_family(), "template_literal");
}

#[test]
fn enrichment_binary_non_arith_specific_values() {
    let site = ParserGapSiteId::BinaryNonArithmeticAddPlaceholder;
    assert_eq!(site.diagnostic_code(), "FE-PARSER-GAP-BINARY-0001");
    assert_eq!(site.feature_family(), "binary_non_arithmetic_expression");
    assert_eq!(site.api_surface(), "lower_ir1_to_ir3");
}

#[test]
fn enrichment_non_ident_assign_specific_values() {
    let site = ParserGapSiteId::NonIdentifierAssignmentNopPlaceholder;
    assert_eq!(site.diagnostic_code(), "FE-PARSER-GAP-ASSIGN-0001");
    assert_eq!(site.feature_family(), "member_assignment_expression");
}
