use frankenengine_engine::parser_gap_inventory::*;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    env::temp_dir().join(format!(
        "frankenengine-parser-gap-integ-{label}-{}-{nanos}",
        process::id()
    ))
}

// --- Inventory construction tests ---

#[test]
fn inventory_has_all_six_sites() {
    let inventory = parser_gap_inventory();
    assert_eq!(inventory.sites.len(), 6);
}

#[test]
fn inventory_schema_versions_are_well_formed() {
    let inventory = parser_gap_inventory();
    assert!(inventory.schema_version.starts_with("franken-engine."));
    assert!(
        inventory
            .diagnostic_schema_version
            .starts_with("franken-engine.")
    );
}

#[test]
fn inventory_component_is_parser_gap_inventory() {
    let inventory = parser_gap_inventory();
    assert_eq!(inventory.component, PARSER_GAP_COMPONENT);
}

#[test]
fn all_site_ids_are_unique() {
    let ids: BTreeSet<String> = ParserGapSiteId::ALL
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();
    assert_eq!(ids.len(), ParserGapSiteId::ALL.len());
}

#[test]
fn all_diagnostic_codes_are_unique() {
    let codes: BTreeSet<String> = ParserGapSiteId::ALL
        .iter()
        .map(|s| s.diagnostic_code().to_string())
        .collect();
    assert_eq!(codes.len(), ParserGapSiteId::ALL.len());
}

#[test]
fn all_diagnostic_codes_have_fe_parser_gap_prefix() {
    for site in ParserGapSiteId::ALL {
        assert!(
            site.diagnostic_code().starts_with("FE-PARSER-GAP-"),
            "diagnostic code for {:?} should start with FE-PARSER-GAP-",
            site
        );
    }
}

// --- Remediation status tests ---

#[test]
fn zero_fail_closed_sites() {
    let inventory = parser_gap_inventory();
    assert_eq!(inventory.fail_closed_site_count(), 0);
}

#[test]
fn zero_open_placeholder_sites() {
    let inventory = parser_gap_inventory();
    assert_eq!(inventory.open_placeholder_site_count(), 0);
}

#[test]
fn for_in_is_resolved() {
    assert_eq!(
        ParserGapSiteId::ForInStatementPlaceholder.remediation_status(),
        ParserGapRemediationStatus::Resolved
    );
}

#[test]
fn for_of_is_resolved() {
    assert_eq!(
        ParserGapSiteId::ForOfStatementPlaceholder.remediation_status(),
        ParserGapRemediationStatus::Resolved
    );
}

#[test]
fn new_expression_is_resolved() {
    assert_eq!(
        ParserGapSiteId::NewExpressionCallPlaceholder.remediation_status(),
        ParserGapRemediationStatus::Resolved
    );
}

#[test]
fn template_literal_is_resolved() {
    assert_eq!(
        ParserGapSiteId::TemplateLiteralRawPlaceholder.remediation_status(),
        ParserGapRemediationStatus::Resolved
    );
}

#[test]
fn binary_non_arithmetic_is_resolved() {
    assert_eq!(
        ParserGapSiteId::BinaryNonArithmeticAddPlaceholder.remediation_status(),
        ParserGapRemediationStatus::Resolved
    );
}

#[test]
fn assignment_nop_is_resolved() {
    assert_eq!(
        ParserGapSiteId::NonIdentifierAssignmentNopPlaceholder.remediation_status(),
        ParserGapRemediationStatus::Resolved
    );
}

// --- Stage classification tests ---

#[test]
fn binary_placeholder_is_ir1_to_ir3_stage() {
    assert_eq!(
        ParserGapSiteId::BinaryNonArithmeticAddPlaceholder.stage(),
        ParserGapStage::Ir1ToIr3
    );
}

#[test]
fn non_binary_sites_are_ir0_to_ir1_stage() {
    let ir0_sites = [
        ParserGapSiteId::ForInStatementPlaceholder,
        ParserGapSiteId::ForOfStatementPlaceholder,
        ParserGapSiteId::NewExpressionCallPlaceholder,
        ParserGapSiteId::TemplateLiteralRawPlaceholder,
        ParserGapSiteId::NonIdentifierAssignmentNopPlaceholder,
    ];
    for site in ir0_sites {
        assert_eq!(
            site.stage(),
            ParserGapStage::Ir0ToIr1,
            "site {:?} should be Ir0ToIr1",
            site
        );
    }
}

// --- Descriptor tests ---

#[test]
fn descriptor_preserves_site_metadata() {
    for site in ParserGapSiteId::ALL {
        let desc = ParserGapSiteDescriptor::from_site(site);
        assert_eq!(desc.site_id, site.as_str());
        assert_eq!(desc.stage, site.stage());
        assert_eq!(desc.remediation_status, site.remediation_status());
        assert_eq!(desc.owner, site.owner());
        assert_eq!(desc.feature_family, site.feature_family());
        assert_eq!(desc.api_surface, site.api_surface());
        assert_eq!(desc.syntax_shape, site.syntax_shape());
        assert_eq!(desc.desired_diagnostic_code, site.diagnostic_code());
        assert_eq!(desc.source_reference, site.source_reference());
    }
}

#[test]
fn descriptor_observed_fallback_behavior_is_nonempty() {
    for site in ParserGapSiteId::ALL {
        let desc = ParserGapSiteDescriptor::from_site(site);
        assert!(
            !desc.observed_fallback_behavior.is_empty(),
            "observed_fallback_behavior for {:?} should be non-empty",
            site
        );
    }
}

#[test]
fn descriptor_required_fail_closed_contract_is_nonempty() {
    for site in ParserGapSiteId::ALL {
        let desc = ParserGapSiteDescriptor::from_site(site);
        assert!(
            !desc.required_fail_closed_contract.is_empty(),
            "required_fail_closed_contract for {:?} should be non-empty",
            site
        );
    }
}

#[test]
fn descriptor_blocking_workloads_are_nonempty() {
    for site in ParserGapSiteId::ALL {
        let desc = ParserGapSiteDescriptor::from_site(site);
        assert!(
            !desc.blocking_workloads.is_empty(),
            "blocking_workloads for {:?} should have at least one entry",
            site
        );
    }
}

// --- UnsupportedSyntaxDiagnostic tests ---

#[test]
fn unsupported_syntax_diagnostic_from_site_has_correct_fields() {
    use frankenengine_engine::ast::SourceSpan;
    let span = SourceSpan {
        start_line: 5,
        start_column: 10,
        end_line: 5,
        end_column: 20,
        start_offset: 50,
        end_offset: 60,
    };
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::NewExpressionCallPlaceholder,
        "test-source",
        Some(span.clone()),
    );
    assert_eq!(diag.diagnostic_code, "FE-PARSER-GAP-NEW-0001");
    assert_eq!(diag.source_label, "test-source");
    assert_eq!(diag.span, Some(span));
    assert_eq!(
        diag.site_id,
        ParserGapSiteId::NewExpressionCallPlaceholder.as_str()
    );
    assert_eq!(diag.stage, ParserGapStage::Ir0ToIr1);
}

#[test]
fn unsupported_syntax_diagnostic_without_span() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::TemplateLiteralRawPlaceholder,
        "template-test",
        None,
    );
    assert!(diag.span.is_none());
    assert_eq!(diag.diagnostic_code, "FE-PARSER-GAP-TEMPLATE-0001");
}

#[test]
fn unsupported_syntax_diagnostic_canonical_hash_is_stable() {
    use frankenengine_engine::ast::SourceSpan;
    let span = SourceSpan {
        start_line: 1,
        start_column: 1,
        end_line: 1,
        end_column: 10,
        start_offset: 0,
        end_offset: 9,
    };
    let d1 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForInStatementPlaceholder,
        "source-a",
        Some(span.clone()),
    );
    let d2 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForInStatementPlaceholder,
        "source-a",
        Some(span),
    );
    assert_eq!(d1.canonical_hash(), d2.canonical_hash());
}

#[test]
fn unsupported_syntax_diagnostic_different_sites_produce_different_hashes() {
    let d1 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForInStatementPlaceholder,
        "src",
        None,
    );
    let d2 = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForOfStatementPlaceholder,
        "src",
        None,
    );
    assert_ne!(d1.canonical_hash(), d2.canonical_hash());
}

#[test]
fn unsupported_syntax_diagnostic_display_includes_code_and_site() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::BinaryNonArithmeticAddPlaceholder,
        "binary-test",
        None,
    );
    let display = format!("{diag}");
    assert!(display.contains("FE-PARSER-GAP-BINARY-0001"));
    assert!(display.contains("binary-test"));
}

#[test]
fn unsupported_syntax_diagnostic_display_includes_span_when_present() {
    use frankenengine_engine::ast::SourceSpan;
    let span = SourceSpan {
        start_line: 42,
        start_column: 7,
        end_line: 42,
        end_column: 15,
        start_offset: 500,
        end_offset: 508,
    };
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::NonIdentifierAssignmentNopPlaceholder,
        "assign-test",
        Some(span),
    );
    let display = format!("{diag}");
    assert!(display.contains("42:7"));
}

#[test]
fn unsupported_syntax_diagnostic_parse_diagnostic_envelope_roundtrip() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::ForOfStatementPlaceholder,
        "envelope-test",
        None,
    );
    let envelope = diag.parse_diagnostic_envelope();
    assert_eq!(envelope.diagnostic_code, "FE-PARSER-GAP-FOR-OF-0001");
    assert_eq!(envelope.source_label, "envelope-test");
}

// --- Serde round-trip tests ---

#[test]
fn inventory_serde_roundtrip() {
    let inventory = parser_gap_inventory();
    let json = serde_json::to_string(&inventory).expect("serialize");
    let deserialized: ParserGapInventory = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(inventory, deserialized);
}

#[test]
fn site_id_serde_roundtrip() {
    for site in ParserGapSiteId::ALL {
        let json = serde_json::to_string(&site).expect("serialize");
        let deserialized: ParserGapSiteId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(site, deserialized);
    }
}

#[test]
fn remediation_status_serde_roundtrip() {
    let statuses = [
        ParserGapRemediationStatus::FailClosed,
        ParserGapRemediationStatus::OpenPlaceholder,
        ParserGapRemediationStatus::Resolved,
    ];
    for status in statuses {
        let json = serde_json::to_string(&status).expect("serialize");
        let deserialized: ParserGapRemediationStatus =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, deserialized);
    }
}

#[test]
fn descriptor_serde_roundtrip() {
    for site in ParserGapSiteId::ALL {
        let desc = ParserGapSiteDescriptor::from_site(site);
        let json = serde_json::to_string(&desc).expect("serialize");
        let deserialized: ParserGapSiteDescriptor =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(desc, deserialized);
    }
}

#[test]
fn unsupported_syntax_diagnostic_serde_roundtrip() {
    let diag = UnsupportedSyntaxDiagnostic::from_site(
        ParserGapSiteId::NewExpressionCallPlaceholder,
        "serde-test",
        None,
    );
    let json = serde_json::to_string(&diag).expect("serialize");
    let deserialized: UnsupportedSyntaxDiagnostic =
        serde_json::from_str(&json).expect("deserialize");
    assert_eq!(diag, deserialized);
}

// --- Bundle write tests ---

#[test]
fn bundle_write_creates_all_expected_files() {
    let out_dir = unique_temp_dir("bundle-write");
    let commands = vec!["test-command".to_string()];
    let artifacts = write_parser_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
}

#[test]
fn bundle_inventory_is_valid_json() {
    let out_dir = unique_temp_dir("bundle-inv-json");
    let commands = vec!["check".to_string()];
    let artifacts = write_parser_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    let bytes = fs::read(&artifacts.inventory_path).expect("read");
    let inventory: ParserGapInventory = serde_json::from_slice(&bytes).expect("parse");
    assert_eq!(inventory.sites.len(), 6);
}

#[test]
fn bundle_manifest_has_correct_counts() {
    let out_dir = unique_temp_dir("bundle-manifest");
    let commands = vec!["verify".to_string()];
    let artifacts = write_parser_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    let bytes = fs::read(&artifacts.run_manifest_path).expect("read");
    let manifest: ParserGapInventoryRunManifest = serde_json::from_slice(&bytes).expect("parse");
    assert_eq!(manifest.site_count, 6);
    assert_eq!(manifest.fail_closed_site_count, 0);
    assert_eq!(manifest.open_placeholder_site_count, 0);
}

#[test]
fn bundle_events_has_correct_structure() {
    let out_dir = unique_temp_dir("bundle-events");
    let commands = vec!["run".to_string()];
    let artifacts = write_parser_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    let events_str = fs::read_to_string(&artifacts.events_path).expect("read");
    // 1 started + 6 recorded + 1 completed = 8
    assert_eq!(events_str.lines().count(), 8);
    for line in events_str.lines() {
        let event: ParserGapInventoryEvent =
            serde_json::from_str(line).expect("each line should be valid JSON");
        assert!(!event.trace_id.is_empty());
        assert!(!event.decision_id.is_empty());
    }
}

#[test]
fn bundle_hash_is_deterministic() {
    let d1 = unique_temp_dir("hash-1");
    let d2 = unique_temp_dir("hash-2");
    let cmds = vec!["det-check".to_string()];
    let a1 = write_parser_gap_inventory_bundle(&d1, &cmds).expect("write 1");
    let a2 = write_parser_gap_inventory_bundle(&d2, &cmds).expect("write 2");
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
}

#[test]
fn bundle_lock_is_released_after_write() {
    let out_dir = unique_temp_dir("lock-release");
    let commands = vec!["test".to_string()];
    let _ = write_parser_gap_inventory_bundle(&out_dir, &commands).expect("write");
    assert!(!out_dir.join(".parser_gap_inventory.lock").exists());
}

// --- Feature family and API surface tests ---

#[test]
fn all_feature_families_are_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(
            !site.feature_family().is_empty(),
            "feature_family for {:?} should be non-empty",
            site
        );
    }
}

#[test]
fn all_api_surfaces_reference_lowering() {
    for site in ParserGapSiteId::ALL {
        assert!(
            site.api_surface().starts_with("lower_"),
            "api_surface for {:?} should start with 'lower_'",
            site
        );
    }
}

#[test]
fn all_syntax_shapes_are_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(
            !site.syntax_shape().is_empty(),
            "syntax_shape for {:?} should be non-empty",
            site
        );
    }
}

#[test]
fn all_message_templates_mention_fail_closed() {
    for site in ParserGapSiteId::ALL {
        assert!(
            site.message_template().contains("fail-closed"),
            "message_template for {:?} should mention fail-closed",
            site
        );
    }
}

#[test]
fn all_owners_are_lowering_pipeline() {
    for site in ParserGapSiteId::ALL {
        assert_eq!(site.owner(), "lowering_pipeline");
    }
}

// --- as_str round-trip tests ---

#[test]
fn parser_gap_stage_as_str_values() {
    assert_eq!(ParserGapStage::Ir0ToIr1.as_str(), "ir0_to_ir1");
    assert_eq!(ParserGapStage::Ir1ToIr3.as_str(), "ir1_to_ir3");
}

#[test]
fn remediation_status_as_str_values() {
    assert_eq!(
        ParserGapRemediationStatus::FailClosed.as_str(),
        "fail_closed"
    );
    assert_eq!(
        ParserGapRemediationStatus::OpenPlaceholder.as_str(),
        "open_placeholder"
    );
    assert_eq!(ParserGapRemediationStatus::Resolved.as_str(), "resolved");
}
