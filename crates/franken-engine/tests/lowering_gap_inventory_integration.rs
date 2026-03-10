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

use frankenengine_engine::lowering_gap_inventory::*;
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
        "frankenengine-lowering-gap-integ-{label}-{}-{nanos}",
        process::id()
    ))
}

// --- Inventory construction tests ---

#[test]
fn inventory_has_all_six_sites() {
    let inventory = lowering_gap_inventory();
    assert_eq!(inventory.sites.len(), 6);
}

#[test]
fn inventory_schema_version_is_well_formed() {
    let inventory = lowering_gap_inventory();
    assert!(inventory.schema_version.starts_with("franken-engine."));
    assert!(inventory.schema_version.contains(".v"));
}

#[test]
fn inventory_component_is_lowering_gap_inventory() {
    let inventory = lowering_gap_inventory();
    assert_eq!(inventory.component, LOWERING_GAP_COMPONENT);
}

#[test]
fn all_site_ids_are_unique() {
    let ids: BTreeSet<String> = LoweringGapSiteId::ALL
        .iter()
        .map(|s| s.as_str().to_string())
        .collect();
    assert_eq!(ids.len(), LoweringGapSiteId::ALL.len());
}

#[test]
fn all_diagnostic_codes_are_unique() {
    let codes: BTreeSet<String> = LoweringGapSiteId::ALL
        .iter()
        .map(|s| s.diagnostic_code().to_string())
        .collect();
    assert_eq!(codes.len(), LoweringGapSiteId::ALL.len());
}

#[test]
fn all_diagnostic_codes_have_fe_prefix() {
    for site in LoweringGapSiteId::ALL {
        assert!(
            site.diagnostic_code().starts_with("FE-"),
            "diagnostic code for {:?} should start with FE-",
            site
        );
    }
}

// --- Status classification tests ---

#[test]
fn zero_fail_closed_sites() {
    let inventory = lowering_gap_inventory();
    assert_eq!(inventory.fail_closed_site_count(), 0);
}

#[test]
fn zero_open_placeholder_sites() {
    let inventory = lowering_gap_inventory();
    assert_eq!(inventory.open_placeholder_site_count(), 0);
}

#[test]
fn all_sites_are_parser_ready() {
    let inventory = lowering_gap_inventory();
    assert_eq!(inventory.parser_ready_site_count(), 6);
}

#[test]
fn no_sites_are_execution_ready() {
    let inventory = lowering_gap_inventory();
    assert_eq!(inventory.execution_ready_site_count(), 0);
}

#[test]
fn for_in_is_resolved() {
    assert_eq!(
        LoweringGapSiteId::ForInStatementPlaceholder.status(),
        LoweringGapStatus::Resolved
    );
}

#[test]
fn for_of_is_resolved() {
    assert_eq!(
        LoweringGapSiteId::ForOfStatementPlaceholder.status(),
        LoweringGapStatus::Resolved
    );
}

#[test]
fn new_expression_is_resolved() {
    assert_eq!(
        LoweringGapSiteId::NewExpressionCallPlaceholder.status(),
        LoweringGapStatus::Resolved
    );
}

#[test]
fn template_literal_is_resolved() {
    assert_eq!(
        LoweringGapSiteId::TemplateLiteralRawPlaceholder.status(),
        LoweringGapStatus::Resolved
    );
}

#[test]
fn binary_non_arithmetic_is_resolved() {
    assert_eq!(
        LoweringGapSiteId::BinaryNonArithmeticAddPlaceholder.status(),
        LoweringGapStatus::Resolved
    );
}

#[test]
fn assignment_nop_is_resolved() {
    assert_eq!(
        LoweringGapSiteId::NonIdentifierAssignmentNopPlaceholder.status(),
        LoweringGapStatus::Resolved
    );
}

// --- Stage classification tests ---

#[test]
fn binary_placeholder_is_ir1_to_ir3_stage() {
    assert_eq!(
        LoweringGapSiteId::BinaryNonArithmeticAddPlaceholder.stage(),
        LoweringGapStage::Ir1ToIr3
    );
}

#[test]
fn all_other_sites_are_ir0_to_ir1_stage() {
    let ir0_sites = [
        LoweringGapSiteId::ForInStatementPlaceholder,
        LoweringGapSiteId::ForOfStatementPlaceholder,
        LoweringGapSiteId::NewExpressionCallPlaceholder,
        LoweringGapSiteId::NonIdentifierAssignmentNopPlaceholder,
        LoweringGapSiteId::TemplateLiteralRawPlaceholder,
    ];
    for site in ir0_sites {
        assert_eq!(
            site.stage(),
            LoweringGapStage::Ir0ToIr1,
            "site {:?} should be Ir0ToIr1",
            site
        );
    }
}

// --- Descriptor tests ---

#[test]
fn descriptor_preserves_site_metadata() {
    for site in LoweringGapSiteId::ALL {
        let desc = LoweringGapSiteDescriptor::from_site(site);
        assert_eq!(desc.site_id, site.as_str());
        assert_eq!(desc.diagnostic_code, site.diagnostic_code());
        assert_eq!(desc.stage, site.stage());
        assert_eq!(desc.status, site.status());
        assert_eq!(desc.owner, site.owner());
        assert_eq!(desc.ast_node_family, site.ast_node_family());
        assert_eq!(desc.emitted_ir_shape, site.emitted_ir_shape());
        assert_eq!(desc.source_reference, site.source_reference());
        assert_eq!(desc.regression_test_hint, site.regression_test_hint());
    }
}

#[test]
fn descriptor_execution_consequence_is_nonempty() {
    for site in LoweringGapSiteId::ALL {
        let desc = LoweringGapSiteDescriptor::from_site(site);
        assert!(
            !desc.execution_consequence.is_empty(),
            "execution_consequence for {:?} should be non-empty",
            site
        );
    }
}

#[test]
fn descriptor_user_visible_divergence_is_nonempty() {
    for site in LoweringGapSiteId::ALL {
        let desc = LoweringGapSiteDescriptor::from_site(site);
        assert!(
            !desc.user_visible_divergence.is_empty(),
            "user_visible_divergence for {:?} should be non-empty",
            site
        );
    }
}

#[test]
fn descriptor_target_replacement_strategy_is_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(
            !site.target_replacement_strategy().is_empty(),
            "target_replacement_strategy for {:?} should be non-empty",
            site
        );
    }
}

// --- as_str round-trip tests ---

#[test]
fn lowering_gap_stage_as_str_is_deterministic() {
    assert_eq!(LoweringGapStage::Ir0ToIr1.as_str(), "ir0_to_ir1");
    assert_eq!(LoweringGapStage::Ir1ToIr3.as_str(), "ir1_to_ir3");
}

#[test]
fn lowering_gap_status_as_str_is_deterministic() {
    assert_eq!(LoweringGapStatus::FailClosed.as_str(), "fail_closed");
    assert_eq!(
        LoweringGapStatus::OpenPlaceholder.as_str(),
        "open_placeholder"
    );
    assert_eq!(LoweringGapStatus::Resolved.as_str(), "resolved");
}

// --- Serde round-trip tests ---

#[test]
fn inventory_serde_roundtrip() {
    let inventory = lowering_gap_inventory();
    let json = serde_json::to_string(&inventory).expect("serialize inventory");
    let deserialized: LoweringGapInventory =
        serde_json::from_str(&json).expect("deserialize inventory");
    assert_eq!(inventory, deserialized);
}

#[test]
fn site_id_serde_roundtrip() {
    for site in LoweringGapSiteId::ALL {
        let json = serde_json::to_string(&site).expect("serialize site id");
        let deserialized: LoweringGapSiteId =
            serde_json::from_str(&json).expect("deserialize site id");
        assert_eq!(site, deserialized);
    }
}

#[test]
fn stage_serde_roundtrip() {
    let stages = [LoweringGapStage::Ir0ToIr1, LoweringGapStage::Ir1ToIr3];
    for stage in stages {
        let json = serde_json::to_string(&stage).expect("serialize");
        let deserialized: LoweringGapStage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(stage, deserialized);
    }
}

#[test]
fn status_serde_roundtrip() {
    let statuses = [
        LoweringGapStatus::FailClosed,
        LoweringGapStatus::OpenPlaceholder,
        LoweringGapStatus::Resolved,
    ];
    for status in statuses {
        let json = serde_json::to_string(&status).expect("serialize");
        let deserialized: LoweringGapStatus = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status, deserialized);
    }
}

#[test]
fn descriptor_serde_roundtrip() {
    for site in LoweringGapSiteId::ALL {
        let desc = LoweringGapSiteDescriptor::from_site(site);
        let json = serde_json::to_string(&desc).expect("serialize descriptor");
        let deserialized: LoweringGapSiteDescriptor =
            serde_json::from_str(&json).expect("deserialize descriptor");
        assert_eq!(desc, deserialized);
    }
}

// --- Bundle write tests ---

#[test]
fn bundle_write_creates_all_expected_files() {
    let out_dir = unique_temp_dir("bundle-write");
    let commands = vec!["test-command".to_string()];
    let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    assert!(artifacts.inventory_path.exists());
    assert!(artifacts.run_manifest_path.exists());
    assert!(artifacts.events_path.exists());
    assert!(artifacts.commands_path.exists());
}

#[test]
fn bundle_inventory_is_valid_json() {
    let out_dir = unique_temp_dir("bundle-inventory-json");
    let commands = vec!["check".to_string()];
    let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    let bytes = fs::read(&artifacts.inventory_path).expect("read");
    let inventory: LoweringGapInventory = serde_json::from_slice(&bytes).expect("parse json");
    assert_eq!(inventory.sites.len(), 6);
}

#[test]
fn bundle_manifest_has_correct_counts() {
    let out_dir = unique_temp_dir("bundle-manifest-counts");
    let commands = vec!["verify".to_string()];
    let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    let bytes = fs::read(&artifacts.run_manifest_path).expect("read");
    let manifest: LoweringGapInventoryRunManifest =
        serde_json::from_slice(&bytes).expect("parse json");
    assert_eq!(manifest.site_count, 6);
    assert_eq!(manifest.fail_closed_site_count, 0);
    assert_eq!(manifest.open_placeholder_site_count, 0);
    assert_eq!(manifest.parser_ready_site_count, 6);
    assert_eq!(manifest.execution_ready_site_count, 0);
}

#[test]
fn bundle_events_has_correct_line_count() {
    let out_dir = unique_temp_dir("bundle-events-count");
    let commands = vec!["run".to_string()];
    let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    let events = fs::read_to_string(&artifacts.events_path).expect("read");
    // 1 started + 6 gap_site_recorded + 1 completed = 8
    assert_eq!(events.lines().count(), 8);
}

#[test]
fn bundle_events_first_line_is_inventory_started() {
    let out_dir = unique_temp_dir("bundle-events-started");
    let commands = vec!["init".to_string()];
    let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    let events = fs::read_to_string(&artifacts.events_path).expect("read");
    let first_line = events.lines().next().expect("has first line");
    let event: LoweringGapInventoryEvent = serde_json::from_str(first_line).expect("parse event");
    assert_eq!(event.event, "inventory_started");
    assert_eq!(event.outcome, "started");
}

#[test]
fn bundle_events_last_line_is_inventory_completed() {
    let out_dir = unique_temp_dir("bundle-events-completed");
    let commands = vec!["finalize".to_string()];
    let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    let events = fs::read_to_string(&artifacts.events_path).expect("read");
    let last_line = events.lines().last().expect("has last line");
    let event: LoweringGapInventoryEvent = serde_json::from_str(last_line).expect("parse event");
    assert_eq!(event.event, "inventory_completed");
    assert_eq!(event.outcome, "completed");
}

#[test]
fn bundle_commands_captures_provided_command_lines() {
    let out_dir = unique_temp_dir("bundle-commands");
    let commands = vec![
        "franken_lowering_gap_inventory".to_string(),
        "--out-dir".to_string(),
        "/some/path".to_string(),
    ];
    let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    let commands_txt = fs::read_to_string(&artifacts.commands_path).expect("read");
    assert!(commands_txt.contains("franken_lowering_gap_inventory"));
    assert!(commands_txt.contains("--out-dir"));
    assert!(commands_txt.contains("/some/path"));
}

#[test]
fn bundle_lock_is_released_after_write() {
    let out_dir = unique_temp_dir("bundle-lock-release");
    let commands = vec!["test".to_string()];
    let _ = write_lowering_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    assert!(!out_dir.join(".lowering_gap_inventory.lock").exists());
}

#[test]
fn bundle_hash_is_deterministic_across_writes() {
    let out_dir1 = unique_temp_dir("bundle-hash-1");
    let out_dir2 = unique_temp_dir("bundle-hash-2");
    let commands = vec!["determinism-check".to_string()];
    let a1 = write_lowering_gap_inventory_bundle(&out_dir1, &commands).expect("write first");
    let a2 = write_lowering_gap_inventory_bundle(&out_dir2, &commands).expect("write second");
    assert_eq!(a1.inventory_hash, a2.inventory_hash);
}

#[test]
fn bundle_site_count_matches_inventory() {
    let out_dir = unique_temp_dir("bundle-site-count");
    let commands = vec!["count".to_string()];
    let artifacts = write_lowering_gap_inventory_bundle(&out_dir, &commands).expect("write bundle");
    assert_eq!(artifacts.site_count, 6);
}

// --- Error display tests ---

#[test]
fn write_error_busy_displays_path() {
    let err = LoweringGapInventoryWriteError::Busy {
        path: "/tmp/test.lock".to_string(),
    };
    let msg = format!("{err}");
    assert!(msg.contains("/tmp/test.lock"));
    assert!(msg.contains("locked"));
}

// --- Ordering tests ---

#[test]
fn site_id_ordering_is_deterministic() {
    let mut sites = LoweringGapSiteId::ALL.to_vec();
    sites.sort();
    let mut sites2 = LoweringGapSiteId::ALL.to_vec();
    sites2.sort();
    assert_eq!(sites, sites2);
}

#[test]
fn status_ordering_is_deterministic() {
    let mut statuses = [
        LoweringGapStatus::Resolved,
        LoweringGapStatus::FailClosed,
        LoweringGapStatus::OpenPlaceholder,
    ];
    statuses.sort();
    assert_eq!(statuses[0], LoweringGapStatus::FailClosed);
    assert_eq!(statuses[1], LoweringGapStatus::OpenPlaceholder);
    assert_eq!(statuses[2], LoweringGapStatus::Resolved);
}

// --- Resolved site semantic checks ---

#[test]
fn resolved_sites_have_real_ir_shapes() {
    let resolved_sites = [
        LoweringGapSiteId::ForInStatementPlaceholder,
        LoweringGapSiteId::ForOfStatementPlaceholder,
    ];
    for site in resolved_sites {
        let shape = site.emitted_ir_shape();
        assert!(
            shape.starts_with("ir1."),
            "resolved site {:?} should emit real IR, got {}",
            site,
            shape
        );
    }
}

#[test]
fn formerly_fail_closed_sites_are_now_resolved() {
    let resolved_sites = [
        LoweringGapSiteId::NewExpressionCallPlaceholder,
        LoweringGapSiteId::TemplateLiteralRawPlaceholder,
    ];
    for site in resolved_sites {
        assert_eq!(
            site.status(),
            LoweringGapStatus::Resolved,
            "site {:?} should be resolved",
            site
        );
    }
}

#[test]
fn resolved_sites_mention_resolved_in_consequence() {
    let resolved_sites = [
        LoweringGapSiteId::ForInStatementPlaceholder,
        LoweringGapSiteId::ForOfStatementPlaceholder,
    ];
    for site in resolved_sites {
        assert!(
            site.execution_consequence().contains("resolved"),
            "resolved site {:?} should mention 'resolved' in consequence",
            site
        );
    }
}

#[test]
fn all_owners_are_lowering_pipeline() {
    for site in LoweringGapSiteId::ALL {
        assert_eq!(site.owner(), "lowering_pipeline");
    }
}

#[test]
fn all_source_references_point_to_lowering_pipeline() {
    for site in LoweringGapSiteId::ALL {
        assert!(
            site.source_reference().contains("lowering_pipeline.rs"),
            "source reference for {:?} should point to lowering_pipeline.rs",
            site
        );
    }
}

#[test]
fn all_regression_test_hints_are_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(
            !site.regression_test_hint().is_empty(),
            "regression_test_hint for {:?} should be non-empty",
            site
        );
    }
}
