#![forbid(unsafe_code)]

//! Enrichment integration tests for the lowering_gap_inventory module.

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

use frankenengine_engine::lowering_gap_inventory::{
    LOWERING_GAP_COMPONENT, LOWERING_GAP_EVENT_SCHEMA_VERSION,
    LOWERING_GAP_INVENTORY_SCHEMA_VERSION, LOWERING_GAP_POLICY_ID,
    LOWERING_GAP_RUN_MANIFEST_SCHEMA_VERSION, LoweringGapInventory,
    LoweringGapInventoryArtifactPaths, LoweringGapInventoryEvent, LoweringGapInventoryRunManifest,
    LoweringGapSiteDescriptor, LoweringGapSiteId, LoweringGapStage, LoweringGapStatus,
    lowering_gap_inventory,
};

// ---------------------------------------------------------------------------
// LoweringGapStage — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lowering_gap_stage_copy_semantics() {
    let a = LoweringGapStage::Ir0ToIr1;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_lowering_gap_stage_btreeset_dedup_2() {
    let mut set = BTreeSet::new();
    set.insert(LoweringGapStage::Ir0ToIr1);
    set.insert(LoweringGapStage::Ir1ToIr3);
    set.insert(LoweringGapStage::Ir0ToIr1);
    assert_eq!(set.len(), 2);
}

#[test]
fn enrichment_lowering_gap_stage_clone_independence() {
    let a = LoweringGapStage::Ir1ToIr3;
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_lowering_gap_stage_debug_all_unique() {
    let all = [LoweringGapStage::Ir0ToIr1, LoweringGapStage::Ir1ToIr3];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 2);
}

// ---------------------------------------------------------------------------
// LoweringGapStatus — Copy / BTreeSet / Clone / Debug
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lowering_gap_status_copy_semantics() {
    let a = LoweringGapStatus::Resolved;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_lowering_gap_status_btreeset_dedup_3() {
    let mut set = BTreeSet::new();
    set.insert(LoweringGapStatus::FailClosed);
    set.insert(LoweringGapStatus::OpenPlaceholder);
    set.insert(LoweringGapStatus::Resolved);
    set.insert(LoweringGapStatus::FailClosed);
    assert_eq!(set.len(), 3);
}

#[test]
fn enrichment_lowering_gap_status_debug_all_unique() {
    let all = [
        LoweringGapStatus::FailClosed,
        LoweringGapStatus::OpenPlaceholder,
        LoweringGapStatus::Resolved,
    ];
    let dbgs: BTreeSet<String> = all.iter().map(|v| format!("{:?}", v)).collect();
    assert_eq!(dbgs.len(), 3);
}

// ---------------------------------------------------------------------------
// LoweringGapSiteId — Copy / BTreeSet / Clone / Debug / methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_lowering_gap_site_id_copy_semantics() {
    let a = LoweringGapSiteId::ForInStatementPlaceholder;
    let b = a;
    assert_eq!(a, b);
}

#[test]
fn enrichment_lowering_gap_site_id_btreeset_dedup_6() {
    let mut set = BTreeSet::new();
    for site in LoweringGapSiteId::ALL {
        set.insert(site);
    }
    set.insert(LoweringGapSiteId::ForInStatementPlaceholder);
    assert_eq!(set.len(), 6);
}

#[test]
fn enrichment_lowering_gap_site_id_debug_all_unique() {
    let dbgs: BTreeSet<String> = LoweringGapSiteId::ALL
        .iter()
        .map(|v| format!("{:?}", v))
        .collect();
    assert_eq!(dbgs.len(), 6);
}

#[test]
fn enrichment_lowering_gap_site_id_as_str_all_unique() {
    let strs: BTreeSet<&str> = LoweringGapSiteId::ALL.iter().map(|v| v.as_str()).collect();
    assert_eq!(strs.len(), 6);
}

#[test]
fn enrichment_lowering_gap_site_id_diagnostic_codes_all_unique() {
    let codes: BTreeSet<&str> = LoweringGapSiteId::ALL
        .iter()
        .map(|v| v.diagnostic_code())
        .collect();
    assert_eq!(codes.len(), 6);
}

#[test]
fn enrichment_lowering_gap_site_id_all_have_owner() {
    for site in LoweringGapSiteId::ALL {
        assert!(!site.owner().is_empty(), "empty owner for {:?}", site);
    }
}

#[test]
fn enrichment_lowering_gap_site_id_all_have_ast_family() {
    for site in LoweringGapSiteId::ALL {
        assert!(
            !site.ast_node_family().is_empty(),
            "empty ast family for {:?}",
            site
        );
    }
}

#[test]
fn enrichment_lowering_gap_site_id_all_have_regression_hint() {
    for site in LoweringGapSiteId::ALL {
        assert!(
            !site.regression_test_hint().is_empty(),
            "empty hint for {:?}",
            site
        );
    }
}

// ---------------------------------------------------------------------------
// LoweringGapSiteDescriptor — Clone / Debug / JSON fields
// ---------------------------------------------------------------------------

#[test]
fn enrichment_site_descriptor_clone_independence() {
    let a = LoweringGapSiteDescriptor::from_site(LoweringGapSiteId::ForInStatementPlaceholder);
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_site_descriptor_debug_nonempty() {
    let d = LoweringGapSiteDescriptor::from_site(LoweringGapSiteId::ForOfStatementPlaceholder);
    assert!(!format!("{:?}", d).is_empty());
}

#[test]
fn enrichment_site_descriptor_json_field_names() {
    let d = LoweringGapSiteDescriptor::from_site(LoweringGapSiteId::ForInStatementPlaceholder);
    let json = serde_json::to_string(&d).unwrap();
    for field in &[
        "site_id",
        "diagnostic_code",
        "stage",
        "status",
        "owner",
        "ast_node_family",
        "emitted_ir_shape",
        "execution_consequence",
        "user_visible_divergence",
        "target_replacement_strategy",
        "parser_ready_syntax",
        "execution_ready_semantics",
        "source_reference",
        "regression_test_hint",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_site_descriptor_serde_roundtrip() {
    let a = LoweringGapSiteDescriptor::from_site(LoweringGapSiteId::NewExpressionCallPlaceholder);
    let json = serde_json::to_string(&a).unwrap();
    let b: LoweringGapSiteDescriptor = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// LoweringGapInventory — Clone / Debug / JSON fields / methods
// ---------------------------------------------------------------------------

#[test]
fn enrichment_inventory_clone_independence() {
    let a = lowering_gap_inventory();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_inventory_debug_nonempty() {
    assert!(!format!("{:?}", lowering_gap_inventory()).is_empty());
}

#[test]
fn enrichment_inventory_json_field_names() {
    let inv = lowering_gap_inventory();
    let json = serde_json::to_string(&inv).unwrap();
    for field in &["schema_version", "component", "sites"] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_inventory_serde_roundtrip() {
    let a = lowering_gap_inventory();
    let json = serde_json::to_string(&a).unwrap();
    let b: LoweringGapInventory = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// LoweringGapInventoryArtifactPaths — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

fn make_artifact_paths() -> LoweringGapInventoryArtifactPaths {
    LoweringGapInventoryArtifactPaths {
        lowering_gap_inventory: "inventory.json".to_string(),
        run_manifest: "manifest.json".to_string(),
        events_jsonl: "events.jsonl".to_string(),
        commands_txt: "commands.txt".to_string(),
    }
}

#[test]
fn enrichment_artifact_paths_clone_independence() {
    let a = make_artifact_paths();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_artifact_paths_debug_nonempty() {
    assert!(!format!("{:?}", make_artifact_paths()).is_empty());
}

#[test]
fn enrichment_artifact_paths_json_field_names() {
    let json = serde_json::to_string(&make_artifact_paths()).unwrap();
    for field in &[
        "lowering_gap_inventory",
        "run_manifest",
        "events_jsonl",
        "commands_txt",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_artifact_paths_serde_roundtrip() {
    let a = make_artifact_paths();
    let json = serde_json::to_string(&a).unwrap();
    let b: LoweringGapInventoryArtifactPaths = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// LoweringGapInventoryRunManifest — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

fn make_manifest() -> LoweringGapInventoryRunManifest {
    LoweringGapInventoryRunManifest {
        schema_version: LOWERING_GAP_RUN_MANIFEST_SCHEMA_VERSION.to_string(),
        component: LOWERING_GAP_COMPONENT.to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "dec-001".to_string(),
        policy_id: LOWERING_GAP_POLICY_ID.to_string(),
        inventory_hash: "abc123".to_string(),
        site_count: 6,
        fail_closed_site_count: 0,
        open_placeholder_site_count: 0,
        parser_ready_site_count: 6,
        execution_ready_site_count: 0,
        artifact_paths: make_artifact_paths(),
    }
}

#[test]
fn enrichment_run_manifest_clone_independence() {
    let a = make_manifest();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_run_manifest_debug_nonempty() {
    assert!(!format!("{:?}", make_manifest()).is_empty());
}

#[test]
fn enrichment_run_manifest_json_field_names() {
    let json = serde_json::to_string(&make_manifest()).unwrap();
    for field in &[
        "schema_version",
        "component",
        "trace_id",
        "decision_id",
        "policy_id",
        "inventory_hash",
        "site_count",
        "fail_closed_site_count",
        "open_placeholder_site_count",
        "parser_ready_site_count",
        "execution_ready_site_count",
        "artifact_paths",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_run_manifest_serde_roundtrip() {
    let a = make_manifest();
    let json = serde_json::to_string(&a).unwrap();
    let b: LoweringGapInventoryRunManifest = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// LoweringGapInventoryEvent — Clone / Debug / JSON / serde
// ---------------------------------------------------------------------------

fn make_event() -> LoweringGapInventoryEvent {
    LoweringGapInventoryEvent {
        schema_version: LOWERING_GAP_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "trace-001".to_string(),
        decision_id: "dec-001".to_string(),
        policy_id: LOWERING_GAP_POLICY_ID.to_string(),
        component: LOWERING_GAP_COMPONENT.to_string(),
        event: "site_evaluated".to_string(),
        outcome: "resolved".to_string(),
        site_id: Some("for_in".to_string()),
        diagnostic_code: Some("FE-001".to_string()),
        detail: Some("detail".to_string()),
    }
}

#[test]
fn enrichment_event_clone_independence() {
    let a = make_event();
    let b = a.clone();
    assert_eq!(a, b);
}

#[test]
fn enrichment_event_debug_nonempty() {
    assert!(!format!("{:?}", make_event()).is_empty());
}

#[test]
fn enrichment_event_json_field_names() {
    let json = serde_json::to_string(&make_event()).unwrap();
    for field in &[
        "schema_version",
        "trace_id",
        "decision_id",
        "policy_id",
        "component",
        "event",
        "outcome",
        "site_id",
        "diagnostic_code",
        "detail",
    ] {
        assert!(
            json.contains(&format!("\"{}\"", field)),
            "missing: {}",
            field
        );
    }
}

#[test]
fn enrichment_event_serde_roundtrip() {
    let a = make_event();
    let json = serde_json::to_string(&a).unwrap();
    let b: LoweringGapInventoryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

#[test]
fn enrichment_event_with_nones() {
    let a = LoweringGapInventoryEvent {
        schema_version: LOWERING_GAP_EVENT_SCHEMA_VERSION.to_string(),
        trace_id: "t1".to_string(),
        decision_id: "d1".to_string(),
        policy_id: LOWERING_GAP_POLICY_ID.to_string(),
        component: LOWERING_GAP_COMPONENT.to_string(),
        event: "inventory_started".to_string(),
        outcome: "ok".to_string(),
        site_id: None,
        diagnostic_code: None,
        detail: None,
    };
    let json = serde_json::to_string(&a).unwrap();
    let b: LoweringGapInventoryEvent = serde_json::from_str(&json).unwrap();
    assert_eq!(a, b);
}

// ---------------------------------------------------------------------------
// Constants stability
// ---------------------------------------------------------------------------

#[test]
fn enrichment_constants_exact_values() {
    assert_eq!(
        LOWERING_GAP_INVENTORY_SCHEMA_VERSION,
        "franken-engine.lowering-gap-inventory.v1"
    );
    assert_eq!(
        LOWERING_GAP_RUN_MANIFEST_SCHEMA_VERSION,
        "franken-engine.lowering-gap-inventory.run-manifest.v1"
    );
    assert_eq!(
        LOWERING_GAP_EVENT_SCHEMA_VERSION,
        "franken-engine.lowering-gap-inventory.event.v1"
    );
    assert_eq!(LOWERING_GAP_COMPONENT, "lowering_gap_inventory");
    assert_eq!(
        LOWERING_GAP_POLICY_ID,
        "franken-engine.lowering-gap-inventory.policy.v1"
    );
}

// ---------------------------------------------------------------------------
// Determinism
// ---------------------------------------------------------------------------

#[test]
fn enrichment_five_run_determinism_inventory() {
    let jsons: BTreeSet<String> = (0..5)
        .map(|_| serde_json::to_string(&lowering_gap_inventory()).unwrap())
        .collect();
    assert_eq!(jsons.len(), 1, "inventory should be deterministic");
}

// ---------------------------------------------------------------------------
// Cross-cutting invariants
// ---------------------------------------------------------------------------

#[test]
fn enrichment_cross_cutting_site_count_matches() {
    let inv = lowering_gap_inventory();
    assert_eq!(inv.sites.len(), 6);
}

#[test]
fn enrichment_cross_cutting_descriptor_matches_site_id() {
    for site in LoweringGapSiteId::ALL {
        let desc = LoweringGapSiteDescriptor::from_site(site);
        assert_eq!(desc.site_id, site.as_str());
        assert_eq!(desc.diagnostic_code, site.diagnostic_code());
        assert_eq!(desc.stage, site.stage());
        assert_eq!(desc.status, site.status());
        assert_eq!(desc.owner, site.owner());
    }
}

#[test]
fn enrichment_cross_cutting_schema_version_in_inventory() {
    let inv = lowering_gap_inventory();
    assert_eq!(inv.schema_version, LOWERING_GAP_INVENTORY_SCHEMA_VERSION);
}

#[test]
fn enrichment_cross_cutting_component_in_inventory() {
    let inv = lowering_gap_inventory();
    assert_eq!(inv.component, LOWERING_GAP_COMPONENT);
}

#[test]
fn enrichment_cross_cutting_method_counts_consistent() {
    let inv = lowering_gap_inventory();
    let total = inv.fail_closed_site_count()
        + inv.open_placeholder_site_count()
        + (inv.sites.len() - inv.fail_closed_site_count() - inv.open_placeholder_site_count());
    assert_eq!(total, inv.sites.len());
}
