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

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::lowering_gap_inventory::{
    self as lgap, LOWERING_GAP_COMPONENT, LOWERING_GAP_EVENT_SCHEMA_VERSION,
    LOWERING_GAP_INVENTORY_SCHEMA_VERSION, LOWERING_GAP_POLICY_ID,
    LOWERING_GAP_RUN_MANIFEST_SCHEMA_VERSION, LoweringGapInventory,
    LoweringGapInventoryRunManifest, LoweringGapSiteDescriptor, LoweringGapSiteId,
    LoweringGapStage, LoweringGapStatus,
};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    env::temp_dir().join(format!("frankenengine-{label}-{}-{nanos}", process::id()))
}

#[test]
fn lowering_gap_inventory_cli_writes_artifact_bundle() {
    let out_dir = unique_temp_dir("lowering-gap-cli");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lowering_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run lowering gap inventory binary");
    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let inventory: LoweringGapInventory =
        serde_json::from_slice(&fs::read(out_dir.join("lowering_gap_inventory.json")).unwrap())
            .expect("inventory json");
    assert_eq!(inventory.sites.len(), LoweringGapSiteId::ALL.len());

    let manifest: LoweringGapInventoryRunManifest =
        serde_json::from_slice(&fs::read(out_dir.join("run_manifest.json")).unwrap())
            .expect("manifest json");
    assert_eq!(manifest.site_count as usize, LoweringGapSiteId::ALL.len());
    assert_eq!(manifest.fail_closed_site_count, 2);
    assert_eq!(manifest.open_placeholder_site_count, 2);
    assert_eq!(
        manifest.parser_ready_site_count as usize,
        LoweringGapSiteId::ALL.len()
    );
    assert_eq!(manifest.execution_ready_site_count, 0);

    let events = fs::read_to_string(out_dir.join("events.jsonl")).expect("read events");
    assert_eq!(events.lines().count(), LoweringGapSiteId::ALL.len() + 2);

    let commands = fs::read_to_string(out_dir.join("commands.txt")).expect("read commands");
    assert!(commands.contains("franken_lowering_gap_inventory"));
    assert!(commands.contains("--out-dir"));

    let cli_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout json summary");
    assert_eq!(
        cli_json["site_count"].as_u64().expect("site_count") as usize,
        LoweringGapSiteId::ALL.len()
    );
    assert_eq!(
        cli_json["inventory_hash"]
            .as_str()
            .expect("inventory_hash")
            .len(),
        64
    );
}

#[test]
fn lowering_gap_inventory_cli_help_exits_with_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lowering_gap_inventory"))
        .arg("--help")
        .output()
        .expect("run lowering gap inventory help");
    // --help goes through Err path in this CLI, exits non-zero
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage: franken_lowering_gap_inventory --out-dir <DIR>"),
        "expected usage in stderr, got: {stderr}"
    );
}

#[test]
fn lowering_gap_site_id_all_has_six_entries() {
    assert_eq!(LoweringGapSiteId::ALL.len(), 6);
}

#[test]
fn lowering_gap_site_id_as_str_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(!site.as_str().is_empty());
    }
}

#[test]
fn lowering_gap_site_id_diagnostic_code_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(site.diagnostic_code().starts_with("FE-"));
    }
}

#[test]
fn lowering_gap_site_id_stages_are_valid() {
    for site in LoweringGapSiteId::ALL {
        let _ = site.stage();
    }
}

#[test]
fn lowering_gap_site_id_statuses_are_valid() {
    for site in LoweringGapSiteId::ALL {
        let _ = site.status();
    }
}

#[test]
fn lowering_gap_stage_as_str_covers_all_variants() {
    let stages = [LoweringGapStage::Ir0ToIr1, LoweringGapStage::Ir1ToIr3];
    for stage in stages {
        assert!(!stage.as_str().is_empty());
    }
}

#[test]
fn lowering_gap_status_as_str_covers_all_variants() {
    let statuses = [
        LoweringGapStatus::FailClosed,
        LoweringGapStatus::OpenPlaceholder,
        LoweringGapStatus::Resolved,
    ];
    for status in statuses {
        assert!(!status.as_str().is_empty());
    }
}

#[test]
fn lowering_gap_site_descriptor_from_site_populates_all_fields() {
    for site in LoweringGapSiteId::ALL {
        let desc = LoweringGapSiteDescriptor::from_site(site);
        assert_eq!(desc.site_id, site.as_str());
        assert!(!desc.diagnostic_code.is_empty());
        assert!(!desc.ast_node_family.is_empty());
        assert!(!desc.emitted_ir_shape.is_empty());
        assert!(!desc.execution_consequence.is_empty());
        assert!(!desc.user_visible_divergence.is_empty());
        assert!(!desc.target_replacement_strategy.is_empty());
        assert!(!desc.source_reference.is_empty());
        assert!(!desc.regression_test_hint.is_empty());
    }
}

#[test]
fn lowering_gap_inventory_counts_match_expectations() {
    let inventory = lgap::lowering_gap_inventory();
    assert_eq!(inventory.sites.len(), LoweringGapSiteId::ALL.len());
    assert_eq!(inventory.fail_closed_site_count(), 2);
    assert_eq!(inventory.open_placeholder_site_count(), 2);
}

#[test]
fn lowering_gap_inventory_serde_roundtrip() {
    let inventory = lgap::lowering_gap_inventory();
    let json = serde_json::to_string(&inventory).expect("serialize");
    let recovered: LoweringGapInventory = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(inventory.sites.len(), recovered.sites.len());
}

#[test]
fn lowering_gap_schema_version_constants_nonempty() {
    assert!(!LOWERING_GAP_INVENTORY_SCHEMA_VERSION.is_empty());
    assert!(!LOWERING_GAP_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!LOWERING_GAP_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!LOWERING_GAP_COMPONENT.is_empty());
    assert!(!LOWERING_GAP_POLICY_ID.is_empty());
}

#[test]
fn lowering_gap_cli_run_manifest_schema_version_is_correct() {
    let out_dir = unique_temp_dir("lowering-gap-cli-mfst");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lowering_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run lowering gap inventory binary");
    assert!(output.status.success());

    let manifest: LoweringGapInventoryRunManifest =
        serde_json::from_slice(&fs::read(out_dir.join("run_manifest.json")).unwrap())
            .expect("manifest json");
    assert_eq!(
        manifest.schema_version,
        LOWERING_GAP_RUN_MANIFEST_SCHEMA_VERSION
    );
}

#[test]
fn lowering_gap_cli_events_are_valid_jsonl() {
    let out_dir = unique_temp_dir("lowering-gap-cli-events");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lowering_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run lowering gap inventory binary");
    assert!(output.status.success());

    let events = fs::read_to_string(out_dir.join("events.jsonl")).expect("read events");
    for line in events.lines() {
        let event: serde_json::Value =
            serde_json::from_str(line).expect("each events.jsonl line should be valid json");
        assert!(event.is_object());
    }
}

#[test]
fn lowering_gap_cli_commands_txt_exists_and_nonempty() {
    let out_dir = unique_temp_dir("lowering-gap-cli-cmds");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lowering_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run lowering gap inventory binary");
    assert!(output.status.success());

    let commands = fs::read_to_string(out_dir.join("commands.txt")).expect("read commands");
    assert!(!commands.is_empty());
}

#[test]
fn lowering_gap_cli_stdout_hash_is_64_hex_chars() {
    let out_dir = unique_temp_dir("lowering-gap-cli-hash");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_lowering_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run lowering gap inventory binary");
    assert!(output.status.success());

    let cli_json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout json");
    let hash = cli_json["inventory_hash"].as_str().expect("hash");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn lowering_gap_site_id_owner_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(!site.owner().is_empty());
    }
}

#[test]
fn lowering_gap_site_id_ast_node_family_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(!site.ast_node_family().is_empty());
    }
}

#[test]
fn lowering_gap_inventory_parser_ready_count() {
    let inventory = lgap::lowering_gap_inventory();
    assert_eq!(
        inventory.parser_ready_site_count(),
        LoweringGapSiteId::ALL.len()
    );
}

#[test]
fn lowering_gap_inventory_execution_ready_count() {
    let inventory = lgap::lowering_gap_inventory();
    assert_eq!(inventory.execution_ready_site_count(), 0);
}

#[test]
fn lowering_gap_site_ids_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for site in LoweringGapSiteId::ALL {
        assert!(
            seen.insert(site.as_str()),
            "duplicate site id: {}",
            site.as_str()
        );
    }
}

#[test]
fn lowering_gap_diagnostic_codes_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for site in LoweringGapSiteId::ALL {
        assert!(
            seen.insert(site.diagnostic_code()),
            "duplicate diagnostic code: {}",
            site.diagnostic_code()
        );
    }
}

#[test]
fn lowering_gap_site_id_emitted_ir_shape_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(!site.emitted_ir_shape().is_empty());
    }
}

#[test]
fn lowering_gap_site_id_execution_consequence_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(!site.execution_consequence().is_empty());
    }
}

#[test]
fn lowering_gap_site_id_user_visible_divergence_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(!site.user_visible_divergence().is_empty());
    }
}

#[test]
fn lowering_gap_site_id_target_replacement_strategy_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(!site.target_replacement_strategy().is_empty());
    }
}

#[test]
fn lowering_gap_site_id_source_reference_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(!site.source_reference().is_empty());
    }
}

#[test]
fn lowering_gap_site_id_regression_test_hint_nonempty() {
    for site in LoweringGapSiteId::ALL {
        assert!(!site.regression_test_hint().is_empty());
    }
}

#[test]
fn lowering_gap_descriptor_serde_roundtrip() {
    for site in LoweringGapSiteId::ALL {
        let desc = LoweringGapSiteDescriptor::from_site(site);
        let json = serde_json::to_string(&desc).expect("serialize");
        let recovered: LoweringGapSiteDescriptor =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(desc.site_id, recovered.site_id);
    }
}
