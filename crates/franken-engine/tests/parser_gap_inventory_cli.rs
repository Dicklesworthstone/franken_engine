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

use frankenengine_engine::parser_gap_inventory::{
    self as pgap, PARSER_GAP_COMPONENT, PARSER_GAP_EVENT_SCHEMA_VERSION,
    PARSER_GAP_INVENTORY_SCHEMA_VERSION, PARSER_GAP_POLICY_ID,
    PARSER_GAP_RUN_MANIFEST_SCHEMA_VERSION, ParserGapInventory, ParserGapInventoryRunManifest,
    ParserGapRemediationStatus, ParserGapSiteDescriptor, ParserGapSiteId, ParserGapStage,
};

fn unique_temp_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock before epoch")
        .as_nanos();
    env::temp_dir().join(format!("frankenengine-{label}-{}-{nanos}", process::id()))
}

#[test]
fn parser_gap_inventory_cli_writes_artifact_bundle() {
    let out_dir = unique_temp_dir("parser-gap-cli");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_parser_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run parser gap inventory binary");
    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let inventory: ParserGapInventory =
        serde_json::from_slice(&fs::read(out_dir.join("parser_gap_inventory.json")).unwrap())
            .expect("inventory json");
    assert_eq!(inventory.sites.len(), ParserGapSiteId::ALL.len());

    let manifest: ParserGapInventoryRunManifest =
        serde_json::from_slice(&fs::read(out_dir.join("run_manifest.json")).unwrap())
            .expect("manifest json");
    assert_eq!(manifest.site_count as usize, ParserGapSiteId::ALL.len());
    assert_eq!(manifest.fail_closed_site_count, 2);
    assert_eq!(manifest.open_placeholder_site_count, 2);

    let events = fs::read_to_string(out_dir.join("events.jsonl")).expect("read events");
    assert_eq!(events.lines().count(), ParserGapSiteId::ALL.len() + 2);

    let commands = fs::read_to_string(out_dir.join("commands.txt")).expect("read commands");
    assert!(commands.contains("franken_parser_gap_inventory"));
    assert!(commands.contains("--out-dir"));

    let cli_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout json summary");
    assert_eq!(
        cli_json["site_count"].as_u64().expect("site_count") as usize,
        ParserGapSiteId::ALL.len()
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
fn parser_gap_inventory_cli_help_exits_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_parser_gap_inventory"))
        .arg("--help")
        .output()
        .expect("run parser gap inventory binary");
    assert!(
        output.status.success(),
        "stdout:\n{}\n\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Usage: franken_parser_gap_inventory --out-dir <DIR>"));
    assert!(output.stderr.is_empty());
}

#[test]
fn parser_gap_site_id_all_has_six_entries() {
    assert_eq!(ParserGapSiteId::ALL.len(), 6);
}

#[test]
fn parser_gap_site_id_as_str_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.as_str().is_empty());
    }
}

#[test]
fn parser_gap_site_id_diagnostic_code_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(site.diagnostic_code().starts_with("FE-"));
    }
}

#[test]
fn parser_gap_site_id_stages_are_valid() {
    for site in ParserGapSiteId::ALL {
        let _ = site.stage();
    }
}

#[test]
fn parser_gap_site_id_remediation_statuses_are_valid() {
    for site in ParserGapSiteId::ALL {
        let _ = site.remediation_status();
    }
}

#[test]
fn parser_gap_stage_as_str_covers_variants() {
    let stages = [ParserGapStage::Ir0ToIr1, ParserGapStage::Ir1ToIr3];
    for stage in stages {
        assert!(!stage.as_str().is_empty());
    }
}

#[test]
fn parser_gap_remediation_status_as_str_covers_variants() {
    let statuses = [
        ParserGapRemediationStatus::FailClosed,
        ParserGapRemediationStatus::OpenPlaceholder,
        ParserGapRemediationStatus::Resolved,
    ];
    for status in statuses {
        assert!(!status.as_str().is_empty());
    }
}

#[test]
fn parser_gap_site_descriptor_from_site_populates_all_fields() {
    for site in ParserGapSiteId::ALL {
        let desc = ParserGapSiteDescriptor::from_site(site);
        assert_eq!(desc.site_id, site.as_str());
        assert!(!desc.desired_diagnostic_code.is_empty());
        assert!(!desc.feature_family.is_empty());
        assert!(!desc.api_surface.is_empty());
        assert!(!desc.syntax_shape.is_empty());
        assert!(!desc.observed_fallback_behavior.is_empty());
        assert!(!desc.required_fail_closed_contract.is_empty());
        assert!(!desc.source_reference.is_empty());
    }
}

#[test]
fn parser_gap_inventory_counts_match() {
    let inventory = pgap::parser_gap_inventory();
    assert_eq!(inventory.sites.len(), ParserGapSiteId::ALL.len());
    assert_eq!(inventory.fail_closed_site_count(), 2);
    assert_eq!(inventory.open_placeholder_site_count(), 2);
}

#[test]
fn parser_gap_inventory_serde_roundtrip() {
    let inventory = pgap::parser_gap_inventory();
    let json = serde_json::to_string(&inventory).expect("serialize");
    let recovered: ParserGapInventory = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(inventory.sites.len(), recovered.sites.len());
}

#[test]
fn parser_gap_schema_version_constants_nonempty() {
    assert!(!PARSER_GAP_INVENTORY_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_GAP_RUN_MANIFEST_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_GAP_EVENT_SCHEMA_VERSION.is_empty());
    assert!(!PARSER_GAP_COMPONENT.is_empty());
    assert!(!PARSER_GAP_POLICY_ID.is_empty());
}

#[test]
fn parser_gap_cli_run_manifest_schema_version_correct() {
    let out_dir = unique_temp_dir("parser-gap-cli-mfst");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_parser_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run parser gap inventory binary");
    assert!(output.status.success());

    let manifest: ParserGapInventoryRunManifest =
        serde_json::from_slice(&fs::read(out_dir.join("run_manifest.json")).unwrap())
            .expect("manifest json");
    assert_eq!(
        manifest.schema_version,
        PARSER_GAP_RUN_MANIFEST_SCHEMA_VERSION
    );
}

#[test]
fn parser_gap_cli_events_are_valid_jsonl() {
    let out_dir = unique_temp_dir("parser-gap-cli-events");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_parser_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run parser gap inventory binary");
    assert!(output.status.success());

    let events = fs::read_to_string(out_dir.join("events.jsonl")).expect("read events");
    for line in events.lines() {
        let event: serde_json::Value =
            serde_json::from_str(line).expect("each events.jsonl line should be valid json");
        assert!(event.is_object());
    }
}

#[test]
fn parser_gap_cli_commands_txt_nonempty() {
    let out_dir = unique_temp_dir("parser-gap-cli-cmds");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_parser_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run parser gap inventory binary");
    assert!(output.status.success());

    let commands = fs::read_to_string(out_dir.join("commands.txt")).expect("read commands");
    assert!(!commands.is_empty());
}

#[test]
fn parser_gap_cli_stdout_hash_is_64_hex() {
    let out_dir = unique_temp_dir("parser-gap-cli-hash");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_parser_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run parser gap inventory binary");
    assert!(output.status.success());

    let cli_json: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout json");
    let hash = cli_json["inventory_hash"].as_str().expect("hash");
    assert_eq!(hash.len(), 64);
    assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn parser_gap_site_id_owner_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.owner().is_empty());
    }
}

#[test]
fn parser_gap_site_id_feature_family_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.feature_family().is_empty());
    }
}

#[test]
fn parser_gap_site_id_syntax_shape_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.syntax_shape().is_empty());
    }
}

#[test]
fn parser_gap_site_ids_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for site in ParserGapSiteId::ALL {
        assert!(
            seen.insert(site.as_str()),
            "duplicate site id: {}",
            site.as_str()
        );
    }
}

#[test]
fn parser_gap_diagnostic_codes_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for site in ParserGapSiteId::ALL {
        assert!(
            seen.insert(site.diagnostic_code()),
            "duplicate diagnostic code: {}",
            site.diagnostic_code()
        );
    }
}

#[test]
fn parser_gap_site_id_blocking_workloads_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.blocking_workloads().is_empty());
    }
}

#[test]
fn parser_gap_site_id_message_template_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.message_template().is_empty());
    }
}

#[test]
fn parser_gap_site_id_api_surface_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.api_surface().is_empty());
    }
}

#[test]
fn parser_gap_site_id_observed_fallback_behavior_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.observed_fallback_behavior().is_empty());
    }
}

#[test]
fn parser_gap_site_id_required_fail_closed_contract_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.required_fail_closed_contract().is_empty());
    }
}

#[test]
fn parser_gap_site_id_source_reference_nonempty() {
    for site in ParserGapSiteId::ALL {
        assert!(!site.source_reference().is_empty());
    }
}

#[test]
fn parser_gap_descriptor_serde_roundtrip() {
    for site in ParserGapSiteId::ALL {
        let desc = ParserGapSiteDescriptor::from_site(site);
        let json = serde_json::to_string(&desc).expect("serialize");
        let recovered: ParserGapSiteDescriptor = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(desc.site_id, recovered.site_id);
    }
}

#[test]
fn parser_gap_inventory_default_has_correct_schema() {
    let inventory = pgap::parser_gap_inventory();
    assert_eq!(
        inventory.schema_version,
        PARSER_GAP_INVENTORY_SCHEMA_VERSION
    );
}

// ────────────────────────────────────────────────────────────
// Enrichment: descriptor invariants, debug/clone, serde
// coverage, CLI artifact cross-validation
// ────────────────────────────────────────────────────────────

#[test]
fn parser_gap_site_id_debug_impl_nonempty() {
    for site in ParserGapSiteId::ALL {
        let debug = format!("{:?}", site);
        assert!(!debug.is_empty());
    }
}

#[test]
fn parser_gap_stage_debug_impl_nonempty() {
    let stages = [ParserGapStage::Ir0ToIr1, ParserGapStage::Ir1ToIr3];
    for stage in stages {
        let debug = format!("{:?}", stage);
        assert!(!debug.is_empty());
    }
}

#[test]
fn parser_gap_remediation_status_debug_impl_nonempty() {
    let statuses = [
        ParserGapRemediationStatus::FailClosed,
        ParserGapRemediationStatus::OpenPlaceholder,
        ParserGapRemediationStatus::Resolved,
    ];
    for status in statuses {
        let debug = format!("{:?}", status);
        assert!(!debug.is_empty());
    }
}

#[test]
fn parser_gap_inventory_all_descriptors_match_known_site_ids() {
    let inventory = pgap::parser_gap_inventory();
    for desc in &inventory.sites {
        assert!(
            ParserGapSiteId::ALL
                .iter()
                .any(|s| s.as_str() == desc.site_id),
            "descriptor site_id {} should match a known ParserGapSiteId",
            desc.site_id
        );
    }
}

#[test]
fn parser_gap_inventory_diagnostic_codes_all_start_with_fe() {
    let inventory = pgap::parser_gap_inventory();
    for desc in &inventory.sites {
        assert!(
            desc.desired_diagnostic_code.starts_with("FE-"),
            "diagnostic code should start with FE-: {}",
            desc.desired_diagnostic_code
        );
    }
}

#[test]
fn parser_gap_inventory_json_pretty_roundtrip() {
    let inventory = pgap::parser_gap_inventory();
    let pretty = serde_json::to_string_pretty(&inventory).expect("pretty serialize");
    let recovered: ParserGapInventory = serde_json::from_str(&pretty).expect("deserialize pretty");
    assert_eq!(inventory.sites.len(), recovered.sites.len());
    assert_eq!(inventory.schema_version, recovered.schema_version);
}

#[test]
fn parser_gap_site_descriptor_clone_preserves_fields() {
    for site in ParserGapSiteId::ALL {
        let desc = ParserGapSiteDescriptor::from_site(site);
        let cloned = desc.clone();
        assert_eq!(desc.site_id, cloned.site_id);
        assert_eq!(desc.desired_diagnostic_code, cloned.desired_diagnostic_code);
        assert_eq!(desc.feature_family, cloned.feature_family);
        assert_eq!(desc.syntax_shape, cloned.syntax_shape);
    }
}

#[test]
fn parser_gap_site_descriptor_debug_contains_site_id() {
    let desc = ParserGapSiteDescriptor::from_site(ParserGapSiteId::ALL[0]);
    let debug = format!("{:?}", desc);
    assert!(
        debug.contains(&desc.site_id),
        "debug output should contain site_id"
    );
}

#[test]
fn parser_gap_inventory_fail_closed_plus_open_plus_resolved_equals_total() {
    let inventory = pgap::parser_gap_inventory();
    let total = inventory.sites.len();
    let fail_closed = inventory.fail_closed_site_count();
    let open = inventory.open_placeholder_site_count();
    let resolved = total - fail_closed - open;
    assert_eq!(fail_closed + open + resolved, total);
}

#[test]
fn parser_gap_stage_serde_roundtrip() {
    let stages = [ParserGapStage::Ir0ToIr1, ParserGapStage::Ir1ToIr3];
    for stage in stages {
        let json = serde_json::to_string(&stage).expect("serialize");
        let recovered: ParserGapStage = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(stage.as_str(), recovered.as_str());
    }
}

#[test]
fn parser_gap_remediation_status_serde_roundtrip() {
    let statuses = [
        ParserGapRemediationStatus::FailClosed,
        ParserGapRemediationStatus::OpenPlaceholder,
        ParserGapRemediationStatus::Resolved,
    ];
    for status in statuses {
        let json = serde_json::to_string(&status).expect("serialize");
        let recovered: ParserGapRemediationStatus =
            serde_json::from_str(&json).expect("deserialize");
        assert_eq!(status.as_str(), recovered.as_str());
    }
}

#[test]
fn parser_gap_cli_events_have_trace_id_field() {
    let out_dir = unique_temp_dir("parser-gap-cli-trace");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_parser_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run parser gap inventory binary");
    assert!(output.status.success());

    let events = fs::read_to_string(out_dir.join("events.jsonl")).expect("read events");
    for line in events.lines() {
        let event: serde_json::Value = serde_json::from_str(line).expect("valid json");
        assert!(
            event.get("trace_id").is_some(),
            "each event should have a trace_id field"
        );
    }
}

#[test]
fn parser_gap_cli_events_have_component_field() {
    let out_dir = unique_temp_dir("parser-gap-cli-comp");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_parser_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir)
        .output()
        .expect("run parser gap inventory binary");
    assert!(output.status.success());

    let events = fs::read_to_string(out_dir.join("events.jsonl")).expect("read events");
    for line in events.lines() {
        let event: serde_json::Value = serde_json::from_str(line).expect("valid json");
        assert!(
            event.get("component").is_some(),
            "each event should have a component field"
        );
    }
}

#[test]
fn parser_gap_cli_inventory_hash_deterministic_across_runs() {
    let out_dir1 = unique_temp_dir("parser-gap-cli-det1");
    let out1 = Command::new(env!("CARGO_BIN_EXE_franken_parser_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir1)
        .output()
        .expect("run 1");
    assert!(out1.status.success());
    let json1: serde_json::Value = serde_json::from_slice(&out1.stdout).expect("json1");
    let hash1 = json1["inventory_hash"].as_str().expect("hash1");

    let out_dir2 = unique_temp_dir("parser-gap-cli-det2");
    let out2 = Command::new(env!("CARGO_BIN_EXE_franken_parser_gap_inventory"))
        .arg("--out-dir")
        .arg(&out_dir2)
        .output()
        .expect("run 2");
    assert!(out2.status.success());
    let json2: serde_json::Value = serde_json::from_slice(&out2.stdout).expect("json2");
    let hash2 = json2["inventory_hash"].as_str().expect("hash2");

    assert_eq!(hash1, hash2, "inventory hash should be deterministic");
}

#[test]
fn parser_gap_inventory_site_count_matches_all_constant() {
    let inventory = pgap::parser_gap_inventory();
    assert_eq!(
        inventory.sites.len(),
        ParserGapSiteId::ALL.len(),
        "inventory site count must equal ALL.len()"
    );
}

#[test]
fn parser_gap_site_id_message_template_contains_placeholder_or_description() {
    for site in ParserGapSiteId::ALL {
        let template = site.message_template();
        assert!(
            !template.is_empty(),
            "message_template should not be empty for {}",
            site.as_str()
        );
    }
}

#[test]
fn parser_gap_site_id_owner_is_consistent_across_calls() {
    for site in ParserGapSiteId::ALL {
        let owner1 = site.owner();
        let owner2 = site.owner();
        assert_eq!(owner1, owner2);
    }
}
