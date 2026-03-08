use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::parser_gap_inventory::{
    self as pgap, ParserGapInventory, ParserGapInventoryRunManifest,
    ParserGapSiteDescriptor, ParserGapSiteId, ParserGapStage, ParserGapRemediationStatus,
    PARSER_GAP_COMPONENT, PARSER_GAP_EVENT_SCHEMA_VERSION,
    PARSER_GAP_INVENTORY_SCHEMA_VERSION, PARSER_GAP_POLICY_ID,
    PARSER_GAP_RUN_MANIFEST_SCHEMA_VERSION,
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

    let cli_json: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("stdout json");
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
        assert!(seen.insert(site.as_str()), "duplicate site id: {}", site.as_str());
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
