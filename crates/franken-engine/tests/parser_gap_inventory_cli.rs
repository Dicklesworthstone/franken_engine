use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::parser_gap_inventory::{
    ParserGapInventory, ParserGapInventoryRunManifest, ParserGapSiteId,
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
    assert_eq!(manifest.fail_closed_site_count, 4);
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
