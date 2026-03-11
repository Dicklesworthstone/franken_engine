#![forbid(unsafe_code)]
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

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::Value;

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    path.push(format!("{name}_{}_{}", std::process::id(), nonce));
    fs::create_dir_all(&path).expect("temp dir should be creatable");
    path
}

#[test]
fn npm_compatibility_matrix_binary_emits_artifacts_and_owner_routing() {
    let out_dir = temp_dir("franken_npm_compatibility_matrix");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_npm_compatibility_matrix"))
        .args(["--out-dir", out_dir.to_str().expect("path should be utf8")])
        .output()
        .expect("binary should execute");

    assert!(
        output.status.success(),
        "binary failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json: Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid json");
    assert_eq!(
        stdout_json["schema_version"].as_str(),
        Some("franken-engine.franken_npm_compatibility_matrix.v1")
    );
    assert_eq!(stdout_json["verdict"].as_str(), Some("blocked"));
    assert_eq!(stdout_json["package_count"].as_u64(), Some(20));
    assert_eq!(stdout_json["incompatibility_count"].as_u64(), Some(8));

    let report_path = out_dir.join("npm_compat_matrix_report.json");
    let trace_ids_path = out_dir.join("trace_ids.json");
    let manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");

    assert!(report_path.exists(), "report should exist");
    assert!(trace_ids_path.exists(), "trace ids should exist");
    assert!(manifest_path.exists(), "run manifest should exist");
    assert!(events_path.exists(), "events should exist");
    assert!(commands_path.exists(), "commands should exist");

    let report_json: Value =
        serde_json::from_slice(&fs::read(&report_path).expect("report should be readable"))
            .expect("report should parse");
    assert_eq!(
        report_json["component"].as_str(),
        Some("npm_compatibility_matrix")
    );
    assert_eq!(report_json["verdict"].as_str(), Some("blocked"));
    assert_eq!(report_json["package_count"].as_u64(), Some(20));
    assert_eq!(report_json["incompatibility_count"].as_u64(), Some(8));
    assert!(
        report_json["cohort_summaries"]
            .as_array()
            .expect("cohort summaries should be an array")
            .iter()
            .any(|summary| summary["tier"].as_str() == Some("tier_1_critical")),
        "report should include tier 1 summary"
    );
    assert!(
        report_json["unresolved_failures"]
            .as_array()
            .expect("unresolved failures should be an array")
            .iter()
            .any(|failure| {
                failure["package_name"].as_str() == Some("prisma")
                    && failure["related_beads"]
                        .as_array()
                        .expect("related beads should be an array")
                        .iter()
                        .any(|bead| bead.as_str() == Some("bd-1lsy.5.9.1"))
            }),
        "report should route native-addon failures to the native-addon bead"
    );

    let trace_ids_json: Value =
        serde_json::from_slice(&fs::read(&trace_ids_path).expect("trace ids should be readable"))
            .expect("trace ids should parse");
    assert_eq!(
        trace_ids_json["scenario_id"].as_str(),
        Some("rgc-404-npm-compatibility-matrix")
    );

    let manifest_json: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("manifest should be readable"))
            .expect("manifest should parse");
    assert_eq!(
        manifest_json["artifact_paths"]["npm_compat_matrix_report"].as_str(),
        Some("npm_compat_matrix_report.json")
    );

    let events = fs::read_to_string(&events_path).expect("events should be readable");
    assert!(events.contains("npm_compatibility_matrix_started"));
    assert!(events.contains("package_outcome_recorded"));
    assert!(events.contains("owner_routing_recorded"));
    assert!(events.contains("npm_compatibility_matrix_completed"));

    let commands = fs::read_to_string(&commands_path).expect("commands should be readable");
    assert!(commands.contains("franken_npm_compatibility_matrix"));
    assert!(commands.contains("npm_compat_matrix_report.json"));
    assert!(commands.contains("rgc_npm_compatibility_matrix_replay.sh"));
}
