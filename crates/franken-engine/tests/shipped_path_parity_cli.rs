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
fn shipped_path_parity_binary_emits_artifacts_and_zero_mismatches() {
    let out_dir = temp_dir("franken_shipped_path_parity");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_shipped_path_parity"))
        .args([
            "--frankenctl-bin",
            env!("CARGO_BIN_EXE_frankenctl"),
            "--out-dir",
            out_dir.to_str().expect("path should be utf8"),
            "--fail-on-mismatch",
        ])
        .output()
        .expect("parity binary should execute");

    assert!(
        output.status.success(),
        "parity binary failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout_json: Value =
        serde_json::from_slice(&output.stdout).expect("stdout should be valid json");
    assert_eq!(
        stdout_json["schema_version"].as_str(),
        Some("franken-engine.shipped-path-parity.v1")
    );
    assert_eq!(stdout_json["mismatch_count"].as_u64(), Some(0));
    assert_eq!(stdout_json["contract_satisfied"].as_bool(), Some(true));

    let run_dir = PathBuf::from(
        stdout_json["run_dir"]
            .as_str()
            .expect("run_dir should be present"),
    );
    let report_path = run_dir.join("parity_report.json");
    let trace_ids_path = run_dir.join("trace_ids.json");
    let manifest_path = run_dir.join("run_manifest.json");
    let events_path = run_dir.join("events.jsonl");
    let commands_path = run_dir.join("commands.txt");

    assert!(report_path.exists(), "parity report should exist");
    assert!(trace_ids_path.exists(), "trace_ids should exist");
    assert!(manifest_path.exists(), "run manifest should exist");
    assert!(events_path.exists(), "events should exist");
    assert!(commands_path.exists(), "commands should exist");

    let report_json: Value =
        serde_json::from_slice(&fs::read(&report_path).expect("report should be readable"))
            .expect("report should parse");
    assert_eq!(
        report_json["component"].as_str(),
        Some("shipped_path_parity")
    );
    assert_eq!(report_json["specimen_count"].as_u64(), Some(9));
    assert_eq!(report_json["js_specimen_count"].as_u64(), Some(6));
    assert_eq!(report_json["ts_specimen_count"].as_u64(), Some(3));
    assert_eq!(report_json["mismatch_count"].as_u64(), Some(0));
    assert!(
        report_json["specimens"]
            .as_array()
            .expect("specimens should be an array")
            .iter()
            .any(|specimen| {
                specimen["command_family"].as_str() == Some("verify_compile_artifact")
            }),
        "parity report should include verify compile-artifact specimens"
    );

    let events = fs::read_to_string(&events_path).expect("events should be readable");
    assert!(events.contains("shipped_path_parity_started"));
    assert!(events.contains("shipped_path_parity_completed"));

    let commands = fs::read_to_string(&commands_path).expect("commands should be readable");
    assert!(commands.contains("frankenctl"));
    assert!(commands.contains("compile"));
    assert!(commands.contains("run"));
    assert!(commands.contains("verify compile-artifact"));
}
