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
fn shape_transition_lattice_binary_emits_required_bundle() {
    let out_dir = temp_dir("franken_shape_lattice_bundle");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_shape_lattice_bundle"))
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
        Some("frankenengine.shape-lattice.bundle-output.v1")
    );
    assert_eq!(
        stdout_json["component"].as_str(),
        Some("shape_transition_algebra")
    );
    assert_eq!(
        stdout_json["trace_id"].as_str(),
        Some("trace-rgc-606a-shape-lattice")
    );
    assert_eq!(stdout_json["shape_count"].as_u64(), Some(3));
    assert_eq!(stdout_json["transition_count"].as_u64(), Some(3));
    assert_eq!(stdout_json["receipt_count"].as_u64(), Some(3));
    assert_eq!(stdout_json["result_kind"].as_str(), Some("int"));

    let shape_manifest_path = out_dir.join("shape_lattice_manifest.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let trace_ids_path = out_dir.join("trace_ids.json");

    for path in [
        &shape_manifest_path,
        &run_manifest_path,
        &events_path,
        &commands_path,
        &trace_ids_path,
    ] {
        assert!(path.exists(), "expected {} to exist", path.display());
    }

    let shape_manifest: Value = serde_json::from_slice(
        &fs::read(&shape_manifest_path).expect("manifest should be readable"),
    )
    .expect("manifest should parse");
    assert_eq!(
        shape_manifest["component"].as_str(),
        Some("shape_transition_algebra")
    );
    assert_eq!(
        shape_manifest["transitions"]
            .as_array()
            .expect("transitions should be an array")
            .len(),
        3
    );
    assert!(
        shape_manifest["transitions"]
            .as_array()
            .expect("transitions should be an array")
            .iter()
            .any(|transition| transition["transition_kind"].as_str() == Some("AddProperty"))
    );
    assert!(
        shape_manifest["transitions"]
            .as_array()
            .expect("transitions should be an array")
            .iter()
            .any(|transition| transition["transition_kind"].as_str() == Some("PropertyCellWrite"))
    );

    let run_manifest: Value = serde_json::from_slice(
        &fs::read(&run_manifest_path).expect("run manifest should be readable"),
    )
    .expect("run manifest should parse");
    assert_eq!(
        run_manifest["artifact_paths"]["shape_lattice_manifest"].as_str(),
        Some("shape_lattice_manifest.json")
    );
    assert_eq!(
        run_manifest["trace_ids"][0].as_str(),
        Some("trace-rgc-606a-shape-lattice")
    );

    let trace_ids: Value =
        serde_json::from_slice(&fs::read(&trace_ids_path).expect("trace ids should be readable"))
            .expect("trace ids should parse");
    assert_eq!(
        trace_ids["decision_ids"][0].as_str(),
        Some("decision-rgc-606a-shape-lattice")
    );

    let events = fs::read_to_string(&events_path).expect("events should be readable");
    assert!(events.contains("\"transition_kind\":\"AddProperty\""));
    assert!(events.contains("\"transition_kind\":\"PropertyCellWrite\""));

    let commands = fs::read_to_string(&commands_path).expect("commands should be readable");
    assert!(commands.contains("franken_shape_lattice_bundle"));
    assert!(commands.contains("shape_lattice_manifest.json"));
    assert!(commands.contains("rgc_shape_transition_lattice_replay.sh"));
}
