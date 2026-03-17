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

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn load_shape_lattice_runner_script() -> String {
    let path = repo_root().join("scripts/run_rgc_shape_transition_lattice.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn load_shape_lattice_replay_script() -> String {
    let path = repo_root().join("scripts/e2e/rgc_shape_transition_lattice_replay.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
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

#[test]
fn shape_transition_lattice_runner_is_rch_only_and_uses_repo_local_target_dir() {
    let script = load_shape_lattice_runner_script();

    assert!(
        script.contains("command -v rch"),
        "runner must fail closed when rch is unavailable"
    );
    assert!(
        script.contains("${root_dir}/target_rch_rgc_shape_transition_lattice"),
        "runner must default to a repo-local target dir"
    );
    assert!(
        script.contains("step_logs_dir=\"${run_dir}/step_logs\""),
        "runner should retain per-step logs for operator triage"
    );
    assert!(
        script.contains("rch reported local fallback; refusing local execution for heavy command"),
        "runner must reject local fallback for heavy commands"
    );
    assert!(
        script.contains("franken_shape_lattice_bundle -- --out-dir ${run_dir}"),
        "runner must publish the bundle emission command with the deterministic run directory"
    );
}

#[test]
fn shape_transition_lattice_replay_uses_latest_complete_bundle() {
    let script = load_shape_lattice_replay_script();

    assert!(
        script.contains("latest_complete_run_dir()"),
        "replay wrapper should locate the latest complete artifact directory"
    );
    assert!(
        script.contains("newest directory ${latest_artifact_dir_path} is incomplete"),
        "replay wrapper should warn when it skips an incomplete newest directory"
    );
    assert!(
        script.contains("latest manifest: ${latest_run_dir}/run_manifest.json"),
        "replay wrapper should print the latest run manifest"
    );
    assert!(
        script.contains(
            "latest shape lattice manifest: ${latest_run_dir}/shape_lattice_manifest.json"
        ),
        "replay wrapper should print the shape lattice manifest"
    );
    assert!(
        script.contains("latest events: ${latest_run_dir}/events.jsonl"),
        "replay wrapper should print the emitted events"
    );
    assert!(
        script.contains("latest commands: ${latest_run_dir}/commands.txt"),
        "replay wrapper should print the replayable commands"
    );
    assert!(
        script.contains("latest trace ids: ${latest_run_dir}/trace_ids.json"),
        "replay wrapper should print the trace identifiers"
    );
}
