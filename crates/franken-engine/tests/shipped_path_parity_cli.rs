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

fn load_runner_script() -> String {
    fs::read_to_string("../../scripts/run_franken_shipped_path_parity.sh")
        .expect("runner script should be readable")
}

fn load_replay_script() -> String {
    fs::read_to_string("../../scripts/e2e/franken_shipped_path_parity_replay.sh")
        .expect("replay script should be readable")
}

#[test]
fn shipped_path_parity_binary_emits_artifacts_and_classifies_divergences() {
    let out_dir = temp_dir("franken_shipped_path_parity");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_shipped_path_parity"))
        .args([
            "--frankenctl-bin",
            env!("CARGO_BIN_EXE_frankenctl"),
            "--out-dir",
            out_dir.to_str().expect("path should be utf8"),
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
    let mismatch_count = stdout_json["mismatch_count"]
        .as_u64()
        .expect("mismatch count should be present");
    assert_eq!(
        stdout_json["contract_satisfied"].as_bool(),
        Some(mismatch_count == 0)
    );

    let run_dir = PathBuf::from(
        stdout_json["run_dir"]
            .as_str()
            .expect("run_dir should be present"),
    );
    let report_path = run_dir.join("parity_report.json");
    let matrix_report_path = run_dir.join("parity_matrix_report.json");
    let trace_ids_path = run_dir.join("trace_ids.json");
    let mismatch_catalog_path = run_dir.join("shipped_path_mismatch_catalog.json");
    let operator_summary_path = run_dir.join("shipped_path_operator_summary.json");
    let manifest_path = run_dir.join("run_manifest.json");
    let events_path = run_dir.join("events.jsonl");
    let commands_path = run_dir.join("commands.txt");

    assert!(report_path.exists(), "parity report should exist");
    assert!(
        matrix_report_path.exists(),
        "parity matrix report should exist"
    );
    assert_eq!(
        stdout_json["matrix_report_path"].as_str(),
        Some(matrix_report_path.to_str().expect("path should be utf8"))
    );
    assert!(trace_ids_path.exists(), "trace_ids should exist");
    assert!(
        mismatch_catalog_path.exists(),
        "mismatch catalog should exist"
    );
    assert!(
        operator_summary_path.exists(),
        "operator summary should exist"
    );
    assert!(manifest_path.exists(), "run manifest should exist");
    assert!(events_path.exists(), "events should exist");
    assert!(commands_path.exists(), "commands should exist");

    let run_manifest: Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("run manifest should be readable"))
            .expect("run manifest should parse");
    let expected_replay = format!(
        "FRANKEN_SHIPPED_PATH_PARITY_REPLAY_RUN_DIR={} ./scripts/e2e/franken_shipped_path_parity_replay.sh",
        run_dir.display()
    );
    assert_eq!(
        run_manifest["replay_command"].as_str(),
        Some(expected_replay.as_str())
    );

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
    assert_eq!(report_json["mismatch_count"].as_u64(), Some(mismatch_count));
    assert_eq!(
        report_json["contract_satisfied"].as_bool(),
        Some(mismatch_count == 0)
    );
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

    let matrix_report_json: Value = serde_json::from_slice(
        &fs::read(&matrix_report_path).expect("matrix report should be readable"),
    )
    .expect("matrix report should parse");
    let matrix_mismatch_count = matrix_report_json["total_mismatches"]
        .as_u64()
        .expect("matrix mismatch count should be present");
    assert!(
        matrix_mismatch_count >= mismatch_count,
        "matrix should retain at least the parity-report mismatch classifications"
    );
    assert_eq!(
        matrix_report_json["overall_verdict"].as_str(),
        Some(if mismatch_count == 0 { "pass" } else { "fail" })
    );
    assert_eq!(
        matrix_report_json["receipt"]["component"].as_str(),
        Some("shipped_path_matrix")
    );
    let matrix_cells = matrix_report_json["cells"]
        .as_array()
        .expect("matrix cells should be an array");
    assert!(
        matrix_cells
            .iter()
            .any(|cell| cell["workload_class"].as_str() == Some("pure_js")),
        "matrix report should include the JS workload cell"
    );
    assert!(
        matrix_cells
            .iter()
            .any(|cell| cell["workload_class"].as_str() == Some("pure_ts")),
        "matrix report should include the TS workload cell"
    );

    let mismatch_catalog_json: Value = serde_json::from_slice(
        &fs::read(&mismatch_catalog_path).expect("mismatch catalog should be readable"),
    )
    .expect("mismatch catalog should parse");
    assert_eq!(
        mismatch_catalog_json["schema_version"].as_str(),
        Some("franken-engine.shipped-path-parity.mismatch-catalog.v1")
    );
    assert_eq!(
        mismatch_catalog_json["mismatch_count"].as_u64(),
        Some(mismatch_count)
    );
    let mismatches = mismatch_catalog_json["mismatches"]
        .as_array()
        .expect("mismatches should be an array");
    assert_eq!(mismatches.len() as u64, mismatch_count);
    if mismatch_count > 0 {
        assert!(
            mismatches.iter().all(|mismatch| {
                mismatch["mismatch_kind"].as_str().is_some()
                    && mismatch["triage_category"].as_str().is_some()
                    && mismatch["owner_route"].as_str().is_some()
            }),
            "every mismatch should carry explicit classification and owner routing"
        );
    }

    let operator_summary_json: Value = serde_json::from_slice(
        &fs::read(&operator_summary_path).expect("operator summary should be readable"),
    )
    .expect("operator summary should parse");
    assert_eq!(
        operator_summary_json["schema_version"].as_str(),
        Some("franken-engine.shipped-path-parity.operator-summary.v1")
    );
    assert_eq!(
        operator_summary_json["status"].as_str(),
        Some(if mismatch_count == 0 {
            "pass"
        } else {
            "fail_closed"
        })
    );
    assert_eq!(
        operator_summary_json["contract_satisfied"].as_bool(),
        Some(mismatch_count == 0)
    );
    assert_eq!(
        operator_summary_json["mismatch_count"].as_u64(),
        Some(mismatch_count)
    );
    assert!(
        operator_summary_json["triage_category_counts"].is_object(),
        "operator summary should expose triage-category counts"
    );
    assert!(
        operator_summary_json["owner_route_counts"].is_object(),
        "operator summary should expose owner-route counts"
    );
    let summary_lines = operator_summary_json["summary_lines"]
        .as_array()
        .expect("summary lines should be an array");
    if mismatch_count == 0 {
        assert!(
            summary_lines.iter().any(|line| line
                .as_str()
                .unwrap()
                .contains("no shipped-path mismatches detected")),
            "operator summary should include the zero-mismatch operator verdict"
        );
    } else {
        assert!(
            summary_lines
                .iter()
                .any(|line| line.as_str().unwrap().contains("blocking specimens")),
            "operator summary should include fail-closed blocking guidance"
        );
    }

    let events = fs::read_to_string(&events_path).expect("events should be readable");
    assert!(events.contains("shipped_path_parity_started"));
    assert!(events.contains("shipped_path_parity_completed"));

    let commands = fs::read_to_string(&commands_path).expect("commands should be readable");
    assert!(commands.contains("frankenctl"));
    assert!(commands.contains("compile"));
    assert!(commands.contains("run"));
    assert!(commands.contains("verify compile-artifact"));
    assert!(commands.contains("franken_shipped_path_parity_replay.sh"));
    assert!(commands.contains(&format!(
        "FRANKEN_SHIPPED_PATH_PARITY_REPLAY_RUN_DIR={} ./scripts/e2e/franken_shipped_path_parity_replay.sh",
        run_dir.display()
    )));
    assert!(
        !commands.contains("./scripts/e2e/franken_shipped_path_parity_replay.sh run"),
        "commands.txt should not point replay at the default artifact root via a generic rerun"
    );
}

#[test]
fn shipped_path_parity_runner_script_uses_unique_repo_local_namespaces() {
    let script = load_runner_script();

    for snippet in [
        "rch is required",
        "rch exec -- env CARGO_TARGET_DIR=\"${target_dir}\"",
        ".rch_target/franken_shipped_path_parity_uid",
        "${artifact_root}/${timestamp}_uid${uid}_${mode}_$$",
        "run_rch bash -lc '",
        "cargo build -p frankenengine-engine --bin frankenctl --bin franken_shipped_path_parity",
        "\"$CARGO_TARGET_DIR\"/debug/franken_shipped_path_parity",
        "--frankenctl-bin \"$CARGO_TARGET_DIR\"/debug/frankenctl",
    ] {
        assert!(
            script.contains(snippet),
            "runner script missing required snippet: {snippet}"
        );
    }

    assert!(
        !script.contains("target_rch_franken_shipped_path_parity"),
        "runner script must not default to a shared fixed target dir"
    );
    assert!(
        !script.contains("\"${target_dir}/debug/franken_shipped_path_parity\""),
        "runner script must not assume remote-built shipped-path parity binaries exist locally"
    );
    assert!(
        !script.contains("\"${target_dir}/debug/frankenctl\""),
        "runner script must not assume remote-built frankenctl binaries exist locally"
    );
    assert!(
        !script.contains("${artifact_root}/${run_stamp}"),
        "runner script must not use a timestamp-only artifact namespace"
    );
}

#[test]
fn shipped_path_parity_replay_wrapper_uses_latest_complete_bundle_and_prints_new_artifacts() {
    let script = load_replay_script();

    for snippet in [
        "run_dir_is_complete()",
        "latest_complete_run_dir()",
        "FRANKEN_SHIPPED_PATH_PARITY_REPLAY_RUN_DIR",
        "explicit run directory is incomplete",
        "newest directory ${latest_artifact_dir_path} is incomplete",
        "warn_about_failed_gate_replay_source()",
        "replay output reflects latest complete run directory",
        "replay output reflects current run directory",
        "run_manifest.json",
        "trace_ids.json",
        "latest trace ids: ${latest_run_dir}/trace_ids.json",
        "events.jsonl",
        "commands.txt",
        "parity_report.json",
        "parity_matrix_report.json",
        "shipped_path_mismatch_catalog.json",
        "shipped_path_operator_summary.json",
    ] {
        assert!(
            script.contains(snippet),
            "replay script missing required snippet: {snippet}"
        );
    }
}
