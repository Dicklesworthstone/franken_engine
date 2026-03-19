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

fn load_runner_script() -> String {
    let path = repo_root().join("scripts/run_rgc_metadata_substrate_evidence.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

fn load_replay_script() -> String {
    let path = repo_root().join("scripts/e2e/metadata_substrate_evidence_replay.sh");
    fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
}

#[test]
fn metadata_substrate_evidence_binary_emits_required_bundle() {
    let out_dir = temp_dir("franken_metadata_substrate_evidence");
    let output = Command::new(env!("CARGO_BIN_EXE_franken_metadata_substrate_evidence"))
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
        Some("frankenengine.metadata-substrate-evidence-output.v1")
    );
    assert_eq!(
        stdout_json["component"].as_str(),
        Some("metadata_substrate_optimized")
    );
    assert_eq!(
        stdout_json["trace_id"].as_str(),
        Some("trace-rgc-626b-metadata-substrate-evidence")
    );
    assert_eq!(stdout_json["profiles_evaluated"].as_u64(), Some(8));
    assert_eq!(stdout_json["override_count"].as_u64(), Some(3));

    let report_path = out_dir.join("runtime_metadata_substrate_report.json");
    let evidence_manifest_path = out_dir.join("runtime_metadata_substrate_evidence_manifest.json");
    let cache_miss_path = out_dir.join("cache_miss_profile.json");
    let fallback_receipts_path = out_dir.join("metadata_fallback_receipts.json");
    let override_receipts_path = out_dir.join("substrate_override_receipts.json");
    let run_manifest_path = out_dir.join("run_manifest.json");
    let events_path = out_dir.join("events.jsonl");
    let commands_path = out_dir.join("commands.txt");
    let trace_ids_path = out_dir.join("trace_ids.json");

    for path in [
        &report_path,
        &evidence_manifest_path,
        &cache_miss_path,
        &fallback_receipts_path,
        &override_receipts_path,
        &run_manifest_path,
        &events_path,
        &commands_path,
        &trace_ids_path,
    ] {
        assert!(path.exists(), "expected {} to exist", path.display());
    }

    let report: Value =
        serde_json::from_slice(&fs::read(&report_path).expect("report should be readable"))
            .expect("report should parse");
    assert_eq!(
        report["profiles"]
            .as_array()
            .expect("profiles should be array")
            .len(),
        8
    );
    assert_eq!(report["optimized_count"].as_u64(), Some(7));
    assert_eq!(report["fallback_count"].as_u64(), Some(1));

    let manifest: Value = serde_json::from_slice(
        &fs::read(&evidence_manifest_path).expect("evidence manifest should be readable"),
    )
    .expect("evidence manifest should parse");
    assert_eq!(manifest["substrates_evaluated"].as_u64(), Some(8));
    assert_eq!(
        manifest["certificates"]
            .as_array()
            .expect("certificates should be array")
            .len(),
        8
    );

    let cache_miss_profile: Value = serde_json::from_slice(
        &fs::read(&cache_miss_path).expect("cache miss profile should be readable"),
    )
    .expect("cache miss profile should parse");
    assert!(
        cache_miss_profile
            .as_array()
            .expect("cache miss profile should be array")
            .iter()
            .any(|entry| {
                entry["substrate_id"].as_str() == Some("shape_table_primary")
                    && entry["miss_rate_millionths"].as_u64() == Some(40_000)
            })
    );

    let fallback_receipts: Value = serde_json::from_slice(
        &fs::read(&fallback_receipts_path).expect("fallback receipts should be readable"),
    )
    .expect("fallback receipts should parse");
    assert!(
        fallback_receipts
            .as_array()
            .expect("fallback receipts should be array")
            .iter()
            .any(|receipt| {
                receipt["substrate_id"].as_str() == Some("gc_mark_bitmap")
                    && receipt["fallback_active"].as_bool() == Some(true)
            })
    );

    let override_receipts: Value = serde_json::from_slice(
        &fs::read(&override_receipts_path).expect("override receipts should be readable"),
    )
    .expect("override receipts should parse");
    assert_eq!(
        override_receipts
            .as_array()
            .expect("override receipts should be array")
            .len(),
        3
    );
    assert!(
        override_receipts
            .as_array()
            .expect("override receipts should be array")
            .iter()
            .any(|receipt| {
                receipt["scenario_id"].as_str() == Some("disable-shape-table-primary")
                    && receipt["overridden_kind"].as_str() == Some("generic_fallback")
            })
    );

    let run_manifest: Value = serde_json::from_slice(
        &fs::read(&run_manifest_path).expect("run manifest should be readable"),
    )
    .expect("run manifest should parse");
    assert_eq!(
        run_manifest["artifact_paths"]["runtime_metadata_substrate_report"].as_str(),
        Some("runtime_metadata_substrate_report.json")
    );
    assert_eq!(
        run_manifest["trace_ids"][0].as_str(),
        Some("trace-rgc-626b-metadata-substrate-evidence")
    );

    let trace_ids: Value =
        serde_json::from_slice(&fs::read(&trace_ids_path).expect("trace ids should be readable"))
            .expect("trace ids should parse");
    assert_eq!(
        trace_ids["decision_ids"][0].as_str(),
        Some("decision-rgc-626b-metadata-substrate-evidence")
    );

    let events = fs::read_to_string(&events_path).expect("events should be readable");
    assert!(events.contains("\"event\":\"inventory_built\""));
    assert!(events.contains("\"event\":\"override_evaluated\""));

    let commands = fs::read_to_string(&commands_path).expect("commands should be readable");
    assert!(commands.contains("franken_metadata_substrate_evidence"));
    assert!(commands.contains("runtime_metadata_substrate_report.json"));
    assert!(commands.contains("metadata_substrate_evidence_replay.sh"));
}

#[test]
fn metadata_substrate_evidence_runner_is_rch_only_and_uses_repo_local_target_dir() {
    let script = load_runner_script();

    assert!(
        script.contains("command -v rch"),
        "runner must fail closed when rch is unavailable"
    );
    assert!(
        script.contains("target_namespace=\"${mode}_$$\""),
        "runner should namespace the target dir per mode and process"
    );
    assert!(
        script
            .contains("${root_dir}/target_rch_rgc_metadata_substrate_evidence_${target_namespace}"),
        "runner must default to a repo-local namespaced target dir"
    );
    assert!(
        script.contains("cargo_build_jobs=\"${CARGO_BUILD_JOBS:-1}\""),
        "runner should pin rch build parallelism for the large engine crate"
    );
    assert!(
        script.contains("\"CARGO_BUILD_JOBS=${cargo_build_jobs}\""),
        "runner must forward the selected build parallelism to rch"
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
        script.contains("if run_rch_strict_logged \"${log_path}\" \"$@\"; then"),
        "runner must preserve the underlying rch exit status"
    );
    assert!(
        !script.contains("if ! run_rch_strict_logged \"${log_path}\" \"$@\"; then"),
        "runner must not invert the rch step exit status before capturing it"
    );
    assert!(
        script.contains("franken_metadata_substrate_evidence -- --out-dir ${run_dir}"),
        "runner must publish the evidence command with the deterministic run directory"
    );
}

#[test]
fn metadata_substrate_evidence_replay_uses_latest_complete_bundle() {
    let script = load_replay_script();

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
            "latest runtime metadata substrate report: ${latest_run_dir}/runtime_metadata_substrate_report.json"
        ),
        "replay wrapper should print the report artifact"
    );
    assert!(
        script.contains(
            "latest fallback receipts: ${latest_run_dir}/metadata_fallback_receipts.json"
        ),
        "replay wrapper should print the fallback receipts"
    );
    assert!(
        script.contains(
            "latest override receipts: ${latest_run_dir}/substrate_override_receipts.json"
        ),
        "replay wrapper should print the override receipts"
    );
    assert!(
        script.contains("latest commands: ${latest_run_dir}/commands.txt"),
        "replay wrapper should print the replayable commands"
    );
    assert!(
        script.contains("latest trace ids: ${latest_run_dir}/trace_ids.json"),
        "replay wrapper should print the trace identifiers"
    );
    assert!(
        script.contains("latest first step log:"),
        "replay wrapper should print the first step log path when available"
    );
}
