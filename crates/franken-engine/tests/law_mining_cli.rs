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
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn parse_stdout_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).expect("stdout should contain valid json")
}

fn assert_artifacts_exist(artifact_dir: &Path) {
    for required in [
        "candidate_law_catalog.json",
        "invariant_seed_ledger.json",
        "normal_form_hypotheses.json",
        "law_provenance_index.json",
        "candidate_scope_hypotheses.json",
        "trace_ids.json",
        "run_manifest.json",
        "events.jsonl",
        "commands.txt",
        "env.json",
        "manifest.json",
        "repro.lock",
        "summary.md",
    ] {
        assert!(
            artifact_dir.join(required).exists(),
            "missing required artifact {required}"
        );
    }
}

#[test]
fn franken_law_mining_writes_bundle_summary_json() {
    let artifact_dir = temp_dir("franken_law_mining_bundle");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--trace-id",
            "trace-law-cli",
            "--decision-id",
            "decision-law-cli",
            "--policy-id",
            "policy-law-cli",
            "--run-id",
            "run-law-cli",
            "--generated-at-utc",
            "2026-03-08T00:00:00Z",
            "--source-commit",
            "deadbeef",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining command should execute");

    assert!(
        output.status.success(),
        "law mining failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json = parse_stdout_json(&output);
    assert_eq!(
        json["candidate_law_catalog_path"].as_str(),
        artifact_dir.join("candidate_law_catalog.json").to_str()
    );
    assert_eq!(
        json["run_manifest_path"].as_str(),
        artifact_dir.join("run_manifest.json").to_str()
    );

    assert_artifacts_exist(&artifact_dir);
}

#[test]
fn franken_law_mining_summary_mode_prints_summary_markdown() {
    let artifact_dir = temp_dir("franken_law_mining_summary");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--summary",
        ])
        .output()
        .expect("law mining summary command should execute");

    assert!(
        output.status.success(),
        "law mining summary failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout should be utf8");
    assert!(stdout.contains("# Law Mining Summary"));
    assert!(stdout.contains("## Top Candidate"));

    assert_artifacts_exist(&artifact_dir);

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("decode run manifest");
    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("franken-engine.law-mining.run-manifest.v1")
    );
}

#[test]
fn franken_law_mining_help_exits_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .arg("--help")
        .output()
        .expect("law mining help should execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("franken_law_mining usage:"));
    assert!(stdout.contains("--artifact-dir"));
}

#[test]
fn franken_law_mining_no_args_fails_with_usage() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .output()
        .expect("law mining no args should execute");
    assert!(!output.status.success());
}

#[test]
fn franken_law_mining_unknown_flag_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .arg("--bogus-flag")
        .output()
        .expect("law mining unknown flag should execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown flag"));
}

#[test]
fn franken_law_mining_artifact_dir_missing_value_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .arg("--artifact-dir")
        .output()
        .expect("law mining missing value should execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires"));
}

#[test]
fn franken_law_mining_bundle_json_output_has_expected_keys() {
    let artifact_dir = temp_dir("franken_law_mining_keys");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--trace-id",
            "trace-key-test",
            "--decision-id",
            "decision-key-test",
            "--policy-id",
            "policy-key-test",
            "--run-id",
            "run-key-test",
            "--generated-at-utc",
            "2026-03-08T01:00:00Z",
            "--source-commit",
            "abcdef12",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining keys test should execute");

    assert!(
        output.status.success(),
        "failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: serde_json::Value = parse_stdout_json(&output);
    assert!(json["candidate_law_catalog_path"].is_string());
    assert!(json["run_manifest_path"].is_string());
}

#[test]
fn franken_law_mining_artifacts_include_all_required_files() {
    let artifact_dir = temp_dir("franken_law_mining_all");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-all-test",
            "--generated-at-utc",
            "2026-03-08T02:00:00Z",
            "--source-commit",
            "face1234",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining all artifacts test should execute");

    assert!(
        output.status.success(),
        "failed with stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );

    assert_artifacts_exist(&artifact_dir);
}

#[test]
fn franken_law_mining_events_jsonl_has_structured_events() {
    let artifact_dir = temp_dir("franken_law_mining_events");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--trace-id",
            "trace-events-test",
            "--decision-id",
            "decision-events-test",
            "--policy-id",
            "policy-events-test",
            "--run-id",
            "run-events-test",
            "--generated-at-utc",
            "2026-03-08T03:00:00Z",
            "--source-commit",
            "11111111",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining events test should execute");

    assert!(output.status.success());

    let events = fs::read_to_string(artifact_dir.join("events.jsonl")).expect("read events");
    assert!(!events.is_empty());
    for line in events.lines() {
        let event: serde_json::Value =
            serde_json::from_str(line).expect("each events.jsonl line should be valid json");
        assert!(event.is_object());
    }
}

#[test]
fn franken_law_mining_commands_txt_records_invocation() {
    let artifact_dir = temp_dir("franken_law_mining_cmds");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-cmds-test",
            "--generated-at-utc",
            "2026-03-08T04:00:00Z",
            "--source-commit",
            "22222222",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining commands test should execute");

    assert!(output.status.success());

    let commands = fs::read_to_string(artifact_dir.join("commands.txt")).expect("read commands");
    assert!(commands.contains("franken_law_mining"));
}

#[test]
fn franken_law_mining_trace_ids_json_is_valid() {
    let artifact_dir = temp_dir("franken_law_mining_trace");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--trace-id",
            "trace-trace-test",
            "--run-id",
            "run-trace-test",
            "--generated-at-utc",
            "2026-03-08T05:00:00Z",
            "--source-commit",
            "33333333",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining trace ids test should execute");

    assert!(output.status.success());

    let trace_ids: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("trace_ids.json")).expect("read trace ids"),
    )
    .expect("trace ids parse");
    assert!(trace_ids["trace_id"].is_string());
}

#[test]
fn franken_law_mining_env_json_is_valid() {
    let artifact_dir = temp_dir("franken_law_mining_env");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-env-test",
            "--generated-at-utc",
            "2026-03-08T06:00:00Z",
            "--source-commit",
            "44444444",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining env test should execute");

    assert!(output.status.success());

    let env_json: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("env.json")).expect("read env json"))
            .expect("env json parse");
    assert!(env_json.is_object());
}

#[test]
fn franken_law_mining_manifest_json_references_artifacts() {
    let artifact_dir = temp_dir("franken_law_mining_mfst");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-mfst-test",
            "--generated-at-utc",
            "2026-03-08T07:00:00Z",
            "--source-commit",
            "55555555",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining manifest test should execute");

    assert!(output.status.success());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("manifest.json")).expect("read manifest"),
    )
    .expect("manifest parse");
    let artifacts = manifest["artifacts"].as_array().expect("artifacts array");
    assert!(!artifacts.is_empty());
}

#[test]
fn franken_law_mining_repro_lock_is_valid_json() {
    let artifact_dir = temp_dir("franken_law_mining_repro");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-repro-test",
            "--generated-at-utc",
            "2026-03-08T08:00:00Z",
            "--source-commit",
            "66666666",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining repro lock test should execute");

    assert!(output.status.success());

    let repro = fs::read_to_string(artifact_dir.join("repro.lock")).expect("read repro.lock");
    assert!(!repro.is_empty());
    assert!(repro.contains("repro lock"));
}

#[test]
fn franken_law_mining_summary_md_not_empty() {
    let artifact_dir = temp_dir("franken_law_mining_sum");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-sum-test",
            "--generated-at-utc",
            "2026-03-08T09:00:00Z",
            "--source-commit",
            "77777777",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining summary md test should execute");

    assert!(output.status.success());

    let summary = fs::read_to_string(artifact_dir.join("summary.md")).expect("read summary");
    assert!(!summary.is_empty());
    assert!(summary.contains("Law Mining"));
}

#[test]
fn franken_law_mining_candidate_law_catalog_has_candidates() {
    let artifact_dir = temp_dir("franken_law_mining_cat");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-cat-test",
            "--generated-at-utc",
            "2026-03-08T10:00:00Z",
            "--source-commit",
            "88888888",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining catalog test should execute");

    assert!(output.status.success());

    let catalog: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("candidate_law_catalog.json")).expect("read catalog"),
    )
    .expect("catalog parse");
    assert!(catalog["candidates"].is_array());
}

#[test]
fn franken_law_mining_invariant_seed_ledger_exists() {
    let artifact_dir = temp_dir("franken_law_mining_seed");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-seed-test",
            "--generated-at-utc",
            "2026-03-08T11:00:00Z",
            "--source-commit",
            "99999999",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining seed test should execute");

    assert!(output.status.success());

    let seed: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("invariant_seed_ledger.json")).expect("read seed ledger"),
    )
    .expect("seed ledger parse");
    assert!(seed.is_object());
}

#[test]
fn franken_law_mining_normal_form_hypotheses_exists() {
    let artifact_dir = temp_dir("franken_law_mining_nf");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-nf-test",
            "--generated-at-utc",
            "2026-03-08T12:00:00Z",
            "--source-commit",
            "aaaaaaaa",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining nf test should execute");

    assert!(output.status.success());

    let nf: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("normal_form_hypotheses.json")).expect("read normal form"),
    )
    .expect("normal form parse");
    assert!(nf.is_object());
}

#[test]
fn franken_law_mining_help_flag_h_works() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .arg("-h")
        .output()
        .expect("law mining -h should execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--artifact-dir"));
}

#[test]
fn franken_law_mining_help_word_works() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .arg("help")
        .output()
        .expect("law mining help word should execute");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--artifact-dir"));
}

#[test]
fn franken_law_mining_run_manifest_has_trace_id() {
    let artifact_dir = temp_dir("franken_law_mining_tid");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--trace-id",
            "trace-tid-check",
            "--run-id",
            "run-tid-test",
            "--generated-at-utc",
            "2026-03-08T13:00:00Z",
            "--source-commit",
            "bbbbbbbb",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining tid test should execute");

    assert!(output.status.success());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("decode run manifest");
    assert_eq!(manifest["trace_id"].as_str(), Some("trace-tid-check"));
}

#[test]
fn franken_law_mining_custom_source_commit_in_manifest() {
    let artifact_dir = temp_dir("franken_law_mining_commit");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--source-commit",
            "custom123456",
            "--run-id",
            "run-commit-test",
            "--generated-at-utc",
            "2026-03-08T14:00:00Z",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining commit test should execute");

    assert!(output.status.success());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("decode run manifest");
    assert_eq!(manifest["source_commit"].as_str(), Some("custom123456"));
}

#[test]
fn franken_law_mining_law_provenance_index_exists() {
    let artifact_dir = temp_dir("franken_law_mining_prov");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-prov-test",
            "--generated-at-utc",
            "2026-03-08T15:00:00Z",
            "--source-commit",
            "cccccccc",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining prov test should execute");

    assert!(output.status.success());

    let prov: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("law_provenance_index.json")).expect("read provenance"),
    )
    .expect("provenance parse");
    assert!(prov.is_object());
}

#[test]
fn franken_law_mining_candidate_scope_hypotheses_exists() {
    let artifact_dir = temp_dir("franken_law_mining_scope");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-scope-test",
            "--generated-at-utc",
            "2026-03-08T16:00:00Z",
            "--source-commit",
            "dddddddd",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining scope test should execute");

    assert!(output.status.success());

    let scope: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("candidate_scope_hypotheses.json")).expect("read scope"),
    )
    .expect("scope parse");
    assert!(scope.is_object());
}

#[test]
fn franken_law_mining_custom_decision_id_in_manifest() {
    let artifact_dir = temp_dir("franken_law_mining_dec");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--decision-id",
            "decision-custom-test",
            "--run-id",
            "run-dec-test",
            "--generated-at-utc",
            "2026-03-08T17:00:00Z",
            "--source-commit",
            "eeeeeeee",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining decision test should execute");

    assert!(output.status.success());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("decode run manifest");
    assert_eq!(
        manifest["decision_id"].as_str(),
        Some("decision-custom-test")
    );
}

#[test]
fn franken_law_mining_custom_policy_id_in_manifest() {
    let artifact_dir = temp_dir("franken_law_mining_pol");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--policy-id",
            "policy-custom-test",
            "--run-id",
            "run-pol-test",
            "--generated-at-utc",
            "2026-03-08T18:00:00Z",
            "--source-commit",
            "ffffffff",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining policy test should execute");

    assert!(output.status.success());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("decode run manifest");
    assert_eq!(manifest["policy_id"].as_str(), Some("policy-custom-test"));
}

#[test]
fn franken_law_mining_custom_run_id_in_manifest() {
    let artifact_dir = temp_dir("franken_law_mining_rid");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-custom-rid-test",
            "--generated-at-utc",
            "2026-03-08T19:00:00Z",
            "--source-commit",
            "11223344",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining run-id test should execute");

    assert!(output.status.success());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("decode run manifest");
    assert_eq!(manifest["run_id"].as_str(), Some("run-custom-rid-test"));
}

#[test]
fn franken_law_mining_custom_generated_at_utc_in_manifest() {
    let artifact_dir = temp_dir("franken_law_mining_utc");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--generated-at-utc",
            "2026-01-15T12:30:00Z",
            "--run-id",
            "run-utc-test",
            "--source-commit",
            "55667788",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining utc test should execute");

    assert!(output.status.success());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("decode run manifest");
    assert_eq!(
        manifest["generated_at_utc"].as_str(),
        Some("2026-01-15T12:30:00Z")
    );
}

#[test]
fn franken_law_mining_custom_toolchain_in_manifest() {
    let artifact_dir = temp_dir("franken_law_mining_tc");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--toolchain",
            "stable",
            "--run-id",
            "run-tc-test",
            "--generated-at-utc",
            "2026-03-08T20:00:00Z",
            "--source-commit",
            "aabbccdd",
        ])
        .output()
        .expect("law mining toolchain test should execute");

    assert!(output.status.success());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("decode run manifest");
    assert_eq!(manifest["toolchain"].as_str(), Some("stable"));
}

#[test]
fn franken_law_mining_stdout_json_has_summary_path() {
    let artifact_dir = temp_dir("franken_law_mining_sumpath");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-sumpath-test",
            "--generated-at-utc",
            "2026-03-08T21:00:00Z",
            "--source-commit",
            "eeff0011",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining sumpath test should execute");

    assert!(output.status.success());

    let json: serde_json::Value = parse_stdout_json(&output);
    assert!(json["summary_path"].is_string());
}

#[test]
fn franken_law_mining_trace_id_missing_value_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args(["--artifact-dir", "/tmp/bogus", "--trace-id"])
        .output()
        .expect("law mining trace-id missing value should execute");
    assert!(!output.status.success());
}

#[test]
fn franken_law_mining_decision_id_missing_value_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args(["--artifact-dir", "/tmp/bogus", "--decision-id"])
        .output()
        .expect("law mining decision-id missing value should execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires"));
}

#[test]
fn franken_law_mining_policy_id_missing_value_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args(["--artifact-dir", "/tmp/bogus", "--policy-id"])
        .output()
        .expect("law mining policy-id missing value should execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires"));
}

#[test]
fn franken_law_mining_run_id_missing_value_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args(["--artifact-dir", "/tmp/bogus", "--run-id"])
        .output()
        .expect("law mining run-id missing value should execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires"));
}

#[test]
fn franken_law_mining_generated_at_utc_missing_value_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args(["--artifact-dir", "/tmp/bogus", "--generated-at-utc"])
        .output()
        .expect("law mining generated-at-utc missing value should execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires"));
}

#[test]
fn franken_law_mining_source_commit_missing_value_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args(["--artifact-dir", "/tmp/bogus", "--source-commit"])
        .output()
        .expect("law mining source-commit missing value should execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires"));
}

#[test]
fn franken_law_mining_toolchain_missing_value_fails() {
    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args(["--artifact-dir", "/tmp/bogus", "--toolchain"])
        .output()
        .expect("law mining toolchain missing value should execute");
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires"));
}

#[test]
fn franken_law_mining_env_json_has_expected_schema_version() {
    let artifact_dir = temp_dir("franken_law_mining_env_schema");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-env-schema-test",
            "--generated-at-utc",
            "2026-03-09T00:00:00Z",
            "--source-commit",
            "aabbccee",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining env schema test should execute");

    assert!(output.status.success());

    let env_json: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("env.json")).expect("read env json"))
            .expect("env json parse");
    assert_eq!(
        env_json["schema_version"].as_str(),
        Some("franken-engine.law-mining.env.v1")
    );
}

#[test]
fn franken_law_mining_env_json_has_run_id_and_source_commit() {
    let artifact_dir = temp_dir("franken_law_mining_env_fields");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-env-fields-test",
            "--source-commit",
            "deadc0de1234",
            "--generated-at-utc",
            "2026-03-09T01:00:00Z",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining env fields test should execute");

    assert!(output.status.success());

    let env_json: serde_json::Value =
        serde_json::from_slice(&fs::read(artifact_dir.join("env.json")).expect("read env json"))
            .expect("env json parse");
    assert_eq!(env_json["run_id"].as_str(), Some("run-env-fields-test"));
    assert_eq!(env_json["source_commit"].as_str(), Some("deadc0de1234"));
    assert_eq!(
        env_json["generated_at_utc"].as_str(),
        Some("2026-03-09T01:00:00Z")
    );
}

#[test]
fn franken_law_mining_candidate_catalog_schema_version() {
    let artifact_dir = temp_dir("franken_law_mining_cat_schema");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-cat-schema-test",
            "--generated-at-utc",
            "2026-03-09T02:00:00Z",
            "--source-commit",
            "cafebabe1234",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining catalog schema test should execute");

    assert!(output.status.success());

    let catalog: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("candidate_law_catalog.json")).expect("read catalog"),
    )
    .expect("catalog parse");
    assert_eq!(
        catalog["schema_version"].as_str(),
        Some("franken-engine.law-mining.candidate-law-catalog.v1")
    );
    assert!(catalog["bead_id"].is_string());
    assert!(catalog["generated_epoch"].is_number());
    assert!(catalog["catalog_hash"].is_string());
}

#[test]
fn franken_law_mining_events_jsonl_has_catalog_mined_event() {
    let artifact_dir = temp_dir("franken_law_mining_events_catalog");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--trace-id",
            "trace-ev-catalog",
            "--decision-id",
            "decision-ev-catalog",
            "--policy-id",
            "policy-ev-catalog",
            "--run-id",
            "run-ev-catalog",
            "--generated-at-utc",
            "2026-03-09T03:00:00Z",
            "--source-commit",
            "f00dcafe1234",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining events catalog test should execute");

    assert!(output.status.success());

    let events_raw = fs::read_to_string(artifact_dir.join("events.jsonl")).expect("read events");
    let events: Vec<serde_json::Value> = events_raw
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse event line"))
        .collect();

    assert!(!events.is_empty());
    let has_catalog_mined = events
        .iter()
        .any(|event| event["event"].as_str() == Some("catalog_mined"));
    assert!(
        has_catalog_mined,
        "expected catalog_mined event in events.jsonl"
    );
}

#[test]
fn franken_law_mining_events_jsonl_has_bundle_written_event() {
    let artifact_dir = temp_dir("franken_law_mining_events_bundle");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-ev-bundle",
            "--generated-at-utc",
            "2026-03-09T04:00:00Z",
            "--source-commit",
            "badc0de09090",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining events bundle test should execute");

    assert!(output.status.success());

    let events_raw = fs::read_to_string(artifact_dir.join("events.jsonl")).expect("read events");
    let events: Vec<serde_json::Value> = events_raw
        .lines()
        .map(|line| serde_json::from_str(line).expect("parse event line"))
        .collect();

    let has_bundle_written = events
        .iter()
        .any(|event| event["event"].as_str() == Some("bundle_written"));
    assert!(
        has_bundle_written,
        "expected bundle_written event in events.jsonl"
    );
}

#[test]
fn franken_law_mining_events_have_outcome_pass() {
    let artifact_dir = temp_dir("franken_law_mining_events_outcome");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-ev-outcome",
            "--generated-at-utc",
            "2026-03-09T05:00:00Z",
            "--source-commit",
            "1234567890ab",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining events outcome test should execute");

    assert!(output.status.success());

    let events_raw = fs::read_to_string(artifact_dir.join("events.jsonl")).expect("read events");
    for line in events_raw.lines() {
        let event: serde_json::Value = serde_json::from_str(line).expect("parse event line");
        assert_eq!(
            event["outcome"].as_str(),
            Some("pass"),
            "each event should have outcome=pass"
        );
    }
}

#[test]
fn franken_law_mining_events_have_component_law_mining() {
    let artifact_dir = temp_dir("franken_law_mining_events_component");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-ev-component",
            "--generated-at-utc",
            "2026-03-09T06:00:00Z",
            "--source-commit",
            "abcdef012345",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining events component test should execute");

    assert!(output.status.success());

    let events_raw = fs::read_to_string(artifact_dir.join("events.jsonl")).expect("read events");
    for line in events_raw.lines() {
        let event: serde_json::Value = serde_json::from_str(line).expect("parse event line");
        assert_eq!(
            event["component"].as_str(),
            Some("law_mining"),
            "each event should have component=law_mining"
        );
    }
}

#[test]
fn franken_law_mining_repro_lock_contains_run_id() {
    let artifact_dir = temp_dir("franken_law_mining_repro_run_id");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-repro-unique-777",
            "--generated-at-utc",
            "2026-03-09T07:00:00Z",
            "--source-commit",
            "111213141516",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining repro run_id test should execute");

    assert!(output.status.success());

    let repro = fs::read_to_string(artifact_dir.join("repro.lock")).expect("read repro.lock");
    assert!(
        repro.contains("run-repro-unique-777"),
        "repro.lock should contain run_id"
    );
}

#[test]
fn franken_law_mining_repro_lock_contains_catalog_hash_field() {
    let artifact_dir = temp_dir("franken_law_mining_repro_hash");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-repro-hash-test",
            "--generated-at-utc",
            "2026-03-09T08:00:00Z",
            "--source-commit",
            "171819202122",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining repro hash test should execute");

    assert!(output.status.success());

    let repro = fs::read_to_string(artifact_dir.join("repro.lock")).expect("read repro.lock");
    assert!(
        repro.contains("catalog_hash="),
        "repro.lock should contain catalog_hash= field"
    );
}

#[test]
fn franken_law_mining_trace_ids_json_has_all_id_fields() {
    let artifact_dir = temp_dir("franken_law_mining_trace_all_ids");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--trace-id",
            "trace-allids-check",
            "--decision-id",
            "decision-allids-check",
            "--policy-id",
            "policy-allids-check",
            "--run-id",
            "run-allids-check",
            "--generated-at-utc",
            "2026-03-09T09:00:00Z",
            "--source-commit",
            "232425262728",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining trace all ids test should execute");

    assert!(output.status.success());

    let trace_ids: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("trace_ids.json")).expect("read trace ids"),
    )
    .expect("trace ids parse");

    assert_eq!(trace_ids["trace_id"].as_str(), Some("trace-allids-check"));
    assert_eq!(
        trace_ids["decision_id"].as_str(),
        Some("decision-allids-check")
    );
    assert_eq!(trace_ids["policy_id"].as_str(), Some("policy-allids-check"));
    assert_eq!(trace_ids["run_id"].as_str(), Some("run-allids-check"));
}

#[test]
fn franken_law_mining_run_manifest_has_schema_version() {
    let artifact_dir = temp_dir("franken_law_mining_manifest_schema");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-manifest-schema-test",
            "--generated-at-utc",
            "2026-03-09T10:00:00Z",
            "--source-commit",
            "293031323334",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining manifest schema test should execute");

    assert!(output.status.success());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("decode run manifest");

    assert_eq!(
        manifest["schema_version"].as_str(),
        Some("franken-engine.law-mining.run-manifest.v1")
    );
    assert!(manifest["bead_id"].is_string());
    assert!(manifest["catalog_hash"].is_string());
    assert!(manifest["generated_epoch"].is_number());
    assert!(manifest["command_invocation"].is_string());
}

#[test]
fn franken_law_mining_run_manifest_artifact_hashes_not_empty() {
    let artifact_dir = temp_dir("franken_law_mining_artifact_hashes");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-art-hashes-test",
            "--generated-at-utc",
            "2026-03-09T11:00:00Z",
            "--source-commit",
            "353637383940",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining artifact hashes test should execute");

    assert!(output.status.success());

    let manifest: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("run_manifest.json")).expect("read run manifest"),
    )
    .expect("decode run manifest");

    let artifact_hashes = manifest["artifact_hashes"]
        .as_array()
        .expect("artifact_hashes array");
    assert!(
        !artifact_hashes.is_empty(),
        "run_manifest artifact_hashes should not be empty"
    );
    for hash_record in artifact_hashes {
        assert!(
            hash_record["path"].is_string(),
            "artifact hash record should have path"
        );
        assert!(
            hash_record["sha256"].is_string(),
            "artifact hash record should have sha256"
        );
    }
}

#[test]
fn franken_law_mining_summary_md_contains_generated_epoch() {
    let artifact_dir = temp_dir("franken_law_mining_sum_epoch");

    let output = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .args([
            "--artifact-dir",
            artifact_dir.to_str().expect("artifact dir utf8"),
            "--run-id",
            "run-sum-epoch-test",
            "--generated-at-utc",
            "2026-03-09T12:00:00Z",
            "--source-commit",
            "414243444546",
            "--toolchain",
            "nightly",
        ])
        .output()
        .expect("law mining summary epoch test should execute");

    assert!(output.status.success());

    let summary = fs::read_to_string(artifact_dir.join("summary.md")).expect("read summary.md");
    assert!(
        summary.contains("generated_epoch:"),
        "summary.md should contain generated_epoch field"
    );
    assert!(
        summary.contains("candidates:"),
        "summary.md should contain candidates field"
    );
    assert!(
        summary.contains("catalog_hash:"),
        "summary.md should contain catalog_hash field"
    );
}

#[test]
fn franken_law_mining_two_runs_same_args_produce_same_catalog_hash() {
    let artifact_dir_a = temp_dir("franken_law_mining_determ_a");
    let artifact_dir_b = temp_dir("franken_law_mining_determ_b");

    let fixed_args = [
        "--trace-id",
        "trace-determ",
        "--decision-id",
        "decision-determ",
        "--policy-id",
        "policy-determ",
        "--run-id",
        "run-determ",
        "--generated-at-utc",
        "2026-03-09T13:00:00Z",
        "--source-commit",
        "474849505152",
        "--toolchain",
        "nightly",
    ];

    let output_a = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .arg("--artifact-dir")
        .arg(artifact_dir_a.to_str().expect("artifact dir a utf8"))
        .args(fixed_args)
        .output()
        .expect("law mining determinism run A should execute");

    let output_b = Command::new(env!("CARGO_BIN_EXE_franken_law_mining"))
        .arg("--artifact-dir")
        .arg(artifact_dir_b.to_str().expect("artifact dir b utf8"))
        .args(fixed_args)
        .output()
        .expect("law mining determinism run B should execute");

    assert!(output_a.status.success());
    assert!(output_b.status.success());

    let manifest_a: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir_a.join("run_manifest.json")).expect("read run manifest A"),
    )
    .expect("decode run manifest A");
    let manifest_b: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir_b.join("run_manifest.json")).expect("read run manifest B"),
    )
    .expect("decode run manifest B");

    assert_eq!(
        manifest_a["catalog_hash"], manifest_b["catalog_hash"],
        "catalog_hash should be deterministic across identical runs"
    );
}
