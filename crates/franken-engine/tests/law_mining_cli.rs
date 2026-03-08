#![forbid(unsafe_code)]

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

    let env_json: serde_json::Value = serde_json::from_slice(
        &fs::read(artifact_dir.join("env.json")).expect("read env json"),
    )
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
    assert_eq!(
        manifest["source_commit"].as_str(),
        Some("custom123456")
    );
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
    assert_eq!(manifest["decision_id"].as_str(), Some("decision-custom-test"));
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
    assert_eq!(manifest["generated_at_utc"].as_str(), Some("2026-01-15T12:30:00Z"));
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
