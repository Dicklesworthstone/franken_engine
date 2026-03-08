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
