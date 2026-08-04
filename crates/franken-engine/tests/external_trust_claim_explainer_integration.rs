#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const MATRIX_SCHEMA_VERSION: &str = "franken-engine.claim-to-proof-matrix.v1";

#[test]
fn frankenctl_claims_explain_reports_supported_fixture() {
    let fixture = fixture_dir("supported");
    fs::create_dir_all(&fixture).expect("create fixture dir");
    let artifact_path = fixture.join("artifact.json");
    fs::write(&artifact_path, b"{\"proof\":\"observed\"}\n").expect("write artifact");
    write_repro_lock_next_to_file(&artifact_path);
    let matrix_path = fixture.join("matrix.json");
    write_matrix(&matrix_path, &artifact_path);
    let beads_path = fixture.join("issues.jsonl");
    fs::write(
        &beads_path,
        serde_json::json!({"id":"bd-cli","status":"closed","assignee":"EmeraldPine"}).to_string(),
    )
    .expect("write beads jsonl");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "claims",
            "explain",
            "FE-CLAIM-CLI",
            "--matrix",
            matrix_path.to_str().expect("utf8 matrix path"),
            "--beads-jsonl",
            beads_path.to_str().expect("utf8 beads path"),
            "--format",
            "json",
        ])
        .output()
        .expect("run frankenctl");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    assert_eq!(
        value["schema_version"].as_str(),
        Some("franken-engine.external-trust-claim-explainer.v1")
    );
    assert_eq!(value["decision"].as_str(), Some("supported"));
    assert_eq!(value["artifact"]["present"].as_bool(), Some(true));
    assert_eq!(value["bead"]["status"].as_str(), Some("closed"));
    assert_eq!(
        value["mutation_policy"]["mutates_br"].as_bool(),
        Some(false)
    );
    assert_eq!(
        value["renderer_boundary"]["future_rich_renderer_provider"].as_str(),
        Some("/dp/frankentui")
    );
}

#[test]
fn frankenctl_claims_explain_missing_requested_bead_snapshot_fails_closed_with_json() {
    let fixture = fixture_dir("missing-bead-snapshot");
    fs::create_dir_all(&fixture).expect("create fixture dir");
    let artifact_path = fixture.join("artifact.json");
    fs::write(&artifact_path, b"{\"proof\":\"observed\"}\n").expect("write artifact");
    let matrix_path = fixture.join("matrix.json");
    write_matrix(&matrix_path, &artifact_path);
    let missing_beads_path = fixture.join("missing-issues.jsonl");

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "claims",
            "explain",
            "FE-CLAIM-CLI",
            "--matrix",
            matrix_path.to_str().expect("utf8 matrix path"),
            "--beads-jsonl",
            missing_beads_path.to_str().expect("utf8 beads path"),
            "--format",
            "json",
        ])
        .output()
        .expect("run frankenctl");

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    assert_eq!(value["decision"].as_str(), Some("fail_closed"));
    assert!(
        value["reason_codes"]
            .as_array()
            .expect("reason codes")
            .iter()
            .any(|code| code.as_str() == Some("stale_tracker_state"))
    );
    assert_eq!(value["bead"]["found"].as_bool(), Some(false));
}

#[test]
fn frankenctl_claims_explain_missing_claim_fails_closed_with_json() {
    let fixture = fixture_dir("missing");
    fs::create_dir_all(&fixture).expect("create fixture dir");
    let artifact_path = fixture.join("artifact.json");
    fs::write(&artifact_path, b"{\"proof\":\"observed\"}\n").expect("write artifact");
    let matrix_path = fixture.join("matrix.json");
    write_matrix(&matrix_path, &artifact_path);

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "claims",
            "explain",
            "FE-CLAIM-MISSING",
            "--matrix",
            matrix_path.to_str().expect("utf8 matrix path"),
            "--no-beads",
            "--format",
            "json",
        ])
        .output()
        .expect("run frankenctl");

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    assert_eq!(value["decision"].as_str(), Some("fail_closed"));
    assert_eq!(value["reason_codes"][0].as_str(), Some("missing_claim_row"));
}

#[test]
fn frankenctl_claims_explain_missing_artifact_fails_closed_with_json() {
    let fixture = fixture_dir("missing-artifact");
    fs::create_dir_all(&fixture).expect("create fixture dir");
    let matrix_path = fixture.join("matrix.json");
    write_matrix_with_claims(
        &matrix_path,
        serde_json::json!([claim_row(
            "FE-CLAIM-MISSING-ARTIFACT",
            fixture.join("missing-artifact.json").display().to_string()
        )]),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "claims",
            "explain",
            "FE-CLAIM-MISSING-ARTIFACT",
            "--matrix",
            matrix_path.to_str().expect("utf8 matrix path"),
            "--no-beads",
            "--format",
            "json",
        ])
        .output()
        .expect("run frankenctl");

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    assert_eq!(value["decision"].as_str(), Some("fail_closed"));
    assert!(
        value["reason_codes"]
            .as_array()
            .expect("reason codes")
            .iter()
            .any(|code| code.as_str() == Some("absent_artifact"))
    );
    assert_eq!(value["artifact"]["present"].as_bool(), Some(false));
}

#[test]
fn frankenctl_claims_explain_stale_artifact_fails_closed_with_json() {
    let fixture = fixture_dir("stale-artifact");
    let artifact_dir = fixture.join("artifact");
    fs::create_dir_all(&artifact_dir).expect("create fixture dir");
    fs::write(
        artifact_dir.join("manifest.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "franken-engine.proof-artifact-manifest.v1",
            "freshness": {
                "generated_utc": "2026-01-01T00:00:00Z"
            }
        }))
        .expect("manifest JSON serializes"),
    )
    .expect("write stale manifest");
    let matrix_path = fixture.join("matrix.json");
    write_matrix_with_claims(
        &matrix_path,
        serde_json::json!([claim_row(
            "FE-CLAIM-STALE",
            artifact_dir.display().to_string()
        )]),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "claims",
            "explain",
            "FE-CLAIM-STALE",
            "--matrix",
            matrix_path.to_str().expect("utf8 matrix path"),
            "--no-beads",
            "--format",
            "json",
        ])
        .output()
        .expect("run frankenctl");

    assert_eq!(output.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON");
    assert_eq!(value["decision"].as_str(), Some("fail_closed"));
    assert!(
        value["reason_codes"]
            .as_array()
            .expect("reason codes")
            .iter()
            .any(|code| code.as_str() == Some("stale_artifact"))
    );
    assert_eq!(
        value["artifact"]["freshness_status"].as_str(),
        Some("stale")
    );
}

fn fixture_dir(label: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "franken-engine-claim-explainer-{label}-{}-{nanos}",
        std::process::id()
    ))
}

fn write_matrix(path: &Path, artifact_path: &Path) {
    write_matrix_with_claims(
        path,
        serde_json::json!([claim_row(
            "FE-CLAIM-CLI",
            artifact_path.display().to_string()
        )]),
    );
}

fn write_matrix_with_claims(path: &Path, claims: serde_json::Value) {
    let matrix = serde_json::json!({
        "schema_version": MATRIX_SCHEMA_VERSION,
        "stale_threshold_days": 30,
        "claims": claims
    });
    fs::write(
        path,
        serde_json::to_vec_pretty(&matrix).expect("matrix serializes"),
    )
    .expect("write matrix");
}

fn write_repro_lock_next_to_file(path: &Path) {
    let parent = path.parent().expect("artifact parent");
    fs::write(parent.join("repro.lock"), b"fixture repro lock\n").expect("write repro lock");
}

fn claim_row(claim_id: &str, artifact_path: String) -> serde_json::Value {
    serde_json::json!({
        "actual_wording_state": "observed",
        "allowed_state": "observed",
        "artifact_path": artifact_path,
        "claim_id": claim_id,
        "claim_scope": "evidence",
        "claim_text": "Fixture claim.",
        "decision": "allow observed fixture",
        "downgrade_text": "Fixture downgrade.",
        "freshness_days": 0,
        "owning_bead": "bd-cli",
        "reason": "Fixture reason.",
        "source_path": concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/frankenctl.rs"),
        "source_span": {
            "start_line": 1,
            "end_line": 1,
            "must_contain": "#![forbid(unsafe_code)]"
        },
        "verification_command": "rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_fixture cargo test -p frankenengine-engine fixture"
    })
}
