#![forbid(unsafe_code)]
//! Integration coverage for the operator-facing `frankenctl oracle run|report`
//! surface (bd-fqlfw.2.10).
//!
//! These tests are hermetic: the cross-runtime cases select only the in-process
//! `franken` + `core` lanes so they never depend on Node/Bun being installed,
//! and the degraded-path case points `--node-bin` at a non-existent binary so
//! the "reference runtime unavailable" branch is exercised deterministically.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_token(name: &str) -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    format!("{name}_{}_{}", std::process::id(), nonce)
}

fn temp_file(name: &str, ext: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!("{}.{ext}", unique_token(name)));
    path
}

fn temp_dir(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(unique_token(name));
    path
}

fn write_fixture(name: &str, source: &str) -> PathBuf {
    let path = temp_file(name, "js");
    fs::write(&path, source).expect("fixture should write");
    path
}

fn run_oracle(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("oracle")
        .args(args)
        .output()
        .expect("frankenctl oracle should execute")
}

fn parse_json(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_slice(bytes).unwrap_or_else(|error| {
        panic!(
            "stdout should be JSON: {error}\n---\n{}\n---",
            String::from_utf8_lossy(bytes)
        )
    })
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[test]
fn oracle_run_with_bundle_emits_content_addressed_bundle() {
    let fixture = write_fixture("oracle_run_bundle", "1 + 1;\n");
    let bundle = temp_dir("oracle_run_bundle_out");

    let output = run_oracle(&[
        "run",
        fixture.to_str().expect("fixture path is utf8"),
        "--engines",
        "franken,core",
        "--bundle",
        bundle.to_str().expect("bundle path is utf8"),
        "--json",
    ]);

    assert!(
        output.status.success(),
        "consensus run should exit 0: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let summary = parse_json(&output.stdout);
    assert_eq!(
        summary["schema_version"].as_str(),
        Some("franken-engine.oracle-run-summary.v1")
    );
    assert_eq!(summary["semantic_verdict"].as_str(), Some("consensus"));
    assert_eq!(summary["degraded"].as_bool(), Some(false));
    assert_eq!(summary["exit_code"].as_i64(), Some(0));
    // Only the two requested lanes ran.
    assert_eq!(
        summary["backends"].as_array().map(Vec::len),
        Some(2),
        "only franken + core should run"
    );

    // The bundle exists with the canonical four (degraded receipt is absent here).
    for required in ["manifest.json", "report.json", "repro.lock"] {
        assert!(
            bundle.join(required).is_file(),
            "bundle should contain {required}"
        );
    }
    assert!(
        !bundle.join("degraded_receipt.json").exists(),
        "non-degraded run must not emit a degraded receipt"
    );
    #[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&bundle)
            .expect("bundle metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "bundle directory must be private");
    }

    // The manifest content-addresses report.json by sha256.
    let manifest: serde_json::Value =
        parse_json(&fs::read(bundle.join("manifest.json")).expect("manifest readable"));
    let recorded = manifest["artifacts"]["report"]["sha256"]
        .as_str()
        .expect("manifest records report sha256");
    let actual = sha256_prefixed(&fs::read(bundle.join("report.json")).expect("report readable"));
    assert_eq!(recorded, actual, "manifest sha256 must match report bytes");

    let bundle_dir = summary["bundle"]["dir"]
        .as_str()
        .expect("summary bundle dir");
    assert_eq!(bundle_dir, bundle.to_str().unwrap());
    assert!(
        summary["bundle"]["bundle_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("sha256:"))
    );
}

#[test]
fn oracle_report_verifies_and_renders_bundle() {
    let fixture = write_fixture("oracle_report_ok", "40 + 2;\n");
    let bundle = temp_dir("oracle_report_ok_out");

    let run = run_oracle(&[
        "run",
        fixture.to_str().unwrap(),
        "--engines",
        "franken,core",
        "--bundle",
        bundle.to_str().unwrap(),
    ]);
    assert!(run.status.success(), "run should succeed");

    let report = run_oracle(&["report", bundle.to_str().unwrap(), "--json"]);
    assert!(
        report.status.success(),
        "report of a consensus bundle should exit 0: stderr={}",
        String::from_utf8_lossy(&report.stderr)
    );
    let payload = parse_json(&report.stdout);
    assert_eq!(payload["integrity"].as_str(), Some("verified"));
    assert_eq!(payload["semantic_verdict"].as_str(), Some("consensus"));
    assert_eq!(payload["exit_code"].as_i64(), Some(0));
    assert!(
        payload["bundle_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("sha256:"))
    );

    // Human render names the case and verdict.
    let human = run_oracle(&["report", bundle.to_str().unwrap()]);
    assert!(human.status.success());
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.contains("integrity: verified"), "human: {text}");
    assert!(text.contains("verdict: consensus"), "human: {text}");
}

#[test]
fn oracle_report_accepts_manifest_basename_from_bundle_directory() {
    let fixture = write_fixture("oracle_report_basename", "40 + 2;\n");
    let bundle = temp_dir("oracle_report_basename_out");
    let run = run_oracle(&[
        "run",
        fixture.to_str().unwrap(),
        "--engines",
        "franken,core",
        "--bundle",
        bundle.to_str().unwrap(),
    ]);
    assert!(run.status.success(), "run should succeed");

    let report = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .current_dir(&bundle)
        .args(["oracle", "report", "manifest.json", "--json"])
        .output()
        .expect("frankenctl oracle report should execute");
    assert!(
        report.status.success(),
        "manifest basename should resolve against the current directory: {}",
        String::from_utf8_lossy(&report.stderr)
    );
    let payload = parse_json(&report.stdout);
    assert_eq!(payload["integrity"].as_str(), Some("verified"));
}

#[test]
fn oracle_bundle_emission_requires_a_new_directory() {
    let fixture = write_fixture("oracle_bundle_existing_dir", "1 + 1;\n");
    let bundle = temp_dir("oracle_bundle_existing_dir_out");
    fs::create_dir(&bundle).expect("fixture directory should be created");

    let output = run_oracle(&[
        "run",
        fixture.to_str().unwrap(),
        "--engines",
        "franken,core",
        "--bundle",
        bundle.to_str().unwrap(),
        "--json",
    ]);
    assert!(
        !output.status.success(),
        "existing output dir must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("must be a new directory"),
        "stderr should explain the fresh-directory contract: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !bundle.join("manifest.json").exists(),
        "a refused existing directory must remain unpublished"
    );
}

#[cfg(all(unix, not(any(target_os = "redox", target_os = "espidf"))))]
#[test]
fn oracle_bundle_io_rejects_symlinked_directory_and_artifact() {
    use std::os::unix::fs::symlink;

    let fixture = write_fixture("oracle_bundle_symlink", "1 + 1;\n");
    let bundle = temp_dir("oracle_bundle_symlink_out");
    let run = run_oracle(&[
        "run",
        fixture.to_str().unwrap(),
        "--engines",
        "franken,core",
        "--bundle",
        bundle.to_str().unwrap(),
    ]);
    assert!(run.status.success(), "run should succeed");

    let bundle_link = temp_dir("oracle_bundle_symlink_link");
    symlink(&bundle, &bundle_link).expect("bundle directory symlink should be created");
    let linked_report = run_oracle(&["report", bundle_link.to_str().unwrap(), "--json"]);
    assert!(
        !linked_report.status.success(),
        "symlinked bundle directories must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&linked_report.stderr).contains("securely open bundle dir"),
        "stderr should identify the secure-open failure: {}",
        String::from_utf8_lossy(&linked_report.stderr)
    );

    let report_path = bundle.join("report.json");
    let report_target = bundle.join("report-target.json");
    fs::rename(&report_path, &report_target).expect("report fixture should move");
    symlink("report-target.json", &report_path).expect("report symlink should be created");
    let artifact_report = run_oracle(&["report", bundle.to_str().unwrap(), "--json"]);
    assert!(
        !artifact_report.status.success(),
        "symlinked bundle artifacts must fail closed"
    );
    assert!(
        String::from_utf8_lossy(&artifact_report.stderr).contains("securely open bundle report"),
        "stderr should identify the artifact secure-open failure: {}",
        String::from_utf8_lossy(&artifact_report.stderr)
    );
}

#[test]
fn oracle_report_rejects_tampered_bundle() {
    let fixture = write_fixture("oracle_report_tamper", "7 * 6;\n");
    let bundle = temp_dir("oracle_report_tamper_out");

    let run = run_oracle(&[
        "run",
        fixture.to_str().unwrap(),
        "--engines",
        "franken,core",
        "--bundle",
        bundle.to_str().unwrap(),
    ]);
    assert!(run.status.success());

    // Tamper with report.json after the manifest recorded its hash.
    let report_path = bundle.join("report.json");
    let mut bytes = fs::read(&report_path).expect("report readable");
    bytes.extend_from_slice(b"\n// tampered\n");
    fs::write(&report_path, bytes).expect("tamper write");

    let report = run_oracle(&["report", bundle.to_str().unwrap(), "--json"]);
    assert!(
        !report.status.success(),
        "tampered bundle must fail integrity"
    );
    let stderr = String::from_utf8_lossy(&report.stderr);
    assert!(
        stderr.contains("integrity failure"),
        "stderr should report integrity failure: {stderr}"
    );
}

#[test]
fn oracle_run_degraded_when_reference_runtime_unavailable() {
    let fixture = write_fixture("oracle_run_degraded", "1 + 1;\n");
    let bundle = temp_dir("oracle_run_degraded_out");

    let output = run_oracle(&[
        "run",
        fixture.to_str().unwrap(),
        "--engines",
        "franken,node",
        // Force the node lane to be unavailable, deterministically.
        "--node-bin",
        "/nonexistent/franken_oracle_test_node_binary",
        "--bundle",
        bundle.to_str().unwrap(),
        "--json",
    ]);

    let summary = parse_json(&output.stdout);
    assert_eq!(
        summary["degraded"].as_bool(),
        Some(true),
        "missing reference runtime must mark the run degraded"
    );
    assert_eq!(
        output.status.code(),
        Some(4),
        "degraded run downgrades to insufficient-data (exit 4): stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(summary["exit_code"].as_i64(), Some(4));

    // The degraded receipt is written and names the unavailable runtime.
    let receipt_path = bundle.join("degraded_receipt.json");
    assert!(receipt_path.is_file(), "degraded receipt should be emitted");
    let receipt: serde_json::Value =
        parse_json(&fs::read(&receipt_path).expect("receipt readable"));
    assert_eq!(receipt["error_code"].as_str(), Some("FE-REPRO-0007"));
    let reasons = receipt["reasons"]
        .as_array()
        .expect("reasons array")
        .iter()
        .filter_map(|value| value.as_str())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        reasons.contains("node_lts"),
        "reasons should name node_lts: {reasons}"
    );
}

#[test]
fn oracle_run_engine_selection_limits_backends() {
    let fixture = write_fixture("oracle_run_single", "1 + 1;\n");

    let output = run_oracle(&[
        "run",
        fixture.to_str().unwrap(),
        "--engines",
        "franken",
        "--json",
    ]);
    // A single lane cannot reach cross-runtime consensus (fewer than two
    // applicable backends ⇒ insufficient data ⇒ exit 4), so we assert on the
    // selection, not on success. stdout still carries the summary.
    let summary = parse_json(&output.stdout);
    let backends = summary["backends"].as_array().expect("backends array");
    assert_eq!(backends.len(), 1, "only the franken lane should run");
    assert_eq!(backends[0]["backend"].as_str(), Some("franken_engine"));
    assert_eq!(
        summary["semantic_verdict"].as_str(),
        Some("insufficient_data")
    );
    assert_eq!(output.status.code(), Some(4));
}

#[test]
fn oracle_unknown_engine_is_rejected() {
    let fixture = write_fixture("oracle_run_badengine", "1 + 1;\n");
    let output = run_oracle(&["run", fixture.to_str().unwrap(), "--engines", "deno"]);
    assert!(!output.status.success(), "unknown engine should fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown engine"), "stderr: {stderr}");
}
