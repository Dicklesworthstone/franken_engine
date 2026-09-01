#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::{Value, json};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "franken-engine-object-id-migration-{label}-{}-{id}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("create test directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_franken_engine_object_id_migration")
}

fn write_request(test_dir: &TestDir, request: &Value) -> PathBuf {
    let path = test_dir.path().join("request.json");
    fs::write(
        &path,
        serde_json::to_vec_pretty(request).expect("serialize request"),
    )
    .expect("write request");
    path
}

fn run_request(test_dir: &TestDir, request: &Value) -> Output {
    let input = write_request(test_dir, request);
    Command::new(binary())
        .args(["--input", input.to_str().expect("UTF-8 input path")])
        .output()
        .expect("run migration CLI")
}

fn policy_request(operation: &str) -> Value {
    json!({
        "operation": operation,
        "domain": "policy_object",
        "zone": "zone-a",
        "schema_definition_hex": hex::encode(br#"{"type":"Policy"}"#),
        "canonical_bytes_hex": hex::encode(br#"{"allow":true}"#)
    })
}

#[test]
fn derive_emits_stable_legacy_and_sha256_v2_vectors() {
    let test_dir = TestDir::new("derive");
    let output = run_request(&test_dir, &policy_request("derive"));
    assert!(
        output.status.success(),
        "derive failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).expect("parse response");
    assert_eq!(response["status"], "ok");
    assert_eq!(response["ids_differ"], true);
    assert_eq!(
        response["legacy_v1"]["schema_id_hex"],
        "9704c8101b9f138f0d7ec78989eb1e1e0760f0756aeade43dee3975b8e73cce5"
    );
    assert_eq!(
        response["legacy_v1"]["object_id_hex"],
        "242c2cd17a8607149ec8dc88944aeb507a042208a522d21a9b58c112729e1ecd"
    );
    assert_eq!(
        response["sha256_v2"]["schema_id_hex"],
        "95dd1a7336da89398ea01216baed44a5170dd518af89379402227a3b12d1922a"
    );
    assert_eq!(
        response["sha256_v2"]["object_id_hex"],
        "cdc31ac7ad5b4d68d7cbdae29179b3230608bd13afdfc641f2e1a4273913b545"
    );
}

#[test]
fn explicit_v2_verification_succeeds() {
    let test_dir = TestDir::new("verify-v2");
    let mut request = policy_request("verify");
    request["version"] = Value::from("sha256_v2");
    request["expected_object_id_hex"] = Value::from(
        "cdc31ac7ad5b4d68d7cbdae29179b3230608bd13afdfc641f2e1a4273913b545",
    );
    let output = run_request(&test_dir, &request);
    assert!(output.status.success());
    let response: Value = serde_json::from_slice(&output.stdout).expect("parse response");
    assert_eq!(response["status"], "verified");
    assert_eq!(response["verified"], true);
    assert_eq!(response["version"], "sha256_v2");
}

#[test]
fn verification_never_falls_back_to_another_version() {
    let test_dir = TestDir::new("no-fallback");
    let mut request = policy_request("verify");
    request["version"] = Value::from("legacy_v1");
    request["expected_object_id_hex"] = Value::from(
        "cdc31ac7ad5b4d68d7cbdae29179b3230608bd13afdfc641f2e1a4273913b545",
    );
    let output = run_request(&test_dir, &request);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).expect("parse response");
    assert_eq!(response["status"], "mismatch");
    assert_eq!(response["verified"], false);
    assert_eq!(response["version"], "legacy_v1");
}

#[test]
fn invalid_hex_is_structured_and_exits_two() {
    let test_dir = TestDir::new("invalid-hex");
    let mut request = policy_request("derive");
    request["canonical_bytes_hex"] = Value::from("not-hex");
    let output = run_request(&test_dir, &request);
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let response: Value = serde_json::from_slice(&output.stderr).expect("parse error response");
    assert_eq!(response["status"], "error");
    assert_eq!(response["error_code"], "invalid_hex");
    assert!(
        response["detail"]
            .as_str()
            .expect("detail")
            .contains("canonical_bytes_hex")
    );
}

#[test]
fn output_file_is_complete_json_and_stdout_remains_empty() {
    let test_dir = TestDir::new("output-file");
    let input = write_request(&test_dir, &policy_request("derive"));
    let output_path = test_dir.path().join("nested/result.json");
    let output = Command::new(binary())
        .args([
            "--input",
            input.to_str().expect("UTF-8 input path"),
            "--output",
            output_path.to_str().expect("UTF-8 output path"),
        ])
        .output()
        .expect("run migration CLI");
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&fs::read(output_path).expect("read result"))
        .expect("parse result");
    assert_eq!(response["status"], "ok");
}

#[test]
fn help_is_successful_and_does_not_emit_error_json() {
    let output = Command::new(binary())
        .arg("--help")
        .output()
        .expect("run help");
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("usage:"));
    assert!(output.stderr.is_empty());
}
