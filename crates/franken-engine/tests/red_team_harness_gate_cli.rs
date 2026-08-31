#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

struct TestDir(PathBuf);

impl TestDir {
    fn new(label: &str) -> Self {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "franken-red-team-harness-gate-{label}-{}-{id}",
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
    env!("CARGO_BIN_EXE_franken_red_team_harness_gate")
}

fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/red_team_harness_output_v1.json"))
        .expect("valid harness fixture")
}

fn write_json(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("serialize test JSON"),
    )
    .expect("write test JSON");
}

#[test]
fn passing_harness_emits_machine_and_markdown_reports() {
    let test_dir = TestDir::new("pass");
    let input = test_dir.path().join("input.json");
    let output = test_dir.path().join("report.json");
    let markdown = test_dir.path().join("report.md");
    write_json(&input, &fixture());

    let result = Command::new(binary())
        .args([
            "--input",
            input.to_str().expect("UTF-8 input path"),
            "--output",
            output.to_str().expect("UTF-8 output path"),
            "--markdown",
            markdown.to_str().expect("UTF-8 markdown path"),
        ])
        .output()
        .expect("run harness gate");

    assert!(
        result.status.success(),
        "gate failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
    let report: Value =
        serde_json::from_slice(&fs::read(output).expect("read report")).expect("parse report");
    assert_eq!(
        report["schema_version"],
        "franken-engine.red-team-harness-gate-output.v1"
    );
    assert_eq!(report["summary"]["node"]["attempts_successful"], 500);
    assert_eq!(
        report["summary"]["frankenengine"]["attempts_successful"],
        0
    );
    assert_eq!(
        report["report"]["reason"],
        "red_team_compromise_rate_reduction_verified"
    );
    let markdown = fs::read_to_string(markdown).expect("read markdown");
    assert!(markdown.contains("Red-Team Compromise-Rate Metric Gate"));
}

#[test]
fn below_minimum_harness_is_rejected_as_invalid_input() {
    let test_dir = TestDir::new("minimum");
    let input = test_dir.path().join("input.json");
    let mut value = fixture();
    value["min_trials_per_runtime"] = Value::from(99);
    write_json(&input, &value);

    let result = Command::new(binary())
        .args(["--input", input.to_str().expect("UTF-8 input path")])
        .output()
        .expect("run harness gate");

    assert_eq!(result.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("below required 100"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn measured_candidate_compromise_exits_fail_closed_with_report() {
    let test_dir = TestDir::new("fail-closed");
    let input = test_dir.path().join("input.json");
    let mut value = fixture();
    for result in value["results"]
        .as_array_mut()
        .expect("results array")
        .iter_mut()
    {
        if result["runtime"] == "franken_engine" {
            result["attempts_successful"] = Value::from(100);
        }
    }
    write_json(&input, &value);

    let result = Command::new(binary())
        .args(["--input", input.to_str().expect("UTF-8 input path")])
        .output()
        .expect("run harness gate");

    assert_eq!(result.status.code(), Some(1));
    assert!(result.stderr.is_empty());
    let report: Value = serde_json::from_slice(&result.stdout).expect("parse gate output");
    assert_eq!(
        report["report"]["reason"],
        "compromise_rate_reduction_below_baseline"
    );
    assert_eq!(report["report"]["reduction_factor_x"], 1);
}

#[test]
fn help_is_a_successful_non_mutating_surface() {
    let result = Command::new(binary())
        .arg("--help")
        .output()
        .expect("run harness gate help");
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("usage:"));
    assert!(result.stderr.is_empty());
}
