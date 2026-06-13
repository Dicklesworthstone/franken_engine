//! Integration tests for `frankenctl check <file>` — per-span authority
//! footprint (E5.T1, `bd-fqlfw.5.1`).
//!
//! These drive the shipped binary end-to-end (no mocks): a fixture with a known
//! ambient-authority read must produce a span-accurate `error[FE-CAP-0001]`
//! diagnostic and the correct minimal capability set, and `--format json` must
//! be byte-deterministic and content-addressed.
#![forbid(unsafe_code)]

use std::fs;
use std::process::{Command, Output};

use tempfile::tempdir;

fn run_check(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .arg("check")
        .args(args)
        .output()
        .expect("frankenctl check should execute")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn check_reports_span_accurate_ambient_authority_read() {
    let dir = tempdir().expect("tempdir");
    let fixture = dir.path().join("ext.js");
    // `process.env.SECRET_KEY` is the ambient-authority read, on line 2.
    fs::write(
        &fixture,
        "const greeting = \"hello\";\nconst secret = process.env.SECRET_KEY;\n",
    )
    .expect("write fixture");

    let output = run_check(&[fixture.to_str().unwrap(), "--format", "json"]);
    assert_eq!(
        output.status.code(),
        Some(1),
        "ambient read => findings present => exit 1\nstdout={}\nstderr={}",
        stdout_of(&output),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: serde_json::Value =
        serde_json::from_str(&stdout_of(&output)).expect("--format json emits a JSON report");

    assert_eq!(
        report["schema_version"],
        "franken-engine.authority-footprint.v1"
    );
    assert_eq!(report["analyzable"], true);

    let findings = report["findings"].as_array().expect("findings array");
    assert_eq!(findings.len(), 1, "first ambient violation is reported");
    assert_eq!(findings[0]["error_code"], "FE-CAP-0001");
    assert_eq!(findings[0]["accessor"], "process.env");
    assert_eq!(findings[0]["implied_capability"], "EnvRead");
    // Span-accurate: the diagnostic points at line 2 (`process.env`).
    assert_eq!(
        findings[0]["location"]["start_line"], 2,
        "process.env is on line 2"
    );

    // Correct minimal capability set: exactly {EnvRead}.
    let caps = report["required_capabilities"]
        .as_array()
        .expect("required_capabilities array");
    assert_eq!(caps.len(), 1, "minimal capability set has one entry");
    assert_eq!(caps[0]["capability"], "EnvRead");
}

#[test]
fn check_json_output_is_deterministic() {
    let dir = tempdir().expect("tempdir");
    let fixture = dir.path().join("ext.js");
    fs::write(&fixture, "const secret = process.env.TOKEN;\n").expect("write fixture");

    let first = run_check(&[fixture.to_str().unwrap(), "--format", "json"]);
    let second = run_check(&[fixture.to_str().unwrap(), "--format", "json"]);
    assert_eq!(
        first.stdout, second.stdout,
        "`check --format json` must be byte-identical across runs"
    );
}

#[test]
fn check_writes_content_addressed_bundle() {
    let dir = tempdir().expect("tempdir");
    let fixture = dir.path().join("ext.js");
    fs::write(&fixture, "const secret = process.env.TOKEN;\n").expect("write fixture");
    let bundle = dir.path().join("bundle");

    let output = run_check(&[
        fixture.to_str().unwrap(),
        "--format",
        "json",
        "--out",
        bundle.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(1));

    let manifest =
        fs::read_to_string(bundle.join("run_manifest.json")).expect("run_manifest.json is written");
    let manifest_json: serde_json::Value =
        serde_json::from_str(&manifest).expect("run_manifest.json is valid JSON");
    let report_sha = manifest_json["report_sha256"]
        .as_str()
        .expect("report_sha256 present");
    assert!(!report_sha.is_empty(), "report is content-addressed");

    let events = fs::read_to_string(bundle.join("events.jsonl")).expect("events.jsonl is written");
    let lines: Vec<&str> = events.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(lines.len(), 1, "one finding => one event line");
    let event: serde_json::Value =
        serde_json::from_str(lines[0]).expect("events.jsonl lines are valid JSON");
    assert_eq!(event["error_code"], "FE-CAP-0001");
}

#[test]
fn check_pure_computation_is_clean_exit_zero() {
    let dir = tempdir().expect("tempdir");
    let fixture = dir.path().join("pure.js");
    fs::write(&fixture, "const a = 1;\nconst b = a + 2;\n").expect("write fixture");

    let output = run_check(&[fixture.to_str().unwrap(), "--format", "json"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "pure arithmetic uses no ambient authority => clean => exit 0\nstdout={}",
        stdout_of(&output)
    );
    let report: serde_json::Value = serde_json::from_str(&stdout_of(&output)).expect("json report");
    assert_eq!(report["analyzable"], true);
    assert_eq!(
        report["findings"].as_array().map(Vec::len),
        Some(0),
        "no authority/IFC findings for pure arithmetic"
    );
}

#[test]
fn check_unparseable_source_fails_closed_exit_two() {
    let dir = tempdir().expect("tempdir");
    let fixture = dir.path().join("broken.js");
    // Unterminated string literal: a hard lexer/parse error.
    fs::write(&fixture, "const x = \"unterminated;\n").expect("write fixture");

    let output = run_check(&[fixture.to_str().unwrap(), "--format", "json"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "unanalyzable source must fail closed with exit 2\nstdout={}",
        stdout_of(&output)
    );
    let report: serde_json::Value =
        serde_json::from_str(&stdout_of(&output)).expect("json report even when fail-closed");
    assert_eq!(report["analyzable"], false);
    assert!(
        report["fail_closed_reason"].is_string(),
        "fail_closed_reason explains why analysis refused"
    );
}
