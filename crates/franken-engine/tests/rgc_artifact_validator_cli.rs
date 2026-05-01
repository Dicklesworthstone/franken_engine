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
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::Value;

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new(prefix: &str) -> Self {
        let unique = format!(
            "{}-{}-{}",
            prefix,
            std::process::id(),
            TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let path = std::env::temp_dir().join(unique);
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn validator_command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rgc_artifact_validator"))
}

fn write_file(path: &Path, content: &str) {
    let parent = path.parent().expect("file has parent");
    fs::create_dir_all(parent).expect("create file parent");
    fs::write(path, content).expect("write file");
}

fn create_valid_triad_fixture() -> (TestTempDir, PathBuf) {
    let guard = TestTempDir::new("rgc-validator-triad");
    let run_dir = guard.path.join("test_run");

    let manifest = serde_json::json!({
        "schema_version": "franken-engine.rgc-test-harness.v1",
        "run_id": "test-run-12345",
        "timestamp": "2026-04-30T00:00:00Z",
        "harness_version": "v1.0.0",
        "events_path": "events.jsonl",
        "commands_path": "commands.txt"
    });

    write_file(
        &run_dir.join("run_manifest.json"),
        &serde_json::to_string_pretty(&manifest).unwrap(),
    );

    let events = r#"{"timestamp":"2026-04-30T00:00:00Z","event":"test_started","data":{}}
{"timestamp":"2026-04-30T00:00:01Z","event":"test_completed","data":{"status":"pass"}}
"#;
    write_file(&run_dir.join("events.jsonl"), events);

    write_file(&run_dir.join("commands.txt"), "echo test\necho complete\n");

    (guard, run_dir)
}

fn create_valid_bundle_fixture() -> (TestTempDir, PathBuf) {
    let guard = TestTempDir::new("rgc-validator-bundle");
    let bundle_dir = guard.path.join("test_bundle");

    // Create multiple triad directories
    for i in 0..2 {
        let run_dir = bundle_dir.join(format!("run_{}", i));

        let manifest = serde_json::json!({
            "schema_version": "franken-engine.rgc-test-harness.v1",
            "run_id": format!("test-run-{}", i),
            "timestamp": "2026-04-30T00:00:00Z",
            "harness_version": "v1.0.0",
            "events_path": "events.jsonl",
            "commands_path": "commands.txt"
        });

        write_file(
            &run_dir.join("run_manifest.json"),
            &serde_json::to_string_pretty(&manifest).unwrap(),
        );

        let events = format!(
            r#"{{"timestamp":"2026-04-30T00:00:0{}Z","event":"test_started","data":{{}}}}
{{"timestamp":"2026-04-30T00:00:0{}Z","event":"test_completed","data":{{"status":"pass"}}}}
"#,
            i,
            i + 1
        );
        write_file(&run_dir.join("events.jsonl"), &events);

        write_file(&run_dir.join("commands.txt"), &format!("echo test_{}\n", i));
    }

    (guard, bundle_dir)
}

#[test]
fn validator_help_output_contains_usage_information() {
    let output = validator_command()
        .arg("--help")
        .output()
        .expect("run validator with --help");

    // Help exits with code 0
    assert!(
        output.status.success(),
        "help should exit with code 0:\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");

    // Golden test: validate help text structure
    assert!(stdout.contains("Usage:"), "help should contain usage line");
    assert!(
        stdout.contains("--run-dir"),
        "help should document --run-dir flag"
    );
    assert!(
        stdout.contains("--bundle-dir"),
        "help should document --bundle-dir flag"
    );
    assert!(
        stdout.contains("--pretty"),
        "help should document --pretty flag"
    );
    assert!(stdout.contains("--out"), "help should document --out flag");
    assert!(
        stdout.contains("--required-lanes"),
        "help should document --required-lanes flag"
    );
    assert!(
        stdout.contains("Exit code 2"),
        "help should explain exit code semantics"
    );
}

#[test]
fn validator_short_help_flag_works() {
    let output = validator_command()
        .arg("-h")
        .output()
        .expect("run validator with -h");

    assert!(output.status.success(), "-h should work like --help");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(stdout.contains("Usage:"), "-h should show help text");
}

#[test]
fn validator_no_arguments_produces_error() {
    let output = validator_command()
        .output()
        .expect("run validator with no arguments");

    // Should exit with code 1 (runtime error)
    assert_eq!(
        output.status.code(),
        Some(1),
        "no arguments should exit with code 1"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("one of `--run-dir` or `--bundle-dir` is required")
            || stderr.contains("exactly one of --run-dir or --bundle-dir must be provided"),
        "should require either run-dir or bundle-dir: {stderr}"
    );
}

#[test]
fn validator_both_run_dir_and_bundle_dir_produces_error() {
    let output = validator_command()
        .arg("--run-dir")
        .arg("/tmp/run")
        .arg("--bundle-dir")
        .arg("/tmp/bundle")
        .output()
        .expect("run validator with both flags");

    assert_eq!(
        output.status.code(),
        Some(1),
        "conflicting flags should exit with code 1"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("mutually exclusive") || stderr.contains("exactly one of"),
        "should reject conflicting flags: {stderr}"
    );
}

#[test]
fn validator_unknown_argument_produces_error() {
    let output = validator_command()
        .arg("--unknown-flag")
        .output()
        .expect("run validator with unknown flag");

    assert_eq!(
        output.status.code(),
        Some(1),
        "unknown flag should exit with code 1"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("unknown argument"),
        "should report unknown argument: {stderr}"
    );
}

#[test]
fn validator_triad_mode_valid_produces_json_report() {
    let (_guard, run_dir) = create_valid_triad_fixture();

    let output = validator_command()
        .arg("--run-dir")
        .arg(&run_dir)
        .output()
        .expect("run validator on valid triad");

    // Should exit with code 0 (valid)
    assert_eq!(
        output.status.code(),
        Some(0),
        "valid triad should exit with code 0:\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");

    // Parse and validate JSON structure
    let report: Value =
        serde_json::from_str(&stdout).expect(&format!("output should be valid JSON: {stdout}"));

    // Golden test: validate report structure
    assert_eq!(
        report["report_kind"], "triad",
        "should indicate triad report type"
    );
    assert!(report["report"].is_object(), "should contain report object");
    assert_eq!(
        report["report"]["valid"], true,
        "should indicate valid triad"
    );
}

#[test]
fn validator_bundle_mode_valid_produces_json_report() {
    let (_guard, bundle_dir) = create_valid_bundle_fixture();

    let output = validator_command()
        .arg("--bundle-dir")
        .arg(&bundle_dir)
        .output()
        .expect("run validator on valid bundle");

    assert_eq!(
        output.status.code(),
        Some(0),
        "valid bundle should exit with code 0:\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");

    let report: Value =
        serde_json::from_str(&stdout).expect(&format!("output should be valid JSON: {stdout}"));

    assert_eq!(
        report["report_kind"], "bundle",
        "should indicate bundle report type"
    );
    assert!(report["report"].is_object(), "should contain report object");
    assert_eq!(
        report["report"]["valid"], true,
        "should indicate valid bundle"
    );
}

#[test]
fn validator_pretty_flag_formats_json_output() {
    let (_guard, run_dir) = create_valid_triad_fixture();

    let regular_output = validator_command()
        .arg("--run-dir")
        .arg(&run_dir)
        .output()
        .expect("run validator without pretty");

    let pretty_output = validator_command()
        .arg("--run-dir")
        .arg(&run_dir)
        .arg("--pretty")
        .output()
        .expect("run validator with pretty");

    let regular_stdout = String::from_utf8(regular_output.stdout).expect("regular stdout utf8");
    let pretty_stdout = String::from_utf8(pretty_output.stdout).expect("pretty stdout utf8");

    // Both should be valid JSON with same content
    let regular_json: Value = serde_json::from_str(&regular_stdout).expect("regular JSON");
    let pretty_json: Value = serde_json::from_str(&pretty_stdout).expect("pretty JSON");

    assert_eq!(regular_json, pretty_json, "content should be identical");

    // Pretty output should have more whitespace
    assert!(
        pretty_stdout.len() > regular_stdout.len(),
        "pretty output should be longer due to formatting"
    );
    assert!(
        pretty_stdout.lines().count() > regular_stdout.lines().count(),
        "pretty output should have more lines"
    );
}

#[test]
fn validator_out_flag_writes_to_file() {
    let (_guard, run_dir) = create_valid_triad_fixture();
    let temp_guard = TestTempDir::new("validator-out");
    let out_path = temp_guard.path.join("report.json");

    let output = validator_command()
        .arg("--run-dir")
        .arg(&run_dir)
        .arg("--out")
        .arg(&out_path)
        .output()
        .expect("run validator with --out");

    assert!(output.status.success(), "should succeed with --out flag");

    // File should be created
    assert!(out_path.exists(), "output file should be created");

    // File content should match stdout
    let file_content = fs::read_to_string(&out_path).expect("read output file");
    let stdout_content = String::from_utf8(output.stdout).expect("stdout utf8");

    assert_eq!(file_content, stdout_content, "file and stdout should match");

    // Both should be valid JSON
    let _json: Value = serde_json::from_str(&file_content).expect("file should contain valid JSON");
}

#[test]
fn validator_nonexistent_run_dir_produces_error() {
    let output = validator_command()
        .arg("--run-dir")
        .arg("/nonexistent/path")
        .output()
        .expect("run validator on nonexistent path");

    // Should exit with code 1 (runtime error, not validation failure)
    assert_eq!(
        output.status.code(),
        Some(1),
        "nonexistent path should exit with code 1"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("No such file") || stderr.contains("not found") || stderr.len() > 0,
        "should report file not found error: {stderr}"
    );
}

#[test]
fn validator_required_lanes_flag_with_bundle() {
    let (_guard, bundle_dir) = create_valid_bundle_fixture();

    let output = validator_command()
        .arg("--bundle-dir")
        .arg(&bundle_dir)
        .arg("--required-lanes")
        .arg("runtime,security")
        .output()
        .expect("run validator with required-lanes");

    // This should work even if the lanes aren't present in the fixture
    // The validation logic will determine if they're actually required
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let _report: Value = serde_json::from_str(&stdout).expect("should produce valid JSON");
}

#[test]
fn validator_required_lanes_without_bundle_dir_produces_error() {
    let (_guard, run_dir) = create_valid_triad_fixture();

    let output = validator_command()
        .arg("--run-dir")
        .arg(&run_dir)
        .arg("--required-lanes")
        .arg("runtime")
        .output()
        .expect("run validator with required-lanes but run-dir");

    assert_eq!(
        output.status.code(),
        Some(1),
        "required-lanes without bundle-dir should fail"
    );

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        stderr.contains("`--required-lanes` requires `--bundle-dir`"),
        "should require bundle-dir with required-lanes: {stderr}"
    );
}

#[test]
fn validator_json_output_structure_golden() {
    let (_guard, run_dir) = create_valid_triad_fixture();

    let output = validator_command()
        .arg("--run-dir")
        .arg(&run_dir)
        .output()
        .expect("run validator");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let report: Value = serde_json::from_str(&stdout).expect("valid JSON");

    // Golden test: ensure specific structure is maintained
    assert!(report.is_object(), "top level should be object");
    assert!(
        report.get("report_kind").is_some(),
        "should have report_kind field"
    );
    assert!(report.get("report").is_some(), "should have report field");

    match report["report_kind"].as_str() {
        Some("triad") => {
            assert!(
                report["report"]["valid"].is_boolean(),
                "triad report should have valid boolean"
            );
        }
        Some("bundle") => {
            assert!(
                report["report"]["valid"].is_boolean(),
                "bundle report should have valid boolean"
            );
        }
        _ => panic!("report_kind should be 'triad' or 'bundle'"),
    }
}

#[test]
fn validator_deterministic_output_for_same_input() {
    let (_guard, run_dir) = create_valid_triad_fixture();

    let output1 = validator_command()
        .arg("--run-dir")
        .arg(&run_dir)
        .output()
        .expect("first validator run");

    let output2 = validator_command()
        .arg("--run-dir")
        .arg(&run_dir)
        .output()
        .expect("second validator run");

    let stdout1 = String::from_utf8(output1.stdout).expect("stdout1 utf8");
    let stdout2 = String::from_utf8(output2.stdout).expect("stdout2 utf8");

    assert_eq!(
        stdout1, stdout2,
        "consecutive runs should produce identical output"
    );
    assert_eq!(
        output1.status.code(),
        output2.status.code(),
        "exit codes should be consistent"
    );
}
