//! Golden tests for benchmark evidence and diagnostic output formats.
//!
//! These tests capture known-good benchmark and diagnostic outputs and compare them against current outputs
//! to detect format changes that could break monitoring/analysis pipelines and external tooling integration.
//!
//! Test pattern: Execute benchmark and diagnostic binaries with representative inputs, scrub timing values
//! while preserving data structure, and compare against frozen golden files.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};

mod golden_diag;

/// Represents the captured output from a benchmark/diagnostic command execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BenchmarkDiagnosticOutput {
    /// Exit code from the process
    exit_code: i32,
    /// Stdout content (scrubbed of timestamps and timing values)
    stdout: String,
    /// Stderr content (scrubbed of timestamps)
    stderr: String,
    /// Command line that was executed
    command: String,
    /// Test case category for organization
    category: String,
}

/// Configuration for a benchmark/diagnostic test case.
#[derive(Debug, Clone)]
struct BenchmarkDiagnosticTestCase {
    /// Binary name (e.g., "franken-benchmark-evidence-export")
    binary: &'static str,
    /// Command line arguments
    args: &'static [&'static str],
    /// Test case name for golden file
    name: &'static str,
    /// Category (benchmark or diagnostic)
    category: &'static str,
    /// Whether to expect this command to succeed (exit code 0)
    expect_success: bool,
    /// Whether to create dummy input files for this test
    needs_input_fixture: bool,
}

impl BenchmarkDiagnosticTestCase {
    const fn new(
        binary: &'static str,
        args: &'static [&'static str],
        name: &'static str,
        category: &'static str,
    ) -> Self {
        Self {
            binary,
            args,
            name,
            category,
            expect_success: true,
            needs_input_fixture: false,
        }
    }

    #[allow(dead_code)]
    const fn with_input_fixture(mut self) -> Self {
        self.needs_input_fixture = true;
        self
    }

    const fn expect_failure(mut self) -> Self {
        self.expect_success = false;
        self
    }
}

/// Test cases for benchmark and diagnostic binaries
const BENCHMARK_DIAGNOSTIC_TEST_CASES: &[BenchmarkDiagnosticTestCase] = &[
    // Benchmark evidence export tests
    BenchmarkDiagnosticTestCase::new(
        "franken-benchmark-evidence-export",
        &["--help"],
        "benchmark_export_help",
        "benchmark",
    ),
    BenchmarkDiagnosticTestCase::new(
        "franken-benchmark-evidence-export",
        &["--version"],
        "benchmark_export_version",
        "benchmark",
    )
    .expect_failure(), // Version flag might not be implemented
    // Runtime diagnostics tests
    BenchmarkDiagnosticTestCase::new(
        "runtime_diagnostics",
        &["help"],
        "runtime_diagnostics_help",
        "diagnostic",
    ),
    BenchmarkDiagnosticTestCase::new(
        "runtime_diagnostics",
        &["diagnostics"],
        "runtime_diagnostics_no_input",
        "diagnostic",
    )
    .expect_failure(), // Should fail without required input
    BenchmarkDiagnosticTestCase::new(
        "runtime_diagnostics",
        &["export-evidence"],
        "runtime_diagnostics_export_no_input",
        "diagnostic",
    )
    .expect_failure(), // Should fail without required input
];

/// Scrub timing values, timestamps, paths, and other non-deterministic content from output
/// while preserving the overall structure for format validation.
fn scrub_benchmark_diagnostic_output(content: &str) -> String {
    let mut scrubbed = content.to_string();

    // Scrub timing values (microseconds, nanoseconds, milliseconds)
    scrubbed = regex::Regex::new(r"\b\d+\.\d+\s*(us|ns|ms|μs)\b")
        .unwrap()
        .replace_all(&scrubbed, "[TIMING_VALUE]")
        .to_string();

    // Scrub standalone timing numbers that look like performance values
    scrubbed = regex::Regex::new(r"\b\d{4,}\.\d+\b")
        .unwrap()
        .replace_all(&scrubbed, "[TIMING_NUMBER]")
        .to_string();

    // Scrub ISO timestamps (2026-04-30T...)
    scrubbed = regex::Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[Z\d\.\-\+:]*")
        .unwrap()
        .replace_all(&scrubbed, "[TIMESTAMP]")
        .to_string();

    // Scrub absolute paths containing /data/projects/franken_engine
    scrubbed = regex::Regex::new(r"/data/projects/franken_engine[/\w\-\.]*")
        .unwrap()
        .replace_all(&scrubbed, "[PROJECT_PATH]")
        .to_string();

    // Scrub temporary paths
    scrubbed = regex::Regex::new(r"/tmp/[/\w\-\.]*")
        .unwrap()
        .replace_all(&scrubbed, "[TMP_PATH]")
        .to_string();

    // Scrub target directory paths
    scrubbed = regex::Regex::new(r"target[/\w\-\.]*")
        .unwrap()
        .replace_all(&scrubbed, "[TARGET_PATH]")
        .to_string();

    // Scrub hash values (SHA256, etc)
    scrubbed = regex::Regex::new(r"\b[a-fA-F0-9]{40,64}\b")
        .unwrap()
        .replace_all(&scrubbed, "[HASH_VALUE]")
        .to_string();

    // Scrub memory addresses
    scrubbed = regex::Regex::new(r"0x[a-fA-F0-9]+")
        .unwrap()
        .replace_all(&scrubbed, "[MEMORY_ADDRESS]")
        .to_string();

    scrubbed
}

/// Create minimal input fixtures for tests that need them.
fn create_input_fixtures() -> Result<BTreeMap<String, PathBuf>, Box<dyn std::error::Error>> {
    let mut fixtures = BTreeMap::new();

    // Create minimal evidence bundle JSON for benchmark export tests
    let bundle_json = r#"{
        "bundle_id": "test-bundle-001",
        "schema_version": "franken-engine.benchmark-evidence-bundle.v1",
        "status": "Draft",
        "created_at": "2026-05-01T00:00:00Z",
        "provenances": [],
        "runs": [],
        "parity_verdicts": [],
        "config": {
            "min_runs_per_workload": 5,
            "max_cv_millionths": 100000,
            "enabled_parity_targets": []
        }
    }"#;

    let bundle_path = std::env::temp_dir().join("test_evidence_bundle.json");
    fs::write(&bundle_path, bundle_json)?;
    fixtures.insert("evidence_bundle".to_string(), bundle_path);

    // Create minimal runtime input JSON for diagnostic tests
    let runtime_json = r#"{
        "trace_id": "test-trace-001",
        "decision_id": "test-decision-001",
        "policy_id": "test-policy-001",
        "component": "test-component",
        "events": [],
        "hostcalls": [],
        "containment_actions": []
    }"#;

    let runtime_path = std::env::temp_dir().join("test_runtime_input.json");
    fs::write(&runtime_path, runtime_json)?;
    fixtures.insert("runtime_input".to_string(), runtime_path);

    Ok(fixtures)
}

/// Execute a benchmark/diagnostic command and capture its output, scrubbing non-deterministic content.
fn capture_benchmark_diagnostic_output(
    test_case: &BenchmarkDiagnosticTestCase,
) -> Result<BenchmarkDiagnosticOutput, Box<dyn std::error::Error>> {
    // Find the built binary
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let target_dir =
        std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| format!("{}/target", manifest_dir));

    let binary_path = std::env::var("CLI_GOLDEN_BIN_DIR")
        .map(|bin_dir| PathBuf::from(bin_dir).join(test_case.binary))
        .unwrap_or_else(|_| {
            PathBuf::from(target_dir)
                .join("debug")
                .join(test_case.binary)
        });

    if !binary_path.exists() {
        return Err(format!("Binary not found: {}", binary_path.display()).into());
    }

    // Create input fixtures if needed
    let _fixtures = if test_case.needs_input_fixture {
        Some(create_input_fixtures()?)
    } else {
        None
    };

    let output = Command::new(&binary_path).args(test_case.args).output()?;

    let stdout = scrub_benchmark_diagnostic_output(&String::from_utf8_lossy(&output.stdout));
    let stderr = scrub_benchmark_diagnostic_output(&String::from_utf8_lossy(&output.stderr));
    let exit_code = output.status.code().unwrap_or(-1);

    let command = format!("{} {}", test_case.binary, test_case.args.join(" "));

    Ok(BenchmarkDiagnosticOutput {
        exit_code,
        stdout,
        stderr,
        command,
        category: test_case.category.to_string(),
    })
}

/// Get the path to the golden file for a test case.
fn golden_file_path(test_case: &BenchmarkDiagnosticTestCase) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("goldens")
        .join("benchmark_diagnostic")
        .join(format!("{}.json", test_case.name))
}

/// Test a single benchmark/diagnostic test case against its golden output.
fn test_benchmark_diagnostic_golden(test_case: &BenchmarkDiagnosticTestCase) {
    let current_output = capture_benchmark_diagnostic_output(test_case)
        .unwrap_or_else(|e| panic!("Failed to capture output for {}: {}", test_case.name, e));

    // Check exit code expectations
    if test_case.expect_success && current_output.exit_code != 0 {
        panic!(
            "Expected success but got exit code {} for {}",
            current_output.exit_code, test_case.name
        );
    }
    if !test_case.expect_success && current_output.exit_code == 0 {
        panic!("Expected failure but got success for {}", test_case.name);
    }

    let fixture_path = golden_file_path(test_case);
    let content = serde_json::to_string_pretty(&current_output).expect("JSON serialization");

    let diag = golden_diag::GoldenDiag {
        framework_name: "Benchmark/diagnostic golden",
        regen_env_var: "UPDATE_GOLDENS",
    };

    diag.assert_golden_match(
        &content,
        &fixture_path,
        test_case.name,
        Some(&format!(
            "{} {} output",
            test_case.category, test_case.binary
        )),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_benchmark_diagnostic_output() {
        let input = "Benchmark run: 1245.67 us, hash: abc123def456, path: /data/projects/franken_engine/test";
        let expected =
            "Benchmark run: [TIMING_VALUE], hash: [HASH_VALUE], path: [PROJECT_PATH]/test";
        assert_eq!(scrub_benchmark_diagnostic_output(input), expected);
    }

    // Generate a test function for each benchmark/diagnostic test case
    #[test]
    fn test_benchmark_export_help() {
        test_benchmark_diagnostic_golden(&BENCHMARK_DIAGNOSTIC_TEST_CASES[0]);
    }

    #[test]
    fn test_benchmark_export_version() {
        test_benchmark_diagnostic_golden(&BENCHMARK_DIAGNOSTIC_TEST_CASES[1]);
    }

    #[test]
    fn test_runtime_diagnostics_help() {
        test_benchmark_diagnostic_golden(&BENCHMARK_DIAGNOSTIC_TEST_CASES[2]);
    }

    #[test]
    fn test_runtime_diagnostics_no_input() {
        test_benchmark_diagnostic_golden(&BENCHMARK_DIAGNOSTIC_TEST_CASES[3]);
    }

    #[test]
    fn test_runtime_diagnostics_export_no_input() {
        test_benchmark_diagnostic_golden(&BENCHMARK_DIAGNOSTIC_TEST_CASES[4]);
    }
}
