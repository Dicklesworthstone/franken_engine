//! Golden tests for CLI binary outputs.
//!
//! These tests capture known-good CLI outputs and compare them against current outputs
//! to detect format changes that could break automation/tooling integration.
//!
//! Test pattern: capture stdout/stderr/exit_code from CLI invocations, scrub
//! timestamps/paths while preserving content structure, and compare against frozen golden files.

#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::str;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

mod golden_diag;

// Hoisted scrub patterns (bd-ub6x8.13) — compile once at first call instead
// of every scrub_output invocation.
static SCRUB_ISO_TIMESTAMP: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[Z\d\.\-\+:]*").unwrap());
static SCRUB_PROJECT_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"/data/projects/franken_engine[/\w\-\.]*").unwrap());
static SCRUB_TMP_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"/tmp/[/\w\-\.]*").unwrap());
static SCRUB_TARGET_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"target[/\w\-\.]*").unwrap());

/// Represents the captured output from a CLI command execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CliOutput {
    /// Exit code from the process
    exit_code: i32,
    /// Stdout content (scrubbed of timestamps/paths)
    stdout: String,
    /// Stderr content (scrubbed of timestamps/paths)
    stderr: String,
    /// Command line that was executed
    command: String,
}

/// Configuration for a CLI test case.
#[derive(Debug, Clone)]
struct CliTestCase {
    /// Binary name (e.g., "franken-architecture-inventory")
    binary: &'static str,
    /// Command line arguments
    args: &'static [&'static str],
    /// Test case name for golden file
    name: &'static str,
    /// Whether to expect this command to succeed (exit code 0)
    expect_success: bool,
}

impl CliTestCase {
    const fn new(binary: &'static str, args: &'static [&'static str], name: &'static str) -> Self {
        Self {
            binary,
            args,
            name,
            expect_success: true,
        }
    }
}

/// Test cases for CLI binaries
const CLI_TEST_CASES: &[CliTestCase] = &[
    // Architecture inventory tests
    CliTestCase::new(
        "franken-architecture-inventory",
        &["--help"],
        "architecture_inventory_help",
    ),
    CliTestCase::new(
        "franken-architecture-inventory",
        &["--stdout"],
        "architecture_inventory_stdout",
    ),
    CliTestCase::new(
        "franken-architecture-inventory",
        &["--check"],
        "architecture_inventory_check",
    ),
    // FrankenCtl tests
    CliTestCase::new("frankenctl", &["--help"], "frankenctl_help"),
    CliTestCase::new("frankenctl", &["version"], "frankenctl_version"),
    // Decision demo tests
    CliTestCase::new("franken-decision-demo", &["--help"], "decision_demo_help"),
];

/// Scrub timestamps, paths, and other non-deterministic content from CLI output
/// while preserving the overall structure.
fn scrub_output(content: &str) -> String {
    let mut scrubbed = content.to_string();
    scrubbed = SCRUB_ISO_TIMESTAMP
        .replace_all(&scrubbed, "[TIMESTAMP]")
        .into_owned();
    scrubbed = SCRUB_PROJECT_PATH
        .replace_all(&scrubbed, "[PROJECT_PATH]")
        .into_owned();
    scrubbed = SCRUB_TMP_PATH
        .replace_all(&scrubbed, "[TMP_PATH]")
        .into_owned();
    scrubbed = SCRUB_TARGET_PATH
        .replace_all(&scrubbed, "[TARGET_PATH]")
        .into_owned();
    scrubbed
}

/// Execute a CLI command and capture its output, scrubbing non-deterministic content.
fn capture_cli_output(test_case: &CliTestCase) -> Result<CliOutput, Box<dyn std::error::Error>> {
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

    let output = Command::new(&binary_path).args(test_case.args).output()?;

    let stdout = scrub_output(&String::from_utf8_lossy(&output.stdout));
    let stderr = scrub_output(&String::from_utf8_lossy(&output.stderr));
    let exit_code = output.status.code().unwrap_or(-1);

    let command = format!("{} {}", test_case.binary, test_case.args.join(" "));

    Ok(CliOutput {
        exit_code,
        stdout,
        stderr,
        command,
    })
}

/// Get the path to the golden file for a test case.
fn golden_file_path(test_case: &CliTestCase) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden_tests")
        .join(format!("{}.json", test_case.name))
}

/// Load golden output from file if it exists.
#[allow(dead_code)]
fn load_golden_output(test_case: &CliTestCase) -> Option<CliOutput> {
    let path = golden_file_path(test_case);
    if !path.exists() {
        return None;
    }

    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Save golden output to file.
#[allow(dead_code)]
fn save_golden_output(
    test_case: &CliTestCase,
    output: &CliOutput,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = golden_file_path(test_case);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let content = serde_json::to_string_pretty(output)?;
    fs::write(path, content)?;

    Ok(())
}

/// Test a single CLI test case against its golden output.
fn test_cli_golden(test_case: &CliTestCase) {
    let current_output = capture_cli_output(test_case)
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

    // Use improved golden diagnostics
    let diag = golden_diag::GoldenDiag::cli();
    let fixture_path = golden_file_path(test_case);
    let actual_json =
        serde_json::to_string_pretty(&current_output).expect("CLI output should serialize to JSON");
    let hint = format!(
        "CLI output: exit_code={}, stdout_lines={}, stderr_lines={}",
        current_output.exit_code,
        current_output.stdout.lines().count(),
        current_output.stderr.lines().count()
    );

    diag.assert_golden_match(&actual_json, &fixture_path, test_case.name, Some(&hint));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_output() {
        let input = "2026-04-30T10:30:45Z wrote /data/projects/franken_engine/docs/test.md";
        let expected = "[TIMESTAMP] wrote [PROJECT_PATH]/docs/test.md";
        assert_eq!(scrub_output(input), expected);
    }

    // Generate a test function for each CLI test case
    #[test]
    fn test_architecture_inventory_help() {
        test_cli_golden(&CLI_TEST_CASES[0]);
    }

    #[test]
    fn test_architecture_inventory_stdout() {
        test_cli_golden(&CLI_TEST_CASES[1]);
    }

    #[test]
    fn test_architecture_inventory_check() {
        test_cli_golden(&CLI_TEST_CASES[2]);
    }

    #[test]
    fn test_frankenctl_help() {
        test_cli_golden(&CLI_TEST_CASES[3]);
    }

    #[test]
    fn test_frankenctl_version() {
        test_cli_golden(&CLI_TEST_CASES[4]);
    }

    #[test]
    fn test_decision_demo_help() {
        test_cli_golden(&CLI_TEST_CASES[5]);
    }
}
