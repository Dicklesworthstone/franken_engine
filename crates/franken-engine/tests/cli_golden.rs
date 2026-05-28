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

use serde::{Deserialize, Serialize};

// golden_diag lives under tests/_support/ so cargo does NOT compile it as a
// standalone (empty) integration-test binary (bd-ub6x8.18). Sibling callers
// pull it in via the same #[path] attribute.
#[path = "_support/golden_diag.rs"]
mod golden_diag;

// Shared scrub patterns now live in golden_diag (bd-ub6x8.12); only re-export
// the names for readability inside this file.
use golden_diag::{SCRUB_ISO_TIMESTAMP, SCRUB_PROJECT_PATH, SCRUB_TARGET_PATH, SCRUB_TMP_PATH};

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

/// Test cases for CLI binaries.
///
/// The `franken-architecture-inventory` binary intentionally has NO entries
/// here: its substantive contract (markdown-rendered inventory) is covered by
/// `architecture_inventory_golden.rs` against `docs/ARCHITECTURE_INVENTORY.md`.
/// A previous `architecture_inventory_stdout` fixture was 76KB of escaped CLI
/// output that re-encoded the same module table, with self-referential
/// generator-banner prose baked into the golden — every module add/rename
/// invalidated the fixture for zero independent signal (bd-ub6x8.10).
const CLI_TEST_CASES: &[CliTestCase] = &[
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
    // Build the binary on demand (bd-ub6x8.20). Removes the prebuild
    // prerequisite and the stale-binary trap from the previous design.
    let binary_path = golden_diag::resolve_built_cli_binary(test_case.binary)?;

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

    // Generate a test function for each CLI test case.
    // (architecture-inventory CLI coverage removed in bd-ub6x8.10;
    // see CLI_TEST_CASES doc-comment.)
    #[test]
    fn test_frankenctl_help() {
        test_cli_golden(&CLI_TEST_CASES[0]);
    }

    #[test]
    fn test_frankenctl_version() {
        test_cli_golden(&CLI_TEST_CASES[1]);
    }

    #[test]
    fn test_decision_demo_help() {
        test_cli_golden(&CLI_TEST_CASES[2]);
    }
}
