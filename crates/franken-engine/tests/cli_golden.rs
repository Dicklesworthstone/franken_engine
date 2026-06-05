//! Golden tests for CLI binary outputs.
//!
//! These tests capture known-good CLI outputs and compare them against current outputs
//! to detect format changes that could break automation/tooling integration.
//!
//! Test pattern: capture stdout/stderr/exit_code from CLI invocations, scrub
//! timestamps/paths while preserving content structure, and compare against frozen golden files.

#![forbid(unsafe_code)]

use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};

// golden_diag lives under tests/_support/ so cargo does NOT compile it as a
// standalone (empty) integration-test binary (bd-ub6x8.18). This suite keeps
// using it for shared scrub patterns and fallback binary resolution; insta now
// owns the snapshot comparison path.
#[allow(dead_code)]
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
    let binary_path = resolve_cli_binary(test_case.binary)?;

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

fn resolve_cli_binary(binary_name: &'static str) -> Result<PathBuf, String> {
    if let Ok(bin_dir) = std::env::var("CLI_GOLDEN_BIN_DIR") {
        let path = PathBuf::from(bin_dir).join(binary_name);
        if path.exists() {
            return Ok(path);
        }
        return Err(format!(
            "CLI_GOLDEN_BIN_DIR set but binary not found: {}",
            path.display()
        ));
    }

    let cargo_built_binary = match binary_name {
        "frankenctl" => option_env!("CARGO_BIN_EXE_frankenctl"),
        "franken-decision-demo" => option_env!("CARGO_BIN_EXE_franken-decision-demo"),
        _ => None,
    };
    if let Some(path) = cargo_built_binary {
        return Ok(PathBuf::from(path));
    }

    golden_diag::resolve_built_cli_binary(binary_name)
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

    let actual =
        serde_json::to_string_pretty(&current_output).expect("CLI output should serialize to JSON");

    insta::assert_snapshot!(test_case.name, actual);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scrub_output() {
        let input = "2026-04-30T10:30:45Z wrote /data/projects/franken_engine/docs/test.md";
        let expected = "[TIMESTAMP] wrote [PROJECT_PATH]";
        assert_eq!(scrub_output(input), expected);

        let flag_and_path =
            "frankenctl doctor --target-platform linux --out-dir target/debug/report.json";
        assert_eq!(
            scrub_output(flag_and_path),
            "frankenctl doctor --target-platform linux --out-dir [TARGET_PATH]"
        );
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
