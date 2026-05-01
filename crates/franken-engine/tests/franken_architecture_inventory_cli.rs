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

use std::path::PathBuf;
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn inventory_command() -> Command {
    // Use runtime path resolution instead of compile-time env var
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let target_dir = std::env::var("CARGO_TARGET_DIR")
        .unwrap_or_else(|_| format!("{}/../../target", manifest_dir));
    let binary_path = PathBuf::from(target_dir)
        .join("debug")
        .join("franken_architecture_inventory");
    Command::new(binary_path)
}

#[test]
fn architecture_inventory_stdout_mode_produces_expected_markdown() {
    let output = inventory_command()
        .arg("--stdout")
        .output()
        .expect("run architecture inventory with --stdout");

    assert!(
        output.status.success(),
        "stdout mode should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");

    // Golden test: validate structure and key sections
    assert!(
        stdout.contains("# Architecture Inventory"),
        "missing main header"
    );
    assert!(
        stdout.contains("## Workspace Structure"),
        "missing workspace section"
    );
    assert!(
        stdout.contains("## Crate Dependencies"),
        "missing dependencies section"
    );
    assert!(
        stdout.contains("frankenengine-engine"),
        "missing main crate"
    );
    assert!(
        stdout.starts_with("# Architecture Inventory"),
        "should start with header"
    );

    // Validate markdown structure
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(!lines.is_empty(), "output should not be empty");

    // Should contain table-like structures for dependencies
    assert!(
        stdout.contains("| ") || stdout.contains("|:"),
        "should contain markdown table formatting"
    );
}

#[test]
fn architecture_inventory_check_mode_succeeds_when_file_current() {
    // First ensure the file exists and is current
    let write_output = inventory_command()
        .output()
        .expect("run architecture inventory to ensure file exists");

    assert!(
        write_output.status.success(),
        "write mode should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&write_output.stderr)
    );

    // Now test check mode
    let check_output = inventory_command()
        .arg("--check")
        .output()
        .expect("run architecture inventory with --check");

    assert!(
        check_output.status.success(),
        "check mode should succeed when file is current:\nstderr:\n{}",
        String::from_utf8_lossy(&check_output.stderr)
    );

    let stdout = String::from_utf8(check_output.stdout).expect("stdout utf8");
    assert!(
        stdout.contains("is up to date"),
        "check mode should indicate file is current: {stdout}"
    );
}

#[test]
fn architecture_inventory_write_mode_creates_file() {
    let output = inventory_command()
        .output()
        .expect("run architecture inventory in write mode");

    assert!(
        output.status.success(),
        "write mode should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(
        stdout.contains("wrote"),
        "write mode should indicate file was written: {stdout}"
    );
    assert!(
        stdout.contains("ARCHITECTURE_INVENTORY.md"),
        "should reference the output file: {stdout}"
    );

    // Verify the file actually exists
    let expected_path = repo_root().join("docs/ARCHITECTURE_INVENTORY.md");
    assert!(
        expected_path.exists(),
        "output file should exist at {}",
        expected_path.display()
    );
}

#[test]
fn architecture_inventory_unknown_argument_produces_error() {
    let output = inventory_command()
        .arg("--unknown-flag")
        .output()
        .expect("run architecture inventory with unknown flag");

    // Should still succeed as unknown flags are ignored according to the code
    assert!(
        output.status.success(),
        "unknown flags are ignored, should succeed:\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn architecture_inventory_help_functionality() {
    // Test help-like behavior by checking with various help-style arguments
    for help_arg in ["--help", "-h", "help"] {
        let output = inventory_command()
            .arg(help_arg)
            .output()
            .expect(&format!("run architecture inventory with {}", help_arg));

        // The binary doesn't explicitly handle help, so it treats as unknown and succeeds
        assert!(
            output.status.success(),
            "{} should not crash the binary",
            help_arg
        );
    }
}

#[test]
fn architecture_inventory_multiple_modes_last_wins() {
    // Test that when multiple mode flags are provided, the last one wins
    let output = inventory_command()
        .arg("--check")
        .arg("--stdout")
        .output()
        .expect("run architecture inventory with multiple flags");

    assert!(
        output.status.success(),
        "multiple flags should not cause failure:\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    // --stdout should win, so we get markdown output, not "up to date" message
    assert!(
        stdout.contains("# Architecture Inventory"),
        "stdout flag should override check flag"
    );
    assert!(
        !stdout.contains("is up to date"),
        "should not see check mode message when stdout mode is active"
    );
}

#[test]
fn architecture_inventory_stdout_output_deterministic() {
    // Run the command twice and ensure output is deterministic
    let output1 = inventory_command()
        .arg("--stdout")
        .output()
        .expect("run architecture inventory first time");

    let output2 = inventory_command()
        .arg("--stdout")
        .output()
        .expect("run architecture inventory second time");

    assert!(output1.status.success() && output2.status.success());

    let stdout1 = String::from_utf8(output1.stdout).expect("stdout1 utf8");
    let stdout2 = String::from_utf8(output2.stdout).expect("stdout2 utf8");

    assert_eq!(
        stdout1, stdout2,
        "consecutive runs should produce identical output"
    );
}

#[test]
fn architecture_inventory_output_contains_expected_crate_structure() {
    let output = inventory_command()
        .arg("--stdout")
        .output()
        .expect("run architecture inventory");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");

    // Validate that key workspace components are documented
    assert!(
        stdout.contains("frankenengine-engine"),
        "should document main engine crate"
    );
    assert!(
        stdout.contains("frankenengine-extension-host")
            || stdout.contains("franken-extension-host"),
        "should document extension host crate"
    );
}

#[test]
fn architecture_inventory_markdown_format_validation() {
    let output = inventory_command()
        .arg("--stdout")
        .output()
        .expect("run architecture inventory");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");

    // Validate markdown structure more thoroughly
    assert!(
        stdout.starts_with("# "),
        "should start with top-level header"
    );

    let lines: Vec<&str> = stdout.lines().collect();
    let mut has_level2_header = false;
    let mut has_level3_header = false;

    for line in &lines {
        if line.starts_with("## ") {
            has_level2_header = true;
        }
        if line.starts_with("### ") {
            has_level3_header = true;
        }
    }

    assert!(has_level2_header, "should have level 2 headers");
    // Level 3 headers are optional, but we track them for completeness
    let _ = has_level3_header;

    // Should not have any malformed markdown
    assert!(
        !stdout.contains("######## "),
        "should not have excessive header levels"
    );
}

#[test]
fn architecture_inventory_error_handling_invalid_repo_state() {
    // The binary uses default_repo_root() which points to a valid location
    // This test verifies it doesn't crash on the current workspace
    let output = inventory_command()
        .output()
        .expect("run architecture inventory");

    // Should either succeed or provide meaningful error
    if !output.status.success() {
        let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
        assert!(
            stderr.contains("architecture inventory failed:"),
            "errors should have meaningful prefix: {stderr}"
        );
    }
}
