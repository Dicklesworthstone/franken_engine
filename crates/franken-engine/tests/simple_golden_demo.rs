#![forbid(unsafe_code)]

//! Simple Golden Artifact Demo
//!
//! Demonstrates the golden artifact testing pattern with a minimal working example.

use std::fs;
use std::path::Path;

/// Core golden comparison function following testing-golden-artifacts pattern
fn assert_golden(test_name: &str, actual: &str) {
    let golden_path = Path::new("tests/golden").join(format!("{test_name}.golden"));

    // UPDATE MODE: overwrite golden with actual output
    if std::env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(
            golden_path
                .parent()
                .expect("Golden path must have parent directory"),
        )
        .expect("Failed to create golden artifacts directory");
        fs::write(&golden_path, actual).expect("Failed to write golden artifact file");
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    // COMPARE MODE: diff actual vs golden
    let expected = fs::read_to_string(&golden_path).unwrap_or_else(|_| {
        panic!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff tests/golden/",
            golden_path.display()
        )
    });

    if actual != expected {
        // Write actual for easy diffing
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, actual)
            .expect("Failed to write actual artifact file for comparison");

        panic!(
            "GOLDEN MISMATCH: {test_name}\n\n\
             Expected length: {} bytes\n\
             Actual length:   {} bytes\n\n\
             To update: UPDATE_GOLDENS=1 cargo test -- {test_name}\n\
             To review: diff {} {}",
            expected.len(),
            actual.len(),
            golden_path.display(),
            actual_path.display(),
        );
    }
}

#[test]
fn test_deterministic_formatting() {
    let mut output = String::new();

    // Generate deterministic output
    output.push_str("FrankenEngine Golden Artifact Demo\n");
    output.push_str("==================================\n\n");

    // Test deterministic data structures
    let test_values = vec![42u64, 100, 255, 1000];
    for (i, value) in test_values.iter().enumerate() {
        output.push_str(&format!("Value {}: {:#x} ({})\n", i, value, value));
    }

    output.push_str("\nHex dump:\n");
    let test_bytes = [0x01, 0x02, 0xFF, 0xAB, 0xCD];
    for (i, byte) in test_bytes.iter().enumerate() {
        if i > 0 && i % 8 == 0 {
            output.push('\n');
        }
        output.push_str(&format!("{:02x} ", byte));
    }
    output.push('\n');

    assert_golden("deterministic_formatting", &output);
}

#[test]
fn test_error_message_formatting() {
    let mut output = String::new();

    // Simulate error message formatting that should be stable
    let test_errors = vec![
        ("InvalidInput", "Parameter 'count' must be positive"),
        ("ParseError", "Expected number at position 42"),
        (
            "ValidationFailed",
            "Schema version mismatch: expected v1, got v2",
        ),
    ];

    output.push_str("Error Message Catalog\n");
    output.push_str("====================\n\n");

    for (error_type, message) in test_errors {
        output.push_str(&format!("{}: {}\n", error_type, message));
    }

    assert_golden("error_message_formatting", &output);
}
