#![forbid(unsafe_code)]

//! Golden Artifact Pattern Example
//!
//! Documentation example for the franken-engine golden-artifact testing
//! pattern. Run with:
//!
//! ```bash
//! cargo run --example golden_pattern -p frankenengine-engine
//! ```
//!
//! Use the `UPDATE_GOLDENS` environment variable to regenerate the fixture
//! files under `crates/franken-engine/tests/golden/` if you intentionally
//! change the demo output. This binary intentionally exercises *no*
//! franken-engine code path -- it is a minimal pedagogical example of the
//! UPDATE-or-compare flow that `assert_golden`-style helpers throughout the
//! crate implement. Bead `bd-ub6x8.17` relocated this from
//! `crates/franken-engine/tests/simple_golden_demo.rs` so it stops compiling
//! and running on every `cargo test` invocation in CI for zero coverage of
//! product code; see also `bd-ub6x8.3` (single shared helper) and
//! `bd-ub6x8.11` (insta-crate migration spike).

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process;

/// Core golden comparison function following the testing-golden-artifacts pattern.
///
/// The fixtures live under `crates/franken-engine/tests/golden/` relative to
/// the crate manifest directory; resolving them via `CARGO_MANIFEST_DIR` keeps
/// the example invocation working regardless of the caller's `cwd`.
fn assert_golden(test_name: &str, actual: &str) -> Result<(), String> {
    let golden_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden");
    let golden_path = golden_dir.join(format!("{test_name}.golden"));

    if env::var("UPDATE_GOLDENS").is_ok() {
        fs::create_dir_all(&golden_dir)
            .map_err(|e| format!("create golden directory failed: {e}"))?;
        fs::write(&golden_path, actual)
            .map_err(|e| format!("write golden artifact failed: {e}"))?;
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return Ok(());
    }

    let expected = fs::read_to_string(&golden_path).map_err(|_| {
        format!(
            "Golden file missing: {}\n\
             Run with UPDATE_GOLDENS=1 to create it\n\
             Then review and commit: git diff {}",
            golden_path.display(),
            golden_dir.display(),
        )
    })?;

    if actual != expected {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, actual)
            .map_err(|e| format!("write actual artifact failed: {e}"))?;
        return Err(format!(
            "GOLDEN MISMATCH: {test_name}\n\n\
             Expected length: {} bytes\n\
             Actual length:   {} bytes\n\n\
             To update: UPDATE_GOLDENS=1 cargo run --example golden_pattern -p frankenengine-engine\n\
             To review: diff {} {}",
            expected.len(),
            actual.len(),
            golden_path.display(),
            actual_path.display(),
        ));
    }

    // Sweep any stale .actual sibling left by a prior failing run (bd-ub6x8.7).
    let _ = fs::remove_file(golden_path.with_extension("actual"));
    Ok(())
}

fn demo_deterministic_formatting() -> Result<(), String> {
    let mut output = String::new();

    output.push_str("FrankenEngine Golden Artifact Demo\n");
    output.push_str("==================================\n\n");

    let test_values = [42u64, 100, 255, 1000];
    for (i, value) in test_values.iter().enumerate() {
        output.push_str(&format!("Value {}: {:#x} ({})\n", i, value, value));
    }

    output.push_str("\nHex dump:\n");
    let test_bytes = [0x01, 0x02, 0xFF, 0xAB, 0xCD];
    for (i, byte) in test_bytes.iter().enumerate() {
        if i > 0 && i.is_multiple_of(8) {
            output.push('\n');
        }
        output.push_str(&format!("{:02x} ", byte));
    }
    output.push('\n');

    assert_golden("deterministic_formatting", &output)
}

fn demo_error_message_formatting() -> Result<(), String> {
    let mut output = String::new();

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

    assert_golden("error_message_formatting", &output)
}

fn main() {
    // Sanity that the fixture directory is reachable; if it is not, give an
    // actionable error instead of a deep stack trace.
    let golden_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden");
    if !golden_dir.exists()
        && env::var("UPDATE_GOLDENS").is_err()
    {
        eprintln!(
            "golden_pattern: fixture directory missing ({}). Run with UPDATE_GOLDENS=1 first.",
            golden_dir.display()
        );
        process::exit(1);
    }

    for (name, demo) in [
        (
            "deterministic_formatting",
            demo_deterministic_formatting as fn() -> Result<(), String>,
        ),
        ("error_message_formatting", demo_error_message_formatting),
    ] {
        match demo() {
            Ok(()) => println!("golden_pattern: {name} ok"),
            Err(error) => {
                eprintln!("golden_pattern: {name} failed:\n{error}");
                process::exit(1);
            }
        }
    }
}
