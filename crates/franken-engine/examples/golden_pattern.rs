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
//! Use `INSTA_UPDATE=always` to regenerate the snapshots under
//! `crates/franken-engine/tests/snapshots/` if the demo output intentionally
//! changes. This binary intentionally exercises *no* franken-engine code path;
//! it is a minimal pedagogical example of the insta snapshot flow that replaced
//! the older hand-rolled update/compare pattern. Bead `bd-ub6x8.17` relocated
//! this from `crates/franken-engine/tests/simple_golden_demo.rs` so it
//! stops compiling and running on every `cargo test` invocation in CI for zero
//! coverage of product code; see also `bd-ub6x8.11` (insta-crate migration
//! spike).

fn assert_demo_snapshot(test_name: &str, actual: &str) {
    let snapshot_name = format!("golden_pattern__{test_name}");

    insta::with_settings!({
        snapshot_path => "../tests/snapshots",
        prepend_module_to_snapshot => false,
    }, {
        insta::assert_snapshot!(snapshot_name, actual);
    });
}

fn demo_deterministic_formatting() -> String {
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

    output
}

fn demo_error_message_formatting() -> String {
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

    output
}

fn main() {
    for (name, demo) in [
        (
            "deterministic_formatting",
            demo_deterministic_formatting as fn() -> String,
        ),
        ("error_message_formatting", demo_error_message_formatting),
    ] {
        assert_demo_snapshot(name, &demo());
        println!("golden_pattern: {name} ok");
    }
}
