#![allow(clippy::too_many_arguments)]

//! Golden file regression testing for adversarial fuzzing harnesses
//!
//! This module implements golden file testing for fuzzing harness outputs to catch
//! behavioral regressions. When fuzzing finds interesting cases, we lock down their
//! outputs as golden files to ensure future changes don't break the behavior.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::LazyLock;

// golden_diag lives under tests/_support/ (bd-ub6x8.18); pulled in via #[path]
// so we don't waste a per-crate test-binary compile on the helper alone.
#[path = "_support/golden_diag.rs"]
mod golden_diag;

// Hoisted scrub patterns (bd-ub6x8.13).
static SCRUB_SHA256: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"sha256:[a-f0-9]{64}").unwrap());
static SCRUB_MEMORY_ADDRESS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"0x[0-9a-f]{6,16}").unwrap());

use frankenengine_engine::parser::{
    CanonicalEs2020Parser, ParseDiagnosticEnvelope, ParseGoal, ParserBudget, ParserMode,
    ParserOptions,
};

/// Golden test result for parser boundary fuzzing
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParserGoldenResult {
    /// Input data (hex encoded for readability)
    input_hex: String,
    /// Parse goal (script or module)
    goal: String,
    /// Parser options used
    options: ParserOptionsSnapshot,
    /// Whether parse succeeded
    parse_succeeded: bool,
    /// Canonical hash of result (for success case)
    result_hash: Option<String>,
    /// Error diagnostic hash (for error case)
    error_hash: Option<String>,
    /// Event IR canonical hash
    event_ir_hash: String,
    /// Number of events in event IR
    event_count: usize,
    /// Parse event types present
    event_types: Vec<String>,
    /// Determinism check passed
    deterministic: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParserOptionsSnapshot {
    mode: String,
    max_source_bytes: u64,
    max_token_count: u64,
    max_recursion_depth: u64,
}

/// Scrub non-deterministic values from golden output
fn scrub_golden_output(input: &str) -> String {
    let mut scrubbed = input.to_string();
    scrubbed = SCRUB_SHA256
        .replace_all(&scrubbed, "sha256:[HASH]")
        .into_owned();
    scrubbed = SCRUB_MEMORY_ADDRESS
        .replace_all(&scrubbed, "0x[ADDR]")
        .into_owned();
    scrubbed
}

// Inline assert_golden + summarize_golden_diff replaced by the shared
// GoldenDiag helper (bd-ub6x8.3 sweep). The fixture path stays under
// tests/golden/fuzz_adversarial/<test>.json so existing fixtures keep
// matching without a re-bake.
fn assert_golden(test_name: &str, actual: &str) {
    let fixture_path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("tests/golden/fuzz_adversarial/{test_name}.json"));
    golden_diag::GoldenDiag {
        framework_name: "Fuzz adversarial golden",
        regen_env_var: "UPDATE_GOLDENS",
    }
    .assert_golden_match(actual, &fixture_path, test_name, None);
}

/// Run parser boundary program and capture golden output
fn run_parser_boundary_golden(data: &[u8]) -> ParserGoldenResult {
    const MAX_PARSER_INPUT_BYTES: usize = 8 * 1024;

    if data.is_empty() || data.len() > MAX_PARSER_INPUT_BYTES {
        return ParserGoldenResult {
            input_hex: hex::encode(data),
            goal: "skipped".to_string(),
            options: ParserOptionsSnapshot {
                mode: "skipped".to_string(),
                max_source_bytes: 0,
                max_token_count: 0,
                max_recursion_depth: 0,
            },
            parse_succeeded: false,
            result_hash: None,
            error_hash: None,
            event_ir_hash: "skipped".to_string(),
            event_count: 0,
            event_types: vec![],
            deterministic: true,
        };
    }

    let goal = parser_boundary_goal(data);
    let source = parser_boundary_source(data, goal);
    let options = parser_boundary_options(data);
    let parser = CanonicalEs2020Parser;

    let (result, event_ir) = parser.parse_with_event_ir(source.as_str(), goal, &options);
    let event_ir_hash = event_ir.canonical_hash();

    // bd-ub6x8.9: route through the types' canonical `as_str()` rather than
    // through Debug. `Debug` is not a stability contract — a future enum
    // variant rename, derived-Debug field reorder, or hand-written impl change
    // would silently break every parser_boundary_case_* golden. `as_str()` is
    // the documented stable snake_case tag (`ParseEventKind::as_str`,
    // `ParseGoal::as_str`, `ParserMode::as_str`).
    let event_types: Vec<String> = event_ir
        .events
        .iter()
        .map(|e| e.kind.as_str().to_string())
        .collect();

    let mut golden = ParserGoldenResult {
        input_hex: hex::encode(data),
        goal: goal.as_str().to_string(),
        options: ParserOptionsSnapshot {
            mode: options.mode.as_str().to_string(),
            max_source_bytes: options.budget.max_source_bytes,
            max_token_count: options.budget.max_token_count,
            max_recursion_depth: options.budget.max_recursion_depth,
        },
        parse_succeeded: result.is_ok(),
        result_hash: None,
        error_hash: None,
        event_ir_hash,
        event_count: event_ir.events.len(),
        event_types,
        deterministic: true,
    };

    match result {
        Ok(tree) => {
            golden.result_hash = Some(tree.canonical_hash());

            // Verify determinism
            let (repeat, repeat_ir) = parser.parse_with_event_ir(source.as_str(), goal, &options);
            if let Ok(repeat_tree) = repeat {
                golden.deterministic = repeat_tree.canonical_hash() == tree.canonical_hash()
                    && repeat_ir.canonical_hash() == event_ir.canonical_hash();
            } else {
                golden.deterministic = false;
            }
        }
        Err(error) => {
            let diagnostic = ParseDiagnosticEnvelope::from_parse_error(&error);
            golden.error_hash = Some(diagnostic.canonical_hash());
        }
    }

    golden
}

// Helper functions from fuzz_adversarial.rs
fn byte(data: &[u8], index: usize) -> u8 {
    data.get(index).copied().unwrap_or(0)
}

fn parser_boundary_goal(data: &[u8]) -> ParseGoal {
    if byte(data, 0) & 1 == 0 {
        ParseGoal::Script
    } else {
        ParseGoal::Module
    }
}

fn parser_boundary_options(data: &[u8]) -> ParserOptions {
    const MAX_PARSER_INPUT_BYTES: usize = 8 * 1024;

    ParserOptions {
        mode: ParserMode::ScalarReference,
        budget: ParserBudget {
            max_source_bytes: u64::try_from(MAX_PARSER_INPUT_BYTES)
                .expect("parser input byte limit fits u64"),
            max_token_count: 16 + u64::from(byte(data, 1)),
            max_recursion_depth: 8 + u64::from(byte(data, 2) % 64),
        },
    }
}

fn parser_boundary_source(data: &[u8], goal: ParseGoal) -> String {
    if data.len() < 4 {
        match goal {
            ParseGoal::Script => "42;".to_string(),
            ParseGoal::Module => "export default 42;".to_string(),
        }
    } else {
        // Use data as synthetic source
        match goal {
            ParseGoal::Script => {
                format!("var x = {}; x + {};", byte(data, 3), byte(data, 4))
            }
            ParseGoal::Module => {
                format!(
                    "export const x = {}; export default x + {};",
                    byte(data, 3),
                    byte(data, 4)
                )
            }
        }
    }
}

#[test]
fn parser_boundary_golden_regression_test() {
    // Test a curated set of interesting parser boundary cases
    let test_cases = [
        // Empty case
        Vec::new(),
        // Simple script case
        vec![0x00, 0x10, 0x08, 0x42],
        // Module case
        vec![0x01, 0x20, 0x10, 0x7B],
        // High recursion case
        vec![0x00, 0x40, 0xFF, 0x10],
        // Edge case with specific pattern
        vec![0x01, 0x01, 0x01, 0x01, 0x41, 0x42, 0x43],
    ];

    for (i, test_data) in test_cases.iter().enumerate() {
        let result = run_parser_boundary_golden(test_data);
        let json_output =
            serde_json::to_string_pretty(&result).expect("should serialize golden result");
        let scrubbed = scrub_golden_output(&json_output);

        assert_golden(&format!("parser_boundary_case_{:02}", i), &scrubbed);
    }
}

#[test]
fn parser_boundary_known_regression_cases() {
    // Test specific cases that have caused issues in the past
    // These would come from actual fuzzing findings

    // Case 1: Maximum recursion depth
    let max_recursion = vec![0x00, 0xFF, 0xFF, 0x28, 0x28, 0x28, 0x28];
    let result = run_parser_boundary_golden(&max_recursion);
    let json_output = serde_json::to_string_pretty(&result).unwrap();
    let scrubbed = scrub_golden_output(&json_output);
    assert_golden("parser_boundary_max_recursion", &scrubbed);

    // Case 2: Minimal valid module
    let minimal_module = vec![0x01, 0x00, 0x00, 0x00];
    let result = run_parser_boundary_golden(&minimal_module);
    let json_output = serde_json::to_string_pretty(&result).unwrap();
    let scrubbed = scrub_golden_output(&json_output);
    assert_golden("parser_boundary_minimal_module", &scrubbed);
}

#[test]
fn golden_output_is_deterministic() {
    // Verify that the same input produces the same golden output
    let test_data = vec![0x01, 0x10, 0x08, 0x42];

    let result1 = run_parser_boundary_golden(&test_data);
    let result2 = run_parser_boundary_golden(&test_data);

    // Results should be identical
    assert_eq!(result1.result_hash, result2.result_hash);
    assert_eq!(result1.event_ir_hash, result2.event_ir_hash);
    assert_eq!(result1.event_count, result2.event_count);
    assert!(result1.deterministic && result2.deterministic);
}
