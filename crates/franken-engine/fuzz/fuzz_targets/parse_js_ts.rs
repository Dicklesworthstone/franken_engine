#![no_main]

use frankenengine_engine::parser_api_stability::{parse_script, parse_module};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Guard against extremely large inputs that would slow down fuzzing.
    // Use 64KB limit as suggested in the bead description.
    if data.is_empty() || data.len() > 65536 {
        return;
    }

    // Convert bytes to string, allowing invalid UTF-8 (common in fuzzing)
    let source = String::from_utf8_lossy(data);

    // Test parse_script - should never panic on any input
    let _script_result = parse_script(&source);

    // Test parse_module - should never panic on any input
    let _module_result = parse_module(&source);

    // Both functions should handle any string input gracefully,
    // either succeeding with a valid AST or failing with a proper error.
    // The key invariant is: no panics, no infinite loops, no excessive memory usage.
});