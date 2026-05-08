#![no_main]

use frankenengine_engine::release_checklist_gate::parse_release_checklist_json;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Guard against extremely large inputs that would slow down fuzzing
    if data.is_empty() || data.len() > 65536 {
        return;
    }

    // Test raw JSON parsing - the primary attack surface
    // Convert bytes to UTF-8 string, allowing invalid UTF-8 to be handled gracefully
    let json_result = std::str::from_utf8(data);

    match json_result {
        Ok(json_str) => {
            // Test the target function with UTF-8 JSON string
            let parse_result = parse_release_checklist_json(json_str);

            match parse_result {
                Ok(checklist) => {
                    // If parsing succeeded, validate that the checklist is well-formed
                    // and can round-trip through serialization
                    let serialized = serde_json::to_string(&checklist)
                        .expect("Valid checklist should always serialize");

                    // Verify round-trip consistency
                    let round_trip_result = parse_release_checklist_json(&serialized);
                    assert!(round_trip_result.is_ok(),
                           "Round-trip parsing should succeed for valid checklist");

                    let round_trip_checklist = round_trip_result.unwrap();
                    assert_eq!(checklist, round_trip_checklist,
                              "Round-trip should preserve checklist equality");

                    // Test that the checklist can be processed without panicking
                    // This exercises downstream validation paths mentioned in the bead
                    let _summary = format!("{:?}", checklist);
                }
                Err(_) => {
                    // Expected for malformed JSON - should not panic, just return error gracefully
                    // This is the correct behavior for invalid/malformed input
                }
            }
        }
        Err(_) => {
            // Invalid UTF-8 should be handled gracefully - no panic expected
            // The function expects &str so invalid UTF-8 won't reach it
        }
    }

    // Additional test: try to force edge cases with hand-crafted JSON patterns
    if data.len() < 100 {
        // Test some common edge case patterns if input is small
        let edge_cases = [
            "{}",                               // Empty object
            "[]",                               // Empty array
            "null",                             // Null
            r#"{"missing_fields": true}"#,      // Missing required fields
            r#"{"duplicate": 1, "duplicate": 2}"#, // Duplicate keys
        ];

        for &edge_case in &edge_cases {
            let _result = parse_release_checklist_json(edge_case);
            // Should not panic on any of these inputs
        }
    }
});