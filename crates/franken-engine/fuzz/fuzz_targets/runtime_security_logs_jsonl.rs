#![no_main]

use frankenengine_engine::runtime_observability::{
    parse_security_logs_jsonl, render_security_logs_jsonl,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Guard against extremely large inputs to focus on logic vs memory exhaustion
    if data.is_empty() || data.len() > 1_048_576 {
        // 1MB cap as suggested in bead
        return;
    }

    // Convert bytes to UTF-8 string, allowing invalid UTF-8 (fuzzing can produce invalid bytes)
    let input = String::from_utf8_lossy(data);

    // Test the parsing function - should never panic
    let parse_result = parse_security_logs_jsonl(&input);

    match parse_result {
        Ok(events) => {
            // If parsing succeeded, test stability via round-trip:
            // parse → render → parse → assert stable event count and fields
            let rendered = render_security_logs_jsonl(&events);
            let reparse_result = parse_security_logs_jsonl(&rendered);

            match reparse_result {
                Ok(reparsed_events) => {
                    // Assert that round-trip parsing is stable
                    assert_eq!(
                        events.len(),
                        reparsed_events.len(),
                        "Round-trip parsing should preserve event count"
                    );

                    // Verify that key fields are preserved across the round trip
                    // (This ensures render/parse consistency)
                    for (original, reparsed) in events.iter().zip(reparsed_events.iter()) {
                        assert_eq!(
                            original.event_type, reparsed.event_type,
                            "Event type should be preserved in round-trip"
                        );
                        assert_eq!(
                            original.outcome, reparsed.outcome,
                            "Outcome should be preserved in round-trip"
                        );
                        assert_eq!(
                            original.timestamp_ms, reparsed.timestamp_ms,
                            "Timestamp should be preserved in round-trip"
                        );
                    }
                }
                Err(_) => {
                    // If re-parsing the rendered output fails, that's a logic bug in render
                    panic!("Round-trip failure: rendered output should always parse");
                }
            }
        }
        Err(_) => {
            // Expected parsing errors are fine - the input was malformed
            // The key invariant is that parsing should never panic, which we test by not panicking here
        }
    }

    // Test specific edge cases if input is reasonable size
    if data.len() < 1024 {
        let test_inputs = [
            "",                           // empty input
            "\n",                         // just newline
            "   \n  \n   ",              // only whitespace and newlines
            "invalid json",               // malformed JSON
            "{\"incomplete\": ",          // incomplete JSON
            "{}",                         // empty object
            "{}\n{}\n{}",                // multiple empty objects
            "{\"unknown_field\": true}", // unknown fields
        ];

        for test_input in &test_inputs {
            let _result = parse_security_logs_jsonl(test_input);
            // Results can be Ok or Err, just testing for no panics
        }
    }
});
