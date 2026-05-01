#![no_main]

use libfuzzer_sys::fuzz_target;
use frankenengine_engine::proof_artifact::{validate_event_json_line, ProofArtifactError};

fuzz_target!(|data: &[u8]| {
    // Convert bytes to string, allowing invalid UTF-8 to be handled gracefully
    let input = String::from_utf8_lossy(data);

    // Try to validate the input as a JSON line from events.jsonl
    let result = validate_event_json_line(&input);

    // We're fuzzing for crashes, not correctness, so we just ensure it doesn't panic
    // The function should either succeed or fail gracefully with a ProofArtifactError
    match result {
        Ok(_event) => {
            // Valid event parsed successfully
        }
        Err(ProofArtifactError::JsonTooDeep { depth, max }) => {
            // Ensure the error makes sense
            assert!(depth > max);
        }
        Err(ProofArtifactError::JsonTooLarge { size, max }) => {
            // Ensure the error makes sense
            assert!(size > max);
        }
        Err(ProofArtifactError::JsonStringTooLong { length, max }) => {
            // Ensure the error makes sense
            assert!(length > max);
        }
        Err(ProofArtifactError::JsonInvalidNumber(_)) => {
            // Non-finite numbers should be rejected
        }
        Err(ProofArtifactError::JsonMalformed(_)) => {
            // Invalid JSON should be rejected
        }
        Err(ProofArtifactError::MissingField(_)) => {
            // Missing required fields should be rejected
        }
        Err(_) => {
            // Other errors are also acceptable
        }
    }

    // Additional targeted fuzzing: try to create pathological JSON structures
    if input.len() < 1000 {
        // Test deeply nested objects
        let nested_obj = format!("{}{}{}",
            "{".repeat(20),
            input.replace("}", "").replace("{", ""),
            "}".repeat(20)
        );
        let _ = validate_event_json_line(&nested_obj);

        // Test large strings
        if !input.is_empty() {
            let large_string = format!(r#"{{"test":"{}"}}"#, "x".repeat(40000));
            let _ = validate_event_json_line(&large_string);
        }

        // Test arrays with many elements
        let large_array = format!("[{}]",
            std::iter::repeat(&input).take(100).collect::<Vec<_>>().join(",")
        );
        let _ = validate_event_json_line(&large_array);
    }
});