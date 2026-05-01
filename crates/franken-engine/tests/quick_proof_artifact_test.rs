use frankenengine_engine::proof_artifact::{ProofArtifactError, validate_event_json_line};

#[test]
fn test_basic_validation_works() {
    // Test valid JSON
    let result = validate_event_json_line(r#"{"test":"value"}"#);
    // This might fail due to missing fields, but it shouldn't panic
    let _ = result;

    // Test invalid JSON
    let result = validate_event_json_line("{invalid}");
    assert!(result.is_err());

    // Test empty string
    let result = validate_event_json_line("");
    assert!(result.is_err());

    // Test large string
    let large_string = format!(r#"{{"test":"{}"}}"#, "x".repeat(100_000));
    let result = validate_event_json_line(&large_string);
    if let Err(ProofArtifactError::JsonStringTooLong { length, max }) = result {
        assert!(length > max);
    } else if let Err(ProofArtifactError::JsonTooLarge { size, max }) = result {
        assert!(size > max);
    }

    // Test deep nesting
    let deep_nested = format!("{}\"test\":\"value\"{}", "{".repeat(30), "}".repeat(30));
    let result = validate_event_json_line(&deep_nested);
    if let Err(ProofArtifactError::JsonTooDeep { depth, max }) = result {
        assert!(depth > max);
    }
}

#[test]
fn test_edge_cases() {
    let test_cases = vec![
        "{",
        "}",
        "null",
        "123",
        "[]",
        "{\"key\":}",
        "{,}",
        "{\"incomplete",
        r#"{"num":1.7976931348623157e+308}"#,
    ];

    for case in test_cases {
        // Should not panic
        let _ = validate_event_json_line(case);
    }
}
