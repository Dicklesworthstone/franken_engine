use frankenengine_engine::proof_artifact::{validate_event_json_line, ProofArtifactError};
use proptest::prelude::*;

// Custom strategy for generating potentially problematic JSON strings
fn json_fuzz_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Normal JSON objects
        prop::collection::vec(
            prop::string::string_regex(r#""[a-zA-Z0-9_]+""#).unwrap(),
            0..20
        )
        .prop_map(|fields| {
            if fields.is_empty() {
                "{}".to_string()
            } else {
                format!("{{{}}}", fields.join(":null,"))
            }
        }),
        // Very deep nested objects (to test depth limit)
        (0..30u32).prop_map(|depth| {
            let open_braces = "{".repeat(depth as usize);
            let close_braces = "}".repeat(depth as usize);
            format!("{}\"test\":\"value\"{}", open_braces, close_braces)
        }),
        // Large strings (to test string length limit)
        (1000..50000usize).prop_map(|size| { format!(r#"{{"test":"{}"}}"#, "x".repeat(size)) }),
        // Large objects (to test size limit)
        (100..1000usize).prop_map(|count| {
            let fields: Vec<String> = (0..count)
                .map(|i| format!(r#""field{}":"value{}""#, i, i))
                .collect();
            format!("{{{}}}", fields.join(","))
        }),
        // Arrays with many elements
        (0..1000usize).prop_map(|count| {
            let elements: Vec<String> = (0..count).map(|i| format!(r#""item{}""#, i)).collect();
            format!("[{}]", elements.join(","))
        }),
        // Special number values
        prop_oneof![
            Just(r#"{"num":null}"#.to_string()),
            Just(r#"{"num":1.7976931348623157e+308}"#.to_string()), // Very large number
            Just(r#"{"num":-1.7976931348623157e+308}"#.to_string()), // Very small number
            Just(r#"{"num":1e-1000}"#.to_string()),                 // Very small positive
        ],
        // Malformed JSON
        prop_oneof![
            Just("{".to_string()),
            Just("}".to_string()),
            Just("{,}".to_string()),
            Just("{\"key\":}".to_string()),
            Just("{\"key\":\"val\",}".to_string()),
            Just("null".to_string()),
            Just("\"string\"".to_string()),
            Just("123".to_string()),
            Just("".to_string()),
            Just("{\"".to_string()),
            Just("{\"key\"".to_string()),
            Just("{\"key\":\"".to_string()),
        ],
        // Mixed valid/invalid patterns
        any::<Vec<u8>>().prop_map(|bytes| String::from_utf8_lossy(&bytes).to_string()),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10000))]

    #[test]
    fn test_validate_event_json_line_doesnt_crash(input in json_fuzz_strategy()) {
        // The main goal is to ensure we don't crash/panic
        let result = validate_event_json_line(&input);

        // We don't care about the result, just that it doesn't panic
        // But let's verify error types are sensible when they occur
        if let Err(error) = result {
            match error {
                ProofArtifactError::JsonTooDeep { depth, max } => {
                    assert!(depth > max);
                    assert!(max > 0);
                }
                ProofArtifactError::JsonTooLarge { size, max } => {
                    assert!(size > max);
                    assert!(max > 0);
                }
                ProofArtifactError::JsonStringTooLong { length, max } => {
                    assert!(length > max);
                    assert!(max > 0);
                }
                ProofArtifactError::JsonInvalidNumber(msg) => {
                    assert!(!msg.is_empty());
                }
                ProofArtifactError::JsonMalformed(msg) => {
                    assert!(!msg.is_empty());
                }
                _ => {
                    // Other errors are also acceptable
                }
            }
        }
    }

    #[test]
    fn test_validate_specific_edge_cases(
        depth in 0..50u32,
        str_len in 0..100000usize,
        array_len in 0..2000usize
    ) {
        // Test deeply nested objects
        if depth > 0 {
            let nested = format!("{}\"x\":1{}", "{".repeat(depth as usize), "}".repeat(depth as usize));
            let _ = validate_event_json_line(&nested);
        }

        // Test long strings
        if str_len > 0 {
            let long_str = format!(r#"{{"test":"{}"}}"#, "a".repeat(str_len));
            let _ = validate_event_json_line(&long_str);
        }

        // Test large arrays
        if array_len > 0 {
            let large_array = format!("[{}]", vec!["1"; array_len].join(","));
            let _ = validate_event_json_line(&large_array);
        }
    }
}

#[cfg(test)]
mod focused_tests {
    use super::*;

    #[test]
    fn test_known_edge_cases() {
        let test_cases = vec![
            // Size limits
            format!(r#"{{"test":"{}"}}"#, "x".repeat(100_000)), // Too large string
            "x".repeat(100_000),                                // Too large overall
            // Depth limits
            format!("{}\"x\":1{}", "{".repeat(30), "}".repeat(30)), // Too deep
            // Invalid JSON
            "{".to_string(),
            "}".to_string(),
            "null".to_string(),
            "".to_string(),
            "{\"key\":}".to_string(),
            "{,}".to_string(),
            // Valid minimal cases
            "{}".to_string(),
            r#"{"test":"value"}"#.to_string(),
            "[]".to_string(),
            r#"[1,2,3]"#.to_string(),
            // Numbers
            r#"{"num":1.7976931348623157e+308}"#.to_string(), // Large number
            r#"{"num":null}"#.to_string(),
        ];

        for test_case in test_cases {
            // Should not panic
            let _ = validate_event_json_line(&test_case);
        }
    }
}
