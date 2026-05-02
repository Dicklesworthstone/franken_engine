//! Strict mode `with` statement rejection test (ES2020 §13.11.1)
//!
//! This test validates that FrankenEngine properly rejects `with` statements
//! in strict mode contexts with the correct SyntaxError, addressing the
//! critical gap identified in CRITICAL_REVIEW_BEAD_STRICT_MODE_GAPS.md

#![forbid(unsafe_code)]

use frankenengine_engine::parser::ParseError;
use frankenengine_engine::parser_api_stability::parse_script;

#[test]
fn strict_mode_with_statement_global_context_rejection() {
    // ES2020 §13.11.1: with statements are forbidden in strict mode
    let source = r#""use strict"; with (obj) { x = 1; }"#;

    let result = parse_script(source);

    match result {
        Ok(_) => {
            // SPEC GAP: Parser accepts with statement in strict mode
            panic!(
                "FALSE ACCEPTANCE: with statement should be SyntaxError in strict mode, but parsing succeeded. \
                This indicates missing ES2020 §13.11.1 implementation. \
                Expected: SyntaxError with strict_mode_with_statement error code."
            );
        }
        Err(parser_error) => {
            // Verify this is the expected strict mode error
            let error_message = parser_error.to_string();
            let error_code = format!("{:?}", parser_error.code);

            // Check for strict mode with statement error code
            if error_code == "StrictModeWithStatement" {
                // SUCCESS: Proper strict mode validation
                println!("✅ CORRECT REJECTION: with statement properly rejected in strict mode");
                println!("   Error code: {}", error_code);
                println!("   Message: {}", error_message);
            } else {
                // WRONG ERROR: Rejected for different reason
                panic!(
                    "INCORRECT REJECTION: with statement rejected but with wrong error code.\n\
                    Expected: 'StrictModeWithStatement'\n\
                    Actual: '{}'\n\
                    Message: '{}'\n\
                    This indicates parser rejects with statements generally, not strict-mode-specific rejection.",
                    error_code, error_message
                );
            }
        }
    }
}

#[test]
fn strict_mode_with_statement_function_context_rejection() {
    // ES2020 §13.11.1: with statements forbidden in function strict mode too
    let source = r#"function f() { "use strict"; with (obj) { return x; } }"#;

    let result = parse_script(source);

    match result {
        Ok(_) => {
            panic!(
                "FALSE ACCEPTANCE: with statement in function strict mode should be SyntaxError, but parsing succeeded."
            );
        }
        Err(parser_error) => {
            let error_code = format!("{:?}", parser_error.code);
            assert_eq!(
                error_code,
                "StrictModeWithStatement",
                "Expected strict mode with statement error, got: {} - {}",
                error_code,
                parser_error.to_string()
            );
        }
    }
}

#[test]
fn non_strict_mode_with_statement_should_parse() {
    // Control test: with statements should parse successfully in non-strict mode
    let source = r#"with (obj) { x = 1; }"#;

    let result = parse_script(source);

    match result {
        Ok(_) => {
            // SUCCESS: Non-strict mode allows with statements
        }
        Err(parser_error) => {
            // This suggests with statements aren't implemented at all
            let error_code = format!("{:?}", parser_error.code);
            let error_message = parser_error.to_string();

            if error_code.contains("Unsupported") || error_message.contains("unsupported") {
                panic!(
                    "IMPLEMENTATION GAP: with statements not implemented at all.\n\
                    Error code: {}\n\
                    Message: {}\n\
                    This indicates missing WithStatement AST variant, not just strict mode validation.",
                    error_code, error_message
                );
            } else {
                panic!(
                    "UNEXPECTED FAILURE: with statement failed to parse in non-strict mode.\n\
                    Error code: {}\n\
                    Message: {}",
                    error_code, error_message
                );
            }
        }
    }
}

#[test]
fn strict_mode_valid_code_should_parse() {
    // Control test: valid strict mode code should parse successfully
    let source = r#""use strict"; var x = 1; console.log(x);"#;

    let result = parse_script(source);

    assert!(
        result.is_ok(),
        "Valid strict mode code should parse successfully, got error: {:?}",
        result.err()
    );
}

/// Test the specific error details for debugging parser implementation
#[test]
fn inspect_with_statement_error_details() {
    let test_cases = vec![
        (r#""use strict"; with (obj) { }"#, "global strict mode"),
        (
            r#"function f() { "use strict"; with (x) { } }"#,
            "function strict mode",
        ),
        (r#"with (obj) { }"#, "non-strict mode"),
    ];

    for (source, context) in test_cases {
        println!("\n=== Testing {} ===", context);
        println!("Source: {}", source);

        match parse_script(source) {
            Ok(_) => println!("✅ PARSED SUCCESSFULLY"),
            Err(e) => {
                println!("❌ PARSE ERROR:");
                println!("   Error code: {:?}", e.code);
                println!("   Message: {}", e.to_string());
                println!("   Debug: {:?}", e);
            }
        }
    }
}
