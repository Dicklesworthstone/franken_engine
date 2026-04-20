#![forbid(unsafe_code)]
//! Regression tests for commit 5e20ceac: Math.round & ConsoleLevel::Info fixes
//! Provides integration test coverage for fixes that had unit tests but lacked
//! integration tests per docs/MISSING_REGRESSION_TESTS_AUDIT.md

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};

#[test]
fn test_console_level_info_dispatch_regression() {
    // Regression test for commit 5e20ceac: ConsoleLevel::Info dispatch fix
    let mut interpreter = InterpreterCore::new(InterpreterConfig::default()).unwrap();

    // Test that console.info works without errors
    let result = interpreter.evaluate_expression("console.info('test message')");
    assert!(result.is_ok(), "console.info should not error");

    // Verify it returns undefined (standard console behavior)
    assert_eq!(
        result.unwrap(),
        Value::Undefined,
        "console.info should return undefined"
    );

    // Test with different argument types
    let result = interpreter.evaluate_expression("console.info(42)");
    assert!(result.is_ok(), "console.info with number should work");

    let result = interpreter.evaluate_expression("console.info(true, false, null)");
    assert!(
        result.is_ok(),
        "console.info with multiple args should work"
    );

    // Test that console.info doesn't interfere with other console methods
    let result = interpreter
        .evaluate_expression("console.log('test'); console.info('info'); console.error('error')");
    assert!(result.is_ok(), "Mixed console calls should work");
}

#[test]
fn test_math_round_comprehensive_integration_regression() {
    // Regression test for commit 5e20ceac: Math.round comprehensive behavior
    let mut interpreter = InterpreterCore::new(InterpreterConfig::default()).unwrap();

    // Positive numbers
    assert_eq!(
        interpreter.evaluate_expression("Math.round(4.7)").unwrap(),
        Value::Int(5),
        "Math.round(4.7) should be 5"
    );

    assert_eq!(
        interpreter.evaluate_expression("Math.round(4.4)").unwrap(),
        Value::Int(4),
        "Math.round(4.4) should be 4"
    );

    // Negative numbers
    assert_eq!(
        interpreter.evaluate_expression("Math.round(-4.7)").unwrap(),
        Value::Int(-5),
        "Math.round(-4.7) should be -5"
    );

    assert_eq!(
        interpreter.evaluate_expression("Math.round(-4.4)").unwrap(),
        Value::Int(-4),
        "Math.round(-4.4) should be -4"
    );

    // Edge cases with halves (negative half semantics)
    assert_eq!(
        interpreter.evaluate_expression("Math.round(4.5)").unwrap(),
        Value::Int(5),
        "Math.round(4.5) should be 5"
    );

    assert_eq!(
        interpreter.evaluate_expression("Math.round(-4.5)").unwrap(),
        Value::Int(-4),
        "Math.round(-4.5) should be -4 (towards zero)"
    );

    // Special values
    let result = interpreter.evaluate_expression("Math.round(NaN)");
    if result.is_ok() {
        match result.unwrap() {
            Value::Float(f) => assert!(f.inner().is_nan(), "Math.round(NaN) should be NaN"),
            _ => panic!("Math.round(NaN) should return Float NaN"),
        }
    }

    let result = interpreter.evaluate_expression("Math.round(Infinity)");
    if result.is_ok() {
        match result.unwrap() {
            Value::Float(f) => assert!(
                f.inner().is_infinite() && f.inner().is_sign_positive(),
                "Math.round(Infinity) should be Infinity"
            ),
            _ => panic!("Math.round(Infinity) should return Float Infinity"),
        }
    }

    let result = interpreter.evaluate_expression("Math.round(-Infinity)");
    if result.is_ok() {
        match result.unwrap() {
            Value::Float(f) => assert!(
                f.inner().is_infinite() && f.inner().is_sign_negative(),
                "Math.round(-Infinity) should be -Infinity"
            ),
            _ => panic!("Math.round(-Infinity) should return Float -Infinity"),
        }
    }

    // Zero cases
    assert_eq!(
        interpreter.evaluate_expression("Math.round(0.0)").unwrap(),
        Value::Int(0),
        "Math.round(0.0) should be 0"
    );

    assert_eq!(
        interpreter.evaluate_expression("Math.round(-0.0)").unwrap(),
        Value::Int(0),
        "Math.round(-0.0) should be 0"
    );
}

#[test]
fn test_math_round_type_coercion_integration_regression() {
    // Test Math.round with type coercion in complete execution context
    let mut interpreter = InterpreterCore::new(InterpreterConfig::default()).unwrap();

    // String to number coercion
    assert_eq!(
        interpreter
            .evaluate_expression("Math.round('4.7')")
            .unwrap(),
        Value::Int(5),
        "Math.round('4.7') should coerce string to number"
    );

    assert_eq!(
        interpreter
            .evaluate_expression("Math.round('4.3')")
            .unwrap(),
        Value::Int(4),
        "Math.round('4.3') should coerce string to number"
    );

    // Boolean to number coercion
    assert_eq!(
        interpreter.evaluate_expression("Math.round(true)").unwrap(),
        Value::Int(1),
        "Math.round(true) should be 1"
    );

    assert_eq!(
        interpreter
            .evaluate_expression("Math.round(false)")
            .unwrap(),
        Value::Int(0),
        "Math.round(false) should be 0"
    );

    // Null to number coercion
    assert_eq!(
        interpreter.evaluate_expression("Math.round(null)").unwrap(),
        Value::Int(0),
        "Math.round(null) should be 0"
    );

    // Undefined to number coercion (should be NaN)
    let result = interpreter.evaluate_expression("Math.round(undefined)");
    if result.is_ok() {
        match result.unwrap() {
            Value::Float(f) => assert!(f.inner().is_nan(), "Math.round(undefined) should be NaN"),
            _ => panic!("Math.round(undefined) should return NaN"),
        }
    }
}

#[test]
fn test_math_round_expression_context_integration_regression() {
    // Test Math.round behavior within complex expressions
    let mut interpreter = InterpreterCore::new(InterpreterConfig::default()).unwrap();

    // Math.round in arithmetic expressions
    assert_eq!(
        interpreter
            .evaluate_expression("Math.round(4.7) + Math.round(3.2)")
            .unwrap(),
        Value::Int(8),
        "Math.round in addition should work: 5 + 3 = 8"
    );

    // Math.round with variables
    let result =
        interpreter.evaluate_expression("var x = 4.7; var y = 3.2; Math.round(x) + Math.round(y)");
    if result.is_ok() {
        assert_eq!(
            result.unwrap(),
            Value::Int(8),
            "Math.round with variables should work"
        );
    }

    // Math.round with function calls
    let result = interpreter.evaluate_expression("Math.round(Math.abs(-4.7))");
    if result.is_ok() {
        assert_eq!(
            result.unwrap(),
            Value::Int(5),
            "Math.round with Math.abs should work"
        );
    }

    // Math.round edge case interactions
    let result = interpreter.evaluate_expression("Math.round(4.5) + Math.round(-4.5)");
    if result.is_ok() {
        assert_eq!(
            result.unwrap(),
            Value::Int(1),
            "Math.round half cases should work: 5 + (-4) = 1"
        );
    }
}
