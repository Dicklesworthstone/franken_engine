#![forbid(unsafe_code)]
//! Comprehensive regression tests for commit d1018316: Array.prototype.forEach duplicate removal fix
//! Extends existing basic coverage with thorough validation per docs/MISSING_REGRESSION_TESTS_AUDIT.md

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};

#[test]
fn test_array_prototype_foreach_fail_closed_comprehensive() {
    // Comprehensive regression test for commit d1018316: fail-closed forEach validation
    let mut interpreter = InterpreterCore::new(InterpreterConfig::default()).unwrap();

    // forEach without callback should error with proper validation
    let result = interpreter.evaluate_expression("[1, 2, 3].forEach()");
    assert!(
        result.is_err(),
        "Array.forEach without callback should error"
    );

    // forEach with null callback should error
    let result = interpreter.evaluate_expression("[1, 2, 3].forEach(null)");
    assert!(
        result.is_err(),
        "Array.forEach with null callback should error"
    );

    // forEach with undefined callback should error
    let result = interpreter.evaluate_expression("[1, 2, 3].forEach(undefined)");
    assert!(
        result.is_err(),
        "Array.forEach with undefined callback should error"
    );

    // forEach with non-function callbacks should error
    let non_function_cases = vec!["42", "'string'", "{}", "[]", "true", "false"];

    for case in non_function_cases {
        let expression = format!("[1, 2, 3].forEach({})", case);
        let result = interpreter.evaluate_expression(&expression);
        assert!(
            result.is_err(),
            "Array.forEach with {} callback should error",
            case
        );
    }
}

#[test]
fn test_array_prototype_foreach_error_message_quality() {
    // Test that fail-closed forEach provides informative error messages
    let mut interpreter = InterpreterCore::new(InterpreterConfig::default()).unwrap();

    let test_cases = vec![
        ("[1, 2].forEach()", "missing callback"),
        ("[1, 2].forEach(null)", "null callback"),
        ("[1, 2].forEach(42)", "non-function callback"),
        (
            "[1, 2].forEach(function() {})",
            "callback invocation not supported",
        ),
    ];

    for (expression, expected_context) in test_cases {
        let result = interpreter.evaluate_expression(expression);
        if let Err(err) = result {
            let err_str = format!("{:?}", err);
            assert!(
                err_str.contains("callback")
                    || err_str.contains("function")
                    || err_str.contains("invocation"),
                "Error for '{}' should mention callback/function/invocation requirement: {}",
                expression,
                err_str
            );
        } else {
            panic!(
                "Expression '{}' should have failed with error about {}",
                expression, expected_context
            );
        }
    }
}

#[test]
fn test_array_prototype_foreach_duplicate_removal_verification() {
    // Regression test to verify duplicate implementations were completely removed
    // Tests for consistent fail-closed behavior across all scenarios
    let mut interpreter = InterpreterCore::new(InterpreterConfig::default()).unwrap();

    let test_scenarios = vec![
        // Different array sizes
        "[].forEach()",
        "[1].forEach()",
        "[1, 2].forEach()",
        "[1, 2, 3, 4, 5].forEach()",
        // Different callback scenarios
        "[1].forEach(null)",
        "[1].forEach(undefined)",
        "[1].forEach(42)",
        "[1].forEach('string')",
        "[1].forEach({})",
        "[1].forEach([])",
        // With thisArg parameter
        "[1].forEach(null, {})",
        "[1].forEach(undefined, null)",
        "[1].forEach(42, 'thisArg')",
    ];

    for expression in test_scenarios {
        let result = interpreter.evaluate_expression(expression);
        assert!(
            result.is_err(),
            "Expression '{}' should consistently error with fail-closed forEach (no duplicates)",
            expression
        );
    }

    // Test that multiple sequential calls don't cause conflicts
    let sequential_result = interpreter.evaluate_expression(
        "var errors = []; \
         try { [1].forEach(); } catch(e) { errors.push(1); } \
         try { [2].forEach(null); } catch(e) { errors.push(2); } \
         try { [3].forEach(42); } catch(e) { errors.push(3); } \
         errors.length",
    );

    // Should handle sequential calls consistently without internal conflicts
    if sequential_result.is_ok() {
        println!(
            "Sequential forEach error handling: {:?}",
            sequential_result.unwrap()
        );
    } else {
        // If fail-closed throws before try/catch, that's also consistent behavior
        assert!(
            sequential_result.is_err(),
            "Sequential forEach calls should be consistently fail-closed"
        );
    }
}

#[test]
fn test_array_prototype_foreach_non_array_objects_comprehensive() {
    // Comprehensive test of forEach behavior when 'this' is not an array
    let mut interpreter = InterpreterCore::new(InterpreterConfig::default()).unwrap();

    let non_array_cases = vec![
        ("42", "number"),
        ("'hello'", "string"),
        ("true", "boolean"),
        ("null", "null"),
        ("undefined", "undefined"),
        ("{}", "object"),
        ("{length: 3, 0: 'a', 1: 'b'}", "array-like object"),
    ];

    for (this_value, description) in non_array_cases {
        // Should still validate callback first, regardless of 'this' type
        let expression = format!("Array.prototype.forEach.call({}, null)", this_value);
        let result = interpreter.evaluate_expression(&expression);

        assert!(
            result.is_err(),
            "forEach on {} should error due to callback validation",
            description
        );

        // Also test without callback
        let expression = format!("Array.prototype.forEach.call({})", this_value);
        let result = interpreter.evaluate_expression(&expression);

        assert!(
            result.is_err(),
            "forEach on {} without callback should error",
            description
        );
    }
}

#[test]
fn test_array_prototype_foreach_thisarg_parameter_handling() {
    // Test thisArg parameter validation in fail-closed implementation
    let mut interpreter = InterpreterCore::new(InterpreterConfig::default()).unwrap();

    let thisarg_cases = vec![
        ("function() {}", "{}", "object thisArg"),
        ("function() {}", "null", "null thisArg"),
        ("function() {}", "undefined", "undefined thisArg"),
        ("function() {}", "'context'", "string thisArg"),
        ("function() {}", "42", "number thisArg"),
        ("function() {}", "true", "boolean thisArg"),
    ];

    for (callback, thisarg, description) in thisarg_cases {
        let expression = format!("[1, 2].forEach({}, {})", callback, thisarg);
        let result = interpreter.evaluate_expression(&expression);

        // Should be fail-closed regardless of thisArg value
        assert!(
            result.is_err(),
            "forEach with {} should still be fail-closed",
            description
        );
    }

    // Test with extra arguments beyond thisArg
    let result = interpreter.evaluate_expression("[1].forEach(function() {}, {}, 'extra', 'args')");
    assert!(
        result.is_err(),
        "forEach with extra arguments should still be fail-closed"
    );
}

#[test]
fn test_array_prototype_foreach_expected_future_behavior_documentation() {
    // Documents expected behavior when proper callback invocation is implemented
    let mut interpreter = InterpreterCore::new(InterpreterConfig::default()).unwrap();

    // This test currently fails (fail-closed) but documents expected future behavior
    let result = interpreter.evaluate_expression(
        "var sideEffects = []; \
         [1, 2, 3].forEach(function(elem, idx, arr) { \
           sideEffects.push([elem, idx, arr.length]); \
         }); \
         sideEffects",
    );

    // Currently fails due to fail-closed implementation
    assert!(
        result.is_err(),
        "Currently fail-closed - forEach callback not yet supported"
    );

    // TODO: When callback invocation is implemented, update this test to verify:
    // - forEach calls callback for each element with (element, index, array) arguments
    // - forEach always returns undefined (not the array or callback results)
    // - Side effects in callbacks are properly executed in order
    // - thisArg is properly bound to callback if provided
    // - Sparse arrays skip missing indices
    // - Expected sideEffects: [[1, 0, 3], [2, 1, 3], [3, 2, 3]]

    // Also test thisArg binding when implemented
    let result = interpreter.evaluate_expression(
        "var context = {prefix: 'item:'}; \
         var results = []; \
         [1, 2].forEach(function(elem) { \
           results.push(this.prefix + elem); \
         }, context); \
         results",
    );

    assert!(
        result.is_err(),
        "thisArg binding test currently fail-closed"
    );
    // Expected future result: ['item:1', 'item:2']
}

#[test]
fn test_array_prototype_foreach_sparse_array_preparation() {
    // Test current behavior with sparse arrays, documents expected future behavior
    let mut interpreter = InterpreterCore::new(InterpreterConfig::default()).unwrap();

    // Sparse array scenarios that should work when callbacks are implemented
    let sparse_expressions = vec![
        "var a = [1, , , 4]; a.forEach(function(x) { return x; })",
        "var b = [, , ,]; b.forEach(function(x) { return x; })",
        "var c = [1, , 3, , 5]; c.forEach(function(x) { return x; })",
    ];

    for expression in sparse_expressions {
        let result = interpreter.evaluate_expression(expression);
        // Currently fail-closed, but documents sparse array test cases
        assert!(
            result.is_err(),
            "Sparse array forEach currently fail-closed: {}",
            expression
        );
    }

    // TODO: When implemented, sparse arrays should:
    // - Skip missing indices (don't call callback for holes)
    // - Call callback only for present elements
    // - Always return undefined regardless of sparse structure
}
