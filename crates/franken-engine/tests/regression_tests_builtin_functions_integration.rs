#![forbid(unsafe_code)]
//! Integration regression tests for builtin function implementations.

use frankenengine_engine::{JsEngine, QuickJsInspiredNativeEngine};

fn eval_value(source: &str) -> String {
    let mut engine = QuickJsInspiredNativeEngine;
    engine
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for `{source}`: {error:?}"))
        .value
}

#[test]
fn test_math_builtin_functions_regression() {
    assert_eq!(eval_value("Math.abs(-5)"), "5");
    assert_eq!(eval_value("Math.max(1, 5, 3)"), "5");
    assert_eq!(eval_value("Math.min(10, 2, 8)"), "2");
}

#[test]
fn test_array_length_property_regression() {
    assert_eq!(eval_value("[].length"), "0");
    assert_eq!(eval_value("[1, 2, 3].length"), "3");
}

#[test]
fn test_array_access_regression() {
    assert_eq!(eval_value("[10, 20, 30][1]"), "20");
    assert_eq!(eval_value("[1, 2][5]"), "undefined");
}

#[test]
fn test_typeof_operator_regression() {
    let test_cases = [
        ("typeof 42", "number"),
        ("typeof 'string'", "string"),
        ("typeof true", "boolean"),
        ("typeof undefined", "undefined"),
        ("typeof null", "object"),
    ];

    for (expr, expected) in test_cases {
        assert_eq!(eval_value(expr), expected, "{expr} should return {expected}");
    }
}

#[test]
fn test_boolean_operations_regression() {
    assert_eq!(eval_value("true"), "true");
    assert_eq!(eval_value("false"), "false");
    assert_eq!(eval_value("true && false"), "false");
}

#[test]
fn test_number_operations_regression() {
    assert_eq!(eval_value("123"), "123");
    assert_eq!(eval_value("3.14"), "3.14");
    assert_eq!(eval_value("-42"), "-42");
}

#[test]
fn test_function_call_regression() {
    assert_eq!(eval_value("Math.round(4.6)"), "5");
    assert_eq!(eval_value("'hello'.charAt(1)"), "e");
}
