#![forbid(unsafe_code)]
//! Integration regression tests for minor fixes and edge cases.

use frankenengine_engine::{JsEngine, QuickJsInspiredNativeEngine};

fn eval_value(source: &str) -> String {
    let mut engine = QuickJsInspiredNativeEngine;
    engine
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for `{source}`: {error:?}"))
        .value
}

#[test]
fn test_string_operations_integration_regression() {
    assert_eq!(eval_value("'hello'.length"), "5");
    assert_eq!(eval_value("'test'.charAt(0)"), "t");
}

#[test]
fn test_console_operations_integration_regression() {
    assert_eq!(eval_value("typeof console"), "object");
}

#[test]
fn test_undefined_null_handling_regression() {
    assert_eq!(eval_value("undefined"), "undefined");
    assert_eq!(eval_value("null"), "null");
}

#[test]
fn test_basic_arithmetic_regression() {
    assert_eq!(eval_value("2 + 3"), "5");
    assert_eq!(eval_value("10 - 4"), "6");
}

#[test]
fn test_variable_operations_regression() {
    assert_eq!(eval_value("var x = 42; x"), "42");
}

#[test]
fn test_error_handling_regression() {
    let mut engine = QuickJsInspiredNativeEngine;
    assert!(engine.eval("invalid syntax here $$").is_err());
    let value = engine
        .eval("1 + 1")
        .unwrap_or_else(|error| panic!("eval failed after prior error: {error:?}"))
        .value;
    assert_eq!(value, "2");
}
