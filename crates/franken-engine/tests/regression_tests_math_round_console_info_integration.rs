#![forbid(unsafe_code)]
//! Integration regression tests for commit 5e20ceac: Math.round + ConsoleLevel::Info fix
//! Addresses missing regression test from docs/MISSING_REGRESSION_TESTS_AUDIT.md

use frankenengine_engine::{JsEngine, QuickJsInspiredNativeEngine};

fn eval_value(source: &str) -> String {
    let mut engine = QuickJsInspiredNativeEngine;
    engine
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for `{source}`: {error:?}"))
        .value
}

#[test]
fn test_math_round_basic_regression() {
    assert_eq!(eval_value("Math.round(4.7)"), "5");
    assert_eq!(eval_value("Math.round(4.4)"), "4");
}

#[test]
fn test_math_round_edge_cases_regression() {
    assert_eq!(eval_value("Math.round(-4.7)"), "-5");
    assert_eq!(eval_value("Math.round(0.0)"), "0");
    assert_eq!(eval_value("Math.round(0.5)"), "1");
}

#[test]
fn test_console_info_level_regression() {
    assert_eq!(eval_value("typeof console"), "object");
    assert_eq!(eval_value("console.info('test message')"), "undefined");
}

#[test]
fn test_math_round_type_coercion_regression() {
    assert_eq!(eval_value("Math.round('4.7')"), "5");
    assert_eq!(eval_value("Math.round(true)"), "1");
}
