#![forbid(unsafe_code)]
//! Regression tests for commit 5e20ceac: Math.round & ConsoleLevel::Info fixes
//! Provides integration test coverage for fixes that had unit tests but lacked
//! integration tests per docs/MISSING_REGRESSION_TESTS_AUDIT.md

use frankenengine_engine::{JsEngine, QuickJsInspiredNativeEngine};

fn eval_value(source: &str) -> String {
    let mut engine = QuickJsInspiredNativeEngine;
    engine
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for `{source}`: {error:?}"))
        .value
}

#[test]
fn test_console_level_info_dispatch_regression() {
    assert_eq!(eval_value("console.info('test message')"), "undefined");
    assert_eq!(eval_value("console.info(42)"), "undefined");
    assert_eq!(eval_value("console.info(true, false, null)"), "undefined");
    assert_eq!(
        eval_value("console.log('test'); console.info('info'); console.error('error')"),
        "undefined"
    );
}

#[test]
fn test_math_round_comprehensive_integration_regression() {
    assert_eq!(eval_value("Math.round(4.7)"), "5");
    assert_eq!(eval_value("Math.round(4.4)"), "4");
    assert_eq!(eval_value("Math.round(-4.7)"), "-5");
    assert_eq!(eval_value("Math.round(-4.4)"), "-4");
    assert_eq!(eval_value("Math.round(4.5)"), "5");
    assert_eq!(eval_value("Math.round(-4.5)"), "-4");
    assert_eq!(eval_value("Math.round(0.0)"), "0");
    assert_eq!(eval_value("Math.round(-0.0)"), "0");
    assert_eq!(eval_value("Math.round(NaN)"), "NaN");
    assert_eq!(eval_value("Math.round(Infinity)"), "Infinity");
    assert_eq!(eval_value("Math.round(-Infinity)"), "-Infinity");
}

#[test]
fn test_math_round_type_coercion_integration_regression() {
    assert_eq!(eval_value("Math.round('4.7')"), "5");
    assert_eq!(eval_value("Math.round('4.3')"), "4");
    assert_eq!(eval_value("Math.round(true)"), "1");
    assert_eq!(eval_value("Math.round(false)"), "0");
    assert_eq!(eval_value("Math.round(null)"), "0");
    assert_eq!(eval_value("Math.round(undefined)"), "NaN");
}

#[test]
fn test_math_round_expression_context_integration_regression() {
    assert_eq!(eval_value("Math.round(4.7) + Math.round(3.2)"), "8");
    assert_eq!(
        eval_value("var x = 4.7; var y = 3.2; Math.round(x) + Math.round(y)"),
        "8"
    );
    assert_eq!(eval_value("Math.round(Math.abs(-4.7))"), "5");
    assert_eq!(eval_value("Math.round(4.5) + Math.round(-4.5)"), "1");
}
