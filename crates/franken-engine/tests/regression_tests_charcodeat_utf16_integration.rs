#![forbid(unsafe_code)]
//! Integration regression tests for commit 5ab2773a: charCodeAt UTF-16 code unit fix
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
fn test_charcodeat_utf16_basic_regression() {
    assert_eq!(eval_value("'A'.charCodeAt(0)"), "65");
    assert_eq!(eval_value("'a'.charCodeAt(0)"), "97");
}

#[test]
fn test_charcodeat_utf16_out_of_bounds_regression() {
    assert_eq!(eval_value("'abc'.charCodeAt(5)"), "NaN");
    assert_eq!(eval_value("'abc'.charCodeAt(-1)"), "NaN");
}

#[test]
fn test_charcodeat_utf16_surrogate_pairs_regression() {
    let value = eval_value("'🔥'.charCodeAt(0)");
    let code_unit = value
        .parse::<u32>()
        .unwrap_or_else(|error| panic!("unexpected charCodeAt result `{value}`: {error}"));
    assert!(
        (0xD800..=0xDBFF).contains(&code_unit),
        "first code unit should be a high surrogate, got {code_unit}"
    );
}

#[test]
fn test_charcodeat_no_args_regression() {
    assert_eq!(eval_value("'test'.charCodeAt()"), "116");
}

#[test]
fn test_charcodeat_type_coercion_regression() {
    assert_eq!(eval_value("'hello'.charCodeAt('1')"), "101");
    assert_eq!(eval_value("'hello'.charCodeAt(true)"), "101");
}

#[test]
fn test_charcodeat_charat_consistency_regression() {
    assert_eq!(eval_value("'ABC'.charAt(1)"), "B");
    assert_eq!(eval_value("'ABC'.charCodeAt(1)"), "66");
}

#[test]
fn test_charcodeat_integration_pipeline_regression() {
    assert_eq!(
        eval_value("var s = 'world'; var code = s.charCodeAt(0); code"),
        "119"
    );
    assert_eq!(eval_value("'A'.charCodeAt(0) + 1"), "66");
}
