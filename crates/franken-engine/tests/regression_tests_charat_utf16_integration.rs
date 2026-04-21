#![forbid(unsafe_code)]
//! Integration regression tests for commit 3b448a39: charAt UTF-16 indexing fix
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
fn test_charat_utf16_basic_regression() {
    assert_eq!(eval_value("'hello'.charAt(0)"), "h");
    assert_eq!(eval_value("'hello'.charAt(4)"), "o");
}

#[test]
fn test_charat_utf16_out_of_bounds_regression() {
    assert_eq!(eval_value("'abc'.charAt(5)"), "");
    assert_eq!(eval_value("'abc'.charAt(-1)"), "");
}

#[test]
fn test_charat_utf16_surrogate_pairs_regression() {
    let value = eval_value("'a🔥b'.charAt(1)");
    assert!(
        !value.is_empty(),
        "charAt on surrogate pair should return a code unit"
    );
}

#[test]
fn test_charat_no_args_regression() {
    assert_eq!(eval_value("'test'.charAt()"), "t");
}

#[test]
fn test_charat_type_coercion_regression() {
    assert_eq!(eval_value("'hello'.charAt('2')"), "l");
    assert_eq!(eval_value("'hello'.charAt(true)"), "e");
}

#[test]
fn test_charat_integration_pipeline_regression() {
    assert_eq!(eval_value("var s = 'world'; var c = s.charAt(1); c"), "o");
    assert_eq!(eval_value("'abc'.charAt(0) + 'def'"), "adef");
}
