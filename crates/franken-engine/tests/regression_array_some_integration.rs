#![forbid(unsafe_code)]
//! Integration tests for `Array.prototype.some` duplicate-removal regression coverage.

use frankenengine_engine::{JsEngine, QuickJsInspiredNativeEngine};

fn eval_value(source: &str) -> String {
    let mut engine = QuickJsInspiredNativeEngine;
    engine
        .eval(source)
        .unwrap_or_else(|error| panic!("eval failed for `{source}`: {error:?}"))
        .value
}

#[test]
fn array_some_duplicate_removal_integration() {
    assert_eq!(
        eval_value("[1, 2, 3].some(function(value) { return value === 2; })"),
        "true"
    );
}

#[test]
fn array_some_false_when_no_match() {
    assert_eq!(
        eval_value("[1, 2, 3].some(function(value) { return value > 10; })"),
        "false"
    );
}

#[test]
fn array_some_empty_array_handling() {
    assert_eq!(eval_value("[].some(function() { return true; })"), "false");
}

#[test]
fn array_some_builtin_id_consistency() {
    let source = include_str!("../src/baseline_interpreter.rs");
    assert!(source.contains("builtin:ArrayPrototypeSome"));
}
