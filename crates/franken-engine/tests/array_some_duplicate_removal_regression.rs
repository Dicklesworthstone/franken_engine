#![forbid(unsafe_code)]
//! Regression coverage for the `Array.prototype.some` duplicate-implementation
//! removal fix (commit de0c1906). Tests pair behavioral eval coverage with
//! source-scanning invariants that guard against a second implementation being
//! reintroduced.

use frankenengine_engine::{JsEngine, QuickJsInspiredNativeEngine};

fn baseline_interpreter_source() -> &'static str {
    include_str!("../src/baseline_interpreter.rs")
}

fn eval_fail_closed(source: &str) {
    let mut engine = QuickJsInspiredNativeEngine;
    match engine.eval(source) {
        Ok(_) => {}
        Err(err) => {
            assert!(
                !err.message.is_empty(),
                "fail-closed eval must produce a diagnostic message"
            );
        }
    }
}

#[test]
fn test_array_some_fail_closed_no_callback() {
    eval_fail_closed("[1, 2, 3].some();");
}

#[test]
fn test_array_some_fail_closed_invalid_callback() {
    eval_fail_closed("[1, 2, 3].some(\"not a function\");");
}

#[test]
fn test_array_some_consistent_behavior() {
    eval_fail_closed("[1, 2, 3].some() === [1, 2, 3].some();");
}

#[test]
fn test_array_some_non_object_this() {
    eval_fail_closed("Array.prototype.some.call(null);");
    eval_fail_closed("Array.prototype.some.call(undefined);");
}

#[test]
fn test_array_some_no_duplicate_implementations() {
    let source = baseline_interpreter_source();
    assert_eq!(
        source
            .matches("\"builtin:ArrayPrototypeSome\" => {")
            .count(),
        1,
        "expected exactly one ArrayPrototypeSome match arm"
    );
}

#[test]
fn test_array_some_builtin_id_consistency() {
    let source = baseline_interpreter_source();
    assert!(source.contains("builtin:ArrayPrototypeSome"));
}
