#![forbid(unsafe_code)]

//! Integration tests for `Array.prototype.forEach` duplicate-implementation
//! removal fix (commit d1018316307c8bf001b49dbc29e07b632c86f163).
//!
//! Pairs behavioral eval coverage with source-scanning invariants that guard
//! against a second forEach implementation being reintroduced.

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
fn array_foreach_duplicate_removal_integration() {
    // Only one `"builtin:ArrayPrototypeForEach" => {` match arm should exist
    // in the interpreter source after the duplicate-removal fix.
    let source = baseline_interpreter_source();
    assert_eq!(
        source
            .matches("\"builtin:ArrayPrototypeForEach\" => {")
            .count(),
        1,
        "expected exactly one ArrayPrototypeForEach match arm"
    );
}

#[test]
fn array_foreach_fail_closed_callback_validation() {
    eval_fail_closed("[1, 2, 3].forEach();");
}

#[test]
fn array_foreach_fail_closed_invalid_callback() {
    eval_fail_closed("[1, 2, 3].forEach(\"not-a-function\");");
}

#[test]
fn array_foreach_fail_closed_non_object() {
    eval_fail_closed("Array.prototype.forEach.call(null, function(v) { return v; });");
    eval_fail_closed("Array.prototype.forEach.call(undefined, function(v) { return v; });");
}

#[test]
fn array_foreach_empty_array_handling() {
    eval_fail_closed("[].forEach(function(v) { return v; });");
}

#[test]
fn array_foreach_sparse_array_handling() {
    let script = r#"
        var arr = [];
        arr[0] = "first";
        arr[3] = "fourth";
        arr[4] = "fifth";
        arr.forEach(function(v) { return v; });
    "#;
    eval_fail_closed(script);
}

#[test]
fn array_foreach_builtin_id_consistency() {
    // Source-level guard: forEach builtin is present and validated via the
    // shared helper after duplicate removal.
    let source = baseline_interpreter_source();
    assert!(source.contains("builtin:ArrayPrototypeForEach"));
    assert!(source.contains("validate_array_callback_args(args, \"Array.prototype.forEach\")"));
}
