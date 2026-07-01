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
fn test_process_global_minimal_shape_regression() {
    // bd-846vj: `typeof` inspects a reference's type without exercising ambient
    // authority (spec: `typeof <unresolved>` is "undefined", never a throw), so
    // `typeof process` / `typeof process.env` resolve the minimal injected
    // `process` global to "object" without an `env.read` capability.
    assert_eq!(eval_value("typeof process"), "object");
    assert_eq!(eval_value("typeof process.env"), "object");

    // A REAL read of the `process` shape (`process.argv`, `process.env.X`, …) IS
    // an ambient-authority exercise and stays gated under the deny-all lowering
    // posture — the SAME gate the red-team `process` scenarios rely on to reject
    // bare `process` / `process.exit` / `process[computed]` access. So
    // `process.argv.length` is rejected rather than returning "0"; the
    // minimal-process-global feature is reduced to typeof-shape (a benign
    // trusted-context shape read is tracked separately, see bd-846vj).
    let mut engine = QuickJsInspiredNativeEngine;
    match engine.eval("process.argv.length") {
        Ok(outcome) => panic!(
            "expected `process.argv.length` to be denied by the ambient-authority gate, \
             got value {:?}",
            outcome.value
        ),
        Err(error) => {
            let rendered = format!("{error:?}").to_lowercase();
            assert!(
                rendered.contains("ambient")
                    || rendered.contains("env.read")
                    || rendered.contains("env_read"),
                "expected an ambient-authority denial for `process.argv.length`, got: {error:?}"
            );
        }
    }
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
