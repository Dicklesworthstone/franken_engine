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

    // bd-xewby: a direct engine `eval` is a TRUSTED top-level eval context, so
    // benign `process`-SHAPE reads are granted (`ProcessShapeRead`). `process.argv`
    // resolves to the injected empty argv array, so `process.argv.length` is "0".
    // (Untrusted extension lowering — via `lower_ir0_to_ir1` / the orchestrator —
    // still rejects the SAME read; see `ambient_authority_lowering_rejection_integration`.)
    assert_eq!(eval_value("process.argv.length"), "0");

    // The trusted grant is NARROW: it confers only `ProcessShapeRead`, never
    // `EnvRead`. An environment VARIABLE VALUE read (`process.env.X`) stays denied
    // at lowering even in a trusted eval — the SAME gate the red-team `process.env`
    // scenarios rely on — so `process.env.PATH` is rejected rather than returning a
    // value.
    let mut engine = QuickJsInspiredNativeEngine;
    match engine.eval("process.env.PATH") {
        Ok(outcome) => panic!(
            "expected `process.env.PATH` (an env VALUE read) to stay denied by the \
             ambient-authority gate even in trusted eval, got value {:?}",
            outcome.value
        ),
        Err(error) => {
            let rendered = format!("{error:?}").to_lowercase();
            assert!(
                rendered.contains("ambient")
                    || rendered.contains("env.read")
                    || rendered.contains("env_read"),
                "expected an ambient-authority denial for `process.env.PATH`, got: {error:?}"
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
