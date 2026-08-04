use frankenengine_engine::{HybridRouter, JsEngine, QuickJsInspiredNativeEngine};

fn eval_value(source: &str) -> String {
    let mut engine = QuickJsInspiredNativeEngine;
    engine
        .eval(source)
        .expect("source should evaluate successfully")
        .value
}

fn eval_error(source: &str) -> String {
    let mut router = HybridRouter::default();
    router
        .eval(source)
        .expect_err("source should fail deterministically")
        .to_string()
}

#[test]
fn new_function_constructor_returns_callable_artifact() {
    assert_eq!(
        eval_value(r#"typeof new Function("x", "return x * 2;");"#),
        "function"
    );
}

#[test]
fn function_constructor_accepts_comma_separated_parameter_strings() {
    assert_eq!(
        eval_value(r#"typeof Function("x, y", "return x + y;");"#),
        "function"
    );
}

#[test]
fn function_constructor_accepts_zero_args_and_empty_body() {
    assert_eq!(eval_value("typeof new Function();"), "function");
    assert_eq!(eval_value(r#"typeof new Function("");"#), "function");
}

#[test]
fn function_constructor_invalid_parameters_fail_with_source_context() {
    let err = eval_error(r#"new Function("x-", "return x;");"#);
    assert!(err.contains("<function-constructor>"), "{err}");
    assert!(err.contains("parse") || err.contains("lower"), "{err}");
}

#[test]
fn function_constructor_invalid_body_fails_with_source_context() {
    let err = eval_error(r#"new Function("x", "return {");"#);
    assert!(err.contains("<function-constructor>"), "{err}");
    assert!(err.contains("parse") || err.contains("lower"), "{err}");
}

#[test]
fn generated_function_invocation_executes_after_bd_8enww_3_3() {
    // The 3.2 slice left invocation fail-closed pending bd-8enww.3.3; that slice
    // is now implemented (see function_constructor_invocation_bd_8enww_3_3.rs),
    // so a generated function with no parameters executes its body and returns.
    assert_eq!(eval_value(r#"new Function("return 1;")();"#), "1");
}
