//! bd-zs4d5 — rest parameters bind trailing args as an Array.
//!
//! `(...xs) => xs.length` previously left `xs` undefined because lowering had
//! no rest-parameter metadata and the interpreter dropped args beyond arity.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn arrow_rest_parameter_length() {
    assert_eq!(eval("let f = (...xs) => xs.length; f(1, 2, 3);"), "3");
}

#[test]
fn function_rest_parameter_element_access_after_fixed_arg() {
    assert_eq!(
        eval("function g(a, ...xs) { return xs[0] + xs[1] + a; } g(1, 2, 3);"),
        "6"
    );
}

#[test]
fn empty_rest_parameter_is_empty_array() {
    assert_eq!(eval("let f = (a, ...xs) => xs.length; f(1);"), "0");
}
