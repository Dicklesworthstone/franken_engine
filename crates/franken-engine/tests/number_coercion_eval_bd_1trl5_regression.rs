//! Regression: the bare `Number(value)` coercion function must be callable from
//! `HybridRouter::eval`.
//!
//! Bead: bd-1trl5 (found by OliveLake eval-probe3). REPRO (`HybridRouter::eval`):
//! `Number("42")+1` faulted "expected function, got undefined" — only the
//! `Number.is*`/`Number.parse*` static members were wired; the bare `Number(x)`
//! coercion global was not. The `builtin:Number` coercion impl already existed;
//! the fix wires the bare-identifier lowering interception
//! (`global_function_call_capability`). Same family as parseInt/Symbol.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn number_from_string() {
    assert_eq!(eval_value(r#"Number("42")"#), "42");
}

#[test]
fn number_from_string_arithmetic() {
    assert_eq!(eval_value(r#"Number("42") + 1"#), "43");
}

#[test]
fn number_from_bool() {
    assert_eq!(eval_value("Number(true)"), "1");
}
