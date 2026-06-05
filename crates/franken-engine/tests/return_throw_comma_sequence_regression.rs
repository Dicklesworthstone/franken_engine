#![forbid(unsafe_code)]
//! Regression: bare comma sequence in `return` / `throw` arguments (bd-h5m8u).
//!
//! `parse_return_statement` / `parse_throw_statement` parsed their argument with
//! `parse_expression` (not `_allowing_sequence`), so an unparenthesized comma
//! sequence fell through to `Expression::Raw` (a string) instead of the comma
//! operator's value (the last operand). Follow-up to bd-qxkli / bd-j4l7k.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn return_comma_sequence_yields_last_operand() {
    assert_eq!(eval_value("(function () { return 1, 2, 3; })()"), "3");
}

#[test]
fn return_comma_sequence_evaluates_operands_left_to_right() {
    // The non-final operands still evaluate (side effects); the value is the last.
    assert_eq!(
        eval_value("let a = 0; (function () { return (a = 7), a + 1; })()"),
        "8"
    );
}

#[test]
fn return_single_expression_unaffected() {
    assert_eq!(eval_value("(function () { return 5; })()"), "5");
}

#[test]
fn throw_comma_sequence_throws_last_operand() {
    assert_eq!(eval_value("try { throw 1, 2, 3; } catch (e) { e }"), "3");
}
