//! bd-bs81a regression — full-pipeline `+0 === -0` must evaluate to `true`.
//!
//! The IR3-direct sibling check
//! (runtime_abstract_ops_conformance.rs::strict_eq_signed_zero) passes, so
//! the gap is in parser/lowering for unary plus/minus on the integer
//! literal `0`. This test exercises the full HybridRouter pipeline.

use frankenengine_engine::{EvalOutcome, HybridRouter};

fn eval(source: &str) -> EvalOutcome {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|err| panic!("HybridRouter::eval failed for {source:?}: {err}"))
}

fn console_text(outcome: &EvalOutcome) -> String {
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn positive_zero_strictly_equals_negative_zero() {
    let outcome = eval("console.log(+0 === -0);");
    assert_eq!(
        console_text(&outcome).trim(),
        "true",
        "+0 === -0 must produce true per ES2020 §7.2.15",
    );
}

#[test]
fn negative_zero_strictly_equals_positive_zero_reverse() {
    let outcome = eval("console.log(-0 === +0);");
    assert_eq!(
        console_text(&outcome).trim(),
        "true",
        "-0 === +0 must produce true (commutativity)",
    );
}

#[test]
fn negative_zero_strictly_equals_zero() {
    let outcome = eval("console.log(-0 === 0);");
    assert_eq!(
        console_text(&outcome).trim(),
        "true",
        "-0 === 0 must produce true",
    );
}
