//! Focused regression for bd-itxl9: optional chaining (`?.`) returned
//! `undefined` even when the base object was defined. The first three cases
//! cover the simplest pattern that the bug description names — `obj?.x`,
//! `obj?.['x']`, and `obj?.method()` — and gate the engine on the ES2020
//! §12.3.2.1 happy-path semantics. Their MUST-tier siblings live in
//! optional_chaining_test262_conformance.rs.

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
fn optional_member_static_returns_property_value() {
    let outcome = eval("const obj = { x: 42 }; console.log(obj?.x);");
    assert_eq!(
        console_text(&outcome).trim(),
        "42",
        "obj?.x on a defined object must yield the property value, not undefined",
    );
}

#[test]
fn optional_member_computed_returns_property_value() {
    let outcome = eval("const obj = { key: 'value' }; console.log(obj?.['key']);");
    assert_eq!(
        console_text(&outcome).trim(),
        "value",
        "obj?.['key'] on a defined object must yield the property value, not undefined",
    );
}

#[test]
fn optional_member_returns_undefined_when_base_is_nullish() {
    let outcome_null = eval("const obj = null; console.log(obj?.x);");
    assert_eq!(
        console_text(&outcome_null).trim(),
        "undefined",
        "obj?.x with null base must short-circuit to undefined",
    );
    let outcome_undefined = eval("let obj; console.log(obj?.x);");
    assert_eq!(
        console_text(&outcome_undefined).trim(),
        "undefined",
        "obj?.x with undefined base must short-circuit to undefined",
    );
}

#[test]
fn optional_method_call_invokes_method_when_receiver_exists() {
    let outcome = eval(
        "const obj = { getValue: function () { return 'result'; } }; console.log(obj?.getValue());",
    );
    assert_eq!(
        console_text(&outcome).trim(),
        "result",
        "obj?.getValue() must invoke the method on a defined receiver",
    );
}

#[test]
fn optional_method_call_short_circuits_when_receiver_is_nullish() {
    // ES2020 §12.3.2.1: the entire optional chain — including the call —
    // must short-circuit when any `?.` link sees null/undefined. Previously
    // the engine threw "type error: expected function, got undefined" here
    // because the parser modelled `obj?.getValue()` as Call(OptionalMember,
    // []) and the wrapping Call had no nullish guard.
    let outcome = eval("const obj = null; console.log(obj?.getValue());");
    assert_eq!(
        console_text(&outcome).trim(),
        "undefined",
        "obj?.getValue() with null receiver must short-circuit to undefined",
    );
    let outcome_undef = eval("let obj; console.log(obj?.getValue());");
    assert_eq!(
        console_text(&outcome_undef).trim(),
        "undefined",
        "obj?.getValue() with undefined receiver must short-circuit to undefined",
    );
}
