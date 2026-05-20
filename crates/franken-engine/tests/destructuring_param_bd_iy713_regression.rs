//! bd-iy713 regression — destructuring parameter call-site arg passing.
//!
//! The hypothesis in the bead is that calling `g([3, 4])` for a function
//! declared `function g([x, y]) { ... }` makes the parameter slot `r0`
//! receive a NUMBER instead of the array. The triage path proposed:
//!
//!   1. Confirm `function f(o){ return o; } f({a:3, b:4})` returns the
//!      object (call-site is fine for non-destructuring params).
//!   2. Confirm `function g([x, y]) { return x*y; } g([3,4])` returns 12
//!      (destructure path works end-to-end).
//!   3. Same for object destructuring.
//!
//! These are spec-anchored MUST-tier cases under ES2020 §14.1.20
//! (FormalParameter destructuring binding). If they pass, the
//! corresponding waivers in KNOWN_DESTRUCTURING_GAPS of
//! destructuring_binding_test262_conformance.rs are stale and should be
//! removed. If they fail, the failure message names the precise call
//! shape and the next root-cause pass can focus there.

use frankenengine_engine::{EvalOutcome, HybridRouter};

fn eval(source: &str) -> Result<EvalOutcome, String> {
    HybridRouter::default()
        .eval(source)
        .map_err(|err| err.to_string())
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
fn identity_call_with_object_arg_returns_the_object() {
    // Triage step 1 (per bead). If this fails the call-site is broken
    // independent of destructuring; if it passes, the issue is
    // destructure-specific.
    let outcome = eval("function f(o) { return typeof o; } console.log(f({ a: 3, b: 4 }));")
        .expect("identity call must not error");
    assert_eq!(
        console_text(&outcome).trim(),
        "object",
        "f({{a:3,b:4}}) must receive the object, not a flattened primitive",
    );
}

#[test]
fn identity_call_with_array_arg_returns_object_typeof() {
    let outcome = eval("function f(o) { return typeof o; } console.log(f([3, 4]));")
        .expect("identity call must not error");
    assert_eq!(
        console_text(&outcome).trim(),
        "object",
        "f([3,4]) must receive the array (typeof returns 'object'), not the first element",
    );
}

#[test]
fn array_destructuring_parameter_multiplies_elements() {
    // Triage step 2 from bd-iy713: the spec-failing case.
    let outcome = eval("function g([x, y]) { return x * y; } console.log(g([3, 4]));")
        .expect("array-destructuring parameter must not raise a runtime fault");
    assert_eq!(
        console_text(&outcome).trim(),
        "12",
        "g([3,4]) with destructured [x,y] params must compute 3*4=12, not throw \
         'expected object, got number'",
    );
}

#[test]
fn object_destructuring_parameter_sums_fields() {
    // Triage step 3.
    let outcome = eval("function g({ a, b }) { return a + b; } console.log(g({ a: 3, b: 4 }));")
        .expect("object-destructuring parameter must not raise a runtime fault");
    assert_eq!(
        console_text(&outcome).trim(),
        "7",
        "g({{a:3,b:4}}) with destructured {{a,b}} params must compute 3+4=7",
    );
}
