//! bd-i08nh — receiver-aware `Number.prototype` methods on number primitives.
//!
//! Before this, `(3.14).toFixed(2)` / `n.toString(16)` faulted with
//! "expected object, got number" because there was no number-primitive
//! prototype-method seam (the numeric analog of the String seam in bd-9a8cz /
//! the Array seam in bd-962ev). Adds `number_property_value` + receiver-aware
//! toFixed/toString/valueOf and Int/Float branches at the member-access sites.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

// ---- toFixed (variable receiver — the bead's REPRO form) -----------------

#[test]
fn to_fixed_rounds_to_digits() {
    assert_eq!(eval("let n = 3.14159; n.toFixed(2);"), "3.14");
}

#[test]
fn to_fixed_zero_digits_rounds_to_integer() {
    assert_eq!(eval("let n = 3.7; n.toFixed(0);"), "4");
}

#[test]
fn to_fixed_default_digits_is_zero() {
    assert_eq!(eval("let n = 2.5; n.toFixed();"), "2");
}

// ---- toString (optional radix) -------------------------------------------

#[test]
fn to_string_radix_16() {
    assert_eq!(eval("let n = 255; n.toString(16);"), "ff");
}

#[test]
fn to_string_default_radix_10() {
    assert_eq!(eval("let n = 255; n.toString();"), "255");
}

#[test]
fn to_string_radix_2() {
    assert_eq!(eval("let n = 5; n.toString(2);"), "101");
}

// ---- valueOf -------------------------------------------------------------

#[test]
fn value_of_returns_the_number() {
    assert_eq!(eval("let n = 42; n.valueOf();"), "42");
}

// ---- unknown member is undefined, not a TypeError ------------------------

#[test]
fn unknown_number_member_is_undefined_not_error() {
    assert_eq!(eval("let n = 1; n.nope;"), "undefined");
}

// ---- parenthesized number-literal receivers (bead pins) ------------------

#[test]
fn paren_literal_to_fixed() {
    assert_eq!(eval("(3.14159).toFixed(2);"), "3.14");
}

#[test]
fn paren_literal_to_string_radix() {
    assert_eq!(eval("(255).toString(16);"), "ff");
}
