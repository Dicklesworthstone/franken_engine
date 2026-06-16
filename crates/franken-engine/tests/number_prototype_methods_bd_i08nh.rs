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
fn to_fixed_truncates_fractional_digits() {
    assert_eq!(eval("(1.5).toFixed(2.9);"), "1.50");
    assert_eq!(eval("(1.5).toFixed('2.9');"), "1.50");
}

#[test]
fn to_fixed_keeps_nan_digits_at_zero() {
    assert_eq!(eval("(1.5).toFixed(0 / 0);"), "2");
}

#[test]
fn to_fixed_zero_digits_rounds_to_integer() {
    assert_eq!(eval("let n = 3.7; n.toFixed(0);"), "4");
}

#[test]
fn to_fixed_default_digits_is_zero() {
    // Default fractionDigits is 0. 2.5 is an exact dyadic tie: per ES2023
    // 21.1.3.3 the tie breaks toward the larger n ("3"), NOT to-even ("2").
    assert_eq!(eval("let n = 2.5; n.toFixed();"), "3");
}

// ---- exact-dyadic-tie rounding (round-half-up, not banker's) -------------

#[test]
fn to_fixed_ties_round_half_up() {
    assert_eq!(eval("(0.5).toFixed(0);"), "1");
    assert_eq!(eval("(1.5).toFixed(0);"), "2");
    assert_eq!(eval("(2.5).toFixed(0);"), "3");
    assert_eq!(eval("(0.25).toFixed(1);"), "0.3");
    assert_eq!(eval("(0.125).toFixed(2);"), "0.13");
}

#[test]
fn to_fixed_rounding_carry_and_negatives() {
    assert_eq!(eval("(9.5).toFixed(0);"), "10");
    assert_eq!(eval("(-2.5).toFixed(0);"), "-3");
    // 1.005 is really 1.00499999...; the exact value rounds down.
    assert_eq!(eval("(1.005).toFixed(2);"), "1.00");
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
