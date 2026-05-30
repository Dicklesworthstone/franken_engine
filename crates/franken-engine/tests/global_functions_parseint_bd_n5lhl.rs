//! bd-n5lhl — standard global functions callable from the eval lane.
//!
//! Before this, `parseInt("42")` faulted with `expected function, got
//! undefined`: `parseInt`/`parseFloat`/`isNaN`/`isFinite` have no binding on the
//! HybridRouter eval scope (bare-global resolution in eval is scope-only). The
//! `builtin:parseInt`/`parseFloat`/`isNaN`/`isFinite` hostcall impls already
//! existed; the fix recognizes a bare-identifier CALL to one of these globals at
//! lowering and routes it to the `builtin:<name>` hostcall — the same mechanism
//! as the Math (`Math.abs`), timer (`setTimeout`) and error-constructor
//! (`new TypeError`) interceptions. Shadowing-safe: a user `let parseInt = …`
//! resolves in scope and is never reinterpreted as the builtin.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

// ---- bead pins -----------------------------------------------------------

#[test]
fn parse_int_basic() {
    assert_eq!(eval(r#"parseInt("42");"#), "42");
}

#[test]
fn parse_float_basic() {
    assert_eq!(eval(r#"parseFloat("3.5");"#), "3.5");
}

#[test]
fn is_nan_of_nan_is_true() {
    assert_eq!(eval("isNaN(NaN);"), "true");
}

// ---- parseInt radix + leading/trailing handling --------------------------

#[test]
fn parse_int_hex_radix() {
    assert_eq!(eval(r#"parseInt("ff", 16);"#), "255");
}

#[test]
fn parse_int_trailing_garbage_is_truncated() {
    assert_eq!(eval(r#"parseInt("42px");"#), "42");
}

#[test]
fn parse_int_non_numeric_is_nan() {
    assert_eq!(eval(r#"parseInt("nope");"#), "NaN");
}

// ---- isNaN / isFinite coercion -------------------------------------------

#[test]
fn is_nan_of_number_is_false() {
    assert_eq!(eval("isNaN(5);"), "false");
}

#[test]
fn is_nan_of_unparseable_string_is_true() {
    assert_eq!(eval(r#"isNaN("frank");"#), "true");
}

#[test]
fn is_finite_of_number_is_true() {
    assert_eq!(eval("isFinite(42);"), "true");
}

// ---- user bindings still shadow the global (interception is miss-only) ----

#[test]
fn user_binding_shadows_global() {
    // `let parseInt = …` is in scope, so the lowering interception backs off and
    // the global builtin must not leak past the user shadow.
    assert_eq!(eval("let parseInt = 7; parseInt;"), "7");
}

#[test]
fn shadowed_global_is_called_as_user_value() {
    // A shadowing binding that is not callable must NOT be silently replaced by
    // the host builtin — calling it should fault, proving we didn't reinterpret.
    assert!(eval("let parseInt = 7; parseInt('42');").starts_with("ERR:"));
}
