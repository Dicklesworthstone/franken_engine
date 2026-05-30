//! Regression: global error constructors (`Error`, `TypeError`, …) must be
//! usable in the `HybridRouter::eval` path.
//!
//! Bead: bd-bg9l1.27.10. Before the fix, bare `Error` (like `Math`/`Symbol`)
//! resolved to `undefined` on the eval scope path, so `new Error(msg)` and
//! `throw new Error(msg)` faulted with "type error: expected function, got
//! undefined". The constructors are now recognized at lowering and routed to the
//! `builtin:<Name>` hostcall (`error_constructor_capability` in
//! `lowering_pipeline.rs`), producing a real error object with `name` + `message`.
//!
//! NOTE: the inline `new Error("x").message` form (member access directly on the
//! `new` result) is NOT exercised here — it hits a *separate* `new X(args).prop`
//! parse-precedence limitation (see `inline_member_on_new_is_separate_gap`),
//! independent of this bead. Real usage (`throw new Error(...)` / a bound
//! `let e = new Error(...)`) works.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn new_error_constructs_object_with_message() {
    assert_eq!(
        eval_value(r#"let e = new Error("boom"); e.message"#),
        "boom"
    );
    assert_eq!(eval_value(r#"let e = new Error("boom"); e.name"#), "Error");
    assert_eq!(
        eval_value(r#"let e = new Error("boom"); typeof e"#),
        "object"
    );
}

#[test]
fn new_error_with_no_argument_has_empty_message() {
    assert_eq!(eval_value("let e = new Error(); e.message"), "");
    assert_eq!(eval_value("let e = new Error(); e.name"), "Error");
}

#[test]
fn throw_new_error_is_catchable() {
    // The thrown Error is caught and bound; the catch block's value is returned.
    assert_eq!(
        eval_value(r#"try { throw new Error("x"); 1; } catch (e) { 42; }"#),
        "42"
    );
}

#[test]
fn catch_binds_thrown_error_message() {
    assert_eq!(
        eval_value(r#"try { throw new Error("kaboom"); } catch (e) { e.message; }"#),
        "kaboom"
    );
}

#[test]
fn error_subclasses_carry_their_own_name() {
    assert_eq!(
        eval_value(r#"let e = new TypeError("t"); e.name"#),
        "TypeError"
    );
    assert_eq!(
        eval_value(r#"let e = new RangeError("r"); e.name"#),
        "RangeError"
    );
    assert_eq!(
        eval_value(r#"let e = new ReferenceError("ref"); e.name"#),
        "ReferenceError"
    );
    assert_eq!(
        eval_value(r#"let e = new SyntaxError("s"); e.name"#),
        "SyntaxError"
    );
    assert_eq!(eval_value(r#"let e = new TypeError("t"); e.message"#), "t");
}

/// A throwing subclass propagates and is catchable, binding the right name.
#[test]
fn throw_subclass_is_catchable_with_name() {
    assert_eq!(
        eval_value(r#"try { throw new TypeError("bad"); } catch (e) { e.name; }"#),
        "TypeError"
    );
}

/// Documents the SEPARATE pre-existing limitation that motivated the two-step
/// forms above: a member access placed directly on a `new X(args)` result faults
/// (parse precedence of `new … (args) . prop`). This is NOT bd-bg9l1.27.10; it is
/// independent of the error-constructor binding and also affects user
/// constructors. Pinned here so a future `new`-precedence fix can flip it.
#[test]
fn inline_member_on_new_is_separate_gap() {
    let inline = eval_value(r#"new Error("boom").message"#);
    assert!(
        inline.starts_with("ERR:"),
        "expected the inline new-member form to still fault (separate gap); got {inline}"
    );
}
