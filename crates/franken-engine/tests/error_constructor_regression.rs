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
//! The inline `new X(args).prop` form (member/call/index directly on a `new`
//! result) is covered by `inline_member_on_new_result` /
//! `inline_call_and_index_on_new_result` — that was a separate parse-precedence
//! gap fixed under bd-if9uy (`parse_new_expression` re-groups the trailing chain
//! per ES2020 §13.3 `new X(a).b` == `(new X(a)).b`).

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

/// `new X(args).prop` (a member/call/index chain directly on a `new` result)
/// must parse as `(new X(args)).prop` per ES2020 §13.3 (bd-if9uy). This was
/// previously a parse-precedence gap (the trailing chain was absorbed into the
/// constructor callee, faulting); `parse_new_expression` now re-groups it.
#[test]
fn inline_member_on_new_result() {
    // Builtin constructor + member.
    assert_eq!(eval_value(r#"new Error("boom").message"#), "boom");
    assert_eq!(eval_value(r#"new TypeError("t").name"#), "TypeError");
    // User constructor + member.
    assert_eq!(
        eval_value(r#"let C = function () { this.x = 5; }; new C().x"#),
        "5"
    );
    // No-arg builtin + member.
    assert_eq!(eval_value(r#"new Error().name"#), "Error");
    // Parenthesised form stays correct (regression guard for the regrouping).
    assert_eq!(eval_value(r#"(new Error("boom")).message"#), "boom");
}

/// Trailing call and index chains on a `new` result also bind to the
/// constructed object (`new X(a).m()`, `new X(a)[k]`).
#[test]
fn inline_call_and_index_on_new_result() {
    // Member-then-call on the constructed object.
    assert_eq!(
        eval_value(r#"let C = function () { this.go = function () { return 9; }; }; new C().go()"#),
        "9"
    );
    // Index access on the constructed object.
    assert_eq!(
        eval_value(r#"let C = function () { this[0] = 7; }; new C()[0]"#),
        "7"
    );
}

/// bd-8enww.4.5 (YTBG-D5) AC3: string coercion of error objects is
/// deterministic and follows Error.prototype.toString — `"<name>: <message>"`,
/// or just the name when the message is empty. Covers concatenation (both
/// operand orders) and template literals.
#[test]
fn error_object_string_coercion_is_deterministic() {
    // Concatenation, both directions.
    assert_eq!(eval_value(r#""" + new Error("boom")"#), "Error: boom");
    assert_eq!(eval_value(r#"new Error("boom") + """#), "Error: boom");
    // Template literal.
    assert_eq!(eval_value(r#"`${new Error("boom")}`"#), "Error: boom");
    // Subclasses carry their own name.
    assert_eq!(
        eval_value(r#"`${new TypeError("bad type")}`"#),
        "TypeError: bad type"
    );
    assert_eq!(
        eval_value(r#""" + new RangeError("out")"#),
        "RangeError: out"
    );
    assert_eq!(
        eval_value(r#"`${new ReferenceError("nope")}`"#),
        "ReferenceError: nope"
    );
    // No message -> just the name (ES2020 §20.5.3.4).
    assert_eq!(eval_value(r#""" + new Error()"#), "Error");
    // Deterministic: identical inputs -> identical output.
    assert_eq!(
        eval_value(r#"`${new TypeError("x")}`"#),
        eval_value(r#"`${new TypeError("x")}`"#)
    );
}

/// A native runtime error, once caught as a JS value, coerces to a string that
/// begins with its error name (`indexOf` avoids pinning the engine's exact
/// diagnostic message text).
#[test]
fn caught_native_error_string_coercion_carries_name() {
    assert_eq!(
        eval_value(
            r#"let r = -1; try { let o = null; o.p; } catch (e) { r = ("" + e).indexOf("TypeError"); } r"#
        ),
        "0"
    );
}
