//! bd-8enww.4.7 — explicit `throw` crossing the generated-function boundary.
//!
//! Track-D (YTBG-D) G-3 exception semantics. An *explicit* `throw` inside a
//! `Function`-constructor-generated function must be catchable by an enclosing
//! `try`/`catch` in the CALLER, carrying the ORIGINAL thrown value — symmetric
//! with a native runtime error (e.g. `null.x` → `TypeError`), which was already
//! catchable across the boundary (bd-8enww.4.3 / 3.5).
//!
//! Background (root cause): a generated function runs in a separate re-entrant
//! `run_loop` whose catch-frame stack is cleared, so the caller's `try`/`catch`
//! is invisible to the inner loop. On an uncaught explicit `throw` the inner run
//! returns `UncaughtException` while preserving the thrown value in
//! `pending_exception`; the dispatch arm that invoked the generated function now
//! re-raises that preserved value into the caller's catch frames
//! (`route_isolated_explicit_throw`), exactly like the `Throw` instruction and
//! the `for…of` iterator re-raise.
//!
//! These tests drive the public `HybridRouter::eval` surface (the parent-bead
//! acceptance path) and assert observable values, not interpreter internals.

use frankenengine_engine::{EvalOutcome, HybridRouter};

/// Evaluate and require the program to COMPLETE (the throw was caught somewhere),
/// returning the formatted completion value.
fn caught(src: &str) -> String {
    let outcome: EvalOutcome = HybridRouter::default()
        .eval(src)
        .unwrap_or_else(|err| panic!("expected `{src}` to complete, got error: {}", err.message));
    outcome.value
}

/// Evaluate and require the program to FAIL CLOSED (no handler), returning the
/// surfaced diagnostic message.
fn uncaught(src: &str) -> String {
    HybridRouter::default()
        .eval(src)
        .map(|ok| format!("UNEXPECTED OK: {}", ok.value))
        .unwrap_err()
        .message
}

// --- primitive thrown values travel verbatim --------------------------------

#[test]
fn explicit_throw_string_is_caught_by_caller() {
    assert_eq!(
        caught(
            r#"var c = "uncaught"; try { new Function("throw 'boom';")(); } catch (e) { c = e; } c;"#
        ),
        "boom",
    );
}

#[test]
fn explicit_throw_number_is_caught_by_caller() {
    assert_eq!(
        caught(r#"var c = -1; try { new Function("throw 42;")(); } catch (e) { c = e; } c;"#),
        "42",
    );
}

#[test]
fn explicit_throw_boolean_is_caught_by_caller() {
    assert_eq!(
        caught(r#"var c = "x"; try { new Function("throw false;")(); } catch (e) { c = e; } c;"#),
        "false",
    );
}

#[test]
fn caught_thrown_primitive_preserves_its_type() {
    // The catch binding holds the original value, so `typeof e` is `number`,
    // not `string` (it was never coerced through the diagnostic surface).
    assert_eq!(
        caught(
            r#"var t = "?"; try { new Function("throw 7;")(); } catch (e) { t = typeof e; } t;"#
        ),
        "number",
    );
}

// --- thrown Error objects survive the boundary (shared-heap survival) --------

#[test]
fn explicit_throw_error_object_preserves_message() {
    assert_eq!(
        caught(
            r#"var c = "no"; try { new Function("throw new Error('bad');")(); } catch (e) { c = e.message; } c;"#
        ),
        "bad",
    );
}

#[test]
fn explicit_throw_typeerror_object_preserves_name() {
    assert_eq!(
        caught(
            r#"var c = "no"; try { new Function("throw new TypeError('nope');")(); } catch (e) { c = e.name; } c;"#
        ),
        "TypeError",
    );
}

// --- finally interaction: the re-thrown exception still crosses the boundary -

#[test]
fn explicit_throw_through_generated_finally_is_caught_by_caller() {
    // The generated body re-raises the exception after its own `finally` runs;
    // the caller still catches it.
    assert_eq!(
        caught(
            r#"var c = "uncaught"; try { new Function("try { throw 'p'; } finally { 1; }")(); } catch (e) { c = e; } c;"#
        ),
        "p",
    );
}

// --- symmetry: native runtime errors remained catchable (regression guard) ---

#[test]
fn native_error_crossing_boundary_still_catchable() {
    assert_eq!(
        caught(
            r#"var c = "no"; try { new Function("var o = null; return o.x;")(); } catch (e) { c = e.name; } c;"#
        ),
        "TypeError",
    );
}

// --- in-body catch still handles the throw without crossing (regression) -----

#[test]
fn explicit_throw_caught_inside_generated_body_does_not_cross() {
    assert_eq!(
        caught(r#"new Function("try { throw 'x'; } catch (e) { return 'caught:' + e; }")();"#),
        "caught:x",
    );
}

// --- fail-closed: an uncaught explicit throw still surfaces deterministically -

#[test]
fn uncaught_explicit_throw_still_surfaces() {
    let m1 = uncaught(r#"new Function("throw 'boom';")();"#);
    assert!(
        m1.contains("uncaught exception") && m1.contains("boom"),
        "uncaught throw must surface carrying the value: {m1}",
    );
    // Deterministic: identical source ⇒ identical surfaced message.
    let m2 = uncaught(r#"new Function("throw 'boom';")();"#);
    assert_eq!(m1, m2);
}

#[test]
fn caller_catch_only_fires_on_throw_not_on_normal_return() {
    // A generated function that returns normally is unaffected by the routing:
    // the caller's catch binding is never touched.
    assert_eq!(
        caught(
            r#"var c = "untouched"; try { c = new Function("return 9;")(); } catch (e) { c = "caught"; } c;"#
        ),
        "9",
    );
}

// --- the CallMethod dispatch arm routes the same way as the plain Call arm ---

#[test]
fn generated_function_called_as_method_throw_is_caught_by_caller() {
    // A generated function invoked as a *method* (`obj.f()`) dispatches through
    // the `CallMethod` arm rather than the plain `Call` arm. The same routing
    // applies, so the explicit throw is caught by the caller and binds the
    // original value.
    assert_eq!(
        caught(
            r#"var o = {}; o.f = new Function("throw 'm';"); var c = "no"; try { o.f(); } catch (e) { c = e; } c;"#
        ),
        "m",
    );
}

// --- the caller can re-throw the crossed exception to a further-out handler ---

#[test]
fn crossed_exception_can_be_rethrown_to_outer_handler() {
    assert_eq!(
        caught(
            r#"var c = "no";
               try {
                 try { new Function("throw 'inner';")(); }
                 catch (e) { throw e + ':again'; }
               } catch (e2) { c = e2; }
               c;"#
        ),
        "inner:again",
    );
}
