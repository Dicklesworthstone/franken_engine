//! Regression: a throw from a custom iterator's `next()` during `for (… of …)`
//! must be catchable by an enclosing `try`/`catch`.
//!
//! Bead: bd-bg9l1.27.7 (DISC-009 throw path). Before the fix, for-of called
//! `next()` via `invoke_inline_method_call`, which runs the method in an isolated
//! context (clearing `catch_frames`); an uncaught throw there surfaced as
//! "uncaught exception" and escaped the loop instead of unwinding to the
//! enclosing handler. The `ForOfNext` handler now re-routes the captured thrown
//! value into the in-loop try/catch unwinding.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

/// Plain-value throw from `next()` (isolates throw-propagation from `new Error`).
#[test]
fn throw_from_iterator_next_is_catchable() {
    let s = eval_value(
        r#"
        let it = {
            [Symbol.iterator]() {
                let c = 0;
                return { next() { if (c === 0) { c++; return { value: 42, done: false }; } throw 99; } };
            }
        };
        try { for (let v of it) {} 1; } catch (e) { 7; }
        "#,
    );
    assert_eq!(
        s, "7",
        "throw from next() should be caught by the for-of's try/catch"
    );
}

/// The catch binds the exact thrown value.
#[test]
fn catch_binds_value_thrown_from_iterator_next() {
    let s = eval_value(
        r#"
        let it = {
            [Symbol.iterator]() {
                let c = 0;
                return { next() { if (c === 0) { c++; return { value: 1, done: false }; } throw 99; } };
            }
        };
        try { for (let v of it) {} } catch (e) { e; }
        "#,
    );
    assert_eq!(s, "99", "catch should bind the value thrown by next()");
}

/// A builtin (`new Error`) used inside a function body must work — its
/// capability is now declared from the function-body instruction stream
/// (bd-bg9l1.27.10 follow-up; previously capability-denied because only
/// module-level builtins were declared in `required_capabilities`).
#[test]
fn new_error_inside_function_body_works() {
    assert_eq!(
        eval_value(r#"let f = function () { let e = new Error("x"); return e.message; }; f()"#),
        "x"
    );
    assert_eq!(
        eval_value(
            r#"let f = function () { throw new Error("x"); }; try { f(); } catch (e) { 7; }"#
        ),
        "7"
    );
}

/// The full conformance shape: throwing `new Error` from `next()`, caught.
#[test]
fn throw_new_error_from_iterator_next_is_catchable() {
    let s = eval_value(
        r#"
        let customIterable = {
            [Symbol.iterator]() {
                let count = 0;
                return {
                    next() {
                        if (count === 0) { count++; return { value: 42, done: false }; }
                        throw new Error("Iterator error");
                    }
                };
            }
        };
        try {
            for (let value of customIterable) {}
        } catch (e) {
            42;
        }
        "#,
    );
    assert_eq!(s, "42", "throwing new Error from next() must be catchable");
}

/// An uncaught throw from `next()` (no surrounding try) still faults — it must
/// not be silently swallowed.
#[test]
fn uncaught_throw_from_iterator_next_still_faults() {
    let s = eval_value(
        r#"
        let it = { [Symbol.iterator]() { return { next() { throw 5; } }; } };
        for (let v of it) {}
        1;
        "#,
    );
    assert!(
        s.starts_with("ERR:"),
        "uncaught next() throw must still fault; got {s}"
    );
}
