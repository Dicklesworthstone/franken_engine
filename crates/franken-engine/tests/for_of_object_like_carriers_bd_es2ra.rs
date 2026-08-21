//! Regression tests for bd-es2ra — for-of iterator init/step must accept
//! every object-like carrier, not only `Value::Object`, while primitives
//! still reject with TypeError.
//!
//! Before the fix, the engine's `iterator_result_property` and
//! `prepare_custom_for_of_state` required the concrete `Value::Object`
//! carrier: a function returned as an iterator (or as an iterator *result*)
//! hit "object returned by @@iterator" / "iterator result object" TypeErrors
//! even though functions are objects in ECMAScript. Now:
//!
//! - an object-like iterator carrier without ordinary-property backing reads
//!   `next` as `undefined` and fails the *callable iterator.next* check
//!   (the spec's per-step behavior for a bare function iterator);
//! - an object-like iterator *result* without ordinary-property backing reads
//!   `done`/`value` as `undefined`, so the step is not done and yields
//!   `undefined`;
//! - primitives keep the historical TypeErrors.
//!
//! Twin: `crates/franken-core/tests/for_of_object_like_carriers_bd_es2ra.rs`.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

/// A function-like iterator *result* is object-like: `done`/`value` read as
/// undefined, so each such step yields `undefined` instead of throwing.
/// On the pre-fix engine this evaluated to a TypeError ("iterator result
/// object, got function").
#[test]
fn function_like_iterator_result_steps_yield_undefined() {
    let s = eval_value(
        r#"
        let c = 0;
        let iterator = {
            next: function () {
                c = c + 1;
                if (c > 2) { return { done: true }; }
                return function () {};
            }
        };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        let seen = 0;
        let allUndefined = 1;
        for (const value of iterable) {
            seen = seen + 1;
            if (value !== undefined) { allUndefined = 0; }
        }
        seen * 10 + allUndefined;
        "#,
    );
    assert_eq!(
        s, "21",
        "two function-like results should each yield undefined, then done"
    );
}

/// A bare function returned by @@iterator is object-like, so it passes the
/// carrier check — and then fails on `next` not being callable (it reads as
/// undefined off a carrier with no ordinary-property backing). The pre-fix
/// engine instead rejected the carrier itself ("object returned by
/// @@iterator, got function").
#[test]
fn bare_function_iterator_rejects_on_missing_next() {
    let s = eval_value(
        r#"
        let iterable = { [Symbol.iterator]: function () { return function () {}; } };
        let caught = "";
        try { for (const value of iterable) { value; } }
        catch (error) { caught = error.name + "|" + error.message; }
        caught;
        "#,
    );
    assert!(
        s.starts_with("TypeError|"),
        "bare-function iterator must throw TypeError, got: {s}"
    );
    assert!(
        s.contains("callable iterator.next"),
        "rejection must be the missing-next check, not the carrier check: {s}"
    );
}

/// Primitives returned by @@iterator keep the historical carrier TypeError.
#[test]
fn primitive_iterator_still_rejects_as_non_object() {
    let s = eval_value(
        r#"
        let iterable = { [Symbol.iterator]: function () { return 5; } };
        let caught = "";
        try { for (const value of iterable) { value; } }
        catch (error) { caught = error.name + "|" + error.message; }
        caught;
        "#,
    );
    assert!(
        s.starts_with("TypeError|"),
        "primitive iterator must throw TypeError, got: {s}"
    );
    assert!(
        s.contains("object returned by @@iterator"),
        "primitive iterator must fail the carrier check: {s}"
    );
}

/// Primitive iterator *results* keep the historical result TypeError.
#[test]
fn primitive_iterator_result_still_rejects() {
    let s = eval_value(
        r#"
        let iterator = { next: function () { return 1; } };
        let iterable = { [Symbol.iterator]: function () { return iterator; } };
        let caught = "";
        try { for (const value of iterable) { value; } }
        catch (error) { caught = error.name + "|" + error.message; }
        caught;
        "#,
    );
    assert!(
        s.starts_with("TypeError|"),
        "primitive iterator result must throw TypeError, got: {s}"
    );
    assert!(
        s.contains("iterator result object"),
        "primitive result must fail the result-carrier check: {s}"
    );
}
