#![forbid(unsafe_code)]
//! Coverage for bd-1lw7r.13: bare global timer builtins
//! (`setTimeout`/`setInterval`/`clearTimeout`/`clearInterval`) must be callable
//! from eval'd JavaScript.
//!
//! Previously a bare `setTimeout(fn, 0)` faulted at the call with
//! "type error: expected function, got undefined" — the global identifier
//! resolved to `undefined` because lowering only recognized builtin calls on
//! member callees (`Math.abs`, `"s".toUpperCase()`), never bare-identifier
//! globals. Lowering now dispatches these as host calls.
//!
//! NOTE: a timer callback that references a global (e.g. `console.log`) still
//! cannot resolve that global inside the timer closure body — that is a
//! separate gap in how closures executed off the event loop resolve the global
//! environment (filed separately). These tests therefore use global-free
//! callback bodies and assert callability + correct shadowing, which is exactly
//! what bd-1lw7r.13 fixes.

use frankenengine_engine::HybridRouter;

fn eval_ok(source: &str) {
    let mut engine = HybridRouter::default();
    engine.eval(source).unwrap_or_else(|err| {
        panic!(
            "`{source}` must eval without a fault (timer builtin must be callable), got: {err:?}"
        )
    });
}

#[test]
fn set_timeout_is_callable() {
    // Empty (global-free) callback: schedules + runs cleanly. Before the fix
    // this faulted at the `setTimeout(...)` call itself.
    eval_ok("setTimeout(function () {}, 0);");
}

#[test]
fn set_timeout_arrow_is_callable() {
    eval_ok("setTimeout(() => {}, 0);");
}

#[test]
fn set_timeout_with_omitted_delay_is_callable() {
    eval_ok("setTimeout(function () {});");
}

#[test]
fn set_interval_is_callable() {
    eval_ok("setInterval(function () {}, 0);");
}

#[test]
fn clear_timeout_and_clear_interval_are_callable() {
    eval_ok("clearTimeout(1);");
    eval_ok("clearInterval(1);");
}

#[test]
fn user_defined_set_timeout_is_not_hijacked_by_the_builtin() {
    // A user binding named `setTimeout` must shadow the builtin recognition:
    // calling it runs the user function (returns 21 * 2 = 42), not the host
    // timer builtin (which would return a timer id / 0).
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval("var setTimeout = function (x) { return x * 2; }; setTimeout(21);")
        .expect("shadowed setTimeout program must eval");
    assert_eq!(
        outcome.value, "42",
        "a user-defined `setTimeout` must be called instead of the timer builtin; \
         got completion value {:?}",
        outcome.value
    );
}
