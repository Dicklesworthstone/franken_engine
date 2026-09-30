//! bd-9vouw.43: function declarations are hoisted.
//!
//! Lowering emitted each function declaration at its textual position, so a
//! call or read before the declaration saw an unwritten binding
//! (`foo(); function foo(){}` threw "expected function, got undefined").
//! Expected strings are what Node v22.2.0 prints for the same programs.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

#[test]
fn top_level_functions_are_callable_before_their_declaration() {
    check("var r = foo(); function foo() { return 'hi'; } r;", "hi");
    check("var t = typeof foo; function foo() {} t;", "function");
}

#[test]
fn function_body_declarations_are_hoisted() {
    check(
        "function outer() { return inner(); function inner() { return 'in'; } } outer();",
        "in",
    );
    // The hoisted inner function sees a local initialized before the call.
    check(
        "function outer() { let x = 1; return inner(); function inner() { return x; } } outer();",
        "1",
    );
    check(
        "class K { m() { return helper(); function helper() { return 'mh'; } } } new K().m();",
        "mh",
    );
}

#[test]
#[ignore = "bd-9vouw.43 follow-up: a captured top-level let/const is declared as an initialized var cell, so an early call reads undefined instead of throwing; routing captured lexicals through the TDZ path broke class inner-name bindings (initialized without InitBinding)"]
fn hoisted_functions_respect_the_temporal_dead_zone() {
    check(
        "var r; try { h(); } catch (e) { r = e.name; } let z = 3; function h() { return z; } \
         r + ':' + h();",
        "ReferenceError:3",
    );
}

/// An arrow function's block body hoists its function declarations too. It
/// lowered them in textual order, so a helper declared after the arrow's
/// `return` was undefined when called (flatted's `stringify` passes such a
/// `replace` to JSON.stringify, and a cyclic value then threw).
#[test]
fn arrow_function_body_declarations_are_hoisted() {
    check(
        "var f = () => { return h(); function h() { return 2; } }; f();",
        "2",
    );
    check(
        "var f = () => { const a = h(); return a; function h() { return 4; } }; f();",
        "4",
    );
    check(
        "var f = () => { let x = 1; while (x < 3) x++; return h(x); function h(v) { return v * 10; } }; f();",
        "30",
    );
    check(
        "var f = () => { return typeof h; function h() {} }; f();",
        "function",
    );
    check(
        "var f = () => { for (const x of [1]) { g(x); } return 'ok'; function g() {} }; f();",
        "ok",
    );
    check(
        "var g = () => { let i = 0; let firstRun = !i; const seen = []; while (i < 2) { firstRun = true; i++; JSON.stringify({ a: 1 }, replace); } return seen.join(); function replace(key, v) { if (firstRun) { firstRun = !firstRun; seen.push('first'); return v; } seen.push(key); return v; } }; g();",
        "first,a,first,a",
    );
}

#[test]
fn hoisting_keeps_the_script_completion_value() {
    check("1; function f() {}", "1");
    check(
        "var n = 0; function inc() { n++; return n; } inc() + inc();",
        "3",
    );
}
