//! bd-ylpdp (YTBG / BotGuard spine): bare references to runtime-injected
//! globals inside a **function body** resolve through the runtime scope chain
//! instead of throwing `ReferenceError` (or decaying to a dead-register
//! `undefined`).
//!
//! Before this slice, `lower_ir0_to_ir1::rewrite_unresolved_function_body_loads`
//! rewrote any unresolved identifier load in a function body to a
//! `ReferenceError` throw — so `Function`, `console`, `process`, and
//! `performance` (which have no source-level binding) only worked at module
//! scope, where the top-level IR2->IR3 path already routes them through
//! `scoped_runtime_binding_ids` to a `LoadScoped`. The concrete consequence was
//! that `new Function(...)` could only be constructed at top level, even though
//! BotGuard constructs and runs `Function` objects *inside* functions.
//!
//! The fix records bare references to the canonical `PREDECLARED_RUNTIME_GLOBALS`
//! (`Function`/`console`/`process`/`performance` — the same set the top-level
//! path uses, kept in `inject_runtime_globals`) on the function's
//! `runtime_global_loads`, and the deferred IR3 body pass lowers each surviving
//! `LoadBinding` to a `LoadScoped` that resolves against the injected realm
//! global frame the closure already captures. Genuinely-unknown identifiers
//! still fail closed with a catchable `ReferenceError`.

use frankenengine_engine::{HybridRouter, JsEngine, QuickJsInspiredNativeEngine};

/// Evaluate through the direct native engine (isolates engine semantics from
/// HybridRouter routing).
fn eval_value(source: &str) -> String {
    let mut engine = QuickJsInspiredNativeEngine;
    engine
        .eval(source)
        .expect("source should evaluate successfully")
        .value
}

/// Evaluate through the HybridRouter — the path BotGuard's `eval` driver uses.
fn eval_value_hybrid(source: &str) -> String {
    let mut router = HybridRouter::default();
    router
        .eval(source)
        .expect("source should evaluate successfully")
        .value
}

fn eval_error(source: &str) -> String {
    let mut router = HybridRouter::default();
    router
        .eval(source)
        .expect_err("source should fail deterministically")
        .to_string()
}

// --- `performance` resolves inside a function body ---------------------------

#[test]
fn typeof_performance_in_function_body_is_object() {
    // The headline regression from bd-8enww.5.3 / bd-ylpdp: `typeof performance`
    // inside a function body previously decayed to "undefined".
    assert_eq!(
        eval_value("function f(){ return typeof performance; } f();"),
        "object"
    );
}

#[test]
fn performance_now_member_call_in_function_body_returns_number() {
    assert_eq!(
        eval_value("function f(){ return typeof performance.now(); } f();"),
        "number"
    );
}

// --- `Function` resolves inside a function body: the YTBG headline -----------

#[test]
fn typeof_function_in_function_body_is_function() {
    assert_eq!(
        eval_value("function f(){ return typeof Function; } f();"),
        "function"
    );
}

#[test]
fn new_function_inside_function_body_constructs_and_runs() {
    // `Function` is NOT a recognized `new`-constructor name, so it lowers as a
    // bare identifier load — the exact path this fix unblocks.
    assert_eq!(
        eval_value(r#"function f(){ return new Function("return 1;")(); } f();"#),
        "1"
    );
}

#[test]
fn new_function_with_args_inside_function_body() {
    assert_eq!(
        eval_value(r#"function f(){ return new Function("a", "b", "return a + b;")(2, 3); } f();"#),
        "5"
    );
}

#[test]
fn make_adder_returns_generated_function_through_hybrid_router() {
    // BotGuard-shaped: a factory function constructs a `Function` from a dynamic
    // body and returns it; the caller invokes the result.
    assert_eq!(
        eval_value_hybrid(
            r#"function makeMul(n){ return new Function("x", "return x * " + n + ";"); } makeMul(6)(7);"#
        ),
        "42"
    );
}

// --- `console` / `process` resolve inside a function body --------------------

#[test]
fn typeof_console_in_function_body_is_object() {
    assert_eq!(
        eval_value("function f(){ return typeof console; } f();"),
        "object"
    );
}

// Note on `process`: it is also in `PREDECLARED_RUNTIME_GLOBALS` (and routes at
// top level), but unlike `console`/`performance` it is a capability-gated
// ambient-authority global (`env.read`). The lowering-time ambient-authority
// check rejects a bare `process` reference inside a function body *before* this
// routing runs (the check fires on the identifier, independent of this fix), so
// `console` is the object-typed representative here. `process`'s top-level
// behaviour is pinned in `top_level_runtime_globals_unchanged` below.

// --- arrow + function-expression forms route identically ---------------------

#[test]
fn typeof_performance_in_arrow_body_is_object() {
    assert_eq!(eval_value("(() => typeof performance)();"), "object");
}

#[test]
fn new_function_inside_function_expression_body() {
    assert_eq!(
        eval_value(r#"(function(){ return new Function("return 9;")(); })();"#),
        "9"
    );
}

#[test]
fn new_function_inside_nested_function_body() {
    assert_eq!(
        eval_value(
            r#"function f(){ function g(){ return new Function("return 7;")(); } return g(); } f();"#
        ),
        "7"
    );
}

// --- fail-closed: genuinely-unknown identifiers still throw ------------------

#[test]
fn unknown_global_in_function_body_fails_closed() {
    // Fail-closed: a genuinely-unknown identifier inside a function body still
    // throws rather than silently resolving to `undefined`.
    let _err = eval_error("function f(){ return zzznope; } f();");
}

#[test]
fn unknown_global_throw_in_function_body_is_catchable() {
    // The fail-closed throw is a real, catchable runtime exception (not a hard
    // lowering abort), so an in-body `try/catch` observes it.
    assert_eq!(
        eval_value("function f(){ try { return zzznope; } catch (e) { return \"caught\"; } } f();"),
        "caught"
    );
}

#[test]
fn typeof_unknown_global_in_function_body_is_undefined() {
    // The `typeof` suppression for a genuinely-unknown identifier is preserved:
    // it must NOT throw and must report "undefined".
    assert_eq!(
        eval_value("function f(){ return typeof zzznope; } f();"),
        "undefined"
    );
}

// --- user bindings shadow the runtime global (no spurious scoped routing) ----

#[test]
fn local_binding_shadows_runtime_global_in_function_body() {
    // A `var performance` is a body-local binding (locally defined), so it must
    // resolve to the local value, never the injected global object.
    assert_eq!(
        eval_value("function f(){ var performance = 5; return performance; } f();"),
        "5"
    );
    assert_eq!(
        eval_value("function f(){ var performance = 5; return typeof performance; } f();"),
        "number"
    );
}

// --- member-call recognizers still bypass the load path (regression guard) ---

#[test]
fn object_keys_member_call_in_function_body_still_works() {
    assert_eq!(
        eval_value("function f(){ return Object.keys({a: 1, b: 2}).length; } f();"),
        "2"
    );
}

// --- top-level behaviour is unchanged (the two paths share the same set) -----

#[test]
fn top_level_runtime_globals_unchanged() {
    // Guards that refactoring the top-level scoped-global insertion to iterate
    // `PREDECLARED_RUNTIME_GLOBALS` preserved the exact prior behaviour for the
    // non-ambient-gated globals. (`process` is intentionally omitted: top-level
    // `typeof process` is independently gated by the ambient-authority lowering
    // check — see the `process` note above — which this refactor does not
    // touch.)
    assert_eq!(eval_value("typeof performance;"), "object");
    assert_eq!(eval_value("typeof Function;"), "function");
    assert_eq!(eval_value("typeof console;"), "object");
    assert_eq!(eval_value(r#"new Function("return 3;")();"#), "3");
}
