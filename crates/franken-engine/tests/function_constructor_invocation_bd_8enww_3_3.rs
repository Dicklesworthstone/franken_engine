//! bd-8enww.3.3 (YTBG-C3): invocation semantics for functions produced by the
//! `Function` constructor.
//!
//! The 3.2 slice parsed and compiled `new Function(args, body)` into a callable
//! artifact but left invocation fail-closed. This slice makes the artifact
//! actually run: the body executes in **global scope** (it cannot capture
//! construction-site or call-site locals — both nonstandard and a containment
//! leak), with positional argument binding, return values, builtin/global calls,
//! and a plain-call `this` of `undefined`. `new f(...)` on a generated function
//! is deliberately refused in v1 (AC#4).
//!
//! Containment note: generated code replaces the caller's capability envelope
//! with the engine-local `VmDispatch`/`HeapAllocate` baseline plus exactly the
//! safe (`Builtin`/`Console`/`Timer`) capabilities validated from its own
//! compiled module and canonical realm builtin references. Bare references to
//! identifiers that are neither a recognized builtin nor present in the live
//! global environment fail closed with a `ReferenceError` rather than silently
//! resolving — the conservative posture for adversary-authored dynamic code.
//!
//! The driving vector is BotGuard's G-2: `var f=new Function("x","return x*2");
//! f(21)` must return `42` through `HybridRouter::eval`.

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

/// Evaluate through the HybridRouter — the path named by the parent-bead AC#1.
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

// --- AC#1: the exact G-2 vector returns 42 -----------------------------------

#[test]
fn exact_g2_vector_returns_42_through_hybrid_router() {
    assert_eq!(
        eval_value_hybrid(r#"var f = new Function("x", "return x * 2;"); f(21);"#),
        "42"
    );
}

#[test]
fn exact_g2_vector_returns_42_through_native_engine() {
    assert_eq!(
        eval_value(r#"var f = new Function("x", "return x * 2;"); f(21);"#),
        "42"
    );
}

// --- AC#3: return values, argument binding, builtin/nested calls, `this` ------

#[test]
fn generated_function_returns_literal_value() {
    assert_eq!(eval_value(r#"new Function("return 7;")();"#), "7");
}

#[test]
fn generated_function_without_return_yields_undefined() {
    assert_eq!(eval_value(r#"new Function("var a = 1;")();"#), "undefined");
}

#[test]
fn generated_function_binds_multiple_arguments_positionally() {
    assert_eq!(
        eval_value(r#"new Function("a", "b", "return a + b;")(2, 3);"#),
        "5"
    );
}

#[test]
fn generated_function_missing_arguments_are_undefined() {
    assert_eq!(
        eval_value(r#"new Function("a", "b", "return typeof b;")(2);"#),
        "undefined"
    );
}

#[test]
fn generated_function_can_call_builtin_globals() {
    // `Math` is a realm builtin reachable from the generated function's
    // global-only scope; the call needs the `Builtin` capability, which the
    // generated module declares and the contained-codegen envelope grants.
    assert_eq!(
        eval_value(r#"new Function("return Math.max(10, 42);")();"#),
        "42"
    );
}

#[test]
fn generated_function_supports_nested_builtin_calls() {
    assert_eq!(
        eval_value(r#"new Function("return Math.max(Math.min(100, 42), 7);")();"#),
        "42"
    );
}

#[test]
fn generated_function_plain_call_this_is_undefined() {
    // A plain call binds `this = undefined`; no construction-site/global-this leak.
    assert_eq!(
        eval_value(r#"new Function("return typeof this;")();"#),
        "undefined"
    );
}

// --- AC#2: global-scope binding (globals visible, locals not) -----------------

#[test]
fn generated_function_cannot_capture_call_site_locals() {
    // The function is invoked deep inside caller() where `callerLocal` is in
    // scope; the global-only collapse means it must still read as undefined.
    // This is the discriminating "cannot capture non-global locals" check:
    // without the global-only scope collapse the call-site `callerLocal` would
    // leak in as "number". (Construction-site locals cannot exist to leak in the
    // first place: `new Function(...)` resolves `Function` only at global scope,
    // so every generated function is necessarily *constructed* in global scope.)
    let src = r#"
        var f = new Function("return typeof callerLocal;");
        function caller() {
            var callerLocal = 5;
            return f();
        }
        caller();
    "#;
    assert_eq!(eval_value(src), "undefined");
}

// --- Containment: bare unbound references fail closed ------------------------

#[test]
fn generated_function_unbound_reference_fails_closed() {
    // A bare reference (not under `typeof`) to an identifier that is neither a
    // recognized builtin nor a live global must not silently resolve; it fails
    // closed rather than reaching into ambient state.
    let _err = eval_error(r#"new Function("return someUndeclaredGlobalXyz + 1;")();"#);
}

// --- AC#4: `new f(...)` on a generated function fails deterministically -------

#[test]
fn constructing_a_generated_function_fails_deterministically() {
    let err = eval_error(r#"var f = new Function("return 1;"); new f();"#);
    assert!(err.contains("bd-8enww.3.3"), "{err}");
    assert!(
        err.contains("construct") || err.contains("unsupported"),
        "{err}"
    );
}

// --- Determinism: identical source ⇒ identical observable result --------------

#[test]
fn generated_function_invocation_is_deterministic() {
    let src = r#"var f = new Function("x", "return x * 2;"); f(21);"#;
    assert_eq!(eval_value(src), eval_value(src));
}
