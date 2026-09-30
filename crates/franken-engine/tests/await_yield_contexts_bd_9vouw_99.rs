#![forbid(unsafe_code)]
//! bd-9vouw.99 (part): `await` and `yield` follow their function contexts.
//! The parser tracked only whether `await` was an operator; `yield` was a
//! yield expression everywhere, so a generator could name a binding `yield`,
//! `void yield` parsed, strict code could read `yield` as a name, and a bare
//! `await` in an async function parsed as an identifier. Each is a
//! SyntaxError in Node v22.2.0; the positive controls below are Node's
//! completion values, and pin that every generator form still yields.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> Result<String, String> {
    HybridRouter::default()
        .eval(source)
        .map(|outcome| outcome.value)
        .map_err(|err| err.to_string())
}

#[test]
fn await_and_yield_misuse_are_syntax_errors() {
    for source in [
        "async function f() { void await; }",
        "async function f() { await; }",
        "function* g() { void yield; }",
        "function* g() { var yield; }",
        "\"use strict\"; function f() { return yield; }",
        "class C { #field; static m() { #field in yield; } }",
    ] {
        let result = eval(source);
        assert!(
            result.is_err(),
            "`{source}` must be a SyntaxError, got {result:?}"
        );
    }
}

#[test]
fn generators_and_plain_functions_keep_their_meaning() {
    for (source, node) in [
        (
            "function* g() { void (yield); return 1; } var it = g(); it.next(); it.next().value",
            "1",
        ),
        ("function f() { var yield = 1; return yield; } f()", "1"),
        (
            "function* g() { function h() { var yield = 2; return yield; } yield h(); } \
             g().next().value",
            "2",
        ),
        (
            "function* g() { yield 1; yield* [2, 3]; } [...g()].join()",
            "1,2,3",
        ),
        ("var o = { *m() { yield 5; } }; o.m().next().value", "5"),
        (
            "class C { *m() { yield 6; } } new C().m().next().value",
            "6",
        ),
        (
            "async function f() { return await 7; } typeof f",
            "function",
        ),
        (
            "var g = function* () { var x = yield 1; return x * 2; }; var it = g(); it.next(); \
             it.next(21).value",
            "42",
        ),
    ] {
        assert_eq!(
            eval(source),
            Ok(node.to_string()),
            "`{source}` must match Node v22.2.0"
        );
    }
}
