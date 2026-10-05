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
        // `await` / `yield` as object-literal keys are names, not operators.
        (
            "function* g() { yield { yield: 1 }.yield; } \
             async function h() { const o = { await: 2 }; return o.await; } \
             [g().next().value, typeof h, \
             (function () { 'use strict'; return { yield: 4, static: 5 }.yield; })(), \
             ({ true: 6, null: 7 }).null].join()",
            "1,function,4,7",
        ),
    ] {
        assert_eq!(
            eval(source),
            Ok(node.to_string()),
            "`{source}` must match Node v22.2.0"
        );
    }
}

/// bd-9vouw.99 (rest): a class static block reserves `await` in its own code,
/// arrow parameters included (ES2022 15.7.1), and a generator's or async
/// function's parameter list may not contain a yield or await expression,
/// an arrow's within them included (ES2020 14.4.1, 14.7.1, 14.8.1). Node
/// v22.2.0 rejects each with a SyntaxError.
#[test]
fn static_block_await_and_parameter_expressions_are_syntax_errors() {
    for source in [
        "class C { static { await; } }",
        "class C { static { (await => 0); } }",
        "class C { static { var await; } }",
        "class C { static { ({ await }); } }",
        "class C { static { await: ; } }",
        "function* g(a = yield) {}",
        "function* g(a = yield 1) {}",
        "async function f(a = await 1) {}",
        "function* g() { (a = yield) => 0; }",
        "async function f() { (a = await 1) => 0; }",
    ] {
        let result = eval(source);
        assert!(
            result.is_err(),
            "`{source}` must be a SyntaxError, got {result:?}"
        );
    }
}

/// Functions and arrow bodies inside a static block, property keys, and
/// parameters without those expressions keep their meaning (Node v22.2.0
/// completion values).
#[test]
fn await_and_yield_stay_usable_where_node_allows_them() {
    for (source, node) in [
        (
            "class C { static { function f() { var await = 4; return await; } C.v = f(); } } C.v",
            "4",
        ),
        ("class C { static { C.v = { await: 5 }.await; } } C.v", "5"),
        (
            "class C { static { C.v = (() => typeof await)(); } } C.v",
            "undefined",
        ),
        ("function* g(a = 1) { yield a; } g().next().value", "1"),
        (
            "function* g() { function h(a = typeof yield) { return a; } yield h(); } \
             g().next().value",
            "undefined",
        ),
        ("async function f(a = 2) { return a; } typeof f", "function"),
    ] {
        assert_eq!(eval(source).as_deref(), Ok(node), "{source}");
    }
}
