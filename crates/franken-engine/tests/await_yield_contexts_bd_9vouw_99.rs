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

#[test]
fn adjacent_await_operands_execute_with_exact_values() {
    let source = r#"
async function f() {
    let x = 3;
    const values = [await[1, 2], await{n: 3}, await'quoted', await`template`,
        await/a+/.test('aa'), await!0, await~1, await+2, await-2, await.5,
        await++x, await--x];
    console.log(values[0].join(':'), values[1].n, values.slice(2).join('|'));
}
f();
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .expect("adjacent await operands must execute");
    let output: Vec<_> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(output, ["1:2 3 quoted|template|true|true|-2|2|-2|0.5|4|3"]);
}

#[test]
fn adjacent_await_preserves_binary_precedence_and_microtask_order() {
    let source = r#"
const order = [];
function right() { order.push('right'); return 3; }
async function f() {
    order.push('start');
    const result = await+2 + right();
    order.push('done:' + result);
}
f();
order.push('sync');
queueMicrotask(() => console.log(order.join(',')));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .expect("await must suspend before the binary right operand runs");
    let output: Vec<_> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(output, ["start,sync,right,done:5"]);
}

#[test]
fn yield_accepts_full_assignment_operands_and_adjacent_unary_operands() {
    let source = r#"
function* g() {
    let x = 1;
    yield x = 7;
    yield x += 2;
    yield x => x + 1;
    yield x ? 11 : 12;
    yield+3 * 2;
    yield-2 + 1;
    yield.5;
    yield++x;
    yield--x;
}
[...g()].map(value => typeof value === 'function' ? value(5) : value).join(',');
"#;
    assert_eq!(eval(source).as_deref(), Ok("7,9,6,11,6,-1,0.5,10,9"));
}

#[test]
fn suspension_keyword_prefixes_remain_ordinary_identifiers() {
    let source = r#"
function f(await, yield) {
    const awaitValue = 10;
    const yieldValue = 20;
    return await+1 + yield-1 + awaitValue + yieldValue;
}
f(2, 3);
"#;
    assert_eq!(eval(source).as_deref(), Ok("35"));
}
