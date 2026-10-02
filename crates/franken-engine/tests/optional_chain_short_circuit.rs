//! ES2020 12.3.9: an optional link short-circuits the whole rest of its chain.
//!
//! FrankenEngine desugared each `?.` on its own, so the links after it still
//! ran on `undefined`: `o.x?.y.z`, `o.a?.b.c()`, `o.a?.['b'].c` and
//! `o.f?.().x` threw TypeError when `o.x` / `o.a` / `o.f` was nullish (Node:
//! undefined). `o.m?.()` called the method with `this` undefined, and
//! `delete o?.a` answered true without deleting. Parentheses still end a
//! chain: `(o.x?.y).z` throws. Expected strings are Node v22.2.0's output.
//!
//! No-claim: a parenthesized optional chain used as a callee, `(a?.b)()`,
//! still short-circuits like `a?.b()` instead of throwing when `a` is
//! nullish.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

const SETUP: &str = "function t(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
                     var o = {v: 3, m() { return this && this.v; }};\n\
                     var deep = {x: {y: {z: 5}}, a: {b: {c() { return this.v; }, v: 9}}};\n";

#[test]
fn optional_links_short_circuit_the_rest_of_the_chain() {
    let source = format!(
        "{SETUP}[t(() => o.x?.y.z), t(() => deep.x?.y.z), t(() => o.a?.b.c()), \
         t(() => deep.a?.b.c()), t(() => o.a?.['b'].c), t(() => o.a?.b[0]), \
         t(() => o.f?.().x), t(() => o.g?.()?.x), t(() => (o.x?.y).z)].join(',');"
    );
    assert_eq!(
        eval(&source),
        "undefined,5,undefined,9,undefined,undefined,undefined,undefined,TypeError"
    );
}

#[test]
fn optional_method_calls_keep_their_receiver() {
    let source =
        format!("{SETUP}[t(() => o.m?.()), t(() => o['m']?.()), t(() => o.n?.())].join(',');");
    assert_eq!(eval(&source), "3,3,undefined");
}

#[test]
fn delete_through_an_optional_chain_deletes_or_short_circuits() {
    assert_eq!(
        eval(
            "var d1 = {a: {b: 1}}; var d2 = {a: {b: 1}}; var n = null;\n\
             [delete d1?.a, JSON.stringify(d1), delete d2?.a?.b, JSON.stringify(d2), \
             delete n?.a, delete n?.a.b].join(',');"
        ),
        "true,{},true,{\"a\":{}},true,true"
    );
}

#[test]
fn short_circuited_arguments_are_not_evaluated_and_the_base_is_read_once() {
    assert_eq!(
        eval(
            "var n = null; var c = 0; n?.f(c++); n?.a.b(c++);\n\
             var k = 0; var o2 = {get p() { k++; return {q: 1}; }}; o2.p?.q; o2.p?.q.r;\n\
             c + ' ' + k;"
        ),
        "0 2"
    );
}

/// `new` may not take an optional chain as its callee (ES2020 12.3.9.1:
/// `new a?.b()` is a SyntaxError), but a parenthesized callee is an ordinary
/// operand. The parser rejected any optional chain anywhere in the callee,
/// so zod's `new (_params?.Err ?? _Err)(issues)` failed to parse.
#[test]
fn parenthesized_optional_chain_can_be_constructed() {
    assert_eq!(
        eval(
            "var p = {Err: function (m) { this.m = m; }}, q = undefined; \
             function E(m) { this.m = 'E' + m; } \
             [new (p?.Err ?? E)(1).m, new (q?.Err ?? E)(2).m, new (p?.Err)(3).m].join()"
        ),
        "1,E2,3"
    );
    for source in ["new a?.b()", "new a?.b", "new a.b?.()"] {
        let error = HybridRouter::default()
            .eval(&format!("var a = {{b: function () {{}}}}; {source}"))
            .expect_err(source);
        assert!(
            error.to_string().contains("optional chaining"),
            "{source}: {error}"
        );
    }
}

/// ES2020 12.15.1 rejects an assignment target only when the target itself
/// is an optional chain. The parser rejected any target with a `?.` anywhere
/// inside it, so a computed key (`t[o?.p] = 1`, arktype's
/// `t[l?.() ?? g()] = o`), a destructuring default or a for-of head with a
/// chain in its key failed to parse. Expected values are Node v22.2.0's.
#[test]
fn optional_chains_inside_assignment_targets_are_ordinary_expressions() {
    let source = "var t = {}, l = null, n = null, r, o = { p: \"k\", f() { return \"q\"; } };\n\
                  t[l?.() ?? \"a\"] = 1;\n\
                  t[o?.p] = 2; t[o?.p] += 3;\n\
                  var u = { k: { m: 0 } }; u[o?.p].m = 4;\n\
                  [t[n?.p ?? \"z\"]] = [5];\n\
                  for (t[o.f?.()] of [6]) ;\n\
                  [r = n?.p] = [];\n\
                  ({ x: t[o?.p + \"2\"] } = { x: 7 });\n\
                  [t.a, t.k, u.k.m, t.z, t.q, String(r), t.k2].join(\",\");";
    assert_eq!(eval(source), "1,5,4,5,6,undefined,7");
    for target in [
        "a?.b = 1",
        "a?.b.c = 1",
        "a?.[0] = 1",
        "a?.b += 1",
        "[a?.b] = []",
        "({ x: a?.b } = {})",
        "[...a?.b] = []",
        "[a?.b = 1] = []",
    ] {
        let error = HybridRouter::default()
            .eval(&format!("var a = {{}}; {target};"))
            .expect_err(target);
        assert!(error.to_string().contains("target"), "{target}: {error}");
    }
}

/// A property named `in` or `instanceof` is a member access, not the
/// relational operator: the binary-operator scan split `o.in.x` at `in`
/// ("unsupported expression syntax: o."), so `o.in + 1`, `o.in()`,
/// `o.instanceof.y` and arktype's `this.inner.in?.rawIn` failed. The
/// operators themselves still work next to them. Expected values are Node
/// v22.2.0's.
#[test]
fn properties_named_in_and_instanceof_are_member_accesses() {
    let source = "var o = { in: { x: 8 }, instanceof: { y: 9 }, f: { in: function () { return 3; } } };\n\
                  [o.in.x, o.in?.x, o['in']?.x, o.instanceof.y, o.instanceof?.y, o.f.in(), o.in.x + 1, \
                  'in' in o, o.in.x in { 8: 0 }, o instanceof Object].join(' ');";
    assert_eq!(eval(source), "8 8 8 9 9 3 9 true true true");
}
