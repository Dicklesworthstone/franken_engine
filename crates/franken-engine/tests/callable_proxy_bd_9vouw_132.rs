//! bd-9vouw.132: a Proxy can wrap a function (ES2020 9.5.12-14, 26.2.1.1).
//!
//! `new Proxy(fn, handler)` threw "expected Proxy target object, got
//! function", so function-wrapping proxies (prettier's plugin wrappers and
//! its chainable color stub, call tracers, spies) failed at construction.
//! A callable proxy is now callable and constructible through its `apply` /
//! `construct` traps (or its target), and its other traps receive the
//! function. Reflect's property operations accept functions. Expected
//! strings are Node v22.2.0's output for the same programs.
//!
//! No-claim: without a `construct` trap, `new.target` is the target rather
//! than the proxy; `class X extends proxyOverFn`, util.inspect of a callable
//! proxy and instanceof with a callable proxy on the right are not covered;
//! `Object.create(fn)` with a plain function (not a proxy) is still refused.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// A proxy over a function is callable: `apply` gets (target, this, args), and without the trap the target runs; typeof is "function" and name/length/call read through.
#[test]
fn callable_proxy_call() {
    let source = "function add(a, b) { return a + b; }\n\
         var log = [];\n\
         var p = new Proxy(add, { apply(t, thisArg, args) { log.push(t === add, thisArg, args.length); return t.apply(thisArg, args) * 10; } });\n\
         var q = new Proxy(add, {});\n\
         [typeof p, p(1, 2), q(3, 4), log.join(','), q.length, q.name, typeof q.call, q.call(null, 5, 6)].join(' ');";
    assert_eq!(eval(source), "function 30 7 true,,2 2 add function 11");
}

/// prettier's chainable color stub: a `get` trap that returns the proxy itself, called through to its String target.
#[test]
fn callable_proxy_chain() {
    let source = "var xn = new Proxy(String, { get: () => xn });\n\
         [xn.red.bold('hi'), xn(5), typeof xn.anything].join(' ');";
    assert_eq!(eval(source), "hi 5 function");
}

/// Traps that forward with Reflect.get / Reflect.apply on the function target (prettier's plugin wrappers).
#[test]
fn callable_proxy_forward() {
    let source = "function base(x) { return x + 1; } base.tag = 't';\n\
         var seen = [];\n\
         var w = new Proxy(base, { get(t, k, r) { seen.push(String(k)); return Reflect.get(t, k, r); }, apply: (t, th, a) => Reflect.apply(t, th, a) * 2 });\n\
         [w(1), w.tag, w.length, seen.join(',')].join(' ');";
    assert_eq!(eval(source), "4 t 1 tag,length");
}

/// [[Construct]]: without a trap the target is constructed; the `construct` trap gets (target, args, newTarget) and must return an object; a non-constructor target is a TypeError.
#[test]
fn callable_proxy_construct() {
    let source = "class Point { constructor(x) { this.x = x; } }\n\
         var P = new Proxy(Point, {});\n\
         var C = new Proxy(Point, { construct(t, args, nt) { return { made: args[0], same: nt === C, target: t === Point }; } });\n\
         var a = new P(3), b = new C(4);\n\
         var e = ''; try { new (new Proxy(() => 1, {}))(); } catch (err) { e = err.constructor.name; }\n\
         var e3 = ''; try { new (new Proxy(Point, { construct: () => 1 }))(); } catch (err) { e3 = err.constructor.name; }\n\
         [a.x, a instanceof Point, b.made, b.same, b.target, e, e3].join(' ');";
    assert_eq!(eval(source), "3 true 4 true true TypeError TypeError");
}

/// Proxy.revocable over a function: callable until revoked, then a TypeError.
#[test]
fn callable_proxy_revoke() {
    let source = "var r = Proxy.revocable(function () { return 1; }, {});\n\
         var before = r.proxy();\n\
         r.revoke();\n\
         var e2 = ''; try { r.proxy(); } catch (err) { e2 = err.constructor.name; }\n\
         [before, e2, typeof r.proxy].join(' ');";
    assert_eq!(eval(source), "1 TypeError function");
}

/// Test262 built-ins/Proxy/get/trap-is-missing-target-is-proxy.js: a proxy over a function proxy reads through both, also as a prototype.
#[test]
fn callable_proxy_nested() {
    let source = "var functionTarget = new Proxy(function (_arg) {}, {});\n\
         var functionProxy = new Proxy(functionTarget, {});\n\
         [Object.create(functionProxy).length, 'call' in functionProxy, 'zz' in functionProxy, functionProxy.length, typeof functionProxy].join(' ');";
    assert_eq!(eval(source), "1 true false 1 function");
}

/// A callable proxy as a method keeps `this`; `set` and `has` traps get the function target.
#[test]
fn callable_proxy_method() {
    let source = "var o = { v: 7, m: new Proxy(function () { return this.v; }, {}) };\n\
         var traps = [];\n\
         var s = new Proxy(function (k) { return k * 2; }, { set(t, k, v) { traps.push('set:' + k); t[k] = v; return true; }, has(t, k) { traps.push('has:' + String(k)); return k in t; } });\n\
         s.extra = 5;\n\
         [o.m(), s(4), s.extra, 'extra' in s, traps.join(',')].join(' ');";
    assert_eq!(eval(source), "7 8 5 true set:extra,has:extra");
}

/// Without a `set` trap a write lands on the function target (and delete removes it there); a `set` trap's receiver is the proxy.
#[test]
fn callable_proxy_writes() {
    let source = "function g() {}\n\
         var q = new Proxy(g, {});\n\
         q.extra = 1;\n\
         var recv;\n\
         var s2 = new Proxy(g, { set(t, k, v, r) { recv = r === s2; t[k] = v; return true; } });\n\
         s2.more = 2;\n\
         [q.extra, g.extra, recv, g.more, delete q.extra, String(g.extra)].join(' ');";
    assert_eq!(eval(source), "1 1 true 2 true undefined");
}

/// Reflect.get/has/set/deleteProperty on a plain function (they threw "expected object with property storage").
#[test]
fn callable_proxy_reflect() {
    let source = "function f(a, b) {} f.x = 1;\n\
         [Reflect.get(f, 'length'), Reflect.get(f, 'name'), Reflect.get(f, 'x'), typeof Reflect.get(f, 'call'), typeof Reflect.get(f, 'prototype'), Reflect.has(f, 'call'), Reflect.has(f, 'zz'), Reflect.set(f, 'y', 2), f.y, Reflect.deleteProperty(f, 'y'), String(f.y), typeof Reflect.get(String, 'fromCharCode'), Reflect.get(String, 'name')].join(' ');";
    assert_eq!(
        eval(source),
        "2 f 1 function object true false true 2 true undefined function String"
    );
}
