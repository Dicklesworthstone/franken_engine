//! bd-9vouw.132: a Proxy can wrap a function (ES2020 9.5.12-14, 26.2.1.1).
//!
//! `new Proxy(fn, handler)` threw "expected Proxy target object, got
//! function", so function-wrapping proxies (prettier's plugin wrappers and
//! its chainable color stub, call tracers, spies) failed at construction.
//! A callable proxy is now callable and constructible through its `apply` /
//! `construct` traps (or its target), and its other traps receive the
//! function. Reflect's property operations accept functions. The original
//! probes below use expected strings captured from Node v22.2.0. The later
//! constructor-forwarding probes identify their reference V8 checks separately.
//!
//! Construction forwards the original newTarget through missing traps,
//! including nested proxies, bound targets, and derived constructors.

#![forbid(unsafe_code)]

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

/// Reflect.construct(proxy, args, newTarget) constructs (it called the proxy) and passes newTarget to the construct trap; a proxy without a trap forwards itself as newTarget to a proxy target.
#[test]
fn callable_proxy_construct_new_target() {
    let source = "var calls = 0, seen;\n\
         var Target = new Proxy(function () { throw new Error('called'); }, { construct(t, args, nt) { calls++; seen = nt; return { sum: args[0] + args[1] }; } });\n\
         var P = new Proxy(Target, {});\n\
         function NT() {}\n\
         var a = Reflect.construct(P, [3, 4], NT); var first = seen === NT;\n\
         var b = new P(1, 2);\n\
         [calls, first, seen === P, a.sum, b.sum].join(' ');";
    assert_eq!(eval(source), "2 true true 7 3");
}

/// util.inspect shows a callable proxy as its target (a revoked one as <Revoked Proxy>), and instanceof reads its prototype through [[Get]].
#[test]
fn callable_proxy_inspect_instanceof() {
    let source = "var util = require('util');\n\
         function add(a, b) {} class A {}\n\
         var P = new Proxy(A, {});\n\
         var r = Proxy.revocable(function f() {}, {}); r.revoke();\n\
         [util.inspect(new Proxy(add, {})), util.inspect(new Proxy(new Proxy(add, {}), {})), util.inspect(r.proxy), new A() instanceof P, {} instanceof P].join(' | ');";
    assert_eq!(
        eval(source),
        "[Function: add] | [Function: add] | <Revoked Proxy> | true | false"
    );
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

/// A callable proxy as newTarget: GetPrototypeFromConstructor reads its `prototype` through [[Get]] (Test262 built-ins/Proxy/construct/trap-is-missing-target-is-proxy.js: new of a proxy over a proxy over Array).
#[test]
fn callable_proxy_proxy_new_target_prototype() {
    let source = "var ArrayProxy = new Proxy(new Proxy(Array, {}), {});\n\
         var arr = new ArrayProxy(1, 2, 3);\n\
         function F() { this.made = true; } F.prototype.kind = 'F';\n\
         var FP = new Proxy(new Proxy(F, {}), {});\n\
         var f = new FP();\n\
         var trapped = new Proxy(F, { get(t, k) { return k === 'prototype' ? { kind: 'trap' } : t[k]; } });\n\
         var viaTrap = Reflect.construct(F, [], trapped);\n\
         var viaArray = Reflect.construct(Array, [5], ArrayProxy);\n\
         class MyArray extends Array {}\n\
         var mine = Reflect.construct(ArrayProxy, [], MyArray);\n\
         [Array.isArray(arr), arr.join(), f.made, f.kind, Object.getPrototypeOf(f) === F.prototype, viaTrap.kind, viaTrap.made, Array.isArray(viaArray), viaArray.length, mine instanceof MyArray].join(' ');";
    assert_eq!(eval(source), "true 1,2,3 true F true trap true true 5 true");
}

// The constructor forwarding probes below were checked against reference V8;
// the Rust tests execute the same programs through the native engine.

#[test]
fn callable_proxy_construct_preserves_own_new_target_and_prototype_trap() {
    let source = r#"
        var log = [], prototype = { marker: 'selected' }, observed;
        function Target(x) { log.push('body'); observed = new.target; this.x = x; }
        var P = new Proxy(Target, {
            get(t, key, receiver) {
                if (key === 'prototype') {
                    log.push('prototype:' + (t === Target) + ':' + (receiver === P));
                    return prototype;
                }
                return Reflect.get(t, key, receiver);
            }
        });
        var instance = new P(42);
        [observed === P, Object.getPrototypeOf(instance) === prototype,
         instance.marker, instance.x, log.join(',')].join(' ');
    "#;
    assert_eq!(eval(source), "true true selected 42 prototype:true:true,body");
}

#[test]
fn callable_proxy_reflect_construct_preserves_default_and_explicit_new_target() {
    let source = r#"
        var observed, reads = 0;
        function Target() { observed = new.target; }
        var P = new Proxy(Target, {
            get(t, key, receiver) {
                if (key === 'prototype') reads++;
                return Reflect.get(t, key, receiver);
            }
        });
        function Other() {}
        var first = Reflect.construct(P, []), defaultTarget = observed === P;
        var second = Reflect.construct(P, [], P), sameTarget = observed === P;
        var third = Reflect.construct(P, [], Other), explicitTarget = observed === Other;
        [defaultTarget, sameTarget, explicitTarget, reads,
         Object.getPrototypeOf(first) === Target.prototype,
         Object.getPrototypeOf(second) === Target.prototype,
         Object.getPrototypeOf(third) === Other.prototype].join(' ');
    "#;
    assert_eq!(eval(source), "true true true 2 true true true");
}

#[test]
fn callable_proxy_nested_construct_preserves_outer_identity_and_get_order() {
    let source = r#"
        var log = [], observed;
        function Target() { observed = new.target; log.push('body'); }
        var inner = new Proxy(Target, {
            get(t, key, receiver) {
                if (key === 'prototype') log.push('inner:' + (receiver === outer));
                return Reflect.get(t, key, receiver);
            }
        });
        var outer = new Proxy(inner, {
            get(t, key, receiver) {
                if (key === 'prototype') log.push('outer:' + (receiver === outer));
                return Reflect.get(t, key, receiver);
            }
        });
        var instance = new outer();
        [observed === outer, Object.getPrototypeOf(instance) === Target.prototype,
         log.join(',')].join(' ');
    "#;
    assert_eq!(eval(source), "true true outer:true,inner:true,body");
}

#[test]
fn callable_proxy_and_bound_construction_apply_distinct_new_target_rules() {
    let source = r#"
        var observed, prototype = { marker: 'proxy' }, reads = 0;
        function Target(a, b) { observed = new.target; this.total = a + b; }
        var bound = Target.bind(null, 3);
        var P = new Proxy(bound, {
            get(t, key, receiver) {
                if (key === 'prototype') { reads++; return prototype; }
                return Reflect.get(t, key, receiver);
            }
        });
        var first = new P(4), proxyTarget = observed === P;
        var rebound = P.bind(null, 5);
        var second = new rebound(), reboundTarget = observed === P;
        var plain = new bound(6), plainTarget = observed === Target;
        [proxyTarget, reboundTarget, plainTarget, first.total, second.total, plain.total,
         Object.getPrototypeOf(first) === prototype,
         Object.getPrototypeOf(second) === prototype, reads].join(' ');
    "#;
    assert_eq!(eval(source), "true true true 7 8 9 true true 2");
}

#[test]
fn callable_proxy_construct_preserves_derived_new_target() {
    let source = r#"
        var observed;
        class Base { constructor(x) { observed = new.target; this.x = x; } }
        class Derived extends Base { constructor(x) { super(x); this.doubled = x * 2; } }
        var P = new Proxy(Derived, {});
        var instance = new P(7);
        [observed === P, instance.x, instance.doubled,
         instance instanceof Base, instance instanceof Derived,
         Object.getPrototypeOf(instance) === Derived.prototype].join(' ');
    "#;
    assert_eq!(eval(source), "true 7 14 true true true");
}

#[test]
fn callable_proxy_can_be_a_derived_constructor_parent() {
    let source = r#"
        var observed, log = [];
        function Base(x) { observed = new.target; this.x = x; log.push('base'); }
        var Parent = new Proxy(Base, {});
        class Explicit extends Parent { constructor(x) { super(x); log.push('derived'); } }
        class Implicit extends Parent {}
        var explicit = new Explicit(8), explicitTarget = observed === Explicit;
        var implicit = new Implicit(9), implicitTarget = observed === Implicit;
        [explicitTarget, implicitTarget, explicit.x, implicit.x,
         explicit instanceof Explicit, implicit instanceof Implicit,
         log.join(',')].join(' ');
    "#;
    assert_eq!(eval(source), "true true 8 9 true true base,derived,base");
}

#[test]
fn callable_proxy_construct_prototype_throw_precedes_body_and_preserves_exception() {
    let source = r#"
        var sentinel = {}, bodies = 0, reads = 0, seen;
        function Target() { bodies++; }
        var P = new Proxy(Target, {
            get(t, key, receiver) {
                if (key === 'prototype') { reads++; throw sentinel; }
                return Reflect.get(t, key, receiver);
            }
        });
        try { new P(); } catch (error) { seen = error; }
        var first = seen === sentinel;
        try { Reflect.construct(P, []); } catch (error) { seen = error; }
        [first, seen === sentinel, bodies, reads].join(' ');
    "#;
    assert_eq!(eval(source), "true true 0 2");
}

#[test]
fn callable_proxy_construct_trap_return_skips_prototype_read() {
    let source = r#"
        var sentinel = {}, observations = [];
        function Target() { throw 'body must not run'; }
        var P = new Proxy(Target, {
            get() { throw 'prototype must not be read'; },
            construct(target, args, newTarget) {
                observations.push(target === Target, newTarget === P, args.join(','));
                return sentinel;
            }
        });
        var result = new P(1, 2);
        [result === sentinel, observations.join('|')].join(' ');
    "#;
    assert_eq!(eval(source), "true true|true|1,2");
}

#[test]
fn callable_proxy_construct_builtin_fallback_and_revocation() {
    let source = r#"
        var reads = 0;
        var P = new Proxy(Array.bind(null), {
            get(t, key, receiver) {
                if (key === 'prototype') { reads++; return 1; }
                return Reflect.get(t, key, receiver);
            }
        });
        var values = new P(2, 3);
        var revoked = Proxy.revocable(function () {}, {});
        revoked.revoke();
        var failed = false;
        try { new revoked.proxy(); } catch (error) { failed = error instanceof TypeError; }
        [Array.isArray(values), values.join(),
         Object.getPrototypeOf(values) === Array.prototype, reads, failed].join(' ');
    "#;
    assert_eq!(eval(source), "true 2,3 true 1 true");
}

#[test]
fn callable_proxy_constructs_builtin_subclasses() {
    let source = r#"
        var reads = 0;
        class Numbers extends Array {
            constructor(size) { super(size); this.observed = new.target; }
        }
        var P = new Proxy(Numbers, {
            get(t, key, receiver) {
                if (key === 'prototype') reads++;
                return Reflect.get(t, key, receiver);
            }
        });
        var numbers = new P(3);
        class Entries extends Map {}
        var entries = new (new Proxy(Entries, {}))([['key', 7]]);
        var Parent = new Proxy(Array, {});
        class Child extends Parent {}
        var child = new Child(4);
        [Array.isArray(numbers), numbers.length, numbers.observed === P,
         numbers instanceof Numbers, reads, entries instanceof Entries,
         entries.get('key'), Array.isArray(child), child.length,
         child instanceof Child].join(' ');
    "#;
    assert_eq!(eval(source), "true 3 true true 1 true 7 true 4 true");
}
