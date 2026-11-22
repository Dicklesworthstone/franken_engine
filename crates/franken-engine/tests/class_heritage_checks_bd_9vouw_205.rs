#![forbid(unsafe_code)]

//! bd-9vouw.205: ClassDefinitionEvaluation (ES2020 14.6.13 step 6.g) throws a
//! TypeError for a superclass that is not a constructor (an arrow, a
//! generator, an async function, a plain object) and for one whose
//! `prototype` is neither an object nor null; the class was defined anyway.
//! Not covered: `class extends null {}`, which still throws (the lowering
//! reads `null.prototype`).
//!
//! Expected line is Node v22.2.0's output (Bun 1.4.2 prints the same).

use frankenengine_engine::HybridRouter;

#[test]
fn class_heritage_must_be_a_constructor_with_an_object_prototype() {
    let source = "const out = [];\nconst cases = [['arrow', () => { const f = () => {}; return class extends f {}; }], ['generator', () => { function* g() {} return class extends g {}; }], ['async', () => { async function a() {} return class extends a {}; }], ['object', () => class extends ({}) {}], ['badproto', () => { function F() {} F.prototype = 1; return class extends F {}; }], ['nullproto', () => { function F() {} F.prototype = null; return class extends F {}; }]];\nfor (const [label, make] of cases) {\n  try { make(); out.push(label + ':ok'); } catch (e) { out.push(label + ':' + e.constructor.name); }\n}\nconsole.log(out.join(' '));\n";
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "arrow:TypeError generator:TypeError async:TypeError object:TypeError badproto:TypeError nullproto:ok"
        ]
    );
}

/// bd-9vouw.216: `F.__proto__ = P` on a function runs Object.prototype's
/// `__proto__` setter: P becomes F's [[Prototype]] (F inherits P's statics),
/// a primitive is ignored, a cycle is a TypeError, and no own `__proto__`
/// property appears. It stored an own data property, so
/// `Object.getPrototypeOf(F)` stayed Function.prototype and `F.s` was
/// undefined. Null and custom prototype mutations are covered below too.
#[test]
fn assigning_proto_on_a_function_sets_its_prototype_bd_9vouw_216() {
    let source = "function P() {} P.s = 1; function C() {} C.__proto__ = P;\nvar r1 = [Object.getPrototypeOf(C) === P, C.s, C.__proto__ === P];\nfunction D() {} D.__proto__ = 5;\nvar r2 = Object.getPrototypeOf(D) === Function.prototype;\nvar cyc; try { P.__proto__ = C; cyc = 'no'; } catch (e) { cyc = e.name; }\nconsole.log(r1.join(), r2, cyc, Object.keys(C).length, Object.prototype.hasOwnProperty.call(C, '__proto__'));\n";
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, ["true,1,true true TypeError 0 false"]);
}

/// bd-9vouw.228: a class element or destructuring key spelled as a numeric
/// literal names ToString of its value, as an object literal key does:
/// binary, octal, hex, exponent, leading-dot and non-canonical decimal
/// accessors, a static accessor, a method, static and instance fields, a
/// BigInt key, the accessor's function name, and `{ 0x10: a }` patterns.
/// The key kept its source text ("0b10"), so `C.prototype['2']` was
/// undefined (31 Test262 tests). Expected lines are Node v22.2.0's output;
/// Bun 1.4.2 agrees.
#[test]
fn numeric_literal_class_and_pattern_keys_are_canonical_bd_9vouw_228() {
    let source = "var log = [];\nclass C { get 0b10() { return 'b'; } set 0b10(v) { log.push(v); } get 1E+9() { return 'e'; } get 0x10() { return 'h'; } get .1() { return 'd'; } get 0.0000001() { return 'n'; } get 0o10() { return 'o'; } static get 0b11() { return 's'; } }\nconsole.log(C.prototype['2'], C.prototype['1000000000'], C.prototype['16'], C.prototype['0.1'], C.prototype['1e-7'], C.prototype['8'], C['3']);\nC.prototype['2'] = 'x';\nconsole.log(log.join(), Object.getOwnPropertyDescriptor(C.prototype, '2').get.name, C.prototype.hasOwnProperty('0b10'));\nclass D { 0x10() { return 'm'; } static 1e3 = 'f'; 0b101 = 'i'; 1n() { return 'big'; } }\nconsole.log(new D()[16](), D[1000], new D()[5], new D()[1](), D.prototype[16].name);\nvar { 0x10: a, 1e1: b, .5: c } = { 16: 'A', 10: 'B', 0.5: 'C' };\nconsole.log(a, b, c);\n";
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        ["b e h d n o s", "x get 2 false", "m f i big 16", "A B C"]
    );
}

/// bd-9vouw.230: a class field with neither initializer nor semicolon ends at
/// a line break when the next token cannot continue it (ASI): a public or
/// private field before a method, two private fields, a static private
/// field, a private method and a getter after them, and a field named
/// `async`. `get` still continues across the line break (a getter), as do an
/// initializer and a parameter list on the next line. The public field
/// swallowed the method silently and the private ones failed to parse.
/// Node v22.2.0 prints this line; Bun 1.4.2 agrees.
#[test]
fn class_fields_end_at_a_line_break_before_the_next_element_bd_9vouw_230() {
    let source = "class A {\n  x\n  m() { return 42; }\n}\nclass B {\n  #x\n  #y\n  static #s\n  m() { return [this.#x, this.#y, B.#s].length; }\n  #p() { return 3; }\n  get g() { return this.#p(); }\n  static s() { return 's'; }\n}\nclass D {\n  async\n  m() { return 'm'; }\n  get\n  h() { return 'h'; }\n  x\n  = 7\n  y\n  (a) { return a; }\n}\nconst a = new A(), b = new B(), d = new D();\nconsole.log(a.m(), 'x' in a, b.m(), b.g, B.s(), 'async' in d, d.m(), d.h, d.x, d.y(9));\n";
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, ["42 true 3 3 s true m h 7 9"]);
}

/// bd-9vouw.98: an ordinary object can have a function as its [[Prototype]]
/// through Object.create, Object.setPrototypeOf, an object literal's
/// `__proto__` and the `__proto__` setter: getPrototypeOf, Reflect and the
/// `__proto__` getter report the function, its statics (a class's static
/// method, with `this` the object) are inherited, and bundlers' `__toESM`
/// (`Object.create(getPrototypeOf(DerivedClass))`) loads. Object.create threw
/// "expected object or null prototype", setPrototypeOf threw, the `__proto__`
/// forms were ignored. Ordinary prototypes are unchanged. Inherited
/// Function.prototype members are covered below. Node v22.2.0's output;
/// Bun 1.4.2 agrees.
#[test]
fn an_object_can_inherit_from_a_function_bd_9vouw_98() {
    let source = "function F() {} F.s = 1;\nconst o = Object.create(F);\nconsole.log(typeof o, Object.getPrototypeOf(o) === F, o.s, Reflect.getPrototypeOf(o) === F, o.__proto__ === F);\nclass A { static k() { return 'k' + (this === o2); } }\nclass B extends A {}\nconst o2 = Object.create(Object.getPrototypeOf(B));\nconsole.log(Object.getPrototypeOf(o2) === A, o2.k());\nvar __create = Object.create, __getProtoOf = Object.getPrototypeOf, __defProp = Object.defineProperty;\nvar target = B != null ? __create(__getProtoOf(B)) : {};\n__defProp(target, 'default', { value: B, enumerable: true });\nconsole.log(typeof target.default, target.default === B, Object.keys(target).join());\nfunction G() {} G.t = 2;\nconst p = {}; Object.setPrototypeOf(p, G);\nconst q = { __proto__: G };\nconst r = {}; r.__proto__ = G;\nconsole.log(Object.getPrototypeOf(p) === G, p.t, Object.getPrototypeOf(q) === G, q.t, r.t, Object.getPrototypeOf(r) === G);\nconsole.log(Object.getPrototypeOf({}) === Object.prototype, Object.getPrototypeOf(Object.create(null)), Object.getPrototypeOf([]) === Array.prototype);\n";
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(
        lines,
        [
            "object true 1 true true",
            "true ktrue",
            "function true default",
            "true 2 true 2 2 true",
            "true null true"
        ]
    );
}

// These traces were checked with an independent V8 execution of these exact
// programs. Each program runs in a fresh native router realm.
fn assert_callable_prototype_trace(source: &str, expected: &[&str]) {
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, expected);
}

#[test]
fn callable_storage_preserves_intrinsic_prototype_chains() {
    assert_callable_prototype_trace(
        r#"
        function ordinary(a) {}
        const closure = function named() {};
        const method = ({ method() {} }).method;
        function* generator() {}
        async function asyncFunction() {}
        async function* asyncGenerator() {}
        const values = [ordinary, closure, method, () => {}, generator, asyncFunction, asyncGenerator, ordinary.bind(null), Array, Promise, Date, TypeError];
        const checks = [];
        for (const value of values) {
            const inherited = Object.create(value);
            checks.push(Object.getPrototypeOf(inherited) === value &&
                inherited.call === Function.prototype.call &&
                inherited.apply === Function.prototype.apply &&
                inherited.bind === Function.prototype.bind &&
                inherited instanceof Function && Reflect.has(inherited, 'call'));
        }
        console.log(checks.join());
        console.log(Object.getPrototypeOf(generator) === Object.getPrototypeOf(function* () {}),
            Object.getPrototypeOf(asyncFunction) === Object.getPrototypeOf(async function () {}),
            Object.getPrototypeOf(asyncGenerator) === Object.getPrototypeOf(async function* () {}));
        Object.defineProperty(Function.prototype, 'sharedValue', {
            get() { return this.tag; }, configurable: true
        });
        const child = Object.create(ordinary);
        child.tag = 'child';
        console.log(child.sharedValue, Reflect.get(child, 'sharedValue', { tag: 'receiver' }));
        "#,
        &[
            "true,true,true,true,true,true,true,true,true,true,true,true",
            "true true true",
            "child receiver",
        ],
    );
}

#[test]
fn function_inherited_descriptors_keep_receivers_and_reject_readonly_writes() {
    assert_callable_prototype_trace(
        r#"
        function target() {}
        const receiver = { value: 0 };
        const log = [];
        Object.defineProperty(Function.prototype, 'feature', {
            get() { return this.value; },
            set(value) { log.push(this === target ? 'target' : 'receiver'); this.value = value; },
            configurable: true
        });
        Object.defineProperty(Function.prototype, 'locked', { value: 7, writable: false, configurable: true });
        target.seed = 1;
        console.log(Reflect.set(target, 'feature', 3), target.feature,
            Reflect.set(target, 'feature', 9, receiver), receiver.value, log.join());
        console.log(Reflect.set(target, 'locked', 8), target.locked,
            Object.prototype.hasOwnProperty.call(target, 'locked'));
        let strictFailure = false;
        try { (function() { 'use strict'; target.locked = 8; })(); }
        catch (error) { strictFailure = error.name === 'TypeError'; }
        console.log(strictFailure, target.locked);
        const inherited = Object.create(target);
        console.log(inherited.feature, Reflect.get(target, 'feature', { value: 12 }));
        "#,
        &[
            "true 3 true 9 target,receiver",
            "false 7 false",
            "true 7",
            "3 12",
        ],
    );
}

#[test]
fn null_and_custom_function_prototypes_are_authoritative() {
    assert_callable_prototype_trace(
        r#"
        function target(a, b) { 'use strict'; }
        const intrinsic = Object.getPrototypeOf(target);
        Object.setPrototypeOf(target, null);
        delete target.name;
        delete target.length;
        const child = Object.create(target);
        console.log(Object.getPrototypeOf(target) === null, target.call, Reflect.get(target, 'bind'),
            'apply' in target, target.name, target.length, Object.getPrototypeOf(child) === target);
        console.log(Reflect.set(target, 'caller', 4), target.caller);
        const parent = {
            name: 'custom', length: 11,
            get answer() { return this.tag; }
        };
        target.tag = 'target';
        Object.setPrototypeOf(target, parent);
        console.log(target.name, target.length, target.answer,
            Reflect.get(target, 'answer', { tag: 'receiver' }), 'bind' in target);
        Object.setPrototypeOf(target, intrinsic);
        console.log(target.name === '', target.length, target.call === Function.prototype.call,
            Reflect.has(target, 'bind'));
        "#,
        &[
            "true undefined undefined false undefined undefined true",
            "true 4",
            "custom 11 target receiver false",
            "true 0 true true",
        ],
    );
}

#[test]
fn derived_constructor_mutations_replace_the_class_definition_parent() {
    assert_callable_prototype_trace(
        r#"
        class First { static feature() { return 'first'; } }
        class Second { static feature() { return 'second'; } }
        class Child extends First {}
        console.log(Object.getPrototypeOf(Child) === First, Child.feature());
        Object.setPrototypeOf(Child, Second);
        delete Child.name;
        console.log(Object.getPrototypeOf(Child) === Second, Child.feature(), Child.name);
        Object.setPrototypeOf(Child, null);
        console.log(Object.getPrototypeOf(Child) === null, Child.feature,
            'feature' in Child, Child.call, Child.name);
        Object.setPrototypeOf(Child, First);
        console.log(Object.getPrototypeOf(Child) === First, Child.feature(), Child.name);
        class ArrayChild extends Array {}
        class ErrorChild extends Error {}
        console.log(Object.getPrototypeOf(ArrayChild) === Array, typeof ArrayChild.from,
            Object.getPrototypeOf(ErrorChild) === Error);
        "#,
        &[
            "true first",
            "true second Second",
            "true undefined false undefined undefined",
            "true first First",
            "true function true",
        ],
    );
}

#[test]
fn function_prototype_mutations_enforce_integrity_and_proxy_boundaries() {
    assert_callable_prototype_trace(
        r#"
        function target() {}
        const parent = Object.getPrototypeOf(target);
        Object.preventExtensions(target);
        let threw = false;
        try { Object.setPrototypeOf(target, {}); }
        catch (error) { threw = error.name === 'TypeError'; }
        console.log(Reflect.setPrototypeOf(target, parent), Reflect.setPrototypeOf(target, {}),
            threw, Object.getPrototypeOf(target) === parent);
        function first() {}
        function second() {}
        Object.setPrototypeOf(first, second);
        console.log(Reflect.setPrototypeOf(second, first), Object.getPrototypeOf(second) === Function.prototype);
        let trapCalls = 0;
        const callable = new Proxy(function() {}, { getPrototypeOf() { trapCalls++; return null; } });
        function throughProxy() {}
        console.log(Reflect.setPrototypeOf(throughProxy, callable),
            Object.getPrototypeOf(throughProxy) === callable, trapCalls);
        const revoked = Proxy.revocable(function() {}, {});
        revoked.revoke();
        function throughRevoked() {}
        console.log(Reflect.setPrototypeOf(throughRevoked, revoked.proxy),
            Object.getPrototypeOf(throughRevoked) === revoked.proxy);
        "#,
        &[
            "true false true true",
            "false true",
            "true true 0",
            "true true",
        ],
    );
}

#[test]
fn proxy_prototype_traps_accept_callable_results_and_enforce_invariants() {
    assert_callable_prototype_trace(
        r#"
        function parent() {}
        function other() {}
        const target = Object.create(parent);
        const proxy = new Proxy(target, { getPrototypeOf() { return parent; } });
        console.log(Object.getPrototypeOf(proxy) === parent);
        Object.preventExtensions(target);
        console.log(Object.getPrototypeOf(proxy) === parent);
        let failed = false;
        const inconsistent = new Proxy(target, { getPrototypeOf() { return other; } });
        try { Reflect.getPrototypeOf(inconsistent); }
        catch (error) { failed = error.name === 'TypeError'; }
        console.log(failed);
        const setter = new Proxy(target, { setPrototypeOf(object, proposed) { return proposed === parent; } });
        console.log(Reflect.setPrototypeOf(setter, parent), Reflect.setPrototypeOf(setter, other));
        "#,
        &["true", "true", "true", "true false"],
    );
}

#[test]
fn arbitrary_native_callable_prototype_identity_is_private_and_immutable() {
    assert_callable_prototype_trace(
        r#"
        const maximum = Math.max;
        const originalKeys = Reflect.ownKeys(maximum).join();
        const child = Object.create(maximum);
        console.log(Object.getPrototypeOf(child) === maximum,
            Reflect.ownKeys(maximum).join() === originalKeys,
            Object.getPrototypeOf(child)(3, 9));
        delete maximum.name;
        delete maximum.length;
        Object.freeze(maximum);
        console.log(Object.getPrototypeOf(child) === maximum,
            Reflect.getPrototypeOf(child) === maximum, Reflect.ownKeys(maximum).length);
        const date = Date;
        const inheritedDate = Object.create(date);
        Date = function replacement() {};
        console.log(Object.getPrototypeOf(inheritedDate) === date);
        "#,
        &["true true 9", "true true 0", "true"],
    );
}

#[test]
fn deleted_function_names_and_lengths_use_the_actual_write_chain() {
    assert_callable_prototype_trace(
        r#"
        function ordinary() {}
        const bound = ordinary.bind(null);
        const values = [ordinary, bound, Math.max];
        const results = [];
        for (const value of values) {
            delete value.name;
            delete value.length;
            const writes = [];
            Object.setPrototypeOf(value, {
                set name(next) { writes.push((this === value) + ':' + next); },
                set length(next) { writes.push((this === value) + ':' + next); }
            });
            value.name = 'updated';
            value.length = 4;
            results.push(writes.join());
            Object.defineProperty(value, 'name', { value: 'first', writable: true });
            value.name = 'second';
            results.push(value.name);
        }
        console.log(results.join('|'));
        function detached() {}
        Object.setPrototypeOf(detached, null);
        const parent = {};
        detached.__proto__ = parent;
        console.log(Object.getPrototypeOf(detached) === null,
            Object.prototype.hasOwnProperty.call(detached, '__proto__'), detached.__proto__ === parent);
        Object.defineProperty(Function.prototype, 'inheritedWrite', {
            set(value) { this.observed = value; }, configurable: true
        });
        Promise.inheritedWrite = 3;
        Date.inheritedWrite = 4;
        console.log(Promise.observed, Date.observed);
        "#,
        &[
            "true:updated,true:4|second|true:updated,true:4|second|true:updated,true:4|second",
            "true true true",
            "3 4",
        ],
    );
}

#[test]
fn dynamic_regexp_own_members_survive_callable_materialization() {
    assert_callable_prototype_trace(
        r#"
        RegExp.marker = 1;
        /(x)/.exec('x');
        console.log(RegExp.$1, Reflect.get(RegExp, 'lastMatch'), '$1' in RegExp);
        Object.setPrototypeOf(RegExp, null);
        /(y)/.exec('y');
        console.log(RegExp.$1, Reflect.get(RegExp, 'lastMatch'), '$1' in RegExp, RegExp.call);
        "#,
        &["x x true", "y y true undefined"],
    );
}

#[test]
fn native_constructor_backings_keep_their_callable_parents() {
    assert_callable_prototype_trace(
        r#"
        TypeError.marker = 1;
        Uint8Array.marker = 1;
        const typed = Object.getPrototypeOf(Uint8Array);
        console.log(Object.getPrototypeOf(TypeError) === Error,
            Object.getPrototypeOf(typed) === Function.prototype,
            typeof Uint8Array.from, TypeError.call === Function.prototype.call);
        console.log(Object.getPrototypeOf(Promise) === Function.prototype,
            Object.getPrototypeOf(Date) === Function.prototype);
        Object.setPrototypeOf(Promise, null);
        Object.setPrototypeOf(Date, null);
        console.log(Promise.call, Date.bind, 'call' in Promise, Reflect.has(Date, 'bind'));
        console.log(typeof Promise.resolve, typeof Date.now);
        "#,
        &[
            "true true function true",
            "true true",
            "undefined undefined false false",
            "function function",
        ],
    );
}
