//! bd-9vouw.35: class methods may be async, generators, async generators and
//! may have computed keys (ES2020 14.6 ClassElement: MethodDefinition).
//!
//! Before this, `async m(){}` installed a method named "async m", `*g(){}`
//! one named "*g", and a computed key `[expr](){}` was replaced by a fixed
//! static key, so `[Symbol.iterator]()` never became iterable. Expected
//! strings are what Node v22.2.0 prints for the same programs.
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
fn async_methods_return_promises() {
    check(
        "class C { async m() { return 1; } } var c = new C(); typeof c.m + ':' + typeof c.m().then;",
        "function:function",
    );
    check(
        "class C { static async m() { return 2; } } typeof C.m().then;",
        "function",
    );
    check(
        "class C { async *ag() { yield 1; } } typeof new C().ag().next;",
        "function",
    );
}

#[test]
fn generator_methods_yield() {
    check(
        "class C { *g() { yield 1; yield 2; } } [...new C().g()].join();",
        "1,2",
    );
    check(
        "class C { static *g() { yield 3; } } C.g().next().value;",
        "3",
    );
}

#[test]
fn computed_keys_define_under_their_value() {
    check(
        "class C { *[Symbol.iterator]() { yield 1; yield 2; } } [...new C()].join();",
        "1,2",
    );
    check(
        "var k = 'dyn'; class C { [k + 'M']() { return 5; } static ['s' + 1]() { return 6; } } \
         new C().dynM() + C.s1();",
        "11",
    );
    // A computed key may itself contain a call's parentheses.
    check(
        "function key() { return 'viaCall'; } class C { [key()]() { return 7; } } new C().viaCall();",
        "7",
    );
    check(
        "var C = class { *['g' + 1]() { yield 9; } }; new C().g1().next().value;",
        "9",
    );
    // Keys are evaluated once each, in class-element order.
    check(
        "var order = []; function k(n) { order.push(n); return 'm' + n; } \
         class C { [k(1)]() {} static [k(2)]() {} [k(3)]() {} } order.join();",
        "1,2,3",
    );
    // SetFunctionName uses the computed key, `[description]` for Symbols.
    check(
        "var k = 'x'; class D { [k]() {} [Symbol.iterator]() {} } \
         D.prototype.x.name + '|' + D.prototype[Symbol.iterator].name;",
        "x|[Symbol.iterator]",
    );
}

#[test]
fn modifier_names_stay_ordinary_method_names() {
    check(
        "class C { async() { return 'a'; } get get() { return 'g'; } } var c = new C(); \
         c.async() + c.get;",
        "ag",
    );
}

/// Minified code writes the element name right after a modifier:
/// lru-cache's `async#K(t, e = {}) { let i = await this.#q(t, e); ... }` was
/// read as a method named `async#K`, so its `await` was rejected. `static=4`
/// and `async=5` stay instance fields named `static` and `async`.
#[test]
fn modifiers_without_whitespace_before_the_name() {
    check(
        "class C{static#p=1;static*g(){yield C.#p}async#k(x){return await x}\
         run(){return this.#k(2)}static['s'+1](){return 's'}async['a'](){return 'a'}\
         static async*ag(){yield 3}static=4;async=5} const c=new C(); \
         [[...C.g()].join(), c.run() instanceof Promise, c.a() instanceof Promise, \
         typeof C.ag().next, C.s1(), c.static, c.async, Object.keys(c).join()].join(' ');",
        "1 true true function s 4 5 static,async",
    );
    // The same forms in an object literal were "invalid object shorthand
    // property".
    check(
        "const k = 'z'; const o = {async*g(){yield 1}, async[k](){return 2}, \
         get['b'](){return 3}, set['c'](v){this._c=v}, get\"q\"(){return 'q'}}; o.c = 7; \
         [typeof o.g().next, o.z() instanceof Promise, o.b, o._c, o.q].join(' ');",
        "function true 3 7 q",
    );
}

/// `get` / `set` directly followed by `(` name an ordinary method (Map-like
/// classes such as lru-cache). They used to become accessors with an empty
/// name, so `new Cache().get(k)` threw "expected function, got undefined".
#[test]
fn methods_named_get_and_set_are_methods() {
    check(
        "class Cache { constructor() { this.m = new Map(); } get(k) { return this.m.get(k); } \
         set(k, v) { this.m.set(k, v); return this; } static get() { return 'S'; } \
         static set(v) { return v * 2; } } \
         const c = new Cache().set('a', 1).set('b', 2); \
         [c.get('a'), c.get('b'), Cache.get(), Cache.set(21), \
         Object.getOwnPropertyNames(Cache.prototype).join(), \
         typeof Object.getOwnPropertyDescriptor(Cache.prototype, 'get').value].join(' ');",
        "1 2 S 42 constructor,get,set function",
    );
    // Accessors keep working, including across a line break and for names
    // that merely start with `get` / `set`.
    check(
        "class D { get\nx() { return 'gx'; } set$(v) { return 'd' + v; } \
         get $() { return 'dollar'; } set y(v) { this._y = v; } } \
         const d = new D(); d.y = 5; [d.x, d.set$(1), d.$, d._y].join(' ');",
        "gx d1 dollar 5",
    );
}

/// Text after a class expression's body is a suffix of that expression:
/// `class A {}.name` is "A" and `class { m() {} }.prototype.m()` calls the
/// method. The class-expression parse took the body and dropped the rest,
/// so each of these evaluated to the class itself.
#[test]
fn member_access_and_calls_after_a_class_expression() {
    check(
        "var n = class A {}.name; var x = class { static y = 5 }.y; \
         [n, class {}.name === '', typeof class {}.prototype, x, \
         class { m() { return 1 } }.prototype.m(), class B extends Array {}.name, \
         new (class { constructor() { this.v = 2 } })().v].join(' ');",
        "A true object 5 1 B 2",
    );
}
