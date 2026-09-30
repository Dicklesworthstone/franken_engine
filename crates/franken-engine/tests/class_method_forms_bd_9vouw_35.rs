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
