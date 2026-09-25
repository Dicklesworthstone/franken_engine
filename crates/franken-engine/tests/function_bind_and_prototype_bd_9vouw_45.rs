//! bd-9vouw.45: `Function.prototype` exists, `Function.prototype.bind`
//! creates bound functions, and functions have a [[Prototype]] that
//! `Object.getPrototypeOf` / `Object.setPrototypeOf` can read and change.
//!
//! Before this, `Function.prototype` was `undefined` (so the Test262 harness
//! file propertyHelper.js could not load), `f.bind` was `undefined`, and
//! `Object.setPrototypeOf(Child, Parent)` threw, which crashed TypeScript's
//! ES5 `__extends`. Expected strings are what Node v22.2.0 prints for the
//! same programs.
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
fn bind_fixes_this_and_leading_arguments() {
    check(
        "function f(a, b) { return this.v + a + b; } var g = f.bind({v: 1}, 2); g(3);",
        "6",
    );
    check(
        "var o = {v: 5, get: function () { return this.v; }}; var unbound = o.get; \
         var bound = unbound.bind(o); bound();",
        "5",
    );
    check("var max = Math.max.bind(null, 10); max(3, 4);", "10");
}

#[test]
fn function_prototype_methods_are_values() {
    check(
        "typeof Function.prototype.call + ':' + typeof Function.prototype.bind;",
        "function:function",
    );
    // The propertyHelper.js idiom that gated the Test262 harness.
    check(
        "var join = Function.prototype.call.bind(Array.prototype.join); join([1, 2], '-');",
        "1-2",
    );
    check(
        "var hasOwn = Function.prototype.call.bind(Object.prototype.hasOwnProperty); \
         hasOwn({a: 1}, 'a') + ':' + hasOwn({a: 1}, 'b');",
        "true:false",
    );
}

#[test]
fn functions_have_a_prototype_chain() {
    check(
        "class A {} class B extends A {} \
         (Object.getPrototypeOf(B) === A) + ':' + (Object.getPrototypeOf(A) === Function.prototype);",
        "true:true",
    );
    check(
        "function P() {} P.s = function () { return 'static'; }; function C() {} \
         Object.setPrototypeOf(C, P); C.s() + ':' + (Object.getPrototypeOf(C) === P);",
        "static:true",
    );
}

#[test]
fn typescript_es5_extends_helper_runs() {
    check(
        r#"var __extends = (this && this.__extends) || (function () {
    var extendStatics = function (d, b) {
        extendStatics = Object.setPrototypeOf ||
            ({ __proto__: [] } instanceof Array && function (d, b) { d.__proto__ = b; }) ||
            function (d, b) { for (var p in b) if (Object.prototype.hasOwnProperty.call(b, p)) d[p] = b[p]; };
        return extendStatics(d, b);
    };
    return function (d, b) {
        if (typeof b !== "function" && b !== null)
            throw new TypeError("Class extends value " + String(b) + " is not a constructor or null");
        extendStatics(d, b);
        function __() { this.constructor = d; }
        d.prototype = b === null ? Object.create(b) : (__.prototype = b.prototype, new __());
    };
})();
var Animal = (function () {
    function Animal(name) { this.name = name; }
    Animal.create = function (n) { return new this(n); };
    Animal.prototype.speak = function () { return this.name + " makes a sound"; };
    return Animal;
}());
var Dog = (function (_super) {
    __extends(Dog, _super);
    function Dog(name) { return _super.call(this, name) || this; }
    Dog.prototype.speak = function () { return this.name + " barks; " + _super.prototype.speak.call(this); };
    return Dog;
}(Animal));
var d = new Dog("Rex");
d.speak() + " " + (d instanceof Animal) + " " + Dog.create("Ace").speak();"#,
        "Rex barks; Rex makes a sound true Ace barks; Ace makes a sound",
    );
}

/// bd-9vouw.32: `new` on a bound function constructs the target with the
/// bound arguments (the bound `this` is ignored), `instanceof` looks through
/// the binding, and `name` / `length` follow ES2020 19.2.3.2.
#[test]
fn bound_functions_construct_and_report_name_and_length() {
    check(
        "function P(x, y) { this.x = x; this.y = y; } var B = P.bind({ignored: true}, 1); \
         var b = new B(2); [b.x, b.y, b instanceof P, b instanceof B, b.ignored].join()",
        "1,2,true,true,",
    );
    check(
        "class K { constructor(a, b) { this.s = a + b; } } var BK = K.bind(null, 10); \
         [new BK(5).s, new BK(5) instanceof K].join()",
        "15,true",
    );
    check(
        "var arrow = () => 1; var BA = arrow.bind(null); var r; \
         try { new BA(); r = 'constructed'; } catch (e) { r = e instanceof TypeError; } r",
        "true",
    );
    check(
        "function f(a, b, c) {} var g = f.bind(null, 1); [g.name, g.length, \
         f.bind(null, 1, 2, 3, 4).length, g.bind(null, 2).name, g.bind(null, 2).length].join()",
        "bound f,2,0,bound bound f,1",
    );
    check(
        "var named = function named(a) {}; [named.bind(null).name, Math.max.bind(null).name].join()",
        "bound named,bound max",
    );
}
