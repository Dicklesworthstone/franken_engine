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

/// A plain call's `this` is undefined (strict code; ES2020 9.2.1.2): a
/// function called without a receiver inside a method used to inherit the
/// method's `this`, so the factory idiom `if (!(this instanceof F)) return
/// new F(v)` ran its body on the caller's receiver and returned undefined
/// (currency.js' `add`), and `g()` in a method saw the method's object. An
/// arrow keeps its lexical `this`; callbacks get their thisArg.
#[test]
fn plain_calls_inside_methods_do_not_inherit_this() {
    check(
        "'use strict'; function F(v) { if (!(this instanceof F)) return new F(v); this.v = v; } \
         F.prototype.add = function (n) { return F(this.v + n); }; function g() { return this; } \
         const o = { m() { return [g() === undefined, (0, g)() === undefined, \
         [1].map(function () { return this; })[0] === undefined, (() => this)() === o].join(); }, \
         n: function () { const self = this; return (function () { return this === undefined && self === o; })(); } }; \
         class C { m() { return g() === undefined; } static s() { return g() === undefined; } } \
         [F(1).add(2).v, o.m(), o.n(), new C().m(), C.s()].join(' ')",
        "3 true,true,true,true true true true",
    );
}

/// bd-9vouw.263: `Function.prototype.bind` reads the target's `length` and
/// `name` when it binds (ES2024 20.2.3.2 steps 4-10): HasOwnProperty, then
/// [[Get]], so getters and proxy traps run then (a throwing `name` getter
/// throws from `bind`), later changes to the target do not reach the bound
/// function, and a Number length keeps its value (2147483648, Infinity,
/// 2.7 -> 2). `Reflect.construct(bound, args, F)` constructs the target with
/// newTarget F, or with the target when F is the bound function itself
/// (10.4.1.2 step 5). The name and length were computed from the live
/// target through engine-internal reads, and a bound function with an
/// explicit newTarget was called rather than constructed. Expected lines
/// are Node v22.2.0's output, captured programmatically; Bun 1.4.2 agrees.
#[test]
fn bind_reads_target_length_and_name_at_bind_time_bd_9vouw_263() {
    let source = r#"function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var target = Object.defineProperty(function () {}, 'name', { value: 'target' });
var bt = target.bind();
Object.defineProperty(target, 'name', { value: 'changed' });
var d = Object.getOwnPropertyDescriptor(bt, 'name');
console.log(bt.name, d.writable, d.enumerable, d.configurable, target.bind().bind().name);
var thrower = Object.defineProperty(function () {}, 'name', { get: function () { throw new RangeError('n'); } });
var symbolNamed = Object.defineProperty(function () {}, 'name', { value: Symbol('s') });
console.log(attempt(function () { return thrower.bind(); }), JSON.stringify(symbolNamed.bind().name), JSON.stringify((function () {}).bind().name));
function f() {}
var lengths = [2147483648, Infinity, -Infinity, NaN, 2.7, -0.5, '3'].map(function (value) {
  Object.defineProperty(f, 'length', { value: value });
  return String(f.bind().length) + '/' + String(f.bind(0, 0).length);
});
console.log(lengths.join(' '));
function g(a, b, c) {}
var beforeDelete = g.bind(null, 1).length;
delete g.length;
console.log(beforeDelete, g.bind().length, Math.max.bind(null, 1).length, Math.max.bind().name);
var order = [];
var proxy = new Proxy(function (a, b) {}, {
  getOwnPropertyDescriptor: function (t, k) { order.push('gopd:' + String(k)); return Reflect.getOwnPropertyDescriptor(t, k); },
  get: function (t, k) { order.push('get:' + String(k)); return Reflect.get(t, k); }
});
console.log(Function.prototype.bind.call(proxy).length, order.join(','));
var newTarget;
function A() { newTarget = new.target; }
function Other() {}
var B = A.bind();
var C = B.bind();
var viaA = Reflect.construct(C, [], A);
var sameA = newTarget === A;
var viaC = Reflect.construct(C, [], C);
var sameC = newTarget === A;
var viaOther = Reflect.construct(B, [], Other);
console.log(sameA, Object.getPrototypeOf(viaA) === A.prototype, sameC, Object.getPrototypeOf(viaC) === A.prototype, newTarget === Other, Object.getPrototypeOf(viaOther) === Other.prototype, new C() instanceof A);
"#;
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
            "bound target false false true bound bound changed",
            "RangeError \"bound \" \"bound \"",
            "2147483648/2147483647 Infinity/Infinity 0/0 0/0 2/1 0/0 0/0",
            "2 0 1 bound max",
            "2 gopd:length,get:length,get:name",
            "true true true true true true true",
        ]
    );
}
