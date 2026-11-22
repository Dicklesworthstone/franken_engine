//! bd-9vouw.45: `Function.prototype` exists, `Function.prototype.bind`
//! creates bound functions, and functions have a [[Prototype]] that
//! `Object.getPrototypeOf` / `Object.setPrototypeOf` can read and change.
//!
//! Before this, `Function.prototype` was `undefined` (so the Test262 harness
//! file propertyHelper.js could not load), `f.bind` was `undefined`, and
//! `Object.setPrototypeOf(Child, Parent)` threw, which crashed TypeScript's
//! ES5 `__extends`. Original expectations were captured from Node v22.2.0;
//! the later prototype-capture probes were checked separately in reference V8.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, expected: &str) {
    assert_eq!(
        eval_to_string(source),
        expected,
        "unexpected observable behavior for `{source}`"
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

/// bd-9vouw.268: four built-in conformance gaps. `trim` and its variants
/// remove ES WhiteSpace and LineTerminator (U+FEFF yes, U+0085 and U+180E
/// no) over exact code units; `Object.prototype.valueOf` is ToObject(this);
/// `Date.prototype.toJSON` is generic (ToPrimitive with hint "number", null
/// when non-finite, then Invoke(O, "toISOString")); and
/// `Function.prototype[Symbol.hasInstance]` exists (OrdinaryHasInstance,
/// not writable, enumerable or configurable), which `instanceof` performs
/// without a guest call. Expected lines are Node v22.2.0's output, captured
/// programmatically; Bun 1.4.2 agrees except that it throws for
/// `{} instanceof Object.create(Function.prototype)`, where OrdinaryHasInstance
/// step 1 answers false.
#[test]
fn builtin_prototype_conformance_bd_9vouw_268() {
    let source = r#"function kind(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var bom = '﻿';
console.log(JSON.stringify([(bom + ' a' + bom).trim(), (bom + 'a ').trimStart(), (' a' + bom).trimEnd(), '\u0085a\u0085'.trim().length, '᠎a'.trim().length, ('\uD800' + bom).trim().length, (bom + '\uDC00 ').trim().length]));
var valueOf = Object.prototype.valueOf;
console.log(typeof valueOf.call(true), typeof valueOf.call(1), typeof valueOf.call('s'), typeof valueOf.call(Symbol()), valueOf.call(2) instanceof Number, kind(function () { return valueOf.call(undefined); }), kind(function () { return valueOf.call(null); }), kind(function () { return (0, Object.prototype.valueOf)(); }));
var toJSON = Date.prototype.toJSON;
var result = {};
var calls = [];
var custom = { toISOString: function () { calls.push('iso'); return result; }, valueOf: function () { calls.push('valueOf'); return 'NaN'; } };
console.log(toJSON.call(custom) === result, calls.join(), toJSON.call({ valueOf: function () { return Infinity; }, toISOString: function () { return 'no'; } }), new Date(0).toJSON(), new Date(NaN).toJSON());
Number.prototype.toISOString = function () { return 'num:' + typeof this; };
console.log(toJSON.call(10), kind(function () { return toJSON.call(undefined); }), kind(function () { return toJSON.call({ toISOString: 1 }); }), kind(function () { return toJSON.call({ valueOf: function () { throw new RangeError('v'); } }); }), JSON.stringify({ d: new Date(0), o: custom }));
delete Number.prototype.toISOString;
var hasInstance = Function.prototype[Symbol.hasInstance];
var d = Object.getOwnPropertyDescriptor(Function.prototype, Symbol.hasInstance);
console.log(typeof hasInstance, hasInstance.name, hasInstance.length, d.writable, d.enumerable, d.configurable);
function F() {}
var f = new F();
var bound = F.bind();
console.log(hasInstance.call(F, f), hasInstance.call(F, {}), hasInstance.call({}, f), hasInstance.call(F, 1), bound[Symbol.hasInstance](f), F[Symbol.hasInstance](f), f instanceof F, f instanceof bound);
console.log(kind(function () { return {} instanceof Object.create(Function.prototype); }), kind(function () { return {} instanceof {}; }));
class WithStatic { static helper() {} }
console.log(new WithStatic() instanceof WithStatic, {} instanceof WithStatic, Reflect.ownKeys(Function.prototype).indexOf(Symbol.hasInstance) >= 0);
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
            "[\"a\",\"a \",\" a\",3,2,1,1]",
            "object object object object true TypeError TypeError TypeError",
            "true valueOf,iso null 1970-01-01T00:00:00.000Z null",
            "num:object TypeError TypeError RangeError {\"d\":\"1970-01-01T00:00:00.000Z\",\"o\":{}}",
            "function [Symbol.hasInstance] 1 false false false",
            "true false false false true true true true",
            "false TypeError",
            "true false true",
        ]
    );
}

// ES2020 BoundFunctionCreate observes and captures [[Prototype]] before
// reading the target's length/name. These exact programs were checked in V8.
#[test]
fn bind_captures_custom_and_null_prototypes() {
    check(
        r#"
const bind = Function.prototype.bind;
const first = {marker: 'first', get receiver() { return this; }};
const second = {marker: 'second'};
function Target(a, b) { return this.value + a + b; }
Object.setPrototypeOf(Target, first);
const bound = Reflect.apply(bind, Target, [{value: 10}, 2]);
Object.setPrototypeOf(Target, second);
const rebound = Reflect.apply(bind, bound, [null, 3]);
function NullTarget(x) { return x + 1; }
Object.setPrototypeOf(NullTarget, null);
const nullBound = Reflect.apply(bind, NullTarget, [null, 4]);
[Object.getPrototypeOf(bound) === first, bound.marker, bound.receiver === bound,
 Object.getPrototypeOf(rebound) === first, rebound(), bound.length, bound.name,
 Object.getPrototypeOf(nullBound) === null, nullBound(), nullBound.call === undefined].join(' ');
"#,
        "true first true true 15 1 bound Target true 5 true",
    );
}

#[test]
fn bind_observes_proxy_prototype_before_metadata() {
    check(
        r#"
const events = [], proto = {marker: 'captured'};
function Target(a, b) { return a + b; }
const handler = {
 getPrototypeOf(target) { events.push('proto:' + (this === handler) + ':' + (target === Target)); return proto; },
 getOwnPropertyDescriptor(target, key) { events.push('own:' + key); return Reflect.getOwnPropertyDescriptor(target, key); },
 get(target, key, receiver) { events.push('get:' + key); return Reflect.get(target, key, receiver); }
};
const proxy = new Proxy(Target, handler);
const bound = Function.prototype.bind.call(proxy, null, 4);
[events.join(','), Object.getPrototypeOf(bound) === proto, bound.marker,
 bound(5), bound.length, bound.name].join(' ');
"#,
        "proto:true:true,own:length,get:length,get:name true captured 9 1 bound Target",
    );
}

#[test]
fn bind_prototype_capture_precedes_metadata_side_effects() {
    check(
        r#"
const first = {marker: 'first'}, second = {marker: 'second'}, events = [];
function Target() {}
Object.setPrototypeOf(Target, first);
Object.defineProperty(Target, 'length', {
 get() { events.push('length'); Object.setPrototypeOf(Target, second); return 3; }
});
Object.defineProperty(Target, 'name', {get() { events.push('name'); return 'Renamed'; }});
const bound = Function.prototype.bind.call(Target, null, 1);
[Object.getPrototypeOf(bound) === first, Object.getPrototypeOf(Target) === second,
 bound.marker, bound.length, bound.name, events.join(',')].join(' ');
"#,
        "true true first 2 bound Renamed length,name",
    );
}

#[test]
fn bind_prototype_errors_short_circuit_metadata() {
    check(
        r#"
const bind = Function.prototype.bind, sentinel = {}, events = [];
function Target() {}
const throwing = new Proxy(Target, {
 getPrototypeOf() { events.push('proto'); throw sentinel; },
 getOwnPropertyDescriptor() { events.push('descriptor'); return undefined; },
 get() { events.push('get'); return 0; }
});
let caught;
try { bind.call(throwing); } catch (error) { caught = error === sentinel; }
const invalid = new Proxy(Target, {
 getPrototypeOf() { events.push('invalid'); return 1; },
 getOwnPropertyDescriptor() { events.push('descriptor'); return undefined; }
});
let invalidType = false;
try { bind.call(invalid); } catch (error) { invalidType = error instanceof TypeError; }
const revoked = Proxy.revocable(Target, {});
revoked.revoke();
let revokedType = false;
try { bind.call(revoked.proxy); } catch (error) { revokedType = error instanceof TypeError; }
const noncallable = new Proxy({}, {getPrototypeOf() { events.push('noncallable'); return null; }});
let callableType = false;
try { bind.call(noncallable); } catch (error) { callableType = error instanceof TypeError; }
[caught, invalidType, revokedType, callableType, events.join(',')].join(' ');
"#,
        "true true true true proto,invalid",
    );
}

#[test]
fn bind_preserves_function_kind_prototypes_and_construction() {
    check(
        r#"
function* generator(value) { yield value; }
async function asyncFunction() { return 1; }
async function* asyncGenerator() { yield 2; }
const boundGenerator = generator.bind(null, 7);
const kinds = [generator, asyncFunction, asyncGenerator].map(function(target) {
 const bound = target.bind(null);
 return Object.getPrototypeOf(bound) === Object.getPrototypeOf(target);
});
class Parent { static inherited() { return 11; } }
class Child extends Parent { constructor(value) { super(); this.value = value; this.target = new.target; } }
const Bound = Child.bind(null, 8);
const instance = new Bound();
[kinds.join(','), boundGenerator().next().value, Object.getPrototypeOf(Bound) === Parent,
 Bound.inherited(), instance.value, instance.target === Child, instance instanceof Child,
 Object.prototype.hasOwnProperty.call(Bound, 'prototype')].join(' ');
"#,
        "true,true,true 7 true 11 8 true true false",
    );
}

#[test]
fn bind_proxy_callable_prototype_identity_and_invariants() {
    check(
        r#"
function Prototype() {}
Prototype.marker = 'callable';
function Target() {}
const proxy = new Proxy(Target, {getPrototypeOf() { return Prototype; }});
const bound = Function.prototype.bind.call(proxy);
const nullProxy = new Proxy(Target, {getPrototypeOf() { return null; }});
const nullBound = Function.prototype.bind.call(nullProxy);
const original = Object.getPrototypeOf(Target), events = [];
Object.preventExtensions(Target);
const good = new Proxy(Target, {getPrototypeOf() { events.push('good'); return original; }});
const goodBound = Function.prototype.bind.call(good);
const bad = new Proxy(Target, {
 getPrototypeOf() { events.push('bad'); return Prototype; },
 getOwnPropertyDescriptor() { events.push('descriptor'); return undefined; }
});
let rejected = false;
try { Function.prototype.bind.call(bad); } catch (error) { rejected = error instanceof TypeError; }
[Object.getPrototypeOf(bound) === Prototype, bound.marker,
 Object.getPrototypeOf(nullBound) === null, Object.getPrototypeOf(goodBound) === original,
 rejected, events.join(',')].join(' ');
"#,
        "true callable true true true good,bad",
    );
}

#[test]
fn bind_retains_prototype_observations_and_restores_caller_context() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ifc_artifacts::Label;
    use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let cases = [
        (
            "proxy_prototype_selection",
            r#"
const choice = '__bind_input__';
const prototype = {};
const target = new Proxy(function Target() {}, {
    getPrototypeOf() { return choice ? prototype : null; }
});
const bound = Function.prototype.bind.call(target);
Object.getPrototypeOf(bound) === prototype;
"#,
            Value::Bool(true),
            true,
        ),
        (
            "stored_prototype_selection",
            r#"
const choice = '__bind_input__', prototype = {};
function Target() {}
Object.setPrototypeOf(Target, choice ? prototype : null);
const bound = Function.prototype.bind.call(Target);
Object.getPrototypeOf(bound) === prototype;
"#,
            Value::Bool(true),
            true,
        ),
        (
            "length_getter_before_public_name",
            r#"
const choice = '__bind_input__';
function Target() {}
Object.defineProperty(Target, 'length', { get() { return choice ? 3 : 0; } });
Object.defineProperty(Target, 'name', { get() { return 'public'; } });
Function.prototype.bind.call(Target).length;
"#,
            Value::Int(3),
            true,
        ),
        (
            "own_length_trap_before_public_metadata",
            r#"
const choice = '__bind_input__';
function Target(a, b) {}
const target = new Proxy(Target, {
    getOwnPropertyDescriptor(object, key) {
        return choice ? Reflect.getOwnPropertyDescriptor(object, key) : undefined;
    }
});
Function.prototype.bind.call(target).length;
"#,
            Value::Int(2),
            true,
        ),
        (
            "prototype_trap_throw",
            r#"
const choice = '__bind_input__';
const target = new Proxy(function Target() {}, {
    getPrototypeOf() {
        if (choice) throw new RangeError('prototype');
        return null;
    }
});
let caught = false;
try { Function.prototype.bind.call(target); }
catch (error) { caught = error instanceof RangeError; }
caught;
"#,
            Value::Bool(true),
            true,
        ),
        (
            "successful_bind_restores_context",
            r#"
const choice = '__bind_input__';
const target = new Proxy(function Target() {}, {
    getPrototypeOf() { return choice ? {} : null; }
});
Function.prototype.bind.call(target);
17;
"#,
            Value::Int(17),
            false,
        ),
    ];

    for (name, source, expected, retains_input_label) in cases {
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: format!("{name}.js"),
                    text: source.into(),
                },
                ParseGoal::Script,
                &ParserOptions::default(),
            )
            .unwrap_or_else(|error| panic!("{name} parses: {error}"));
        let mut module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, format!("{name}.js")),
            &LoweringContext::new(name, "bound-prototype-observation", "builtin-only"),
        )
        .unwrap_or_else(|error| panic!("{name} lowers: {error}"))
        .ir3;
        let mut patched = 0;
        for instruction in &mut module.instructions {
            if let Ir3Instruction::LoadStr { dst, pool_index } = *instruction
                && module.constant_pool[pool_index as usize].as_str() == Some("__bind_input__")
            {
                *instruction = Ir3Instruction::Move { dst, src: 255 };
                patched += 1;
            }
        }
        assert_eq!(patched, 1, "{name}: exactly one labelled input");
        for v8 in [false, true] {
            for stress in [None, Some(7)] {
                for label in [Label::Public, Label::Secret] {
                    let mut config = if v8 {
                        InterpreterConfig::v8_defaults()
                    } else {
                        InterpreterConfig::quickjs_defaults()
                    };
                    config.granted_capabilities = [
                        RuntimeCapability::VmDispatch,
                        RuntimeCapability::HeapAllocate,
                        RuntimeCapability::Builtin,
                    ]
                    .into_iter()
                    .collect();
                    let mut core = InterpreterCore::new(config, name);
                    core.seed_register(255, Value::Bool(true)).unwrap();
                    core.set_register_label(255, label.clone()).unwrap();
                    core.set_gc_stress_interval(stress);
                    let outcome = core.execute(&module).unwrap_or_else(|error| {
                        panic!("{name}: profile={v8}, GC={stress:?}, label={label:?}: {error}")
                    });
                    assert_eq!(outcome.value, expected, "{name}: result");
                    assert_eq!(
                        outcome.completion_label,
                        if retains_input_label {
                            label
                        } else {
                            Label::Public
                        },
                        "{name}: profile={v8}, GC={stress:?}"
                    );
                    assert_eq!(
                        core.estimated_memory_bytes(),
                        core.recompute_estimated_memory_bytes(),
                        "{name}: retained observation or bound backing accounting drift"
                    );
                }
            }
        }
    }
}
