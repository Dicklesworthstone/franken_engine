//! bd-9vouw.17 (first slice): functions are objects and hold own properties.
//!
//! Before this change every write of a non-`prototype` property to a user
//! function value (`F.x = 1`, class `static` members, Test262's own
//! `Test262Error.thrower = ...` in harness/sta.js) failed with
//! "type error: expected object, got function", so no harness-based Test262
//! test could run. Expected strings are what Node v22.2.0 prints for the same
//! programs.
//!
//! No mocks: real source through parse -> IR0->IR3 lowering -> QuickJsLane.

use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::HybridRouter;
use frankenengine_engine::baseline_interpreter::QuickJsLane;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;

fn eval_to_string(source: &str) -> String {
    let tree = parse_script(source).expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "function_own_properties_bd_9vouw_17.js");
    let context = LoweringContext::new("fop-trace", "fop-decision", "fop-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    match QuickJsLane::new().execute(&module, "fop-trace") {
        Ok(result) => result.value.to_string(),
        Err(err) => format!("ERROR: {err}"),
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
fn declared_function_holds_own_properties() {
    check("function F() {} F.x = 1; F.x;", "1");
    check("function F() {} F.x = 1; F.x = F.x + 41; F.x;", "42");
    check("function F() {} F.missing;", "undefined");
}

#[test]
fn function_expression_and_arrow_hold_own_properties() {
    check("const g = function () {}; g.tag = 'k'; g.tag;", "k");
    check("const h = () => 1; h.meta = 7; h.meta + h();", "8");
}

#[test]
fn distinct_function_objects_have_distinct_properties() {
    // Two closures created from the same function source are distinct objects.
    check(
        "function mk() { return function () {}; } const a = mk(); const b = mk(); a.x = 1; b.x;",
        "undefined",
    );
    check(
        "function mk() { return function () {}; } const a = mk(); const b = mk(); a.x = 1; b.x = 2; a.x;",
        "1",
    );
}

#[test]
fn function_valued_property_is_callable_as_a_method() {
    // The Test262 sta.js shape: a static helper that throws an instance.
    check(
        "function E(m) { this.message = m; } \
         E.thrower = function (m) { throw new E(m); }; \
         let r; try { E.thrower('boom'); } catch (e) { r = (e instanceof E) + ':' + e.message; } r;",
        "true:boom",
    );
}

#[test]
fn class_static_members_install_on_the_constructor() {
    check("class C { static s() { return 3; } } C.s();", "3");
    check("class C { static get v() { return 5; } } C.v;", "5");
    check(
        "class C { static make() { return new C(); } hi() { return 'hi'; } } C.make().hi();",
        "hi",
    );
}

#[test]
fn functions_expose_name_and_length() {
    check(
        "function foo(a, b) {} foo.length + ':' + foo.name;",
        "2:foo",
    );
    check("function rest(a, ...more) {} rest.length;", "1");
    // `name` / `length` are non-writable: a sloppy assignment is ignored.
    check("function F() {} F.length = 5; F.length;", "0");
    check("function F() {} F.name = 'x'; F.name;", "F");
}

#[test]
fn prototype_path_is_unchanged() {
    check(
        "function F() {} F.prototype.m = function () { return 7; }; F.x = 1; new F().m() + F.x;",
        "8",
    );
    // An own property on the function is not visible on instances.
    check("function F() {} F.x = 1; new F().x;", "undefined");
}

// Second slice: own-property reflection on function values. Before it,
// `Object.getOwnPropertyDescriptor(fn, 'length')` was undefined, `delete`,
// `Object.defineProperty` and `Object.defineProperties` on a function threw
// "expected object", `Object.keys` / `getOwnPropertyNames` of a function were
// empty, and built-in functions (`Math.max`, `[].push`, ...) had no `length`
// or `name` at all and refused own properties.

/// The public eval path (built-ins granted), as the other bd-9vouw.17 suites.
fn router_check(source: &str, node: &str) {
    let got = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(got, node, "`{source}` must match Node v22.2.0");
}

/// Console lines of a real `frankenctl run` (for `console.log` formatting).
fn frankenctl_console(source: &str) -> Vec<String> {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fe_fnprops17_{}_{nonce}", std::process::id()));
    fs::create_dir_all(&dir).expect("scratch dir");
    let input = dir.join("program.js");
    let report = dir.join("report.json");
    fs::write(&input, source).expect("program");
    let output = Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args([
            "run",
            "--input",
            input.to_str().expect("utf8"),
            "--extension-id",
            "fnprops17",
            "--out",
            report.to_str().expect("utf8"),
        ])
        .output()
        .expect("frankenctl should execute");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&report).expect("report")).expect("json");
    report["console_output"]
        .as_array()
        .expect("console")
        .iter()
        .map(|entry| entry["message"].as_str().expect("message").to_string())
        .collect()
}

#[test]
fn function_length_and_name_have_standard_descriptors() {
    router_check(
        "function foo(a, b) {} JSON.stringify(Object.getOwnPropertyDescriptor(foo, 'length'));",
        r#"{"value":2,"writable":false,"enumerable":false,"configurable":true}"#,
    );
    router_check(
        "function foo(a, b) {} JSON.stringify(Object.getOwnPropertyDescriptor(foo, 'name'));",
        r#"{"value":"foo","writable":false,"enumerable":false,"configurable":true}"#,
    );
    router_check(
        "function f(a, b, c) {} var g = f.bind(null, 1); \
         g.length + ':' + g.name + ':' + JSON.stringify(Object.getOwnPropertyDescriptor(g, 'length'));",
        r#"2:bound f:{"value":2,"writable":false,"enumerable":false,"configurable":true}"#,
    );
}

#[test]
fn function_own_properties_can_be_deleted() {
    // `length` and `name` are configurable; once deleted, the inherited
    // Function.prototype values (0 and "") show through.
    router_check(
        "function foo(a, b) {} var d = delete foo.length; \
         d + ':' + foo.hasOwnProperty('length') + ':' + foo.length;",
        "true:false:0",
    );
    router_check(
        "function foo() {} delete foo.name; JSON.stringify(foo.name) + ':' + foo.hasOwnProperty('name');",
        r#""":false"#,
    );
    router_check(
        "function F() {} F.x = 1; var d = delete F.x; d + ':' + F.x;",
        "true:undefined",
    );
}

#[test]
fn function_own_property_names_and_keys() {
    router_check(
        "'use strict'; function f() {} f.x = 1; Object.getOwnPropertyNames(f).join();",
        "length,name,prototype,x",
    );
    router_check(
        "class C {} C.x = 1; Object.getOwnPropertyNames(C).join();",
        "length,name,prototype,x",
    );
    // Arrow functions have no `prototype`.
    router_check(
        "var f = (a) => a; f.x = 1; Object.getOwnPropertyNames(f).join();",
        "length,name,x",
    );
    router_check(
        "function F() {} F.x = 1; F.y = 2; Object.keys(F).join();",
        "x,y",
    );
}

#[test]
fn define_property_on_functions() {
    router_check(
        "function F() {} Object.defineProperty(F, 'answer', { value: 42 }); \
         F.answer + ':' + Object.keys(F).length + ':' + F.propertyIsEnumerable('answer');",
        "42:0:false",
    );
    router_check(
        "function F() {} Object.defineProperties(F, { a: { value: 1, enumerable: true }, b: { value: 2 } }); \
         Object.keys(F).join() + ':' + F.b;",
        "a:2",
    );
    router_check(
        "function F() {} Object.defineProperty(F, 'name', { value: 'G' }); F.name;",
        "G",
    );
    // Babel >= 7.16 `_createClass` ends with this call.
    router_check(
        "function C() { this.v = 1; } C.prototype.m = function () { return this.v; }; \
         Object.defineProperty(C, 'prototype', { writable: false }); \
         (new C() instanceof C) + ':' + new C().m();",
        "true:1",
    );
    router_check(
        "class A { static name() { return 'm'; } } typeof A.name;",
        "function",
    );
}

#[test]
fn builtin_functions_have_length_and_name() {
    router_check(
        "[Math.max.length, Math.max.name, [].push.length, Array.prototype.slice.name, \
         'x'.padStart.length, Date.prototype.getDay.length, Date.prototype.getDay.name, \
         Object.keys.length, JSON.stringify.length].join();",
        "2,max,1,slice,1,0,getDay,1,3",
    );
    router_check(
        "JSON.stringify(Object.getOwnPropertyDescriptor(Math.max, 'length')) + \
         JSON.stringify(Object.getOwnPropertyDescriptor([].map, 'name'));",
        r#"{"value":2,"writable":false,"enumerable":false,"configurable":true}{"value":"map","writable":false,"enumerable":false,"configurable":true}"#,
    );
    router_check(
        "Object.getOwnPropertyNames(Math.max).join() + ':' + Math.max.hasOwnProperty('length');",
        "length,name:true",
    );
}

/// `Date` and `Promise` keep their statics on a property object of their own;
/// that object had no `length` or `name`, so `Date.name` was undefined.
#[test]
fn materialized_constructors_have_length_and_name() {
    router_check(
        "const d = Object.getOwnPropertyDescriptor(Date, 'name'); \
         const p = Object.getOwnPropertyDescriptor(Promise, 'length'); \
         [Date.name, Date.length, Promise.name, Promise.length, d.writable, d.enumerable, \
         d.configurable, p.value, p.writable, Object.keys(Date).length, \
         Object.keys(Promise).length, new Promise(() => {}).constructor.name, \
         Promise.resolve(1).constructor === Promise].join(' ');",
        "Date 7 Promise 1 false false true 1 false 0 0 Promise true",
    );
}

#[test]
fn builtin_functions_hold_and_delete_own_properties() {
    router_check(
        "var d = delete Math.min.name; d + ':' + JSON.stringify(Math.min.name) + ':' + Math.min.hasOwnProperty('name');",
        r#"true:"":false"#,
    );
    router_check(
        "Math.abs.tag = 'k'; Math.abs.length = 9; Math.abs.tag + ':' + Math.abs.length + ':' + Math.abs(-3);",
        "k:1:3",
    );
    router_check(
        "Math.round.extra = 1; Object.keys(Math.round).join();",
        "extra",
    );
}

/// A `new Function` body is lowered as its own module, so its `length` and
/// `name` come from that module's function table; they were read from the
/// caller's, which has no entry (or another function's) at that index.
#[test]
fn function_constructor_results_have_their_own_length() {
    router_check(
        "const f = new Function('a', 'b', 'return a + b'); \
         const g = Function('x', 'y', 'z', 'return 1'); const h = new Function('return this'); \
         [f.length, f.name, g.length, h.length, f(2, 3), \
         (new Function('...r', 'return r.length')).length].join();",
        "2,anonymous,3,0,5,0",
    );
}

#[test]
fn inspect_keeps_hiding_non_enumerable_function_properties() {
    assert_eq!(
        frankenctl_console(
            "function F() {} F.x = 1; Object.getOwnPropertyDescriptor(F, 'length'); \
             console.log(F); console.log(Math.max);"
        ),
        vec![
            "[Function: F] { x: 1 }".to_string(),
            "[Function: max]".to_string()
        ],
    );
}

/// A function's [[Prototype]] is %Function.prototype% (ES2020 19.2.3): a key
/// the function itself does not hold is read there, then on
/// Object.prototype. Only the synthesized `call`/`apply`/`bind`/`toString`
/// were, so `fn.constructor` was undefined, `Function.prototype.constructor`
/// was Object, and members a program adds to Function.prototype or
/// Object.prototype (`Function.prototype.method = ...`, getters included),
/// `valueOf` and `__proto__` did not reach functions.
#[test]
fn functions_inherit_from_function_prototype() {
    router_check(
        "function f() {} class C {} const arrow = () => 1; const bound = f.bind(null); \
         [f.constructor === Function, arrow.constructor === Function, C.constructor === Function, \
         bound.constructor === Function, Math.max.constructor === Function, \
         Array.constructor === Function, Function.prototype.constructor === Function, \
         Function.prototype.hasOwnProperty('constructor'), f.hasOwnProperty('constructor'), \
         new f.constructor('a', 'return a * 2')(21), f.__proto__ === Function.prototype, \
         Math.max.__proto__ === Function.prototype].join(' ')",
        "true true true true true true true true false 42 true true",
    );
    router_check(
        "Function.prototype.twice = function (x) { return this(this(x)); }; \
         Object.prototype.tag = 'o'; function inc(n) { return n + 1; } \
         Object.defineProperty(Function.prototype, 'self', { get() { return this; }, configurable: true }); \
         [inc.twice(1), ((s) => s + '!').twice('a'), Math.abs.twice(-3), inc.tag, Math.max.tag, \
         inc.valueOf() === inc, typeof inc.toLocaleString, inc.self === inc, 'twice' in inc, \
         inc.hasOwnProperty('twice'), String(inc.missing)].join(' ')",
        "3 a!! 3 o o true function true true false undefined",
    );
}

/// Generator, async and async generator functions inherit from
/// %GeneratorFunction.prototype%, %AsyncFunction.prototype% and
/// %AsyncGeneratorFunction.prototype% (ES2020 25.2.3, 25.7.3; ES2018 25.3.3),
/// which inherit from Function.prototype, carry an @@toStringTag and have
/// the intrinsic constructors as `constructor`. Every function's
/// [[Prototype]] was Function.prototype, so `is-generator-function`'s
/// `getProto(fn) === getProto(function* () {})` said every function was a
/// generator function, and `fn.constructor.name === 'AsyncFunction'` threw.
#[test]
fn generator_and_async_functions_have_their_kind_prototypes() {
    router_check(
        "function* g() {} async function a() {} async function* ag() {} function f() {} \
         const GF = Object.getPrototypeOf(g), AF = Object.getPrototypeOf(a), AGF = Object.getPrototypeOf(ag); \
         const isGen = (fn) => Object.getPrototypeOf(fn) === Object.getPrototypeOf(function* () {}); \
         [g.constructor.name, a.constructor.name, ag.constructor.name, GF === Function.prototype, \
         Object.getPrototypeOf(GF) === Function.prototype, Object.getPrototypeOf(AGF) === Function.prototype, \
         GF.constructor === g.constructor, AF.constructor.length, typeof AF.constructor, \
         Object.getPrototypeOf(a.constructor) === Function, g[Symbol.toStringTag], a[Symbol.toStringTag], \
         Object.prototype.toString.call(AGF), isGen(g), isGen(f), isGen(a), \
         g.constructor === Function, AF.hasOwnProperty('constructor'), g instanceof Function, \
         'call' in g, typeof ag.call, g.__proto__ === GF].join(' ')",
        "GeneratorFunction AsyncFunction AsyncGeneratorFunction false true true true 1 function true \
         GeneratorFunction AsyncFunction [object AsyncGeneratorFunction] true false false false true \
         true true function true",
    );
    router_check(
        "function* g() {} async function a() {} \
         Function.prototype.hello = function () { return 'hi ' + this.name; }; [g.hello(), a.hello()].join(' ')",
        "hi g hi a",
    );
    // Deviation, pinned: Node compiles `new AsyncFunction('return 1')` and
    // `GeneratorFunction('yield 1')`; creating these kinds from source text is
    // not supported here, and the constructors refuse with a TypeError.
    assert_eq!(
        HybridRouter::default()
            .eval(
                "async function a() {} function* g() {} const r = []; \
                 try { new a.constructor('return 1'); r.push('ok'); } catch (e) { r.push(e.constructor.name); } \
                 try { g.constructor('yield 1'); r.push('ok'); } catch (e) { r.push(e.constructor.name); } \
                 r.join(' ')"
            )
            .map(|outcome| outcome.value)
            .unwrap_or_else(|err| format!("ERROR: {err:?}")),
        "TypeError TypeError"
    );
}

/// The Function constructor ToStrings each parameter and the body, in
/// order, before parsing (ES2020 19.2.1.1.1): an object argument's toString
/// runs (an array joins). Object arguments read "[object Object]", so
/// handlebars, which passes source-map SourceNodes, failed to compile its
/// templates.
#[test]
fn function_constructor_to_strings_object_arguments() {
    router_check(
        "const log = []; const p = { toString() { log.push('p'); return 'x'; } }; \
         const b = { toString() { log.push('b'); return 'return x * 3'; } }; let e; \
         try { Function(Symbol('s')); } catch (x) { e = x.constructor.name; } \
         [Function(p, b)(7), log.join(), new Function(new String('return 4'))(), \
         new Function(['a', 'b'], 'return a + b')(1, 2), e].join(' ')",
        "21 p,b 4 3 TypeError",
    );
}

/// bd-9vouw.277: a function without an intrinsic `prototype` (bound, arrow,
/// method, accessor) takes `prototype` as an ordinary own property:
/// Object.defineProperty installs a value or an accessor, a read runs the
/// getter (Reflect.construct's GetPrototypeFromConstructor and
/// OrdinaryHasInstance throw what it throws), and hasOwnProperty and
/// getOwnPropertyDescriptor see it. The definition was dropped. A function
/// with an intrinsic `prototype` keeps its dedicated storage. Expected
/// lines are Node v22.2.0's output, captured programmatically; Bun 1.4.2
/// agrees.
#[test]
fn own_prototype_on_functions_without_one_bd_9vouw_277() {
    let source = r#"function kind(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var bound = function () {}.bind(null);
Object.defineProperty(bound, 'prototype', { get: function () { throw new EvalError('proto'); }, configurable: true });
console.log(kind(function () { return Reflect.construct(Uint8Array, [1], bound); }), kind(function () { return Reflect.construct(ArrayBuffer, [1], bound); }), kind(function () { return Reflect.construct(Map, [], bound); }));
var accessor = Object.getOwnPropertyDescriptor({ get g() { return 1; } }, 'g').get;
Object.defineProperty(accessor, 'prototype', { get: function () { throw new RangeError('p'); } });
console.log(kind(function () { return accessor[Symbol.hasInstance]({}); }), kind(function () { return {} instanceof accessor; }));
var arrow = () => {};
var proto = { tag: 'arrowproto' };
Object.defineProperty(arrow, 'prototype', { value: proto, writable: true, configurable: true });
var b2 = function () {}.bind(null);
var p2 = {};
Object.defineProperty(b2, 'prototype', { value: p2 });
var made = Reflect.construct(Uint8Array, [2], b2);
console.log(arrow.prototype === proto, arrow.hasOwnProperty('prototype'), JSON.stringify(Object.getOwnPropertyDescriptor(arrow, 'prototype')), Object.getPrototypeOf(made) === p2, b2.prototype === p2, Object.create(proto) instanceof arrow);
function F() {}
var fp = {};
Object.defineProperty(F, 'prototype', { value: fp });
var d = Object.getOwnPropertyDescriptor(F, 'prototype');
console.log(F.prototype === fp, new F() instanceof F, d.writable, d.enumerable, d.configurable, typeof (function () {}).prototype, (() => {}).hasOwnProperty('prototype'));
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
            "EvalError EvalError EvalError",
            "RangeError RangeError",
            "true true {\"value\":{\"tag\":\"arrowproto\"},\"writable\":true,\"enumerable\":false,\"configurable\":true} true true true",
            "true true true false false object false",
        ]
    );
}
