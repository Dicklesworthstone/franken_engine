//! bd-9vouw.133: a Function-constructor body runs in a realm that binds the
//! standard values and has a global object of its own.
//!
//! The contained generated-code realm (bd-fw7zd.8.3) bound only console,
//! performance, Promise, Math, Date and the timers, so inside a Function body
//! `typeof Object`, `typeof JSON`, `typeof globalThis` were "undefined" and
//! reading `Object` as a value threw (`Object.keys(o)` worked only as a call
//! lowering rewrites). `Function('return this')()` was undefined, so core-js
//! 2's global detection, bundled into json5's dist build, babel-polyfill and
//! many UMD builds, failed while loading. The realm now binds its own JSON
//! and Reflect namespaces, the standard constructors and global functions
//! (the same stateless values the main realm binds, `Function` excepted:
//! generated code gets no recursive code generation by name), and its own
//! global object as `globalThis`, `global` and the sloppy `this` of its
//! functions. Expected strings are Node v22.2.0's output for the same
//! programs, except where a test says otherwise.
//!
//! No-claim: the generated realm's global object is not the main realm's,
//! so `Function('return this')() === globalThis` is false here (true in
//! Node), and so is Math identity across the two realms; its members are a
//! snapshot of the realm's bindings, and a free name in generated code does
//! not resolve through it (`globalThis.x = 1; x` inside a Function body);
//! its members are non-enumerable (Node's global has enumerable ones);
//! `Function` is not bound inside (Node: it is). Calls a contained grant
//! refuses (bd-9vouw.125) are not covered.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// Inside a Function body the standard constructors, namespaces and global functions are values.
#[test]
fn generated_realm_standard_values_are_bound() {
    let source = "var probe = Function(\"return [typeof Object, typeof Array, typeof String, typeof Error, typeof Map, typeof Symbol, typeof JSON, \" +\n\
           \"typeof Reflect, typeof parseInt, typeof encodeURIComponent, typeof globalThis, typeof global].join(' ')\");\n\
         [probe()].join(' ');";
    assert_eq!(
        eval(source),
        "function function function function function function object object function function object object"
    );
}

/// The realm's global object is its globalThis, global and the sloppy this of its functions, and holds its bindings.
#[test]
fn generated_realm_global_object_and_sloppy_this() {
    let source = "var g = Function('return this')();\n\
         [typeof g, g === Function('return globalThis')(), Function('return global === globalThis')(), typeof g.Object, typeof g.Math.max,\n\
          typeof g.JSON.stringify, Function('return this.Array === Array')(), Function('\"use strict\"; return this')() === undefined].join(' ');";
    assert_eq!(
        eval(source),
        "object true true function function function true true"
    );
}

/// core-js 2's global detection (json5's dist build, babel-polyfill) finds an object it can define properties on.
#[test]
fn generated_realm_core_js_global_detection() {
    let source = "var global = typeof window != 'undefined' && window.Math == Math ? window\n\
           : typeof self != 'undefined' && self.Math == Math ? self : Function('return this')();\n\
         Object.defineProperty(global, '__core_probe', { value: 7, configurable: true });\n\
         [typeof global, global.__core_probe, typeof global.Symbol, typeof global.Promise, typeof global.Object.defineProperty].join(' ');";
    assert_eq!(eval(source), "object 7 function function function");
}

/// Standard values read inside a Function body behave as they do outside.
#[test]
fn generated_realm_values_work_in_generated_code() {
    let source = "var run = Function(\"var m = new Map([[1, 'one']]); \" +\n\
           \"return [m.get(1), Array.isArray([]), [] instanceof Array, JSON.stringify({ a: [1] }), Reflect.ownKeys({ b: 1 }).join(), \" +\n\
           \"Object.keys({ c: 1, d: 2 }).join(), typeof Object.prototype.hasOwnProperty, new Error('e') instanceof Error].join(' ')\");\n\
         [run()].join(' ');";
    assert_eq!(
        eval(source),
        "one true true {\"a\":[1]} b c,d function true"
    );
}

/// Writes through the generated realm's global object stay in that realm
/// (bd-fw7zd.8.3 isolation; bd-9vouw.133 design option (a)). Node shares one
/// global object and prints "number number 1 2"; this expectation is the
/// engine's deliberate divergence.
#[test]
fn generated_realm_writes_stay_in_the_generated_realm() {
    let source = "var g = Function('return this')();\n\
         Function('this.leakedThroughThis = 1; globalThis.leakedThroughGlobalThis = 2')();\n\
         [typeof leakedThroughThis, typeof leakedThroughGlobalThis, g.leakedThroughThis, Function('return globalThis.leakedThroughGlobalThis')()].join(' ');";
    assert_eq!(eval(source), "undefined undefined 1 2");
}
