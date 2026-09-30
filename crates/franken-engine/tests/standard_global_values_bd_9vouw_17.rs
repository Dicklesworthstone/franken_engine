//! bd-9vouw.17 (second slice): standard globals are first-class values.
//!
//! Before this change `typeof Object`, `typeof TypeError`, `typeof JSON`,
//! `typeof parseInt` (and 36 more standard globals) were "undefined": direct
//! calls like `new TypeError(m)` or `JSON.stringify(v)` worked only because the
//! lowering pattern-matches them at the call site. Test262's harness needs the
//! values themselves (`assert.throws(TypeError, f)` compares
//! `thrown.constructor !== TypeError`). Expected strings are what Node v22.2.0
//! prints for the same programs.
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
fn standard_globals_have_the_right_typeof() {
    check(
        "[typeof Object, typeof Array, typeof Number, typeof String, typeof Boolean, \
          typeof BigInt, typeof Map, typeof Set, typeof Error, typeof TypeError, \
          typeof RangeError, typeof ReferenceError, typeof SyntaxError, typeof EvalError, \
          typeof URIError].join(',');",
        "function,function,function,function,function,function,function,function,\
         function,function,function,function,function,function,function",
    );
    check(
        "[typeof JSON, typeof parseInt, typeof parseFloat, typeof isNaN, typeof isFinite].join(',');",
        "object,function,function,function,function",
    );
}

#[test]
fn error_constructors_are_identities_shared_with_thrown_errors() {
    check("TypeError === TypeError;", "true");
    check("TypeError === RangeError;", "false");
    check(
        "let r; try { null.x; } catch (e) { r = e.constructor === TypeError; } r;",
        "true",
    );
    check("new TypeError('x').constructor === TypeError;", "true");
    check("TypeError.prototype.constructor === TypeError;", "true");
    check("TypeError.name + ':' + TypeError.length;", "TypeError:1");
}

#[test]
fn constructors_work_when_passed_as_values() {
    check("const E = TypeError; new E('m').message;", "m");
    check(
        "const E = RangeError; E('m') instanceof RangeError;",
        "true",
    );
    check(
        "function throws(C, f) { try { f(); } catch (e) { return e.constructor === C; } return false; } \
         throws(TypeError, function () { null.x; });",
        "true",
    );
}

#[test]
fn constructor_is_not_an_enumerable_prototype_property() {
    check(
        "Object.keys(TypeError.prototype).indexOf('constructor');",
        "-1",
    );
}

#[test]
fn array_constructor_value() {
    check("new Array(3).length;", "3");
    check("new Array(3).join('-');", "--");
    check("Array(1, 2, 3).join();", "1,2,3");
    check("[].constructor === Array;", "true");
}

#[test]
fn number_constructor_members() {
    check("Number.MAX_SAFE_INTEGER;", "9007199254740991");
    check("Number.MIN_SAFE_INTEGER;", "-9007199254740991");
    check("const N = Number; N('42') + 1;", "43");
}

#[test]
fn static_builtins_are_callable_values() {
    check(
        "const keys = Object.keys; keys({ a: 1, b: 2 }).join();",
        "a,b",
    );
    check("const J = JSON; J.stringify({ a: 1 });", "{\"a\":1}");
    check("const p = parseInt; p('42px');", "42");
    check("parseInt === parseInt;", "true");
    // js-yaml's bundle calls these through a value; the runtime's list of
    // first-class Object statics lacked them ("expected known static
    // builtin").
    check(
        "const d = Object.getOwnPropertyDescriptors; const dp = Object.defineProperties; \
         const o = dp({}, d({ a: 1, get b() { return 2; } })); \
         [o.a, o.b, typeof d, d.length, dp.length, d.name].join();",
        "1,2,function,1,2,getOwnPropertyDescriptors",
    );
}

#[test]
fn bigint_constructor_value() {
    check("typeof BigInt(10);", "bigint");
    check("String(BigInt('0012'));", "12");
    check(
        "let r; try { BigInt('x'); } catch (e) { r = e.name; } r;",
        "SyntaxError",
    );
    check(
        "let r; try { BigInt(1.5); } catch (e) { r = e.name; } r;",
        "RangeError",
    );
}

#[test]
fn error_objects_stringify_through_error_prototype_to_string() {
    check("String(new RangeError('deep'));", "RangeError: deep");
    check("'' + new TypeError('x');", "TypeError: x");
    check(
        "let r; try { null.x; } catch (e) { r = String(e).split(':')[0]; } r;",
        "TypeError",
    );
    check("String(new Error(''));", "Error");
    // A user-defined toString on the instance still wins.
    check(
        "const e = new Error('m'); e.toString = function () { return 'custom'; }; String(e);",
        "custom",
    );
}

#[test]
fn builtin_prototypes_expose_their_methods() {
    check(
        "typeof Array.prototype.every + ',' + typeof String.prototype.slice + ',' + typeof Number.prototype.toFixed;",
        "function,function,function",
    );
    // Test262's dominant shape: a prototype method applied to an array-like.
    check(
        "Array.prototype.map.call({length: 2, 0: 'a', 1: 'b'}, x => x + x).join();",
        "aa,bb",
    );
    check(
        "Array.prototype.every.call({length: 2, 0: 2, 1: 4}, x => x % 2 === 0);",
        "true",
    );
    check("String.prototype.slice.call('hello', 1, 3);", "el");
    check("Number.prototype.toFixed.call(2.5, 0);", "3");
    // Map's iterator methods (`entries`/`keys`/`values`) are bd-9vouw.33.
    check(
        "typeof Map.prototype.get + ',' + typeof Set.prototype.has;",
        "function,function",
    );
    check("Map.prototype.get.call(new Map([[1, 'a']]), 1);", "a");
    check(
        "const o = Object.create(Array.prototype); typeof o.push;",
        "function",
    );
    // Still virtual: not enumerable, and unknown names stay undefined.
    check("Object.keys(Array.prototype).length;", "0");
    check("typeof Array.prototype.missing;", "undefined");
}

#[test]
fn test262_sta_prelude_shape_runs() {
    // harness/sta.js assigns to its constructor function and the tests pass
    // constructors around; this is the shape (not the file) of that prelude.
    check(
        "function Test262Error(message) { this.message = message || ''; } \
         Test262Error.prototype.toString = function () { return 'Test262Error: ' + this.message; }; \
         Test262Error.thrower = function (message) { throw new Test262Error(message); }; \
         let r; try { Test262Error.thrower('boom'); } catch (e) { r = String(e); } r;",
        "Test262Error: boom",
    );
}

/// `Reflect` is a first-class namespace object, like `JSON` and `Math`.
/// `typeof Reflect` was "undefined" and `var R = Reflect` threw
/// "Reflect is not defined": only the direct `Reflect.m(...)` call shape
/// worked, because the lowering intercepts it. Feature checks
/// (`typeof Reflect !== 'undefined'`) and destructuring (`const { ownKeys } =
/// Reflect`) failed.
#[test]
fn reflect_is_a_first_class_namespace_object() {
    check(
        "var R = Reflect; var { ownKeys, has } = Reflect; \
         var o = { a: 1, [Symbol.iterator]: 2 }; \
         [typeof Reflect, typeof R.get, R.get(o, 'a'), has(o, 'a'), ownKeys(o).length, \
          R.apply(Math.max, null, [1, 3, 2]), Object.keys(Reflect).length, \
          typeof Reflect.construct].join('|')",
        "object|function|1|true|2|3|0|function",
    );
    check(
        "function F(x) { this.x = x; } \
         var c = [Reflect.construct].map(function (f) { return f(F, [7]).x; }); \
         [c[0], Reflect.apply.call(null, Math.min, null, [4, 2]), \
          Reflect.getPrototypeOf([]) === Array.prototype].join('|')",
        "7|2|true",
    );
}

/// The global object (bd-9vouw.17): `globalThis` and Node's `global` are one
/// object holding the standard intrinsics exactly as the bare names resolve,
/// non-enumerable as in Node. lodash's `freeGlobal` test and a UMD wrapper
/// that exports onto `globalThis` both work. Expected strings are Node
/// v22.2.0's.
#[test]
fn global_object_holds_the_standard_intrinsics() {
    check(
        "[typeof globalThis, typeof global, globalThis === global, \
          globalThis.Object === Object, globalThis.Math === Math, global.JSON === JSON, \
          globalThis.setTimeout === setTimeout, globalThis.globalThis === globalThis, \
          globalThis.Array === Array].join();",
        "object,object,true,true,true,true,true,true,true",
    );
    check(
        "var freeGlobal = typeof global == 'object' && global && global.Object === Object \
          && global; typeof freeGlobal;",
        "object",
    );
    check(
        // Braced: an unbraced `if (..) x; else y;` does not parse yet
        // (bd-9vouw.88).
        "(function (root, factory) { if (typeof define === 'function' && define.amd) \
          { define(factory); } else { root.myLib = factory(); } })(typeof globalThis \
          !== 'undefined' ? globalThis : this, function () { return 42; }); globalThis.myLib;",
        "42",
    );
    check(
        "Object.keys(globalThis).indexOf('Object') + ':' + typeof globalThis.parseInt;",
        "-1:function",
    );
}

/// The global object never carries a host-authority binding: a computed
/// read cannot reach `process` (Node would return its process object), and a
/// static `globalThis.process` read stays gated at lowering like the bare
/// identifier (ambient_authority_lowering_rejection_integration).
#[test]
fn global_object_exposes_no_host_authority() {
    check(
        "var k = 'pro' + 'cess'; [typeof globalThis[k], typeof global['req' + 'uire']].join();",
        "undefined,undefined",
    );
}

/// A program's own binding named `global` (or `globalThis`, or any other
/// runtime global) shadows the global at top level, in blocks and in
/// functions, as Node's module scope does. Seeding the object as a realm
/// dynamic global broke the top-level case (`global` read undefined), and a
/// top-level block's `const` overwrote the injected global.
#[test]
fn program_bindings_named_global_shadow_the_global_object() {
    check(
        "var global = 5; [global, typeof globalThis].join();",
        "5,object",
    );
    check(
        "const global = Symbol.for('shared'); [global === Symbol.for('shared'), typeof global].join();",
        "true,symbol",
    );
    check(
        "var r; { const global = 'x'; r = global; } r + ':' + typeof global;",
        "x:object",
    );
    check(
        "function f() { const global = 7; return global; } f();",
        "7",
    );
    // The same holds for the other runtime globals, whose block-scoped
    // shadows overwrote the injected global before (typeof gave "string").
    check(
        "var r; { const performance = 'x'; r = performance; } r + ':' + typeof performance;",
        "x:object",
    );
    check(
        "var r; { let setTimeout = 'x'; r = setTimeout; } r + ':' + typeof setTimeout;",
        "x:function",
    );
}

/// ES2022 `Object.hasOwn(object, key)`: own properties only (not inherited),
/// symbol and numeric keys, arrays, a string's own index and `length`, a
/// function's own `name`; `null` is a TypeError. It was undefined.
#[test]
fn object_has_own() {
    check(
        "var sym = Symbol('s'); var o = { a: 1, [sym]: 2, 1: 'x' }; var h = Object.create(o); \
         h.b = 2; function fn() {} const has = Object.hasOwn; var t; \
         try { Object.hasOwn(null, 'a'); t = 'no'; } catch (e) { t = e.constructor.name; } \
         [Object.hasOwn(o, 'a'), Object.hasOwn(h, 'a'), Object.hasOwn(h, 'b'), Object.hasOwn(o, sym), \
         Object.hasOwn(o, 1), Object.hasOwn([5], 0), Object.hasOwn([5], 'length'), \
         Object.hasOwn('abc', 'length'), Object.hasOwn('abc', 1), Object.hasOwn(fn, 'name'), \
         has(o, 'a'), typeof Object.hasOwn, Object.hasOwn.name, Object.hasOwn.length, t].join();",
        "true,false,true,true,true,true,true,true,true,true,true,function,hasOwn,2,TypeError",
    );
    // Object.prototype.hasOwnProperty, which now shares the helper: a
    // nullish `this` is a TypeError (ToObject), a primitive is boxed.
    check(
        "var r = []; for (const v of [undefined, null]) { try { \
         Object.prototype.hasOwnProperty.call(v, 'x'); r.push('no'); } \
         catch (e) { r.push(e.constructor.name); } } \
         r.join() + ' ' + Object.prototype.hasOwnProperty.call('ab', 'length') + ' ' + \
         Object.prototype.hasOwnProperty.call(5, 'x');",
        "TypeError,TypeError true false",
    );
}
