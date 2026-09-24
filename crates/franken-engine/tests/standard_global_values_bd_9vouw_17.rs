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
