//! bd-9vouw.34: every object's [[Prototype]] chain reaches `Object.prototype`.
//!
//! Before this, ordinary objects and arrays carried no prototype link, so
//! `({}) instanceof Object` and `[] instanceof Object` were false,
//! `Object.getPrototypeOf({})` was null, methods added to `Array.prototype` or
//! `Object.prototype` were invisible, and functions were not
//! `instanceof Function`. An unset link now means the realm's
//! `Array.prototype` / `Object.prototype`, and an explicit null
//! (`Object.create(null)`, `setPrototypeOf(o, null)`, `__proto__: null`) still
//! ends the chain. Expected strings are what Node v22.2.0 prints for
//! `String(eval(source))`.
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
fn every_object_kind_is_instanceof_object() {
    check(
        "[{} instanceof Object, [] instanceof Object, (function () {}) instanceof Object, \
         (() => 1) instanceof Function, new Map() instanceof Object, \
         new Error('x') instanceof Object, Promise.resolve(1) instanceof Object, \
         new Set() instanceof Object].join()",
        "true,true,true,true,true,true,true,true",
    );
    check(
        "class A {} class B extends A {} [new A() instanceof Object, new B() instanceof Object, \
         B instanceof Function, B instanceof Object, \
         Object.getPrototypeOf(A.prototype) === Object.prototype].join()",
        "true,true,true,true,true",
    );
}

#[test]
fn get_prototype_of_reports_the_default_intrinsics() {
    check(
        "[Object.getPrototypeOf({}) === Object.prototype, \
         Object.getPrototypeOf([]) === Array.prototype, \
         Object.getPrototypeOf(Array.prototype) === Object.prototype, \
         Object.getPrototypeOf(Object.prototype), \
         ({}).__proto__ === Object.prototype].join()",
        "true,true,true,,true",
    );
}

#[test]
fn builtin_prototypes_chain_to_object_prototype() {
    check(
        "[Object.getPrototypeOf(Array.prototype) === Object.prototype, \
         Object.getPrototypeOf(String.prototype) === Object.prototype, \
         Object.getPrototypeOf(Number.prototype) === Object.prototype, \
         Object.getPrototypeOf(Boolean.prototype) === Object.prototype, \
         Object.getPrototypeOf(Error.prototype) === Object.prototype, \
         Object.getPrototypeOf(Map.prototype) === Object.prototype, \
         Object.getPrototypeOf(Set.prototype) === Object.prototype, \
         Object.getPrototypeOf(Function.prototype) === Object.prototype, \
         Object.getPrototypeOf(TypeError.prototype) === Error.prototype].join()",
        "true,true,true,true,true,true,true,true,true",
    );
}

#[test]
fn explicit_null_prototypes_end_the_chain() {
    check(
        "var n = Object.create(null); var o = {}; Object.setPrototypeOf(o, null); \
         [Object.getPrototypeOf(n), n instanceof Object, o instanceof Object, \
         Object.getPrototypeOf(o), ({ __proto__: null }) instanceof Object].join()",
        ",false,false,,false",
    );
}

#[test]
fn methods_added_to_builtin_prototypes_are_inherited() {
    check(
        "Array.prototype.sumAll = function () { var t = 0; \
         for (var i = 0; i < this.length; i++) t += this[i]; return t; }; \
         Object.prototype.tag = 'T'; class K {} \
         [[1, 2, 3].sumAll(), ({}).tag, [].tag, new K().tag, \
         typeof Object.create(null).tag].join()",
        "6,T,T,T,undefined",
    );
    // for-in visits inherited enumerable properties; delete removes them.
    check(
        "Object.prototype.inherited = 1; var keys = []; for (var k in { own: 2 }) keys.push(k); \
         delete Object.prototype.inherited; keys.join() + '|' + ('inherited' in {})",
        "own,inherited|false",
    );
}

#[test]
fn constructor_and_in_see_the_builtin_methods() {
    check(
        "[({}).constructor === Object, [].constructor === Array, 'hasOwnProperty' in {}, \
         'push' in [], 'toString' in Object.create(null), ({}).hasOwnProperty('x')].join()",
        "true,true,true,true,false,false",
    );
}

#[test]
fn is_prototype_of_walks_objects_and_functions() {
    check(
        "class P {} class Q extends P {} [Object.prototype.isPrototypeOf([]), \
         Array.prototype.isPrototypeOf([]), Array.prototype.isPrototypeOf({}), \
         P.prototype.isPrototypeOf(new Q()), P.isPrototypeOf(Q), \
         Object.prototype.isPrototypeOf(1), Function.prototype.isPrototypeOf(P)].join()",
        "true,true,false,true,true,false,true",
    );
}

#[test]
fn date_promise_and_regexp_have_intrinsic_prototypes() {
    // Before this, `x instanceof Date` / `x instanceof Promise` threw
    // "expected function, got function" and `RegExp` was not a value.
    check(
        "[new Date(0) instanceof Date, new Date(0) instanceof Object, \
         Promise.resolve(1) instanceof Promise, /x/ instanceof RegExp, \
         new RegExp('a') instanceof RegExp, typeof RegExp, RegExp('a', 'g').flags, \
         /x/ instanceof Object].join()",
        "true,true,true,true,true,function,g,true",
    );
    check(
        "[Object.getPrototypeOf(new Date(0)) === Date.prototype, \
         Object.getPrototypeOf(Date.prototype) === Object.prototype, \
         Object.getPrototypeOf(Promise.resolve(1)) === Promise.prototype, \
         Object.getPrototypeOf(Promise.prototype) === Object.prototype, \
         Object.getPrototypeOf(/x/) === RegExp.prototype, \
         Object.getPrototypeOf(RegExp.prototype) === Object.prototype].join()",
        "true,true,true,true,true,true",
    );
    check(
        "[typeof Date.prototype.getTime, Date.prototype.getTime.call(new Date(5)), \
         RegExp.prototype.test.call(/a/, 'cat'), typeof Promise.prototype.then].join()",
        "function,5,true,function",
    );
    check(
        "Date.prototype.addDays = function (n) { return new Date(this.getTime() + n * 864e5); }; \
         RegExp.prototype.twice = function (s) { return this.test(s) && this.test(s); }; \
         [new Date(0).addDays(1).getTime(), /a/.twice('a')].join()",
        "86400000,true",
    );
}

#[test]
fn cyclic_prototypes_and_missing_create_argument_throw() {
    // `[]` inherits from Array.prototype, so making it Array.prototype's
    // prototype would close a cycle.
    check(
        "var r; try { Object.setPrototypeOf(Array.prototype, []); r = 'no error'; } \
         catch (e) { r = e instanceof TypeError; } \
         var s; try { Object.create(); s = 'no error'; } catch (e) { s = e instanceof TypeError; } \
         r + ',' + s",
        "true,true",
    );
}
