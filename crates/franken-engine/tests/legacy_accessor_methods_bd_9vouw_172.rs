//! bd-9vouw.172: the Annex B accessor methods of Object.prototype.
//!
//! `o.__defineGetter__('x', f)` threw "expected function, got undefined":
//! Object.prototype had no __defineGetter__, __defineSetter__,
//! __lookupGetter__ or __lookupSetter__ (Annex B.2.2.2-5), which older
//! bundles and polyfills still call. They now define an enumerable,
//! configurable accessor through [[DefineOwnProperty]] (a Proxy's trap
//! included) and look accessors up the prototype chain. Expected strings
//! are Node v22.2.0's output for the same programs.
//!
//! No-claim: Array.fromAsync, the other half of bd-9vouw.172, is not here.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// __defineGetter__/__defineSetter__ define an enumerable, configurable accessor; __lookupGetter__/__lookupSetter__ return its functions, undefined for a data property or none.
#[test]
fn legacy_accessors_define_and_lookup() {
    let source = "var o = {};\n\
         o.__defineGetter__('x', function () { return 4; });\n\
         o.__defineSetter__('x', function (v) { this.y = v * 2; });\n\
         o.x = 5;\n\
         var d = Object.getOwnPropertyDescriptor(o, 'x');\n\
         [o.x, o.y, typeof o.__lookupGetter__('x'), o.__lookupGetter__('x') === d.get, o.__lookupSetter__('x') === d.set,\n\
          d.enumerable, d.configurable, String(o.__lookupSetter__('nope')), String(({ a: 1 }).__lookupGetter__('a'))].join(' ');";
    assert_eq!(
        eval(source),
        "4 10 function true true true true undefined undefined"
    );
}

/// Lookups walk the prototype chain; keys go through ToPropertyKey (symbols too); a non-callable function, an undefined this and a frozen target throw.
#[test]
fn legacy_accessors_chain_keys_and_errors() {
    let source = "function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }\n\
         var proto = {}; proto.__defineGetter__('p', function () { return 'from-proto'; });\n\
         var child = Object.create(proto);\n\
         var s = Symbol('k'), o2 = {}; o2.__defineGetter__(s, function () { return 'sym'; });\n\
         var n = {}; n.__defineGetter__(1, function () { return 'one'; });\n\
         [child.p, typeof child.__lookupGetter__('p'), o2[s], n['1'], attempt(function () { return ({}).__defineGetter__('q', 5); }),\n\
          attempt(function () { return Object.prototype.__defineGetter__.call(undefined, 'q', function () {}); }),\n\
          attempt(function () { return Object.freeze({}).__defineGetter__('z', function () {}); }),\n\
          String('abc'.__lookupGetter__('length')), Object.prototype.__defineGetter__.length, Object.prototype.__lookupSetter__.length,\n\
          Object.prototype.__defineSetter__.name, '__lookupGetter__' in {}].join(' ');";
    assert_eq!(
        eval(source),
        "from-proto function sym one TypeError TypeError TypeError undefined 2 1 __defineSetter__ true"
    );
}
