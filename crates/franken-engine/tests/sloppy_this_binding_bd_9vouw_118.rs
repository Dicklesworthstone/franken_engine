//! bd-9vouw.118: ES2020 9.2.1.2 OrdinaryCallBindThis. A non-strict function
//! called with an undefined or null `this` gets the global object, and a
//! primitive `this` its wrapper object; strict functions, class code and
//! modules keep the value as passed. Sloppy functions saw `undefined`, so the
//! global-object fallbacks of polyfills and older libraries
//! (`Function('return this')()`, `(function () { return this })()`) found
//! nothing. Expected strings are Node v22.2.0's output.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value
}

#[test]
fn sloppy_functions_bind_the_global_object_and_box_primitives() {
    let source = "var r = [];\n\
                  r.push((function () { return this; })() === globalThis);\n\
                  r.push((function () { return typeof this; }).call(5), \
                  (function () { return this instanceof Number; }).call(5));\n\
                  r.push(Function('return this')() === globalThis);\n\
                  r.push((function () { var a = () => this; return a(); })() === globalThis);\n\
                  r.push((function () { return this === this; }).call('s'));\n\
                  var o = { m: function () { return this; } }; var m = o.m;\n\
                  r.push(m() === globalThis, o.m() === o);\n\
                  r.push([1].map(function () { return this; })[0] === globalThis);\n\
                  r.push((function () { return this; }).call(null) === globalThis);\n\
                  r.join(' ');";
    assert_eq!(
        eval(source),
        "true object true true true true true true true true"
    );
}

#[test]
fn strict_code_keeps_this_as_passed() {
    let source = "var r = [];\n\
                  r.push((function () { 'use strict'; return this; })() === undefined, \
                  (function () { 'use strict'; return typeof this; }).call(5));\n\
                  class C { m() { return this; } } var cm = new C().m; r.push(cm() === undefined);\n\
                  r.push((function () { return (function () { 'use strict'; return this; })(); })() \
                  === undefined);\n\
                  r.join(' ');";
    assert_eq!(eval(source), "true number true true");
}
