#![forbid(unsafe_code)]

//! bd-9vouw.74: parameters are initialized left to right, and a default that
//! reads (or assigns, or applies typeof to) its own or a later parameter
//! throws a ReferenceError before the body runs (ES2020 9.2.10 step 27). The
//! engine read such a parameter as undefined (46 Node-passing Test262
//! dflt-params-ref-later / dflt-params-ref-self tests in the rc-next33
//! merged-tree census).

use frankenengine_engine::HybridRouter;

/// Every function kind (declaration, arrow, object and class methods, a
/// generator, an async function), a destructuring default, and the cases
/// that keep working: a default closure reading a later parameter after it
/// is initialized, a default reading an earlier parameter, a body `var`
/// redeclaring a parameter, an unmapped `arguments`, and `length`. Expected
/// lines are Node v22.2.0's output, captured programmatically.
///
/// No-claim: the separate parameter and body variable environments of a
/// function whose parameters have expressions (ES2020 9.2.10 step 28) are
/// not modelled; a closure in a default still sees a body `var` of the same
/// name.
#[test]
fn parameter_defaults_see_later_parameters_in_their_temporal_dead_zone() {
    let source = r#"function k(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } }
var calls = 0;
function later(x = y, y) { calls++; }
function self(x = x) { calls++; }
function viaTypeof(a = typeof b, b) { calls++; }
function viaAssign(a = (b = 1), b) { calls++; }
function nested({ a = b }, b) { calls++; }
console.log(k(function () { later(); }), k(function () { self(); }), k(function () { viaTypeof(); }), k(function () { viaAssign(); }), k(function () { nested({}); }), calls);
var arrow = (x = y, y) => x;
var obj = { m(x = x) { return x; }, *g(x = y, y) { yield x; } };
class C { static s(x = y, y) { return x; } i(x = x) { return x; } }
console.log(k(function () { arrow(); }), k(function () { obj.m(); }), k(function () { obj.g(); }), k(function () { C.s(); }), k(function () { new C().i(); }));
async function af(x = y, y) { return x; }
af().then(function () { console.log('async resolved'); }, function (e) { console.log('async rejected', e.constructor.name); });
function closure(a = function () { return b; }, b = 2) { return a(); }
function prior(a, b = a + 1, c) { return [a, b, c]; }
function redeclared(a = 1, b) { var b; return [a, b]; }
function fromPattern({ x }, y = x) { return y; }
function unmapped(a = 0, b) { b = 9; return arguments[1]; }
console.log(closure(), prior(1), prior(1, 5, 7), redeclared(undefined, 5), fromPattern({ x: 4 }), unmapped(1, 2));
console.log(later(1, 2), self(3), arrow(4, 5), obj.m(6), C.s(7, 8), new C().i(9), (function (a, b = 1, c) {}).length, calls);
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
            "ReferenceError ReferenceError ReferenceError ReferenceError ReferenceError 0",
            "ReferenceError ReferenceError ReferenceError ReferenceError ReferenceError",
            "2 [ 1, 2, undefined ] [ 1, 5, 7 ] [ 1, 5 ] 4 2",
            "undefined undefined 4 6 7 9 1 2",
            "async rejected ReferenceError",
        ]
    );
}
