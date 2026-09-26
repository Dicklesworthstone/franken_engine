//! bd-9vouw.50: `Math.max(...arr)`, `Math.max.apply(null, arr)`,
//! `Reflect.apply(Math.min, null, arr)` and
//! `String.fromCharCode.apply(null, codes)` accept argument lists longer than
//! a register frame.
//!
//! Such calls staged every argument in the caller's fixed-stride register
//! frame and failed with "register 4294967295 out of bounds" past about 254
//! elements. Math.max/min and fromCharCode/fromCodePoint now take the list as
//! a vector (up to 2^17 entries, charged to the memory budget before it is
//! materialized). They also convert arguments with ES2020 ToNumber:
//! `Math.max("5", 3)` was NaN and `String.fromCharCode("65")` was "\0".
//!
//! Expected strings are what Node v22.2.0 prints for `String(<program>)`, each
//! run in a fresh context.
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
fn long_spread_and_apply_lists_reach_variadic_builtins() {
    check(
        "var a = []; for (var i = 0; i < 1000; i++) a.push(i); \
         [Math.max(...a), Math.min(...a), Math.max.apply(null, a), \
         Reflect.apply(Math.min, null, a)].join()",
        "999,0,999,0",
    );
    check(
        "var codes = []; for (var i = 0; i < 1000; i++) codes.push(65 + (i % 26)); \
         var s = String.fromCharCode.apply(null, codes); \
         [s.length, s.slice(0, 5), String.fromCharCode(...codes).length, \
         String.fromCodePoint.apply(null, codes).length].join()",
        "1000,ABCDE,1000,1000",
    );
}

#[test]
fn numeric_builtins_convert_arguments_with_to_number() {
    check(
        "[Math.max('5', 3), Math.max({valueOf: function () { return 9; }}, 2), \
         Math.min(' 2 ', 7), Math.max(true, 0), String.fromCharCode('65', 66.9), \
         Math.max.apply(null, ['7', 1]), Math.max(), Math.min(), 1 / Math.max(-0, 0), \
         1 / Math.min(0, -0), Math.max(1, NaN, 3), Math.max(1, 'x')].join()",
        "5,9,2,1,AB,7,-Infinity,Infinity,Infinity,-Infinity,NaN,NaN",
    );
    // Every argument is converted, in order, even after a NaN.
    check(
        "var log = []; var o = function (v) { return {valueOf: function () { \
         log.push(v); return v; }}; }; var r = Math.max(o(1), NaN, o(2)); \
         [r, log.join('|')].join()",
        "NaN,1|2",
    );
}

#[test]
fn long_lists_keep_error_semantics() {
    check(
        "var big = []; for (var i = 0; i < 500; i++) big.push(i); big.push('x'); \
         var r1 = Math.max(...big); var cps = []; for (var j = 0; j < 400; j++) cps.push(66); \
         cps.push(0x110000); var r2; try { String.fromCodePoint.apply(null, cps); r2 = 'no'; } \
         catch (e) { r2 = e instanceof RangeError; } var r3; \
         try { Math.max(1n); r3 = 'no'; } catch (e) { r3 = e instanceof TypeError; } \
         [r1, r2, r3].join()",
        "NaN,true,true",
    );
}
