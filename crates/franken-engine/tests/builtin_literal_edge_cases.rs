#![forbid(unsafe_code)]

//! Built-in and literal edge cases that differed from Node (Test262 failures of
//! the land33 census): the NativeError prototypes are ordinary objects
//! ("[object Object]"); Object.is with missing arguments compares undefined;
//! Math.hypot is +Infinity for any infinite argument, Math.sign(-0) is -0 and
//! Math.atanh(+-1) is +-Infinity; Symbol(desc) and Symbol.for(key) run ToString
//! on an object; Annex B legacy octal integer literals (070 is 56, 08 is 8);
//! BigInt(value) and BigInt.asIntN / asUintN run ToPrimitive on an object.

use frankenengine_engine::HybridRouter;

/// Expected lines are Node v22.2.0's output, captured programmatically from the
/// same source. Line H (non-callable __defineGetter__ / __defineSetter__)
/// already matched; it guards the legacy accessor methods.
#[test]
fn builtin_and_literal_edge_cases_match_node() {
    let source = r#"function k(f) { try { var r = f(); return typeof r === 'string' ? r : String(r); } catch (e) { return e.constructor.name; } }
var ts = Object.prototype.toString;
console.log('A', ts.call(TypeError.prototype), ts.call(RangeError.prototype), ts.call(Error.prototype), ts.call(new TypeError('x')));
console.log('B', Object.is(), Object.is(undefined), Object.is(NaN, NaN), Object.is(0, -0));
console.log('C', Math.hypot(NaN, Infinity), Math.hypot(-Infinity, NaN), 1 / Math.sign(-0), Math.atanh(-1), Math.atanh(1));
var log = [];
var desc = { toString: function () { log.push('toString'); return 'test262'; }, valueOf: function () { log.push('valueOf'); return 'no'; } };
console.log('D', Symbol(desc).description, Symbol.for(desc).description, log.join(','));
console.log('E', 070, 0777, 08, 09.5, 010 + 1);
console.log('H', k(function () { return {}.__defineGetter__('x', 5); }), k(function () { return {}.__defineSetter__('x', 5); }));
var o = { valueOf: function () { return 5n; } };
console.log('J', k(function () { return BigInt(o); }), k(function () { return BigInt.asIntN(8, o); }), k(function () { return BigInt({ toString: function () { return "12"; }, valueOf: null }); }), k(function () { return BigInt(Object(3n)); }));
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
            "A [object Object] [object Object] [object Object] [object Error]",
            "B true true true false",
            "C Infinity Infinity -Infinity -Infinity Infinity",
            "D test262 test262 toString,toString",
            "E 56 511 8 9.5 9",
            "H TypeError TypeError",
            "J 5 5 12 3",
        ]
    );
}
