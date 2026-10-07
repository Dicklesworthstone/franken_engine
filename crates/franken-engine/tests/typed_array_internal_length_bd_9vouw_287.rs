#![forbid(unsafe_code)]

//! bd-9vouw.287: the %TypedArray%.prototype methods that share an Array
//! kind iterated LengthOfArrayLike instead of the view's [[ArrayLength]]
//! (32 Node-passing Test262 tests under built-ins/TypedArray/prototype).

use frankenengine_engine::HybridRouter;

/// With throwing `length` getters on %TypedArray%.prototype and on the
/// instances (as Test262's get-length-ignores-length-prop tests define
/// them), every, some, includes, indexOf, lastIndexOf, reduce,
/// reduceRight, find, findIndex, findLast, findLastIndex, forEach and at
/// visit every element of an Int16Array and a BigUint64Array, and no
/// getter runs (the engine answered as if the length were 0). An empty
/// receiver answers includes/indexOf/lastIndexOf before fromIndex converts,
/// for typed arrays and Arrays. Expected lines are Node v22.2.0's output,
/// captured programmatically (Bun 1.4.2 agrees).
///
/// No-claim: Object.defineProperty(ta, 'length', ...) still writes the
/// engine's internal length mirror of the instance, so the result is not
/// reported as an own property, and Array.prototype methods called on
/// such a typed array read that mirror instead of calling the accessor.
#[test]
fn typed_array_methods_iterate_the_internal_length_bd_9vouw_287() {
    let source = r#"function k(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var TA = Object.getPrototypeOf(Int8Array);
var original = Object.getOwnPropertyDescriptor(TA.prototype, 'length');
var reads = 0;
var poisoned = { get: function () { reads++; throw new RangeError('length read'); }, configurable: true };
Object.defineProperty(TA.prototype, 'length', poisoned);
var s = new Int16Array([1, 2, 3]);
var b = new BigUint64Array([5n, 6n]);
Object.defineProperty(s, 'length', poisoned);
Object.defineProperty(b, 'length', poisoned);
var results = [
  k(function () { return s.every(function (v) { return v > 0; }); }),
  k(function () { return s.some(function (v) { return v > 2; }); }),
  k(function () { return s.includes(3); }),
  k(function () { return s.indexOf(3); }),
  k(function () { return s.lastIndexOf(1); }),
  k(function () { return s.reduce(function (a, v) { return a + v; }); }),
  k(function () { return s.reduceRight(function (a, v) { return a + '' + v; }, ''); }),
  k(function () { return s.find(function (v) { return v === 3; }); }),
  k(function () { return s.findIndex(function (v) { return v === 3; }); }),
  k(function () { return s.findLast(function (v) { return v < 3; }); }),
  k(function () { return s.findLastIndex(function (v) { return v < 3; }); }),
  k(function () { var n = 0; s.forEach(function () { n++; }); return n; }),
  k(function () { return s.at(-1); }),
  k(function () { return b.includes(6n); }),
  k(function () { return b.indexOf(6n); }),
  k(function () { return b.find(function (v) { return v > 5n; }); }),
  reads
];
Object.defineProperty(TA.prototype, 'length', original);
console.log(results.join(' '));
var fromIndex = { valueOf: function () { throw new RangeError('fromIndex converted'); } };
console.log(k(function () { return new Int8Array(0).includes(0, fromIndex); }), k(function () { return new Float32Array(0).indexOf(0, fromIndex); }), k(function () { return new Uint8Array(0).lastIndexOf(0, fromIndex); }), k(function () { return [].includes(0, fromIndex); }), k(function () { return [].indexOf(0, fromIndex); }), k(function () { return [].lastIndexOf(0, fromIndex); }), k(function () { return [1].includes(0, fromIndex); }));
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
            "true true true 2 0 6 321 3 2 2 1 3 3 true 1 6 0",
            "false -1 -1 false -1 -1 RangeError",
        ]
    );
}
