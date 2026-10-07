#![forbid(unsafe_code)]

//! bd-9vouw.258: %TypedArray%.prototype.toReversed, toSorted and with
//! (ES2023 change array by copy) were undefined; Array.prototype had them.
//! About 40 Node-passing Test262 tests failed with "expected function, got
//! undefined", and `ta.toSorted()` threw in code written for Node 20+.
//!
//! PROGRAM covers the copies (new arrays of the receiver's intrinsic type,
//! never the species, the receiver unchanged), toSorted's default numeric
//! order and comparator, with's relative index, value conversion and
//! RangeErrors, BigInt arrays, the lengths and names, and non-typed-array
//! receivers. Expected lines are Node v22.2.0's output, captured
//! programmatically.
//!
//! `with` converts its index before its value (ES2023 23.2.3.36 steps 4
//! and 7; Test262 built-ins/TypedArray/prototype/with/order-of-evaluation.js).
//! Node v22.2.0 converts the value first, so that order is checked against
//! the specification, not Node.

use frankenengine_engine::HybridRouter;

fn console_lines(source: &str) -> Vec<String> {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect()
}

#[test]
fn typed_array_change_by_copy_matches_node_bd_9vouw_258() {
    let source = r#"function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var ta = new Uint8Array([3, 1, 2]);
var reversed = ta.toReversed();
var sorted = ta.toSorted();
console.log(reversed.join(), sorted.join(), ta.join(), reversed instanceof Uint8Array, reversed !== ta, sorted.buffer !== ta.buffer);
console.log(new Float64Array([2, NaN, -0, 1]).toSorted().join(), new Int8Array([1, 2, 3]).toSorted((a, b) => b - a).join(), attempt(() => ta.toSorted(null)));
console.log(ta.with(0, 9).join(), ta.with(-1, 7).join(), ta.with(1, '5').join(), attempt(() => ta.with(3, 0)), attempt(() => ta.with(-4, 0)), ta.join());
console.log(new BigInt64Array([1n, 2n]).with(1, 5n).join(), attempt(() => new BigInt64Array([1n]).with(0, 1)), new Uint8ClampedArray([1]).with(0, 300).join());
class MyArray extends Uint8Array { static get [Symbol.species]() { throw new Error('species read'); } }
var mine = new MyArray([1, 2]);
console.log(mine.toReversed().constructor.name, mine.toSorted().constructor.name, mine.with(0, 3).constructor.name);
var calls = [];
var valueObject = { valueOf() { calls.push('value'); return 4; } };
var indexObject = { valueOf() { calls.push('index'); return 0; } };
console.log(ta.with(indexObject, valueObject).join(), calls.length);
var TAP = Object.getPrototypeOf(Uint8Array.prototype);
console.log(TAP.toReversed.length, TAP.toSorted.length, TAP.with.length, TAP.with.name, attempt(() => TAP.toReversed.call([1, 2])), attempt(() => TAP.with.call({}, 0, 0)));"#;
    assert_eq!(
        console_lines(source),
        [
            r#"2,1,3 1,2,3 3,1,2 true true true"#,
            r#"0,1,2,NaN 3,2,1 TypeError"#,
            r#"9,1,2 3,1,7 3,5,2 RangeError RangeError 3,1,2"#,
            r#"1,5 TypeError 255"#,
            r#"Uint8Array Uint8Array Uint8Array"#,
            r#"4,1,2 2"#,
            r#"0 1 2 with TypeError TypeError"#,
        ]
    );
}

#[test]
fn with_converts_the_index_before_the_value_bd_9vouw_258() {
    let source = r#"var logs = [];
var index = { valueOf() { logs.push('index'); return 0; } };
var value = { valueOf() { logs.push('value'); return 0; } };
new Uint8Array(1).with(index, value);
console.log(logs.join());"#;
    assert_eq!(console_lines(source), ["index,value"]);
}
