//! Regression coverage for the final bd-962ev.2 methods: receiver-aware
//! `Array.prototype.reduce`, `reduceRight`, and `sort` on the `HybridRouter`
//! method seam. reduce/reduceRight reuse `invoke_simple_reduce_callback`; sort
//! supports a user comparator (sign of its result) via a manual insertion sort
//! and falls back to lexicographic ToString ordering.
//!
//! Value-asserting through `HybridRouter::eval`.

use frankenengine_engine::HybridRouter;

fn eval_value(src: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(src)
        .unwrap_or_else(|e| panic!("eval failed for {src:?}: {e}"));
    format!("{outcome:?}")
        .split("value: \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn reduce_folds_left_with_and_without_initial() {
    assert_eq!(
        eval_value("[1, 2, 3, 4].reduce(function(a, b) { return a + b; }, 0);"),
        "10"
    );
    // no initial value: first element seeds the accumulator.
    assert_eq!(
        eval_value("[1, 2, 3, 4].reduce(function(a, b) { return a + b; });"),
        "10"
    );
    assert_eq!(
        eval_value("[1, 2, 3, 4].reduce(function(a, b) { return a + b; }, 100);"),
        "110"
    );
    // single element, no initial: returned without calling the callback.
    assert_eq!(
        eval_value("[7].reduce(function(a, b) { return a + b; });"),
        "7"
    );
}

#[test]
fn reduce_right_folds_from_the_end() {
    // 10 - 3 - 2 - 1 = 4 (right-to-left).
    assert_eq!(
        eval_value("[1, 2, 3].reduceRight(function(a, b) { return a - b; }, 10);"),
        "4"
    );
    // visit order 3,2,1 encoded positionally: ((0*10+3)*10+2)*10+1 = 321.
    assert_eq!(
        eval_value("[1, 2, 3].reduceRight(function(a, b) { return a * 10 + b; }, 0);"),
        "321"
    );
}

#[test]
fn reduce_and_reduce_right_accept_first_class_builtin_callbacks() {
    // Array.isArray observes the accumulator (callback argument 0), so these
    // cases also pin the callback argument order with an explicit initial value.
    assert_eq!(eval_value("[1].reduce(Array.isArray, []);"), "true");
    assert_eq!(eval_value("[1].reduceRight(Array.isArray, {});"), "false");

    // Without an initial value, reduce seeds from the left and reduceRight
    // seeds from the right before invoking the builtin callback.
    assert_eq!(eval_value("[[1], 2].reduce(Array.isArray);"), "true");
    assert_eq!(eval_value("[2, [1]].reduceRight(Array.isArray);"), "true");
}

#[test]
fn sort_default_is_lexicographic() {
    assert_eq!(eval_value("let a = [3, 1, 2]; a.sort(); a[0];"), "1");
    assert_eq!(eval_value("let a = [3, 1, 2]; a.sort(); a[2];"), "3");
    // ToString ordering: 1, 10, 2 (not numeric).
    assert_eq!(eval_value("let a = [10, 2, 1]; a.sort(); a[1];"), "10");
    // sort returns the array itself.
    assert_eq!(
        eval_value("let a = [3, 1, 2]; let b = a.sort(); b[0];"),
        "1"
    );
}

#[test]
fn sort_with_comparator_orders_numerically() {
    // ascending numeric comparator.
    assert_eq!(
        eval_value("let a = [10, 2, 1]; a.sort(function(x, y) { return x - y; }); a[0];"),
        "1"
    );
    assert_eq!(
        eval_value("let a = [10, 2, 1]; a.sort(function(x, y) { return x - y; }); a[2];"),
        "10"
    );
    // descending comparator.
    assert_eq!(
        eval_value("let a = [1, 2, 3]; a.sort(function(x, y) { return y - x; }); a[0];"),
        "3"
    );
    assert_eq!(
        eval_value("let a = [1, 2, 3]; a.sort(function(x, y) { return y - x; }); a[2];"),
        "1"
    );
}

/// bd-9vouw.265: `Array.prototype.sort` on an Array follows ES2023
/// 23.1.3.30 when its element storage cannot stand in for the spec steps:
/// holes are skipped and deleted after the sorted values (they became own
/// `undefined` elements), element setters run, an object element's ToString
/// calls its `toString` (it was ordered as ""), a comparator that is
/// neither undefined nor callable is a TypeError even for 0 or 1 elements,
/// a frozen array throws, and strings order by UTF-16 code units (an astral
/// character sorts before U+FFFF), as `toSorted` does too. Expected lines
/// are Node v22.2.0's output, captured programmatically; Bun 1.4.2 agrees.
#[test]
fn array_sort_runs_spec_steps_on_irregular_arrays_bd_9vouw_265() {
    let source = r#"function attempt(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
var holes = [3, , 1, undefined, , 2];
holes.sort();
console.log(holes.length, JSON.stringify(Object.keys(holes)), String(holes), 4 in holes, 5 in holes);
var sparse = [];
sparse[5] = 'e'; sparse[2] = 'b'; sparse[9] = 'a';
sparse.sort();
console.log(sparse.length, JSON.stringify(Object.keys(sparse)), String(sparse));
var calls = 0;
var counted = { toString: function () { calls++; return 'x'; } };
[counted, counted].sort();
console.log(calls > 0, String([{ toString: function () { return 'b'; } }, { toString: function () { return 'a'; } }].sort()));
console.log(attempt(function () { return [].sort({}); }), attempt(function () { return [1].sort(null); }), attempt(function () { return [2, 1].sort(1); }));
var log = [];
var accessors = [3, 2, 1];
Object.defineProperty(accessors, '1', { get: function () { log.push('get'); return 2; }, set: function (v) { log.push('set' + v); }, configurable: true });
accessors.sort();
console.log(log.join(','), String([accessors[0], accessors[2]]));
console.log(JSON.stringify(['￿', '😀', 'a'].sort()), JSON.stringify(['￿', '😀'].toSorted()));
var frozen = Object.freeze([2, 1]);
console.log(attempt(function () { return frozen.sort(); }), String(frozen));
Array.prototype[0] = 'z';
var inherit = [, 'a'];
inherit.sort();
delete Array.prototype[0];
console.log(JSON.stringify(inherit), inherit.hasOwnProperty(0), inherit.hasOwnProperty(1));
console.log(String([10, 9, 1, 100].sort()), String([10, 9, 1, 100].sort(function (a, b) { return a - b; })), String([true, null, 'm', 0.5, -0].sort()));
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
            "6 [\"0\",\"1\",\"2\",\"3\"] 1,2,3,,, false false",
            "10 [\"0\",\"1\",\"2\"] a,b,e,,,,,,,",
            "true a,b",
            "TypeError TypeError TypeError",
            "get,set2 1,3",
            "[\"a\",\"\u{1f600}\",\"\u{ffff}\"] [\"\u{1f600}\",\"\u{ffff}\"]",
            "TypeError 2,1",
            "[\"a\",\"z\"] true true",
            "1,10,100,9 1,9,10,100 0,0.5,m,,true",
        ]
    );
}

/// bd-9vouw.276: Array.prototype.copyWithin runs the spec steps (ES2020
/// 23.1.3.3) on a primitive or array-like `this`, an Array with holes,
/// accessors or read-only elements, and index arguments that are objects:
/// the length is read first, the indices convert in order (a valueOf may
/// shrink the array), and each element moves with HasProperty, Get and
/// Set or DeletePropertyOrThrow, backwards when the ranges overlap. It
/// accepted only Arrays and read their storage. Expected lines are Node
/// v22.2.0's output, captured programmatically; Bun 1.4.2 agrees.
#[test]
fn array_copy_within_runs_the_spec_steps_bd_9vouw_276() {
    let source = r#"function kind(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
console.log(String([1, 2, 3, 4, 5].copyWithin(0, 3)), String([1, 2, 3, 4, 5].copyWithin(1, 0, 3)), String([1, 2, 3, 4, 5].copyWithin(-2, -4, -1)), JSON.stringify(Object.keys([1, , 3, 4].copyWithin(0, 1))), typeof Array.prototype.copyWithin.call(true, 0, 0));
var arrayLike = { length: 4, 0: 'a', 1: 'b', 3: 'd' };
Array.prototype.copyWithin.call(arrayLike, 1, 0);
console.log(JSON.stringify(arrayLike));
var log = [];
var arr = [0, 1, 2, 3, 4];
console.log(String(arr.copyWithin({ valueOf: function () { log.push('target'); arr.length = 3; return 0; } }, { valueOf: function () { log.push('start'); return 1; } })), log.join());
var frozen = Object.freeze([1, 2, 3]);
console.log(kind(function () { return frozen.copyWithin(0, 1); }), kind(function () { return Array.prototype.copyWithin.call({ get length() { throw new RangeError('len'); } }, 0, 0); }), kind(function () { return Array.prototype.copyWithin.call({ length: Symbol() }, 0, 0); }));
var withSetter = [1, 2, 3];
Object.defineProperty(withSetter, 0, { set: function (v) { throw new EvalError('set ' + v); }, configurable: true });
var sealedHole = Object.seal([ , 2]);
console.log(kind(function () { return withSetter.copyWithin(0, 1); }), kind(function () { return Object.defineProperty([1, 2], 0, { configurable: false }).copyWithin(0, 2, 3); }), kind(function () { var a = [ , 1]; Object.defineProperty(a, 1, { value: 1, configurable: false }); return a.copyWithin(1, 0); }));
var p = new Proxy([1, 2, 3], { has: function (t, k) { if (k === '1') throw new SyntaxError('has'); return Reflect.has(t, k); } });
console.log(kind(function () { return Array.prototype.copyWithin.call(p, 0, 1); }), String([].copyWithin(0, 0)), String([1, 2].copyWithin(5, 0)));
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
            "4,5,3,4,5 1,1,2,3,5 1,2,3,2,3 [\"1\",\"2\",\"3\"] object",
            "{\"0\":\"a\",\"1\":\"a\",\"2\":\"b\",\"length\":4}",
            "1,2, target,start",
            "TypeError RangeError TypeError",
            "EvalError 1,2 TypeError",
            "SyntaxError  1,2",
        ]
    );
}
