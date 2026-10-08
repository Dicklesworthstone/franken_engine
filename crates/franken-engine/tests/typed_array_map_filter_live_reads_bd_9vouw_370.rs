//! bd-9vouw.370: %TypedArray%.prototype.map and filter read each element
//! when its step runs (ES2024 23.2.3.22, 23.2.3.10): a callback that
//! writes a later element, or shrinks a resizable buffer (later reads are
//! undefined), and a species constructor that shrinks the receiver all
//! show in the values the callbacks see. map Sets each mapped value as its
//! step runs, converting it then (an object's valueOf runs between
//! callbacks). Every element was read before the first callback, and map
//! wrote its results after the last one without running valueOf. The
//! line is Node v22.2.0's output for the same program.

use frankenengine_engine::HybridRouter;

#[test]
fn typed_array_map_and_filter_read_each_element_when_its_step_runs() {
    let source = r#"
var out = [];
var s = new Int8Array([42, 43, 44]);
var seen = []; s.map(function (v, i) { if (i < s.length - 1) s[i + 1] = 42; seen.push(v); return 0; }); out.push(seen.join());
var f = new Int8Array([42, 43, 44]); seen = []; var kept = f.filter(function (v, i) { if (i < f.length - 1) f[i + 1] = 7; seen.push(v); return v > 10; }); out.push(seen.join() + "/" + kept.join());
var rab = new ArrayBuffer(4, { maxByteLength: 8 }); var ta = new Uint8Array(rab); ta.set([1, 2, 3, 4]); seen = []; var m = ta.map(function (v, i) { if (i === 1) rab.resize(2); seen.push(String(v)); return v * 10; }); out.push(seen.join() + "/" + m.join() + "/" + m.length);
var rab2 = new ArrayBuffer(4, { maxByteLength: 8 }); var tb = new Uint8Array(rab2); tb.set([5, 6, 7, 8]); seen = []; var k2 = tb.filter(function (v, i) { if (i === 0) rab2.resize(2); seen.push(String(v)); return true; }); out.push(seen.join() + "/" + k2.length);
var log = []; var conv = new Int16Array([1, 2]).map(function (v) { log.push("cb" + v); return { valueOf: function () { log.push("conv" + v); return v * 3; } }; }); out.push(log.join() + "/" + conv.join());
var big = new BigInt64Array([1n, 2n]).map(function (v) { return v * 5n; }); out.push(big.join() + " " + big.constructor.name);
var src = new Uint8Array(new ArrayBuffer(4, { maxByteLength: 8 })); src.set([9, 8, 7, 6]); var calls = []; src.constructor = {}; src.constructor[Symbol.species] = function (n) { src.buffer.resize(1); return new Uint8Array(n); }; var sm = src.map(function (v, i) { calls.push(String(v)); return 1; }); out.push(calls.join() + "/" + sm.join());
console.log(out.join(' | '));
"#;
    let outcome = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"));
    let lines: Vec<&str> = outcome
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect();
    assert_eq!(
        lines,
        [
            "42,42,42 | 42,7,7/42 | 1,2,undefined,undefined/10,20,0,0/4 | 5,6,undefined,undefined/4 | cb1,conv1,cb2,conv2/3,6 | 5,10 BigInt64Array | 9,undefined,undefined,undefined/1,1,1,1",
        ]
    );
}
