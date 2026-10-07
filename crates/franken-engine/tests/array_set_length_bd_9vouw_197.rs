#![forbid(unsafe_code)]

//! bd-9vouw.197: ES2020 9.4.2.4 ArraySetLength deletes elements from the end
//! and stops at the first one that cannot be deleted: a non-configurable
//! element keeps `length` one past it and the write fails (silently in
//! sloppy code, a TypeError in strict code). `arr.length = 2` deleted a
//! non-configurable index 2. Test262
//! built-ins/Array/prototype/filter/15.4.4.20-9-b-16.js turned red once
//! accessor elements were read through their getters (bd-9vouw.182): its
//! getter shrinks the array mid-filter.
//!
//! Expected lines are Node v22.2.0's output. Bun 1.4.2 deviates: it throws
//! "Unable to delete property" for the sloppy write too.

use frankenengine_engine::HybridRouter;

#[test]
fn array_length_writes_stop_at_non_configurable_elements() {
    let source = "var arr = [0, 1, 2];\nObject.defineProperty(arr, '2', { get: function () { return 'u'; }, configurable: false });\narr.length = 2;\nconsole.log(arr.length, arr[2]);\nvar b = [0, 1, 2, 3, 4];\nObject.defineProperty(b, '2', { value: 'x', configurable: false });\nb.length = 0;\nconsole.log(b.length, JSON.stringify(b));\nvar c = [1, 2, 3]; c.length = 1; console.log(c.length, JSON.stringify(c));\n(function () { 'use strict'; var s = [0, 1]; Object.defineProperty(s, '1', { value: 1, configurable: false }); try { s.length = 0; console.log('no error'); } catch (e) { console.log(e.name, s.length); } })();\n";
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, ["3 u", "3 [0,1,\"x\"]", "1 [1]", "TypeError 2"]);
}

/// bd-9vouw.279: Object.defineProperty(array, 'length', { value }) is
/// ArraySetLength: the value goes through ToUint32 and ToNumber (an
/// object's valueOf twice, a string by StringToNumber), a shrink stops past
/// a non-configurable element and is rejected, and writable: false applies
/// after the deletions. An index at or past a non-writable length can be
/// neither defined nor assigned. Expected lines: Node v22.2.0's output,
/// captured programmatically.
#[test]
fn define_array_length_is_array_set_length_bd_9vouw_279() {
    let source = r#"function k(f) { try { return String(f()); } catch (e) { return e.constructor.name; } }
function d(a) { var x = Object.getOwnPropertyDescriptor(a, 'length'); return x.value + (x.writable ? 'w' : 'r'); }
var a = [0, 1];
Object.defineProperty(a, '1', { value: 1, configurable: false });
console.log(k(function () { Object.defineProperty(a, 'length', { value: 1 }); }), d(a), a.join());
var b = [0, 1, 2];
Object.defineProperty(b, '1', { configurable: false });
console.log(k(function () { Object.defineProperty(b, 'length', { value: 0, writable: false }); }), d(b), b.join(), k(function () { return Reflect.defineProperty(b, 'length', { value: 0 }); }));
var c = [];
Object.defineProperty(c, 'length', { value: '0x00B' });
var calls = 0;
var e = [1, 2, 3];
Object.defineProperty(e, 'length', { value: { valueOf: function () { calls++; return 2; } } });
console.log(d(c), d(e), calls, k(function () { Object.defineProperty([], 'length', { value: '1.5' }); }), k(function () { Object.defineProperty([], 'length', { value: { valueOf: function () { return -1; } } }); }));
var f = [1, 2];
Object.defineProperty(f, 'length', { writable: false });
console.log(k(function () { Object.defineProperty(f, '5', { value: 1 }); }), k(function () { return Reflect.defineProperty(f, '2', { value: 1 }); }), k(function () { f[3] = 1; return f[3]; }), k(function () { 'use strict'; f[4] = 1; }), d(f), k(function () { return Reflect.defineProperty(f, 'length', { value: 2 }); }), k(function () { return Reflect.defineProperty(f, 'length', { value: 2, writable: true }); }), k(function () { return Reflect.defineProperty(f, '1', { value: 9 }); }), f.join());
var g = [1, 2, 3, 4];
Object.defineProperty(g, 'length', { value: 2, writable: false });
console.log(d(g), g.join(), k(function () { return Reflect.defineProperty(g, 'length', { value: 4 }); }), k(function () { return Reflect.defineProperty(g, 'length', { value: 2, enumerable: true }); }));
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
            "TypeError 2w 0,1",
            "TypeError 2r 0,1 false",
            "11w 2w 2 RangeError RangeError",
            "TypeError false undefined TypeError 2r true false true 1,9",
            "2r 1,2 false false",
        ]
    );
}
