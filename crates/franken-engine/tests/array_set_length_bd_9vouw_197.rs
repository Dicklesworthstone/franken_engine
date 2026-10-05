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
