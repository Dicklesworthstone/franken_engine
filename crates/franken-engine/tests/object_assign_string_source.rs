#![forbid(unsafe_code)]

//! ES2020 19.1.2.1 Object.assign: a string source is ToObject'd, so its
//! code units are own enumerable index properties copied with
//! Set(to, key, value, true). The engine skipped string sources (4
//! Node-passing Test262 tests in the rc-next33 merged-tree census:
//! Object/assign/{Source-String,Override,Override-notstringtarget,
//! target-Array}).

use frankenengine_engine::HybridRouter;

/// String sources among other primitives and objects, onto objects, arrays,
/// a String wrapper (read-only indices: TypeError), a frozen object, through
/// setters, an empty string and a surrogate pair (two code units). Expected
/// lines are Node v22.2.0's output, captured programmatically.
#[test]
fn assign_copies_string_source_indices() {
    let source = r#"function k(f) { try { return JSON.stringify(f()); } catch (e) { return e.constructor.name; } }
console.log(JSON.stringify(Object.assign({}, 'ab', null, undefined, 1, true, [7], { x: 1 })), JSON.stringify(Object.assign({ a: 1 }, 'xyz')), JSON.stringify(Object.assign([], 'hi')));
console.log(k(function () { return Object.assign('a', 'b'); }), k(function () { return Object.assign(Object.freeze({}), 'q'); }), k(function () { return Object.assign({}, ''); }), JSON.stringify(Object.assign({}, '😀')));
var log = [];
var target = { set 0(v) { log.push('0=' + v); }, set 1(v) { log.push('1=' + v); } };
Object.assign(target, 'xy');
console.log(log.join(','));
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
            "{\"0\":7,\"1\":\"b\",\"x\":1} {\"0\":\"x\",\"1\":\"y\",\"2\":\"z\",\"a\":1} [\"h\",\"i\"]",
            "TypeError TypeError {} {\"0\":\"\\ud83d\",\"1\":\"\\ude00\"}",
            "0=x,1=y",
        ]
    );
}

/// [[Set]] onto an array index grows the array's length for every caller,
/// not only the SetProperty instruction: Object.assign from an array or
/// object source (cli-table3 sizes its columns with
/// `Object.assign(vals, result, auto)`, so every cell was truncated to
/// '…'), Reflect.set, and a Proxy over an array. The elements were stored
/// but length stayed 0. Expected lines are Node v22.2.0's output, captured
/// programmatically.
#[test]
fn set_onto_an_array_index_grows_its_length() {
    let source = r#"var a = []; Object.assign(a, [4, 4]); var r = []; r[0] = 3; r[1] = 5; var b = Object.assign([], r, {}); var c = [1]; Object.assign(c, { 2: 9 });
console.log(a.length, JSON.stringify(a), b.length, c.length, JSON.stringify(c), JSON.stringify(Object.assign([], { 0: 'z' })));
var d = []; console.log(Reflect.set(d, 0, 5), d.length, Reflect.set(d, '3', 6), d.length, JSON.stringify(d));
var p = new Proxy([], {}); Object.assign(p, [1, 2]); console.log(p.length);
var widths = []; Object.assign(widths, [4, 4], {}); for (var j = 0; j < widths.length; j++) widths[j] = Math.max(1, widths[j] || 0); console.log(JSON.stringify(widths));
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
            "2 [4,4] 2 3 [1,null,9] [\"z\"]",
            "true 1 true 4 [5,null,null,6]",
            "2",
            "[4,4]",
        ]
    );
}
