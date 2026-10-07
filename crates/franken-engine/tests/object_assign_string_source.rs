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
