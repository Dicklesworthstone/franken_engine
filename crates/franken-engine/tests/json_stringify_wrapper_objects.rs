#![forbid(unsafe_code)]

//! ES2020 24.5.2 JSON.stringify with Number and String wrapper objects: a
//! wrapper value is ToNumber'd / ToString'd (SerializeJSONProperty step 4),
//! a wrapper replacer-array item ToString'd (step 4.b.iii.5.e) and a wrapper
//! space ToNumber'd / ToString'd (step 5), so their valueOf / toString run.
//! The engine serialized a wrapper's internal primitive and ignored wrapper
//! replacer items and spaces (7 Node-passing Test262 tests in the
//! rc-next33 merged-tree census: replacer-array-{number,string}-object,
//! space-{number,string}-object, space-number-float, value-{number,string}-
//! object).

use frankenengine_engine::HybridRouter;

/// Wrapper values with overridden valueOf / toString, wrapper replacer
/// items and spaces, abrupt conversions, and a plain-object space (ignored).
/// Expected lines are Node v22.2.0's output, captured programmatically.
#[test]
fn json_stringify_converts_wrapper_objects() {
    let source = r#"function k(f) { try { return f(); } catch (e) { return e.constructor.name + ':' + e.message; } }
var num = new Number(42);
num.toString = function () { throw new Error('toString'); };
num.valueOf = function () { return 2; };
var str = new String('str');
str.toString = function () { return 'toString'; };
str.valueOf = function () { throw new Error('valueOf'); };
console.log(JSON.stringify([num, str, new Number(8.5), new String('x'), new Boolean(false)]));
var keyNum = new Number(10);
keyNum.toString = function () { return 'toString'; };
console.log(JSON.stringify({ 10: 1, toString: 2, valueOf: 3 }, [keyNum]), JSON.stringify({ a: 1, b: 2 }, [new String('b')]));
var space = new Number(3.7);
space.valueOf = function () { return 2; };
var spaceStr = new String('--');
spaceStr.toString = function () { return '..'; };
function lines(text) { return text.split('\n').join('|'); }
console.log(lines(JSON.stringify({ a: [1] }, null, space)), lines(JSON.stringify({ a: 1 }, null, spaceStr)), lines(JSON.stringify({ a: 1 }, null, new Number(1))));
var bad = new Number(1);
bad.valueOf = function () { throw new Error('boom'); };
console.log(k(function () { return JSON.stringify([bad]); }), k(function () { return JSON.stringify({}, null, bad); }), JSON.stringify({ a: 1 }, null, { valueOf: function () { return 4; } }));
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
            "[2,\"toString\",8.5,\"x\",false]",
            "{\"toString\":2} {\"b\":2}",
            "{|  \"a\": [|    1|  ]|} {|..\"a\": 1|} {| \"a\": 1|}",
            "Error:boom Error:boom {\"a\":1}",
        ]
    );
}
