#![forbid(unsafe_code)]

//! bd-9vouw.289: an object literal getter or setter named `yield` inside a
//! generator was refused by lowering (FE-LOWER-UNSUPPORTED-STATIC-OBJECT-
//! KEY-0001): its key parsed as a yield expression (5 Node-passing Test262
//! yield-as-literal-property-name tests).

use frankenengine_engine::HybridRouter;

/// `yield` as a data, method, getter and setter key inside generators
/// (functions, class methods), other contextual words as keys, and `await`
/// accessors inside an async function. Expected lines are Node v22.2.0's
/// output, captured programmatically (Bun 1.4.2 agrees).
#[test]
fn object_accessor_keys_match_node_bd_9vouw_289() {
    let source = r#"function* g1() { return ({ yield: 1 }).yield; }
function* g2() { return ({ yield() { return 2; } }).yield(); }
function* g3() { return ({ get yield() { return 3; } }).yield; }
function* g4() { return ({ set yield(v) { this.v = v; } }); }
function* g5() { var o = { await: 5, async: 6, get: 7, set: 8, static: 9 }; return o.await + o.async + o.get + o.set + o.static; }
function* g6() { class K { yield() { return 6; } static get yield() { return 66; } } return new K().yield() + K.yield; }
function* g7() { var o = {}; o.yield = 7; return o.yield; }
console.log(g1().next().value, g2().next().value, g3().next().value, typeof g4().next().value, g5().next().value, g6().next().value, g7().next().value);
async function a1() { return ({ get await() { return 8; }, set await(v) {} }).await; }
a1().then(function (v) { console.log('await getter', v); });
"#;
    let lines: Vec<String> = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect();
    assert_eq!(lines, ["1 2 3 object 35 72 7", "await getter 8",]);
}
