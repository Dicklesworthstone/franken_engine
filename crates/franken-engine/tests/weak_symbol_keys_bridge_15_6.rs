#![forbid(unsafe_code)]

//! BRIDGE-15.6 (slice): Symbols as WeakMap keys and WeakSet values (ES2023
//! CanBeHeldWeakly). WeakMap.prototype.set and WeakSet.prototype.add threw a
//! TypeError for every symbol (16 Node-passing Test262 tests in the
//! rc-next33 merged-tree census).

use frankenengine_engine::HybridRouter;

/// A symbol outside the global registry (a fresh `Symbol()` or a
/// well-known symbol) is a valid key: set / get / has / delete, the
/// iterable constructors, and re-setting a key; a `Symbol.for` symbol and
/// other primitives stay TypeErrors for set / add and answer false or
/// undefined elsewhere. Expected lines are Node v22.2.0's output, captured
/// programmatically.
///
/// No-claim: symbol-keyed entries are held strongly (the engine never
/// reclaims a symbol); collection is unobservable either way.
#[test]
fn symbols_are_weak_collection_keys_bridge_15_6() {
    let source = r#"function k(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } }
var wm = new WeakMap(), ws = new WeakSet(), s = Symbol('k'), wk = Symbol.iterator, reg = Symbol.for('reg');
wm.set(s, 1);
wm.set(wk, 2);
console.log(wm.get(s), wm.has(s), wm.get(wk), wm.has(Symbol('k')), wm.delete(s), wm.has(s), wm.get(reg));
console.log(k(function () { wm.set(reg, 1); }), k(function () { ws.add(reg); }), wm.has(reg), ws.has(reg), wm.delete(reg), ws.delete(reg));
ws.add(s);
console.log(ws.has(s), ws.has(wk), ws.delete(s), ws.has(s), ws.add(wk) === ws, ws.has(wk));
var wm2 = new WeakMap([[s, 'a'], [{}, 'b'], [wk, 'c']]);
var ws2 = new WeakSet([s, wk]);
console.log(wm2.get(s), wm2.get(wk), ws2.has(wk), ws2.has(s), k(function () { new WeakMap([[reg, 1]]); }), k(function () { new WeakSet([reg]); }));
var o = {};
wm.set(o, 'obj');
wm.set(s, 'again');
console.log(wm.get(o), wm.get(s), k(function () { wm.set(1, 1); }), k(function () { ws.add('x'); }), wm.has(1), ws.has('x'));
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
            "1 true 2 false true false undefined",
            "TypeError TypeError false false false false",
            "true false true false true true",
            "a c true true TypeError TypeError",
            "obj again TypeError TypeError false false",
        ]
    );
}
