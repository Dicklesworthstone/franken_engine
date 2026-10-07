#![forbid(unsafe_code)]

//! Map, Set, WeakMap and WeakSet construct through every construction path (a
//! constructor read as a value, Reflect.construct with and without a newTarget,
//! a derived class's super()) while a call (plain, Reflect.apply, .call) throws
//! a TypeError. The construct paths fell back to the call path for these
//! names, which b98fb79d4 made throw.

use frankenengine_engine::HybridRouter;

/// Expected lines are Node v22.2.0's output, captured programmatically from the
/// same source.
#[test]
fn collections_construct_on_every_path_and_throw_when_called() {
    let source = r#"const M = Map, S = Set, WM = WeakMap, WS = WeakSet;
const key = {};
console.log(new M([[1, 2]]).size, new S([1, 1, 2]).size, new WM([[key, 1]]).get(key), new WS([key]).has(key));
console.log(Reflect.construct(Map, [[[1, 2]]]).get(1), Reflect.construct(Set, [[3]]).has(3), Reflect.construct(WeakMap, []) instanceof WeakMap, Reflect.construct(WeakSet, []) instanceof WeakSet);
class SubMap extends Map {}
class SubWeakMap extends WeakMap {}
class SubWeakSet extends WeakSet {}
const sub = Reflect.construct(Map, [[[5, 6]]], SubMap);
console.log(new SubMap([[1, 2]]).get(1), new SubWeakMap([[key, 7]]).get(key), new SubWeakSet([key]).has(key), sub instanceof SubMap, sub.get(5));
function attempt(f) { try { f(); return 'none'; } catch (e) { return e.constructor.name; } }
console.log(attempt(function () { M(); }), attempt(function () { Reflect.apply(Set, undefined, []); }), attempt(function () { WM.call({}); }));
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
            "1 2 1 true",
            "2 true true true",
            "2 7 true true 6",
            "TypeError TypeError TypeError",
        ]
    );
}
