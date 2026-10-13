//! bd-9vouw.341: Array.prototype[Symbol.unscopables] is a null-prototype
//! object whose own `true` data properties name the methods a `with` body
//! does not resolve on an array (ES2020 22.1.3.32 and later editions'
//! names), held in a non-writable, non-enumerable, configurable property
//! listed after Symbol.iterator. The engine had none and emulated it in
//! `with` with a hard-coded list, so reading it gave undefined and deleting
//! it changed nothing. `with` still resolves `keys` and `values` outward
//! (also past an own `keys`), `concat` on the array, and after the delete
//! `keys` on the array. Node v22.2.0 gives this line.

use frankenengine_engine::HybridRouter;

#[test]
fn array_prototype_has_an_unscopables_object() {
    let source = r#"
var out = [];
var u = Array.prototype[Symbol.unscopables];
var d = Object.getOwnPropertyDescriptor(Array.prototype, Symbol.unscopables);
out.push(typeof u, Object.getPrototypeOf(u) === null, Object.keys(u).join(','));
out.push(d.writable, d.enumerable, d.configurable, u === Array.prototype[Symbol.unscopables]);
out.push(JSON.stringify(Object.getOwnPropertyDescriptor(u, 'flat')));
out.push(Reflect.ownKeys(Array.prototype).filter(function (k) { return typeof k === 'symbol'; }).map(String).join(','));
var keys = 'outer', values = 'outerV', concat = 'outerC';
with ([]) { out.push(keys, values, typeof concat); }
var arr = [];
arr.keys = 'own';
with (arr) { out.push(keys); }
delete Array.prototype[Symbol.unscopables];
with ([]) { out.push(typeof keys); }
console.log(out.join(' '));
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
            "object true at,copyWithin,entries,fill,find,findIndex,findLast,findLastIndex,flat,\
             flatMap,includes,keys,toReversed,toSorted,toSpliced,values false false true true \
             {\"value\":true,\"writable\":true,\"enumerable\":true,\"configurable\":true} \
             Symbol(Symbol.iterator),Symbol(Symbol.unscopables) outer outerV function outer function"
        ]
    );
}
