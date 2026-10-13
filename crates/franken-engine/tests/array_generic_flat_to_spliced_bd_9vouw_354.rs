//! bd-9vouw.354: Array.prototype.flat, flatMap and toSpliced run generically
//! on a receiver that is not an Array (ES2019 22.1.3.10-11, ES2023
//! 23.1.3.35): a primitive `this` is boxed (it was a TypeError), and a Proxy
//! or an array-like is read through [[HasProperty]] and [[Get]], so traps and
//! getters run in the spec's order (flat reads `length`, the species
//! `constructor`, then has/get per index). toReversed, toSorted, with and
//! toSpliced throw ArrayCreate's RangeError for a length past 2^32 - 1
//! before buffering it (the run died with "memory budget exceeded"), and
//! toSpliced's new length past 2^53 - 1 is a TypeError. The line is Node
//! v22.2.0's (Bun 1.4.2 agrees).
//!
//! No-claim: a typed array as the `this` of these Array methods keeps the
//! ordinary path.

use frankenengine_engine::HybridRouter;

#[test]
fn flat_flatmap_and_to_spliced_run_generically() {
    let source = r#"
var out = [];
function t(name, f) { try { out.push(name + ':' + JSON.stringify(f())); } catch (e) { out.push(name + ':' + e.constructor.name); } }
var AP = Array.prototype;
var huge = { length: Math.pow(2, 32) };
t('toReversed-huge', function () { return AP.toReversed.call(huge).length; });
t('with-huge', function () { return AP.with.call(huge, 0, 1).length; });
t('toSorted-huge', function () { return AP.toSorted.call(huge).length; });
t('toSpliced-huge', function () { return AP.toSpliced.call(huge, 0, 0).length; });
t('toSpliced-maxsafe', function () { return AP.toSpliced.call({ length: Math.pow(2, 53) - 1 }, 0, 0, 1).length; });
t('flat-bool', function () { return AP.flat.call(true); });
t('flatMap-num', function () { return AP.flatMap.call(5, function (x) { return x; }); });
t('toSpliced-str', function () { return AP.toSpliced.call('abc', 1, 1, 'X'); });
t('flat-str', function () { return AP.flat.call('ab'); });
var alike = { length: 4, 0: [1, [2]], 1: { length: 1, 0: 'no' }, 3: [[3, [4]]] };
t('flat-alike', function () { return AP.flat.call(alike); });
t('flat-alike-inf', function () { return AP.flat.call(alike, Infinity); });
t('flat-alike-0', function () { return AP.flat.call(alike, 0).length; });
t('flat-neg', function () { return AP.flat.call(alike, -3).length; });
t('flatMap-alike', function () { return AP.flatMap.call({ length: 3, 0: 1, 2: 3 }, function (x, i, o) { return [x, i, typeof o]; }); });
t('flatMap-this', function () { return AP.flatMap.call({ length: 1, 0: 2 }, function (x) { return this.k * x; }, { k: 21 }); });
var log = [];
var getterObj = { get length() { log.push('len'); return 2; }, get 0() { log.push('g0'); return [7]; }, get 1() { log.push('g1'); return 8; } };
t('flatMap-getters', function () { return AP.flatMap.call(getterObj, function (x) { log.push('cb'); return x; }); });
t('flatMap-getters-log', function () { return log.join(','); });
var log2 = [];
var noncallable = { get length() { log2.push('len'); return 1; } };
t('flatMap-noncallable', function () { return AP.flatMap.call(noncallable, null); });
t('flatMap-noncallable-log', function () { return log2.join(','); });
t('flatMap-symlen', function () { return AP.flatMap.call({ length: Symbol() }, function (x) { return x; }); });
var traps = [];
var p = new Proxy([1, [2, 3], 4], { get: function (tg, k, r) { traps.push(typeof k === 'symbol' ? 'sym' : k); return Reflect.get(tg, k, r); }, has: function (tg, k) { traps.push('has:' + k); return Reflect.has(tg, k); } });
t('flat-proxy', function () { return AP.flat.call(p); });
t('flat-proxy-traps', function () { return traps.join(','); });
t('toSpliced-holes', function () { return AP.toSpliced.call({ length: 3, 1: 'b' }, 1, 0, 'x'); });
t('toSpliced-tolength', function () { return AP.toSpliced.call({ length: 2.5, 0: 0, 1: 1, 2: 2 }); });
t('toSpliced-neg', function () { return AP.toSpliced.call({ length: 4, 0: 'a', 1: 'b', 2: 'c', 3: 'd' }, -2, 1); });
t('real-flat', function () { return [1, [2, [3, [4]]]].flat(2); });
t('real-toSpliced', function () { return [1, 2, 3].toSpliced(1, 1, 'z'); });
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
            "toReversed-huge:RangeError with-huge:RangeError toSorted-huge:RangeError toSpliced-huge:RangeError toSpliced-maxsafe:TypeError flat-bool:[] flatMap-num:[] toSpliced-str:[\"a\",\"X\",\"c\"] flat-str:[\"a\",\"b\"] flat-alike:[1,[2],{\"0\":\"no\",\"length\":1},[3,[4]]] flat-alike-inf:[1,2,{\"0\":\"no\",\"length\":1},3,4] flat-alike-0:3 flat-neg:3 flatMap-alike:[1,0,\"object\",3,2,\"object\"] flatMap-this:[42] flatMap-getters:[7,8] flatMap-getters-log:\"len,g0,cb,g1,cb\" flatMap-noncallable:TypeError flatMap-noncallable-log:\"len\" flatMap-symlen:TypeError flat-proxy:[1,2,3,4] flat-proxy-traps:\"length,constructor,has:0,0,has:1,1,has:2,2\" toSpliced-holes:[null,\"x\",\"b\",null] toSpliced-tolength:[0,1] toSpliced-neg:[\"a\",\"b\",\"d\"] real-flat:[1,2,3,[4]] real-toSpliced:[1,\"z\",3]"
        ]
    );
}
