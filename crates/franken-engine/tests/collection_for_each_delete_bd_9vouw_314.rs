//! bd-9vouw.314: Map and Set forEach visit every entry present when its
//! turn comes. A callback that deletes the current or an earlier entry made
//! the walk skip the next one, because only for-of iterators moved back on a
//! delete. The cases cover deleting the current entry, deleting and
//! re-adding (the entry is visited again at the end), deleting around an
//! appended entry, deleting a later entry (not visited), clearing and
//! adding, and nested walks over one set. Node v22.2.0 gives this value;
//! Bun 1.4.2 agrees.

use frankenengine_engine::HybridRouter;

#[test]
fn collection_for_each_survives_deletes_in_its_callback() {
    let source = r#"
var out = [];
var s = new Set([1, 2, 3, 4]); var seen = [];
s.forEach(function (v) { seen.push(v); s.delete(v); });
out.push(seen.join(',') + '|' + s.size);
var m = new Map([[1, 'a'], [2, 'b'], [3, 'c'], [4, 'd']]); seen = [];
m.forEach(function (v, k) { seen.push(k + v); if (k % 2 === 1) m.delete(k); });
out.push(seen.join(',') + '|' + [...m.keys()].join(''));
var s2 = new Set([1, 2, 3]); seen = [];
s2.forEach(function (v) { seen.push(v); if (v === 2) { s2.delete(1); s2.add(1); } });
out.push(seen.join(','));
var m2 = new Map([[1, 1], [2, 2], [3, 3]]); seen = [];
m2.forEach(function (v, k) { seen.push(k); if (k === 2) { m2.delete(1); m2.delete(3); m2.set(4, 4); } });
out.push(seen.join(','));
var s3 = new Set([1, 2, 3]); seen = [];
s3.forEach(function (v) { seen.push(v); if (v === 1) s3.delete(2); });
out.push(seen.join(','));
var s4 = new Set([1, 2, 3]); seen = [];
s4.forEach(function (v) { seen.push(v); if (v === 1) { s4.clear(); s4.add(9); } });
out.push(seen.join(','));
var outer = new Set([1, 2]); seen = [];
outer.forEach(function (a) { outer.forEach(function (b) { seen.push(a + '' + b); if (b === 1 && a === 1) outer.delete(1); }); });
out.push(seen.join(','));
out.join(' ');
"#;
    let value = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value;
    assert_eq!(
        value,
        "1,2,3,4|0 1a,2b,3c,4d|24 1,2,3,1 1,2,4 1,3 1,9 11,12,22"
    );
}
