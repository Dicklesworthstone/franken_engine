//! bd-9vouw.131: Map and Set iteration (for-of, the keys/values/entries
//! iterators and forEach) walks the live entry list (ES2020 23.1.5.2.1,
//! 23.2.5.2.1, 23.1.3.5, 23.2.3.6): entries added while iterating are
//! visited, deleted ones are not, and an iterator created before `clear()`
//! sees what is added after it. Iteration walked a copy of the entries
//! present when it started, so worklist loops such as
//! `for (const n of pending) pending.add(next)` stopped after the initial
//! entries. Expected strings are Node v22.2.0's output.
//!
//! No-claim: `Array.from(collection, mapper)` and spread still read the
//! entries once (no guest code runs between spread steps).

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}"))
        .value
}

#[test]
fn additions_and_deletions_during_iteration_are_seen() {
    let source = "var s = new Set([1]), seen = [];\n\
                  for (var x of s) { seen.push(x); if (x < 5) s.add(x + 1); }\n\
                  var m = new Map([['a', 1], ['b', 2], ['c', 3]]), ks = [];\n\
                  for (var [k] of m) { ks.push(k); if (k === 'a') { m.delete('b'); m.set('d', 4); } }\n\
                  var s2 = new Set([1, 2, 3]), f = [];\n\
                  s2.forEach(function (v) { f.push(v); if (v === 1) { s2.delete(2); s2.add(4); } });\n\
                  var s3 = new Set([1, 2]), it = s3.values(); it.next(); s3.clear(); s3.add(9);\n\
                  [seen.join(','), ks.join(','), f.join(','), JSON.stringify(it.next())].join(' ');";
    assert_eq!(
        eval(source),
        "1,2,3,4,5 a,c,d 1,3,4 {\"value\":9,\"done\":false}"
    );
}

#[test]
fn readded_current_and_deleted_entries() {
    let source = "var out = [];\n\
                  var s = new Set([1, 2]), a = [];\n\
                  for (var x of s) { a.push(x); if (x === 1 && a.length === 1) { s.delete(1); s.add(1); } }\n\
                  out.push(a.join(','));\n\
                  var m2 = new Map([['a', 1], ['b', 2], ['c', 3]]), k = [];\n\
                  for (var [key] of m2) { k.push(key); m2.delete(key); }\n\
                  out.push(k.join(',') + '/' + m2.size);\n\
                  var s5 = new Set([1, 2, 3]), it5 = s5[Symbol.iterator](), r5 = [];\n\
                  r5.push(it5.next().value); s5.delete(2); r5.push(it5.next().value); s5.add(4);\n\
                  r5.push(it5.next().value, it5.next().done);\n\
                  out.push(r5.join(','));\n\
                  out.join(' | ');";
    assert_eq!(eval(source), "1,2,1 | a,b,c/0 | 1,3,4,true");
}

/// A finished iterator stays finished, entries are fresh arrays, and nested
/// or clearing forEach calls keep their own positions.
#[test]
fn finished_iterators_fresh_entries_and_nested_for_each() {
    let source = "var out = [];\n\
                  var s2 = new Set([1]), it = s2.values(); it.next(); var d1 = it.next().done;\n\
                  s2.add(2); out.push(d1 + '/' + it.next().done);\n\
                  var m = new Map([[1, 'a']]), e1 = m.entries().next().value, \
                  e2 = m.entries().next().value; e1[1] = 'z';\n\
                  out.push((e1 !== e2) + '/' + m.get(1));\n\
                  var s3 = new Set([1, 2, 3]), n = [];\n\
                  s3.forEach(function (v) { s3.forEach(function (w) { n.push(v + '' + w); \
                  if (v === 1 && w === 1) s3.delete(3); }); });\n\
                  out.push(n.join(','));\n\
                  var s4 = new Set([1, 2, 3]), c = [];\n\
                  s4.forEach(function (v) { c.push(v); if (v === 1) { s4.clear(); s4.add(7); } });\n\
                  out.push(c.join(','));\n\
                  out.join(' | ');";
    assert_eq!(eval(source), "true/true | true/a | 11,12,21,22 | 1,7");
}

/// bd-9vouw.121: Map and Set iterators inherit %MapIteratorPrototype% and
/// %SetIteratorPrototype% (ES2020 23.1.5.2, 23.2.5.2), each with `next` and
/// its @@toStringTag, under %IteratorPrototype%; they reported
/// %ArrayIteratorPrototype% ("[object Array Iterator]").
#[test]
fn map_and_set_iterators_have_their_own_prototypes() {
    let source = "var m = new Map([[1, 2]]), s = new Set([1]);\n\
                  var mi = m.keys(), si = s.values();\n\
                  var MP = Object.getPrototypeOf(mi), SP = Object.getPrototypeOf(si);\n\
                  var IP = Object.getPrototypeOf(Object.getPrototypeOf([].keys()));\n\
                  [Object.prototype.toString.call(mi), Object.prototype.toString.call(si), \
                  Object.prototype.toString.call([].keys()), \
                  MP === Object.getPrototypeOf(m.entries()), MP !== SP, \
                  SP === Object.getPrototypeOf(s.entries()), MP[Symbol.toStringTag], \
                  SP[Symbol.toStringTag], Object.getPrototypeOf(MP) === IP, \
                  Object.getPrototypeOf(SP) === IP, typeof MP.next, MP.hasOwnProperty('next'), \
                  mi[Symbol.iterator]() === mi, Object.prototype.toString.call(m[Symbol.iterator]()), \
                  String(si)].join(' ');";
    assert_eq!(
        eval(source),
        "[object Map Iterator] [object Set Iterator] [object Array Iterator] true true true \
         Map Iterator Set Iterator true true function true true [object Map Iterator] \
         [object Set Iterator]"
    );
}

/// String.prototype[@@iterator] iterates ToString(RequireObjectCoercible(this))
/// (ES2020 21.1.3.29): core-js's iterator feature detection calls it on `new
/// String`, and the engine's "expected string iterator receiver" error aborted
/// xregexp's bundle while it loaded. Expected values are Node v22.2.0's.
/// No-claim: the iterator's own prototype and toStringTag ("String Iterator")
/// are not covered (bd-9vouw.121 remainder).
#[test]
fn string_iterator_accepts_wrapper_number_and_object_receivers() {
    let source = "var it = String.prototype[Symbol.iterator];\n\
                  var w = Array.from({ [Symbol.iterator]: function () { return it.call(new String('ab')); } });\n\
                  var n = Array.from({ [Symbol.iterator]: function () { return it.call(12); } });\n\
                  var o = Array.from({ [Symbol.iterator]: function () { return it.call({ toString: function () { return 'xy'; } }); } });\n\
                  var e = ''; try { it.call(null); } catch (err) { e = err.constructor.name; }\n\
                  [w.join(','), n.join(','), o.join(','), e].join(' ');";
    assert_eq!(eval(source), "a,b 1,2 x,y TypeError");
}

/// for-of and spread honor an overridden @@iterator on a Map or Set: a
/// subclass generator method, an own property on the instance, and a
/// replaced Set.prototype[@@iterator] (ES2020 7.4.1 GetIterator). The native
/// entry walk applied whenever the collection storage was present, so
/// `class M extends Map { *[Symbol.iterator]() {} }` iterated its entries in
/// for-of and spread while Array.from called the override. Expected values
/// are Node v22.2.0's. A subclass without an override still iterates entries.
#[test]
fn overridden_collection_iterator_is_used_by_for_of_and_spread() {
    let source = "var out = [];\n\
                  class M extends Map { *[Symbol.iterator]() { yield 'z'; } }\n\
                  var m = new M([['a', 1]]), f = [];\n\
                  for (var x of m) f.push(x);\n\
                  out.push(f.join(',') + '/' + [...m].join(',') + '/' + Array.from(m).join(','));\n\
                  class S extends Set { *[Symbol.iterator]() { for (var v of super.values()) yield v * 10; } }\n\
                  var s = new S([1, 2]), g = [];\n\
                  for (var y of s) g.push(y);\n\
                  out.push(g.join(',') + '/' + [...s].join(','));\n\
                  var own = new Set([1, 2]); own[Symbol.iterator] = function* () { yield 'own'; };\n\
                  out.push([...own].join(',') + '/' + Array.from(own).join(','));\n\
                  var saved = Set.prototype[Symbol.iterator];\n\
                  Set.prototype[Symbol.iterator] = function* () { yield 'proto'; };\n\
                  var p = [];\n\
                  for (var w of new Set([7])) p.push(w);\n\
                  out.push(p.join(',') + '/' + [...new Set([8])].join(','));\n\
                  Set.prototype[Symbol.iterator] = saved;\n\
                  class Plain extends Map {}\n\
                  out.push([...new Plain([['k', 2]])].join(',') + '/' + [...new Set([3, 4])].join(','));\n\
                  out.join(' | ');";
    assert_eq!(
        eval(source),
        "z/z/z | 10,20/10,20 | own/own | proto/proto | k,2/3,4"
    );
}
