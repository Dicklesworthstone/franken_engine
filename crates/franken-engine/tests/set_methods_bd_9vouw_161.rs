//! bd-9vouw.161: the ES2025 Set methods (ECMA-262 2025 24.2.4) that Node
//! v22 ships: union, intersection, difference, symmetricDifference,
//! isSubsetOf, isSupersetOf and isDisjointFrom. They were undefined. The
//! argument is any set-like object read through GetSetRecord (size, then
//! has and keys); which side a method walks follows the two sizes, and those
//! guest calls are observable. Expected strings are Node v22.2.0's output for
//! the same programs.
//!
//! No-claim: the receiver's elements are walked from a snapshot taken when
//! the method starts, so a `has` callback that adds to or deletes from the
//! receiver mid-walk is not modeled; Function-constructor code is not
//! granted these methods.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("evaluation failed: {error}\nsource: {source}"))
        .value
}

/// All seven methods against another Set, in result order.
#[test]
fn set_methods_results_against_sets() {
    let source = "var a = new Set([1, 2, 3, 4]), b = new Set([3, 4, 5]);\n\
         var show = (s) => '{' + [...s].join(',') + '}';\n\
         [show(a.union(b)), show(a.intersection(b)), show(a.difference(b)), show(a.symmetricDifference(b)),\n\
          a.isSubsetOf(b), new Set([3]).isSubsetOf(b), a.isSupersetOf(new Set([1, 4])), a.isSupersetOf(b),\n\
          a.isDisjointFrom(b), a.isDisjointFrom(new Set([9])), show(a), a.union(b) instanceof Set,\n\
          Object.getPrototypeOf(a.union(b)) === Set.prototype, a.union(a) !== a].join(' ');";
    assert_eq!(
        eval(source),
        "{1,2,3,4,5} {3,4} {1,2} {1,2,5} false true true false false true {1,2,3,4} true true true"
    );
}

/// A Map is set-like through its size, has and keys; so is any object with them.
#[test]
fn set_methods_maps_and_set_likes() {
    let source = "var a = new Set(['x', 'y', 'z']);\n\
         var m = new Map([['y', 1], ['w', 2]]);\n\
         var like = { size: 2, has: (v) => v === 'x' || v === 'q', keys: () => ['x', 'q'][Symbol.iterator]() };\n\
         var show = (s) => [...s].join(',');\n\
         [show(a.union(m)), show(a.intersection(m)), show(a.difference(like)), show(a.symmetricDifference(like)),\n\
          new Set(['x']).isSubsetOf(like), a.isSupersetOf(like), show(new Set([-0]).union(new Set([0]))),\n\
          Object.is([...new Set([1]).union({ size: 1, has: () => false, keys: () => [-0][Symbol.iterator]() })][1], 0)].join(' ');";
    assert_eq!(eval(source), "x,y,z,w y y,z y,z,q true false 0 true");
}

/// Which side is walked follows the sizes; size, has and keys are read in order and an early false closes the keys iterator.
#[test]
fn set_methods_observable_call_order() {
    let source = "var log = [];\n\
         function setLike(values, size) {\n\
           return {\n\
             get size() { log.push('size'); return size; },\n\
             get has() { log.push('get has'); return (v) => { log.push('has ' + v); return values.includes(v); }; },\n\
             get keys() { log.push('get keys'); return () => { log.push('keys'); var i = 0;\n\
               return { next() { log.push('next'); return i < values.length ? { value: values[i++], done: false } : { value: undefined, done: true }; },\n\
                        return() { log.push('return'); return {}; } }; }; },\n\
           };\n\
         }\n\
         var a = new Set([1, 2]);\n\
         var r1 = a.intersection(setLike([2, 3, 4], 3)); log.push('|');\n\
         var r2 = a.intersection(setLike([2], 1)); log.push('|');\n\
         var r3 = new Set([1, 2, 3]).isSupersetOf(setLike([1, 9, 2], 3)); log.push('|');\n\
         var r4 = a.isDisjointFrom(setLike([2, 7], 1));\n\
         [[...r1].join(), [...r2].join(), r3, r4, log.join(';')].join(' ');";
    assert_eq!(
        eval(source),
        "2 2 false false size;get has;get keys;has 1;has 2;|;size;get has;get keys;keys;next;next;|;size;get has;get keys;keys;next;next;return;|;size;get has;get keys;keys;next;return"
    );
}

/// GetSetRecord rejects a non-object, a NaN or negative size and a missing has or keys; a non-Set receiver is a TypeError.
#[test]
fn set_methods_set_record_errors() {
    let source = "function attempt(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } }\n\
         var s = new Set([1]);\n\
         [attempt(() => s.union([1])), attempt(() => s.union({ size: 'x', has() {}, keys() {} })),\n\
          attempt(() => s.union({ size: -1, has() {}, keys() {} })), attempt(() => s.union({ size: 1, keys() {} })),\n\
          attempt(() => s.union({ size: 1, has() {} })), attempt(() => Set.prototype.union.call({}, new Set())),\n\
          attempt(() => s.union({ size: Infinity, has: () => true, keys: () => [][Symbol.iterator]() })),\n\
          Set.prototype.union.length, Set.prototype.isDisjointFrom.name, typeof Set.prototype.symmetricDifference].join(' ');";
    assert_eq!(
        eval(source),
        "TypeError TypeError RangeError TypeError TypeError TypeError ok 1 isDisjointFrom function"
    );
}
