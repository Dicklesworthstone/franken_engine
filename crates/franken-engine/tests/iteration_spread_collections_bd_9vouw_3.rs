//! Spreading generators and iterating Map/Set (reality check 2026-09-23).
//!
//! `[...g()]` failed with "expected iterable, got object" (array spread had no
//! arm for generator objects), and `for (const [k, v] of map)`, `[...set]` and
//! friends failed with "expected callable Symbol.iterator method" (collections
//! exposed no iteration). Expected strings are what Node v22.2.0 prints.
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn eval_to_string(source: &str) -> String {
    match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    }
}

fn check(source: &str, node: &str) {
    assert_eq!(
        eval_to_string(source),
        node,
        "`{source}` must match Node v22.2.0"
    );
}

/// Map.prototype, Set.prototype and String.prototype hold their @@iterator
/// (Map's is `entries`, Set's `values`); only instances and primitives had
/// it, so `typeof Map.prototype[Symbol.iterator]` was "undefined" (Test262
/// String/prototype/Symbol.iterator/name and relatives).
#[test]
fn collection_and_string_prototypes_have_their_iterator() {
    check(
        "[typeof String.prototype[Symbol.iterator], typeof Map.prototype[Symbol.iterator], \
         typeof Set.prototype[Symbol.iterator], \
         Map.prototype[Symbol.iterator] === Map.prototype.entries, \
         Set.prototype[Symbol.iterator] === Set.prototype.values, \
         Map.prototype[Symbol.iterator] === new Map()[Symbol.iterator], \
         [...String.prototype[Symbol.iterator].call('ab')].join(), \
         [...Map.prototype[Symbol.iterator].call(new Map([[1, 2]]))].join(), \
         Symbol.iterator in Map.prototype].join(' ')",
        "function function function true true true a,b 1,2 true",
    );
}

#[test]
fn generator_objects_spread_into_arrays() {
    check(
        "function* g() { yield 1; yield 2; } [...g()].join();",
        "1,2",
    );
    check(
        "function* g() { yield* [1, 2]; yield 3; } [...g()].join();",
        "1,2,3",
    );
    check("function* g() {} [...g()].length;", "0");
    check(
        "function* g() { yield 'b'; } ['a', ...g(), 'c'].join('');",
        "abc",
    );
}

#[test]
fn map_iterates_entries_in_insertion_order() {
    check(
        "const m = new Map(); m.set('b', 1); m.set('a', 2); m.set(3, 'x'); \
         let out = []; for (const [k, v] of m) out.push(k + '=' + v); out.join(',');",
        "b=1,a=2,3=x",
    );
    check(
        "const m = new Map([['k', 1]]); m.set('k', 5); [...m].map(e => e.join(':')).join();",
        "k:5",
    );
    check(
        "const o = {}; const m = new Map(); m.set(o, 1); let hit = false; \
         for (const [k] of m) hit = k === o; hit;",
        "true",
    );
}

/// A regex literal right after a spread's `...` was read as a division by the
/// statement scanner ("empty expression statement").
#[test]
fn a_regex_literal_can_follow_a_spread() {
    check(
        "[[.../ab/.exec('xab')].join(), [...'q', .../c(d)/.exec('cd')].join(), \
         (function () { return [...arguments, .../z/g.exec('z')].length; })(1, 2)].join(' ');",
        "ab q,cd,d 3",
    );
}

#[test]
fn set_iterates_values_in_insertion_order() {
    check("[...new Set([3, 1, 3, 2])].join();", "3,1,2");
    check(
        "let t = 0; for (const v of new Set([1, 2, 2, 3])) t += v; t;",
        "6",
    );
}

/// An arguments object has an own, non-enumerable @@iterator that is
/// %Array.prototype.values% (ES2020 9.4.4.6), so it spreads, converts and
/// iterates like an array. It had none: `[...arguments]` threw "expected
/// callable Symbol.iterator method".
#[test]
fn arguments_objects_are_iterable() {
    check(
        "(function () { let s = ''; for (const a of arguments) s += a; \
         return [[...arguments].join(), Array.from(arguments).length, s, \
         JSON.stringify(Object.keys(arguments)), arguments[Symbol.iterator] === Array.prototype.values, \
         Object.getOwnPropertyDescriptor(arguments, Symbol.iterator).enumerable, \
         [...arguments, .../z/g.exec('z')].length].join(' '); })(1, 2);",
        r#"1,2 2 12 ["0","1"] true false 3"#,
    );
}

/// Map, Set, WeakMap and WeakSet seed from any iterable through the
/// iteration protocol (ES2020 23.1.1.1ff.): another collection, a generator,
/// a `keys()`/`values()` iterator, a user iterable, a string, an array with
/// holes. A Map entry is any object (`Get(entry, "0")`, `Get(entry, "1")`),
/// and a non-iterable, a non-object entry or a value that cannot be weakly
/// held is a TypeError. Seeding read indexed properties instead, so
/// `new Map(otherMap)`, `new Set(generator())` and `new Set(map.keys())`
/// were silently empty and the errors were skipped.
#[test]
fn collections_seed_from_any_iterable() {
    check(
        "function* g() { yield ['k', 'v']; yield ['k2', 'v2']; } \
         var m = new Map([[1, 'a'], [2, 'b']]); \
         var it = { [Symbol.iterator]() { var i = 0; return { next() { \
         return i++ < 2 ? { value: [i, i * 10], done: false } : { done: true }; } }; } }; \
         var holes = [1, 2]; holes[5] = 6; \
         [new Map(m).get(2), new Set(new Set([1, 2])).size, new Map(g()).get('k2'), \
         new Set(m.keys()).size, [...new Set(m.values())].join(''), new Map([[1, 2]].values()).get(1), \
         new Map(it).get(2), new Map([{ 0: 'a', 1: 'b' }]).get('a'), new Set('abca').size, \
         new Set(holes).size, new Map(undefined).size, new Set(null).size].join();",
        "b,2,v2,2,ab,2,20,b,3,4,0,0",
    );
    check(
        "function attempt(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } } \
         var k = {}; var fn = function () {}; \
         [attempt(() => new Map(5)), attempt(() => new Set({ length: 2, 0: 'a' })), \
         attempt(() => new Map(['ab'])), attempt(() => new Map([1])), \
         attempt(() => new WeakMap([[1, 'x']])), attempt(() => new WeakMap([1])), \
         attempt(() => new WeakSet([1])), new WeakSet(new Set([k])).has(k), \
         new WeakMap(new Map([[k, 1], [fn, 2]])).get(fn), new WeakSet([fn]).has(fn)].join();",
        "TypeError,TypeError,TypeError,TypeError,TypeError,TypeError,TypeError,true,2,true",
    );
    // A failed WeakMap seed keeps what the program's iterator allocated.
    check(
        "function attempt(f) { try { f(); return 'ok'; } catch (e) { return e.constructor.name; } } \
         var saved; var leaky = { [Symbol.iterator]() { return { next() { \
         saved = { kept: true }; return { value: 1, done: false }; } }; } }; \
         [attempt(() => new WeakMap(leaky)), saved.kept, JSON.stringify(saved)].join(' ');",
        r#"TypeError true {"kept":true}"#,
    );
}

/// A spread element owns its whole operand (`...AssignmentExpression`):
/// `[...a ?? [], 2]`, `[...b || []]`, `[...c ? x : y]` and `[...d = [5]]`
/// spread the operand's value. The operator splits ran first, so the
/// element became a `??`, `||`, `?:` or `=` whose operand was the spread,
/// and the array held the operand's value itself (zod's
/// `[...def.checks ?? [], ...chks]` built a nested array and failed).
#[test]
fn a_spread_operand_can_contain_operators() {
    check(
        "var a; var b = [1]; var c = true; var d; \
         JSON.stringify([[...a ?? [], 2], [...b || [], 2], [0, ...b ?? [], 2], \
         [...c ? [1, 2] : [], 3], [...b && [7, 8]], [...d = [5]], d]);",
        "[[2],[1,2],[0,1,2],[1,2,3],[7,8],[5],[5]]",
    );
}

/// The same for a spread argument: `f(...c > 0 ? [a, b] : [b, a])` spreads
/// the conditional's array. bun emits this shape without parentheses
/// (date-fns' formatDistance), and it passed one argument, so date-fns
/// printed "almost NaN years".
#[test]
fn a_spread_argument_can_contain_operators() {
    check(
        "var c = 5; var a; function n() { return arguments.length; } \
         [n(...c > 0 ? [1, 2, 3] : []), Math.max(...c > 0 ? [7, 9] : [1]), n(...a ?? [1, 2]), \
         n(0, ...a || [4, 5], 6), [].concat(...c ? [[1], [2]] : []).length].join();",
        "3,9,2,4,2",
    );
}

/// Iterator, generator and async generator values report their intrinsic
/// prototypes (ES2020 22.1.5.2, 25.1.2, 25.4.1; ES2018 25.5.1):
/// %ArrayIteratorPrototype% (`next`, "Array Iterator") inherits from
/// %IteratorPrototype%, whose own @@iterator returns its receiver;
/// %GeneratorPrototype% and %AsyncGeneratorPrototype% are their function
/// kinds' `prototype` and have them as `constructor`. Object.getPrototypeOf
/// of an iterator threw ("object with property storage"), so core-js and
/// regenerator-runtime, which run `getProto(getProto([].keys()))` at load,
/// failed (xregexp's bundle did).
///
/// No-claim: Map, Set and String iterators also report
/// %ArrayIteratorPrototype% (they are array iterators over a snapshot here),
/// and a generator object reports %GeneratorPrototype% rather than its
/// function's `prototype`.
#[test]
fn iteration_intrinsic_prototypes() {
    check(
        "const getProto = Object.getPrototypeOf; const o = {}; \
         const AIP = getProto([].keys()); const IP = getProto(AIP); \
         function* g() { yield 1; } async function* ag() {} \
         const GP = getProto(g).prototype; const AGP = getProto(ag).prototype; \
         const NativeIteratorPrototype = getProto(getProto([][Symbol.iterator]())); \
         [IP === NativeIteratorPrototype, getProto(IP) === Object.prototype, \
         Object.prototype.hasOwnProperty.call(IP, Symbol.iterator), IP[Symbol.iterator].call(o) === o, \
         typeof AIP.next, AIP[Symbol.toStringTag], Object.prototype.toString.call([].values()), \
         AIP.next.call([7].values()).value, Object.isExtensible([].keys()), \
         getProto(new Map().keys()) !== Object.prototype, getProto(GP) === IP, GP[Symbol.toStringTag], \
         GP.constructor === getProto(g), typeof GP.next, GP.next.call(g()).value, \
         GP.hasOwnProperty('return'), AGP[Symbol.toStringTag], AGP.constructor === getProto(ag), \
         typeof AGP[Symbol.asyncIterator], [].keys()[Symbol.toStringTag], String([].entries())].join(' ')",
        "true true true true function Array Iterator [object Array Iterator] 7 true true true Generator \
         true function 1 true AsyncGenerator true function Array Iterator [object Array Iterator]",
    );
}
