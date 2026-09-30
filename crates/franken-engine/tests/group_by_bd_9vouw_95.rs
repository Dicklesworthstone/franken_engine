//! bd-9vouw.95: ES2024 Object.groupBy and Map.groupBy.
//!
//! Both were missing (`Object.groupBy(...)` threw "expected function, got
//! undefined"). Expected strings are Node v22.2.0's completion values for the
//! same programs (`vm.runInNewContext`).
//!
//! No-claim: every item is read before the first callback runs (the spec
//! interleaves iteration and callback calls; only a callback that mutates
//! the iterable it is grouping can tell).
//!
//! No mocks: real source through the public `HybridRouter::eval` path.

use frankenengine_engine::HybridRouter;

fn check(source: &str, node: &str) {
    let value = match HybridRouter::default().eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERROR: {err:?}"),
    };
    assert_eq!(value, node, "`{source}` must match Node v22.2.0");
}

/// Object.groupBy: a null-prototype object of arrays, keys in first-seen
/// order (integer keys first, as in any object), the callback gets the index.
#[test]
fn object_group_by_groups_into_a_null_prototype_object() {
    check(
        "const g = Object.groupBy([1, 2, 3, 4, 5, 6.5], (x, i) => x % 2 === 0 ? 'even' : 'odd'); \
         [Object.getPrototypeOf(g) === null, Object.keys(g).join(), g.odd.join(), g.even.join(), \
         Array.isArray(g.odd)].join(' ')",
        "true odd,even 1,3,5,6.5 2,4 true",
    );
    check(
        "const g = Object.groupBy(['a', 'bb', 'cc', 'ddd'], s => s.length); \
         [JSON.stringify(g), Object.keys(g).join()].join(' ')",
        "{\"1\":[\"a\"],\"2\":[\"bb\",\"cc\"],\"3\":[\"ddd\"]} 1,2,3",
    );
    check(
        "const seen = []; Object.groupBy('xyz', (c, i) => { seen.push(c + i); return 'k'; }); seen.join()",
        "x0,y1,z2",
    );
    check(
        "const g = Object.groupBy(new Set([1, 2, 3]), x => x < 2 ? 'small' : 'big'); \
         [g.small.join(), g.big.join()].join(' ')",
        "1 2,3",
    );
    check(
        "const g = Object.groupBy([1, 2], x => ({ toString() { return 'k' + x; } })); Object.keys(g).join()",
        "k1,k2",
    );
}

/// Map.groupBy keys by SameValueZero (objects by identity, -0 as +0).
#[test]
fn map_group_by_keys_by_same_value_zero() {
    check(
        "const k1 = {}, k2 = {}; const m = Map.groupBy([{id: k1, v: 1}, {id: k2, v: 2}, {id: k1, v: 3}], o => o.id); \
         [m instanceof Map, m.size, m.get(k1).map(o => o.v).join(), m.get(k2).map(o => o.v).join()].join(' ')",
        "true 2 1,3 2",
    );
    check(
        "const m = Map.groupBy([1, 2, 3], x => x > 1 ? -0 : 0); \
         [m.size, m.get(0).join(), [...m.keys()].map(k => Object.is(k, -0)).join()].join(' ')",
        "1 1,2,3 false",
    );
}

/// Null/undefined or non-iterable items and a non-callable callback throw
/// TypeErrors; both statics are first-class functions of length 2.
#[test]
fn group_by_errors_and_function_values() {
    check(
        "const r = []; for (const f of [() => Object.groupBy(null, x => x), () => Object.groupBy([1], 'nope'), \
         () => Map.groupBy(undefined, x => x), () => Object.groupBy(5, x => x)]) \
         { try { f(); r.push('no'); } catch (e) { r.push(e.constructor.name); } } r.join()",
        "TypeError,TypeError,TypeError,TypeError",
    );
    check(
        "[typeof Object.groupBy, Object.groupBy.length, Object.groupBy.name, typeof Map.groupBy, \
         Map.groupBy.length].join(' ')",
        "function 2 groupBy function 2",
    );
}
