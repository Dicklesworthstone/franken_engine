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
    assert_eq!(eval_to_string(source), node, "`{source}` must match Node v22.2.0");
}

#[test]
fn generator_objects_spread_into_arrays() {
    check("function* g() { yield 1; yield 2; } [...g()].join();", "1,2");
    check(
        "function* g() { yield* [1, 2]; yield 3; } [...g()].join();",
        "1,2,3",
    );
    check("function* g() {} [...g()].length;", "0");
    check("function* g() { yield 'b'; } ['a', ...g(), 'c'].join('');", "abc");
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

#[test]
fn set_iterates_values_in_insertion_order() {
    check("[...new Set([3, 1, 3, 2])].join();", "3,1,2");
    check(
        "let t = 0; for (const v of new Set([1, 2, 2, 3])) t += v; t;",
        "6",
    );
}
