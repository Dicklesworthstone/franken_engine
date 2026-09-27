//! Map, Set, WeakMap, WeakSet, Date and RegExp objects keep their state in
//! internal slots, which ordinary property enumeration never sees. The
//! engine stores that state as own properties (`__type`, `__entries`,
//! `__values`, `size`, `__timestamp`, `source`, `flags`, `lastIndex`).
//! Those properties were enumerable, so:
//! - `Object.keys(new Map())` listed `["__type","__entries","size"]`;
//! - `JSON.stringify({ m: new Map() })` serialized the engine's storage;
//! - `{ ...date }` copied `__type` and `__timestamp` into a plain object,
//!   which the engine then took for a Date.
//! The slots are now non-enumerable, and the objects themselves behave as
//! before.
//!
//! Expected strings are what Node v22.2.0 prints for `String(<program>)`.
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

const SETUP: &str = "var m = new Map([[1, 'a']]), s = new Set([1]), d = new Date(0), r = /a/g, \
                     wm = new WeakMap(), ws = new WeakSet(); ";

#[test]
fn builtin_state_is_not_listed_or_serialized() {
    check(
        &format!(
            "{SETUP}JSON.stringify([Object.keys(m), Object.keys(s), Object.keys(d), \
             Object.keys(r), Object.keys(wm), Object.keys(ws)])"
        ),
        "[[],[],[],[],[],[]]",
    );
    check(
        &format!("{SETUP}JSON.stringify({{ m: m, s: s, r: r, d: d }})"),
        r#"{"m":{},"s":{},"r":{},"d":"1970-01-01T00:00:00.000Z"}"#,
    );
}

#[test]
fn enumeration_and_copies_skip_builtin_state() {
    check(
        &format!(
            "{SETUP}var keys = []; for (var k in m) keys.push(k); \
             for (var k2 in d) keys.push(k2); keys.length"
        ),
        "0",
    );
    check(
        &format!(
            "{SETUP}var copy = Object.assign({{}}, m, d), spread = {{ ...s, ...r }}; \
             [Object.keys(copy).length, Object.keys(spread).length].join()"
        ),
        "0,0",
    );
}

/// `Object.assign` and object spread copy only enumerable own properties
/// (CopyDataProperties). The copy path ignored `enumerable: false` from
/// `Object.defineProperty`, for string and symbol keys alike.
#[test]
fn copies_skip_user_defined_non_enumerable_properties() {
    check(
        "var o = Object.defineProperty({ a: 1 }, 'hidden', { value: 2, enumerable: false }); \
         var sym = Symbol('s'); Object.defineProperty(o, sym, { value: 3, enumerable: false }); \
         var c = Object.assign({}, o), sp = { ...o }; \
         [Object.keys(c).join(), Object.keys(sp).join(), 'hidden' in c, 'hidden' in sp, \
          Object.getOwnPropertySymbols(c).length, \
          Object.getOwnPropertySymbols(sp).length].join('|')",
        "a|a|false|false|0|0",
    );
}

#[test]
fn builtin_objects_still_work() {
    check(
        &format!(
            "{SETUP}class M2 extends Map {{}} \
             [Object.keys(new M2([[1, 2]])).length, new M2([[1, 2]]).size, m.size, s.has(1), \
             d.getTime(), r.lastIndex, r.source, r.flags].join()"
        ),
        "0,1,1,true,0,0,a,g",
    );
}
