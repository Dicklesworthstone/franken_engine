//! bd-9vouw.33 and siblings: `Map/Set.prototype.forEach`, `keys`, `values`,
//! `entries`, `String.prototype.concat`/`toLocaleLowerCase`/
//! `toLocaleUpperCase`, and `Number.prototype.toPrecision`/`toExponential`.
//!
//! Before this each read was `undefined` ("expected function, got
//! undefined"). Expected strings are what Node v22.2.0 prints for the same
//! programs.
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

#[test]
fn map_and_set_for_each() {
    check(
        "var s = 0; new Map([[1, 2], [3, 4]]).forEach(function (v, k) { s += v * 10 + k; }); s;",
        "64",
    );
    check(
        "var out = []; new Set(['a', 'b']).forEach(function (v, k, set) { out.push(v + k + set.size); }); \
         out.join();",
        "aa2,bb2",
    );
    check(
        "var ctx = {n: 0}; new Set([5]).forEach(function (v) { this.n += v; }, ctx); ctx.n;",
        "5",
    );
}

#[test]
fn map_and_set_iterators() {
    check(
        "var m = new Map([[1, 'a'], [2, 'b']]); \
         [...m.keys()].join() + '|' + [...m.values()].join() + '|' + [...m.entries()].join(';');",
        "1,2|a,b|1,a;2,b",
    );
    check(
        "var s = new Set([1, 2]); \
         [...s.values()].join() + '|' + [...s.keys()].join() + '|' + [...s.entries()].join(';');",
        "1,2|1,2|1,1;2,2",
    );
    check(
        "var it = new Map([[1, 'x']]).entries(); var r = it.next(); \
         r.value[0] + r.value[1] + ':' + it.next().done;",
        "1x:true",
    );
}

#[test]
fn string_concat_and_locale_case() {
    check("'a'.concat('b', 1, null);", "ab1null");
    check(
        "'ABC'.toLocaleLowerCase() + 'def'.toLocaleUpperCase();",
        "abcDEF",
    );
}

#[test]
fn number_to_precision_and_exponential() {
    check(
        "[(123.456).toPrecision(4), (0.000123).toPrecision(2), (123456).toPrecision(2), \
         (2.5).toPrecision(1), (1.25).toPrecision(2), (0).toPrecision(3), \
         (-1.5).toPrecision(1)].join();",
        "123.5,0.00012,1.2e+5,3,1.3,0.00,-2",
    );
    check(
        "[(123.456).toExponential(2), (0).toExponential(1), (1.5).toExponential(), \
         (12345).toExponential(), (-0.00015).toExponential(1)].join();",
        "1.23e+2,0.0e+0,1.5e+0,1.2345e+4,-1.5e-4",
    );
    check(
        "var r; try { (1).toPrecision(0); r = 'no'; } catch (e) { r = e instanceof RangeError; } r;",
        "true",
    );
}
