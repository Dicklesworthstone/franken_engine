//! `Array.prototype.reduce` / `reduceRight` with ordinary callbacks.
//!
//! Reducers ran on a restricted mini-lane that threw "unsupported reducer
//! instruction" for any comparison, method call, allocation or block scope,
//! so common idioms (flatten with `concat`, group-by, max with `>`) failed.
//! Such callbacks now take the ordinary callback path; the choice is made by
//! a static scan before the callback runs, so no side effect is replayed.
//! Expected strings are what Node v22.2.0 prints for `String(eval(source))`.
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
fn flatten_and_group_by_reducers() {
    check(
        "[[1, 2], [3]].reduce(function (a, b) { return a.concat(b); }, []).join() + '|' + \
         [[1, 2], [3]].reduceRight(function (a, b) { return a.concat(b); }, []).join()",
        "1,2,3|3,1,2",
    );
    check(
        "JSON.stringify([{k: 'a', v: 1}, {k: 'b', v: 2}, {k: 'a', v: 3}].reduce(function (m, o) { \
         (m[o.k] = m[o.k] || []).push(o.v); return m; }, {}))",
        r#"{"a":[1,3],"b":[2]}"#,
    );
}

#[test]
fn reducers_with_comparisons_and_block_scopes() {
    check(
        "[1, 2, 3].reduce(function (acc, x) { if (x > 1) { let z = x * 10; acc.push(z); } \
         return acc; }, []).join()",
        "20,30",
    );
    check(
        "[3, 9, 4].reduce(function (best, x) { return x > best ? x : best; }) + ',' + \
         [1, 2, 3, 4].reduce(function (a, b) { return a + b; }) + ',' + \
         [1, 2, 3].reduce(function (acc, x) { const y = x * 2; return acc + y; }, 0)",
        "9,10,12",
    );
}

#[test]
fn reducer_receives_index_and_array() {
    check(
        "var seen = []; var r = [1, 2, 3].reduce(function (acc, x, i, arr) { \
         seen.push(i + ':' + (arr.length)); return acc * x; }, 1); r + '|' + seen.join()",
        "6|0:3,1:3,2:3",
    );
}
