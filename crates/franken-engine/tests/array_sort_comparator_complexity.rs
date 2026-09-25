//! `Array.prototype.sort` with a comparator (ES2020 22.1.3.27).
//!
//! The comparator path was an insertion sort: O(n^2) comparator calls, each
//! re-entering the interpreter, so sorting 5,000 numbers took minutes. It is
//! now a stable merge sort. Undefined elements sort last without reaching the
//! comparator, and the comparator result goes through ToNumber. Expected
//! strings are what Node v22.2.0 prints for `String(eval(source))`, except
//! the call-count bound, which is an engine complexity property.
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
fn comparator_orders_numbers_and_is_stable() {
    check(
        "[5, 1, 4, 2, 3].sort(function (a, b) { return a - b; }).join() + '|' + \
         [5, 1, 4, 2, 3].sort(function (a, b) { return b - a; }).join()",
        "1,2,3,4,5|5,4,3,2,1",
    );
    check(
        "var r = [{k: 1, v: 'a'}, {k: 0, v: 'b'}, {k: 1, v: 'c'}, {k: 0, v: 'd'}, \
         {k: 1, v: 'e'}].sort(function (x, y) { return x.k - y.k; }); \
         r.map(function (o) { return o.v; }).join('')",
        "bdace",
    );
}

#[test]
fn undefined_sorts_last_without_reaching_the_comparator() {
    check(
        "var r = [3, undefined, 1, undefined, 2].sort(function (a, b) { \
         if (a === undefined || b === undefined) throw new Error('undefined reached comparator'); \
         return a - b; }); r.join() + '|' + r.length",
        "1,2,3,,|5",
    );
    check("[3, undefined, 'b', 1, 'a'].sort().join()", "1,3,a,b,");
    check("[10, 9, 1, 100].sort().join()", "1,10,100,9");
}

#[test]
fn a_throwing_comparator_leaves_the_array_unchanged() {
    check(
        "var a = [3, 1, 2]; try { a.sort(function () { throw new Error('boom'); }); } \
         catch (e) { } a.join()",
        "3,1,2",
    );
}

#[test]
fn comparator_calls_are_n_log_n() {
    // 256 shuffled elements: a merge sort makes at most n * log2(n) = 2,048
    // comparisons; the old insertion sort made about 16,000.
    let source = "var a = []; for (var i = 0; i < 256; i++) a.push((i * 7919) % 256); \
                  var calls = 0; a.sort(function (x, y) { calls++; return x - y; }); \
                  var sorted = true; for (var j = 1; j < a.length; j++) \
                  if (a[j - 1] > a[j]) sorted = false; sorted + ',' + (calls <= 2048)";
    assert_eq!(
        eval_to_string(source),
        "true,true",
        "comparator sort must be correct and use O(n log n) calls"
    );
}
