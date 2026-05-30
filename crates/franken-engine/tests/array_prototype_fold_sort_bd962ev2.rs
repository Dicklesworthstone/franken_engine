//! Regression coverage for the final bd-962ev.2 methods: receiver-aware
//! `Array.prototype.reduce`, `reduceRight`, and `sort` on the `HybridRouter`
//! method seam. reduce/reduceRight reuse `invoke_simple_reduce_callback`; sort
//! supports a user comparator (sign of its result) via a manual insertion sort
//! and falls back to lexicographic ToString ordering.
//!
//! Value-asserting through `HybridRouter::eval`.

use frankenengine_engine::HybridRouter;

fn eval_value(src: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(src)
        .unwrap_or_else(|e| panic!("eval failed for {src:?}: {e}"));
    format!("{outcome:?}")
        .split("value: \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap_or_default()
        .to_string()
}

#[test]
fn reduce_folds_left_with_and_without_initial() {
    assert_eq!(
        eval_value("[1, 2, 3, 4].reduce(function(a, b) { return a + b; }, 0);"),
        "10"
    );
    // no initial value: first element seeds the accumulator.
    assert_eq!(
        eval_value("[1, 2, 3, 4].reduce(function(a, b) { return a + b; });"),
        "10"
    );
    assert_eq!(
        eval_value("[1, 2, 3, 4].reduce(function(a, b) { return a + b; }, 100);"),
        "110"
    );
    // single element, no initial: returned without calling the callback.
    assert_eq!(
        eval_value("[7].reduce(function(a, b) { return a + b; });"),
        "7"
    );
}

#[test]
fn reduce_right_folds_from_the_end() {
    // 10 - 3 - 2 - 1 = 4 (right-to-left).
    assert_eq!(
        eval_value("[1, 2, 3].reduceRight(function(a, b) { return a - b; }, 10);"),
        "4"
    );
    // visit order 3,2,1 encoded positionally: ((0*10+3)*10+2)*10+1 = 321.
    assert_eq!(
        eval_value("[1, 2, 3].reduceRight(function(a, b) { return a * 10 + b; }, 0);"),
        "321"
    );
}

#[test]
fn sort_default_is_lexicographic() {
    assert_eq!(eval_value("let a = [3, 1, 2]; a.sort(); a[0];"), "1");
    assert_eq!(eval_value("let a = [3, 1, 2]; a.sort(); a[2];"), "3");
    // ToString ordering: 1, 10, 2 (not numeric).
    assert_eq!(eval_value("let a = [10, 2, 1]; a.sort(); a[1];"), "10");
    // sort returns the array itself.
    assert_eq!(
        eval_value("let a = [3, 1, 2]; let b = a.sort(); b[0];"),
        "1"
    );
}

#[test]
fn sort_with_comparator_orders_numerically() {
    // ascending numeric comparator.
    assert_eq!(
        eval_value("let a = [10, 2, 1]; a.sort(function(x, y) { return x - y; }); a[0];"),
        "1"
    );
    assert_eq!(
        eval_value("let a = [10, 2, 1]; a.sort(function(x, y) { return x - y; }); a[2];"),
        "10"
    );
    // descending comparator.
    assert_eq!(
        eval_value("let a = [1, 2, 3]; a.sort(function(x, y) { return y - x; }); a[0];"),
        "3"
    );
    assert_eq!(
        eval_value("let a = [1, 2, 3]; a.sort(function(x, y) { return y - x; }); a[2];"),
        "1"
    );
}
