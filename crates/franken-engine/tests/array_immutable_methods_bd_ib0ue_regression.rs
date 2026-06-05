#![forbid(unsafe_code)]
//! Regression: ES2023 immutable Array methods (bd-ib0ue).
//!
//! `toReversed`, `toSorted`, `with`, and `toSpliced` each return a NEW array and
//! must leave the receiver unchanged. Before this fix the eval surface had no
//! `array_prototype_method` entries for them, so the calls faulted. These tests
//! exercise the public `HybridRouter::eval` surface and assert both the result
//! AND receiver-immutability.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn to_reversed_returns_reversed_copy_without_mutating() {
    assert_eq!(
        eval_value(
            "let a = [1, 2, 3]; let r = a.toReversed(); r.join(\",\") + \"|\" + a.join(\",\")"
        ),
        "3,2,1|1,2,3"
    );
}

#[test]
fn to_sorted_default_orders_copy_without_mutating() {
    assert_eq!(
        eval_value(
            "let a = [3, 1, 2]; let r = a.toSorted(); r.join(\",\") + \"|\" + a.join(\",\")"
        ),
        "1,2,3|3,1,2"
    );
}

#[test]
fn to_sorted_honors_comparator() {
    assert_eq!(
        eval_value("[3, 1, 2].toSorted(function (x, y) { return y - x; }).join(\",\")"),
        "3,2,1"
    );
}

#[test]
fn with_replaces_index_in_copy_without_mutating() {
    assert_eq!(
        eval_value(
            "let a = [1, 2, 3]; let r = a.with(1, 9); r.join(\",\") + \"|\" + a.join(\",\")"
        ),
        "1,9,3|1,2,3"
    );
}

#[test]
fn with_supports_negative_index() {
    assert_eq!(eval_value("[1, 2, 3].with(-1, 9).join(\",\")"), "1,2,9");
}

#[test]
fn with_out_of_range_throws_range_error() {
    // Out-of-range index must throw (RangeError), not silently return a value.
    assert!(
        eval_value("[1, 2, 3].with(5, 9)").starts_with("ERR"),
        "out-of-range with() must throw"
    );
}

#[test]
fn to_spliced_returns_modified_copy_without_mutating() {
    assert_eq!(
        eval_value(
            "let a = [1, 2, 3, 4]; let r = a.toSpliced(1, 2, 9); r.join(\",\") + \"|\" + a.join(\",\")"
        ),
        "1,9,4|1,2,3,4"
    );
}

#[test]
fn to_spliced_insert_only_when_delete_count_zero() {
    assert_eq!(
        eval_value("[1, 2, 3].toSpliced(1, 0, 8, 9).join(\",\")"),
        "1,8,9,2,3"
    );
}
