//! Regression coverage for bd-962ev.2: receiver-aware `Array.prototype`
//! callback methods on the `HybridRouter` method seam (`array_prototype_method`)
//! — `forEach`, `map`, `filter`, `find`, `findIndex`, `some`, `every`. Before
//! this change these faulted with "expected function, got undefined" on the
//! baseline path (the seam wired only the non-callback methods); the callbacks
//! are invoked through the existing `invoke_array_callback` machinery, reachable
//! from `dispatch_builtin_function` via its `module` parameter.
//!
//! Value-asserting through `HybridRouter::eval` (not merely `eval == Ok`).

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
fn for_each_invokes_callback_per_element() {
    // forEach drives side effects (here, via push) and returns undefined.
    assert_eq!(
        eval_value("let acc = []; [10, 20, 30].forEach(function(x) { acc.push(x); }); acc[1];"),
        "20"
    );
    assert_eq!(
        eval_value("let acc = []; [10, 20, 30].forEach(function(x) { acc.push(x); }); acc.length;"),
        "3"
    );
}

#[test]
fn map_collects_callback_results() {
    assert_eq!(
        eval_value("let r = [1, 2, 3].map(function(x) { return x * 2; }); r[0];"),
        "2"
    );
    assert_eq!(
        eval_value("let r = [1, 2, 3].map(function(x) { return x * 2; }); r[2];"),
        "6"
    );
    assert_eq!(
        eval_value("let r = [1, 2, 3].map(function(x) { return x * 2; }); r.length;"),
        "3"
    );
}

#[test]
fn filter_keeps_truthy_elements() {
    assert_eq!(
        eval_value("let r = [1, 2, 3, 4].filter(function(x) { return x > 2; }); r[0];"),
        "3"
    );
    assert_eq!(
        eval_value("let r = [1, 2, 3, 4].filter(function(x) { return x > 2; }); r[1];"),
        "4"
    );
    assert_eq!(
        eval_value("let r = [1, 2, 3, 4].filter(function(x) { return x > 2; }); r.length;"),
        "2"
    );
}

#[test]
fn find_returns_first_match_or_undefined() {
    assert_eq!(
        eval_value("[1, 2, 3].find(function(x) { return x > 1; });"),
        "2"
    );
    assert_eq!(
        eval_value("[1, 2, 3].find(function(x) { return x > 9; });"),
        "undefined"
    );
}

#[test]
fn find_index_returns_first_match_index_or_minus_one() {
    assert_eq!(
        eval_value("[1, 2, 3].findIndex(function(x) { return x === 3; });"),
        "2"
    );
    assert_eq!(
        eval_value("[1, 2, 3].findIndex(function(x) { return x > 9; });"),
        "-1"
    );
}

#[test]
fn some_reports_any_match() {
    assert_eq!(
        eval_value("[1, 2, 3].some(function(x) { return x > 2; });"),
        "true"
    );
    assert_eq!(
        eval_value("[1, 2, 3].some(function(x) { return x > 9; });"),
        "false"
    );
}

#[test]
fn every_reports_all_match() {
    assert_eq!(
        eval_value("[1, 2, 3].every(function(x) { return x > 0; });"),
        "true"
    );
    assert_eq!(
        eval_value("[1, 2, 3].every(function(x) { return x > 1; });"),
        "false"
    );
}
