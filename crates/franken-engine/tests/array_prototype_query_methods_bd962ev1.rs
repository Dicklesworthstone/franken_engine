//! Regression coverage for bd-962ev.1: non-callback `Array.prototype` methods
//! resolved through the `HybridRouter` receiver-aware method seam
//! (`array_prototype_method`) — `indexOf`, `includes`, `reverse`, `fill`, and
//! `join`. Before this change the seam wired only push/pop/shift/unshift, so
//! these resolved to `undefined` and errored when called.
//!
//! Value-asserting (not merely `eval == Ok`): each checks `ExecutionResult.value`
//! through `HybridRouter::eval`, mirroring `array_prototype_push_disc012.rs` /
//! `array_prototype_mutators_bd962ev.rs`.

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
fn index_of_returns_first_strict_match_or_minus_one() {
    assert_eq!(eval_value("[10, 20, 30].indexOf(20);"), "1");
    assert_eq!(eval_value("[10, 20, 30].indexOf(10);"), "0");
    assert_eq!(eval_value("[10, 20, 30].indexOf(99);"), "-1");
    // strict equality: a string "20" does not match the number 20.
    assert_eq!(eval_value("[10, 20, 30].indexOf(\"20\");"), "-1");
    // first match wins.
    assert_eq!(eval_value("[5, 7, 5].indexOf(5);"), "0");
}

#[test]
fn index_of_honors_from_index() {
    // search starting past the first occurrence finds the later one.
    assert_eq!(eval_value("[5, 7, 5].indexOf(5, 1);"), "2");
    // negative fromIndex counts from the end.
    assert_eq!(eval_value("[5, 7, 5].indexOf(5, -1);"), "2");
    // fromIndex beyond length yields no match.
    assert_eq!(eval_value("[5, 7, 5].indexOf(7, 5);"), "-1");
}

#[test]
fn includes_reports_membership() {
    assert_eq!(eval_value("[1, 2, 3].includes(2);"), "true");
    assert_eq!(eval_value("[1, 2, 3].includes(9);"), "false");
    assert_eq!(eval_value("[1, 2, 3].includes(1, 1);"), "false");
    assert_eq!(eval_value("[1, 2, 3].includes(3, 1);"), "true");
}

#[test]
fn reverse_reverses_in_place_and_returns_array() {
    assert_eq!(eval_value("let a = [1, 2, 3]; a.reverse(); a[0];"), "3");
    assert_eq!(eval_value("let a = [1, 2, 3]; a.reverse(); a[1];"), "2");
    assert_eq!(eval_value("let a = [1, 2, 3]; a.reverse(); a[2];"), "1");
    assert_eq!(eval_value("let a = [1, 2, 3]; a.reverse(); a.length;"), "3");
    // even-length arrays reverse cleanly too.
    assert_eq!(eval_value("let a = [1, 2, 3, 4]; a.reverse(); a[0];"), "4");
    assert_eq!(eval_value("let a = [1, 2, 3, 4]; a.reverse(); a[3];"), "1");
}

#[test]
fn fill_fills_range_in_place() {
    // no bounds: fill the whole array.
    assert_eq!(eval_value("let a = [1, 2, 3]; a.fill(0); a[0];"), "0");
    assert_eq!(eval_value("let a = [1, 2, 3]; a.fill(0); a[2];"), "0");
    // start only: leave the prefix untouched.
    assert_eq!(eval_value("let a = [1, 2, 3]; a.fill(9, 1); a[0];"), "1");
    assert_eq!(eval_value("let a = [1, 2, 3]; a.fill(9, 1); a[1];"), "9");
    // start and (exclusive) end.
    assert_eq!(
        eval_value("let a = [1, 2, 3, 4]; a.fill(7, 1, 3); a[0];"),
        "1"
    );
    assert_eq!(
        eval_value("let a = [1, 2, 3, 4]; a.fill(7, 1, 3); a[1];"),
        "7"
    );
    assert_eq!(
        eval_value("let a = [1, 2, 3, 4]; a.fill(7, 1, 3); a[3];"),
        "4"
    );
}

#[test]
fn join_concatenates_with_separator() {
    assert_eq!(eval_value("[1, 2, 3].join();"), "1,2,3");
    assert_eq!(eval_value("[1, 2, 3].join(\"-\");"), "1-2-3");
    // single element, no separator emitted.
    assert_eq!(eval_value("[42].join(\"-\");"), "42");
    // empty array joins to the empty string.
    assert_eq!(eval_value("[].join(\",\");"), "");
}
