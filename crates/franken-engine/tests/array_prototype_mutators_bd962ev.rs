//! Regression coverage for bd-962ev: receiver-aware `Array.prototype`
//! mutators beyond `push` — `pop`, `shift`, and `unshift`. Before this change
//! `arr.pop()` / `arr.shift()` / `arr.unshift(x)` resolved to `undefined`
//! (the `array_prototype_method` seam wired only `push`), so the calls errored
//! with "expected function, got undefined".
//!
//! These assert the exact runtime values (not merely `eval == Ok`) so the
//! is_ok conformance harness cannot mask a wrong-value regression. They mirror
//! the `array_prototype_push_disc012.rs` style and continue the DISC-012 /
//! bd-bg9l1.27.9 pattern (`array_push()` + `array_prototype_method` + the
//! `dispatch_builtin_function` arm with dense-length cache coherence).

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
fn pop_returns_last_element_and_decrements_length() {
    // pop returns the removed last element.
    assert_eq!(eval_value("let a = [1, 2, 3]; a.pop();"), "3");
    // pop mutates `this`: length shrinks and the tail index is gone.
    assert_eq!(eval_value("let a = [1, 2, 3]; a.pop(); a.length;"), "2");
    assert_eq!(eval_value("let a = [1, 2, 3]; a.pop(); a[1];"), "2");
    // repeated pop walks back down the array.
    assert_eq!(
        eval_value("let a = [1, 2, 3]; a.pop(); a.pop(); a[0];"),
        "1"
    );
    assert_eq!(
        eval_value("let a = [1, 2, 3]; a.pop(); a.pop(); a.length;"),
        "1"
    );
}

#[test]
fn pop_on_empty_array_leaves_length_zero() {
    // pop on an empty array must not error and must leave length at 0.
    assert_eq!(eval_value("let a = []; a.pop(); a.length;"), "0");
}

#[test]
fn push_then_pop_round_trips() {
    // push/pop compose: push returns new length, pop returns what was pushed.
    assert_eq!(
        eval_value("let a = []; a.push(7); a.push(8); a.pop();"),
        "8"
    );
    assert_eq!(
        eval_value("let a = []; a.push(7); a.push(8); a.pop(); a.length;"),
        "1"
    );
}

#[test]
fn shift_returns_first_element_and_reindexes() {
    // shift returns the removed first element.
    assert_eq!(eval_value("let a = [1, 2, 3]; a.shift();"), "1");
    // remaining elements move down one index.
    assert_eq!(eval_value("let a = [1, 2, 3]; a.shift(); a[0];"), "2");
    assert_eq!(eval_value("let a = [1, 2, 3]; a.shift(); a[1];"), "3");
    assert_eq!(eval_value("let a = [1, 2, 3]; a.shift(); a.length;"), "2");
    // repeated shift drains from the front.
    assert_eq!(
        eval_value("let a = [1, 2, 3]; a.shift(); a.shift(); a[0];"),
        "3"
    );
}

#[test]
fn shift_on_empty_array_leaves_length_zero() {
    assert_eq!(eval_value("let a = []; a.shift(); a.length;"), "0");
}

#[test]
fn unshift_prepends_and_returns_new_length() {
    // unshift returns the new length.
    assert_eq!(eval_value("let a = [2, 3]; a.unshift(1);"), "3");
    // prepended element lands at index 0; existing elements shift up.
    assert_eq!(eval_value("let a = [2, 3]; a.unshift(1); a[0];"), "1");
    assert_eq!(eval_value("let a = [2, 3]; a.unshift(1); a[1];"), "2");
    assert_eq!(eval_value("let a = [2, 3]; a.unshift(1); a[2];"), "3");
    // multiple arguments are prepended in order.
    assert_eq!(eval_value("let a = [3]; a.unshift(1, 2); a.length;"), "3");
    assert_eq!(eval_value("let a = [3]; a.unshift(1, 2); a[0];"), "1");
    assert_eq!(eval_value("let a = [3]; a.unshift(1, 2); a[1];"), "2");
    assert_eq!(eval_value("let a = [3]; a.unshift(1, 2); a[2];"), "3");
}

#[test]
fn unshift_onto_empty_array() {
    assert_eq!(eval_value("let a = []; a.unshift(42);"), "1");
    assert_eq!(eval_value("let a = []; a.unshift(42); a[0];"), "42");
}

#[test]
fn shift_then_unshift_round_trips() {
    // shift removes the head; unshift puts a new head back.
    let src = "let a = [1, 2, 3]; a.shift(); a.unshift(9); a[0];";
    assert_eq!(eval_value(src), "9");
    let src_len = "let a = [1, 2, 3]; a.shift(); a.unshift(9); a.length;";
    assert_eq!(eval_value(src_len), "3");
}
