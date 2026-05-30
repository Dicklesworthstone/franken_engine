//! Regression coverage for bd-bg9l1.27.9 / DISC-012: `Array.prototype.push`
//! must be a receiver-aware method — it appends to the `this` array and returns
//! the new length. Before the fix, `arr.push` resolved to `undefined`
//! ("expected function, got undefined") because array exotic objects exposed no
//! prototype methods, and the receiver-less `builtin:ArrayPrototypePush` stub
//! allocated a throwaway array instead of mutating `this`.
//!
//! These assert the exact runtime values the conformance case
//! `break-for-of-early-exit` depends on (now promoted to EXPECTED_PASS).

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
fn push_mutates_receiver_and_returns_new_length() {
    // push returns the new length.
    assert_eq!(eval_value("let a = []; a.push(10);"), "1");
    assert_eq!(eval_value("let a = []; a.push(10); a.push(20);"), "2");
    // push mutates `this`: length and indexed reads reflect appended elements.
    assert_eq!(
        eval_value("let a = []; a.push(10); a.push(20); a.length;"),
        "2"
    );
    assert_eq!(
        eval_value("let a = []; a.push(10); a.push(20); a[1];"),
        "20"
    );
    // push onto a non-empty literal appends after the existing length.
    assert_eq!(eval_value("let a = [1, 2, 3]; a.push(4); a.length;"), "4");
    assert_eq!(eval_value("let a = [1, 2, 3]; a.push(4); a[3];"), "4");
}

#[test]
fn push_inside_for_of_with_early_break() {
    // The exact shape of the `break-for-of-early-exit` conformance case.
    let src = r#"
        let seen = [];
        for (const value of [1, 2, 3, 4, 5]) {
            seen.push(value);
            if (value === 3) break;
        }
        seen.length;
    "#;
    assert_eq!(eval_value(src), "3");
}
