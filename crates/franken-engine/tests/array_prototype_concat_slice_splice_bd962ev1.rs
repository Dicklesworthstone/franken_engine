//! Regression coverage for the remaining bd-962ev.1 non-callback Array.prototype
//! methods on the HybridRouter `array_prototype_method` seam: `concat`, `slice`,
//! `lastIndexOf`, and `splice`. Completes bd-962ev.1 (after
//! indexOf/includes/reverse/fill/join in 75ca2b59).
//!
//! Value-asserting through HybridRouter::eval.

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
fn concat_appends_arrays_and_values() {
    // Array argument is spread one level.
    assert_eq!(eval_value("let a = [1, 2]; a.concat([3, 4])[2];"), "3");
    assert_eq!(eval_value("let a = [1, 2]; a.concat([3, 4]).length;"), "4");
    // Non-array arguments are appended as single elements.
    assert_eq!(eval_value("let a = [1]; a.concat(2, 3).length;"), "3");
    assert_eq!(eval_value("let a = [1]; a.concat(2, 3)[2];"), "3");
    // Original array is not mutated.
    assert_eq!(eval_value("let a = [1, 2]; a.concat([3]); a.length;"), "2");
}

#[test]
fn slice_extracts_subrange() {
    assert_eq!(eval_value("let a = [1, 2, 3, 4]; a.slice(1, 3)[0];"), "2");
    assert_eq!(
        eval_value("let a = [1, 2, 3, 4]; a.slice(1, 3).length;"),
        "2"
    );
    // Negative start counts from the end; end defaults to length.
    assert_eq!(eval_value("let a = [1, 2, 3, 4]; a.slice(-2)[0];"), "3");
    assert_eq!(eval_value("let a = [1, 2, 3, 4]; a.slice(2).length;"), "2");
    // slice does not mutate the original.
    assert_eq!(
        eval_value("let a = [1, 2, 3, 4]; a.slice(1, 3); a.length;"),
        "4"
    );
}

#[test]
fn last_index_of_scans_backward() {
    assert_eq!(eval_value("[1, 2, 1, 3].lastIndexOf(1);"), "2");
    assert_eq!(eval_value("[5, 5, 5].lastIndexOf(5);"), "2");
    assert_eq!(eval_value("[1, 2, 3].lastIndexOf(9);"), "-1");
}

#[test]
fn splice_removes_and_returns() {
    // Remove 2 elements at index 1; returns the removed array.
    assert_eq!(eval_value("let a = [1, 2, 3, 4]; a.splice(1, 2)[0];"), "2");
    assert_eq!(
        eval_value("let a = [1, 2, 3, 4]; a.splice(1, 2).length;"),
        "2"
    );
    // The receiver shrinks and re-indexes in place.
    assert_eq!(
        eval_value("let a = [1, 2, 3, 4]; a.splice(1, 2); a.length;"),
        "2"
    );
    assert_eq!(
        eval_value("let a = [1, 2, 3, 4]; a.splice(1, 2); a[1];"),
        "4"
    );
}

#[test]
fn splice_inserts_items() {
    // deleteCount 0 + items inserts without removing.
    assert_eq!(
        eval_value("let a = [1, 4]; a.splice(1, 0, 2, 3); a.length;"),
        "4"
    );
    assert_eq!(
        eval_value("let a = [1, 4]; a.splice(1, 0, 2, 3); a[1];"),
        "2"
    );
    assert_eq!(
        eval_value("let a = [1, 4]; a.splice(1, 0, 2, 3); a[2];"),
        "3"
    );
    assert_eq!(
        eval_value("let a = [1, 4]; a.splice(1, 0, 2, 3); a[3];"),
        "4"
    );
}

#[test]
fn splice_then_push_appends_at_the_new_length() {
    // After splice shrinks the array, push must append at the post-splice
    // length, not the pre-splice one. The dense-length cache has to follow
    // splice's new length; a stale cache made push write past the end,
    // leaving holes (e.g. index 5 instead of 2 here).
    assert_eq!(
        eval_value("let a = [1, 2, 3, 4, 5]; a.splice(0, 3); a.push(9); a.length;"),
        "3"
    );
    assert_eq!(
        eval_value("let a = [1, 2, 3, 4, 5]; a.splice(0, 3); a.push(9); a[2];"),
        "9"
    );
    // Growing splice (net insert) then push: length 2 -> 4 -> 5.
    assert_eq!(
        eval_value("let a = [1, 4]; a.splice(1, 0, 2, 3); a.push(5); a.length;"),
        "5"
    );
    assert_eq!(
        eval_value("let a = [1, 4]; a.splice(1, 0, 2, 3); a.push(5); a[4];"),
        "5"
    );
}
