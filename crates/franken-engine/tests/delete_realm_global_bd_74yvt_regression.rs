//! bd-74yvt regression — `delete` of an identifier that names a sloppy-created
//! realm global must remove it, not merely return `true`.
//!
//! A sloppy assignment to an unresolvable identifier (`x = 1`) installs a
//! realm dynamic global. Before the name-delete seam, `delete x` returned
//! `true` without removing that property, so `typeof x` still reported the
//! stale value's type. These full-pipeline checks pin the ES `delete`
//! semantics: remove the configurable global and evaluate to `undefined`
//! afterwards, while genuinely missing names still succeed with no GetValue.

use frankenengine_engine::{EvalOutcome, HybridRouter};

fn eval(source: &str) -> EvalOutcome {
    HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|err| panic!("HybridRouter::eval failed for {source:?}: {err}"))
}

fn console_text(outcome: &EvalOutcome) -> String {
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn delete_removes_sloppy_created_realm_global() {
    let outcome = eval("x = 1; delete x; console.log(typeof x);");
    assert_eq!(
        console_text(&outcome).trim(),
        "undefined",
        "delete must remove the sloppy-created realm global"
    );
}

#[test]
fn delete_identifier_returns_true_for_sloppy_global() {
    let outcome = eval("x = 1; console.log(delete x);");
    assert_eq!(
        console_text(&outcome).trim(),
        "true",
        "deleting a configurable realm global succeeds"
    );
}

#[test]
fn delete_missing_identifier_returns_true_without_side_effects() {
    let outcome = eval("console.log(delete never_defined_bd_74yvt);");
    assert_eq!(
        console_text(&outcome).trim(),
        "true",
        "delete of an unresolvable identifier is true with no GetValue"
    );
}

#[test]
fn delete_then_reassign_reinstalls_the_global() {
    let outcome = eval("x = 1; delete x; x = 2; console.log(typeof x + \":\" + x);");
    assert_eq!(
        console_text(&outcome).trim(),
        "number:2",
        "a fresh sloppy assignment after delete reinstalls the global"
    );
}
