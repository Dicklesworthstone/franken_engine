//! Regression: a closure that ASSIGNS to a captured outer binding must write
//! back to that binding — the mutation persists across calls and is visible to
//! the enclosing scope.
//!
//! Bead: bd-p89tp. REPRO (`HybridRouter::eval`):
//! `let c = 0; let inc = () => c = c + 1; inc(); inc(); c;` yields `"0"`
//! (WRONG; expect `2`). The closure CAPTURES `c` (reads work), but its
//! assignment hits a by-value CLONE of the captured binding, so the outer `c`
//! never updates.
//!
//! ROOT CAUSE (PurpleCave/SapphireBridge/CreamOx, IR-verified): closures capture
//! BY VALUE — `CreateClosure` snapshots a clone of the enclosing frame, and the
//! call/`restore_scope_chain_for_frame` path never propagates a closure's writes
//! back to the caller's live frames (module-level vars additionally live in
//! registers, disconnected from the scope binding the closure read/writes). This
//! is the SAME defect family as bd-g0aok (named-function self-reference reads the
//! captured name as undefined). The fix is the closure capture-RESOLUTION model
//! (box captured-mutable bindings into a shared cell, or write-back keyed on the
//! capture source) — baseline_interpreter.rs, leased by another agent at staging
//! time. These cases are `#[ignore]`d until it lands; un-ignore them then.
//!
//! They assert VALUES (silent stale-value bug the eval==Ok harness cannot see).

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
#[ignore = "bd-p89tp: blocked on closure capture-resolution model (by-value capture); un-ignore when landed"]
fn arrow_closure_assignment_persists() {
    assert_eq!(
        eval_value("let c = 0; let inc = () => c = c + 1; inc(); inc(); c"),
        "2"
    );
}

#[test]
#[ignore = "bd-p89tp: blocked on closure capture-resolution model; un-ignore when landed"]
fn function_expression_closure_assignment_persists() {
    assert_eq!(
        eval_value("let a = 0; let f = function () { a = a + 1; }; f(); f(); f(); a"),
        "3"
    );
}

#[test]
#[ignore = "bd-p89tp: blocked on closure capture-resolution model; un-ignore when landed"]
fn counter_factory_keeps_private_state() {
    // A returned closure over a function-local `let` must accumulate state.
    assert_eq!(
        eval_value(
            "function makeCounter() { let n = 0; return () => { n = n + 1; return n; }; } \
             let c = makeCounter(); c(); c(); c()"
        ),
        "3"
    );
}
