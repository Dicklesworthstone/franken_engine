//! Regression: compound-assignment used as an EXPRESSION value over a CAPTURED
//! variable inside a function/closure must read the captured value, not an
//! uninitialised local register.
//!
//! Bead: bd-ut6ku (follow-up to bd-um9a3, which fixed top-level `++`/`--`).
//!
//! ROOT CAUSE (pinned via IR dump + `HybridRouter::eval` at HEAD): the IR1->IR3
//! function-body lowering identifies a function's free (captured) variables by
//! scanning `body_ops` for `LoadBinding`/`StoreBinding` only — both in
//! `free_var_binding_ids` and `fv_id_to_name` (lowering_pipeline.rs ~4537/4565).
//! A captured variable that is referenced ONLY via `AssignOp` (a compound
//! read-modify-write with no separate read) was therefore omitted from the
//! free-var set, so its `AssignOp` fell through to the local-binding path and
//! operated on a freshly-allocated, uninitialised register -> `NaN`.
//!
//! This is exactly what postfix `c++` desugars to (bd-um9a3): `(c += 1) - 1`,
//! where `c` is read only through the compound assignment. At top level it
//! worked (module-level lowering); inside a function body, `return c++` yielded
//! `NaN`, so every `for (let i = 0; i < n; i++) { ... }` written inside a
//! function misbehaved.
//!
//! FIX: include `Ir1Op::AssignOp` in both free-var scans, so a solely
//! compound-assigned captured variable is resolved through the scoped
//! (LoadScoped/StoreScoped) path like every other capture.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn postfix_increment_expression_over_captured_var_reads_captured_value() {
    // `return c++` => `(c += 1) - 1`; c starts 5, returns old value 5, c becomes 6.
    assert_eq!(
        eval_value("let c = 5; let f = function () { return c++; }; f();"),
        "5"
    );
}

#[test]
fn explicit_compound_assign_expression_over_captured_var() {
    // The desugar, written out: (c += 1) - 1 == 5 when c starts at 5.
    assert_eq!(
        eval_value("let c = 5; let f = function () { return (c += 1) - 1; }; f();"),
        "5"
    );
}

#[test]
fn prefix_increment_expression_over_captured_var_reads_new_value() {
    // `return ++c` => `c += 1`; returns the new value 6.
    assert_eq!(
        eval_value("let c = 5; let f = function () { return ++c; }; f();"),
        "6"
    );
}

#[test]
fn compound_assign_statement_over_captured_var_still_works() {
    // Was already correct (the `return c` emits a LoadBinding that registered
    // the free var); pin it so the fix doesn't regress it.
    assert_eq!(
        eval_value("let c = 5; let f = function () { c += 1; return c; }; f();"),
        "6"
    );
}

#[test]
fn postfix_increment_expression_over_local_var_still_works() {
    // Local (non-captured) var uses the local-binding path; pin it.
    assert_eq!(
        eval_value("let f = function () { var c = 5; return c++; }; f();"),
        "5"
    );
}

#[test]
fn closure_counter_advances_across_calls() {
    // The canonical "counter closure": each call returns the pre-increment
    // value and advances the captured counter. 0,1,2 across three calls.
    assert_eq!(
        eval_value(
            "let mk = function () { let c = 0; return function () { return c++; }; }; \
             let f = mk(); f(); f(); f();"
        ),
        "2"
    );
}

#[test]
fn c_style_for_loop_with_increment_inside_function_terminates_and_accumulates() {
    // The headline impact: `for (let i = 0; i < n; i++)` written INSIDE a
    // function. Sums 0+1+2+3 = 6; before the fix the `i++` update misbehaved.
    assert_eq!(
        eval_value(
            "let sum = function (n) { let s = 0; for (let i = 0; i < n; i++) { s = s + i; } return s; }; \
             sum(4);"
        ),
        "6"
    );
}
