#![forbid(unsafe_code)]
//! Regression: labeled BLOCK statements (bd-rj2yz).
//!
//! `outer: { ... }` previously fell through to `Expression::Raw` (a string), so
//! the block body never executed and `break outer;` had no target. A labeled
//! block must (a) execute its body and (b) support `break <label>` to exit the
//! block early — mirroring the existing labeled-loop support.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn labeled_block_executes_body() {
    assert_eq!(eval_value("let r = 0; outer: { r = 5; } r"), "5");
}

#[test]
fn break_to_block_label_exits_early() {
    assert_eq!(
        eval_value("let r = 0; outer: { r = 1; break outer; r = 2; } r"),
        "1"
    );
}

#[test]
fn labeled_block_runs_multiple_statements() {
    assert_eq!(
        eval_value("let a = 0; let b = 0; lbl: { a = 2; b = 3; } a + b"),
        "5"
    );
}

#[test]
fn break_to_block_label_skips_remaining_statements() {
    assert_eq!(
        eval_value("let log = 0; m: { log = 1; break m; log = 99; } log"),
        "1"
    );
}
