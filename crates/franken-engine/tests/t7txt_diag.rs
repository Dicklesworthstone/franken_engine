//! Regression coverage for bd-t7txt (labelled break/continue across a loop
//! boundary), kept live now that the fix has landed.
//!
//! ACTUAL ROOT CAUSE (fixed in 25ff606f): NOT the operand-stack/`value_stack`
//! unwinding originally hypothesised, but a parser statement-splitter bug. The
//! splitter only split after a block-closing `}` when the raw segment started
//! with a block keyword (for/while/if/...). A labelled statement starts with
//! `label:`, so `outer: for(;;){..} rest;` was never split — the labelled body
//! greedily absorbed `rest`, the inner block parsed as a Raw expression, and
//! lowering produced garbage IR (a string load + an infinite self-jump),
//! faulting at runtime with `expected function, got string` (and an infinite
//! loop for `label: while(){.. continue label;}`). `strip_leading_labels()`
//! now removes leading `label:` prefixes before the block-terminator check, so
//! labelled compound statements split exactly like their unlabelled forms. An
//! IR dump disproved the original value_stack-desync hypothesis.
//!
//! These tests assert the ECMA-correct behaviour: each program evaluates
//! without fault. They guard against regressions of the splitter fix.

use frankenengine_engine::HybridRouter;

fn eval_ok(src: &str) -> Result<(), String> {
    let mut engine = HybridRouter::default();
    engine.eval(src).map(|_| ()).map_err(|e| e.to_string())
}

#[test]
fn labelled_break_with_trailing_statement() {
    // Pre-fix this faulted ("expected function, got string"); must be Ok(0).
    eval_ok("outer: for (;;) { inner: for (;;) { break outer; } } 0;")
        .expect("labelled break followed by a statement must not fault");
}

#[test]
fn labelled_continue_inner_for_to_outer_while() {
    eval_ok(
        "let done = false; loop: while (!done) { done = true; for (;;) { continue loop; } } done;",
    )
    .expect("labelled continue from inner for to outer while must not fault");
}

#[test]
fn labelled_continue_direct_in_while_terminates() {
    // Pre-fix this exhausted the instruction budget (infinite loop).
    eval_ok("let done = false; loop: while (!done) { done = true; continue loop; } done;")
        .expect("labelled continue directly in a while must re-check the condition and terminate");
}
