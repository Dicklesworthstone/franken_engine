//! Pending regression for bd-t7txt (labelled break/continue value_stack desync).
//!
//! ROOT CAUSE (pinned): the IR2->IR3 lowering threads a compile-time
//! `value_stack` of register refs (lowering_pipeline.rs). `Ir1Op::Jump`
//! (~:3822) emits the jump WITHOUT reconciling `value_stack`, and `Label`
//! (~:3805) does not reset it to a canonical depth. A labelled `break`/
//! `continue` jumps to an OUTER loop's label from a deeper `value_stack`
//! state, so register allocation after that label desyncs and a later read
//! hits the wrong register — surfacing at runtime as
//! `RuntimeFault: expected function, got string`.
//!
//! This also affects labelled `break` (bd-bg9l1.27.4 / 0780a152): it passed
//! its conformance case ONLY because that case had no statement after the
//! labelled loop. Any trailing statement triggers the fault.
//!
//! These tests are `#[ignore]`d so they do not fail CI while the lowering fix
//! is pending. Un-ignore them to verify the fix (they assert the
//! ECMA-correct behaviour: each program evaluates without fault).

use frankenengine_engine::HybridRouter;

fn eval_ok(src: &str) -> Result<(), String> {
    let mut engine = HybridRouter::default();
    engine.eval(src).map(|_| ()).map_err(|e| e.to_string())
}

#[test]
#[ignore = "bd-t7txt: labelled break/continue value_stack desync; un-ignore when fixed"]
fn labelled_break_with_trailing_statement() {
    // Currently faults ("expected function, got string"); should be Ok(0).
    eval_ok("outer: for (;;) { inner: for (;;) { break outer; } } 0;")
        .expect("labelled break followed by a statement must not fault");
}

#[test]
#[ignore = "bd-t7txt: labelled break/continue value_stack desync; un-ignore when fixed"]
fn labelled_continue_inner_for_to_outer_while() {
    eval_ok(
        "let done = false; loop: while (!done) { done = true; for (;;) { continue loop; } } done;",
    )
    .expect("labelled continue from inner for to outer while must not fault");
}

#[test]
#[ignore = "bd-t7txt: labelled continue direct-in-while loops forever; un-ignore when fixed"]
fn labelled_continue_direct_in_while_terminates() {
    // Currently exhausts the instruction budget (infinite loop).
    eval_ok("let done = false; loop: while (!done) { done = true; continue loop; } done;")
        .expect("labelled continue directly in a while must re-check the condition and terminate");
}
