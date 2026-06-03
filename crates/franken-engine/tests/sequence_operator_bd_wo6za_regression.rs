//! Regression: the comma / sequence operator `(a, b, c)` must evaluate each
//! operand left-to-right and yield the LAST operand's value (ES2020 §13.16),
//! while the side effects of the earlier operands still occur.
//!
//! Bead: bd-wo6za. REPRO (`HybridRouter::eval`): `let x = (1,2,3); x;` yields
//! `"1,2,3"` (WRONG; expect `3`). The comma-joined rendering shows `(1,2,3)` is
//! mis-parsed (array-like / multi-value) instead of a SequenceExpression.
//!
//! SCOPE: there is no `SequenceExpression` AST node today, so the fix spans
//! ast.rs (add the node) + parser.rs (parse a parenthesized comma sequence) +
//! lowering_pipeline.rs (evaluate each operand, discard all but the last). A
//! parser-only desugar to an arrow IIFE does NOT work: `(a = 5, a + 1)` would
//! then write `a` inside a closure and hit the by-value-capture bug (bd-p89tp),
//! so the outer `a` would not update. lowering_pipeline.rs is leased by another
//! agent at staging time; these cases are `#[ignore]`d until the fix lands —
//! un-ignore them in that commit.
//!
//! They assert VALUES (not just `eval == Ok`), including the side-effect
//! ordering the conformance harness cannot see.

use frankenengine_engine::HybridRouter;

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

#[test]
fn sequence_yields_last_operand() {
    assert_eq!(eval_value("let x = (1, 2, 3); x"), "3");
}

#[test]
fn sequence_result_equals_last() {
    assert_eq!(eval_value("let r = ((1, 2, 3) === 3); r"), "true");
}

#[test]
fn sequence_evaluates_earlier_operands_for_side_effects() {
    // The earlier operand `a = 5` runs (side effect), and the result is the
    // last operand `a + 1` == 6.
    assert_eq!(eval_value("let a = 0; let r = (a = 5, a + 1); r"), "6");
}

#[test]
fn sequence_earlier_operand_side_effect_persists() {
    // After the sequence, the earlier operand's assignment is observable.
    assert_eq!(eval_value("let a = 0; (a = 5, a + 1); a"), "5");
}
