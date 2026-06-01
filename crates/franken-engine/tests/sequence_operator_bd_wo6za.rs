//! bd-wo6za — comma/sequence operator `(a, b, c)` evaluates each operand
//! left-to-right and yields the LAST (ES2020 §13.16).
//!
//! Before this, a parenthesized top-level comma list fell through to
//! `Expression::Raw`, so `(1,2,3)` rendered as the string "1,2,3". The parser
//! now desugars `(e0,…,eN)` to `((__seq_0,…,__seq_N) => __seq_N)(e0,…,eN)`:
//! arguments evaluate left-to-right (side effects preserved) and the arrow
//! returns the final operand. Parser-only — reuses existing arrow + call
//! lowering, no SequenceExpression IR.

use frankenengine_engine::HybridRouter;

fn eval(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

// ---- bead pins -----------------------------------------------------------

#[test]
fn sequence_yields_last_value() {
    assert_eq!(eval("(1,2,3);"), "3");
}

#[test]
fn sequence_strict_equals_last() {
    assert_eq!(eval("(1,2,3) === 3;"), "true");
}

#[test]
fn sequence_evaluates_side_effects_and_yields_last() {
    // (a=5, a+1) === 6 — earlier operand's assignment runs, value is the last.
    assert_eq!(eval("let a = 0; (a = 5, a + 1);"), "6");
}

#[test]
fn sequence_side_effect_persists_in_scope() {
    // …and a === 5 afterwards (the a=5 operand actually executed).
    assert_eq!(eval("let a = 0; (a = 5, a + 1); a;"), "5");
}

// ---- additional coverage -------------------------------------------------

#[test]
fn two_operand_sequence() {
    assert_eq!(eval("(10, 20);"), "20");
}

#[test]
fn left_to_right_order_of_mutations() {
    // each operand runs in order; final operand reads the accumulated value.
    assert_eq!(eval("let x = 1; (x = x + 1, x = x + 1, x);"), "3");
}

#[test]
fn nested_sequences() {
    assert_eq!(eval("((1, 2), (3, 4));"), "4");
}

// ---- grouping without a comma is unchanged --------------------------------

#[test]
fn plain_grouping_unchanged() {
    assert_eq!(eval("(42);"), "42");
}

#[test]
fn plain_grouping_expression_unchanged() {
    assert_eq!(eval("(2 + 3) * 4;"), "20");
}
