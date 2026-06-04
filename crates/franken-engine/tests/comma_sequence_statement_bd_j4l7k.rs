//! Regression: a bare expression statement that is a top-level comma sequence
//! (`a, b`) must evaluate each operand left-to-right and yield the last
//! (ES2020 §13.16 / §14.5). Before the fix it fell through to `Expression::Raw`
//! and the statement's value was the literal source string (e.g. `"a,b"`).
//!
//! Bead: bd-j4l7k (sibling of bd-qxkli, which fixed the same gap in `for`-header
//! clauses). FIX (JadeOx): the expression-statement fall-through in
//! `parse_statement` now uses `parse_expression_allowing_sequence`, applying the
//! shared `build_sequence_expression` desugar. Variable declarations
//! (`let a = 1, b = 2`) are parsed earlier and are unaffected.

use frankenengine_engine::HybridRouter;

fn ev(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(o) => o.value,
        Err(e) => format!("ERR:{e}"),
    }
}

#[test]
fn bare_comma_statement_yields_last() {
    assert_eq!(ev("let a=1,b=2; a,b"), "2");
}

#[test]
fn bare_comma_statement_runs_side_effects() {
    // a=5 operand executes, statement value is the last operand (a+1 == 6)
    assert_eq!(ev("let a=0; a=5, a+1"), "6");
}

#[test]
fn bare_comma_statement_side_effect_persists() {
    assert_eq!(ev("let a=0; a=5, a+1; a"), "5");
}

#[test]
fn bare_comma_statement_three_operands() {
    assert_eq!(ev("let x=1; x=x+1, x=x+1, x"), "3");
}

#[test]
fn variable_declaration_commas_unaffected() {
    // The declaration's commas separate declarators — NOT a sequence operator.
    assert_eq!(ev("let a=1,b=2,c=3; a+b+c"), "6");
}

#[test]
fn single_expression_statement_unchanged() {
    assert_eq!(ev("let a=2; a+3"), "5");
}

#[test]
fn parenthesized_sequence_statement_still_works() {
    assert_eq!(ev("(1,2,3)"), "3");
}
