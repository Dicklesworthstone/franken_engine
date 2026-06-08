//! Regression: a C-style `for`-loop whose update (or condition) clause is a bare,
//! unparenthesized comma sequence — e.g. `for (let i=0, j=10; i<3; i++, j--)` —
//! must evaluate every comma operand for its side effects each iteration.
//!
//! Bead: bd-qxkli. The comma/sequence-operator desugar (bd-wo6za) only fired
//! inside parentheses, so an unparenthesized clause fell through to
//! `Expression::Raw` (a string): the loop either faulted ("expected number, got
//! string" from the postfix `-1` desugar applied to a string) or, when the
//! counter update was stringified, never advanced and ran out of instruction
//! budget. FIX (JadeOx): parser-only — `parse_for_clause_expression` applies the
//! shared `build_sequence_expression` desugar to comma'd condition/update clauses.

use frankenengine_engine::HybridRouter;

fn ev(src: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(src) {
        Ok(o) => o.value,
        Err(e) => format!("ERR:{e}"),
    }
}

#[test]
fn for_update_comma_both_counters_advance() {
    // sum of (i+j) for i=0,1,2 and j=10,9,8 = 10+10+10 = 30
    assert_eq!(
        ev("let s=0; for(let i=0,j=10;i<3;i++,j--){ s+=i+j; } s"),
        "30"
    );
}

#[test]
fn for_update_comma_decrement_side_effect() {
    // j starts 10, decremented each of 3 iterations; last observed j is 8
    assert_eq!(
        ev("let last=0; for(let i=0,j=10;i<3;i++,j--){ last=j; } last"),
        "8"
    );
}

#[test]
fn for_update_comma_primary_counter_advances() {
    assert_eq!(
        ev("let last=0; for(let i=0,j=10;i<3;i++,j--){ last=i; } last"),
        "2"
    );
}

#[test]
fn for_update_comma_two_increments_terminates() {
    // Both counters increment; the loop must terminate (no infinite loop) and
    // j accumulates 0+1+2 = 3.
    assert_eq!(ev("let s=0; for(let i=0,j=0;i<3;i++,j++){ s+=j; } s"), "3");
}

#[test]
fn for_update_comma_three_expressions() {
    assert_eq!(
        ev("let s=0; for(let i=0,j=0,k=0;i<3;i++,j++,k++){ s+=k; } s"),
        "3"
    );
}

#[test]
fn for_single_update_unchanged() {
    // Single-expression update must still parse exactly as before.
    assert_eq!(ev("let s=0; for(let i=0;i<3;i++){ s+=i; } s"), "3");
}

#[test]
fn parenthesized_sequence_still_works() {
    // The pre-existing parenthesized comma-operator path must be unaffected.
    assert_eq!(ev("(1, 2, 3)"), "3");
    assert_eq!(ev("let i=0,j=10; (i++,j--); i + ',' + j"), "1,9");
}
