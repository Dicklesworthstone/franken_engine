//! Regression tests for bd-rmxao — franken-core member-target value semantics.
//!
//! Two related gaps surfaced while closing bd-xi3bk (which fixed *identifier*-
//! target update semantics but scoped member targets out):
//!
//! 1. NON-LOGICAL MEMBER COMPOUND ASSIGNMENT (`obj.x += rhs`, `a[i] *= rhs`, …)
//!    ignored the operator: the lowering evaluated `rhs` and stored it with a
//!    bare `SetProperty`, so `o.x += 1` set `o.x = 1` rather than `o.x + 1`. The
//!    fix loads the current property value, combines it with the RHS through the
//!    operator's `BinaryOp`, and writes the result back — evaluating the object
//!    and computed key exactly once.
//!
//! 2. CONSUMED MEMBER-TARGET POSTFIX/PREFIX (`obj.x++`, `a[i]--`) desugared to a
//!    compound assignment, which (a) yielded the NEW value even for a postfix
//!    update (should be the prior value) and (b) did not `ToNumber`-coerce the
//!    operand. Member targets now lower to `Expression::Update` with the same
//!    ToNumber + prior/new result semantics as identifier targets, again with
//!    single-evaluation of the object and computed key.
//!
//! These pin the combined value, the operand mutation, the consumed result value
//! (prior vs new), ToNumber coercion, computed-key targets, and that the object
//! and computed key are each evaluated exactly once.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, QuickJsLane, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

use std::collections::BTreeSet;

/// Parse -> IR0 -> IR3 -> execute on the QuickJS lane with the minimal execution
/// capabilities, returning the full execution result.
fn run(source: &str) -> ExecutionResult {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_rmxao");
    let context = LoweringContext::new("bd-rmxao-trace", "bd-rmxao-decision", "bd-rmxao-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "bd-rmxao-trace")
        .expect("execution should succeed")
}

/// Completion value of a script whose final statement is an expression.
fn completion(source: &str) -> Value {
    run(source).value
}

// --- GAP #2: non-logical member compound assignment loads + combines. ---------

#[test]
fn member_add_assign_combines_with_current_value() {
    // The exact bd-rmxao repro: `o.x += 3` must set o.x to 8, not 3.
    let src = "(function () { var o = {x: 5}; o.x += 3; return o.x; })();";
    assert_eq!(completion(src), Value::Int(8));
}

#[test]
fn member_subtract_assign_combines_with_current_value() {
    let src = "(function () { var o = {x: 5}; o.x -= 2; return o.x; })();";
    assert_eq!(completion(src), Value::Int(3));
}

#[test]
fn member_multiply_assign_combines_with_current_value() {
    let src = "(function () { var o = {x: 5}; o.x *= 4; return o.x; })();";
    assert_eq!(completion(src), Value::Int(20));
}

#[test]
fn member_bitwise_or_assign_combines_with_current_value() {
    // 5 | 2 == 7 — a bitwise compound operator, distinct from the arithmetic path.
    let src = "(function () { var o = {x: 5}; o.x |= 2; return o.x; })();";
    assert_eq!(completion(src), Value::Int(7));
}

#[test]
fn member_add_assign_yields_the_combined_value() {
    // A compound assignment is itself an expression whose value is the assigned
    // (combined) value.
    let src = "(function () { var o = {x: 5}; var y = (o.x += 3); return y; })();";
    assert_eq!(completion(src), Value::Int(8));
}

#[test]
fn member_add_assign_concatenates_strings() {
    // `+=` follows `+` semantics: two strings concatenate.
    let src = "(function () { var o = {s: \"a\"}; o.s += \"b\"; return o.s; })();";
    assert_eq!(completion(src), Value::str("ab"));
}

#[test]
fn computed_member_add_assign_combines_with_current_value() {
    let src = "(function () { var a = [10, 20, 30]; var i = 1; a[i] += 5; return a[1]; })();";
    assert_eq!(completion(src), Value::Int(25));
}

#[test]
fn plain_member_assignment_still_stores_the_rhs() {
    // Control: a plain `=` must remain a bare store (no load-combine).
    let src = "(function () { var o = {x: 5}; o.x = 9; return o.x; })();";
    assert_eq!(completion(src), Value::Int(9));
}

// --- GAP #1: consumed member-target postfix yields the PRIOR value. ------------

#[test]
fn consumed_member_postfix_increment_yields_prior_value() {
    let src = "(function () { var o = {x: 5}; var y = o.x++; return y; })();";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn consumed_member_postfix_increment_still_mutates_property() {
    let src = "(function () { var o = {x: 5}; var y = o.x++; return o.x; })();";
    assert_eq!(completion(src), Value::Int(6));
}

#[test]
fn consumed_member_postfix_decrement_yields_prior_value() {
    let src = "(function () { var o = {x: 5}; var y = o.x--; return y; })();";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn consumed_member_postfix_decrement_still_mutates_property() {
    let src = "(function () { var o = {x: 5}; var y = o.x--; return o.x; })();";
    assert_eq!(completion(src), Value::Int(4));
}

// --- GAP #1: consumed member-target prefix yields the NEW value. --------------

#[test]
fn consumed_member_prefix_increment_yields_new_value() {
    let src = "(function () { var o = {x: 5}; var y = ++o.x; return y; })();";
    assert_eq!(completion(src), Value::Int(6));
}

#[test]
fn consumed_member_prefix_increment_mutates_property() {
    let src = "(function () { var o = {x: 5}; ++o.x; return o.x; })();";
    assert_eq!(completion(src), Value::Int(6));
}

// --- GAP #1: computed member-target update. -----------------------------------

#[test]
fn consumed_computed_member_postfix_yields_prior_value() {
    // `a[i]++` reads a[1] (20), yields 20, then advances a[1] to 21.
    let src = "(function () { var a = [10, 20, 30]; var i = 1; var y = a[i]++; return y; })();";
    assert_eq!(completion(src), Value::Int(20));
}

#[test]
fn consumed_computed_member_postfix_mutates_element() {
    let src = "(function () { var a = [10, 20, 30]; var i = 1; a[i]++; return a[1]; })();";
    assert_eq!(completion(src), Value::Int(21));
}

// --- GAP #1: ToNumber coercion on a member operand. ---------------------------

#[test]
fn member_postfix_increment_coerces_string_property_to_number() {
    // o.x starts as the string "5"; the consumed postfix result must be the
    // NUMBER 5 (ToNumber), and o.x must become the number 6 — not the string
    // "51" that `o.x += 1` would produce.
    let src = "(function () { var o = {x: \"5\"}; var y = o.x++; return y; })();";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn member_postfix_increment_string_property_becomes_number() {
    let src = "(function () { var o = {x: \"5\"}; o.x++; return o.x; })();";
    assert_eq!(completion(src), Value::Int(6));
}

// --- Single-evaluation of the computed key (no double side effects). ----------
//
// A side-effecting *key expression* `i++` makes the single evaluation directly
// observable: if the key were evaluated twice, `i` would advance twice. (A
// closure-counter probe would be cleaner but is confounded by a franken-core
// nested-function closure write-back limitation, orthogonal to bd-rmxao.)

#[test]
fn computed_member_postfix_evaluates_key_expression_once() {
    // The computed key `i++` must be evaluated exactly once for the whole update,
    // so `i` advances from 0 to 1 (not 2) even though the reference is reused for
    // both the load and the store.
    let src = "(function () { var a = [10, 20]; var i = 0; a[i++]++; return i; })();";
    assert_eq!(completion(src), Value::Int(1));
}

#[test]
fn computed_member_postfix_uses_the_single_key_evaluation() {
    // The one key evaluation (i's prior value, 0) is the index actually updated:
    // a[0] advances from 10 to 11.
    let src = "(function () { var a = [10, 20]; var i = 0; a[i++]++; return a[0]; })();";
    assert_eq!(completion(src), Value::Int(11));
}

#[test]
fn computed_member_compound_assign_evaluates_key_expression_once() {
    let src = "(function () { var a = [10, 20]; var i = 0; a[i++] += 5; return i; })();";
    assert_eq!(completion(src), Value::Int(1));
}

#[test]
fn computed_member_compound_assign_uses_the_single_key_evaluation() {
    // The single key evaluation (0) is the index used, so a[0] becomes 15.
    let src = "(function () { var a = [10, 20]; var i = 0; a[i++] += 5; return a[0]; })();";
    assert_eq!(completion(src), Value::Int(15));
}
