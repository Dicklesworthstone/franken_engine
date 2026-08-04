//! Regression tests for bd-xi3bk — franken-core postfix/prefix `++`/`--` value
//! semantics when the result is consumed.
//!
//! bd-my5ar added `++`/`--` parser support by desugaring BOTH prefix and postfix
//! updates to a compound assignment (`i += 1` / `i -= 1`). That is correct for a
//! statement / for-update `i++` (the value is discarded) and for the *side
//! effect*, but a CONSUMED postfix update yields the wrong value: `var x = i++`
//! must bind i's PRIOR value to x, whereas a compound assignment yields the
//! incremented value. It is also incorrect for a non-numeric operand, since
//! `++`/`--` always operate on `ToNumber(operand)` while `+= 1` string-
//! concatenates a string.
//!
//! The fix introduces an `Expression::Update { operator, argument, prefix }` AST
//! node for identifier operands, lowered as: read operand, `ToNumber` (unary
//! `+`), stash the prior value for a postfix result, write back operand ± 1, and
//! yield the prior (postfix) or new (prefix) value. These tests pin the consumed
//! result value, the operand side effect, the ToNumber coercion, and that the
//! statement / for-update common case (bd-my5ar) still holds.

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
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_xi3bk");
    let context = LoweringContext::new("bd-xi3bk-trace", "bd-xi3bk-decision", "bd-xi3bk-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "bd-xi3bk-trace")
        .expect("execution should succeed")
}

/// Completion value of a script whose final statement is an expression.
fn completion(source: &str) -> Value {
    run(source).value
}

// --- Consumed postfix yields the PRIOR value (the bd-xi3bk bug). --------------

#[test]
fn consumed_postfix_increment_yields_prior_value() {
    // The exact bd-xi3bk repro: x is bound to i's value BEFORE the increment.
    let src = "(function () { var i = 5; var x = i++; return x; })();";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn consumed_postfix_increment_still_mutates_operand() {
    let src = "(function () { var i = 5; var x = i++; return i; })();";
    assert_eq!(completion(src), Value::Int(6));
}

#[test]
fn consumed_postfix_decrement_yields_prior_value() {
    let src = "(function () { var i = 5; var x = i--; return x; })();";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn consumed_postfix_decrement_still_mutates_operand() {
    let src = "(function () { var i = 5; var x = i--; return i; })();";
    assert_eq!(completion(src), Value::Int(4));
}

// --- Consumed prefix yields the NEW value. ------------------------------------

#[test]
fn consumed_prefix_increment_yields_new_value() {
    let src = "(function () { var i = 5; var x = ++i; return x; })();";
    assert_eq!(completion(src), Value::Int(6));
}

#[test]
fn consumed_prefix_decrement_yields_new_value() {
    let src = "(function () { var i = 5; var x = --i; return x; })();";
    assert_eq!(completion(src), Value::Int(4));
}

// --- Postfix consumed in other value positions (bead examples). ---------------

#[test]
fn postfix_increment_consumed_in_subscript() {
    // `a[i++]` reads a at i's prior value, then advances i.
    let src = "(function () { var a = [10, 20, 30]; var i = 1; var x = a[i++]; return x; })();";
    assert_eq!(completion(src), Value::Int(20));
}

#[test]
fn postfix_increment_consumed_as_call_argument() {
    let src = "(function () { function f(n) { return n; } var i = 5; return f(i++); })();";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn postfix_increment_consumed_in_return() {
    let src = "(function () { var i = 5; return i++; })();";
    assert_eq!(completion(src), Value::Int(5));
}

// --- ToNumber coercion: `++` is numeric, unlike `+= 1`. -----------------------

#[test]
fn postfix_increment_coerces_string_operand_to_number() {
    // `i` starts as the string "5"; the consumed postfix result must be the
    // NUMBER 5 (ToNumber), not the string, and i must become the number 6 — not
    // the string "51" that `i += 1` would produce.
    let src = "(function () { var i = \"5\"; var x = i++; return x; })();";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn postfix_increment_string_operand_becomes_number() {
    let src = "(function () { var i = \"5\"; i++; return i; })();";
    assert_eq!(completion(src), Value::Int(6));
}

// --- Controls: statement / for-update common case still holds (bd-my5ar). -----

#[test]
fn statement_postfix_increment_still_mutates_binding() {
    let src = "(function () { var i = 7; i++; return i; })();";
    assert_eq!(completion(src), Value::Int(8));
}

#[test]
fn for_update_postfix_increment_still_accumulates() {
    let src = "(function () { var s = 0; for (var i = 0; i < 5; i++) { s += i; } return s; })();";
    assert_eq!(completion(src), Value::Int(10));
}

#[test]
fn for_update_prefix_increment_still_accumulates() {
    let src = "(function () { var s = 0; for (var i = 0; i < 5; ++i) { s += i; } return s; })();";
    assert_eq!(completion(src), Value::Int(10));
}
