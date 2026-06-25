//! Regression tests for bd-my5ar — engine<->core completion-value divergence
//! on a loop-accumulate function, surfaced by the bd-fqlfw.2.3.1 internal
//! differential oracle.
//!
//! Two independent franken-core defects conspired to make
//! `(function () { var s = 0; for (var i = 0; i < 5; i++) { s += i; } return s; })()`
//! return `0` instead of `10`:
//!
//!  1. **Function-body conditional/loop polarity.** The IR2->IR3 deferred
//!     function-body loop lowered `JumpIfFalsy` to a single `JumpIf`, but the
//!     interpreter's `JumpIf` jumps on TRUTHY — so every function-body `if`,
//!     ternary, `while`, and `for` test was inverted (the loop body / `if`
//!     consequent was skipped whenever the condition was true). The
//!     module-level loop already used the correct two-instruction
//!     "skip-on-truthy then jump-to-label" pattern; the fix gives the
//!     function-body loop the same pattern (and resolves its
//!     `PendingJump::JumpIfFalsy` targets).
//!
//!  2. **No `++` / `--` parser support.** The string-based parser mis-split
//!     postfix `i++` into `i + Raw("+")` and collapsed prefix `++i` into
//!     `+(+i)`, so the loop counter never advanced. Both forms now desugar to
//!     the equivalent compound assignment (`i += 1` / `i -= 1`).
//!
//! These tests pin both fixes across module-level and function-body contexts.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, QuickJsLane, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

use std::collections::BTreeSet;

/// Parse -> IR0 -> IR3 -> execute on the QuickJS lane with the minimal
/// execution capabilities, returning the full execution result.
fn run(source: &str) -> ExecutionResult {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_my5ar");
    let context = LoweringContext::new("bd-my5ar-trace", "bd-my5ar-decision", "bd-my5ar-policy");
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "bd-my5ar-trace")
        .expect("execution should succeed")
}

/// Completion value of a script whose final statement is an expression.
fn completion(source: &str) -> Value {
    run(source).value
}

// --- The bead repro and its near neighbours. ---------------------------------

#[test]
fn iife_for_loop_accumulate_returns_ten() {
    // The exact bd-my5ar corpus case: 0+1+2+3+4 == 10.
    let src = "(function () { var s = 0; for (var i = 0; i < 5; i++) { s += i; } return s; })();";
    assert_eq!(completion(src), Value::Int(10));
}

#[test]
fn iife_for_loop_accumulate_explicit_assign_returns_ten() {
    // Same loop with `s = s + i` / `i = i + 1` instead of `+=` / `++`: isolates
    // the function-body polarity fix from the `++` parser fix.
    let src = "(function () { var s = 0; for (var i = 0; i < 5; i = i + 1) { s = s + i; } return s; })();";
    assert_eq!(completion(src), Value::Int(10));
}

#[test]
fn iife_while_loop_accumulate_returns_ten() {
    let src = "(function () { var s = 0; var i = 0; while (i < 5) { s += i; i++; } return s; })();";
    assert_eq!(completion(src), Value::Int(10));
}

// --- Function-body conditional polarity. -------------------------------------

#[test]
fn iife_if_true_enters_body() {
    let src = "(function () { var s = 5; if (s > 0) { s = 99; } return s; })();";
    assert_eq!(completion(src), Value::Int(99));
}

#[test]
fn iife_if_false_skips_body() {
    let src = "(function () { var s = 5; if (s < 0) { s = 99; } return s; })();";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn iife_if_else_takes_then_branch_when_true() {
    let src = "(function () { var s = 5; if (s > 0) { s = 1; } else { s = 2; } return s; })();";
    assert_eq!(completion(src), Value::Int(1));
}

#[test]
fn iife_ternary_true_branch() {
    let src = "(function () { return (1 > 0) ? 11 : 22; })();";
    assert_eq!(completion(src), Value::Int(11));
}

#[test]
fn iife_while_false_does_not_run() {
    let src = "(function () { var s = 5; while (s > 100) { s = 0; } return s; })();";
    assert_eq!(completion(src), Value::Int(5));
}

// --- `++` / `--` parser support, prefix and postfix, both contexts. ----------

#[test]
fn module_level_for_postfix_increment() {
    // Module-level (main loop) `i++` — exercises the parser fix where the
    // main-loop polarity was already correct.
    let src = "var s = 0; for (var i = 0; i < 5; i++) { s += i; } s;";
    assert_eq!(completion(src), Value::Int(10));
}

#[test]
fn prefix_increment_in_loop() {
    let src = "(function () { var s = 0; for (var i = 0; i < 5; ++i) { s += i; } return s; })();";
    assert_eq!(completion(src), Value::Int(10));
}

#[test]
fn postfix_decrement_counts_down() {
    let src = "(function () { var n = 0; for (var i = 5; i > 0; i--) { n += 1; } return n; })();";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn prefix_increment_statement_mutates_binding() {
    // `++i` as a statement must increment the binding (was `+(+i)` = no-op).
    let src = "(function () { var i = 7; ++i; return i; })();";
    assert_eq!(completion(src), Value::Int(8));
}

#[test]
fn postfix_increment_statement_mutates_binding() {
    let src = "(function () { var i = 7; i++; return i; })();";
    assert_eq!(completion(src), Value::Int(8));
}

// --- Controls: nested loop + accumulation across both contexts. --------------

#[test]
fn nested_iife_loops_multiply() {
    let src = "(function () { var t = 0; for (var i = 0; i < 3; i++) { for (var j = 0; j < 4; j++) { t += 1; } } return t; })();";
    assert_eq!(completion(src), Value::Int(12));
}
