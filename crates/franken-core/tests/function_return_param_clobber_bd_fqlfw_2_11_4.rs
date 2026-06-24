//! Regression tests for bd-fqlfw.2.11.4 — function-body completion-convention.
//!
//! FUNCTION-LEVEL TWIN of bd-fqlfw.2.11.1. franken-core's function-body
//! IR2→IR3 lowering overloaded register 0 as BOTH the function's first
//! parameter (the calling convention writes args to the callee window at
//! r0,r1,...) AND the completion register: the function-body `Pop` handler
//! emitted `Move { dst: 0, src: reg }` and the function-body `Return` read r0
//! (the IR1 for `return X` is `[eval X, Pop, Return]`, and the preceding `Pop`
//! emptied the value stack so `Return` underflowed to `value: 0`).
//!
//! So `return <param0>` after an expression statement returned the clobbered
//! value (`f(a){ a+1; return a; }` returned `a+1`), and a function that fell
//! off the end returned param0 instead of `undefined`.
//!
//! The fix decouples function-body return delivery from r0 (the engine lane was
//! already correct): the function-body `Pop` DISCARDS without touching r0 (and
//! records the discarded register), `Return` delivers that actual register, and
//! the trailing implicit return loads `undefined`. The module-level completion
//! path (which legitimately reserves r0) is unchanged.
//!
//! Harness mirrors loop_call_register_clobber_bd_fqlfw_2_11_1.rs.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, QuickJsLane, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

use std::collections::BTreeSet;

fn run(source: &str) -> ExecutionResult {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_fqlfw_2_11_4");
    let context = LoweringContext::new(
        "bd-fqlfw-2-11-4-trace",
        "bd-fqlfw-2-11-4-decision",
        "bd-fqlfw-2-11-4-policy",
    );
    let module = lower_ir0_to_ir3(&ir0, &context)
        .expect("source should lower")
        .ir3;
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    QuickJsLane::with_config(config)
        .execute(&module, "bd-fqlfw-2-11-4-trace")
        .expect("execution should succeed")
}

fn completion(source: &str) -> Value {
    run(source).value
}

// --- The bug: `return <param0>` after an expression statement ---

#[test]
fn return_param0_after_expression_statement_reads_the_real_param() {
    // The canonical repro: the intervening `a+1;` expression statement must NOT
    // clobber param `a`. `return a` delivers 5, not 6.
    let src = "function f(a){ a+1; return a; } f(5);";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn return_param0_after_multiple_expression_statements() {
    let src = "function h(a){ a+1; a+2; a+3; return a; } h(7);";
    assert_eq!(completion(src), Value::Int(7));
}

#[test]
fn return_param0_after_expression_statement_in_two_param_fn() {
    // param0 (`a`) survives the expression statement; `return a` delivers 4.
    let src = "function g(a,b){ a+b; return a; } g(4,5);";
    assert_eq!(completion(src), Value::Int(4));
}

// --- Fall-off-end and bare-return must yield `undefined`, not param0 ---

#[test]
fn fall_off_end_returns_undefined_not_param0() {
    let src = "function k(a){ a; } k(9);";
    assert_eq!(completion(src), Value::Undefined);
}

#[test]
fn empty_body_returns_undefined_not_param0() {
    let src = "function e(a){} e(3);";
    assert_eq!(completion(src), Value::Undefined);
}

#[test]
fn bare_return_yields_undefined() {
    let src = "function r(a){ a+1; return; } r(8);";
    assert_eq!(completion(src), Value::Undefined);
}

// --- Controls / regression guards (must NOT regress) ---

#[test]
fn return_param1_still_delivers() {
    // Returning a non-first parameter always worked (the return-delivery Pop
    // overwrote r0 with the right value just before Return); pin it.
    let src = "function r(a,b){ return b; } r(4,5);";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn two_param_return_after_expression_statement_does_not_regress() {
    // The prior session's naive discard regressed this 9 -> 2; pin 9.
    let src = "function s(a,b){ a+b; return a+b; } s(4,5);";
    assert_eq!(completion(src), Value::Int(9));
}

#[test]
fn return_literal_after_expression_statement() {
    let src = "function lit(a){ a; return 42; } lit(1);";
    assert_eq!(completion(src), Value::Int(42));
}

#[test]
fn return_computed_expression_still_works() {
    let src = "function add(a,b){ return a+b; } add(2,3);";
    assert_eq!(completion(src), Value::Int(5));
}

#[test]
fn no_param_function_return_after_expression_statement() {
    // No parameter pinned to r0 at all — the value must still be delivered.
    let src = "function c(){ var x = 10; x+1; return x; } c();";
    assert_eq!(completion(src), Value::Int(10));
}
