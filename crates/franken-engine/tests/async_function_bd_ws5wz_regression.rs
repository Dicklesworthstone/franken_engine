//! Regression: async functions must lower to async function values, not plain closures.
//!
//! Bead: bd-ws5wz. The AST preserves `is_async`, and the baseline interpreter
//! already has `Value::AsyncFunction` call handling, but IR1 function ops dropped
//! the async flag. Eval therefore returned `[closure#N]` from `async fn()` calls
//! instead of a promise value.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

fn lowers_to_async_function(source: &str) -> bool {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse(source, ParseGoal::Script)
        .expect("source should parse");
    let ir0 = Ir0Module::from_syntax_tree(tree, "bd_ws5wz_async_function.js");
    let context = LoweringContext::new("trace-bd-ws5wz", "decision-bd-ws5wz", "policy-bd-ws5wz");
    let output = lower_ir0_to_ir3(&ir0, &context).expect("source should lower");

    output
        .ir3
        .instructions
        .iter()
        .any(|instruction| matches!(instruction, Ir3Instruction::CreateAsyncFunction { .. }))
}

fn eval_value(source: &str) -> String {
    let mut engine = HybridRouter::default();
    match engine.eval(source) {
        Ok(outcome) => outcome.value,
        Err(err) => format!("ERR:{err}"),
    }
}

fn assert_promise_value(source: &str) {
    let value = eval_value(source);
    assert!(
        value.starts_with("[promise#"),
        "expected async function call to return a promise, got {value:?} for {source:?}"
    );
    assert!(
        !value.contains("closure"),
        "async function call must not expose a plain closure value: {value:?}"
    );
}

#[test]
fn async_function_declaration_lowers_to_async_function() {
    assert!(
        lowers_to_async_function("async function f() { return 42; }\n"),
        "async declarations must emit CreateAsyncFunction, not CreateClosure"
    );
}

#[test]
fn async_arrow_function_lowers_to_async_function() {
    assert!(
        lowers_to_async_function("let f = async () => 5;\n"),
        "async arrow expressions must emit CreateAsyncFunction, not CreateClosure"
    );
}

#[test]
fn async_arrow_function_call_returns_promise() {
    assert_promise_value("let f = async () => 5; f();");
}
