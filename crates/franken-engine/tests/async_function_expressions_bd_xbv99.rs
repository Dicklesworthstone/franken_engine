//! bd-xbv99: async function *expressions* (arrow and `function`) must be real
//! async functions.
//!
//! Before the fix the expression parser did not recognize `async()=>...`
//! (no space before the parameter list) or `async function (...) {...}` in
//! expression position, fell through to `Expression::Raw`, and lowering turned
//! the source text into a string literal that was then called:
//! `const f = async()=>{ return 1 }; f()` faulted with "expected function, got
//! string". Async function *declarations* were unaffected.
//!
//! Expected outputs are Node v22.2.0's for the same source.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::ir_contract::{Ir0Module, Ir1Literal, Ir1Op};
use frankenengine_engine::lowering_pipeline::lower_ir0_to_ir1;
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};

fn eval_console(name: &str, source: &str) -> String {
    let mut engine = HybridRouter::default();
    let outcome = engine
        .eval(source)
        .unwrap_or_else(|error| panic!("{name}: eval failed for {source:?}: {error}"));
    outcome
        .console_output
        .iter()
        .map(|entry| entry.message.clone())
        .collect::<Vec<_>>()
        .join("|")
}

const CASES: &[(&str, &str, &str)] = &[
    (
        "async_arrow_iife_without_space",
        "(async()=>{ console.log('in') })(); console.log('out');",
        "in|out",
    ),
    (
        "async_arrow_bound_then_called",
        "const f = async()=>{ return 1 }; f().then(v=>console.log('v', v));",
        "v 1",
    ),
    (
        "async_function_expression",
        "const g = async function(){ return 7 }; g().then(v=>console.log(v));",
        "7",
    ),
    (
        "named_async_function_expression_iife",
        "(async function named(){ console.log('named') })();",
        "named",
    ),
    (
        "async_arrow_identifier_parameter",
        "const h = async x => x * 2; h(21).then(v=>console.log(v));",
        "42",
    ),
    (
        "async_arrow_with_await",
        "const k = async (a, b) => { const s = await Promise.resolve(a + b); return s }; k(1, 2).then(v=>console.log(v));",
        "3",
    ),
    // `async` is also an ordinary identifier; the arrow change must not turn
    // these into async arrows.
    (
        "async_as_called_function_name",
        "function async(x){ return x + 1 } console.log(async(1));",
        "2",
    ),
    (
        "async_as_arrow_parameter_name",
        "const id = async => async + 1; console.log(id(41));",
        "42",
    ),
    // Generator function expressions used to be rejected by the same
    // expression arm (`function*` was not accepted after `function`).
    (
        "generator_function_expression",
        "const gen = function*(){ yield 1; yield 2 }; console.log([...gen()].join());",
        "1,2",
    ),
];

#[test]
fn async_function_expressions_run_like_node_bd_xbv99() {
    for (name, source, expected) in CASES {
        assert_eq!(eval_console(name, source), *expected, "{name}: {source}");
    }
}

#[test]
fn function_expressions_never_lower_to_their_source_text_bd_xbv99() {
    // The failure mode was a string literal holding the unparsed expression
    // followed by a call. No case may lower any literal equal to a function
    // expression's own source.
    for (name, source, _) in CASES {
        let tree = CanonicalEs2020Parser
            .parse(*source, ParseGoal::Script)
            .unwrap_or_else(|error| panic!("{name}: parse failed: {error}"));
        let ir0 = Ir0Module::from_syntax_tree(tree, format!("{name}.js"));
        let ir1 = lower_ir0_to_ir1(&ir0)
            .unwrap_or_else(|error| panic!("{name}: lowering failed: {error}"));
        for op in &ir1.module.ops {
            if let Ir1Op::LoadLiteral {
                value: Ir1Literal::String(text),
            } = op
            {
                let text = text.to_string();
                assert!(
                    !(text.contains("=>") || text.contains("function")),
                    "{name}: an expression was lowered as its source text {text:?}"
                );
            }
        }
    }
}
