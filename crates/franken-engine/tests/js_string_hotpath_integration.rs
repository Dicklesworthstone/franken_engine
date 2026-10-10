#![forbid(unsafe_code)]
//! Shared-string optimizations must remain correct through the actual IR3 lane.

use std::collections::BTreeSet;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};

fn expect_true(label: &str, source: &str) {
    let parser = CanonicalEs2020Parser;
    let tree = parser
        .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
        .unwrap_or_else(|err| panic!("{label} should parse: {err:?}"));
    let ir0 = Ir0Module::from_syntax_tree(tree, format!("string-hotpath-{label}.js"));
    let ctx = LoweringContext::new(
        format!("trace-string-hotpath-{label}"),
        format!("decision-string-hotpath-{label}"),
        format!("policy-string-hotpath-{label}"),
    );
    let lowering = lower_ir0_to_ir3(&ir0, &ctx)
        .unwrap_or_else(|err| panic!("{label} should lower: {err:?}"));
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    let mut core = InterpreterCore::new(config, format!("trace-string-hotpath-{label}"));
    let result = core
        .execute(&lowering.ir3)
        .unwrap_or_else(|err| panic!("{label} should execute: {err:?}"));
    assert_eq!(result.value, Value::Bool(true), "{label}");
}

#[test]
fn ascii_indexing_and_length_remain_exact() {
    expect_true(
        "ascii-indexing",
        include_str!("fixtures/string_hotpaths/ascii_indexing.js"),
    );
}

#[test]
fn unicode_surrogate_indexing_and_healing_remain_exact() {
    expect_true(
        "unicode-indexing",
        include_str!("fixtures/string_hotpaths/unicode_indexing.js"),
    );
}
