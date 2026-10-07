#![forbid(unsafe_code)]

//! Creating a RegExp must not leave an inline-callback provenance context
//! behind. construct_regexp's ToString of the pattern recorded the context
//! label (json_observe_label) outside any scope that clears it, so after the
//! first regex literal every array element write took the context-joining
//! path: three more instructions per write (Test262's property-escape
//! harness ran 18% more instructions and 290 of its tests timed out in the
//! land38 census).

use std::collections::BTreeSet;

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions};

fn execute_source(label: &str, source: &str) -> ExecutionResult {
    let tree = CanonicalEs2020Parser
        .parse_with_options(source, ParseGoal::Script, &ParserOptions::default())
        .unwrap_or_else(|err| panic!("program `{label}` should parse: {err:?}"));
    let ir0 = Ir0Module::from_syntax_tree(tree, format!("regexp-context-{label}.js"));
    let ctx = LoweringContext::new(
        format!("trace-regexp-context-{label}"),
        format!("decision-regexp-context-{label}"),
        format!("policy-regexp-context-{label}"),
    );
    let lowering = lower_ir0_to_ir3(&ir0, &ctx)
        .unwrap_or_else(|err| panic!("program `{label}` should lower to IR3: {err:?}"));
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]);
    let mut core = InterpreterCore::new(config, format!("trace-regexp-context-{label}"));
    core.execute(&lowering.ir3)
        .unwrap_or_else(|err| panic!("program `{label}` should execute: {err:?}"))
}

/// 20,000 array writes cost the same with and without a regex literal (and
/// a RegExp construction whose pattern object runs its toString) before
/// them, up to the handful of instructions that create the RegExp. The
/// defect added 60,010 (measured on the land38 gate frankenctl).
#[test]
fn array_writes_after_a_regex_cost_what_they_cost_before() {
    let loop_source = "var a = []; for (var i = 0; i < 20000; i++) { a[i] = i; } a.length";
    let plain = execute_source("plain", loop_source);
    let literal = execute_source("literal", &format!("var r = /a/u;\n{loop_source}"));
    let constructed = execute_source(
        "constructed",
        &format!(
            "var r = new RegExp({{ toString: function () {{ return 'b'; }} }}, 'g');\n{loop_source}"
        ),
    );
    for result in [&plain, &literal, &constructed] {
        assert_eq!(result.value, Value::Int(20000));
    }
    for (label, result) in [("literal", &literal), ("constructed", &constructed)] {
        let extra = result
            .instructions_executed
            .saturating_sub(plain.instructions_executed);
        assert!(
            extra < 100,
            "{label}: {} instructions vs {} without the RegExp (+{extra})",
            result.instructions_executed,
            plain.instructions_executed
        );
    }
}
