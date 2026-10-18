//! Shared protocol programs through the actual parser, lowerer and interpreter.
//! The Node-host reference runner does not execute this test target.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const CASES: &str = include_str!("fixtures/stream_operator_protocol.js");
const CASE_COUNT: usize = 19;

fn run_case(index: usize, esm: bool) {
    let header = if esm {
        "import { Readable } from 'node:stream';\n"
    } else {
        "const { Readable } = require('node:stream');\n"
    };
    let expected = format!("OPERATOR_PROTOCOL_OK {index}");
    let source = format!(
        "{header}const cases = {CASES};\n\
         if (cases.length !== {CASE_COUNT}) throw new Error('protocol case count drift');\n\
         cases[{index}][1](Readable).then(() => console.log('{expected}'));\n"
    );
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "stream-operator-protocol.js".to_string(),
                text: source,
            },
            if esm { ParseGoal::Module } else { ParseGoal::Script },
            &ParserOptions::default(),
        )
        .expect("protocol fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "stream-operator-protocol.js"),
        &LoweringContext::new("stream-operator-protocol", "iteration", "builtin-only"),
    )
    .expect("protocol fixture lowers")
    .ir3;
    for throughput in [false, true] {
        for stress in [None, Some(1), Some(7)] {
            let mut config = if throughput {
                InterpreterConfig::v8_defaults()
            } else {
                InterpreterConfig::quickjs_defaults()
            };
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
                RuntimeCapability::Builtin,
                RuntimeCapability::Console,
                RuntimeCapability::ModuleLoad,
            ]
            .into_iter()
            .collect();
            let mut core = InterpreterCore::new(config, "stream-operator-protocol");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&module).unwrap_or_else(|error| {
                panic!("case {index}, esm={esm}, throughput={throughput}, gc={stress:?}: {error}")
            });
            let lines: Vec<_> = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect();
            // Success must include settlement, not merely a clean VM exit.
            assert_eq!(lines, [expected.as_str()], "case {index}, esm={esm}");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "case {index}, esm={esm}, throughput={throughput}, gc={stress:?}"
            );
        }
    }
}

#[test]
fn commonjs_operators_preserve_protocol_and_cancellation_on_both_profiles() {
    for index in 0..CASE_COUNT {
        run_case(index, false);
    }
}

#[test]
fn esm_operators_share_single_read_and_abrupt_completion_behavior() {
    for index in [0, 2, 7, 12] {
        run_case(index, true);
    }
}
