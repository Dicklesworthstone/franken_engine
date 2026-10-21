//! Execute the shared consumer programs through the native parser and runtime.
//! Host-factory test results are not evidence that this target has passed.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PROGRAM: &str = include_str!("fixtures/stream_consumer_fragmentation.js");

fn run_case(index: usize, esm: bool) {
    let header = if esm {
        "import * as consumer from 'node:stream/consumers';"
    } else {
        "const consumer = require('node:stream/consumers');"
    };
    let expected = format!("CONSUMER_FRAGMENTATION_OK {index}");
    let source = format!(
        "{header}\nconst program = {PROGRAM};\n\
         program(consumer, {index}).then(() => console.log('{expected}'));"
    );
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "consumer-fragmentation.js".to_string(),
                text: source,
            },
            if esm {
                ParseGoal::Module
            } else {
                ParseGoal::Script
            },
            &ParserOptions::default(),
        )
        .expect("consumer program parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "consumer-fragmentation.js"),
        &LoweringContext::new("consumer-fragmentation", "text", "builtin-only"),
    )
    .expect("consumer program lowers")
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
            let mut core = InterpreterCore::new(config, "consumer-fragmentation");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&module).unwrap_or_else(|error| {
                panic!("case {index}, esm={esm}, throughput={throughput}, gc={stress:?}: {error}")
            });
            let lines: Vec<_> = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect();
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
fn commonjs_consumers_preserve_fragmented_text_and_failures() {
    for index in 0..6 {
        run_case(index, false);
    }
}

#[test]
fn esm_consumers_preserve_fragmented_text_and_failures() {
    for index in 0..6 {
        run_case(index, true);
    }
}

#[test]
fn commonjs_consumers_isolate_private_storage_without_hiding_caller_protocols() {
    for index in 6..10 {
        run_case(index, false);
    }
}

#[test]
fn esm_consumers_isolate_private_storage_without_hiding_caller_protocols() {
    for index in 6..10 {
        run_case(index, true);
    }
}
