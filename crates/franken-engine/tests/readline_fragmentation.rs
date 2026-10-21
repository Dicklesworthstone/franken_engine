//! Exercise the shared line collector through native parsing, lowering and VM.
//! Host-factory differential checks do not establish that these tests pass.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const COMMONJS: &str = "const __readline = require('node:readline');\n\
    const { EventEmitter: __EventEmitter } = require('node:events');\n";
const ESM: &str = "import * as __readline from 'node:readline';\n\
    import { EventEmitter as __EventEmitter } from 'node:events';\n";
const EXPECTED: &str =
    "readline fragmentation: content, EOF, UTF-16, UTF-8, reentry, question, iteration";

fn run(shadow_array: bool) {
    for (goal, imports) in [(ParseGoal::Script, COMMONJS), (ParseGoal::Module, ESM)] {
        let shadow = if shadow_array { "const Array = null;\n" } else { "" };
        let source = format!(
            "{imports}{shadow}{}\n\
             verifyReadlineFragments(__readline, __EventEmitter).then(\
                 function (result) {{ console.log(result); }});",
            include_str!("fixtures/readline_fragmentation.js"),
        );
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "readline-fragmentation.js".into(),
                    text: source,
                },
                goal,
                &ParserOptions::default(),
            )
            .expect("shared fragmentation fixture parses");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "readline-fragmentation.js"),
            &LoweringContext::new("readline", "fragmentation", "builtin-only"),
        )
        .expect("canonical readline module imports lower")
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
                ]
                .into_iter()
                .collect();
                let mut core = InterpreterCore::new(config, "readline-fragmentation");
                core.set_gc_stress_interval(stress);
                let result = core.execute(&module).unwrap_or_else(|error| {
                    panic!("throughput={throughput}, stress={stress:?}: {error}")
                });
                let lines: Vec<_> = result
                    .console_output
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect();
                assert_eq!(lines, [EXPECTED], "asynchronous completion must run");
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes(),
                );
            }
        }
    }
}

#[test]
fn fragmented_line_output_and_teardown_complete_in_both_module_modes() {
    run(false);
}

#[test]
fn fragment_join_does_not_depend_on_a_guest_array_constructor_binding() {
    run(true);
}
