//! Exercise the shipped delimiter scanner through both public import modes.
//! The JS-on-Node differential suite is not evidence that these VM tests pass.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn run(goal: ParseGoal, imports: &str) {
    let source = format!(
        "{imports}{}\n\
         verifyReadlineDelimiters(__readline, __EventEmitter).then(\
             function (result) {{ console.log(result); }});",
        include_str!("fixtures/readline_delimiters.js"),
    );
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "readline-delimiters.js".into(),
                text: source,
            },
            goal,
            &ParserOptions::default(),
        )
        .expect("shared delimiter fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "readline-delimiters.js"),
        &LoweringContext::new("readline", "delimiters", "builtin-only"),
    )
    .expect("canonical readline imports lower")
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
            let mut core = InterpreterCore::new(config, "readline-delimiters");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&module).unwrap_or_else(|error| {
                panic!("throughput={throughput}, stress={stress:?}: {error}")
            });
            let lines: Vec<_> = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect();
            assert_eq!(
                lines,
                ["readline delimiters: long lines, CRLF, UTF-16, UTF-8, reentry, question, iteration"],
                "asynchronous completion must execute",
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
            );
        }
    }
}

#[test]
fn bulk_delimiter_search_preserves_commonjs_line_delivery() {
    run(
        ParseGoal::Script,
        "const __readline = require('node:readline');\n\
         const { EventEmitter: __EventEmitter } = require('node:events');\n",
    );
}

#[test]
fn bulk_delimiter_search_preserves_esm_line_delivery() {
    run(
        ParseGoal::Module,
        "import * as __readline from 'node:readline';\n\
         import { EventEmitter as __EventEmitter } from 'node:events';\n",
    );
}
