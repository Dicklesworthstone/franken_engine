//! Shared public programs run through the real parser, lowerer and interpreter.
//! Host/Node reference execution is not proof these native tests pass.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const COMMONJS: &str = "const __r = require('node:readline');\n\
    const { Readline: __Readline } = require('readline/promises');\n\
    const { Writable: __Writable } = require('stream');\n";
const ESM: &str = "import * as __r from 'node:readline';\n\
    import { Readline as __Readline } from 'readline/promises';\n\
    import { Writable as __Writable } from 'node:stream';\n";

fn run(body: &str, expected: &str, shadowed: bool) {
    for (goal, imports) in [(ParseGoal::Script, COMMONJS), (ParseGoal::Module, ESM)] {
        let shadows = if shadowed {
            "const Number=null, RangeError=null, WeakMap=null, Reflect=null;\n\
             const __franken_readline_cursor_tick=()=>{throw new Error('guest tick');};\n"
        } else {
            ""
        };
        let source = format!("{imports}{shadows}{body}");
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: "readline-cursor.js".into(),
                    text: source,
                },
                goal,
                &ParserOptions::default(),
            )
            .expect("cursor program parses");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "readline-cursor.js"),
            &LoweringContext::new("cursor", "output", "builtin-only"),
        )
        .expect("cursor module imports lower")
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
                let mut core = InterpreterCore::new(config, "readline-cursor");
                core.set_gc_stress_interval(stress);
                let result = core.execute(&module).unwrap_or_else(|error| {
                    panic!("throughput={throughput}, stress={stress:?}: {error}")
                });
                let lines: Vec<_> = result.console_output.iter().map(|entry| entry.message.as_str()).collect();
                assert_eq!(lines, [expected], "completion must actually run");
                assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
            }
        }
    }
}

#[test]
fn callback_and_transactional_cursor_output_complete_in_both_module_modes() {
    run(include_str!("fixtures/readline_cursor.js"), "READLINE_CURSOR_OK", false);
}

#[test]
fn cursor_implementation_uses_realm_helpers_not_guest_shadow_bindings() {
    run(include_str!("fixtures/readline_cursor.js"), "READLINE_CURSOR_OK", true);
}

#[test]
fn reentrant_output_keeps_batches_and_completion_ownership_separate() {
    run(include_str!("fixtures/readline_cursor_reentry.js"), "READLINE_CURSOR_REENTRY_OK", false);
}
