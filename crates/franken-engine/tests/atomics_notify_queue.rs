//! Native single-agent waitAsync/notify execution; never delegate to Node.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};

#[test]
fn notifications_preserve_address_identity_fifo_and_reentrant_completion() {
    let source = include_str!("fixtures/atomics/notify_queue.js");
    let expected = include_str!("fixtures/atomics/notify_queue.expected").trim_end();
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource { label: "atomics-notify-queue.js".into(), text: source.into() },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("notification source parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "atomics-notify-queue.js"),
        &LoweringContext::new("atomics-notify", "single-agent", "builtin-only"),
    )
    .expect("notification source lowers")
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
            let mut core = InterpreterCore::new(config, "atomics-notify-queue");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&module).unwrap_or_else(|error| {
                panic!("throughput={throughput}, stress={stress:?}: {error}")
            });
            let output = result.console_output.iter().map(|entry| entry.message.as_str())
                .collect::<Vec<_>>().join("\n");
            assert_eq!(output, expected, "throughput={throughput}, stress={stress:?}");
            assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes());
        }
    }
}
