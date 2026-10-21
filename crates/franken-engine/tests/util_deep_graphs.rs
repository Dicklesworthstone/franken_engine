//! The shared graph fixture through native parse/lower/execute, not the host shim.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn run(goal: ParseGoal, imports: &str) {
    let source = format!(
        "{imports}\n{}\nconsole.log(verifyUtilDeepGraphs(__equal));",
        include_str!("fixtures/util_deep_graphs.js"),
    );
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "util-deep-graphs.js".into(),
                text: source,
            },
            goal,
            &ParserOptions::default(),
        )
        .expect("shared graph fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "util-deep-graphs.js"),
        &LoweringContext::new("util-graphs", "active-pairs", "builtin-only"),
    )
    .expect("canonical util import lowers")
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
            let mut core = InterpreterCore::new(config, "util-deep-graphs");
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
                ["util deep graphs: chains, cycles, partners, rollback, getters, exceptions, reentry"],
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "temporary indexes must retain exact heap accounting",
            );
        }
    }
}

#[test]
fn deep_graph_comparison_from_commonjs_keeps_active_pair_semantics() {
    run(
        ParseGoal::Script,
        "const __equal = require('node:util').isDeepStrictEqual;",
    );
}

#[test]
fn deep_graph_comparison_from_esm_keeps_active_pair_semantics() {
    run(
        ParseGoal::Module,
        "import { isDeepStrictEqual as __equal } from 'node:util';",
    );
}
