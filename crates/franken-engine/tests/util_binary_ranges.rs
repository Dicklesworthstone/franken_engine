//! Native parse/lower/execute coverage for the shared binary-equality fixture.
//! The Node-host suite does not establish that these native checks pass.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn run(goal: ParseGoal, imports: &str) {
    let source = format!(
        "{imports}\n{}\nconsole.log(verifyUtilBinaryRanges(__equal));",
        include_str!("fixtures/util_binary_ranges.js"),
    );
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "util-binary-ranges.js".into(),
                text: source,
            },
            goal,
            &ParserOptions::default(),
        )
        .expect("shared binary fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "util-binary-ranges.js"),
        &LoweringContext::new("util-binary", "byte-windows", "builtin-only"),
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
            let mut core = InterpreterCore::new(config, "util-binary-ranges");
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
                ["util binary ranges: windows, payloads, metadata, ordering, exceptions, deep graphs"],
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "comparison views must retain exact heap accounting",
            );
        }
    }
}

#[test]
fn binary_comparison_from_commonjs_keeps_window_and_property_semantics() {
    run(
        ParseGoal::Script,
        "const __equal = require('node:util').isDeepStrictEqual;",
    );
}

#[test]
fn binary_comparison_from_esm_keeps_window_and_property_semantics() {
    run(
        ParseGoal::Module,
        "import { isDeepStrictEqual as __equal } from 'node:util';",
    );
}

#[test]
fn binary_intrinsics_are_not_captured_by_guest_lexical_bindings() {
    run(
        ParseGoal::Script,
        "const __equal = require('node:util').isDeepStrictEqual;\n\
         const Buffer = null; const Uint8Array = globalThis.Uint8Array;",
    );
}
