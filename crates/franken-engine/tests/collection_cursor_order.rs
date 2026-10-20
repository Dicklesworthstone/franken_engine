//! Exercise the shared named-key carrier through actual collection builtins.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const CASES: &str = include_str!("fixtures/collection_cursor_order.js");
const EXPECTED: [&str; 8] = [
    "512:130816:512",
    "a,a,b,b,d,z,z,true,true,later,true",
    "outer1,inner1,inner3,inner4,outer3,outer4|3,4",
    // Difference visits its private copied data even if other.has clears the
    // source. Node 22.16.0 differs here; do not replace the required result
    // with that reference-host behavior (ECMA-262 2025 24.2.4.5).
    "1,3,4:4|1,2,3:1,3",
    "a,a,b,true,b,c,d,true",
    "2,10,lone,replacement,a,b|8,2,4,5,6,7",
    "96:129:97:130:63:8967:30:5205:65",
    "0:263:36675:1:true:true:2000",
];

fn run_case(index: usize) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "collection-cursor-order.js".to_string(),
                text: format!("const cases = {CASES}; console.log(cases[{index}]());"),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("collection cursor fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "collection-cursor-order.js"),
        &LoweringContext::new("collection-cursor-order", "iteration", "builtin-only"),
    )
    .expect("collection cursor fixture lowers")
    .ir3;
    for throughput in [false, true] {
        for stress in [None, Some(7)] {
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
            let mut core = InterpreterCore::new(config, "collection-cursor-order");
            core.set_gc_stress_interval(stress);
            let result = core.execute(&module).unwrap_or_else(|error| {
                panic!("case {index}, throughput={throughput}, gc={stress:?}: {error}")
            });
            let lines: Vec<_> = result
                .console_output
                .iter()
                .map(|entry| entry.message.as_str())
                .collect();
            assert_eq!(lines, [EXPECTED[index]], "case {index}");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "case {index}, throughput={throughput}, gc={stress:?}"
            );
        }
    }
}

#[test]
fn collection_walks_keep_live_cursors_and_member_identity() {
    for index in [0, 1, 2, 4, 5] {
        run_case(index);
    }
}

#[test]
fn set_algebra_keeps_live_and_private_copy_iteration_distinct() {
    run_case(3);
}

#[test]
fn collection_cursors_survive_deleted_prefixes_and_order_index_rebuilds() {
    for index in [6, 7] {
        run_case(index);
    }
}
