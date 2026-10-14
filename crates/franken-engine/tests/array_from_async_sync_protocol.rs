//! Native Async-from-Sync completion and cleanup, not a host-side JS adapter.
#![forbid(unsafe_code)]

use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser_api_stability::parse_script;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    name: String,
    source: String,
    expected: String,
}

fn config(throughput: bool) -> InterpreterConfig {
    let mut config = if throughput {
        InterpreterConfig::v8_defaults()
    } else {
        InterpreterConfig::quickjs_defaults()
    };
    // Preserve the normal instruction and memory budgets of each profile.
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
        RuntimeCapability::Console,
    ]
    .into_iter()
    .collect();
    config
}

#[test]
fn sync_completion_and_cleanup_follow_the_native_promise_scheduler() {
    let fixtures: Vec<Fixture> = serde_json::from_str(include_str!(
        "fixtures/array_from_async/sync_protocol.json"
    ))
    .expect("shared fixtures decode");
    assert_eq!(fixtures.len(), 24);
    for fixture in fixtures {
        let tree = parse_script(&fixture.source).expect("source parses");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, fixture.name.clone()),
            &LoweringContext::new("async-sync-protocol", "native", "builtin-only"),
        )
        .unwrap_or_else(|error| panic!("{} lowers: {error}", fixture.name))
        .ir3;
        for throughput in [false, true] {
            for stress in [None, Some(1), Some(7)] {
                let mut core = InterpreterCore::new(config(throughput), "async-sync-protocol");
                core.set_gc_stress_interval(stress);
                let result = core.execute(&module).unwrap_or_else(|error| {
                    panic!("{}: throughput={throughput}, gc={stress:?}: {error}", fixture.name)
                });
                let actual = result.console_output.iter().map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>().join("\n");
                assert_eq!(actual, fixture.expected,
                    "{}: throughput={throughput}, gc={stress:?}", fixture.name);
                assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes(),
                    "{}: throughput={throughput}, gc={stress:?}", fixture.name);
            }
        }
    }
}

#[test]
fn sync_next_resource_exhaustion_cannot_be_caught_or_start_cleanup() {
    let source = r#"
        const source = { [Symbol.iterator]() { return {
          next() { while (true) {} },
          return() { console.log('unexpected cleanup'); return {}; }
        }; } };
        Array.fromAsync(source).catch(() => console.log('caught native fault'));
        console.log('continued after native fault');
    "#;
    let tree = parse_script(source).expect("resource fixture parses");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "async-sync-resource.js"),
        &LoweringContext::new("async-sync-protocol", "resource", "builtin-only"),
    )
    .expect("resource fixture lowers")
    .ir3;
    for throughput in [false, true] {
        let mut config = config(throughput);
        config.instruction_budget = 2048;
        let mut core = InterpreterCore::new(config, "async-sync-resource");
        assert!(matches!(core.execute(&module), Err(InterpreterError::BudgetExhausted { .. })));
        assert!(core.console_output().is_empty());
    }
}
