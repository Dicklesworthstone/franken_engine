//! Public constructor/streaming programs on the actual native interpreter.
//! The separate Node runner checks reference behavior, not this Rust engine.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

#[test]
fn japanese_decoders_execute_on_both_native_profiles_with_gc_stress() {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/text_decoder/japanese.json"
    )).expect("Japanese decoder fixtures");
    for fixture in fixtures.as_array().unwrap() {
        let name = fixture["name"].as_str().unwrap();
        let tree = CanonicalEs2020Parser.parse_with_options(
            ParserSource {
                label: format!("japanese-{name}.js"),
                text: fixture["source"].as_str().unwrap().to_owned(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        ).expect("Japanese decoder program parses");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "japanese-decoder.js"),
            &LoweringContext::new("japanese-decoder", "multibyte", "builtin-only"),
        ).expect("Japanese decoder program lowers").ir3;
        let expected: Vec<_> = fixture["expected"].as_array().unwrap()
            .iter().map(|line| line.as_str().unwrap()).collect();
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
                ].into_iter().collect();
                let mut core = InterpreterCore::new(config, "japanese-decoder");
                core.set_gc_stress_interval(stress);
                let result = core.execute(&module).unwrap_or_else(|error| {
                    panic!("{name}, throughput={throughput}, stress={stress:?}: {error}")
                });
                let actual: Vec<_> = result.console_output.iter()
                    .map(|entry| entry.message.as_str()).collect();
                assert_eq!(actual, expected, "{name}, throughput={throughput}, stress={stress:?}");
                assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes(), "{name}");
            }
        }
    }
}
