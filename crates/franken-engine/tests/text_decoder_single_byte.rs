//! Native TextDecoder programs; Node execution is only a reference check.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

#[test]
fn all_single_byte_encodings_execute_through_the_native_constructor_and_decoder() {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/text_decoder_single_byte.json"
    )).expect("WHATWG fixtures");
    let program = include_str!("fixtures/text_decoder_single_byte.js");
    for entry in fixtures["encodings"].as_array().unwrap() {
        let name = entry["name"].as_str().unwrap();
        let source = format!("const __case = {};\n{program}", serde_json::to_string(entry).unwrap());
        let tree = CanonicalEs2020Parser.parse_with_options(
            ParserSource { label: format!("{name}.js"), text: source },
            ParseGoal::Script,
            &ParserOptions::default(),
        ).expect("public decoder program parses");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "legacy-decoder.js"),
            &LoweringContext::new("legacy-decoder", "single-byte", "builtin-only"),
        ).expect("public decoder program lowers").ir3;
        let missing = entry["high"].as_array().unwrap().iter().filter(|value| value.is_null()).count();
        let expected = format!("LEGACY_SINGLE_BYTE_OK {name} {missing}");
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
                let mut core = InterpreterCore::new(config, "legacy-decoder");
                core.set_gc_stress_interval(stress);
                let result = core.execute(&module).unwrap_or_else(|error| {
                    panic!("{name}, throughput={throughput}, stress={stress:?}: {error}")
                });
                let lines: Vec<_> = result.console_output.iter().map(|entry| entry.message.as_str()).collect();
                assert_eq!(lines, [expected.as_str()], "{name}, throughput={throughput}, stress={stress:?}");
                assert_eq!(core.estimated_memory_bytes(), core.recompute_estimated_memory_bytes(), "{name}");
            }
        }
    }
}
