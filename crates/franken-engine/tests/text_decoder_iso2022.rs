//! Execute shared ISO-2022-JP programs through the real parser/lowerer/runtime.
//! The separate Node reference may disagree with normative malformed-input
//! recovery. Reference/model execution does not verify these native tests.
#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn execute_fixtures(goal: ParseGoal) {
    let fixtures: serde_json::Value = serde_json::from_str(include_str!(
        "fixtures/text_decoder/iso2022.json"
    ))
    .expect("ISO-2022-JP fixtures");
    for fixture in fixtures.as_array().unwrap() {
        let name = fixture["name"].as_str().unwrap();
        let tree = CanonicalEs2020Parser
            .parse_with_options(
                ParserSource {
                    label: format!("iso2022-{name}.js"),
                    text: fixture["source"].as_str().unwrap().to_owned(),
                },
                goal,
                &ParserOptions::default(),
            )
            .expect("ISO-2022-JP program parses");
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, "iso2022-decoder.js"),
            &LoweringContext::new("iso2022-decoder", "designation", "builtin-only"),
        )
        .expect("ISO-2022-JP program lowers")
        .ir3;
        let expected: Vec<_> = fixture["expected"]
            .as_array().unwrap().iter().map(|line| line.as_str().unwrap()).collect();
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
                let mut core = InterpreterCore::new(config, "iso2022-decoder");
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

#[test]
fn iso2022_script_decoders_complete_on_both_profiles() {
    execute_fixtures(ParseGoal::Script);
}

#[test]
fn iso2022_module_decoders_complete_on_both_profiles() {
    execute_fixtures(ParseGoal::Module);
}
