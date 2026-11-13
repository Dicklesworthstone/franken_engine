#![forbid(unsafe_code)]

//! ES2020 TypeScript instance initialization executes through the core parser,
//! lowerer, and both interpreter lane configurations.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ir_contract::Ir0Module;
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};
use frankenengine_core::ts_normalization::{TsNormalizationConfig, normalize_typescript_to_es2020};

#[path = "fixtures/typescript_instance_fields.rs"]
mod fixtures;

#[test]
fn typescript_instance_fields_match_the_es2020_reference() {
    for &(name, source, expected) in fixtures::CASES {
        let normalized = normalize_typescript_to_es2020(
            source,
            &TsNormalizationConfig::default(),
            name,
            name,
            name,
        )
        .unwrap_or_else(|error| panic!("{name} normalization: {error}"));
        let tree = CanonicalEs2020Parser
            .parse(normalized.normalized_source.as_str(), ParseGoal::Script)
            .unwrap_or_else(|error| {
                panic!("{name} parse: {error}\n{}", normalized.normalized_source)
            });
        let module = lower_ir0_to_ir3(
            &Ir0Module::from_syntax_tree(tree, format!("{name}.ts")),
            &LoweringContext::new(name, name, name),
        )
        .unwrap_or_else(|error| panic!("{name} lowering: {error}"))
        .ir3;
        for mut config in [
            InterpreterConfig::quickjs_defaults(),
            InterpreterConfig::v8_defaults(),
        ] {
            config.granted_capabilities = [
                RuntimeCapability::VmDispatch,
                RuntimeCapability::HeapAllocate,
            ]
            .into_iter()
            .collect();
            let result = InterpreterCore::new(config, name)
                .execute(&module)
                .unwrap_or_else(|error| panic!("{name} execution: {error:?}"));
            let actual: Vec<_> = result
                .console_output
                .iter()
                .map(|line| line.message.as_str())
                .collect();
            assert_eq!(actual, expected, "{name}");
        }
    }
}
