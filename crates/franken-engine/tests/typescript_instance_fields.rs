#![forbid(unsafe_code)]

//! The engine ingestion path shares core's TypeScript field normalization,
//! while native JavaScript class fields retain their ES2022 runtime contract.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};
use frankenengine_engine::ts_normalization::{
    TsNormalizationConfig, normalize_typescript_to_es2020,
};

#[path = "../../franken-core/tests/fixtures/typescript_instance_fields.rs"]
mod fixtures;

fn assert_javascript(name: &str, source: &str, expected: &[&str]) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: format!("{name}.js"),
                text: source.to_owned(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .unwrap_or_else(|error| panic!("{name} parse: {error}\n{source}"));
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, format!("{name}.js")),
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
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
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
        assert_javascript(name, &normalized.normalized_source, expected);
    }
}

#[test]
fn native_javascript_fields_still_initialize_before_base_parameter_defaults() {
    assert_javascript(
        "native-javascript-fields",
        r#"
let trace = '';
class Native {
    value = (trace += 'field|');
    constructor(input = (trace += 'default|')) { trace += 'body|'; }
}
new Native();
console.log(trace);
"#,
        &["field|default|body|"],
    );
}

#[test]
fn instance_lowering_preserves_static_and_computed_method_evaluation_order() {
    let source = r#"
let trace = '';
function mark(label: string): string { trace += label + '|'; return label; }
class Mixed {
    value = mark('instance');
    static initial = mark('static');
    [mark('key')]() { return this.value; }
}
const mixed = new Mixed();
console.log(trace, mixed.value, Mixed.initial);
"#;
    let normalized = normalize_typescript_to_es2020(
        source,
        &TsNormalizationConfig::default(),
        "mixed-fields",
        "mixed-fields",
        "mixed-fields",
    )
    .expect("mixed class must normalize");
    assert_javascript(
        "mixed-fields",
        &normalized.normalized_source,
        &["key|static|instance| instance static"],
    );
}
