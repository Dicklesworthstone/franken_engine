#![forbid(unsafe_code)]

//! Real parse/lower/execute coverage for StringToBigInt and its comparison users.
use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::Ir0Module;
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn assert_output(source: &str, expected: &[&str]) {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "bigint-string-admission.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("regression source must parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "bigint-string-admission.js"),
        &LoweringContext::new(
            "bigint-admission-trace",
            "bigint-admission-decision",
            "bigint-policy",
        ),
    )
    .expect("regression source must lower")
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
        let mut core = InterpreterCore::new(config, "bigint-string-admission");
        let result = core.execute(&module).expect("native execution must succeed");
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn constructor_rejects_non_ecmascript_whitespace() {
    assert_output(
        r#"
        try { BigInt('\u00851'); console.log('wrong'); }
        catch (error) { console.log(error.name); }
        try { BigInt('1\u0085'); console.log('wrong'); }
        catch (error) { console.log(error.name); }
        console.log(String(BigInt('\uFEFF\u2028-42\u00A0')));
        "#,
        &["SyntaxError", "SyntaxError", "-42"],
    );
}

#[test]
fn comparisons_use_the_same_string_integer_grammar() {
    assert_output(
        r#"
        console.log(1n == '\u00851', 1n == ' \uFEFF1 ');
        console.log(1n < '\u00852', 1n > '\u00850');
        console.log(255n == '0x00ff', -42n == '-00042');
        "#,
        &["false true", "false false", "true true"],
    );
}

#[test]
fn long_zero_prefixes_and_radices_keep_exact_values() {
    assert_output(
        r#"
        const zeroes = '0'.repeat(10000);
        console.log(String(BigInt('-' + zeroes)), String(BigInt('+' + zeroes + '42')));
        console.log(String(BigInt('0x' + zeroes + 'ff')));
        console.log(String(BigInt('0o' + zeroes + '77')), String(BigInt('0b' + zeroes + '101')));
        "#,
        &["0 42", "255", "63 5"],
    );
}
