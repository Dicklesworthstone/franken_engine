//! bd-9vouw.161: live Set algebra and the exact iterator/copy boundaries.
#![forbid(unsafe_code)]

use frankenengine_engine::HybridRouter;

#[test]
fn native_set_mutations_preserve_spec_observable_order() {
    // Thirteen lines match Node v22.16.0 on this identical source. Two are
    // deliberately specification-derived: that Node version copies union's
    // receiver too early and walks difference's receiver instead of its copy.
    // See the Stage 4 algorithms, unchanged at these boundaries since 2024:
    // https://tc39.es/proposal-set-methods/#sec-set.prototype.union
    // https://tc39.es/proposal-set-methods/#sec-set.prototype.difference
    let source = include_str!("fixtures/set_algebra/mutations.js");
    let expected = include_str!("fixtures/set_algebra/mutations.expected").trim_end();
    let result = HybridRouter::default()
        .eval(source)
        .unwrap_or_else(|error| panic!("Set mutation source failed: {error}"));
    assert_eq!(result.value, expected);
}

#[test]
fn adversarial_reinsertion_stops_at_native_budget_not_a_guest_catch() {
    use frankenengine_engine::ast::ParseGoal;
    use frankenengine_engine::baseline_interpreter::{
        InterpreterConfig, InterpreterCore, InterpreterError,
    };
    use frankenengine_engine::capability::RuntimeCapability;
    use frankenengine_engine::ir_contract::Ir0Module;
    use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
    use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

    let source = r#"
        let set = new Set([1]);
        try {
            set.isSubsetOf({ size: Infinity, keys() { throw 'unused'; }, has(value) {
                set.delete(value); set.add(value); return true;
            } });
        } catch (error) { console.log('caught resource refusal'); }
        console.log('escaped live traversal');
    "#;
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "set-budget.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("budget regression must parse");
    let module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "set-budget.js"),
        &LoweringContext::new("set-budget", "set-budget", "set-budget"),
    )
    .expect("budget regression must lower")
    .ir3;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.instruction_budget = 2048;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "set-budget");
        let result = core.execute(&module);
        assert!(
            matches!(result, Err(InterpreterError::BudgetExhausted { .. })),
            "{result:?}"
        );
        assert!(
            core.console_output().is_empty(),
            "resource refusal reached guest continuation"
        );
    }
}
