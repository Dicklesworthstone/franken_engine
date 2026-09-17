//! Observable property keys and Reflect operations through both native profiles.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "reflect-property-execution.js".into(),
                text: format!("const log = console.log;\n{source}"),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("property regression source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "reflect-property-execution.js"),
        &LoweringContext::new("property-trace", "property-decision", "property-policy"),
    )
    .expect("property regression source must lower")
    .ir3
}

fn cores() -> impl Iterator<Item = InterpreterCore> {
    [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ]
    .into_iter()
    .map(|mut config| {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        InterpreterCore::new(config, "reflect-property-execution")
    })
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for mut core in cores() {
        let result = core
            .execute(&module)
            .expect("property execution must succeed");
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected, "{source}");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn throwing_computed_key_getter_is_local_control_flow_not_secret_egress() {
    // This exact source was rejected by IR2 at ToPropertyKey, TopSecret -> Secret.
    let source = "let trace = ''; const key = {get [Symbol.toPrimitive]() {trace += 'g'; throw 7;}}; try {const result = {[key]: (trace += 'bad', 1)};} catch(e) {trace += e;} trace;";
    let result = frankenengine_engine::HybridRouter::default()
        .eval(source)
        .unwrap();
    assert_eq!(result.value, "g7");
}

#[test]
fn computed_key_nested_conversion_restores_context_and_exception_order() {
    assert_output(
        r#"
        let trace = '';
        const key = {[Symbol.toPrimitive](hint) { trace += hint; JSON.parse('1'); return 'x'; }};
        log(({[key]: 7}).x, trace);
        try { ({[{[Symbol.toPrimitive]() { throw 23; }}]: (trace += 'bad', 1)}); }
        catch (e) { trace += ':' + e; }
        log(trace, ({[key]: 9}).x);
        "#,
        &["7 string", "string:23 9"],
    );
}

#[test]
fn property_key_intrinsic_preserves_high_input_and_enforces_real_sink() {
    for label in [Label::Secret, Label::TopSecret] {
        for mut core in cores() {
            core.seed_register(0, Value::Int(42)).unwrap();
            core.set_register_label(0, label.clone()).unwrap();
            let mut module = lower("0;");
            module.instructions = vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:ToPropertyKey".into()),
                    args: RegRange { start: 0, count: 1 },
                    dst: 1,
                },
                Ir3Instruction::Return { value: 1 },
            ];
            let result = core.execute(&module).unwrap();
            assert_eq!(result.value, Value::str("42"));
            assert_eq!(result.completion_label, label);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
        for mut core in cores() {
            core.seed_register(0, Value::Int(42)).unwrap();
            core.set_register_label(0, label.clone()).unwrap();
            let mut module = lower("0;");
            module.instructions = vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:ToPropertyKey".into()),
                    args: RegRange { start: 0, count: 1 },
                    dst: 1,
                },
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:ConsoleLog".into()),
                    args: RegRange { start: 1, count: 1 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
            ];
            assert!(
                matches!(core.execute(&module), Err(InterpreterError::CapabilityDenied { capability })
                if capability == "console:log:confidentiality"),
                "key conversion laundered {label:?}"
            );
            assert!(core.console_output().is_empty());
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn property_key_conversion_work_is_bounded_and_refusal_releases_scratch() {
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.instruction_budget = 100;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "property-key-budget");
        let mut module = lower("0;");
        module.instructions = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ToPropertyKey".into()),
                args: RegRange { start: 0, count: 1 },
                dst: 1,
            },
            Ir3Instruction::Return { value: 1 },
        ];
        core.seed_register(0, Value::str("x".repeat(16_384)))
            .unwrap();
        assert!(matches!(
            core.execute(&module),
            Err(InterpreterError::BudgetExhausted { .. })
        ));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn console_aliases_refuse_high_labels_before_capturing_output() {
    for capability in [
        "console:log",
        "console:error",
        "console:warn",
        "console:info",
        "builtin:ConsoleLog",
        "builtin:ConsoleError",
        "builtin:ConsoleWarn",
        "builtin:ConsoleInfo",
    ] {
        for label in [
            Label::Public,
            Label::Internal,
            Label::Confidential,
            Label::Secret,
            Label::TopSecret,
        ] {
            for mut core in cores() {
                core.seed_register(0, Value::str("payload")).unwrap();
                core.set_register_label(0, label.clone()).unwrap();
                let mut module = lower("0;");
                module.instructions = vec![
                    Ir3Instruction::HostCall {
                        capability: CapabilityTag(capability.into()),
                        args: RegRange { start: 0, count: 1 },
                        dst: 1,
                    },
                    Ir3Instruction::Return { value: 1 },
                ];
                let outcome = core.execute(&module);
                if label.can_flow_to(&Label::Internal) {
                    let result = outcome.expect("admitted console output");
                    assert_eq!(result.console_output.len(), 1);
                    assert_eq!(result.console_output[0].message, "payload");
                } else {
                    assert!(
                        matches!(outcome, Err(InterpreterError::CapabilityDenied { capability })
                        if capability.ends_with(":confidentiality"))
                    );
                    assert!(core.console_output().is_empty());
                }
                assert_eq!(
                    core.estimated_memory_bytes(),
                    core.recompute_estimated_memory_bytes()
                );
            }
        }
    }
}

#[test]
fn seeded_register_retention_is_accounted_before_execution_and_refused_atomically() {
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        config.max_total_memory_bytes = 131_072;
        let mut core = InterpreterCore::new(config, "seed-admission");
        core.seed_register(0, Value::str("retained")).unwrap();
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        let before = core.estimated_memory_bytes();
        assert!(matches!(
            core.seed_register(0, Value::str("x".repeat(262_144))),
            Err(InterpreterError::MemoryBudgetExceeded { .. })
        ));
        assert_eq!(core.estimated_memory_bytes(), before);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
        core.seed_register(0, Value::Int(0)).unwrap();
        assert!(core.estimated_memory_bytes() < before);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}
