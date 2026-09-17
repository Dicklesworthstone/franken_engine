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

fn assert_value(source: &str, expected: Value) {
    let module = lower(source);
    for mut core in cores() {
        let result = core
            .execute(&module)
            .expect("native property execution must succeed");
        assert_eq!(result.value, expected, "{source}");
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn computed_key_getter_throw_is_not_misclassified_as_key_material_egress() {
    assert_value(
        "let trace = ''; const key = {get [Symbol.toPrimitive]() {trace += 'g'; throw 7;}}; try {const result = {[key]: (trace += 'bad', 1)};} catch(e) {trace += e;} trace;",
        Value::str("g7"),
    );
}

#[test]
fn computed_keys_keep_nested_conversion_order_and_original_symbol_identity() {
    assert_value(
        r#"
        let trace = '';
        const s = Symbol('slot');
        const key = { [Symbol.toPrimitive](hint) {
            trace += hint;
            const nested = { [Symbol.toPrimitive]() { trace += 'n'; return 'inner'; } };
            const ignored = { [nested]: 1 };
            return s;
        } };
        const result = { [key]: (trace += 'v', 7), slot: 9 };
        trace + ':' + result[s] + ':' + result.slot;
        "#,
        Value::str("stringnv:7:9"),
    );
}

#[test]
fn internal_key_canonicalization_retains_secret_result_labels() {
    for mut core in cores() {
        core.seed_register(0, Value::str("selected")).unwrap();
        core.set_register_label(0, Label::Secret).unwrap();
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
        assert_eq!(result.value, Value::str("selected"));
        assert_eq!(result.completion_label, Label::Secret);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn property_key_work_is_budgeted_without_leaking_temporary_ownership() {
    let module = lower(&format!(
        "const key = '{}'; const result = {{ [key]: 7 }};",
        "a".repeat(16_384)
    ));
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
        let mut core = InterpreterCore::new(config, "property-key-work-budget");
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
fn all_four_operations_convert_once_with_string_hint_and_symbol_identity() {
    assert_value(
        r#"
        let calls = 0; let trace = '';
        const symbol = Symbol('slot'); const target = { [symbol]: 7, slot: 100 };
        const key = { [Symbol.toPrimitive](hint) { calls++; trace += hint; return symbol; } };
        const value = Reflect.get(target, key);
        const assigned = Reflect.set(target, key, 9);
        const present = Reflect.has(target, key);
        const removed = Reflect.deleteProperty(target, key);
        calls + ':' + trace + ':' + value + ':' + assigned + ':' + present + ':' + removed + ':' + target.slot;
        "#,
        Value::str("4:stringstringstringstring:7:true:true:true:100"),
    );
}

#[test]
fn invalid_targets_are_rejected_before_key_conversion() {
    assert_value(
        r#"
        let calls = 0; let errors = 0;
        const key = { [Symbol.toPrimitive]() { calls++; throw 99; } };
        try { Reflect.get(null, key); } catch(e) { if (e instanceof TypeError) errors++; }
        try { Reflect.set(0, key, 1); } catch(e) { if (e instanceof TypeError) errors++; }
        try { Reflect.has(true, key); } catch(e) { if (e instanceof TypeError) errors++; }
        try { Reflect.deleteProperty('x', key); } catch(e) { if (e instanceof TypeError) errors++; }
        calls + ':' + errors;
        "#,
        Value::str("0:4"),
    );
}

#[test]
fn missing_property_and_value_arguments_are_undefined_not_arity_errors() {
    assert_value(
        r#"
        const target = { undefined: 7 };
        const a = Reflect.get(target);
        const b = Reflect.has(target);
        const c = Reflect.set(target);
        const d = target.undefined;
        const e = Reflect.deleteProperty(target);
        a + ':' + b + ':' + c + ':' + d + ':' + e;
        "#,
        Value::str("7:true:true:undefined:true"),
    );
}

#[test]
fn get_reads_live_state_after_key_hooks_and_preserves_receiver() {
    assert_value(
        r#"
        let trace = '';
        const target = { get slot() { trace += 'g'; return this.answer; } };
        const receiver = { answer: 1 };
        const key = { get [Symbol.toPrimitive]() {
            trace += 'm';
            return function(hint) { trace += hint; receiver.answer = 17; return 'slot'; };
        } };
        const result = Reflect.get(target, key, receiver);
        trace + ':' + result;
        "#,
        Value::str("mstringg:17"),
    );
}

#[test]
fn explicit_undefined_receiver_is_not_replaced_with_target() {
    assert_value(
        r#"
        const target = {};
        const proxy = new Proxy(target, {
            get(t, k, r) { return r === undefined ? 'undefined' : r === proxy ? 'proxy' : 'other'; },
            set(t, k, v, r) { return r === undefined; }
        });
        Reflect.get(proxy, 'slot') + ':' + Reflect.get(proxy, 'slot', undefined) + ':' +
            Reflect.set(proxy, 'slot', 4, undefined) + ':' + Reflect.set(proxy, 'slot', 4);
        "#,
        Value::str("proxy:undefined:true:false"),
    );
}

#[test]
fn inherited_setter_receives_original_receiver_and_missing_value() {
    assert_value(
        r#"
        const parent = { set slot(v) { this.stored = v; } };
        const target = Object.create(parent); const receiver = {};
        const key = { toString() { return 'slot'; } };
        const a = Reflect.set(target, key, 23, receiver);
        const b = Reflect.set(target, key);
        a + ':' + receiver.stored + ':' + b + ':' + target.stored;
        "#,
        Value::str("true:23:true:undefined"),
    );
}

#[test]
fn ordinary_key_conversion_reads_methods_in_order() {
    assert_value(
        r#"
        let trace = '';
        const key = {
            get toString() { trace += 'g'; return function() { trace += 't'; return {}; }; },
            get valueOf() { trace += 'h'; return function() { trace += 'v'; return 'slot'; }; }
        };
        const value = Reflect.get({ slot: 31 }, key);
        trace + ':' + value;
        "#,
        Value::str("gthv:31"),
    );
}

#[test]
fn key_conversion_failure_preserves_effects_without_calling_target_traps() {
    assert_value(
        r#"
        let trace = ''; let errors = 0;
        const proxy = new Proxy({}, { get() { trace += 'bad'; return 1; }, set() { trace += 'bad'; return true; } });
        const throwing = { [Symbol.toPrimitive]() { trace += 'x'; throw 7; } };
        const objectResult = { [Symbol.toPrimitive]() { trace += 'o'; return {}; } };
        const notCallable = { [Symbol.toPrimitive]: 17 };
        try { Reflect.get(proxy, throwing); } catch(e) { trace += e; }
        try { Reflect.set(proxy, objectResult, 1); } catch(e) { if (e instanceof TypeError) errors++; }
        try { Reflect.get(proxy, notCallable); } catch(e) { if (e instanceof TypeError) errors++; }
        trace + ':' + errors;
        "#,
        Value::str("x7o:2"),
    );
}

#[test]
fn proxy_traps_receive_converted_keys_target_receiver_and_handler_this() {
    assert_value(
        r#"
        let trace = ''; const target = {}; const symbol = Symbol('slot');
        const receiver = {};
        const handler = {
            get(t,k,r) { trace += 'g'; return t === target && k === symbol && r === receiver && this === handler; },
            set(t,k,v,r) { trace += 's'; return t === target && k === symbol && v === 7 && r === receiver; },
            has(t,k) { trace += 'h'; return 0; },
            deleteProperty(t,k) { trace += 'd'; return false; }
        };
        const proxy = new Proxy(target, handler);
        const key = { [Symbol.toPrimitive]() { trace += 'k'; return symbol; } };
        const a = Reflect.get(proxy, key, receiver);
        const b = Reflect.set(proxy, key, 7, receiver);
        const c = Reflect.has(proxy, key);
        const d = Reflect.deleteProperty(proxy, key);
        trace + ':' + a + ':' + b + ':' + c + ':' + d;
        "#,
        Value::str("kgkskhkd:true:true:false:false"),
    );
}

#[test]
fn revoked_target_is_checked_after_key_conversion() {
    assert_value(
        r#"
        let trace = '';
        const pair = Proxy.revocable({}, {}); pair.revoke();
        const key = { [Symbol.toPrimitive]() { trace += 'k'; return 'slot'; } };
        try { Reflect.get(pair.proxy, key); } catch(e) { trace += e instanceof TypeError; }
        trace;
        "#,
        Value::str("ktrue"),
    );
}

#[test]
fn key_hook_can_revoke_target_before_the_requested_operation() {
    assert_value(
        r#"
        let trace = '';
        const pair = Proxy.revocable({}, { has() { trace += 'bad'; return true; } });
        const key = { [Symbol.toPrimitive]() { trace += 'k'; pair.revoke(); return 'slot'; } };
        try { Reflect.has(pair.proxy, key); } catch(e) { trace += e instanceof TypeError; }
        trace;
        "#,
        Value::str("ktrue"),
    );
}

#[test]
fn nested_reflection_and_json_do_not_replace_outer_key_or_callback_state() {
    assert_value(
        r#"
        let trace = '';
        const inner = { [Symbol.toPrimitive](hint) { trace += 'i'; return 'value'; } };
        const key = { [Symbol.toPrimitive](hint) {
            trace += 'o';
            const value = Reflect.get(JSON.parse('{"value":"slot"}'), inner);
            trace += 'n'; return value;
        } };
        const target = { slot: 19 }; const result = Reflect.get(target, key);
        trace + ':' + result + ':' + Reflect.has(target, 'slot');
        "#,
        Value::str("oin:19:true"),
    );
}

#[test]
fn reflected_keys_keep_lone_surrogates_and_numeric_property_names_exact() {
    assert_value(
        r#"
        const target = { '\ud800': 1, '\ud801': 2, '0': 3, 'NaN': 4, '17': 5 };
        const key = { [Symbol.toPrimitive]() { return '\ud800'; } };
        Reflect.get(target, key) + ':' + Reflect.get(target, '\ud801') + ':' +
            Reflect.get(target, -0) + ':' + Reflect.get(target, NaN) + ':' + Reflect.get(target, 17n);
        "#,
        Value::str("1:2:3:4:5"),
    );
}

#[test]
fn deletion_succeeds_for_absent_own_keys_without_removing_inherited_values() {
    assert_value(
        r#"
        const parent = { slot: 19 }; const target = Object.create(parent);
        const symbol = Symbol('absent'); Object.freeze(target);
        Reflect.deleteProperty(target, 'slot') + ':' + target.slot + ':' +
            Reflect.deleteProperty(target, 'missing') + ':' + Reflect.deleteProperty(target, symbol);
        "#,
        Value::str("true:19:true:true"),
    );
}

#[test]
fn deletion_keeps_array_length_and_typed_array_elements() {
    assert_value(
        r#"
        const array = [3, 5]; const typed = new Uint8Array([7, 11]);
        const a = Reflect.deleteProperty(array, 'length');
        const b = Reflect.deleteProperty(array, 0);
        const c = Reflect.deleteProperty(typed, 0);
        const d = Reflect.deleteProperty(typed, 4);
        a + ':' + b + ':' + array.length + ':' + (0 in array) + ':' + c + ':' + d + ':' + typed[0];
        "#,
        Value::str("false:true:2:false:false:true:7"),
    );
}

#[test]
fn frozen_data_writes_and_frozen_own_deletes_return_false_without_mutating() {
    assert_value(
        r#"
        const target = Object.freeze({ slot: 7 });
        const receiver = {}; const frozenReceiver = Object.freeze({});
        const a = Reflect.set(target, 'slot', 9);
        const b = Reflect.set(Object.create(target), 'slot', 9, receiver);
        const c = Reflect.set({}, 'slot', 9, frozenReceiver);
        const d = Reflect.deleteProperty(target, 'slot');
        a + ':' + b + ':' + c + ':' + d + ':' + target.slot + ':' + receiver.slot;
        "#,
        Value::str("false:false:false:false:7:undefined"),
    );
}

#[test]
fn freezing_an_accessor_owner_does_not_disable_its_setter() {
    assert_value(
        r#"
        let stored = 0;
        const target = Object.freeze({ set slot(v) { stored = v; } });
        Reflect.set(target, 'slot', 29) + ':' + stored;
        "#,
        Value::str("true:29"),
    );
}

#[test]
fn data_write_does_not_call_or_overwrite_a_distinct_receiver_accessor() {
    assert_value(
        r#"
        let called = 0;
        const target = { slot: 1 }; const receiver = { get slot() { return 7; }, set slot(v) { called++; } };
        const result = Reflect.set(target, 'slot', 23, receiver);
        result + ':' + called + ':' + receiver.slot + ':' + target.slot;
        "#,
        Value::str("false:0:7:1"),
    );
}

#[test]
fn transparent_proxy_deletion_updates_the_actual_enumerated_object() {
    assert_value(
        r#"
        const target = { a: 1, b: 2, c: 3 }; const proxy = new Proxy(target, {});
        let seen = '';
        for (const key in target) {
            seen += key;
            if (key === 'a') Reflect.deleteProperty(proxy, 'b');
        }
        seen + ':' + Reflect.deleteProperty(proxy, 'b');
        "#,
        Value::str("ac:true"),
    );
}

#[test]
fn reflected_property_results_retain_secret_key_selection() {
    for (name, expected) in [
        ("ReflectGet", Value::Undefined),
        ("ReflectSet", Value::Bool(true)),
        ("ReflectHas", Value::Bool(false)),
        ("ReflectDeleteProperty", Value::Bool(true)),
    ] {
        for mut core in cores() {
            let target = core.alloc_object_with_prototype(None).unwrap();
            core.seed_register(0, Value::Object(target)).unwrap();
            core.seed_register(1, Value::str("slot")).unwrap();
            core.seed_register(2, Value::Int(17)).unwrap();
            core.set_register_label(1, Label::Secret).unwrap();
            let mut module = lower("0;");
            module.instructions = vec![
                Ir3Instruction::HostCall {
                    capability: CapabilityTag(format!("builtin:{name}")),
                    args: RegRange {
                        start: 0,
                        count: if name == "ReflectSet" { 3 } else { 2 },
                    },
                    dst: 3,
                },
                Ir3Instruction::Return { value: 3 },
            ];
            let result = core.execute(&module).unwrap();
            assert_eq!(result.value, expected, "{name}");
            assert_eq!(result.completion_label, Label::Secret, "{name}");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn reflected_set_taints_distinct_receiver_before_alias_reads() {
    for mut core in cores() {
        let target = core.alloc_object_with_prototype(None).unwrap();
        let receiver = core.alloc_object_with_prototype(None).unwrap();
        for (register, value) in [
            (0, Value::Object(target)),
            (1, Value::str("slot")),
            (2, Value::Int(17)),
            (3, Value::Object(receiver)),
            (4, Value::Object(receiver)),
            (5, Value::str("slot")),
        ] {
            core.seed_register(register, value).unwrap();
        }
        core.set_register_label(2, Label::Secret).unwrap();
        let mut module = lower("0;");
        module.instructions = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ReflectSet".into()),
                args: RegRange { start: 0, count: 4 },
                dst: 6,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ReflectGet".into()),
                args: RegRange { start: 4, count: 2 },
                dst: 6,
            },
            Ir3Instruction::Return { value: 6 },
        ];
        let result = core.execute(&module).unwrap();
        assert_eq!(result.value, Value::Int(17));
        assert_eq!(result.completion_label, Label::Secret);
        assert_eq!(core.get_register_label(4).unwrap(), &Label::Public);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn deleting_with_secret_selection_taints_later_public_alias_membership() {
    for mut core in cores() {
        let target = core.alloc_object_with_prototype(None).unwrap();
        for (register, value) in [
            (0, Value::Object(target)),
            (1, Value::str("slot")),
            (2, Value::Int(17)),
            (4, Value::Object(target)),
            (5, Value::str("slot")),
            (6, Value::Object(target)),
            (7, Value::str("slot")),
        ] {
            core.seed_register(register, value).unwrap();
        }
        core.set_register_label(5, Label::Secret).unwrap();
        let mut module = lower("0;");
        module.instructions = vec![
            Ir3Instruction::SetProperty {
                obj: 0,
                key: 1,
                val: 2,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ReflectDeleteProperty".into()),
                args: RegRange { start: 4, count: 2 },
                dst: 8,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ReflectHas".into()),
                args: RegRange { start: 6, count: 2 },
                dst: 8,
            },
            Ir3Instruction::Return { value: 8 },
        ];
        let result = core.execute(&module).unwrap();
        assert_eq!(result.value, Value::Bool(false));
        assert_eq!(result.completion_label, Label::Secret);
        assert_eq!(core.get_register_label(6).unwrap(), &Label::Public);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn reflective_key_conversion_handles_deep_inputs_without_a_recursive_prewalk() {
    assert_value(
        r#"
        const root = { toString() { return 'slot'; } }; let cursor = root;
        for (let i = 0; i < 400; i++) { cursor.child = {}; cursor = cursor.child; }
        const target = { slot: 17 }; Reflect.get(target, root);
        "#,
        Value::Int(17),
    );
}

#[test]
fn reflected_long_keys_refuse_before_getters_and_release_scratch() {
    let module = lower(&format!(
        "Reflect.get(new Proxy({{}}, {{ get() {{ throw 'getter'; }} }}), '{}');",
        "a".repeat(16_384)
    ));
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
        let mut core = InterpreterCore::new(config, "reflect-key-budget");
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
fn late_inherited_proxy_trap_getter_labels_reach_actual_mutation_and_alias_reads() {
    use frankenengine_engine::ir_contract::Ir3FunctionDesc;
    for (trap, mutation, observation, expected, labelled_register) in [
        ("set", "ReflectSet", "ReflectGet", Value::Int(29), 9),
        (
            "deleteProperty",
            "ReflectDeleteProperty",
            "ReflectHas",
            Value::Bool(false),
            9,
        ),
        ("set", "ReflectSet", "ReflectGet", Value::Int(29), 8),
        (
            "deleteProperty",
            "ReflectDeleteProperty",
            "ReflectHas",
            Value::Bool(false),
            8,
        ),
    ] {
        for mut core in cores() {
            let target = core.alloc_object_with_prototype(None).unwrap();
            let prototype = core.alloc_object_with_prototype(None).unwrap();
            let handler = core.alloc_object_with_prototype(Some(prototype)).unwrap();
            for (register, value) in [
                (0, Value::Object(target)),
                (1, Value::Object(handler)),
                (3, Value::str("slot")),
                (4, Value::Int(29)),
                (5, Value::Object(target)),
                (6, Value::str("slot")),
                (7, Value::Object(prototype)),
                (8, Value::str(trap)),
                (
                    9,
                    Value::Accessor {
                        get: Some(std::sync::Arc::new(Value::Function(0))),
                        set: None,
                    },
                ),
                (11, Value::Int(17)),
            ] {
                core.seed_register(register, value).unwrap();
            }
            core.set_register_label(labelled_register, Label::Secret)
                .unwrap();
            let mut module = lower("0;");
            module.instructions = vec![
                Ir3Instruction::SetProperty {
                    obj: 0,
                    key: 3,
                    val: 11,
                },
                Ir3Instruction::SetProperty {
                    obj: 7,
                    key: 8,
                    val: 9,
                },
                Ir3Instruction::HostCall {
                    capability: CapabilityTag("builtin:Proxy".into()),
                    args: RegRange { start: 0, count: 2 },
                    dst: 2,
                },
                Ir3Instruction::HostCall {
                    capability: CapabilityTag(format!("builtin:{mutation}")),
                    args: RegRange {
                        start: 2,
                        count: if trap == "set" { 3 } else { 2 },
                    },
                    dst: 10,
                },
                Ir3Instruction::HostCall {
                    capability: CapabilityTag(format!("builtin:{observation}")),
                    args: RegRange { start: 5, count: 2 },
                    dst: 10,
                },
                Ir3Instruction::Return { value: 10 },
                Ir3Instruction::LoadUndefined { dst: 0 },
                Ir3Instruction::Return { value: 0 },
            ];
            module.function_table = vec![Ir3FunctionDesc {
                entry: 6,
                arity: 0,
                frame_size: 1,
                name: Some("absent_trap_getter".into()),
                is_generator: false,
                rest_param_index: None,
            }];
            let result = core.execute(&module).unwrap();
            assert_eq!(result.value, expected, "{trap}");
            assert_eq!(result.completion_label, Label::Secret, "{trap}");
            assert_eq!(core.get_register_label(5).unwrap(), &Label::Public);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn cancelled_property_calls_propagate_cancellation_and_release_scratch() {
    use frankenengine_engine::checkpoint::CancellationToken;
    for mut config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        let token = CancellationToken::new();
        config.cancellation_token = Some(token.clone());
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "reflect-cancelled");
        let target = core.alloc_object_with_prototype(None).unwrap();
        core.seed_register(0, Value::Object(target)).unwrap();
        core.seed_register(1, Value::str("slot")).unwrap();
        core.seed_register(2, Value::Int(29)).unwrap();
        let mut module = lower("0;");
        module.instructions = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ReflectSet".into()),
                args: RegRange { start: 0, count: 3 },
                dst: 3,
            },
            Ir3Instruction::Return { value: 3 },
        ];
        token.cancel();
        assert!(matches!(
            core.execute(&module),
            Err(InterpreterError::Cancelled)
        ));
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn property_canonicalization_does_not_lower_real_sink_clearance() {
    use frankenengine_engine::hash_tiers::ContentHash;
    use frankenengine_engine::ir_contract::{Ir1Literal, Ir1Module, Ir1Op};
    use frankenengine_engine::lowering_pipeline::lower_ir1_to_ir2;

    for sink in ["net:request", "fs:write", "console:log"] {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"reflect-flow"), "reflect-flow.js");
        ir1.ops = vec![
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("my_secret_token".into()),
            },
            Ir1Op::HostCall {
                capability: "builtin:ToPropertyKey".into(),
                arg_count: 1,
            },
            Ir1Op::HostCall {
                capability: sink.into(),
                arg_count: 1,
            },
            Ir1Op::Return,
        ];
        let module = lower_ir1_to_ir2(&ir1).unwrap().module;
        let internal = module.ops[1].flow.as_ref().unwrap();
        assert_eq!(internal.sink_clearance, Label::TopSecret);
        let external = module.ops[2].flow.as_ref().unwrap();
        assert_eq!(external.data_label, Label::Secret);
        assert!(
            !external.data_label.can_flow_to(&external.sink_clearance),
            "{sink}"
        );
        assert!(external.declassification_required, "{sink}");
    }
}

#[test]
fn inherited_property_shape_is_not_laundered_by_a_public_child_reference() {
    for (operation, expected) in [
        ("ReflectGet", Value::Int(7)),
        ("ReflectHas", Value::Bool(true)),
    ] {
        for mut core in cores() {
            let prototype = core.alloc_object_with_prototype(None).unwrap();
            let target = core.alloc_object_with_prototype(Some(prototype)).unwrap();
            for (register, value) in [
                (0, Value::Object(target)),
                (1, Value::str("slot")),
                (3, Value::Object(prototype)),
                (4, Value::str("slot")),
                (5, Value::Int(7)),
            ] {
                core.seed_register(register, value).unwrap();
            }
            core.set_register_label(4, Label::Secret).unwrap();
            let mut module = lower("0;");
            module.instructions = vec![
                Ir3Instruction::SetProperty {
                    obj: 3,
                    key: 4,
                    val: 5,
                },
                Ir3Instruction::HostCall {
                    capability: CapabilityTag(format!("builtin:{operation}")),
                    args: RegRange { start: 0, count: 2 },
                    dst: 2,
                },
                Ir3Instruction::Return { value: 2 },
            ];
            let result = core.execute(&module).unwrap();
            assert_eq!(result.value, expected);
            assert_eq!(result.completion_label, Label::Secret);
            assert_eq!(core.get_register_label(0).unwrap(), &Label::Public);
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn proxy_prototype_get_preserves_receivers_and_authoritative_undefined() {
    assert_value(
        r#"
        let trace = '';
        const target = { slot: 7 };
        const proto = new Proxy(target, { get(t, k, r) {
            trace += k + ':' + (r === child) + ',';
            if (k === 'toString') return undefined;
            return t[k];
        } });
        const child = Object.create(proto);
        const direct = child.slot;
        const reflected = Reflect.get(child, 'slot', {});
        const absent = child.toString;
        direct + ':' + reflected + ':' + absent + ':' + trace;
        "#,
        Value::str("7:7:undefined:slot:true,slot:false,toString:true,"),
    );
}

#[test]
fn proxy_prototype_has_observes_in_and_reflect_without_reading_values() {
    assert_value(
        r#"
        let trace = '';
        const proto = new Proxy({}, {
            has(t, k) { trace += k + ','; return k === 'present'; },
            get() { throw 'Get must not replace HasProperty'; }
        });
        const child = Object.create(proto);
        const a = 'present' in child;
        const b = Reflect.has(child, 'missing');
        a + ':' + b + ':' + trace;
        "#,
        Value::str("true:false:present,missing,"),
    );
}

#[test]
fn proxy_prototype_set_receives_original_receiver_before_own_creation() {
    assert_value(
        r#"
        let trace = '';
        const target = {};
        const receiver = {};
        const proto = new Proxy(target, { set(t, k, v, r) {
            trace += k + ':' + v + ':' + (r === receiver);
            Object.defineProperty(r, 'saved', {value: v});
            return true;
        } });
        const child = Object.create(proto);
        const accepted = Reflect.set(child, 'slot', 23, receiver);
        trace + ':' + accepted + ':' + receiver.saved + ':' + Reflect.has(target, 'slot');
        "#,
        Value::str("slot:23:true:true:23:false"),
    );
}

#[test]
fn transparent_proxy_prototypes_reach_accessors_without_changing_receiver() {
    assert_value(
        r#"
        const receiver = {};
        const backing = {
            get slot() { return this.saved; },
            set slot(v) { Object.defineProperty(this, 'saved', {value: v}); }
        };
        const child = Object.create(new Proxy(new Proxy(backing, {}), {}));
        const written = Reflect.set(child, 'slot', 31, receiver);
        written + ':' + Reflect.get(child, 'slot', receiver) + ':' + Reflect.has(child, 'slot');
        "#,
        Value::str("true:31:true"),
    );
}

#[test]
fn proxy_handler_itself_uses_observable_get_for_trap_selection() {
    assert_value(
        r#"
        let trace = '';
        const handler = new Proxy({}, {get(t, k, r) {
            trace += k + ':' + (r === handler) + ',';
            if (k === 'get') return function(t, k, r) { return t[k] + 1; };
            return undefined;
        }});
        const target = new Proxy({slot: 8}, handler);
        Reflect.get(target, 'slot') + ':' + trace;
        "#,
        Value::str("9:get:true,"),
    );
}

#[test]
fn revoked_proxy_prototype_is_observed_only_after_an_own_property_miss() {
    assert_value(
        r#"
        const pair = Proxy.revocable({}, {});
        const child = Object.create(pair.proxy);
        Object.defineProperty(child, 'own', {value: 9});
        pair.revoke();
        let errors = 0;
        try { Reflect.get(child, 'missing'); } catch(e) { if(e instanceof TypeError) errors++; }
        try { Reflect.has(child, 'missing'); } catch(e) { if(e instanceof TypeError) errors++; }
        try { Reflect.set(child, 'missing', 1); } catch(e) { if(e instanceof TypeError) errors++; }
        child.own + ':' + errors;
        "#,
        Value::str("9:3"),
    );
}

#[test]
fn deleting_own_absence_does_not_invoke_a_proxy_prototype() {
    assert_value(
        r#"
        let calls = 0;
        const proto = new Proxy({slot: 7}, {deleteProperty() {calls++; return false;}});
        const child = Object.create(proto);
        Reflect.deleteProperty(child, 'slot') + ':' + calls + ':' + Reflect.get(child, 'slot');
        "#,
        Value::str("true:0:7"),
    );
}

#[test]
fn recursive_proxy_handler_prototype_refuses_without_exhausting_the_host_stack() {
    for operation in [
        "proxy.slot;",
        "Reflect.get(proxy, 'slot');",
        "'slot' in proxy;",
        "Reflect.set(proxy, 'slot', 1);",
    ] {
        let source = format!(
            "const handler = {{}}; const proxy = new Proxy({{}}, handler); handler.__proto__ = proxy; {operation}"
        );
        let module = lower(&source);
        let recovery = lower(
            "const p = new Proxy({slot: 17}, {get(target, key) {return target[key];}}); p.slot;",
        );
        for mut core in cores() {
            assert!(
                matches!(
                    core.execute(&module),
                    Err(InterpreterError::StackOverflow { .. })
                ),
                "{operation}"
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
            // The transient lookup guard must unwind on a resource refusal,
            // without becoming replay/activation state or poisoning a rerun.
            let result = core
                .execute(&recovery)
                .expect("recovery after bounded Proxy lookup");
            assert_eq!(result.value, Value::Int(17));
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn direct_assignment_uses_a_proxy_prototype_without_creating_an_own_property() {
    assert_value(
        r#"
        let calls = 0; let receiverMatches = false;
        const prototype = new Proxy({}, {set(target, key, value, receiver) {
            calls++; receiverMatches = receiver === child;
            return key === 'slot' && value === 11;
        }});
        const child = Object.create(prototype);
        child.slot = 11;
        calls + ':' + receiverMatches + ':' + child.hasOwnProperty('slot');
        "#,
        Value::str("1:true:false"),
    );
}

#[test]
fn revocable_factory_supports_quoted_calls_and_preserves_lexical_shadowing() {
    assert_value(
        r#"
        const pair = Proxy['revocable']({slot: 4}, {});
        const before = Reflect.get(pair.proxy, 'slot'); pair.revoke();
        let rejected = false;
        try { Reflect.has(pair.proxy, 'slot'); } catch(e) { rejected = e instanceof TypeError; }
        function localFactory() {
            const Proxy = { revocable(a, b) { return a + b; } };
            return Proxy.revocable(7, 9);
        }
        before + ':' + rejected + ':' + localFactory();
        "#,
        Value::str("4:true:16"),
    );
}

#[test]
fn proxy_factory_labels_remain_on_results_and_block_console_egress() {
    for capability in ["builtin:Proxy", "builtin:ProxyRevocable"] {
        for emit in [false, true] {
            for mut core in cores() {
                let target = core.alloc_object_with_prototype(None).unwrap();
                let handler = core.alloc_object_with_prototype(None).unwrap();
                core.seed_register(0, Value::Object(target)).unwrap();
                core.seed_register(1, Value::Object(handler)).unwrap();
                core.set_register_label(1, Label::Secret).unwrap();
                let mut module = lower("0;");
                module.instructions = vec![Ir3Instruction::HostCall {
                    capability: CapabilityTag(capability.into()),
                    args: RegRange { start: 0, count: 2 },
                    dst: 2,
                }];
                if emit {
                    module.instructions.push(Ir3Instruction::HostCall {
                        capability: CapabilityTag("console:log".into()),
                        args: RegRange { start: 2, count: 1 },
                        dst: 3,
                    });
                }
                module
                    .instructions
                    .push(Ir3Instruction::Return { value: 2 });
                let outcome = core.execute(&module);
                if emit {
                    assert!(
                        matches!(outcome, Err(InterpreterError::CapabilityDenied { capability }) if capability.ends_with(":confidentiality"))
                    );
                    assert!(core.console_output().is_empty());
                } else {
                    let result = outcome.unwrap();
                    assert!(matches!(result.value, Value::Object(_)));
                    assert_eq!(result.completion_label, Label::Secret);
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
fn proxy_factory_clearance_is_exact_and_does_not_declassify_returned_objects() {
    use frankenengine_engine::hash_tiers::ContentHash;
    use frankenengine_engine::ir_contract::{Ir1Literal, Ir1Module, Ir1Op};
    use frankenengine_engine::lowering_pipeline::lower_ir1_to_ir2;
    for factory in [
        "builtin:Proxy",
        "builtin:ProxyRevocable",
        "builtin:ProxyFutureMethod",
    ] {
        let mut ir1 = Ir1Module::new(ContentHash::compute(b"proxy-factory-flow"), "proxy-flow.js");
        ir1.ops = vec![
            Ir1Op::NewObject { count: 0 },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("payload".into()),
            },
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("my_secret_token".into()),
            },
            Ir1Op::NewObject { count: 1 },
            Ir1Op::HostCall {
                capability: factory.into(),
                arg_count: 2,
            },
            Ir1Op::HostCall {
                capability: "net:request".into(),
                arg_count: 1,
            },
            Ir1Op::Return,
        ];
        let module = lower_ir1_to_ir2(&ir1).unwrap().module;
        let creation = module.ops[4].flow.as_ref().unwrap();
        let expected = if factory == "builtin:ProxyFutureMethod" {
            Label::Internal
        } else {
            Label::TopSecret
        };
        assert_eq!(creation.sink_clearance, expected, "{factory}");
        let external = module.ops[5].flow.as_ref().unwrap();
        assert_eq!(external.sink_clearance, Label::Public);
        assert!(Label::Secret.can_flow_to(&external.data_label));
        assert!(external.declassification_required);
    }
}
