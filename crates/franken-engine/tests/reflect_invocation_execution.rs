//! Reflect invocation through observable argument lists and both native VM profiles.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "reflect-invocation-execution.js".into(),
                text: format!("const log = console.log;\n{source}"),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("reflection regression source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "reflect-invocation-execution.js"),
        &LoweringContext::new("json-trace", "json-decision", "json-policy"),
    )
    .expect("reflection regression source must lower")
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
        InterpreterCore::new(config, "reflect-invocation-execution")
    })
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for mut core in cores() {
        let result = core
            .execute(&module)
            .expect("native reflection execution must succeed");
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
fn reflect_apply_reads_length_then_live_indices_before_calling_target() {
    assert_output(
        r#"
        const seen = [];
        const list = { get length() { seen.push('length'); return 2; }, get 0() { seen.push('0'); this[1] = 9; return 3; }, 1: 4 };
        function target(a, b) { seen.push('call'); return this.base + a + b; }
        log(Reflect.apply(target, { base: 10 }, list), seen.join('|'));
    "#,
        &["22 length|0|call"],
    );
}

#[test]
fn reflect_argument_list_uses_get_not_iteration_or_own_only_lookup() {
    assert_output(
        r#"
        const list = Object.create({ 1: 8 });
        list[0] = 3;
        list.length = 3;
        list[Symbol.iterator] = function() { throw 'must-not-iterate'; };
        function target(a, b, c) { return a + ':' + b + ':' + (c === undefined); }
        log(Reflect.apply(target, null, list));
        log(target.apply(null, list));
    "#,
        &["3:8:true", "3:8:true"],
    );
}

#[test]
fn reflect_rejects_nonobjects_but_function_apply_accepts_nullish_lists() {
    assert_output(
        r#"
        function target(a = 7) { return a; }
        for (const list of [null, undefined, '12', 4, true, 1n, Symbol()]) {
            try { Reflect.apply(target, null, list); } catch (error) { log(error instanceof TypeError); }
        }
        log(target.apply(null, null), target.apply(null, undefined));
        try { Reflect.construct(target, null); } catch (error) { log(error instanceof TypeError); }
    "#,
        &[
            "true", "true", "true", "true", "true", "true", "true", "7 7", "true",
        ],
    );
}

#[test]
fn invalid_targets_and_new_targets_are_checked_before_list_getters() {
    assert_output(
        r#"
        const list = { get length() { throw 'length-read-too-early'; } };
        function target() { throw 'target-called'; }
        try { Reflect.apply({}, null, list); } catch (error) { log(error instanceof TypeError); }
        try { Reflect.construct({}, list); } catch (error) { log(error instanceof TypeError); }
        try { Reflect.construct(target, list, undefined); } catch (error) { log(error instanceof TypeError); }
        try { Reflect.construct(target, list, () => 1); } catch (error) { log(error instanceof TypeError); }
    "#,
        &["true", "true", "true", "true"],
    );
}

#[test]
fn reflect_length_coercion_runs_once_with_number_hint_and_exact_grammar() {
    assert_output(
        r#"
        const seen = [];
        const length = { [Symbol.toPrimitive]: function(hint) { seen.push(hint); return 2.9; } };
        function target(a = 7, b = 11) { return a + b; }
        log(Reflect.apply(target, null, { length: length, 0: 2, 1: 3, 2: 99 }), seen.join('|'));
        log(Reflect.apply(target, null, { length: '\ufeff \ufeff\n0b10\ufeff', 0: 4, 1: 5 }));
        log(Reflect.apply(target, null, { length: '\u00851', 0: 99 }));
        log(target.apply(null, { length: '\u00851', 0: 99 }));
        for (const value of [1n, Symbol()]) {
            try { Reflect.apply(target, null, { length: value }); } catch (error) { log(error instanceof TypeError); }
        }
    "#,
        &["5 number", "9", "18", "18", "true", "true"],
    );
}

#[test]
fn reflect_proxy_argument_list_preserves_get_order_and_receiver() {
    assert_output(
        r#"
        const seen = [];
        const list = new Proxy({ length: 2, 0: 4, 1: 6 }, {
            get: function(target, key, receiver) { seen.push(key + ':' + (receiver === list)); return target[key]; }
        });
        function target(a, b) { return a + b; }
        log(Reflect.apply(target, undefined, list), seen.join('|'));
    "#,
        &["10 length:true|0:true|1:true"],
    );
}

#[test]
fn abrupt_argument_reads_preserve_effects_and_skip_remaining_reads_and_target() {
    assert_output(
        r#"
        const seen = [];
        const token = {};
        const list = { length: 3, get 0() { seen.push('0'); return 1; }, get 1() { seen.push('1'); throw token; }, get 2() { seen.push('2'); return 3; } };
        function target() { seen.push('target'); }
        try { Reflect.apply(target, null, list); } catch (error) { log(error === token); }
        try { Reflect.construct(target, list); } catch (error) { log(error === token); }
        log(seen.join('|'));
        log(Reflect.apply(function(x) { return x; }, null, [19]));
    "#,
        &["true", "true", "0|1|0|1", "19"],
    );
}

#[test]
fn reflect_construct_extracts_arguments_before_new_target_prototype_lookup() {
    assert_output(
        r#"
        const seen = [];
        function Target(value) { seen.push('construct'); this.value = value; }
        function NewTarget() { throw 'new-target-body'; }
        const prototype = { tag: 42 };
        const list = { get length() { seen.push('length'); return 1; }, get 0() { seen.push('0'); NewTarget.prototype = prototype; return 9; } };
        const result = Reflect.construct(Target, list, NewTarget);
        log(result.value, result.tag, Object.getPrototypeOf(result) === prototype, seen.join('|'));
    "#,
        &["9 42 true length|0|construct"],
    );
}

#[test]
fn reflect_construct_supports_object_return_and_shared_nested_invocation() {
    assert_output(
        r#"
        const returned = {};
        function Target(value) { returned.value = value; return returned; }
        const list = { length: 2, get 0() { return Reflect.apply(function(x) { return x + 1; }, null, { 0: 4, length: 1 }); }, get 1() { return 8; } };
        log(Reflect.construct(Target, list) === returned, returned.value);
        log(Reflect.apply(function(a, b) { return a + b; }, null, list));
    "#,
        &["true 5", "13"],
    );
}

#[test]
fn reflect_apply_accepts_generator_async_and_async_generator_callables() {
    assert_output(
        r#"
        function* generator(value) { yield this.base + value; }
        const iterator = Reflect.apply(generator, { base: 7 }, [3]);
        log(iterator.next().value, iterator.next().done);
        async function asyncTarget(value) { return this.base + value; }
        Reflect.apply(asyncTarget, { base: 20 }, [2]).then(function(value) { log(value); });
        async function* asyncGenerator(value) { yield this.base + value; }
        Reflect.apply(asyncGenerator, { base: 30 }, [3]).next().then(function(result) { log(result.value, result.done); });
    "#,
        &["10 true", "22", "33 false"],
    );
}

#[test]
fn oversized_argument_lists_refuse_before_indexed_getters_or_target() {
    for source in [
        "Reflect.apply(function() { log('target'); }, null, { get length() { log('length'); return 1e12; }, get 0() { log('index'); } });",
        "Reflect.construct(function() { log('target'); }, { get length() { log('length'); return Infinity; }, get 0() { log('index'); } });",
    ] {
        let module = lower(source);
        for mut core in cores() {
            assert!(matches!(
                core.execute(&module),
                Err(InterpreterError::RegisterOutOfBounds { .. })
            ));
            assert_eq!(
                core.console_output()
                    .iter()
                    .map(|entry| entry.message.as_str())
                    .collect::<Vec<_>>(),
                ["length"]
            );
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}

#[test]
fn reflecting_deep_argument_graphs_uses_bounded_provenance_walk() {
    assert_output(
        r#"
        const list = { length: 1, 0: 42 };
        let cursor = list;
        for (let index = 0; index < 400; index++) { cursor.child = {}; cursor = cursor.child; }
        log(Reflect.apply(function(value) { return value; }, null, list));
    "#,
        &["42"],
    );
}

#[test]
fn proxy_own_keys_consumes_observable_array_like_trap_results() {
    assert_output(
        r#"
        const seen = [];
        const symbol = Symbol('key');
        const list = Object.create({ 1: symbol });
        Object.defineProperty(list, 'length', { get: function() { seen.push('length'); return 2; } });
        Object.defineProperty(list, '0', { get: function() { seen.push('0'); return 'name'; } });
        const proxy = new Proxy({}, { ownKeys: function() { seen.push('ownKeys'); return list; } });
        const keys = Reflect.ownKeys(proxy);
        log(keys.length, keys[0], keys[1] === symbol, seen.join('|'));
    "#,
        &["2 name true ownKeys|length|0"],
    );
}

#[test]
fn proxy_own_keys_trap_result_can_itself_be_a_proxy() {
    assert_output(
        r#"
        const seen = [];
        const list = new Proxy({ length: 2, 0: 'a', 1: 'b' }, { get: function(target, key, receiver) { seen.push(key + ':' + (receiver === list)); return target[key]; } });
        const proxy = new Proxy({ a: 1, b: 2 }, { ownKeys: function() { return list; } });
        log(Object.keys(proxy).join(','), seen.join('|'));
    "#,
        &["a,b length:true|0:true|1:true"],
    );
}

#[test]
fn proxy_own_keys_stops_before_later_getters_after_invalid_element() {
    assert_output(
        r#"
        const seen = [];
        const list = { length: 2, get 0() { seen.push('0'); return 17; }, get 1() { seen.push('1'); throw 'read-too-far'; } };
        const proxy = new Proxy({}, { ownKeys: function() { return list; } });
        try { Reflect.ownKeys(proxy); } catch (error) { log(error instanceof TypeError); }
        log(seen.join('|'));
    "#,
        &["true", "0"],
    );
}

#[test]
fn proxy_own_keys_checks_duplicates_only_after_consuming_the_list() {
    assert_output(
        r#"
        const seen = [];
        const list = { length: 3, get 0() { seen.push('0'); return 'a'; }, get 1() { seen.push('1'); return 'a'; }, get 2() { seen.push('2'); return 'b'; } };
        const proxy = new Proxy({}, { ownKeys: function() { return list; } });
        try { Reflect.ownKeys(proxy); } catch (error) { log(error instanceof TypeError); }
        log(seen.join('|'));
    "#,
        &["true", "0|1|2"],
    );
}

#[test]
fn proxy_key_list_reentrancy_and_abrupt_reads_do_not_corrupt_reflect_context() {
    assert_output(
        r#"
        const token = {};
        const list = { get length() { return Reflect.apply(function(x) { return x; }, null, [1]); }, get 0() { throw token; } };
        const proxy = new Proxy({}, { ownKeys: function() { return list; } });
        try { Reflect.ownKeys(proxy); } catch (error) { log(error === token); }
        log(Reflect.apply(function(a) { return a; }, null, [42]));
    "#,
        &["true", "42"],
    );
}

#[test]
fn oversized_proxy_key_list_refuses_before_indexed_getters() {
    let module = lower(
        "Reflect.ownKeys(new Proxy({}, { ownKeys: function() { return { length: Infinity, get 0() { log('index'); return 'a'; } }; } }));",
    );
    for mut core in cores() {
        assert!(matches!(
            core.execute(&module),
            Err(InterpreterError::RegisterOutOfBounds { .. })
        ));
        assert!(core.console_output().is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn reflected_calls_keep_secret_argument_shape_even_when_target_returns_a_literal() {
    use frankenengine_engine::baseline_interpreter::Value;
    use frankenengine_engine::ifc_artifacts::Label;
    use frankenengine_engine::ir_contract::{
        CapabilityTag, Ir3FunctionDesc, Ir3Instruction, RegRange,
    };
    for mut core in cores() {
        let list = core.alloc_object_with_prototype(None).unwrap();
        for (register, value) in [
            (0, Value::Function(0)),
            (1, Value::Undefined),
            (2, Value::Object(list)),
            (5, Value::str("0")),
            (6, Value::Int(42)),
            (7, Value::Object(list)),
            (8, Value::str("length")),
            (9, Value::Int(1)),
        ] {
            core.seed_register(register, value).unwrap();
        }
        core.set_register_label(6, Label::Secret).unwrap();
        let mut module = lower("0;");
        module.instructions = vec![
            Ir3Instruction::SetProperty {
                obj: 2,
                key: 5,
                val: 6,
            },
            Ir3Instruction::SetProperty {
                obj: 2,
                key: 8,
                val: 9,
            },
            Ir3Instruction::Move { dst: 2, src: 7 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("builtin:ReflectApply".into()),
                args: RegRange { start: 0, count: 3 },
                dst: 4,
            },
            Ir3Instruction::Return { value: 4 },
            Ir3Instruction::LoadInt { dst: 0, value: 99 },
            Ir3Instruction::Return { value: 0 },
        ];
        module.function_table = vec![Ir3FunctionDesc {
            entry: 5,
            arity: 1,
            frame_size: 1,
            name: Some("literal_target".into()),
            is_generator: false,
            rest_param_index: None,
        }];
        let result = core.execute(&module).unwrap();
        assert_eq!(result.value, Value::Int(99));
        assert_eq!(result.completion_label, Label::Secret);
        assert_eq!(core.get_register_label(2).unwrap(), &Label::Public);
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn long_array_like_length_conversion_is_budgeted_before_indexed_getters() {
    let module = lower(&format!(
        "Reflect.apply(function() {{ log('target'); }}, null, {{ length: '{}', get 0() {{ log('index'); }} }});",
        "0".repeat(16_384)
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
            RuntimeCapability::Console,
        ]
        .into_iter()
        .collect();
        let mut core = InterpreterCore::new(config, "reflection-work-budget");
        assert!(matches!(
            core.execute(&module),
            Err(InterpreterError::BudgetExhausted { .. })
        ));
        assert!(core.console_output().is_empty());
        assert_eq!(
            core.estimated_memory_bytes(),
            core.recompute_estimated_memory_bytes()
        );
    }
}

#[test]
fn arrow_functions_are_not_reflect_or_direct_constructors() {
    assert_output(
        r#"
        const arrow = () => { throw 'body-must-not-run'; };
        const list = { get length() { throw 'length-must-not-run'; } };
        try { Reflect.construct(arrow, list); } catch (error) { log(error instanceof TypeError); }
        try { new arrow(); } catch (error) { log(error instanceof TypeError); }
        log(Reflect.apply(() => 42, null, []));
    "#,
        &["true", "true", "42"],
    );
}

#[test]
fn prototype_replacement_is_live_for_future_instances_and_instanceof() {
    assert_output(
        r#"
        function Target() { this.value = 9; }
        const alias = Target;
        const before = new Target();
        const original = Target.prototype;
        const replacement = { tag: 42 };
        alias.prototype = replacement;
        const after = new Target();
        log(Target.prototype === replacement, Object.getPrototypeOf(before) === original, Object.getPrototypeOf(after) === replacement);
        log(before instanceof Target, after instanceof Target, after.value, after.tag);
        Target.prototype = null;
        log(Target.prototype === null, Object.getPrototypeOf(new Target()) === Object.prototype);
        try { log(after instanceof Target); } catch (error) { log(error instanceof TypeError); }
        log(1 instanceof Target);
    "#,
        &[
            "true true true",
            "false true 9 42",
            "true true",
            "true",
            "false",
        ],
    );
}

#[test]
fn closure_prototypes_are_owned_by_each_closure_not_only_its_function_index() {
    assert_output(
        r#"
        function factory(value) { return function() { this.value = value; }; }
        const A = factory(1); const B = factory(2);
        A.prototype = { tag: 'a' }; B.prototype = { tag: 'b' };
        const a = Reflect.construct(A, []); const b = Reflect.construct(B, []);
        log(a.value, a.tag, b.value, b.tag, a instanceof A, a instanceof B);
        const arrow = () => 42;
        log(arrow.prototype === undefined);
        arrow.prototype = {};
        try { new arrow(); } catch (error) { log(error instanceof TypeError); }
    "#,
        &["1 a 2 b true false", "true", "true"],
    );
}
