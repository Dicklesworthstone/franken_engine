#![forbid(unsafe_code)]

//! Calls and construction expand iterator-driven argument lists before entering
//! the ordinary callable path, preserving receiver identity and abrupt exits.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionSeed, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::hash_tiers::ContentHash;
use frankenengine_core::ifc_artifacts::Label;
use frankenengine_core::ir_contract::{
    CapabilityTag, Ir0Module, Ir1Literal, Ir1Module, Ir1Op, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3, lower_ir1_to_ir2};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("argument-spread fixture must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "argument-spread.js"),
        &LoweringContext::new("argument-spread", "argument-spread", "argument-spread"),
    )
    .expect("argument-spread fixture must lower")
    .ir3
}

fn configs() -> [InterpreterConfig; 2] {
    [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ]
    .map(|mut config| {
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
        ]
        .into_iter()
        .collect();
        config
    })
}

fn assert_output(source: &str, expected: &[&str]) {
    let module = lower(source);
    for config in configs() {
        let result = InterpreterCore::new(config, "argument-spread")
            .execute(&module)
            .expect("argument-spread fixture must execute");
        let actual: Vec<_> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected);
    }
}

fn input_module(source: &str) -> Ir3Module {
    let mut module = lower(source);
    let mut replacements = 0;
    for instruction in &mut module.instructions {
        if let Ir3Instruction::LoadInt { dst, value: 987654 } = *instruction {
            *instruction = Ir3Instruction::Move { dst, src: 255 };
            replacements += 1;
        }
    }
    assert_eq!(replacements, 1);
    module
}

fn seed_input(core: &mut InterpreterCore, value: Value, label: &Label) {
    core.write_register(255, value);
    let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
    wire["register_labels"][255] = serde_json::to_value(label).unwrap();
    core.reset_execution_state_from_seed(&serde_json::from_value::<ExecutionSeed>(wire).unwrap())
        .unwrap();
}

#[test]
fn ordinary_calls_expand_mixed_spreads_and_keep_evaluation_order() {
    assert_output(
        r#"
        let trace = '';
        function mark(value) { trace += value; return value; }
        function* tail() { yield mark(3); yield mark(4); }
        function collect(...values) { return values.join(','); }
        const result = collect(mark(1), ...[mark(2)], ...tail(), ...[], mark(5), ...'A💩');
        console.log(result, trace, collect(...[]));
        "#,
        &["1,2,3,4,5,A,💩 12345 "],
    );
}

#[test]
fn member_lookup_precedes_arguments_and_preserves_the_original_receiver() {
    assert_output(
        r#"
        let trace = '';
        const receiver = {
            base: 10,
            get method() {
                trace += 'g';
                return function(a, b) { trace += 'c'; return this.base + a + b; };
            }
        };
        function object() { trace += 'o'; return receiver; }
        function key() { trace += 'k'; return 'method'; }
        function* values() { trace += 'i'; yield 20; yield 12; }
        const result = object()[key()](...values());
        console.log(result, trace);
        "#,
        &["42 okgic"],
    );
}

#[test]
fn optional_calls_skip_iteration_and_keep_method_receivers() {
    assert_output(
        r#"
        let calls = 0;
        function* values() { calls++; yield 2; yield 3; }
        const absent = null;
        const receiver = { base: 7, method(a, b) { return this.base + a + b; } };
        const skipped = absent?.(...values());
        const result = receiver.method?.(...values());
        const missing = receiver.missing?.(...values());
        console.log(skipped === undefined, missing === undefined, result, calls);
        "#,
        &["true true 12 1"],
    );
}

#[test]
fn nullish_optional_spreads_preserve_guard_provenance_without_evaluation() {
    for expression in [
        "input?.(...values())",
        "input?.(...iterable)",
        "input?.method(...values())",
        "input?.[key()](...values())",
        "({ method: input }).method?.(...values())",
        "({ method: input })?.method?.(...iterable)",
    ] {
        let source = format!(
            "const input = 987654; \
             function values() {{ throw 99; }} \
             function key() {{ throw 100; }} \
             const iterable = {{ [Symbol.iterator]() {{ throw 101; }} }}; \
             {expression};"
        );
        let module = input_module(&source);
        for input in [Value::Null, Value::Undefined] {
            for config in configs() {
                let mut core = InterpreterCore::new(config, "optional-spread-labels");
                seed_input(&mut core, input.clone(), &Label::Secret);
                let result = core.execute(&module).unwrap();
                assert_eq!(result.value, Value::Undefined, "{expression}");
                assert_eq!(result.completion_label, Label::Secret, "{expression}");
            }
        }
    }
}

#[test]
fn overridden_array_iterators_and_protocol_getters_drive_argument_expansion() {
    assert_output(
        r#"
        let trace = '';
        let index = 0;
        const iterable = {
            get [Symbol.iterator]() {
                trace += 'i';
                return function() {
                    trace += this === iterable ? 'm' : '?';
                    return {
                        get next() {
                            trace += 'n';
                            return function() {
                                index++;
                                return {
                                    get done() { trace += 'd'; return index > 2; },
                                    get value() { trace += 'v'; return index * 10; }
                                };
                            };
                        }
                    };
                };
            }
        };
        const array = [90, 91];
        array[Symbol.iterator] = function* () { yield 12; };
        function sum(a, b, c) { return a + b + c; }
        console.log(sum(...iterable, ...array), trace);
        "#,
        &["42 imndvdvd"],
    );
}

#[test]
fn abrupt_iterators_preserve_the_exact_throw_and_skip_the_call_and_later_arguments() {
    for producer in [
        "{ get [Symbol.iterator]() { throw failure; } }",
        "{ [Symbol.iterator]() { throw failure; } }",
        "{ [Symbol.iterator]() { return { get next() { throw failure; }, return() { trace += 'r'; } }; } }",
        "{ [Symbol.iterator]() { return { next() { throw failure; }, return() { trace += 'r'; } }; } }",
        "{ [Symbol.iterator]() { return { next() { return { get done() { throw failure; } }; }, return() { trace += 'r'; } }; } }",
        "{ [Symbol.iterator]() { return { next() { return { done: false, get value() { throw failure; } }; }, return() { trace += 'r'; } }; } }",
    ] {
        let source = format!(
            "const failure = {{}}; let trace = ''; const iterable = {producer}; \
             function later() {{ trace += 'l'; return 9; }} \
             function called() {{ trace += 'c'; }} \
             function expand() {{ try {{ return called(...iterable, later()); }} finally {{ trace += 'f'; }} }} \
             let same = false; try {{ expand(); }} catch (error) {{ same = error === failure; }} \
             console.log(same, trace);"
        );
        assert_output(&source, &["true f"]);
    }
}

#[test]
fn invalid_callees_are_checked_after_spread_evaluation_and_throw_catchably() {
    assert_output(
        r#"
        let trace = '';
        function* values() { trace += 'i'; yield 1; trace += 'd'; }
        let caught = false;
        try { const missing = 7; missing(...values()); }
        catch (error) { caught = error.name === 'TypeError'; }
        function called() { trace += 'c'; }
        try { called(...{}); } catch (error) { trace += error.name === 'TypeError' ? 't' : '?'; }
        console.log(caught, trace);
        "#,
        &["true idt"],
    );
}

#[test]
fn spread_calls_cross_the_positional_lowering_register_limit() {
    assert_output(
        r#"
        const values = [];
        for (let i = 0; i < 180; i++) { values.push(i); }
        function collect(first, ...rest) { return first + rest.length + rest[178]; }
        const receiver = { method: collect };
        console.log(collect(...values), receiver.method(...values), receiver.method?.(...values));
        "#,
        &["358 358 358"],
    );
}

#[test]
fn constructor_spread_keeps_new_target_and_large_rest_tails() {
    assert_output(
        r#"
        const values = [];
        for (let i = 0; i < 300; i++) { values.push(i); }
        class Base {
            constructor(first, ...rest) {
                this.first = first; this.rest = rest; this.target = new.target;
            }
        }
        class Child extends Base {}
        const child = new Child(...values);
        console.log(child.first, child.rest.length, child.rest[298],
            child.target === Child, child instanceof Base, child instanceof Child);
        "#,
        &["0 299 299 true true true"],
    );
}

#[test]
fn static_builtin_and_console_calls_expand_their_argument_lists() {
    assert_output(
        r#"
        const object = Object.assign(...[{}, {a: 20}, {b: 22}]);
        console.log(...[object.a + object.b, String.fromCharCode(...[65, 66])]);
        Promise.resolve(...[42]).then(function(value) { console.log(value); });
        new Promise(...[function(resolve) { resolve(7); }]).then(function(value) { console.log(value); });
        "#,
        &["42 AB", "42", "7"],
    );
}

#[test]
fn async_and_generator_callees_keep_their_existing_invocation_semantics() {
    assert_output(
        r#"
        function* generator(first, ...rest) { yield first; yield rest[0]; }
        const result = generator(...[20, 22]);
        console.log(result.next().value, result.next().value, result.next().done);
        async function sum(a, b) { return a + b; }
        sum(...[20, 22]).then(function(value) { console.log(value); });
        const receiver = { base: 10, async method(a, b) { return this.base + a + b; } };
        receiver.method(...[20, 12]).then(function(value) { console.log(value); });
        "#,
        &["20 22 true", "42", "42"],
    );
}

#[test]
fn optional_member_spreads_skip_keys_and_arguments_and_keep_this() {
    assert_output(
        r#"
        let trace = '';
        const absent = null;
        function key() { trace += 'k'; return 'method'; }
        function* values() { trace += 'i'; yield 20; yield 12; }
        const receiver = { base: 10, method(a, b) { return this.base + a + b; } };
        const skipped = absent?.[key()](...values());
        const result = receiver?.[key()](...values());
        const skippedAgain = absent?.[key()]?.(...values());
        console.log(skipped === undefined, skippedAgain === undefined, result, trace);
        "#,
        &["true true 42 ki"],
    );
}

#[test]
fn constructor_spread_keeps_replacement_objects_and_exact_throws() {
    assert_output(
        r#"
        const replacement = {};
        function Replace(a, b) { replacement.total = a + b; replacement.target = new.target; return replacement; }
        const value = new Replace(...[20, 22]);
        const failure = {};
        let trace = '';
        function* values() { trace += 'i'; yield 1; trace += 'd'; }
        function Throw(value) { trace += 'c'; throw failure; }
        let same = false;
        try { new Throw(...values()); } catch (error) { same = error === failure; }
        let invalid = false;
        try { const missing = 7; new missing(...values()); } catch (error) { invalid = error.name === 'TypeError'; }
        console.log(value === replacement, value.total, value.target === Replace, same, invalid, trace);
        "#,
        &["true 42 true true true idcid"],
    );
}

#[test]
fn private_empty_spreads_label_defaults_rest_shapes_body_effects_and_exceptions() {
    for (source, empty_array, expected) in [
        (
            "const input = 987654; function read(first = 42) { return first; } read(...input);",
            true,
            Some(Value::Int(42)),
        ),
        (
            "const input = 987654; function read(...values) { return values.length; } read(...input);",
            true,
            Some(Value::Int(0)),
        ),
        (
            "const input = 987654; const sink = {}; function read() { sink.value = 17; } read(...input); sink.value;",
            true,
            Some(Value::Int(17)),
        ),
        (
            "const input = 987654; const sink = {}; const receiver = {async method() { sink.value = 17; }}; receiver.method(...input); sink.value;",
            true,
            Some(Value::Int(17)),
        ),
        (
            "const input = 987654; const sink = {}; const receiver = {method: async function* () { sink.value = 17; yield 1; }}; const generator = receiver.method(...input); generator.next(); sink.value;",
            true,
            Some(Value::Int(17)),
        ),
        (
            "const input = 987654; const iterable = {[Symbol.iterator]() { return {next() { return {done: input}; }}; }}; function read(first = 42) { return first; } read(...iterable);",
            false,
            Some(Value::Int(42)),
        ),
        (
            "const input = 987654; const failure = {}; function read() { throw failure; } let caught; try { read(...input); } catch (error) { caught = error; } caught;",
            true,
            None,
        ),
        (
            "const input = 987654; function Construct(first = 42) { this.value = first; } new Construct(...input).value;",
            true,
            Some(Value::Int(42)),
        ),
    ] {
        let module = input_module(source);
        for config in configs() {
            for label in [
                Label::Secret,
                Label::Custom {
                    name: "private-spread-shape".repeat(16),
                    level: 4,
                },
            ] {
                let mut core = InterpreterCore::new(config.clone(), "private-spread-shape");
                let input = if empty_array {
                    Value::Object(core.alloc_array_with_prototype(None).unwrap())
                } else {
                    Value::Bool(true)
                };
                seed_input(&mut core, input, &label);
                let result = core.execute(&module).unwrap();
                if let Some(expected) = &expected {
                    assert_eq!(&result.value, expected, "{source}");
                } else {
                    assert!(matches!(result.value, Value::Object(_)), "{source}");
                }
                assert_eq!(result.completion_label, label, "{source}");
            }
        }
    }
}

#[test]
fn selected_callee_receiver_and_yielded_values_keep_their_provenance() {
    for (source, kind) in [
        (
            "function selected() { return 42; } const input = 987654; input(...[]);",
            0,
        ),
        (
            "function selected() { return this.value; } const input = 987654; input.method = selected; input.value = 42; input.method(...[]);",
            1,
        ),
        (
            "const input = 987654; function* values() { yield input; } function read(value) { return value; } read(...values());",
            2,
        ),
    ] {
        let module = input_module(source);
        for config in configs() {
            let mut core = InterpreterCore::new(config, "spread-selection-labels");
            let input = match kind {
                0 | 1 => {
                    let index = module
                        .function_table
                        .iter()
                        .position(|function| function.name.as_deref() == Some("selected"))
                        .unwrap() as u32;
                    if kind == 0 {
                        Value::Function(index)
                    } else {
                        Value::Object(core.alloc_object_with_prototype(None).unwrap())
                    }
                }
                _ => Value::Int(42),
            };
            seed_input(&mut core, input, &Label::Secret);
            let result = core.execute(&module).unwrap();
            assert_eq!(result.value, Value::Int(42), "{source}");
            assert_eq!(result.completion_label, Label::Secret, "{source}");
        }
    }
}

#[test]
fn spread_hostcall_tags_are_closed_and_module_loading_still_needs_authority() {
    for tag in [
        "spread:unknown",
        "spread:spread:console:log",
        "spread:builtin:CallSpread",
        "spread:builtin:ConstructSpread",
        "spread:builtin:ConstructSuperSpread",
        "spread:ifc.check_flow",
        "spread:module.import",
    ] {
        let mut module = Ir3Module::new(
            ContentHash::compute(b"spread-authority"),
            "spread-authority",
        );
        module.instructions = vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag(tag.into()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::Return { value: 0 },
        ];
        for config in configs() {
            let error = InterpreterCore::new(config, "spread-authority")
                .execute(&module)
                .unwrap_err();
            assert!(
                matches!(error, InterpreterError::CapabilityDenied { capability } if capability == tag)
            );
        }
    }
    let module = lower("require(...['./must-not-be-loaded.cjs']);");
    for config in configs() {
        let error = InterpreterCore::new(config, "spread-module-authority")
            .execute(&module)
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::CapabilityDenied { capability } if capability == "module_load")
        );
    }
}

#[test]
fn endless_argument_lists_exhaust_fuel_without_entering_the_callee() {
    let module = lower(
        r#"
        const step = {value: 1, done: false};
        const endless = {[Symbol.iterator]() { return {next() { return step; }}; }};
        function called() { console.log('must not enter'); }
        try { called(...endless); } catch (error) { console.log('must not swallow budget'); }
        "#,
    );
    for mut config in configs() {
        config.instruction_budget = 2000;
        let error = InterpreterCore::new(config, "spread-fuel")
            .execute(&module)
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::BudgetExhausted { .. }),
            "{error:?}"
        );
    }
}

#[test]
fn spread_static_calls_preserve_the_original_ifc_clearance() {
    for capability in [
        "console:log",
        "module:require",
        "builtin:ObjectDefineProperty",
    ] {
        let mut observed = Vec::new();
        for capability in [capability.to_string(), format!("spread:{capability}")] {
            let mut module = Ir1Module::new(ContentHash::compute(b"spread-flow"), "spread-flow");
            module.ops = vec![
                Ir1Op::LoadLiteral {
                    value: Ir1Literal::String("secret_value".into()),
                },
                Ir1Op::HostCall {
                    capability,
                    arg_count: 1,
                },
                Ir1Op::Return,
            ];
            let lowered = lower_ir1_to_ir2(&module).unwrap().module;
            observed.push(lowered.ops[1].flow.clone().unwrap());
        }
        assert_eq!(observed[0], observed[1], "{capability}");
    }
}

#[test]
fn argument_register_and_memory_limits_remain_fatal() {
    let module = lower(
        r#"
        const values = [];
        for (let i = 0; i < 300; i++) { values.push(i); }
        function called(...values) { console.log('must not enter'); }
        try { called(...values); } catch (error) { console.log('must not swallow register limit'); }
        "#,
    );
    for mut config in configs() {
        config.max_registers = 256;
        let error = InterpreterCore::new(config, "spread-register-limit")
            .execute(&module)
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::RegisterOutOfBounds { .. }),
            "{error:?}"
        );
    }
    let module = lower(
        r#"
        const step = {value: 0, done: false};
        const iterable = {[Symbol.iterator]() { return {next() { step.value++; step.done = step.value > 10000; return step; }}; }};
        function called(...values) { console.log('must not enter'); }
        try { called(...iterable); } catch (error) { console.log('must not swallow memory limit'); }
        "#,
    );
    for mut config in configs() {
        config.max_total_memory_bytes = 262_144;
        config.instruction_budget = 1_000_000;
        let mut core = InterpreterCore::new(config, "spread-memory-limit");
        let error = core.execute(&module).unwrap_err();
        assert!(
            matches!(error, InterpreterError::MemoryBudgetExceeded { .. }),
            "{error:?}"
        );
        assert!(core.get_heap().iter().any(|object| {
            object.is_array && matches!(object.properties.get("length"), Some(Value::Int(length)) if *length > 0)
        }));
    }
}
