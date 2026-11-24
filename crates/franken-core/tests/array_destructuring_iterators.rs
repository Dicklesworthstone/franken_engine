#![forbid(unsafe_code)]

//! Array binding patterns consume iterator records lazily, including elisions,
//! rest, defaults, and the close obligation on normal and abrupt completion.

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
        .expect("array-destructuring fixture must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "array-destructuring.js"),
        &LoweringContext::new("array-destructuring", "array-destructuring", "array-destructuring"),
    )
    .expect("array-destructuring fixture must lower")
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
        let result = InterpreterCore::new(config, "array-destructuring")
            .execute(&module)
            .expect("array-destructuring fixture must execute");
        let actual: Vec<_> = result.console_output.iter()
            .map(|entry| entry.message.as_str()).collect();
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

const PRIVATE_ADAPTERS: [(&str, u32); 5] = [
    ("builtin:DestructureIteratorInit", 1),
    ("builtin:DestructureIteratorNext", 1),
    ("builtin:DestructureIteratorElide", 1),
    ("builtin:DestructureIteratorDone", 2),
    ("builtin:DestructureValue", 2),
];

fn direct_hostcall(tag: &str, count: u32) -> Ir3Module {
    let mut module = Ir3Module::new(
        ContentHash::compute(b"destructure-private-operation"),
        "destructure-private-operation",
    );
    module.instructions = vec![
        Ir3Instruction::HostCall {
            capability: CapabilityTag(tag.into()),
            args: RegRange { start: 0, count },
            dst: 0,
        },
        Ir3Instruction::Return { value: 0 },
    ];
    module
}

#[test]
fn overridden_array_iterators_and_generator_close_drive_bindings() {
    assert_output(
        r#"
        const values = [1, 2];
        values[Symbol.iterator] = function* () {
            try { yield 42; yield 99; }
            finally { console.log('closed'); }
        };
        const [first] = values;
        console.log(first);
        "#,
        &["closed", "42"],
    );
}

#[test]
fn empty_patterns_still_acquire_and_close_the_iterator() {
    assert_output(
        r#"
        let trace = '';
        const iterable = {
            [Symbol.iterator]() {
                trace += 'i';
                return {
                    next() { trace += 'n'; return {done: false, value: 1}; },
                    return() { trace += 'r'; return {}; }
                };
            }
        };
        const [] = iterable;
        let caught = false;
        try { const [] = {}; } catch (error) { caught = true; }
        console.log(trace, caught);
        "#,
        &["ir true"],
    );
}

#[test]
fn elisions_advance_without_reading_iterator_result_values() {
    assert_output(
        r#"
        let trace = '';
        let value = 0;
        const iterable = {
            [Symbol.iterator]() {
                return {
                    next() {
                        trace += 'n';
                        return {done: false, get value() { trace += 'v'; return ++value; }};
                    },
                    return() { trace += 'r'; return {}; }
                };
            }
        };
        const [, second] = iterable;
        console.log(second, trace);
        "#,
        &["1 nnvr"],
    );
}

#[test]
fn rest_and_exhaustion_are_lazy_and_use_string_code_points() {
    assert_output(
        r#"
        let calls = 0;
        let returns = 0;
        const iterable = {
            [Symbol.iterator]() {
                return {
                    next() {
                        calls++;
                        if (calls === 1) { return {value: 20, done: false}; }
                        return {done: true, get value() { throw 99; }};
                    },
                    return() { returns++; return {}; }
                };
            }
        };
        const [first, second = 22, third = 7, ...tail] = iterable;
        const [letter, next, ...empty] = '💩x';
        console.log(first, second, third, tail.length, calls, returns, letter, next, empty.length);
        "#,
        &["20 22 7 0 2 0 💩 x 0"],
    );
}

#[test]
fn nested_patterns_parameter_defaults_and_loop_assignments_use_iterators() {
    assert_output(
        r#"
        let trace = '';
        function* pair() {
            try { yield 20; yield 22; }
            finally { trace += 'p'; }
        }
        function total([first, second]) { return first + second; }
        function* outer() { try { yield pair(); } finally { trace += 'o'; } }
        const [[first, second]] = outer();
        let left = 0;
        let right = 0;
        for ([left, right] of [pair()]) {}
        console.log(total(pair()), first + second, left + right, trace);
        "#,
        &["42 42 42 popp"],
    );
}

#[test]
fn default_failures_close_and_preserve_the_original_throw() {
    assert_output(
        r#"
        let trace = '';
        const failure = {};
        const iterable = {
            [Symbol.iterator]() {
                trace += 'i';
                return {
                    next() { trace += 'n'; return {done: false, value: undefined}; },
                    return() { trace += 'r'; throw {}; }
                };
            }
        };
        function fail() { trace += 'd'; throw failure; }
        let caught;
        try { const [value = fail()] = iterable; } catch (error) { caught = error; }
        console.log(caught === failure, trace);
        "#,
        &["true indr"],
    );
}

#[test]
fn parameter_tdz_failures_close_before_the_body_runs() {
    assert_output(
        r#"
        let trace = '';
        function* values() {
            try { yield undefined; yield 42; }
            finally { trace += 'r'; }
        }
        function read([first = second, second]) { trace += 'b'; }
        let caught = false;
        try { read(values()); } catch (error) { caught = true; }
        console.log(caught, trace);
        "#,
        &["true r"],
    );
}

#[test]
fn acquisition_captures_next_once_without_calling_it_for_empty_patterns() {
    assert_output(
        r#"
        let trace = '';
        const invalidNext = {
            [Symbol.iterator]() {
                trace += 'i';
                return {
                    get next() { trace += 'g'; return 42; },
                    return() { trace += 'r'; return {}; }
                };
            }
        };
        const [] = invalidNext;
        let caught = false;
        try { const [value] = invalidNext; } catch (error) { caught = true; }
        console.log(trace, caught);
        let reads = 0;
        let calls = 0;
        const iterator = {
            get next() {
                reads++;
                return function() {
                    calls++;
                    return {done: false, value: calls};
                };
            },
            return() { return {}; }
        };
        const iterable = {[Symbol.iterator]() { return iterator; }};
        const [first, second] = iterable;
        console.log(first, second, reads, calls);
        "#,
        &["igrig true", "1 2 1 2"],
    );
}

#[test]
fn empty_nested_patterns_and_native_array_elisions_remain_observable() {
    assert_output(
        r#"
        let trace = '';
        const nested = {
            [Symbol.iterator]() {
                trace += 'i';
                return {
                    next() { return {done: true}; },
                    return() { trace += 'r'; return {}; }
                };
            }
        };
        const [[]] = [nested];
        let failed = false;
        try { const [{}] = [null]; } catch (error) { failed = true; }
        const values = [];
        Object.defineProperty(values, '0', {get() { trace += 'g'; return 42; }});
        values.length = 2;
        const [, second = 7] = values;
        const [...[a, b]] = 'xy';
        console.log(trace, failed, second, a, b);
        "#,
        &["irg true 7 x y"],
    );
}

#[test]
fn next_done_and_value_failures_preserve_identity_without_calling_return() {
    for (next_body, expected_trace) in [
        ("throw failure;", "in"),
        ("return {get done() { trace += 'd'; throw failure; }};", "ind"),
        (
            "return {get done() { trace += 'd'; return false; }, get value() { trace += 'v'; throw failure; }};",
            "indv",
        ),
    ] {
        let source = format!(
            r#"
            let trace = '';
            const failure = {{}};
            const iterable = {{
                [Symbol.iterator]() {{
                    trace += 'i';
                    return {{
                        next() {{ trace += 'n'; {next_body} }},
                        return() {{ trace += 'r'; return {{}}; }}
                    }};
                }}
            }};
            let caught;
            try {{ const [value] = iterable; }} catch (error) {{ caught = error; }}
            console.log(caught === failure, trace);
            "#
        );
        assert_output(&source, &[&format!("true {expected_trace}")]);
    }
}

#[test]
fn inner_step_and_acquisition_failures_close_only_the_owning_outer_record() {
    for inner in [
        "{[Symbol.iterator]() { trace += 'i'; throw failure; }}",
        "{[Symbol.iterator]() { trace += 'i'; return {next() { trace += 'n'; throw failure; }, return() { trace += 'x'; return {}; }}; }}",
    ] {
        let source = format!(
            r#"
            let trace = '';
            const failure = {{}};
            const inner = {inner};
            function* outer() {{ try {{ yield inner; }} finally {{ trace += 'o'; }} }}
            let caught;
            try {{ const [[value]] = outer(); }} catch (error) {{ caught = error; }}
            console.log(caught === failure, trace);
            "#
        );
        let expected = if inner.contains("next()") { "true ino" } else { "true io" };
        assert_output(&source, &[expected]);
    }
    assert_output(
        r#"
        let trace = '';
        function* inner() { try { yield null; } finally { trace += 'i'; } }
        function* outer() { try { yield inner(); } finally { trace += 'o'; } }
        let failed = false;
        try { const [[{}]] = outer(); } catch (error) { failed = true; }
        console.log(failed, trace);
        "#,
        &["true io"],
    );
}

#[test]
fn normal_close_errors_propagate_and_shared_throw_precedence_is_preserved() {
    // Core's shared IteratorClose follows the later-edition rule that an
    // incoming throw also wins over GetMethod("return") errors. ES2020's
    // GetMethod ordering differs; this increment does not change for-of.
    for return_property in [
        "get return() { throw failure; }",
        "return() { throw failure; }",
        "return: 42",
        "return() { return 42; }",
    ] {
        let source = format!(
            r#"
            const failure = {{}};
            const original = {{}};
            const iterable = {{
                [Symbol.iterator]() {{
                    return {{next() {{ return {{done: false, value: undefined}}; }}, {return_property}}};
                }}
            }};
            let normal;
            let abrupt;
            try {{ const [] = iterable; }} catch (error) {{ normal = error; }}
            function fail() {{ throw original; }}
            try {{ const [value = fail()] = iterable; }} catch (error) {{ abrupt = error; }}
            console.log(normal === failure, typeof normal, abrupt === original);
            "#
        );
        let expected = if return_property.contains("throw failure") {
            "true object true"
        } else {
            "false object true"
        };
        assert_output(&source, &[expected]);
    }
}

#[test]
fn return_during_a_suspended_default_closes_before_outer_finally() {
    assert_output(
        r#"
        let trace = '';
        function* values() { try { yield undefined; yield 2; } finally { trace += 'i'; } }
        function* consume() {
            try { const [value = yield 20] = values(); trace += 'b'; yield value; }
            finally { trace += 'o'; }
        }
        const iterator = consume();
        console.log(iterator.next().value, trace);
        console.log(iterator.return(42).value, trace);
        "#,
        &["20 ", "42 io"],
    );
    assert_output(
        r#"
        let trace = '';
        function* values() { try { yield undefined; } finally { trace += 'i'; } }
        async function consume() {
            const [value = await Promise.resolve(42)] = values();
            return value;
        }
        consume().then(function(value) { console.log(value, trace); });
        "#,
        &["42 i"],
    );
}

#[test]
fn return_during_a_for_of_head_keeps_return_close_precedence() {
    assert_output(
        r#"
        let trace = '';
        const closeFailure = {};
        function* inner() {
            try { yield undefined; yield 2; }
            finally { trace += 'i'; }
        }
        const outer = {
            [Symbol.iterator]() {
                return {
                    next() { return {done: false, value: inner()}; },
                    return() { trace += 'o'; throw closeFailure; }
                };
            }
        };
        function* consume() {
            for (const [value = yield 20] of outer) { trace += 'b'; }
        }
        const iterator = consume();
        console.log(iterator.next().value, trace);
        let caught;
        try { iterator.return(42); } catch (error) { caught = error; }
        console.log(caught === closeFailure, trace);
        "#,
        &["20 ", "true io"],
    );
}

#[test]
fn values_defaults_and_empty_rest_keep_input_and_done_provenance() {
    for (source, input_kind, expected) in [
        (
            "const input = 987654; input[0] = 42; const [value] = input; value;",
            0,
            Value::Int(42),
        ),
        (
            "const input = 987654; const [value = 42] = input; value;",
            0,
            Value::Int(42),
        ),
        (
            "const input = 987654; const [...rest] = input; rest.length;",
            0,
            Value::Int(0),
        ),
        (
            "const input = 987654; const iterable = {[Symbol.iterator]() { return {next() { return {get done() { return input; }}; }}; }}; const [, value = 42] = iterable; value;",
            1,
            Value::Int(42),
        ),
        (
            "const input = 987654; const iterable = {[Symbol.iterator]() { return {next() { return {done: input}; }}; }}; const [,...rest] = iterable; rest.length;",
            1,
            Value::Int(0),
        ),
        (
            "const input = 987654; const iterable = {[Symbol.iterator]() { return {next() { return {done: false, get value() { return input; }}; }, return() { return {}; }}; }}; const [value] = iterable; value;",
            2,
            Value::Int(42),
        ),
    ] {
        let module = input_module(source);
        for config in configs() {
            for label in [
                Label::Secret,
                Label::Custom { name: "private-pattern".repeat(16), level: 4 },
            ] {
                let mut core = InterpreterCore::new(config.clone(), "destructure-provenance");
                let input = match input_kind {
                    0 => Value::Object(core.alloc_array_with_prototype(None).unwrap()),
                    1 => Value::Bool(true),
                    _ => Value::Int(42),
                };
                seed_input(&mut core, input, &label);
                let result = core.execute(&module).unwrap();
                assert_eq!(result.value, expected, "{source}");
                assert_eq!(result.completion_label, label, "{source}");
            }
        }
    }
}

#[test]
fn close_getters_callbacks_and_failures_retain_iterator_provenance() {
    for (effect, readback, expected) in [
        (
            "get return() { sink.value = 17; return function() { return {}; }; }",
            "sink.value;",
            Some(Value::Int(17)),
        ),
        (
            "return() { sink.value = 19; return {}; }",
            "sink.value;",
            Some(Value::Int(19)),
        ),
        (
            "return() { return 0; }",
            "caught;",
            None,
        ),
    ] {
        let source = format!(
            r#"
            const input = 987654;
            const sink = {{}};
            input[Symbol.iterator] = function() {{
                return {{next() {{ return {{done: false, value: 1}}; }}, {effect}}};
            }};
            let caught;
            try {{ const [] = input; }} catch (error) {{ caught = error; }}
            {readback}
            "#
        );
        let module = input_module(&source);
        for config in configs() {
            let mut core = InterpreterCore::new(config, "destructure-close-provenance");
            let input = Value::Object(core.alloc_object_with_prototype(None).unwrap());
            seed_input(&mut core, input, &Label::Secret);
            let result = core.execute(&module).unwrap();
            if let Some(expected) = &expected {
                assert_eq!(&result.value, expected, "{source}");
            } else {
                assert!(matches!(result.value, Value::Object(_)), "{source}");
            }
            assert_eq!(result.completion_label, Label::Secret, "{source}");
        }
    }
}

#[test]
fn private_adapter_names_and_arities_are_closed_even_in_direct_ir() {
    for (name, count) in PRIVATE_ADAPTERS {
        for tag in [
            format!("{name}Unknown"),
            format!("spread:{name}"),
            format!("spread:spread:{name}"),
        ] {
            let module = direct_hostcall(&tag, count);
            for config in configs() {
                let error = InterpreterCore::new(config, "destructure-private-name")
                    .execute(&module).unwrap_err();
                assert!(
                    matches!(error, InterpreterError::CapabilityDenied { capability } if capability == tag)
                );
            }
        }
        for wrong_count in [0, count + 1] {
            let module = direct_hostcall(name, wrong_count);
            for config in configs() {
                let error = InterpreterCore::new(config, "destructure-private-arity")
                    .execute(&module).unwrap_err();
                assert!(
                    matches!(error, InterpreterError::TypeError { expected, .. } if expected == format!("{count} destructuring operands"))
                );
            }
        }
    }
}

#[test]
fn private_adapters_preserve_static_data_clearance() {
    for (name, count) in PRIVATE_ADAPTERS {
        let mut module = Ir1Module::new(ContentHash::compute(b"destructure-flow"), "destructure-flow");
        module.ops = vec![
            Ir1Op::LoadLiteral { value: Ir1Literal::Integer(0) },
            Ir1Op::LoadLiteral { value: Ir1Literal::String("secret_value".into()) },
            Ir1Op::HostCall { capability: name.into(), arg_count: count },
        ];
        let lowered = lower_ir1_to_ir2(&module).unwrap().module;
        let flow = lowered.ops[2].flow.as_ref().unwrap();
        assert_eq!(flow.data_label, Label::Secret, "{name}");
        assert_eq!(flow.sink_clearance, Label::Secret, "{name}");
    }
}

#[test]
fn close_callbacks_cannot_swallow_denied_authority() {
    for pattern in ["[]", "[value = fail()]"] {
        let source = format!(
            r#"
            function fail() {{ throw {{}}; }}
            const iterable = {{
                [Symbol.iterator]() {{
                    return {{
                        next() {{ return {{done: false, value: undefined}}; }},
                        return() {{ require('./must-not-load.cjs'); return {{}}; }}
                    }};
                }}
            }};
            try {{ const {pattern} = iterable; }} catch (error) {{ console.log('must not catch'); }}
            "#
        );
        let module = lower(&source);
        for config in configs() {
            let error = InterpreterCore::new(config, "destructure-close-authority")
                .execute(&module).unwrap_err();
            assert!(
                matches!(error, InterpreterError::CapabilityDenied { capability } if capability == "module_load")
            );
        }
    }
}

#[test]
fn rest_collection_obeys_fatal_fuel_and_memory_limits() {
    let module = lower(
        r#"
        const step = {value: 1, done: false};
        const endless = {[Symbol.iterator]() { return {next() { return step; }}; }};
        try { const [...rest] = endless; } catch (error) { console.log('must not catch fuel'); }
        "#,
    );
    for mut config in configs() {
        config.instruction_budget = 2000;
        let error = InterpreterCore::new(config, "destructure-rest-fuel")
            .execute(&module).unwrap_err();
        assert!(matches!(error, InterpreterError::BudgetExhausted { .. }), "{error:?}");
    }
    let module = lower(
        r#"
        const step = {value: 0, done: false};
        const iterable = {[Symbol.iterator]() { return {next() {
            step.value++;
            step.done = step.value > 10000;
            return step;
        }}; }};
        try { const [...rest] = iterable; } catch (error) { console.log('must not catch memory'); }
        "#,
    );
    for mut config in configs() {
        config.max_total_memory_bytes = 262_144;
        config.instruction_budget = 1_000_000;
        let mut core = InterpreterCore::new(config, "destructure-rest-memory");
        let error = core.execute(&module).unwrap_err();
        assert!(matches!(error, InterpreterError::MemoryBudgetExceeded { .. }), "{error:?}");
        assert!(core.get_heap().iter().any(|object| {
            object.is_array && matches!(object.properties.get("length"), Some(Value::Int(length)) if *length > 0)
        }));
    }
}
