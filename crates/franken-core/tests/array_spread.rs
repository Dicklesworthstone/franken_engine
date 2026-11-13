#![forbid(unsafe_code)]

//! Array literal spread observes the iterator protocol without snapshotting
//! values, losing provenance, or bypassing the interpreter's resource limits.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    AccessorProperty, ExecutionSeed, HeapObject, InterpreterConfig, InterpreterCore,
    InterpreterError, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ifc_artifacts::Label;
use frankenengine_core::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("array-spread fixture must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "array-spread.js"),
        &LoweringContext::new("array-spread", "array-spread", "array-spread"),
    )
    .expect("array-spread fixture must lower")
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
        let result = InterpreterCore::new(config, "array-spread")
            .execute(&module)
            .expect("array-spread fixture must execute");
        let actual: Vec<&str> = result
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
fn generators_and_custom_array_iterators_expand_in_evaluation_order() {
    assert_output(
        r#"
        let trace = '';
        function mark(value) { trace += value; return value; }
        function* sequence() { yield mark(2); yield mark(3); }
        const values = [90, 91];
        values[Symbol.iterator] = function* () { yield mark(4); yield mark(5); };
        const result = [mark(1), ...sequence(), ...values, mark(6)];
        const finished = sequence();
        finished.next(); finished.next(); finished.next();
        console.log(result.length, result.join(','), [...finished].length, trace);
        "#,
        &["6 1,2,3,4,5,6 0 12345623"],
    );
}

#[test]
fn protocol_getters_run_once_in_order_with_the_correct_receiver() {
    assert_output(
        r#"
        let trace = '';
        let index = 0;
        const iterator = {
            get next() {
                trace += 'n';
                return function() {
                    trace += this === iterator ? 'N' : '?';
                    index++;
                    return {
                        get done() { trace += 'd'; return index > 2; },
                        get value() { trace += 'v'; return index * 10; }
                    };
                };
            }
        };
        const iterable = {
            get [Symbol.iterator]() {
                trace += 'i';
                return function() {
                    trace += this === iterable ? 'm' : '?';
                    return iterator;
                };
            }
        };
        const result = [...iterable];
        console.log(result.length, result[0], result[1], trace);
        "#,
        &["2 10 20 imnNdvNdvNd"],
    );
}

#[test]
fn sparse_elisions_stay_holes_while_spread_holes_become_own_undefined() {
    assert_output(
        r#"
        const source = [, 2, ,];
        const result = [, ...source, , ...'A💩\ud800'];
        console.log(result.length, 0 in result, 1 in result, result[1] === undefined,
            result[2], 3 in result, 4 in result, result[5], result[6], result[7] === '\ud800');
        "#,
        &["8 false true true 2 true false A 💩 true"],
    );
}

#[test]
fn protocol_failures_keep_exact_throws_and_do_not_close_or_evaluate_later_elements() {
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
             function expand() {{ try {{ return [...iterable, later()]; }} finally {{ trace += 'f'; }} }} \
             let same = false; try {{ expand(); }} catch (error) {{ same = error === failure; }} \
             console.log(same, trace);"
        );
        assert_output(&source, &["true f"]);
    }
}

#[test]
fn noniterables_and_malformed_iterators_raise_catchable_type_errors() {
    assert_output(
        r#"
        function rejected(value) {
            try { [...value]; } catch (error) { return error.name === 'TypeError'; }
            return false;
        }
        const absent = [1]; absent[Symbol.iterator] = undefined;
        const nullMethod = [1]; nullMethod[Symbol.iterator] = null;
        console.log(rejected(null), rejected(undefined), rejected(7), rejected(true),
            rejected({length: 1, 0: 9}), rejected(absent), rejected(nullMethod));
        console.log(rejected({[Symbol.iterator]: 7}),
            rejected({[Symbol.iterator]() { return 7; }}),
            rejected({[Symbol.iterator]() { return {}; }}),
            rejected({[Symbol.iterator]() { return {next: 7}; }}),
            rejected({[Symbol.iterator]() { return {next() { return 7; }}; }}));
        "#,
        &[
            "true true true true true true true",
            "true true true true true",
        ],
    );
}

#[test]
fn nested_spread_callbacks_restore_the_callers_finally_and_registers() {
    assert_output(
        r#"
        let steps = 0;
        let trace = '';
        const iterable = {
            [Symbol.iterator]() {
                return {
                    next() {
                        const nested = [...'xy'];
                        steps++;
                        trace += nested[0];
                        return {value: nested[1], done: steps > 2};
                    }
                };
            }
        };
        function expand() {
            const before = 41;
            try { const result = [before, ...iterable, before + 1]; return result.join(','); }
            finally { trace += 'f'; }
        }
        console.log(expand(), trace);
        "#,
        &["41,y,y,42 xxxf"],
    );
}

#[test]
fn native_array_iteration_observes_index_getters_and_length_mutation() {
    let module = input_module(
        r#"
        function first() { this[1] = 9; this.push(3); return 7; }
        const input = 987654;
        const result = [...input];
        console.log(result.length, result[0], result[1], result[2]);
        "#,
    );
    let getter = module
        .function_table
        .iter()
        .position(|function| function.name.as_deref() == Some("first"))
        .unwrap() as u32;
    for config in configs() {
        let mut core = InterpreterCore::new(config, "array-spread-native-getter");
        let array = core.alloc_array_with_prototype(None).unwrap();
        core.write_register(255, Value::Object(array));
        let mut seeded = HeapObject::default();
        seeded.is_array = true;
        seeded.properties.insert("length".into(), Value::Int(2));
        seeded.properties.insert("1".into(), Value::Int(2));
        seeded.accessors.insert(
            "0".into(),
            AccessorProperty {
                get: Some(Value::Function(getter)),
                set: None,
            },
        );
        let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
        wire["heap"][array.0 as usize] = serde_json::to_value(seeded).unwrap();
        core.reset_execution_state_from_seed(
            &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
        )
        .unwrap();
        let result = core.execute(&module).unwrap();
        assert_eq!(result.console_output[0].message, "3 7 9 3");
    }
}

#[test]
fn literal_appends_define_own_data_without_invoking_inherited_setters() {
    let mut module = lower(
        r#"
        function setter(value) { throw 'inherited setter must not run'; }
        const result = [...'ab', 'c'];
        console.log(result.length, result[0], result[1], result[2]);
        "#,
    );
    let setter = module
        .function_table
        .iter()
        .position(|function| function.name.as_deref() == Some("setter"))
        .unwrap() as u32;
    let mut replacements = 0;
    for instruction in &mut module.instructions {
        if let Ir3Instruction::NewArray { dst } = *instruction {
            *instruction = Ir3Instruction::Move { dst, src: 255 };
            replacements += 1;
        }
    }
    assert_eq!(replacements, 1);
    for config in configs() {
        let mut core = InterpreterCore::new(config, "array-literal-own-data");
        let prototype = core.alloc_object_with_prototype(None).unwrap();
        let array = core.alloc_array_with_prototype(Some(prototype)).unwrap();
        core.write_register(255, Value::Object(array));
        let mut inherited = HeapObject::default();
        for index in ["0", "1", "2"] {
            inherited.accessors.insert(
                index.into(),
                AccessorProperty {
                    get: None,
                    set: Some(Value::Function(setter)),
                },
            );
        }
        let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
        wire["heap"][prototype.0 as usize] = serde_json::to_value(inherited).unwrap();
        core.reset_execution_state_from_seed(
            &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
        )
        .unwrap();
        let result = core.execute(&module).unwrap();
        assert_eq!(result.console_output[0].message, "3 a b c");
    }
}

#[test]
fn empty_and_completed_iterators_preserve_shape_and_later_element_provenance() {
    for (source, empty_array, expected) in [
        (
            "const input = 987654; [...input].length;",
            true,
            Value::Int(0),
        ),
        (
            "const input = 987654; [...input, 42][0];",
            true,
            Value::Int(42),
        ),
        (
            "const input = 987654; [...input, , 42][1];",
            true,
            Value::Int(42),
        ),
        (
            "const input = 987654; const iterable = { [Symbol.iterator]() { return { next() { return {done: input}; } }; } }; [...iterable].length;",
            false,
            Value::Int(0),
        ),
        (
            "const input = 987654; let steps = 0; const iterable = { [Symbol.iterator]() { return { next() { steps++; return steps === 1 ? {value: 8, done: false} : {done: input}; } }; } }; [...iterable, 42][1];",
            false,
            Value::Int(42),
        ),
    ] {
        let module = input_module(source);
        for config in configs() {
            for label in [
                Label::Secret,
                Label::Custom {
                    name: "private-spread-shape".repeat(32),
                    level: 4,
                },
            ] {
                let mut core = InterpreterCore::new(config.clone(), "array-spread-shape");
                let input = if empty_array {
                    Value::Object(core.alloc_array_with_prototype(None).unwrap())
                } else {
                    Value::Bool(true)
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
fn yielded_values_and_iterator_callback_side_effects_retain_source_labels() {
    for (source, expected) in [
        (
            "const input = 987654; function* values() { yield input; } [...values()][0];",
            Value::Int(42),
        ),
        (
            "const input = 987654; const sink = {}; input[Symbol.iterator] = function() { sink.value = 17; return {next() { return {done: true}; }}; }; [...input]; sink.value;",
            Value::Int(17),
        ),
        (
            "const input = 987654; const sink = {}; input[Symbol.iterator] = function() { return {next() { sink.value = 17; return {done: true}; }}; }; [...input]; sink.value;",
            Value::Int(17),
        ),
        (
            "const input = 987654; const sink = {}; input[Symbol.iterator] = function* () { sink.value = 17; yield 8; }; [...input]; sink.value;",
            Value::Int(17),
        ),
        (
            "const input = 987654; const failure = {}; input[Symbol.iterator] = function() { return {next() { throw failure; }}; }; let caught; try { [...input]; } catch (error) { caught = error; } caught;",
            Value::Undefined,
        ),
    ] {
        let module = input_module(source);
        for config in configs() {
            let mut core = InterpreterCore::new(config, "array-spread-callback-labels");
            let input = if source.contains("function* values") {
                Value::Int(42)
            } else {
                Value::Object(core.alloc_array_with_prototype(None).unwrap())
            };
            seed_input(&mut core, input, &Label::Secret);
            let result = core.execute(&module).unwrap();
            if expected == Value::Undefined {
                assert!(matches!(result.value, Value::Object(_)));
            } else {
                assert_eq!(result.value, expected, "{source}");
            }
            assert_eq!(result.completion_label, Label::Secret, "{source}");
        }
    }
}

#[test]
fn endless_spreads_consume_fuel_and_cannot_be_swallowed_by_guest_catch() {
    let module = lower(
        r#"
        const step = {value: 1, done: false};
        const endless = { [Symbol.iterator]() { return {next() { return step; }}; } };
        try { [...endless]; } catch (error) { console.log('budget must escape'); }
        "#,
    );
    for mut config in configs() {
        config.instruction_budget = 2000;
        let error = InterpreterCore::new(config, "array-spread-fuel")
            .execute(&module)
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::BudgetExhausted { .. }),
            "{error:?}"
        );
    }
}

#[test]
fn streaming_values_and_string_expansion_respect_total_memory_limits() {
    let module = lower(
        r#"
        const step = {value: 0, done: false};
        const iterable = {
            [Symbol.iterator]() {
                return {next() { step.value++; step.done = step.value > 10000; return step; }};
            }
        };
        try { [...iterable]; } catch (error) { console.log('memory limit must escape'); }
        "#,
    );
    for mut config in configs() {
        config.max_total_memory_bytes = 262_144;
        config.instruction_budget = 1_000_000;
        let mut core = InterpreterCore::new(config, "array-spread-memory");
        let error = core.execute(&module).unwrap_err();
        assert!(
            matches!(error, InterpreterError::MemoryBudgetExceeded { .. }),
            "{error:?}"
        );
        assert!(core.get_heap().iter().any(|object| {
            object.is_array && matches!(object.properties.get("length"), Some(Value::Int(length)) if *length > 0)
        }));
    }
    let module = input_module("const input = 987654; [...input];");
    for mut config in configs() {
        config.max_total_memory_bytes = 262_144;
        let mut core = InterpreterCore::new(config, "array-spread-string-memory");
        seed_input(&mut core, Value::str("x".repeat(8192)), &Label::Public);
        let error = core.execute(&module).unwrap_err();
        assert!(
            matches!(error, InterpreterError::MemoryBudgetExceeded { .. }),
            "{error:?}"
        );
        assert!(core.get_heap().iter().any(|object| {
            object.is_array && object.properties.get("length") == Some(&Value::Int(0))
        }));
    }
}
