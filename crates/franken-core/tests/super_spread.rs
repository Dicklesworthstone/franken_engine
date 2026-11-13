#![forbid(unsafe_code)]

//! Dynamic superclass argument lists use the iterator protocol and enter the
//! ordinary constructor state machine without expanding the caller frame.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionSeed, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::hash_tiers::ContentHash;
use frankenengine_core::ifc_artifacts::Label;
use frankenengine_core::ir_contract::{
    Ir0Module, Ir1Literal, Ir1Module, Ir1Op, Ir3Instruction, Ir3Module,
};
use frankenengine_core::lowering_pipeline::{
    LoweringContext, lower_ir0_to_ir3, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("super-spread fixture must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "super-spread.js"),
        &LoweringContext::new("super-spread", "super-spread", "super-spread"),
    )
    .expect("super-spread fixture must lower")
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
        let result = InterpreterCore::new(config, "super-spread")
            .execute(&module)
            .expect("super-spread fixture must execute");
        let actual: Vec<&str> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected);
        assert!(result.hostcall_decisions.iter().any(|decision| {
            decision.capability.0 == "builtin:ConstructSuperSpread" && decision.allowed
        }));
    }
}

#[test]
fn mixed_spreads_evaluate_in_order_and_keep_string_code_points() {
    assert_output(
        r#"
        let trace = '';
        function mark(value) { trace += value; return value; }
        class Base {
            constructor(first, ...rest) { this.first = first; this.rest = rest; }
        }
        class Child extends Base {
            constructor() {
                super(mark(1), ...[mark(2), mark(3)], mark(4), ...[], ...'A💩');
            }
        }
        const child = new Child();
        console.log(trace, child.first, child.rest.length,
            child.rest[0], child.rest[1], child.rest[2], child.rest[3], child.rest[4]);
        "#,
        &["1234 1 5 2 3 4 A 💩"],
    );
}

#[test]
fn large_rest_tails_and_default_constructor_chains_keep_new_target() {
    let source = r#"
        const values = [];
        for (let i = 0; i < 300; i++) { values.push(i); }
        class Base {
            constructor(first, ...rest) {
                this.first = first; this.rest = rest; this.target = new.target;
            }
        }
        class Middle extends Base {}
        class Child extends Middle {
            constructor(values) { super(...values); this.ready = true; }
        }
        class Last extends Child {}
        const child = new Last(values);
        console.log(child.first, child.rest.length, child.rest[0], child.rest[298]);
        console.log(child.target === Last, child instanceof Base, child instanceof Last, child.ready);
    "#;
    let module = lower(source);
    assert!(
        module
            .function_table
            .iter()
            .all(|function| function.frame_size <= 256)
    );
    assert_output(source, &["0 299 1 299", "true true true true"]);
}

#[test]
fn returned_replacement_object_becomes_this_and_super_expression_value() {
    assert_output(
        r#"
        const replacement = {};
        class Base {
            constructor(...values) {
                replacement.sum = values[0] + values[1];
                replacement.target = new.target;
                return replacement;
            }
        }
        class Child extends Base {
            constructor(...values) {
                const receiver = super(...values);
                this.same = receiver === this;
                this.initialized = 9;
            }
        }
        const child = new Child(20, 22);
        console.log(child === replacement, child.sum, child.target === Child, child.same, child.initialized);
        "#,
        &["true 42 true true 9"],
    );
}

#[test]
fn array_iterator_overrides_and_generator_yields_are_observed() {
    assert_output(
        r#"
        let calls = 0;
        const values = [1, 2];
        values[Symbol.iterator] = function* () { calls++; yield 7; yield 8; };
        function* tail() { yield 9; }
        class Base {
            constructor(a, b, c) { this.total = a * 100 + b * 10 + c; }
        }
        class Child extends Base { constructor() { super(...values, ...tail()); } }
        console.log(new Child().total, calls);
        "#,
        &["789 1"],
    );
}

#[test]
fn iterator_getters_are_evaluated_once_in_protocol_order() {
    assert_output(
        r#"
        let trace = '';
        let index = 0;
        const iterator = {
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
        const iterable = { [Symbol.iterator]() { trace += 'i'; return iterator; } };
        class Base { constructor(a, b) { trace += 'b'; this.total = a + b; } }
        class Child extends Base { constructor() { super(...iterable); } }
        console.log(new Child().total, trace);
        "#,
        &["30 indvdvdb"],
    );
}

#[test]
fn iterator_failure_preserves_identity_and_skips_parent_and_later_arguments() {
    // ArgumentListEvaluation propagates IteratorStep/IteratorValue failure
    // without calling return() on the failed iterator.
    let source = r#"
        const failure = {};
        let trace = '';
        let steps = 0;
        const iterable = {
            [Symbol.iterator]() {
                return {
                    next() { steps++; if (steps === 2) { throw failure; } return {value: 1, done: false}; },
                    return() { trace += 'r'; return {done: true}; }
                };
            }
        };
        function later() { trace += 'l'; return 2; }
        class Base { constructor() { trace += 'b'; } }
        class Child extends Base {
            constructor() { try { super(...iterable, later()); } finally { trace += 'f'; } }
        }
        let same = false;
        try { new Child(); } catch (error) { same = error === failure; }
        console.log(same, trace, steps);
    "#;
    // Expansion fails before the internal constructor hostcall is reached.
    for config in configs() {
        let result = InterpreterCore::new(config, "super-spread-iterator-throw")
            .execute(&lower(source))
            .unwrap();
        assert_eq!(result.console_output[0].message, "true f 2");
    }
}

#[test]
fn parent_throw_restores_enclosing_finally_and_exact_exception() {
    assert_output(
        r#"
        const failure = {};
        let trace = '';
        class Base { constructor(value) { trace += value; throw failure; } }
        class Child extends Base {
            constructor() { try { super(...[4]); } finally { trace += 'f'; } }
        }
        let same = false;
        try { new Child(); } catch (error) { same = error === failure; }
        console.log(same, trace);
        "#,
        &["true 4f"],
    );
}

#[test]
fn noniterables_and_uninitialized_or_repeated_this_remain_errors() {
    let source = r#"
        class Base {}
        class Child extends Base { constructor(value) { super(...value); } }
        let rejected = 0;
        try { new Child(null); } catch (error) { if (error.name === 'TypeError') { rejected++; } }
        try { new Child(7); } catch (error) { if (error.name === 'TypeError') { rejected++; } }
        try { new Child({length: 1, 0: 7}); } catch (error) { if (error.name === 'TypeError') { rejected++; } }
        class Early extends Base { constructor() { this.value = 1; super(...[]); } }
        try { new Early(); } catch (error) { if (error.name === 'ReferenceError') { rejected++; } }
        class Twice extends Base { constructor() { super(...[]); super(...[]); } }
        try { new Twice(); } catch (error) { rejected++; }
        console.log(rejected);
        "#;
    // An omitted base constructor must still evaluate its super-call
    // arguments. Keep this case even where a reference runtime optimizes the
    // empty superclass and accidentally skips noniterable validation.
    assert_output(source, &["5"]);
    assert_output(
        &source.replace("class Base {}", "class Base { constructor() {} }"),
        &["5"],
    );
}

#[test]
fn fixed_and_rest_arguments_preserve_their_provenance() {
    for return_value in ["child.first", "child.rest[0]", "child.rest.length"] {
        let source = format!(
            "const privateValue = 987654; \
             class Base {{ constructor(first, ...rest) {{ this.first = first; this.rest = rest; }} }} \
             class Child extends Base {{ constructor(value) {{ super(...[value, value]); }} }} \
             const child = new Child(privateValue); {return_value};"
        );
        let mut module = lower(&source);
        let mut replacements = 0;
        for instruction in &mut module.instructions {
            if let Ir3Instruction::LoadInt { dst, value: 987654 } = *instruction {
                *instruction = Ir3Instruction::Move { dst, src: 255 };
                replacements += 1;
            }
        }
        assert_eq!(replacements, 1);
        for config in configs() {
            let mut core = InterpreterCore::new(config, "super-spread-labels");
            core.write_register(255, Value::Int(42));
            let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
            wire["register_labels"][255] = serde_json::to_value(Label::Secret).unwrap();
            core.reset_execution_state_from_seed(
                &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
            )
            .unwrap();
            let result = core.execute(&module).unwrap();
            assert_eq!(result.completion_label, Label::Secret, "{return_value}");
            assert_eq!(
                result.value,
                Value::Int(if return_value.ends_with("length") {
                    1
                } else {
                    42
                })
            );
        }
    }
}

#[test]
fn empty_spreads_keep_shape_position_and_final_done_provenance() {
    for (source, empty_array_input, expected) in [
        (
            "const input = 987654; \
             class Base { constructor(...rest) { this.count = rest.length; } } \
             class Child extends Base { constructor() { super(...input); } } \
             new Child().count;",
            true,
            Value::Int(0),
        ),
        (
            "const input = 987654; \
             class Base { constructor(first) { this.first = first; } } \
             class Child extends Base { constructor() { super(...input, 42); } } \
             new Child().first;",
            true,
            Value::Int(42),
        ),
        (
            "const input = 987654; \
             class Base { constructor(first) { this.first = first; } } \
             class Child extends Base { constructor() { super(...input); } } \
             new Child().first;",
            true,
            Value::Undefined,
        ),
        (
            "const input = 987654; \
             class Base { constructor(first = 42) { this.first = first; } } \
             class Child extends Base { constructor() { super(...input); } } \
             new Child().first;",
            true,
            Value::Int(42),
        ),
        (
            "const input = 987654; const sink = {}; \
             class Base { constructor() { sink.value = 17; } } \
             class Child extends Base { constructor() { super(...input); } } \
             new Child(); sink.value;",
            true,
            Value::Int(17),
        ),
        (
            "const input = 987654; \
             const iterable = { [Symbol.iterator]() { return { next() { return { done: input }; } }; } }; \
             class Base { constructor(...rest) { this.count = rest.length; } } \
             class Child extends Base { constructor() { super(...iterable); } } \
             new Child().count;",
            false,
            Value::Int(0),
        ),
    ] {
        let mut module = lower(source);
        let mut replacements = 0;
        for instruction in &mut module.instructions {
            if let Ir3Instruction::LoadInt { dst, value: 987654 } = *instruction {
                *instruction = Ir3Instruction::Move { dst, src: 255 };
                replacements += 1;
            }
        }
        assert_eq!(replacements, 1);
        for config in configs() {
            for label in [
                Label::Secret,
                Label::Custom {
                    name: "private-iterator-shape".repeat(16),
                    level: 4,
                },
            ] {
                let mut core = InterpreterCore::new(config.clone(), "empty-super-spread-labels");
                let value = if empty_array_input {
                    Value::Object(core.alloc_array_with_prototype(None).unwrap())
                } else {
                    Value::Bool(true)
                };
                core.write_register(255, value);
                let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
                wire["register_labels"][255] = serde_json::to_value(&label).unwrap();
                core.reset_execution_state_from_seed(
                    &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
                )
                .unwrap();
                let result = core.execute(&module).unwrap();
                assert_eq!(result.value, expected);
                assert_eq!(result.completion_label, label, "{source}");
            }
        }
    }
}

#[test]
fn constructor_language_operation_does_not_relax_external_sink_clearance() {
    for (capability, clearance, declassification_required) in [
        ("builtin:ConstructSuperSpread", Label::Secret, false),
        ("net.send", Label::Public, true),
        ("fs.write", Label::Internal, true),
    ] {
        let mut module = Ir1Module::new(ContentHash::compute(b"super-flow"), "super-flow");
        module.ops = vec![
            Ir1Op::LoadLiteral {
                value: Ir1Literal::String("secret_value".into()),
            },
            Ir1Op::HostCall {
                capability: capability.into(),
                arg_count: 1,
            },
            Ir1Op::Return,
        ];
        let ir2 = lower_ir1_to_ir2(&module).unwrap().module;
        let flow = ir2.ops[1].flow.as_ref().unwrap();
        assert_eq!(flow.data_label, Label::Secret);
        assert_eq!(flow.sink_clearance, clearance, "{capability}");
        assert_eq!(
            flow.declassification_required, declassification_required,
            "{capability}"
        );
        let ir3 = lower_ir2_to_ir3(&ir2).unwrap().module;
        assert_eq!(
            ir3.instructions.iter().any(|instruction| {
                matches!(instruction, Ir3Instruction::HostCall { capability, .. } if capability.0 == "ifc.check_flow")
            }),
            declassification_required,
            "only external sinks must retain their confidentiality guard: {capability}"
        );
    }
}

#[test]
fn infinite_spread_consumes_the_normal_instruction_budget() {
    let module = lower(
        r#"
        class Base {}
        const endless = { [Symbol.iterator]() { return { next() { return {value: 1, done: false}; } }; } };
        class Child extends Base { constructor() { super(...endless); } }
        try { new Child(); } catch (error) { console.log('must not swallow the budget'); }
        "#,
    );
    for mut config in configs() {
        config.instruction_budget = 2000;
        let error = InterpreterCore::new(config, "super-spread-budget")
            .execute(&module)
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::BudgetExhausted { .. }),
            "{error:?}"
        );
    }
}

#[test]
fn growing_spread_arrays_cannot_escape_the_memory_budget_through_guest_catch() {
    let module = lower(
        r#"
        const step = {value: 0, done: false};
        const iterable = {
            [Symbol.iterator]() {
                return { next() { step.value++; step.done = step.value > 10000; return step; } };
            }
        };
        class Base { constructor(...values) { this.values = values; } }
        class Child extends Base { constructor() { super(...iterable); } }
        try { new Child(); } catch (error) { console.log('must not swallow the memory limit'); }
        "#,
    );
    for mut config in configs() {
        config.max_total_memory_bytes = 262_144;
        config.instruction_budget = 1_000_000;
        let mut core = InterpreterCore::new(config, "super-spread-memory");
        let error = core.execute(&module).unwrap_err();
        assert!(
            matches!(error, InterpreterError::MemoryBudgetExceeded { .. }),
            "{error:?}"
        );
        assert!(
            core.get_heap().iter().any(|object| {
                object.is_array
                    && matches!(object.properties.get("length"), Some(Value::Int(length)) if *length > 0)
            }),
            "the budget must stop an argument expansion that has begun"
        );
    }
}

#[test]
fn the_internal_capability_gate_still_rejects_unknown_tags() {
    let mut module = lower(
        "class Base {} class Child extends Base { constructor() { super(...[]); } } new Child();",
    );
    for instruction in &mut module.instructions {
        if let Ir3Instruction::HostCall { capability, .. } = instruction
            && capability.0 == "builtin:ConstructSuperSpread"
        {
            capability.0.push_str("Unchecked");
        }
    }
    for config in configs() {
        let error = InterpreterCore::new(config, "super-spread-capability")
            .execute(&module)
            .unwrap_err();
        assert!(
            matches!(error, InterpreterError::CapabilityDenied { .. }),
            "{error:?}"
        );
    }
}
