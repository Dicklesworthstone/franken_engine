#![forbid(unsafe_code)]

//! Optional method calls retain the captured reference and skip evaluation
//! only when the selected base or callable value is nullish.

use frankenengine_core::ast::ParseGoal;
use frankenengine_core::baseline_interpreter::{
    ExecutionSeed, InterpreterConfig, InterpreterCore, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::ifc_artifacts::Label;
use frankenengine_core::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_core::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_core::parser::{CanonicalEs2020Parser, Es2020Parser};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("optional-call fixture must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "optional-call.js"),
        &LoweringContext::new("optional-call", "optional-call", "optional-call"),
    )
    .expect("optional-call fixture must lower")
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
        let result = InterpreterCore::new(config, "optional-call")
            .execute(&module)
            .expect("optional-call fixture must execute");
        let actual: Vec<_> = result
            .console_output
            .iter()
            .map(|entry| entry.message.as_str())
            .collect();
        assert_eq!(actual, expected);
    }
}

#[test]
fn optional_method_calls_keep_the_original_receiver_after_argument_mutation() {
    assert_output(
        r#"
        const original = {
            base: 40,
            method(value) { return this.base + value; }
        };
        let receiver = original;
        function argument() {
            receiver = {base: 1000};
            return 2;
        }
        console.log(receiver.method?.(argument()), receiver.base);
        console.log(original?.method?.(2));
        "#,
        &["42 1000", "42"],
    );
}

#[test]
fn optional_computed_method_lookup_runs_once_before_arguments() {
    assert_output(
        r#"
        let trace = '';
        const receiver = {
            base: 40,
            get method() {
                trace += 'g';
                return function(value) { trace += 'c'; return this.base + value; };
            }
        };
        function object() { trace += 'o'; return receiver; }
        function key() { trace += 'k'; return 'method'; }
        function argument() { trace += 'a'; return 2; }
        console.log(object()[key()]?.(argument()), trace);
        "#,
        &["42 okgac"],
    );
}

#[test]
fn nullish_optional_bases_and_methods_skip_keys_getters_and_arguments() {
    assert_output(
        r#"
        let calls = 0;
        function key() { calls++; return 'method'; }
        function argument() { calls++; return 2; }
        const absent = null;
        const missing = {method: undefined};
        const nullMethod = {method: null};
        console.log(absent?.[key()]?.(argument()) === undefined);
        console.log(missing.method?.(argument()) === undefined);
        console.log(nullMethod.method?.(argument()) === undefined, calls);
        "#,
        &["true", "true", "true 0"],
    );
}

#[test]
fn non_nullish_noncallables_evaluate_arguments_then_throw() {
    assert_output(
        r#"
        let calls = 0;
        let failures = 0;
        function argument() { calls++; }
        const receiver = {zero: 0, no: false, empty: ''};
        try { receiver.zero?.(argument()); } catch (error) {
            if (error.name === 'TypeError') failures++;
        }
        try { receiver.no?.(argument()); } catch (error) {
            if (error.name === 'TypeError') failures++;
        }
        try { receiver.empty?.(argument()); } catch (error) {
            if (error.name === 'TypeError') failures++;
        }
        console.log(calls, failures);
        "#,
        &["3 3"],
    );
}

#[test]
fn throwing_optional_method_getters_keep_exact_exception_and_skip_arguments() {
    assert_output(
        r#"
        const failure = {};
        let calls = 0;
        const receiver = {get method() { throw failure; }};
        function argument() { calls++; }
        let same = false;
        try { receiver.method?.(argument()); } catch (error) {
            same = error === failure;
        }
        console.log(same, calls);
        "#,
        &["true 0"],
    );
}

#[test]
fn optional_super_method_calls_use_the_derived_receiver() {
    assert_output(
        r#"
        class Base {
            constructor() { this.base = 40; }
            method(value) { return this.base + value; }
        }
        class Derived extends Base {
            read() { return super.method?.(2); }
            computed() { return super['method']?.(2); }
        }
        const value = new Derived();
        console.log(value.read(), value.computed());
        "#,
        &["42 42"],
    );
}

#[test]
fn optional_calls_preserve_bare_and_intrinsic_callable_behavior() {
    assert_output(
        r#"
        function read(value) { return value + 1; }
        const receiver = {method: read};
        console.log(read?.(41), receiver.method?.(41), Array.isArray?.([]));
        "#,
        &["42 42 true"],
    );
}

#[test]
fn optional_generator_and_async_methods_keep_this_across_suspension() {
    assert_output(
        r#"
        const receiver = {
            base: 40,
            generator: function* (value) { yield this.base + value; },
            method: async function(value) {
                const result = await Promise.resolve(value);
                return this.base + result;
            }
        };
        console.log(receiver.generator?.(2).next().value);
        receiver.method?.(2).then(function(value) { console.log(value); });
        "#,
        &["42", "42"],
    );
}

#[test]
fn skipped_optional_calls_preserve_the_selected_guard_label() {
    for expression in [
        "input?.(argument())",
        "({method: input}).method?.(argument())",
        "input?.[key()]?.(argument())",
    ] {
        let source = format!(
            "const input = 987654; \
             function argument() {{ throw 99; }} \
             function key() {{ throw 100; }} \
             {expression};"
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
        for input in [Value::Null, Value::Undefined] {
            for config in configs() {
                let mut core = InterpreterCore::new(config, "optional-call-labels");
                core.write_register(255, input.clone());
                let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
                wire["register_labels"][255] = serde_json::to_value(Label::Secret).unwrap();
                core.reset_execution_state_from_seed(
                    &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
                )
                .unwrap();
                let result = core.execute(&module).unwrap();
                assert_eq!(result.value, Value::Undefined, "{expression}");
                assert_eq!(result.completion_label, Label::Secret, "{expression}");
            }
        }
    }
}

#[test]
fn invoked_optional_methods_preserve_receiver_and_callable_provenance() {
    for source in [
        "const input = 987654; \
         const receivers = [{method() { return 42; }}]; \
         receivers[input].method?.();",
        "const input = 987654; \
         const methods = [function() { return 42; }]; \
         methods[input]?.();",
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
            let mut core = InterpreterCore::new(config, "optional-call-invocation-labels");
            core.write_register(255, Value::Int(0));
            let mut wire = serde_json::to_value(core.capture_execution_seed()).unwrap();
            wire["register_labels"][255] = serde_json::to_value(Label::Secret).unwrap();
            core.reset_execution_state_from_seed(
                &serde_json::from_value::<ExecutionSeed>(wire).unwrap(),
            )
            .unwrap();
            let result = core.execute(&module).unwrap();
            assert_eq!(result.value, Value::Int(42), "{source}");
            assert_eq!(result.completion_label, Label::Secret, "{source}");
        }
    }
}
