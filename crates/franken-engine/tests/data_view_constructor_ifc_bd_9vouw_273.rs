#![forbid(unsafe_code)]

//! DataView construction retains labels learned from coercion and prototype
//! callbacks. Seed only a property written after the public argument objects
//! and their callbacks exist, so constructor operand labels cannot supply the
//! missing callback observation on their own.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    ExecutionResult, InterpreterConfig, InterpreterCore, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

const PAYLOAD: &str = "__data_view_callback_payload__";
const PAYLOAD_REGISTER: u32 = 255;

fn lower_with_runtime_payload(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "data-view-constructor-ifc.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("DataView callback-label source parses");
    let mut module = lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "data-view-constructor-ifc.js"),
        &LoweringContext::new("data-view-trace", "data-view-decision", "data-view-policy"),
    )
    .expect("public-looking source lowers before runtime-only label injection")
    .ir3;
    if let Some(main) = module.function_table.first_mut() {
        main.frame_size = main.frame_size.max(PAYLOAD_REGISTER + 1);
    }
    let mut patched = 0;
    for instruction in &mut module.instructions {
        if let Ir3Instruction::LoadStr { dst, pool_index } = *instruction
            && module.constant_pool[pool_index as usize].as_str() == Some(PAYLOAD)
        {
            *instruction = Ir3Instruction::Move {
                dst,
                src: PAYLOAD_REGISTER,
            };
            patched += 1;
        }
    }
    assert_eq!(patched, 1, "label exactly the later property assignment");
    module
}

fn execute(
    source: &str,
    input: i64,
    label: Label,
    mut config: InterpreterConfig,
    gc_interval: Option<u64>,
) -> ExecutionResult {
    let module = lower_with_runtime_payload(source);
    config.granted_capabilities = [
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
        RuntimeCapability::Builtin,
    ]
    .into_iter()
    .collect();
    let mut core = InterpreterCore::new(config, "data-view-constructor-ifc");
    core.set_gc_stress_interval(gc_interval);
    core.seed_register(PAYLOAD_REGISTER, Value::Int(input))
        .expect("seed callback payload");
    core.set_register_label(PAYLOAD_REGISTER, label)
        .expect("label callback payload");
    let result = core.execute(&module).expect("DataView program completes");
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes(),
        "callback observation scopes release their temporary accounting"
    );
    result
}

fn callback_source(assignment: &str, construction: &str) -> String {
    format!(
        r#"
        const offsetState = {{ value: 2 }};
        const lengthState = {{ value: 3 }};
        const offset = {{ valueOf: function () {{ return offsetState.value; }} }};
        const length = {{ valueOf: function () {{ return lengthState.value; }} }};
        const buffer = new ArrayBuffer(8);
        const Constructor = DataView;
        const target = Object.defineProperty(function () {{}}.bind(), 'prototype', {{
            get: function () {{ return DataView.prototype; }}
        }});
        class Derived extends DataView {{}}
        {assignment}
        {construction}
        "#
    )
}

#[test]
fn data_view_constructors_retain_each_argument_conversion_result_label() {
    for construction in [
        "new Constructor(buffer, offset, length);",
        "Reflect.construct(DataView, [buffer, offset, length], target);",
        "new Derived(buffer, offset, length);",
    ] {
        for (state, input) in [("offsetState", 2), ("lengthState", 3)] {
            let source = callback_source(&format!("{state}.value = '{PAYLOAD}';"), construction);
            for config in [
                InterpreterConfig::quickjs_defaults(),
                InterpreterConfig::v8_defaults(),
            ] {
                for interval in [None, Some(1), Some(7)] {
                    for label in [Label::Public, Label::Secret] {
                        let result =
                            execute(&source, input, label.clone(), config.clone(), interval);
                        assert!(matches!(result.value, Value::Object(_)));
                        assert_eq!(
                            result.completion_label, label,
                            "{construction} must retain {state}'s conversion under GC {interval:?}"
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn data_view_explicit_new_target_retains_prototype_getter_result_label() {
    let source = format!(
        r#"
        const state = {{ value: 0 }};
        const first = Object.create(DataView.prototype);
        const second = Object.create(DataView.prototype);
        const target = Object.defineProperty(function () {{}}.bind(), 'prototype', {{
            get: function () {{
                if (state.value === 2) return first;
                return second;
            }}
        }});
        state.value = '{PAYLOAD}';
        Reflect.construct(DataView, [new ArrayBuffer(8), 2, 3], target);
        "#
    );
    for config in [
        InterpreterConfig::quickjs_defaults(),
        InterpreterConfig::v8_defaults(),
    ] {
        for interval in [None, Some(1), Some(7)] {
            for label in [Label::Public, Label::Secret] {
                let result = execute(&source, 2, label.clone(), config.clone(), interval);
                assert!(matches!(result.value, Value::Object(_)));
                assert_eq!(result.completion_label, label);
            }
        }
    }
}

#[test]
fn data_view_conversion_failure_keeps_its_label_and_releases_the_scope() {
    for construction in [
        "new Constructor(buffer, offset, length)",
        "Reflect.construct(DataView, [buffer, offset, length], target)",
        "new Derived(buffer, offset, length)",
    ] {
        for config in [
            InterpreterConfig::quickjs_defaults(),
            InterpreterConfig::v8_defaults(),
        ] {
            for label in [Label::Public, Label::Secret] {
                let failing = callback_source(
                    &format!("offsetState.value = '{PAYLOAD}';"),
                    &format!(
                        "let name = 'no error'; try {{ {construction}; }} \
                         catch (error) {{ name = error.name; }} name;"
                    ),
                );
                let result = execute(&failing, -1, label.clone(), config.clone(), Some(1));
                assert_eq!(result.value, Value::str("RangeError"));
                assert_eq!(result.completion_label, label, "{construction}");

                let recovering = callback_source(
                    &format!("offsetState.value = '{PAYLOAD}';"),
                    &format!(
                        "try {{ {construction}; }} catch (error) {{}} \
                         new Constructor(new ArrayBuffer(8), 0, 1);"
                    ),
                );
                let result = execute(&recovering, -1, label, config.clone(), Some(1));
                assert!(matches!(result.value, Value::Object(_)));
                assert_eq!(
                    result.completion_label,
                    Label::Public,
                    "a failed {construction} must not taint the next public construction"
                );
            }
        }
    }
}
