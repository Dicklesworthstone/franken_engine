//! Native reflection failures must retain observations after callback scopes unwind.

#![forbid(unsafe_code)]

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir0Module, Ir3FunctionDesc, Ir3Instruction, Ir3Module, RegRange,
};
use frankenengine_engine::lowering_pipeline::{LoweringContext, lower_ir0_to_ir3};
use frankenengine_engine::parser::{CanonicalEs2020Parser, ParserOptions, ParserSource};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse_with_options(
            ParserSource {
                label: "reflect-failure-confidentiality.js".into(),
                text: source.into(),
            },
            ParseGoal::Script,
            &ParserOptions::default(),
        )
        .expect("regression source must parse");
    lower_ir0_to_ir3(
        &Ir0Module::from_syntax_tree(tree, "reflect-failure-confidentiality.js"),
        &LoweringContext::new("reflect-trace", "reflect-decision", "reflect-policy"),
    )
    .expect("regression source must lower")
    .ir3
}

fn configs() -> impl Iterator<Item = InterpreterConfig> {
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
        config
    })
}

fn call(capability: &str, start: u32, count: u32, dst: u32) -> Ir3Instruction {
    Ir3Instruction::HostCall {
        capability: CapabilityTag(capability.into()),
        args: RegRange { start, count },
        dst,
    }
}

fn return_or_leak(module: &mut Ir3Module, caught: u32, leak: bool) {
    if leak {
        module
            .instructions
            .push(call("builtin:ConsoleLog", caught, 1, caught + 1));
    }
    module
        .instructions
        .push(Ir3Instruction::Return { value: caught });
}

fn length_failure(
    config: InterpreterConfig,
    label: Label,
    construct: bool,
    leak: bool,
) -> (InterpreterCore, Ir3Module, u32) {
    let mut core = InterpreterCore::new(config, "reflect-length-failure");
    let list = core.alloc_object_with_prototype(None).unwrap();
    for (register, value) in [
        (0, Value::Function(0)),
        (
            1,
            if construct {
                Value::Object(list)
            } else {
                Value::Undefined
            },
        ),
        (2, Value::Object(list)),
        (5, Value::str("length")),
        (6, Value::BigInt("1".into())),
        (7, Value::Object(list)),
    ] {
        core.seed_register(register, value).unwrap();
    }
    core.set_register_label(6, label).unwrap();
    let mut module = lower("0;");
    module.instructions = vec![
        Ir3Instruction::SetProperty {
            obj: 7,
            key: 5,
            val: 6,
        },
        Ir3Instruction::BeginTry {
            catch_target: 6,
            finally_target: None,
        },
        call(
            if construct {
                "builtin:ReflectConstruct"
            } else {
                "builtin:ReflectApply"
            },
            0,
            if construct { 2 } else { 3 },
            4,
        ),
        Ir3Instruction::EndTry,
        Ir3Instruction::LoadUndefined { dst: 8 },
        Ir3Instruction::Jump { target: 7 },
        Ir3Instruction::EnterCatch { dst: 8 },
    ];
    return_or_leak(&mut module, 8, leak);
    let entry = module.instructions.len() as u32;
    module.instructions.extend([
        Ir3Instruction::LoadInt { dst: 0, value: 333 },
        Ir3Instruction::Return { value: 0 },
    ]);
    module.function_table = vec![Ir3FunctionDesc {
        entry,
        arity: 0,
        frame_size: 1,
        name: Some("must_not_run".into()),
        is_generator: false,
        rest_param_index: None,
    }];
    (core, module, if construct { 1 } else { 2 })
}

fn key_list_failure(
    config: InterpreterConfig,
    label: Label,
    leak: bool,
) -> (InterpreterCore, Ir3Module, u32) {
    let mut core = InterpreterCore::new(config, "reflect-key-list-failure");
    let target = core.alloc_object_with_prototype(None).unwrap();
    let handler = core.alloc_object_with_prototype(None).unwrap();
    let list = core.alloc_object_with_prototype(None).unwrap();
    for (register, value) in [
        (0, Value::Object(target)),
        (1, Value::Object(handler)),
        (5, Value::Object(list)),
        (6, Value::Int(42)),
        (7, Value::str("0")),
        (8, Value::str("length")),
        (9, Value::Int(1)),
        (10, Value::str("list")),
        (11, Value::str("ownKeys")),
        (12, Value::Function(0)),
    ] {
        core.seed_register(register, value).unwrap();
    }
    core.set_register_label(6, label).unwrap();
    let mut module = lower("0;");
    // Publish the public aliases before the list acquires secret storage.
    // Neither the handler nor the proxy argument register is itself secret.
    module.instructions = vec![
        Ir3Instruction::SetProperty {
            obj: 0,
            key: 10,
            val: 5,
        },
        Ir3Instruction::SetProperty {
            obj: 1,
            key: 11,
            val: 12,
        },
        Ir3Instruction::SetProperty {
            obj: 5,
            key: 8,
            val: 9,
        },
        Ir3Instruction::SetProperty {
            obj: 5,
            key: 7,
            val: 6,
        },
        call("builtin:Proxy", 0, 2, 2),
        Ir3Instruction::BeginTry {
            catch_target: 10,
            finally_target: None,
        },
        call("builtin:ReflectOwnKeys", 2, 1, 4),
        Ir3Instruction::EndTry,
        Ir3Instruction::LoadUndefined { dst: 16 },
        Ir3Instruction::Jump { target: 11 },
        Ir3Instruction::EnterCatch { dst: 16 },
    ];
    return_or_leak(&mut module, 16, leak);
    let entry = module.instructions.len() as u32;
    let pool_index = module.constant_pool.len() as u32;
    module.constant_pool.push("list".into());
    module.instructions.extend([
        Ir3Instruction::LoadStr { dst: 1, pool_index },
        Ir3Instruction::GetProperty {
            obj: 0,
            key: 1,
            dst: 2,
        },
        Ir3Instruction::Return { value: 2 },
    ]);
    module.function_table = vec![Ir3FunctionDesc {
        entry,
        arity: 1,
        frame_size: 3,
        name: Some("own_keys".into()),
        is_generator: false,
        rest_param_index: None,
    }];
    (core, module, 2)
}

fn assert_confidential_failure(
    mut core: InterpreterCore,
    module: &Ir3Module,
    alias: u32,
    label: &Label,
) {
    let result = core
        .execute(module)
        .expect("the language fault must be caught");
    assert!(
        matches!(result.value, Value::Object(_)),
        "expected the caught Error object"
    );
    assert_eq!(
        &result.completion_label, label,
        "native fault laundered its scoped observations"
    );
    assert_eq!(core.get_register_label(alias).unwrap(), &Label::Public);
    assert!(core.console_output().is_empty());
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

fn assert_sink_denied(mut core: InterpreterCore, module: &Ir3Module) {
    assert!(matches!(
        core.execute(module),
        Err(InterpreterError::CapabilityDenied { capability })
            if capability == "console:log:confidentiality"
    ));
    assert!(
        core.console_output().is_empty(),
        "a caught fault escaped to a public sink"
    );
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn reflected_apply_and_construct_native_faults_keep_secret_length_observations() {
    for label in [Label::Secret, Label::TopSecret] {
        for construct in [false, true] {
            for config in configs() {
                let (core, module, alias) = length_failure(config, label.clone(), construct, false);
                assert_confidential_failure(core, &module, alias, &label);
            }
        }
    }
}

#[test]
fn reflected_length_errors_cannot_be_laundered_through_catch_to_console() {
    for label in [Label::Secret, Label::TopSecret] {
        for construct in [false, true] {
            for config in configs() {
                let (core, module, _) = length_failure(config, label.clone(), construct, true);
                assert_sink_denied(core, &module);
            }
        }
    }
}

#[test]
fn proxy_key_list_type_errors_keep_secret_storage_observations() {
    for label in [Label::Secret, Label::TopSecret] {
        for config in configs() {
            let (core, module, alias) = key_list_failure(config, label.clone(), false);
            assert_confidential_failure(core, &module, alias, &label);
        }
    }
}

#[test]
fn proxy_key_list_errors_cannot_be_laundered_through_catch_to_console() {
    for label in [Label::Secret, Label::TopSecret] {
        for config in configs() {
            let (core, module, _) = key_list_failure(config, label.clone(), true);
            assert_sink_denied(core, &module);
        }
    }
}

#[test]
fn oversized_reflection_lists_still_escape_guest_catch_as_resource_failures() {
    for source in [
        "try { Reflect.apply(function() {}, null, { length: Infinity }); } catch (error) { 7; }",
        "try { Reflect.construct(function() {}, { length: Infinity }); } catch (error) { 7; }",
        "try { Reflect.ownKeys(new Proxy({}, { ownKeys() { return { length: Infinity }; } })); } catch (error) { 7; }",
    ] {
        let module = lower(source);
        for config in configs() {
            let mut core = InterpreterCore::new(config, "reflect-resource-failure");
            assert!(matches!(
                core.execute(&module),
                Err(InterpreterError::RegisterOutOfBounds { .. })
            ));
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes()
            );
        }
    }
}
