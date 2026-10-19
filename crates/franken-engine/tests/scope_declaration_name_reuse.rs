#![forbid(unsafe_code)]

//! Scope declarations borrow executable names until a frame needs an owned
//! key. Exercise the shared-cell, label, TDZ, and fallback-name behavior at
//! the public interpreter boundary as well as through parsed JavaScript.

use frankenengine_engine::HybridRouter;
use frankenengine_engine::baseline_interpreter::{
    InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{
    Ir3FunctionDesc, Ir3Instruction as Op, Ir3Module, IrHeader, IrLevel, IrSchemaVersion, RegRange,
};
use frankenengine_engine::js_string::JsString;

fn core() -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities.extend([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    InterpreterCore::new(config, "scope-declaration-name-reuse")
}

fn module(instructions: Vec<Op>, constant_pool: Vec<JsString>) -> Ir3Module {
    Ir3Module {
        header: IrHeader {
            schema_version: IrSchemaVersion::CURRENT,
            level: IrLevel::Ir3,
            source_hash: None,
            source_label: "scope-declaration-name-reuse.js".to_owned(),
        },
        instructions,
        constant_pool,
        function_table: Vec::new(),
        specialization: None,
        required_capabilities: Vec::new(),
        function_lengths: Default::default(),
        function_sources: Default::default(),
        sloppy_functions: Default::default(),
    }
}

#[test]
fn repeated_var_keeps_the_captured_cell_and_its_label() {
    let mut module = module(
        vec![
            Op::DeclareBinding {
                name_pool_index: 0,
                kind: 0,
            },
            Op::LoadInt { dst: 0, value: 7 },
            Op::InitBinding {
                name_pool_index: 0,
                src: 0,
            },
            Op::CreateClosure {
                dst: 1,
                function_index: 0,
                capture_count: 0,
            },
            Op::DeclareBinding {
                name_pool_index: 0,
                kind: 0,
            },
            Op::LoadInt { dst: 0, value: 9 },
            Op::StoreScoped {
                name_pool_index: 0,
                src: 0,
            },
            Op::Call {
                callee: 1,
                args: RegRange { start: 3, count: 0 },
                dst: 2,
            },
            Op::Return { value: 2 },
            Op::LoadScoped {
                dst: 0,
                name_pool_index: 0,
            },
            Op::Return { value: 0 },
        ],
        vec![JsString::from("π_長い名前")],
    );
    module.function_table.push(Ir3FunctionDesc {
        entry: 9,
        arity: 0,
        frame_size: 1,
        name: Some("readCaptured".to_owned()),
        is_generator: false,
        rest_param_index: None,
    });
    let mut core = core();
    core.set_register_label(0, Label::Secret)
        .expect("seed label");
    let result = core.execute(&module).expect("captured var remains live");
    assert_eq!(result.value, Value::Int(9));
    assert_eq!(result.completion_label, Label::Secret);
    assert_eq!(
        core.estimated_memory_bytes(),
        core.recompute_estimated_memory_bytes()
    );
}

#[test]
fn declaration_names_keep_unicode_and_missing_pool_fallbacks() {
    for (pool, index) in [
        (vec![JsString::from("名𐐀")], 0),
        (vec![JsString::from_code_units(&[0xd800])], 0),
        (Vec::new(), 37),
    ] {
        let module = module(
            vec![
                Op::DeclareBinding {
                    name_pool_index: index,
                    kind: 1,
                },
                Op::LoadInt { dst: 0, value: 42 },
                Op::InitBinding {
                    name_pool_index: index,
                    src: 0,
                },
                Op::LoadScoped {
                    dst: 1,
                    name_pool_index: index,
                },
                Op::Return { value: 1 },
            ],
            pool,
        );
        assert_eq!(
            core()
                .execute(&module)
                .expect("matching name projection")
                .value,
            Value::Int(42)
        );
    }
}

#[test]
fn lexical_redeclaration_still_replaces_the_cell_with_a_tdz_cell() {
    let module = module(
        vec![
            Op::DeclareBinding {
                name_pool_index: 0,
                kind: 0,
            },
            Op::LoadInt { dst: 0, value: 7 },
            Op::InitBinding {
                name_pool_index: 0,
                src: 0,
            },
            Op::DeclareBinding {
                name_pool_index: 0,
                kind: 1,
            },
            Op::LoadScoped {
                dst: 1,
                name_pool_index: 0,
            },
            Op::Return { value: 1 },
        ],
        vec![JsString::from("shadow")],
    );
    assert!(matches!(
        core().execute(&module),
        Err(InterpreterError::UninitializedBinding { name }) if name == "shadow"
    ));
}

#[test]
fn invalid_binding_kind_remains_a_typed_error() {
    let module = module(
        vec![Op::DeclareBinding {
            name_pool_index: 0,
            kind: 255,
        }],
        vec![JsString::from("invalid")],
    );
    assert!(matches!(
        core().execute(&module),
        Err(InterpreterError::TypeError { expected, got })
            if expected == "binding kind 0..=5" && got == "kind 255"
    ));
}

#[test]
fn scope_heavy_closures_keep_shadowing_redeclarations_and_iteration_cells() {
    let result = HybridRouter::default()
        .eval(
            r#"
        const read = [];
        function outer(seed) {
            let total = seed;
            function add(value) {
                var local = value;
                var local;
                const observe = () => local;
                { let local = value + 100; total += local; }
                local += 1;
                total += observe();
                return total;
            }
            for (let i = 0; i < 5; i++) {
                read.push(() => i);
                add(i);
            }
            return total;
        }
        console.log(outer(3), read.map(f => f()).join(','));
    "#,
        )
        .expect("scope-heavy program");
    let output: Vec<_> = result
        .console_output
        .iter()
        .map(|line| line.message.as_str())
        .collect();
    assert_eq!(output, ["528 0,1,2,3,4"]);
}
