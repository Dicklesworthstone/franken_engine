#![forbid(unsafe_code)]

//! bd-9vouw.503: reading an outer binding does not by itself require a
//! second named copy of every parameter. Simple callback parameters already
//! occupy registers; captures retain their exact scope cells. Bodies with
//! observable environments keep the original parameter setup.

use frankenengine_engine::ast::ParseGoal;
use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ifc_artifacts::Label;
use frankenengine_engine::ir_contract::{Ir0Module, Ir3Instruction, Ir3Module};
use frankenengine_engine::lowering_pipeline::{
    lower_ir0_to_ir1, lower_ir1_to_ir2, lower_ir2_to_ir3,
};
use frankenengine_engine::parser::{CanonicalEs2020Parser, Es2020Parser};
use frankenengine_engine::{JsEngine, QuickJsInspiredNativeEngine, V8InspiredNativeEngine};

fn lower(source: &str) -> Ir3Module {
    let tree = CanonicalEs2020Parser
        .parse(source, ParseGoal::Script)
        .expect("source parses");
    let ir0 = Ir0Module::from_syntax_tree(tree, "uncaptured_parameter_registers.js");
    let ir1 = lower_ir0_to_ir1(&ir0).expect("IR0->IR1").module;
    let ir2 = lower_ir1_to_ir2(&ir1).expect("IR1->IR2").module;
    lower_ir2_to_ir3(&ir2).expect("IR2->IR3").module
}

fn function_instructions<'a>(module: &'a Ir3Module, name: &str) -> &'a [Ir3Instruction] {
    let index = module
        .function_table
        .iter()
        .position(|function| function.name.as_deref() == Some(name))
        .unwrap_or_else(|| panic!("missing function {name}"));
    let start = module.function_table[index].entry as usize;
    let end = module
        .function_table
        .get(index + 1)
        .map_or(module.instructions.len(), |function| {
            function.entry as usize
        });
    &module.instructions[start..end]
}

#[test]
fn captured_outer_reads_do_not_mirror_uncaptured_parameters() {
    let module = lower(
        "let total = 0; function add(value, index) { value += index; total += value; \
         return total; } add(2, 3);",
    );
    let instructions = function_instructions(&module, "add");
    assert!(
        !instructions.iter().any(|instruction| matches!(
            instruction,
            Ir3Instruction::PushScope
                | Ir3Instruction::DeclareBinding { .. }
                | Ir3Instruction::InitBinding { .. }
        )),
        "the two parameters must avoid all five legacy setup instructions: {instructions:?}"
    );
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::LoadScoped { .. })),
        "the outer capture must still be read through its scope cell"
    );
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::StoreScoped { .. })),
        "the outer capture must still be written through its scope cell"
    );

    // The dominant JSON-transformation join has this exact callback shape:
    // read a property of its own parameter and of an outer order object.
    let module = lower(
        "const order = { user_id: 2 }; function matches(user) { return user.id === \
         order.user_id; } [{ id: 1 }, { id: 2 }].find(matches);",
    );
    let instructions = function_instructions(&module, "matches");
    assert!(
        !instructions.iter().any(|instruction| matches!(
            instruction,
            Ir3Instruction::PushScope
                | Ir3Instruction::DeclareBinding { .. }
                | Ir3Instruction::InitBinding { .. }
        )),
        "the join predicate must avoid its three legacy setup instructions: {instructions:?}"
    );
    assert!(
        instructions
            .iter()
            .any(|instruction| matches!(instruction, Ir3Instruction::LoadScoped { .. })),
        "the order object remains a captured binding"
    );
}

#[test]
fn observable_parameter_environments_keep_the_named_mirror() {
    for source in [
        "let outer = 1; function f(value) { return () => value + outer; } f(2);",
        "let outer = 1; function f(value) { return arguments[0] + outer; } f(2);",
        "let outer = 1; function f(value = 2) { return value + outer; } f();",
        "let outer = 1; function f(value, ...tail) { return value + tail.length + outer; } \
         f(2, 3);",
        "let outer = 1; function f(value, value) { return value + outer; } f(2, 3);",
        "let outer = 1; function f(value) { missing = value; return outer; } f(2);",
        "let outer = 1; function f(value) { with ({ value: 3 }) { value += 4; } \
         return value + outer; } f(2);",
    ] {
        let module = lower(source);
        let instructions = function_instructions(&module, "f");
        assert!(
            instructions
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::PushScope)),
            "the conservative path must keep its environment: {source}"
        );
        assert!(
            instructions
                .iter()
                .any(|instruction| matches!(instruction, Ir3Instruction::DeclareBinding { .. })),
            "the conservative path must keep named parameter bindings: {source}"
        );
    }
}

#[test]
fn register_parameters_preserve_callback_and_scope_semantics() {
    // Expected values were evaluated with live Node/V8 for these exact
    // programs. Both native interpreter profiles must agree with them.
    let cases = [
        (
            "let total = 0; const add = (value, index) => { value += index; total += value; \
             return value; }; const mapped = [2, 4, 6].map(add); \
             [mapped.join(','), total].join(':');",
            "2,5,8:15",
        ),
        (
            "let outer = 10; function mutate(value) { var value; value += outer; return \
             value; } function shadow(outer) { outer *= 2; return outer; } let value = 2; \
             [mutate(value), shadow(3), value, outer].join(',');",
            "12,6,2,10",
        ),
        (
            "let outer = 1; function make(value) { const next = () => { value += outer; \
             return value; }; value += 2; return next; } const a = make(3), b = make(10); \
             [a(), b(), a()].join(',');",
            "6,13,7",
        ),
        (
            "let outer = 10; function defaults(a = outer, b = a + 1) { return a + b + \
             outer; } function rest(a, ...tail) { return a + tail.length + outer; } \
             function duplicate(a, a) { return a + outer; } \
             [defaults(), rest(1, 2, 3), duplicate(2, 3)].join(',');",
            "31,13,13",
        ),
        (
            "let outer = 10; function f(value) { 'use strict'; const saved = arguments; \
             value += outer; saved[0] = 3; return [value, saved === arguments, \
             arguments[0]].join(','); } f(2);",
            "12,true,3",
        ),
        (
            "let outer = 5; function f(value) { return helper(); function helper() { \
             return value + outer; } } f(2);",
            "7",
        ),
        (
            "var outer = 10; function f(value) { with ({ value: 3 }) { value += 4; } \
             return value + outer; } f(2);",
            "12",
        ),
        (
            "let outer = 1; const fail = value => { outer += value; throw value + outer; \
             }; let seen = ''; try { [2, 3].map(fail); } catch (error) { seen = error + \
             ':' + outer; } const add = value => value + outer; seen + ':' + add(4);",
            "5:3:7",
        ),
        (
            "let outer = 1; function finish(value) { try { return value + outer; } \
             finally { outer += value; } } [finish(2), outer, finish(3), outer].join(',');",
            "3,3,6,6",
        ),
        (
            "let outer = 1; function sum(value) { return value === 0 ? outer : value + \
             sum(value - 1); } sum(10);",
            "56",
        ),
        (
            "let outer = 10; function f(value) { try { throw value + 1; } catch (value) { \
             return value + outer; } } f(2);",
            "13",
        ),
        (
            "let outer = 1; function vars(value) { for (var value = 2; value < 5; value++) \
             outer += value; return value + outer; } function lets(value) { for (let \
             value = 0; value < 3; value++) outer += value; return value + outer; } \
             [vars(20), lets(20), outer].join(',');",
            "15,33,13",
        ),
        (
            "let outer = 1; const read = value => value + outer; function f(value, run) { \
             value += 2; return run(value) + outer; } f(3, read);",
            "7",
        ),
        (
            "let outer = 1; const inspect = new Function('return typeof value;'); const \
             object = { get probe() { return inspect(); } }; function f(value) { return \
             inspect() + ':' + object.probe + ':' + value + ':' + outer; } f('local');",
            "undefined:undefined:local:1",
        ),
        (
            "const users = [{ id: 1, name: 'Ada' }, { id: 2, name: 'Grace' }]; const \
             orders = [{ user_id: 2 }, { user_id: 1 }, { user_id: 2 }]; orders.map(order \
             => users.find(user => user.id === order.user_id).name).join(',');",
            "Grace,Ada,Grace",
        ),
    ];
    for (source, expected) in cases {
        let mut engines: [Box<dyn JsEngine>; 2] = [
            Box::new(QuickJsInspiredNativeEngine),
            Box::new(V8InspiredNativeEngine),
        ];
        for engine in &mut engines {
            let kind = engine.kind();
            let result = engine
                .eval(source)
                .unwrap_or_else(|error| panic!("{kind:?}: {error}; source: {source}"));
            assert_eq!(result.value, expected, "{kind:?}; source: {source}");
        }
    }
}

#[test]
fn register_parameters_keep_return_throw_and_array_labels() {
    const INPUT: i64 = 442_211;
    for source in [
        "let outer = 1; function f(value) { return value + outer; } f(442211);",
        "let outer = 1; const fail = value => { throw value + outer; }; let result; \
         try { fail(442211); } catch (error) { result = error; } result;",
        "let outer = 1; [442211].map(value => value + outer)[0];",
    ] {
        let mut module = lower(source);
        let mut config = InterpreterConfig::quickjs_defaults();
        config.instruction_budget = 1_000_000;
        config.granted_capabilities = [
            RuntimeCapability::VmDispatch,
            RuntimeCapability::HeapAllocate,
            RuntimeCapability::Builtin,
        ]
        .into_iter()
        .collect();
        // Feed a genuinely labelled runtime input into the source-lowered
        // program. A literal cannot express an IFC label. Reserve a main-frame
        // slot outside the compiler's live range and replace only its unique
        // marker load with a Move from the seeded input.
        let input_register = config.max_registers - 1;
        assert!(module.function_table[0].frame_size <= input_register);
        let marker = module
            .instructions
            .iter_mut()
            .find(|instruction| matches!(instruction, Ir3Instruction::LoadInt { value, .. } if *value == INPUT))
            .expect("unique source marker");
        let Ir3Instruction::LoadInt { dst, .. } = *marker else {
            unreachable!()
        };
        *marker = Ir3Instruction::Move {
            dst,
            src: input_register,
        };
        module.function_table[0].frame_size = config.max_registers;
        for label in [
            Label::Secret,
            Label::Custom {
                name: "parameter-provenance".repeat(16),
                level: 4,
            },
        ] {
            let mut core = InterpreterCore::new(config.clone(), "labelled-register-parameter");
            core.seed_register(input_register, Value::Int(INPUT))
                .expect("seed value");
            core.set_register_label(input_register, label.clone())
                .expect("seed label");
            let result = core
                .execute(&module)
                .unwrap_or_else(|error| panic!("{source}: {error}"));
            assert_eq!(result.value, Value::Int(INPUT + 1), "{source}");
            assert_eq!(result.completion_label, label, "{source}");
            assert_eq!(
                core.estimated_memory_bytes(),
                core.recompute_estimated_memory_bytes(),
                "incremental memory accounting must remain exact: {source}"
            );
        }
    }
}

#[test]
fn direct_and_nested_eval_keep_the_existing_authority_refusal() {
    // This engine deliberately rejects direct eval at lowering. Removing an
    // unobservable mirror must not make a direct or nested eval eligible.
    for source in [
        "let outer = 1; function f(value) { return eval('value + outer'); } f(2);",
        "let outer = 1; function f(value) { return (() => eval('value + outer'))(); } f(2);",
    ] {
        let mut engines: [Box<dyn JsEngine>; 2] = [
            Box::new(QuickJsInspiredNativeEngine),
            Box::new(V8InspiredNativeEngine),
        ];
        for engine in &mut engines {
            let kind = engine.kind();
            let error = engine.eval(source).expect_err("direct eval stays denied");
            assert!(
                error.to_string().contains("runtime.eval"),
                "{kind:?}: unexpected refusal for {source}: {error}"
            );
        }
    }
}

#[test]
fn indirect_eval_stays_inert_in_direct_and_nested_callbacks() {
    for source in [
        "const indirect = eval; let outer = 1; function f(value) { return \
         indirect('value + outer'); } try { f(2); } catch (error) { error.name; }",
        "const indirect = eval; let outer = 1; function f(value) { return () => \
         indirect('value + outer'); } try { f(2)(); } catch (error) { error.name; }",
    ] {
        let mut engines: [Box<dyn JsEngine>; 2] = [
            Box::new(QuickJsInspiredNativeEngine),
            Box::new(V8InspiredNativeEngine),
        ];
        for engine in &mut engines {
            let kind = engine.kind();
            let result = engine
                .eval(source)
                .unwrap_or_else(|error| panic!("{kind:?}: {error}; source: {source}"));
            assert_eq!(result.value, "EvalError", "{kind:?}; source: {source}");
        }
    }
}
