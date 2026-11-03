//! Promise static methods through the public IR3 execution boundary.
//! These tests exercise the core hostcall API, including queued reactions and
//! allSettled, independently of the main engine's source-level Promise API.

use std::collections::BTreeSet;

use frankenengine_core::baseline_interpreter::{
    ExecutionSeed, InterpreterConfig, InterpreterCore, InterpreterError, Value,
};
use frankenengine_core::capability::RuntimeCapability;
use frankenengine_core::hash_tiers::ContentHash;
use frankenengine_core::ifc_artifacts::Label;
use frankenengine_core::ir_contract::{CapabilityTag, Ir3Instruction, Ir3Module, RegRange};

fn core() -> InterpreterCore {
    let mut config = InterpreterConfig::quickjs_defaults();
    config.granted_capabilities = BTreeSet::from([
        RuntimeCapability::VmDispatch,
        RuntimeCapability::HeapAllocate,
    ]);
    InterpreterCore::new(config, "promise-static-regression")
}

fn module(instructions: Vec<Ir3Instruction>) -> Ir3Module {
    let mut module = Ir3Module::new(
        ContentHash::compute(b"promise-static-regression"),
        "promise-static-regression",
    );
    module.instructions = instructions;
    module.constant_pool = vec!["reason".into()];
    module
}

fn call(method: &str, start: u32, count: u32, dst: u32) -> Ir3Instruction {
    Ir3Instruction::HostCall {
        capability: CapabilityTag(format!("promise:{method}")),
        args: RegRange { start, count },
        dst,
    }
}

#[test]
fn resolve_preserves_identity_in_every_source_state() {
    for method in ["constructor", "resolve", "reject"] {
        let mut core = core();
        let result = core
            .execute(&module(vec![
                Ir3Instruction::LoadInt { dst: 0, value: 17 },
                call(method, 0, u32::from(method != "constructor"), 1),
                Ir3Instruction::LoadInt { dst: 2, value: 99 },
                call("resolve", 1, 2, 3),
                Ir3Instruction::StrictEq {
                    dst: 0,
                    lhs: 1,
                    rhs: 3,
                },
                Ir3Instruction::Halt,
            ]))
            .unwrap_or_else(|error| panic!("source {method}: {error:?}"));
        assert_eq!(result.value, Value::Bool(true), "source {method}");
    }
}

#[test]
fn static_methods_cannot_settle_a_pending_argument() {
    for method in ["resolve", "reject"] {
        let mut core = core();
        let error = core
            .execute(&module(vec![
                call("constructor", 0, 0, 1),
                Ir3Instruction::LoadInt { dst: 2, value: 99 },
                call(method, 1, 2, 3),
                Ir3Instruction::StrictEq {
                    dst: 0,
                    lhs: 1,
                    rhs: 3,
                },
                // At this public IR boundary a pending await needs an async
                // frame. A fulfilled/rejected argument would take a different
                // path, so this also observes that it remains pending.
                Ir3Instruction::AwaitValue { promise_reg: 1 },
                Ir3Instruction::Halt,
            ]))
            .expect_err("the source must remain pending");
        assert!(
            matches!(error, InterpreterError::TypeError { expected, got }
                if expected == "await only in async function"
                    && got == "await outside async function context"),
            "{method} must not acquire settlement authority"
        );
        assert_eq!(core.get_registers()[0], Value::Bool(method == "resolve"));
    }
}

fn inspect_rejection_reason() -> Ir3Module {
    module(vec![
        Ir3Instruction::NewArray { dst: 4 },
        Ir3Instruction::ArrayPush {
            array: 4,
            element: 0,
        },
        call("allSettled", 4, 1, 5),
        Ir3Instruction::AwaitValue { promise_reg: 5 },
        Ir3Instruction::LoadInt { dst: 6, value: 0 },
        Ir3Instruction::GetProperty {
            obj: 5,
            key: 6,
            dst: 7,
        },
        Ir3Instruction::LoadStr {
            dst: 8,
            pool_index: 0,
        },
        Ir3Instruction::GetProperty {
            obj: 7,
            key: 8,
            dst: 0,
        },
        Ir3Instruction::Halt,
    ])
}

#[test]
fn rejection_retains_promise_identity_through_aggregation_and_queued_reactions() {
    for method in ["constructor", "resolve", "reject"] {
        for queued in [false, true] {
            let mut core = core();
            let mut instructions = vec![
                Ir3Instruction::LoadInt { dst: 0, value: 17 },
                call(method, 0, u32::from(method != "constructor"), 1),
                call("reject", 1, 1, 2),
            ];
            if queued {
                instructions.push(call("then", 2, 1, 3));
            }
            instructions.push(Ir3Instruction::Halt);
            core.execute(&module(instructions))
                .unwrap_or_else(|error| panic!("source {method}, queued {queued}: {error:?}"));
            let source = core.get_registers()[1].clone();
            let rejected = core.get_registers()[if queued { 3 } else { 2 }].clone();
            assert_ne!(source, rejected, "reject must allocate a new Promise");

            // Updating the public execution seed starts a new invocation from
            // these handles rather than replaying the previous invocation.
            core.write_register(0, rejected);
            let result = core.execute(&inspect_rejection_reason()).unwrap();
            assert_eq!(result.value, source, "source {method}, queued {queued}");
        }
    }
}

#[test]
fn rejection_carries_the_reason_label_and_ignores_extra_arguments() {
    let mut core = core();
    core.execute(&module(vec![
        call("constructor", 0, 0, 1),
        Ir3Instruction::Halt,
    ]))
    .unwrap();
    let source = core.get_registers()[1].clone();
    core.write_register(2, Value::str("ignored"));

    // ExecutionSeed's public serialization is the replay boundary for labeled
    // inputs. Give the actual reason and ignored argument distinct provenance.
    let mut seed = serde_json::to_value(core.capture_execution_seed()).unwrap();
    seed["register_labels"][1] = serde_json::to_value(Label::Secret).unwrap();
    seed["register_labels"][2] = serde_json::to_value(Label::Custom {
        name: "ignored-argument".to_string(),
        level: 100,
    })
    .unwrap();
    let seed: ExecutionSeed = serde_json::from_value(seed).unwrap();
    core.reset_execution_state_from_seed(&seed).unwrap();
    let result = core
        .execute(&module(vec![call("reject", 1, 2, 0), Ir3Instruction::Halt]))
        .unwrap();
    assert_eq!(result.completion_label, Label::Secret);
    assert_ne!(result.value, source);

    // Force a distinct seed while preserving the returned handle in register0.
    core.write_register(2, Value::Undefined);
    let result = core.execute(&inspect_rejection_reason()).unwrap();
    assert_eq!(result.value, source);
    assert_eq!(result.completion_label, Label::Secret);
}
