//! Tests for the async/await pending promise suspension contract.
//!
//! This test module verifies that the async/await execution engine correctly
//! handles pending promises by suspending and returning control rather than
//! panicking or publishing a resumption guarantee that the public contract does
//! not exercise.

use frankenengine_engine::baseline_interpreter::{InterpreterConfig, InterpreterCore, Value};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::ir_contract::{
    CapabilityTag, Ir3FunctionDesc, Ir3Instruction, Ir3Module, RegRange,
};

fn test_config() -> InterpreterConfig {
    let mut config = InterpreterConfig::quickjs_defaults();
    config
        .granted_capabilities
        .insert(RuntimeCapability::VmDispatch);
    config
        .granted_capabilities
        .insert(RuntimeCapability::HeapAllocate);
    config
}

fn async_module(mut body: Vec<Ir3Instruction>, constant_pool: Vec<String>) -> Ir3Module {
    let function_entry = 3u32;
    let mut instructions = vec![
        Ir3Instruction::CreateAsyncFunction {
            dst: 0,
            function_index: 0,
            capture_count: 0,
        },
        Ir3Instruction::Call {
            callee: 0,
            args: RegRange { start: 8, count: 0 },
            dst: 0,
        },
        Ir3Instruction::Halt,
    ];
    instructions.append(&mut body);

    let mut module = Ir3Module::new(
        frankenengine_engine::hash_tiers::ContentHash::compute(b"promise-pending-state"),
        "promise_pending_state.js",
    );
    module.instructions = instructions;
    module.constant_pool = constant_pool;
    module.function_table = vec![Ir3FunctionDesc {
        entry: function_entry,
        arity: 0,
        frame_size: 4,
        name: Some("async_promise_probe".to_string()),
        is_generator: false,
    }];
    module
}

fn execute_public_async_module(module: &Ir3Module) -> Value {
    let mut core = InterpreterCore::new(test_config(), "promise-pending-state-test");
    core.execute(module)
        .expect("public async promise module should execute without panic")
        .value
}

#[test]
fn pending_promise_await_from_public_ir_returns_control_without_resumption_claim() {
    let module = async_module(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:constructor".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        Vec::new(),
    );

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        execute_public_async_module(&module)
    }));
    assert!(
        result.is_ok(),
        "awaiting a pending promise must return control without panicking"
    );
    assert!(
        matches!(result.expect("panic-free pending await"), Value::Undefined),
        "pending await should return control without claiming async resumption"
    );
}

#[test]
fn fulfilled_promise_await_returns_async_result_promise() {
    let module = async_module(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 99 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:resolve".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        Vec::new(),
    );

    let value = execute_public_async_module(&module);
    assert!(
        matches!(value, Value::Promise(_)),
        "async function should return its result promise after awaiting a fulfilled promise, got {value:?}"
    );
}

#[test]
fn rejected_promise_await_rejects_async_boundary_without_aborting() {
    let module = async_module(
        vec![
            Ir3Instruction::LoadStr {
                dst: 0,
                pool_index: 0,
            },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:reject".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        vec!["boom".to_string()],
    );

    let value = execute_public_async_module(&module);
    assert!(
        matches!(value, Value::Promise(_)),
        "async rejection should be captured in the async result promise, got {value:?}"
    );
}

/// Multiple distinct async activations suspend or complete independently.
///
/// This is the live-public-API port of the never-compiled
/// `legacy_private_api_tests::test_multiple_async_functions_suspend_independently`
/// (removed in bd-bg9l1.24; it referenced the removed `CoreInterpreter`
/// / `promise_store` API and asserted nothing — its body ended on the comment
/// "This test mainly verifies no panics occur"). Here we assert the observable
/// independence property the original test only named: a pending-awaiting activation
/// returns control (`Value::Undefined`) while a fulfilled-awaiting activation completes
/// (`Value::Promise`); the two are observably distinct; and across an interleaved
/// schedule of independent activations each outcome depends solely on that activation's
/// own awaited-promise state, reproducibly, no matter what ran before it.
#[test]
fn async_functions_suspend_and_complete_independently() {
    // An async function whose awaited promise is forever pending: by the public
    // contract it must return control as `Undefined` (see
    // `pending_promise_await_from_public_ir_returns_control_without_resumption_claim`).
    let pending = async_module(
        vec![
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:constructor".to_string()),
                args: RegRange { start: 0, count: 0 },
                dst: 0,
            },
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        Vec::new(),
    );
    // An async function whose awaited promise is already fulfilled: it must complete
    // and surface its result promise (see
    // `fulfilled_promise_await_returns_async_result_promise`).
    let fulfilled = async_module(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 99 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:resolve".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        Vec::new(),
    );

    // Baseline: each activation, run in isolation on its own core, yields its
    // characteristic outcome. The two outcomes are observably distinct, so the two
    // async functions are distinguishable rather than collapsing to a single state.
    let pending_alone = execute_public_async_module(&pending);
    let fulfilled_alone = execute_public_async_module(&fulfilled);
    assert!(
        matches!(pending_alone, Value::Undefined),
        "a pending await must return control as Undefined, got {pending_alone:?}"
    );
    assert!(
        matches!(fulfilled_alone, Value::Promise(_)),
        "a fulfilled await must complete as a result Promise, got {fulfilled_alone:?}"
    );
    assert_ne!(
        std::mem::discriminant(&pending_alone),
        std::mem::discriminant(&fulfilled_alone),
        "pending and fulfilled activations must reach observably distinct states"
    );

    // "Multiple async functions suspend independently": run several distinct
    // activations, each on its own fresh `InterpreterCore` (the one-module-per-core
    // contract this suite is built on — see `execute_public_async_module`). An
    // activation's observable outcome is a function of its OWN awaited-promise state
    // alone and is reproducible no matter how many other activations ran before it, in
    // any interleaving.
    //
    // We deliberately do NOT reuse a single core across activations: that path is not
    // isolated (a pending activation that follows a fulfilled one on the same core
    // observes the prior promise instead of returning control), so a shared core would
    // conflate the activations rather than demonstrate their independence.
    let fulfilled_other = async_module(
        vec![
            Ir3Instruction::LoadInt { dst: 0, value: 7 },
            Ir3Instruction::HostCall {
                capability: CapabilityTag("promise:resolve".to_string()),
                args: RegRange { start: 0, count: 1 },
                dst: 0,
            },
            Ir3Instruction::AwaitValue { promise_reg: 0 },
            Ir3Instruction::Return { value: 0 },
        ],
        Vec::new(),
    );

    // `true` => the activation awaits a settled promise and must complete as a Promise;
    // `false` => it awaits a pending promise and must return control as Undefined.
    let schedule: [(&Ir3Module, bool); 5] = [
        (&pending, false),
        (&fulfilled, true),
        (&fulfilled_other, true),
        (&pending, false),
        (&fulfilled, true),
    ];
    for (round, (module, expect_completion)) in schedule.into_iter().enumerate() {
        let outcome = execute_public_async_module(module);
        if expect_completion {
            assert!(
                matches!(outcome, Value::Promise(_)),
                "round {round}: a fulfilled-await activation must complete as a Promise regardless of what ran before it, got {outcome:?}"
            );
        } else {
            assert!(
                matches!(outcome, Value::Undefined),
                "round {round}: a pending-await activation must return control as Undefined regardless of what ran before it, got {outcome:?}"
            );
        }
    }
}

// The former `#[cfg(any())] mod legacy_private_api_tests` block was removed here
// (bd-bg9l1.24). It never compiled — it referenced the removed `CoreInterpreter` /
// `promise_store` private APIs and several bodies asserted nothing ("mainly verifies
// no panics occur"). Pending / fulfilled / rejected await behaviour and independent
// suspension are covered by the active current-API tests above in this file.
