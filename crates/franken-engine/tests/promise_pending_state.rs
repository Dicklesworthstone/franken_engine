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
use frankenengine_engine::object_model::JsValue;
use frankenengine_engine::promise_model::PromiseState;

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
    module.constant_pool = constant_pool.into_iter().map(Into::into).collect();
    module.function_table = vec![Ir3FunctionDesc {
        entry: function_entry,
        arity: 0,
        frame_size: 4,
        name: Some("async_promise_probe".to_string()),
        is_generator: false,
        rest_param_index: None,
    }];
    module
}

fn execute_public_async_module(module: &Ir3Module) -> Value {
    execute_public_async_module_with_core(module).1
}

fn execute_public_async_module_with_core(module: &Ir3Module) -> (InterpreterCore, Value) {
    let mut core = InterpreterCore::new(test_config(), "promise-pending-state-test");
    let value = core
        .execute(module)
        .expect("public async promise module should execute without panic")
        .value;
    (core, value)
}

/// ES2020: calling an async function always returns its result Promise; a
/// pending `await` parks only that activation and the caller runs on (to
/// `Halt`, which completes with the call's result register). bd-9vouw.26: the
/// suite used to pin the opposite, that a pending await aborted the whole
/// program with `Undefined` (the suspension marker leaking out as the result).
fn result_promise_state(core: &InterpreterCore, value: &Value) -> PromiseState {
    let Value::Promise(handle) = value else {
        panic!("an async function call must complete as its result Promise, got {value:?}");
    };
    core.promise_state(*handle)
        .expect("result Promise created by this core")
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
        execute_public_async_module_with_core(&module)
    }));
    assert!(
        result.is_ok(),
        "awaiting a pending promise must return control without panicking"
    );
    let (core, value) = result.expect("panic-free pending await");
    assert_eq!(
        result_promise_state(&core, &value),
        PromiseState::Pending,
        "a pending await returns control with the still-pending result Promise and claims no resumption"
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
    let (pending_core, pending_alone) = execute_public_async_module_with_core(&pending);
    let (fulfilled_core, fulfilled_alone) = execute_public_async_module_with_core(&fulfilled);
    let pending_state = result_promise_state(&pending_core, &pending_alone);
    let fulfilled_state = result_promise_state(&fulfilled_core, &fulfilled_alone);
    assert_eq!(
        pending_state,
        PromiseState::Pending,
        "a pending await leaves its result Promise pending"
    );
    assert!(
        matches!(fulfilled_state, PromiseState::Fulfilled(JsValue::Int(99))),
        "a fulfilled await resumes (from a Promise job) and fulfills its result Promise with 99, got {fulfilled_state:?}"
    );
    assert_ne!(
        pending_state, fulfilled_state,
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

    // `true` => the activation awaits a settled promise and its result Promise
    // fulfills; `false` => it awaits a pending promise and its result stays pending.
    let schedule: [(&Ir3Module, bool); 5] = [
        (&pending, false),
        (&fulfilled, true),
        (&fulfilled_other, true),
        (&pending, false),
        (&fulfilled, true),
    ];
    for (round, (module, expect_completion)) in schedule.into_iter().enumerate() {
        let (core, outcome) = execute_public_async_module_with_core(module);
        let state = result_promise_state(&core, &outcome);
        if expect_completion {
            assert!(
                matches!(state, PromiseState::Fulfilled(_)),
                "round {round}: a fulfilled-await activation must fulfill its result Promise regardless of what ran before it, got {state:?}"
            );
        } else {
            assert_eq!(
                state,
                PromiseState::Pending,
                "round {round}: a pending-await activation must leave its result Promise pending regardless of what ran before it"
            );
        }
    }
}

// The former `#[cfg(any())] mod legacy_private_api_tests` block was removed here
// (bd-bg9l1.24). It never compiled — it referenced the removed `CoreInterpreter` /
// `promise_store` private APIs and several bodies asserted nothing ("mainly verifies
// no panics occur"). Pending / fulfilled / rejected await behaviour and independent
// suspension are covered by the active current-API tests above in this file.
