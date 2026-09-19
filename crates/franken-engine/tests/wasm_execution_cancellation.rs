#![forbid(unsafe_code)]

//! Whole-instance cancellation, distinct from host-service revocation.
//! All fixtures run the production numeric VM, including hostless loops.

use std::collections::BTreeSet;
use std::sync::Barrier;
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleRequest, ResolutionContext, wasm_module_required_capabilities,
};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits,
    WasmNumericVm, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue, WasmFunctionSignature, WasmNativeLoadError, WasmValueType,
};
use WasmBoundaryValue::I32;

type Outcome = Result<Vec<WasmBoundaryValue>, WasmNumericVmError>;

fn leb(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let low = (value & 127) as u8;
        value >>= 7;
        bytes.push(low | if value == 0 { 0 } else { 128 });
        if value == 0 { return bytes; }
    }
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(payload.len()));
    module.extend_from_slice(payload);
}

fn program(start: bool, host: bool) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[2, 0x60, 0, 1, 0x7f, 0x60, 0, 0]);
    if host { section(&mut bytes, 2, &[1, 1, b'h', 1, b'f', 0, 0]); }
    section(&mut bytes, 3, &[6, 0, 0, 0, 0, 0, 1]);
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    section(&mut bytes, 5, &[1, 1, 1, 1]);
    section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
    let base = u8::from(host);
    let mut exports = vec![7];
    for (name, kind, index) in [
        ("step", 0, base), ("indirect", 0, base + 1), ("nested", 0, base + 2),
        ("spin", 0, base + 3), ("trap", 0, base + 4), ("m", 2, 0), ("g", 3, 0),
    ] {
        exports.extend(leb(name.len()));
        exports.extend_from_slice(name.as_bytes());
        exports.extend([kind, index]);
    }
    section(&mut bytes, 7, &exports);
    if start { section(&mut bytes, 8, &[base + 5]); }
    section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, base]);
    // `step` commits g += 1 before optionally calling the host, then stores
    // the returned value. Cancellation in that callback must retain g but
    // prevent the later store. Hostless `spin` has no call instruction.
    let mut step = vec![0x23, 0, 0x41, 1, 0x6a, 0x24, 0, 0x41, 0];
    step.extend(if host { vec![0x10, 0] } else { vec![0x23, 0] });
    step.extend([0x36, 2, 0, 0x23, 0, 0x0b]);
    let bodies = [
        step,
        vec![0x41, 0, 0x11, 0, 0, 0x0b],
        vec![0x10, base + 1, 0x0b],
        vec![0x03, 0x40, 0x0c, 0, 0x0b, 0x41, 42, 0x0b],
        vec![0x00, 0x0b],
        vec![0x10, base, 0x1a, 0x0b],
    ];
    let mut code = leb(bodies.len());
    for body in bodies {
        code.extend(leb(body.len() + 1));
        code.push(0);
        code.extend(body);
    }
    section(&mut bytes, 10, &code);
    bytes
}

fn vm(start: bool, host: bool) -> WasmNumericVm {
    WasmNumericVm::parse(&program(start, host), WasmNumericLimits::default()).unwrap()
}

fn control(token: &CancellationToken) -> WasmHostImports {
    let mut imports = WasmHostImports::new(BTreeSet::new());
    imports.bind_execution_cancellation(token.clone(), "guest-execution").unwrap();
    imports
}

fn host_control<F>(token: &CancellationToken, callback: F) -> WasmHostImports
where F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue]) -> Outcome + Send + Sync + 'static {
    let mut imports = WasmHostImports::new(
        [RuntimeCapability::VmDispatch, RuntimeCapability::Builtin].into(),
    );
    imports.bind_execution_cancellation(token.clone(), "guest-and-host").unwrap();
    imports.define("h", "f", WasmFunctionSignature {
        params: vec![], results: vec![WasmValueType::I32],
    }, [RuntimeCapability::Builtin].into(), 3, callback).unwrap();
    imports
}

fn cancelled(error: WasmNumericVmError) {
    assert_eq!(error, WasmNumericVmError::State(WasmStateError::Host(WasmHostError::ExecutionCancelled)));
}

#[test]
fn hostless_control_preserves_results_state_and_work_accounting_when_not_cancelled() {
    for start in [false, true] {
        let vm = vm(start, false);
        let mut baseline = vm.instantiate().unwrap();
        let mut controlled = vm.instantiate_with_imports(control(&CancellationToken::new())).unwrap();
        assert_eq!(controlled.start_execution(), baseline.start_execution());
        for name in ["step", "indirect", "nested", "step"] {
            assert_eq!(controlled.call_export(name, &[]).unwrap(), baseline.call_export(name, &[]).unwrap());
            assert_eq!(controlled.memory_export("m"), baseline.memory_export("m"));
            assert_eq!(controlled.global_export("g"), baseline.global_export("g"));
        }
    }
}

#[test]
fn cancellation_precedes_allocation_and_guest_startup_even_after_token_reset() {
    let token = CancellationToken::new();
    token.cancel();
    let imports = control(&token);
    token.reset();
    let vm = WasmNumericVm::parse(&program(true, false), WasmNumericLimits {
        max_memory_pages: 0, ..WasmNumericLimits::default()
    }).unwrap();
    cancelled(vm.instantiate_with_imports(imports).unwrap_err());
}

#[test]
fn cancelled_hostless_instance_cannot_run_or_mutate_through_any_guest_export() {
    let vm = vm(false, false);
    let token = CancellationToken::new();
    let mut instance = vm.instantiate_with_imports(control(&token)).unwrap();
    assert_eq!(instance.call_export("step", &[]).unwrap().results, [I32(1)]);
    let memory = instance.memory_export("m").unwrap().to_vec();
    token.cancel();
    token.reset();
    for name in ["step", "indirect", "nested", "spin", "trap"] {
        cancelled(instance.call_export(name, &[]).unwrap_err());
        assert_eq!(instance.memory_export("m").unwrap(), memory);
        assert_eq!(instance.global_export("g"), Some(&I32(1)));
    }
}

#[test]
fn execution_signal_cannot_be_replaced_to_erase_a_pending_request() {
    let vm = vm(false, false);
    let token = CancellationToken::new();
    let mut imports = control(&token);
    token.cancel();
    token.reset();
    assert_eq!(imports.bind_execution_cancellation(CancellationToken::new(), "replacement"),
        Err(WasmHostError::ExecutionCancellationAlreadyBound));
    cancelled(vm.instantiate_with_imports(imports).unwrap_err());
}

#[test]
fn shared_execution_signal_stops_existing_instances_but_not_a_fresh_authorized_scope() {
    let vm = vm(false, false);
    let signal = CancellationToken::new();
    let mut a = vm.instantiate_with_imports(control(&signal)).unwrap();
    let mut b = vm.instantiate_with_imports(control(&signal)).unwrap();
    let mut unrelated = vm.instantiate_with_imports(control(&CancellationToken::new())).unwrap();
    signal.cancel();
    signal.reset();
    for instance in [&mut a, &mut b] { cancelled(instance.call_export("step", &[]).unwrap_err()); }
    assert_eq!(unrelated.call_export("step", &[]).unwrap().results, [I32(1)]);
    let mut fresh = vm.instantiate_with_imports(control(&signal)).unwrap();
    assert_eq!(fresh.call_export("step", &[]).unwrap().results, [I32(1)]);
    cancelled(a.call_export("step", &[]).unwrap_err());
}

#[test]
fn host_only_and_service_signals_remain_distinct_from_whole_instance_cancellation() {
    let vm = vm(false, false);
    let host_signal = CancellationToken::new();
    let service_signal = CancellationToken::new();
    let execution_signal = CancellationToken::new();
    let mut imports = control(&execution_signal);
    imports.bind_cancellation(host_signal.clone(), "host-only").unwrap();
    imports.bind_capability_revocation(RuntimeCapability::VmDispatch, service_signal.clone(), "service-only").unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    host_signal.cancel();
    service_signal.cancel();
    assert_eq!(instance.call_export("nested", &[]).unwrap().results, [I32(1)]);
    execution_signal.cancel();
    cancelled(instance.call_export("nested", &[]).unwrap_err());
}

#[test]
fn cancelling_a_hostless_loop_from_another_thread_does_not_require_guest_hostcalls() {
    let vm = WasmNumericVm::parse(&program(false, false), WasmNumericLimits {
        // Finite even if cancellation regresses; a budget trap is a failure,
        // never accepted as evidence of cancellation.
        max_instructions: 10_000_000, ..WasmNumericLimits::default()
    }).unwrap();
    let signal = CancellationToken::new();
    let mut instance = vm.instantiate_with_imports(control(&signal)).unwrap();
    let ready = Barrier::new(2);
    std::thread::scope(|scope| {
        let execution = scope.spawn(|| {
            ready.wait();
            instance.call_export("spin", &[])
        });
        ready.wait();
        signal.cancel();
        signal.reset();
        // Scheduling may linearize the request at entry or an opcode
        // boundary. No wall-clock latency or forced scheduling is claimed.
        cancelled(execution.join().unwrap().unwrap_err());
    });
    assert_eq!(instance.global_export("g"), Some(&I32(0)));
}

#[test]
fn cancellation_inside_nested_host_leaf_retains_prior_stores_and_unwinds_guest_frames() {
    for name in ["step", "indirect", "nested"] {
        let vm = vm(false, true);
        let token = CancellationToken::new();
        let signal = token.clone();
        let mut instance = vm.instantiate_with_imports(host_control(&token, move |caller, _| {
            caller.write_memory(8, &[9, 8, 7, 6])?;
            signal.cancel();
            signal.reset();
            cancelled(caller.checkpoint().unwrap_err());
            cancelled(caller.write_memory(8, &[99; 4]).unwrap_err());
            Ok(vec![I32(99)])
        })).unwrap();
        cancelled(instance.call_export(name, &[]).unwrap_err());
        assert_eq!(instance.global_export("g"), Some(&I32(1)));
        assert_eq!(&instance.memory_export("m").unwrap()[..12], &[0, 0, 0, 0, 0, 0, 0, 0, 9, 8, 7, 6]);
        cancelled(instance.call_export("step", &[]).unwrap_err());
        let mut fresh = vm.instantiate_with_imports(host_control(&CancellationToken::new(), |_, _| Ok(vec![I32(42)]))).unwrap();
        assert_eq!(fresh.call_export(name, &[]).unwrap().results, [I32(1)]);
    }
}

#[test]
fn return_boundary_cancellation_is_recorded_without_losing_completed_host_effects() {
    use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
    for start in [false, true] {
        let vm = vm(start, true);
        let token = CancellationToken::new();
        let signal = token.clone();
        let mut bindings = host_control(&token, move |caller, _| {
            caller.write_memory(8, &[1, 3, 5, 7])?;
            signal.cancel();
            signal.reset();
            Ok(vec![I32(99)]) // No provider poll; the VM return gate must observe.
        });
        let recorder = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
        let expected = if start {
            vm.instantiate_with_imports(bindings).unwrap_err()
        } else {
            let mut live = vm.instantiate_with_imports(bindings).unwrap();
            let error = live.call_export("nested", &[]).unwrap_err();
            assert_eq!(&live.memory_export("m").unwrap()[..4], &[0; 4]);
            error
        };
        cancelled(expected.clone());
        let tape = recorder.snapshot().unwrap();
        assert_eq!(tape.call_count(), 1);
        let mut bindings = host_control(&CancellationToken::new(), |_, _| panic!("replay called provider"));
        let replay = bindings.replay_calls(tape, WasmHostTraceLimits::default()).unwrap();
        if start {
            assert_eq!(vm.instantiate_with_imports(bindings).unwrap_err(), expected);
        } else {
            let mut replayed = vm.instantiate_with_imports(bindings).unwrap();
            assert_eq!(replayed.call_export("nested", &[]).unwrap_err(), expected);
            assert_eq!(&replayed.memory_export("m").unwrap()[8..12], &[1, 3, 5, 7]);
        }
        replay.verify_complete().unwrap();
    }
}

#[test]
fn a_successful_replay_tape_cannot_resume_a_live_cancelled_guest_instance() {
    use frankenengine_engine::wasm_runtime_lane::host_replay::{WasmHostTraceError, WasmHostTraceLimits};
    let vm = vm(false, true);
    let mut bindings = host_control(&CancellationToken::new(), |_, _| Ok(vec![I32(42)]));
    let recorder = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    vm.instantiate_with_imports(bindings).unwrap().call_export("step", &[]).unwrap();
    let token = CancellationToken::new();
    let mut bindings = host_control(&token, |_, _| panic!("replay called provider"));
    let replay = bindings.replay_calls(recorder.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    let mut replayed = vm.instantiate_with_imports(bindings).unwrap();
    token.cancel();
    cancelled(replayed.call_export("step", &[]).unwrap_err());
    assert_eq!(replayed.global_export("g"), Some(&I32(0)));
    assert_eq!(&replayed.memory_export("m").unwrap()[..4], &[0; 4]);
    assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Incomplete { remaining: 1 }));
}

#[test]
fn prior_host_budget_fault_wins_but_cancellation_blocks_the_next_guest_invocation() {
    let vm = vm(false, true);
    let token = CancellationToken::new();
    let signal = token.clone();
    let mut instance = vm.instantiate_with_imports(host_control(&token, move |caller, _| {
        let first = caller.charge_work(u64::MAX).unwrap_err();
        signal.cancel();
        signal.reset();
        assert_eq!(caller.checkpoint().unwrap_err(), first);
        Ok(vec![I32(99)])
    })).unwrap();
    assert!(matches!(instance.call_export("step", &[]), Err(WasmNumericVmError::InstructionBudgetExceeded { .. })));
    cancelled(instance.call_export("step", &[]).unwrap_err());
    assert_eq!(instance.global_export("g"), Some(&I32(1)));
}

#[test]
fn inactive_execution_control_does_not_replace_budget_or_depth_refusals() {
    let limited = WasmNumericVm::parse(&program(false, false), WasmNumericLimits {
        max_instructions: 12, max_call_depth: 2, ..WasmNumericLimits::default()
    }).unwrap();
    let mut instance = limited.instantiate_with_imports(control(&CancellationToken::new())).unwrap();
    assert!(matches!(instance.call_export("nested", &[]), Err(WasmNumericVmError::CallDepthExceeded { max: 2 })));
    assert!(matches!(instance.call_export("spin", &[]), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 12 })));
    // The rejected activations did not leave poisoned live-value accounting.
    assert_eq!(instance.call_export("step", &[]).unwrap().results, [I32(1)]);
}

#[test]
fn resolved_hostless_module_keeps_the_execution_subscription_after_loading() {
    let limits = WasmNumericLimits::default();
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver.register_workspace_module("/app/pure.wasm",
        ModuleDefinition::wasm_binary(&program(false, false), &limits).unwrap()).unwrap();
    let policy = CapabilityPolicyHook::new(wasm_module_required_capabilities());
    let ctx = ResolutionContext::new("trace", "decision", "policy");
    let module = resolver.load_wasm(&ModuleRequest::new("/app/pure.wasm", ImportStyle::Import), &ctx, &policy, limits).unwrap();
    let signal = CancellationToken::new();
    let mut instance = module.instantiate_with_imports(&ctx, &policy, control(&signal)).unwrap();
    assert_eq!(instance.call_export("nested", &[], &ctx, &policy).unwrap().results, [I32(1)]);
    signal.cancel();
    signal.reset();
    match instance.call_export("step", &[], &ctx, &policy) {
        Err(WasmNativeLoadError::Execution(error)) => cancelled(error),
        other => panic!("lost resolved execution cancellation: {other:?}"),
    }
    assert_eq!(instance.global_export("g", &ctx, &policy).unwrap(), Some(&I32(1)));
}

#[test]
fn direct_and_indirect_host_tail_calls_preserve_execution_cancellation() {
    for indirect in [false, true] {
        let mut bytes = b"\0asm\x01\0\0\0".to_vec();
        section(&mut bytes, 1, &[1, 0x60, 0, 1, 0x7f]);
        section(&mut bytes, 2, &[1, 1, b'h', 1, b'f', 0, 0]);
        section(&mut bytes, 3, &[1, 0]);
        section(&mut bytes, 4, &[1, 0x70, 0, 1]);
        section(&mut bytes, 5, &[1, 0, 1]);
        section(&mut bytes, 7, &[2, 4, b's', b't', b'e', b'p', 0, 1, 1, b'm', 2, 0]);
        section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
        let body = if indirect { vec![0, 0x41, 0, 0x13, 0, 0, 0x0b] }
            else { vec![0, 0x12, 0, 0x0b] };
        let mut code = vec![1];
        code.extend(leb(body.len()));
        code.extend(body);
        section(&mut bytes, 10, &code);
        let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits {
            max_call_depth: 1, max_live_values: 1, ..WasmNumericLimits::default()
        }).unwrap();
        let signal = CancellationToken::new();
        let provider_signal = signal.clone();
        let mut first = true;
        let mut instance = vm.instantiate_with_imports(host_control(&signal, move |caller, _| {
            if first { first = false; return Ok(vec![I32(42)]); }
            caller.write_memory(0, &[1, 2, 3, 4])?;
            provider_signal.cancel();
            provider_signal.reset();
            Ok(vec![I32(99)])
        })).unwrap();
        let success = instance.call_export("step", &[]).unwrap();
        assert_eq!(success.results, [I32(42)]);
        assert_eq!(success.max_call_depth, 1);
        cancelled(instance.call_export("step", &[]).unwrap_err());
        assert_eq!(&instance.memory_export("m").unwrap()[..4], &[1, 2, 3, 4]);
        cancelled(instance.call_export("step", &[]).unwrap_err());
    }
}
