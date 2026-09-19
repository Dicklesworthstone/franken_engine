#![forbid(unsafe_code)]

//! Cooperative cancellation of real native Wasm host dispatch. Guest-only
//! execution and arbitrary native code are deliberately not called preemptible.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleRequest, ResolutionContext, wasm_module_required_capabilities,
};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits, WasmNumericVm,
    WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue, WasmFunctionSignature, WasmNativeLoadError, WasmValueType,
};
use WasmBoundaryValue::I32;

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

fn program(start: bool) -> Vec<u8> {
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    section(&mut module, 1, &[2, 0x60, 1, 0x7f, 1, 0x7f, 0x60, 0, 0]);
    section(&mut module, 2, &[1, 3, b'e', b'n', b'v', 4, b's', b't', b'e', b'p', 0, 0]);
    section(&mut module, 3, &[4, 0, 0, 0, 1]);
    section(&mut module, 4, &[1, 0x70, 0, 1]);
    section(&mut module, 5, &[1, 1, 1, 1]);
    let mut exports = vec![6];
    for (name, kind, index) in [
        ("host", 0, 0), ("direct", 0, 1), ("indirect", 0, 2),
        ("pure", 0, 3), ("m", 2, 0), ("t", 1, 0),
    ] {
        exports.extend(leb(name.len()));
        exports.extend_from_slice(name.as_bytes());
        exports.extend([kind, index]);
    }
    section(&mut module, 7, &exports);
    if start { section(&mut module, 8, &[4]); }
    section(&mut module, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
    let mut bodies = vec![4];
    for code in [
        &[0x41, 4, 0x20, 0, 0x10, 0, 0x36, 2, 0, 0x41, 4, 0x28, 2, 0, 0x0b][..],
        &[0x41, 4, 0x20, 0, 0x41, 0, 0x11, 0, 0, 0x36, 2, 0, 0x41, 4, 0x28, 2, 0, 0x0b],
        &[0x41, 42, 0x0b],
        &[0x41, 2, 0x10, 0, 0x1a, 0x0b],
    ] {
        bodies.extend(leb(code.len() + 1));
        bodies.push(0);
        bodies.extend_from_slice(code);
    }
    section(&mut module, 10, &bodies);
    section(&mut module, 11, &[1, 0, 0x41, 8, 0x0b, 3, 0xff, 0x80, 0xfe]);
    module
}

fn grants() -> BTreeSet<RuntimeCapability> {
    [RuntimeCapability::VmDispatch, RuntimeCapability::Builtin].into_iter().collect()
}

fn imports<F>(token: &CancellationToken, callback: F) -> WasmHostImports
where
    F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue])
            -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError> + Send + Sync + 'static,
{
    let mut imports = WasmHostImports::new(grants());
    imports.bind_cancellation(token.clone(), "wasm-cancel-test").unwrap();
    imports.define("env", "step", WasmFunctionSignature {
        params: vec![WasmValueType::I32], results: vec![WasmValueType::I32],
    }, [RuntimeCapability::Builtin].into(), 3, callback).unwrap();
    imports
}

fn add(_: &mut WasmHostCaller<'_, '_>, arguments: &[WasmBoundaryValue])
    -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError>
{
    let [I32(value)] = arguments else { panic!("validated argument type") };
    Ok(vec![I32(value.wrapping_add(40))])
}

fn vm(start: bool) -> WasmNumericVm {
    WasmNumericVm::parse(&program(start), WasmNumericLimits::default()).unwrap()
}

fn cancelled(error: WasmNumericVmError) {
    assert_eq!(error, WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Cancelled)));
}

#[test]
fn already_cancelled_scope_refuses_before_state_allocation_or_startup() {
    let token = CancellationToken::new();
    token.cancel();
    let vm = WasmNumericVm::parse(&program(true), WasmNumericLimits {
        max_memory_pages: 0, ..WasmNumericLimits::default()
    }).unwrap();
    let imports = imports(&token, |_, _| panic!("cancelled startup must not call a provider"));
    token.reset();
    cancelled(vm.instantiate_with_imports(imports).unwrap_err());
}

#[test]
fn cancel_then_reset_before_first_poll_cannot_erase_an_attached_request() {
    let token = CancellationToken::new();
    let imports = imports(&token, |_, _| panic!("cancelled scope"));
    token.cancel();
    token.reset();
    assert!(!token.is_cancelled());
    cancelled(vm(true).instantiate_with_imports(imports).unwrap_err());
}

#[test]
fn cancellation_binding_cannot_be_replaced_with_a_fresh_signal() {
    let token = CancellationToken::new();
    let mut imports = imports(&token, add);
    assert_eq!(imports.bind_cancellation(CancellationToken::new(), "replacement"),
        Err(WasmHostError::CancellationAlreadyBound));
    token.cancel();
    token.reset();
    cancelled(vm(false).instantiate_with_imports(imports).unwrap_err());
}

#[test]
fn direct_indirect_and_exported_imports_all_observe_the_same_scope() {
    let vm = vm(false);
    let token = CancellationToken::new();
    let effects = Arc::new(AtomicUsize::new(0));
    let observed = effects.clone();
    let mut instance = vm.instantiate_with_imports(imports(&token, move |caller, args| {
        observed.fetch_add(1, Ordering::SeqCst);
        add(caller, args)
    })).unwrap();
    assert_eq!(instance.call_export("direct", &[I32(2)]).unwrap().results, [I32(42)]);
    let before = instance.memory_export("m").unwrap().to_vec();
    token.cancel();
    token.reset();
    for name in ["direct", "indirect", "host"] {
        cancelled(instance.call_export(name, &[I32(9)]).unwrap_err());
        assert_eq!(instance.memory_export("m").unwrap(), before);
    }
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}

#[test]
fn ignored_callback_checkpoint_refusal_cannot_publish_results_or_continue_guest() {
    let vm = vm(false);
    let token = CancellationToken::new();
    let signal = token.clone();
    let mut instance = vm.instantiate_with_imports(imports(&token, move |caller, _| {
        caller.write_memory(0, &[11, 12, 13, 14])?;
        signal.cancel();
        signal.reset();
        cancelled(caller.checkpoint().unwrap_err());
        cancelled(caller.write_memory(0, &[99, 99, 99, 99]).unwrap_err());
        cancelled(caller.read_memory(8, 3).unwrap_err());
        cancelled(caller.charge_work(0).unwrap_err());
        // Deliberately swallow errors: the VM boundary must retain the refusal.
        Ok(vec![I32(99)])
    })).unwrap();
    cancelled(instance.call_export("direct", &[I32(1)]).unwrap_err());
    assert_eq!(&instance.memory_export("m").unwrap()[..8], &[11, 12, 13, 14, 0, 0, 0, 0]);
    cancelled(instance.call_export("host", &[I32(1)]).unwrap_err());
}

#[test]
fn automatic_buffer_and_work_checks_do_not_require_an_explicit_provider_poll() {
    for operation in 0..3 {
        let vm = vm(false);
        let token = CancellationToken::new();
        let signal = token.clone();
        let mut instance = vm.instantiate_with_imports(imports(&token, move |caller, _| {
            signal.cancel();
            signal.reset();
            let error = match operation {
                0 => caller.read_memory(8, 3).unwrap_err(),
                1 => caller.write_memory(0, &[1, 2, 3, 4]).unwrap_err(),
                _ => caller.charge_work(1).unwrap_err(),
            };
            cancelled(error);
            Ok(vec![I32(99)])
        })).unwrap();
        cancelled(instance.call_export("direct", &[I32(1)]).unwrap_err());
        assert_eq!(&instance.memory_export("m").unwrap()[..8], &[0; 8]);
    }
}

#[test]
fn post_callback_checkpoint_observes_a_request_even_when_provider_never_polls() {
    let vm = vm(false);
    let token = CancellationToken::new();
    let signal = token.clone();
    let mut instance = vm.instantiate_with_imports(imports(&token, move |_, _| {
        signal.cancel();
        signal.reset();
        Ok(vec![I32(99)])
    })).unwrap();
    cancelled(instance.call_export("direct", &[I32(1)]).unwrap_err());
    assert_eq!(&instance.memory_export("m").unwrap()[4..8], &[0; 4]);
}

#[test]
fn concurrent_request_during_provider_execution_is_observed_on_return() {
    let vm = vm(false);
    let token = CancellationToken::new();
    let entered = Arc::new(Barrier::new(2));
    let released = Arc::new(Barrier::new(2));
    let callback_entered = entered.clone();
    let callback_released = released.clone();
    let mut instance = vm.instantiate_with_imports(imports(&token, move |caller, _| {
        caller.write_memory(0, &[1, 2, 3, 4])?;
        callback_entered.wait();
        callback_released.wait();
        Ok(vec![I32(99)])
    })).unwrap();
    std::thread::scope(|scope| {
        scope.spawn(|| {
            entered.wait();
            token.cancel();
            token.reset();
            released.wait();
        });
        cancelled(instance.call_export("direct", &[I32(1)]).unwrap_err());
    });
    assert_eq!(&instance.memory_export("m").unwrap()[..8], &[1, 2, 3, 4, 0, 0, 0, 0]);
}

#[test]
fn startup_cancellation_does_not_produce_a_usable_instance() {
    let vm = vm(true);
    let token = CancellationToken::new();
    let signal = token.clone();
    let effects = Arc::new(AtomicUsize::new(0));
    let observed = effects.clone();
    let imports = imports(&token, move |_, _| {
        observed.fetch_add(1, Ordering::SeqCst);
        signal.cancel();
        Ok(vec![I32(99)])
    });
    cancelled(vm.instantiate_with_imports(imports).unwrap_err());
    // The native effect happened before the request; no rollback is claimed.
    assert_eq!(effects.load(Ordering::SeqCst), 1);
}

#[test]
fn cancellation_is_sticky_for_one_instance_but_reset_allows_a_new_scope() {
    let vm = vm(false);
    let token = CancellationToken::new();
    let mut old = vm.instantiate_with_imports(imports(&token, add)).unwrap();
    token.cancel();
    cancelled(old.call_export("host", &[I32(1)]).unwrap_err());
    token.reset();
    let mut fresh = vm.instantiate_with_imports(imports(&token, add)).unwrap();
    assert_eq!(fresh.call_export("host", &[I32(2)]).unwrap().results, [I32(42)]);
    cancelled(old.call_export("host", &[I32(2)]).unwrap_err());
}

#[test]
fn separate_tokens_keep_unrelated_instances_running() {
    let vm = vm(false);
    let token_a = CancellationToken::new();
    let token_b = CancellationToken::new();
    let mut a = vm.instantiate_with_imports(imports(&token_a, add)).unwrap();
    let mut b = vm.instantiate_with_imports(imports(&token_b, add)).unwrap();
    token_a.cancel();
    cancelled(a.call_export("host", &[I32(1)]).unwrap_err());
    assert_eq!(b.call_export("direct", &[I32(2)]).unwrap().results, [I32(42)]);
}

#[test]
fn provider_checkpoints_do_not_spend_or_replenish_the_shared_work_budget() {
    let vm = vm(false);
    let token = CancellationToken::new();
    let mut instance = vm.instantiate_with_imports(imports(&token, |caller, args| {
        let before = caller.remaining_work();
        for _ in 0..10_000 { caller.checkpoint()?; }
        assert_eq!(caller.remaining_work(), before);
        caller.charge_work(5)?;
        assert_eq!(caller.remaining_work(), before - 5);
        add(caller, args)
    })).unwrap();
    let execution = instance.call_export("host", &[I32(2)]).unwrap();
    assert_eq!(execution.results, [I32(42)]);
    assert_eq!(execution.instructions_executed, 9); // fixed cost 3 + ABI 1 + work 5
}

#[test]
fn latched_budget_failure_is_not_replaced_by_the_new_checkpoint_path() {
    let vm = vm(false);
    let token = CancellationToken::new();
    let mut instance = vm.instantiate_with_imports(imports(&token, |caller, _| {
        let first = caller.charge_work(u64::MAX).unwrap_err();
        assert_eq!(caller.checkpoint().unwrap_err(), first);
        Ok(vec![I32(99)])
    })).unwrap();
    assert!(matches!(instance.call_export("direct", &[I32(1)]),
        Err(WasmNumericVmError::InstructionBudgetExceeded { .. })));
    assert_eq!(&instance.memory_export("m").unwrap()[4..8], &[0; 4]);
}

#[test]
fn host_scope_cancellation_does_not_claim_to_preempt_guest_only_execution() {
    let vm = vm(false);
    let token = CancellationToken::new();
    let mut instance = vm.instantiate_with_imports(imports(&token, add)).unwrap();
    token.cancel();
    assert_eq!(instance.call_export("pure", &[I32(0)]).unwrap().results, [I32(42)]);
    cancelled(instance.call_export("host", &[I32(0)]).unwrap_err());
    assert_eq!(instance.call_export("pure", &[I32(0)]).unwrap().results, [I32(42)]);
}

#[test]
fn resolved_loader_preserves_the_bound_cancellation_scope_without_a_raw_vm_escape() {
    let mut capabilities = wasm_module_required_capabilities();
    capabilities.insert(RuntimeCapability::Builtin);
    let policy = CapabilityPolicyHook::new(capabilities);
    let context = ResolutionContext::new("trace-cancel", "decision-cancel", "policy-cancel");
    let limits = WasmNumericLimits::default();
    let definition = ModuleDefinition::wasm_binary(&program(false), &limits).unwrap()
        .require_capability(RuntimeCapability::Builtin);
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver.register_workspace_module("/app/cancel.wasm", definition).unwrap();
    let module = resolver.load_wasm(&ModuleRequest::new("/app/cancel.wasm", ImportStyle::Import),
        &context, &policy, limits).unwrap();
    let token = CancellationToken::new();
    let mut instance = module.instantiate_with_imports(&context, &policy, imports(&token, add)).unwrap();
    assert_eq!(instance.call_export("direct", &[I32(2)], &context, &policy).unwrap().results, [I32(42)]);
    token.cancel();
    token.reset();
    match instance.call_export("indirect", &[I32(9)], &context, &policy) {
        Err(WasmNativeLoadError::Execution(error)) => cancelled(error),
        other => panic!("loader lost cancellation: {other:?}"),
    }
    assert_eq!(&instance.memory_export("m", &context, &policy).unwrap().unwrap()[4..8], &42_i32.to_le_bytes());
}

#[test]
fn cancellation_records_completed_effects_and_replays_without_the_provider() {
    use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
    for start in [false, true] {
        let vm = vm(start);
        let token = CancellationToken::new();
        let signal = token.clone();
        let mut bindings = imports(&token, move |caller, _| {
            caller.write_memory(0, &[1, 2, 3, 4])?;
            signal.cancel();
            signal.reset();
            // Return success without polling: recording must retain both the
            // completed write and the boundary's cancellation outcome.
            Ok(vec![I32(99)])
        });
        let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
        let expected = if start {
            vm.instantiate_with_imports(bindings).unwrap_err()
        } else {
            let mut live = vm.instantiate_with_imports(bindings).unwrap();
            let error = live.call_export("direct", &[I32(2)]).unwrap_err();
            assert_eq!(&live.memory_export("m").unwrap()[..8], &[1, 2, 3, 4, 0, 0, 0, 0]);
            error
        };
        cancelled(expected.clone());
        let transcript = recording.snapshot().unwrap();
        assert_eq!(transcript.call_count(), 1);
        let mut bindings = imports(&CancellationToken::new(), |_, _| panic!("replay invoked provider"));
        let replay = bindings.replay_calls(transcript, WasmHostTraceLimits::default()).unwrap();
        let actual = if start {
            vm.instantiate_with_imports(bindings).unwrap_err()
        } else {
            let mut replayed = vm.instantiate_with_imports(bindings).unwrap();
            let error = replayed.call_export("direct", &[I32(2)]).unwrap_err();
            assert_eq!(&replayed.memory_export("m").unwrap()[..8], &[1, 2, 3, 4, 0, 0, 0, 0]);
            error
        };
        assert_eq!(actual, expected);
        replay.verify_complete().unwrap();
    }
}

#[test]
fn a_live_cancellation_cannot_be_bypassed_with_a_successful_replay_tape() {
    use frankenengine_engine::wasm_runtime_lane::host_replay::{WasmHostTraceError, WasmHostTraceLimits};
    let vm = vm(false);
    let mut bindings = imports(&CancellationToken::new(), |caller, _| {
        caller.write_memory(0, &[1, 2, 3, 4])?;
        Ok(vec![I32(42)])
    });
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    vm.instantiate_with_imports(bindings).unwrap().call_export("host", &[I32(2)]).unwrap();
    let token = CancellationToken::new();
    let mut bindings = imports(&token, |_, _| panic!("replay invoked provider"));
    let replay = bindings.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    let mut replayed = vm.instantiate_with_imports(bindings).unwrap();
    token.cancel();
    token.reset();
    cancelled(replayed.call_export("host", &[I32(2)]).unwrap_err());
    assert_eq!(&replayed.memory_export("m").unwrap()[..8], &[0; 8]);
    assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Incomplete { remaining: 1 }));
}

fn two_services() -> WasmNumericVm {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[1, 0x60, 1, 0x7f, 1, 0x7f]);
    let mut imported = vec![2];
    let mut exported = vec![2];
    for (index, name) in ["read", "compute"].into_iter().enumerate() {
        imported.extend([3, b'e', b'n', b'v']);
        imported.extend(leb(name.len()));
        imported.extend_from_slice(name.as_bytes());
        imported.extend([0, 0]);
        exported.extend(leb(name.len()));
        exported.extend_from_slice(name.as_bytes());
        exported.extend([0, index as u8]);
    }
    section(&mut bytes, 2, &imported);
    section(&mut bytes, 7, &exported);
    WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap()
}

fn service_imports(granted: BTreeSet<RuntimeCapability>) -> WasmHostImports {
    let mut imports = WasmHostImports::new(granted);
    for (name, capability) in [("read", RuntimeCapability::FsRead), ("compute", RuntimeCapability::Builtin)] {
        imports.define("env", name, WasmFunctionSignature {
            params: vec![WasmValueType::I32], results: vec![WasmValueType::I32],
        }, [capability].into(), 3, add).unwrap();
    }
    imports
}

fn service_grants() -> BTreeSet<RuntimeCapability> {
    [RuntimeCapability::VmDispatch, RuntimeCapability::FsRead, RuntimeCapability::Builtin].into()
}

fn revoked(error: WasmNumericVmError, capability: RuntimeCapability, name: &str) {
    assert_eq!(error, WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied {
        module: "env".to_string(), name: name.to_string(), capability,
    })));
}

#[test]
fn service_revocation_blocks_only_the_bindings_that_require_it() {
    let vm = two_services();
    let signal = CancellationToken::new();
    let mut imports = service_imports(service_grants());
    imports.bind_capability_revocation(RuntimeCapability::FsRead, signal.clone(), "read-authority").unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(instance.call_export("read", &[I32(2)]).unwrap().results, [I32(42)]);
    signal.cancel();
    signal.reset();
    revoked(instance.call_export("read", &[I32(3)]).unwrap_err(), RuntimeCapability::FsRead, "read");
    assert_eq!(instance.call_export("compute", &[I32(4)]).unwrap().results, [I32(44)]);
    revoked(instance.call_export("read", &[I32(5)]).unwrap_err(), RuntimeCapability::FsRead, "read");
    assert_eq!(instance.call_export("compute", &[I32(6)]).unwrap().results, [I32(46)]);
}

#[test]
fn vm_dispatch_revocation_covers_all_host_services() {
    let vm = two_services();
    let signal = CancellationToken::new();
    let mut imports = service_imports(service_grants());
    imports.bind_capability_revocation(RuntimeCapability::VmDispatch, signal.clone(), "host-dispatch").unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    signal.cancel();
    for name in ["read", "compute"] {
        revoked(instance.call_export(name, &[I32(2)]).unwrap_err(), RuntimeCapability::VmDispatch, name);
    }
}

#[test]
fn an_already_revoked_required_service_prevents_linking_before_startup() {
    let vm = vm(true);
    let signal = CancellationToken::new();
    let mut imports = imports(&CancellationToken::new(), |_, _| panic!("revoked startup callback"));
    signal.cancel();
    imports.bind_capability_revocation(RuntimeCapability::Builtin, signal.clone(), "builtin-authority").unwrap();
    signal.reset();
    revoked(vm.instantiate_with_imports(imports).unwrap_err(), RuntimeCapability::Builtin, "step");
}

#[test]
fn an_unused_revocation_signal_neither_grants_nor_blocks_other_services() {
    let vm = two_services();
    let signal = CancellationToken::new();
    signal.cancel();
    let mut imports = service_imports(service_grants());
    imports.bind_capability_revocation(RuntimeCapability::NetworkEgress, signal, "unused-network").unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(instance.call_export("read", &[I32(2)]).unwrap().results, [I32(42)]);
    assert_eq!(instance.call_export("compute", &[I32(3)]).unwrap().results, [I32(43)]);
}

#[test]
fn binding_a_signal_cannot_grant_an_absent_capability_or_replace_an_old_signal() {
    let vm = two_services();
    let signal = CancellationToken::new();
    let mut imports = service_imports(grants()); // FsRead was never granted.
    imports.bind_capability_revocation(RuntimeCapability::FsRead, signal.clone(), "missing-grant").unwrap();
    revoked(vm.instantiate_with_imports(imports).unwrap_err(), RuntimeCapability::FsRead, "read");

    let mut imports = service_imports(service_grants());
    imports.bind_capability_revocation(RuntimeCapability::FsRead, signal.clone(), "original").unwrap();
    assert_eq!(imports.bind_capability_revocation(RuntimeCapability::FsRead, CancellationToken::new(), "replacement"),
        Err(WasmHostError::CapabilityRevocationAlreadyBound { capability: RuntimeCapability::FsRead }));
    signal.cancel();
    signal.reset();
    revoked(vm.instantiate_with_imports(imports).unwrap_err(), RuntimeCapability::FsRead, "read");
}

#[test]
fn in_callback_service_revocation_latches_buffer_and_result_refusal() {
    let vm = vm(false);
    let signal = CancellationToken::new();
    let callback_signal = signal.clone();
    let mut imports = imports(&CancellationToken::new(), move |caller, _| {
        caller.write_memory(0, &[10, 20, 30, 40])?;
        callback_signal.cancel();
        callback_signal.reset();
        revoked(caller.write_memory(0, &[99; 4]).unwrap_err(), RuntimeCapability::Builtin, "step");
        revoked(caller.read_memory(8, 3).unwrap_err(), RuntimeCapability::Builtin, "step");
        revoked(caller.charge_work(0).unwrap_err(), RuntimeCapability::Builtin, "step");
        Ok(vec![I32(99)]) // Deliberate error swallowing must not resume the guest.
    });
    imports.bind_capability_revocation(RuntimeCapability::Builtin, signal, "live-builtin").unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    revoked(instance.call_export("direct", &[I32(1)]).unwrap_err(), RuntimeCapability::Builtin, "step");
    assert_eq!(&instance.memory_export("m").unwrap()[..8], &[10, 20, 30, 40, 0, 0, 0, 0]);
    revoked(instance.call_export("indirect", &[I32(1)]).unwrap_err(), RuntimeCapability::Builtin, "step");
}

#[test]
fn post_callback_service_revocation_is_checked_even_without_a_provider_poll() {
    let vm = vm(false);
    let signal = CancellationToken::new();
    let callback_signal = signal.clone();
    let mut imports = imports(&CancellationToken::new(), move |_, _| {
        callback_signal.cancel();
        callback_signal.reset();
        Ok(vec![I32(99)])
    });
    imports.bind_capability_revocation(RuntimeCapability::Builtin, signal, "live-builtin").unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    revoked(instance.call_export("direct", &[I32(1)]).unwrap_err(), RuntimeCapability::Builtin, "step");
    assert_eq!(&instance.memory_export("m").unwrap()[4..8], &[0; 4]);
}

#[test]
fn shared_service_revocation_reaches_every_existing_instance_after_reset() {
    let vm = two_services();
    let signal = CancellationToken::new();
    let build_imports = || {
        let mut imports = service_imports(service_grants());
        imports.bind_capability_revocation(RuntimeCapability::FsRead, signal.clone(), "shared-read").unwrap();
        imports
    };
    let mut a = vm.instantiate_with_imports(build_imports()).unwrap();
    let mut b = vm.instantiate_with_imports(build_imports()).unwrap();
    signal.cancel();
    signal.reset();
    for instance in [&mut a, &mut b] {
        revoked(instance.call_export("read", &[I32(2)]).unwrap_err(), RuntimeCapability::FsRead, "read");
        assert_eq!(instance.call_export("compute", &[I32(2)]).unwrap().results, [I32(42)]);
    }
    // A new authorized scope after reset is independent of the drained ones.
    let mut fresh = vm.instantiate_with_imports(build_imports()).unwrap();
    assert_eq!(fresh.call_export("read", &[I32(2)]).unwrap().results, [I32(42)]);
    revoked(a.call_export("read", &[I32(2)]).unwrap_err(), RuntimeCapability::FsRead, "read");
}

#[test]
fn every_required_capability_is_observed_at_provider_checkpoints() {
    for capability in [RuntimeCapability::Builtin, RuntimeCapability::FsRead] {
        let vm = vm(false);
        let signal = CancellationToken::new();
        let callback_signal = signal.clone();
        let mut imports = WasmHostImports::new(service_grants());
        imports.define("env", "step", WasmFunctionSignature {
            params: vec![WasmValueType::I32], results: vec![WasmValueType::I32],
        }, [RuntimeCapability::Builtin, RuntimeCapability::FsRead].into(), 3, move |caller, _| {
            callback_signal.cancel();
            revoked(caller.checkpoint().unwrap_err(), capability, "step");
            Ok(vec![I32(99)])
        }).unwrap();
        imports.bind_capability_revocation(capability, signal, "multi-capability").unwrap();
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        revoked(instance.call_export("direct", &[I32(1)]).unwrap_err(), capability, "step");
        assert_eq!(&instance.memory_export("m").unwrap()[4..8], &[0; 4]);
    }
}

#[test]
fn whole_scope_cancellation_still_covers_services_without_revocation_subscriptions() {
    let vm = two_services();
    let whole_scope = CancellationToken::new();
    let read_scope = CancellationToken::new();
    let mut imports = service_imports(service_grants());
    imports.bind_cancellation(whole_scope.clone(), "whole-scope").unwrap();
    imports.bind_capability_revocation(RuntimeCapability::FsRead, read_scope.clone(), "read-only").unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    read_scope.cancel();
    revoked(instance.call_export("read", &[I32(1)]).unwrap_err(), RuntimeCapability::FsRead, "read");
    assert_eq!(instance.call_export("compute", &[I32(2)]).unwrap().results, [I32(42)]);
    whole_scope.cancel();
    cancelled(instance.call_export("compute", &[I32(2)]).unwrap_err());
    cancelled(instance.call_export("read", &[I32(2)]).unwrap_err());
}

#[test]
fn a_successful_tape_cannot_regrant_a_live_revoked_service() {
    use frankenengine_engine::wasm_runtime_lane::host_replay::{WasmHostTraceError, WasmHostTraceLimits};
    let vm = two_services();
    let mut bindings = service_imports(service_grants());
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    vm.instantiate_with_imports(bindings).unwrap().call_export("read", &[I32(2)]).unwrap();
    let signal = CancellationToken::new();
    let mut bindings = service_imports(service_grants());
    bindings.bind_capability_revocation(RuntimeCapability::FsRead, signal.clone(), "read-replay").unwrap();
    let replay = bindings.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    let mut replayed = vm.instantiate_with_imports(bindings).unwrap();
    signal.cancel();
    signal.reset();
    revoked(replayed.call_export("read", &[I32(2)]).unwrap_err(), RuntimeCapability::FsRead, "read");
    assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Incomplete { remaining: 1 }));
}

#[test]
fn service_revocation_on_return_retains_a_replayable_effect_record() {
    use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
    let vm = vm(false);
    let signal = CancellationToken::new();
    let provider_signal = signal.clone();
    let mut bindings = imports(&CancellationToken::new(), move |caller, _| {
        caller.write_memory(0, &[4, 3, 2, 1])?;
        provider_signal.cancel();
        provider_signal.reset();
        Ok(vec![I32(99)])
    });
    bindings.bind_capability_revocation(RuntimeCapability::Builtin, signal, "record-builtin").unwrap();
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    let mut live = vm.instantiate_with_imports(bindings).unwrap();
    let expected = live.call_export("host", &[I32(2)]).unwrap_err();
    revoked(expected.clone(), RuntimeCapability::Builtin, "step");
    let tape = recording.snapshot().unwrap();
    assert_eq!(tape.call_count(), 1);
    let mut bindings = imports(&CancellationToken::new(), |_, _| panic!("replay invoked provider"));
    let replay = bindings.replay_calls(tape, WasmHostTraceLimits::default()).unwrap();
    let mut replayed = vm.instantiate_with_imports(bindings).unwrap();
    assert_eq!(replayed.call_export("host", &[I32(2)]).unwrap_err(), expected);
    assert_eq!(replayed.memory_export("m"), live.memory_export("m"));
    replay.verify_complete().unwrap();
}
