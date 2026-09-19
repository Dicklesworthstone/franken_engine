#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::future::Future;
use std::num::NonZeroU64;
use std::sync::{Arc, Barrier, atomic::{AtomicUsize, Ordering}};
use std::task::{Context, Poll, Wake, Waker};

use frankenengine_engine::capability::RuntimeCapability::{Builtin, VmDispatch};
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::memory_pool::{
    WASM_MEMORY_POOL_MAX_DEPTH, WasmMemoryPool,
};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmCallStep, WasmHostCaller, WasmHostError, WasmHostImports,
    WasmNumericLimits, WasmNumericVm, WasmNumericVmError, WasmStateError,
};
use WasmBoundaryValue::I32;

type HostResult = Result<Vec<WasmBoundaryValue>, WasmNumericVmError>;
fn revoked() -> WasmNumericVmError { WasmHostError::MemoryPoolRevoked.into() }
fn work(n: u64) -> NonZeroU64 { NonZeroU64::new(n).unwrap() }
fn leb(mut n: u32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 127) as u8; n >>= 7;
        out.push(byte | if n == 0 { 0 } else { 128 });
        if n == 0 { return out; }
    }
}
fn section(out: &mut Vec<u8>, id: u8, payload: &[u8]) {
    out.push(id); out.extend(leb(payload.len() as u32)); out.extend(payload);
}
fn name(out: &mut Vec<u8>, value: &str) {
    out.extend(leb(value.len() as u32)); out.extend(value.as_bytes());
}

// Real binary modules, shared by raw, resolved, cooperative and replay tests.
fn program(host: bool, start: bool, memory: Option<(u32, u32)>) -> Vec<u8> {
    let mut out = b"\0asm\x01\0\0\0".to_vec();
    section(&mut out, 1, &[2, 0x60, 0, 0, 0x60, 1, 0x7f, 1, 0x7f]);
    if host { section(&mut out, 2, &[1, 1, b'h', 1, b'f', 0, 0]); }
    section(&mut out, 3, &[5, 0, 0, 1, 0, 0]);
    section(&mut out, 4, &[1, 0x70, 0, 1]);
    if let Some((minimum, maximum)) = memory {
        let mut declaration = vec![1, 1];
        declaration.extend(leb(minimum)); declaration.extend(leb(maximum));
        section(&mut out, 5, &declaration);
    }
    let base = u8::from(host);
    let mut exports = vec![6 + u8::from(memory.is_some()) + u8::from(host)];
    for (export, index) in [("run", base), ("spin", base + 1), ("grow", base + 2),
        ("indirect", base + 3), ("tail", base + 4), ("_start", base)] {
        name(&mut exports, export); exports.extend([0, index]);
    }
    if memory.is_some() { name(&mut exports, "memory"); exports.extend([2, 0]); }
    if host { name(&mut exports, "host"); exports.extend([0, 0]); }
    section(&mut out, 7, &exports);
    if start { section(&mut out, 8, &[base]); }
    section(&mut out, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
    let mut run = vec![0];
    if memory.is_some_and(|(minimum, _)| minimum > 0) {
        run.extend([0x41, 0, 0x41, 7, 0x36, 2, 0]);
    }
    if host { run.extend([0x10, 0]); }
    if memory.is_some_and(|(minimum, _)| minimum > 0) {
        run.extend([0x41, 4, 0x41, 9, 0x36, 2, 0]);
    }
    run.push(0x0b);
    let bodies = [run,
        vec![0, 0x03, 0x40, 0x0c, 0, 0x0b, 0x0b],
        if memory.is_some() { vec![0, 0x20, 0, 0x40, 0, 0x0b] }
            else { vec![0, 0x41, 0x7f, 0x0b] },
        vec![0, 0x41, 0, 0x11, 0, 0, 0x0b],
        vec![0, 0x12, 0, 0x0b],
    ];
    let mut code = vec![bodies.len() as u8];
    for body in bodies { code.extend(leb(body.len() as u32)); code.extend(body); }
    section(&mut out, 10, &code);
    out
}
fn vm(host: bool, start: bool) -> WasmNumericVm {
    WasmNumericVm::parse(&program(host, start, Some((1, 2))), WasmNumericLimits::default()).unwrap()
}
fn imports(pool: &WasmMemoryPool) -> WasmHostImports {
    let mut imports = WasmHostImports::new(BTreeSet::from([Builtin, VmDispatch]));
    imports.bind_memory_pool(pool.clone()).unwrap();
    imports
}
fn provider<F>(pool: &WasmMemoryPool, callback: F) -> WasmHostImports
where F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue]) -> HostResult + Send + Sync + 'static {
    let mut imports = imports(pool);
    imports.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![] },
        BTreeSet::from([Builtin]), 1, callback).unwrap();
    imports
}
#[derive(Default)]
struct WakeCount(AtomicUsize);
impl Wake for WakeCount {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}

#[test]
fn revocation_is_permanent_inherited_and_cannot_refund_or_widen_capacity() {
    let root = WasmMemoryPool::new(8);
    let a = root.partition(4).unwrap();
    let b = root.partition(4).unwrap();
    let grandchild = a.partition(2).unwrap();
    a.clone().revoke(); a.revoke();
    assert!(a.is_revoked()); assert!(grandchild.is_revoked());
    assert!(!root.is_revoked()); assert!(!b.is_revoked());
    assert!(matches!(a.partition(0), Err(WasmHostError::MemoryPoolRevoked)));
    assert!(matches!(grandchild.partition(0), Err(WasmHostError::MemoryPoolRevoked)));
    assert_eq!(root.reserved_pages(), 8); assert_eq!(a.reserved_pages(), 2);
    drop(a);
    assert_eq!(root.reserved_pages(), 8); // Descendant still owns a's allotment.
    drop(grandchild);
    assert_eq!(root.reserved_pages(), 4);
    root.revoke();
    assert!(b.is_revoked()); assert_eq!(root.reserved_pages(), 4);
    drop(b); assert_eq!(root.available_pages(), 8);
    assert!(matches!(root.partition(1), Err(WasmHostError::MemoryPoolRevoked)));
}

#[test]
fn nesting_is_bounded_before_reservation_even_for_zero_page_partitions() {
    let root = WasmMemoryPool::new(1);
    let mut deepest = root.clone();
    for _ in 0..WASM_MEMORY_POOL_MAX_DEPTH { deepest = deepest.partition(1).unwrap(); }
    assert_eq!(deepest.reserved_pages(), 0);
    for pages in [0, 1] {
        assert!(matches!(deepest.partition(pages),
            Err(WasmHostError::MemoryPoolDepthExceeded { max }) if max == WASM_MEMORY_POOL_MAX_DEPTH));
        assert_eq!(deepest.reserved_pages(), 0);
    }
    root.revoke(); assert!(deepest.is_revoked());
    drop(deepest); assert_eq!(root.reserved_pages(), 0);
}

#[test]
fn revoked_admission_precedes_allocation_and_includes_memoryless_modules() {
    let root = WasmMemoryPool::new(0);
    root.revoke();
    for memory in [None, Some((0, 0)), Some((1, 2))] {
        let vm = WasmNumericVm::parse(&program(false, false, memory),
            WasmNumericLimits { max_memory_pages: 0, ..WasmNumericLimits::default() }).unwrap();
        assert!(matches!(vm.instantiate_with_imports(imports(&root)), Err(error) if error == revoked()));
        assert_eq!(root.reserved_pages(), 0);
    }
    let mut bindings = imports(&root);
    assert_eq!(bindings.bind_memory_pool(WasmMemoryPool::new(10)), Err(WasmHostError::MemoryPoolAlreadyBound));
}

#[test]
fn existing_guest_state_stays_inspectable_and_charged_but_cannot_execute() {
    let vm = vm(false, false);
    let pool = WasmMemoryPool::new(2);
    let mut instance = vm.instantiate_with_imports(imports(&pool)).unwrap();
    instance.call_export("run", &[]).unwrap();
    let before = instance.memory_export("memory").unwrap().to_vec();
    pool.revoke();
    for export in ["run", "spin", "indirect", "tail"] {
        assert_eq!(instance.call_export(export, &[]).unwrap_err(), revoked());
    }
    assert_eq!(instance.call_export("grow", &[I32(1)]).unwrap_err(), revoked());
    assert_eq!(instance.memory_export("memory").unwrap(), before);
    assert_eq!(pool.reserved_pages(), 2);
    drop(instance); assert_eq!(pool.reserved_pages(), 0);
}

#[test]
fn child_revocation_stops_existing_descendants_not_ancestors_or_siblings() {
    let vm = vm(false, false);
    let root = WasmMemoryPool::new(8);
    let a = root.partition(4).unwrap(); let b = root.partition(2).unwrap();
    let nested = a.partition(2).unwrap();
    let mut parent_guest = vm.instantiate_with_imports(imports(&root)).unwrap();
    let mut a_guest = vm.instantiate_with_imports(imports(&nested)).unwrap();
    let mut b_guest = vm.instantiate_with_imports(imports(&b)).unwrap();
    a.revoke();
    assert_eq!(a_guest.call_export("run", &[]).unwrap_err(), revoked());
    parent_guest.call_export("run", &[]).unwrap(); b_guest.call_export("run", &[]).unwrap();
    root.revoke();
    assert_eq!(b_guest.call_export("run", &[]).unwrap_err(), revoked());
    assert_eq!(parent_guest.call_export("run", &[]).unwrap_err(), revoked());
}

#[test]
fn direct_indirect_tail_and_exported_imports_cannot_bypass_revocation() {
    let vm = vm(true, false);
    for export in ["run", "indirect", "tail", "host"] {
        let pool = WasmMemoryPool::new(2); let signal = pool.clone();
        let calls = Arc::new(AtomicUsize::new(0)); let seen = calls.clone();
        let bindings = provider(&pool, move |_, _| {
            seen.fetch_add(1, Ordering::SeqCst); signal.revoke(); Ok(vec![])
        });
        let mut instance = vm.instantiate_with_imports(bindings).unwrap();
        assert_eq!(instance.call_export(export, &[]).unwrap_err(), revoked());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(&instance.memory_export("memory").unwrap()[4..8], &[0; 4]);
        assert_eq!(instance.call_export("host", &[]).unwrap_err(), revoked());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn ignored_revocation_blocks_later_buffers_work_and_exit_but_retains_prior_write() {
    let vm = vm(true, false);
    let pool = WasmMemoryPool::new(2); let signal = pool.clone();
    let bindings = provider(&pool, move |caller, _| {
        caller.write_memory(0, b"kept")?;
        signal.revoke();
        assert_eq!(caller.checkpoint().unwrap_err(), revoked());
        assert_eq!(caller.read_memory(0, 1).unwrap_err(), revoked());
        assert_eq!(caller.write_memory(0, b"lost").unwrap_err(), revoked());
        assert_eq!(caller.charge_work(0).unwrap_err(), revoked());
        assert_eq!(caller.exit(7), revoked());
        Ok(vec![]) // Deliberately swallow every refusal.
    });
    let mut instance = vm.instantiate_with_imports(bindings).unwrap();
    assert_eq!(instance.call_export("host", &[]).unwrap_err(), revoked());
    assert_eq!(&instance.memory_export("memory").unwrap()[..4], b"kept");
    assert_eq!(instance.process_exit_status(), None);
    assert_eq!(pool.reserved_pages(), 2);
}

#[test]
fn prior_budget_and_buffer_faults_keep_precedence_over_later_subtree_revocation() {
    let vm = vm(true, false);
    for budget in [false, true] {
        let pool = WasmMemoryPool::new(2); let signal = pool.clone();
        let bindings = provider(&pool, move |caller, _| {
            let first = if budget { caller.charge_work(u64::MAX).unwrap_err() }
                else { caller.write_memory(u32::MAX, b"bad").unwrap_err() };
            signal.revoke();
            assert_eq!(caller.write_memory(0, b"bad").unwrap_err(), first);
            assert_eq!(caller.exit(8), first);
            Ok(vec![])
        });
        let mut instance = vm.instantiate_with_imports(bindings).unwrap();
        let error = instance.call_export("host", &[]).unwrap_err();
        if budget { assert!(matches!(error, WasmNumericVmError::InstructionBudgetExceeded { .. })); }
        else { assert!(matches!(error, WasmNumericVmError::State(WasmStateError::MemoryOutOfBounds { .. }))); }
        assert_eq!(instance.process_exit_status(), None);
        assert_eq!(instance.call_export("run", &[]).unwrap_err(), revoked());
        assert_eq!(&instance.memory_export("memory").unwrap()[..4], &[0; 4]);
    }
}

#[test]
fn explicit_execution_cancellation_and_established_exit_keep_their_precedence() {
    let vm = vm(true, false);
    let pool = WasmMemoryPool::new(2);
    let token = CancellationToken::new();
    let mut bindings = imports(&pool);
    bindings.bind_execution_cancellation(token.clone(), "cancel-first").unwrap();
    let instance = WasmNumericVm::parse(&program(false, false, Some((1, 2))),
        WasmNumericLimits::default()).unwrap();
    // Own this hostless VM for longer than its instance.
    let mut guest = instance.instantiate_with_imports(bindings).unwrap();
    token.cancel(); pool.revoke();
    assert!(matches!(guest.call_export("run", &[]),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::ExecutionCancelled)))));
    drop(guest);
    let pool = WasmMemoryPool::new(2); let signal = pool.clone();
    let mut guest = vm.instantiate_with_imports(provider(&pool, move |caller, _| {
        let exit = caller.exit(u32::MAX); signal.revoke(); Err(exit)
    })).unwrap();
    assert_eq!(guest.call_export("host", &[]).unwrap_err(), WasmHostError::ProcessExit { code: u32::MAX }.into());
    assert_eq!(guest.process_exit_status(), Some(u32::MAX));
    assert_eq!(pool.reserved_pages(), 2);
}

#[test]
fn failed_start_releases_memory_but_retains_completed_recording() {
    let vm = vm(true, true);
    let pool = WasmMemoryPool::new(2); let signal = pool.clone();
    let mut bindings = provider(&pool, move |caller, _| {
        caller.write_memory(0, b"kept")?; signal.revoke(); Ok(vec![])
    });
    let observer = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    assert!(matches!(vm.instantiate_with_imports(bindings), Err(error) if error == revoked()));
    assert_eq!(pool.reserved_pages(), 0);
    assert!(observer.snapshot().is_ok());
}

#[test]
fn cooperative_start_cleans_up_on_revocation_and_never_repeats_effects() {
    let vm = vm(false, true);
    let root = WasmMemoryPool::new(2); let child = root.partition(2).unwrap();
    let wake = Arc::new(WakeCount::default()); let waker = Waker::from(wake.clone());
    let mut cx = Context::from_waker(&waker);
    let mut future = Box::pin(vm.instantiate_cooperatively_with_imports(imports(&child), work(1)));
    assert_eq!(child.reserved_pages(), 0);
    assert!(future.as_mut().poll(&mut cx).is_pending());
    assert_eq!(child.reserved_pages(), 2); assert_eq!(wake.0.load(Ordering::SeqCst), 1);
    root.revoke();
    assert!(matches!(future.as_mut().poll(&mut cx), Poll::Ready(Err(error)) if error == revoked()));
    assert_eq!(child.reserved_pages(), 0); assert_eq!(root.reserved_pages(), 2);
    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
}

#[test]
fn a_suspended_call_retains_writes_and_lease_without_entering_pending_host_work() {
    let vm = vm(true, false);
    let pool = WasmMemoryPool::new(2);
    let seen = Arc::new(AtomicUsize::new(0)); let calls = seen.clone();
    let mut instance = vm.instantiate_with_imports(provider(&pool, move |_, _| {
        calls.fetch_add(1, Ordering::SeqCst); Ok(vec![])
    })).unwrap();
    let call = instance.begin_call("run", &[]).unwrap();
    let WasmCallStep::Pending(call) = call.resume(work(3)).unwrap() else { panic!("expected yield before host"); };
    pool.revoke();
    assert!(matches!(call.resume(work(100)), Err(error) if error == revoked()));
    assert_eq!(seen.load(Ordering::SeqCst), 0);
    assert_eq!(&instance.memory_export("memory").unwrap()[..4], &7_i32.to_le_bytes());
    assert_eq!(pool.reserved_pages(), 2);
    drop(instance); assert_eq!(pool.reserved_pages(), 0);
}

#[test]
fn another_thread_can_stop_a_hostless_guest_through_its_ancestor() {
    let root = WasmMemoryPool::new(2); let child = root.partition(2).unwrap();
    let barrier = Arc::new(Barrier::new(2)); let worker_ready = barrier.clone();
    let worker = std::thread::spawn(move || {
        let vm = WasmNumericVm::parse(&program(false, false, Some((1, 2))),
            WasmNumericLimits { max_instructions: 2_000_000, ..WasmNumericLimits::default() }).unwrap();
        let mut instance = vm.instantiate_with_imports(imports(&child)).unwrap();
        worker_ready.wait();
        let error = instance.call_export("spin", &[]).unwrap_err();
        assert_eq!(child.reserved_pages(), 2);
        error
    });
    barrier.wait(); root.revoke();
    assert_eq!(worker.join().unwrap(), revoked());
    assert_eq!(root.reserved_pages(), 0);
}

#[test]
fn a_successful_tape_cannot_supply_authority_to_a_revoked_live_pool() {
    let vm = vm(true, false);
    let limits = WasmHostTraceLimits::default();
    let original = WasmMemoryPool::new(2);
    let mut bindings = provider(&original, |caller, _| { caller.write_memory(0, b"tape")?; Ok(vec![]) });
    let observer = bindings.record_calls(limits).unwrap();
    let mut original_guest = vm.instantiate_with_imports(bindings).unwrap();
    original_guest.call_export("host", &[]).unwrap();
    let pool = WasmMemoryPool::new(2);
    let mut bindings = provider(&pool, |_, _| panic!("replay must not invoke providers"));
    let replay = bindings.replay_calls(observer.snapshot().unwrap(), limits).unwrap();
    let mut guest = vm.instantiate_with_imports(bindings).unwrap();
    pool.revoke();
    assert_eq!(guest.call_export("host", &[]).unwrap_err(), revoked());
    assert_eq!(&guest.memory_export("memory").unwrap()[..4], &[0; 4]);
    assert!(replay.verify_complete().is_err());
    assert_eq!(pool.reserved_pages(), 2);
}

#[test]
fn recorded_revocation_replays_its_refusal_without_revoking_an_unrelated_live_pool() {
    let vm = vm(true, false);
    let limits = WasmHostTraceLimits::default();
    let original = WasmMemoryPool::new(2); let signal = original.clone();
    let mut bindings = provider(&original, move |caller, _| {
        caller.write_memory(0, b"kept")?; signal.revoke(); Ok(vec![])
    });
    let observer = bindings.record_calls(limits).unwrap();
    let mut guest = vm.instantiate_with_imports(bindings).unwrap();
    assert_eq!(guest.call_export("host", &[]).unwrap_err(), revoked());
    let pool = WasmMemoryPool::new(2);
    let mut bindings = provider(&pool, |_, _| panic!("a tape is not a live control-plane command"));
    let replay = bindings.replay_calls(observer.snapshot().unwrap(), limits).unwrap();
    let mut replayed = vm.instantiate_with_imports(bindings).unwrap();
    assert_eq!(replayed.call_export("host", &[]).unwrap_err(), revoked());
    assert_eq!(&replayed.memory_export("memory").unwrap()[..4], b"kept");
    replay.verify_complete().unwrap();
    assert!(!pool.is_revoked());
    assert_eq!(pool.reserved_pages(), 2);
}

mod interrupted_hosts {
    use super::*;
    use std::num::NonZeroUsize;
    use std::panic::{AssertUnwindSafe, catch_unwind, panic_any};
    use frankenengine_engine::module_resolver::{
        CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
        ModuleRequest, ResolutionContext, wasm_module_required_capabilities,
    };
    use frankenengine_engine::wasm_runtime_lane::{WasmNativeLoadError, WasmNativeModule};
    use frankenengine_engine::wasm_runtime_lane::scheduler::{WasmNativeScheduler, WasmTaskOutcome};

    fn interrupted() -> WasmNumericVmError { WasmHostError::HostCallInterrupted.into() }
    fn context() -> ResolutionContext { ResolutionContext::new("unwind", "contain", "current") }
    fn policy() -> CapabilityPolicyHook {
        let mut capabilities = wasm_module_required_capabilities();
        capabilities.insert(Builtin);
        CapabilityPolicyHook::new(capabilities)
    }
    fn module(host: bool, start: bool) -> WasmNativeModule {
        let limits = WasmNumericLimits::default();
        let mut resolver = DeterministicModuleResolver::new("/app");
        let definition = ModuleDefinition::wasm_binary(&program(host, start, Some((1, 2))), &limits)
            .unwrap().require_capability(Builtin);
        resolver.register_workspace_module("/app/guest.wasm", definition).unwrap();
        resolver.load_wasm(&ModuleRequest::new("/app/guest.wasm", ImportStyle::Import),
            &context(), &policy(), limits).unwrap()
    }

    #[test]
    fn caught_native_panics_keep_payload_and_retire_every_reentry_surface() {
        let vm = vm(true, false);
        for export in ["run", "indirect", "tail", "host"] {
            let pool = WasmMemoryPool::new(2);
            let count = Arc::new(AtomicUsize::new(0)); let calls = count.clone();
            let mut instance = vm.instantiate_with_imports(provider(&pool, move |caller, _| {
                calls.fetch_add(1, Ordering::SeqCst);
                caller.write_memory(8, b"kept")?;
                panic_any("provider exploded");
            })).unwrap();
            let payload = catch_unwind(AssertUnwindSafe(|| instance.call_export(export, &[]))).unwrap_err();
            assert_eq!(payload.downcast_ref::<&str>(), Some(&"provider exploded"));
            let before = instance.memory_export("memory").unwrap().to_vec();
            assert_eq!(&before[8..12], b"kept");
            assert_eq!(&before[4..8], &[0; 4]); // Interrupted caller never resumed.
            for next in ["run", "indirect", "tail", "host", "spin"] {
                assert_eq!(instance.call_export(next, &[]).unwrap_err(), interrupted());
            }
            assert_eq!(instance.call_export("grow", &[I32(1)]).unwrap_err(), interrupted());
            let sliced = instance.begin_call("grow", &[I32(1)])
                .and_then(|call| call.resume(work(100)));
            assert!(matches!(sliced, Err(error) if error == interrupted()));
            assert_eq!(count.load(Ordering::SeqCst), 1);
            assert_eq!(instance.memory_export("memory").unwrap(), before);
            assert!(!pool.is_revoked()); assert_eq!(pool.reserved_pages(), 2);
            drop(instance); assert_eq!(pool.reserved_pages(), 0);
        }
    }

    #[test]
    fn interrupted_instance_does_not_revoke_siblings_or_release_live_memory() {
        let vm = vm(true, false);
        let root = WasmMemoryPool::new(4);
        let tenant = root.partition(4).unwrap();
        let mut broken = vm.instantiate_with_imports(provider(&tenant, |caller, _| {
            caller.write_memory(0, b"kept")?; panic!("provider failed");
        })).unwrap();
        let mut healthy = vm.instantiate_with_imports(provider(&tenant, |_, _| Ok(vec![]))).unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| broken.call_export("host", &[]))).is_err());
        assert!(!root.is_revoked()); assert!(!tenant.is_revoked());
        assert_eq!(tenant.reserved_pages(), 4);
        healthy.call_export("run", &[]).unwrap();
        assert_eq!(&healthy.memory_export("memory").unwrap()[4..8], &9_i32.to_le_bytes());
        assert_eq!(broken.call_export("run", &[]).unwrap_err(), interrupted());
        drop(broken); assert_eq!(tenant.reserved_pages(), 2);
        let replacement = vm.instantiate_with_imports(provider(&tenant, |_, _| Ok(vec![]))).unwrap();
        drop(healthy); drop(replacement);
        assert_eq!(tenant.reserved_pages(), 0); assert_eq!(root.reserved_pages(), 4);
        drop(tenant); assert_eq!(root.reserved_pages(), 0);
    }

    #[test]
    fn ordinary_returned_faults_are_not_interrupted_host_boundaries() {
        let vm = vm(true, false);
        for kind in 0..3 {
            let pool = WasmMemoryPool::new(2);
            let mut entered = false;
            let mut instance = vm.instantiate_with_imports(provider(&pool, move |caller, _| {
                if !entered {
                    entered = true;
                    return match kind {
                        0 => Err(WasmHostError::trap("ordinary failure").into()),
                        1 => caller.write_memory(u32::MAX, b"bad").map(|()| vec![]),
                        _ => caller.charge_work(u64::MAX).map(|()| vec![]),
                    };
                }
                caller.write_memory(8, b"next")?; Ok(vec![])
            })).unwrap();
            let error = instance.call_export("host", &[]).unwrap_err();
            assert_ne!(error, interrupted());
            match kind {
                0 => assert!(matches!(error, WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trap { .. })))),
                1 => assert!(matches!(error, WasmNumericVmError::State(WasmStateError::MemoryOutOfBounds { .. }))),
                _ => assert!(matches!(error, WasmNumericVmError::InstructionBudgetExceeded { .. })),
            }
            instance.call_export("host", &[]).unwrap();
            assert_eq!(&instance.memory_export("memory").unwrap()[8..12], b"next");
            assert_eq!(instance.call_export("grow", &[I32(1)]).unwrap().results, [I32(1)]);
            assert_eq!(pool.reserved_pages(), 2);
        }
    }

    #[test]
    fn trusted_provider_internal_recovery_is_not_engine_boundary_interruption() {
        let vm = vm(true, false);
        let pool = WasmMemoryPool::new(2);
        let mut instance = vm.instantiate_with_imports(provider(&pool, |caller, _| {
            assert!(catch_unwind(|| panic!("caught inside trusted provider")).is_err());
            caller.write_memory(8, b"safe")?; Ok(vec![])
        })).unwrap();
        for _ in 0..2 { instance.call_export("run", &[]).unwrap(); }
        assert_eq!(&instance.memory_export("memory").unwrap()[8..12], b"safe");
        assert_eq!(&instance.memory_export("memory").unwrap()[4..8], &9_i32.to_le_bytes());
    }

    #[test]
    fn cooperative_unwind_cannot_leave_a_resumable_instance() {
        let vm = vm(true, false);
        let pool = WasmMemoryPool::new(2);
        let mut instance = vm.instantiate_with_imports(provider(&pool, |_, _| panic!("sliced host"))).unwrap();
        let call = instance.begin_call("run", &[]).unwrap();
        let WasmCallStep::Pending(call) = call.resume(work(3)).unwrap() else { panic!("missing yield"); };
        assert!(catch_unwind(AssertUnwindSafe(|| call.resume(work(100)))).is_err());
        assert_eq!(&instance.memory_export("memory").unwrap()[..4], &7_i32.to_le_bytes());
        assert_eq!(&instance.memory_export("memory").unwrap()[4..8], &[0; 4]);
        assert_eq!(instance.call_export("run", &[]).unwrap_err(), interrupted());
        assert_eq!(pool.reserved_pages(), 2);
    }

    #[test]
    fn incomplete_recording_cannot_be_escaped_by_guest_only_reentry() {
        let vm = vm(true, false);
        let pool = WasmMemoryPool::new(2);
        let mut bindings = provider(&pool, |caller, _| {
            caller.write_memory(0, b"kept")?; panic!("recorded provider failed");
        });
        let observer = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
        let mut instance = vm.instantiate_with_imports(bindings).unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| instance.call_export("host", &[]))).is_err());
        assert!(observer.snapshot().is_err());
        assert_eq!(instance.call_export("grow", &[I32(1)]).unwrap_err(), interrupted());
        assert_eq!(instance.memory_export("memory").unwrap().len(), 65_536);
        assert_eq!(&instance.memory_export("memory").unwrap()[..4], b"kept");
        drop(instance); assert_eq!(pool.reserved_pages(), 0);
        assert!(observer.snapshot().is_err());
    }

    #[test]
    fn startup_unwind_never_publishes_state_or_repeats_a_provider_on_repoll() {
        let vm = vm(true, true);
        let pool = WasmMemoryPool::new(2);
        assert!(catch_unwind(AssertUnwindSafe(|| {
            vm.instantiate_with_imports(provider(&pool, |_, _| panic!("startup")))
        })).is_err());
        assert_eq!(pool.reserved_pages(), 0);
        let calls = Arc::new(AtomicUsize::new(0)); let entered = calls.clone();
        let mut future = Box::pin(vm.instantiate_cooperatively_with_imports(
            provider(&pool, move |_, _| { entered.fetch_add(1, Ordering::SeqCst); panic!("future startup"); }), work(100)));
        let waker = Waker::from(Arc::new(WakeCount::default()));
        let mut cx = Context::from_waker(&waker);
        assert!(catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(&mut cx))).is_err());
        assert_eq!(pool.reserved_pages(), 2); // Future still owns unpublished memory.
        assert!(catch_unwind(AssertUnwindSafe(|| future.as_mut().poll(&mut cx))).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        drop(future); assert_eq!(pool.reserved_pages(), 0);
        assert!(!pool.is_revoked());
    }

    #[test]
    fn exit_then_unwind_does_not_masquerade_as_successful_exit_on_reentry() {
        let vm = vm(true, false);
        let pool = WasmMemoryPool::new(2);
        let mut instance = vm.instantiate_with_imports(provider(&pool, |caller, _| {
            assert_eq!(caller.exit(7), WasmHostError::ProcessExit { code: 7 }.into());
            panic!("provider panicked after requesting exit");
        })).unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| instance.call_export("host", &[]))).is_err());
        assert_eq!(instance.process_exit_status(), Some(7)); // Historical observation, not success.
        assert_eq!(instance.call_export("host", &[]).unwrap_err(), interrupted());
        pool.revoke(); // Cannot hide the incomplete native boundary either.
        assert_eq!(instance.call_export("run", &[]).unwrap_err(), interrupted());
        assert_eq!(pool.reserved_pages(), 2);
    }

    #[test]
    fn resolved_scheduler_retires_panicked_work_not_healthy_sibling_instances() {
        let module = module(true, false);
        let pool = WasmMemoryPool::new(4);
        let context = context(); let policy = policy();
        let mut broken = module.instantiate_with_imports(&context, &policy,
            provider(&pool, |caller, _| { caller.write_memory(8, b"kept")?; panic!("scheduled host"); })).unwrap();
        let mut healthy = module.instantiate_with_imports(&context, &policy, provider(&pool, |_, _| Ok(vec![]))).unwrap();
        let mut scheduler = WasmNativeScheduler::new(NonZeroUsize::new(2).unwrap());
        scheduler.submit(broken.begin_call("run", &[], &context, &policy).unwrap()).unwrap();
        let next = scheduler.submit(healthy.begin_call("run", &[], &context, &policy).unwrap()).unwrap();
        assert!(catch_unwind(AssertUnwindSafe(|| scheduler.run_next(work(100), &context, &policy))).is_err());
        assert_eq!(scheduler.next_task(), Some(next.id()));
        assert_eq!(pool.reserved_pages(), 4); assert!(!pool.is_revoked());
        assert!(matches!(scheduler.run_next(work(100), &context, &policy).unwrap().outcome, WasmTaskOutcome::Complete(_)));
        assert!(scheduler.is_empty()); drop(scheduler);
        assert!(matches!(broken.call_export("grow", &[I32(1)], &context, &policy),
            Err(WasmNativeLoadError::Execution(error)) if error == interrupted()));
        assert_eq!(&broken.memory_export("memory", &context, &policy).unwrap().unwrap()[8..12], b"kept");
        healthy.call_export("run", &[], &context, &policy).unwrap();
        drop(broken); drop(healthy); assert_eq!(pool.reserved_pages(), 0);
    }

    #[test]
    fn owned_command_unwind_releases_private_state_without_revoking_tenant() {
        let context = context(); let policy = policy();
        for start in [false, true] {
            let module = module(true, start);
            let pool = WasmMemoryPool::new(2);
            let mut task = module.prepare_command(provider(&pool, |_, _| panic!("command provider")));
            let result = catch_unwind(AssertUnwindSafe(|| {
                for _ in 0..2 {
                    match task.resume(work(100), &context, &policy).unwrap() {
                        frankenengine_engine::wasm_runtime_lane::command::WasmCommandStep::Pending(pending) => task = pending,
                        frankenengine_engine::wasm_runtime_lane::command::WasmCommandStep::Complete(_) => panic!("unexpected command success"),
                    }
                }
            }));
            let payload = result.unwrap_err();
            assert_eq!(payload.downcast_ref::<&str>(), Some(&"command provider"));
            assert_eq!(pool.reserved_pages(), 0); assert!(!pool.is_revoked());
            let replacement = module.prepare_command(provider(&pool, |_, _| Ok(vec![])));
            assert!(matches!(replacement.resume(work(100), &context, &policy).unwrap(),
                frankenengine_engine::wasm_runtime_lane::command::WasmCommandStep::Pending(_)));
            assert_eq!(pool.reserved_pages(), 0); // Discarded pending replacement releases its lease.
        }
    }

    #[test]
    fn interrupted_host_without_pool_memory_or_recording_is_still_terminal() {
        let vm = WasmNumericVm::parse(&program(true, false, None), WasmNumericLimits::default()).unwrap();
        let mut bindings = WasmHostImports::new(BTreeSet::from([Builtin, VmDispatch]));
        bindings.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![] },
            BTreeSet::from([Builtin]), 1, |_, _| panic!("unpooled host")).unwrap();
        let mut instance = vm.instantiate_with_imports(bindings).unwrap();
        let payload = catch_unwind(AssertUnwindSafe(|| instance.call_export("host", &[]))).unwrap_err();
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"unpooled host"));
        assert!(instance.memory_export("memory").is_none());
        assert_eq!(instance.call_export("grow", &[I32(0)]).unwrap_err(), interrupted());
        assert_eq!(instance.call_export("spin", &[]).unwrap_err(), interrupted());
    }

    #[test]
    fn subtree_revocation_retires_all_three_task_kinds_without_stopping_a_sibling() {
        use frankenengine_engine::wasm_runtime_lane::command::WasmCommandStep;
        use frankenengine_engine::wasm_runtime_lane::scheduler::WasmStartupStep;
        let starting = module(false, true);
        let running = module(false, false);
        let context = context(); let policy = policy();
        let root = WasmMemoryPool::new(8);
        let tenant = root.partition(6).unwrap(); let sibling = root.partition(2).unwrap();
        let mut instance = running.instantiate_with_imports(&context, &policy, imports(&tenant)).unwrap();
        let mut healthy = running.instantiate_with_imports(&context, &policy, imports(&sibling)).unwrap();
        let WasmStartupStep::Pending(startup) = starting.prepare_startup_with_imports(imports(&tenant))
            .resume(work(1), &context, &policy).unwrap() else { panic!("startup must yield"); };
        let WasmCommandStep::Pending(command) = running.prepare_command(imports(&tenant))
            .resume(work(1), &context, &policy).unwrap() else { panic!("command must yield before entry"); };
        assert_eq!(tenant.reserved_pages(), 6);
        let mut scheduler = WasmNativeScheduler::new(NonZeroUsize::new(4).unwrap());
        scheduler.submit_startup(startup).unwrap();
        scheduler.submit_command(command).unwrap();
        scheduler.submit(instance.begin_call("run", &[], &context, &policy).unwrap()).unwrap();
        let next = scheduler.submit(healthy.begin_call("run", &[], &context, &policy).unwrap()).unwrap();
        tenant.revoke();
        for _ in 0..3 {
            assert!(matches!(scheduler.run_next(work(100), &context, &policy).unwrap().outcome,
                WasmTaskOutcome::Failed(WasmNativeLoadError::Execution(error)) if error == revoked()));
        }
        assert_eq!(tenant.reserved_pages(), 2); // Retained export instance, not cancelled work.
        assert_eq!(scheduler.next_task(), Some(next.id()));
        assert!(matches!(scheduler.run_next(work(100), &context, &policy).unwrap().outcome,
            WasmTaskOutcome::Complete(_)));
        drop(scheduler);
        assert!(instance.memory_export("memory", &context, &policy).unwrap().unwrap().iter().all(|byte| *byte == 0));
        assert!(!root.is_revoked()); assert!(!sibling.is_revoked());
        healthy.call_export("run", &[], &context, &policy).unwrap();
        drop(instance); assert_eq!(tenant.reserved_pages(), 0);
    }
}
