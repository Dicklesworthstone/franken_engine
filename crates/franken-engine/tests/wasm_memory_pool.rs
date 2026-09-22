#![forbid(unsafe_code)]

use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::{
    Arc, Barrier,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Wake, Waker};

use WasmBoundaryValue::I32;
use frankenengine_engine::capability::RuntimeCapability::{Builtin, VmDispatch};
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::wasm_runtime_lane::memory_pool::WasmMemoryPool;
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmCallStep, WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits, WasmNumericVm,
    WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature};

const END: &[u8] = &[0x0b];
const HOST: &[u8] = &[0x10, 0, 0x0b];
const LOOP: &[u8] = &[0x03, 0x40, 0x0c, 0, 0x0b, 0x0b];
const TRAP: &[u8] = &[0x00, 0x0b];
const STORE_TRAP: &[u8] = &[0x41, 0, 0x41, 42, 0x36, 2, 0, 0x00, 0x0b];

fn leb(mut value: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return bytes;
        }
    }
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    bytes.push(id);
    bytes.extend(leb(payload.len() as u32));
    bytes.extend(payload);
}

// An optional binary start, a separate command entry, and a grow export. The
// bodies are real guest code executed by the production VM in every test.
fn fixture(
    memory: Option<(u32, Option<u32>)>,
    start: Option<&[u8]>,
    entry: &[u8],
    host: bool,
    bad_data: bool,
) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[2, 0x60, 0, 0, 0x60, 1, 0x7f, 1, 0x7f]);
    if host {
        section(&mut bytes, 2, &[1, 1, b'h', 1, b'f', 0, 0]);
    }
    section(&mut bytes, 3, &[3, 0, 0, 1]);
    if let Some((minimum, maximum)) = memory {
        let mut declaration = vec![1, u8::from(maximum.is_some())];
        declaration.extend(leb(minimum));
        if let Some(maximum) = maximum {
            declaration.extend(leb(maximum));
        }
        section(&mut bytes, 5, &declaration);
    }
    let base = u8::from(host);
    let mut exports = vec![2 + u8::from(memory.is_some()), 6];
    exports.extend(b"_start");
    exports.extend([0, base + 1, 4]);
    exports.extend(b"grow");
    exports.extend([0, base + 2]);
    if memory.is_some() {
        exports.extend([1, b'm', 2, 0]);
    }
    section(&mut bytes, 7, &exports);
    if start.is_some() {
        section(&mut bytes, 8, &[base]);
    }
    let grow: &[u8] = if memory.is_some() {
        &[0x20, 0, 0x40, 0, 0x0b]
    } else {
        &[0x41, 0, 0x0b]
    };
    let mut bodies = vec![3];
    for body in [start.unwrap_or(END), entry, grow] {
        bodies.extend(leb(body.len() as u32 + 1));
        bodies.push(0);
        bodies.extend(body);
    }
    section(&mut bytes, 10, &bodies);
    if bad_data {
        section(&mut bytes, 11, &[1, 0, 0x41, 0x80, 0x80, 4, 0x0b, 1, 7]);
    }
    bytes
}

fn vm(
    minimum: u32,
    maximum: Option<u32>,
    start: Option<&[u8]>,
    entry: &[u8],
    host: bool,
) -> WasmNumericVm {
    WasmNumericVm::parse(
        &fixture(Some((minimum, maximum)), start, entry, host, false),
        WasmNumericLimits::default(),
    )
    .unwrap()
}

fn imports(pool: &WasmMemoryPool) -> WasmHostImports {
    let mut imports = WasmHostImports::new([VmDispatch, Builtin].into());
    imports.bind_memory_pool(pool.clone()).unwrap();
    imports
}

fn provider<F>(pool: &WasmMemoryPool, callback: F) -> WasmHostImports
where
    F: FnMut(
            &mut WasmHostCaller<'_, '_>,
            &[WasmBoundaryValue],
        ) -> Result<Vec<WasmBoundaryValue>, WasmNumericVmError>
        + Send
        + Sync
        + 'static,
{
    let mut imports = imports(pool);
    imports
        .define(
            "h",
            "f",
            WasmFunctionSignature {
                params: vec![],
                results: vec![],
            },
            [Builtin].into(),
            1,
            callback,
        )
        .unwrap();
    imports
}

fn exhausted(error: WasmNumericVmError, requested: u64, available: u64) {
    assert_eq!(
        error,
        WasmNumericVmError::State(WasmStateError::Host(WasmHostError::MemoryPoolExhausted {
            requested_pages: requested,
            available_pages: available
        },))
    );
}

struct Noop;
impl Wake for Noop {
    fn wake(self: Arc<Self>) {}
}
fn waker() -> Waker {
    Waker::from(Arc::new(Noop))
}
fn quantum() -> NonZeroU64 {
    NonZeroU64::new(1).unwrap()
}

#[test]
fn binding_is_lazy_and_cannot_replace_a_smaller_pool() {
    let small = WasmMemoryPool::new(1);
    let big = WasmMemoryPool::new(20);
    let mut registry = imports(&small);
    assert_eq!(
        registry.bind_memory_pool(big.clone()),
        Err(WasmHostError::MemoryPoolAlreadyBound)
    );
    assert_eq!(small.reserved_pages(), 0);
    assert_eq!(big.reserved_pages(), 0);
    exhausted(
        vm(0, Some(2), None, END, false)
            .instantiate_with_imports(registry)
            .unwrap_err(),
        2,
        1,
    );
    assert_eq!(small.available_pages(), 1);
}

#[test]
fn effective_maximum_not_initial_allocation_is_reserved() {
    let pool = WasmMemoryPool::new(3);
    let bytes = fixture(Some((0, None)), None, END, false, false);
    let vm = WasmNumericVm::parse(
        &bytes,
        WasmNumericLimits {
            max_memory_pages: 3,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    let mut instance = vm.instantiate_with_imports(imports(&pool)).unwrap();
    assert_eq!(instance.memory_export("m").unwrap().len(), 0);
    assert_eq!(pool.reserved_pages(), 3);
    assert_eq!(pool.available_pages(), 0);
    assert_eq!(
        instance.call_export("grow", &[I32(3)]).unwrap().results,
        [I32(0)]
    );
    assert_eq!(instance.memory_export("m").unwrap().len(), 3 * 65_536);
    assert!(
        instance
            .memory_export("m")
            .unwrap()
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(
        instance.call_export("grow", &[I32(1)]).unwrap().results,
        [I32(-1)]
    );
    assert_eq!(pool.reserved_pages(), 3);
    drop(instance);
    assert_eq!(pool.available_pages(), 3);
}

#[test]
fn vm_page_ceiling_narrows_reservation_and_invalid_minimum_does_not_reserve() {
    let pool = WasmMemoryPool::new(1);
    for minimum in [0, 2] {
        let bytes = fixture(Some((minimum, Some(3))), None, END, false, false);
        let vm = WasmNumericVm::parse(
            &bytes,
            WasmNumericLimits {
                max_memory_pages: 1,
                ..WasmNumericLimits::default()
            },
        )
        .unwrap();
        match vm.instantiate_with_imports(imports(&pool)) {
            Ok(mut instance) => {
                assert_eq!(minimum, 0);
                assert_eq!(pool.reserved_pages(), 1);
                assert_eq!(
                    instance.call_export("grow", &[I32(2)]).unwrap().results,
                    [I32(-1)]
                );
            }
            Err(error) => {
                assert_eq!(minimum, 2);
                assert!(matches!(
                    error,
                    WasmNumericVmError::State(WasmStateError::LimitExceeded {
                        actual: 2,
                        max: 1,
                        ..
                    })
                ));
            }
        }
        assert_eq!(pool.reserved_pages(), 0);
    }
}

#[test]
fn memoryless_and_effective_zero_maximum_modules_need_no_pages() {
    let pool = WasmMemoryPool::new(0);
    for memory in [None, Some((0, Some(0)))] {
        let vm = WasmNumericVm::parse(
            &fixture(memory, None, END, false, false),
            WasmNumericLimits::default(),
        )
        .unwrap();
        let mut instance = vm.instantiate_with_imports(imports(&pool)).unwrap();
        instance.call_export("_start", &[]).unwrap();
        assert_eq!(pool.capacity_pages(), 0);
        assert_eq!(pool.reserved_pages(), 0);
    }
    exhausted(
        vm(0, Some(1), None, END, false)
            .instantiate_with_imports(imports(&pool))
            .unwrap_err(),
        1,
        0,
    );
}

#[test]
fn multiple_instances_share_capacity_and_only_destruction_refunds_it() {
    let pool = WasmMemoryPool::new(4);
    let vm = vm(1, Some(2), None, END, false);
    let a = vm.instantiate_with_imports(imports(&pool)).unwrap();
    let b = vm.instantiate_with_imports(imports(&pool)).unwrap();
    assert_eq!(pool.reserved_pages(), 4);
    exhausted(
        vm.instantiate_with_imports(imports(&pool)).unwrap_err(),
        2,
        0,
    );
    drop(a);
    let c = vm.instantiate_with_imports(imports(&pool)).unwrap();
    assert_eq!(pool.reserved_pages(), 4);
    drop((b, c));
    assert_eq!(pool.available_pages(), 4);
}

#[test]
fn admission_is_atomic_across_threads_and_does_not_overcommit() {
    const THREADS: usize = 12;
    let pool = WasmMemoryPool::new(6);
    let vm = vm(1, Some(2), None, END, false);
    let start = Barrier::new(THREADS + 1);
    let admitted = Barrier::new(THREADS + 1);
    let release = Barrier::new(THREADS + 1);
    std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for _ in 0..THREADS {
            let (pool, vm, start, admitted, release) = (&pool, &vm, &start, &admitted, &release);
            handles.push(scope.spawn(move || {
                start.wait();
                let result = vm.instantiate_with_imports(imports(pool));
                admitted.wait();
                release.wait();
                result.map(drop)
            }));
        }
        start.wait();
        admitted.wait();
        let held = pool.reserved_pages();
        release.wait(); // Release workers before asserting or joining failures.
        assert_eq!(held, 6);
        let mut successes = 0;
        for handle in handles {
            match handle.join().unwrap() {
                Ok(()) => successes += 1,
                Err(error) => exhausted(error, 2, 0),
            }
        }
        assert_eq!(successes, 3);
    });
    assert_eq!(pool.reserved_pages(), 0);
}

#[test]
fn failed_growth_and_trapped_exports_retain_the_live_instance_reservation() {
    let pool = WasmMemoryPool::new(2);
    let bytes = fixture(Some((1, Some(2))), None, STORE_TRAP, false, false);
    let vm = WasmNumericVm::parse(
        &bytes,
        WasmNumericLimits {
            max_instructions: 10,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    let mut instance = vm.instantiate_with_imports(imports(&pool)).unwrap();
    assert!(matches!(
        instance.call_export("grow", &[I32(1)]),
        Err(WasmNumericVmError::InstructionBudgetExceeded { .. })
    ));
    assert_eq!(instance.memory_export("m").unwrap().len(), 65_536);
    assert!(matches!(
        instance.call_export("_start", &[]),
        Err(WasmNumericVmError::Unreachable { .. })
    ));
    assert_eq!(
        &instance.memory_export("m").unwrap()[..4],
        &42_i32.to_le_bytes()
    );
    assert_eq!(pool.reserved_pages(), 2);
    let call = instance.begin_call("_start", &[]).unwrap();
    let WasmCallStep::Pending(call) = call.resume(quantum()).unwrap() else {
        panic!("pending store");
    };
    call.cancel();
    assert_eq!(pool.reserved_pages(), 2);
    drop(instance);
    assert_eq!(pool.reserved_pages(), 0);
}

#[test]
fn invalid_segments_and_failed_startup_release_admission() {
    let pool = WasmMemoryPool::new(2);
    let bad = WasmNumericVm::parse(
        &fixture(Some((1, Some(2))), None, END, false, true),
        WasmNumericLimits::default(),
    )
    .unwrap();
    assert!(matches!(
        bad.instantiate_with_imports(imports(&pool)),
        Err(WasmNumericVmError::State(
            WasmStateError::DataSegmentOutOfBounds { .. }
        ))
    ));
    assert_eq!(pool.reserved_pages(), 0);
    assert!(matches!(
        vm(1, Some(2), Some(TRAP), END, false).instantiate_with_imports(imports(&pool)),
        Err(WasmNumericVmError::Unreachable { .. })
    ));
    assert_eq!(pool.reserved_pages(), 0);
}

#[test]
fn denied_imports_and_live_cancellation_precede_reservation_or_callbacks() {
    let pool = WasmMemoryPool::new(0);
    let vm = vm(1, Some(2), Some(HOST), END, true);
    assert!(matches!(
        vm.instantiate_with_imports(imports(&pool)),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::MissingBinding { .. }
        )))
    ));
    let mut registry = WasmHostImports::new([VmDispatch].into());
    registry.bind_memory_pool(pool.clone()).unwrap();
    registry
        .define(
            "h",
            "f",
            WasmFunctionSignature {
                params: vec![],
                results: vec![],
            },
            [Builtin].into(),
            1,
            |_, _| panic!("unauthorized host"),
        )
        .unwrap();
    assert!(matches!(
        vm.instantiate_with_imports(registry),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied { .. }
        )))
    ));
    let mut registry = provider(&pool, |_, _| panic!("cancelled host"));
    let token = CancellationToken::new();
    registry
        .bind_execution_cancellation(token.clone(), "pool-cancel")
        .unwrap();
    token.cancel();
    assert!(matches!(
        vm.instantiate_with_imports(registry),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::ExecutionCancelled
        )))
    ));
    assert_eq!(pool.reserved_pages(), 0);
}

#[test]
fn capacity_refusal_precedes_all_guest_and_host_startup_effects() {
    let pool = WasmMemoryPool::new(1);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let registry = provider(&pool, move |_, _| {
        observed.fetch_add(1, Ordering::SeqCst);
        Ok(vec![])
    });
    exhausted(
        vm(1, Some(2), Some(HOST), END, true)
            .instantiate_with_imports(registry)
            .unwrap_err(),
        2,
        1,
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(pool.reserved_pages(), 0);
}

#[test]
fn unfinished_future_holds_capacity_only_after_first_poll() {
    let pool = WasmMemoryPool::new(2);
    let vm = vm(1, Some(2), Some(LOOP), END, false);
    let mut future = vm.instantiate_cooperatively_with_imports(imports(&pool), quantum());
    assert_eq!(pool.reserved_pages(), 0);
    let waker = waker();
    let mut cx = Context::from_waker(&waker);
    assert!(Pin::new(&mut future).poll(&mut cx).is_pending());
    assert_eq!(pool.reserved_pages(), 2);
    drop(future);
    assert_eq!(pool.reserved_pages(), 0);
}

#[test]
fn completed_future_transfers_its_reservation_to_the_published_instance() {
    let pool = WasmMemoryPool::new(2);
    let vm = vm(1, Some(2), None, END, false);
    let mut future = vm.instantiate_cooperatively_with_imports(imports(&pool), quantum());
    let waker = waker();
    let mut cx = Context::from_waker(&waker);
    let Poll::Ready(Ok(instance)) = Pin::new(&mut future).poll(&mut cx) else {
        panic!("ready instance");
    };
    drop(future);
    assert_eq!(pool.reserved_pages(), 2);
    drop(instance);
    assert_eq!(pool.reserved_pages(), 0);
}

#[test]
fn normal_guest_exit_keeps_capacity_until_inspectable_instance_is_destroyed() {
    let pool = WasmMemoryPool::new(2);
    let vm = vm(1, Some(2), None, HOST, true);
    let mut instance = vm
        .instantiate_with_imports(provider(&pool, |caller, _| Err(caller.exit(17))))
        .unwrap();
    assert!(matches!(
        instance.call_export("_start", &[]),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::ProcessExit { code: 17 }
        )))
    ));
    assert_eq!(instance.process_exit_status(), Some(17));
    assert_eq!(pool.reserved_pages(), 2);
    drop(instance);
    assert_eq!(pool.reserved_pages(), 0);
}

#[test]
fn startup_provider_panic_unwinds_the_reservation_without_poisoning_the_pool() {
    let pool = WasmMemoryPool::new(2);
    let vm = vm(1, Some(2), Some(HOST), END, true);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        vm.instantiate_with_imports(provider(&pool, |_, _| panic!("provider failure")))
    }));
    assert!(result.is_err());
    assert_eq!(pool.reserved_pages(), 0);
    let instance = vm
        .instantiate_with_imports(provider(&pool, |_, _| Ok(vec![])))
        .unwrap();
    assert_eq!(pool.reserved_pages(), 2);
    drop(instance);
    assert_eq!(pool.available_pages(), 2);
}

mod tenant_lifecycles {
    use super::*;
    use frankenengine_engine::module_resolver::{
        CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
        ModuleRequest, ResolutionContext, wasm_module_required_capabilities,
    };
    use frankenengine_engine::wasm_runtime_lane::command::{
        WasmCommandExecution, WasmCommandStep, WasmCommandTask,
    };
    use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
    use frankenengine_engine::wasm_runtime_lane::scheduler::{
        WasmNativeScheduler, WasmStartupStep, WasmTaskAdmissionErrorKind, WasmTaskOutcome,
    };
    use frankenengine_engine::wasm_runtime_lane::{WasmNativeLoadError, WasmNativeModule};
    use std::num::NonZeroUsize;

    fn context() -> ResolutionContext {
        ResolutionContext::new("pool-trace", "pool-decision", "pool-policy")
    }
    fn policy() -> CapabilityPolicyHook {
        let mut caps = wasm_module_required_capabilities();
        caps.insert(Builtin);
        CapabilityPolicyHook::new(caps)
    }
    fn load(start: Option<&[u8]>, entry: &[u8], host: bool) -> WasmNativeModule {
        let limits = WasmNumericLimits::default();
        let mut resolver = DeterministicModuleResolver::new("/app");
        let definition = ModuleDefinition::wasm_binary(
            &fixture(Some((1, Some(2))), start, entry, host, false),
            &limits,
        )
        .unwrap()
        .require_capability(Builtin);
        resolver
            .register_workspace_module("/app/pool.wasm", definition)
            .unwrap();
        resolver
            .load_wasm(
                &ModuleRequest::new("/app/pool.wasm", ImportStyle::Import),
                &context(),
                &policy(),
                limits,
            )
            .unwrap()
    }
    fn finish(
        mut command: WasmCommandTask<'_>,
    ) -> Result<WasmCommandExecution, WasmNativeLoadError> {
        for _ in 0..128 {
            match command.resume(NonZeroU64::new(8).unwrap(), &context(), &policy())? {
                WasmCommandStep::Pending(next) => command = next,
                WasmCommandStep::Complete(execution) => return Ok(execution),
            }
        }
        panic!("bounded command failed to terminate");
    }

    #[test]
    fn partitions_protect_idle_tenant_capacity_and_cannot_overcommit_parent() {
        let root = WasmMemoryPool::new(4);
        let a = root.partition(2).unwrap();
        let b = root.partition(2).unwrap();
        assert!(!root.is_partition());
        assert!(a.is_partition());
        assert_eq!(root.available_pages(), 0);
        assert!(matches!(
            root.partition(1),
            Err(WasmHostError::MemoryPoolExhausted {
                requested_pages: 1,
                available_pages: 0
            })
        ));
        let vm = vm(1, Some(2), None, END, false);
        let mut a_instance = vm.instantiate_with_imports(imports(&a)).unwrap();
        exhausted(vm.instantiate_with_imports(imports(&a)).unwrap_err(), 2, 0);
        // The idle sibling's two pages are not borrowed by the saturated tenant.
        let b_instance = vm.instantiate_with_imports(imports(&b)).unwrap();
        assert_eq!(
            a_instance.call_export("grow", &[I32(1)]).unwrap().results,
            [I32(1)]
        );
        assert_eq!(root.reserved_pages(), 4);
        drop((a_instance, b_instance));
        assert_eq!(a.available_pages(), 2);
        assert_eq!(b.available_pages(), 2);
        drop((a, b));
        assert_eq!(root.available_pages(), 4);
    }

    #[test]
    fn dropping_partition_handles_never_refunds_a_live_descendant_instance() {
        let root = WasmMemoryPool::new(8);
        let tenant = root.partition(4).unwrap();
        let cell = tenant.partition(2).unwrap();
        let vm = vm(1, Some(2), None, END, false);
        let instance = vm.instantiate_with_imports(imports(&cell)).unwrap();
        drop(tenant);
        drop(cell);
        assert_eq!(root.reserved_pages(), 4);
        drop(instance);
        assert_eq!(root.reserved_pages(), 0);
        let replacement = root.partition(8).unwrap();
        drop(replacement);
        assert_eq!(root.available_pages(), 8);
    }

    #[test]
    fn unused_partition_clones_release_once_and_capacity_arithmetic_never_wraps() {
        let root = WasmMemoryPool::new(u64::MAX);
        let child = root.partition(u64::MAX - 1).unwrap();
        assert_eq!(root.available_pages(), 1);
        let clone = child.clone();
        drop(child);
        assert_eq!(root.reserved_pages(), u64::MAX - 1);
        assert!(matches!(
            root.partition(2),
            Err(WasmHostError::MemoryPoolExhausted {
                requested_pages: 2,
                available_pages: 1
            })
        ));
        let empty = clone.partition(0).unwrap();
        assert_eq!(empty.capacity_pages(), 0);
        drop(clone);
        assert_eq!(root.available_pages(), 1);
        drop(empty);
        assert_eq!(root.available_pages(), u64::MAX);
    }

    #[test]
    fn scheduled_startup_holds_capacity_after_leaving_the_scheduler() {
        let pool = WasmMemoryPool::new(2);
        let module = load(None, END, false);
        let mut scheduler = WasmNativeScheduler::new(NonZeroUsize::new(1).unwrap());
        scheduler
            .submit_startup(module.prepare_startup_with_imports(imports(&pool)))
            .unwrap();
        assert_eq!(pool.reserved_pages(), 0);
        let turn = scheduler
            .run_next(quantum(), &context(), &policy())
            .unwrap();
        let WasmTaskOutcome::Initialized(instance) = turn.outcome else {
            panic!("initialized instance");
        };
        drop(scheduler);
        assert_eq!(pool.reserved_pages(), 2);
        drop(instance);
        assert_eq!(pool.reserved_pages(), 0);
    }

    #[test]
    fn queued_startup_cancellation_releases_capacity_for_a_new_command() {
        let pool = WasmMemoryPool::new(2);
        let spinner = load(Some(LOOP), END, false);
        let useful = load(None, END, false);
        let mut scheduler = WasmNativeScheduler::new(NonZeroUsize::new(2).unwrap());
        let spinning = scheduler
            .submit_startup(spinner.prepare_startup_with_imports(imports(&pool)))
            .unwrap();
        assert!(matches!(
            scheduler
                .run_next(quantum(), &context(), &policy())
                .unwrap()
                .outcome,
            WasmTaskOutcome::Pending
        ));
        assert_eq!(pool.reserved_pages(), 2);
        scheduler
            .submit_command(useful.prepare_command(imports(&pool)))
            .unwrap();
        // The spinner keeps its reservation while rejoining the tail.
        assert!(matches!(
            scheduler
                .run_next(quantum(), &context(), &policy())
                .unwrap()
                .outcome,
            WasmTaskOutcome::Pending
        ));
        let turn = scheduler
            .run_next(quantum(), &context(), &policy())
            .unwrap();
        match turn.outcome {
            WasmTaskOutcome::Failed(WasmNativeLoadError::Execution(error)) => {
                exhausted(error, 2, 0)
            }
            other => panic!("missing shared capacity refusal: {other:?}"),
        }
        spinning.cancel();
        assert!(matches!(
            scheduler
                .run_next(quantum(), &context(), &policy())
                .unwrap()
                .outcome,
            WasmTaskOutcome::Cancelled
        ));
        assert_eq!(pool.reserved_pages(), 0);
        assert_eq!(
            finish(useful.prepare_command(imports(&pool)))
                .unwrap()
                .exit_code,
            0
        );
        assert_eq!(pool.reserved_pages(), 0);
    }

    #[test]
    fn rejected_and_withdrawn_commands_keep_the_original_memory_reservation() {
        let pool = WasmMemoryPool::new(4);
        let module = load(None, END, false);
        let mut scheduler = WasmNativeScheduler::new(NonZeroUsize::new(1).unwrap());
        let occupied = scheduler
            .submit_startup(module.prepare_startup_with_imports(imports(&pool)))
            .unwrap();
        let command = module.prepare_command(imports(&pool));
        let WasmCommandStep::Pending(command) =
            command.resume(quantum(), &context(), &policy()).unwrap()
        else {
            panic!("phase yield");
        };
        assert_eq!(pool.reserved_pages(), 2);
        let rejected = scheduler.submit_command(command).unwrap_err();
        assert_eq!(rejected.kind(), WasmTaskAdmissionErrorKind::QueueFull);
        assert_eq!(pool.reserved_pages(), 2);
        occupied.cancel();
        assert!(matches!(
            scheduler
                .run_next(quantum(), &context(), &policy())
                .unwrap()
                .outcome,
            WasmTaskOutcome::Cancelled
        ));
        let handle = scheduler
            .submit_command((*rejected).into_command())
            .unwrap();
        let command = scheduler.take_command(handle.id()).unwrap();
        drop(scheduler);
        assert_eq!(pool.reserved_pages(), 2);
        command.cancel();
        assert_eq!(pool.reserved_pages(), 0);
    }

    #[test]
    fn policy_denial_releases_partial_state_without_returning_a_live_instance() {
        let pool = WasmMemoryPool::new(2);
        let module = load(Some(LOOP), END, false);
        let startup = module.prepare_startup_with_imports(imports(&pool));
        let WasmStartupStep::Pending(startup) =
            startup.resume(quantum(), &context(), &policy()).unwrap()
        else {
            panic!("pending initialization");
        };
        assert_eq!(pool.reserved_pages(), 2);
        assert!(matches!(
            startup.resume(
                quantum(),
                &context(),
                &CapabilityPolicyHook::new(Default::default())
            ),
            Err(WasmNativeLoadError::Resolution(_))
        ));
        assert_eq!(pool.reserved_pages(), 0);
        // A denial before the first slice cannot consume any capacity either.
        let startup = module.prepare_startup_with_imports(imports(&pool));
        assert!(matches!(
            startup.resume(
                quantum(),
                &context(),
                &CapabilityPolicyHook::new(Default::default())
            ),
            Err(WasmNativeLoadError::Resolution(_))
        ));
        assert_eq!(pool.reserved_pages(), 0);
    }

    #[test]
    fn replay_observers_neither_hold_capacity_nor_bypass_live_admission() {
        let pool = WasmMemoryPool::new(2);
        let module = load(Some(HOST), HOST, true);
        let holder_vm = vm(1, Some(2), None, END, false);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let mut registry = provider(&pool, move |caller, _| {
            count.fetch_add(1, Ordering::SeqCst);
            caller.write_memory(0, b"pool")?;
            Ok(vec![])
        });
        let limits = WasmHostTraceLimits::default();
        let record = registry.record_calls(limits).unwrap();
        let expected = finish(module.prepare_command(registry)).unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(pool.reserved_pages(), 0);
        let transcript = record.snapshot().unwrap();
        let holder = holder_vm.instantiate_with_imports(imports(&pool)).unwrap();
        let mut registry = provider(&pool, |_, _| panic!("denied replay provider"));
        let observer = registry.replay_calls(transcript.clone(), limits).unwrap();
        match finish(module.prepare_command(registry)) {
            Err(WasmNativeLoadError::Execution(error)) => exhausted(error, 2, 0),
            other => panic!("replay bypassed memory admission: {other:?}"),
        }
        assert!(observer.verify_complete().is_err());
        drop(holder);
        let mut registry = provider(&pool, |_, _| panic!("replayed provider"));
        let observer = registry.replay_calls(transcript, limits).unwrap();
        assert_eq!(finish(module.prepare_command(registry)).unwrap(), expected);
        observer.verify_complete().unwrap();
        assert_eq!(pool.reserved_pages(), 0); // Both independent observers remain alive.
    }

    #[test]
    fn a_command_exit_releases_pool_capacity_but_not_completed_host_effects() {
        let pool = WasmMemoryPool::new(2);
        let module = load(None, HOST, true);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let registry = provider(&pool, move |caller, _| {
            count.fetch_add(1, Ordering::SeqCst);
            Err(caller.exit(u32::MAX))
        });
        assert_eq!(
            finish(module.prepare_command(registry)).unwrap().exit_code,
            u32::MAX
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(pool.reserved_pages(), 0);
    }

    #[test]
    fn resolved_future_publication_denial_releases_its_pool_reservation() {
        let pool = WasmMemoryPool::new(2);
        let module = load(None, END, false);
        let reads = Arc::new(AtomicUsize::new(0));
        let observed = reads.clone();
        let mut future = Box::pin(module.instantiate_cooperatively_with_imports(
            imports(&pool),
            quantum(),
            move || {
                let allow = if observed.fetch_add(1, Ordering::SeqCst) == 0 {
                    policy()
                } else {
                    CapabilityPolicyHook::new(Default::default())
                };
                Ok((context(), allow))
            },
        ));
        let waker = waker();
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            future.as_mut().poll(&mut cx),
            Poll::Ready(Err(WasmNativeLoadError::Resolution(_)))
        ));
        assert_eq!(reads.load(Ordering::SeqCst), 2);
        assert_eq!(pool.reserved_pages(), 0);
    }
}
