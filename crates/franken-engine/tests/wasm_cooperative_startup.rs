#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll, Wake, Waker};

use frankenengine_engine::capability::RuntimeCapability::{Builtin, VmDispatch};
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits, WasmNumericVm,
    WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue::I32, WasmFunctionSignature, WasmValueType,
};

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

fn quantum(n: u64) -> NonZeroU64 {
    NonZeroU64::new(n).unwrap()
}
fn poll<F: Future + Unpin>(future: &mut F, wakes: &Arc<Wakes>) -> Poll<F::Output> {
    let waker = Waker::from(wakes.clone());
    Pin::new(future).poll(&mut Context::from_waker(&waker))
}
fn run<F: Future + Unpin>(mut future: F) -> F::Output {
    let wakes = Arc::new(Wakes::default());
    for _ in 0..100_000 {
        let before = wakes.0.load(Ordering::SeqCst);
        match poll(&mut future, &wakes) {
            Poll::Ready(result) => {
                assert_eq!(
                    wakes.0.load(Ordering::SeqCst),
                    before,
                    "Ready must not self-schedule"
                );
                return result;
            }
            Poll::Pending => assert_eq!(wakes.0.load(Ordering::SeqCst), before + 1),
        }
    }
    panic!("startup failed to terminate within the test poll bound");
}

fn leb(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let low = (n & 127) as u8;
        n >>= 7;
        out.push(low | if n == 0 { 0 } else { 128 });
        if n == 0 {
            return out;
        }
    }
}
fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    bytes.push(id);
    bytes.extend(leb(payload.len()));
    bytes.extend_from_slice(payload);
}

// Two defined functions: [] -> [] startup and [] -> i32 global getter.
// All optional imports have the void signature, including imported starts.
fn program(code: &[u8], imports: u8, start: Option<u32>) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[2, 0x60, 0, 0, 0x60, 0, 1, 0x7f]);
    if imports != 0 {
        let mut entries = vec![imports];
        for name in [b'f', b'x'].into_iter().take(usize::from(imports)) {
            entries.extend([1, b'h', 1, name, 0, 0]);
        }
        section(&mut bytes, 2, &entries);
    }
    section(&mut bytes, 3, &[2, 0, 1]);
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    section(&mut bytes, 5, &[1, 1, 1, 2]);
    section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
    section(
        &mut bytes,
        7,
        &[
            5,
            1,
            b's',
            0,
            imports,
            1,
            b'g',
            3,
            0,
            1,
            b'f',
            0,
            imports + 1,
            1,
            b'm',
            2,
            0,
            1,
            b't',
            1,
            0,
        ],
    );
    if let Some(start) = start {
        section(&mut bytes, 8, &leb(start as usize));
    }
    section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
    let mut bodies = vec![2];
    bodies.extend(leb(code.len() + 1));
    bodies.push(0);
    bodies.extend_from_slice(code);
    bodies.extend([4, 0, 0x23, 0, 0x0b]);
    section(&mut bytes, 10, &bodies);
    section(&mut bytes, 11, &[1, 0, 0x41, 0, 0x0b, 3, 0xff, 0x80, 0xfe]);
    bytes
}

const STORES: &[u8] = &[
    0x41, 7, 0x24, 0, 0x41, 16, 0x41, 9, 0x36, 2, 0, 0x41, 42, 0x24, 0, 0x0b,
];
const HOST_TWICE: &[u8] = &[0x41, 1, 0x24, 0, 0x10, 0, 0x41, 2, 0x24, 0, 0x10, 0, 0x0b];
fn vm(code: &[u8], imports: u8, start: Option<u32>) -> WasmNumericVm {
    WasmNumericVm::parse(&program(code, imports, start), WasmNumericLimits::default()).unwrap()
}
fn bindings<F>(callback: F) -> WasmHostImports
where
    F: FnMut(
            &mut WasmHostCaller<'_, '_>,
            &[frankenengine_engine::wasm_runtime_lane::WasmBoundaryValue],
        ) -> Result<
            Vec<frankenengine_engine::wasm_runtime_lane::WasmBoundaryValue>,
            WasmNumericVmError,
        > + Send
        + Sync
        + 'static,
{
    let mut imports = WasmHostImports::new(BTreeSet::from([Builtin, VmDispatch]));
    imports
        .define(
            "h",
            "f",
            WasmFunctionSignature {
                params: vec![],
                results: vec![],
            },
            BTreeSet::from([Builtin]),
            3,
            callback,
        )
        .unwrap();
    imports
}
fn counting(calls: Arc<AtomicUsize>) -> WasmHostImports {
    bindings(move |caller, _| {
        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
        assert_eq!(caller.read_memory(0, 3)?, &[0xff, 0x80, 0xfe]);
        caller.write_memory(8, &[n as u8])?;
        Ok(vec![])
    })
}

#[test]
fn future_is_lazy_and_dropping_it_before_poll_has_no_effects() {
    let vm = vm(HOST_TWICE, 1, Some(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let future = vm.instantiate_cooperatively_with_imports(counting(calls.clone()), quantum(1));
    fn embedding_traits<T: Send + Sync + Unpin>(_: &T) {}
    embedding_traits(&future);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    drop(future);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(
        run(vm.instantiate_cooperatively_with_imports(counting(calls.clone()), quantum(1))).is_ok()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn each_quantum_matches_synchronous_start_state_and_metrics() {
    let vm = vm(STORES, 0, Some(0));
    let expected = vm.instantiate().unwrap();
    for work in [1, 2, 3, 7, 8, 128, u64::MAX] {
        let mut actual = run(vm.instantiate_cooperatively(quantum(work))).unwrap();
        assert_eq!(actual.start_execution(), expected.start_execution());
        assert_eq!(actual.start_execution().unwrap().instructions_executed, 8);
        assert_eq!(actual.memory_export("m"), expected.memory_export("m"));
        assert_eq!(actual.global_export("g"), Some(&I32(42)));
        assert_eq!(actual.table_export("t"), expected.table_export("t"));
        let start = actual.start_execution().cloned();
        assert_eq!(actual.call_export("f", &[]).unwrap().results, [I32(42)]);
        assert_eq!(actual.start_execution(), start.as_ref());
    }
}

#[test]
fn no_start_and_empty_start_preserve_distinct_metadata() {
    let no_start = vm(STORES, 0, None);
    let mut future = no_start.instantiate_cooperatively(quantum(1));
    let wakes = Arc::new(Wakes::default());
    let Poll::Ready(Ok(instance)) = poll(&mut future, &wakes) else {
        panic!("no start must be immediately ready");
    };
    assert_eq!(instance.start_execution(), None);
    assert_eq!(instance.global_export("g"), Some(&I32(0)));
    assert_eq!(
        &instance.memory_export("m").unwrap()[..3],
        &[0xff, 0x80, 0xfe]
    );
    assert_eq!(wakes.0.load(Ordering::SeqCst), 0);
    let empty = vm(&[0x0b], 0, Some(0));
    assert_eq!(
        run(empty.instantiate_cooperatively(quantum(1)))
            .unwrap()
            .start_execution()
            .unwrap()
            .instructions_executed,
        1
    );
}

#[test]
fn pending_polls_wake_only_the_current_task_once() {
    let vm = vm(STORES, 0, Some(0));
    let mut future = vm.instantiate_cooperatively(quantum(1));
    let a = Arc::new(Wakes::default());
    let b = Arc::new(Wakes::default());
    assert!(poll(&mut future, &a).is_pending());
    assert!(poll(&mut future, &b).is_pending());
    assert_eq!(a.0.load(Ordering::SeqCst), 1);
    assert_eq!(b.0.load(Ordering::SeqCst), 1);
    run(future).unwrap();
    assert_eq!(a.0.load(Ordering::SeqCst), 1);
    assert_eq!(b.0.load(Ordering::SeqCst), 1);
}

#[test]
fn dropping_pending_start_keeps_completed_external_effects_without_running_later_calls() {
    let vm = vm(HOST_TWICE, 1, Some(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut future = vm.instantiate_cooperatively_with_imports(counting(calls.clone()), quantum(1));
    let wakes = Arc::new(Wakes::default());
    for _ in 0..3 {
        assert!(poll(&mut future, &wakes).is_pending());
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        0,
        "pending callee has not entered"
    );
    assert!(poll(&mut future, &wakes).is_pending());
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(future);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn linking_rejects_all_missing_or_mismatched_imports_before_allocation() {
    let bytes = program(&[0x10, 0, 0x0b], 2, Some(2));
    let vm = WasmNumericVm::parse(
        &bytes,
        WasmNumericLimits {
            max_memory_pages: 0,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    let imports = bindings(|_, _| panic!("no callback before full link"));
    assert!(
        matches!(run(vm.instantiate_cooperatively_with_imports(imports, quantum(1))),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::MissingBinding { name, .. }))) if name == "x")
    );
    let mut imports = WasmHostImports::new(BTreeSet::from([Builtin, VmDispatch]));
    imports
        .define(
            "h",
            "f",
            WasmFunctionSignature {
                params: vec![WasmValueType::I32],
                results: vec![],
            },
            BTreeSet::from([Builtin]),
            1,
            |_, _| panic!("wrong ABI"),
        )
        .unwrap();
    assert!(matches!(
        run(vm.instantiate_cooperatively_with_imports(imports, quantum(1))),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::SignatureMismatch { .. }
        )))
    ));
}

#[test]
fn default_route_does_not_require_unused_imports_or_install_host_authority() {
    let no_start = vm(HOST_TWICE, 1, None);
    run(no_start.instantiate_cooperatively(quantum(1))).unwrap();
    let start = vm(HOST_TWICE, 1, Some(1));
    assert!(matches!(
        run(start.instantiate_cooperatively(quantum(1))),
        Err(WasmNumericVmError::ImportedFunctionUnsupported { .. })
    ));
}

#[test]
fn one_start_budget_is_shared_across_all_polls_and_later_exports_get_their_own() {
    for work in [1, 2, 128] {
        let bytes = program(STORES, 0, Some(0));
        let low = WasmNumericVm::parse(
            &bytes,
            WasmNumericLimits {
                max_instructions: 7,
                ..WasmNumericLimits::default()
            },
        )
        .unwrap();
        assert!(matches!(
            run(low.instantiate_cooperatively(quantum(work))),
            Err(WasmNumericVmError::InstructionBudgetExceeded { max: 7 })
        ));
        let exact = WasmNumericVm::parse(
            &bytes,
            WasmNumericLimits {
                max_instructions: 8,
                ..WasmNumericLimits::default()
            },
        )
        .unwrap();
        let mut instance = run(exact.instantiate_cooperatively(quantum(work))).unwrap();
        assert_eq!(instance.call_export("f", &[]).unwrap().results, [I32(42)]);
    }
}

#[test]
fn nested_and_tail_start_calls_keep_the_existing_activation_limits() {
    let nested = vm(&[0x10, 1, 0x1a, 0x0b], 0, Some(0));
    let result = run(nested.instantiate_cooperatively(quantum(1))).unwrap();
    assert_eq!(
        result.start_execution(),
        nested.instantiate().unwrap().start_execution()
    );
    assert_eq!(result.start_execution().unwrap().max_call_depth, 2);
    for tail in [vec![0x12, 0], vec![0x41, 0, 0x13, 0, 0]] {
        let mut code = vec![
            0x23, 0, 0x41, 1, 0x6a, 0x24, 0, 0x23, 0, 0x41, 10, 0x48, 0x04, 0x40,
        ];
        code.extend(tail);
        code.extend([0x0b, 0x0b]);
        let vm = WasmNumericVm::parse(
            &program(&code, 0, Some(0)),
            WasmNumericLimits {
                max_call_depth: 1,
                ..WasmNumericLimits::default()
            },
        )
        .unwrap();
        let instance = run(vm.instantiate_cooperatively(quantum(1))).unwrap();
        assert_eq!(instance.global_export("g"), Some(&I32(10)));
        assert_eq!(
            instance.start_execution(),
            vm.instantiate().unwrap().start_execution()
        );
        assert_eq!(instance.start_execution().unwrap().max_call_depth, 1);
    }
}

#[test]
fn imported_start_uses_the_same_host_abi_and_records_once() {
    let vm = vm(&[0x0b], 1, Some(0));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut imports = counting(calls.clone());
    let recorder = imports
        .record_calls(WasmHostTraceLimits::default())
        .unwrap();
    let instance = run(vm.instantiate_cooperatively_with_imports(imports, quantum(1))).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(instance.start_execution().unwrap().results.is_empty());
    assert_eq!(recorder.snapshot().unwrap().call_count(), 1);
    assert_eq!(instance.memory_export("m").unwrap()[8], 1);
}

#[test]
fn startup_recordings_replay_across_different_quanta_without_provider_entry() {
    let vm = vm(HOST_TWICE, 1, Some(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut imports = counting(calls.clone());
    let recorder = imports
        .record_calls(WasmHostTraceLimits::default())
        .unwrap();
    let instance = run(vm.instantiate_cooperatively_with_imports(imports, quantum(1))).unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let tape = recorder.snapshot().unwrap();
    assert_eq!(tape.call_count(), 2);
    for work in [1, 100_000] {
        let mut imports = bindings(|_, _| panic!("replay must not run a provider"));
        let replay = imports
            .replay_calls(tape.clone(), WasmHostTraceLimits::default())
            .unwrap();
        let reproduced =
            run(vm.instantiate_cooperatively_with_imports(imports, quantum(work))).unwrap();
        assert_eq!(reproduced.start_execution(), instance.start_execution());
        assert_eq!(reproduced.memory_export("m"), instance.memory_export("m"));
        replay.verify_complete().unwrap();
    }
}

#[test]
fn failed_start_keeps_recorded_host_effects_but_cannot_publish_or_restart() {
    let vm = vm(&[0x10, 0, 0, 0x0b], 1, Some(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut imports = counting(calls.clone());
    let recorder = imports
        .record_calls(WasmHostTraceLimits::default())
        .unwrap();
    let mut future = vm.instantiate_cooperatively_with_imports(imports, quantum(100_000));
    let wakes = Arc::new(Wakes::default());
    assert!(matches!(
        poll(&mut future, &wakes),
        Poll::Ready(Err(WasmNumericVmError::Unreachable { .. }))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(recorder.snapshot().unwrap().call_count(), 1);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poll(&mut future, &wakes)))
            .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn cancellation_before_first_poll_wins_before_memory_refusal_even_after_reset() {
    let token = CancellationToken::new();
    let mut imports = WasmHostImports::new(BTreeSet::new());
    imports
        .bind_execution_cancellation(token.clone(), "lazy-start")
        .unwrap();
    let vm = WasmNumericVm::parse(
        &program(STORES, 0, Some(0)),
        WasmNumericLimits {
            max_memory_pages: 0,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    let future = vm.instantiate_cooperatively_with_imports(imports, quantum(1));
    token.cancel();
    token.reset();
    assert!(matches!(
        run(future),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::ExecutionCancelled
        )))
    ));
}

#[test]
fn cancellation_between_start_polls_never_resurrects_unpublished_state() {
    let vm = vm(STORES, 0, Some(0));
    let token = CancellationToken::new();
    let mut imports = WasmHostImports::new(BTreeSet::new());
    imports
        .bind_execution_cancellation(token.clone(), "between-start-polls")
        .unwrap();
    let mut future = vm.instantiate_cooperatively_with_imports(imports, quantum(1));
    let wakes = Arc::new(Wakes::default());
    assert!(poll(&mut future, &wakes).is_pending());
    token.cancel();
    token.reset();
    assert!(matches!(
        poll(&mut future, &wakes),
        Poll::Ready(Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::ExecutionCancelled
        ))))
    ));
    assert_eq!(wakes.0.load(Ordering::SeqCst), 1);
    let fresh = run(vm.instantiate_cooperatively(quantum(1))).unwrap();
    assert_eq!(fresh.global_export("g"), Some(&I32(42)));
}

#[test]
fn service_revocation_between_polls_blocks_the_pending_start_host_call() {
    let vm = vm(HOST_TWICE, 1, Some(1));
    let token = CancellationToken::new();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut imports = counting(calls.clone());
    imports
        .bind_capability_revocation(Builtin, token.clone(), "start-revoke")
        .unwrap();
    let mut future = vm.instantiate_cooperatively_with_imports(imports, quantum(1));
    let wakes = Arc::new(Wakes::default());
    for _ in 0..3 {
        assert!(poll(&mut future, &wakes).is_pending());
    }
    token.cancel();
    token.reset();
    assert!(matches!(
        poll(&mut future, &wakes),
        Poll::Ready(Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied {
                capability: Builtin,
                ..
            }
        ))))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn panicked_provider_poisoning_prevents_reentry_on_a_caught_unwind() {
    let vm = vm(&[0x10, 0, 0x0b], 1, Some(1));
    let calls = Arc::new(AtomicUsize::new(0));
    let captured = calls.clone();
    let imports = bindings(move |_, _| {
        captured.fetch_add(1, Ordering::SeqCst);
        panic!("provider panic");
    });
    let mut future = vm.instantiate_cooperatively_with_imports(imports, quantum(100_000));
    let wakes = Arc::new(Wakes::default());
    for _ in 0..2 {
        assert!(
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poll(&mut future, &wakes)))
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn another_runnable_start_can_finish_while_a_long_start_is_pending() {
    let long = vm(STORES, 0, Some(0));
    let short = vm(&[0x0b], 0, Some(0));
    let mut a = long.instantiate_cooperatively(quantum(1));
    let mut b = short.instantiate_cooperatively(quantum(1));
    let wakes = Arc::new(Wakes::default());
    assert!(poll(&mut a, &wakes).is_pending());
    assert!(matches!(poll(&mut b, &wakes), Poll::Ready(Ok(_))));
    assert!(poll(&mut a, &wakes).is_pending());
    run(a).unwrap();
}
