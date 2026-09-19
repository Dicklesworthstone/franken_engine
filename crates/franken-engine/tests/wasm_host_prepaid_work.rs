#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmCallStep, WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits,
    WasmNumericVm, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::work_pool::WasmWorkPool;

type HostResult = Result<Vec<WasmBoundaryValue>, WasmNumericVmError>;

fn leb(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let low = (n & 127) as u8; n >>= 7;
        out.push(low | if n == 0 { 0 } else { 128 });
        if n == 0 { return out; }
    }
}
fn section(out: &mut Vec<u8>, id: u8, bytes: &[u8]) {
    out.push(id); out.extend(leb(bytes.len())); out.extend(bytes);
}
fn fixture(start: bool) -> Vec<u8> {
    let mut out = b"\0asm\x01\0\0\0".to_vec();
    section(&mut out, 1, &[1, 0x60, 0, 0]);
    section(&mut out, 2, &[1, 1, b'h', 1, b'f', 0, 0]);
    section(&mut out, 3, &[4, 0, 0, 0, 0]);
    section(&mut out, 4, &[1, 0x70, 0, 1]);
    section(&mut out, 5, &[1, 1, 1, 1]);
    section(&mut out, 7, &[6, 1, b'h', 0, 0, 1, b'f', 0, 1, 1, b'i', 0, 2,
        1, b't', 0, 3, 1, b'u', 0, 4, 1, b'm', 2, 0]);
    if start { section(&mut out, 8, &[0]); }
    section(&mut out, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
    let bodies: [&[u8]; 4] = [
        &[0, 0x10, 0, 0x0b],
        &[0, 0x41, 0, 0x11, 0, 0, 0x0b],
        &[0, 0x12, 0, 0x0b],
        &[0, 0x0b],
    ];
    let mut code = vec![4];
    for body in bodies { code.extend(leb(body.len())); code.extend(body); }
    section(&mut out, 10, &code);
    out
}
fn vm(start: bool, budget: u64) -> WasmNumericVm {
    WasmNumericVm::parse(&fixture(start), WasmNumericLimits {
        max_instructions: budget, ..WasmNumericLimits::default()
    }).unwrap()
}
fn imports<F>(pool: &WasmWorkPool, callback: F) -> WasmHostImports
where F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue]) -> HostResult + Send + Sync + 'static {
    let mut registry = WasmHostImports::new(BTreeSet::from([
        RuntimeCapability::VmDispatch, RuntimeCapability::Builtin,
    ]));
    registry.bind_work_pool(pool.clone()).unwrap();
    registry.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![] },
        BTreeSet::from([RuntimeCapability::Builtin]), 1, callback).unwrap();
    registry
}
fn host_error<T: std::fmt::Debug>(result: Result<T, WasmNumericVmError>) -> WasmHostError {
    let Err(WasmNumericVmError::State(WasmStateError::Host(error))) = result else {
        panic!("expected host error: {result:?}");
    };
    error
}
// Exercise the real shared meter in a second instance at a deterministic point
// inside the first callback. No sleeps, timing assumptions or fabricated charge.
fn spend_unreserved(pool: &WasmWorkPool) -> u64 {
    let before = pool.remaining();
    let vm = vm(false, 1000);
    let mut other = vm.instantiate_with_imports(imports(pool, |_, _| panic!("unused import"))).unwrap();
    for _ in 0..before { other.call_export("u", &[]).unwrap(); }
    assert_eq!(pool.remaining(), 0);
    before
}

#[test]
fn exact_prepaid_accesses_do_not_double_charge_or_require_spare_fuel() {
    let vm = vm(false, 5);
    let pool = WasmWorkPool::new(5);
    let registry = imports(&pool, |caller, _| caller.with_prepaid_work(4, |caller| {
        assert_eq!(caller.remaining_work(), 4);
        caller.write_memory(0, b"A")?;
        assert_eq!(caller.remaining_work(), 3);
        assert_eq!(caller.read_memory(0, 1)?, b"A");
        caller.charge_work(1)?;
        caller.write_memory(64, b"B")?;
        assert_eq!(caller.remaining_work(), 0);
        Ok(vec![])
    }));
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert_eq!(instance.call_export("h", &[]).unwrap().instructions_executed, 5);
    assert_eq!(pool.remaining(), 0);
    assert_eq!(instance.memory_export("m").unwrap()[64], b'B');
}

#[test]
fn competing_instance_cannot_steal_work_between_completed_buffer_writes() {
    let vm = vm(false, 100);
    let pool = WasmWorkPool::new(20);
    let competing = pool.clone();
    let registry = imports(&pool, move |caller, _| caller.with_prepaid_work(2, |caller| {
        caller.write_memory(0, b"A")?;
        assert_eq!(spend_unreserved(&competing), 17);
        assert_eq!(caller.remaining_work(), 1);
        caller.write_memory(64, b"B")?;
        Ok(vec![])
    }));
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert_eq!(instance.call_export("h", &[]).unwrap().instructions_executed, 3);
    assert_eq!(&instance.memory_export("m").unwrap()[..1], b"A");
    assert_eq!(&instance.memory_export("m").unwrap()[64..65], b"B");
    assert!(matches!(host_error(instance.call_export("u", &[])), WasmHostError::WorkPool(_)));
}

#[test]
fn insufficient_local_or_shared_credit_refuses_before_operation_entry() {
    for local in [false, true] {
        let vm = vm(false, if local { 4 } else { 100 });
        let pool = WasmWorkPool::new(if local { 100 } else { 4 });
        let entered = Arc::new(AtomicUsize::new(0)); let calls = entered.clone();
        let registry = imports(&pool, move |caller, _| {
            let refused: HostResult = caller.with_prepaid_work(4, |caller| {
                calls.fetch_add(1, Ordering::SeqCst);
                caller.write_memory(0, b"bad")?;
                Ok(vec![])
            });
            assert!(refused.is_err());
            assert!(caller.write_memory(0, b"bad").is_err());
            Ok(vec![]) // Ignoring reservation failure is not success.
        });
        let mut instance = vm.instantiate_with_imports(registry).unwrap();
        let error = instance.call_export("h", &[]).unwrap_err();
        if local { assert!(matches!(error, WasmNumericVmError::InstructionBudgetExceeded { max: 4 })); }
        else { assert!(matches!(error, WasmNumericVmError::State(WasmStateError::Host(WasmHostError::WorkPool(_))))); }
        assert_eq!(entered.load(Ordering::SeqCst), 0);
        assert_eq!(pool.remaining(), if local { 99 } else { 3 });
        assert!(instance.memory_export("m").unwrap().iter().all(|byte| *byte == 0));
    }
}

#[test]
fn nested_scopes_partition_parent_credit_without_charging_it_twice() {
    let vm = vm(false, 100);
    let pool = WasmWorkPool::new(10);
    let registry = imports(&pool, |caller, _| {
        caller.with_prepaid_work::<_, WasmNumericVmError>(4, |caller| {
            caller.with_prepaid_work::<_, WasmNumericVmError>(2, |caller| {
                caller.write_memory(0, b"a")?;
                Ok(()) // The unused inner unit is burned, not returned.
            })?;
            assert_eq!(caller.remaining_work(), 2);
            caller.write_memory(1, b"b")?;
            Ok(()) // The unused outer unit is burned too.
        })?;
        assert_eq!(caller.remaining_work(), 5);
        caller.write_memory(2, b"c")?;
        Ok(vec![])
    });
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert_eq!(instance.call_export("h", &[]).unwrap().instructions_executed, 6);
    assert_eq!(pool.remaining(), 4);
    assert_eq!(&instance.memory_export("m").unwrap()[..3], b"abc");
}

#[test]
fn scope_overrun_cannot_spill_into_available_parent_or_shared_balance() {
    let vm = vm(false, 100);
    let pool = WasmWorkPool::new(100);
    let registry = imports(&pool, |caller, _| caller.with_prepaid_work(4, |caller| {
        let refusal: Result<(), WasmNumericVmError> = caller.with_prepaid_work(5, |_| panic!("overdrawn scope entered"));
        assert_eq!(host_error(refusal), WasmHostError::PrepaidWorkExceeded { requested: 5, remaining: 4 });
        assert!(caller.write_memory(0, b"bad").is_err());
        Ok(vec![])
    }));
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert_eq!(host_error(instance.call_export("h", &[])), WasmHostError::PrepaidWorkExceeded { requested: 5, remaining: 4 });
    assert_eq!(pool.remaining(), 95);
    assert_eq!(&instance.memory_export("m").unwrap()[..3], &[0; 3]);
}

#[test]
fn unused_credit_is_not_available_to_later_invocations() {
    let vm = vm(false, 100);
    let pool = WasmWorkPool::new(5);
    let registry = imports(&pool, |caller, _| caller.with_prepaid_work(4, |_| Ok(vec![])));
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert_eq!(instance.call_export("h", &[]).unwrap().instructions_executed, 5);
    assert!(matches!(host_error(instance.call_export("u", &[])), WasmHostError::WorkPool(_)));
    drop(instance);
    assert_eq!(pool.remaining(), 0);
}

#[test]
fn zero_scope_is_not_unlimited_and_maximum_reservation_cannot_wrap() {
    let vm = vm(false, u64::MAX);
    for units in [0, u64::MAX] {
        let pool = WasmWorkPool::new(u64::MAX);
        let registry = imports(&pool, move |caller, _| caller.with_prepaid_work(units, |caller| {
            caller.write_memory(65_536, b"")?;
            caller.write_memory(0, b"x")?;
            Ok(vec![])
        }));
        let mut instance = vm.instantiate_with_imports(registry).unwrap();
        let error = instance.call_export("h", &[]).unwrap_err();
        if units == 0 {
            assert_eq!(error, WasmHostError::PrepaidWorkExceeded { requested: 1, remaining: 0 }.into());
        } else { assert!(matches!(error, WasmNumericVmError::InstructionBudgetExceeded { max: u64::MAX })); }
        assert_eq!(pool.remaining(), u64::MAX - 1);
    }
}

#[test]
fn prepaid_access_preserves_bounds_failures_and_completed_prefixes() {
    let vm = vm(false, 100);
    let pool = WasmWorkPool::new(10);
    let registry = imports(&pool, |caller, _| caller.with_prepaid_work(4, |caller| {
        caller.write_memory(0, b"a")?;
        assert!(caller.write_memory(u32::MAX, b"bad").is_err());
        assert!(caller.write_memory(1, b"bad").is_err());
        Ok(vec![])
    }));
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert!(matches!(instance.call_export("h", &[]), Err(WasmNumericVmError::State(WasmStateError::MemoryOutOfBounds { .. }))));
    assert_eq!(&instance.memory_export("m").unwrap()[..4], b"a\0\0\0");
    assert_eq!(pool.remaining(), 5);
}

#[test]
fn live_cancellation_and_service_revocation_still_stop_prepaid_access() {
    for scope in 0..3 {
        let vm = vm(false, 100);
        let pool = WasmWorkPool::new(10);
        let token = CancellationToken::new(); let signal = token.clone();
        let mut registry = imports(&pool, move |caller, _| caller.with_prepaid_work(4, |caller| {
            caller.write_memory(0, b"a")?;
            signal.cancel();
            caller.write_memory(1, b"bad")?;
            Ok(vec![])
        }));
        match scope {
            0 => registry.bind_cancellation(token, "prepaid").unwrap(),
            1 => registry.bind_execution_cancellation(token, "prepaid").unwrap(),
            _ => registry.bind_capability_revocation(RuntimeCapability::Builtin, token, "prepaid").unwrap(),
        }
        let mut instance = vm.instantiate_with_imports(registry).unwrap();
        let error = host_error(instance.call_export("h", &[]));
        match scope {
            0 => assert_eq!(error, WasmHostError::Cancelled),
            1 => assert_eq!(error, WasmHostError::ExecutionCancelled),
            _ => assert!(matches!(error, WasmHostError::CapabilityDenied { capability: RuntimeCapability::Builtin, .. })),
        }
        assert_eq!(&instance.memory_export("m").unwrap()[..4], b"a\0\0\0");
        assert_eq!(pool.remaining(), 5);
    }
}

#[test]
fn caught_scope_unwind_is_latched_even_after_accounting_is_restored() {
    let vm = vm(false, 100);
    let pool = WasmWorkPool::new(10);
    let registry = imports(&pool, |caller, _| {
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            caller.with_prepaid_work::<(), WasmNumericVmError>(4, |caller| {
                caller.write_memory(0, b"a")?;
                panic!("interrupted compound operation");
            })
        }));
        assert!(unwind.is_err());
        assert_eq!(host_error(caller.write_memory(1, b"bad")), WasmHostError::PrepaidWorkInterrupted);
        Ok(vec![])
    });
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert_eq!(host_error(instance.call_export("h", &[])), WasmHostError::PrepaidWorkInterrupted);
    assert_eq!(&instance.memory_export("m").unwrap()[..4], b"a\0\0\0");
    assert_eq!(pool.remaining(), 5);
}

#[test]
fn an_earlier_latched_failure_wins_over_a_later_scope_unwind() {
    let vm = vm(false, 100);
    let pool = WasmWorkPool::new(10);
    let registry = imports(&pool, |caller, _| {
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            caller.with_prepaid_work::<(), WasmNumericVmError>(4, |caller| {
                let _ = caller.write_memory(u32::MAX, b"x");
                panic!("later panic");
            })
        }));
        assert!(unwind.is_err());
        Ok(vec![])
    });
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert!(matches!(instance.call_export("h", &[]), Err(WasmNumericVmError::State(WasmStateError::MemoryOutOfBounds { .. }))));
    assert_eq!(pool.remaining(), 5);
}

#[test]
fn uncaught_scope_unwind_keeps_the_instance_host_boundary_poisoned() {
    let vm = vm(false, 100);
    let pool = WasmWorkPool::new(10);
    let registry = imports(&pool, |caller, _| caller.with_prepaid_work(4, |caller| {
        caller.write_memory(0, b"a")?;
        panic!("provider unwind");
    }));
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| instance.call_export("h", &[]))).is_err());
    assert_eq!(host_error(instance.call_export("u", &[])), WasmHostError::HostCallInterrupted);
    assert_eq!(pool.remaining(), 5);
}

#[test]
fn recording_and_replay_charge_the_complete_reservation_including_unused_credit() {
    let vm = vm(false, 10_000);
    let pool = WasmWorkPool::new(10_000);
    let mut registry = imports(&pool, |caller, _| caller.with_prepaid_work(4, |caller| {
        caller.write_memory(0, b"a")?;
        caller.write_memory(1, b"b")?;
        Ok(vec![])
    }));
    let recording = registry.record_calls(WasmHostTraceLimits::default()).unwrap();
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    let expected = instance.call_export("h", &[]).unwrap();
    assert_eq!(expected.instructions_executed, 1029); // dispatch + memory hash + all 4 units
    let tape = recording.snapshot().unwrap();
    for enough in [false, true] {
        let pool = WasmWorkPool::new(expected.instructions_executed - u64::from(!enough));
        let mut registry = imports(&pool, |_, _| panic!("replay entered provider"));
        let replay = registry.replay_calls(tape.clone(), WasmHostTraceLimits::default()).unwrap();
        let mut instance = vm.instantiate_with_imports(registry).unwrap();
        let result = instance.call_export("h", &[]);
        if enough {
            assert_eq!(result.unwrap(), expected);
            assert_eq!(&instance.memory_export("m").unwrap()[..2], b"ab");
            replay.verify_complete().unwrap();
            assert_eq!(pool.remaining(), 0);
        } else {
            assert!(matches!(host_error(result), WasmHostError::WorkPool(_)));
            assert_eq!(&instance.memory_export("m").unwrap()[..2], &[0, 0]);
            assert!(replay.verify_complete().is_err());
            assert_eq!(pool.remaining(), 3);
        }
    }
}

#[test]
fn failed_recorded_operation_keeps_debit_and_replays_only_its_completed_effects() {
    let vm = vm(false, 10_000);
    let pool = WasmWorkPool::new(10_000);
    let mut registry = imports(&pool, |caller, _| caller.with_prepaid_work(4, |caller| {
        caller.write_memory(0, b"a")?;
        Err(WasmHostError::trap("source failed").into())
    }));
    let recording = registry.record_calls(WasmHostTraceLimits::default()).unwrap();
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    let expected = instance.call_export("h", &[]).unwrap_err();
    assert_eq!(pool.remaining(), 10_000 - 1029);
    let mut registry = imports(&WasmWorkPool::new(1029), |_, _| panic!("replay entered failed provider"));
    let replay = registry.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert_eq!(instance.call_export("h", &[]).unwrap_err(), expected);
    assert_eq!(&instance.memory_export("m").unwrap()[..2], b"a\0");
    replay.verify_complete().unwrap();
}

#[test]
fn imported_start_direct_indirect_and_tail_calls_use_the_same_prepaid_boundary() {
    for export in ["h", "f", "i", "t"] {
        let vm = vm(false, 100);
        let mut reference = vm.instantiate_with_imports(imports(&WasmWorkPool::new(100), |caller, _| {
            caller.write_memory(0, b"ab")?;
            caller.write_memory(2, b"cd")?;
            Ok(vec![])
        })).unwrap();
        let expected = reference.call_export(export, &[]).unwrap();
        let pool = WasmWorkPool::new(100);
        let registry = imports(&pool, |caller, _| caller.with_prepaid_work(2, |caller| {
            caller.write_memory(0, b"ab")?;
            caller.write_memory(2, b"cd")?;
            Ok(vec![])
        }));
        let mut instance = vm.instantiate_with_imports(registry).unwrap();
        assert_eq!(instance.call_export(export, &[]).unwrap(), expected);
        assert_eq!(pool.remaining(), 100 - expected.instructions_executed);
        assert_eq!(&instance.memory_export("m").unwrap()[..4], b"abcd");
    }
    let vm = vm(true, 3);
    let pool = WasmWorkPool::new(3);
    let instance = vm.instantiate_with_imports(imports(&pool, |caller, _| caller.with_prepaid_work(2, |caller| {
        caller.write_memory(0, b"a")?; caller.write_memory(1, b"b")?; Ok(vec![])
    }))).unwrap();
    assert_eq!(instance.start_execution().unwrap().instructions_executed, 3);
    assert_eq!(&instance.memory_export("m").unwrap()[..2], b"ab");
}

#[test]
fn cooperative_slices_never_split_or_repeat_a_prepaid_operation() {
    let vm = vm(false, 100);
    let pool = WasmWorkPool::new(100);
    let calls = Arc::new(AtomicUsize::new(0)); let observed = calls.clone();
    let registry = imports(&pool, move |caller, _| caller.with_prepaid_work(2, |caller| {
        observed.fetch_add(1, Ordering::SeqCst);
        caller.write_memory(0, b"a")?; caller.write_memory(1, b"b")?; Ok(vec![])
    }));
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    let mut call = instance.begin_call("f", &[]).unwrap();
    let mut complete = None;
    for _ in 0..10 {
        match call.resume(NonZeroU64::MIN).unwrap() {
            WasmCallStep::Pending(next) => call = next,
            WasmCallStep::Complete(result) => { complete = Some(result); break; }
        }
    }
    assert_eq!(complete.unwrap().instructions_executed, 5);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(pool.remaining(), 95);
}

#[test]
fn ordinary_provider_error_restores_outer_accounting_without_refund() {
    enum Failure { Errno, Vm(WasmNumericVmError) }
    impl From<WasmNumericVmError> for Failure { fn from(error: WasmNumericVmError) -> Self { Self::Vm(error) } }
    let vm = vm(false, 100);
    let pool = WasmWorkPool::new(10);
    let registry = imports(&pool, |caller, _| {
        let outcome: Result<(), Failure> = caller.with_prepaid_work(4, |_| Err(Failure::Errno));
        match outcome { Err(Failure::Errno) => {}, Err(Failure::Vm(error)) => return Err(error), Ok(()) => panic!("lost errno") }
        assert_eq!(caller.remaining_work(), 5);
        caller.write_memory(0, b"a")?;
        Ok(vec![])
    });
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert_eq!(instance.call_export("h", &[]).unwrap().instructions_executed, 6);
    assert_eq!(pool.remaining(), 4);
}
