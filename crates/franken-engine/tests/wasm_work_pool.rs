#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::{Arc, Barrier, atomic::{AtomicUsize, Ordering}};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmCallStep, WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits,
    WasmNumericVm, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::work_pool::{WasmWorkPool, WasmWorkPoolExhausted};
use WasmBoundaryValue::I32;

type HostResult = Result<Vec<WasmBoundaryValue>, WasmNumericVmError>;

fn leb(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let low = (n & 127) as u8; n >>= 7;
        out.push(low | if n == 0 { 0 } else { 128 });
        if n == 0 { return out; }
    }
}
fn section(out: &mut Vec<u8>, id: u8, payload: &[u8]) {
    out.push(id); out.extend(leb(payload.len())); out.extend(payload);
}
fn name(out: &mut Vec<u8>, text: &str) { out.extend(leb(text.len())); out.extend(text.as_bytes()); }

// All variants export inc (six units), unit (one), _start (five), fill
// (seven) and grow (1027). The optional binary start runs _start once.
fn fixture(start: bool, host: bool, large_locals: bool) -> Vec<u8> {
    let mut out = b"\0asm\x01\0\0\0".to_vec();
    section(&mut out, 1, &[2, 0x60, 0, 1, 0x7f, 0x60, 0, 0]);
    if host { section(&mut out, 2, &[1, 1, b'h', 1, b'f', 0, 1]); }
    section(&mut out, 3, &[5, 0, 1, 1, 1, 0]);
    section(&mut out, 5, &[1, 1, 1, 2]);
    section(&mut out, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
    let base = u8::from(host);
    let mut exports = vec![7 + base];
    for (function, index) in [("inc", base), ("unit", base + 1), ("_start", base + 2),
        ("fill", base + 3), ("grow", base + 4)] {
        name(&mut exports, function); exports.extend([0, index]);
    }
    name(&mut exports, "m"); exports.extend([2, 0]);
    name(&mut exports, "g"); exports.extend([3, 0]);
    if host { name(&mut exports, "host"); exports.extend([0, 0]); }
    section(&mut out, 7, &exports);
    if start { section(&mut out, 8, &[base + 2]); }
    let mut unit = if large_locals { let mut v = vec![1]; v.extend(leb(300)); v.push(0x7f); v } else { vec![0] };
    unit.push(0x0b);
    let bodies = [
        vec![0, 0x23, 0, 0x41, 1, 0x6a, 0x24, 0, 0x23, 0, 0x0b],
        unit,
        vec![0, 0x23, 0, 0x41, 1, 0x6a, 0x24, 0, 0x0b],
        vec![0, 0x41, 0, 0x41, 7, 0x41, 0x80, 1, 0xfc, 11, 0, 0x0b],
        vec![0, 0x41, 1, 0x40, 0, 0x0b],
    ];
    let mut code = leb(bodies.len());
    for body in bodies { code.extend(leb(body.len())); code.extend(body); }
    section(&mut out, 10, &code);
    out
}
fn vm(start: bool, host: bool, large: bool, max: u64) -> WasmNumericVm {
    WasmNumericVm::parse(&fixture(start, host, large), WasmNumericLimits {
        max_instructions: max, ..WasmNumericLimits::default()
    }).unwrap()
}
fn imports(pool: &WasmWorkPool) -> WasmHostImports {
    let mut registry = WasmHostImports::new(BTreeSet::new());
    registry.bind_work_pool(pool.clone()).unwrap();
    registry
}
fn host_imports<F>(pool: &WasmWorkPool, callback: F) -> WasmHostImports
where F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue]) -> HostResult + Send + Sync + 'static {
    let mut registry = WasmHostImports::new([RuntimeCapability::Builtin, RuntimeCapability::VmDispatch].into());
    registry.bind_work_pool(pool.clone()).unwrap();
    registry.define("h", "f", WasmFunctionSignature { params: vec![], results: vec![] },
        [RuntimeCapability::Builtin].into(), 5, callback).unwrap();
    registry
}
fn depleted(result: Result<impl std::fmt::Debug, WasmNumericVmError>) -> WasmWorkPoolExhausted {
    match result {
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::WorkPool(error)))) => error,
        other => panic!("expected shared work refusal, got {other:?}"),
    }
}

#[test]
fn repeated_calls_and_fresh_instances_share_one_nonrefundable_quota() {
    let vm = vm(false, false, false, 100);
    let pool = WasmWorkPool::new(18);
    let mut a = vm.instantiate_with_imports(imports(&pool)).unwrap();
    let mut b = vm.instantiate_with_imports(imports(&pool)).unwrap();
    assert_eq!(a.call_export("inc", &[]).unwrap().results, [I32(1)]);
    assert_eq!(b.call_export("inc", &[]).unwrap().results, [I32(1)]);
    assert_eq!(a.call_export("inc", &[]).unwrap().instructions_executed, 6);
    assert_eq!(depleted(b.call_export("inc", &[])).remaining, 0);
    assert_eq!(a.global_export("g"), Some(&I32(2)));
    assert_eq!(b.global_export("g"), Some(&I32(1)));
    drop(a); drop(b);
    assert_eq!(pool.remaining(), 0);
    let mut fresh = vm.instantiate_with_imports(imports(&pool)).unwrap();
    depleted(fresh.call_export("unit", &[]));
}

#[test]
fn shared_refusal_precedes_the_unaffordable_store_and_retains_prior_stores() {
    let vm = vm(false, false, false, 100);
    for (quota, expected) in [(3, 0), (4, 1)] {
        let pool = WasmWorkPool::new(quota);
        let mut instance = vm.instantiate_with_imports(imports(&pool)).unwrap();
        assert_eq!(depleted(instance.call_export("inc", &[])).requested, 1);
        assert_eq!(instance.global_export("g"), Some(&I32(expected)));
        assert_eq!(pool.remaining(), 0);
    }
}

#[test]
fn local_budget_refusal_does_not_debit_a_rejected_shared_charge() {
    let vm = vm(false, false, false, 2);
    let pool = WasmWorkPool::new(100);
    let mut instance = vm.instantiate_with_imports(imports(&pool)).unwrap();
    assert!(matches!(instance.call_export("inc", &[]), Err(WasmNumericVmError::InstructionBudgetExceeded { max: 2 })));
    assert_eq!(pool.remaining(), 98);
    assert_eq!(instance.global_export("g"), Some(&I32(0)));
}

#[test]
fn invalid_entry_and_prepared_drop_do_not_spend_work() {
    let vm = vm(false, false, false, 100);
    let pool = WasmWorkPool::new(5);
    let mut instance = vm.instantiate_with_imports(imports(&pool)).unwrap();
    assert!(instance.call_export("absent", &[]).is_err());
    assert!(instance.begin_call("inc", &[I32(1)]).is_err());
    instance.begin_call("inc", &[]).unwrap().cancel();
    assert_eq!(pool.remaining(), 5);
}

#[test]
fn unbound_execution_keeps_existing_metrics_and_bound_execution_matches_them() {
    let vm = vm(false, false, false, 100);
    let expected = vm.instantiate().unwrap().call_export("inc", &[]).unwrap();
    let pool = WasmWorkPool::new(100);
    let actual = vm.instantiate_with_imports(imports(&pool)).unwrap().call_export("inc", &[]).unwrap();
    assert_eq!(actual, expected);
    assert_eq!(pool.remaining(), 100 - actual.instructions_executed);
}

#[test]
fn concurrent_instances_cannot_overdraw_the_shared_counter() {
    let vm = vm(false, false, false, 100);
    let pool = WasmWorkPool::new(1000);
    let barrier = Barrier::new(8);
    let total = std::thread::scope(|scope| {
        let mut threads = Vec::new();
        for _ in 0..8 {
            let vm = &vm; let pool = &pool; let barrier = &barrier;
            threads.push(scope.spawn(move || {
                let mut instance = vm.instantiate_with_imports(imports(pool)).unwrap();
                barrier.wait();
                let mut success = 0;
                for _ in 0..250 {
                    match instance.call_export("unit", &[]) {
                        Ok(execution) => { assert_eq!(execution.instructions_executed, 1); success += 1; }
                        error => { assert_eq!(depleted(error).remaining, 0); }
                    }
                }
                success
            }));
        }
        threads.into_iter().map(|thread| thread.join().unwrap()).sum::<usize>()
    });
    assert_eq!(total, 1000);
    assert_eq!(pool.remaining(), 0);
}

#[test]
fn registry_cannot_replace_its_quota_before_linking() {
    let first = WasmWorkPool::new(1); let other = WasmWorkPool::new(100);
    let mut registry = imports(&first);
    assert!(matches!(registry.bind_work_pool(other.clone()), Err(WasmHostError::WorkPoolAlreadyBound)));
    let vm = vm(false, false, false, 100);
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    instance.call_export("unit", &[]).unwrap();
    depleted(instance.call_export("unit", &[]));
    assert_eq!(other.remaining(), 100);
}

#[test]
fn binary_start_and_later_exports_spend_the_same_balance() {
    let vm = vm(true, false, false, 100);
    let pool = WasmWorkPool::new(11);
    let mut instance = vm.instantiate_with_imports(imports(&pool)).unwrap();
    assert_eq!(instance.start_execution().unwrap().instructions_executed, 5);
    assert_eq!(pool.remaining(), 6);
    assert_eq!(instance.call_export("inc", &[]).unwrap().results, [I32(2)]);
    assert_eq!(pool.remaining(), 0);
    let failed = WasmWorkPool::new(4);
    depleted(vm.instantiate_with_imports(imports(&failed)));
    assert_eq!(failed.remaining(), 0);
}

#[test]
fn host_fixed_charge_refuses_before_provider_entry_without_partial_debit() {
    let vm = vm(false, true, false, 100);
    let pool = WasmWorkPool::new(4);
    let entered = Arc::new(AtomicUsize::new(0)); let counter = entered.clone();
    let registry = host_imports(&pool, move |_, _| { counter.fetch_add(1, Ordering::SeqCst); Ok(vec![]) });
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert_eq!(depleted(instance.call_export("host", &[])), WasmWorkPoolExhausted { requested: 5, remaining: 4 });
    assert_eq!(pool.remaining(), 4);
    assert_eq!(entered.load(Ordering::SeqCst), 0);
}

#[test]
fn ignored_provider_quota_refusal_latches_before_any_later_buffer_write() {
    let vm = vm(false, true, false, 100);
    let pool = WasmWorkPool::new(7);
    let registry = host_imports(&pool, |caller, _| {
        assert_eq!(caller.remaining_work(), 2);
        let first = caller.charge_work(3).unwrap_err();
        assert_eq!(caller.write_memory(0, b"bad").unwrap_err(), first);
        Ok(vec![])
    });
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert_eq!(depleted(instance.call_export("host", &[])).requested, 3);
    assert_eq!(pool.remaining(), 2);
    assert_eq!(&instance.memory_export("m").unwrap()[..3], &[0, 0, 0]);
}

#[test]
fn bulk_memory_work_refuses_atomically_and_keeps_unused_units() {
    let vm = vm(false, false, false, 10000);
    let pool = WasmWorkPool::new(5);
    let mut instance = vm.instantiate_with_imports(imports(&pool)).unwrap();
    assert_eq!(depleted(instance.call_export("fill", &[])), WasmWorkPoolExhausted { requested: 2, remaining: 1 });
    assert_eq!(pool.remaining(), 1);
    assert!(instance.memory_export("m").unwrap().iter().all(|byte| *byte == 0));
    instance.call_export("unit", &[]).unwrap(); // The failed large charge did not consume this unit.
    assert_eq!(pool.remaining(), 0);
}

#[test]
fn growth_and_large_activation_setup_use_the_same_shared_precharge() {
    let vm = vm(false, false, true, 10000);
    let pool = WasmWorkPool::new(1025);
    let mut instance = vm.instantiate_with_imports(imports(&pool)).unwrap();
    assert_eq!(depleted(instance.call_export("grow", &[])).requested, 1024);
    assert_eq!(instance.memory_export("m").unwrap().len(), 65536);
    assert_eq!(pool.remaining(), 1023);
    let small = WasmWorkPool::new(3);
    let mut large = vm.instantiate_with_imports(imports(&small)).unwrap();
    assert_eq!(depleted(large.call_export("unit", &[])).requested, 4);
    assert_eq!(small.remaining(), 3);
}

#[test]
fn host_fault_and_panic_never_refund_completed_work() {
    let vm = vm(false, true, false, 100);
    let pool = WasmWorkPool::new(100);
    let registry = host_imports(&pool, |caller, _| {
        caller.charge_work(3)?;
        Err(WasmHostError::trap("provider fault").into())
    });
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert!(instance.call_export("host", &[]).is_err());
    assert_eq!(pool.remaining(), 92);
    drop(instance);
    let registry = host_imports(&pool, |caller, _| { caller.charge_work(3)?; panic!("provider panic"); });
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| instance.call_export("host", &[]))).is_err());
    drop(instance);
    assert_eq!(pool.remaining(), 84);
}

#[test]
fn cancellation_and_slice_drop_do_not_reset_or_refund_shared_work() {
    let vm = vm(false, false, false, 100);
    let pool = WasmWorkPool::new(100);
    let signal = CancellationToken::new();
    let mut registry = imports(&pool);
    registry.bind_execution_cancellation(signal.clone(), "quota-cancel").unwrap();
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    let call = instance.begin_call("inc", &[]).unwrap();
    let WasmCallStep::Pending(call) = call.resume(NonZeroU64::new(4).unwrap()).unwrap() else { panic!("pending store"); };
    assert_eq!(pool.remaining(), 96);
    signal.cancel();
    assert!(matches!(call.resume(NonZeroU64::new(4).unwrap()), Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::ExecutionCancelled)))));
    assert_eq!(pool.remaining(), 96);
    assert_eq!(instance.global_export("g"), Some(&I32(1)));
    drop(instance);
    let mut instance = vm.instantiate_with_imports(imports(&pool)).unwrap();
    let WasmCallStep::Pending(call) = instance.begin_call("inc", &[]).unwrap().resume(NonZeroU64::new(2).unwrap()).unwrap() else { panic!("pending"); };
    call.cancel();
    assert_eq!(pool.remaining(), 94);
}

#[test]
fn replay_must_pay_live_quota_before_effects_without_reentering_providers() {
    let vm = vm(false, true, false, 10000);
    let pool = WasmWorkPool::new(10000);
    let mut registry = host_imports(&pool, |caller, _| { caller.charge_work(3)?; caller.write_memory(0, b"ok")?; Ok(vec![]) });
    let recorder = registry.record_calls(WasmHostTraceLimits::default()).unwrap();
    let mut instance = vm.instantiate_with_imports(registry).unwrap();
    let execution = instance.call_export("host", &[]).unwrap();
    let tape = recorder.snapshot().unwrap();
    assert_eq!(pool.remaining(), 10000 - execution.instructions_executed);
    drop(instance);
    for enough in [false, true] {
        let quota = WasmWorkPool::new(execution.instructions_executed - u64::from(!enough));
        let mut registry = host_imports(&quota, |_, _| panic!("replay called provider"));
        let replay = registry.replay_calls(tape.clone(), WasmHostTraceLimits::default()).unwrap();
        let mut instance = vm.instantiate_with_imports(registry).unwrap();
        let result = instance.call_export("host", &[]);
        if enough {
            assert_eq!(result.unwrap(), execution);
            assert_eq!(&instance.memory_export("m").unwrap()[..2], b"ok");
            replay.verify_complete().unwrap();
            assert_eq!(quota.remaining(), 0);
        } else {
            assert_eq!(depleted(result).requested, 4);
            assert_eq!(&instance.memory_export("m").unwrap()[..2], &[0, 0]);
            assert!(replay.verify_complete().is_err());
            assert_eq!(quota.remaining(), 3);
        }
    }
}

#[test]
fn imported_start_is_charged_before_and_inside_the_provider() {
    let mut bytes = fixture(true, true, false);
    let mut offset = 8;
    loop {
        let id = bytes[offset]; offset += 1;
        let mut size = 0usize; let mut shift = 0;
        loop {
            let byte = bytes[offset]; offset += 1;
            size |= usize::from(byte & 127) << shift;
            if byte & 128 == 0 { break; }
            shift += 7;
        }
        if id == 8 { assert_eq!(size, 1); bytes[offset] = 0; break; }
        offset += size;
    }
    let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    for limit in [7, 8] {
        let pool = WasmWorkPool::new(limit);
        let entered = Arc::new(AtomicUsize::new(0)); let counter = entered.clone();
        let registry = host_imports(&pool, move |caller, _| {
            counter.fetch_add(1, Ordering::SeqCst);
            caller.charge_work(3)?;
            Ok(vec![])
        });
        let result = vm.instantiate_with_imports(registry);
        if limit == 7 {
            assert_eq!(depleted(result), WasmWorkPoolExhausted { requested: 3, remaining: 2 });
            assert_eq!(pool.remaining(), 2);
        } else {
            let instance = result.unwrap();
            assert_eq!(instance.start_execution().unwrap().instructions_executed, 8);
            assert_eq!(instance.global_export("g"), Some(&I32(0)));
            assert_eq!(pool.remaining(), 0);
        }
        assert_eq!(entered.load(Ordering::SeqCst), 1);
    }
}
