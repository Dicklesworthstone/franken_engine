#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleRequest, ResolutionContext, wasm_module_required_capabilities,
};
use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue, WasmFunctionSignature, WasmNativeLoadError, WasmNativeModule, WasmValueType,
};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostCaller, WasmHostImports, WasmNumericLimits, WasmNumericVmError,
};
use frankenengine_engine::wasm_runtime_lane::scheduler::{
    WasmNativeScheduler, WasmTaskAdmissionErrorKind, WasmTaskHandle, WasmTaskOutcome,
};
use WasmBoundaryValue::I32;

type HostResult = Result<Vec<WasmBoundaryValue>, WasmNumericVmError>;

fn work(value: u64) -> NonZeroU64 { NonZeroU64::new(value).unwrap() }
fn slots(value: usize) -> NonZeroUsize { NonZeroUsize::new(value).unwrap() }
fn context() -> ResolutionContext { ResolutionContext::new("schedule-trace", "schedule-decision", "schedule-policy") }

fn policy(host: bool) -> CapabilityPolicyHook {
    let mut caps = wasm_module_required_capabilities();
    if host { caps.insert(RuntimeCapability::Builtin); }
    CapabilityPolicyHook::new(caps)
}

fn leb(mut value: usize) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let low = (value & 127) as u8;
        value >>= 7;
        result.push(low | if value == 0 { 0 } else { 128 });
        if value == 0 { return result; }
    }
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    bytes.push(id); bytes.extend(leb(payload.len())); bytes.extend(payload);
}

fn fixture(host: bool) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[1, 0x60, 1, 0x7f, 1, 0x7f]);
    if host { section(&mut bytes, 2, &[1, 1, b'h', 1, b'f', 0, 0]); }
    section(&mut bytes, 3, &[4, 0, 0, 0, 0]);
    section(&mut bytes, 5, &[1, 1, 1, 1]);
    section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
    let base = u8::from(host);
    let mut exports = vec![6];
    for (name, kind, index) in [
        ("run", 0, base), ("spin", 0, base + 1), ("trap", 0, base + 2),
        ("host", 0, base + 3), ("m", 2, 0), ("g", 3, 0),
    ] {
        exports.extend(leb(name.len())); exports.extend(name.as_bytes()); exports.extend([kind, index]);
    }
    section(&mut bytes, 7, &exports);
    let bodies = [
        vec![0, 0x02, 0x40, 0x03, 0x40, 0x20, 0, 0x45, 0x0d, 1,
             0x23, 0, 0x41, 1, 0x6a, 0x24, 0, 0x20, 0, 0x41, 1, 0x6b, 0x21, 0,
             0x0c, 0, 0x0b, 0x0b, 0x23, 0, 0x0b],
        vec![0, 0x03, 0x40, 0x0c, 0, 0x0b, 0x41, 0, 0x0b],
        vec![0, 0x41, 0, 0x41, 7, 0x36, 2, 0, 0x00, 0x0b],
        if host { vec![0, 0x20, 0, 0x10, 0, 0x41, 1, 0x6a, 0x0b] }
            else { vec![0, 0x20, 0, 0x41, 1, 0x6a, 0x0b] },
    ];
    let mut code = leb(bodies.len());
    for body in bodies { code.extend(leb(body.len())); code.extend(body); }
    section(&mut bytes, 10, &code);
    bytes
}

fn load(host: bool, limits: WasmNumericLimits) -> WasmNativeModule {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let mut definition = ModuleDefinition::wasm_binary(&fixture(host), &limits).unwrap();
    if host { definition = definition.require_capability(RuntimeCapability::Builtin); }
    resolver.register_workspace_module("/app/task.wasm", definition).unwrap();
    resolver.load_wasm(&ModuleRequest::new("/app/task.wasm", ImportStyle::Import),
        &context(), &policy(host), limits).unwrap()
}

fn bindings<F>(callback: F) -> WasmHostImports
where F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue]) -> HostResult + Send + Sync + 'static {
    let mut imports = WasmHostImports::new([RuntimeCapability::VmDispatch, RuntimeCapability::Builtin].into());
    imports.define("h", "f", WasmFunctionSignature {
        params: vec![WasmValueType::I32], results: vec![WasmValueType::I32],
    }, [RuntimeCapability::Builtin].into(), 3, callback).unwrap();
    imports
}

#[test]
fn three_real_instances_run_in_fifo_turns_and_match_unsliced_results_and_meters() {
    let module = load(false, WasmNumericLimits::default());
    let ctx = context(); let allow = policy(false);
    let mut a = module.instantiate(&ctx, &allow).unwrap();
    let mut b = module.instantiate(&ctx, &allow).unwrap();
    let mut c = module.instantiate(&ctx, &allow).unwrap();
    let mut scheduler = WasmNativeScheduler::new(slots(3));
    let handles = [
        scheduler.submit(a.begin_call("run", &[I32(1)], &ctx, &allow).unwrap()).unwrap(),
        scheduler.submit(b.begin_call("run", &[I32(2)], &ctx, &allow).unwrap()).unwrap(),
        scheduler.submit(c.begin_call("run", &[I32(3)], &ctx, &allow).unwrap()).unwrap(),
    ];
    for round in 0..2 {
        for handle in &handles {
            assert_eq!(scheduler.next_task(), Some(handle.id()));
            let turn = scheduler.run_next(work(1), &ctx, &allow).unwrap();
            assert_eq!(turn.task_id, handle.id());
            assert!(matches!(turn.outcome, WasmTaskOutcome::Pending));
            assert_eq!(turn.event.work_after, Some(round + 1));
            assert_eq!(turn.event.trace_id, ctx.trace_id);
            assert_eq!(turn.event.decision_id, ctx.decision_id);
            assert_eq!(turn.event.policy_id, ctx.policy_id);
            assert_eq!(turn.event.component, "wasm_native_scheduler");
            assert_eq!(turn.event.error_code, "none");
            assert_eq!(turn.event.outcome, "yield");
        }
    }
    let mut completed = BTreeSet::new();
    for _ in 0..500 {
        let Some(turn) = scheduler.run_next(work(3), &ctx, &allow) else { break; };
        match turn.outcome {
            WasmTaskOutcome::Pending => {},
            WasmTaskOutcome::Complete(execution) => {
                let index = handles.iter().position(|handle| handle.id() == turn.task_id).unwrap();
                let expected = module.instantiate(&ctx, &allow).unwrap()
                    .call_export("run", &[I32(index as i32 + 1)], &ctx, &allow).unwrap();
                assert_eq!(execution, expected);
                assert!(completed.insert(turn.task_id));
            }
            other => panic!("unexpected task outcome: {other:?}"),
        }
    }
    assert_eq!(completed.len(), 3);
    assert!(scheduler.is_empty());
    assert!(scheduler.run_next(work(1), &ctx, &allow).is_none());
    drop(scheduler);
    assert_eq!(a.global_export("g", &ctx, &allow).unwrap(), Some(&I32(1)));
    assert_eq!(b.global_export("g", &ctx, &allow).unwrap(), Some(&I32(2)));
    assert_eq!(c.global_export("g", &ctx, &allow).unwrap(), Some(&I32(3)));
}

#[test]
fn an_infinite_guest_cannot_starve_a_useful_task() {
    let module = load(false, WasmNumericLimits::default());
    let ctx = context(); let allow = policy(false);
    let mut spinner = module.instantiate(&ctx, &allow).unwrap();
    let mut useful = module.instantiate(&ctx, &allow).unwrap();
    let mut scheduler = WasmNativeScheduler::new(slots(2));
    let spin = scheduler.submit(spinner.begin_call("spin", &[I32(0)], &ctx, &allow).unwrap()).unwrap();
    let finite = scheduler.submit(useful.begin_call("run", &[I32(1)], &ctx, &allow).unwrap()).unwrap();
    let mut finished = false;
    for _ in 0..64 {
        let turn = scheduler.run_next(work(4), &ctx, &allow).unwrap();
        if let WasmTaskOutcome::Complete(result) = turn.outcome {
            assert_eq!(turn.task_id, finite.id()); assert_eq!(result.results, [I32(1)]);
            finished = true; break;
        }
        assert!(matches!(turn.outcome, WasmTaskOutcome::Pending));
    }
    assert!(finished);
    assert_eq!(scheduler.len(), 1);
    spin.cancel();
    let turn = scheduler.run_next(work(4), &ctx, &allow).unwrap();
    assert_eq!(turn.task_id, spin.id());
    assert!(matches!(turn.outcome, WasmTaskOutcome::Cancelled));
    assert_eq!(turn.event.work_after, Some(turn.event.work_before));
    assert!(scheduler.is_empty());
}

#[test]
fn full_queue_returns_unexecuted_work_and_reuses_capacity_without_reusing_identity() {
    let module = load(false, WasmNumericLimits::default());
    let ctx = context(); let allow = policy(false);
    let mut a = module.instantiate(&ctx, &allow).unwrap();
    let mut b = module.instantiate(&ctx, &allow).unwrap();
    let mut scheduler = WasmNativeScheduler::new(slots(1));
    let old = scheduler.submit(a.begin_call("run", &[I32(0)], &ctx, &allow).unwrap()).unwrap();
    let error = scheduler.submit(b.begin_call("run", &[I32(2)], &ctx, &allow).unwrap()).unwrap_err();
    assert_eq!(error.kind(), WasmTaskAdmissionErrorKind::QueueFull);
    let recovered = (*error).into_call();
    assert_eq!(recovered.instructions_executed(), 0);
    assert!(matches!(scheduler.run_next(work(100), &ctx, &allow).unwrap().outcome, WasmTaskOutcome::Complete(_)));
    let next = scheduler.submit(recovered).unwrap();
    assert_eq!(next.id().get(), old.id().get() + 1);
    old.cancel(); // Cannot cancel the newly admitted invocation.
    match scheduler.run_next(work(100), &ctx, &allow).unwrap().outcome {
        WasmTaskOutcome::Complete(result) => assert_eq!(result.results, [I32(2)]),
        other => panic!("lost recovered invocation: {other:?}"),
    }
}

#[test]
fn current_policy_is_rechecked_on_each_turn_and_denial_does_not_block_other_tasks() {
    let module = load(false, WasmNumericLimits::default());
    let ctx = context(); let allow = policy(false);
    let mut a = module.instantiate(&ctx, &allow).unwrap();
    let mut b = module.instantiate(&ctx, &allow).unwrap();
    let mut scheduler = WasmNativeScheduler::new(slots(2));
    let denied = scheduler.submit(a.begin_call("run", &[I32(3)], &ctx, &allow).unwrap()).unwrap();
    assert!(matches!(scheduler.run_next(work(9), &ctx, &allow).unwrap().outcome, WasmTaskOutcome::Pending));
    let healthy = scheduler.submit(b.begin_call("run", &[I32(1)], &ctx, &allow).unwrap()).unwrap();
    let changed = ResolutionContext::new("new-trace", "new-decision", "revoked-policy");
    let turn = scheduler.run_next(work(100), &changed, &CapabilityPolicyHook::new(BTreeSet::new())).unwrap();
    assert_eq!(turn.task_id, denied.id());
    assert!(matches!(turn.outcome, WasmTaskOutcome::Failed(WasmNativeLoadError::Resolution(_))));
    assert_eq!(turn.event.outcome, "deny");
    assert_eq!(turn.event.trace_id, "new-trace");
    assert_eq!(turn.event.policy_id, "revoked-policy");
    assert_eq!(scheduler.next_task(), Some(healthy.id()));
    assert!(matches!(scheduler.run_next(work(100), &ctx, &allow).unwrap().outcome, WasmTaskOutcome::Complete(_)));
    drop(scheduler);
    assert_eq!(a.global_export("g", &ctx, &allow).unwrap(), Some(&I32(1)));
    assert_eq!(b.global_export("g", &ctx, &allow).unwrap(), Some(&I32(1)));
}

#[test]
fn guest_faults_retire_only_the_faulting_task_and_preserve_its_completed_writes() {
    let module = load(false, WasmNumericLimits::default());
    let ctx = context(); let allow = policy(false);
    let mut a = module.instantiate(&ctx, &allow).unwrap();
    let mut b = module.instantiate(&ctx, &allow).unwrap();
    let mut scheduler = WasmNativeScheduler::new(slots(2));
    scheduler.submit(a.begin_call("trap", &[I32(0)], &ctx, &allow).unwrap()).unwrap();
    scheduler.submit(b.begin_call("run", &[I32(1)], &ctx, &allow).unwrap()).unwrap();
    let turn = scheduler.run_next(work(100), &ctx, &allow).unwrap();
    assert!(matches!(turn.outcome, WasmTaskOutcome::Failed(WasmNativeLoadError::Execution(WasmNumericVmError::Unreachable { .. }))));
    assert_eq!(turn.event.work_after, None); // Unknown is not zero/refunded work.
    assert_eq!(scheduler.len(), 1);
    assert!(matches!(scheduler.run_next(work(100), &ctx, &allow).unwrap().outcome, WasmTaskOutcome::Complete(_)));
    drop(scheduler);
    assert_eq!(&a.memory_export("m", &ctx, &allow).unwrap().unwrap()[..4], &7_i32.to_le_bytes());
    assert_eq!(a.call_export("run", &[I32(1)], &ctx, &allow).unwrap().results, [I32(1)]);
}

#[test]
fn a_new_slice_does_not_replenish_the_vm_hard_invocation_budget() {
    let module = load(false, WasmNumericLimits { max_instructions: 20, ..WasmNumericLimits::default() });
    let ctx = context(); let allow = policy(false);
    let mut instance = module.instantiate(&ctx, &allow).unwrap();
    let mut scheduler = WasmNativeScheduler::new(slots(1));
    scheduler.submit(instance.begin_call("run", &[I32(100)], &ctx, &allow).unwrap()).unwrap();
    let mut failed = false;
    for _ in 0..30 {
        let turn = scheduler.run_next(work(1), &ctx, &allow).unwrap();
        match turn.outcome {
            WasmTaskOutcome::Pending => {},
            WasmTaskOutcome::Failed(WasmNativeLoadError::Execution(WasmNumericVmError::InstructionBudgetExceeded { max: 20 })) => { failed = true; break; }
            other => panic!("unexpected budget outcome: {other:?}"),
        }
    }
    assert!(failed); assert!(scheduler.is_empty());
}

#[test]
fn yielding_never_repeats_a_host_effect_and_policy_denial_precedes_pending_callbacks() {
    let module = load(true, WasmNumericLimits::default());
    let ctx = context(); let allow = policy(true);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mut instance = module.instantiate_with_imports(&ctx, &allow, bindings(move |_, args| {
        observed.fetch_add(1, Ordering::SeqCst);
        let [I32(value)] = args else { panic!("checked host ABI") };
        Ok(vec![I32(value * 2)])
    })).unwrap();
    let mut scheduler = WasmNativeScheduler::new(slots(1));
    scheduler.submit(instance.begin_call("host", &[I32(41)], &ctx, &allow).unwrap()).unwrap();
    let mut complete = false;
    for _ in 0..32 {
        let turn = scheduler.run_next(work(1), &ctx, &allow).unwrap();
        if let WasmTaskOutcome::Complete(result) = turn.outcome {
            assert_eq!(result.results, [I32(83)]); complete = true; break;
        }
        assert!(matches!(turn.outcome, WasmTaskOutcome::Pending));
    }
    assert!(complete); assert_eq!(calls.load(Ordering::SeqCst), 1);
    drop(scheduler);
    let mut scheduler = WasmNativeScheduler::new(slots(1));
    scheduler.submit(instance.begin_call("host", &[I32(41)], &ctx, &allow).unwrap()).unwrap();
    assert!(matches!(scheduler.run_next(work(1), &ctx, &allow).unwrap().outcome, WasmTaskOutcome::Pending));
    assert!(matches!(scheduler.run_next(work(100), &ctx, &policy(false)).unwrap().outcome,
        WasmTaskOutcome::Failed(WasmNativeLoadError::Resolution(_))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn task_cancellation_is_scoped_and_discards_results_but_not_completed_effects() {
    let module = load(true, WasmNumericLimits::default());
    let ctx = context(); let allow = policy(true);
    let handle_slot: Arc<Mutex<Option<WasmTaskHandle>>> = Arc::new(Mutex::new(None));
    let provider_handle = handle_slot.clone();
    let mut instance = module.instantiate_with_imports(&ctx, &allow, bindings(move |caller, _| {
        caller.write_memory(8, &[1, 2, 3, 4])?;
        provider_handle.lock().unwrap().as_ref().unwrap().cancel();
        Ok(vec![I32(99)])
    })).unwrap();
    let mut scheduler = WasmNativeScheduler::new(slots(1));
    let handle = scheduler.submit(instance.begin_call("host", &[I32(0)], &ctx, &allow).unwrap()).unwrap();
    *handle_slot.lock().unwrap() = Some(handle);
    let turn = scheduler.run_next(work(100), &ctx, &allow).unwrap();
    assert!(matches!(turn.outcome, WasmTaskOutcome::Cancelled));
    assert!(turn.event.work_after.unwrap() > 0);
    assert!(scheduler.is_empty());
    drop(scheduler);
    assert_eq!(&instance.memory_export("m", &ctx, &allow).unwrap().unwrap()[8..12], &[1, 2, 3, 4]);
    // Cancellation targeted this invocation, not every future use of its instance.
    assert_eq!(instance.call_export("run", &[I32(1)], &ctx, &allow).unwrap().results, [I32(1)]);
}

#[test]
fn cancellation_before_dispatch_never_executes_even_the_first_guest_store() {
    let module = load(false, WasmNumericLimits::default());
    let ctx = context(); let allow = policy(false);
    let mut instance = module.instantiate(&ctx, &allow).unwrap();
    let mut scheduler = WasmNativeScheduler::new(slots(1));
    let handle = scheduler.submit(instance.begin_call("trap", &[I32(0)], &ctx, &allow).unwrap()).unwrap();
    handle.cancel();
    let turn = scheduler.run_next(work(100), &ctx, &allow).unwrap();
    assert!(matches!(turn.outcome, WasmTaskOutcome::Cancelled));
    assert_eq!(turn.event.work_after, Some(0));
    drop(scheduler);
    assert_eq!(&instance.memory_export("m", &ctx, &allow).unwrap().unwrap()[..4], &[0; 4]);
}

#[test]
fn withdrawal_transfers_the_live_continuation_without_resetting_its_meter() {
    let module = load(false, WasmNumericLimits::default());
    let ctx = context(); let allow = policy(false);
    let mut instance = module.instantiate(&ctx, &allow).unwrap();
    let mut scheduler = WasmNativeScheduler::new(slots(1));
    let first = scheduler.submit(instance.begin_call("run", &[I32(3)], &ctx, &allow).unwrap()).unwrap();
    let first_turn = scheduler.run_next(work(9), &ctx, &allow).unwrap();
    let resumed = scheduler.take(first.id()).unwrap();
    assert_eq!(resumed.instructions_executed(), first_turn.event.work_after.unwrap());
    assert!(scheduler.is_empty());
    let next = scheduler.submit(resumed).unwrap();
    first.cancel(); // Its queue position and private signal were retired.
    assert_ne!(first.id(), next.id());
    match scheduler.run_next(work(100), &ctx, &allow).unwrap().outcome {
        WasmTaskOutcome::Complete(result) => {
            let expected = module.instantiate(&ctx, &allow).unwrap().call_export("run", &[I32(3)], &ctx, &allow).unwrap();
            assert_eq!(result, expected);
        }
        other => panic!("withdrew a broken continuation: {other:?}"),
    }
}

#[test]
fn dropping_a_scheduler_releases_instances_without_undoing_prior_slices() {
    let module = load(false, WasmNumericLimits::default());
    let ctx = context(); let allow = policy(false);
    let mut instance = module.instantiate(&ctx, &allow).unwrap();
    {
        let mut scheduler = WasmNativeScheduler::new(slots(1));
        scheduler.submit(instance.begin_call("run", &[I32(3)], &ctx, &allow).unwrap()).unwrap();
        assert!(matches!(scheduler.run_next(work(9), &ctx, &allow).unwrap().outcome, WasmTaskOutcome::Pending));
    }
    assert_eq!(instance.global_export("g", &ctx, &allow).unwrap(), Some(&I32(1)));
    assert_eq!(instance.call_export("run", &[I32(1)], &ctx, &allow).unwrap().results, [I32(2)]);
}
