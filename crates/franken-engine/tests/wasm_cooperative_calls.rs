#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature, WasmValueType};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmCall, WasmCallStep, WasmHostImports, WasmNumericExecution, WasmNumericLimits,
    WasmNumericVm, WasmNumericVmError,
};
use WasmBoundaryValue::{F64Bits, I32, I64};

// Each body below is a real binary program for the production validator/VM.
// Const/global/host effects make restarts and omitted operations observable.
const IDENTITY: &[u8] = &[0x20, 0, 0x0b];
const HOST_CALL: &[u8] = &[0x20, 0, 0x10, 0, 0x0b];
const INDIRECT_HOST_CALL: &[u8] = &[0x20, 0, 0x41, 0, 0x11, 0, 0, 0x0b];
const TWO_HOST_CALLS: &[u8] = &[0x20, 0, 0x10, 0, 0x1a, 0x20, 0, 0x10, 0, 0x0b];
const TRAP_AFTER_STORE: &[u8] = &[0x20, 0, 0x24, 0, 0x00, 0x0b];
const INFINITE: &[u8] = &[
    0x03, 0x40, 0x23, 0, 0x41, 1, 0x6a, 0x24, 0, 0x0c, 0, 0x0b, 0x0b,
];
const SUM_DOWN: &[u8] = &[
    0x20, 0, 0x04, 0x7f, 0x41, 1, 0x20, 0, 0x41, 1, 0x6b, 0x10, 0,
    0x6a, 0x05, 0x41, 0, 0x0b, 0x0b,
];
const FILL: &[u8] = &[0x41, 0, 0x41, 42, 0x20, 0, 0xfc, 11, 0, 0x0b];
const LOOP: &[u8] = &[
    0x02, 0x40, 0x03, 0x40, 0x20, 0, 0x45, 0x0d, 1,
    0x23, 0, 0x41, 1, 0x6a, 0x24, 0,
    0x20, 0, 0x41, 1, 0x6b, 0x21, 0, 0x0c, 0, 0x0b, 0x0b, 0x23, 0, 0x0b,
];

fn leb(mut n: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let low = (n & 127) as u8;
        n >>= 7;
        bytes.push(low | if n == 0 { 0 } else { 128 });
        if n == 0 { return bytes; }
    }
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    bytes.push(id); bytes.extend(leb(payload.len())); bytes.extend_from_slice(payload);
}

fn fixture(params: &[u8], results: &[u8], bodies: &[&[u8]], host: bool) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    let mut ty = vec![1, 0x60];
    ty.extend(leb(params.len())); ty.extend_from_slice(params);
    ty.extend(leb(results.len())); ty.extend_from_slice(results);
    section(&mut bytes, 1, &ty);
    if host { section(&mut bytes, 2, &[1, 1, b'h', 1, b'f', 0, 0]); }
    let mut functions = leb(bodies.len()); functions.resize(functions.len() + bodies.len(), 0);
    section(&mut bytes, 3, &functions);
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    section(&mut bytes, 5, &[1, 1, 1, 2]);
    section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
    let mut exports = vec![4 + u8::from(host), 1, b'f', 0, u8::from(host),
        1, b'm', 2, 0, 1, b'g', 3, 0, 1, b't', 1, 0];
    if host { exports.extend([1, b'h', 0, 0]); }
    section(&mut bytes, 7, &exports);
    section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
    let mut code = leb(bodies.len());
    for body in bodies { code.extend(leb(body.len() + 1)); code.push(0); code.extend_from_slice(body); }
    section(&mut bytes, 10, &code);
    section(&mut bytes, 11, &[1, 0, 0x41, 8, 0x0b, 4, 9, 8, 7, 6]);
    bytes
}

fn vm(code: &[u8], results: &[u8], limits: WasmNumericLimits) -> WasmNumericVm {
    WasmNumericVm::parse(&fixture(&[0x7f], results, &[code], false), limits).unwrap()
}

fn quantum(work: u64) -> NonZeroU64 { NonZeroU64::new(work).unwrap() }

fn finish(mut call: WasmCall<'_, '_>, work: u64) -> Result<WasmNumericExecution, WasmNumericVmError> {
    // Bound the test driver independently of the engine: resetting the hard
    // budget or returning an empty suspension must fail, not hang the suite.
    let mut before = 0;
    for _ in 0..100_000 {
        match call.resume(quantum(work))? {
            WasmCallStep::Complete(execution) => return Ok(execution),
            WasmCallStep::Pending(next) => {
                assert!(next.instructions_executed() > before, "yield made no work progress");
                before = next.instructions_executed();
                call = next;
            }
        }
    }
    panic!("invocation did not complete or exhaust its original budget");
}

fn provider(calls: Arc<AtomicUsize>) -> WasmHostImports {
    let mut imports = WasmHostImports::new(BTreeSet::from([
        RuntimeCapability::Builtin, RuntimeCapability::VmDispatch,
    ]));
    imports.define("h", "f", WasmFunctionSignature {
        params: vec![WasmValueType::I32], results: vec![WasmValueType::I32],
    }, BTreeSet::from([RuntimeCapability::Builtin]), 7, move |caller, args| {
        let [I32(value)] = args else { panic!("validated host ABI"); };
        caller.write_memory(0, &value.to_le_bytes())?;
        calls.fetch_add(1, Ordering::SeqCst);
        Ok(vec![I32(*value)])
    }).unwrap();
    imports
}

#[test]
fn slices_preserve_structured_loops_and_every_execution_metric() {
    let vm = vm(LOOP, &[0x7f], WasmNumericLimits::default());
    let expected = vm.call_export("f", &[I32(17)]).unwrap();
    assert_eq!(expected.results, [I32(17)]);
    for work in [1, 2, 3, 7, 32, u64::MAX] {
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(finish(instance.begin_call("f", &[I32(17)]).unwrap(), work).unwrap(), expected);
        assert_eq!(instance.global_export("g"), Some(&I32(17)));
        // Completed invocation state persists; preparation never reruns startup.
        assert_eq!(instance.call_export("f", &[I32(2)]).unwrap().results, [I32(19)]);
    }
}

#[test]
fn nested_calls_keep_suspended_operands_locals_and_depth() {
    let vm = vm(SUM_DOWN, &[0x7f], WasmNumericLimits::default());
    let expected = vm.call_export("f", &[I32(40)]).unwrap();
    assert_eq!(expected.results, [I32(40)]);
    assert_eq!(expected.max_call_depth, 41);
    for work in [1, 2, 7, 100] {
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(finish(instance.begin_call("f", &[I32(40)]).unwrap(), work).unwrap(), expected);
    }
}

#[test]
fn a_return_at_the_exact_slice_boundary_completes_without_an_empty_yield() {
    let vm = vm(IDENTITY, &[0x7f], WasmNumericLimits::default());
    let mut instance = vm.instantiate().unwrap();
    let step = instance.begin_call("f", &[I32(42)]).unwrap().resume(quantum(2)).unwrap();
    match step {
        WasmCallStep::Complete(result) => {
            assert_eq!(result.results, [I32(42)]);
            assert_eq!(result.instructions_executed, 2);
        }
        WasmCallStep::Pending(_) => panic!("terminal end was deferred"),
    }
}

#[test]
fn hard_instruction_budget_is_shared_across_all_slices() {
    let vm = vm(INFINITE, &[], WasmNumericLimits { max_instructions: 31, ..WasmNumericLimits::default() });
    let mut blocking = vm.instantiate().unwrap();
    let expected = blocking.call_export("f", &[I32(0)]).unwrap_err();
    assert_eq!(expected, WasmNumericVmError::InstructionBudgetExceeded { max: 31 });
    for work in [1, 2, 5, 31, u64::MAX] {
        let mut sliced = vm.instantiate().unwrap();
        assert_eq!(finish(sliced.begin_call("f", &[I32(0)]).unwrap(), work).unwrap_err(), expected);
        assert_eq!(sliced.global_export("g"), blocking.global_export("g"));
    }
}

#[test]
fn live_value_and_call_depth_limits_do_not_reset_when_suspended() {
    for limits in [
        WasmNumericLimits { max_live_values: 16, ..WasmNumericLimits::default() },
        WasmNumericLimits { max_call_depth: 8, ..WasmNumericLimits::default() },
    ] {
        let vm = vm(SUM_DOWN, &[0x7f], limits);
        let expected = vm.call_export("f", &[I32(40)]).unwrap_err();
        assert!(matches!(expected, WasmNumericVmError::LiveValueLimitExceeded { .. } | WasmNumericVmError::CallDepthExceeded { .. }));
        for work in [1, 3, 13] {
            let mut instance = vm.instantiate().unwrap();
            assert_eq!(finish(instance.begin_call("f", &[I32(40)]).unwrap(), work).unwrap_err(), expected);
        }
    }
}

#[test]
fn arguments_are_owned_and_preparation_does_not_execute_guest_code() {
    let vm = vm(IDENTITY, &[0x7f], WasmNumericLimits::default());
    let mut instance = vm.instantiate().unwrap();
    let mut arguments = vec![I32(42)];
    let call = instance.begin_call("f", &arguments).unwrap();
    arguments[0] = I32(99);
    assert_eq!(call.instructions_executed(), 0);
    assert_eq!(finish(call, 1).unwrap().results, [I32(42)]);
    for name in ["missing", "m", "g", "t"] { assert!(instance.begin_call(name, &[I32(0)]).is_err()); }
    assert!(matches!(instance.begin_call("f", &[I64(0)]), Err(WasmNumericVmError::TypeMismatch { .. })));
    assert!(matches!(instance.begin_call("f", &[]), Err(WasmNumericVmError::ArityMismatch { .. })));
    assert_eq!(instance.global_export("g"), Some(&I32(0)));
}

#[test]
fn cancelling_a_pending_callee_does_not_enter_it() {
    let vm = WasmNumericVm::parse(&fixture(&[0x7f], &[0x7f], &[HOST_CALL], true), WasmNumericLimits::default()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut instance = vm.instantiate_with_imports(provider(calls.clone())).unwrap();
    let call = instance.begin_call("f", &[I32(42)]).unwrap();
    match call.resume(quantum(2)).unwrap() {
        WasmCallStep::Pending(call) => {
            assert_eq!(call.instructions_executed(), 2);
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            call.cancel();
        }
        WasmCallStep::Complete(_) => panic!("pending host was entered past the boundary"),
    }
    assert_eq!(&instance.memory_export("m").unwrap()[..4], &[0; 4]);
    assert_eq!(instance.call_export("f", &[I32(42)]).unwrap().results, [I32(42)]);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn cancelling_after_an_atomic_host_call_keeps_its_effect_exactly_once() {
    let vm = WasmNumericVm::parse(&fixture(&[0x7f], &[0x7f], &[HOST_CALL], true), WasmNumericLimits::default()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut instance = vm.instantiate_with_imports(provider(calls.clone())).unwrap();
    let WasmCallStep::Pending(call) = instance.begin_call("f", &[I32(42)]).unwrap().resume(quantum(2)).unwrap()
        else { panic!("expected pending host"); };
    let WasmCallStep::Pending(call) = call.resume(quantum(1)).unwrap()
        else { panic!("callback must yield before caller end"); };
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert!(call.instructions_executed() > 3, "atomic host cost overran the soft quantum");
    drop(call);
    assert_eq!(&instance.memory_export("m").unwrap()[..4], &42_i32.to_le_bytes());
    assert_eq!(instance.call_export("h", &[I32(7)]).unwrap().results, [I32(7)]);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn direct_indirect_and_exported_host_calls_match_blocking_execution() {
    for code in [HOST_CALL, INDIRECT_HOST_CALL, TWO_HOST_CALLS] {
        let vm = WasmNumericVm::parse(&fixture(&[0x7f], &[0x7f], &[code], true), WasmNumericLimits::default()).unwrap();
        for export in ["f", "h"] {
            let mut blocking = vm.instantiate_with_imports(provider(Arc::new(AtomicUsize::new(0)))).unwrap();
            let expected = blocking.call_export(export, &[I32(-7)]).unwrap();
            for work in [1, 2, 4, 64] {
                let calls = Arc::new(AtomicUsize::new(0));
                let mut instance = vm.instantiate_with_imports(provider(calls.clone())).unwrap();
                assert_eq!(finish(instance.begin_call(export, &[I32(-7)]).unwrap(), work).unwrap(), expected);
                assert_eq!(instance.memory_export("m"), blocking.memory_export("m"));
                assert_eq!(calls.load(Ordering::SeqCst), if code == TWO_HOST_CALLS && export == "f" { 2 } else { 1 });
            }
        }
    }
}

#[test]
fn bulk_instruction_is_not_split_and_still_refuses_on_the_hard_budget() {
    let vm = vm(FILL, &[], WasmNumericLimits::default());
    let mut instance = vm.instantiate().unwrap();
    let WasmCallStep::Pending(call) = instance.begin_call("f", &[I32(4096)]).unwrap().resume(quantum(4)).unwrap()
        else { panic!("fill should yield before end"); };
    assert_eq!(call.instructions_executed(), 68); // 4 opcodes + 4096 / 64
    call.cancel();
    assert!(instance.memory_export("m").unwrap()[..4096].iter().all(|byte| *byte == 42));
    let limited = self::vm(FILL, &[], WasmNumericLimits { max_instructions: 4, ..WasmNumericLimits::default() });
    let mut instance = limited.instantiate().unwrap();
    let before = instance.memory_export("m").unwrap().to_vec();
    assert_eq!(finish(instance.begin_call("f", &[I32(4096)]).unwrap(), 1).unwrap_err(),
        WasmNumericVmError::InstructionBudgetExceeded { max: 4 });
    assert_eq!(instance.memory_export("m").unwrap(), before);
}

#[test]
fn a_later_trap_ends_the_continuation_but_preserves_completed_guest_stores() {
    let vm = vm(TRAP_AFTER_STORE, &[], WasmNumericLimits::default());
    let mut instance = vm.instantiate().unwrap();
    assert!(matches!(finish(instance.begin_call("f", &[I32(42)]).unwrap(), 1), Err(WasmNumericVmError::Unreachable { .. })));
    assert_eq!(instance.global_export("g"), Some(&I32(42)));
    assert!(matches!(instance.call_export("f", &[I32(7)]), Err(WasmNumericVmError::Unreachable { .. })));
    assert_eq!(instance.global_export("g"), Some(&I32(7)));
}

#[test]
fn sliced_and_blocking_host_transcripts_are_identical_and_replay_with_new_quanta() {
    let vm = WasmNumericVm::parse(&fixture(&[0x7f], &[0x7f], &[TWO_HOST_CALLS], true), WasmNumericLimits::default()).unwrap();
    let mut bindings = provider(Arc::new(AtomicUsize::new(0)));
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    let mut blocking = vm.instantiate_with_imports(bindings).unwrap();
    let expected = blocking.call_export("f", &[I32(42)]).unwrap();
    let transcript = recording.snapshot().unwrap();
    for work in [1, 2, 9, 1024, u64::MAX] {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut bindings = provider(calls.clone());
        let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
        let mut live = vm.instantiate_with_imports(bindings).unwrap();
        assert_eq!(finish(live.begin_call("f", &[I32(42)]).unwrap(), work).unwrap(), expected);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(recording.snapshot().unwrap(), transcript);
        let never_called = Arc::new(AtomicUsize::new(0));
        let mut bindings = provider(never_called.clone());
        let replay = bindings.replay_calls(transcript.clone(), WasmHostTraceLimits::default()).unwrap();
        let mut replayed = vm.instantiate_with_imports(bindings).unwrap();
        assert_eq!(finish(replayed.begin_call("f", &[I32(42)]).unwrap(), work).unwrap(), expected);
        assert_eq!(never_called.load(Ordering::SeqCst), 0);
        assert_eq!(replayed.memory_export("m"), blocking.memory_export("m"));
        replay.verify_complete().unwrap();
    }
}

#[test]
fn multivalue_returns_retain_exact_float_and_integer_bits_across_call_boundaries() {
    let caller = &[0x20, 0, 0x20, 1, 0x10, 1, 0x0b][..];
    let callee = &[0x20, 0, 0x20, 1, 0x0b][..];
    let bytes = fixture(&[0x7e, 0x7c], &[0x7e, 0x7c], &[caller, callee], false);
    let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    let args = [I64(i64::MIN), F64Bits(0x7ff0_0000_0000_0042)];
    let expected = vm.call_export("f", &args).unwrap();
    assert_eq!(expected.results, args);
    for work in [1, 2, 3] {
        let mut instance = vm.instantiate().unwrap();
        assert_eq!(finish(instance.begin_call("f", &args).unwrap(), work).unwrap(), expected);
    }
}

#[test]
fn continuations_are_send_and_sync_and_prepared_cancellation_has_no_effects() {
    fn assert_traits<T: Send + Sync>() {}
    assert_traits::<WasmCall<'static, 'static>>();
    assert_traits::<WasmCallStep<'static, 'static>>();
    let vm = vm(TRAP_AFTER_STORE, &[], WasmNumericLimits::default());
    let mut instance = vm.instantiate().unwrap();
    instance.begin_call("f", &[I32(99)]).unwrap().cancel();
    assert_eq!(instance.global_export("g"), Some(&I32(0)));
}

mod resolved {
    use super::*;
    use frankenengine_engine::module_resolver::{
        CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
        ModuleRequest, ModuleSyntax, ResolutionContext, ResolutionErrorCode,
        wasm_module_required_capabilities,
    };
    use frankenengine_engine::wasm_runtime_lane::{
        WasmNativeCall, WasmNativeCallStep, WasmNativeLoadError, WasmNativeModule,
    };

    fn context() -> ResolutionContext { ResolutionContext::new("slice-trace", "slice-decision", "current") }

    fn policy() -> CapabilityPolicyHook {
        let mut caps = wasm_module_required_capabilities();
        caps.insert(RuntimeCapability::Builtin);
        CapabilityPolicyHook::new(caps)
    }

    fn module(code: &[u8], host: bool, results: &[u8], limits: WasmNumericLimits) -> WasmNativeModule {
        let bytes = fixture(&[0x7f], results, &[code], host);
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver.register_workspace_module("/app/main.mjs", ModuleDefinition::new(
            ModuleSyntax::EsModule, "import './task.wasm';",
        )).unwrap();
        resolver.register_workspace_module("/app/task.wasm", ModuleDefinition::wasm_binary(
            &bytes, &WasmNumericLimits::default(),
        ).unwrap().require_capability(RuntimeCapability::Builtin)).unwrap();
        resolver.load_wasm(
            &ModuleRequest::new("./task.wasm", ImportStyle::Import).with_referrer("/app/main.mjs"),
            &context(), &policy(), limits,
        ).unwrap()
    }

    fn finish(mut call: WasmNativeCall<'_, '_>, work: u64, policy: &CapabilityPolicyHook) -> Result<WasmNumericExecution, WasmNativeLoadError> {
        let mut before = 0;
        for _ in 0..100_000 {
            match call.resume(quantum(work), &context(), policy)? {
                WasmNativeCallStep::Complete(result) => return Ok(result),
                WasmNativeCallStep::Pending(next) => {
                    assert!(next.instructions_executed() > before);
                    before = next.instructions_executed();
                    call = next;
                }
            }
        }
        panic!("resolved call never terminated");
    }

    fn denied<T: std::fmt::Debug>(result: Result<T, WasmNativeLoadError>) {
        match result {
            Err(WasmNativeLoadError::Resolution(error)) => assert_eq!(error.code, ResolutionErrorCode::PolicyDenied),
            other => panic!("expected current-policy denial, got {other:?}"),
        }
    }

    #[test]
    fn resolved_execution_keeps_the_same_result_and_metrics_across_slices() {
        let module = module(LOOP, false, &[0x7f], WasmNumericLimits::default());
        let grants = policy();
        let mut blocking = module.instantiate(&context(), &grants).unwrap();
        let expected = blocking.call_export("f", &[I32(20)], &context(), &grants).unwrap();
        for work in [1, 3, 11, u64::MAX] {
            let mut instance = module.instantiate(&context(), &grants).unwrap();
            let call = instance.begin_call("f", &[I32(20)], &context(), &grants).unwrap();
            assert_eq!(finish(call, work, &grants).unwrap(), expected);
            assert_eq!(instance.global_export("g", &context(), &grants).unwrap(), Some(&I32(20)));
        }
    }

    #[test]
    fn revocation_at_a_yield_prevents_pending_host_entry_but_retains_prior_guest_writes() {
        let code = &[0x41, 9, 0x24, 0, 0x20, 0, 0x10, 0, 0x0b];
        let module = module(code, true, &[0x7f], WasmNumericLimits::default());
        let grants = policy();
        for capability in [RuntimeCapability::Builtin, RuntimeCapability::VmDispatch, RuntimeCapability::ModuleLoad] {
            let calls = Arc::new(AtomicUsize::new(0));
            let mut instance = module.instantiate_with_imports(&context(), &grants, provider(calls.clone())).unwrap();
            let call = instance.begin_call("f", &[I32(42)], &context(), &grants).unwrap();
            let WasmNativeCallStep::Pending(call) = call.resume(quantum(4), &context(), &grants).unwrap()
                else { panic!("expected pending callback"); };
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            let mut revoked = grants.clone(); revoked.granted_capabilities.remove(&capability);
            denied(call.resume(quantum(100), &context(), &revoked));
            assert_eq!(calls.load(Ordering::SeqCst), 0);
            assert_eq!(instance.global_export("g", &context(), &grants).unwrap(), Some(&I32(9)));
            assert_eq!(&instance.memory_export("m", &context(), &grants).unwrap().unwrap()[..4], &[0; 4]);
            // Denial consumed the old continuation, so the new call cannot
            // accidentally resume its pending callback as well as its own.
            let fresh = instance.begin_call("f", &[I32(7)], &context(), &grants).unwrap();
            assert_eq!(finish(fresh, 1, &grants).unwrap().results, [I32(7)]);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn request_and_canonical_deny_lists_are_rechecked_on_resume() {
        let module = module(IDENTITY, false, &[0x7f], WasmNumericLimits::default());
        let grants = policy();
        for name in ["./task.wasm", "/app/task.wasm"] {
            let mut instance = module.instantiate(&context(), &grants).unwrap();
            let WasmNativeCallStep::Pending(call) = instance.begin_call("f", &[I32(42)], &context(), &grants)
                .unwrap().resume(quantum(1), &context(), &grants).unwrap()
                else { panic!("expected yield before end"); };
            denied(call.resume(quantum(1), &context(), &grants.clone().deny_specifier(name)));
            assert_eq!(instance.call_export("f", &[I32(7)], &context(), &grants).unwrap().results, [I32(7)]);
        }
    }

    #[test]
    fn denied_preparation_cannot_acquire_a_continuation_or_mutate_guest_state() {
        let module = module(TRAP_AFTER_STORE, false, &[], WasmNumericLimits::default());
        let grants = policy();
        let mut instance = module.instantiate(&context(), &grants).unwrap();
        let denied_policy = CapabilityPolicyHook::new(BTreeSet::new());
        denied(instance.begin_call("f", &[I32(99)], &context(), &denied_policy));
        assert_eq!(instance.global_export("g", &context(), &grants).unwrap(), Some(&I32(0)));
        instance.begin_call("f", &[I32(99)], &context(), &grants).unwrap().cancel();
        assert_eq!(instance.global_export("g", &context(), &grants).unwrap(), Some(&I32(0)));
    }

    #[test]
    fn resumed_native_calls_keep_hard_limits_and_release_the_instance_after_failure() {
        let module = module(INFINITE, false, &[], WasmNumericLimits { max_instructions: 17, ..WasmNumericLimits::default() });
        let grants = policy();
        let mut instance = module.instantiate(&context(), &grants).unwrap();
        let call = instance.begin_call("f", &[I32(0)], &context(), &grants).unwrap();
        assert!(matches!(finish(call, 1, &grants), Err(WasmNativeLoadError::Execution(
            WasmNumericVmError::InstructionBudgetExceeded { max: 17 }
        ))));
        assert!(instance.global_export("g", &context(), &grants).unwrap().is_some());
        let call = instance.begin_call("f", &[I32(0)], &context(), &grants).unwrap();
        assert!(matches!(finish(call, 3, &grants), Err(WasmNativeLoadError::Execution(
            WasmNumericVmError::InstructionBudgetExceeded { max: 17 }
        ))));
    }

    #[test]
    fn cancellation_releases_exclusive_state_for_permanent_host_revocation() {
        fn assert_traits<T: Send + Sync>() {}
        assert_traits::<WasmNativeCall<'static, 'static>>();
        let module = module(HOST_CALL, true, &[0x7f], WasmNumericLimits::default());
        let grants = policy();
        let calls = Arc::new(AtomicUsize::new(0));
        let mut instance = module.instantiate_with_imports(&context(), &grants, provider(calls.clone())).unwrap();
        let WasmNativeCallStep::Pending(call) = instance.begin_call("f", &[I32(42)], &context(), &grants)
            .unwrap().resume(quantum(2), &context(), &grants).unwrap()
            else { panic!("expected pending host"); };
        call.cancel();
        assert!(instance.revoke_host_capability(RuntimeCapability::Builtin));
        let call = instance.begin_call("f", &[I32(42)], &context(), &grants).unwrap();
        assert!(finish(call, 1, &grants).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn an_independent_instance_can_finish_while_another_call_is_suspended() {
    let vm = vm(LOOP, &[0x7f], WasmNumericLimits::default());
    let mut first = vm.instantiate().unwrap();
    let mut second = vm.instantiate().unwrap();
    let WasmCallStep::Pending(call) = first.begin_call("f", &[I32(20)]).unwrap().resume(quantum(7)).unwrap()
        else { panic!("expected a live loop continuation"); };
    assert_eq!(second.call_export("f", &[I32(3)]).unwrap().results, [I32(3)]);
    assert_eq!(finish(call, 2).unwrap().results, [I32(20)]);
    assert_eq!(first.global_export("g"), Some(&I32(20)));
    assert_eq!(second.global_export("g"), Some(&I32(3)));
}

#[test]
fn setup_work_alone_can_end_a_slice_before_any_guest_opcode() {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[1, 0x60, 0, 1, 0x7f]);
    section(&mut bytes, 3, &[1, 0]);
    section(&mut bytes, 7, &[1, 1, b'f', 0, 0]);
    let mut body = vec![1]; // one local declaration group
    body.extend(leb(193)); body.push(0x7f);
    body.extend([0x41, 42, 0x0b]);
    let mut code = vec![1]; code.extend(leb(body.len())); code.extend(body);
    section(&mut bytes, 10, &code);
    let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    let expected = vm.call_export("f", &[]).unwrap();
    assert_eq!(expected.instructions_executed, 5);
    let mut instance = vm.instantiate().unwrap();
    let WasmCallStep::Pending(call) = instance.begin_call("f", &[]).unwrap().resume(quantum(1)).unwrap()
        else { panic!("frame setup should consume the first quantum"); };
    assert_eq!(call.instructions_executed(), 3);
    assert_eq!(call.peak_stack_values(), 0);
    assert_eq!(call.max_call_depth(), 1);
    assert_eq!(finish(call, 1).unwrap(), expected);
}

#[test]
fn u64_work_counter_endpoint_traps_instead_of_yielding_forever() {
    let vm = WasmNumericVm::parse(&fixture(&[0x7f], &[0x7f], &[HOST_CALL], true),
        WasmNumericLimits { max_instructions: u64::MAX, ..WasmNumericLimits::default() }).unwrap();
    let mut imports = WasmHostImports::new(BTreeSet::from([
        RuntimeCapability::Builtin, RuntimeCapability::VmDispatch,
    ]));
    imports.define("h", "f", WasmFunctionSignature {
        params: vec![WasmValueType::I32], results: vec![WasmValueType::I32],
    }, BTreeSet::from([RuntimeCapability::Builtin]), 1, |caller, args| {
        // Two guest opcodes and the fixed/ABI work already consumed four.
        caller.charge_work(u64::MAX - 4)?;
        Ok(args.to_vec())
    }).unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    let WasmCallStep::Pending(call) = instance.begin_call("f", &[I32(42)]).unwrap()
        .resume(quantum(u64::MAX)).unwrap()
        else { panic!("caller end must still be pending"); };
    assert_eq!(call.instructions_executed(), u64::MAX);
    assert!(matches!(call.resume(quantum(1)),
        Err(WasmNumericVmError::InstructionBudgetExceeded { max: u64::MAX })));
}

#[test]
fn cancellation_signal_between_slices_is_observed_before_pending_host_entry() {
    use frankenengine_engine::checkpoint::CancellationToken;
    use frankenengine_engine::wasm_runtime_lane::numeric::{WasmHostError, WasmStateError};
    for (code, work) in [(HOST_CALL, 2), (INDIRECT_HOST_CALL, 4)] {
        let vm = WasmNumericVm::parse(&fixture(&[0x7f], &[0x7f], &[code], true), WasmNumericLimits::default()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let token = CancellationToken::new();
        let mut imports = provider(calls.clone());
        imports.bind_cancellation(token.clone(), "between-slices").unwrap();
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        let WasmCallStep::Pending(call) = instance.begin_call("f", &[I32(42)]).unwrap().resume(quantum(work)).unwrap()
            else { panic!("host entry should be pending"); };
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        token.cancel();
        token.reset(); // a new slice must not erase the attached cancellation epoch
        assert_eq!(call.resume(quantum(1)).unwrap_err(),
            WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Cancelled)));
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(&instance.memory_export("m").unwrap()[..4], &[0; 4]);
    }
}

#[test]
fn live_service_revocation_between_slices_preserves_only_the_completed_callback() {
    use frankenengine_engine::checkpoint::CancellationToken;
    use frankenengine_engine::wasm_runtime_lane::numeric::{WasmHostError, WasmStateError};
    let vm = WasmNumericVm::parse(&fixture(&[0x7f], &[0x7f], &[TWO_HOST_CALLS], true), WasmNumericLimits::default()).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let token = CancellationToken::new();
    let mut imports = provider(calls.clone());
    imports.bind_capability_revocation(RuntimeCapability::Builtin, token.clone(), "between-slices").unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    let WasmCallStep::Pending(call) = instance.begin_call("f", &[I32(42)]).unwrap().resume(quantum(2)).unwrap()
        else { panic!("first host entry should be pending"); };
    let WasmCallStep::Pending(call) = call.resume(quantum(1)).unwrap()
        else { panic!("caller should resume after the first callback"); };
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    token.cancel();
    token.reset();
    assert!(matches!(finish(call, 1),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied {
            capability: RuntimeCapability::Builtin, ..
        })))));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(&instance.memory_export("m").unwrap()[..4], &42_i32.to_le_bytes());
}

#[test]
fn tail_replacements_keep_one_activation_across_direct_and_indirect_slices() {
    for tail in [&[0x12, 0][..], &[0x41, 0, 0x13, 0, 0][..]] {
        let mut body = vec![0x20, 0, 0x04, 0x7f, 0x20, 0, 0x41, 1, 0x6b];
        body.extend_from_slice(tail);
        body.extend([0x05, 0x41, 42, 0x0b, 0x0b]);
        let vm = vm(&body, &[0x7f], WasmNumericLimits {
            max_call_depth: 1, max_live_values: 3, ..WasmNumericLimits::default()
        });
        let expected = vm.call_export("f", &[I32(100)]).unwrap();
        assert_eq!(expected.results, [I32(42)]);
        assert_eq!(expected.max_call_depth, 1);
        for work in [1, 2, 7] {
            let mut instance = vm.instantiate().unwrap();
            assert_eq!(finish(instance.begin_call("f", &[I32(100)]).unwrap(), work).unwrap(), expected);
        }
    }
}

#[test]
fn yielding_before_a_host_tail_neither_repeats_nor_resurrects_its_caller() {
    let bytes = fixture(&[0x7f], &[0x7f], &[&[0x20, 0, 0x12, 0, 0x0b]], true);
    let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits {
        max_call_depth: 1, ..WasmNumericLimits::default()
    }).unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let mut instance = vm.instantiate_with_imports(provider(calls.clone())).unwrap();
    let WasmCallStep::Pending(call) = instance.begin_call("f", &[I32(42)]).unwrap().resume(quantum(2)).unwrap()
        else { panic!("tail callback should be pending"); };
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    let WasmCallStep::Complete(result) = call.resume(quantum(1)).unwrap()
        else { panic!("a host tail has no caller left to resume"); };
    assert_eq!(result.results, [I32(42)]);
    assert_eq!(result.max_call_depth, 1);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(&instance.memory_export("m").unwrap()[..4], &42_i32.to_le_bytes());
}
