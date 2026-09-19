#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature, WasmValueType};
use frankenengine_engine::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleRequest, ModuleSyntax, ResolutionContext, ResolutionErrorCode,
};
use frankenengine_engine::wasm_runtime_lane::{WasmNativeLoadError, WasmNativeModule};
use frankenengine_engine::wasm_runtime_lane::host_replay::{WasmHostTraceError, WasmHostTraceLimits, WasmHostTranscript};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits,
    WasmNumericVm, WasmNumericVmError, WasmStateError,
};
use WasmBoundaryValue::I32;

type Outcome = Result<Vec<WasmBoundaryValue>, WasmNumericVmError>;

fn leb(mut value: usize) -> Vec<u8> {
    let mut result = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        result.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 { return result; }
    }
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    bytes.push(id); bytes.extend(leb(payload.len())); bytes.extend(payload);
}

fn fixture(start: bool, trap_after_call: bool) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[2, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0]);
    section(&mut bytes, 2, &[1, 1, b'h', 1, b'f', 0, 0]);
    section(&mut bytes, 3, if start { &[4, 0, 0, 0, 1] } else { &[3, 0, 0, 0] });
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    section(&mut bytes, 5, &[1, 0, 1]);
    section(&mut bytes, 7, &[6, 1, b'f', 0, 1, 1, b'i', 0, 2, 1, b'h', 0, 0,
        3, b's', b'e', b't', 0, 3, 1, b'm', 2, 0, 1, b't', 1, 0]);
    if start { section(&mut bytes, 8, &[4]); }
    section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
    let mut direct = vec![0, 0x20, 0, 0x20, 1, 0x10, 0];
    if trap_after_call { direct.push(0); }
    direct.push(0x0b);
    let mut functions = vec![direct,
        vec![0, 0x20, 0, 0x20, 1, 0x41, 0, 0x11, 0, 0, 0x0b],
        vec![0, 0x20, 0, 0x20, 1, 0x36, 2, 0, 0x41, 0, 0x0b]];
    if start { functions.push(vec![0, 0x41, 0, 0x41, 4, 0x10, 0, 0x1a, 0x0b]); }
    let mut code = leb(functions.len());
    for body in functions { code.extend(leb(body.len())); code.extend(body); }
    section(&mut bytes, 10, &code);
    section(&mut bytes, 11, &[1, 0, 0x41, 0, 0x0b, 4, 9, 8, 7, 6]);
    bytes
}

fn vm(start: bool, trap: bool) -> WasmNumericVm {
    WasmNumericVm::parse(&fixture(start, trap), WasmNumericLimits::default()).unwrap()
}

fn grants() -> BTreeSet<RuntimeCapability> {
    [RuntimeCapability::VmDispatch, RuntimeCapability::Builtin].into_iter().collect()
}

fn imports<F>(callback: F) -> WasmHostImports
where F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue]) -> Outcome + Send + Sync + 'static {
    let mut imports = WasmHostImports::new(grants());
    imports.define("h", "f", WasmFunctionSignature {
        params: vec![WasmValueType::I32; 2], results: vec![WasmValueType::I32],
    }, [RuntimeCapability::Builtin].into_iter().collect(), 3, callback).unwrap();
    imports
}

fn forbidden(_: &mut WasmHostCaller<'_, '_>, _: &[WasmBoundaryValue]) -> Outcome {
    panic!("replay must not invoke a native provider")
}

fn transform(caller: &mut WasmHostCaller<'_, '_>, arguments: &[WasmBoundaryValue]) -> Outcome {
    let [I32(address), I32(length)] = arguments else { panic!("checked ABI"); };
    let input = caller.read_memory(*address as u32, *length as u32)?.to_vec();
    caller.charge_work(7)?;
    caller.write_memory(8, &input)?;
    Ok(vec![I32(42)])
}

fn trace_error(error: WasmNumericVmError) -> WasmHostTraceError {
    match error {
        WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trace(error))) => error,
        other => panic!("expected trace error, got {other:?}"),
    }
}

#[test]
fn records_real_buffers_and_replays_without_calling_the_provider() {
    for export in ["f", "i", "h"] {
        let vm = vm(false, false);
        let mut bindings = imports(transform);
        let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
        let mut live = vm.instantiate_with_imports(bindings).unwrap();
        let expected = live.call_export(export, &[I32(0), I32(4)]).unwrap();
        assert_eq!(expected.results, [I32(42)]);
        assert_eq!(&live.memory_export("m").unwrap()[8..12], &[9, 8, 7, 6]);
        if export == "f" { assert_eq!(expected.instructions_executed, 1041); }
        let transcript = recording.snapshot().unwrap();
        assert_eq!(transcript.call_count(), 1);
        let bytes = transcript.to_json(WasmHostTraceLimits::default()).unwrap();
        let decoded = WasmHostTranscript::from_json(&bytes, WasmHostTraceLimits::default()).unwrap();
        assert_eq!(decoded, transcript);
        let mut bindings = imports(forbidden);
        let replay = bindings.replay_calls(decoded, WasmHostTraceLimits::default()).unwrap();
        assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Incomplete { remaining: 1 }));
        let mut reproduced = vm.instantiate_with_imports(bindings).unwrap();
        assert_eq!(reproduced.call_export(export, &[I32(0), I32(4)]).unwrap(), expected);
        assert_eq!(reproduced.memory_export("m"), live.memory_export("m"));
        replay.verify_complete().unwrap();
    }
}

#[test]
fn ordered_overlapping_writes_and_stateful_host_results_replay_exactly() {
    let vm = vm(false, false);
    let mut count = 0;
    let mut bindings = imports(move |caller, _| {
        count += 1;
        caller.write_memory(8, &[0xff, count, 0x80, 0xfe])?;
        caller.write_memory(9, &[0xaa, 0xbb])?;
        Ok(vec![I32(i32::from(count))])
    });
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    let mut live = vm.instantiate_with_imports(bindings).unwrap();
    let first = live.call_export("f", &[I32(0), I32(0)]).unwrap();
    let second = live.call_export("f", &[I32(0), I32(0)]).unwrap();
    assert_eq!(first.results, [I32(1)]);
    assert_eq!(second.results, [I32(2)]);
    assert_eq!(&live.memory_export("m").unwrap()[8..12], &[0xff, 0xaa, 0xbb, 0xfe]);
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    let mut reproduced = vm.instantiate_with_imports(bindings).unwrap();
    assert_eq!(reproduced.call_export("f", &[I32(0), I32(0)]).unwrap(), first);
    assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Incomplete { remaining: 1 }));
    assert_eq!(reproduced.call_export("f", &[I32(0), I32(0)]).unwrap(), second);
    assert_eq!(reproduced.memory_export("m"), live.memory_export("m"));
    replay.verify_complete().unwrap();
}

#[test]
fn startup_and_later_invocations_share_one_trace_without_rerunning_start() {
    let vm = vm(true, false);
    let mut bindings = imports(transform);
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    let mut live = vm.instantiate_with_imports(bindings).unwrap();
    assert_eq!(recording.snapshot().unwrap().call_count(), 1);
    let expected = live.call_export("f", &[I32(0), I32(4)]).unwrap();
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    let mut reproduced = vm.instantiate_with_imports(bindings).unwrap();
    assert_eq!(reproduced.start_execution(), live.start_execution());
    assert_eq!(reproduced.call_export("f", &[I32(0), I32(4)]).unwrap(), expected);
    replay.verify_complete().unwrap();
}

#[test]
fn recording_survives_failed_start_and_replays_the_exact_host_trap() {
    let vm = vm(true, false);
    let mut bindings = imports(|caller, _| {
        caller.write_memory(8, &[0xaa])?;
        Err(WasmHostError::trap("startup service unavailable").into())
    });
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    let error = vm.instantiate_with_imports(bindings).unwrap_err();
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    assert_eq!(vm.instantiate_with_imports(bindings).unwrap_err(), error);
    replay.verify_complete().unwrap();
}

#[test]
fn provider_budget_faults_are_replayed_with_preceding_writes_retained() {
    let vm = vm(false, false);
    let mut bindings = imports(|caller, _| {
        caller.write_memory(8, &[0xaa])?;
        let _ = caller.charge_work(u64::MAX);
        let _ = caller.write_memory(9, &[0xbb]);
        Ok(vec![I32(1)])
    });
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    let mut live = vm.instantiate_with_imports(bindings).unwrap();
    let error = live.call_export("f", &[I32(0), I32(0)]).unwrap_err();
    assert!(matches!(error, WasmNumericVmError::InstructionBudgetExceeded { .. }));
    assert_eq!(&live.memory_export("m").unwrap()[8..10], &[0xaa, 0]);
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    let mut reproduced = vm.instantiate_with_imports(bindings).unwrap();
    assert_eq!(reproduced.call_export("f", &[I32(0), I32(0)]).unwrap_err(), error);
    assert_eq!(reproduced.memory_export("m"), live.memory_export("m"));
    replay.verify_complete().unwrap();
}

#[test]
fn host_result_abi_errors_and_later_guest_traps_preserve_completed_effects() {
    for bad in [vec![], vec![WasmBoundaryValue::I64(1)], vec![I32(1), I32(2)]] {
        let vm = vm(false, false);
        let mut bindings = imports(move |caller, _| { caller.write_memory(8, &[99])?; Ok(bad.clone()) });
        let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
        let mut live = vm.instantiate_with_imports(bindings).unwrap();
        let expected = live.call_export("f", &[I32(0), I32(0)]).unwrap_err();
        let mut bindings = imports(forbidden);
        bindings.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
        let mut reproduced = vm.instantiate_with_imports(bindings).unwrap();
        assert_eq!(reproduced.call_export("f", &[I32(0), I32(0)]).unwrap_err(), expected);
        assert_eq!(reproduced.memory_export("m"), live.memory_export("m"));
    }
    let vm = vm(false, true);
    let mut bindings = imports(transform);
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    let mut live = vm.instantiate_with_imports(bindings).unwrap();
    let expected = live.call_export("f", &[I32(0), I32(4)]).unwrap_err();
    assert!(matches!(expected, WasmNumericVmError::Unreachable { .. }));
    let mut bindings = imports(forbidden);
    bindings.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    let mut reproduced = vm.instantiate_with_imports(bindings).unwrap();
    assert_eq!(reproduced.call_export("f", &[I32(0), I32(4)]).unwrap_err(), expected);
    assert_eq!(reproduced.memory_export("m"), live.memory_export("m"));
}

fn one_call(vm: &WasmNumericVm) -> WasmHostTranscript {
    let mut bindings = imports(transform);
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    vm.instantiate_with_imports(bindings).unwrap().call_export("f", &[I32(0), I32(4)]).unwrap();
    recording.snapshot().unwrap()
}

#[test]
fn different_arguments_memory_or_call_path_fail_before_replay_mutation() {
    let vm = vm(false, false);
    let transcript = one_call(&vm);
    for case in 0..3 {
        let mut bindings = imports(forbidden);
        let replay = bindings.replay_calls(transcript.clone(), WasmHostTraceLimits::default()).unwrap();
        let mut instance = vm.instantiate_with_imports(bindings).unwrap();
        if case == 1 { instance.call_export("set", &[I32(0), I32(100)]).unwrap(); }
        let before = instance.memory_export("m").unwrap().to_vec();
        let args = if case == 0 { [I32(0), I32(3)] } else { [I32(0), I32(4)] };
        let name = if case == 2 { "h" } else { "f" };
        assert_eq!(trace_error(instance.call_export(name, &args).unwrap_err()), WasmHostTraceError::Diverged { call: 0 });
        assert_eq!(instance.memory_export("m").unwrap(), before);
        assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Unavailable));
        // A divergence is sticky; retry cannot cherry-pick a matching suffix.
        assert_eq!(trace_error(instance.call_export("f", &[I32(0), I32(4)]).unwrap_err()), WasmHostTraceError::Unavailable);
    }
}

#[test]
fn changed_binding_contract_or_vm_limits_cannot_reinterpret_a_trace() {
    let vm = vm(false, false);
    let transcript = one_call(&vm);
    for cost in [2, 4] {
        let mut bindings = WasmHostImports::new(grants());
        bindings.define("h", "f", WasmFunctionSignature { params: vec![WasmValueType::I32; 2], results: vec![WasmValueType::I32] },
            [RuntimeCapability::Builtin].into_iter().collect(), cost, forbidden).unwrap();
        bindings.replay_calls(transcript.clone(), WasmHostTraceLimits::default()).unwrap();
        let mut instance = vm.instantiate_with_imports(bindings).unwrap();
        assert!(matches!(trace_error(instance.call_export("f", &[I32(0), I32(4)]).unwrap_err()), WasmHostTraceError::Diverged { .. }));
    }
    let altered = WasmNumericVm::parse(&fixture(false, false), WasmNumericLimits { max_instructions: 100_000, ..WasmNumericLimits::default() }).unwrap();
    let mut bindings = imports(forbidden);
    bindings.replay_calls(transcript, WasmHostTraceLimits::default()).unwrap();
    assert!(matches!(trace_error(altered.instantiate_with_imports(bindings).unwrap().call_export("f", &[I32(0), I32(4)]).unwrap_err()), WasmHostTraceError::Diverged { .. }));
}

#[test]
fn replay_does_not_restore_revoked_capabilities_or_consume_denied_calls() {
    let vm = vm(false, false);
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(one_call(&vm), WasmHostTraceLimits::default()).unwrap();
    let mut instance = vm.instantiate_with_imports(bindings).unwrap();
    assert!(instance.revoke_host_capability(RuntimeCapability::Builtin));
    assert!(matches!(instance.call_export("f", &[I32(0), I32(4)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { .. })))));
    assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Incomplete { remaining: 1 }));
    assert!(instance.memory_export("m").unwrap()[8..12].iter().all(|byte| *byte == 0));
}

#[test]
fn exhausted_trace_never_falls_back_to_native_execution() {
    let vm = vm(false, false);
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(one_call(&vm), WasmHostTraceLimits::default()).unwrap();
    let mut instance = vm.instantiate_with_imports(bindings).unwrap();
    instance.call_export("f", &[I32(0), I32(4)]).unwrap();
    replay.verify_complete().unwrap();
    let before = instance.memory_export("m").unwrap().to_vec();
    assert_eq!(trace_error(instance.call_export("f", &[I32(0), I32(4)]).unwrap_err()), WasmHostTraceError::Exhausted { call: 1 });
    assert_eq!(instance.memory_export("m").unwrap(), before);
    assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Unavailable));
}

#[test]
fn recording_quotas_refuse_before_callbacks_or_before_the_unrecorded_write() {
    let vm = vm(false, false);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = calls.clone();
    let mut bindings = imports(move |_, _| { observed.fetch_add(1, Ordering::SeqCst); Ok(vec![I32(1)]) });
    let recording = bindings.record_calls(WasmHostTraceLimits { max_calls: 0, ..WasmHostTraceLimits::default() }).unwrap();
    let mut instance = vm.instantiate_with_imports(bindings).unwrap();
    assert_eq!(trace_error(instance.call_export("f", &[I32(0), I32(0)]).unwrap_err()), WasmHostTraceError::LimitExceeded);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(recording.snapshot().unwrap_err(), WasmHostTraceError::Unavailable);
    let mut bindings = imports(|caller, _| {
        let _ = caller.write_memory(8, &[255; 4096]);
        let _ = caller.write_memory(0, &[99]);
        Ok(vec![I32(1)])
    });
    let recording = bindings.record_calls(WasmHostTraceLimits { max_bytes: 4096, ..WasmHostTraceLimits::default() }).unwrap();
    let mut instance = vm.instantiate_with_imports(bindings).unwrap();
    let before = instance.memory_export("m").unwrap().to_vec();
    assert_eq!(trace_error(instance.call_export("f", &[I32(0), I32(0)]).unwrap_err()), WasmHostTraceError::LimitExceeded);
    assert_eq!(instance.memory_export("m").unwrap(), before);
    assert_eq!(recording.snapshot().unwrap_err(), WasmHostTraceError::Unavailable);
}

#[test]
fn hashing_work_is_precharged_and_default_execution_metrics_are_unchanged() {
    let vm = vm(false, false);
    let mut untraced = vm.instantiate_with_imports(imports(transform)).unwrap();
    assert_eq!(untraced.call_export("f", &[I32(0), I32(4)]).unwrap().instructions_executed, 17);
    let bounded = WasmNumericVm::parse(&fixture(false, false), WasmNumericLimits { max_instructions: 1000, ..WasmNumericLimits::default() }).unwrap();
    let mut bindings = imports(forbidden);
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    assert_eq!(bounded.instantiate_with_imports(bindings).unwrap().call_export("f", &[I32(0), I32(4)]),
        Err(WasmNumericVmError::InstructionBudgetExceeded { max: 1000 }));
    assert_eq!(recording.snapshot().unwrap().call_count(), 0);
}

#[test]
fn corrupted_truncated_unknown_schema_and_oversized_transcripts_are_rejected() {
    let vm = vm(false, false);
    let original = one_call(&vm).to_json(WasmHostTraceLimits::default()).unwrap();
    let mut altered: serde_json::Value = serde_json::from_slice(&original).unwrap();
    altered["data"]["calls"][0]["outcome"] = serde_json::json!({"Ok": [{"I32": 999}]});
    assert_eq!(WasmHostTranscript::from_json(&serde_json::to_vec(&altered).unwrap(), WasmHostTraceLimits::default()).unwrap_err(), WasmHostTraceError::InvalidTranscript);
    altered = serde_json::from_slice(&original).unwrap();
    altered["data"]["version"] = serde_json::json!(99);
    assert_eq!(WasmHostTranscript::from_json(&serde_json::to_vec(&altered).unwrap(), WasmHostTraceLimits::default()).unwrap_err(), WasmHostTraceError::InvalidTranscript);
    altered = serde_json::from_slice(&original).unwrap();
    altered["unexpected"] = serde_json::json!(true);
    assert_eq!(WasmHostTranscript::from_json(&serde_json::to_vec(&altered).unwrap(), WasmHostTraceLimits::default()).unwrap_err(), WasmHostTraceError::InvalidTranscript);
    assert!(WasmHostTranscript::from_json(&original[..original.len() - 1], WasmHostTraceLimits::default()).is_err());
    assert_eq!(WasmHostTranscript::from_json(&original, WasmHostTraceLimits { max_calls: 0, ..WasmHostTraceLimits::default() }).unwrap_err(), WasmHostTraceError::LimitExceeded);
    assert_eq!(WasmHostTranscript::from_json(&vec![b' '; 2049], WasmHostTraceLimits { max_bytes: 2048, ..WasmHostTraceLimits::default() }).unwrap_err(), WasmHostTraceError::LimitExceeded);
}

#[test]
fn inspecting_inside_a_callback_does_not_deadlock_and_panics_poison_recording() {
    let vm = vm(false, false);
    let mut bindings = WasmHostImports::new(grants());
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    let observer = recording.clone();
    bindings.define("h", "f", WasmFunctionSignature { params: vec![WasmValueType::I32; 2], results: vec![WasmValueType::I32] },
        [RuntimeCapability::Builtin].into_iter().collect(), 3, move |_, _| {
            assert_eq!(observer.snapshot().unwrap_err(), WasmHostTraceError::Unavailable);
            panic!("provider panic");
        }).unwrap();
    let mut instance = vm.instantiate_with_imports(bindings).unwrap();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| instance.call_export("f", &[I32(0), I32(0)])));
    assert!(result.is_err());
    assert_eq!(recording.snapshot().unwrap_err(), WasmHostTraceError::Unavailable);
}

#[test]
fn configuration_cannot_replace_an_existing_recording_or_replay() {
    let mut bindings = imports(transform);
    let recorder = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    assert_eq!(bindings.record_calls(WasmHostTraceLimits::default()).unwrap_err(), WasmHostTraceError::AlreadyConfigured);
    assert_eq!(bindings.replay_calls(recorder.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap_err(), WasmHostTraceError::AlreadyConfigured);
    let mut bindings = imports(forbidden);
    bindings.replay_calls(recorder.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    assert_eq!(bindings.record_calls(WasmHostTraceLimits::default()).unwrap_err(), WasmHostTraceError::AlreadyConfigured);
}

fn resolved_policy() -> CapabilityPolicyHook {
    CapabilityPolicyHook::new([
        RuntimeCapability::ModuleLoad, RuntimeCapability::VmDispatch,
        RuntimeCapability::Builtin, RuntimeCapability::FsRead,
    ].into_iter().collect())
}

fn resolved_context() -> ResolutionContext {
    ResolutionContext::new("trace-resolved-replay", "decision-resolved-replay", "policy-current")
}

fn resolved(bytes: &[u8], path: &str, origin: &str, extra_capability: bool) -> WasmNativeModule {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let mut definition = ModuleDefinition::wasm_binary(bytes, &WasmNumericLimits::default()).unwrap()
        .with_provenance(origin).require_capability(RuntimeCapability::Builtin);
    if extra_capability { definition = definition.require_capability(RuntimeCapability::FsRead); }
    resolver.register_workspace_module(path, definition).unwrap();
    resolver.load_wasm(&ModuleRequest::new(path, ImportStyle::Import), &resolved_context(),
        &resolved_policy(), WasmNumericLimits::default()).unwrap()
}

fn resolved_recording(module: &WasmNativeModule) -> WasmHostTranscript {
    let mut bindings = imports(transform);
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    let mut instance = module.instantiate_with_imports(&resolved_context(), &resolved_policy(), bindings).unwrap();
    instance.call_export("f", &[I32(0), I32(4)], &resolved_context(), &resolved_policy()).unwrap();
    recording.snapshot().unwrap()
}

fn scope_error(error: WasmNativeLoadError) -> WasmHostTraceError {
    match error {
        WasmNativeLoadError::Execution(error) => trace_error(error),
        other => panic!("expected execution scope error, got {other:?}"),
    }
}

#[test]
fn resolved_recordings_pin_the_module_before_start_and_replay_real_state() {
    let module = resolved(&fixture(true, false), "/app/replay.wasm", "release-a", false);
    let ctx = resolved_context();
    let policy = resolved_policy();
    let mut bindings = imports(transform);
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    assert_eq!(recording.snapshot().unwrap().module_hash(), None);
    let mut live = module.instantiate_with_imports(&ctx, &policy, bindings).unwrap();
    assert_eq!(recording.snapshot().unwrap().call_count(), 1);
    assert_eq!(recording.snapshot().unwrap().module_hash(), Some(module.resolution().module.content_hash));
    let expected = live.call_export("f", &[I32(0), I32(4)], &ctx, &policy).unwrap();
    let transcript = recording.snapshot().unwrap();
    let encoded = transcript.to_json(WasmHostTraceLimits::default()).unwrap();
    let decoded = WasmHostTranscript::from_json(&encoded, WasmHostTraceLimits::default()).unwrap();
    assert_eq!(decoded, transcript);
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(decoded, WasmHostTraceLimits::default()).unwrap();
    let mut reproduced = module.instantiate_with_imports(&ctx, &policy, bindings).unwrap();
    assert_eq!(reproduced.start_execution(&ctx, &policy).unwrap(), live.start_execution(&ctx, &policy).unwrap());
    assert_eq!(reproduced.call_export("f", &[I32(0), I32(4)], &ctx, &policy).unwrap(), expected);
    assert_eq!(reproduced.memory_export("m", &ctx, &policy).unwrap(), live.memory_export("m", &ctx, &policy).unwrap());
    replay.verify_complete().unwrap();
}

#[test]
fn matching_host_calls_cannot_replay_against_changed_source_name_or_provenance() {
    let original = fixture(true, false);
    let module = resolved(&original, "/app/replay.wasm", "release-a", false);
    let transcript = resolved_recording(&module);
    let mut changed_source = original.clone();
    // Same executable instructions, different exact code artifact.
    section(&mut changed_source, 0, &[1, b'x', 1]);
    for (bytes, path, origin, extra) in [
        (changed_source.as_slice(), "/app/replay.wasm", "release-a", false),
        (original.as_slice(), "/app/other.wasm", "release-a", false),
        (original.as_slice(), "/app/replay.wasm", "release-b", false),
        (original.as_slice(), "/app/replay.wasm", "release-a", true),
    ] {
        let changed = resolved(bytes, path, origin, extra);
        assert_ne!(changed.resolution().module.content_hash, module.resolution().module.content_hash);
        let mut bindings = imports(forbidden);
        let replay = bindings.replay_calls(transcript.clone(), WasmHostTraceLimits::default()).unwrap();
        assert_eq!(scope_error(changed.instantiate_with_imports(&resolved_context(), &resolved_policy(), bindings).unwrap_err()),
            WasmHostTraceError::ModuleMismatch);
        assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Unavailable));
    }
}

#[test]
fn scoped_transcripts_cannot_escape_through_the_raw_numeric_vm() {
    let bytes = fixture(true, false);
    let module = resolved(&bytes, "/app/replay.wasm", "release-a", false);
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(resolved_recording(&module), WasmHostTraceLimits::default()).unwrap();
    let vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    assert_eq!(trace_error(vm.instantiate_with_imports(bindings).unwrap_err()), WasmHostTraceError::ModuleMismatch);
    assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Unavailable));
}

#[test]
fn unscoped_transcripts_cannot_be_relabelled_by_a_resolved_instantiation() {
    let bytes = fixture(false, false);
    let raw_vm = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    let transcript = one_call(&raw_vm);
    assert_eq!(transcript.module_hash(), None);
    let module = resolved(&bytes, "/app/replay.wasm", "release-a", false);
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(transcript, WasmHostTraceLimits::default()).unwrap();
    assert_eq!(scope_error(module.instantiate_with_imports(&resolved_context(), &resolved_policy(), bindings).unwrap_err()),
        WasmHostTraceError::ModuleMismatch);
    assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Unavailable));
}

#[test]
fn scoped_empty_prefixes_require_identity_even_without_any_host_call() {
    let bytes = fixture(false, false);
    let module = resolved(&bytes, "/app/replay.wasm", "release-a", false);
    let mut bindings = imports(forbidden);
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    module.instantiate_with_imports(&resolved_context(), &resolved_policy(), bindings).unwrap();
    let transcript = recording.snapshot().unwrap();
    assert_eq!(transcript.call_count(), 0);
    assert_eq!(transcript.module_hash(), Some(module.resolution().module.content_hash));
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(transcript.clone(), WasmHostTraceLimits::default()).unwrap();
    assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::ModuleMismatch));
    module.instantiate_with_imports(&resolved_context(), &resolved_policy(), bindings).unwrap();
    replay.verify_complete().unwrap();
    let mut bindings = imports(forbidden);
    bindings.replay_calls(transcript, WasmHostTraceLimits::default()).unwrap();
    let raw = WasmNumericVm::parse(&bytes, WasmNumericLimits::default()).unwrap();
    assert_eq!(trace_error(raw.instantiate_with_imports(bindings).unwrap_err()), WasmHostTraceError::ModuleMismatch);
}

#[test]
fn current_policy_denials_and_permanent_host_revocation_still_gate_scoped_replay() {
    let module = resolved(&fixture(true, false), "/app/replay.wasm", "release-a", false);
    let ctx = resolved_context();
    let policy = resolved_policy();
    let transcript = resolved_recording(&module);
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(transcript.clone(), WasmHostTraceLimits::default()).unwrap();
    let mut instance = module.instantiate_with_imports(&ctx, &policy, bindings).unwrap();
    let mut denied = policy.clone();
    denied.granted_capabilities.remove(&RuntimeCapability::Builtin);
    let denied_specifier = policy.clone().deny_specifier("/app/replay.wasm");
    let before = instance.memory_export("m", &ctx, &policy).unwrap().unwrap().to_vec();
    for rejected in [&denied, &denied_specifier] {
        assert!(matches!(instance.call_export("f", &[I32(0), I32(4)], &ctx, rejected),
            Err(WasmNativeLoadError::Resolution(error)) if error.code == ResolutionErrorCode::PolicyDenied));
        assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Incomplete { remaining: 1 }));
        assert_eq!(instance.memory_export("m", &ctx, &policy).unwrap().unwrap(), before);
    }
    // A current-policy denial neither consumes the trace nor revokes the
    // provider-owned grant. Explicit permanent revocation is separate.
    instance.call_export("f", &[I32(0), I32(4)], &ctx, &policy).unwrap();
    replay.verify_complete().unwrap();
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(transcript, WasmHostTraceLimits::default()).unwrap();
    let mut instance = module.instantiate_with_imports(&ctx, &policy, bindings).unwrap();
    assert!(instance.revoke_host_capability(RuntimeCapability::Builtin));
    assert!(matches!(instance.call_export("f", &[I32(0), I32(4)], &ctx, &policy),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { .. }))))));
    assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Incomplete { remaining: 1 }));
}

#[test]
fn registry_updates_do_not_rebind_an_already_loaded_replay_identity() {
    let bytes = fixture(false, false);
    let mut resolver = DeterministicModuleResolver::new("/app");
    let definition = ModuleDefinition::wasm_binary(&bytes, &WasmNumericLimits::default()).unwrap()
        .with_provenance("release-a").require_capability(RuntimeCapability::Builtin);
    resolver.register_workspace_module("/app/replay.wasm", definition.clone()).unwrap();
    let request = ModuleRequest::new("/app/replay.wasm", ImportStyle::Import);
    let ctx = resolved_context();
    let policy = resolved_policy();
    let old = resolver.load_wasm(&request, &ctx, &policy, WasmNumericLimits::default()).unwrap();
    let transcript = resolved_recording(&old);
    resolver.register_workspace_module("/app/replay.wasm", definition.with_provenance("release-b")).unwrap();
    let new = resolver.load_wasm(&request, &ctx, &policy, WasmNumericLimits::default()).unwrap();
    let mut bindings = imports(forbidden);
    bindings.replay_calls(transcript.clone(), WasmHostTraceLimits::default()).unwrap();
    assert_eq!(scope_error(new.instantiate_with_imports(&ctx, &policy, bindings).unwrap_err()), WasmHostTraceError::ModuleMismatch);
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(transcript, WasmHostTraceLimits::default()).unwrap();
    old.instantiate_with_imports(&ctx, &policy, bindings).unwrap()
        .call_export("f", &[I32(0), I32(4)], &ctx, &policy).unwrap();
    replay.verify_complete().unwrap();
}

#[test]
fn aliases_share_canonical_identity_but_their_current_denials_still_apply() {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver.register_workspace_module("/app/main.mjs",
        ModuleDefinition::new(ModuleSyntax::EsModule, "import './replay.wasm';")).unwrap();
    resolver.register_workspace_module("/app/replay.wasm",
        ModuleDefinition::wasm_binary(&fixture(false, false), &WasmNumericLimits::default()).unwrap()
            .require_capability(RuntimeCapability::Builtin)).unwrap();
    let ctx = resolved_context();
    let policy = resolved_policy();
    let direct = resolver.load_wasm(&ModuleRequest::new("/app/replay.wasm", ImportStyle::Import),
        &ctx, &policy, WasmNumericLimits::default()).unwrap();
    let alias = resolver.load_wasm(&ModuleRequest::new("./replay.wasm", ImportStyle::Import).with_referrer("/app/main.mjs"),
        &ctx, &policy, WasmNumericLimits::default()).unwrap();
    assert_eq!(direct.resolution().module.content_hash, alias.resolution().module.content_hash);
    let transcript = resolved_recording(&direct);
    let mut bindings = imports(forbidden);
    let replay = bindings.replay_calls(transcript, WasmHostTraceLimits::default()).unwrap();
    let mut instance = alias.instantiate_with_imports(&ctx, &policy, bindings).unwrap();
    assert!(matches!(instance.call_export("f", &[I32(0), I32(4)], &ctx, &policy.clone().deny_specifier("./replay.wasm")),
        Err(WasmNativeLoadError::Resolution(error)) if error.code == ResolutionErrorCode::PolicyDenied));
    assert_eq!(replay.verify_complete(), Err(WasmHostTraceError::Incomplete { remaining: 1 }));
    instance.call_export("f", &[I32(0), I32(4)], &ctx, &policy).unwrap();
    replay.verify_complete().unwrap();
}

#[test]
fn transcript_scope_is_explicit_versioned_and_part_of_the_content_digest() {
    let module = resolved(&fixture(false, false), "/app/replay.wasm", "release-a", false);
    let scoped = resolved_recording(&module);
    let bytes = scoped.to_json(WasmHostTraceLimits::default()).unwrap();
    for change in 0..4 {
        let mut wire: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        match change {
            0 => { wire["data"].as_object_mut().unwrap().remove("scope"); }
            1 => { wire["data"]["scope"] = serde_json::json!("Unscoped"); }
            2 => { wire["data"]["scope"] = serde_json::json!({"Resolved": vec![0_u8; 32]}); }
            3 => { wire["data"]["version"] = serde_json::json!(1); }
            _ => unreachable!(),
        }
        assert_eq!(WasmHostTranscript::from_json(&serde_json::to_vec(&wire).unwrap(), WasmHostTraceLimits::default()).unwrap_err(),
            WasmHostTraceError::InvalidTranscript);
    }
}
