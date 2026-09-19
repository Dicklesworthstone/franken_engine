#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::wasm_runtime_lane::{WasmBoundaryValue, WasmFunctionSignature, WasmValueType};
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
