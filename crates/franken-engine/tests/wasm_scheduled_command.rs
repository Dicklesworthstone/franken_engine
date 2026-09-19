#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleRequest, ModuleSyntax, ResolutionContext, wasm_module_required_capabilities,
};
use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue, WasmFunctionSignature, WasmNativeLoadError, WasmNativeModule, WasmValueType,
};
use frankenengine_engine::wasm_runtime_lane::command::{
    WasmCommandExecution, WasmCommandStep, WasmCommandTask,
};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::wasi_preview1::{WASI_PREVIEW1_MODULE, WasiPreview1Config};
use RuntimeCapability::{Builtin, FsRead, VmDispatch};
use WasmBoundaryValue::I32;

type HostResult = Result<Vec<WasmBoundaryValue>, WasmNumericVmError>;

fn work(value: u64) -> NonZeroU64 { NonZeroU64::new(value).unwrap() }
fn context() -> ResolutionContext { ResolutionContext::new("command-trace", "command-decision", "command-policy") }
fn grants() -> BTreeSet<RuntimeCapability> { [Builtin, VmDispatch].into() }
fn policy() -> CapabilityPolicyHook {
    let mut capabilities = wasm_module_required_capabilities(); capabilities.insert(Builtin);
    CapabilityPolicyHook::new(capabilities)
}
fn leb(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 127) as u8; value >>= 7;
        out.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 { return out; }
    }
}
fn signed(mut value: i32) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 127) as u8; value >>= 7;
        let done = (value == 0 && byte & 64 == 0) || (value == -1 && byte & 64 != 0);
        out.push(byte | if done { 0 } else { 128 });
        if done { return out; }
    }
}
fn name(out: &mut Vec<u8>, text: &str) { out.extend(leb(text.len())); out.extend(text.as_bytes()); }
fn section(out: &mut Vec<u8>, id: u8, bytes: &[u8]) { out.push(id); out.extend(leb(bytes.len())); out.extend(bytes); }

// Imported indices: proc_exit=0, effect=1. Local indices: binary start=2,
// command entry=3. Memory is intentionally NOT exported; only an authorized
// host caller can observe it, including the initialized bytes during startup.
fn fixture(start: Option<&[u8]>, entry: &[u8], entry_type: u8, export: &str) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[3, 0x60, 0, 0, 0x60, 1, 0x7f, 0, 0x60, 0, 1, 0x7f]);
    let mut imports = vec![2];
    for (module, function) in [(WASI_PREVIEW1_MODULE, "proc_exit"), ("h", "effect")] {
        name(&mut imports, module); name(&mut imports, function); imports.extend([0, 1]);
    }
    section(&mut bytes, 2, &imports);
    section(&mut bytes, 3, &[2, 0, entry_type]);
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    section(&mut bytes, 5, &[1, 1, 1, 1]);
    let mut exports = vec![1]; name(&mut exports, export); exports.extend([0, 3]);
    section(&mut bytes, 7, &exports);
    if start.is_some() { section(&mut bytes, 8, &[2]); }
    section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
    let mut bodies = vec![2];
    for body in [start.unwrap_or(&[0x0b]), entry] {
        bodies.extend(leb(body.len() + 1)); bodies.push(0); bodies.extend(body);
    }
    section(&mut bytes, 10, &bodies);
    section(&mut bytes, 11, &[1, 0, 0x41, 0, 0x0b, 3, 255, 128, 254]);
    bytes
}
fn effect(value: i32) -> Vec<u8> {
    let mut code = vec![0x41]; code.extend(signed(value)); code.extend([0x10, 1, 0x0b]); code
}
fn exit(code: u32, opcode: u8) -> Vec<u8> {
    let mut bytes = vec![0x41]; bytes.extend(signed(code as i32));
    if matches!(opcode, 0x11 | 0x13) { bytes.extend([0x41, 0, opcode, 1, 0]); }
    else { bytes.extend([opcode, 0]); }
    bytes.extend([0x00, 0x0b]); // Normal return from proc_exit is forbidden.
    bytes
}
fn load(bytes: &[u8], declared: &[RuntimeCapability], limits: WasmNumericLimits) -> WasmNativeModule {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver.register_workspace_module("/app/main.mjs", ModuleDefinition::new(ModuleSyntax::EsModule, "import './command.wasm';")).unwrap();
    let mut definition = ModuleDefinition::wasm_binary(bytes, &limits).unwrap();
    definition.required_capabilities.extend(declared.iter().copied());
    resolver.register_workspace_module("/app/command.wasm", definition).unwrap();
    let mut allowed = policy(); allowed.granted_capabilities.extend(declared.iter().copied());
    resolver.load_wasm(&ModuleRequest::new("./command.wasm", ImportStyle::Import).with_referrer("/app/main.mjs"),
        &context(), &allowed, limits).unwrap()
}
fn command(start: Option<&[u8]>, entry: &[u8], limits: WasmNumericLimits) -> WasmNativeModule {
    load(&fixture(start, entry, 0, "_start"), &[Builtin], limits)
}
fn bindings<F>(callback: F) -> WasmHostImports
where F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue]) -> HostResult + Send + Sync + 'static {
    let mut imports = WasiPreview1Config::default().into_imports(grants()).unwrap();
    imports.define("h", "effect", WasmFunctionSignature {
        params: vec![WasmValueType::I32], results: vec![],
    }, [Builtin].into(), 1, callback).unwrap();
    imports
}
fn recording_effects(events: Arc<Mutex<Vec<i32>>>) -> WasmHostImports {
    bindings(move |_, args| {
        let [I32(value)] = args else { panic!("validated callback ABI"); };
        events.lock().unwrap().push(*value); Ok(vec![])
    })
}
fn pending(step: WasmCommandStep<'_>) -> WasmCommandTask<'_> {
    match step { WasmCommandStep::Pending(task) => task, other => panic!("expected pending, got {other:?}") }
}
fn finish(task: WasmCommandTask<'_>, quanta: &[u64]) -> Result<WasmCommandExecution, WasmNativeLoadError> {
    finish_with_policy(task, quanta, &policy())
}
fn finish_with_policy(mut task: WasmCommandTask<'_>, quanta: &[u64], allowed: &CapabilityPolicyHook)
    -> Result<WasmCommandExecution, WasmNativeLoadError>
{
    for turn in 0..10_000 {
        match task.resume(work(quanta[turn % quanta.len()]), &context(), allowed)? {
            WasmCommandStep::Pending(next) => task = next,
            WasmCommandStep::Complete(result) => return Ok(result),
        }
    }
    panic!("finite command did not complete");
}
fn forbidden(_: &mut WasmHostCaller<'_, '_>, _: &[WasmBoundaryValue]) -> HostResult {
    panic!("provider must not execute");
}
fn denied(error: WasmNativeLoadError) {
    assert!(matches!(error, WasmNativeLoadError::Resolution(_)));
}

#[test]
fn one_command_retains_state_effect_order_and_work_across_both_phases() {
    let mut start = vec![0x41, 4, 0x41, 7, 0x3a, 0, 0]; start.extend(effect(1));
    let module = command(Some(&start), &effect(2), WasmNumericLimits::default());
    let run = |quanta: &[u64]| {
        let events = Arc::new(Mutex::new(Vec::new())); let observed = events.clone();
        let imports = bindings(move |caller, args| {
            let [I32(value)] = args else { panic!("ABI"); };
            assert_eq!(caller.read_memory(0, 3)?, &[255, 128, 254]);
            let byte = caller.read_memory(4, 1)?[0];
            observed.lock().unwrap().push((*value, byte));
            caller.write_memory(4, &[byte + 1])?; Ok(vec![])
        });
        let result = finish(module.prepare_command(imports), quanta).unwrap();
        assert_eq!(result.exit_code, 0);
        assert_eq!(*events.lock().unwrap(), [(1, 7), (2, 8)]);
        result
    };
    let expected = run(&[u64::MAX]);
    for quanta in [&[1][..], &[2, 7, 1, 99], &[3, 5]] { assert_eq!(run(quanta), expected); }
    assert_eq!(expected.instructions_executed, 19);
}

#[test]
fn entry_is_always_a_separate_authorized_turn_even_without_binary_start() {
    let initializer = effect(1);
    for start in [None, Some(&[0x0b][..]), Some(initializer.as_slice())] {
        let module = command(start, &effect(2), WasmNumericLimits::default());
        let events = Arc::new(Mutex::new(Vec::new()));
        let task = module.prepare_command(recording_effects(events.clone()));
        assert!(events.lock().unwrap().is_empty()); assert_eq!(task.instructions_executed(), 0);
        let task = pending(task.resume(work(u64::MAX), &context(), &policy()).unwrap());
        assert!(!events.lock().unwrap().contains(&2));
        denied(task.resume(work(u64::MAX), &context(), &CapabilityPolicyHook::new(BTreeSet::new())).unwrap_err());
        assert!(!events.lock().unwrap().contains(&2));
    }
}

#[test]
fn binary_start_and_entry_cannot_each_spend_a_fresh_hard_budget() {
    for (budget, expected_effects) in [(8, vec![1]), (9, vec![1, 2])] {
        let module = command(Some(&effect(1)), &effect(2), WasmNumericLimits {
            max_instructions: budget, ..WasmNumericLimits::default()
        });
        let events = Arc::new(Mutex::new(Vec::new()));
        let error = finish(module.prepare_command(recording_effects(events.clone())), &[1, 2]).unwrap_err();
        assert!(matches!(error, WasmNativeLoadError::Execution(WasmNumericVmError::InstructionBudgetExceeded { max }) if max == budget));
        assert_eq!(*events.lock().unwrap(), expected_effects);
    }
    let module = command(Some(&effect(1)), &effect(2), WasmNumericLimits { max_instructions: 10, ..WasmNumericLimits::default() });
    assert_eq!(finish(module.prepare_command(bindings(|_, _| Ok(vec![]))), &[1]).unwrap().instructions_executed, 10);
}

#[test]
fn direct_indirect_and_tail_process_exit_preserve_full_unsigned_status() {
    for opcode in [0x10, 0x11, 0x12, 0x13] {
        for code in [0, 7, i32::MAX as u32, 0x8000_0000, u32::MAX] {
            let module = command(None, &exit(code, opcode), WasmNumericLimits::default());
            let result = finish(module.prepare_command(bindings(forbidden)), &[1, 7]).unwrap();
            assert_eq!(result.exit_code, code);
        }
    }
}

#[test]
fn exit_during_binary_start_never_enters_the_command_entry() {
    let module = command(Some(&exit(73, 0x10)), &effect(2), WasmNumericLimits::default());
    assert_eq!(finish(module.prepare_command(bindings(forbidden)), &[1]).unwrap().exit_code, 73);
}

#[test]
fn wrong_or_missing_entry_abi_refuses_before_initializer_effects_or_allocation() {
    for (entry, ty, export) in [
        (&[0x0b][..], 1, "_start"), (&[0x41, 0, 0x0b][..], 2, "_start"),
        (&[0x0b][..], 0, "other"),
    ] {
        let module = load(&fixture(Some(&effect(1)), entry, ty, export), &[Builtin], WasmNumericLimits {
            max_memory_pages: 0, ..WasmNumericLimits::default()
        });
        let error = module.prepare_command(bindings(forbidden)).resume(work(1), &context(), &policy()).unwrap_err();
        assert!(matches!(error, WasmNativeLoadError::Execution(
            WasmNumericVmError::InvalidModule { .. } | WasmNumericVmError::UnknownExport { .. }
        )));
    }
}

#[test]
fn absent_bindings_and_provider_grants_are_checked_before_binary_start() {
    let module = command(Some(&effect(1)), &exit(0, 0x10), WasmNumericLimits::default());
    let missing = WasmHostImports::new(grants());
    let error = module.prepare_command(missing).resume(work(1), &context(), &policy()).unwrap_err();
    assert!(matches!(error, WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::MissingBinding { .. })))));
    let mut imports = WasiPreview1Config::default().into_imports([Builtin].into()).unwrap();
    imports.define("h", "effect", WasmFunctionSignature { params: vec![WasmValueType::I32], results: vec![] },
        [Builtin].into(), 1, forbidden).unwrap();
    let error = module.prepare_command(imports).resume(work(1), &context(), &policy()).unwrap_err();
    assert!(matches!(error, WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { capability: VmDispatch, .. })))));
}

#[test]
fn broad_provider_and_policy_do_not_supply_undeclared_module_authority() {
    let module = load(&fixture(Some(&effect(1)), &[0x0b], 0, "_start"), &[], WasmNumericLimits::default());
    let error = module.prepare_command(bindings(forbidden)).resume(work(100), &context(), &policy()).unwrap_err();
    assert!(matches!(error, WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { capability: Builtin, .. })))));
    let module = load(&fixture(None, &[0x0b], 0, "_start"), &[Builtin, FsRead], WasmNumericLimits::default());
    denied(module.prepare_command(bindings(forbidden)).resume(work(100), &context(), &policy()).unwrap_err());
}

#[test]
fn requested_and_canonical_deny_lists_remain_live_between_phases() {
    let module = command(Some(&effect(1)), &effect(2), WasmNumericLimits::default());
    for specifier in ["./command.wasm", "/app/command.wasm"] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let task = pending(module.prepare_command(recording_effects(events.clone())).resume(work(100), &context(), &policy()).unwrap());
        denied(task.resume(work(100), &context(), &policy().deny_specifier(specifier)).unwrap_err());
        assert_eq!(*events.lock().unwrap(), [1]);
    }
}

#[test]
fn cancellation_and_selective_revocation_stop_a_pending_entry() {
    let module = command(None, &effect(2), WasmNumericLimits::default());
    for execution in [false, true] {
        let token = CancellationToken::new();
        let mut imports = bindings(forbidden);
        if execution { imports.bind_execution_cancellation(token.clone(), "command").unwrap(); }
        else { imports.bind_capability_revocation(Builtin, token.clone(), "command").unwrap(); }
        let task = pending(module.prepare_command(imports).resume(work(100), &context(), &policy()).unwrap());
        token.cancel(); token.reset();
        let error = task.resume(work(100), &context(), &policy()).unwrap_err();
        assert!(matches!(error, WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::ExecutionCancelled | WasmHostError::CapabilityDenied { .. }
        )))));
    }
}

#[test]
fn dropping_unstarted_or_partially_run_commands_never_repeats_completed_effects() {
    let module = command(Some(&effect(1)), &effect(2), WasmNumericLimits::default());
    module.prepare_command(bindings(forbidden)).cancel();
    let events = Arc::new(Mutex::new(Vec::new()));
    let task = pending(module.prepare_command(recording_effects(events.clone())).resume(work(100), &context(), &policy()).unwrap());
    task.cancel(); assert_eq!(*events.lock().unwrap(), [1]);
    finish(module.prepare_command(recording_effects(events.clone())), &[1]).unwrap();
    assert_eq!(*events.lock().unwrap(), [1, 1, 2]);
}

#[test]
fn guest_traps_and_lookalike_host_messages_are_not_exit_statuses() {
    let module = command(Some(&effect(1)), &[0x00, 0x0b], WasmNumericLimits::default());
    let events = Arc::new(Mutex::new(Vec::new()));
    assert!(matches!(finish(module.prepare_command(recording_effects(events.clone())), &[1]),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::Unreachable { .. }))));
    assert_eq!(*events.lock().unwrap(), [1]);
    let module = command(None, &effect(2), WasmNumericLimits::default());
    assert!(matches!(finish(module.prepare_command(bindings(|_, _| Err(WasmHostError::trap("wasm guest exited with status 0").into()))), &[1]),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trap { .. }))))));
}

#[test]
fn one_scoped_transcript_replays_both_phases_without_provider_execution() {
    let mut entry = effect(2); entry.pop(); entry.extend(exit(0xffff_ffff, 0x10));
    let module = command(Some(&effect(1)), &entry, WasmNumericLimits::default());
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut imports = recording_effects(events.clone());
    let observer = imports.record_calls(WasmHostTraceLimits::default()).unwrap();
    let expected = finish(module.prepare_command(imports), &[1, 3, 2000]).unwrap();
    assert_eq!(*events.lock().unwrap(), [1, 2]);
    let transcript = observer.snapshot().unwrap(); assert_eq!(transcript.call_count(), 3);
    let mut imports = bindings(forbidden);
    let replay = imports.replay_calls(transcript, WasmHostTraceLimits::default()).unwrap();
    assert_eq!(finish(module.prepare_command(imports), &[9999]).unwrap(), expected);
    replay.verify_complete().unwrap();
}

#[test]
fn command_replay_rejects_another_pinned_module_before_any_effect() {
    let a = command(None, &effect(1), WasmNumericLimits::default());
    let b = command(None, &effect(2), WasmNumericLimits::default());
    let mut imports = bindings(|_, _| Ok(vec![]));
    let recording = imports.record_calls(WasmHostTraceLimits::default()).unwrap();
    finish(a.prepare_command(imports), &[10000]).unwrap();
    let mut imports = bindings(forbidden);
    imports.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    let error = b.prepare_command(imports).resume(work(10000), &context(), &policy()).unwrap_err();
    assert!(matches!(error, WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::Trace(_))))));
}

#[test]
fn prior_budget_failure_cannot_be_disguised_by_a_later_exit() {
    let module = command(None, &effect(2), WasmNumericLimits::default());
    let imports = bindings(|caller, _| {
        let _ = caller.charge_work(u64::MAX);
        Err(caller.exit(0))
    });
    assert!(matches!(finish(module.prepare_command(imports), &[1]),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::InstructionBudgetExceeded { .. }))));
}

#[test]
fn provider_panic_consumes_the_task_and_leaves_independent_commands_usable() {
    let module = command(Some(&effect(1)), &effect(2), WasmNumericLimits::default());
    let task = module.prepare_command(bindings(|_, _| panic!("provider failed")));
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || task.resume(work(100), &context(), &policy()))).is_err());
    assert_eq!(finish(module.prepare_command(bindings(|_, _| Ok(vec![]))), &[1]).unwrap().exit_code, 0);
}

#[test]
fn command_task_and_results_preserve_send_sync_contracts() {
    fn check<T: Send + Sync>() {}
    check::<WasmCommandTask<'static>>(); check::<WasmCommandExecution>();
}

fn stdio_command_fixture() -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[3, 0x60, 0, 0, 0x60, 1, 0x7f, 0,
        0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f]);
    let mut imports = vec![2];
    for (function, ty) in [("proc_exit", 1), ("fd_write", 2)] {
        name(&mut imports, WASI_PREVIEW1_MODULE); name(&mut imports, function); imports.extend([0, ty]);
    }
    section(&mut bytes, 2, &imports); section(&mut bytes, 3, &[2, 0, 0]);
    section(&mut bytes, 5, &[1, 1, 1, 1]);
    let mut exports = vec![2]; name(&mut exports, "_start"); exports.extend([0, 3]);
    name(&mut exports, "memory"); exports.extend([2, 0]); section(&mut bytes, 7, &exports);
    section(&mut bytes, 8, &[2]);
    let startup = [0x41, 1, 0x41, 0, 0x41, 1, 0x41, 8, 0x10, 1, 0x1a, 0x0b];
    let entry = [0x41, 2, 0x41, 0, 0x41, 1, 0x41, 8, 0x10, 1, 0x1a,
        0x41, 9, 0x10, 0, 0x00, 0x0b];
    let mut code = vec![2];
    for body in [startup.as_slice(), entry.as_slice()] {
        code.extend(leb(body.len() + 1)); code.push(0); code.extend(body);
    }
    section(&mut bytes, 10, &code);
    section(&mut bytes, 11, &[2, 0, 0x41, 0, 0x0b, 8, 64, 0, 0, 0, 3, 0, 0, 0,
        0, 0x41, 0xc0, 0, 0x0b, 3, 255, 0, 128]);
    bytes
}

#[test]
fn actual_wasi_streams_and_exit_share_the_resolved_cooperative_command_lifecycle() {
    use frankenengine_engine::wasm_runtime_lane::wasi_preview1::WasiStdioLimits;
    let module = load(&stdio_command_fixture(), &[Builtin, RuntimeCapability::Console], WasmNumericLimits::default());
    let mut allowed = policy(); allowed.granted_capabilities.insert(RuntimeCapability::Console);
    let make = || WasiPreview1Config::default().into_imports_with_stdio(
        [VmDispatch, Builtin, RuntimeCapability::Console].into(), vec![], WasiStdioLimits::default(),
    ).unwrap();
    let (mut imports, output) = make();
    let recording = imports.record_calls(WasmHostTraceLimits::default()).unwrap();
    let expected = finish_with_policy(module.prepare_command(imports), &[1, 2, 3000], &allowed).unwrap();
    assert_eq!(expected.exit_code, 9);
    let captured = output.take_output().unwrap();
    assert_eq!(captured.stdout, [255, 0, 128]); assert_eq!(captured.stderr, [255, 0, 128]);
    let (mut imports, output) = make();
    let replay = imports.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
    assert_eq!(finish_with_policy(module.prepare_command(imports), &[9999], &allowed).unwrap(), expected);
    replay.verify_complete().unwrap();
    let captured = output.take_output().unwrap();
    assert!(captured.stdout.is_empty()); assert!(captured.stderr.is_empty());
}

mod scheduling {
    use super::*;
    use std::num::NonZeroUsize;
    use frankenengine_engine::wasm_runtime_lane::scheduler::{
        WasmNativeScheduler, WasmTaskAdmissionErrorKind, WasmTaskHandle, WasmTaskKind, WasmTaskOutcome,
    };

    fn slots(n: usize) -> NonZeroUsize { NonZeroUsize::new(n).unwrap() }

    #[test]
    fn infinite_command_cannot_starve_existing_exports_startup_or_finite_commands() {
        let spin = command(None, &[0x03, 0x40, 0x0c, 0, 0x0b, 0x0b], WasmNumericLimits::default());
        let fast = command(None, &[0x0b], WasmNumericLimits::default());
        let ctx = context(); let allowed = policy();
        let mut instance = fast.instantiate_with_imports(&ctx, &allowed, bindings(forbidden)).unwrap();
        let mut queue = WasmNativeScheduler::new(slots(4));
        let spinner = queue.submit_command(spin.prepare_command(bindings(forbidden))).unwrap();
        let call = queue.submit(instance.begin_call("_start", &[], &ctx, &allowed).unwrap()).unwrap();
        let startup = queue.submit_startup(fast.prepare_startup_with_imports(bindings(forbidden))).unwrap();
        let finite = queue.submit_command(fast.prepare_command(bindings(forbidden))).unwrap();
        let order = [spinner.id(), call.id(), startup.id(), finite.id()];
        let mut completed = BTreeSet::new();
        for turn in 0..32 {
            let result = queue.run_next(work(2), &ctx, &allowed).unwrap();
            if turn < 4 { assert_eq!(result.task_id, order[turn]); }
            match result.outcome {
                WasmTaskOutcome::Pending => {},
                WasmTaskOutcome::Complete(_) | WasmTaskOutcome::Initialized(_) | WasmTaskOutcome::Exited(_) => {
                    assert!(completed.insert(result.task_id));
                }
                other => panic!("unexpected scheduled outcome: {other:?}"),
            }
            if completed.len() == 3 { break; }
        }
        assert_eq!(completed, BTreeSet::from([call.id(), startup.id(), finite.id()]));
        assert_eq!(queue.len(), 1);
        spinner.cancel();
        assert!(matches!(queue.run_next(work(1), &ctx, &allowed).unwrap().outcome, WasmTaskOutcome::Cancelled));
        assert!(queue.is_empty());
    }

    #[test]
    fn command_identity_and_cumulative_work_span_startup_and_unsigned_exit() {
        let module = command(Some(&effect(1)), &exit(u32::MAX, 0x10), WasmNumericLimits::default());
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut queue = WasmNativeScheduler::new(slots(1));
        let handle = queue.submit_command(module.prepare_command(recording_effects(events.clone()))).unwrap();
        let mut before = 0;
        let mut complete = false;
        for _ in 0..20 {
            assert_eq!(queue.next_task_kind(), Some(WasmTaskKind::Command));
            let turn = queue.run_next(work(1), &context(), &policy()).unwrap();
            assert_eq!(turn.task_id, handle.id()); assert_eq!(turn.kind, WasmTaskKind::Command);
            assert_eq!(turn.event.event, "wasm_command_turn");
            assert_eq!(turn.event.work_before, before); assert_eq!(turn.event.error_code, "none");
            before = turn.event.work_after.unwrap();
            match turn.outcome {
                WasmTaskOutcome::Pending => assert_eq!(turn.event.outcome, "yield"),
                WasmTaskOutcome::Exited(execution) => {
                    assert_eq!(execution.exit_code, u32::MAX);
                    assert_eq!(execution.instructions_executed, 9);
                    assert_eq!(before, 9); assert_eq!(turn.event.outcome, "exit");
                    complete = true; break;
                }
                other => panic!("unexpected result: {other:?}"),
            }
        }
        assert!(complete); assert_eq!(*events.lock().unwrap(), [1]);
        assert!(queue.run_next(work(1), &context(), &policy()).is_none());
    }

    #[test]
    fn queue_full_returns_a_partially_executed_command_without_refunding_work() {
        let module = command(Some(&effect(1)), &effect(2), WasmNumericLimits::default());
        let fast = command(None, &[0x0b], WasmNumericLimits::default());
        let events = Arc::new(Mutex::new(Vec::new()));
        let task = pending(module.prepare_command(recording_effects(events.clone())).resume(work(100), &context(), &policy()).unwrap());
        assert_eq!(task.instructions_executed(), 5);
        let ctx = context(); let allowed = policy();
        let mut instance = fast.instantiate_with_imports(&ctx, &allowed, bindings(forbidden)).unwrap();
        let mut queue = WasmNativeScheduler::new(slots(1));
        let old = queue.submit(instance.begin_call("_start", &[], &ctx, &allowed).unwrap()).unwrap();
        let error = queue.submit_command(task).unwrap_err();
        assert_eq!(error.kind(), WasmTaskAdmissionErrorKind::QueueFull);
        let task = (*error).into_command(); assert_eq!(task.instructions_executed(), 5);
        let error = queue.submit_startup(fast.prepare_startup_with_imports(bindings(forbidden))).unwrap_err();
        assert_eq!(error.kind(), WasmTaskAdmissionErrorKind::QueueFull);
        (*error).into_startup().cancel();
        assert!(matches!(queue.run_next(work(100), &ctx, &allowed).unwrap().outcome, WasmTaskOutcome::Complete(_)));
        let new = queue.submit_command(task).unwrap();
        assert_eq!(new.id().get(), old.id().get() + 1); old.cancel();
        match queue.run_next(work(100), &ctx, &allowed).unwrap().outcome {
            WasmTaskOutcome::Exited(execution) => assert_eq!(execution.instructions_executed, 10),
            other => panic!("lost admitted command: {other:?}"),
        }
        assert_eq!(*events.lock().unwrap(), [1, 2]);
    }

    #[test]
    fn withdrawal_is_kind_safe_and_does_not_restart_a_command_phase() {
        let module = command(Some(&effect(1)), &effect(2), WasmNumericLimits::default());
        let fast = command(None, &[0x0b], WasmNumericLimits::default());
        let events = Arc::new(Mutex::new(Vec::new()));
        let task = pending(module.prepare_command(recording_effects(events.clone())).resume(work(100), &context(), &policy()).unwrap());
        let ctx = context(); let allowed = policy();
        let mut instance = fast.instantiate_with_imports(&ctx, &allowed, bindings(forbidden)).unwrap();
        let mut queue = WasmNativeScheduler::new(slots(3));
        let cmd = queue.submit_command(task).unwrap();
        let startup = queue.submit_startup(fast.prepare_startup_with_imports(bindings(forbidden))).unwrap();
        let call = queue.submit(instance.begin_call("_start", &[], &ctx, &allowed).unwrap()).unwrap();
        assert!(queue.take_startup(cmd.id()).is_none()); assert!(queue.take(cmd.id()).is_none());
        assert!(queue.take_command(startup.id()).is_none()); assert!(queue.take_command(call.id()).is_none());
        assert_eq!(queue.next_task(), Some(cmd.id())); assert_eq!(queue.len(), 3);
        let task = queue.take_command(cmd.id()).unwrap();
        assert_eq!(task.instructions_executed(), 5); cmd.cancel();
        let resubmitted = queue.submit_command(task).unwrap();
        assert!(resubmitted.id().get() > call.id().get());
        assert_eq!(queue.next_task(), Some(startup.id()));
        assert!(matches!(queue.run_next(work(100), &ctx, &allowed).unwrap().outcome, WasmTaskOutcome::Initialized(_)));
        assert!(matches!(queue.run_next(work(100), &ctx, &allowed).unwrap().outcome, WasmTaskOutcome::Complete(_)));
        assert!(matches!(queue.run_next(work(100), &ctx, &allowed).unwrap().outcome, WasmTaskOutcome::Exited(_)));
        assert_eq!(*events.lock().unwrap(), [1, 2]);
    }

    #[test]
    fn cancelled_admission_stops_before_allocation_and_cannot_be_transferred() {
        let module = command(Some(&effect(1)), &effect(2), WasmNumericLimits {
            max_memory_pages: 0, ..WasmNumericLimits::default()
        });
        let mut queue = WasmNativeScheduler::new(slots(1));
        let handle = queue.submit_command(module.prepare_command(bindings(forbidden))).unwrap();
        handle.cancel();
        assert!(queue.take_command(handle.id()).is_none());
        let turn = queue.run_next(work(100), &context(), &policy()).unwrap();
        assert!(matches!(turn.outcome, WasmTaskOutcome::Cancelled));
        assert_eq!(turn.event.work_before, 0); assert_eq!(turn.event.work_after, Some(0));
        assert!(queue.is_empty());
    }

    #[test]
    fn revoked_policy_retires_only_the_selected_command_before_entry_effects() {
        let module = command(Some(&effect(1)), &effect(2), WasmNumericLimits::default());
        let fast = command(None, &[0x0b], WasmNumericLimits::default());
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut queue = WasmNativeScheduler::new(slots(2));
        let denied = queue.submit_command(module.prepare_command(recording_effects(events.clone()))).unwrap();
        assert!(matches!(queue.run_next(work(100), &context(), &policy()).unwrap().outcome, WasmTaskOutcome::Pending));
        let healthy = queue.submit_command(fast.prepare_command(bindings(forbidden))).unwrap();
        let changed = ResolutionContext::new("revoked-trace", "revoked-decision", "revoked-policy");
        let turn = queue.run_next(work(100), &changed, &CapabilityPolicyHook::new(BTreeSet::new())).unwrap();
        assert_eq!(turn.task_id, denied.id());
        assert!(matches!(turn.outcome, WasmTaskOutcome::Failed(WasmNativeLoadError::Resolution(_))));
        assert_eq!(turn.event.policy_id, "revoked-policy"); assert_eq!(turn.event.outcome, "deny");
        assert_eq!(turn.event.work_before, 5); assert_eq!(turn.event.work_after, None);
        assert_eq!(queue.next_task(), Some(healthy.id()));
        assert!(matches!(queue.run_next(work(100), &context(), &policy()).unwrap().outcome, WasmTaskOutcome::Pending));
        assert!(matches!(queue.run_next(work(100), &context(), &policy()).unwrap().outcome, WasmTaskOutcome::Exited(_)));
        assert_eq!(*events.lock().unwrap(), [1]);
    }

    #[test]
    fn cancellation_in_the_final_callback_suppresses_command_completion_not_effects() {
        let module = command(None, &effect(2), WasmNumericLimits::default());
        let signal = Arc::new(Mutex::new(None::<WasmTaskHandle>)); let captured = signal.clone();
        let events = Arc::new(Mutex::new(Vec::new())); let observed = events.clone();
        let imports = bindings(move |caller, _| {
            observed.lock().unwrap().push(1);
            captured.lock().unwrap().as_ref().unwrap().cancel();
            Err(caller.exit(71))
        });
        let mut queue = WasmNativeScheduler::new(slots(1));
        *signal.lock().unwrap() = Some(queue.submit_command(module.prepare_command(imports)).unwrap());
        assert!(matches!(queue.run_next(work(100), &context(), &policy()).unwrap().outcome, WasmTaskOutcome::Pending));
        let turn = queue.run_next(work(100), &context(), &policy()).unwrap();
        assert!(matches!(turn.outcome, WasmTaskOutcome::Cancelled));
        assert_eq!(turn.event.work_after, Some(4)); assert_eq!(*events.lock().unwrap(), [1]);
        assert!(queue.is_empty());
    }

    #[test]
    fn cancellation_does_not_replace_a_real_command_budget_failure() {
        let module = command(None, &effect(2), WasmNumericLimits::default());
        let signal = Arc::new(Mutex::new(None::<WasmTaskHandle>)); let captured = signal.clone();
        let imports = bindings(move |caller, _| {
            captured.lock().unwrap().as_ref().unwrap().cancel();
            caller.charge_work(u64::MAX)?;
            Ok(vec![])
        });
        let mut queue = WasmNativeScheduler::new(slots(1));
        *signal.lock().unwrap() = Some(queue.submit_command(module.prepare_command(imports)).unwrap());
        assert!(matches!(queue.run_next(work(100), &context(), &policy()).unwrap().outcome, WasmTaskOutcome::Pending));
        let turn = queue.run_next(work(100), &context(), &policy()).unwrap();
        assert!(matches!(turn.outcome, WasmTaskOutcome::Failed(WasmNativeLoadError::Execution(WasmNumericVmError::InstructionBudgetExceeded { .. }))));
        assert_eq!(turn.event.work_after, None); assert!(queue.is_empty());
    }

    #[test]
    fn scheduled_replay_consumes_the_same_command_trace_without_reexecuting_effects() {
        let module = command(Some(&effect(1)), &exit(17, 0x13), WasmNumericLimits::default());
        let mut imports = bindings(|_, _| Ok(vec![]));
        let recording = imports.record_calls(WasmHostTraceLimits::default()).unwrap();
        let expected = finish(module.prepare_command(imports), &[10000]).unwrap();
        let mut imports = bindings(forbidden);
        let replay = imports.replay_calls(recording.snapshot().unwrap(), WasmHostTraceLimits::default()).unwrap();
        let mut queue = WasmNativeScheduler::new(slots(1));
        queue.submit_command(module.prepare_command(imports)).unwrap();
        let mut completed = false;
        for _ in 0..100 {
            let turn = queue.run_next(work(1), &context(), &policy()).unwrap();
            match turn.outcome {
                WasmTaskOutcome::Exited(execution) => { assert_eq!(execution, expected); completed = true; break; }
                WasmTaskOutcome::Pending => {},
                other => panic!("unexpected replay outcome: {other:?}"),
            }
        }
        assert!(completed); replay.verify_complete().unwrap(); assert!(queue.is_empty());
    }

    #[test]
    fn a_panicked_command_is_removed_without_losing_other_ready_work() {
        let module = command(Some(&effect(1)), &effect(2), WasmNumericLimits::default());
        let fast = command(None, &[0x0b], WasmNumericLimits::default());
        let events = Arc::new(Mutex::new(Vec::new())); let observed = events.clone();
        let imports = bindings(move |_, args| {
            let [I32(value)] = args else { panic!("ABI"); };
            if *value == 2 { panic!("entry provider panicked"); }
            observed.lock().unwrap().push(*value); Ok(vec![])
        });
        let mut queue = WasmNativeScheduler::new(slots(2));
        queue.submit_command(module.prepare_command(imports)).unwrap();
        let healthy = queue.submit_command(fast.prepare_command(bindings(forbidden))).unwrap();
        assert!(matches!(queue.run_next(work(100), &context(), &policy()).unwrap().outcome, WasmTaskOutcome::Pending));
        assert!(matches!(queue.run_next(work(100), &context(), &policy()).unwrap().outcome, WasmTaskOutcome::Pending));
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| queue.run_next(work(100), &context(), &policy()))).is_err());
        assert_eq!(queue.len(), 1); assert_eq!(queue.next_task(), Some(healthy.id()));
        assert!(matches!(queue.run_next(work(100), &context(), &policy()).unwrap().outcome, WasmTaskOutcome::Exited(_)));
        assert_eq!(*events.lock().unwrap(), [1]);
    }
}
