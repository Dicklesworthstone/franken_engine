#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::future::Future;
use std::num::NonZeroU64;
use std::pin::Pin;
use std::sync::{Arc, atomic::{AtomicBool, AtomicUsize, Ordering}};
use std::task::{Context, Poll, Wake, Waker};

use frankenengine_engine::capability::RuntimeCapability::{Builtin, VmDispatch};
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleRequest, ResolutionContext, wasm_module_required_capabilities,
};
use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue, WasmFunctionSignature, WasmNativeLoadError, WasmNativeModule,
};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostCaller, WasmHostError, WasmHostImports, WasmNumericLimits, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::wasi_preview1::WasiPreview1Config;

type Outcome = Result<Vec<WasmBoundaryValue>, WasmNumericVmError>;

fn leb(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let low = (value & 127) as u8;
        value >>= 7;
        bytes.push(low | if value == 0 { 0 } else { 128 });
        if value == 0 { return bytes; }
    }
}

fn section(bytes: &mut Vec<u8>, id: u8, payload: &[u8]) {
    bytes.push(id); bytes.extend(leb(payload.len())); bytes.extend(payload);
}

// Imported h.step and proc_exit are real typed native bindings, not VM mocks.
// Local functions 2/3 are binary startup and the command's exported entry.
fn fixture(start: Option<&[u8]>, command: &[u8], export: bool, result: bool) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[3, 0x60, 0, 0, 0x60, 1, 0x7f, 0, 0x60, 0, 1, 0x7f]);
    let mut imports = vec![2, 1, b'h', 4, b's', b't', b'e', b'p', 0, 0];
    let wasi = b"wasi_snapshot_preview1";
    imports.extend(leb(wasi.len())); imports.extend(wasi);
    imports.extend([9, b'p', b'r', b'o', b'c', b'_', b'e', b'x', b'i', b't', 0, 1]);
    section(&mut bytes, 2, &imports);
    section(&mut bytes, 3, &[2, 0, if result { 2 } else { 0 }]);
    section(&mut bytes, 5, &[1, 1, 1, 1]);
    if export { section(&mut bytes, 7, &[1, 6, b'_', b's', b't', b'a', b'r', b't', 0, 3]); }
    if start.is_some() { section(&mut bytes, 8, &[2]); }
    let mut code = vec![2];
    for body in [start.unwrap_or(&[0x0b]), command] {
        code.extend(leb(body.len() + 1)); code.push(0); code.extend(body);
    }
    section(&mut bytes, 10, &code);
    bytes
}

fn context() -> ResolutionContext { ResolutionContext::new("command-trace", "command-decision", "command-policy") }
fn policy() -> CapabilityPolicyHook {
    let mut grants = wasm_module_required_capabilities(); grants.insert(Builtin);
    CapabilityPolicyHook::new(grants)
}
fn load(bytes: &[u8], limits: WasmNumericLimits, declared: bool) -> WasmNativeModule {
    let mut resolver = DeterministicModuleResolver::new("/app");
    let mut definition = ModuleDefinition::wasm_binary(bytes, &limits).unwrap();
    if declared { definition.required_capabilities.insert(Builtin); }
    resolver.register_workspace_module("/app/command.wasm", definition).unwrap();
    resolver.load_wasm(&ModuleRequest::new("/app/command.wasm", ImportStyle::Import), &context(), &policy(), limits).unwrap()
}
fn module(start: Option<&[u8]>, command: &[u8]) -> WasmNativeModule {
    load(&fixture(start, command, true, false), WasmNumericLimits::default(), true)
}
fn imports<F>(callback: F) -> WasmHostImports
where F: FnMut(&mut WasmHostCaller<'_, '_>, &[WasmBoundaryValue]) -> Outcome + Send + Sync + 'static {
    let mut imports = WasiPreview1Config::default().into_imports(BTreeSet::from([Builtin, VmDispatch])).unwrap();
    imports.define("h", "step", WasmFunctionSignature { params: vec![], results: vec![] },
        BTreeSet::from([Builtin]), 1, callback).unwrap();
    imports
}
fn counted(calls: Arc<AtomicUsize>) -> WasmHostImports {
    imports(move |_, _| { calls.fetch_add(1, Ordering::SeqCst); Ok(vec![]) })
}
fn reader() -> impl FnMut() -> Result<(ResolutionContext, CapabilityPolicyHook), WasmNativeLoadError> {
    || Ok((context(), policy()))
}
fn live_reader(allowed: Arc<AtomicBool>) -> impl FnMut() -> Result<(ResolutionContext, CapabilityPolicyHook), WasmNativeLoadError> {
    move || Ok((context(), if allowed.load(Ordering::SeqCst) { policy() } else { CapabilityPolicyHook::new(BTreeSet::new()) }))
}
fn work(n: u64) -> NonZeroU64 { NonZeroU64::new(n).unwrap() }

#[derive(Default)]
struct Wakes(AtomicUsize);
impl Wake for Wakes {
    fn wake(self: Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
    fn wake_by_ref(self: &Arc<Self>) { self.0.fetch_add(1, Ordering::SeqCst); }
}
fn poll<F: Future>(future: Pin<&mut F>, wakes: &Arc<Wakes>) -> Poll<F::Output> {
    let waker = Waker::from(wakes.clone());
    future.poll(&mut Context::from_waker(&waker))
}
fn finish<F: Future>(future: Pin<&mut F>, wakes: &Arc<Wakes>) -> F::Output {
    let mut future = future;
    for _ in 0..20_000 {
        let before = wakes.0.load(Ordering::SeqCst);
        match poll(future.as_mut(), wakes) {
            Poll::Ready(result) => return result,
            Poll::Pending => assert_eq!(wakes.0.load(Ordering::SeqCst), before + 1),
        }
    }
    panic!("bounded test command did not finish")
}
fn policy_denied<T>(result: Result<T, WasmNativeLoadError>) {
    assert!(matches!(result, Err(WasmNativeLoadError::Resolution(_))));
}

#[test]
fn synchronous_commands_translate_only_real_exits_and_do_not_enter_after_startup_exit() {
    for exit in [0_u32, 17, u32::MAX] {
        // i32.const -1 preserves all exit bits; other constants fit one signed byte.
        let constant = if exit == u32::MAX { 0x7f } else { exit as u8 };
        let body = [0x10, 0, 0x41, constant, 0x10, 1, 0x10, 0, 0x0b];
        for startup_exit in [false, true] {
            let module = if startup_exit { module(Some(&body), &[0x10, 0, 0x0b]) }
                else { module(None, &body) };
            let calls = Arc::new(AtomicUsize::new(0));
            assert_eq!(module.run_wasi_command(&context(), &policy(), counted(calls.clone())).unwrap().exit_code(), exit);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }
    assert_eq!(module(None, &[0x0b]).run_wasi_command(&context(), &policy(), counted(Arc::new(AtomicUsize::new(0)))).unwrap().exit_code(), 0);
}

#[test]
fn lazy_construction_and_mandatory_phase_yield_do_not_run_command_entry_early() {
    let module = module(None, &[0x10, 0, 0x0b]);
    let calls = Arc::new(AtomicUsize::new(0)); let wakes = Arc::new(Wakes::default());
    let mut future = Box::pin(module.run_wasi_command_cooperatively(counted(calls.clone()), work(100), reader()));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(poll(future.as_mut(), &wakes).is_pending());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(finish(future.as_mut(), &wakes).unwrap().exit_code(), 0);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn every_quantum_preserves_startup_state_and_exact_once_entry_effects() {
    let init = [0x41, 0, 0x41, 7, 0x36, 2, 0, 0x10, 0, 0x0b];
    let entry = [0x10, 0, 0x10, 0, 0x41, 17, 0x10, 1, 0x0b];
    let module = module(Some(&init), &entry);
    for quantum in [1, 2, 3, 7, 64, u64::MAX] {
        let calls = Arc::new(AtomicUsize::new(0)); let observed = calls.clone();
        let bindings = imports(move |caller, _| {
            assert_eq!(caller.read_memory(0, 4)?, &[7, 0, 0, 0]);
            observed.fetch_add(1, Ordering::SeqCst); Ok(vec![])
        });
        let mut future = Box::pin(module.run_wasi_command_cooperatively(bindings, work(quantum), reader()));
        assert_eq!(finish(future.as_mut(), &Arc::new(Wakes::default())).unwrap().exit_code(), 17);
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }
}

#[test]
fn invalid_or_missing_entry_fails_before_linking_allocation_and_startup() {
    for (export, result, body) in [(false, false, vec![0x0b]), (true, true, vec![0x41, 1, 0x0b])] {
        let module = load(&fixture(Some(&[0x10, 0, 0x0b]), &body, export, result),
            WasmNumericLimits { max_memory_pages: 0, ..WasmNumericLimits::default() }, true);
        for cooperative in [false, true] {
            let bindings = WasmHostImports::new(BTreeSet::new());
            let outcome = if cooperative {
                finish(Box::pin(module.run_wasi_command_cooperatively(bindings, work(1), reader())).as_mut(), &Arc::new(Wakes::default()))
            } else { module.run_wasi_command(&context(), &policy(), bindings) };
            assert!(matches!(outcome, Err(WasmNativeLoadError::Execution(
                WasmNumericVmError::UnknownExport { .. } | WasmNumericVmError::InvalidModule { .. }
            ))));
        }
    }
}

#[test]
fn policy_precedes_entry_validation_and_provider_grants_cannot_supply_manifest_authority() {
    let bad = load(&fixture(None, &[0x0b], false, false), WasmNumericLimits::default(), true);
    policy_denied(bad.run_wasi_command(&context(), &CapabilityPolicyHook::new(BTreeSet::new()), WasmHostImports::new(BTreeSet::new())));
    let undeclared = load(&fixture(Some(&[0x10, 0, 0x0b]), &[0x0b], true, false), WasmNumericLimits::default(), false);
    let calls = Arc::new(AtomicUsize::new(0));
    let result = finish(Box::pin(undeclared.run_wasi_command_cooperatively(counted(calls.clone()), work(1), reader())).as_mut(), &Arc::new(Wakes::default()));
    assert!(matches!(result, Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(
        WasmStateError::Host(WasmHostError::CapabilityDenied { capability: Builtin, .. })
    )))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn revoked_current_policy_stops_the_next_entry_slice_and_keeps_completed_effects() {
    let module = module(None, &[0x10, 0, 0x10, 0, 0x0b]);
    let allowed = Arc::new(AtomicBool::new(true)); let calls = Arc::new(AtomicUsize::new(0));
    let wakes = Arc::new(Wakes::default());
    let mut future = Box::pin(module.run_wasi_command_cooperatively(counted(calls.clone()), work(1), live_reader(allowed.clone())));
    for _ in 0..20 {
        assert!(poll(future.as_mut(), &wakes).is_pending());
        if calls.load(Ordering::SeqCst) == 1 { break; }
    }
    assert_eq!(calls.load(Ordering::SeqCst), 1); allowed.store(false, Ordering::SeqCst);
    policy_denied(finish(future.as_mut(), &wakes));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn final_policy_check_gates_normal_return_and_exit_in_both_phases() {
    for startup_exit in [false, true] { for exit in [false, true] {
        let body = if exit { vec![0x10, 0, 0x41, 17, 0x10, 1, 0x0b] }
            else { vec![0x10, 0, 0x0b] };
        let module = if startup_exit { module(Some(&body), &[0x0b]) } else { module(None, &body) };
        let allowed = Arc::new(AtomicBool::new(true)); let revoke = allowed.clone();
        let bindings = imports(move |_, _| { revoke.store(false, Ordering::SeqCst); Ok(vec![]) });
        policy_denied(finish(Box::pin(module.run_wasi_command_cooperatively(bindings, work(100), live_reader(allowed))).as_mut(), &Arc::new(Wakes::default())));
    } }
}

#[test]
fn traps_are_not_exit_statuses_and_keep_precedence_over_later_policy_changes() {
    let module = module(None, &[0x10, 0, 0x0b]);
    let allowed = Arc::new(AtomicBool::new(true)); let revoke = allowed.clone();
    let bindings = imports(move |_, _| {
        revoke.store(false, Ordering::SeqCst);
        Err(WasmHostError::trap("provider failed before exit").into())
    });
    let result = finish(Box::pin(module.run_wasi_command_cooperatively(bindings, work(100), live_reader(allowed))).as_mut(), &Arc::new(Wakes::default()));
    assert!(matches!(result, Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(
        WasmStateError::Host(WasmHostError::Trap { .. })
    )))));
    assert!(matches!(module.run_wasi_command(&context(), &policy(), imports(|_, _| Err(WasmHostError::trap("not an exit").into()))),
        Err(WasmNativeLoadError::Execution(_))));
}

#[test]
fn startup_and_entry_exhaustion_are_errors_not_refunded_by_polling() {
    let spin = [0x03, 0x40, 0x0c, 0, 0x0b, 0x0b];
    for start in [false, true] {
        let bytes = if start { fixture(Some(&spin), &[0x0b], true, false) }
            else { fixture(None, &spin, true, false) };
        let module = load(&bytes, WasmNumericLimits { max_instructions: 12, ..WasmNumericLimits::default() }, true);
        let result = finish(Box::pin(module.run_wasi_command_cooperatively(counted(Arc::new(AtomicUsize::new(0))), work(1), reader())).as_mut(), &Arc::new(Wakes::default()));
        assert!(matches!(result, Err(WasmNativeLoadError::Execution(WasmNumericVmError::InstructionBudgetExceeded { max: 12 }))));
    }
}

#[test]
fn spinning_initialization_cannot_prevent_another_command_from_finishing() {
    let spinner = module(Some(&[0x03, 0x40, 0x0c, 0, 0x0b, 0x0b]), &[0x0b]);
    let useful = module(None, &[0x41, 17, 0x10, 1, 0x0b]);
    let mut a = Box::pin(spinner.run_wasi_command_cooperatively(counted(Arc::new(AtomicUsize::new(0))), work(2), reader()));
    let mut b = Box::pin(useful.run_wasi_command_cooperatively(counted(Arc::new(AtomicUsize::new(0))), work(2), reader()));
    let wakes = Arc::new(Wakes::default());
    for _ in 0..20 {
        assert!(poll(a.as_mut(), &wakes).is_pending());
        if let Poll::Ready(result) = poll(b.as_mut(), &wakes) { assert_eq!(result.unwrap().exit_code(), 17); return; }
    }
    panic!("useful command was starved")
}

#[test]
fn dropping_partial_command_keeps_prior_effects_without_running_pending_calls() {
    for start in [false, true] {
        let body = [0x10, 0, 0x10, 0, 0x0b];
        let module = if start { module(Some(&body), &[0x10, 0, 0x0b]) } else { module(None, &body) };
        let calls = Arc::new(AtomicUsize::new(0)); let wakes = Arc::new(Wakes::default());
        let mut future = Box::pin(module.run_wasi_command_cooperatively(counted(calls.clone()), work(1), reader()));
        for _ in 0..20 {
            assert!(poll(future.as_mut(), &wakes).is_pending());
            if calls.load(Ordering::SeqCst) == 1 { break; }
        }
        drop(future); assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn live_execution_cancellation_is_never_translated_into_a_success_status() {
    let module = module(None, &[0x10, 0, 0x41, 17, 0x10, 1, 0x0b]);
    let token = CancellationToken::new(); let request = token.clone();
    let mut bindings = imports(move |_, _| { request.cancel(); Ok(vec![]) });
    bindings.bind_execution_cancellation(token, "command-cancel").unwrap();
    let result = finish(Box::pin(module.run_wasi_command_cooperatively(bindings, work(100), reader())).as_mut(), &Arc::new(Wakes::default()));
    assert!(matches!(result, Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(
        WasmStateError::Host(WasmHostError::ExecutionCancelled)
    )))));
}

#[test]
fn scoped_replay_covers_both_phases_without_repeating_provider_effects() {
    let module = module(Some(&[0x10, 0, 0x0b]), &[0x10, 0, 0x41, 17, 0x10, 1, 0x0b]);
    let calls = Arc::new(AtomicUsize::new(0)); let mut live = counted(calls.clone());
    let recording = live.record_calls(WasmHostTraceLimits::default()).unwrap();
    assert_eq!(finish(Box::pin(module.run_wasi_command_cooperatively(live, work(1), reader())).as_mut(), &Arc::new(Wakes::default())).unwrap().exit_code(), 17);
    let tape = recording.snapshot().unwrap(); assert_eq!(tape.call_count(), 3);
    assert_eq!(calls.load(Ordering::SeqCst), 2);
    let mut replay = imports(|_, _| panic!("replay entered the provider"));
    let observer = replay.replay_calls(tape, WasmHostTraceLimits::default()).unwrap();
    assert_eq!(finish(Box::pin(module.run_wasi_command_cooperatively(replay, work(7), reader())).as_mut(), &Arc::new(Wakes::default())).unwrap().exit_code(), 17);
    observer.verify_complete().unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn completion_and_caught_provider_panics_cannot_restart_entry() {
    let module = module(None, &[0x10, 0, 0x0b]);
    for panic_provider in [false, true] {
        let calls = Arc::new(AtomicUsize::new(0)); let observed = calls.clone();
        let bindings = imports(move |_, _| {
            observed.fetch_add(1, Ordering::SeqCst);
            assert!(!panic_provider, "trusted provider panic"); Ok(vec![])
        });
        let wakes = Arc::new(Wakes::default());
        let mut future = Box::pin(module.run_wasi_command_cooperatively(bindings, work(100), reader()));
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| finish(future.as_mut(), &wakes)));
        assert_eq!(outcome.is_err(), panic_provider);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| poll(future.as_mut(), &wakes))).is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn command_future_can_move_between_executor_threads() {
    fn is_send<T: Send>(_: &T) {}
    let module = module(None, &[0x0b]);
    let future = module.run_wasi_command_cooperatively(counted(Arc::new(AtomicUsize::new(0))), work(1), reader());
    is_send(&future);
}

#[test]
fn normal_return_preserves_separate_startup_and_entry_metrics() {
    use frankenengine_engine::wasm_runtime_lane::wasi_preview1::WasiCommandOutcome;
    let module = module(Some(&[0x10, 0, 0x0b]), &[0x10, 0, 0x10, 0, 0x0b]);
    let expected = module.run_wasi_command(&context(), &policy(), counted(Arc::new(AtomicUsize::new(0)))).unwrap();
    assert!(matches!(&expected, WasiCommandOutcome::Returned { startup: Some(_), .. }));
    for quantum in [1, 2, 7, u64::MAX] {
        let actual = finish(Box::pin(module.run_wasi_command_cooperatively(
            counted(Arc::new(AtomicUsize::new(0))), work(quantum), reader(),
        )).as_mut(), &Arc::new(Wakes::default())).unwrap();
        assert_eq!(actual, expected);
    }
}

#[test]
fn cooperative_exit_retains_full_unsigned_status_and_its_original_phase() {
    use frankenengine_engine::wasm_runtime_lane::wasi_preview1::{WasiCommandOutcome, WasiCommandPhase};
    for start in [false, true] {
        let body = [0x41, 0x7f, 0x10, 1, 0x10, 0, 0x0b];
        let module = if start { module(Some(&body), &[0x10, 0, 0x0b]) } else { module(None, &body) };
        for quantum in [1, 2, 7, u64::MAX] {
            let calls = Arc::new(AtomicUsize::new(0));
            let actual = finish(Box::pin(module.run_wasi_command_cooperatively(
                counted(calls.clone()), work(quantum), reader(),
            )).as_mut(), &Arc::new(Wakes::default())).unwrap();
            assert_eq!(actual, WasiCommandOutcome::Exited {
                code: u32::MAX,
                phase: if start { WasiCommandPhase::Instantiation } else { WasiCommandPhase::Command },
            });
            assert_eq!(calls.load(Ordering::SeqCst), 0);
        }
    }
}
