#![forbid(unsafe_code)]

//! Real native startup driven by changing scheduler quanta and policy snapshots.

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::module_resolver::{
    CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
    ModuleRequest, ModuleSyntax, ResolutionContext, ResolutionErrorCode,
    wasm_module_required_capabilities,
};
use frankenengine_engine::wasm_runtime_lane::{
    WasmBoundaryValue, WasmFunctionSignature, WasmNativeInstance, WasmNativeLoadError, WasmNativeModule,
};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostError, WasmHostImports, WasmNumericLimits, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::scheduler::{WasmStartupTask, WasmStartupStep};
use RuntimeCapability::{Builtin, VmDispatch};
use WasmBoundaryValue::I32;

fn leb(mut value: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        bytes.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 { return bytes; }
    }
}

fn signed(mut value: i32) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        let done = (value == 0 && byte & 64 == 0) || (value == -1 && byte & 64 != 0);
        bytes.push(byte | if done { 0 } else { 128 });
        if done { return bytes; }
    }
}

fn section(module: &mut Vec<u8>, id: u8, payload: &[u8]) {
    module.push(id);
    module.extend(leb(payload.len()));
    module.extend_from_slice(payload);
}

// Reuse the saved, independently exercised startup programs: direct, indirect,
// direct tail and indirect tail recursion. Every worker updates memory/global.
fn program(depth: i32, mode: u8, hosts: u8, trap: bool, start: bool) -> Vec<u8> {
    let imported = u8::from(hosts != 0);
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[3, 0x60, 0, 0, 0x60, 0, 1, 0x7f, 0x60, 1, 0x7f, 0]);
    if imported != 0 { section(&mut bytes, 2, &[1, 1, b'h', 4, b't', b'i', b'c', b'k', 0, 0]); }
    section(&mut bytes, 3, &[3, 2, 1, 0]);
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    section(&mut bytes, 5, &[1, 1, 1, 1]);
    section(&mut bytes, 6, &[1, 0x7f, 1, 0x41, 0, 0x0b]);
    let mut exports = vec![5];
    for (name, kind, index) in [("get", 0, imported + 1), ("start", 0, imported + 2),
        ("g", 3, 0), ("m", 2, 0), ("t", 1, 0)] {
        exports.extend(leb(name.len())); exports.extend(name.as_bytes()); exports.extend([kind, index]);
    }
    section(&mut bytes, 7, &exports);
    if start { section(&mut bytes, 8, &[imported + 2]); }
    section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, imported]);
    let mut worker = vec![0, 0x23, 0, 0x41, 1, 0x6a, 0x24, 0,
        0x41, 0, 0x23, 0, 0x36, 2, 0, 0x20, 0, 0x04, 0x40, 0x20, 0, 0x41, 1, 0x6b];
    if mode & 1 == 0 { worker.extend([if mode == 2 { 0x12 } else { 0x10 }, imported]); }
    else { worker.extend([0x41, 0, if mode == 3 { 0x13 } else { 0x11 }, 2, 0]); }
    worker.extend([0x0b, 0x0b]);
    let getter = vec![0, 0x23, 0, 0x0b];
    let mut startup = vec![0, 0x41]; startup.extend(signed(depth)); startup.extend([0x10, imported]);
    for _ in 0..hosts { startup.extend([0x10, 0]); }
    if trap { startup.push(0); }
    startup.push(0x0b);
    let mut code = vec![3];
    for body in [&worker, &getter, &startup] { code.extend(leb(body.len())); code.extend(body); }
    section(&mut bytes, 10, &code);
    section(&mut bytes, 11, &[1, 0, 0x41, 8, 0x0b, 3, 255, 128, 254]);
    bytes
}

fn quantum(work: u64) -> NonZeroU64 { NonZeroU64::new(work).unwrap() }
fn context() -> ResolutionContext { ResolutionContext::new("startup-task", "startup-decision", "current") }
fn policy() -> CapabilityPolicyHook {
    let mut caps = wasm_module_required_capabilities(); caps.insert(Builtin);
    CapabilityPolicyHook::new(caps)
}
fn load(bytes: &[u8], declared: bool, limits: WasmNumericLimits) -> WasmNativeModule {
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver.register_workspace_module("/app/main.mjs",
        ModuleDefinition::new(ModuleSyntax::EsModule, "import './init.wasm';")).unwrap();
    let mut definition = ModuleDefinition::wasm_binary(bytes, &limits).unwrap();
    if declared { definition.required_capabilities.insert(Builtin); }
    resolver.register_workspace_module("/app/init.wasm", definition).unwrap();
    resolver.load_wasm(&ModuleRequest::new("./init.wasm", ImportStyle::Import).with_referrer("/app/main.mjs"),
        &context(), &policy(), limits).unwrap()
}
fn module(bytes: &[u8]) -> WasmNativeModule { load(bytes, true, WasmNumericLimits::default()) }

fn imports(effects: Arc<AtomicUsize>, forbidden: bool) -> WasmHostImports {
    let mut imports = WasmHostImports::new(BTreeSet::from([VmDispatch, Builtin]));
    imports.define("h", "tick", WasmFunctionSignature { params: vec![], results: vec![] },
        BTreeSet::from([Builtin]), 1, move |caller, _| {
            assert!(!forbidden, "replay entered the provider");
            effects.fetch_add(1, Ordering::SeqCst);
            let input = caller.read_memory(8, 3)?.to_vec();
            caller.write_memory(16, &input)?;
            Ok(vec![])
        }).unwrap();
    imports
}
fn run<'vm>(mut task: WasmStartupTask<'vm>, quanta: &[u64]) -> WasmNativeInstance<'vm> {
    assert!(!quanta.is_empty());
    for turn in 0..1_000_000 {
        let before = task.instructions_executed();
        match task.resume(quantum(quanta[turn % quanta.len()]), &context(), &policy()).unwrap() {
            WasmStartupStep::Pending(next) => {
                assert!(next.instructions_executed() > before);
                task = next;
            }
            WasmStartupStep::Complete(instance) => return instance,
        }
    }
    panic!("startup did not make bounded progress")
}
fn denied<T: std::fmt::Debug>(result: Result<T, WasmNativeLoadError>) {
    match result {
        Err(WasmNativeLoadError::Resolution(error)) => assert_eq!(error.code, ResolutionErrorCode::PolicyDenied),
        other => panic!("expected module-policy denial, got {other:?}"),
    }
}
fn first_effect<'vm>(module: &'vm WasmNativeModule, effects: Arc<AtomicUsize>) -> WasmStartupTask<'vm> {
    let mut task = module.prepare_startup_with_imports(imports(effects.clone(), false));
    for _ in 0..10_000 {
        task = match task.resume(quantum(1), &context(), &policy()).unwrap() {
            WasmStartupStep::Pending(task) => task,
            _ => panic!("startup must yield before its second host call"),
        };
        if effects.load(Ordering::SeqCst) == 1 { return task; }
    }
    panic!("first effect was not reached")
}

#[test]
fn prepared_startup_is_lazy_and_denial_precedes_allocation() {
    let module = load(&program(0, 0, 1, false, true), true, WasmNumericLimits {
        max_memory_pages: 0, ..WasmNumericLimits::default()
    });
    let effects = Arc::new(AtomicUsize::new(0));
    let task = module.prepare_startup_with_imports(imports(effects.clone(), false));
    assert_eq!(task.instructions_executed(), 0);
    task.cancel();
    let denied_policy = CapabilityPolicyHook::new(BTreeSet::new());
    denied(module.prepare_startup_with_imports(imports(effects.clone(), false))
        .resume(quantum(1), &context(), &denied_policy));
    assert!(matches!(module.prepare_startup_with_imports(imports(effects.clone(), false))
        .resume(quantum(1), &context(), &policy()),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::LimitExceeded { .. })))));
    assert_eq!(effects.load(Ordering::SeqCst), 0);
}

#[test]
fn variable_slices_match_synchronous_startup_state_and_metrics() {
    for mode in 0..4 { for quanta in [&[1][..], &[2, 7, 1, 64], &[u64::MAX]] {
        let module = module(&program(12, mode, 0, false, true));
        let expected = module.instantiate(&context(), &policy()).unwrap();
        let mut actual = run(module.prepare_startup(), quanta);
        assert_eq!(actual.start_execution(&context(), &policy()).unwrap(), expected.start_execution(&context(), &policy()).unwrap());
        assert_eq!(actual.memory_export("m", &context(), &policy()).unwrap(), expected.memory_export("m", &context(), &policy()).unwrap());
        assert_eq!(actual.table_export("t", &context(), &policy()).unwrap(), expected.table_export("t", &context(), &policy()).unwrap());
        assert_eq!(actual.call_export("get", &[], &context(), &policy()).unwrap().results, [I32(13)]);
        assert_eq!(actual.call_export("get", &[], &context(), &policy()).unwrap().results, [I32(13)]);
    } }
}

#[test]
fn no_start_publication_is_authorized_and_remains_once_only() {
    let module = module(&program(9, 0, 0, false, false));
    denied(module.prepare_startup().resume(quantum(1), &context(), &policy().deny_specifier("./init.wasm")));
    let mut instance = run(module.prepare_startup(), &[1]);
    assert!(instance.start_execution(&context(), &policy()).unwrap().is_none());
    assert_eq!(instance.call_export("get", &[], &context(), &policy()).unwrap().results, [I32(0)]);
}

#[test]
fn tail_startup_retains_one_callee_activation_across_yields() {
    for mode in [2, 3] {
        let module = load(&program(20_000, mode, 0, false, true), true, WasmNumericLimits {
            max_call_depth: 2, max_live_values: 4, ..WasmNumericLimits::default()
        });
        let instance = run(module.prepare_startup(), &[113, 17]);
        assert_eq!(instance.global_export("g", &context(), &policy()).unwrap(), Some(&I32(20_001)));
        assert_eq!(instance.start_execution(&context(), &policy()).unwrap().unwrap().max_call_depth, 2);
    }
}

#[test]
fn startup_hard_budget_is_not_refilled_by_changing_quanta() {
    let module = load(&program(20, 0, 0, false, true), true, WasmNumericLimits {
        max_instructions: 25, ..WasmNumericLimits::default()
    });
    for work in [1, 7, 64] {
        let mut task = module.prepare_startup();
        let mut exhausted = false;
        for _ in 0..100 {
            match task.resume(quantum(work), &context(), &policy()) {
                Ok(WasmStartupStep::Pending(next)) => { assert!(next.instructions_executed() <= 25); task = next; }
                Err(WasmNativeLoadError::Execution(WasmNumericVmError::InstructionBudgetExceeded { max: 25 })) => {
                    exhausted = true; break;
                }
                other => panic!("expected exact startup budget refusal: {other:?}"),
            }
        }
        assert!(exhausted);
    }
}

#[test]
fn every_current_policy_revocation_stops_the_next_startup_host_effect() {
    let module = module(&program(0, 0, 2, false, true));
    for capability in [RuntimeCapability::ModuleLoad, VmDispatch, Builtin] {
        let effects = Arc::new(AtomicUsize::new(0));
        let task = first_effect(&module, effects.clone());
        let mut revoked = policy(); revoked.granted_capabilities.remove(&capability);
        denied(task.resume(quantum(100), &context(), &revoked));
        assert_eq!(effects.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn alias_and_canonical_deny_lists_apply_after_startup_suspension() {
    let module = module(&program(0, 0, 2, false, true));
    for name in ["./init.wasm", "/app/init.wasm"] {
        let effects = Arc::new(AtomicUsize::new(0));
        let task = first_effect(&module, effects.clone());
        denied(task.resume(quantum(100), &context(), &policy().deny_specifier(name)));
        assert_eq!(effects.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn dropping_partial_startup_keeps_external_effects_without_repeating_them() {
    let module = module(&program(0, 0, 2, false, true));
    let effects = Arc::new(AtomicUsize::new(0));
    first_effect(&module, effects.clone()).cancel();
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    let ready = run(module.prepare_startup_with_imports(imports(effects.clone(), false)), &[1]);
    assert_eq!(effects.load(Ordering::SeqCst), 3);
    assert_eq!(ready.global_export("g", &context(), &policy()).unwrap(), Some(&I32(1)));
}

#[test]
fn declarations_and_provider_grants_cannot_be_manufactured_by_a_turn_policy() {
    let bytes = program(0, 0, 1, false, true);
    let effects = Arc::new(AtomicUsize::new(0));
    let undeclared = load(&bytes, false, WasmNumericLimits::default());
    assert!(matches!(undeclared.prepare_startup_with_imports(imports(effects.clone(), false))
        .resume(quantum(1), &context(), &policy()),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied { capability: Builtin, .. }))))));
    let module = module(&bytes);
    assert!(matches!(module.prepare_startup().resume(quantum(u64::MAX), &context(), &policy()),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::ImportedFunctionUnsupported { .. }))));
    assert_eq!(effects.load(Ordering::SeqCst), 0);
}

#[test]
fn live_execution_cancellation_survives_reset_between_startup_turns() {
    let module = module(&program(20, 0, 0, false, true));
    let token = CancellationToken::new();
    let mut bindings = WasmHostImports::new(BTreeSet::new());
    bindings.bind_execution_cancellation(token.clone(), "scheduled-start").unwrap();
    let task = match module.prepare_startup_with_imports(bindings).resume(quantum(7), &context(), &policy()).unwrap() {
        WasmStartupStep::Pending(task) => task,
        _ => panic!("expected pending initialization"),
    };
    token.cancel(); token.reset();
    assert!(matches!(task.resume(quantum(7), &context(), &policy()),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::ExecutionCancelled))))));
}

#[test]
fn selective_revocation_before_the_first_resume_prevents_host_startup() {
    let module = module(&program(0, 0, 1, false, true));
    let effects = Arc::new(AtomicUsize::new(0));
    let token = CancellationToken::new();
    let mut bindings = imports(effects.clone(), false);
    bindings.bind_capability_revocation(Builtin, token.clone(), "startup-service").unwrap();
    let task = module.prepare_startup_with_imports(bindings);
    token.cancel(); token.reset();
    assert!(matches!(task.resume(quantum(100), &context(), &policy()),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied { capability: Builtin, .. }))))));
    assert_eq!(effects.load(Ordering::SeqCst), 0);
}

#[test]
fn scoped_startup_replay_is_independent_of_quanta_and_never_reenters_providers() {
    let module = module(&program(4, 3, 2, false, true));
    let effects = Arc::new(AtomicUsize::new(0));
    let mut bindings = imports(effects.clone(), false);
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    let live = run(module.prepare_startup_with_imports(bindings), &[1, 7, 2]);
    let tape = recording.snapshot().unwrap();
    assert_eq!(tape.call_count(), 2);
    let mut bindings = imports(effects.clone(), true);
    let replay = bindings.replay_calls(tape, WasmHostTraceLimits::default()).unwrap();
    let reproduced = run(module.prepare_startup_with_imports(bindings), &[u64::MAX]);
    replay.verify_complete().unwrap();
    assert_eq!(effects.load(Ordering::SeqCst), 2);
    assert_eq!(live.start_execution(&context(), &policy()).unwrap(), reproduced.start_execution(&context(), &policy()).unwrap());
    assert_eq!(live.memory_export("m", &context(), &policy()).unwrap(), reproduced.memory_export("m", &context(), &policy()).unwrap());
}

#[test]
fn a_later_start_trap_preserves_completed_callback_recording() {
    let module = module(&program(0, 0, 1, true, true));
    let effects = Arc::new(AtomicUsize::new(0));
    let mut bindings = imports(effects.clone(), false);
    let recording = bindings.record_calls(WasmHostTraceLimits::default()).unwrap();
    assert!(matches!(module.prepare_startup_with_imports(bindings).resume(quantum(u64::MAX), &context(), &policy()),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::Unreachable { .. }))));
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(recording.snapshot().unwrap().call_count(), 1);
}
