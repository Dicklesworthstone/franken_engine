#![forbid(unsafe_code)]

//! Real numeric-VM integration, including a freestanding compiled C command.
//! Scripted test sources verify plumbing, NOT cryptographic entropy quality.

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::wasm_runtime_lane::WasmBoundaryValue::I32;
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmCallStep, WasmHostError, WasmHostImports, WasmNumericInstance, WasmNumericLimits,
    WasmNumericVm, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::wasi_preview1::{
    WasiPreview1Config, WasiPreview1Error, WasiStdioLimits, run_command,
};
use frankenengine_engine::wasm_runtime_lane::wasi_preview1::sources::{
    WasiRandomLimits, WasiSourceError,
};
use frankenengine_engine::wasm_runtime_lane::work_pool::WasmWorkPool;

fn leb(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (n & 127) as u8; n >>= 7;
        out.push(byte | if n == 0 { 0 } else { 128 });
        if n == 0 { return out; }
    }
}
fn section(out: &mut Vec<u8>, id: u8, payload: &[u8]) {
    out.push(id); out.extend(leb(payload.len())); out.extend(payload);
}
fn name(out: &mut Vec<u8>, text: &str) { out.extend(leb(text.len())); out.extend(text.as_bytes()); }
fn fixture(memory: bool, start: bool) -> Vec<u8> {
    let mut out = b"\0asm\x01\0\0\0".to_vec();
    section(&mut out, 1, &[2, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0]);
    let mut imports = vec![1];
    name(&mut imports, "wasi_snapshot_preview1"); name(&mut imports, "random_get"); imports.extend([0, 0]);
    section(&mut out, 2, &imports);
    section(&mut out, 3, if start { &[3, 0, 0, 1] } else { &[2, 0, 0] });
    section(&mut out, 4, &[1, 0x70, 0, 1]);
    if memory { section(&mut out, 5, &[1, 1, 1, 1]); }
    let mut exports = vec![3 + u8::from(memory)];
    for (index, export) in ["random", "direct", "indirect"].iter().enumerate() {
        name(&mut exports, export); exports.extend([0, index as u8]);
    }
    if memory { name(&mut exports, "memory"); exports.extend([2, 0]); }
    section(&mut out, 7, &exports);
    if start { section(&mut out, 8, &[3]); }
    section(&mut out, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
    let direct = [0, 0x20, 0, 0x20, 1, 0x10, 0, 0x0b];
    let indirect = [0, 0x20, 0, 0x20, 1, 0x41, 0, 0x11, 0, 0, 0x0b];
    let startup = [0, 0x41, 0xc0, 0, 0x41, 0xc1, 0, 0x10, 0, 0x1a, 0x0b];
    let mut code = vec![if start { 3 } else { 2 }];
    for body in [direct.as_slice(), indirect.as_slice()].into_iter().chain(start.then_some(startup.as_slice())) {
        code.extend(leb(body.len())); code.extend(body);
    }
    section(&mut out, 10, &code);
    if memory {
        let mut data = vec![1, 0, 0x41, 0, 0x0b]; data.extend(leb(512)); data.extend([0xaa; 512]);
        section(&mut out, 11, &data);
    }
    out
}
fn caps() -> BTreeSet<RuntimeCapability> {
    BTreeSet::from([RuntimeCapability::VmDispatch, RuntimeCapability::RandomRead])
}
fn vm(memory: bool, start: bool, work: u64) -> WasmNumericVm {
    WasmNumericVm::parse(&fixture(memory, start), WasmNumericLimits { max_instructions: work, ..Default::default() }).unwrap()
}
fn scripted(limits: WasiRandomLimits) -> (WasmHostImports, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0)); let observed = Arc::clone(&count);
    let mut next = 0_u8;
    let imports = WasmHostImports::new(caps()).with_wasi_random_source(move |output: &mut [u8]| {
        observed.fetch_add(1, Ordering::SeqCst);
        for byte in output { *byte = next; next = next.wrapping_add(1); }
        Ok(())
    }, limits).unwrap();
    (imports, count)
}
fn call(instance: &mut WasmNumericInstance<'_>, export: &str, pointer: i32, length: i32) -> i32 {
    let result = instance.call_export(export, &[I32(pointer), I32(length)]).unwrap();
    let [I32(code)] = result.results.as_slice() else { panic!("errno ABI"); }; *code
}
fn memory<'a>(instance: &'a WasmNumericInstance<'_>) -> &'a [u8] { instance.memory_export("memory").unwrap() }

#[test]
fn direct_indirect_and_exported_random_imports_fill_exact_binary_ranges() {
    let vm = vm(true, false, 10000);
    let (imports, count) = scripted(WasiRandomLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    for (index, export) in ["random", "direct", "indirect"].iter().enumerate() {
        assert_eq!(call(&mut instance, export, 64, 65), 0);
        let expected: Vec<u8> = (index * 65..(index + 1) * 65).map(|n| n as u8).collect();
        assert_eq!(&memory(&instance)[64..129], expected);
        assert_eq!(memory(&instance)[63], 0xaa); assert_eq!(memory(&instance)[129], 0xaa);
    }
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[test]
fn no_default_source_and_no_builtin_to_entropy_authority_substitution() {
    let vm = vm(true, true, 10000);
    let mut grants = caps(); grants.insert(RuntimeCapability::Builtin);
    assert!(matches!(vm.instantiate_with_imports(WasiPreview1Config::default().into_imports(grants).unwrap()),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::MissingBinding { .. })))));
    let count = Arc::new(AtomicUsize::new(0)); let seen = Arc::clone(&count);
    let imports = WasmHostImports::new(BTreeSet::from([RuntimeCapability::VmDispatch, RuntimeCapability::Builtin]))
        .with_wasi_random_source(move |_: &mut [u8]| { seen.fetch_add(1, Ordering::SeqCst); Ok(()) }, Default::default()).unwrap();
    assert!(matches!(vm.instantiate_with_imports(imports),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { capability: RuntimeCapability::RandomRead, .. })))));
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn complete_unsigned_bounds_fail_without_source_access_or_partial_output() {
    let vm = vm(true, false, 10000);
    let (imports, count) = scripted(Default::default()); let mut instance = vm.instantiate_with_imports(imports).unwrap();
    let before = memory(&instance).to_vec();
    for (pointer, length) in [(-1, 0), (-1, 1), (65_537, 0), (65_535, 2), (0, -1)] {
        assert_eq!(call(&mut instance, "random", pointer, length), 21);
        assert_eq!(memory(&instance), before);
    }
    assert_eq!(count.load(Ordering::SeqCst), 0);
    assert_eq!(call(&mut instance, "random", 65_535, 1), 0);
    assert_eq!(memory(&instance)[65_535], 0);
}

#[test]
fn empty_requests_need_existing_memory_but_no_source_or_lifetime_quota() {
    for has_memory in [false, true] {
        let vm = vm(has_memory, false, 10000);
        let (imports, count) = scripted(WasiRandomLimits { max_request_bytes: 0, max_total_bytes: 0, max_calls: 0, ..Default::default() });
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        assert_eq!(call(&mut instance, "random", 0, 0), if has_memory { 0 } else { 21 });
        if has_memory {
            assert_eq!(call(&mut instance, "random", 65_536, 0), 0);
            assert_eq!(call(&mut instance, "random", 0, 1), 42);
        }
        assert_eq!(count.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn request_and_lifetime_byte_quotas_cannot_be_reset_by_new_invocations() {
    let vm = vm(true, false, 10000);
    let (imports, count) = scripted(WasiRandomLimits { max_request_bytes: 64, max_total_bytes: 100, ..Default::default() });
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(call(&mut instance, "random", 0, 65), 42);
    assert_eq!(call(&mut instance, "random", 0, 64), 0);
    assert_eq!(call(&mut instance, "random", 0, 37), 42);
    assert_eq!(call(&mut instance, "random", 0, 36), 0);
    assert_eq!(call(&mut instance, "random", 0, 1), 42);
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[test]
fn source_failure_discards_partial_scratch_and_consumes_attempt_quota() {
    let vm = vm(true, false, 10000);
    for (source_error, expected) in [(WasiSourceError::Io, 29), (WasiSourceError::WouldBlock, 6), (WasiSourceError::Unsupported, 58)] {
        let imports = WasmHostImports::new(caps()).with_wasi_random_source(move |bytes: &mut [u8]| {
            bytes[0] = 123; Err(source_error)
        }, WasiRandomLimits { max_calls: 1, ..Default::default() }).unwrap();
        let mut instance = vm.instantiate_with_imports(imports).unwrap(); let before = memory(&instance).to_vec();
        assert_eq!(call(&mut instance, "random", 0, 65), expected);
        assert_eq!(memory(&instance), before);
        assert_eq!(call(&mut instance, "random", 0, 1), 42);
    }
}

#[test]
fn exact_host_work_and_preflight_budget_refusal_precede_source_entry() {
    for budget in [7, 8] {
        let vm = vm(true, false, budget);
        let (imports, count) = scripted(Default::default()); let mut instance = vm.instantiate_with_imports(imports).unwrap();
        let result = instance.call_export("random", &[I32(0), I32(65)]);
        if budget == 7 {
            assert!(matches!(result, Err(WasmNumericVmError::InstructionBudgetExceeded { .. })));
            assert_eq!(count.load(Ordering::SeqCst), 0); assert!(memory(&instance)[..512].iter().all(|byte| *byte == 0xaa));
        } else {
            let result = result.unwrap(); assert_eq!(result.results, [I32(0)]); assert_eq!(result.instructions_executed, 8);
            assert_eq!(count.load(Ordering::SeqCst), 1);
        }
    }
}

#[test]
fn rejected_shared_work_does_not_consume_source_quota_or_hide_vm_failure() {
    let vm = vm(true, false, 10000); let pool = WasmWorkPool::new(7);
    let (mut imports, count) = scripted(WasiRandomLimits { max_calls: 1, ..Default::default() });
    imports.bind_work_pool(pool.clone()).unwrap(); let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert!(matches!(instance.call_export("random", &[I32(0), I32(65)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::WorkPool(_))))));
    assert_eq!(pool.remaining(), 5); assert_eq!(count.load(Ordering::SeqCst), 0);
    assert_eq!(call(&mut instance, "random", 0, 1), 0);
    assert_eq!(pool.remaining(), 0); assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn return_boundary_controls_cannot_be_converted_to_errno_or_publish_entropy() {
    for control in 0..3 {
        let vm = vm(true, false, 10000); let token = CancellationToken::new(); let signal = token.clone();
        let mut imports = WasmHostImports::new(caps()).with_wasi_random_source(move |output: &mut [u8]| {
            output.fill(99); signal.cancel(); Ok(())
        }, Default::default()).unwrap();
        match control {
            0 => imports.bind_cancellation(token, "random").unwrap(),
            1 => imports.bind_execution_cancellation(token, "random").unwrap(),
            _ => imports.bind_capability_revocation(RuntimeCapability::RandomRead, token, "random").unwrap(),
        }
        let mut instance = vm.instantiate_with_imports(imports).unwrap(); let before = memory(&instance).to_vec();
        assert!(instance.call_export("random", &[I32(0), I32(65)]).is_err());
        assert_eq!(memory(&instance), before);
    }
}

#[test]
fn concurrent_shared_fuel_depletion_after_source_never_partially_publishes() {
    let vm = vm(true, false, 10000); let pool = WasmWorkPool::new(100); let source_pool = pool.clone();
    let count = Arc::new(AtomicUsize::new(0)); let seen = Arc::clone(&count);
    let mut imports = WasmHostImports::new(caps()).with_wasi_random_source(move |output: &mut [u8]| {
        seen.fetch_add(1, Ordering::SeqCst); output.fill(17);
        let _delegated = source_pool.partition(source_pool.remaining()).unwrap(); Ok(())
    }, Default::default()).unwrap();
    imports.bind_work_pool(pool.clone()).unwrap(); let mut instance = vm.instantiate_with_imports(imports).unwrap();
    let before = memory(&instance).to_vec();
    assert!(matches!(instance.call_export("random", &[I32(0), I32(65)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::WorkPool(_))))));
    assert_eq!(count.load(Ordering::SeqCst), 1); assert_eq!(memory(&instance), before); assert_eq!(pool.remaining(), 0);
}

#[test]
fn startup_shares_the_source_and_its_lifetime_quota_without_reexecution() {
    let vm = vm(true, true, 10000);
    let (imports, count) = scripted(WasiRandomLimits { max_calls: 1, ..Default::default() });
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert!(instance.start_execution().is_some()); assert_eq!(count.load(Ordering::SeqCst), 1);
    assert_eq!(&memory(&instance)[64..129], (0..65).collect::<Vec<u8>>());
    assert_eq!(call(&mut instance, "random", 0, 1), 42); assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn replay_restores_startup_and_later_entropy_without_entering_a_source() {
    let vm = vm(true, true, 100000); let limits = WasmHostTraceLimits::default();
    let (mut imports, original_calls) = scripted(Default::default()); let recording = imports.record_calls(limits).unwrap();
    let mut original = vm.instantiate_with_imports(imports).unwrap(); assert_eq!(call(&mut original, "direct", 192, 65), 0);
    let (mut imports, replay_calls) = scripted(WasiRandomLimits { max_calls: 0, ..Default::default() });
    let replay = imports.replay_calls(recording.snapshot().unwrap(), limits).unwrap();
    let mut replayed = vm.instantiate_with_imports(imports).unwrap(); assert_eq!(call(&mut replayed, "direct", 192, 65), 0);
    replay.verify_complete().unwrap(); assert_eq!(memory(&replayed), memory(&original));
    assert_eq!(original_calls.load(Ordering::SeqCst), 2); assert_eq!(replay_calls.load(Ordering::SeqCst), 0);
}

#[test]
fn sliced_guest_calls_never_repeat_a_completed_source_request() {
    let vm = vm(true, false, 10000); let (imports, count) = scripted(Default::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    let mut pending = instance.begin_call("indirect", &[I32(0), I32(65)]).unwrap();
    loop {
        match pending.resume(NonZeroU64::MIN).unwrap() {
            WasmCallStep::Pending(call) => { assert!(count.load(Ordering::SeqCst) <= 1); pending = call; }
            WasmCallStep::Complete(result) => { assert_eq!(result.results, [I32(0)]); break; }
        }
    }
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[test]
fn source_panic_does_not_publish_or_allow_interrupted_instance_reentry() {
    let vm = vm(true, false, 10000);
    let imports = WasmHostImports::new(caps()).with_wasi_random_source(|bytes: &mut [u8]| -> Result<(), WasiSourceError> {
        bytes.fill(42); panic!("test source panic")
    }, Default::default()).unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| instance.call_export("random", &[I32(0), I32(65)]))).is_err());
    assert!(memory(&instance)[..512].iter().all(|byte| *byte == 0xaa));
    assert!(matches!(instance.call_export("random", &[I32(0), I32(1)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::HostCallInterrupted)))));
}

#[test]
fn duplicate_installation_is_a_binding_error_not_source_replacement() {
    let (imports, count) = scripted(Default::default());
    let result = imports.with_wasi_random_source(|_: &mut [u8]| Ok(()), Default::default());
    assert!(matches!(result, Err(WasiPreview1Error::Binding(WasmHostError::DuplicateBinding { .. }))));
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn resolved_manifest_and_current_policy_cannot_manufacture_entropy_authority() {
    use frankenengine_engine::module_resolver::{CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle,
        ModuleDefinition, ModuleRequest, ResolutionContext, wasm_module_required_capabilities};
    use frankenengine_engine::wasm_runtime_lane::WasmNativeLoadError;
    let limits = WasmNumericLimits::default(); let context = ResolutionContext::new("random", "decision", "policy");
    let mut manifest = wasm_module_required_capabilities(); let mut grants = manifest.clone(); grants.insert(RuntimeCapability::RandomRead);
    let policy = CapabilityPolicyHook::new(grants.clone()); let mut resolver = DeterministicModuleResolver::new("/app");
    for declared in [false, true] {
        if declared { manifest.insert(RuntimeCapability::RandomRead); }
        let mut definition = ModuleDefinition::wasm_binary(&fixture(true, false), &limits).unwrap();
        definition.required_capabilities = manifest.clone(); resolver.register_workspace_module("/app/random.wasm", definition).unwrap();
        let module = resolver.load_wasm(&ModuleRequest::new("/app/random.wasm", ImportStyle::Import), &context, &policy, limits.clone()).unwrap();
        let (imports, count) = scripted(Default::default()); let result = module.instantiate_with_imports(&context, &policy, imports);
        if !declared { assert!(result.is_err()); assert_eq!(count.load(Ordering::SeqCst), 0); continue; }
        let mut instance = result.unwrap(); let mut denied = policy.clone(); denied.granted_capabilities.remove(&RuntimeCapability::RandomRead);
        assert!(matches!(instance.call_export("random", &[I32(0), I32(1)], &context, &denied), Err(WasmNativeLoadError::Resolution(_))));
        assert_eq!(count.load(Ordering::SeqCst), 0);
        assert_eq!(instance.call_export("random", &[I32(0), I32(1)], &context, &policy).unwrap().results, [I32(0)]);
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}

#[test]
fn compiled_c_command_reads_entropy_and_emits_it_through_real_wasi_stdio() {
    let vm = WasmNumericVm::parse(include_bytes!("fixtures/wasi_random_smoke.wasm"), WasmNumericLimits::default()).unwrap();
    let mut grants = caps(); grants.extend([RuntimeCapability::Console, RuntimeCapability::Builtin]);
    let (imports, output) = WasiPreview1Config::default().into_imports_with_stdio(grants, Vec::new(), WasiStdioLimits::default()).unwrap();
    let imports = imports.with_wasi_random_source(|bytes: &mut [u8]| {
        for (i, byte) in bytes.iter_mut().enumerate() { *byte = i as u8; } Ok(())
    }, Default::default()).unwrap();
    assert_eq!(run_command(&vm, imports).unwrap(), 0);
    let captured = output.take_output().unwrap(); assert_eq!(captured.stdout, (0..65).collect::<Vec<u8>>()); assert!(captured.stderr.is_empty());
}
