#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::wasm_runtime_lane::WasmBoundaryValue::{I32, I64};
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmCallStep, WasmHostError, WasmHostImports, WasmNumericInstance, WasmNumericLimits,
    WasmNumericVm, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::wasi_preview1::{
    WasiPreview1Config, WasiPreview1Error, WasiStdioLimits, run_command,
};
use frankenengine_engine::wasm_runtime_lane::wasi_preview1::sources::{
    WasiClockId, WasiClockLimits, WasiClockRequest, WasiRandomLimits, WasiSourceError,
};
use frankenengine_engine::wasm_runtime_lane::work_pool::WasmWorkPool;

fn leb(mut n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop { let byte = (n & 127) as u8; n >>= 7; out.push(byte | if n == 0 { 0 } else { 128 }); if n == 0 { return out; } }
}
fn section(out: &mut Vec<u8>, id: u8, payload: &[u8]) { out.push(id); out.extend(leb(payload.len())); out.extend(payload); }
fn name(out: &mut Vec<u8>, text: &str) { out.extend(leb(text.len())); out.extend(text.as_bytes()); }
fn fixture(memory: bool, start: bool) -> Vec<u8> {
    let mut out = b"\0asm\x01\0\0\0".to_vec();
    section(&mut out, 1, &[3, 0x60, 3, 0x7f, 0x7e, 0x7f, 1, 0x7f, 0x60, 2, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 0]);
    let mut imports = vec![2];
    for (index, function) in ["clock_time_get", "clock_res_get"].iter().enumerate() {
        name(&mut imports, "wasi_snapshot_preview1"); name(&mut imports, function); imports.extend([0, index as u8]);
    }
    section(&mut out, 2, &imports); section(&mut out, 3, if start { &[3, 0, 0, 2] } else { &[2, 0, 0] });
    section(&mut out, 4, &[1, 0x70, 0, 1]); if memory { section(&mut out, 5, &[1, 1, 1, 1]); }
    let mut exports = vec![4 + u8::from(memory)];
    for (index, function) in ["time", "resolution", "direct", "indirect"].iter().enumerate() {
        name(&mut exports, function); exports.extend([0, index as u8]);
    }
    if memory { name(&mut exports, "memory"); exports.extend([2, 0]); }
    section(&mut out, 7, &exports); if start { section(&mut out, 8, &[4]); }
    section(&mut out, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
    let direct = [0, 0x20, 0, 0x20, 1, 0x20, 2, 0x10, 0, 0x0b];
    let indirect = [0, 0x20, 0, 0x20, 1, 0x20, 2, 0x41, 0, 0x11, 0, 0, 0x0b];
    let startup = [0, 0x41, 1, 0x42, 0, 0x41, 0, 0x10, 0, 0x1a, 0x0b];
    let mut code = vec![if start { 3 } else { 2 }];
    for body in [direct.as_slice(), indirect.as_slice()].into_iter().chain(start.then_some(startup.as_slice())) {
        code.extend(leb(body.len())); code.extend(body);
    }
    section(&mut out, 10, &code);
    if memory { let mut data = vec![1, 0, 0x41, 0, 0x0b, 32]; data.extend([0xaa; 32]); section(&mut out, 11, &data); }
    out
}
fn caps() -> BTreeSet<RuntimeCapability> { BTreeSet::from([RuntimeCapability::VmDispatch, RuntimeCapability::Timer]) }
fn vm(memory: bool, start: bool, work: u64) -> WasmNumericVm {
    WasmNumericVm::parse(&fixture(memory, start), WasmNumericLimits { max_instructions: work, ..Default::default() }).unwrap()
}
fn imports<F>(source: F, limits: WasiClockLimits) -> WasmHostImports
where F: FnMut(WasiClockRequest) -> Result<u64, WasiSourceError> + Send + Sync + 'static {
    WasmHostImports::new(caps()).with_wasi_clock_source(source, limits).unwrap()
}
fn scripted(limits: WasiClockLimits) -> (WasmHostImports, Arc<AtomicUsize>) {
    let count = Arc::new(AtomicUsize::new(0)); let seen = Arc::clone(&count);
    (imports(move |_| Ok(seen.fetch_add(1, Ordering::SeqCst) as u64 + 100), limits), count)
}
fn time(instance: &mut WasmNumericInstance<'_>, name: &str, id: i32, precision: u64, out: i32) -> i32 {
    let result = instance.call_export(name, &[I32(id), I64(precision as i64), I32(out)]).unwrap();
    let [I32(errno)] = result.results.as_slice() else { panic!("clock errno ABI"); }; *errno
}
fn resolution(instance: &mut WasmNumericInstance<'_>, id: i32, out: i32) -> i32 {
    let result = instance.call_export("resolution", &[I32(id), I32(out)]).unwrap();
    let [I32(errno)] = result.results.as_slice() else { panic!("resolution errno ABI"); }; *errno
}
fn memory<'a>(instance: &'a WasmNumericInstance<'_>) -> &'a [u8] { instance.memory_export("memory").unwrap() }
fn word(instance: &WasmNumericInstance<'_>, offset: usize) -> u64 {
    u64::from_le_bytes(memory(instance)[offset..offset + 8].try_into().unwrap())
}

#[test]
fn all_clock_ids_preserve_unsigned_precision_and_timestamp_bits() {
    let vm = vm(true, false, 10000); let observed = Arc::new(Mutex::new(Vec::new())); let seen = Arc::clone(&observed);
    let provider = imports(move |request| {
        seen.lock().unwrap().push(request);
        Ok(match request { WasiClockRequest::Resolution(clock) => 1 + clock as u64,
            WasiClockRequest::Time { clock, .. } => u64::MAX - clock as u64 })
    }, Default::default());
    let mut instance = vm.instantiate_with_imports(provider).unwrap();
    for clock in [WasiClockId::Realtime, WasiClockId::Monotonic, WasiClockId::ProcessCpu, WasiClockId::ThreadCpu] {
        assert_eq!(resolution(&mut instance, clock as i32, 3), 0); assert_eq!(word(&instance, 3), 1 + clock as u64);
        assert_eq!(time(&mut instance, "time", clock as i32, u64::MAX, 3), 0); assert_eq!(word(&instance, 3), u64::MAX - clock as u64);
        assert_eq!(memory(&instance)[2], 0xaa); assert_eq!(memory(&instance)[11], 0xaa);
    }
    let events = observed.lock().unwrap();
    assert_eq!(events.len(), 8);
    for event in events.iter().skip(1).step_by(2) { assert!(matches!(event, WasiClockRequest::Time { precision_ns: u64::MAX, .. })); }
}

#[test]
fn direct_indirect_and_exported_time_calls_use_one_owned_source() {
    let vm = vm(true, false, 10000); let (provider, count) = scripted(Default::default());
    let mut instance = vm.instantiate_with_imports(provider).unwrap();
    for (index, export) in ["time", "direct", "indirect"].iter().enumerate() {
        assert_eq!(time(&mut instance, export, 1, 0, 0), 0); assert_eq!(word(&instance, 0), 100 + index as u64);
    }
    assert_eq!(count.load(Ordering::SeqCst), 3);
}

#[test]
fn invalid_ids_and_bad_unsigned_extents_never_query_the_source() {
    let vm = vm(true, false, 10000); let (provider, count) = scripted(Default::default());
    let mut instance = vm.instantiate_with_imports(provider).unwrap(); let before = memory(&instance).to_vec();
    for id in [4, -1, i32::MAX] {
        assert_eq!(resolution(&mut instance, id, 0), 28); assert_eq!(time(&mut instance, "time", id, 0, 0), 28);
    }
    for out in [-1, 65_529, 65_536] {
        assert_eq!(resolution(&mut instance, 1, out), 21); assert_eq!(time(&mut instance, "time", 1, 0, out), 21);
    }
    assert_eq!(memory(&instance), before); assert_eq!(count.load(Ordering::SeqCst), 0);
    assert_eq!(time(&mut instance, "time", 1, 0, 65_528), 0); assert_eq!(word(&instance, 65_528), 100);
}

#[test]
fn missing_memory_does_not_create_a_host_timestamp_buffer() {
    let vm = vm(false, false, 10000); let (provider, count) = scripted(Default::default());
    let mut instance = vm.instantiate_with_imports(provider).unwrap();
    assert_eq!(resolution(&mut instance, 1, 0), 21); assert_eq!(time(&mut instance, "time", 1, 0, 0), 21);
    assert_eq!(count.load(Ordering::SeqCst), 0);
}

#[test]
fn invalid_zero_resolution_and_source_errors_leave_output_unchanged() {
    let vm = vm(true, false, 10000);
    for result in [Ok(0), Err(WasiSourceError::Io), Err(WasiSourceError::WouldBlock), Err(WasiSourceError::Unsupported)] {
        let provider = imports(move |_| result, WasiClockLimits { max_calls: 1, ..Default::default() });
        let mut instance = vm.instantiate_with_imports(provider).unwrap(); let before = memory(&instance).to_vec();
        let expected = match result { Ok(_) | Err(WasiSourceError::Io) => 29, Err(WasiSourceError::WouldBlock) => 6, Err(WasiSourceError::Unsupported) => 58 };
        assert_eq!(resolution(&mut instance, 1, 0), expected); assert_eq!(memory(&instance), before);
        assert_eq!(time(&mut instance, "time", 1, 0, 0), 42);
    }
}

#[test]
fn monotonic_and_cpu_clocks_reject_regression_but_allow_equal_readings() {
    let vm = vm(true, false, 10000);
    for id in [1, 2, 3] {
        let mut readings = [10, 9, 10, 11].into_iter();
        let mut instance = vm.instantiate_with_imports(imports(move |_| Ok(readings.next().unwrap()), Default::default())).unwrap();
        for (expected, value) in [(0, 10), (29, 10), (0, 10), (0, 11)] {
            assert_eq!(time(&mut instance, "time", id, 0, 0), expected); assert_eq!(word(&instance, 0), value);
        }
    }
}

#[test]
fn realtime_can_jump_backwards_and_monotonic_zero_is_valid() {
    let vm = vm(true, false, 10000); let mut readings = [10, 0, 0].into_iter();
    let mut instance = vm.instantiate_with_imports(imports(move |_| Ok(readings.next().unwrap()), Default::default())).unwrap();
    assert_eq!(time(&mut instance, "time", 0, 0, 0), 0); assert_eq!(word(&instance, 0), 10);
    assert_eq!(time(&mut instance, "time", 0, 0, 0), 0); assert_eq!(word(&instance, 0), 0);
    assert_eq!(time(&mut instance, "time", 1, 0, 0), 0); assert_eq!(word(&instance, 0), 0);
}

#[test]
fn clock_domains_and_independent_registries_do_not_share_high_water_marks() {
    let vm = vm(true, false, 10000); let mut readings = [100, 1, 2, 100].into_iter();
    let mut a = vm.instantiate_with_imports(imports(move |_| Ok(readings.next().unwrap()), Default::default())).unwrap();
    for id in [1, 2, 3, 1] { assert_eq!(time(&mut a, "time", id, 0, 0), 0); }
    let mut b = vm.instantiate_with_imports(imports(|_| Ok(0), Default::default())).unwrap();
    assert_eq!(time(&mut b, "time", 1, 0, 0), 0); assert_eq!(word(&b, 0), 0);
}

#[test]
fn resolution_time_and_startup_share_one_nonrefundable_query_allowance() {
    let vm = vm(true, true, 10000); let (provider, count) = scripted(WasiClockLimits { max_calls: 2, ..Default::default() });
    let mut instance = vm.instantiate_with_imports(provider).unwrap();
    assert!(instance.start_execution().is_some()); assert_eq!(word(&instance, 0), 100);
    assert_eq!(resolution(&mut instance, 1, 8), 0); assert_eq!(word(&instance, 8), 101);
    assert_eq!(time(&mut instance, "time", 1, 0, 0), 42); assert_eq!(word(&instance, 0), 100);
    assert_eq!(count.load(Ordering::SeqCst), 2);
}

#[test]
fn local_and_shared_work_refusal_precede_clock_query_and_preserve_exact_cost() {
    for use_pool in [false, true] { for work in [2, 3] {
        let vm = vm(true, false, if use_pool { 10000 } else { work });
        let (mut provider, count) = scripted(Default::default()); let pool = WasmWorkPool::new(work);
        if use_pool { provider.bind_work_pool(pool.clone()).unwrap(); }
        let mut instance = vm.instantiate_with_imports(provider).unwrap();
        let result = instance.call_export("time", &[I32(1), I64(0), I32(0)]);
        if work == 2 {
            assert!(result.is_err()); assert_eq!(count.load(Ordering::SeqCst), 0); assert_eq!(word(&instance, 0), 0xaaaa_aaaa_aaaa_aaaa);
        } else {
            let result = result.unwrap(); assert_eq!(result.results, [I32(0)]); assert_eq!(result.instructions_executed, 3);
            assert_eq!(count.load(Ordering::SeqCst), 1); if use_pool { assert_eq!(pool.remaining(), 0); }
        }
    } }
}

#[test]
fn no_ambient_clock_and_builtin_cannot_substitute_for_timer_authority() {
    let vm = vm(true, true, 10000);
    let unbound = WasiPreview1Config::default().into_imports(caps()).unwrap();
    assert!(vm.instantiate_with_imports(unbound).is_err());
    let calls = Arc::new(AtomicUsize::new(0)); let seen = Arc::clone(&calls);
    let provider = WasmHostImports::new(BTreeSet::from([RuntimeCapability::VmDispatch, RuntimeCapability::Builtin]))
        .with_wasi_clock_source(move |_| { seen.fetch_add(1, Ordering::SeqCst); Ok(1) }, Default::default()).unwrap();
    assert!(matches!(vm.instantiate_with_imports(provider),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { capability: RuntimeCapability::Timer, .. })))));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[test]
fn cancellation_or_timer_revocation_on_return_prevents_timestamp_publication() {
    for service in [false, true] {
        let vm = vm(true, false, 10000); let token = CancellationToken::new(); let signal = token.clone();
        let mut provider = imports(move |_| { signal.cancel(); Ok(999) }, Default::default());
        if service { provider.bind_capability_revocation(RuntimeCapability::Timer, token, "clock").unwrap(); }
        else { provider.bind_execution_cancellation(token, "clock").unwrap(); }
        let mut instance = vm.instantiate_with_imports(provider).unwrap(); let before = memory(&instance).to_vec();
        assert!(instance.call_export("time", &[I32(1), I64(0), I32(0)]).is_err()); assert_eq!(memory(&instance), before);
    }
}

#[test]
fn source_panic_cannot_resample_a_poisoned_clock_after_caught_unwind() {
    let vm = vm(true, false, 10000);
    let provider = imports(|_| -> Result<u64, WasiSourceError> { panic!("clock panic") }, Default::default());
    let mut instance = vm.instantiate_with_imports(provider).unwrap();
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| instance.call_export("time", &[I32(1), I64(0), I32(0)]))).is_err());
    assert_eq!(word(&instance, 0), 0xaaaa_aaaa_aaaa_aaaa);
    assert!(matches!(instance.call_export("resolution", &[I32(1), I32(0)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::HostCallInterrupted)))));
}

#[test]
fn clock_replay_reproduces_startup_and_results_without_sampling_new_time() {
    let vm = vm(true, true, 100000); let trace_limits = WasmHostTraceLimits::default();
    let (mut provider, count) = scripted(Default::default()); let recording = provider.record_calls(trace_limits).unwrap();
    let mut original = vm.instantiate_with_imports(provider).unwrap();
    assert_eq!(resolution(&mut original, 1, 8), 0); assert_eq!(time(&mut original, "indirect", 1, u64::MAX, 16), 0);
    let (mut provider, replay_count) = scripted(WasiClockLimits { max_calls: 0, ..Default::default() });
    let replay = provider.replay_calls(recording.snapshot().unwrap(), trace_limits).unwrap();
    let mut replayed = vm.instantiate_with_imports(provider).unwrap();
    assert_eq!(resolution(&mut replayed, 1, 8), 0); assert_eq!(time(&mut replayed, "indirect", 1, u64::MAX, 16), 0);
    replay.verify_complete().unwrap(); assert_eq!(memory(&replayed), memory(&original));
    assert_eq!(count.load(Ordering::SeqCst), 3); assert_eq!(replay_count.load(Ordering::SeqCst), 0);
}

#[test]
fn sliced_calls_and_duplicate_installation_do_not_create_extra_source_reads() {
    let vm = vm(true, false, 10000); let (provider, count) = scripted(Default::default());
    let mut instance = vm.instantiate_with_imports(provider).unwrap();
    let mut call = instance.begin_call("direct", &[I32(1), I64(-1), I32(0)]).unwrap();
    loop { match call.resume(NonZeroU64::MIN).unwrap() {
        WasmCallStep::Pending(next) => { call = next; assert!(count.load(Ordering::SeqCst) <= 1); }
        WasmCallStep::Complete(result) => { assert_eq!(result.results, [I32(0)]); break; }
    } }
    assert_eq!(count.load(Ordering::SeqCst), 1);
    let (provider, _) = scripted(Default::default());
    assert!(matches!(provider.with_wasi_clock_source(|_| Ok(1), Default::default()),
        Err(WasiPreview1Error::Binding(WasmHostError::DuplicateBinding { .. }))));
}

fn command_grants() -> BTreeSet<RuntimeCapability> {
    let mut grants = caps(); grants.extend([RuntimeCapability::RandomRead, RuntimeCapability::Console, RuntimeCapability::Builtin]); grants
}
fn command_sources(replay: bool) -> (WasmHostImports, frankenengine_engine::wasm_runtime_lane::wasi_preview1::WasiStdio) {
    let (provider, output) = WasiPreview1Config::default().into_imports_with_stdio(command_grants(), Vec::new(), WasiStdioLimits::default()).unwrap();
    let provider = provider.with_wasi_random_source(|bytes: &mut [u8]| {
        for (i, byte) in bytes.iter_mut().enumerate() { *byte = 240 + i as u8; } Ok(())
    }, WasiRandomLimits { max_calls: if replay { 0 } else { 1 }, ..Default::default() }).unwrap();
    let mut time = 1_u64 << 63;
    let provider = provider.with_wasi_clock_source(move |request| match request {
        WasiClockRequest::Resolution(WasiClockId::Monotonic) => Ok(1),
        WasiClockRequest::Time { clock: WasiClockId::Monotonic, precision_ns } => {
            assert_eq!(precision_ns, if time == 1_u64 << 63 { u64::MAX } else { 0 });
            let result = time; time += 5; Ok(result)
        }
        _ => Err(WasiSourceError::Unsupported),
    }, WasiClockLimits { max_calls: if replay { 0 } else { 3 }, ..Default::default() }).unwrap();
    (provider, output)
}
fn expected_command_output() -> Vec<u8> {
    let mut result = Vec::new(); for n in [1_u64, 1_u64 << 63, (1_u64 << 63) + 5] { result.extend(n.to_le_bytes()); }
    result.extend(240_u8..=255); result
}

#[test]
fn compiled_c_command_combines_clock_entropy_and_stdio_with_exact_u64_bits() {
    let vm = WasmNumericVm::parse(include_bytes!("fixtures/wasi_clock_smoke.wasm"), WasmNumericLimits::default()).unwrap();
    let (provider, output) = command_sources(false); assert_eq!(run_command(&vm, provider).unwrap(), 0);
    let captured = output.take_output().unwrap(); assert_eq!(captured.stdout, expected_command_output()); assert!(captured.stderr.is_empty());
}

#[test]
fn compiled_command_replay_neither_reads_sources_nor_reemits_stdout() {
    let vm = WasmNumericVm::parse(include_bytes!("fixtures/wasi_clock_smoke.wasm"), WasmNumericLimits::default()).unwrap();
    let limits = WasmHostTraceLimits::default(); let (mut provider, output) = command_sources(false);
    let recording = provider.record_calls(limits).unwrap(); assert_eq!(run_command(&vm, provider).unwrap(), 0);
    assert_eq!(output.take_output().unwrap().stdout, expected_command_output());
    let (mut provider, output) = command_sources(true); let replay = provider.replay_calls(recording.snapshot().unwrap(), limits).unwrap();
    assert_eq!(run_command(&vm, provider).unwrap(), 0); replay.verify_complete().unwrap();
    assert!(output.take_output().unwrap().stdout.is_empty());
}

#[test]
fn resolved_scheduled_command_rechecks_policy_and_executes_both_source_families() {
    use frankenengine_engine::module_resolver::{CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle,
        ModuleDefinition, ModuleRequest, ResolutionContext, wasm_module_required_capabilities};
    use frankenengine_engine::wasm_runtime_lane::{WasmNativeLoadError, command::WasmCommandStep};
    let limits = WasmNumericLimits::default(); let context = ResolutionContext::new("clock", "decision", "policy");
    let mut grants = wasm_module_required_capabilities(); grants.extend(command_grants()); let policy = CapabilityPolicyHook::new(grants.clone());
    let mut definition = ModuleDefinition::wasm_binary(include_bytes!("fixtures/wasi_clock_smoke.wasm"), &limits).unwrap(); definition.required_capabilities = grants;
    let mut resolver = DeterministicModuleResolver::new("/app"); resolver.register_workspace_module("/app/clock.wasm", definition).unwrap();
    let module = resolver.load_wasm(&ModuleRequest::new("/app/clock.wasm", ImportStyle::Import), &context, &policy, limits).unwrap();
    let (provider, output) = command_sources(false); let command = module.prepare_command(provider);
    let WasmCommandStep::Pending(command) = command.resume(NonZeroU64::MIN, &context, &policy).unwrap() else { panic!("phase boundary"); };
    let mut denied = policy.clone(); denied.granted_capabilities.remove(&RuntimeCapability::Timer);
    assert!(matches!(command.resume(NonZeroU64::MIN, &context, &denied), Err(WasmNativeLoadError::Resolution(_))));
    assert!(output.take_output().unwrap().stdout.is_empty());
    let (provider, output) = command_sources(false); let mut command = module.prepare_command(provider); let mut completed = false;
    for _ in 0..10000 {
        match command.resume(NonZeroU64::MIN, &context, &policy).unwrap() {
            WasmCommandStep::Pending(next) => command = next,
            WasmCommandStep::Complete(result) => { assert_eq!(result.exit_code, 0); completed = true; break; }
        }
    }
    assert!(completed); assert_eq!(output.take_output().unwrap().stdout, expected_command_output());
}
