#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use frankenengine_engine::capability::RuntimeCapability;
use frankenengine_engine::wasm_runtime_lane::WasmBoundaryValue::I32;
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostError, WasmHostImports, WasmNumericInstance, WasmNumericLimits,
    WasmNumericVm, WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::wasi_preview1::{
    WASI_PREVIEW1_MODULE, WasiPreview1Config, WasiPreview1Error, WasiStdio, WasiStdioLimits,
};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;

const PAYLOAD: [u8; 5] = [255, 0, 65, 66, 67];
fn leb(mut n: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop { let low = (n & 127) as u8; n >>= 7; bytes.push(low | if n == 0 { 0 } else { 128 }); if n == 0 { return bytes; } }
}
fn section(bytes: &mut Vec<u8>, id: u8, contents: &[u8]) {
    bytes.push(id); bytes.extend(leb(contents.len())); bytes.extend(contents);
}
fn name(bytes: &mut Vec<u8>, text: &str) { bytes.extend(leb(text.len())); bytes.extend(text.as_bytes()); }
fn fixture(start: bool) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[3, 0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f,
        0x60, 2, 0x7f, 0x7f, 0, 0x60, 0, 0]);
    let mut imports = vec![2];
    for function in ["fd_write", "fd_read"] {
        name(&mut imports, WASI_PREVIEW1_MODULE); name(&mut imports, function); imports.extend([0, 0]);
    }
    section(&mut bytes, 2, &imports);
    section(&mut bytes, 3, if start { &[4, 1, 0, 0, 2] } else { &[3, 1, 0, 0] });
    section(&mut bytes, 4, &[1, 0x70, 0, 1]);
    section(&mut bytes, 5, &[1, 1, 1, 1]);
    let mut exports = vec![6];
    for (index, function) in ["fd_write", "fd_read", "set", "write", "read"].iter().enumerate() {
        name(&mut exports, function); exports.push(0); exports.extend(leb(index));
    }
    name(&mut exports, "memory"); exports.extend([2, 0]);
    section(&mut bytes, 7, &exports);
    if start { section(&mut bytes, 8, &[5]); }
    section(&mut bytes, 9, &[1, 0, 0x41, 0, 0x0b, 1, 0]);
    let set = [0x20, 0, 0x20, 1, 0x36, 2, 0, 0x0b];
    let write = [0x20, 0, 0x20, 1, 0x20, 2, 0x20, 3, 0x41, 0, 0x11, 0, 0, 0x0b];
    let read = [0x20, 0, 0x20, 1, 0x20, 2, 0x20, 3, 0x10, 1, 0x0b];
    let startup = [0x41, 1, 0x41, 0, 0x41, 2, 0x41, 24, 0x10, 0, 0x1a, 0x0b];
    let mut bodies = vec![if start { 4 } else { 3 }];
    for code in [set.as_slice(), write.as_slice(), read.as_slice()].into_iter().chain(start.then_some(startup.as_slice())) {
        bodies.extend(leb(code.len() + 1)); bodies.push(0); bodies.extend(code);
    }
    section(&mut bytes, 10, &bodies);
    let mut data = vec![3, 0, 0x41, 0, 0x0b, 16];
    for word in [128_u32, 3, 131, 2] { data.extend(word.to_le_bytes()); }
    data.extend([0, 0x41, 24, 0x0b, 4, 0x77, 0x77, 0x77, 0x77]);
    data.extend([0, 0x41, 0x80, 1, 0x0b, 5]); data.extend(PAYLOAD);
    section(&mut bytes, 11, &data);
    bytes
}
fn vm(start: bool, limits: WasmNumericLimits) -> WasmNumericVm {
    WasmNumericVm::parse(&fixture(start), limits).unwrap()
}
fn providers(input: &[u8], limits: WasiStdioLimits) -> (WasmHostImports, WasiStdio) {
    WasiPreview1Config::default().into_imports_with_stdio(
        BTreeSet::from([RuntimeCapability::VmDispatch, RuntimeCapability::Console, RuntimeCapability::FsRead]),
        input.to_vec(), limits,
    ).unwrap()
}
fn call(instance: &mut WasmNumericInstance<'_>, export: &str, values: [i32; 4]) -> i32 {
    let result = instance.call_export(export, &values.map(I32)).unwrap();
    let [I32(errno)] = result.results.as_slice() else { panic!("errno result"); };
    *errno
}
fn set(instance: &mut WasmNumericInstance<'_>, address: i32, value: i32) {
    assert!(instance.call_export("set", &[I32(address), I32(value)]).unwrap().results.is_empty());
}
fn returned(instance: &WasmNumericInstance<'_>) -> u32 {
    u32::from_le_bytes(instance.memory_export("memory").unwrap()[24..28].try_into().unwrap())
}

#[test]
fn guest_indirect_write_captures_binary_stdout_and_stderr_without_process_io() {
    let vm = vm(false, WasmNumericLimits::default());
    let (imports, output) = providers(&[], WasiStdioLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(call(&mut instance, "write", [1, 0, 2, 24]), 0);
    assert_eq!(returned(&instance), 5);
    assert_eq!(call(&mut instance, "write", [2, 0, 2, 24]), 0);
    let captured = output.take_output().unwrap();
    assert_eq!(captured.stdout, PAYLOAD); assert_eq!(captured.stderr, PAYLOAD);
    assert!(output.take_output().unwrap().stdout.is_empty());
}

#[test]
fn stdin_scatter_reads_advance_only_the_supplied_cursor_and_report_eof() {
    let vm = vm(false, WasmNumericLimits::default());
    let (imports, output) = providers(b"abcdef", WasiStdioLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(call(&mut instance, "read", [0, 0, 2, 24]), 0);
    assert_eq!(returned(&instance), 5); assert_eq!(output.input_consumed().unwrap(), 5);
    assert_eq!(&instance.memory_export("memory").unwrap()[128..133], b"abcde");
    assert_eq!(call(&mut instance, "read", [0, 0, 2, 24]), 0);
    assert_eq!(returned(&instance), 1); assert_eq!(output.input_consumed().unwrap(), 6);
    assert_eq!(&instance.memory_export("memory").unwrap()[128..133], b"fbcde");
    assert_eq!(call(&mut instance, "read", [0, 0, 2, 24]), 0);
    assert_eq!(returned(&instance), 0); assert_eq!(output.input_consumed().unwrap(), 6);
}

#[test]
fn output_capacity_is_a_lifetime_cap_not_refunded_by_draining_capture() {
    let vm = vm(false, WasmNumericLimits::default());
    let (imports, output) = providers(&[], WasiStdioLimits { max_output_bytes: 4, ..WasiStdioLimits::default() });
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(call(&mut instance, "fd_write", [1, 0, 2, 24]), 51);
    assert_eq!(returned(&instance), 0x7777_7777); assert!(output.take_output().unwrap().stdout.is_empty());
    set(&mut instance, 4, 2);
    assert_eq!(call(&mut instance, "fd_write", [1, 0, 2, 24]), 0);
    assert_eq!(output.take_output().unwrap().stdout, [255, 0, 66, 67]);
    assert_eq!(call(&mut instance, "fd_write", [2, 0, 2, 24]), 51);
    assert!(output.take_output().unwrap().stderr.is_empty());
}

#[test]
fn a_bad_later_iovec_or_result_pointer_cannot_partially_consume_or_emit() {
    let vm = vm(false, WasmNumericLimits::default());
    for export in ["fd_read", "fd_write"] {
        let (imports, output) = providers(b"abcde", WasiStdioLimits::default());
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        let fd = if export == "fd_read" { 0 } else { 1 };
        assert_eq!(call(&mut instance, export, [fd, 0, 2, 65_535]), 21);
        set(&mut instance, 8, 65_535);
        let before = instance.memory_export("memory").unwrap().to_vec();
        assert_eq!(call(&mut instance, export, [fd, 0, 2, 24]), 21);
        assert_eq!(instance.memory_export("memory").unwrap(), before);
        assert_eq!(output.input_consumed().unwrap(), 0);
        assert!(output.take_output().unwrap().stdout.is_empty());
    }
}

#[test]
fn negative_unsigned_pointers_and_lengths_are_rejected_without_wrapping() {
    let vm = vm(false, WasmNumericLimits::default());
    let (imports, output) = providers(b"abcde", WasiStdioLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    for export in ["fd_read", "fd_write"] {
        let fd = if export == "fd_read" { 0 } else { 1 };
        assert_eq!(call(&mut instance, export, [fd, -1, 2, 24]), 21);
        assert_eq!(call(&mut instance, export, [fd, 0, -1, 24]), 28);
        set(&mut instance, 4, -1);
        assert_eq!(call(&mut instance, export, [fd, 0, 2, 24]), 21);
        set(&mut instance, 4, 3);
    }
    assert_eq!(returned(&instance), 0x7777_7777);
    assert_eq!(output.input_consumed().unwrap(), 0);
}

#[test]
fn iovec_count_and_transfer_ceiling_bound_guest_controlled_scratch() {
    let vm = vm(false, WasmNumericLimits::default());
    for (limits, expected) in [
        (WasiStdioLimits { max_iovecs: 1, ..WasiStdioLimits::default() }, 28),
        (WasiStdioLimits { max_transfer_bytes: 4, ..WasiStdioLimits::default() }, 42),
    ] {
        let (imports, output) = providers(b"abcde", limits);
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        assert_eq!(call(&mut instance, "fd_write", [1, 0, 2, 24]), expected);
        assert_eq!(call(&mut instance, "fd_read", [0, 0, 2, 24]), expected);
        assert_eq!(returned(&instance), 0x7777_7777); assert_eq!(output.input_consumed().unwrap(), 0);
        assert!(output.take_output().unwrap().stdout.is_empty());
    }
}

#[test]
fn budget_refusal_precedes_stream_effects_and_exact_charges_are_shared() {
    for (export, fd, budget) in [("fd_write", 1, 10), ("fd_read", 0, 8)] {
        let tight = vm(false, WasmNumericLimits { max_instructions: budget - 1, ..WasmNumericLimits::default() });
        let (imports, output) = providers(b"abcde", WasiStdioLimits::default());
        let mut instance = tight.instantiate_with_imports(imports).unwrap();
        assert!(matches!(instance.call_export(export, &[I32(fd), I32(0), I32(2), I32(24)]),
            Err(WasmNumericVmError::InstructionBudgetExceeded { .. })));
        assert_eq!(returned(&instance), 0x7777_7777); assert_eq!(output.input_consumed().unwrap(), 0);
        assert!(output.take_output().unwrap().stdout.is_empty());
        let exact = vm(false, WasmNumericLimits { max_instructions: budget, ..WasmNumericLimits::default() });
        let (imports, _) = providers(b"abcde", WasiStdioLimits::default());
        let mut instance = exact.instantiate_with_imports(imports).unwrap();
        assert_eq!(instance.call_export(export, &[I32(fd), I32(0), I32(2), I32(24)]).unwrap().instructions_executed, budget);
    }
}

#[test]
fn output_aliasing_a_source_buffer_cannot_change_already_gathered_bytes() {
    let vm = vm(false, WasmNumericLimits::default());
    let (imports, output) = providers(&[], WasiStdioLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(call(&mut instance, "fd_write", [1, 0, 2, 128]), 0);
    assert_eq!(output.take_output().unwrap().stdout, PAYLOAD);
    assert_eq!(&instance.memory_export("memory").unwrap()[128..132], &5_u32.to_le_bytes());
}

#[test]
fn input_overwriting_descriptor_memory_uses_a_validated_iovec_snapshot() {
    let vm = vm(false, WasmNumericLimits::default());
    let (imports, output) = providers(b"abcdefgh", WasiStdioLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    set(&mut instance, 0, 8); set(&mut instance, 4, 4); // overwrite NEXT descriptor
    set(&mut instance, 8, 128); set(&mut instance, 12, 4);
    assert_eq!(call(&mut instance, "fd_read", [0, 0, 2, 24]), 0);
    assert_eq!(&instance.memory_export("memory").unwrap()[8..12], b"abcd");
    assert_eq!(&instance.memory_export("memory").unwrap()[128..132], b"efgh");
    assert_eq!(returned(&instance), 8); assert_eq!(output.input_consumed().unwrap(), 8);
}

#[test]
fn only_the_three_explicit_standard_stream_descriptors_exist() {
    let vm = vm(false, WasmNumericLimits::default());
    let (imports, output) = providers(b"abc", WasiStdioLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    for fd in [0, 3, -1] { assert_eq!(call(&mut instance, "fd_write", [fd, 0, 2, 24]), 8); }
    for fd in [1, 2, 3, -1] { assert_eq!(call(&mut instance, "fd_read", [fd, 0, 2, 24]), 8); }
    assert_eq!(output.input_consumed().unwrap(), 0); assert_eq!(returned(&instance), 0x7777_7777);
}

#[test]
fn zero_vector_requests_are_successful_noops_with_a_zero_result() {
    let vm = vm(false, WasmNumericLimits::default());
    let (imports, output) = providers(b"abc", WasiStdioLimits { max_output_bytes: 0, ..WasiStdioLimits::default() });
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(call(&mut instance, "fd_write", [1, 65_536, 0, 24]), 0);
    assert_eq!(call(&mut instance, "fd_read", [0, 65_536, 0, 24]), 0);
    assert_eq!(returned(&instance), 0); assert_eq!(output.input_consumed().unwrap(), 0);
}

#[test]
fn startup_can_emit_after_data_initialization_without_rerunning_on_inspection() {
    let vm = vm(true, WasmNumericLimits::default());
    let (imports, output) = providers(&[], WasiStdioLimits::default());
    let instance = vm.instantiate_with_imports(imports).unwrap();
    assert!(instance.start_execution().is_some());
    assert_eq!(output.take_output().unwrap().stdout, PAYLOAD);
    assert_eq!(returned(&instance), 5);
    assert!(output.take_output().unwrap().stdout.is_empty());
}

#[test]
fn revoked_input_capability_does_not_consume_stdin_or_disable_output() {
    let vm = vm(false, WasmNumericLimits::default());
    let (imports, output) = providers(b"abcde", WasiStdioLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert!(instance.revoke_host_capability(RuntimeCapability::FsRead));
    assert!(matches!(instance.call_export("read", &[I32(0), I32(0), I32(2), I32(24)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { .. })))));
    assert_eq!(output.input_consumed().unwrap(), 0);
    assert_eq!(call(&mut instance, "write", [1, 0, 2, 24]), 0);
    assert_eq!(output.take_output().unwrap().stdout, PAYLOAD);
}

#[test]
fn separate_registries_never_share_stream_positions_or_output() {
    let vm = vm(false, WasmNumericLimits::default());
    let (a, a_out) = providers(b"12345", WasiStdioLimits::default());
    let (b, b_out) = providers(b"abcde", WasiStdioLimits::default());
    let mut a = vm.instantiate_with_imports(a).unwrap();
    let b = vm.instantiate_with_imports(b).unwrap();
    assert_eq!(call(&mut a, "read", [0, 0, 2, 24]), 0);
    assert_eq!(call(&mut a, "write", [1, 0, 2, 24]), 0);
    assert_eq!(a_out.input_consumed().unwrap(), 5); assert_eq!(b_out.input_consumed().unwrap(), 0);
    assert_eq!(a_out.take_output().unwrap().stdout, b"12345"); assert!(b_out.take_output().unwrap().stdout.is_empty());
    assert_eq!(&b.memory_export("memory").unwrap()[128..133], &PAYLOAD);
}

#[test]
fn explicit_stdin_is_bounded_before_any_registry_is_published() {
    assert!(matches!(WasiPreview1Config::default().into_imports_with_stdio(
        BTreeSet::new(), vec![1, 2, 3], WasiStdioLimits { max_stdin_bytes: 2, ..WasiStdioLimits::default() },
    ), Err(WasiPreview1Error::LimitExceeded { resource: "stdin bytes", actual: 3, max: 2 })));
}

#[test]
fn replay_restores_guest_buffers_without_reconsuming_or_reemitting_host_streams() {
    let vm = vm(false, WasmNumericLimits::default());
    let limits = WasmHostTraceLimits::default();
    let (mut imports, output) = providers(b"abcde", WasiStdioLimits::default());
    let recorder = imports.record_calls(limits).unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(call(&mut instance, "read", [0, 0, 2, 24]), 0);
    assert_eq!(call(&mut instance, "write", [1, 0, 2, 24]), 0);
    assert_eq!(output.take_output().unwrap().stdout, b"abcde");
    let memory = instance.memory_export("memory").unwrap().to_vec();
    let (mut imports, replay_output) = providers(b"different", WasiStdioLimits::default());
    let replay = imports.replay_calls(recorder.snapshot().unwrap(), limits).unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(call(&mut instance, "read", [0, 0, 2, 24]), 0);
    assert_eq!(call(&mut instance, "write", [1, 0, 2, 24]), 0);
    replay.verify_complete().unwrap();
    assert_eq!(instance.memory_export("memory").unwrap(), memory);
    assert_eq!(replay_output.input_consumed().unwrap(), 0);
    assert!(replay_output.take_output().unwrap().stdout.is_empty());
}

#[test]
fn resolver_policy_and_manifest_bound_the_standard_services_before_execution() {
    use frankenengine_engine::module_resolver::{
        CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
        ModuleRequest, ResolutionContext, wasm_module_required_capabilities,
    };
    use frankenengine_engine::wasm_runtime_lane::WasmNativeLoadError;
    let context = ResolutionContext::new("wasi-trace", "wasi-decision", "current-policy");
    let request = ModuleRequest::new("./command.wasm", ImportStyle::Import).with_referrer("/app/main.mjs");
    let mut capabilities = wasm_module_required_capabilities();
    capabilities.extend([RuntimeCapability::FsRead, RuntimeCapability::Console]);
    let policy = CapabilityPolicyHook::new(capabilities.clone());
    let mut definition = ModuleDefinition::wasm_binary(&fixture(false), &WasmNumericLimits::default()).unwrap();
    definition.required_capabilities = capabilities;
    let mut resolver = DeterministicModuleResolver::new("/app");
    resolver.register_workspace_module("/app/main.mjs", ModuleDefinition::new(
        frankenengine_engine::module_resolver::ModuleSyntax::EsModule,
        "import './command.wasm';",
    )).unwrap();
    resolver.register_workspace_module("/app/command.wasm", definition.clone()).unwrap();
    let module = resolver.load_wasm(&request, &context, &policy, WasmNumericLimits::default()).unwrap();
    let (imports, output) = providers(b"abcde", WasiStdioLimits::default());
    let mut instance = module.instantiate_with_imports(&context, &policy, imports).unwrap();
    let mut revoked = policy.clone();
    revoked.granted_capabilities.remove(&RuntimeCapability::Console);
    assert!(matches!(instance.call_export("write", &[I32(1), I32(0), I32(2), I32(24)], &context, &revoked),
        Err(WasmNativeLoadError::Resolution(_))));
    assert!(output.take_output().unwrap().stdout.is_empty());
    assert_eq!(instance.call_export("write", &[I32(1), I32(0), I32(2), I32(24)], &context, &policy).unwrap().results, [I32(0)]);
    assert_eq!(output.take_output().unwrap().stdout, PAYLOAD);
    // A process/provider grant cannot compensate for an absent manifest grant.
    definition.required_capabilities.remove(&RuntimeCapability::Console);
    resolver.register_workspace_module("/app/command.wasm", definition).unwrap();
    let module = resolver.load_wasm(&request, &context, &policy, WasmNumericLimits::default()).unwrap();
    let (imports, output) = providers(&[], WasiStdioLimits::default());
    assert!(matches!(module.instantiate_with_imports(&context, &policy, imports),
        Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(WasmStateError::Host(WasmHostError::CapabilityDenied { .. }))))));
    assert!(output.take_output().unwrap().stdout.is_empty());
}

fn echo_module() -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    section(&mut bytes, 1, &[2, 0x60, 4, 0x7f, 0x7f, 0x7f, 0x7f, 1, 0x7f, 0x60, 0, 1, 0x7f]);
    let mut imports = vec![2];
    for function in ["fd_write", "fd_read"] {
        name(&mut imports, WASI_PREVIEW1_MODULE); name(&mut imports, function); imports.extend([0, 0]);
    }
    section(&mut bytes, 2, &imports); section(&mut bytes, 3, &[1, 1]);
    section(&mut bytes, 5, &[1, 1, 1, 1]);
    let mut exports = vec![2]; name(&mut exports, "echo"); exports.extend([0, 2]);
    name(&mut exports, "memory"); exports.extend([2, 0]); section(&mut bytes, 7, &exports);
    let code = [1, 1, 0x7f, // one errno local
        0x02, 0x40, 0x03, 0x40,
        0x41, 0, 0x41, 0, 0x41, 1, 0x41, 24, 0x10, 1, 0x22, 0,
        0x04, 0x40, 0x20, 0, 0x0f, 0x0b,
        0x41, 24, 0x28, 2, 0, 0x45, 0x0d, 1, // leave on EOF
        0x41, 4, 0x41, 24, 0x28, 2, 0, 0x36, 2, 0, // write exactly nread
        0x41, 1, 0x41, 0, 0x41, 1, 0x41, 24, 0x10, 0, 0x22, 0,
        0x04, 0x40, 0x20, 0, 0x0f, 0x0b,
        0x41, 4, 0x41, 0xc0, 0, 0x36, 2, 0, // restore 64-byte read capacity
        0x0c, 0, 0x0b, 0x0b, 0x41, 0, 0x0b];
    let mut bodies = vec![1]; bodies.extend(leb(code.len())); bodies.extend(code); section(&mut bytes, 10, &bodies);
    section(&mut bytes, 11, &[1, 0, 0x41, 0, 0x0b, 8, 128, 0, 0, 0, 64, 0, 0, 0]);
    bytes
}

#[test]
fn real_guest_echo_loop_combines_scatter_io_and_eof_under_the_existing_vm() {
    let bytes: Vec<u8> = (0..1000).map(|value| (value % 256) as u8).collect();
    let vm = WasmNumericVm::parse(&echo_module(), WasmNumericLimits::default()).unwrap();
    let (imports, output) = providers(&bytes, WasiStdioLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(instance.call_export("echo", &[]).unwrap().results, [I32(0)]);
    assert_eq!(output.input_consumed().unwrap(), bytes.len());
    assert_eq!(output.take_output().unwrap().stdout, bytes);
    assert_eq!(instance.call_export("echo", &[]).unwrap().results, [I32(0)]);
    assert!(output.take_output().unwrap().stdout.is_empty());
}

#[test]
fn guest_echo_returns_capture_errors_instead_of_silently_dropping_output() {
    let vm = WasmNumericVm::parse(&echo_module(), WasmNumericLimits::default()).unwrap();
    let (imports, output) = providers(b"abcdef", WasiStdioLimits { max_output_bytes: 4, ..WasiStdioLimits::default() });
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(instance.call_export("echo", &[]).unwrap().results, [I32(51)]);
    assert_eq!(output.input_consumed().unwrap(), 6); // earlier completed read is retained
    assert!(output.take_output().unwrap().stdout.is_empty());
}
