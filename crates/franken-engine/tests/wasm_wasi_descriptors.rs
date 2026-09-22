#![forbid(unsafe_code)]

use frankenengine_engine::capability::RuntimeCapability::{Builtin, Console, FsRead, VmDispatch};
use frankenengine_engine::wasm_runtime_lane::WasmBoundaryValue::{self, I32, I64};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostError, WasmHostImports, WasmNumericInstance, WasmNumericLimits, WasmNumericVm,
    WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::wasi_preview1::{
    WASI_PREVIEW1_MODULE, WasiPreview1Config, WasiStdio, WasiStdioLimits, run_command,
};
use std::collections::BTreeSet;

const READ_RIGHTS: u64 = (1 << 1) | (1 << 3) | (1 << 21);
const WRITE_RIGHTS: u64 = (1 << 6) | (1 << 3) | (1 << 21);

fn leb(mut n: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    loop {
        let byte = (n & 127) as u8;
        n >>= 7;
        bytes.push(byte | if n == 0 { 0 } else { 128 });
        if n == 0 {
            return bytes;
        }
    }
}
fn section(bytes: &mut Vec<u8>, id: u8, data: &[u8]) {
    bytes.push(id);
    bytes.extend(leb(data.len()));
    bytes.extend_from_slice(data);
}
fn name(bytes: &mut Vec<u8>, text: &str) {
    bytes.extend(leb(text.len()));
    bytes.extend_from_slice(text.as_bytes());
}

fn fixture() -> Vec<u8> {
    let functions: &[(&str, &[u8])] = &[
        ("fd_close", &[0x7f]),
        ("fd_renumber", &[0x7f, 0x7f]),
        ("fd_fdstat_get", &[0x7f, 0x7f]),
        ("fd_filestat_get", &[0x7f, 0x7f]),
        ("fd_fdstat_set_rights", &[0x7f, 0x7e, 0x7e]),
        ("fd_fdstat_set_flags", &[0x7f, 0x7f]),
        ("fd_read", &[0x7f; 4]),
        ("fd_write", &[0x7f; 4]),
        ("fd_seek", &[0x7f, 0x7e, 0x7f, 0x7f]),
        ("fd_tell", &[0x7f, 0x7f]),
        ("fd_prestat_get", &[0x7f, 0x7f]),
        ("fd_prestat_dir_name", &[0x7f; 3]),
    ];
    let mut bytes = b"\0asm\x01\0\0\0".to_vec();
    let mut types = leb(functions.len() + 1);
    let mut imports = leb(functions.len());
    let mut exports = leb(functions.len() + 3);
    for (index, (function, params)) in functions.iter().enumerate() {
        types.push(0x60);
        types.extend(leb(params.len()));
        types.extend_from_slice(params);
        types.extend([1, 0x7f]);
        name(&mut imports, WASI_PREVIEW1_MODULE);
        name(&mut imports, function);
        imports.push(0);
        imports.extend(leb(index));
        name(&mut exports, function);
        exports.push(0);
        exports.extend(leb(index));
    }
    types.extend([0x60, 0, 0]);
    section(&mut bytes, 1, &types);
    section(&mut bytes, 2, &imports);
    section(
        &mut bytes,
        3,
        &[2, functions.len() as u8, functions.len() as u8],
    );
    section(&mut bytes, 5, &[1, 0, 1]);
    exports.extend([1, b'm', 2, 0]);
    for (index, function) in ["guest_close", "close_trap"].iter().enumerate() {
        name(&mut exports, function);
        exports.push(0);
        exports.extend(leb(functions.len() + index));
    }
    section(&mut bytes, 7, &exports);
    let mut code = vec![2];
    for body in [
        &[0, 0x41, 1, 0x10, 0, 0x1a, 0x0b][..],
        &[0, 0x41, 1, 0x10, 0, 0x1a, 0, 0x0b][..],
    ] {
        code.extend(leb(body.len()));
        code.extend_from_slice(body);
    }
    section(&mut bytes, 10, &code);
    let mut data = vec![1, 0, 0x41, 0, 0x0b, 67];
    data.extend(64_u32.to_le_bytes());
    data.extend(3_u32.to_le_bytes());
    data.resize(6 + 64, 0);
    data.extend(b"abc");
    section(&mut bytes, 11, &data);
    bytes
}
fn vm(limits: WasmNumericLimits) -> WasmNumericVm {
    WasmNumericVm::parse(&fixture(), limits).unwrap()
}
fn providers(limits: WasiStdioLimits) -> (WasmHostImports, WasiStdio) {
    WasiPreview1Config::default()
        .into_imports_with_stdio(
            BTreeSet::from([Builtin, Console, FsRead, VmDispatch]),
            b"xyz".to_vec(),
            limits,
        )
        .unwrap()
}
fn call(instance: &mut WasmNumericInstance<'_>, function: &str, args: &[WasmBoundaryValue]) -> i32 {
    let result = instance.call_export(function, args).unwrap();
    let [I32(errno)] = result.results.as_slice() else {
        panic!("WASI errno ABI");
    };
    *errno
}
fn io(instance: &mut WasmNumericInstance<'_>, function: &str, fd: u32) -> i32 {
    call(
        instance,
        function,
        &[I32(fd as i32), I32(0), I32(1), I32(32)],
    )
}
fn stat(instance: &mut WasmNumericInstance<'_>, fd: u32) -> Vec<u8> {
    assert_eq!(
        call(instance, "fd_fdstat_get", &[I32(fd as i32), I32(128)]),
        0
    );
    instance.memory_export("m").unwrap()[128..152].to_vec()
}
fn rights(instance: &mut WasmNumericInstance<'_>, fd: u32, base: u64, inheriting: u64) -> i32 {
    call(
        instance,
        "fd_fdstat_set_rights",
        &[I32(fd as i32), I64(base as i64), I64(inheriting as i64)],
    )
}

#[test]
fn descriptor_records_have_exact_padding_rights_and_no_inheriting_authority() {
    let vm = vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(providers(WasiStdioLimits::default()).0)
        .unwrap();
    for fd in 0..3 {
        let mut expected = vec![0; 24];
        expected[0] = 2;
        expected[8..16]
            .copy_from_slice(&(if fd == 0 { READ_RIGHTS } else { WRITE_RIGHTS }).to_le_bytes());
        assert_eq!(stat(&mut instance, fd), expected);
    }
}

#[test]
fn virtual_filestat_is_stable_and_does_not_disclose_input_size() {
    let vm = vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(providers(WasiStdioLimits::default()).0)
        .unwrap();
    for fd in 0..3 {
        assert_eq!(
            call(&mut instance, "fd_filestat_get", &[I32(fd), I32(128)]),
            0
        );
        let mut expected = [0; 64];
        expected[8..16].copy_from_slice(&(fd as u64 + 1).to_le_bytes());
        expected[16] = 2;
        expected[24] = 1;
        assert_eq!(&instance.memory_export("m").unwrap()[128..192], &expected);
    }
}

#[test]
fn metadata_faults_never_partially_write_or_close_a_descriptor() {
    let vm = vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(providers(WasiStdioLimits::default()).0)
        .unwrap();
    for function in ["fd_fdstat_get", "fd_filestat_get"] {
        for address in [65_535, -1] {
            let before = instance.memory_export("m").unwrap().to_vec();
            assert_eq!(call(&mut instance, function, &[I32(1), I32(address)]), 21);
            assert_eq!(instance.memory_export("m").unwrap(), before);
        }
        assert_eq!(call(&mut instance, function, &[I32(3), I32(-1)]), 8);
    }
    assert_eq!(io(&mut instance, "fd_write", 1), 0);
}

#[test]
fn close_is_terminal_for_the_handle_but_retains_output_and_other_streams() {
    let vm = vm(WasmNumericLimits::default());
    let (imports, output) = providers(WasiStdioLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(io(&mut instance, "fd_write", 1), 0);
    assert_eq!(call(&mut instance, "fd_close", &[I32(1)]), 0);
    assert_eq!(call(&mut instance, "fd_close", &[I32(1)]), 8);
    assert_eq!(io(&mut instance, "fd_write", 1), 8);
    assert_eq!(call(&mut instance, "fd_fdstat_get", &[I32(1), I32(128)]), 8);
    assert_eq!(io(&mut instance, "fd_write", 2), 0);
    let captured = output.take_output().unwrap();
    assert_eq!(captured.stdout, b"abc");
    assert_eq!(captured.stderr, b"abc");
    assert_eq!(io(&mut instance, "fd_read", 0), 0);
}

#[test]
fn renumber_supports_full_unsigned_handles_without_reinterpreting_stream_identity() {
    let vm = vm(WasmNumericLimits::default());
    for target in [3_u32, 41, 0x8000_0000, u32::MAX] {
        let (imports, output) = providers(WasiStdioLimits::default());
        let mut instance = vm.instantiate_with_imports(imports).unwrap();
        assert_eq!(
            call(&mut instance, "fd_renumber", &[I32(0), I32(target as i32)]),
            0
        );
        assert_eq!(io(&mut instance, "fd_read", 0), 8);
        assert_eq!(io(&mut instance, "fd_read", target), 0);
        assert_eq!(&instance.memory_export("m").unwrap()[64..67], b"xyz");
        assert_eq!(output.input_consumed().unwrap(), 3);
        assert_eq!(io(&mut instance, "fd_write", target), 8);
    }
}

#[test]
fn replacing_and_self_renumbering_preserve_rights_flags_and_destination() {
    let vm = vm(WasmNumericLimits::default());
    let (imports, output) = providers(WasiStdioLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(rights(&mut instance, 1, 1 << 6, 0), 0);
    let before = stat(&mut instance, 1);
    assert_eq!(call(&mut instance, "fd_renumber", &[I32(1), I32(1)]), 0);
    assert_eq!(stat(&mut instance, 1), before);
    assert_eq!(call(&mut instance, "fd_renumber", &[I32(1), I32(2)]), 0);
    assert_eq!(stat(&mut instance, 2), before);
    assert_eq!(io(&mut instance, "fd_write", 1), 8);
    assert_eq!(io(&mut instance, "fd_write", 2), 0);
    let capture = output.take_output().unwrap();
    assert_eq!(capture.stdout, b"abc");
    assert!(capture.stderr.is_empty());
    assert_eq!(call(&mut instance, "fd_renumber", &[I32(1), I32(2)]), 8);
    assert_eq!(stat(&mut instance, 2), before);
    assert_eq!(call(&mut instance, "fd_renumber", &[I32(99), I32(99)]), 8);
}

#[test]
fn attenuation_cannot_be_undone_by_renumbering_or_forged_high_bits() {
    let vm = vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(providers(WasiStdioLimits::default()).0)
        .unwrap();
    for (base, inheriting) in [(u64::MAX, 0), (READ_RIGHTS, 1), (1 << 63, 0)] {
        assert_eq!(rights(&mut instance, 0, base, inheriting), 76);
        assert_eq!(
            u64::from_le_bytes(stat(&mut instance, 0)[8..16].try_into().unwrap()),
            READ_RIGHTS
        );
    }
    assert_eq!(rights(&mut instance, 0, 0, 0), 0);
    assert_eq!(io(&mut instance, "fd_read", 0), 76);
    assert_eq!(rights(&mut instance, 0, READ_RIGHTS, 0), 76);
    assert_eq!(call(&mut instance, "fd_renumber", &[I32(0), I32(41)]), 0);
    assert_eq!(io(&mut instance, "fd_read", 41), 76);
    assert_eq!(
        call(&mut instance, "fd_filestat_get", &[I32(41), I32(128)]),
        76
    );
    assert_eq!(call(&mut instance, "fd_close", &[I32(41)]), 0);
}

#[test]
fn flags_are_validated_and_require_the_remaining_set_flags_right() {
    let vm = vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(providers(WasiStdioLimits::default()).0)
        .unwrap();
    assert_eq!(
        call(&mut instance, "fd_fdstat_set_flags", &[I32(1), I32(4)]),
        0
    );
    assert_eq!(&stat(&mut instance, 1)[2..4], &[4, 0]);
    for (flags, error) in [(1, 58), (2, 58), (8, 58), (16, 58), (32, 28), (-1, 28)] {
        assert_eq!(
            call(&mut instance, "fd_fdstat_set_flags", &[I32(1), I32(flags)]),
            error
        );
        assert_eq!(&stat(&mut instance, 1)[2..4], &[4, 0]);
    }
    assert_eq!(rights(&mut instance, 1, 1 << 6, 0), 0);
    assert_eq!(
        call(&mut instance, "fd_fdstat_set_flags", &[I32(1), I32(0)]),
        76
    );
    assert_eq!(&stat(&mut instance, 1)[2..4], &[4, 0]);
}

#[test]
fn moving_output_onto_stdin_does_not_grant_read_access_or_refund_output_quota() {
    let vm = vm(WasmNumericLimits::default());
    let (imports, output) = providers(WasiStdioLimits {
        max_output_bytes: 3,
        ..WasiStdioLimits::default()
    });
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(io(&mut instance, "fd_write", 1), 0);
    output.take_output().unwrap();
    assert_eq!(call(&mut instance, "fd_renumber", &[I32(1), I32(0)]), 0);
    assert_eq!(io(&mut instance, "fd_read", 0), 8);
    assert_eq!(io(&mut instance, "fd_write", 0), 51);
    assert_eq!(io(&mut instance, "fd_write", 2), 51);
}

#[test]
fn nonseekable_streams_and_absent_preopens_never_fabricate_positions_or_paths() {
    let vm = vm(WasmNumericLimits::default());
    let mut instance = vm
        .instantiate_with_imports(providers(WasiStdioLimits::default()).0)
        .unwrap();
    let before = instance.memory_export("m").unwrap().to_vec();
    for fd in 0..3 {
        assert_eq!(
            call(
                &mut instance,
                "fd_seek",
                &[I32(fd), I64(i64::MIN), I32(0), I32(128)]
            ),
            70
        );
        assert_eq!(call(&mut instance, "fd_tell", &[I32(fd), I32(128)]), 70);
        assert_eq!(
            call(
                &mut instance,
                "fd_seek",
                &[I32(fd), I64(0), I32(3), I32(128)]
            ),
            28
        );
    }
    for fd in [0, 1, 2, 3, -1] {
        assert_eq!(
            call(&mut instance, "fd_prestat_get", &[I32(fd), I32(128)]),
            8
        );
        assert_eq!(
            call(
                &mut instance,
                "fd_prestat_dir_name",
                &[I32(fd), I32(128), I32(16)]
            ),
            8
        );
    }
    assert_eq!(instance.memory_export("m").unwrap(), before);
}

#[test]
fn cost_refusal_precedes_close_and_metadata_writes() {
    let vm = vm(WasmNumericLimits {
        max_instructions: 2,
        ..WasmNumericLimits::default()
    });
    let mut instance = vm
        .instantiate_with_imports(providers(WasiStdioLimits::default()).0)
        .unwrap();
    assert!(matches!(
        instance.call_export("guest_close", &[]),
        Err(WasmNumericVmError::InstructionBudgetExceeded { .. })
    ));
    assert_eq!(call(&mut instance, "fd_close", &[I32(1)]), 0); // The refused guest call did not close it.
    assert_eq!(call(&mut instance, "fd_close", &[I32(1)]), 8);
    let before = instance.memory_export("m").unwrap().to_vec();
    assert!(matches!(
        instance.call_export("fd_fdstat_get", &[I32(0), I32(128)]),
        Err(WasmNumericVmError::InstructionBudgetExceeded { .. })
    ));
    assert_eq!(instance.memory_export("m").unwrap(), before);
}

#[test]
fn a_later_guest_trap_keeps_close_effects_and_other_instances_are_isolated() {
    let vm = vm(WasmNumericLimits::default());
    let mut first = vm
        .instantiate_with_imports(providers(WasiStdioLimits::default()).0)
        .unwrap();
    assert!(matches!(
        first.call_export("close_trap", &[]),
        Err(WasmNumericVmError::Unreachable { .. })
    ));
    assert_eq!(io(&mut first, "fd_write", 1), 8);
    let mut second = vm
        .instantiate_with_imports(providers(WasiStdioLimits::default()).0)
        .unwrap();
    assert_eq!(io(&mut second, "fd_write", 1), 0);
}

#[test]
fn renamed_descriptors_cannot_bypass_revoked_host_capabilities() {
    let vm = vm(WasmNumericLimits::default());
    let (imports, output) = providers(WasiStdioLimits::default());
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(call(&mut instance, "fd_renumber", &[I32(1), I32(41)]), 0);
    instance.revoke_host_capability(Console);
    assert!(matches!(
        instance.call_export("fd_write", &[I32(41), I32(0), I32(1), I32(32)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied {
                capability: Console,
                ..
            }
        )))
    ));
    assert!(output.take_output().unwrap().stdout.is_empty());
    assert_eq!(io(&mut instance, "fd_read", 41), 8);
    instance.revoke_host_capability(Builtin);
    assert!(matches!(
        instance.call_export("fd_close", &[I32(41)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied {
                capability: Builtin,
                ..
            }
        )))
    ));
}

#[test]
fn replay_reproduces_descriptor_results_without_consuming_or_emitting_again() {
    fn sequence(instance: &mut WasmNumericInstance<'_>) {
        stat(instance, 0);
        assert_eq!(call(instance, "fd_renumber", &[I32(1), I32(2)]), 0);
        assert_eq!(io(instance, "fd_read", 0), 0);
        assert_eq!(io(instance, "fd_write", 2), 0);
        assert_eq!(rights(instance, 0, 0, 0), 0);
        assert_eq!(io(instance, "fd_read", 0), 76);
        assert_eq!(call(instance, "fd_close", &[I32(2)]), 0);
        assert_eq!(io(instance, "fd_write", 2), 8);
    }
    let vm = vm(WasmNumericLimits::default());
    let (mut imports, output) = providers(WasiStdioLimits::default());
    let limits = WasmHostTraceLimits::default();
    let recording = imports.record_calls(limits).unwrap();
    let mut original = vm.instantiate_with_imports(imports).unwrap();
    sequence(&mut original);
    let (mut imports, replay_output) = providers(WasiStdioLimits::default());
    let replay = imports
        .replay_calls(recording.snapshot().unwrap(), limits)
        .unwrap();
    let mut replayed = vm.instantiate_with_imports(imports).unwrap();
    sequence(&mut replayed);
    assert_eq!(replayed.memory_export("m"), original.memory_export("m"));
    replay.verify_complete().unwrap();
    assert_eq!(output.take_output().unwrap().stdout, b"xyz");
    assert!(replay_output.take_output().unwrap().stdout.is_empty());
    assert_eq!(replay_output.input_consumed().unwrap(), 0);
}

#[test]
fn compiler_generated_command_executes_descriptor_lifecycle_and_echoes_to_original_stdout() {
    let vm = WasmNumericVm::parse(
        include_bytes!("fixtures/wasi_descriptor_smoke.wasm"),
        WasmNumericLimits::default(),
    )
    .unwrap();
    let payload: Vec<u8> = (0..=255).cycle().take(1000).collect();
    let (imports, output) = WasiPreview1Config::default()
        .into_imports_with_stdio(
            BTreeSet::from([Builtin, Console, FsRead, VmDispatch]),
            payload.clone(),
            WasiStdioLimits::default(),
        )
        .unwrap();
    assert_eq!(run_command(&vm, imports).unwrap(), 0);
    let captured = output.take_output().unwrap();
    assert_eq!(captured.stdout, payload);
    assert!(captured.stderr.is_empty());
    assert_eq!(output.input_consumed().unwrap(), 1000);
}

#[test]
fn descriptor_bindings_require_explicit_stdio_and_builtin_authority() {
    let vm = vm(WasmNumericLimits::default());
    let grants = BTreeSet::from([Builtin, Console, FsRead, VmDispatch]);
    let no_stdio = WasiPreview1Config::default().into_imports(grants).unwrap();
    assert!(matches!(
        vm.instantiate_with_imports(no_stdio),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::MissingBinding { .. }
        )))
    ));
    let (imports, _) = WasiPreview1Config::default()
        .into_imports_with_stdio(
            BTreeSet::from([Console, FsRead, VmDispatch]),
            vec![],
            WasiStdioLimits::default(),
        )
        .unwrap();
    assert!(matches!(
        vm.instantiate_with_imports(imports),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied {
                capability: Builtin,
                ..
            }
        )))
    ));
}

#[test]
fn live_management_revocation_prevents_close_without_stopping_unrelated_output() {
    use frankenengine_engine::checkpoint::CancellationToken;
    let vm = vm(WasmNumericLimits::default());
    let (mut imports, output) = providers(WasiStdioLimits::default());
    let token = CancellationToken::new();
    imports
        .bind_capability_revocation(Builtin, token.clone(), "descriptor-revocation")
        .unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    token.cancel();
    token.reset();
    assert!(matches!(
        instance.call_export("fd_close", &[I32(1)]),
        Err(WasmNumericVmError::State(WasmStateError::Host(
            WasmHostError::CapabilityDenied {
                capability: Builtin,
                ..
            }
        )))
    ));
    assert_eq!(io(&mut instance, "fd_write", 1), 0);
    assert_eq!(output.take_output().unwrap().stdout, b"abc");
}

#[test]
fn all_initial_sources_and_target_classes_move_without_creating_extra_descriptors() {
    let vm = vm(WasmNumericLimits::default());
    for source in 0..3 {
        for target in [0_u32, 1, 2, 3, 41, u32::MAX] {
            let mut instance = vm
                .instantiate_with_imports(providers(WasiStdioLimits::default()).0)
                .unwrap();
            let before = stat(&mut instance, source);
            assert_eq!(
                call(
                    &mut instance,
                    "fd_renumber",
                    &[I32(source as i32), I32(target as i32)]
                ),
                0
            );
            assert_eq!(stat(&mut instance, target), before);
            let mut handles = BTreeSet::from([0_u32, 1, 2]);
            handles.remove(&source);
            handles.insert(target);
            for fd in [0_u32, 1, 2, 3, 41, u32::MAX] {
                let actual = call(&mut instance, "fd_fdstat_get", &[I32(fd as i32), I32(128)]);
                assert_eq!(actual, if handles.contains(&fd) { 0 } else { 8 });
            }
        }
    }
}
