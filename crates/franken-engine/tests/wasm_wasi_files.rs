//! Execute real WASI imports against private read-only trees, never mock the VM.
#![forbid(unsafe_code)]

use frankenengine_engine::capability::RuntimeCapability::{
    self, Builtin, Console, FsRead, VmDispatch,
};
use frankenengine_engine::checkpoint::CancellationToken;
use frankenengine_engine::wasm_runtime_lane::WasmBoundaryValue::{self, I32, I64};
use frankenengine_engine::wasm_runtime_lane::host_replay::WasmHostTraceLimits;
use frankenengine_engine::wasm_runtime_lane::numeric::{
    WasmHostError, WasmHostImports, WasmNumericInstance, WasmNumericLimits, WasmNumericVm,
    WasmNumericVmError, WasmStateError,
};
use frankenengine_engine::wasm_runtime_lane::wasi_preview1::{
    WasiPreview1Config, WasiReadOnlyFiles, WasiStdioLimits,
};
use std::collections::{BTreeMap, BTreeSet};

const READ: u64 = 1 << 1;
const SEEK: u64 = 1 << 2;
const TELL: u64 = 1 << 5;
const FILESTAT: u64 = 1 << 21;
const FILE: u64 = READ | SEEK | TELL | FILESTAT | (1 << 3);
const DIRECTORY: u64 = (1 << 13) | (1 << 18) | FILESTAT;

fn leb(mut value: usize) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let byte = (value & 127) as u8;
        value >>= 7;
        out.push(byte | if value == 0 { 0 } else { 128 });
        if value == 0 {
            return out;
        }
    }
}
fn section(out: &mut Vec<u8>, id: u8, payload: &[u8]) {
    out.push(id);
    out.extend(leb(payload.len()));
    out.extend(payload);
}
fn text(out: &mut Vec<u8>, name: &str) {
    out.extend(leb(name.len()));
    out.extend(name.as_bytes());
}

fn binary() -> Vec<u8> {
    let functions: &[(&str, &[u8])] = &[
        (
            "path_open",
            &[0x7f, 0x7f, 0x7f, 0x7f, 0x7f, 0x7e, 0x7e, 0x7f, 0x7f],
        ),
        ("path_filestat_get", &[0x7f; 5]),
        ("fd_read", &[0x7f; 4]),
        ("fd_pread", &[0x7f, 0x7f, 0x7f, 0x7e, 0x7f]),
        ("fd_seek", &[0x7f, 0x7e, 0x7f, 0x7f]),
        ("fd_tell", &[0x7f; 2]),
        ("fd_fdstat_get", &[0x7f; 2]),
        ("fd_filestat_get", &[0x7f; 2]),
        ("fd_close", &[0x7f]),
        ("fd_renumber", &[0x7f; 2]),
        ("fd_fdstat_set_rights", &[0x7f, 0x7e, 0x7e]),
        ("fd_fdstat_set_flags", &[0x7f; 2]),
        ("fd_prestat_get", &[0x7f; 2]),
        ("fd_prestat_dir_name", &[0x7f; 3]),
        ("fd_write", &[0x7f; 4]),
        ("fd_readdir", &[0x7f, 0x7f, 0x7f, 0x7e, 0x7f]),
    ];
    let mut out = b"\0asm\x01\0\0\0".to_vec();
    let mut types = leb(functions.len() + 1);
    for (_, params) in functions {
        types.push(0x60);
        types.extend(leb(params.len()));
        types.extend(*params);
        types.extend([1, 0x7f]);
    }
    types.extend([0x60, 2, 0x7f, 0x7f, 0]);
    section(&mut out, 1, &types);
    let mut imports = leb(functions.len());
    let mut exports = leb(functions.len() + 2);
    for (index, (name, _)) in functions.iter().enumerate() {
        text(&mut imports, "wasi_snapshot_preview1");
        text(&mut imports, name);
        imports.push(0);
        imports.extend(leb(index));
        text(&mut exports, name);
        exports.push(0);
        exports.extend(leb(index));
    }
    section(&mut out, 2, &imports);
    let mut declarations = vec![1];
    declarations.extend(leb(functions.len()));
    section(&mut out, 3, &declarations);
    section(&mut out, 5, &[1, 1, 1, 1]);
    text(&mut exports, "store");
    exports.push(0);
    exports.extend(leb(functions.len()));
    text(&mut exports, "memory");
    exports.extend([2, 0]);
    section(&mut out, 7, &exports);
    section(&mut out, 10, &[1, 9, 0, 0x20, 0, 0x20, 1, 0x3a, 0, 0, 0x0b]);
    out
}
fn vm() -> WasmNumericVm {
    WasmNumericVm::parse(&binary(), WasmNumericLimits::default()).unwrap()
}
fn grants() -> BTreeSet<RuntimeCapability> {
    BTreeSet::from([VmDispatch, Builtin, FsRead, Console])
}
fn files() -> WasiReadOnlyFiles {
    WasiReadOnlyFiles {
        files: BTreeMap::from([
            ("alpha.txt".into(), b"abcdef".to_vec()),
            ("dir/beta.bin".into(), vec![0, 128, 255, 7]),
            ("empty".into(), vec![]),
            ("bulk".into(), vec![42; 128]),
            ("é.txt".into(), b"unicode".to_vec()),
        ]),
        max_open_descriptors: 12,
        ..WasiReadOnlyFiles::default()
    }
}
fn registry(config: WasiReadOnlyFiles) -> WasmHostImports {
    WasiPreview1Config::default()
        .into_imports_with_read_only_files(grants(), vec![], WasiStdioLimits::default(), config)
        .unwrap()
        .0
}
fn errno(instance: &mut WasmNumericInstance<'_>, name: &str, args: &[WasmBoundaryValue]) -> i32 {
    let result = instance.call_export(name, args).unwrap();
    match result.results.as_slice() {
        [I32(code)] => *code,
        other => panic!("invalid errno result: {other:?}"),
    }
}
fn put(instance: &mut WasmNumericInstance<'_>, address: u32, data: &[u8]) {
    for (offset, byte) in data.iter().enumerate() {
        instance
            .call_export(
                "store",
                &[I32((address + offset as u32) as i32), I32(i32::from(*byte))],
            )
            .unwrap();
    }
}
fn u32_at(instance: &WasmNumericInstance<'_>, address: usize) -> u32 {
    u32::from_le_bytes(
        instance.memory_export("memory").unwrap()[address..address + 4]
            .try_into()
            .unwrap(),
    )
}
fn u64_at(instance: &WasmNumericInstance<'_>, address: usize) -> u64 {
    u64::from_le_bytes(
        instance.memory_export("memory").unwrap()[address..address + 8]
            .try_into()
            .unwrap(),
    )
}
fn open_at(
    instance: &mut WasmNumericInstance<'_>,
    root: u32,
    path: &[u8],
    rights: u64,
    inheriting: u64,
    flags: i32,
    result: i32,
) -> i32 {
    put(instance, 256, path);
    errno(
        instance,
        "path_open",
        &[
            I32(root as i32),
            I32(1),
            I32(256),
            I32(path.len() as i32),
            I32(flags),
            I64(rights as i64),
            I64(inheriting as i64),
            I32(0),
            I32(result),
        ],
    )
}
fn open(instance: &mut WasmNumericInstance<'_>, path: &[u8]) -> u32 {
    assert_eq!(open_at(instance, 3, path, FILE, 0, 0, 64), 0);
    u32_at(instance, 64)
}
fn iovec(instance: &mut WasmNumericInstance<'_>, width: u32) {
    put(instance, 0, &512_u32.to_le_bytes());
    put(instance, 4, &width.to_le_bytes());
}
fn read(instance: &mut WasmNumericInstance<'_>, fd: u32, width: u32) -> Vec<u8> {
    iovec(instance, width);
    assert_eq!(
        errno(
            instance,
            "fd_read",
            &[I32(fd as i32), I32(0), I32(1), I32(32)]
        ),
        0
    );
    let n = u32_at(instance, 32) as usize;
    instance.memory_export("memory").unwrap()[512..512 + n].to_vec()
}
fn tell(instance: &mut WasmNumericInstance<'_>, fd: u32) -> u64 {
    assert_eq!(errno(instance, "fd_tell", &[I32(fd as i32), I32(72)]), 0);
    u64_at(instance, 72)
}

#[test]
fn supplied_preopen_and_file_metadata_have_exact_bounds_and_zero_padding() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    put(&mut instance, 128, &[0xaa; 64]);
    assert_eq!(
        errno(&mut instance, "fd_prestat_get", &[I32(3), I32(128)]),
        0
    );
    assert_eq!(
        &instance.memory_export("memory").unwrap()[128..136],
        &[0, 0, 0, 0, 5, 0, 0, 0]
    );
    assert_eq!(
        errno(
            &mut instance,
            "fd_prestat_dir_name",
            &[I32(3), I32(256), I32(4)]
        ),
        37
    );
    assert_eq!(
        errno(
            &mut instance,
            "fd_prestat_dir_name",
            &[I32(3), I32(256), I32(5)]
        ),
        0
    );
    assert_eq!(
        &instance.memory_export("memory").unwrap()[256..261],
        b"/data"
    );
    let fd = open(&mut instance, b"alpha.txt");
    assert_eq!(
        errno(&mut instance, "fd_fdstat_get", &[I32(fd as i32), I32(128)]),
        0
    );
    assert_eq!(instance.memory_export("memory").unwrap()[128], 4);
    assert_eq!(u64_at(&instance, 136), FILE);
    assert_eq!(u64_at(&instance, 144), 0);
    assert_eq!(
        errno(
            &mut instance,
            "fd_filestat_get",
            &[I32(fd as i32), I32(128)]
        ),
        0
    );
    assert_eq!(u64_at(&instance, 160), 6);
    assert_eq!(u64_at(&instance, 152), 1);
    assert_eq!(
        &instance.memory_export("memory").unwrap()[168..192],
        &[0; 24]
    );
    assert_eq!(
        errno(
            &mut instance,
            "fd_filestat_get",
            &[I32(fd as i32), I32(65536 - 63)]
        ),
        21
    );
    assert_eq!(
        errno(&mut instance, "fd_prestat_get", &[I32(fd as i32), I32(128)]),
        8
    );
}

#[test]
fn each_open_has_an_independent_cursor_and_empty_files_reach_eof() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    let a = open(&mut instance, b"alpha.txt");
    let b = open(&mut instance, b"alpha.txt");
    assert_eq!(read(&mut instance, a, 2), b"ab");
    assert_eq!(read(&mut instance, a, 10), b"cdef");
    assert_eq!(read(&mut instance, b, 3), b"abc");
    assert_eq!(tell(&mut instance, a), 6);
    assert!(read(&mut instance, a, 4).is_empty());
    let empty = open(&mut instance, b"empty");
    assert!(read(&mut instance, empty, 5).is_empty());
    let unicode = open(&mut instance, "é.txt".as_bytes());
    assert_eq!(read(&mut instance, unicode, 10), b"unicode");
}

#[test]
fn positional_reads_and_checked_seeks_preserve_cursor_semantics() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    let fd = open(&mut instance, b"alpha.txt");
    assert_eq!(read(&mut instance, fd, 2), b"ab");
    iovec(&mut instance, 3);
    assert_eq!(
        errno(
            &mut instance,
            "fd_pread",
            &[I32(fd as i32), I32(0), I32(1), I64(3), I32(32)]
        ),
        0
    );
    assert_eq!(&instance.memory_export("memory").unwrap()[512..515], b"def");
    assert_eq!(tell(&mut instance, fd), 2);
    assert_eq!(
        errno(
            &mut instance,
            "fd_pread",
            &[I32(fd as i32), I32(0), I32(1), I64(-1), I32(32)]
        ),
        0
    );
    assert_eq!(u32_at(&instance, 32), 0);
    assert_eq!(tell(&mut instance, fd), 2);
    assert_eq!(
        errno(
            &mut instance,
            "fd_seek",
            &[I32(fd as i32), I64(-2), I32(2), I32(72)]
        ),
        0
    );
    assert_eq!(u64_at(&instance, 72), 4);
    assert_eq!(read(&mut instance, fd, 10), b"ef");
    assert_eq!(
        errno(
            &mut instance,
            "fd_seek",
            &[I32(fd as i32), I64(-7), I32(0), I32(72)]
        ),
        28
    );
    assert_eq!(tell(&mut instance, fd), 6);
    assert_eq!(
        errno(
            &mut instance,
            "fd_seek",
            &[I32(fd as i32), I64(i64::MAX), I32(0), I32(72)]
        ),
        0
    );
    assert_eq!(
        errno(
            &mut instance,
            "fd_seek",
            &[I32(fd as i32), I64(i64::MAX), I32(1), I32(72)]
        ),
        0
    );
    assert_eq!(tell(&mut instance, fd), u64::MAX - 1);
    assert_eq!(
        errno(
            &mut instance,
            "fd_seek",
            &[I32(fd as i32), I64(2), I32(1), I32(72)]
        ),
        28
    );
    assert!(read(&mut instance, fd, 1).is_empty());
}

#[test]
fn directory_capabilities_confine_traversal_without_normalizing_past_files() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    for (path, code) in [
        (b"../alpha.txt".as_slice(), 76),
        (b"/alpha.txt", 76),
        (b"alpha.txt/../empty", 54),
        (b"alpha.txt/", 54),
        (b"missing", 44),
        (b"", 44),
        (b"alpha\0.txt", 28),
        (&[255], 25),
    ] {
        assert_eq!(
            open_at(&mut instance, 3, path, FILE, 0, 0, 64),
            code,
            "{path:?}"
        );
    }
    assert_eq!(
        open_at(&mut instance, 3, b"dir", DIRECTORY, FILE | DIRECTORY, 2, 64),
        0
    );
    let dir = u32_at(&instance, 64);
    assert_eq!(
        open_at(&mut instance, dir, b"../alpha.txt", FILE, 0, 0, 64),
        76
    );
    assert_eq!(
        open_at(&mut instance, dir, b"./beta.bin", FILE, 0, 0, 64),
        0
    );
    let fd = u32_at(&instance, 64);
    assert_eq!(read(&mut instance, fd, 10), [0, 128, 255, 7]);
    assert_eq!(
        open_at(&mut instance, 3, b"dir/../alpha.txt", FILE, 0, 0, 64),
        0
    );
    put(&mut instance, 256, b"dir/beta.bin");
    assert_eq!(
        errno(
            &mut instance,
            "path_filestat_get",
            &[I32(3), I32(1), I32(256), I32(12), I32(128)]
        ),
        0
    );
    assert_eq!(u64_at(&instance, 160), 4);
}

#[test]
fn descriptor_and_inheriting_rights_only_shrink() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    let fd = open(&mut instance, b"alpha.txt");
    assert_eq!(
        errno(
            &mut instance,
            "fd_fdstat_set_rights",
            &[I32(fd as i32), I64(TELL as i64), I64(0)]
        ),
        0
    );
    assert_eq!(
        errno(
            &mut instance,
            "fd_seek",
            &[I32(fd as i32), I64(0), I32(1), I32(72)]
        ),
        0
    );
    assert_eq!(
        errno(
            &mut instance,
            "fd_seek",
            &[I32(fd as i32), I64(1), I32(1), I32(72)]
        ),
        76
    );
    iovec(&mut instance, 1);
    assert_eq!(
        errno(
            &mut instance,
            "fd_read",
            &[I32(fd as i32), I32(0), I32(1), I32(32)]
        ),
        76
    );
    assert_eq!(
        errno(
            &mut instance,
            "fd_fdstat_set_rights",
            &[I32(fd as i32), I64(FILE as i64), I64(0)]
        ),
        76
    );
    assert_eq!(
        errno(
            &mut instance,
            "fd_fdstat_set_rights",
            &[I32(3), I64(DIRECTORY as i64), I64(READ as i64)]
        ),
        0
    );
    assert_eq!(open_at(&mut instance, 3, b"alpha.txt", FILE, 0, 0, 64), 76);
    assert_eq!(open_at(&mut instance, 3, b"alpha.txt", READ, 0, 0, 64), 0);
    let limited = u32_at(&instance, 64);
    assert_eq!(read(&mut instance, limited, 3), b"abc");
    assert_eq!(
        errno(
            &mut instance,
            "fd_fdstat_set_rights",
            &[
                I32(3),
                I64(DIRECTORY as i64),
                I64((FILE | DIRECTORY) as i64)
            ]
        ),
        76
    );
}

#[test]
fn close_and_large_renumber_move_file_position_without_replenishing_rights() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    let fd = open(&mut instance, b"alpha.txt");
    assert_eq!(read(&mut instance, fd, 2), b"ab");
    assert_eq!(
        errno(&mut instance, "fd_renumber", &[I32(fd as i32), I32(-1)]),
        0
    );
    assert_eq!(read(&mut instance, u32::MAX, 2), b"cd");
    assert_eq!(tell(&mut instance, u32::MAX), 4);
    assert_eq!(
        errno(&mut instance, "fd_tell", &[I32(fd as i32), I32(72)]),
        8
    );
    assert_eq!(errno(&mut instance, "fd_renumber", &[I32(-1), I32(1)]), 0);
    assert_eq!(read(&mut instance, 1, 9), b"ef");
    assert_eq!(
        errno(
            &mut instance,
            "fd_write",
            &[I32(1), I32(0), I32(1), I32(32)]
        ),
        76
    );
    assert_eq!(errno(&mut instance, "fd_close", &[I32(1)]), 0);
    assert_eq!(errno(&mut instance, "fd_close", &[I32(1)]), 8);
}

#[test]
fn failed_open_never_consumes_a_slot_and_closed_slots_are_reusable() {
    let vm = vm();
    let mut config = files();
    config.max_open_descriptors = 5;
    let mut instance = vm.instantiate_with_imports(registry(config)).unwrap();
    assert_eq!(open_at(&mut instance, 3, b"alpha.txt", FILE, 0, 0, -1), 21);
    let fd = open(&mut instance, b"alpha.txt");
    assert_eq!(open_at(&mut instance, 3, b"alpha.txt", FILE, 0, 0, 64), 33);
    assert_eq!(errno(&mut instance, "fd_close", &[I32(fd as i32)]), 0);
    let replacement = open(&mut instance, b"alpha.txt");
    assert_eq!(read(&mut instance, replacement, 2), b"ab");
}

#[test]
fn creation_truncation_and_write_rights_never_modify_supplied_files() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    for flag in [1, 8, 9] {
        assert_eq!(
            open_at(&mut instance, 3, b"alpha.txt", FILE, 0, flag, 64),
            69
        );
    }
    assert_eq!(
        open_at(&mut instance, 3, b"alpha.txt", FILE | (1 << 6), 0, 0, 64),
        76
    );
    assert_eq!(open_at(&mut instance, 3, b"alpha.txt", FILE, 0, 2, 64), 54);
    let fd = open(&mut instance, b"alpha.txt");
    assert_eq!(read(&mut instance, fd, 20), b"abcdef");
}

#[test]
fn complete_ranges_are_checked_before_any_read_or_cursor_change() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    let fd = open(&mut instance, b"alpha.txt");
    put(&mut instance, 0, &512_u32.to_le_bytes());
    put(&mut instance, 4, &2_u32.to_le_bytes());
    put(&mut instance, 8, &65535_u32.to_le_bytes());
    put(&mut instance, 12, &2_u32.to_le_bytes());
    assert_eq!(
        errno(
            &mut instance,
            "fd_read",
            &[I32(fd as i32), I32(0), I32(2), I32(32)]
        ),
        21
    );
    assert_eq!(
        &instance.memory_export("memory").unwrap()[512..514],
        &[0; 2]
    );
    assert_eq!(tell(&mut instance, fd), 0);
    assert_eq!(
        errno(
            &mut instance,
            "fd_seek",
            &[I32(fd as i32), I64(3), I32(0), I32(65530)]
        ),
        21
    );
    assert_eq!(tell(&mut instance, fd), 0);
}

#[test]
fn read_snapshots_iovecs_before_overwriting_their_own_metadata() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    let fd = open(&mut instance, b"alpha.txt");
    for (address, value) in [(0, 8_u32), (4, 3), (8, 512), (12, 3)] {
        put(&mut instance, address, &value.to_le_bytes());
    }
    assert_eq!(
        errno(
            &mut instance,
            "fd_read",
            &[I32(fd as i32), I32(0), I32(2), I32(32)]
        ),
        0
    );
    assert_eq!(&instance.memory_export("memory").unwrap()[8..11], b"abc");
    assert_eq!(&instance.memory_export("memory").unwrap()[512..515], b"def");
    assert_eq!(tell(&mut instance, fd), 6);
}

#[test]
fn work_refusal_precedes_first_file_byte_and_cursor_mutation() {
    let vm = WasmNumericVm::parse(
        &binary(),
        WasmNumericLimits {
            max_instructions: 100,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    let mut config = files();
    config.max_open_descriptors = 5;
    let mut instance = vm.instantiate_with_imports(registry(config)).unwrap();
    let fd = open(&mut instance, b"bulk");
    for n in 0..64_u32 {
        put(&mut instance, n * 8, &(1024 + n).to_le_bytes());
        put(&mut instance, n * 8 + 4, &1_u32.to_le_bytes());
    }
    put(&mut instance, 2048, &0xdead_beef_u32.to_le_bytes());
    assert!(matches!(
        instance.call_export("fd_read", &[I32(fd as i32), I32(0), I32(64), I32(2048)]),
        Err(WasmNumericVmError::InstructionBudgetExceeded { max: 100 })
    ));
    assert_eq!(tell(&mut instance, fd), 0);
    assert_eq!(u32_at(&instance, 2048), 0xdead_beef);
    assert_eq!(
        &instance.memory_export("memory").unwrap()[1024..1088],
        &[0; 64]
    );
}

#[test]
fn file_configuration_limits_and_path_collisions_fail_before_linking() {
    for bad in ["", "/abs", "a//b", "a/../b", "./a", "a/", "a\0b"] {
        let mut config = files();
        config.files = BTreeMap::from([(bad.into(), vec![])]);
        assert!(
            WasiPreview1Config::default()
                .into_imports_with_read_only_files(
                    grants(),
                    vec![],
                    WasiStdioLimits::default(),
                    config
                )
                .is_err()
        );
    }
    for mode in 0..5 {
        let mut config = files();
        match mode {
            0 => config.max_bytes = 1,
            1 => config.max_entries = 2,
            2 => config.max_path_bytes = 2,
            3 => config.max_open_descriptors = 3,
            _ => {
                config.files = BTreeMap::from([("a".into(), vec![]), ("a/b".into(), vec![])]);
            }
        }
        assert!(
            WasiPreview1Config::default()
                .into_imports_with_read_only_files(
                    grants(),
                    vec![],
                    WasiStdioLimits::default(),
                    config
                )
                .is_err()
        );
    }
}

#[test]
fn independent_registries_never_share_cursors_or_closed_handles() {
    let vm = vm();
    let mut a = vm.instantiate_with_imports(registry(files())).unwrap();
    let mut b = vm.instantiate_with_imports(registry(files())).unwrap();
    let fa = open(&mut a, b"alpha.txt");
    let fb = open(&mut b, b"alpha.txt");
    assert_eq!(read(&mut a, fa, 4), b"abcd");
    assert_eq!(read(&mut b, fb, 2), b"ab");
    assert_eq!(errno(&mut a, "fd_close", &[I32(fa as i32)]), 0);
    assert_eq!(read(&mut b, fb, 9), b"cdef");
}

#[test]
fn replay_restores_file_reads_without_executing_live_providers() {
    let vm = vm();
    let limits = WasmHostTraceLimits::default();
    let mut imports = registry(files());
    let recording = imports.record_calls(limits).unwrap();
    let mut a = vm.instantiate_with_imports(imports).unwrap();
    let fd = open(&mut a, b"alpha.txt");
    let expected = read(&mut a, fd, 4);
    assert_eq!(tell(&mut a, fd), 4);
    let tape = recording.snapshot().unwrap();
    assert_eq!(tape.call_count(), 3);
    let mut changed = files();
    changed
        .files
        .insert("alpha.txt".into(), b"CHANGED".to_vec());
    let mut imports = registry(changed);
    let replay = imports.replay_calls(tape, limits).unwrap();
    let mut b = vm.instantiate_with_imports(imports).unwrap();
    let fd = open(&mut b, b"alpha.txt");
    assert_eq!(read(&mut b, fd, 4), expected);
    assert_eq!(tell(&mut b, fd), 4);
    replay.verify_complete().unwrap();
}

#[test]
fn live_fs_revocation_stops_reads_and_metadata_not_as_successful_errno() {
    let vm = vm();
    let token = CancellationToken::new();
    let mut imports = registry(files());
    imports
        .bind_capability_revocation(FsRead, token.clone(), "file-read")
        .unwrap();
    let mut instance = vm.instantiate_with_imports(imports).unwrap();
    let fd = open(&mut instance, b"alpha.txt");
    iovec(&mut instance, 2);
    token.cancel();
    token.reset();
    for (name, args) in [
        ("fd_read", vec![I32(fd as i32), I32(0), I32(1), I32(32)]),
        ("fd_filestat_get", vec![I32(fd as i32), I32(128)]),
    ] {
        assert!(matches!(
            instance.call_export(name, &args),
            Err(WasmNumericVmError::State(WasmStateError::Host(
                WasmHostError::CapabilityDenied {
                    capability: FsRead,
                    ..
                }
            )))
        ));
    }
    assert_eq!(
        &instance.memory_export("memory").unwrap()[512..514],
        &[0; 2]
    );
}

#[test]
fn resolver_manifest_must_authorize_files_even_with_broader_provider_grants() {
    use frankenengine_engine::module_resolver::{
        CapabilityPolicyHook, DeterministicModuleResolver, ImportStyle, ModuleDefinition,
        ModuleRequest, ResolutionContext, wasm_module_required_capabilities,
    };
    use frankenengine_engine::wasm_runtime_lane::WasmNativeLoadError;
    let context = ResolutionContext::new("files", "load", "policy");
    let mut policy_grants = wasm_module_required_capabilities();
    policy_grants.extend(grants());
    let policy = CapabilityPolicyHook::new(policy_grants);
    for declared in [false, true] {
        let mut definition =
            ModuleDefinition::wasm_binary(&binary(), &WasmNumericLimits::default()).unwrap();
        definition.required_capabilities.extend([Builtin, Console]);
        if declared {
            definition.required_capabilities.insert(FsRead);
        }
        let mut resolver = DeterministicModuleResolver::new("/app");
        resolver
            .register_workspace_module("/app/read.wasm", definition)
            .unwrap();
        let module = resolver
            .load_wasm(
                &ModuleRequest::new("/app/read.wasm", ImportStyle::Import),
                &context,
                &policy,
                WasmNumericLimits::default(),
            )
            .unwrap();
        let result = module.instantiate_with_imports(&context, &policy, registry(files()));
        if declared {
            assert!(result.is_ok());
        } else {
            assert!(matches!(
                result,
                Err(WasmNativeLoadError::Execution(WasmNumericVmError::State(
                    WasmStateError::Host(WasmHostError::CapabilityDenied {
                        capability: FsRead,
                        ..
                    })
                )))
            ));
        }
    }
}

fn listing(instance: &mut WasmNumericInstance<'_>, fd: u32, length: u32, cookie: u64) -> Vec<u8> {
    assert_eq!(
        errno(
            instance,
            "fd_readdir",
            &[
                I32(fd as i32),
                I32(4096),
                I32(length as i32),
                I64(cookie as i64),
                I32(32)
            ]
        ),
        0
    );
    let used = u32_at(instance, 32) as usize;
    instance.memory_export("memory").unwrap()[4096..4096 + used].to_vec()
}
fn decode_entries(bytes: &[u8]) -> Vec<(u64, u64, String, u8)> {
    let mut entries = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        assert!(bytes.len() - at >= 24);
        let next = u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let inode = u64::from_le_bytes(bytes[at + 8..at + 16].try_into().unwrap());
        let length = u32::from_le_bytes(bytes[at + 16..at + 20].try_into().unwrap()) as usize;
        assert_eq!(&bytes[at + 21..at + 24], &[0; 3]);
        let name = std::str::from_utf8(&bytes[at + 24..at + 24 + length])
            .unwrap()
            .to_owned();
        entries.push((next, inode, name, bytes[at + 20]));
        at += 24 + length;
    }
    entries
}

#[test]
fn directory_entries_are_complete_sorted_and_deterministic_with_stable_cookies() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    put(&mut instance, 4096, &[0xaa; 1024]);
    let bytes = listing(&mut instance, 3, 1024, 0);
    let entries = decode_entries(&bytes);
    assert_eq!(
        entries
            .iter()
            .map(|entry| entry.2.as_str())
            .collect::<Vec<_>>(),
        [".", "..", "alpha.txt", "bulk", "dir", "empty", "é.txt"]
    );
    for (index, entry) in entries.iter().enumerate() {
        assert_eq!(entry.0, index as u64 + 1);
    }
    assert_eq!(entries[0].1, entries[1].1);
    assert_eq!(entries[4].3, 3);
    assert_eq!(entries[2].3, 4);
    assert_eq!(listing(&mut instance, 3, 1024, 0), bytes);
    assert!(listing(&mut instance, 3, 1024, entries.len() as u64).is_empty());
}

#[test]
fn short_readdir_buffers_return_exact_prefixes_and_can_retry_the_same_cookie() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    let full = listing(&mut instance, 3, 1024, 0);
    for length in [0, 1, 7, 23, 24, 25, 26, 50, 64] {
        assert_eq!(
            listing(&mut instance, 3, length, 0),
            full[..length as usize]
        );
    }
    let dot = listing(&mut instance, 3, 25, 0);
    assert_eq!(decode_entries(&dot)[0].2, ".");
    let remainder = listing(&mut instance, 3, 1024, 1);
    assert_eq!(remainder, full[25..]);
}

#[test]
fn directory_handles_remain_anchored_after_renumber_and_root_close() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    let rights = DIRECTORY | (1 << 14);
    assert_eq!(open_at(&mut instance, 3, b"dir", rights, FILE, 2, 64), 0);
    let dir = u32_at(&instance, 64);
    let expected = listing(&mut instance, dir, 1024, 0);
    assert_eq!(
        errno(&mut instance, "fd_renumber", &[I32(dir as i32), I32(-1)]),
        0
    );
    assert_eq!(errno(&mut instance, "fd_close", &[I32(3)]), 0);
    assert_eq!(listing(&mut instance, u32::MAX, 1024, 0), expected);
    assert_eq!(
        open_at(&mut instance, u32::MAX, b"../alpha.txt", FILE, 0, 0, 64),
        76
    );
    assert_eq!(
        open_at(&mut instance, u32::MAX, b"beta.bin", FILE, 0, 0, 64),
        0
    );
    let fd = u32_at(&instance, 64);
    assert_eq!(read(&mut instance, fd, 8), [0, 128, 255, 7]);
}

#[test]
fn directory_enumeration_cannot_restore_removed_rights_or_read_regular_files() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    let fd = open(&mut instance, b"alpha.txt");
    assert_eq!(
        errno(
            &mut instance,
            "fd_readdir",
            &[I32(fd as i32), I32(4096), I32(100), I64(0), I32(32)]
        ),
        54
    );
    assert_eq!(
        errno(
            &mut instance,
            "fd_fdstat_set_rights",
            &[I32(3), I64(DIRECTORY as i64), I64(FILE as i64)]
        ),
        0
    );
    assert_eq!(
        errno(
            &mut instance,
            "fd_readdir",
            &[I32(3), I32(4096), I32(100), I64(0), I32(32)]
        ),
        76
    );
    assert_eq!(
        errno(
            &mut instance,
            "fd_fdstat_set_rights",
            &[
                I32(3),
                I64((DIRECTORY | (1 << 14)) as i64),
                I64(FILE as i64)
            ]
        ),
        76
    );
}

#[test]
fn invalid_cookie_ranges_and_transfer_limits_do_not_publish_directory_bytes() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    put(&mut instance, 32, &0xdead_beef_u32.to_le_bytes());
    for args in [
        vec![I32(3), I32(4096), I32(100), I64(-1), I32(32)],
        vec![I32(3), I32(65530), I32(20), I64(0), I32(32)],
        vec![I32(3), I32(4096), I32(65537), I64(0), I32(32)],
        vec![I32(3), I32(4096), I32(100), I64(0), I32(65534)],
    ] {
        assert_ne!(errno(&mut instance, "fd_readdir", &args), 0);
        assert_eq!(u32_at(&instance, 32), 0xdead_beef);
        assert_eq!(
            &instance.memory_export("memory").unwrap()[4096..4196],
            &[0; 100]
        );
    }
}

#[test]
fn readdir_precharges_output_work_before_any_payload_or_count_write() {
    let vm = WasmNumericVm::parse(
        &binary(),
        WasmNumericLimits {
            max_instructions: 50,
            ..WasmNumericLimits::default()
        },
    )
    .unwrap();
    let mut config = files();
    config.max_open_descriptors = 4;
    let mut instance = vm.instantiate_with_imports(registry(config)).unwrap();
    put(&mut instance, 32, &0xdead_beef_u32.to_le_bytes());
    assert!(matches!(
        instance.call_export(
            "fd_readdir",
            &[I32(3), I32(4096), I32(4096), I64(0), I32(32)]
        ),
        Err(WasmNumericVmError::InstructionBudgetExceeded { max: 50 })
    ));
    assert_eq!(u32_at(&instance, 32), 0xdead_beef);
    assert_eq!(
        &instance.memory_export("memory").unwrap()[4096..4352],
        &[0; 256]
    );
}

#[test]
fn overlapping_directory_count_is_written_after_the_snapshotted_payload() {
    let vm = vm();
    let mut instance = vm.instantiate_with_imports(registry(files())).unwrap();
    let expected = listing(&mut instance, 3, 1024, 0);
    assert_eq!(
        errno(
            &mut instance,
            "fd_readdir",
            &[I32(3), I32(4096), I32(1024), I64(0), I32(4096)]
        ),
        0
    );
    assert_eq!(u32_at(&instance, 4096), expected.len() as u32);
    assert_eq!(
        &instance.memory_export("memory").unwrap()[4100..4096 + expected.len()],
        &expected[4..]
    );
}

#[test]
fn immutable_directory_replay_restores_the_historical_listing() {
    let vm = vm();
    let limits = WasmHostTraceLimits::default();
    let mut imports = registry(files());
    let record = imports.record_calls(limits).unwrap();
    let mut a = vm.instantiate_with_imports(imports).unwrap();
    let expected = listing(&mut a, 3, 1024, 0);
    let mut config = files();
    config.files.clear();
    let mut imports = registry(config);
    let replay = imports
        .replay_calls(record.snapshot().unwrap(), limits)
        .unwrap();
    let mut b = vm.instantiate_with_imports(imports).unwrap();
    assert_eq!(listing(&mut b, 3, 1024, 0), expected);
    replay.verify_complete().unwrap();
}

fn compiled_input() -> Vec<u8> {
    (0..1000).map(|index| index as u8).collect()
}
fn compiled_registry(
    payload: Vec<u8>,
) -> (
    WasmHostImports,
    frankenengine_engine::wasm_runtime_lane::wasi_preview1::WasiStdio,
) {
    let files = WasiReadOnlyFiles {
        files: BTreeMap::from([("nested/input.bin".into(), payload)]),
        max_open_descriptors: 8,
        ..WasiReadOnlyFiles::default()
    };
    WasiPreview1Config::default()
        .into_imports_with_read_only_files(grants(), vec![], WasiStdioLimits::default(), files)
        .unwrap()
}

#[test]
fn clang_compiled_guest_discovers_opens_seeks_and_copies_an_entire_input_file() {
    use frankenengine_engine::wasm_runtime_lane::wasi_preview1::run_command;
    let bytes = include_bytes!("fixtures/wasi_file_smoke.wasm");
    let vm = WasmNumericVm::parse(bytes, WasmNumericLimits::default()).unwrap();
    let (imports, output) = compiled_registry(compiled_input());
    assert_eq!(run_command(&vm, imports).unwrap(), 0);
    let captured = output.take_output().unwrap();
    assert_eq!(captured.stdout, compiled_input());
    assert!(captured.stderr.is_empty());
}

#[test]
fn compiled_file_command_replay_preserves_results_without_recapturing_output() {
    use frankenengine_engine::wasm_runtime_lane::wasi_preview1::run_command;
    let vm = WasmNumericVm::parse(
        include_bytes!("fixtures/wasi_file_smoke.wasm"),
        WasmNumericLimits::default(),
    )
    .unwrap();
    let limits = WasmHostTraceLimits::default();
    let (mut imports, output) = compiled_registry(compiled_input());
    let recording = imports.record_calls(limits).unwrap();
    assert_eq!(run_command(&vm, imports).unwrap(), 0);
    let transcript = recording.snapshot().unwrap();
    assert_eq!(transcript.call_count(), 19);
    assert_eq!(output.take_output().unwrap().stdout, compiled_input());
    let (mut imports, replayed_output) = compiled_registry(b"different live file".to_vec());
    let replay = imports.replay_calls(transcript, limits).unwrap();
    assert_eq!(run_command(&vm, imports).unwrap(), 0);
    replay.verify_complete().unwrap();
    assert!(replayed_output.take_output().unwrap().stdout.is_empty());
}
