//! FileHandle operations on the real orchestrated, capability-gated host path.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    HostIoRecorder, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn run(source: &str, root: &Path, filesystem_caps: &[&str]) -> Result<Vec<String>, String> {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox provider"));
    let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io(provider, Some(recorder));
    let mut capabilities = vec!["vm_dispatch", "heap_allocate", "builtin", "console"];
    capabilities.extend_from_slice(filesystem_caps);
    let package = ExtensionPackage {
        extension_id: "fs-file-handle-regression".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = orchestrator
        .execute(&package)
        .map_err(|error| format!("{error:?}"))?;
    Ok(result
        .console_output
        .into_iter()
        .map(|entry| entry.message)
        .collect())
}

#[test]
fn file_handle_write_sync_read_and_close_use_real_files() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "const fs = require('fs'); let h; \
         fs.promises.open('out.txt', 'w+').then(value => { \
           h = value; console.log(typeof h.fd); return h.write('hello'); \
         }).then(result => { \
           console.log(result.bytesWritten, result.buffer); return h.sync(); \
         }).then(() => h.read({buffer: Buffer.alloc(2), position: 1})) \
         .then(result => { \
           console.log(result.bytesRead, result.buffer.toString()); return h.close(); \
         }).then(() => console.log(h.fd));",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("native descriptor lifecycle");
    assert_eq!(output, ["number", "5 hello", "2 el", "-1"]);
    assert_eq!(std::fs::read(root.path().join("out.txt")).unwrap(), b"hello");
}

#[test]
fn file_handle_windows_preserve_buffers_and_positioned_io() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("input.txt"), b"abcdef").unwrap();
    let output = run(
        "let h; const buffer = Buffer.alloc(4, 45); \
         require('node:fs/promises').open('input.txt', 'r').then(value => { \
           h = value; return h.read(buffer, {offset: 1, length: 2, position: 2}); \
         }).then(result => { \
           console.log(result.bytesRead, result.buffer === buffer, buffer.toString()); \
           return h.read({buffer: Buffer.alloc(2)}); \
         }).then(result => { console.log(result.buffer.toString()); return h.close(); });",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("native positioned reads");
    assert_eq!(output, ["2 true -cd-", "ab"]);
}

#[test]
fn file_handle_close_is_idempotent_and_stale_operations_reject() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "let h; require('fs/promises').open('empty.txt', 'w+').then(value => { \
           h = value; const first = h.close(); console.log(h.fd, first === h.close()); \
           return first; \
         }).then(() => h.write('forbidden')).catch(error => { \
           console.log(error.code, error.syscall); return h.read(); \
         }).catch(error => { console.log(error.code, error.syscall); return h.sync(); }) \
         .catch(error => console.log(error.code, error.syscall));",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("closed handles reject without native access");
    assert_eq!(output, ["-1 true", "EBADF write", "EBADF read", "EBADF fsync"]);
    assert!(std::fs::read(root.path().join("empty.txt")).unwrap().is_empty());
}

#[test]
fn file_handle_close_during_option_getter_drains_the_active_write() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "let h; let closed; require('fs/promises').open('safe.txt', 'w').then(value => { \
           h = value; return h.write(Buffer.from('safe'), { \
             get offset() { closed = h.close(); return 0; }, length: 4 \
           }); \
         }).then(result => { console.log(result.bytesWritten); return closed; }) \
         .then(() => console.log(h.fd));",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("close cannot release an active descriptor");
    assert_eq!(output, ["4", "-1"]);
    assert_eq!(std::fs::read(root.path().join("safe.txt")).unwrap(), b"safe");
}

#[test]
fn file_handle_open_does_not_grant_write_authority() {
    let root = tempfile::tempdir().expect("sandbox");
    let result = run(
        "require('fs/promises').open('forbidden.txt', 'w');",
        root.path(),
        &["fs_read"],
    );
    assert!(!root.path().join("forbidden.txt").exists());
    let error = result.expect_err("FsWrite is required by the native open operation");
    assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
}

#[test]
fn file_handle_globals_are_not_captured_from_guest_lexical_bindings() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "const Buffer = 'guest'; const Error = 'guest'; const RangeError = 'guest'; \
         const Promise = 'guest'; const Reflect = 'guest'; let h; \
         require('fs/promises').open('shadow.txt', 'w+').then(value => { \
           h = value; return h.write('ok'); \
         }).then(() => h.read({position: 0})).then(result => { \
           console.log(result.bytesRead, result.buffer.length); return h.close(); \
         });",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("facade helpers use realm globals");
    assert_eq!(output, ["2 16384"]);
    assert_eq!(std::fs::read(root.path().join("shadow.txt")).unwrap(), b"ok");
}

#[test]
fn file_handle_array_buffer_views_use_byte_windows_and_keep_identity() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("views.txt"), b"abcdef").unwrap();
    let output = run(
        "let h; const bytes = new Uint8Array(12); bytes.fill(45); \
         const words = new Uint16Array(bytes.buffer, 2, 3); \
         const view = new DataView(bytes.buffer, 3, 4); \
         require('fs/promises').open('views.txt', 'r+').then(value => { \
           h = value; return h.read(words, {offset: 1, length: 4, position: 1}); \
         }).then(result => { \
           console.log(result.bytesRead, result.buffer === words); \
           console.log(Buffer.from(bytes.buffer).toString('hex')); \
           return h.write(view, 1, 2, 0); \
         }).then(result => { \
           console.log(result.bytesWritten, result.buffer === view); return h.close(); \
         });",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("native ArrayBufferView descriptor operations");
    assert_eq!(output, ["4 true", "2d2d2d626364652d2d2d2d2d", "2 true"]);
    assert_eq!(std::fs::read(root.path().join("views.txt")).unwrap(), b"cdcdef");
}

#[test]
fn file_handle_vectors_and_sync_exports_accept_mixed_byte_views() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "const fs = require('node:fs'); let h; \
         const bytes = new Uint8Array([33, 65, 66, 67, 68, 33]); \
         const parts = [new DataView(bytes.buffer, 1, 2), \
           new Uint16Array(bytes.buffer, 2, 1), new Uint8Array(0)]; \
         const out = new Uint8Array(8); out.fill(45); \
         const targets = [new Uint16Array(out.buffer, 2, 1), new DataView(out.buffer, 5, 2)]; \
         fs.promises.open('vectors.txt', 'w+').then(value => { \
           h = value; return h.writev(parts, 0); \
         }).then(result => { \
           console.log(result.bytesWritten, result.buffers === parts); \
           return h.readv(targets, 0); \
         }).then(result => { \
           console.log(result.bytesRead, result.buffers === targets); \
           console.log(Buffer.from(out.buffer).toString()); \
           console.log(fs.writevSync(h.fd, parts, 0), fs.readvSync(h.fd, targets, 0)); \
           return h.close(); \
         });",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("native mixed view vector operations");
    assert_eq!(output, ["4 true", "4 true", "--AB-BC-", "4 4"]);
    assert_eq!(std::fs::read(root.path().join("vectors.txt")).unwrap(), b"ABBC");
}

#[test]
fn file_handle_whole_file_and_iterable_writes_preserve_view_bytes() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "let h; const bytes = new Uint8Array([33, 33, 65, 66, 67, 68, 33, 33]); \
         const words = new Uint16Array(bytes.buffer, 2, 2); \
         const view = new DataView(bytes.buffer, 3, 2); \
         require('fs/promises').open('chunks.txt', 'w+').then(value => { \
           h = value; return h.writeFile(words); \
         }).then(() => h.appendFile(view)) \
         .then(() => h.writeFile([words, view])) \
         .then(() => h.close()).then(() => console.log('closed'));",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("native byte views and iterable chunks");
    assert_eq!(output, ["closed"]);
    assert_eq!(
        std::fs::read(root.path().join("chunks.txt")).unwrap(),
        b"ABCDBCABCDBC"
    );
}

#[test]
fn file_handle_read_file_preserves_multichunk_utf8_and_cursor() {
    let root = tempfile::tempdir().expect("sandbox");
    let text = format!("#{}\u{20ac}{}", "x".repeat(16383), "\u{1f603}".repeat(9000));
    std::fs::write(root.path().join("unicode.txt"), &text).unwrap();
    let output = run(
        "let h; require('fs/promises').open('unicode.txt').then(value => { \
           h = value; return h.read(Buffer.alloc(1)); \
         }).then(result => { \
           console.log(result.bytesRead, result.buffer.toString()); return h.readFile('utf8'); \
         }).then(text => { \
           console.log(text.length, text.charCodeAt(16383), text.charCodeAt(16384), \
             text.charCodeAt(text.length - 1)); return h.readFile(); \
         }).then(empty => { console.log(empty.length); return h.close(); });",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("descriptor contents are assembled before decoding");
    assert_eq!(output, ["1 #", "34384 8364 55357 56835", "0"]);
    assert_eq!(
        std::fs::read_to_string(root.path().join("unicode.txt")).unwrap(),
        text
    );
}

#[test]
fn file_handle_single_nonempty_vector_preserves_view_offsets_and_short_read_tail() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "let h; const data = Buffer.from('ABCD'); \
         const parts = [Buffer.alloc(0), data, new Uint8Array(0)]; \
         const out = new Uint8Array(8); out.fill(45); \
         const target = new DataView(out.buffer, 2, 4); \
         const targets = [new Uint8Array(0), target, Buffer.alloc(0)]; \
         require('fs/promises').open('single.txt', 'w+').then(value => { \
           h = value; return h.writev(parts, 0); \
         }).then(result => { \
           console.log(result.bytesWritten, result.buffers === parts); return h.readv(targets, 1); \
         }).then(result => { \
           console.log(result.bytesRead, result.buffers === targets); \
           console.log(Buffer.from(out.buffer).toString()); return h.close(); \
         });",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("single-window vector descriptor operations");
    assert_eq!(output, ["4 true", "3 true", "--BCD---"]);
    assert_eq!(std::fs::read(root.path().join("single.txt")).unwrap(), b"ABCD");
}
