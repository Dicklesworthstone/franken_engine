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
