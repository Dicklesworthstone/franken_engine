//! Whole-file FileHandle I/O through the real sandboxed orchestrator.
//! Run with: rch exec -- cargo test -p frankenengine-engine --test fs_file_handle_contents
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
        extension_id: "fs-file-handle-contents-regression".into(),
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
fn whole_file_methods_preserve_cursor_and_do_not_truncate() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("data.txt"), b"abcdefghij").unwrap();
    let output = run(
        "let h; require('node:fs/promises').open('data.txt', 'r+').then(value => { \
           h = value; return h.read(Buffer.alloc(2)); \
         }).then(() => h.writeFile('XY')).then(value => { \
           console.log(typeof value); return h.appendFile(Buffer.from('Z')); \
         }).then(() => h.readFile('utf8')).then(text => { \
           console.log(text); return h.readFile(); \
         }).then(bytes => { \
           console.log(Buffer.isBuffer(bytes), bytes.length); return h.close(); \
         }).then(() => console.log(h.fd));",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("whole-file native descriptor lifecycle");
    assert_eq!(output, ["undefined", "fghij", "true 0", "-1"]);
    assert_eq!(
        std::fs::read(root.path().join("data.txt")).unwrap(),
        b"abXYZfghij"
    );
}

#[test]
fn append_file_uses_descriptor_open_flags_and_encoding() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("data.txt"), b"prefix").unwrap();
    let output = run(
        "let h; require('fs/promises').open('data.txt', 'a').then(value => { \
           h = value; return h.appendFile('4142', 'hex'); \
         }).then(() => h.writeFile('!')).then(() => h.close()) \
         .then(() => console.log('done'));",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("append flag stays on the native descriptor");
    assert_eq!(output, ["done"]);
    assert_eq!(
        std::fs::read(root.path().join("data.txt")).unwrap(),
        b"prefixAB!"
    );
}

#[test]
fn cancelled_and_closed_whole_file_operations_leave_the_file_unchanged() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "let h; require('fs/promises').open('empty.txt', 'w+').then(value => { \
           h = value; return h.writeFile('forbidden', {signal: {aborted: true, reason: 'stop'}}); \
         }).catch(error => { \
           console.log(error.name, error.code, error.cause); return h.close(); \
         }).then(() => h.readFile()).catch(error => { \
           console.log(error.code); return h.writeFile('late'); \
         }).catch(error => { \
           console.log(error.code); return h.appendFile('late'); \
         }).catch(error => console.log(error.code));",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("cancellation and closed-handle rejections");
    assert_eq!(output, ["AbortError ABORT_ERR stop", "EBADF", "EBADF", "EBADF"]);
    assert!(std::fs::read(root.path().join("empty.txt")).unwrap().is_empty());
}

#[test]
fn close_from_a_whole_file_option_getter_waits_for_the_write() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "let h; let closing; require('fs/promises').open('data.txt', 'w').then(value => { \
           h = value; return h.writeFile('safe', { \
             get encoding() { closing = h.close(); return 'utf8'; } \
           }); \
         }).then(() => closing).then(() => console.log(h.fd));",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("a pending operation retains ownership across getters");
    assert_eq!(output, ["-1"]);
    assert_eq!(std::fs::read(root.path().join("data.txt")).unwrap(), b"safe");
}

#[test]
fn a_write_grant_does_not_authorize_whole_file_reads() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("data.txt"), b"data").unwrap();
    let error = run(
        "require('fs/promises').open('data.txt', 'r').then(h => h.readFile());",
        root.path(),
        &["fs_write"],
    )
    .expect_err("readFile must still require FsRead");
    assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
}

#[test]
fn file_handle_vectors_preserve_offsets_and_buffer_identity() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("data.txt"), b"abcdefghij").unwrap();
    let output = run(
        "const Array = 'guest'; let h; \
         const input = [Buffer.from('XY'), Buffer.alloc(0), Buffer.from('Z')]; \
         const output = [Buffer.alloc(2, 45), Buffer.alloc(0), Buffer.alloc(5, 45)]; \
         require('fs/promises').open('data.txt', 'r+').then(value => { \
           h = value; return h.writev(input, 2); \
         }).then(result => { \
           console.log(result.bytesWritten, result.buffers === input); return h.readv(output, 6); \
         }).then(result => { \
           console.log(result.bytesRead, result.buffers === output); \
           console.log(output[0].toString(), output[2].toString()); return h.read(Buffer.alloc(2)); \
         }).then(result => { console.log(result.buffer.toString()); return h.close(); });",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("vector methods route through native descriptor effects");
    assert_eq!(output, ["3 true", "4 true", "gh ij---", "ab"]);
    assert_eq!(
        std::fs::read(root.path().join("data.txt")).unwrap(),
        b"abXYZfghij"
    );
}

#[test]
fn file_handle_vectors_validate_all_entries_before_io() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "let h; require('fs/promises').open('empty.txt', 'w+').then(value => { \
           h = value; return h.writev([Buffer.from('not written'), 'invalid']); \
         }).catch(error => { \
           console.log(error.code); return h.readv([Buffer.alloc(2), 1]); \
         }).catch(error => { console.log(error.code); return h.close(); });",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("invalid vector inputs reject without partial I/O");
    assert_eq!(output, ["ERR_INVALID_ARG_TYPE", "ERR_INVALID_ARG_TYPE"]);
    assert!(std::fs::read(root.path().join("empty.txt")).unwrap().is_empty());
}

#[test]
fn a_vector_entry_getter_cannot_close_the_active_descriptor() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "let h; let closing; require('fs/promises').open('data.txt', 'w').then(value => { \
           h = value; const buffers = [Buffer.from('ab')]; \
           Object.defineProperty(buffers, '1', {get() { \
             closing = h.close(); return Buffer.from('cd'); \
           }}); return h.writev(buffers); \
         }).then(result => { console.log(result.bytesWritten); return closing; }) \
         .then(() => console.log(h.fd));",
        root.path(),
        &["fs_read", "fs_write"],
    )
    .expect("vector admission pins its descriptor across getters");
    assert_eq!(output, ["4", "-1"]);
    assert_eq!(std::fs::read(root.path().join("data.txt")).unwrap(), b"abcd");
}

#[test]
fn vector_reads_do_not_inherit_write_authority() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("data.txt"), b"data").unwrap();
    let error = run(
        "require('fs/promises').open('data.txt', 'r').then(h => h.readv([Buffer.alloc(4)]));",
        root.path(),
        &["fs_write"],
    )
    .expect_err("nonempty readv must require FsRead");
    assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
}
