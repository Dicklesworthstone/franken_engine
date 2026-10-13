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
