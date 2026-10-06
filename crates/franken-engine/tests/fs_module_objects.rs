//! First-class fs methods must traverse the real, capability-gated host seam.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt,
    OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    HostIoRecorder, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn run(source: &str, root: &Path, filesystem_caps: &[&str]) -> Result<Vec<String>, String> {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox provider"));
    let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    orchestrator.set_host_io(provider, Some(recorder));
    let mut capabilities: Vec<String> = ["vm_dispatch", "heap_allocate", "builtin", "console"]
        .into_iter()
        .map(str::to_string)
        .collect();
    capabilities.extend(filesystem_caps.iter().map(|capability| (*capability).to_string()));
    let package = ExtensionPackage {
        extension_id: "fs-module-object-regression".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities,
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = orchestrator.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok(result.console_output.into_iter().map(|entry| entry.message).collect())
}

#[test]
fn module_values_and_extracted_functions_need_no_filesystem_authority() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "const fs = require('fs'); const {readFileSync: read} = fs; \
         function load() { return require('node:fs'); } \
         console.log(typeof fs, typeof read, load() === fs); \
         console.log(require('fs/promises') === fs.promises, \
           require('node:fs/promises') === fs.promises, \
           fs.promises.constants === fs.constants);",
        root.path(), &[],
    ).expect("constructing a module grants no host authority");
    assert_eq!(output, ["object function true", "true true true"]);
    assert_eq!(std::fs::read_dir(root.path()).expect("directory").count(), 0);
}

#[test]
fn extracted_read_functions_execute_with_only_read_authority() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("input.txt"), "native bytes").expect("input");
    let output = run(
        "const {readFileSync: read, statSync: stat} = require('fs'); \
         function invoke(f) { return f('input.txt', 'utf8'); } \
         console.log(invoke(read), stat('input.txt').size); \
         console.log((() => require('node:fs'))().readFileSync === read);",
        root.path(), &["fs_read"],
    ).expect("first-class read traverses the real provider");
    assert_eq!(output, ["native bytes 12", "true"]);
}

#[test]
fn extracted_writes_and_descriptor_methods_modify_real_files() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "const fs = require('fs'); const {writeFileSync: write, appendFileSync: append, \
         openSync: open, writeSync: put, closeSync: close, readFileSync: read} = fs; \
         write('result.txt', 'one'); append('result.txt', '-two'); \
         const fd = open('fd.txt', 'w'); console.log(put(fd, 'fd-data')); close(fd); \
         console.log(read('result.txt', 'utf8'), read('fd.txt', 'utf8'));",
        root.path(), &["fs_read", "fs_write"],
    ).expect("writes execute through native host I/O");
    assert_eq!(output, ["7", "one-two fd-data"]);
    assert_eq!(std::fs::read(root.path().join("result.txt")).expect("written"), b"one-two");
    assert_eq!(std::fs::read(root.path().join("fd.txt")).expect("fd written"), b"fd-data");
}

#[test]
fn first_class_writes_do_not_gain_authority_from_the_module_object() {
    let root = tempfile::tempdir().expect("sandbox");
    let result = run(
        "const write = require('fs').writeFileSync; \
         write('forbidden.txt', 'not permitted'); console.log('authority bypass');",
        root.path(), &["fs_read"],
    );
    assert!(!root.path().join("forbidden.txt").exists(), "denied write reached disk");
    let error = result.expect_err("invoking an extracted writer needs FsWrite authority");
    assert!(
        error.to_ascii_lowercase().contains("capabil"),
        "must fail for authority, not an unrelated parse/lowering error: {error}"
    );
}

#[test]
fn nested_and_bound_callbacks_retain_native_deferred_completion() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("input.txt"), "callback bytes").expect("input");
    let output = run(
        "function load() { return require('fs').readFile; } \
         let inline = true; \
         function done(label, error, value) { console.log(label, inline, error, value); } \
         load()('input.txt', 'utf8', done.bind(null, 'read')); \
         inline = false; console.log('scheduled');",
        root.path(), &["fs_read"],
    ).expect("native callback queue drains");
    assert_eq!(output, ["scheduled", "read false null callback bytes"]);
}

#[test]
fn invalid_callbacks_are_rejected_before_writing() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "const {writeFile: write} = require('fs'); \
         try { write('invalid.txt', 'bad', 3); } \
         catch (error) { console.log(error instanceof TypeError, error.code); }",
        root.path(), &["fs_read", "fs_write"],
    ).expect("argument validation is catchable");
    assert_eq!(output, ["true ERR_INVALID_ARG_TYPE"]);
    assert!(!root.path().join("invalid.txt").exists());
}

#[test]
fn filesystem_promise_errors_reject_and_metadata_methods_return_promises() {
    let root = tempfile::tempdir().expect("sandbox");
    std::fs::write(root.path().join("input.txt"), "promise bytes").expect("input");
    let output = run(
        "const {readFile: read, stat} = require('fs/promises'); \
         const pending = read('input.txt', 'utf8'); console.log(pending instanceof Promise); \
         pending.then(value => console.log(value)).then(() => stat('input.txt')) \
         .then(info => console.log(info.size)).then(() => read('absent.txt')) \
         .catch(error => console.log(error.code));",
        root.path(), &["fs_read"],
    ).expect("promises settle through the engine");
    assert_eq!(output, ["true", "promise bytes", "13", "ENOENT"]);
}

#[test]
fn lexical_require_is_not_replaced_and_guest_globals_do_not_capture_the_facade() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        "const Promise = 'guest'; const Reflect = 'guest'; const Object = 'guest'; \
         function custom(require) { return require('fs'); } \
         console.log(custom(name => 'custom:' + name)); \
         const fs = require('fs'); console.log(typeof fs.readFileSync, fs.constants.R_OK); \
         { const require = name => 'block:' + name; console.log(require('node:fs')); }",
        root.path(), &[],
    ).expect("lexical shadowing is preserved");
    assert_eq!(output, ["custom:fs", "function 4", "block:node:fs"]);
}
