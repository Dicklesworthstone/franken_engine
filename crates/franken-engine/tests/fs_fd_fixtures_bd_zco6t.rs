//! End-to-end proof for bd-b0hm6 fs compat corpus fixtures 0021–0023
//! (numeric fd lifecycle + positional Buffer mutation) on the orchestrated
//! product path (bd-zco6t).
//!
//! Each test executes its fixture VERBATIM through
//! `ExecutionOrchestrator::execute` with a real `SandboxedHostIo`, exercising
//! the full wiring landed with this change: `fs_sync_builtin_spec` rows →
//! NUL-sentinel `FsOperation` discriminators → the interpreter's fd-shaped
//! dispatch → `FsMeta` effects → the sandbox fd table.

#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt,
    OrchestratorConfig, OrchestratorResult,
};
use frankenengine_extension_host::host_io::{
    HostIoRecorder, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn sandbox_root(name: &str) -> PathBuf {
    let mut root = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_nanos();
    root.push(format!("{name}_{}_{}", std::process::id(), nonce));
    std::fs::create_dir_all(&root).expect("sandbox root should be creatable");
    root
}

fn run_fixture(name: &str, source: &str) -> (PathBuf, OrchestratorResult) {
    let root = sandbox_root(name);
    let provider = Arc::new(SandboxedHostIo::with_root(&root).expect("sandboxed provider"));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());

    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    orchestrator.set_host_io(provider, Some(recorder_dyn));

    let package = ExtensionPackage {
        extension_id: format!("{name}-e2e"),
        source: source.to_string(),
        source_file: None,
        module_root: None,
        capabilities: vec![
            "vm_dispatch".to_string(),
            "heap_allocate".to_string(),
            // `Buffer.alloc` rewrites to the `builtin:BufferAlloc` hostcall,
            // which the registry gates on the canonical Builtin authority —
            // the same grant the asw4m.3 / zyndq fixtures carry. It is NOT
            // folded into heap_allocate.
            "builtin".to_string(),
            "console".to_string(),
            "fs_read".to_string(),
            "fs_write".to_string(),
        ],
        version: "1.0.0".to_string(),
        metadata: BTreeMap::new(),
    };

    let result = orchestrator
        .execute(&package)
        .expect("corpus fixture source must execute through the product stack");
    (root, result)
}

fn console_messages(result: &OrchestratorResult) -> Vec<&str> {
    result
        .console_output
        .iter()
        .map(|entry| entry.message.as_str())
        .collect()
}

/// Corpus fixture 0021_fs_writesync.js (verbatim): openSync('w') hands out a
/// numeric fd, writeSync returns the byte count, closeSync releases the fd,
/// and the bytes are really on disk.
#[test]
fn fixture_0021_writesync_returns_count_bd_zco6t() {
    let (root, result) = run_fixture(
        "fe_zco6t_0021",
        "const fs = require('fs');\n\
         const fd = fs.openSync('fd.txt', 'w');\n\
         const n = fs.writeSync(fd, 'fd write');\n\
         fs.closeSync(fd);\n\
         console.log(n);\n\
         console.log(fs.readFileSync('fd.txt', 'utf8'));\n",
    );
    assert_eq!(
        console_messages(&result),
        vec!["8", "fd write"],
        "Node reference output: the write count then the file contents"
    );
    assert_eq!(
        std::fs::read(root.join("fd.txt")).expect("fixture file on disk"),
        b"fd write",
        "the fd write must have produced the real file"
    );
}

/// Corpus fixture 0022_fs_readsync.js (verbatim): a positional readSync into
/// a Buffer window — 4 bytes at position 2 of "abcdefgh" mutate the guest
/// Buffer in place ("cdef") and the call evaluates to the count.
#[test]
fn fixture_0022_readsync_positional_buffer_mutation_bd_zco6t() {
    let (_root, result) = run_fixture(
        "fe_zco6t_0022",
        "const fs = require('fs');\n\
         fs.writeFileSync('r.txt', 'abcdefgh');\n\
         const fd = fs.openSync('r.txt', 'r');\n\
         const buf = Buffer.alloc(4);\n\
         const n = fs.readSync(fd, buf, 0, 4, 2);\n\
         fs.closeSync(fd);\n\
         console.log(n);\n\
         console.log(buf.toString('utf8'));\n",
    );
    assert_eq!(
        console_messages(&result),
        vec!["4", "cdef"],
        "Node reference output: 4 bytes read positionally into the Buffer window"
    );
}

/// Corpus fixture 0023_fs_fsyncsync.js (verbatim): write through the fd,
/// fsyncSync flushes, and the durable contents read back.
#[test]
fn fixture_0023_fsyncsync_durable_bd_zco6t() {
    let (root, result) = run_fixture(
        "fe_zco6t_0023",
        "const fs = require('fs');\n\
         const fd = fs.openSync('sync.txt', 'w');\n\
         fs.writeSync(fd, 'durable');\n\
         fs.fsyncSync(fd);\n\
         fs.closeSync(fd);\n\
         console.log(fs.readFileSync('sync.txt', 'utf8'));\n",
    );
    assert_eq!(
        console_messages(&result),
        vec!["durable"],
        "Node reference output: the fsynced contents read back"
    );
    assert_eq!(
        std::fs::read(root.join("sync.txt")).expect("fixture file on disk"),
        b"durable",
        "the fsynced bytes must be on the real filesystem"
    );
}

/// Lifecycle guard on the same wired path: using a closed fd is a
/// guest-visible EBADF filesystem error, not a silent no-op.
#[test]
fn closed_fd_is_guest_visible_ebadf_bd_zco6t() {
    let (_root, result) = run_fixture(
        "fe_zco6t_stale_fd",
        "const fs = require('fs');\n\
         const fd = fs.openSync('gone.txt', 'w');\n\
         fs.closeSync(fd);\n\
         try {\n\
           fs.writeSync(fd, 'late');\n\
           console.log('unreachable');\n\
         } catch (error) {\n\
           console.log('caught:' + (String(error).includes('EBADF')));\n\
         }\n",
    );
    assert_eq!(
        console_messages(&result),
        vec!["caught:true"],
        "a stale fd write must throw a catchable EBADF error"
    );
}
