//! Iterable filesystem writes through the native orchestrator and sandbox.
//! Run: rch exec -- cargo test -p frankenengine-engine --test fs_streaming_writes
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
        extension_id: "fs-streaming-writes-regression".into(),
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
fn synchronous_chunks_preserve_encoding_and_private_handle_dispatch() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        r#"
        const fs = require('fs/promises');
        async function main() {
          const h = await fs.open('data.txt', 'w');
          h.writeFile = () => { throw new Error('public replacement'); };
          await fs.writeFile(h, ['41', Buffer.from('B'), '43'], 'hex');
          await fs.appendFile(h, ['!', '?']);
          await h.close();
          console.log(h.fd);
        }
        main();
        "#,
        root.path(),
        &["fs_write"],
    )
    .expect("iterables use private descriptor operations");
    assert_eq!(output, ["-1"]);
    assert_eq!(std::fs::read(root.path().join("data.txt")).unwrap(), b"ABC!?");
}

#[test]
fn asynchronous_producer_drains_before_a_requested_close() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        r#"
        const fs = require('node:fs/promises');
        async function main() {
          const h = await fs.open('data.txt', 'w');
          let release;
          const gate = new Promise(resolve => { release = resolve; });
          async function* chunks() { yield await gate; yield 'tail'; }
          const writing = h.writeFile(chunks());
          const closing = h.close();
          console.log(h.fd);
          release('head');
          await writing;
          await closing;
          try { await h.writeFile(['late']); }
          catch (error) { console.log(error.code); }
        }
        main();
        "#,
        root.path(),
        &["fs_write"],
    )
    .expect("the active writer retains descriptor ownership through await");
    assert_eq!(output, ["-1", "EBADF"]);
    assert_eq!(std::fs::read(root.path().join("data.txt")).unwrap(), b"headtail");
}

#[test]
fn invalid_stream_chunk_runs_generator_cleanup_and_keeps_handle_usable() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        r#"
        async function main() {
          const h = await require('fs/promises').open('data.txt', 'w');
          let finalized = false;
          async function* chunks() {
            try { yield 'first'; yield {}; yield 'never'; }
            finally { await Promise.resolve(); finalized = true; }
          }
          try { await h.writeFile(chunks()); }
          catch (error) { console.log(error.code, finalized); }
          await h.writeFile(['last']);
          await h.close();
        }
        main();
        "#,
        root.path(),
        &["fs_write"],
    )
    .expect("IteratorClose completes before write rejection");
    assert_eq!(output, ["ERR_INVALID_ARG_TYPE true"]);
    assert_eq!(std::fs::read(root.path().join("data.txt")).unwrap(), b"firstlast");
}

#[test]
fn abort_of_a_pending_source_does_not_write_its_late_chunk() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        r#"
        async function main() {
          const h = await require('fs/promises').open('data.txt', 'w');
          const controller = new AbortController();
          let release;
          let finalized = false;
          const gate = new Promise(resolve => { release = resolve; });
          async function* chunks() {
            try { yield await gate; }
            finally { finalized = true; }
          }
          const writing = h.writeFile(chunks(), {signal: controller.signal});
          controller.abort('stop');
          const closing = h.close();
          release('forbidden');
          try { await writing; }
          catch (error) { console.log(error.code, error.cause, finalized); }
          await closing;
        }
        main();
        "#,
        root.path(),
        &["fs_write"],
    )
    .expect("cancellation is checked when the source resumes");
    assert_eq!(output, ["ABORT_ERR stop true"]);
    assert!(std::fs::read(root.path().join("data.txt")).unwrap().is_empty());
}

#[test]
fn iterator_protocol_keys_are_not_taken_from_guest_lexical_symbol() {
    let root = tempfile::tempdir().expect("sandbox");
    let output = run(
        r#"
        const Symbol = 'guest';
        async function main() {
          const h = await require('fs/promises').open('data.txt', 'w');
          await h.writeFile(['one', 'two']);
          await h.close();
          console.log(Symbol);
        }
        main();
        "#,
        root.path(),
        &["fs_write"],
    )
    .expect("filesystem iterator keys come from the realm");
    assert_eq!(output, ["guest"]);
    assert_eq!(std::fs::read(root.path().join("data.txt")).unwrap(), b"onetwo");
}

#[test]
fn iterable_writes_cannot_create_a_file_without_filesystem_write_authority() {
    let root = tempfile::tempdir().expect("sandbox");
    let result = run(
        "require('fs/promises').open('denied.txt', 'w').then(h => h.writeFile(['data']));",
        root.path(),
        &["fs_read"],
    );
    assert!(!root.path().join("denied.txt").exists());
    let error = result.expect_err("FsWrite is still required");
    assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
}
