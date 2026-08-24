//! End-to-end proof for bd-b0hm6 fs compat corpus fixture 0030
//! (`fs.promises` mkdir → writeFile ×2 → readdir promise chain) on the
//! orchestrated product path (bd-zco6t).
//!
//! The fixture is the corpus's Promise-chain microtask-drainage probe: every
//! `.then` handler RETURNS another fs.promises Promise, so each derived
//! promise must adopt the returned promise's eventual state (not fulfill with
//! the Promise object), and the event loop must drain the whole chain to
//! idle after top-level evaluation before the run report is finalized. The
//! test executes the fixture source VERBATIM through
//! `ExecutionOrchestrator::execute` with a real `SandboxedHostIo` — no mocks
//! — and asserts the exact Node reference console output plus the real
//! directory contents in the sandbox.

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

/// Corpus fixture 0030_fs_promises_readdir.js (verbatim): the four-link
/// fs.promises chain must drain to idle, each handler-returned Promise must
/// be adopted, and the final handler prints the sorted directory listing.
#[test]
fn fixture_0030_fs_promises_chain_drains_to_idle_bd_zco6t() {
    let (root, result) = run_fixture(
        "fe_zco6t_0030",
        "const fs = require('fs');\n\
         fs.promises.mkdir('pdir')\n\
           .then(() => fs.promises.writeFile('pdir/one.txt', '1'))\n\
           .then(() => fs.promises.writeFile('pdir/two.txt', '2'))\n\
           .then(() => fs.promises.readdir('pdir'))\n\
           .then((names) => console.log(names.sort().join(',')));\n",
    );

    // Every link performed its real filesystem effect before the loop went
    // idle — the drainage proof is that the LAST link's data exists and the
    // handler observed it.
    assert!(
        root.join("pdir").is_dir(),
        "fs.promises.mkdir must create the real directory"
    );
    assert_eq!(
        std::fs::read(root.join("pdir/one.txt")).expect("first chained write on disk"),
        b"1",
        "the first chained writeFile must land before the chain continues"
    );
    assert_eq!(
        std::fs::read(root.join("pdir/two.txt")).expect("second chained write on disk"),
        b"2",
        "the second chained writeFile must land before readdir runs"
    );
    assert_eq!(
        console_messages(&result),
        vec!["one.txt,two.txt"],
        "Node reference output: the final handler prints the sorted readdir names, \
         proving each handler-returned Promise was adopted and the microtask \
         chain drained to idle"
    );
}

/// Adoption ordering probe for the same surface: a value queued by a plain
/// resolved-Promise handler AFTER the chain starts must still print before
/// the chain's final link (the chain is length 4; the plain microtask runs in
/// the first checkpoint). This pins that fs.promises links neither starve the
/// queue nor complete synchronously.
#[test]
fn fixture_0030_chain_interleaves_with_plain_microtasks_bd_zco6t() {
    let (root, result) = run_fixture(
        "fe_zco6t_0030_interleave",
        "const fs = require('fs');\n\
         fs.promises.mkdir('d')\n\
           .then(() => fs.promises.writeFile('d/f.txt', 'x'))\n\
           .then(() => fs.promises.readdir('d'))\n\
           .then((names) => console.log('chain:' + names.join(',')));\n\
         Promise.resolve('plain').then((v) => console.log(v));\n\
         console.log('sync');\n",
    );

    let messages = console_messages(&result);
    assert_eq!(
        messages.first().copied(),
        Some("sync"),
        "top-level synchronous output precedes every microtask"
    );
    assert!(
        messages.contains(&"plain") && messages.contains(&"chain:f.txt"),
        "both the plain microtask and the fs.promises chain must complete: {messages:?}"
    );
    let plain_index = messages.iter().position(|m| *m == "plain").expect("plain");
    let chain_index = messages
        .iter()
        .position(|m| *m == "chain:f.txt")
        .expect("chain");
    assert!(
        plain_index < chain_index,
        "a plain single-hop microtask must not be starved behind the multi-hop \
         fs.promises chain: {messages:?}"
    );
    assert_eq!(
        std::fs::read(root.join("d/f.txt")).expect("chained write on disk"),
        b"x",
        "the chained write must have really landed"
    );
}


/// An async function returning a native fs.promises promise must adopt its
/// eventual value (ES2020 async-function-completion semantics).
#[test]
fn async_function_returning_native_promise_adopts_value_bd_zco6t() {
    let (root, result) = run_fixture(
        "fe_zco6t_async_adopt",
        "const fs = require('fs');\n\
         async function main() {\n\
           await fs.promises.mkdir('ad');\n\
           await fs.promises.writeFile('ad/x.txt', 'v');\n\
           return fs.promises.readdir('ad');\n\
         }\n\
         main().then((names) => console.log(names.join(',')));\n",
    );

    assert_eq!(
        console_messages(&result),
        vec!["x.txt"],
        "the async function's returned readdir promise must be adopted so its \
         resolved names array reaches the chain"
    );
    assert_eq!(
        std::fs::read(root.join("ad/x.txt")).expect("async-chained write on disk"),
        b"v",
        "the awaited write must have really landed"
    );
}
