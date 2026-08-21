//! End-to-end proof for the Buffer identity / binary-bytes pair of the
//! bd-b0hm6 fs compat corpus (fixtures 0004 + 0038), on the orchestrated
//! product path (bd-zco6t).
//!
//! Each test executes the fixture source VERBATIM (the `const fs =
//! require('fs')` alias form included) through `ExecutionOrchestrator::execute`
//! with a real `SandboxedHostIo` provider — no mocks, no hand-built IR — and
//! asserts the exact console output the Node reference produces, plus the raw
//! bytes on the real sandbox filesystem.

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

/// Corpus fixture 0004_fs_readfilesync.js (verbatim): a no-encoding
/// `readFileSync` must return a real Buffer — `Buffer.isBuffer` recognizes it
/// and `.toString()` utf8-decodes the actual file contents.
#[test]
fn fixture_0004_readfilesync_returns_buffer_identity_bd_zco6t() {
    let (root, result) = run_fixture(
        "fe_zco6t_0004",
        "const fs = require('fs');\n\
         fs.writeFileSync('buf.txt', 'buffer bytes');\n\
         const buf = fs.readFileSync('buf.txt');\n\
         console.log(Buffer.isBuffer(buf));\n\
         console.log(buf.toString());\n",
    );

    assert_eq!(
        console_messages(&result),
        vec!["true", "buffer bytes"],
        "Node reference output: Buffer.isBuffer(buf) === true, buf.toString() === contents"
    );
    assert_eq!(
        std::fs::read(root.join("buf.txt")).expect("fixture file on disk"),
        b"buffer bytes",
        "writeFileSync must have produced the real file in the sandbox"
    );
}

/// Corpus fixture 0038_fs_writefilesync.js (verbatim): writing a
/// `Buffer.from([0, 1, 127, 128, 255])` must store the RAW bytes (no utf8
/// mangling of 128/255), and the round-tripped Buffer exposes `.length` and
/// `Array.from` element access over those exact bytes.
#[test]
fn fixture_0038_writefilesync_roundtrips_binary_bytes_bd_zco6t() {
    let (root, result) = run_fixture(
        "fe_zco6t_0038",
        "const fs = require('fs');\n\
         fs.writeFileSync('bytes.bin', Buffer.from([0, 1, 127, 128, 255]));\n\
         const buf = fs.readFileSync('bytes.bin');\n\
         console.log(buf.length);\n\
         console.log(Array.from(buf).join(','));\n",
    );

    assert_eq!(
        console_messages(&result),
        vec!["5", "0,1,127,128,255"],
        "Node reference output: byte length 5 and the exact binary byte values"
    );
    // The crux of the fixture: bytes 128 and 255 must land on disk raw, not
    // as their multi-byte UTF-8 encodings.
    assert_eq!(
        std::fs::read(root.join("bytes.bin")).expect("fixture file on disk"),
        vec![0u8, 1, 127, 128, 255],
        "writeFileSync(Buffer) must write the raw binary bytes"
    );
}
