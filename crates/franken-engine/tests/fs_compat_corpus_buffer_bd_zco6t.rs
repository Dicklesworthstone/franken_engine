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
    run_fixture_with_capabilities(name, source, &[])
}

fn run_fixture_with_capabilities(
    name: &str,
    source: &str,
    additional_capabilities: &[&str],
) -> (PathBuf, OrchestratorResult) {
    let root = sandbox_root(name);
    let provider = Arc::new(SandboxedHostIo::with_root(&root).expect("sandboxed provider"));
    let recorder = Arc::new(InMemoryHostIoTranscript::recording());

    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig::default());
    let recorder_dyn: Arc<dyn HostIoRecorder> = recorder.clone();
    orchestrator.set_host_io(provider, Some(recorder_dyn));

    let mut package = ExtensionPackage {
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

    package.capabilities.extend(
        additional_capabilities
            .iter()
            .map(|capability| (*capability).to_string()),
    );

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

/// UTF-16 file reads must preserve exact JavaScript code units through real
/// host I/O, including lone surrogates, the BOM, and an ignored odd final byte.
#[test]
fn readfilesync_utf16_aliases_preserve_code_units_through_real_io() {
    let (root, result) = run_fixture_with_capabilities(
        "fe_fs_utf16_exact",
        r#"
const fs = require('fs');
const raw = Buffer.from([255, 254, 0, 216, 65, 0, 0, 220, 61, 216, 128, 222, 0, 0, 171]);
fs.writeFileSync('units.bin', raw);
const encodings = ['utf16le', 'UTF16LE', 'utf-16le', 'UTF-16LE', 'ucs2', 'UCS2', 'ucs-2', 'UCS-2'];
for (const encoding of encodings) {
    const text = fs.readFileSync('units.bin', encoding);
    const fromOptions = fs.readFileSync('units.bin', { encoding: encoding });
    if (text !== fromOptions) throw new Error('encoding argument forms differ');
    const units = [];
    for (let i = 0; i < text.length; i++) units.push(text.charCodeAt(i));
    console.log(units.join(','));
    console.log(Buffer.from(text, encoding).toString('hex'));
}
"#,
        &["builtin"],
    );

    let expected = [
        "65279,55296,65,56320,55357,56960,0",
        "fffe00d8410000dc3dd880de0000",
    ]
    .repeat(8);
    assert_eq!(console_messages(&result), expected);
    assert_eq!(
        std::fs::read(root.join("units.bin")).expect("original UTF-16 bytes on disk"),
        vec![255, 254, 0, 216, 65, 0, 0, 220, 61, 216, 128, 222, 0, 0, 171],
        "decoding must not change the file or consume its odd trailing byte"
    );
}
