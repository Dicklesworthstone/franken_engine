//! Filesystem streams through the real orchestrator and sandboxed host I/O.
//! The JavaScript reference suites do not substitute for running this target.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, OrchestratorConfig,
};
use frankenengine_engine::runtime_config::RuntimeConfig;
use frankenengine_extension_host::host_io::{
    HostIoRecorder, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn run(source: &str, root: &Path, lane: LaneChoice, caps: &[&str]) -> Result<Vec<String>, String> {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox"));
    let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
    let mut runtime = RuntimeConfig::default();
    // Same finite instruction envelope as stream_buffering_hotpaths.
    runtime.execution.deterministic_budget = 200_000_000;
    runtime.execution.throughput_budget = 200_000_000;
    let mut orchestrator = ExecutionOrchestrator::try_new_lab_with_runtime_config(
        OrchestratorConfig {
            force_lane: Some(lane),
            ..OrchestratorConfig::default()
        },
        runtime,
    )
    .expect("stream test configuration");
    orchestrator.set_host_io(provider, Some(recorder));
    let mut capabilities = vec!["vm_dispatch", "heap_allocate", "builtin", "console", "timer"];
    capabilities.extend_from_slice(caps);
    let package = ExtensionPackage {
        extension_id: "native-filesystem-streams".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = orchestrator.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok(result.console_output.into_iter().map(|entry| entry.message).collect())
}

const READ_RANGE: &str = r#"
const fs = require('fs');
const stream = fs.createReadStream('input.txt', {start: 1, end: 5, highWaterMark: 2});
let text = '';
stream.setEncoding('utf8');
stream.on('data', chunk => { text += chunk; });
stream.on('end', () => console.log(text, stream.bytesRead));
stream.on('close', () => console.log(stream.fd, stream.pending));
"#;

#[test]
fn path_read_stream_uses_inclusive_byte_ranges_and_native_decoder() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input.txt"), "Aé€😃Z").unwrap();
        let output = run(READ_RANGE, root.path(), lane, &["fs_read", "fs_write"])
            .expect("native read-stream lifecycle");
        assert_eq!(output, ["é€ 5", "null true"]);
        assert_eq!(std::fs::read_to_string(root.path().join("input.txt")).unwrap(), "Aé€😃Z");
    }
}

const READ_HANDLE: &str = r#"
require('fs/promises').open('input.txt', 'r').then(async handle => {
  const fd = handle.fd;
  const stream = handle.createReadStream({start: 2, end: 4, autoClose: false, highWaterMark: 2});
  let text = '';
  for await (const chunk of stream) text += chunk.toString();
  const result = await handle.read(Buffer.alloc(2));
  console.log(text, result.buffer.toString(), handle.fd === fd);
  await new Promise(resolve => stream.close(resolve));
  console.log(handle.fd);
});
"#;

#[test]
fn handle_read_stream_keeps_its_cursor_and_closes_the_original_owner() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input.txt"), "abcdefghij").unwrap();
        assert_eq!(
            run(READ_HANDLE, root.path(), lane, &["fs_read", "fs_write"])
                .expect("native handle stream"),
            ["cde ab true", "-1"]
        );
    }
}

#[test]
fn stream_factory_does_not_grant_descriptor_or_read_authority() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        for caps in [&["fs_read"][..], &["fs_write"][..]] {
            let root = tempfile::tempdir().unwrap();
            std::fs::write(root.path().join("input.txt"), "private").unwrap();
            let error = run(READ_RANGE, root.path(), lane, caps)
                .expect_err("both existing descriptor and read authorities remain required");
            assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
            assert_eq!(std::fs::read_to_string(root.path().join("input.txt")).unwrap(), "private");
        }
    }
}

const FILE_PIPELINE: &str = r#"
const fs = require('fs');
const stream = require('stream');
const input = fs.createReadStream('input.txt', {highWaterMark: 2048});
const output = fs.createWriteStream('output.txt', {highWaterMark: 16});
stream.promises.pipeline(input, output).then(() => {
  console.log(input.bytesRead, output.bytesWritten, input.fd, output.fd);
});
"#;

#[test]
fn file_pipeline_uses_the_shared_stream_machinery_and_real_descriptor_effects() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        let input = "alpha\n".repeat(3000);
        std::fs::write(root.path().join("input.txt"), &input).unwrap();
        assert_eq!(
            run(FILE_PIPELINE, root.path(), lane, &["fs_read", "fs_write"])
                .expect("native file-to-file pipeline"),
            ["18000 18000 null null"]
        );
        assert_eq!(std::fs::read(root.path().join("output.txt")).unwrap(), input.as_bytes());
    }
}

const CORKED_WRITE: &str = r#"
const fs = require('fs');
const stream = fs.createWriteStream('output.txt', {flush: true, highWaterMark: 2});
let callbacks = 0;
stream.cork();
stream.write('A', () => { callbacks += 1; });
stream.write(Buffer.from([0, 255]), () => { callbacks += 1; });
stream.write('é', () => { callbacks += 1; });
stream.on('close', () => console.log(stream.bytesWritten, callbacks, stream.fd));
stream.end();
"#;

#[test]
fn corked_writes_keep_byte_counts_callbacks_and_flush_close() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        assert_eq!(
            run(CORKED_WRITE, root.path(), lane, &["fs_write"])
                .expect("native corked writes"),
            ["5 3 null"]
        );
        assert_eq!(std::fs::read(root.path().join("output.txt")).unwrap(), b"A\0\xff\xc3\xa9");
    }
}

const WRITE_HANDLE: &str = r#"
require('fs/promises').open('input.txt', 'r+').then(handle => {
  const stream = handle.createWriteStream({start: 1, autoClose: false});
  stream.on('finish', () => console.log(stream.bytesWritten));
  stream.write('XY');
  stream.close(() => console.log(handle.fd));
});
"#;

#[test]
fn handle_write_stream_drains_then_closes_the_same_positioned_owner() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input.txt"), "abcdefghij").unwrap();
        assert_eq!(
            run(WRITE_HANDLE, root.path(), lane, &["fs_write"])
                .expect("native handle writer"),
            ["2", "-1"]
        );
        assert_eq!(std::fs::read_to_string(root.path().join("input.txt")).unwrap(), "aXYdefghij");
    }
}

#[test]
fn write_stream_does_not_grant_filesystem_write_authority() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        let error = run(CORKED_WRITE, root.path(), lane, &[])
            .expect_err("stream construction does not grant FsWrite");
        assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
        assert!(!root.path().join("output.txt").exists());
    }
}
