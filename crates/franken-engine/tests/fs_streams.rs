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
