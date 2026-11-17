//! Descriptor metadata uses the same admitted host effect in both engine lanes.
#![forbid(unsafe_code)]
#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    FsMetaResult, FsOperation, HostIoCapability, HostIoError, HostIoOutcome, HostIoRecorder,
    HostIoRequest, HostIoResponse, InMemoryHostIoTranscript, SandboxedHostIo,
};

struct Execution {
    output: Vec<String>,
    entries: Vec<(HostIoRequest, HostIoOutcome)>,
}

fn run(source: &str, root: &Path, lane: LaneChoice) -> Execution {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox provider"));
    let transcript = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder: Arc<dyn HostIoRecorder> = transcript.clone();
    let mut runtime = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        ..OrchestratorConfig::default()
    });
    runtime.set_host_io(provider, Some(recorder));
    let package = ExtensionPackage {
        extension_id: "fs-descriptor-stat".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: [
            "vm_dispatch",
            "heap_allocate",
            "builtin",
            "console",
            "fs_read",
            "fs_write",
        ]
        .into_iter()
        .map(str::to_string)
        .collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = runtime
        .execute(&package)
        .expect("native descriptor metadata execution");
    Execution {
        output: result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect(),
        entries: transcript.recorded_entries(),
    }
}

#[test]
fn fstat_named_exports_preserve_file_identity_cursor_and_callback_completion() {
    let source = r#"
import { openSync, readSync, closeSync, fstatSync, fstat, renameSync, unlinkSync, writeFileSync } from 'node:fs';
const fd = openSync('input.txt', 'r');
const bytes = Buffer.alloc(2);
readSync(fd, bytes, 0, 2, null);
console.log('PREFIX', bytes.toString());
renameSync('input.txt', 'moved.txt');
writeFileSync('input.txt', 'replacement with a different size');
const stats = fstatSync(fd);
console.log('STAT', stats.size, stats.isFile(), stats.isDirectory(), stats.isSymbolicLink());
unlinkSync('moved.txt');
const big = fstatSync(fd, { bigint: true });
console.log('BIG', typeof big.size, String(big.size), typeof big.mode, typeof big.mtimeMs);
readSync(fd, bytes, 0, 2, null);
console.log('CURSOR', bytes.toString());
try { fstatSync(-1); } catch (error) { console.log('INVALID', error.code); }
let returned = false;
const completion = fstat(fd, function (error, result) {
  if (error) throw error;
  console.log('CALLBACK', returned, result.size, result.isFile());
  closeSync(fd);
  fstat(fd, function (error, result) {
    console.log('CLOSED', error.code, result === undefined);
  });
});
console.log('RETURN', completion === undefined);
returned = true;
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        std::fs::write(root.path().join("input.txt"), b"abcdef").unwrap();
        let execution = run(source, root.path(), lane);
        assert_eq!(
            execution.output,
            [
                "PREFIX ab",
                "STAT 6 true false false",
                "BIG bigint 6 bigint bigint",
                "CURSOR cd",
                "INVALID ERR_OUT_OF_RANGE",
                "RETURN true",
                "CALLBACK true 6 true",
                "CLOSED EBADF true",
            ]
        );
        let stats: Vec<_> = execution
            .entries
            .iter()
            .filter(|(request, _)| {
                matches!(
                    request,
                    HostIoRequest::FsMeta {
                        operation: FsOperation::Fstat,
                        ..
                    }
                )
            })
            .collect();
        assert_eq!(
            stats.len(),
            4,
            "invalid input must not dispatch a host effect"
        );
        for (request, _) in &stats {
            assert_eq!(request.required_capability(), HostIoCapability::FsRead);
            let HostIoRequest::FsMeta {
                path,
                arguments,
                data,
                ..
            } = request
            else {
                unreachable!()
            };
            assert_eq!(arguments, &[format!("fd={path}")]);
            assert!(data.is_empty(), "stat must not read file contents");
        }
        for (_, outcome) in &stats[..3] {
            assert!(
                matches!(outcome, Ok(HostIoResponse::FsMeta { result: FsMetaResult::Metadata(value) }) if value.size == 6)
            );
        }
        assert!(matches!(&stats[3].1, Err(HostIoError::Fs { code, .. }) if code == "EBADF"));
        assert_eq!(
            std::fs::read(root.path().join("input.txt")).unwrap(),
            b"replacement with a different size"
        );
    }
}

#[test]
fn file_handle_stat_keeps_ownership_through_options_and_rejects_after_close() {
    let source = r#"
const fs = require('fs');
let handle, closing, reads = 0;
fs.promises.open('owned.txt', 'w').then(function (value) {
  handle = value;
  return handle.write('owned');
}).then(function () {
  Object.defineProperty(handle, 'fd', { value: 999999 });
  fs.fstatSync = function () { throw new Error('public method replaced'); };
  return handle.stat({ get bigint() {
    reads += 1;
    closing = handle.close();
    return true;
  } });
}).then(function (stats) {
  console.log('OWNED', reads, typeof stats.size, String(stats.size), stats.isFile());
  return closing;
}).then(function () {
  return handle.stat();
}).catch(function (error) {
  console.log('CLOSED', error.code, error.syscall);
});
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        let execution = run(source, root.path(), lane);
        assert_eq!(
            execution.output,
            ["OWNED 1 bigint 5 true", "CLOSED EBADF fstat"]
        );
        let operations: Vec<_> = execution
            .entries
            .iter()
            .filter_map(|(request, _)| match request {
                HostIoRequest::FsMeta { operation, .. } => Some(*operation),
                _ => None,
            })
            .collect();
        assert_eq!(
            operations,
            [
                FsOperation::Open,
                FsOperation::WriteFd,
                FsOperation::Fstat,
                FsOperation::CloseFd
            ]
        );
        assert_eq!(
            std::fs::read(root.path().join("owned.txt")).unwrap(),
            b"owned"
        );
    }
}
