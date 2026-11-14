//! Descriptor mutations retain the admitted inode and the ordinary host boundary.
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
    FsMetaResult, FsOperation, HostIoCapability, HostIoOutcome, HostIoRecorder, HostIoRequest,
    HostIoResponse, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn run(
    source: &str,
    root: &Path,
    lane: LaneChoice,
) -> (Vec<String>, Vec<(HostIoRequest, HostIoOutcome)>) {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox provider"));
    let transcript = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder: Arc<dyn HostIoRecorder> = transcript.clone();
    let mut runtime = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        ..OrchestratorConfig::default()
    });
    runtime.set_host_io(provider, Some(recorder));
    let package = ExtensionPackage {
        extension_id: "fs-descriptor-mutations".into(),
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
        .expect("native descriptor mutation execution");
    (
        result
            .console_output
            .into_iter()
            .map(|line| line.message)
            .collect(),
        transcript.recorded_entries(),
    )
}

fn mutations(entries: &[(HostIoRequest, HostIoOutcome)]) -> Vec<FsOperation> {
    entries
        .iter()
        .filter_map(|(request, outcome)| {
            let HostIoRequest::FsMeta {
                operation,
                arguments,
                data,
                ..
            } = request
            else {
                return None;
            };
            if !matches!(
                operation,
                FsOperation::Ftruncate
                    | FsOperation::Fdatasync
                    | FsOperation::Fchmod
                    | FsOperation::Futimes
            ) {
                return None;
            }
            assert_eq!(request.required_capability(), HostIoCapability::FsWrite);
            assert!(
                arguments
                    .first()
                    .is_some_and(|argument| argument.starts_with("fd="))
            );
            assert!(data.is_empty());
            assert!(matches!(
                outcome,
                Ok(HostIoResponse::FsMeta {
                    result: FsMetaResult::Unit
                })
            ));
            Some(*operation)
        })
        .collect()
}

#[test]
fn sync_and_callback_exports_mutate_the_held_file_and_preserve_cursor() {
    let source = r#"
import { openSync, closeSync, readSync, fstatSync, renameSync, writeFileSync,
  ftruncateSync, fdatasyncSync, fchmodSync, futimesSync } from 'node:fs';
const fs = require('fs');
const fd = openSync('input.txt', 'r+');
readSync(fd, Buffer.alloc(2), 0, 2, null);
renameSync('input.txt', 'held.txt');
writeFileSync('input.txt', 'replacement');
ftruncateSync(fd, 4);
ftruncateSync(fd, 8);
fchmodSync(fd, '640');
futimesSync(fd, new Date(-2500), '1234.5');
fdatasyncSync(fd);
const before = fstatSync(fd);
console.log('SYNC', before.size, before.mode & 511, before.mtimeMs);
const tail = Buffer.alloc(6);
console.log('CURSOR', readSync(fd, tail, 0, 6, null), tail.toString('hex'));
try { fs.ftruncateSync(fd, 1.5); } catch (error) { console.log('INVALID', error.code); }
let returned = false;
fs.ftruncate(fd, 3, function (error) {
  if (error) throw error;
  console.log('DEFERRED', returned);
  fs.fchmod(fd, 384, function (error) {
    if (error) throw error;
    fs.futimes(fd, new Date(2000), '3.5', function (error) {
      if (error) throw error;
      fs.fdatasync(fd, function (error) {
        if (error) throw error;
        const after = fstatSync(fd);
        console.log('CALLBACK', after.size, after.mode & 511, after.mtimeMs);
        closeSync(fd);
      });
    });
  });
});
returned = true;
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        std::fs::write(root.path().join("input.txt"), b"abcdef").unwrap();
        let (output, entries) = run(source, root.path(), lane);
        assert_eq!(
            output,
            [
                "SYNC 8 416 1234500",
                "CURSOR 6 636400000000",
                "INVALID ERR_OUT_OF_RANGE",
                "DEFERRED true",
                "CALLBACK 3 384 3500"
            ]
        );
        assert_eq!(
            mutations(&entries),
            [
                FsOperation::Ftruncate,
                FsOperation::Ftruncate,
                FsOperation::Fchmod,
                FsOperation::Futimes,
                FsOperation::Fdatasync,
                FsOperation::Ftruncate,
                FsOperation::Fchmod,
                FsOperation::Futimes,
                FsOperation::Fdatasync
            ]
        );
        assert_eq!(std::fs::read(root.path().join("held.txt")).unwrap(), b"abc");
        assert_eq!(
            std::fs::read(root.path().join("input.txt")).unwrap(),
            b"replacement"
        );
        let times: Vec<_> = entries
            .iter()
            .filter_map(|(request, _)| match request {
                HostIoRequest::FsMeta {
                    operation: FsOperation::Futimes,
                    arguments,
                    ..
                } => Some(arguments),
                _ => None,
            })
            .collect();
        assert_eq!(&times[0][1..], ["atime=-2.5", "mtime=1234.5"]);
        assert_eq!(&times[1][1..], ["atime=2", "mtime=3.5"]);
    }
}

#[test]
fn file_handle_mutations_keep_private_ownership_and_reject_after_close() {
    let source = r#"
const fs = require('node:fs');
let handle;
fs.promises.open('owned.txt', 'w+').then(function (value) {
  handle = value;
  return handle.write('abcdef');
}).then(function () {
  Object.defineProperty(handle, 'fd', { value: 999999 });
  fs.ftruncateSync = function () { throw new Error('public method replaced'); };
  return handle.truncate(3);
}).then(function (result) {
  console.log('TRUNCATE', result === undefined);
  return handle.chmod('600');
}).then(function () {
  return handle.utimes(new Date(2000), '3.5');
}).then(function () {
  return handle.datasync();
}).then(function () {
  return handle.stat();
}).then(function (stats) {
  console.log('OWNED', stats.size, stats.mode & 511, stats.mtimeMs);
  return handle.close();
}).then(function () {
  return handle.truncate(1);
}).catch(function (error) {
  console.log('CLOSED', error.code, error.syscall);
});
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        let (output, entries) = run(source, root.path(), lane);
        assert_eq!(
            output,
            [
                "TRUNCATE true",
                "OWNED 3 384 3500",
                "CLOSED EBADF ftruncate"
            ]
        );
        assert_eq!(
            mutations(&entries),
            [
                FsOperation::Ftruncate,
                FsOperation::Fchmod,
                FsOperation::Futimes,
                FsOperation::Fdatasync
            ]
        );
        assert_eq!(
            std::fs::read(root.path().join("owned.txt")).unwrap(),
            b"abc"
        );
    }
}
