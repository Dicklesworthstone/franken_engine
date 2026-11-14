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
fn path_metadata_normalizes_direct_calls_callbacks_and_promises_before_recording() {
    use std::os::unix::fs::MetadataExt;

    let source = r#"
import { chmodSync, utimesSync, statSync } from 'node:fs';
const fs = require('fs');
const beforeEpoch = new Date(-2500);
beforeEpoch.getTime = function () { throw new Error('public Date hook'); };
chmodSync('direct.txt', '640');
utimesSync('direct.txt', beforeEpoch, '1234.5');
console.log('DIRECT', statSync('direct.txt').mode & 511, statSync('direct.txt').mtimeMs);
try { chmodSync('direct.txt', '8'); } catch (error) { console.log('MODE', error.name, error.code); }
try { utimesSync('direct.txt', 1, NaN); } catch (error) { console.log('TIME', error.name, error.code); }
let returned = false;
const queuedDate = new Date(-1250);
fs.utimes('callback.txt', queuedDate, '2.75', function (error) {
  if (error) throw error;
  console.log('CALLBACK', returned, fs.statSync('callback.txt').mtimeMs);
});
queuedDate.setTime(0);
returned = true;
fs.promises.chmod('promise.txt', '600').then(function () {
  return fs.promises.utimes('promise.txt', new Date(-1750), 3.25);
}).then(function () {
  const stats = fs.statSync('promise.txt');
  console.log('PROMISE', stats.mode & 511, stats.mtimeMs);
});
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        for path in ["direct.txt", "callback.txt", "promise.txt"] {
            std::fs::write(root.path().join(path), b"metadata").unwrap();
        }
        let (output, entries) = run(source, root.path(), lane);
        assert_eq!(
            output,
            [
                "DIRECT 416 1234500",
                "MODE TypeError ERR_INVALID_ARG_VALUE",
                "TIME TypeError ERR_INVALID_ARG_TYPE",
                "CALLBACK true 2750",
                "PROMISE 384 3250",
            ]
        );
        let mut changed = BTreeMap::new();
        for (request, outcome) in &entries {
            let HostIoRequest::FsMeta {
                operation,
                path,
                arguments,
                data,
            } = request
            else {
                continue;
            };
            if !matches!(operation, FsOperation::Chmod | FsOperation::Utimes) {
                continue;
            }
            assert_eq!(request.required_capability(), HostIoCapability::FsWrite);
            assert!(data.is_empty());
            assert_eq!(
                outcome,
                &Ok(HostIoResponse::FsMeta {
                    result: FsMetaResult::Unit
                })
            );
            changed.insert((path.as_str(), operation.as_str()), arguments.clone());
        }
        assert_eq!(
            changed.len(),
            5,
            "invalid arguments must not dispatch a host effect"
        );
        assert_eq!(changed[&("direct.txt", "chmod")], ["416"]);
        assert_eq!(changed[&("promise.txt", "chmod")], ["384"]);
        for (path, accessed, modified, arguments) in [
            (
                "direct.txt",
                (-3, 500_000_000),
                (1234, 500_000_000),
                ["atime=-2.5", "mtime=1234.5"],
            ),
            (
                "callback.txt",
                (-2, 750_000_000),
                (2, 750_000_000),
                ["atime=-1.25", "mtime=2.75"],
            ),
            (
                "promise.txt",
                (-2, 250_000_000),
                (3, 250_000_000),
                ["atime=-1.75", "mtime=3.25"],
            ),
        ] {
            assert_eq!(changed[&(path, "utimes")], arguments);
            let metadata = std::fs::metadata(root.path().join(path)).unwrap();
            assert_eq!((metadata.atime(), metadata.atime_nsec()), accessed);
            assert_eq!((metadata.mtime(), metadata.mtime_nsec()), modified);
        }
    }
}

#[test]
fn direct_timestamp_now_and_descriptor_negative_zero_have_canonical_effect_arguments() {
    let source = r#"
import { utimesSync, statSync } from 'node:fs';
const fs = require('fs');
utimesSync('clock.txt', -1, -2);
console.log('NOW', statSync('clock.txt').mtimeMs > 0);
fs.promises.open('zero.txt', 'w+').then(function (handle) {
  return handle.truncate(-0).then(function () {
    return handle.chmod(-0);
  }).then(function () {
    return handle.chmod('600');
  }).then(function () {
    return handle.stat();
  }).then(function (stats) {
    console.log('ZERO', stats.size, stats.mode & 511);
    return handle.close();
  });
});
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        std::fs::write(root.path().join("clock.txt"), b"clock").unwrap();
        let (output, entries) = run(source, root.path(), lane);
        assert_eq!(output, ["NOW true", "ZERO 0 384"]);
        let mut observed = Vec::new();
        for (request, _) in entries {
            let HostIoRequest::FsMeta {
                operation,
                arguments,
                ..
            } = request
            else {
                continue;
            };
            match operation {
                FsOperation::Utimes => {
                    assert_eq!(arguments.len(), 2);
                    for (argument, name) in arguments.iter().zip(["atime=", "mtime="]) {
                        let seconds = argument.strip_prefix(name).unwrap().parse::<f64>().unwrap();
                        assert!(seconds > 0.0 && seconds.is_finite());
                    }
                }
                FsOperation::Ftruncate | FsOperation::Fchmod => observed.push(arguments[1].clone()),
                _ => {}
            }
        }
        assert_eq!(observed, ["length=0", "mode=0", "mode=384"]);
    }
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

#[test]
fn exclusive_and_synchronous_opens_reach_the_owned_host_descriptor() {
    let source = r#"
const fs = require('node:fs');
const fd = fs.openSync('owned.txt', 'wx+');
fs.writeSync(fd, 'original');
fs.closeSync(fd);
const plain = fs.openSync('owned.txt');
const prefix = Buffer.alloc(3);
fs.readSync(plain, prefix, 0, 3, null);
fs.closeSync(plain);
console.log('DEFAULT', prefix.toString());
try { fs.openSync('owned.txt', 'xw'); }
catch (error) { console.log('EXCLUSIVE', error.code); }
fs.promises.writeFile('owned.txt', 'must not overwrite', { flag: 'wx' }).catch(function (error) {
  console.log('WRITEFILE', error.code);
  return fs.promises.appendFile('owned.txt', 'must not append', { flag: 'ax' });
}).catch(function (error) {
  console.log('APPEND', error.code);
  return fs.promises.open('owned.txt', 'sa+');
}).then(function (handle) {
  return handle.write('!', 0).then(function () { return handle.close(); });
}).then(function () {
  return fs.promises.open('owned.txt', 'sr');
}).then(function (handle) {
  return handle.readFile('utf8').then(function (value) {
    console.log('PRESERVED', value);
    return handle.close();
  });
});
"#;
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().expect("sandbox");
        let (output, entries) = run(source, root.path(), lane);
        assert_eq!(
            output,
            [
                "DEFAULT ori",
                "EXCLUSIVE EEXIST",
                "WRITEFILE EEXIST",
                "APPEND EEXIST",
                "PRESERVED original!"
            ]
        );
        let opens: Vec<_> = entries
            .iter()
            .filter_map(|(request, outcome)| match request {
                HostIoRequest::FsMeta {
                    operation: FsOperation::Open,
                    arguments,
                    ..
                } => Some((arguments, outcome)),
                _ => None,
            })
            .collect();
        assert_eq!(opens.len(), 7);
        for (entry, flags) in opens.iter().zip(["wx+", "r", "xw", "wx", "ax", "sa+", "sr"]) {
            assert_eq!(entry.0, &[format!("flags={flags}")]);
        }
        for (_, outcome) in &opens[2..5] {
            assert!(
                matches!(outcome, Err(frankenengine_extension_host::host_io::HostIoError::Fs { code, .. }) if code == "EEXIST")
            );
        }
        assert_eq!(
            std::fs::read(root.path().join("owned.txt")).unwrap(),
            b"original!"
        );
    }
}
