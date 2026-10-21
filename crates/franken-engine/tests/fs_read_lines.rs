//! FileHandle line streams compose the engine filesystem, stream and readline
//! owners. Host-JavaScript checks do not establish native test success.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    FsOperation, HostIoOutcome, HostIoRecorder, HostIoRequest, InMemoryHostIoTranscript,
    SandboxedHostIo,
};

type Run = (Vec<String>, Vec<(HostIoRequest, HostIoOutcome)>);

fn run(source: &str, root: &Path, caps: &[&str], lane: LaneChoice) -> Result<Run, String> {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox provider"));
    let transcript = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder: Arc<dyn HostIoRecorder> = transcript.clone();
    let mut runtime = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        ..OrchestratorConfig::default()
    });
    runtime.set_host_io(provider, Some(recorder));
    let mut capabilities = vec!["vm_dispatch", "heap_allocate", "builtin", "console"];
    capabilities.extend_from_slice(caps);
    let package = ExtensionPackage {
        extension_id: "file-read-lines".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = runtime.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok((
        result.console_output.into_iter().map(|entry| entry.message).collect(),
        transcript.entries(),
    ))
}

#[test]
fn implicit_readline_dependency_streams_lines_through_bounded_descriptor_effects() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input"), format!("{}\r\nβ\rfinal", "x".repeat(40007))).unwrap();
        let (lines, effects) = run(
            r#"const fs=require('node:fs/promises');const WeakMap='guest';
            (async function(){const h=await fs.open('input');const rl=h.readLines();
              const closed=new Promise(resolve=>rl.input.once('close',resolve));
              const lines=[];for await(const line of rl)lines.push(line);
              await closed;console.log('LINES',lines.length,lines[0].length,lines[1],lines[2],h.fd);
            })();"#,
            root.path(), &["fs_read", "fs_write"], lane,
        ).expect("native line completion");
        assert_eq!(lines, ["LINES 3 40007 β final -1"]);
        let (mut reads, mut opens, mut closes) = (0, 0, 0);
        for (request, _) in effects {
            let HostIoRequest::FsMeta { operation, arguments, .. } = request else {
                panic!("line streaming must not use a whole-file or external effect");
            };
            match operation {
                FsOperation::ReadFd => {
                    reads += 1;
                    let length = arguments.iter().find_map(|arg| arg.strip_prefix("length=")).unwrap();
                    assert!(length.parse::<usize>().unwrap() <= 16384);
                }
                FsOperation::Open => opens += 1,
                FsOperation::CloseFd => closes += 1,
                other => panic!("unexpected line-stream effect: {other:?}"),
            }
        }
        assert!(reads >= 4);
        assert_eq!((opens, closes), (1, 1));
    }
}

#[test]
fn explicit_modules_share_interface_identity_and_retained_cursor_ownership() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input"), b"skip\nfirst\nlast").unwrap();
        let (lines, _) = run(
            r#"const fs=require('fs/promises');const lines=require('node:readline');
            const streams=require('stream');(async function(){const h=await fs.open('input');
              await h.read(Buffer.alloc(5));const rl=h.readLines({autoClose:false,highWaterMark:1});
              console.log('SHARED',rl instanceof lines.Interface,rl.input instanceof streams.Readable);
              const output=[];for await(const line of rl)output.push(line);
              console.log('CURSOR',output.join('|'),h.fd>=0,rl.input.destroyed);
              await h.close();console.log('CLOSED',h.fd);
            })();"#,
            root.path(), &["fs_read", "fs_write"], lane,
        ).expect("shared native module identity");
        assert_eq!(lines, ["SHARED true true", "CURSOR first|last true false", "CLOSED -1"]);
    }
}

#[test]
fn early_return_preserves_borrowed_input_and_explicit_cleanup_prevents_further_reads() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input"), format!("first\n{}", "rest\n".repeat(1000))).unwrap();
        let (lines, effects) = run(
            r#"(async function(){const h=await require('fs/promises').open('input');
              const rl=h.readLines({autoClose:false,highWaterMark:1});
              for await(const line of rl){console.log('FIRST',line);break;}
              console.log('BORROWED',h.fd>=0,rl.input.destroyed);
              const closed=new Promise(resolve=>rl.input.once('close',resolve));
              rl.input.destroy();await closed;await h.close();console.log('RELEASED',h.fd);
            })();"#,
            root.path(), &["fs_read", "fs_write"], lane,
        ).expect("early-return ownership");
        assert_eq!(lines, ["FIRST first", "BORROWED true false", "RELEASED -1"]);
        let reads = effects.iter().filter(|(request, _)| matches!(request,
            HostIoRequest::FsMeta { operation: FsOperation::ReadFd, .. })).count();
        assert!(reads <= 8, "a paused line iterator must not consume the remaining file");
    }
}

#[test]
fn line_stream_errors_reject_and_creation_does_not_infer_read_authority() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input"), b"data\n").unwrap();
        let (lines, _) = run(
            r#"(async function(){const h=await require('fs/promises').open('input','w');
              const rl=h.readLines();const closed=new Promise(resolve=>rl.input.once('close',resolve));
              try{for await(const line of rl){throw Error('unexpected data');}}
              catch(error){console.log('FAILED',error.code);}
              rl.close();await closed;console.log('RELEASED',h.fd);
            })();"#,
            root.path(), &["fs_read", "fs_write"], lane,
        ).expect("native read error is not successful EOF");
        assert_eq!(lines, ["FAILED EBADF", "RELEASED -1"]);
        let denied = run(
            "require('fs/promises').open('input').then(h=>h.readLines());",
            root.path(), &[], lane,
        );
        assert!(denied.is_err(), "opening a line stream requires ordinary file authority");
    }
}
