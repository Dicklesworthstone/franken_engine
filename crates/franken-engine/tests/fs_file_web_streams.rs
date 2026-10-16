//! File descriptors feed canonical Web byte streams without whole-file effects.
//! Node-host checks do not establish that these native regressions pass.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    FsOperation, HostIoOutcome, HostIoRecorder, HostIoRequest, InMemoryHostIoTranscript, SandboxedHostIo,
};

type Run = (Vec<String>, Vec<(HostIoRequest, HostIoOutcome)>);

fn run(source: &str, root: &Path, caps: &[&str], lane: LaneChoice) -> Result<Run, String> {
    let provider = Arc::new(SandboxedHostIo::with_root(root).expect("sandbox provider"));
    let recording = Arc::new(InMemoryHostIoTranscript::recording());
    let recorder: Arc<dyn HostIoRecorder> = recording.clone();
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        ..OrchestratorConfig::default()
    });
    orchestrator.set_host_io(provider, Some(recorder));
    let mut capabilities = vec!["vm_dispatch", "heap_allocate", "builtin", "console"];
    capabilities.extend_from_slice(caps);
    let package = ExtensionPackage {
        extension_id: "file-web-stream".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: capabilities.into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let output = orchestrator.execute(&package).map_err(|error| format!("{error:?}"))?;
    Ok((
        output.console_output.into_iter().map(|entry| entry.message).collect(),
        recording.entries(),
    ))
}

#[test]
fn file_bytes_use_the_shared_web_constructor_and_bounded_descriptor_reads() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input"), vec![82_u8; 40007]).unwrap();
        let (lines, effects) = run(
            r#"const fs=require('fs/promises');const web=require('stream/web');
            const Object='guest';const DataView='guest';
            (async function(){const h=await fs.open('input');
              const stream=h.readableWebStream({autoClose:true});
              console.log(stream instanceof web.ReadableStream);
              let bytes=0,total=0;for await(const chunk of stream){
                bytes+=chunk.byteLength;for(const byte of chunk)total+=byte;
              }console.log('FILE_STREAM',bytes,total,h.fd);
            })();"#,
            root.path(), &["fs_read", "fs_write"], lane,
        ).expect("native byte stream completes");
        assert_eq!(lines, ["true", "FILE_STREAM 40007 3280574 -1"]);
        let mut reads = 0;
        let mut opens = 0;
        let mut closes = 0;
        for (request, _) in effects {
            if let HostIoRequest::FsMeta { operation, arguments, .. } = request {
                match operation {
                    FsOperation::ReadFd => {
                        reads += 1;
                        let length = arguments.iter().find_map(|value| value.strip_prefix("length=")).unwrap();
                        assert!(length.parse::<usize>().unwrap() <= 16384);
                    }
                    FsOperation::Open => opens += 1,
                    FsOperation::CloseFd => closes += 1,
                    other => panic!("unexpected non-descriptor operation {other:?}"),
                }
            } else {
                panic!("unexpected whole-file or non-filesystem request");
            }
        }
        assert!(reads >= 4);
        assert_eq!((opens, closes), (1, 1));
    }
}

#[test]
fn byob_storage_minimum_fill_and_borrowed_file_cursor_share_one_owner() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input"), b"0123456789abcdefgh").unwrap();
        let (lines, _) = run(
            r#"(async function(){const h=await require('fs/promises').open('input');
              await h.read(Buffer.alloc(2));const s=h.readableWebStream();
              const r=s.getReader({mode:'byob'});let text='';
              for(;;){const input=new Uint16Array(new ArrayBuffer(14),2,4);
                const result=await r.read(input,{min:2});
                if(input.buffer.byteLength!==0)throw Error('buffer not transferred');
                text+=Buffer.from(result.value.buffer,result.value.byteOffset,result.value.byteLength).toString();
                if(result.done)break;
              }await r.closed;r.releaseLock();console.log('BYOB',text,h.fd>=0);
              await h.close();console.log('CLOSED',h.fd);
            })();"#,
            root.path(), &["fs_read", "fs_write"], lane,
        ).expect("native BYOB ownership and transfer");
        assert_eq!(lines, ["BYOB 23456789abcdefgh true", "CLOSED -1"]);
    }
}

#[test]
fn cancellation_and_manual_close_do_not_read_or_close_a_descriptor_twice() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input"), b"kept").unwrap();
        let (lines, effects) = run(
            r#"(async function(){const h=await require('fs/promises').open('input');
              const s=h.readableWebStream({autoClose:true});
              try{h.readableWebStream();}catch(e){console.log('ONCE',e.code);}
              await s.cancel();await h.close();console.log('CANCELLED',h.fd);
              const h2=await require('fs/promises').open('input');const s2=h2.readableWebStream();
              const r=s2.getReader({mode:'byob'});await h2.close();
              console.log('MANUAL',(await r.read(new Uint8Array(8))).done);r.releaseLock();
            })();"#,
            root.path(), &["fs_read", "fs_write"], lane,
        ).expect("native cancellation before demand");
        assert_eq!(lines, ["ONCE ERR_INVALID_STATE", "CANCELLED -1", "MANUAL true"]);
        assert!(!effects.iter().any(|(request, _)| matches!(request,
            HostIoRequest::FsMeta { operation: FsOperation::ReadFd, .. })));
        assert_eq!(effects.iter().filter(|(request, _)| matches!(request,
            HostIoRequest::FsMeta { operation: FsOperation::CloseFd, .. })).count(), 2);
    }
}

#[test]
fn file_streams_feed_shared_text_transforms_and_wait_for_sink_finalization() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input"), "hé😀\n").unwrap();
        let (lines, _) = run(
            r#"const web=require('node:stream/web');
            (async function(){const h=await require('node:fs/promises').open('input');
              let text='',closed=false;
              await h.readableWebStream({autoClose:true})
                .pipeThrough(new web.TextDecoderStream())
                .pipeThrough(new web.TransformStream({transform(chunk,c){c.enqueue(chunk.toUpperCase());}}))
                .pipeTo(new web.WritableStream({async write(chunk){await Promise.resolve();text+=chunk;},
                  async close(){await Promise.resolve();closed=true;}}));
              console.log('PIPE',JSON.stringify(text),closed,h.fd);
            })();"#,
            root.path(), &["fs_read", "fs_write"], lane,
        ).expect("native file-Web-text pipeline");
        assert_eq!(lines, ["PIPE \"HÉ😀\\n\" true -1"]);
    }
}

#[test]
fn write_authority_does_not_confer_read_authority_on_file_web_streams() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(root.path().join("input"), b"private").unwrap();
        let error = run(
            "require('fs/promises').open('input').then(h=>h.readableWebStream().getReader().read());",
            root.path(), &["fs_write"], lane,
        ).expect_err("file byte streams must keep the original read authority check");
        assert!(error.to_ascii_lowercase().contains("capabil"), "{error}");
    }
}
