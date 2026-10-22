//! Promised pipeline sources through the existing native runtime and stream owners.
//! Host JavaScript tests do not establish that these native tests pass.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::sync::Arc;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};
use frankenengine_extension_host::host_io::{
    HostIoRecorder, InMemoryHostIoTranscript, SandboxedHostIo,
};

fn run(source: &str, lane: LaneChoice) -> (tempfile::TempDir, Vec<String>) {
    let root = tempfile::tempdir().expect("sandbox root");
    let provider = Arc::new(SandboxedHostIo::with_root(root.path()).expect("host provider"));
    let recorder: Arc<dyn HostIoRecorder> = Arc::new(InMemoryHostIoTranscript::recording());
    let mut runtime = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        ..OrchestratorConfig::default()
    });
    runtime.set_host_io(provider, Some(recorder));
    let package = ExtensionPackage {
        extension_id: "stream-pipeline-values".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        // Stream nextTick uses the existing explicit timer capability.
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console", "fs_read", "fs_write", "timer"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = runtime.execute(&package).expect("native stream cancellation completes");
    (root, result.console_output.into_iter().map(|entry| entry.message).collect())
}

#[test]
fn promised_pipeline_records_retain_identity_and_function_sink_results() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const S=require('node:stream');
            (async function(){const record={names:['one','two']};let identity=false;
              const result=await S.promises.pipeline(Promise.resolve(record),
                async function*(input){for await(const item of input){identity=item===record;
                  for(const name of item.names)yield name.toUpperCase();}},
                async function(input){let text='';for await(const name of input)text+=name+';';return text;});
              console.log('promised',result,identity);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["promised ONE;TWO; true"]);
    }
}

#[test]
fn promised_callback_pipeline_preserves_sink_identity_and_closed_completion() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const S=require('stream');let text='',calls=0;
            const sink=new S.Writable({write(chunk,encoding,done){text+=chunk.toString();done();}});
            const returned=S.pipeline(Promise.resolve(Buffer.from('café')),sink,function(error){
              if(error)throw error;calls++;console.log('callback',returned===sink,sink.closed,text,calls);
            });"#,
            lane,
        );
        assert_eq!(lines, ["callback true true café 1"]);
    }
}

#[test]
fn promised_source_rejection_waits_for_owned_sink_cleanup() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const S=require('node:stream');
            (async function(){const reason=new Error('unavailable');let closed=false,finals=0;
              const sink=new S.Writable({write(chunk,encoding,done){done();},
                final(done){finals++;done();},destroy(error,done){queueMicrotask(function(){closed=true;done(error);});}});
              let result;try{await S.promises.pipeline(Promise.reject(reason),sink);}catch(error){result=error;}
              console.log('failure',result===reason,closed,sink.closed,finals);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["failure true true true 0"]);
    }
}

#[test]
fn promised_source_connects_to_canonical_web_transform_without_copying_records() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const S=require('stream');const web=require('node:stream/web');
            (async function(){const record={name:'shared'};let identity=false,text='';
              const transform=new web.TransformStream({transform(value,controller){
                identity=value===record;controller.enqueue(value.name.toUpperCase());}});
              const sink=new S.Writable({write(value,encoding,done){text+=value.toString();done();}});
              await S.promises.pipeline(Promise.resolve(record),transform,sink);
              console.log('shared',text,identity,sink.closed);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["shared SHARED true true"]);
    }
}

#[test]
fn pending_promised_source_can_cancel_without_waiting_for_producer_settlement() {
    // Stronger than the observed Node 22.16 unresolved-source pipeline. The
    // native candidate must emit this completion marker, not exit quietly
    // with an unfulfilled pipeline promise. The producer itself is not cancelled.
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const S=require('node:stream');
            (async function(){let publish,writes=0;const controller=new AbortController();
              const source=new Promise(function(resolve){publish=resolve;});
              const sink=new S.Writable({write(value,encoding,done){writes++;done();}});
              const result=S.promises.pipeline(source,sink,{signal:controller.signal}).then(function(){return null;},function(error){return error;});
              controller.abort(false);const error=await result;publish('late');await Promise.resolve();
              console.log('cancelled',error.code,sink.closed,writes);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["cancelled ABORT_ERR true 0"]);
    }
}

#[test]
fn mixed_node_readable_web_writable_pairs_run_through_the_existing_pipeline() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const S=require('node:stream');const W=require('node:stream/web');
            (async function(){const readable=new S.Readable({read(){}});let closed=false;
              const writable=new W.WritableStream({write(value){readable.push(Buffer.from(value.toString().toUpperCase()));},
                close(){closed=true;readable.push(null);}});
              const channel=S.Duplex.from({readable,writable});let result='';
              const destination=new S.Writable({write(value,encoding,done){result+=value.toString();done();}});
              await S.promises.pipeline(S.Readable.from(['hello',' café']),channel,destination);
              console.log(result,closed,destination.closed);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["HELLO CAFÉ true true"]);
    }
}

#[test]
fn paired_web_readable_and_node_writer_preserve_independent_object_modes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const S=require('stream');const W=require('stream/web');
            (async function(){let controller;
              const readable=new W.ReadableStream({start(value){controller=value;}});
              const writable=new S.Writable({objectMode:true,
                write(value,encoding,done){controller.enqueue(Buffer.from(value.id+':'+value.name+';'));done();},
                final(done){controller.close();done();}});
              const channel=S.Duplex.from({readable,writable});let result='';
              await S.promises.pipeline(S.Readable.from([{id:7,name:'café'},{id:9,name:'東京'}]),channel,
                new S.Writable({write(value,encoding,done){result+=value.toString();done();}}));
              console.log(result,channel.readableObjectMode,channel.writableObjectMode);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["7:café;9:東京; false true"]);
    }
}

#[test]
fn nested_blob_pair_uses_the_shared_binary_and_stream_owners() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const S=require('stream');const W=require('stream/web');const B=require('buffer');
            (async function(){let command='';
              const channel=S.Duplex.from({readable:{readable:new B.Blob(['archive café'])},
                writable:new W.WritableStream({write(value){command+=value.toString();}})});
              const completed=S.promises.finished(channel);channel.end('verify');
              let result='',count=0;for await(const value of channel){
                if(!(value instanceof ArrayBuffer))throw new Error('wrong record');
                count++;result+=Buffer.from(value).toString();}
              await completed;console.log(result,count,command);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["archive café 1 verify"]);
    }
}

#[test]
fn partial_pair_setup_releases_acquired_reader_without_aborting_locked_writer() {
    // This asserts adapter ownership, not parity with Node's partial setup.
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const S=require('stream');const W=require('stream/web');
            (async function(){let retired,cancels=0,aborts=0,failed=false;
              const cleaned=new Promise(resolve=>{retired=resolve;});
              const readable=new W.ReadableStream({cancel(){cancels++;retired();}});
              const writable=new W.WritableStream({abort(){aborts++;}});const held=writable.getWriter();
              try{S.Duplex.from({readable,writable});}catch(error){failed=error instanceof TypeError;}
              await cleaned;console.log(failed,cancels,aborts,writable.locked);held.releaseLock();
            })();"#,
            lane,
        );
        assert_eq!(lines, ["true 1 0 true"]);
    }
}
