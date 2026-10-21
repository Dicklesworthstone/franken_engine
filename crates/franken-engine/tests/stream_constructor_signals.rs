//! Constructor cancellation through the shared native runtime on both lanes.
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
        extension_id: "stream-constructor-signals".into(),
        source: source.into(),
        source_file: None,
        module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console", "fs_read", "fs_write"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(),
        metadata: BTreeMap::new(),
    };
    let result = runtime.execute(&package).expect("native stream cancellation completes");
    (root, result.console_output.into_iter().map(|entry| entry.message).collect())
}

#[test]
fn constructor_abort_preserves_reason_and_destroys_both_duplex_halves_once() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const streams=require('node:stream');
            (async function(){
              for(const name of ['Readable','Writable','Duplex','Transform','PassThrough']){
                const c=new AbortController();let destroys=0;let errors=0;
                const s=new streams[name]({signal:c.signal,read(){},write(x,e,cb){cb();},
                  destroy(e,cb){destroys++;cb(e);}});
                s.on('error',e=>{if(e.code!=='ABORT_ERR'||e.cause!==false)throw e;errors++;});
                const closed=new Promise(resolve=>s.once('close',resolve));
                c.abort(false);console.log(name,s.destroyed);await closed;
                console.log(destroys,errors);
              }
            })();"#,
            lane,
        );
        assert_eq!(lines, ["Readable true", "1 1", "Writable true", "1 1",
            "Duplex true", "1 1", "Transform true", "1 1", "PassThrough true", "1 1"]);
    }
}

#[test]
fn pipeline_cancellation_preserves_accepted_file_prefix_without_finalization() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (root, lines) = run(
            r#"const fs=require('fs');const {Readable:R}=require('stream');
            const {Writable:W,promises:p}=require('node:stream');const WeakMap='guest';
            (async function(){const c=new AbortController();let accepted;
              const ready=new Promise(resolve=>accepted=resolve);let sent=false;
              fs.writeFileSync('out.txt','');
              const source=new R({signal:c.signal,read(){if(!sent){sent=true;this.push('accepted\n');}}});
              const sink=new W({write(x,e,cb){fs.appendFileSync('out.txt',x);cb();accepted();},
                final(cb){fs.writeFileSync('unexpected.txt','success');cb();}});
              const result=p.pipeline(source,sink).then(()=>null,e=>e);
              await ready;c.abort(null);const error=await result;
              console.log(error.code,error.cause===null,source.destroyed,sink.destroyed);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["ABORT_ERR true true true"]);
        assert_eq!(std::fs::read(root.path().join("out.txt")).unwrap(), b"accepted\n");
        assert!(!root.path().join("unexpected.txt").exists());
    }
}

#[test]
fn cancellation_waits_for_construct_before_releasing_an_acquired_resource() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const {Writable}=require('stream');
            (async function(){const c=new AbortController();let finish;let ready;
              const started=new Promise(resolve=>ready=resolve);let writes=0;let destroys=0;
              const s=new Writable({signal:c.signal,
                construct(cb){finish=cb;ready();},write(x,e,cb){writes++;cb();},
                destroy(e,cb){destroys++;queueMicrotask(()=>cb(e));}});
              s.on('error',e=>console.log(e.code,e.cause));
              const closed=new Promise(resolve=>s.once('close',resolve));
              s.write('late',()=>{});await started;c.abort('stop');
              console.log(s.destroyed,destroys,writes);finish();await closed;
              console.log(destroys,writes,s.closed);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["true 0 0", "ABORT_ERR stop", "1 0 true"]);
    }
}

#[test]
fn completed_non_autodestroy_stream_does_not_become_aborted_later() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const {Writable}=require('node:stream');
            (async function(){const c=new AbortController();let errors=0;let text='';
              const s=new Writable({signal:c.signal,autoDestroy:false,
                write(x,e,cb){text+=x.toString();cb();}});
              s.on('error',()=>errors++);
              const finished=new Promise(resolve=>s.once('finish',resolve));
              s.end('complete');await finished;c.abort('late');await Promise.resolve();
              console.log(text,s.destroyed,errors);s.destroy();
            })();"#,
            lane,
        );
        assert_eq!(lines, ["complete false 0"]);
    }
}

#[test]
fn async_cursor_getters_publish_each_record_once_through_the_native_pipeline() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (root, lines) = run(
            r#"const fs=require('fs');const streams=require('node:stream');
            (async function(){
              const rows=['first\n','second\n','third\n'];let gets=0;let returned=0;
              const cursor={ [Symbol.asyncIterator](){return this;},
                async next(){return rows.length?{done:false,
                  get value(){gets++;return rows.shift()||null;}}:{done:true};},
                return(){returned++;return {done:true};}};
              fs.writeFileSync('records.txt','');
              const sink=new streams.Writable({write(chunk,encoding,done){
                fs.appendFileSync('records.txt',chunk);queueMicrotask(done);}});
              await streams.promises.pipeline(streams.Readable.from(cursor,{objectMode:false}),sink);
              console.log('CURSOR_COMPLETE',gets,returned,sink.writableFinished);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["CURSOR_COMPLETE 3 1 true"]);
        assert_eq!(std::fs::read(root.path().join("records.txt")).unwrap(), b"first\nsecond\nthird\n");
    }
}

#[test]
fn mixed_sync_and_promised_records_reenter_the_bounded_native_pump() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const streams=require('stream');
            (async function(){let next=0;let expected=0;let total=0;
              const producer={ [Symbol.iterator](){return this;},next(){
                if(next===257)return {done:true};const n=next++;
                return {done:false,value:n%64===0?Promise.resolve(n):n};}};
              const sink=new streams.Writable({objectMode:true,highWaterMark:1,
                write(value,encoding,done){if(value!==expected++)throw Error('out of order');
                  total+=value;queueMicrotask(done);}});
              await streams.promises.pipeline(streams.Readable.from(producer),sink);
              console.log('MIXED_COMPLETE',expected,total,sink.writableFinished);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["MIXED_COMPLETE 257 32896 true"]);
    }
}

#[test]
fn stopped_native_iterable_does_not_observe_late_result_getters() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const streams=require('node:stream');
            (async function(){let ready,settle;let reads=0;let returns=0;
              const started=new Promise(resolve=>ready=resolve);
              const pending=new Promise(resolve=>settle=resolve);
              const producer={ [Symbol.asyncIterator](){return this;},
                next(){ready();return pending;},return(){returns++;return {done:true};}};
              const source=streams.Readable.from(producer);const reason=new Error('stop');
              let same=false;source.on('error',error=>same=error===reason);
              const closed=new Promise(resolve=>source.once('close',resolve));
              source.resume();await started;source.destroy(reason);await closed;
              settle({get done(){reads++;return false;},get value(){reads++;return 9;}});
              await Promise.resolve();await Promise.resolve();
              console.log('RETIRED_COMPLETE',reads,returns,same,source.closed);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["RETIRED_COMPLETE 0 1 true true"]);
    }
}

#[test]
fn native_readline_iterator_cleanup_preserves_the_original_abort() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const streams=require('node:stream');const line=require('node:readline');
            (async function(){const input=new streams.PassThrough();
              const lines=line.createInterface({input:input,terminal:false});
              const source=streams.Readable.from(lines);const reason=new Error('cancel export');
              let same=false;source.on('error',error=>same=error===reason);
              const closed=new Promise(resolve=>source.once('close',resolve));
              const accepted=new Promise(resolve=>source.once('data',resolve));
              source.resume();input.write('accepted\n');await accepted;
              source.destroy(reason);await closed;
              console.log('LINE_ABORT_COMPLETE',same,lines.closed,input.destroyed);
              input.destroy();
            })();"#,
            lane,
        );
        assert_eq!(lines, ["LINE_ABORT_COMPLETE true true false"]);
    }
}

#[test]
fn web_adapters_cancel_acquired_endpoints_before_reporting_pre_aborted_close() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const s=require('node:stream');const web=require('stream/web');
            (async function(){
              for(const name of ['Readable','Writable','Duplex']){
                const c=new AbortController();c.abort(false);let released=0;let reason=true;
                const r=new web.ReadableStream({cancel(e){reason=reason&&e.code==='ABORT_ERR'&&e.cause===false;
                  return Promise.resolve().then(()=>{released++;});}},{highWaterMark:0});
                const w=new web.WritableStream({abort(e){reason=reason&&e.code==='ABORT_ERR'&&e.cause===false;
                  return Promise.resolve().then(()=>{released++;});}});
                const input=name==='Readable'?r:name==='Writable'?w:{readable:r,writable:w};
                const n=s[name].fromWeb(input,{signal:c.signal});let errors=0;
                n.on('error',e=>{if(e.code!=='ABORT_ERR'||e.cause!==false)throw e;errors++;});
                await new Promise(resolve=>n.once('close',resolve));
                console.log('ADOPTED',name,released,errors,reason,n.closed);
              }
            })();"#,
            lane,
        );
        assert_eq!(lines, [
            "ADOPTED Readable 1 1 true true",
            "ADOPTED Writable 1 1 true true",
            "ADOPTED Duplex 2 1 true true",
        ]);
    }
}

#[test]
fn pre_aborted_web_pipeline_waits_for_the_owned_file_release() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (root, lines) = run(
            r#"const fs=require('fs');const s=require('stream');const web=require('node:stream/web');
            (async function(){fs.writeFileSync('resource.txt','owned');
              const fd=fs.openSync('resource.txt','r');const c=new AbortController();c.abort(null);
              const source=new web.ReadableStream({cancel(e){return Promise.resolve().then(()=>{
                fs.closeSync(fd);fs.writeFileSync('released.txt','closed\n');
              });}},{highWaterMark:0});
              const input=s.Readable.fromWeb(source,{signal:c.signal});
              const output=new s.Writable({write(x,e,cb){cb();},
                final(cb){fs.writeFileSync('unexpected.txt','published');cb();}});
              try{await s.promises.pipeline(input,output);throw Error('success');}
              catch(e){console.log('WEB_CANCEL',e.code,e.cause===null,input.closed,output.destroyed);}
              console.log('RELEASED',fs.readFileSync('released.txt','utf8').trim());
            })();"#,
            lane,
        );
        assert_eq!(lines, ["WEB_CANCEL ABORT_ERR true true true", "RELEASED closed"]);
        assert_eq!(std::fs::read(root.path().join("released.txt")).unwrap(), b"closed\n");
        assert!(!root.path().join("unexpected.txt").exists());
    }
}

#[test]
fn web_duplex_pre_abort_starts_both_cleanup_sides_before_awaiting_either() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const {Duplex}=require('stream');const web=require('stream/web');
            (async function(){let rReady,wReady;const calls=[];
              const left=new Promise(resolve=>rReady=resolve),right=new Promise(resolve=>wReady=resolve);
              const r=new web.ReadableStream({cancel(){calls.push('read');rReady();return right;}},{highWaterMark:0});
              const w=new web.WritableStream({abort(){calls.push('write');wReady();return left;}});
              const c=new AbortController();c.abort('stop');
              const d=Duplex.fromWeb({readable:r,writable:w},{signal:c.signal});
              let original=false;d.on('error',e=>{original=e.code==='ABORT_ERR'&&e.cause==='stop';});
              await new Promise(resolve=>d.once('close',resolve));
              console.log('BOTH_RELEASED',calls.join(','),original,d.closed);
            })();"#,
            lane,
        );
        assert_eq!(lines, ["BOTH_RELEASED read,write true true"]);
    }
}

#[test]
fn web_pipeline_preserves_admitted_bytes_before_reporting_source_failure() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (root, lines) = run(
            r#"const fs=require('fs');const s=require('node:stream');const w=require('stream/web');
            (async function(){const reason=new Error('upstream');let writes=0;
              const input=new w.ReadableStream({pull(c){c.enqueue(Buffer.from('accepted\n'));c.error(reason);}},
                {highWaterMark:0});
              const output=new s.Writable({write(chunk,encoding,done){
                fs.appendFileSync('partial.txt',chunk);writes++;done();},
                final(done){fs.writeFileSync('unexpected.txt','published');done();}});
              fs.writeFileSync('partial.txt','');await Promise.resolve();
              let same=false;try{await s.promises.pipeline(input,output);}catch(error){same=error===reason;}
              console.log('ADMITTED_COMPLETE',same,writes,output.closed,
                fs.readFileSync('partial.txt','utf8')==='accepted\n');
            })();"#,
            lane,
        );
        assert_eq!(lines, ["ADMITTED_COMPLETE true 1 true true"]);
        assert_eq!(std::fs::read(root.path().join("partial.txt")).unwrap(), b"accepted\n");
        assert!(!root.path().join("unexpected.txt").exists());
    }
}

#[test]
fn web_duplex_admitted_record_precedes_both_endpoint_failure_cleanup() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let (_, lines) = run(
            r#"const s=require('stream');const w=require('node:stream/web');
            (async function(){const reason=new Error('source');const row={id:7};let accepted=false;
              let released=false;let original=false;
              const source=new w.ReadableStream({pull(c){c.enqueue(row);c.error(reason);}},{highWaterMark:0});
              const target=new w.WritableStream({abort(error){original=error===reason;
                return Promise.resolve().then(()=>{released=true;});}});
              const input=s.Duplex.fromWeb({readable:source,writable:target},{objectMode:true});
              const output=new s.Writable({objectMode:true,write(value,encoding,done){accepted=value===row;done();}});
              await Promise.resolve();let same=false;
              try{await s.promises.pipeline(input,output);}catch(error){same=error===reason;}
              console.log('DUPLEX_ADMITTED',accepted,released,original,same,input.closed,output.closed);
            })();"#,
            lane,
        );
        // Intentional stronger delivery/cleanup than the Node 22 explicit
        // Duplex adapter. The host differential suite records that difference.
        assert_eq!(lines, ["DUPLEX_ADMITTED true true true true true true"]);
    }
}
