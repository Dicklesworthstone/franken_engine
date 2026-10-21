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
