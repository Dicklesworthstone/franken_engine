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
