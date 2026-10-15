//! Default-mode Web Streams on the actual native orchestrator, not a Node shim.
#![forbid(unsafe_code)]
use std::collections::BTreeMap;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};

fn run(source: &str, lane: LaneChoice) -> Vec<String> {
    let mut orchestrator = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane),
        ..OrchestratorConfig::default()
    });
    let package = ExtensionPackage {
        extension_id: "web-streams".into(), source: source.into(),
        source_file: None, module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(), metadata: BTreeMap::new(),
    };
    orchestrator.execute(&package).expect("native stream completion")
        .console_output.into_iter().map(|entry| entry.message).collect()
}

#[test]
fn shared_readable_module_drains_real_promises_without_filesystem_authority() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let lines = run(
            "const web=require('node:stream/web');const alias=require('stream/web');\
             const WeakMap='guest';const Promise='guest';const Object='guest';\
             let n=0;const s=new web.ReadableStream({pull(c){if(n===3)c.close();else c.enqueue(++n);}});\
             (async function(){const values=[];for await(const value of s)values.push(value);\
             console.log('READABLE_COMPLETE',values.join(','),s.locked,web===alias);})();",
            lane,
        );
        assert_eq!(lines, ["READABLE_COMPLETE 1,2,3 false true"]);
    }
}

#[test]
fn reader_release_preserves_source_and_cancellation_is_exactly_once() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let lines = run(
            "const {ReadableStream}=require('stream/web');let c,cancels=0;\
             const s=new ReadableStream({start(x){c=x;},cancel(reason){cancels++;console.log(reason);}},\
             {highWaterMark:0});(async function(){const a=s.getReader();\
             const pending=a.read().catch(e=>e instanceof TypeError);a.releaseLock();\
             console.log('RELEASE',await pending,s.locked);const b=s.getReader();\
             const read=b.read();c.enqueue(42);console.log((await read).value);\
             await b.cancel('stop');await b.cancel('again');b.releaseLock();\
             console.log('CANCEL_COMPLETE',cancels,s.locked);})();", lane,
        );
        assert_eq!(lines, ["RELEASE true false", "42", "stop", "CANCEL_COMPLETE 1 false"]);
    }
}

#[test]
fn default_streams_feed_the_existing_shared_stream_consumer() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let lines = run(
            "const {ReadableStream}=require('stream/web');const {text}=require('stream/consumers');\
             text(new ReadableStream({start(c){c.enqueue('hello');c.enqueue(' world');c.close();}}))\
             .then(value=>console.log('CONSUMER_COMPLETE',value));", lane,
        );
        assert_eq!(lines, ["CONSUMER_COMPLETE hello world"]);
    }
}

#[test]
fn shared_transform_pipeline_finishes_ordered_writes_and_flush_on_both_lanes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let lines = run(
            "const web=require('stream/web');const AbortController='guest';\
             const AbortSignal='guest';const EventTarget='guest';const out=[];\
             const t=new web.TransformStream({async transform(value,c){await Promise.resolve();c.enqueue(value*2);},\
             flush(c){c.enqueue('end');}});\
             web.ReadableStream.from([1,2,3]).pipeThrough(t).pipeTo(\
             new web.WritableStream({write(value){out.push(value);}}))\
             .then(()=>console.log('PIPE_COMPLETE',out.join(','),t.readable.locked,t.writable.locked));", lane,
        );
        assert_eq!(lines, ["PIPE_COMPLETE 2,4,6,end false false"]);
    }
}

#[test]
fn signal_cancellation_releases_pipe_ownership_without_a_source_chunk() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let lines = run(
            "const web=require('node:stream/web');const controller=new AbortController();const events=[];\
             const r=new web.ReadableStream({cancel(reason){events.push('cancel:'+reason);}},{highWaterMark:0});\
             const w=new web.WritableStream({abort(reason){events.push('abort:'+reason);}});\
             const done=r.pipeTo(w,{signal:controller.signal});controller.abort('stop');\
             done.catch(reason=>console.log('PIPE_ABORT',reason,events.join(','),r.locked,w.locked));", lane,
        );
        assert_eq!(lines, ["PIPE_ABORT stop abort:stop,cancel:stop false false"]);
    }
}

#[test]
fn source_error_after_publication_does_not_drop_an_admitted_pipe_chunk() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let lines = run(
            "const web=require('stream/web');const out=[];\
             const r=new web.ReadableStream({pull(c){c.enqueue(42);c.error('after-read');}},{highWaterMark:0});\
             r.pipeTo(new web.WritableStream({write(value){out.push(value);},abort(reason){out.push(reason);}}))\
             .catch(reason=>console.log('PIPE_FAILURE',out.join(','),reason,r.locked));", lane,
        );
        assert_eq!(lines, ["PIPE_FAILURE 42,after-read after-read false"]);
    }
}

#[test]
fn native_cli_esm_imports_use_the_shared_stream_pipeline() {
    let root = tempfile::tempdir().expect("temporary project");
    let entry = root.path().join("main.mjs");
    std::fs::write(&entry,
        "import {ReadableStream as R,WritableStream as W,TransformStream as T} from 'node:stream/web';\
         const out=[];R.from([20,21]).pipeThrough(new T({transform(value,c){c.enqueue(value*2);}}))\
         .pipeTo(new W({write(value){out.push(value);}})).then(()=>console.log('ESM_PIPE',out.join(',')));"
    ).expect("write native ESM input");
    let report = root.path().join("report.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input"]).arg(&entry)
        .args(["--goal", "module", "--extension-id", "web-streams-esm", "--out"])
        .arg(&report).output().expect("execute native frankenctl");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let payload: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    let lines: Vec<_> = payload["console_output"].as_array().unwrap().iter()
        .map(|line| line["message"].as_str().unwrap()).collect();
    assert_eq!(lines, ["ESM_PIPE 40,42"]);
}
