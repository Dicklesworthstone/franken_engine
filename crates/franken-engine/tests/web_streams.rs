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
