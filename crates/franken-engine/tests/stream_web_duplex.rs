//! Duplex interop through the native orchestrator and CLI. The host-only
//! scripts/tests/stream_web_duplex.cjs suite cannot prove these native paths.
#![forbid(unsafe_code)]
use std::collections::BTreeMap;
use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};

fn run(source: &str, lane: LaneChoice) -> Vec<String> {
    let mut engine = ExecutionOrchestrator::new(OrchestratorConfig {
        force_lane: Some(lane), ..OrchestratorConfig::default()
    });
    let package = ExtensionPackage {
        extension_id: "stream-web-duplex".into(), source: source.into(),
        source_file: None, module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(), metadata: BTreeMap::new(),
    };
    engine.execute(&package).expect("native duplex completion")
        .console_output.into_iter().map(|entry| entry.message).collect()
}

const ROUNDTRIP: &str = r#"
const s=require('node:stream');
const Object='guest', Promise='guest', Reflect='guest', TypeError='guest';
const inner=new s.Transform({objectMode:true,transform(value,encoding,done){done(null,value*2);}});
const pair=s.Duplex.toWeb(inner),duplex=s.Duplex.fromWeb(pair,{objectMode:true}),out=[];
s.promises.pipeline(s.Readable.from([20,21]),duplex,
 new s.Writable({objectMode:true,write(value,encoding,done){out.push(value);done();}}))
 .then(()=>console.log('DUPLEX_ROUNDTRIP',out.join(','),inner.writableFinished));
"#;

#[test]
fn node_only_import_roundtrips_through_the_canonical_lazy_web_module() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(ROUNDTRIP, lane), ["DUPLEX_ROUNDTRIP 40,42 true"]);
    }
}

const EXPLICIT: &str = r#"
const {Duplex:D}=require('node:stream');const web=require('stream/web');
const transform=new web.TransformStream({transform(value,c){c.enqueue(value+1);},flush(c){c.enqueue('done');}});
const d=D.fromWeb(transform,{objectMode:true}),out=[];
d.on('data',value=>out.push(value));
d.on('end',()=>console.log('DUPLEX_WEB_COMPLETE',out.join(','),transform.readable.locked,transform.writable.locked));
d.write(40);d.end(41);
"#;

#[test]
fn destructured_duplex_reuses_explicit_web_endpoints_and_observes_flush() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(EXPLICIT, lane), ["DUPLEX_WEB_COMPLETE 41,42,done true true"]);
    }
}

const CLEANUP: &str = r#"
const s=require('stream'),web=require('stream/web'),calls=[];
const r=new web.ReadableStream({cancel(reason){calls.push('cancel:'+reason.message);}},{highWaterMark:0});
const w=new web.WritableStream({abort(reason){calls.push('abort:'+reason.message);}});
const d=s.Duplex.fromWeb({readable:r,writable:w});
d.on('error',error=>calls.push('error:'+error.message));
d.on('close',()=>console.log('DUPLEX_CLEANUP',calls.join(','),r.locked,w.locked));
d.destroy(new Error('stop'));
"#;

#[test]
fn duplex_destruction_completes_both_endpoint_lifetimes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(CLEANUP, lane), ["DUPLEX_CLEANUP cancel:stop,abort:stop,error:stop true true"]);
    }
}

const ESM: &str = r#"
import {Duplex, Transform, Readable, Writable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
const transform=new Transform({objectMode:true,transform(value,encoding,done){done(null,value+2);}});
const endpoint=Duplex.fromWeb(Duplex.toWeb(transform),{objectMode:true}),out=[];
pipeline(Readable.from([40]),endpoint,new Writable({objectMode:true,write(value,encoding,done){out.push(value);done();}}))
 .then(()=>console.log('ESM_DUPLEX',out.join(',')));
"#;

#[test]
fn esm_named_duplex_imports_execute_on_the_native_cli() {
    let root = tempfile::tempdir().expect("temporary project");
    let entry = root.path().join("main.mjs");
    std::fs::write(&entry, ESM).expect("write source");
    let report = root.path().join("report.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input"]).arg(entry)
        .args(["--goal", "module", "--extension-id", "stream-web-duplex", "--out"])
        .arg(&report).output().expect("native CLI");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let payload: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    let lines: Vec<_> = payload["console_output"].as_array().unwrap().iter()
        .map(|entry| entry["message"].as_str().unwrap()).collect();
    assert_eq!(lines, ["ESM_DUPLEX 42"]);
}
