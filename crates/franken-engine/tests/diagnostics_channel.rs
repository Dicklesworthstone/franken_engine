//! Actual native orchestrator tests. Host-factory tests do not prove these pass.
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
        extension_id: "diagnostics-channel".into(), source: source.into(),
        source_file: None, module_root: None,
        capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
            .into_iter().map(str::to_string).collect(),
        version: "1.0.0".into(), metadata: BTreeMap::new(),
    };
    engine.execute(&package).expect("native diagnostics completion")
        .console_output.into_iter().map(|line| line.message).collect()
}

const CHANNELS: &str = r#"
const dc=require('diagnostics_channel'), alias=require('node:diagnostics_channel');
const Map='guest', WeakMap='guest', Array='guest', Object='guest', Reflect='guest';
const TypeError='guest', queueMicrotask='guest';
const c=dc.channel('example'), message={value:40}, out=[];
function receive(value,name){out.push(name+':'+value.value);value.value++;}
alias.subscribe('example',receive);c.subscribe(receive);c.publish(message);
console.log('CHANNELS',dc===alias,c===alias.channel('example'),out.join(','),message.value);
console.log('UNSUBSCRIBE',dc.unsubscribe('example',receive),c.hasSubscribers,
 c.unsubscribe(receive),dc.hasSubscribers('example'),c.unsubscribe(receive));
"#;

const REENTRANT: &str = r#"
const dc=require('node:diagnostics_channel'), c=dc.channel('reentrant'), out=[];
let nested=false;
function b(value){out.push('b'+value);}
function d(value){out.push('d'+value);}
c.subscribe(function(value){out.push('a'+value);if(!nested){nested=true;c.unsubscribe(b);c.subscribe(d);c.publish(2);}});
c.subscribe(b);c.publish(1);c.publish(3);
console.log('REENTRANT',out.join(','));
"#;

const STORES: &str = r#"
const dc=require('diagnostics_channel'), t=dc.tracingChannel('work'), events=[];
let current='outside';
const store={run(value,fn){const old=current;current=value;try{return fn();}finally{current=old;}}};
t.start.bindStore(store,c=>c.id);
for(const name of ['start','end','error'])t[name].subscribe(c=>events.push(name+':'+current+':'+c.id));
const context={id:'task'};
const result=t.traceSync(function(x){console.log('INSIDE',current,this.base+x);return this.base+x;},context,{base:40},2);
try{t.traceSync(()=>{throw false;},{id:'fail'});}catch(error){console.log('ERROR',error===false);}
console.log('TRACE',result,context.result,current,events.join(','));
"#;

#[test]
fn channels_preserve_identity_and_protected_realm_helpers_on_both_lanes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(CHANNELS,lane), [
            "CHANNELS true true example:40,example:41 42",
            "UNSUBSCRIBE true true true false false",
        ]);
    }
}

#[test]
fn reentrant_publication_uses_stable_subscriber_snapshots_on_both_lanes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(REENTRANT,lane), ["REENTRANT a1,a2,d2,b1,a3,d3"]);
    }
}

const PRIVATE_SUBSCRIBERS: &str = r#"
const dc=require('diagnostics_channel');
let interceptions=0, rows='', nested=false;
const c=dc.channel('private-snapshots');
function second(value){rows+='b'+value+',';}
function third(value){rows+='c'+value+',';}
function first(value){
 rows+='a'+value+',';
 if(!nested){nested=true;c.unsubscribe(second);c.subscribe(third);c.publish(2);}
}
Object.defineProperty(Array.prototype,'0',{configurable:true,set(value){interceptions++;}});
try {
 c.subscribe(first);c.subscribe(second);c.publish(1);c.publish(3);
 c.unsubscribe(first);c.unsubscribe(third);
} finally {delete Array.prototype[0];}
console.log('PRIVATE_SUBSCRIBERS',interceptions,rows,c.hasSubscribers);
let calls=0, removed=false;
function subscriber(){calls++;}
Object.defineProperty(Object.prototype,'0',{value:'blocked',writable:false,configurable:true});
try {c.subscribe(subscriber);c.subscribe(subscriber);c.publish(1);c.unsubscribe(subscriber);c.publish(2);removed=c.unsubscribe(subscriber);}
finally {delete Object.prototype[0];}
console.log('FROZEN_SUBSCRIBERS',calls,removed,c.hasSubscribers);
let constructors=0;
const original=Object.getOwnPropertyDescriptor(Array.prototype,'constructor');
Object.defineProperty(Array.prototype,'constructor',{configurable:true,get(){constructors++;throw new Error('private array escaped');}});
try {c.subscribe(subscriber);c.publish(3);c.unsubscribe(subscriber);}
finally {Object.defineProperty(Array.prototype,'constructor',original);}
console.log('PRIVATE_SPECIES',constructors,calls,c.hasSubscribers);
"#;

#[test]
fn subscriber_snapshots_resist_inherited_indices_and_species_on_both_lanes() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(
            run(PRIVATE_SUBSCRIBERS, lane),
            [
                "PRIVATE_SUBSCRIBERS 0 a1,a2,c2,b1,a3,c3, false",
                "FROZEN_SUBSCRIBERS 3 true false",
                "PRIVATE_SPECIES 0 4 false",
            ]
        );
    }
}

#[test]
fn store_scopes_and_sync_tracing_preserve_result_receiver_and_falsy_errors() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(STORES,lane), ["INSIDE task 42", "ERROR true",
            "TRACE 42 42 outside start:task:task,end:task:task,start:fail:fail,error:fail:fail,end:fail:fail"]);
    }
}

const PROMISE_TRACES: &str = r#"
const dc=require('node:diagnostics_channel'), trace=dc.tracingChannel('async'), events=[];
for(const name of ['start','end','asyncStart','asyncEnd','error'])
 trace[name].subscribe(context=>events.push(name+':'+context.id));
(async function(){
 const success={id:'ok'}, failure={id:'bad'};
 const value=await trace.tracePromise(async function(add){await Promise.resolve();return this.base+add;},success,{base:40},2);
 let same=false;
 try{await trace.tracePromise(async function(){await Promise.resolve();throw false;},failure);}
 catch(error){same=error===false;}
 console.log('PROMISE_TRACE',value,success.result,same,failure.error===false,events.join(','));
})();
"#;

const CALLBACK_TRACES: &str = r#"
const dc=require('diagnostics_channel'), trace=dc.tracingChannel('callback'), events=[];
let current='outer', callback;
const store={run(value,fn){const old=current;current=value;try{return fn();}finally{current=old;}}};
trace.asyncStart.bindStore(store,context=>context.result);
for(const name of ['start','end','asyncStart','asyncEnd'])trace[name].subscribe(()=>events.push(name+':'+current));
const receiver={base:40}, callbackReceiver={name:'callback'}, context={};
const returned=trace.traceCallback(function(add,done){callback=done;return this.base+add;},-1,context,receiver,2,
 function(error,value,extra){events.push('callback:'+this.name+':'+current+':'+extra);});
Promise.resolve().then(function(){callback.call(callbackReceiver,null,42,'extra');})
 .then(function(){console.log('CALLBACK_TRACE',returned,context.result,current,events.join(','));});
"#;

#[test]
fn promise_traces_observe_settlement_and_preserve_original_falsy_rejections() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(PROMISE_TRACES, lane), [
            "PROMISE_TRACE 42 42 true true start:ok,end:ok,asyncStart:ok,asyncEnd:ok,start:bad,end:bad,error:bad,asyncStart:bad,asyncEnd:bad",
        ]);
    }
}

#[test]
fn callback_traces_restore_scopes_and_keep_both_receivers_and_all_arguments() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(CALLBACK_TRACES, lane), [
            "CALLBACK_TRACE 42 42 outer start:outer,end:outer,asyncStart:42,callback:callback:42:extra,asyncEnd:42",
        ]);
    }
}

const ESM_TRACES: &str = r#"
import dc, {tracingChannel as tracing} from 'node:diagnostics_channel';
const trace=tracing('esm'), same=dc.channel('tracing:esm:end')===trace.end, rows=[];
trace.end.subscribe(context=>rows.push('end:'+context.id));
trace.asyncEnd.subscribe(context=>rows.push('done:'+context.result));
trace.tracePromise(async function(){await Promise.resolve();return 42;},{id:'job'})
 .then(value=>console.log('ESM_DIAGNOSTICS',same,value,rows.join(',')));
"#;

#[test]
fn esm_default_and_named_imports_execute_the_canonical_diagnostics_factory() {
    let root = tempfile::tempdir().expect("temporary project");
    let entry = root.path().join("main.mjs");
    std::fs::write(&entry, ESM_TRACES).expect("write ESM program");
    let report = root.path().join("report.json");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_frankenctl"))
        .args(["run", "--input"]).arg(&entry)
        .args(["--goal", "module", "--extension-id", "diagnostics-esm", "--out"])
        .arg(&report).output().expect("execute native frankenctl");
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    let payload: serde_json::Value = serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    let lines: Vec<_> = payload["console_output"].as_array().unwrap().iter()
        .map(|line| line["message"].as_str().unwrap()).collect();
    assert_eq!(lines, ["ESM_DIAGNOSTICS true 42 end:job,done:42"]);
}
