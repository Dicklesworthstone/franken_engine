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

#[test]
fn store_scopes_and_sync_tracing_preserve_result_receiver_and_falsy_errors() {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        assert_eq!(run(STORES,lane), ["INSIDE task 42", "ERROR true",
            "TRACE 42 42 outside start:task:task,end:task:task,start:fail:fail,error:fail:fail,end:fail:fail"]);
    }
}
