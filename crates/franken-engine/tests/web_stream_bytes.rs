//! Native byte-stream integration. Host-factory checks do not execute these tests.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use frankenengine_engine::baseline_interpreter::LaneChoice;
use frankenengine_engine::execution_orchestrator::{
    ExecutionOrchestrator, ExtensionPackage, LabFixtureExecutionOrchestratorExt, OrchestratorConfig,
};

fn check(source: &str, expected: &[&str]) {
    for lane in [LaneChoice::QuickJs, LaneChoice::V8] {
        let mut engine = ExecutionOrchestrator::new(OrchestratorConfig {
            force_lane: Some(lane),
            ..OrchestratorConfig::default()
        });
        let package = ExtensionPackage {
            extension_id: "web-stream-bytes".into(),
            source: source.into(),
            source_file: None,
            module_root: None,
            capabilities: ["vm_dispatch", "heap_allocate", "builtin", "console"]
                .into_iter().map(str::to_string).collect(),
            version: "1.0.0".into(),
            metadata: BTreeMap::new(),
        };
        let actual: Vec<_> = engine.execute(&package).expect("native byte-stream completion")
            .console_output.into_iter().map(|line| line.message).collect();
        assert_eq!(actual, expected, "lane {lane:?}");
    }
}

const TYPES: &str = r#"
const web=require('stream/web'), alias=require('node:stream/web');
const ArrayBuffer='guest', DataView='guest', Uint8Array='guest', Int8Array='guest';
const Uint8ClampedArray='guest', Int16Array='guest', Uint16Array='guest';
const Int32Array='guest', Uint32Array='guest', Float32Array='guest', Float64Array='guest';
const BigInt64Array='guest', BigUint64Array='guest';
(async function(){
 let c;const s=new web.ReadableStream({type:'bytes',start(value){c=value;}});
 const backing=new globalThis.ArrayBuffer(12), view=new globalThis.DataView(backing,3,4);
 new globalThis.Uint8Array(backing,3,4).set([10,20,30,40]);c.enqueue(view);c.close();
 const r=new alias.ReadableStreamBYOBReader(s), supplied=new globalThis.Uint16Array(4);
 const pending=r.read(supplied,{min:2}), detached=supplied.byteLength;
 const item=await pending, last=await r.read(new globalThis.Uint8Array(2));r.releaseLock();
 console.log('TYPES',web===alias,c instanceof web.ReadableByteStreamController,
  backing.byteLength,detached,item.value instanceof globalThis.Uint16Array,
  Array.from(new globalThis.Uint8Array(item.value.buffer)).slice(0,4).join(','),last.done,s.locked);
})();
"#;

const PARTIAL: &str = r#"
const {ReadableStream}=require('node:stream/web');
(async function(){
 let n=0,stale=0;const offsets=[];
 const s=new ReadableStream({type:'bytes',pull(c){const q=c.byobRequest;offsets.push(q.view.byteOffset);
  if(n===6){c.close();q.respond(0);}else{q.view[0]=++n;q.respond(1);if(q.view===null)stale++;}}});
 const r=s.getReader({mode:'byob'}),a=await r.read(new Uint16Array(new ArrayBuffer(12),4,3),{min:2});
 const b=await r.read(new Uint16Array(4),{min:2});r.releaseLock();
 console.log('PARTIAL',Array.from(new Uint8Array(a.value.buffer,4,a.value.byteLength)).join(','),
  Array.from(new Uint8Array(b.value.buffer,0,b.value.byteLength)).join(','),a.done,b.done,stale,offsets.join(','));
})();
"#;

const AUTO_PIPE: &str = r#"
const {ReadableStream,WritableStream}=require('stream/web');
(async function(){
 let n=0,sum=0,closed=false,max=0,active=0;
 const s=new ReadableStream({type:'bytes',autoAllocateChunkSize:8,async pull(c){
  max=Math.max(max,++active);await Promise.resolve();const q=c.byobRequest;
  if(n===32){c.close();q.respond(0);}else{q.view[0]=++n;q.respond(1);}active--;
 }});
 const w=new WritableStream({write(chunk){sum+=chunk[0];},async close(){await Promise.resolve();closed=true;}});
 await s.pipeTo(w);console.log('AUTO_PIPE',n,sum,max,closed,s.locked,w.locked);
})();
"#;

const OWNERSHIP: &str = r#"
const {ReadableStream}=require('stream/web');
(async function(){
 let c,release,reason,cancelled=false;const s=new ReadableStream({type:'bytes',start(x){c=x;},
  cancel(value){reason=value;return new Promise(done=>{release=()=>{cancelled=true;done();};});}});
 const first=s.getReader({mode:'byob'}),p=first.read(new Uint8Array(8)).catch(e=>e instanceof TypeError);
 const pending=c.byobRequest;first.releaseLock();const failed=await p;
 const second=s.getReader({mode:'byob'}),q=second.read(new Uint8Array(8));
 pending.view.set([4,2]);pending.respond(2);const item=await q;
 const next=second.read(new Uint8Array(8)),cancel=second.cancel(false),end=await next;
 const before=cancelled;release();await cancel;second.releaseLock();
 console.log('OWNERSHIP',failed,Array.from(item.value).join(','),end.done,end.value===undefined,
  before,cancelled,reason===false,s.locked,pending.view===null);
})();
"#;

const TRUNCATED: &str = r#"
const {ReadableStream}=require('stream/web');
(async function(){
 let c;const s=new ReadableStream({type:'bytes',start(x){c=x;}}),r=s.getReader({mode:'byob'});
 const read=r.read(new Uint32Array(2)).catch(e=>e instanceof TypeError);
 const closed=r.closed.catch(e=>e instanceof TypeError);c.byobRequest.view[0]=1;c.byobRequest.respond(1);
 let failed=false;try{c.close();}catch(e){failed=e instanceof TypeError;}
 console.log('TRUNCATED',failed,await read,await closed,c.byobRequest===null,c.desiredSize===null);
})();
"#;

#[test]
fn byte_queues_move_buffers_and_protect_intrinsic_view_types() {
    check(TYPES, &["TYPES true true 0 0 true 10,20,30,40 true false"]);
}

#[test]
fn byob_minimums_preserve_partial_elements_and_aligned_eof() {
    check(PARTIAL, &["PARTIAL 1,2,3,4 5,6 false true 6 4,5,6,7,0,1,2"]);
}

#[test]
fn automatic_buffers_reach_the_existing_pipe_lifecycle() {
    check(AUTO_PIPE, &["AUTO_PIPE 32 528 1 true false false"]);
}

#[test]
fn released_reader_requests_and_joined_cancellation_preserve_ownership() {
    check(OWNERSHIP, &["OWNERSHIP true 4,2 true true false true true false true"]);
}

#[test]
fn incomplete_typed_elements_error_both_reader_promises() {
    check(TRUNCATED, &["TRUNCATED true true true true true"]);
}
