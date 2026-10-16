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

const TEE_VIEWS: &str = r#"
const web=require('node:stream/web'),alias=require('stream/web');
const Uint8Array='guest',ArrayBuffer='guest',Uint16Array='guest';
(async function(){
 let n=0;const s=new web.ReadableStream({type:'bytes',pull(c){const q=c.byobRequest;
  if(n===8){c.close();if(q)q.respond(0);}else if(q){q.view[0]=++n;q.respond(1);}
  else{c.enqueue(new globalThis.Uint8Array([++n]));}}});
 const pair=s.tee(),a=pair[0].getReader({mode:'byob'}),b=new alias.ReadableStreamBYOBReader(pair[1]);
 const pa=a.read(new globalThis.Uint16Array(4),{min:3}),pb=b.read(new globalThis.Uint8Array(8),{min:8});
 const x=await pa,bytes=new globalThis.Uint8Array(x.value.buffer),first=Array.from(bytes.slice(0,x.value.byteLength)).join(',');
 bytes[0]=255;const y=await pb,tail=await a.read(new globalThis.Uint8Array(8));
 const ends=await Promise.all([a.read(new globalThis.Uint8Array(2)),b.read(new globalThis.Uint8Array(2))]);
 a.releaseLock();b.releaseLock();
 console.log('TEE_VIEWS',first,Array.from(y.value).join(','),Array.from(tail.value).join(','),
  ends[0].done,ends[1].done,s.locked,pair[0].locked,pair[1].locked);
})();
"#;

const TEE_CANCEL: &str = r#"
const {ReadableStream}=require('stream/web');
(async function(){
 let release,reason,calls=0,finished=false;const ready=new Promise(done=>release=done);
 const s=new ReadableStream({type:'bytes',cancel(value){reason=value;calls++;return ready.then(()=>{finished=true;});}});
 const pair=s.tee(),a=pair[0].getReader({mode:'byob'}),b=pair[1].getReader();
 const pending=[a.read(new Uint8Array(8)),b.read()];const cb=b.cancel(false),ca=a.cancel('first');
 const before=finished,values=await Promise.all(pending);release();await Promise.all([ca,cb]);a.releaseLock();b.releaseLock();
 console.log('TEE_CANCEL',before,finished,calls,reason[0],reason[1]===false,values[0].done,
  values[0].value===undefined,values[1].done,s.locked,pair[0].locked,pair[1].locked);
})();
"#;

const TEE_ERRORS: &str = r#"
const {ReadableStream}=require('node:stream/web');
(async function(){
 const failure={code:'source'};const s=new ReadableStream({type:'bytes',pull(c){const q=c.byobRequest;
  if(q){q.view[0]=7;q.respond(1);}else c.enqueue(new Uint8Array([7]));c.error(failure);}});
 const pair=s.tee(),a=pair[0].getReader({mode:'byob'}),b=pair[1].getReader();
 const closed=[a.closed.catch(e=>e===failure),b.closed.catch(e=>e===failure)];
 const values=await Promise.all([a.read(new Uint8Array(8)),b.read()]);
 const failed=await Promise.all(closed);a.releaseLock();b.releaseLock();
 console.log('TEE_ERRORS',values[0].value[0],values[1].value[0],failed[0],failed[1]);
})();
"#;

const TEE_NESTED: &str = r#"
const {ReadableStream}=require('stream/web');
(async function(){
 let at=0;const s=new ReadableStream({type:'bytes',autoAllocateChunkSize:8,async pull(c){
  await Promise.resolve();const q=c.byobRequest;if(at===32){c.close();q.respond(0);}else{q.view[0]=++at;q.respond(1);}}});
 const pair=s.tee(),nested=pair[0].tee();
 async function consume(stream){const r=stream.getReader({mode:'byob'});let buffer=new ArrayBuffer(16),sum=0,count=0;
  for(;;){const x=await r.read(new Uint8Array(buffer,4,8),{min:8});buffer=x.value.buffer;
   for(const byte of x.value){sum+=byte;count++;}x.value.fill(255);if(x.done)break;}r.releaseLock();return count+':'+sum;}
 const results=await Promise.all([consume(nested[0]),consume(nested[1]),consume(pair[1])]);
 console.log('TEE_NESTED',results.join(','),s.locked,pair[0].locked);
})();
"#;

#[test]
fn byte_tee_preserves_typed_views_and_isolates_sibling_writes() {
    check(TEE_VIEWS, &["TEE_VIEWS 1,2,3,4,5,6 1,2,3,4,5,6,7,8 7,8 true true true false false"]);
}

#[test]
fn byte_tee_cancellations_join_one_upstream_cleanup_in_branch_order() {
    check(TEE_CANCEL, &["TEE_CANCEL false true 1 first true true true true true false false"]);
}

#[test]
fn byte_tee_keeps_admitted_chunks_before_later_source_errors() {
    check(TEE_ERRORS, &["TEE_ERRORS 7 7 true true"]);
}

#[test]
fn nested_byte_tees_serialize_the_source_and_preserve_all_consumers() {
    check(TEE_NESTED, &["TEE_NESTED 32:528,32:528,32:528 true true"]);
}
