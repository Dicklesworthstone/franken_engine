'use strict';
// Exact production factory on host primitives, NOT native-engine execution.
const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const reference = require('node:stream/web');
const sourcePath = process.env.WEB_STREAM_SOURCE || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/web_stream_module.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const primitives = {Promise, Reflect, Object, TypeError, RangeError, WeakMap, Symbol,
  AbortController, AbortSignal, EventTarget, ArrayBuffer, DataView, Uint8Array,
  Uint8ClampedArray, Int8Array, Int16Array, Uint16Array, Int32Array, Uint32Array,
  Float32Array, Float64Array, BigInt64Array, BigUint64Array};
function candidate() { return vm.runInNewContext(source, primitives, {filename:sourcePath}); }
const flush = async () => { for (let i=0;i<12;i++) await Promise.resolve(); };
const bytes = value => value === undefined ? null : Array.from(new Uint8Array(value.buffer,value.byteOffset,value.byteLength));
function plain(value) { return JSON.parse(JSON.stringify(value)); }
async function both(fn) { const expected=plain(await fn(reference)); assert.deepEqual(plain(await fn(candidate())),expected); }
function check(name, fn) { test(name,{timeout:3000},fn); }
function byteSource(api, data, size=3) {
  let offset=0;
  return new api.ReadableStream({type:'bytes',pull(c){
    if(offset===data.length) {c.close(); if(c.byobRequest) c.byobRequest.respond(0); return;}
    if(c.byobRequest) {
      const r=c.byobRequest, count=Math.min(size,r.view.length,data.length-offset);
      r.view.set(data.subarray(offset,offset+count)); offset+=count; r.respond(count);
    } else {const count=Math.min(size,data.length-offset);c.enqueue(data.slice(offset,offset+count));offset+=count;}
  }});
}
check('byte controller and BYOB reader are distinct brands', async()=>both(async api=>{
  let c; const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}), r=s.getReader({mode:'byob'});
  const out=[c instanceof api.ReadableByteStreamController, r instanceof api.ReadableStreamBYOBReader,
    c.byobRequest===null, c.desiredSize, Object.prototype.toString.call(r)];
  assert.throws(()=>new api.ReadableStreamBYOBReader(new api.ReadableStream()),TypeError);
  assert.throws(()=>new api.ReadableByteStreamController(),TypeError);
  assert.throws(()=>new api.ReadableStreamBYOBRequest(),TypeError);
  await assert.rejects(api.ReadableStreamDefaultReader.prototype.read.call(r),TypeError);
  await r.cancel(); return out;
}));
check('byte queue moves all aliases and returns only the original viewed range',async()=>both(async api=>{
  let c; const s=new api.ReadableStream({type:'bytes',start(x){c=x;}});
  const b=new ArrayBuffer(12), all=new Uint8Array(b);all.set([0,1,2,3,4,5,6,7,8]);
  c.enqueue(new DataView(b,2,5)); const detached=[b.byteLength,all.length];c.close();
  const r=s.getReader(), item=await r.read(), end=await r.read();
  return [detached,bytes(item.value),item.value.byteOffset,item.value.buffer.byteLength,item.done,end.done];
}));
check('byte high-water mark measures bytes and defaults to no speculative pull',async()=>both(async api=>{
  let count=0,c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;},pull(){count++;}});
  await flush();const initial=count;c.enqueue(new Uint8Array([1,2,3]));const pressure=c.desiredSize;
  const r=s.getReader();await r.read();await flush();await r.cancel();
  return [initial,pressure,count];
}));
check('invalid chunks cannot poison a byte stream or detach their allocations',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}});
  for(const bad of [undefined,null,1,'x',{},new ArrayBuffer(4),new Uint8Array(0)]) assert.throws(()=>c.enqueue(bad),TypeError);
  const b=new SharedArrayBuffer(4);assert.throws(()=>c.enqueue(new Uint8Array(b)),TypeError);
  c.enqueue(new Uint8Array([42]));c.close();return bytes((await s.getReader().read()).value);
}));
check('byte strategies reject arbitrary size callbacks',()=>{
  for(const api of [reference,candidate()]){
    assert.throws(()=>new api.ReadableStream({type:'bytes'},{size(){return 1;}}),RangeError);
    assert.throws(()=>new api.ReadableStream({type:'unknown'}),TypeError);
    assert.throws(()=>new api.ReadableStream().getReader({mode:'byob'}),TypeError);
  }
});
for(const Ctor of [Uint8Array,Uint8ClampedArray,Int8Array,Uint16Array,Int16Array,Uint32Array,Int32Array,
  Float32Array,Float64Array,BigInt64Array,BigUint64Array,DataView]) {
  check('BYOB preserves intrinsic view type and byte offsets: '+Ctor.name,async()=>both(async api=>{
    const element=Ctor.BYTES_PER_ELEMENT||1, buf=new ArrayBuffer(element*8), view=new Ctor(buf,element*2,3);
    const s=byteSource(api,new Uint8Array(element*3).fill(37),element*3),r=s.getReader({mode:'byob'});
    const pending=r.read(view), detached=buf.byteLength;
    const item=await pending;const out=[detached,item.value.constructor.name,item.value.byteOffset,
      item.value.buffer.byteLength,bytes(item.value),item.done];await r.cancel();return out;
  }));
}
check('min reads accumulate across partial source responses and invalidate each request',async()=>both(async api=>{
  const offsets=[],stale=[];let n=0;
  const s=new api.ReadableStream({type:'bytes',pull(c){const req=c.byobRequest;
    offsets.push(req.view.byteOffset);req.view[0]=++n;req.respond(1);
    stale.push(req.view===null);assert.throws(()=>req.respond(1),TypeError);
  }});
  const r=s.getReader({mode:'byob'}), item=await r.read(new Uint16Array(new ArrayBuffer(12),4,3),{min:2});
  await r.cancel();return [offsets,stale,bytes(item.value),item.value.length,item.done];
}));
check('enqueue fills pending BYOB reads across chunks and retains incomplete-element remainder',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}), r=s.getReader({mode:'byob'});
  const p=r.read(new Uint16Array(4),{min:2});c.enqueue(new Uint8Array([1,2,3]));c.enqueue(new Uint8Array([4,5,6,7]));
  const a=await p,b=await r.read(new Uint8Array(3));c.close();const end=await r.read(new Uint8Array(2));
  return [bytes(a.value),bytes(b.value),bytes(end.value),end.done];
}));
check('queued bytes drain without an extra pull and closed reads return an empty typed view',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;c.enqueue(new Uint8Array([1,2,3,4]));c.close();}});
  const r=s.getReader({mode:'byob'}), a=await r.read(new Uint16Array(8));
  const b=new ArrayBuffer(8), last=await r.read(new DataView(b,3,2));
  return [bytes(a.value),a.done,c.desiredSize,last.done,last.value.constructor.name,last.value.byteOffset,b.byteLength];
}));
check('close alone leaves a pending BYOB read for the producer EOF acknowledgement',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}),r=s.getReader({mode:'byob'});
  let settled=false;const p=r.read(new Uint8Array(5)).then(v=>{settled=true;return v;});
  c.close();await flush();const before=settled, req=c.byobRequest;req.respond(0);const end=await p;
  return [before,end.done,bytes(end.value),req.view,c.byobRequest];
}));
check('EOF returns an aligned partial min read and rejects an incomplete typed element',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}),r=s.getReader({mode:'byob'});
  const p=r.read(new Uint16Array(4),{min:3});c.byobRequest.view.set([1,2]);c.byobRequest.respond(2);
  c.close();c.byobRequest.respond(0);const part=await p;
  let bad;const broken=new api.ReadableStream({type:'bytes',start(x){bad=x;}}),br=broken.getReader({mode:'byob'});
  const q=br.read(new Uint16Array(4));const rejected=assert.rejects(q,TypeError), closed=assert.rejects(br.closed,TypeError);
  bad.byobRequest.view[0]=1;bad.byobRequest.respond(1);assert.throws(()=>bad.close(),TypeError);await rejected;await closed;
  return [part.done,bytes(part.value),bad.byobRequest];
}));
check('cancel joins actual cleanup and resolves pending reads without fabricating a buffer',async()=>both(async api=>{
  let release,c,calls=0,reason;const s=new api.ReadableStream({type:'bytes',start(x){c=x;},cancel(v){calls++;reason=v;return new Promise(r=>release=r);}});
  const r=s.getReader({mode:'byob'}),p=r.read(new Uint8Array(5)),req=c.byobRequest;
  let settled=false;const stop=r.cancel(false).then(()=>settled=true);const end=await p;await flush();const before=settled;
  release();await stop;return [calls,reason,end.done,end.value,before,settled,req.view,c.byobRequest];
}));
check('reader release rejects every outstanding read but preserves the first producer-owned request',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}),r=s.getReader({mode:'byob'});
  const first=r.read(new Uint8Array(4)),second=r.read(new Uint8Array(3));
  const failures=[assert.rejects(first,TypeError),assert.rejects(second,TypeError),assert.rejects(r.closed,TypeError)];
  const req=c.byobRequest;r.releaseLock();await Promise.all(failures);
  const next=s.getReader({mode:'byob'}),p=next.read(new Uint8Array(4));req.view.set([5,6]);req.respond(2);
  const item=await p;await next.cancel();return [bytes(item.value),req.view];
}));
check('released partially filled read contributes its accepted bytes to the next reader',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}),r=s.getReader({mode:'byob'});
  const p=r.read(new Uint16Array(4),{min:3}),reject=assert.rejects(p,TypeError);
  c.byobRequest.view.set([1,2]);c.byobRequest.respond(2);const req=c.byobRequest;
  r.releaseLock();await reject;const next=s.getReader({mode:'byob'}),q=next.read(new Uint8Array(8));
  req.view.set([3,4]);req.respond(2);const item=await q;await next.cancel();return bytes(item.value);
}));
check('respondWithNewView accepts a transferred producer allocation, invalidates only the current request',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}),r=s.getReader({mode:'byob'});
  const p=r.read(new Uint8Array(new ArrayBuffer(12),3,5));const req=c.byobRequest;
  const buffer=req.view.buffer.transfer();new Uint8Array(buffer,3,2).set([40,42]);
  req.respondWithNewView(new DataView(buffer,3,2));const item=await p;await r.cancel();
  return [buffer.byteLength,req.view,bytes(item.value),item.value.byteOffset];
}));
check('respond validation leaves an active request recoverable',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}),r=s.getReader({mode:'byob'}),p=r.read(new Uint8Array(4));
  const req=c.byobRequest;assert.throws(()=>req.respond(0),TypeError);assert.throws(()=>req.respond(5),RangeError);
  assert.throws(()=>req.respondWithNewView(new Uint8Array(8)),RangeError);
  req.view.set([7,8]);req.respond(2);const item=await p;await r.cancel();return bytes(item.value);
}));
check('automatic buffers allow a BYOB-only producer to serve default readers',async()=>both(async api=>{
  let calls=0;const lengths=[];const s=new api.ReadableStream({type:'bytes',autoAllocateChunkSize:8,pull(c){
    const req=c.byobRequest;lengths.push(req.view.length);
    if(calls++===2){c.close();req.respond(0);}else{req.view.set([1,2,3]);req.respond(3);}
  }});const out=[];for await(const chunk of s)out.push(bytes(chunk));return [out,lengths,s.locked];
}));
check('byte pipes use the same writer lifecycle and preserve final bytes',async()=>both(async api=>{
  const source=byteSource(api,new Uint8Array([1,2,3,4,5]),2),out=[];let closed=false;
  const target=new api.WritableStream({async write(v){await Promise.resolve();out.push(...v);},async close(){await Promise.resolve();closed=true;}});
  await source.pipeTo(target);return [out,closed,source.locked,target.locked];
}));
check('spec-defined intrinsic view construction ignores shadow properties (recorded Node difference)',async()=>{
  async function probe(api) {
    class Sub extends Uint16Array {} const v=new Sub(new ArrayBuffer(16),4,4);
    for(const k of ['buffer','byteOffset','byteLength','constructor'])Object.defineProperty(v,k,{get(){throw Error('guest '+k);}});
    const r=byteSource(api,new Uint8Array([1,2,3,4]),4).getReader({mode:'byob'});
    try {const item=await r.read(v);return [item.value.constructor.name,item.value.byteOffset,bytes(item.value)];}
    finally {await r.cancel();}
  }
  await assert.rejects(probe(reference),/guest constructor/);
  assert.deepEqual(await probe(candidate()),['Uint16Array',4,[1,2,3,4]]);
});
check('source errors preserve falsy identity and invalidate the pending request',async()=>both(async api=>{
  const out=[];
  for(const value of [undefined,null,false,0,'']){
    let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}),r=s.getReader({mode:'byob'});
    const p=r.read(new Uint8Array(4)).then(()=>false,e=>Object.is(e,value));
    const closed=r.closed.then(()=>false,e=>Object.is(e,value)),req=c.byobRequest;c.error(value);
    out.push(await p,await closed,req.view===null,c.byobRequest===null);
  }return out;
}));
check('4096 asynchronous BYOB responses preserve serial pulls and byte order',async()=>both(async api=>{
  let n=0,active=0,peak=0;const s=new api.ReadableStream({type:'bytes',async pull(c){peak=Math.max(peak,++active);await Promise.resolve();
    const req=c.byobRequest;if(n===4096){c.close();req.respond(0);}else{req.view[0]=n++%251;req.respond(1);}active--;}});
  const r=s.getReader({mode:'byob'});let count=0,sum=0;
  for(;;){const item=await r.read(new Uint8Array(17),{min:7});for(const v of item.value){assert.equal(v,count++%251);sum+=v;}if(item.done)break;}
  r.releaseLock();return [count,sum,peak,s.locked];
}));

check('buffer transfers preserve resizable backing allocation bounds',async()=>both(async api=>{
  const b=new ArrayBuffer(8,{maxByteLength:20});
  const s=new api.ReadableStream({type:'bytes',start(c){c.enqueue(new Uint8Array(b,2,3));c.close();}});
  const item=await s.getReader().read();return [b.byteLength,item.value.buffer.resizable,item.value.buffer.maxByteLength,item.value.byteOffset];
}));

check('invalid min and detached views do not consume queued data or detach valid arguments',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}),r=s.getReader({mode:'byob'});
  for(const min of [0,-1,5,NaN,Infinity,1.5,'2',{}]){
    const v=new Uint16Array(4);await assert.rejects(r.read(v,{min}),min===5 ? RangeError : TypeError);assert.equal(v.byteLength,8);
  }
  for(const min of [1n,Symbol('min')])await assert.rejects(r.read(new Uint8Array(4),{min}),TypeError);
  const detached=new Uint8Array(8);detached.buffer.transfer();await assert.rejects(r.read(detached),TypeError);
  c.enqueue(new Uint8Array([4,2]));c.close();return bytes((await r.read(new Uint8Array(8))).value);
}));
check('min getter may release the reader without granting the old reader ownership',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}),r=s.getReader({mode:'byob'}),v=new Uint8Array(8);
  await assert.rejects(r.read(v,{get min(){r.releaseLock();return 1;}}),TypeError);
  c.enqueue(new Uint8Array([9]));c.close();return [v.byteLength,bytes((await s.getReader().read()).value)];
}));
check('respond coercion may cancel or replace the active request without resurrecting it',async()=>both(async api=>{
  let c;const s=new api.ReadableStream({type:'bytes',start(x){c=x;}}),r=s.getReader({mode:'byob'}),pending=r.read(new Uint8Array(4));
  const req=c.byobRequest;let cleanup;
  assert.throws(()=>req.respond({valueOf(){cleanup=r.cancel('during count');return 1;}}),TypeError);
  const end=await pending;await cleanup;return [end.done,end.value,req.view,c.byobRequest];
}));
check('queued min fills agree for 192 fixed-seed partitions and typed capacities',async()=>{
  let seed=9217;function next(){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed;}
  for(let trial=0;trial<192;trial++){
    const width=[1,2,4,8][next()%4],Ctor={1:Uint8Array,2:Uint16Array,4:Uint32Array,8:BigUint64Array}[width];
    const count=1+next()%12,total=width*(1+next()%24),chunkSize=1+next()%17,min=1+next()%count;
    const data=Uint8Array.from({length:total},(_,i)=>(i*19+trial)%251);
    await both(async api=>{
      const r=byteSource(api,data,chunkSize).getReader({mode:'byob'}),out=[];
      for(;;){const item=await r.read(new Ctor(count),{min});out.push([bytes(item.value),item.done]);if(item.done)break;}
      r.releaseLock();assert.deepEqual(out.flatMap(x=>x[0]),Array.from(data));return out;
    });
  }
});
