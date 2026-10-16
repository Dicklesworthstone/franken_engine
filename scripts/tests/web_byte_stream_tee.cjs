'use strict';
// Byte fan-out over the exact engine-owned factory on host primitives.
// Contract: https://streams.spec.whatwg.org/#readable-byte-stream-tee This does not
// execute Franken's Rust parser/interpreter or prove native resource accounting.
// Node is a behavioral oracle only; no host stream enters the candidate factory.
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const reference = require('node:stream/web');
const source = process.env.WEB_STREAM_SOURCE || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/web_stream_module.js');
const primitiveNames = ['ArrayBuffer','DataView','Int8Array','Uint8Array','Uint8ClampedArray',
  'Int16Array','Uint16Array','Int32Array','Uint32Array','Float32Array','Float64Array',
  'BigInt64Array','BigUint64Array'];
function candidate(extra = {}) {
  const context = {AbortController,AbortSignal,EventTarget, ...extra};
  for (const name of primitiveNames) if (!(name in context)) context[name] = globalThis[name];
  return vm.runInNewContext(fs.readFileSync(source,'utf8'), context, {filename:source});
}
function flat(value) { return JSON.parse(JSON.stringify(value)); }
function view(value) {
  return value === undefined ? null : [Object.prototype.toString.call(value),
    value.byteOffset, value.byteLength, value.buffer.byteLength,
    [...new Uint8Array(value.buffer, value.byteOffset, value.byteLength)]];
}
function readResult(result) { return [result.done,view(result.value)]; }
async function collect(stream) { const out=[]; for await(const chunk of stream)out.push([...chunk]); return out; }
function defer() { let resolve,reject; const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject}; }
function bounded(promise, role) {
  let timer; return Promise.race([promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error(role+' did not settle')),1500)})]).finally(()=>clearTimeout(timer));
}
function compare(name, operation) {
  test(name,{timeout:5000},async()=> {
    const expected=await bounded(operation(reference),'reference: '+name), actual=await bounded(operation(candidate()),'candidate: '+name);
    assert.deepEqual(flat(actual),flat(expected));
  });
}
const tick = () => new Promise(resolve=>setImmediate(resolve));

compare('byte tee supports different BYOB minimums and isolates sibling mutations',async w=>{
 let i=0;const s=new w.ReadableStream({type:'bytes',pull(c){const q=c.byobRequest;
   if(i===8){c.close();if(q)q.respond(0);return}
   if(q){q.view[0]=++i;q.respond(1)}else{c.enqueue(new Uint8Array([++i]))}}});
 const [a,b]=s.tee(),ra=a.getReader({mode:'byob'}),rb=b.getReader({mode:'byob'});
 const pa=ra.read(new Uint16Array(4),{min:3}), pb=rb.read(new Uint8Array(8),{min:8});
 const av=await pa;const before=view(av.value);new Uint8Array(av.value.buffer)[0]=255;
 const bv=await pb;const rest=await ra.read(new Uint8Array(8));const endA=await ra.read(new Uint8Array(2));const endB=await rb.read(new Uint8Array(2));
 ra.releaseLock();rb.releaseLock();return [before,readResult(bv),readResult(rest),readResult(endA),readResult(endB),s.locked];
});
compare('byte tee switches upstream reader kinds across branch demand',async w=>{
 let i=0;const s=new w.ReadableStream({type:'bytes',autoAllocateChunkSize:3,pull(c){const q=c.byobRequest;
  if(i===3){c.close();if(q)q.respond(0);return}q.view[0]=++i;q.respond(1)}});
 const [a,b]=s.tee(),ra=a.getReader(),rb=b.getReader({mode:'byob'});
 const one=await ra.read(),two=await rb.read(new Uint8Array(2));const three=await rb.read(new Uint8Array(2));
 const cancellation=ra.cancel('unused');const four=await rb.read(new Uint8Array(2));const end=await rb.read(new Uint8Array(2));
 await cancellation;ra.releaseLock();rb.releaseLock();return [one,two,three,four,end].map(readResult);
});


compare('tee cancellation is branch-ordered and waits for the source cleanup',async w=>{
 let reasons;const wait=defer();const s=new w.ReadableStream({type:'bytes',cancel(x){reasons=x;return wait.promise}}),[a,b]=s.tee();
 const ra=a.getReader({mode:'byob'}),rb=b.getReader({mode:'byob'});
 const pending=[ra.read(new Uint8Array(4)),rb.read(new Uint8Array(4))];
 const second=rb.cancel('b');let done=false;second.then(()=>done=true);await tick();const before=done;
 const first=ra.cancel('a');await tick();const during=done;wait.resolve();await Promise.all([first,second]);
 return [before,during,reasons,(await Promise.all(pending)).map(readResult)];
});
compare('cancelling the currently forwarded BYOB branch preserves the sibling data',async w=>{
 let c;const s=new w.ReadableStream({type:'bytes',start(x){c=x}}),[a,b]=s.tee(),ra=a.getReader({mode:'byob'}),rb=b.getReader({mode:'byob'});
 const first=ra.read(new Uint8Array(8));await tick();const q=c.byobRequest;const cancellation=ra.cancel('unused');
 const second=rb.read(new Uint8Array(8));q.view[0]=21;q.respond(1);const out=await second;
 const end=rb.read(new Uint8Array(8));await tick();c.close();c.byobRequest.respond(0);await end;await cancellation;
 return [readResult(await first),readResult(out)];
});
compare('tee reports upstream errors to both branches including a pending fill',async w=>{
 let c;const s=new w.ReadableStream({type:'bytes',start(x){c=x}}),[a,b]=s.tee();const ra=a.getReader({mode:'byob'}),rb=b.getReader();
 const failure={id:1},p=ra.read(new Uint8Array(8)).then(()=>false,e=>e===failure),q=rb.read().then(()=>false,e=>e===failure);
 await tick();c.error(failure);return Promise.all([p,q]);
});
compare('tee branches can change reader type after completing a read',async w=>{
 let i=0;const s=new w.ReadableStream({type:'bytes',autoAllocateChunkSize:8,pull(c){const q=c.byobRequest;
  if(i===4){c.close();if(q)q.respond(0)}else{q.view[0]=++i;q.respond(1)}}}),[a,b]=s.tee();
 let ra=a.getReader({mode:'byob'});const first=await ra.read(new Uint8Array(8));ra.releaseLock();ra=a.getReader();
 const left=[];while(true){const x=await ra.read();if(x.done)break;left.push([...x.value])}ra.releaseLock();
 return [readResult(first),left,await collect(b),s.locked];
});

compare('default object streams retain queue sizing, transform flushing, tee identities and cleanup',async w=>{
 const records=[];for(let n=0;n<32;n++){
  let cancels=0,source;const payload={n};
  const s=new w.ReadableStream({start(c){source=c;c.enqueue(payload);},cancel(){cancels++;}},{highWaterMark:0});
  const [a,b]=s.tee();const ar=a.getReader(),br=b.getReader();
  const [x,y]=await Promise.all([ar.read(),br.read()]);assert.equal(x.value,payload);assert.equal(y.value,payload);
  const p=ar.cancel('a'),q=br.cancel('b');await Promise.all([p,q]);ar.releaseLock();br.releaseLock();
  const output=[],events=[];let control;
  const input=new w.ReadableStream({start(c){control=c;}},{highWaterMark:3,size:()=>2});
  control.enqueue(n);const desired=control.desiredSize;control.enqueue(n+1);control.close();
  await input.pipeThrough(new w.TransformStream({transform(v,c){c.enqueue(v*2);},flush(c){c.enqueue('done');}}))
   .pipeTo(new w.WritableStream({write(v){output.push(v);return Promise.resolve();},close(){events.push('closed');}}));
  records.push([cancels,source.desiredSize,a.locked,b.locked,desired,output,events,input.locked]);
 }
 return records;
});


compare('tee locks at construction and zero-HWM branches stay idle until demand',async w=>{
 let pulls=0,cancels=0;const s=new w.ReadableStream({type:'bytes',pull(c){pulls++;c.enqueue(new Uint8Array([1]));},cancel(){cancels++;}});
 const [a,b]=s.tee();await tick();const before=[s.locked,a.locked,b.locked,pulls];
 let locked=false;try{s.getReader()}catch(e){locked=e.name==='TypeError'}
 await Promise.all([a.cancel(),b.cancel()]);return [before,locked,cancels,s.locked];
});
compare('both default consumers receive independent exact-range byte copies',async w=>{
 const buffer=new ArrayBuffer(16);new Uint8Array(buffer,5,3).set([7,8,9]);
 const s=new w.ReadableStream({type:'bytes',start(c){c.enqueue(new Uint8Array(buffer,5,3));c.close();}}),[a,b]=s.tee();
 const ra=a.getReader(),rb=b.getReader();const [x,y]=await Promise.all([ra.read(),rb.read()]);
 const before=[readResult(x),readResult(y),buffer.byteLength,x.value.buffer===y.value.buffer];x.value[0]=255;
 const untouched=[...y.value];const ends=await Promise.all([ra.read(),rb.read()]);ra.releaseLock();rb.releaseLock();
 return [before,untouched,ends.map(readResult),s.locked,a.locked,b.locked];
});
compare('an unused branch can cancel before reads without cancelling the source',async w=>{
 let calls=0;const s=new w.ReadableStream({type:'bytes',start(c){c.enqueue(new Uint8Array([1,2]));c.close();},cancel(){calls++;}}),[a,b]=s.tee();
 const stop=a.cancel('unused');let settled=false;stop.then(()=>settled=true);await tick();const early=settled;
 const result=await collect(b);await stop;return [early,result,calls,s.locked];
});
compare('nested byte tees serve four independent consumer buffers',async w=>{
 let at=0,active=0,maximum=0;const source=new w.ReadableStream({type:'bytes',autoAllocateChunkSize:4,async pull(c){
  active++;maximum=Math.max(maximum,active);await Promise.resolve();
  const q=c.byobRequest;if(at===24){c.close();q.respond(0);}else{const n=Math.min(q.view.byteLength,24-at,3);for(let i=0;i<n;i++)q.view[i]=at++;q.respond(n);}active--;
 }});
 const [a,b]=source.tee(),[a1,a2]=a.tee(),[b1,b2]=b.tee();
 async function consume(s,size,min){const reader=s.getReader({mode:'byob'}),out=[];let buffer=new ArrayBuffer(size+4);
  for(;;){const x=await reader.read(new Uint8Array(buffer,4,size),{min});buffer=x.value.buffer;out.push(...x.value);x.value.fill(255);if(x.done)break;}reader.releaseLock();return out;}
 const values=await Promise.all([consume(a1,5,3),consume(a2,7,6),consume(b1,8,8),consume(b2,4,1)]);
 assert(values.every(bytes=>bytes.join(',')===Array.from({length:24},(_,i)=>i).join(',')));
 return [values,maximum,source.locked,a.locked,b.locked];
});
compare('reader handoff during a pending tee fill retains accepted bytes at EOF',async w=>{
 let c;const s=new w.ReadableStream({type:'bytes',start(x){c=x}}),[a,b]=s.tee();
 const old=a.getReader({mode:'byob'}),p=old.read(new Uint16Array(4),{min:2}).catch(e=>e.name);await tick();
 const upstream=c.byobRequest;old.releaseLock();const current=a.getReader({mode:'byob'}),next=current.read(new Uint8Array(4));
 upstream.view.set([1,2,3]);upstream.respond(3);const data=await next;
 const tail=current.read(new Uint8Array(4));await tick();c.close();c.byobRequest.respond(0);
 const done=await tail;current.releaseLock();return [await p,readResult(data),readResult(done),await collect(b)];
});
compare('already admitted byte chunks precede a later synchronous source error',async w=>{
 const failure={code:'source'};const s=new w.ReadableStream({type:'bytes',pull(c){
  const q=c.byobRequest;if(q){q.view[0]=7;q.respond(1);}else c.enqueue(new Uint8Array([7]));c.error(failure);
 }}),[a,b]=s.tee();const ra=a.getReader({mode:'byob'}),rb=b.getReader();
 const out=await Promise.all([ra.read(new Uint8Array(8)),rb.read(),ra.closed,rb.closed].map(p=>p.then(()=>false,e=>e===failure)));
 ra.releaseLock();rb.releaseLock();return out;
});
compare('already errored and asynchronously rejected starts fail every tee reader',async w=>{
 const results=[];for(const mode of ['error','reject']){
  const reason=Object.freeze({mode});const s=new w.ReadableStream({type:'bytes',start(c){if(mode==='error')c.error(reason);else return Promise.reject(reason);}});
  const [a,b]=s.tee(),ra=a.getReader({mode:'byob'}),rb=b.getReader();
  results.push(await Promise.all([ra.read(new Uint8Array(4)),rb.read(),ra.closed,rb.closed].map(p=>p.then(()=>false,e=>e===reason))));
  ra.releaseLock();rb.releaseLock();
 }return results;
});
compare('tee cancellation propagates falsy cleanup failures to both cancelling branches',async w=>{
 const out=[];for(const reason of [undefined,null,false,0,'']){
  const done=defer();let calls=0,reasons;const s=new w.ReadableStream({type:'bytes',cancel(x){calls++;reasons=x;return done.promise;}}),[a,b]=s.tee();
  const rb=b.getReader({mode:'byob'}),pending=rb.read(new Uint8Array(8));await tick();
  const ca=a.cancel('a').then(()=>false,e=>e===reason),cb=rb.cancel('b').then(()=>false,e=>e===reason);
  done.reject(reason);out.push([await ca,await cb,calls,reasons,readResult(await pending),s.locked]);rb.releaseLock();
 }return out;
});
compare('pending cancellation resolves normally when the live sibling errors at source',async w=>{
 let c,cancels=0;const reason={bad:1};const s=new w.ReadableStream({type:'bytes',start(x){c=x},cancel(){cancels++;}}),[a,b]=s.tee();
 const stopped=a.cancel('a');let resolved=false;stopped.then(()=>resolved=true);await tick();const early=resolved;
 const rb=b.getReader({mode:'byob'}),pending=rb.read(new Uint8Array(4)).then(()=>false,e=>e===reason);c.error(reason);
 await stopped;rb.releaseLock();return [early,resolved,await pending,cancels];
});
compare('empty normal EOF returns zero-length storage for both BYOB branches',async w=>{
 const s=new w.ReadableStream({type:'bytes',pull(c){const q=c.byobRequest;c.close();if(q)q.respond(0);}}),[a,b]=s.tee();
 const ra=a.getReader({mode:'byob'}),rb=b.getReader({mode:'byob'});const out=await Promise.all([
  ra.read(new Uint16Array(new ArrayBuffer(12),4,3)),rb.read(new DataView(new ArrayBuffer(16),6,6))]);
 ra.releaseLock();rb.releaseLock();return out.map(readResult);
});
compare('a complete final chunk is delivered when the producer immediately closes',async w=>{
 let pulls=0;const s=new w.ReadableStream({type:'bytes',pull(c){pulls++;const q=c.byobRequest;q.view.set([1,2,3,4]);q.respond(4);c.close();}}),[a,b]=s.tee();
 const ra=a.getReader({mode:'byob'}),rb=b.getReader({mode:'byob'});const data=await Promise.all([
  ra.read(new Uint16Array(4),{min:2}),rb.read(new Uint32Array(2))]);
 const end=await Promise.all([ra.read(new Uint8Array(8)),rb.read(new Uint8Array(8))]);ra.releaseLock();rb.releaseLock();
 return [pulls,data.map(readResult),end.map(readResult)];
});
compare('512 seeded tee partitions match data, alignment and terminal minimum failures',async w=>{
 let seed=0xD0B0;function random(n){seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n;}
 const out=[];for(let trial=0;trial<512;trial++){
  const total=8*random(12),stride=1+random(7),modes=[random(4),random(4)],widths=[Uint8Array,Uint16Array,Uint32Array,DataView];let at=0,pulls=0,active=0,max=0;
  const s=new w.ReadableStream({type:'bytes',autoAllocateChunkSize:8,async pull(c){active++;max=Math.max(max,active);pulls++;await Promise.resolve();const q=c.byobRequest;
   if(at===total){c.close();q.respond(0)}else{const n=Math.min(q.view.byteLength,total-at,stride);for(let i=0;i<n;i++)q.view[i]=at++%251;q.respond(n)}active--;}});
  const [a,b]=s.tee();const counts=[1+random(5),1+random(5)],mins=counts.map(n=>1+random(n));
  async function consume(stream,i){const C=widths[modes[i]],size=C.BYTES_PER_ELEMENT||1,r=stream.getReader({mode:'byob'}),bytes=[];let buffer=new ArrayBuffer(8+counts[i]*size);
   // A queued remainder smaller than min at EOF is a specified rejection,
   // unlike a live pending read closed with aligned partial data. Keep these
   // cases in the denominator and compare their exact observed prefixes.
   const closed=r.closed.catch(e=>e.name);
   try {
    for(let n=0;n<=total+1;n++){const value=new C(buffer,8,C===DataView?counts[i]*size:counts[i]),x=await r.read(value,{min:mins[i]});
     buffer=x.value.buffer;bytes.push(...new Uint8Array(buffer,x.value.byteOffset,x.value.byteLength));if(x.done){assert.equal(bytes.length,total);return {bytes,end:'closed'};}}
    throw Error('missing EOF');
   } catch(error){assert.equal(error.name,'TypeError');assert(bytes.length<total);return {bytes,end:error.name};}
   finally {r.releaseLock();await closed;}}
  const values=await Promise.all([consume(a,0),consume(b,1)]);const expected=Array.from({length:total},(_,i)=>i%251);
  for(const value of values)assert.deepEqual(value.bytes,expected.slice(0,value.bytes.length));out.push([values,max,pulls]);
 }return out;
});
compare('4096 asynchronous chunks keep one upstream pull and preserve both outputs',async w=>{
 let produced=0,active=0,max=0;const s=new w.ReadableStream({type:'bytes',autoAllocateChunkSize:8,async pull(c){
  active++;max=Math.max(max,active);await Promise.resolve();const q=c.byobRequest;
  if(produced===4096){c.close();q.respond(0)}else{q.view[0]=produced++%251;q.respond(1)}active--;
 }}),[a,b]=s.tee();
 async function consume(stream){const r=stream.getReader({mode:'byob'});let buffer=new ArrayBuffer(16),count=0,sum=0;
  for(;;){const x=await r.read(new Uint8Array(buffer,4,8),{min:8});buffer=x.value.buffer;for(const byte of x.value){count++;sum+=byte;}if(x.done)break;}
  r.releaseLock();return [count,sum];}
 return [await Promise.all([consume(a),consume(b)]),produced,max,s.locked];
});

test('copy allocation failure errors both branches before publishing either chunk',{timeout:5000},async()=>{
 const failure=Error('copy allocation refused');let cancels=0,reason;
 const Limited=new Proxy(Uint8Array,{construct(C,args){if(args.length===1&&args[0]===37)throw failure;return Reflect.construct(C,args);}});
 const w=candidate({Uint8Array:Limited});const s=new w.ReadableStream({type:'bytes',pull(c){c.enqueue(new Uint8Array(37));},cancel(e){reason=e;cancels++;}});
 const [a,b]=s.tee(),ra=a.getReader(),rb=b.getReader();
 const results=await Promise.all([ra.read(),rb.read(),ra.closed,rb.closed].map(p=>p.then(()=>false,e=>e===failure)));
 assert.deepEqual(results,[true,true,true,true]);assert.equal(cancels,1);assert.equal(reason,failure);
 ra.releaseLock();rb.releaseLock();
});
test('copy failure after forwarded-branch cancellation joins actual upstream cleanup',{timeout:5000},async()=>{
 const failure=Error('copy refused'),gate=defer();let c,cancels=0,reason;
 const Limited=new Proxy(Uint8Array,{construct(C,args){if(args.length===1&&args[0]===3)throw failure;return Reflect.construct(C,args);}});
 const w=candidate({Uint8Array:Limited}),s=new w.ReadableStream({type:'bytes',start(x){c=x;},cancel(e){cancels++;reason=e;return gate.promise;}});
 const [a,b]=s.tee(),ra=a.getReader({mode:'byob'}),rb=b.getReader();
 const abandoned=ra.read(new Uint8Array(8));await tick();const q=c.byobRequest;
 const cancellation=ra.cancel('unused');let complete=false;cancellation.then(()=>complete=true);
 const pending=rb.read();const failed=assert.rejects(pending,e=>e===failure);
 q.view.set([1,2,3]);q.respond(3);await failed;await tick();assert.equal(complete,false);
 assert.equal(cancels,1);assert.equal(reason,failure);gate.resolve();await cancellation;
 assert.equal(complete,true);assert.equal((await abandoned).done,true);ra.releaseLock();rb.releaseLock();
});
test('tee internal operations ignore replaced public reader/controller methods',{timeout:5000},async()=>{
 const w=candidate(),fail=()=>{throw Error('public replacement must not be called internally')};
 const enqueue=w.ReadableByteStreamController.prototype.enqueue,close=w.ReadableByteStreamController.prototype.close;
 const read=w.ReadableStreamBYOBReader.prototype.read,release=w.ReadableStreamBYOBReader.prototype.releaseLock;
 const getReader=w.ReadableStream.prototype.getReader;
 const s=new w.ReadableStream({type:'bytes',start(c){enqueue.call(c,new Uint8Array([1,2,3,4]));close.call(c);}});
 s.getReader=fail;const [a,b]=s.tee();const ra=getReader.call(a,{mode:'byob'}),rb=getReader.call(b,{mode:'byob'});
 w.ReadableStreamDefaultReader.prototype.read=fail;w.ReadableStreamDefaultReader.prototype.releaseLock=fail;
 w.ReadableStreamBYOBReader.prototype.read=fail;w.ReadableStreamBYOBReader.prototype.releaseLock=fail;
 w.ReadableStreamBYOBRequest.prototype.respond=fail;w.ReadableStreamBYOBRequest.prototype.respondWithNewView=fail;
 w.ReadableByteStreamController.prototype.enqueue=fail;w.ReadableByteStreamController.prototype.close=fail;
 const result=await bounded(Promise.all([read.call(ra,new Uint8Array(8)),read.call(rb,new Uint16Array(4))]),'private operations');
 assert.deepEqual(result.map(x=>Array.from(new Uint8Array(x.value.buffer,0,x.value.byteLength))),[[1,2,3,4],[1,2,3,4]]);
 await Promise.all([read.call(ra,new Uint8Array(8)),read.call(rb,new Uint16Array(4))]);release.call(ra);release.call(rb);
});
