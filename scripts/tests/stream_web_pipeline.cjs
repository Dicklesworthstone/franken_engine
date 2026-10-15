'use strict';
// Execute the shipped bridge on Node primitives. This is not Rust execution.
// The restricted-core lane rejects raw Web destinations just as the existing
// engine pipeline does, so Node's native Web support cannot mask a missing bridge.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const node = require('node:stream');
const web = require('node:stream/web');
const sourcePath = process.env.FRANKEN_PIPELINE_SOURCE || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_web_bridge.js');
const install = vm.runInThisContext(fs.readFileSync(sourcePath, 'utf8'));
const nativePipeline = node.pipeline, nativePromise = node.promises.pipeline;
const tick = () => new Promise(resolve => setImmediate(resolve));
function defer() { let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject}; }
function guard(args, callback) {
  let entries = args.slice(0, callback ? -1 : args.length);
  if (Array.isArray(entries[0])) entries = entries[0];
  for (const x of entries) {
    if (x && typeof x === 'object' && !(x instanceof node.Stream) &&
        (typeof x.getWriter === 'function' || (x.readable && x.writable))) {
      throw new TypeError('unadapted Web stage reached the restricted core');
    }
  }
}
function candidate(restricted=true, load=()=>web) {
  function R(config) { return Reflect.construct(node.Readable,[config],new.target); }
  function W(config) { return Reflect.construct(node.Writable,[config],new.target); }
  function D(config) { return Reflect.construct(node.Duplex,[config],new.target); }
  for (const [a,b] of [[R,node.Readable],[W,node.Writable],[D,node.Duplex]]) {
    a.prototype=b.prototype;Object.setPrototypeOf(a,b);
  }
  return install({Readable:R,Writable:W,Duplex:D,finished:node.finished,
    pipeline: restricted ? function (...args) {guard(args,true);return nativePipeline(...args);} : nativePipeline,
    promises:{pipeline: restricted ? function (...args) {guard(args,false);return nativePromise(...args);} : nativePromise}},load);
}
function group(name, fn) { test(name,{timeout:5000},async()=>{let timer;try{
  await Promise.race([fn(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('unfinished pipeline: '+name)),4000);})]);
}finally{clearTimeout(timer);}}); }
async function compare(fn) {const expected=await fn(node);for(const s of [candidate(false),candidate(true)])assert.deepEqual(await fn(s),expected);return expected;}
const readable = values => web.ReadableStream.from(values);

group('Web sources and destinations preserve objects, strings and byte views',async()=>{
  await compare(async s=>{const item={x:42},bytes=new Uint8Array([9,65,66,8]).subarray(1,3),seen=[];
    const r=readable([item,'hello',bytes]),w=new web.WritableStream({write(x){seen.push(x);}});
    await s.promises.pipeline(r,w);assert.equal(seen[0],item);assert.equal(seen[2],bytes);
    return [seen[1],[...seen[2]],r.locked,w.locked];});
});
group('array form mixes Web transforms and Node transforms without changing input',async()=>{
  await compare(async s=>{const result=[];const r=readable([1,2,3]);
    const a=new web.TransformStream({transform(x,c){c.enqueue(x*2);}});
    const b=new node.Transform({objectMode:true,transform(x,e,cb){cb(null,x+1);}});
    const w=new web.WritableStream({write(x){result.push(x);}});const stages=[r,a,b,w];
    await s.promises.pipeline(stages);assert.deepEqual(stages,[r,a,b,w]);return result;});
});
group('callback pipeline returns the original Web destination and calls back once',async()=>{
  await compare(s=>new Promise((resolve,reject)=>{let calls=0;const out=[],dest=new web.WritableStream({write(x){out.push(x);}});
    const returned=s.pipeline(readable([20,22]),dest,(error,value)=>{calls++;if(error)return reject(error);
      assert.equal(returned,dest);resolve([out,calls,value]);});}));
});
group('end false waits for writes but does not close or abort the Web sink',async()=>{
  await compare(async s=>{const events=[],gate=defer();const w=new web.WritableStream({async write(x){events.push(x);await gate.promise;},close(){events.push('close');},abort(){events.push('abort');}});
    let done=false;const p=s.promises.pipeline([1,2],w,{end:false}).then(()=>done=true);await tick();assert.equal(done,false);
    gate.resolve();await p;return [events,w.locked];});
});
group('source factories receive the core signal and may return a Web readable',async()=>{
  await compare(async s=>{let signal,calls=0;const out=[];
    await s.promises.pipeline(options=>{calls++;signal=options.signal;return readable(['a','b']);},new web.WritableStream({write(x){out.push(x);}}));
    return [out,calls,signal instanceof AbortSignal];});
});
group('async-generator transforms and promise sinks keep core return values',async()=>{
  await compare(async s=>{let signal;const value=await s.promises.pipeline(readable([1,2,3]),
    async function*(source,{signal:sig}){signal=sig;for await(const x of source)yield x*2;},
    async function(source){let sum=0;for await(const x of source)sum+=x;return sum;});
    return [value,signal instanceof AbortSignal];});
});
group('normal close awaits the asynchronous Web close algorithm',async()=>{
  await compare(async s=>{const gate=defer(),events=[];const w=new web.WritableStream({write(x){events.push(x);},close(){events.push('closing');return gate.promise;}});
    let done=false;const p=s.promises.pipeline(readable([1]),w).then(()=>done=true);await tick();assert.equal(done,false);assert.deepEqual(events,[1,'closing']);gate.resolve();await p;return events;});
});
group('record Node cancellation-reason difference without masking the original failure',async()=>{
  async function run(s, expectedReason){const error=Error('sink'),events=[];let n=0;
    const r=new web.ReadableStream({pull(c){c.enqueue(++n);},cancel(reason){events.push(reason);}}, {highWaterMark:0});
    const w=new web.WritableStream({write(){throw error;}});
    assert.equal(await s.promises.pipeline(r,w).catch(e=>e),error);
    assert.equal(events.length,1);assert.equal(events[0],expectedReason ? error : undefined);
  }
  await run(node,false);await run(candidate(false),true);await run(candidate(true),true);
});
group('source failure aborts a Web destination and cannot become successful EOF',async()=>{
  await compare(async s=>{const error=Error('source'),events=[];
    const r=new web.ReadableStream({start(c){c.error(error);}}),w=new web.WritableStream({abort(e){events.push(e===error);}});
    assert.equal(await s.promises.pipeline(r,w).catch(e=>e),error);return events;});
});
group('AbortSignal interrupts a pending read and awaits both cleanup algorithms',async()=>{
  const s=candidate(),a=new AbortController(),readGate=defer(),writeGate=defer(),events=[];
  const r=new web.ReadableStream({cancel(e){events.push(['cancel',e.code]);return readGate.promise;}},{highWaterMark:0});
  const w=new web.WritableStream({abort(e){events.push(['abort',e.code]);return writeGate.promise;}});
  let done=false;const p=s.promises.pipeline(r,w,{signal:a.signal}).then(()=>{throw Error('unexpected success');},e=>{done=true;return e;});
  await tick();a.abort('stop');await tick();assert.equal(done,false);assert.equal(events.length,2);
  readGate.resolve();await tick();assert.equal(done,false);writeGate.resolve();assert.equal((await p).code,'ABORT_ERR');assert.equal(r.locked,false);
});
group('AbortSignal interrupts a stalled writable callback through its Web controller',async()=>{
  const s=candidate(),a=new AbortController(),entered=defer();let aborted=false;
  const w=new web.WritableStream({write(x,c){entered.resolve();return new Promise(resolve=>c.signal.addEventListener('abort',()=>{aborted=true;resolve();},{once:true}));}});
  const p=s.promises.pipeline(readable([1,2]),w,{signal:a.signal}).catch(e=>e);await entered.promise;a.abort('stop');
  assert.equal((await p).code,'ABORT_ERR');assert.equal(aborted,true);
});
group('later locked endpoints are refused before earlier sources are adopted',async()=>{
  const s=candidate();let cancels=0;const r=new web.ReadableStream({cancel(){cancels++;}},{highWaterMark:0});
  const w=new web.WritableStream(),writer=w.getWriter();await assert.rejects(s.promises.pipeline(r,w),{code:'ERR_INVALID_STATE'});
  assert.equal(r.locked,false);assert.equal(cancels,0);writer.releaseLock();
});
group('duplicate endpoint ownership is rejected without taking a source lock',async()=>{
  const s=candidate(),r=readable([1]),w=new web.WritableStream();
  await assert.rejects(s.promises.pipeline(r,{readable:r,writable:w},new web.WritableStream()),{code:'ERR_INVALID_STATE'});
  assert.equal(r.locked,false);assert.equal(w.locked,false);
});
group('invalid signal and missing callback never acquire endpoint ownership',async()=>{
  const s=candidate(),r=readable([1]),w=new web.WritableStream();
  await assert.rejects(s.promises.pipeline(r,w,{signal:{}}),TypeError);assert.equal(r.locked,false);assert.equal(w.locked,false);
  assert.throws(()=>s.pipeline(r,w),TypeError);assert.equal(r.locked,false);assert.equal(w.locked,false);
});
group('source-factory setup failure drains a destination adopted before core registration',async()=>{
  const s=candidate(),gate=defer(),error=Error('factory');let count=0,done=false;
  const w=new web.WritableStream({abort(e){count++;assert.equal(e,error);return gate.promise;}});
  const p=s.promises.pipeline(()=>{throw error;},w).catch(e=>{done=true;return e;});await tick();assert.equal(count,1);assert.equal(done,false);gate.resolve();assert.equal(await p,error);
});
group('captured endpoint methods survive own replacements',async()=>{
  const s=candidate(),r=readable(['a']),out=[],w=new web.WritableStream({write(x){out.push(x);}});
  r.getReader=()=>{throw Error('public replacement');};w.getWriter=r.getReader;
  await s.promises.pipeline(r,w);assert.deepEqual(out,['a']);
});
group('ordinary Node pipelines do not initialize the Web module',async()=>{
  let loads=0;const s=candidate(true,()=>{loads++;return web;}),out=[];
  const w=new node.Writable({objectMode:true,write(x,e,cb){out.push(x);cb();}});
  await s.promises.pipeline(node.Readable.from([1,2]),w,{end:true});assert.deepEqual(out,[1,2]);assert.equal(loads,0);
});
group('falsy source failures retain their cause instead of becoming completion',async()=>{
  const s=candidate();for(const reason of [null,undefined,false,0,'']){const r=new web.ReadableStream({start(c){c.error(reason);}});
    await assert.rejects(s.promises.pipeline(r,new web.WritableStream()),e=>e.code==='ERR_STREAM_WEB'&&e.cause===reason);}
});
group('explicit Node-boundary null refusal prevents silent truncation',async()=>{
  const s=candidate(),out=[];await assert.rejects(s.promises.pipeline(readable([null,42]),new web.WritableStream({write(x){out.push(x);}})),{code:'ERR_STREAM_NULL_VALUES'});
  assert.deepEqual(out,[]);
});
group('large mixed pipeline serializes writes and respects bounded bridge demand',async()=>{
  const s=candidate();let n=0,active=0,max=0,count=0,sum=0;
  const r=new web.ReadableStream({pull(c){if(n===2048)c.close();else c.enqueue(n++);}},{highWaterMark:0});
  const t=new web.TransformStream({transform(x,c){c.enqueue(x+1);}});
  const w=new web.WritableStream({async write(x){active++;max=Math.max(max,active);await Promise.resolve();count++;sum+=x;active--;}});
  await s.promises.pipeline(r,t,w);assert.equal(count,2048);assert.equal(sum,2048*2049/2);assert.equal(max,1);
});
group('custom promisification returns the same promise pipeline',async()=>{
  const s=candidate(),p=require('node:util').promisify(s.pipeline),out=[];
  assert.equal(p,s.promises.pipeline);await p(readable([42]),new web.WritableStream({write(x){out.push(x);}}));assert.deepEqual(out,[42]);
});
group('array callback form preserves destination identity and frozen input',async()=>{
  await compare(s=>new Promise((resolve,reject)=>{const out=[],w=new web.WritableStream({write(x){out.push(x);}}),r=readable(['a','b']);
    const stages=Object.freeze([r,w]);const returned=s.pipeline(stages,e=>{if(e)return reject(e);assert.equal(returned,w);resolve(out);});}));
});
group('callback setup errors keep asynchronous cleanup owned',async()=>{
  const s=candidate(),gate=defer(),reason=Error('setup');let count=0,closed=false,called=false;
  const w=new web.WritableStream({async abort(e){count++;assert.equal(e,reason);await gate.promise;closed=true;}});
  assert.throws(()=>s.pipeline(()=>{throw reason;},w,()=>{called=true;}),e=>e===reason);
  await tick();assert.equal(count,1);assert.equal(closed,false);gate.resolve();await tick();assert.equal(closed,true);assert.equal(called,false);
});
group('callback runtime failures wait for delayed paired cleanup before completion',async()=>{
  const s=candidate(),left=defer(),right=defer(),reason=Error('write');let called=false;
  const source=new web.ReadableStream({pull(c){c.enqueue(1);},cancel(){return left.promise;}},{highWaterMark:0});
  const t={readable:source,writable:new web.WritableStream({abort(){return right.promise;}})};
  // An independent readable/writable pair also owns both cleanup algorithms.
  const dest=new node.Writable({objectMode:true,write(x,e,cb){cb(reason);}});
  const done=new Promise(resolve=>s.pipeline(readable([1,2]),t,dest,e=>{called=true;resolve(e);}));
  await tick();assert.equal(called,false);left.resolve();await tick();assert.equal(called,false);right.resolve();assert.equal(await done,reason);
});
group('explicit fromWeb adapters retain their original lock ownership',async()=>{
  const s=candidate(),source=readable(['x']);const r=s.Readable.fromWeb(source);for await(const x of r)assert.equal(x.toString(),'x');assert.equal(source.locked,true);
});
group('bad late stage type cleans earlier adopted sources and sinks',async()=>{
  const s=candidate();let cancelled=0;const r=new web.ReadableStream({cancel(){cancelled++;}},{highWaterMark:0});
  await assert.rejects(s.promises.pipeline(r,42,new web.WritableStream()),TypeError);assert.equal(r.locked,false);assert.equal(cancelled,1);
});
group('options access happens once and before Web ownership',async()=>{
  const s=candidate(),r=readable([1]),w=new web.WritableStream();let ends=0,signals=0;
  await s.promises.pipeline(r,w,{get end(){ends++;assert.equal(r.locked,false);return true;},get signal(){signals++;assert.equal(w.locked,false);return undefined;}});
  assert.equal(ends,1);assert.equal(signals,1);
});
group('Web pair getters are snapshotted once before adaptation',async()=>{
  const s=candidate(),t=new web.TransformStream(),out=[];let reads=0,writes=0;
  const pair={get readable(){reads++;return t.readable;},get writable(){writes++;return t.writable;}};
  await s.promises.pipeline(readable([1,2]),pair,new web.WritableStream({write(x){out.push(x);}}));
  assert.equal(reads,1);assert.equal(writes,1);assert.deepEqual(out,[1,2]);
});
