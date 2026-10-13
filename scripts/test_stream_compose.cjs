'use strict';
// Execute production composition and pipeline code, with real Node streams as
// transport. No Node compose/pipeline implementation is called by the adapter.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const native = require('node:stream');
const source = fs.readFileSync(process.env.FRANKEN_STREAM_SOURCE || path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/stream_module.js'), 'utf8');
function section(first, last) {
  const start = source.indexOf(first), end = source.indexOf(last, start);
  assert(start >= 0 && end > start, `missing source section ${first}`);
  return source.slice(start, end);
}
const code = section('  function makeError(', '  function isUint8Array(')
  + section('  function aggregateTwoErrors(', '  // ---- buffer list ----')
  + section('  // ---- finished (end-of-stream) ----', '  // ---- module object ----');
function fixture() {
  const context = { AbortController, AbortSignal, EventTarget, Reflect, Object, Array, Symbol,
    Buffer, Promise, Error, TypeError, AggregateError, Readable: native.Readable,
    PassThrough: native.PassThrough, Duplex: native.Duplex, nextTick: process.nextTick };
  return vm.runInNewContext(`(function () {
    const kIsDestroyed = Symbol('kIsDestroyed'); function nop() {} ${code}
    return { compose: typeof compose === 'function' ? compose : undefined,
      readableCompose: typeof readableCompose === 'function' ? readableCompose : undefined };
  })()`, context);
}
const opts = { timeout: 2000 };
const turn = () => new Promise(r => setImmediate(r));
function bounded(promise) {
  let timer;
  const deadline = new Promise((r,j) => {timer=setTimeout(() => j(new Error('composition deadline')),700)});
  return Promise.race([promise,deadline]).finally(()=>clearTimeout(timer));
}
async function collect(stream) { const out=[]; for await (const value of stream) out.push(value); return out; }
function closed(stream) { return new Promise(resolve=>stream.once('close',resolve)); }
function transform(fn = x => x, options={}) {
  return new native.Transform({ objectMode:true, ...options,
    transform(chunk, encoding, callback) { try { callback(null,fn(chunk)); } catch(e){callback(e)} } });
}
function guard(t, ...streams) { for (const s of streams) { s.on('error',()=>{}); t.after(()=>s.destroy()); } }
function deferred() { let resolve,reject;const promise=new Promise((r,j)=>{resolve=r;reject=j});return{resolve,reject,promise}; }

test('reusable transform composition forwards input and output in order',opts,async t=>{
 const {compose}=fixture(); const a=transform(x=>x*2), b=transform(x=>x+1);guard(t,a,b);
 const d=compose(a,b);guard(t,d);const out=bounded(collect(d)); d.write(1);d.write(2);d.end(3);
 assert.deepEqual(await out,[3,5,7]);assert(d instanceof native.Duplex);assert(a.destroyed&&b.destroyed);
});
test('composition can itself be piped between independent streams',opts,async t=>{
 const {compose}=fixture();const d=compose(transform(x=>x+2),transform(x=>x*3));guard(t,d);
 const values=[];const sink=new native.Writable({objectMode:true,write(c,e,cb){values.push(c);cb()}});guard(t,sink);
 await bounded(new Promise((r,j)=>native.pipeline(native.Readable.from([1,2,3]),d,sink,e=>e?j(e):r())));
 assert.deepEqual(values,[9,12,15]);
});
test('byte streams retain bytes and independent object-mode boundaries',opts,async t=>{
 const {compose}=fixture();const a=new native.Transform({writableObjectMode:true,transform(c,e,cb){cb(null,Buffer.from(c.name))}});
 const b=new native.Transform({readableObjectMode:true,transform(c,e,cb){cb(null,{text:c.toString()})}});
 const d=compose(a,b);guard(t,a,b,d);const out=bounded(collect(d));d.end({name:'hello'});
 assert.equal(d.writableObjectMode,true);assert.equal(d.readableObjectMode,true);assert.deepEqual(await out,[{text:'hello'}]);
});
test('async generator transforms compose over writable input',opts,async t=>{
 const {compose}=fixture();const d=compose(async function*(source){for await(const x of source)yield x*2;},
 async function*(source){for await(const x of source)yield x+1;});guard(t,d);
 const out=bounded(collect(d));d.write(3);d.end(5);assert.deepEqual(await out,[7,11]);
});
test('one async generator function becomes a transform Duplex',opts,async t=>{
 const {compose}=fixture();const d=compose(async function*(input){for await(const x of input)yield x.toUpperCase()});guard(t,d);
 const out=bounded(collect(d));d.end('hello');assert.deepEqual(await out,['HELLO']);
});
test('async sink functions create writable-only compositions',opts,async t=>{
 const {compose}=fixture();const values=[];const d=compose(async input=>{for await(const x of input)values.push(x)});guard(t,d);
 assert.equal(d.readable,false);assert.equal(d.writable,true);
 const done=bounded(new Promise((r,j)=>d.end(9,e=>e?j(e):r())));await done;assert.deepEqual(values,[9]);
});
test('async sink non-null return values fail rather than fabricating output',opts,async t=>{
 const {compose}=fixture();const d=compose(async input=>{for await(const x of input){}return 12;});guard(t,d);
 const error=bounded(new Promise(r=>d.once('error',r)));d.end(9);assert.equal((await error).code,'ERR_INVALID_RETURN_VALUE');
});
test('iterable and readable sources create read-only compositions',opts,async t=>{
 const {compose}=fixture();for(const source of [[1,2],native.Readable.from([1,2])]){
  const d=compose(source,transform(x=>x*3));guard(t,d);assert.equal(d.writable,false);assert.deepEqual(await bounded(collect(d)),[3,6]);}
});
test('single readable, writable, string, iterable, and Duplex forms',opts,async t=>{
 const {compose}=fixture();const pt=new native.PassThrough();guard(t,pt);assert.equal(compose(pt),pt);
 for(const [input,expected]of [[native.Readable.from([1,2]),[1,2]],[[3,4],[3,4]],['text',['text']]]){
  const d=compose(input);guard(t,d);assert.deepEqual(await bounded(collect(d)),expected);}
 const values=[];const sink=new native.Writable({objectMode:true,write(c,e,cb){values.push(c);cb()}});
 const d=compose(sink);guard(t,sink,d);assert.equal(d.readable,false);
 await bounded(new Promise((r,j)=>d.end(1,e=>e?j(e):r())));assert.deepEqual(values,[1]);
});
test('invalid stages reject before piping or invoking factories',opts,async t=>{
 const {compose}=fixture();assert.throws(()=>compose(),{code:'ERR_MISSING_ARGS'});
 let called=0;assert.throws(()=>compose(()=>{called++},{}),{code:'ERR_INVALID_ARG_TYPE'});assert.equal(called,0);
 const head=transform();const tail=native.Readable.from([1]);guard(t,head,tail);
 assert.throws(()=>compose(head,tail),{code:'ERR_INVALID_ARG_VALUE'});assert.equal(head.listenerCount('data'),0);
});
test('stage errors reach outer Duplex and destroy siblings',opts,async t=>{
 const {compose}=fixture();const failure=new Error('stage failed');const a=transform(),b=transform(()=>{throw failure});
 const d=compose(a,b);guard(t,a,b,d);const error=bounded(new Promise(r=>d.once('error',r)));d.end(1);
 assert.equal(await error,failure);assert(a.destroyed&&b.destroyed&&d.destroyed);
});
test('explicit destruction preserves its error and waits for asynchronous cleanup',opts,async t=>{
 const {compose}=fixture();const release=deferred();let destroyed=false;
 const a=transform();const b=new native.Transform({objectMode:true,transform(x,e,cb){cb(null,x)},
  destroy(error,cb){release.promise.then(()=>{destroyed=true;cb(error)})}});guard(t,a,b);
 const d=compose(a,b);guard(t,d);const failure=new Error('cancelled');let done=false;
 const ended=bounded(closed(d));ended.then(()=>{done=true});t.after(()=>release.resolve());d.destroy(failure);
 await turn();assert.equal(done,false);release.resolve();await ended;assert(destroyed);assert.equal(d.errored,failure);
});
test('reading pressure prevents unbounded consumption of an infinite source',opts,async t=>{
 const {compose}=fixture();let pulled=0,cleaned=false;
 async function* source(){try{while(true)yield pulled++;}finally{cleaned=true}}
 const d=compose(source(),transform(x=>x,{highWaterMark:2}));guard(t,d);
 await turn();const first=pulled;await turn();assert.equal(pulled,first);assert(first>0&&first<32);
 const ended=bounded(closed(d));d.destroy();await ended;assert.equal(cleaned,true);
});
test('write callbacks wait for admitted writes and finish waits for finalization',opts,async t=>{
 const {compose}=fixture();const release=deferred();let writing;let callback=false,finished=false;
 const a=new native.Transform({objectMode:true,transform(x,e,cb){writing=()=>cb(null,x)},final(cb){release.promise.then(()=>cb())}});
 const b=transform();const d=compose(a,b);guard(t,a,b,d);t.after(()=>release.resolve());const out=bounded(collect(d));
 d.write(1,()=>{callback=true});d.end(()=>{finished=true});await turn();assert.equal(callback,false);
 writing();await turn();assert.equal(callback,true);assert.equal(finished,false);release.resolve();assert.deepEqual(await out,[1]);
});
test('Readable.compose forwards signal cancellation to all stages',opts,async t=>{
 const {readableCompose}=fixture();const a=new native.Readable({read(){}});const b=new native.PassThrough();const c=new AbortController();
 const d=readableCompose.call(a,b,{signal:c.signal});guard(t,a,b,d);const error=bounded(new Promise(r=>d.once('error',r)));
 c.abort('stop');assert.equal((await error).cause,'stop');assert(a.destroyed&&b.destroyed&&d.destroyed);
});

test('external abort marks outer destroyed before asynchronous teardown finishes',opts,async t=>{
 const {readableCompose}=fixture();const release=deferred();t.after(()=>release.resolve());
 const src=new native.Readable({read(){}});const dst=new native.Transform({transform(c,e,cb){cb(null,c)},
  destroy(error,cb){release.promise.then(()=>cb(error))}});const ctrl=new AbortController();
 const d=readableCompose.call(src,dst,{signal:ctrl.signal});guard(t,src,dst,d);
 let done=false;const ended=bounded(closed(d));ended.then(()=>{done=true});ctrl.abort('stop');
 assert.equal(d.destroyed,true);await turn();assert.equal(done,false);release.resolve();await ended;
});
test('failure while constructing the outer wrapper tears down started stages',opts,async t=>{
 const {compose}=fixture();const a=transform(),b=transform();guard(t,a,b);const failure=new Error('size getter failed');
 Object.defineProperty(b,'readableHighWaterMark',{get(){throw failure}});
 assert.throws(()=>compose(a,b),e=>e===failure);await turn();assert(a.destroyed&&b.destroyed);
});
test('read-only natural EOF drains slow source destruction without AbortError',opts,async t=>{
 const {compose}=fixture();const release=deferred();t.after(()=>release.resolve());let supplied=false;
 const src=new native.Readable({objectMode:true,read(){if(!supplied){supplied=true;this.push(1);this.push(null)}},
  destroy(error,cb){release.promise.then(()=>cb(error))}});
 const d=compose(src,transform(x=>x+1));guard(t,src,d);let done=false;const values=bounded(collect(d));values.then(()=>{done=true},()=>{});
 await turn();assert.equal(done,false);release.resolve();assert.deepEqual(await values,[2]);assert.equal(d.errored,null);
});
test('composition waits for pending iterator cleanup and drops late producer values',opts,async t=>{
 const {compose}=fixture();const pending=deferred(),cleanup=deferred();let returned=0,writes=0,pulled=false;
 t.after(()=>{pending.resolve({done:true});cleanup.resolve({done:true})});
 const source={ [Symbol.asyncIterator](){return this},next(){pulled=true;return pending.promise},
  return(){returned++;return cleanup.promise} };
 const tail=transform(x=>{writes++;return x});const d=compose(source,tail);guard(t,d,tail);
 d.resume();await turn();assert.equal(pulled,true);let done=false;const ended=bounded(closed(d));ended.then(()=>{done=true});d.destroy();
 pending.resolve({done:false,value:'late'});await turn();assert.equal(writes,0);assert.equal(returned,1);assert.equal(done,false);
 cleanup.resolve({done:true});await ended;
});
test('prototype composition validates options and signals before stage effects',opts,async t=>{
 const {readableCompose}=fixture();const src=new native.Readable({read(){}}),dst=new native.PassThrough();guard(t,src,dst);
 for(const options of [null,1,false])assert.throws(()=>readableCompose.call(src,dst,options),{code:'ERR_INVALID_ARG_TYPE'});
 for(const signal of [null,{}, {aborted:false}])assert.throws(()=>readableCompose.call(src,dst,{signal}),{code:'ERR_INVALID_ARG_TYPE'});
 assert.equal(src.listenerCount('data'),0);assert.equal(dst.listenerCount('pipe'),0);
});
test('native comparison covers data, endpoint modes, sink completion, and error identity',opts,async t=>{
 async function exercise(compose) {
  const a=transform(x=>x+1),b=transform(x=>x*2),d=compose(a,b);guard(t,a,b,d);
  const mode=[d.readable,d.writable,d.readableObjectMode,d.writableObjectMode,d.allowHalfOpen];
  const data=bounded(collect(d));d.write(3);d.end(4);const result=await data;
  const sinkValues=[];const sink=compose(async input=>{for await(const x of input)sinkValues.push(x)});guard(t,sink);
  await bounded(new Promise((r,j)=>sink.end(7,e=>e?j(e):r())));
  const failure=new Error('source failed');const failing=compose(transform(()=>{throw failure}),transform());guard(t,failing);
  const seen=bounded(new Promise(r=>failing.once('error',r)));failing.end(1);
  return{mode,result,sinkValues,errorIdentity:await seen===failure};
 }
 assert.deepEqual(await exercise(fixture().compose),await exercise(native.compose));
});

test('a tail listener-registration failure destroys the unreturned composition',opts,async t=>{
 const {compose}=fixture();const head=transform(),tail=transform();guard(t,head,tail);
 const add=tail.on;const failure=new Error('registration failed');
 tail.on=function(name,fn){if(name==='readable')throw failure;return add.call(this,name,fn)};
 assert.throws(()=>compose(head,tail),error=>error===failure);await turn();assert(head.destroyed&&tail.destroyed);
});
test('outer pending write and end callbacks settle once with the stage error',opts,async t=>{
 const {compose}=fixture();let release;const failure=new Error('write failed');
 const head=new native.Transform({objectMode:true,transform(value,enc,cb){release=()=>cb(failure)}});
 const tail=transform(),outer=compose(head,tail);guard(t,head,tail,outer);
 let writes=0,ends=0;const write=bounded(new Promise(r=>outer.write(1,error=>{writes++;r(error)})));
 const end=bounded(new Promise(r=>outer.end(error=>{ends++;r(error)})));
 const finished=bounded(closed(outer));release();assert.equal(await write,failure);assert.equal(await end,failure);
 await finished;await turn();assert.equal(writes,1);assert.equal(ends,1);
});
test('pre-aborted Readable.compose does not deliver chunks and preserves the cause',opts,async t=>{
 const {readableCompose}=fixture();const src=native.Readable.from([1,2,3]),tail=transform();const reason=new Error('pre-abort');
 const outer=readableCompose.call(src,tail,{signal:AbortSignal.abort(reason)});guard(t,src,tail,outer);
 assert.equal(outer.destroyed,true);let delivered=0;outer.on('data',()=>{delivered++});
 const error=await bounded(new Promise(r=>outer.once('error',r)));assert.equal(error.code,'ABORT_ERR');assert.equal(error.cause,reason);
 assert.equal(delivered,0);
});
test('successful composition removes its own readable and end observers',opts,async t=>{
 const {compose}=fixture();const first=transform(),last=transform();guard(t,first,last);
 const counts=[last.listenerCount('readable'),last.listenerCount('end')];const outer=compose(first,last);guard(t,outer);
 const out=bounded(collect(outer));outer.end(1);assert.deepEqual(await out,[1]);await turn();
 assert.deepEqual([last.listenerCount('readable'),last.listenerCount('end')],counts);
});
test('composed function stages share a signal, including teardown on explicit destroy',opts,async t=>{
 const {compose}=fixture();const signals=[];
 async function* stage(input,{signal}){signals.push(signal);for await(const value of input)yield value}
 const outer=compose(stage,stage);guard(t,outer);outer.write(1);outer.resume();await turn();
 assert.equal(signals.length,2);assert(signals[0] instanceof AbortSignal);assert.equal(signals[0],signals[1]);
 const done=bounded(closed(outer));outer.destroy();await done;assert.equal(signals[0].aborted,true);
});

test('the actual module export block installs both composition entry points',opts,async t=>{
 // Isolate public prototype installation from the Node oracle. All stream
 // operations below still use real Node stream state machines as transport.
 class AdapterReadable extends native.Readable {}
 Object.defineProperty(AdapterReadable.prototype,'compose',{value:undefined,configurable:true});
 const moduleStart=source.indexOf('  // ---- module object ----');
 const moduleEnd=source.indexOf('  return Stream;',moduleStart);
 assert(moduleStart>=0&&moduleEnd>moduleStart,'missing production export section');
 const context={AbortController,AbortSignal,EventTarget,Reflect,Object,Array,Symbol,Buffer,Promise,
  Error,TypeError,AggregateError,Readable:AdapterReadable,Writable:native.Writable,
  PassThrough:native.PassThrough,Duplex:native.Duplex,Transform:native.Transform,
  nextTick:process.nextTick,isUint8Array:native._isUint8Array,toBuffer:native._uint8ArrayToBuffer};
 const api=vm.runInNewContext(`(function(){function Stream(){}function nop(){}
  const kIsDestroyed=Symbol('kIsDestroyed');${code}
  ${source.slice(moduleStart,moduleEnd)}return Stream;})()`,context);
 assert.equal(typeof api.compose,'function');
 const descriptor=Object.getOwnPropertyDescriptor(api.Readable.prototype,'compose');
 assert.equal(typeof descriptor.value,'function');assert.equal(descriptor.enumerable,false);
 let read=false;const input=new api.Readable({objectMode:true,read(){if(!read){read=true;this.push(3);this.push(null)}}});
 const output=input.compose(transform(x=>x*2));guard(t,input,output);assert.deepEqual(await bounded(collect(output)),[6]);
});
