'use strict';
// Exact shipped bridge on Node primitives, not execution by the Rust engine.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const node = require('node:stream');
const web = require('node:stream/web');
const {once} = require('node:events');
const sourcePath = process.env.FRANKEN_DUPLEX_BRIDGE_SOURCE || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_web_bridge.js');
const install = vm.runInThisContext(fs.readFileSync(sourcePath,'utf8'),{filename:sourcePath});
function candidate(loader = () => web) {
  function R(o) { return Reflect.construct(node.Readable,[o],new.target); }
  function W(o) { return Reflect.construct(node.Writable,[o],new.target); }
  function D(o) { return Reflect.construct(node.Duplex,[o],new.target); }
  for(const [wrapper,reference] of [[R,node.Readable],[W,node.Writable],[D,node.Duplex]]) {
    wrapper.prototype=reference.prototype; Object.setPrototypeOf(wrapper,reference);
    // No reference adapter may be inherited if production forgot an export.
    wrapper.fromWeb=undefined;wrapper.toWeb=undefined;
  }
  const result=install({Readable:R,Writable:W,Duplex:D,finished:node.finished},loader);
  for(const C of [R,W,D])for(const key of ['fromWeb','toWeb'])assert.equal(typeof C[key],'function');
  return result;
}
const tick=()=>new Promise(resolve=>setImmediate(resolve));
function gate(){let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject};}
function observe(stream){const errors=[];stream.on('error',e=>errors.push(e));return {errors,closed:new Promise(r=>stream.once('close',r))};}
async function collect(stream){const out=[];for await(const x of stream)out.push(x);return out;}
async function both(fn){for(const api of [node,candidate()])await fn(api);}
const tests=[];
function test(name,fn){tests.push([name,fn]);}

test('Duplex installation is lazy and shares one canonical Web dependency',async()=>{
 let loads=0;const s=candidate(()=>{loads++;return web;});assert.equal(loads,0);
 for(let i=0;i<2;i++){
  const t=new web.TransformStream();const d=s.Duplex.fromWeb(t,{objectMode:true});
  const output=collect(d);d.end(42);assert.deepEqual(await output,[42]);
 }
 assert.equal(loads,1);
});
test('fromWeb transform preserves ordered objects, values and final flush',()=>both(async s=>{
 const object={n:42},seen=[];let active=0,max=0;
 const t=new web.TransformStream({async transform(value,c){active++;max=Math.max(max,active);await Promise.resolve();c.enqueue(value);active--;},flush(c){c.enqueue('flushed');}});
 const d=s.Duplex.fromWeb(t,{objectMode:true,highWaterMark:1});
 await node.promises.pipeline(node.Readable.from([false,0,object,'tail']),d,
  new node.Writable({objectMode:true,write(value,enc,cb){seen.push(value);cb();}}));
 assert.deepEqual(seen,[false,0,object,'tail','flushed']);assert.equal(seen[2],object);assert.equal(max,1);
 assert(t.readable.locked&&t.writable.locked);assert(d.destroyed);
}));
test('toWeb exposes a Node transform through the existing reader and writer bridges',()=>both(async s=>{
 const t=new node.Transform({objectMode:true,transform(value,enc,cb){cb(null,value*2);},flush(cb){this.push(99);cb();}});
 const pair=s.Duplex.toWeb(t);assert(pair.readable instanceof web.ReadableStream);assert(pair.writable instanceof web.WritableStream);
 const output=collect(pair.readable),w=pair.writable.getWriter();await w.write(20);await w.write(21);await w.close();
 assert.deepEqual(await output,[40,42,99]);
}));
test('Duplex adapters compose a full Node-Web-Node pipeline',()=>both(async s=>{
 const inner=new node.Transform({objectMode:true,highWaterMark:1,transform(value,enc,cb){cb(null,value+1);}});
 const roundtrip=s.Duplex.fromWeb(s.Duplex.toWeb(inner),{objectMode:true,highWaterMark:1});
 const out=[];await node.promises.pipeline(node.Readable.from([1,2,3]),roundtrip,
  new node.Writable({objectMode:true,write(x,e,cb){out.push(x);cb();}}));
 assert.deepEqual(out,[2,3,4]);assert(inner.writableFinished&&inner.readableEnded);
}));
test('byte mode and incremental text decoding cross arbitrary UTF-8 cuts',()=>both(async s=>{
 const t=new web.TransformStream();const d=s.Duplex.fromWeb(t,{encoding:'utf8',highWaterMark:1});
 const output=collect(d);d.write(new Uint8Array([0xe2]));d.write(new Uint8Array([0x82]));d.end(new Uint8Array([0xac,33]));
 assert.equal((await output).join(''),'€!');
}));
test('fromWeb decodeStrings false preserves writable string inputs',()=>both(async s=>{
 const seen=[],t=new web.TransformStream({transform(x,c){seen.push(typeof x);c.enqueue(x);}});
 const d=s.Duplex.fromWeb(t,{decodeStrings:false});const output=collect(d);d.end('hello');
 assert.equal(Buffer.concat(await output).toString(),'hello');assert.deepEqual(seen,['string']);
}));
test('fromWeb half-open mode preserves writes after readable EOF',()=>both(async s=>{
 const seen=[],r=new web.ReadableStream({start(c){c.close();}}),w=new web.WritableStream({write(x){seen.push(x.toString());}});
 const d=s.Duplex.fromWeb({readable:r,writable:w},{allowHalfOpen:true});d.resume();await once(d,'end');
 assert.equal(d.writableEnded,false);d.end('after-eof');await node.promises.finished(d);assert.deepEqual(seen,['after-eof']);
}));
test('fromWeb default closes writable after the independent readable ends',()=>both(async s=>{
 let closed=0;const r=new web.ReadableStream({start(c){c.close();}}),w=new web.WritableStream({close(){closed++;}});
 const d=s.Duplex.fromWeb({readable:r,writable:w});d.resume();await node.promises.finished(d);assert.equal(closed,1);
}));
test('destruction starts both cleanup operations and awaits the slower one',()=>both(async s=>{
 const a=gate(),b=gate(),calls=[],reason=Error('stop');
 const r=new web.ReadableStream({cancel(e){assert.equal(e,reason);calls.push('cancel');return a.promise;}},{highWaterMark:0});
 const w=new web.WritableStream({abort(e){assert.equal(e,reason);calls.push('abort');return b.promise;}});
 const d=s.Duplex.fromWeb({readable:r,writable:w}),event=observe(d);let closed=false;event.closed.then(()=>closed=true);
 d.destroy(reason);d.destroy(Error('ignored'));await tick();assert.deepEqual(calls,['cancel','abort']);a.resolve();await tick();assert.equal(closed,false);
 b.resolve();await event.closed;assert.equal(event.errors[0],reason);assert.equal(event.errors.length,1);
}));
test('record Node source-error cleanup gap; candidate also aborts the sink',()=>both(async s=>{
 let controller,aborted;const reason=Error('source');
 const r=new web.ReadableStream({start(c){controller=c;}},{highWaterMark:0});const w=new web.WritableStream({abort(e){aborted=e;}});
 const d=s.Duplex.fromWeb({readable:r,writable:w}),event=observe(d);controller.error(reason);await event.closed;
 assert.equal(event.errors[0],reason);
 // Node 22.16 rejects cancellation of the already errored reader before
 // aborting its sibling. The candidate starts and awaits both operations.
 assert.equal(aborted,s===node?undefined:reason);
}));
test('record Node sink-error cleanup gap; candidate also cancels the source',()=>both(async s=>{
 let controller,cancelled;const reason=Error('sink');const r=new web.ReadableStream({cancel(e){cancelled=e;}},{highWaterMark:0});
 const w=new web.WritableStream({start(c){controller=c;}}),d=s.Duplex.fromWeb({readable:r,writable:w}),event=observe(d);
 d.resume();await tick();controller.error(reason);await event.closed;assert.equal(event.errors[0],reason);
 assert.equal(cancelled,s===node?undefined:reason);
}));
test('AbortSignal owns both sides and runs their cleanup once',()=>both(async s=>{
 const a=new AbortController(),calls=[];const r=new web.ReadableStream({cancel(e){calls.push(e);}},{highWaterMark:0});
 const w=new web.WritableStream({abort(e){calls.push(e);}}),d=s.Duplex.fromWeb({readable:r,writable:w},{signal:a.signal}),event=observe(d);
 a.abort('requested');await event.closed;assert.equal(calls.length,2);assert.equal(calls[0],calls[1]);assert.equal(calls[0].code,'ABORT_ERR');
 assert.equal(event.errors[0],calls[0]);
}));
test('invalid constructor options and paired locks leave unowned endpoints available',async()=>{
 const s=candidate();for(const config of [null,{highWaterMark:-1},{encoding:'bad-encoding'},{objectMode:'bad'},{decodeStrings:null},{allowHalfOpen:'bad'}]){
  const r=new web.ReadableStream({}, {highWaterMark:0}),w=new web.WritableStream();
  assert.throws(()=>s.Duplex.fromWeb({readable:r,writable:w},config));assert.equal(r.locked,false);assert.equal(w.locked,false);
 }
 for(const side of ['readable','writable']){
  const pair={readable:new web.ReadableStream({}, {highWaterMark:0}),writable:new web.WritableStream()};
  const owner=side==='readable'?pair.readable.getReader():pair.writable.getWriter();
  assert.throws(()=>s.Duplex.fromWeb(pair),{code:'ERR_INVALID_STATE'});
  assert.equal(pair[side==='readable'?'writable':'readable'].locked,false);owner.releaseLock();
 }
 const pair={readable:new web.ReadableStream({}, {highWaterMark:0}),writable:new web.WritableStream()};let owner;
 assert.throws(()=>s.Duplex.fromWeb(pair,{get encoding(){owner=pair.writable.getWriter();}}),{code:'ERR_INVALID_STATE'});
 assert.equal(pair.readable.locked,false);owner.releaseLock();
});
test('invalid pairs and suppressed Node close notifications reject without adoption',async()=>{
 const s=candidate();for(const pair of [null,undefined,42,{}, {readable:{},writable:{}}])assert.throws(()=>s.Duplex.fromWeb(pair));
 const d=new node.Duplex({emitClose:false,read(){},write(x,e,cb){cb();}});
 assert.throws(()=>s.Duplex.toWeb(d),{code:'ERR_STREAM_WEB_UNSUPPORTED'});
 for(const event of ['data','end','error','close','finish'])assert.equal(d.listenerCount(event),0);
 assert.equal(d.destroyed,false);d.destroy();
});
test('falsy source errors and unrepresentable null chunks remain explicit failures',async()=>{
 const s=candidate();for(const reason of [undefined,null,false,0,'']){
  const r=new web.ReadableStream({start(c){c.error(reason);}}),w=new web.WritableStream();
  await assert.rejects(collect(s.Duplex.fromWeb({readable:r,writable:w})),e=>e.code==='ERR_STREAM_WEB'&&e.cause===reason);
 }
 const r=web.ReadableStream.from([null,42]),w=new web.WritableStream();
 await assert.rejects(collect(s.Duplex.fromWeb({readable:r,writable:w},{objectMode:true})),{code:'ERR_STREAM_NULL_VALUES'});
});
test('cleanup rejection still waits for its sibling and preserves falsy causes',async()=>{
 const s=candidate(),slow=gate(),r=new web.ReadableStream({cancel(){throw false;}},{highWaterMark:0});
 const w=new web.WritableStream({abort(){return slow.promise;}}),d=s.Duplex.fromWeb({readable:r,writable:w}),event=observe(d);let closed=false;
 event.closed.then(()=>closed=true);d.destroy();await tick();assert.equal(closed,false);slow.resolve();await event.closed;
 assert.equal(event.errors[0].code,'ERR_STREAM_WEB');assert.equal(event.errors[0].cause,false);
});
test('record Node buffered-acceptance timing; candidate waits for write callbacks',()=>both(async s=>{
 const pending=gate(),closing=gate(),events=[];
 const d=new node.Duplex({read(){this.push(null);},write(x,e,cb){events.push('write');pending.promise.then(()=>cb());},final(cb){events.push('final');closing.promise.then(()=>cb());}});
 const pair=s.Duplex.toWeb(d),read=collect(pair.readable),w=pair.writable.getWriter();let wrote=false;
 const write=w.write('a').then(()=>wrote=true);await tick();assert.equal(wrote,s===node);pending.resolve();await write;
 let closed=false;const done=w.close().then(()=>closed=true);await tick();assert.deepEqual(events,['write','final']);assert.equal(closed,false);
 closing.resolve();await done;await read;
}));
test('toWeb backpressure holds accepted writes until the callback and drain',()=>both(async s=>{
 const pending=gate(),d=new node.Duplex({highWaterMark:1,read(){this.push(null);},write(x,e,cb){pending.promise.then(()=>cb());}});
 const pair=s.Duplex.toWeb(d),output=collect(pair.readable),writer=pair.writable.getWriter();let wrote=false;
 const write=writer.write('a').then(()=>wrote=true);await tick();assert.equal(wrote,false);
 pending.resolve();await write;await writer.close();await output;
}));
test('long two-way transform pipeline does not overlap writes or lose records',()=>both(async s=>{
 let active=0,max=0;const t=new web.TransformStream({async transform(x,c){active++;max=Math.max(max,active);await Promise.resolve();c.enqueue(x+1);active--;}});
 const d=s.Duplex.fromWeb(t,{objectMode:true,highWaterMark:2});let count=0,sum=0;
 await node.promises.pipeline(node.Readable.from((function*(){for(let i=0;i<1024;i++)yield i;})()),d,
  new node.Writable({objectMode:true,highWaterMark:1,write(x,e,cb){count++;sum+=x;cb();}}));
 assert.equal(count,1024);assert.equal(sum,1024*1025/2);assert.equal(max,1);
}));
(async()=>{
 for(const [name,run] of tests){let timer;try{await Promise.race([Promise.resolve().then(run),new Promise((_,reject)=>{
  timer=setTimeout(()=>reject(Error('Unfinished test: '+name)),5000);
 })]);console.log('PASS',name);}finally{clearTimeout(timer);}}
 console.log('PASS',tests.length,'host Duplex groups; Rust execution unverified');
})().catch(e=>{console.error(e);process.exitCode=1;});
