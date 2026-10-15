'use strict';
// The shipped adapter on Node primitives, NOT execution of the Rust engine.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const node = require('node:stream');
const web = require('node:stream/web');
const install = vm.runInThisContext(fs.readFileSync(path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_web_bridge.js'), 'utf8'));
function candidate(loader = () => web) {
  function R(options) { return Reflect.construct(node.Readable, [options], new.target); }
  function W(options) { return Reflect.construct(node.Writable, [options], new.target); }
  R.prototype = node.Readable.prototype; W.prototype = node.Writable.prototype;
  Object.setPrototypeOf(R, node.Readable); Object.setPrototypeOf(W, node.Writable);
  return install({ Readable: R, Writable: W, Duplex: node.Duplex, finished: node.finished }, loader);
}
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() { let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject}; }
function completed(s) { return new Promise((resolve,reject)=>node.finished(s,e=>e?reject(e):resolve())); }
async function collect(s) { const out=[]; for await(const x of s) out.push(x); return out; }
async function bytes(s) { return Buffer.concat(await collect(s)).toString('hex'); }
async function both(fn) { const expected=await fn(node);const actual=await fn(candidate());assert.deepEqual(actual,expected);return actual; }
function group(name,fn) { test(name,{timeout:4000},async()=>{let timer;try {
 return await Promise.race([fn(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(Error('Unfinished bridge case: '+name)),3000);})]);
 } finally {clearTimeout(timer);} }); }

group('installation does not load Web Streams and aliases reuse one dependency',async()=>{
 let loads=0;const s=candidate(()=>{loads++;return web;});assert.equal(loads,0);
 const r=s.Readable.fromWeb(web.ReadableStream.from([Buffer.from('a')]));assert.equal(loads,1);assert.equal(await bytes(r),'61');
 const w=s.Writable.fromWeb(new web.WritableStream());w.end();await completed(w);assert.equal(loads,1);
});
group('fromWeb byte mode preserves viewed bytes and permanently owns the reader',async()=>{
 assert.deepEqual(await both(async s=>{const source=web.ReadableStream.from([new Uint8Array([99,1,2,88]).subarray(1,3),Buffer.from('a')]);
 const r=s.Readable.fromWeb(source,{highWaterMark:2});const locked=source.locked;return [await bytes(r),locked,source.locked];}),['010261',true,true]);
});
group('fromWeb object mode preserves chunk identities without assimilating thenables',async()=>{
 await both(async s=>{let calls=0;const item={then(){calls++;throw Error('not a promise');}};
 const source=new web.ReadableStream({start(c){c.enqueue(item);c.enqueue(42);c.close();}});
 const r=s.Readable.fromWeb(source,{objectMode:true});const items=[];r.on('data',x=>items.push(x));await completed(r);assert.equal(items[0],item);return [calls,items[1]];});
});
group('fromWeb read demand is serialized and early destruction awaits cancellation',async()=>{
 await both(async s=>{let pulls=0,active=0,max=0,cancels=0;const gate=deferred(),closed=deferred();
 const source=new web.ReadableStream({async pull(c){pulls++;active++;max=Math.max(max,active);await gate.promise;c.enqueue(Buffer.from('x'));active--;},
 cancel(reason){cancels++;return closed.promise;}},{highWaterMark:0});
 const r=s.Readable.fromWeb(source,{highWaterMark:1});r.read();r.read();await tick();assert.equal(pulls,1);
 const done=new Promise(res=>r.once('close',res));r.destroy();let finished=false;done.then(()=>finished=true);await tick();assert.equal(finished,false);
 closed.resolve();await done;gate.resolve();await tick();return [max,cancels,source.locked];});
});
group('fromWeb source errors propagate while no read is requested',async()=>{
 await both(async s=>{let c;const source=new web.ReadableStream({start(x){c=x;}},{highWaterMark:0});const error=Error('source');
 const r=s.Readable.fromWeb(source);const done=completed(r).catch(e=>e===error);c.error(error);return [await done,r.destroyed];});
});
group('fromWeb Node options reject before a Web lock is acquired',async()=>{
 const s=candidate();for(const value of [null,42]){const source=new web.ReadableStream();assert.throws(()=>s.Readable.fromWeb(source,value),{code:'ERR_INVALID_ARG_TYPE'});assert.equal(source.locked,false);}
 for(const settings of [{highWaterMark:-1},{objectMode:'yes'},{encoding:'not-an-encoding'}]){
 const source=new web.ReadableStream();assert.throws(()=>s.Readable.fromWeb(source,settings));assert.equal(source.locked,false);}
 const locked=new web.ReadableStream();locked.getReader();assert.throws(()=>s.Readable.fromWeb(locked));
});
group('fromWeb writable waits for actual write and final completion',async()=>{
 await both(async s=>{const gate=deferred(),finish=deferred(),events=[];let active=0,max=0;
 const dest=new web.WritableStream({async write(value){active++;max=Math.max(max,active);events.push(value.toString());if(events.length===1)await gate.promise;active--;},close(){events.push('close');return finish.promise;}});
 const w=s.Writable.fromWeb(dest,{highWaterMark:1});const done=completed(w);w.write('a');w.end('b');await tick();assert.deepEqual(events,['a']);
 gate.resolve();await tick();assert.deepEqual(events,['a','b','close']);let ended=false;done.then(()=>ended=true);await tick();assert.equal(ended,false);
 finish.resolve();await done;return [events,max,dest.locked];});
});
group('fromWeb writable object mode and decodeStrings false preserve inputs',async()=>{
 await both(async s=>{const item={v:1},seen=[];const dest=new web.WritableStream({write(x){seen.push(x);}});
 const w=s.Writable.fromWeb(dest,{objectMode:true});const done=completed(w);w.write(item);w.end('a');await done;assert.equal(seen[0],item);
 const values=[];const out=s.Writable.fromWeb(new web.WritableStream({write(x){values.push(typeof x);}}),{decodeStrings:false});out.end('hello');await completed(out);return [seen[1],values];});
});
group('fromWeb writable failure destroys Node and preserves error identity',async()=>{
 await both(async s=>{const e=Error('sink');const dest=new web.WritableStream({write(){throw e;}});const w=s.Writable.fromWeb(dest);const done=completed(w).catch(x=>x===e);w.end('a');return [await done,w.destroyed,dest.locked];});
});
group('toWeb readable preserves chunk boundaries and copies Buffer in byte mode',async()=>{
 await both(async s=>{const first=Buffer.from([1,2]),second=Buffer.from([3]);const r=new node.Readable({read(){this.push(first);this.push(second);this.push(null);}});
 const source=s.Readable.toWeb(r),reader=source.getReader();const a=(await reader.read()).value,b=(await reader.read()).value;
 assert.notEqual(a,first);first[0]=99;const end=(await reader.read()).done;return [[...a],[...b],Buffer.isBuffer(a),end];});
});
group('toWeb readable object mode keeps identities including Buffer chunks',async()=>{
 await both(async s=>{const item=Buffer.from('x'),obj={n:1};const r=node.Readable.from([item,obj]);const items=await collect(s.Readable.toWeb(r));return [items[0]===item,items[1]===obj];});
});
group('toWeb readable honors low queue pressure instead of eagerly draining input',async()=>{
 await both(async s=>{let pulls=0;const r=new node.Readable({objectMode:true,highWaterMark:1,read(){this.push(++pulls);}});
 const out=s.Readable.toWeb(r,{strategy:{highWaterMark:1,size(){return 1;}}});await tick();const early=pulls;await tick();assert.equal(pulls,early);assert(early<=3);
 const read=out.getReader();const a=await read.read();await tick();assert(pulls<=early+2);await read.cancel();return [a.value,r.destroyed];});
});
group('record Node early cancellation settlement; candidate awaits actual destruction',async()=>{
 async function check(s,waits){const gate=deferred();let destroyed=0;const r=new node.Readable({read(){},destroy(e,cb){destroyed++;gate.promise.then(()=>cb(e));}});
 const out=s.Readable.toWeb(r);const reason=Error('stop');let settled=false;const stop=out.cancel(reason).then(()=>settled=true);
 await tick();assert.equal(settled,!waits);gate.resolve();await stop;await tick();return [destroyed,r.destroyed];}
 assert.deepEqual(await check(node,false),[1,true]);assert.deepEqual(await check(candidate(),true),[1,true]);
});
group('toWeb readable errors and premature close cannot become successful EOF',async()=>{
 await both(async s=>{const e=Error('bad');const r=new node.Readable({read(){}});const out=s.Readable.toWeb(r);const read=out.getReader();const pending=read.read().catch(x=>x===e);r.destroy(e);return [await pending,r.destroyed];});
 const s=candidate(),r=new node.Readable({read(){}}),out=s.Readable.toWeb(r);const read=out.getReader().read();r.destroy();await assert.rejects(read,{code:'ERR_STREAM_PREMATURE_CLOSE'});
});
group('toWeb writable includes callback and drain in completion, then awaits final',async()=>{
 await both(async s=>{const gate=deferred(),finish=deferred(),events=[];const dest=new node.Writable({highWaterMark:1,write(c,e,cb){events.push(c.toString());gate.promise.then(()=>cb());},final(cb){events.push('final');finish.promise.then(()=>cb());}});
 const out=s.Writable.toWeb(dest),writer=out.getWriter();let ready=false;const p=writer.write('a').then(()=>ready=true);await tick();assert.equal(ready,false);
 gate.resolve();await p;const closing=writer.close();await tick();assert.deepEqual(events,['a','final']);finish.resolve();await closing;return [events,dest.writableFinished];});
});
group('toWeb writable errors while idle reject closed and subsequent writes',async()=>{
 await both(async s=>{const e=Error('idle');const dest=new node.Writable({write(c,e,cb){cb();}});const out=s.Writable.toWeb(dest),w=out.getWriter();const closed=w.closed.catch(x=>x===e);dest.destroy(e);await tick();const write=w.write('x').catch(x=>x===e);return [await closed,await write];});
});
group('toWeb writable abort interrupts a stalled Node write and runs cleanup once',async()=>{
 const s=candidate();const events=[];const dest=new node.Writable({write(c,e,cb){events.push('write');},destroy(e,cb){events.push('destroy');cb(e);}});
 const out=s.Writable.toWeb(dest),w=out.getWriter();const reason=Error('abort');const write=w.write('a').catch(e=>e===reason);await tick();const abort=w.abort(reason);await abort;
 assert.equal(await write,true);assert.deepEqual(events,['write','destroy']);assert(dest.destroyed);
});
group('all four adapters compose in a streaming transform round trip',async()=>{
 await both(async s=>{const input=node.Readable.from([1,2,3]);const out=[];const dest=new node.Writable({objectMode:true,write(x,e,cb){out.push(x);cb();}});
 const a=s.Readable.toWeb(input);const transformed=a.pipeThrough(new web.TransformStream({transform(x,c){c.enqueue(x*2);}}));
 await node.promises.pipeline(s.Readable.fromWeb(transformed,{objectMode:true}),s.Writable.fromWeb(s.Writable.toWeb(dest),{objectMode:true}));return out;});
});
group('long object-mode workload completes with serialized writes',async()=>{
 const s=candidate();let n=0,count=0,sum=0;const source=new web.ReadableStream({pull(c){if(n===4096)c.close();else c.enqueue(n++);}});
 const dest=new node.Writable({objectMode:true,highWaterMark:4,write(x,e,cb){count++;sum+=x;cb();}});
 await node.promises.pipeline(s.Readable.fromWeb(source,{objectMode:true,highWaterMark:2}),s.Writable.fromWeb(s.Writable.toWeb(dest),{objectMode:true,highWaterMark:2}));
 assert.equal(count,4096);assert.equal(sum,4095*4096/2);
});
group('terminal bridges remove installed Node and abort listeners',async()=>{
 const s=candidate();const r=node.Readable.from(['a']);await collect(s.Readable.toWeb(r));await tick();
 for(const event of ['data','end','error','close'])assert.equal(r.listenerCount(event),0,event);
 const w=new node.Writable({write(x,e,cb){cb();}});const out=s.Writable.toWeb(w),writer=out.getWriter();await writer.write('a');await writer.close();await tick();
 for(const event of ['drain','finish','error','close'])assert.equal(w.listenerCount(event),0,event);
});
group('candidate refuses unrepresentable null and preserves falsy failures as cause',async()=>{
 const s=candidate();const r=s.Readable.fromWeb(web.ReadableStream.from([null,42]),{objectMode:true});await assert.rejects(collect(r),{code:'ERR_STREAM_NULL_VALUES'});
 for(const reason of [undefined,null,false,0,'']){const source=new web.ReadableStream({start(c){c.error(reason);}});const input=s.Readable.fromWeb(source);await assert.rejects(collect(input),e=>e.code==='ERR_STREAM_WEB'&&e.cause===reason);}
});

group('byte-mode invalid Web chunks fail instead of escaping a Promise reaction',async()=>{
 const s=candidate();const source=web.ReadableStream.from([{invalid:'byte chunk'}]);
 await assert.rejects(collect(s.Readable.fromWeb(source)),{code:'ERR_INVALID_ARG_TYPE'});
});
group('fromWeb signal cancellation preserves the Node abort contract',async()=>{
 await both(async s=>{const a=new AbortController(),reason=Error('stop');let cancel;
 const source=new web.ReadableStream({cancel(x){cancel=x;}},{highWaterMark:0});
 const r=s.Readable.fromWeb(source,{signal:a.signal});const done=completed(r).catch(e=>e);r.read();a.abort(reason);const error=await done;
 return [error.code,error.cause===reason,cancel===error,r.destroyed,source.locked];});
});
group('record Node Duplex close coupling; candidate observes only the writable side',async()=>{
 const d=new node.Duplex({objectMode:true,read(){},write(x,e,cb){cb();}});
 const ref=node.Writable.toWeb(d).getWriter();await ref.write(42);let closed=false;const closing=ref.close().then(()=>closed=true);
 await tick();assert.equal(closed,false);d.push(null);d.resume();await closing;
 const s=candidate(),seen=[];const target=new node.Duplex({objectMode:true,read(){},write(x,e,cb){seen.push(x);cb();}});
 const w=s.Writable.toWeb(target).getWriter();await w.write(42);await w.close();assert.equal(target.readable,true);assert.deepEqual(seen,[42]);target.destroy();
});
group('backpressure size errors destroy the source and release listeners',async()=>{
 const s=candidate(),reason=Error('size');const r=node.Readable.from([1,2]);
 const out=s.Readable.toWeb(r,{strategy:{highWaterMark:1,size(){throw reason;}}});await tick();
 await assert.rejects(out.getReader().read(),e=>e===reason);assert(r.destroyed);await tick();assert.equal(r.listenerCount('data'),0);
});
group('strategy configuration is read once before source listeners are installed',async()=>{
 const s=candidate();let calls=0;const r=node.Readable.from(['a']);const out=s.Readable.toWeb(r,{get strategy(){calls++;return {highWaterMark:1};}});
 assert.equal(calls,1);await collect(out);
 const invalid=node.Readable.from(['a']);assert.throws(()=>s.Readable.toWeb(invalid,{strategy:{highWaterMark:-1}}),RangeError);
 assert.equal(invalid.listenerCount('data'),0);invalid.destroy();
});
group('closed sources, failed sinks and zero-length data keep terminal semantics',async()=>{
 const s=candidate();const r=new node.Readable({read(){this.push(null);}});r.resume();await completed(r);
 assert.deepEqual(await collect(s.Readable.toWeb(r)),[]);
 const e=Error('prior');const w=new node.Writable({write(x,e,cb){cb();}});w.on('error',()=>{});w.destroy(e);await tick();
 const writer=s.Writable.toWeb(w).getWriter();await assert.rejects(writer.closed,x=>x===e);await assert.rejects(writer.write('a'),x=>x===e);
});
group('captured Web and Node methods survive replacement on adapted instances',async()=>{
 const s=candidate();const initial=s.Readable.fromWeb(web.ReadableStream.from([]));await collect(initial);
 const source=web.ReadableStream.from([Buffer.from('ok')]);source.getReader=()=>{throw Error('replacement');};
 assert.equal(Buffer.concat(await collect(s.Readable.fromWeb(source))).toString(),'ok');
 const dest=new node.Writable({write(x,e,cb){cb();}});dest.write=()=>{throw Error('replacement');};dest.end=dest.write;
 const writer=s.Writable.toWeb(dest).getWriter();await writer.write('x');await writer.close();
});
group('explicit refusal for suppressed close notifications has no adoption side effects',()=>{
 const s=candidate();for(const [Ctor,adapt] of [[node.Readable,s.Readable.toWeb],[node.Writable,s.Writable.toWeb]]){
 const n=new Ctor({emitClose:false,read(){},write(x,e,cb){cb();}});
 assert.throws(()=>adapt(n),{code:'ERR_STREAM_WEB_UNSUPPORTED'});assert.equal(n.listenerCount('error'),0);assert.equal(n.destroyed,false);n.destroy();}
});
group('errors during Node finalization reject Web close with original identity',async()=>{
 await both(async s=>{const error=Error('final');const dest=new node.Writable({write(x,e,cb){cb();},final(cb){cb(error);}});
 const writer=s.Writable.toWeb(dest).getWriter();await writer.write('a');return await writer.close().then(()=>false,e=>e===error);});
});
group('pending Web reads close on Node cancellation without a late data event',async()=>{
 const s=candidate();let read=0;const r=new node.Readable({read(){read++;}});const source=s.Readable.toWeb(r),reader=source.getReader();
 const pending=reader.read();await tick();await reader.cancel();assert.deepEqual(await pending,{value:undefined,done:true});assert(r.destroyed);assert.equal(r.listenerCount('data'),0);assert(read>=1);
});

group('private adapter dictionaries do not inherit ambient source algorithms',async()=>{
 const s=candidate();let calls=0;const r=node.Readable.from(['a']);const n=new node.Writable({write(c,e,cb){calls++;cb();}});
 let readable,writable;
 try {
   Object.prototype.type='bytes';Object.prototype.size=()=>{throw Error('ambient size');};
   readable=s.Readable.toWeb(r);writable=s.Writable.toWeb(n);
 } finally {delete Object.prototype.type;delete Object.prototype.size;}
 const values=await collect(readable);const writer=writable.getWriter();await writer.write('x');await writer.close();
 assert.deepEqual(values,['a']);assert.equal(calls,1);
});
group('destroyed Node sources retain prior errors without starting new reads',async()=>{
 const s=candidate(),reason=Error('prior');let reads=0;const r=new node.Readable({read(){reads++;}});r.on('error',()=>{});r.destroy(reason);await tick();
 const out=s.Readable.toWeb(r);await assert.rejects(out.getReader().read(),x=>x===reason);assert.equal(reads,0);
});
group('two adapters on a Web endpoint cannot silently share the same lock',async()=>{
 const s=candidate();const source=web.ReadableStream.from(['a']);const first=s.Readable.fromWeb(source);assert.throws(()=>s.Readable.fromWeb(source));await collect(first);
 const dest=new web.WritableStream();const writer=s.Writable.fromWeb(dest);assert.throws(()=>s.Writable.fromWeb(dest));writer.end();await completed(writer);
});
group('writable abort during delayed destruction waits for its callback',async()=>{
 const s=candidate(),finish=deferred(),reason=Error('stop');const dest=new node.Writable({write(x,e,cb){cb();},destroy(e,cb){finish.promise.then(()=>cb(e));}});
 const writer=s.Writable.toWeb(dest).getWriter();await writer.write('a');let completed=false;const abort=writer.abort(reason).then(()=>completed=true);
 await tick();assert.equal(completed,false);finish.resolve();await abort;assert.equal(completed,true);
});
