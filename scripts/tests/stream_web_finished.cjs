'use strict';
// Actual Web kernel and Node bridge on host primitives; NOT native execution.
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const {load} = require('./stream_pipeline_values.cjs');
const native = require('node:stream');
const nativeWeb = require('node:stream/web');
const root = path.resolve(__dirname, '../../crates/franken-engine/src/lowering_pipeline');
const tick = () => new Promise(resolve => setImmediate(resolve));
function loadFinished() {
  const web = process.env.FINISHED_NODE_WEB === '1' ? nativeWeb : new Function('return '+
    fs.readFileSync(process.env.FINISHED_WEB_SOURCE || path.join(root, 'web_stream_module.js'), 'utf8'))();
  const lane = load(web);
  let loads = 0;
  if (process.env.FINISHED_BEFORE !== '1') {
    const source = fs.readFileSync(process.env.FINISHED_SOURCE || path.join(root,'stream_finished.js'), 'utf8');
    new Function('__franken_stream_web_tick','return '+source)(cb=>process.nextTick(cb))(
      lane.stream, ()=>{loads++;return web;});
  }
  return {stream:lane.stream, web, loads:()=>loads};
}
async function bounded(promise) {
  let timer;
  try {return await Promise.race([promise,new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(new Error('completion did not settle')),1500);
  })]);} finally {clearTimeout(timer);}
}
function compare(name, action) {
  test(name,{timeout:5000},async()=>{
    await bounded(action(native,nativeWeb,'reference'));
    const c=loadFinished();await bounded(action(c.stream,c.web,'candidate'));
  });
}
function candidate(name,action) {
  test('candidate: '+name,{timeout:4000},async()=>{const c=loadFinished();await bounded(action(c.stream,c.web,c));});
}
function observed(io,value,options) { return io.promises.finished(value,options); }
async function consume(readable) { const reader=readable.getReader(),out=[];try{while(true){const s=await reader.read();if(s.done)return out;out.push(s.value);}}finally{reader.releaseLock();} }
if(require.main===module){
compare('readable completion neither acquires a lock nor consumes queued data',async(io,web)=>{
  let controller,pulls=0,done=false;
  const r=new web.ReadableStream({start(c){controller=c;},pull(){pulls++;}},{highWaterMark:0});
  const p=observed(io,r).then(()=>{done=true;});
  await tick();assert.equal(r.locked,false);assert.equal(pulls,0);assert.equal(done,false);
  controller.enqueue('café');controller.close();await tick();assert.equal(done,false);
  assert.deepEqual(await consume(r),['café']);await p;assert.equal(done,true);
});
compare('reader release does not report a stream error or steal the next lock',async(io,web)=>{
  let c;const r=new web.ReadableStream({start(x){c=x;}},{highWaterMark:0});
  const first=r.getReader();const p=observed(io,r);assert.equal(r.locked,true);
  first.releaseLock();await tick();assert.equal(r.locked,false);
  const second=r.getReader();c.enqueue(42);c.close();assert.deepEqual(await second.read(),{value:42,done:false});
  await p;assert.equal(r.locked,true);second.releaseLock();
});
compare('BYOB completion observes the byte stream independently of its reader',async(io,web)=>{
  let c;const r=new web.ReadableStream({type:'bytes',start(x){c=x;}});
  const reader=r.getReader({mode:'byob'}),p=observed(io,r);
  const read=reader.read(new Uint8Array(4));c.enqueue(new Uint8Array([65,66]));c.close();
  assert.deepEqual(Array.from((await read).value),[65,66]);await p;assert.equal(r.locked,true);reader.releaseLock();
});
compare('writable completion waits for writes and asynchronous sink close',async(io,web)=>{
  const out=[];let closed=false;
  const w=new web.WritableStream({async write(x){await tick();out.push(x);},async close(){await tick();closed=true;}});
  const p=observed(io,w);assert.equal(w.locked,false);const writer=w.getWriter();
  await writer.write('written');await writer.close();await p;
  assert.equal(closed,true);assert.deepEqual(out,['written']);assert.equal(w.locked,true);writer.releaseLock();
});
compare('writer release is not stream completion',async(io,web)=>{
  const w=new web.WritableStream();let done=false;const writer=w.getWriter();
  const p=observed(io,w).then(()=>{done=true;});writer.releaseLock();await tick();assert.equal(done,false);
  await w.close();await p;assert.equal(w.locked,false);
});
compare('readable errors preserve identity before and after observation',async(io,web)=>{
  for(const before of [false,true]) {const error=new Error('source failed');let c;const r=new web.ReadableStream({start(x){c=x;}});
    if(before)c.error(error);const p=observed(io,r);if(!before)c.error(error);await assert.rejects(p,e=>e===error);}
});
compare('writable write errors preserve identity and do not resolve successfully',async(io,web)=>{
  const reason=new Error('write failed');const w=new web.WritableStream({write(){throw reason;}}),writer=w.getWriter();
  const p=observed(io,w);await assert.rejects(writer.write('x'),e=>e===reason);await assert.rejects(p,e=>e===reason);writer.releaseLock();
});
compare('already closed streams notify asynchronously with the original receiver',async(io,web)=>{
  const r=new web.ReadableStream({start(c){c.close();}});let returned=false,calls=0;
  await new Promise((resolve,reject)=>{const clean=io.finished(r,function(error){calls++;try{assert.equal(this,r);assert(returned);assert.equal(error,undefined);resolve();}catch(e){reject(e);}});assert.equal(typeof clean,'function');returned=true;});
  assert.equal(calls,1);
});
test('reference difference: Web callback cleanup suppresses later notification in candidate only',async()=>{
  for(const role of ['reference','candidate']){
    const lane=role==='reference'?{stream:native,web:nativeWeb}:loadFinished(),io=lane.stream,web=lane.web;
    let c,calls=0;const r=new web.ReadableStream({start(x){c=x;}});
    const cleanup=io.finished(r,()=>{calls++;});cleanup();cleanup();c.error(new Error('later'));await tick();
    assert.equal(calls,role==='reference'?1:0);
  }
});
compare('cleanup:true and disabled-side options still observe Web state',async(io,web)=>{
  for(const settings of [{cleanup:true},{cleanup:null},{cleanup:0},{cleanup:''},{readable:false},{writable:false},{error:false},{readable:false,writable:false}]){
    let c,done=false;const r=new web.ReadableStream({start(x){c=x;}});const p=observed(io,r,settings).then(()=>{done=true;});
    await tick();assert.equal(done,false);c.close();await p;
  }
});
compare('promisification uses the same completion implementation',async(io,web)=>{
  const finish=require('node:util').promisify(io.finished),w=new web.WritableStream();
  const p=finish(w);await w.close();assert.equal(await p,undefined);
});
compare('invalid options callback and signal reject without locking',async(io,web)=>{
  const r=new web.ReadableStream();
  for(const settings of [[],false,1,'x'])await assert.rejects(observed(io,r,settings),e=>e.code==='ERR_INVALID_ARG_TYPE');
  for(const signal of [null,{},false])await assert.rejects(observed(io,r,{signal}),e=>e.code==='ERR_INVALID_ARG_TYPE');
  assert.throws(()=>io.finished(r,{},null),e=>e.code==='ERR_INVALID_ARG_TYPE');assert.equal(r.locked,false);await r.cancel();
});
compare('Promise cleanup option is validated rather than silently ignored',async(io,web)=>{
  for(const cleanup of [1,'true',{}]){
    const w=new web.WritableStream();
    assert.throws(()=>observed(io,w,{cleanup}),e=>e.code==='ERR_INVALID_ARG_TYPE');await w.close();
  }
});
compare('cancelling observation leaves the underlying stream usable',async(io,web)=>{
  const ac=new AbortController();let c,cancels=0;const r=new web.ReadableStream({start(x){c=x;},cancel(){cancels++;}});
  const reason={stop:true};const p=observed(io,r,{signal:ac.signal});ac.abort(reason);
  await assert.rejects(p,e=>e.code==='ABORT_ERR'&&e.cause===reason);assert.equal(r.locked,false);assert.equal(cancels,0);
  const next=observed(io,r);c.enqueue('still usable');c.close();assert.deepEqual(await consume(r),['still usable']);await next;
});
compare('already aborted wait is asynchronous and retains falsy abort causes',async(io,web)=>{
  for(const reason of [null,false,0]){const ac=new AbortController();ac.abort(reason);const w=new web.WritableStream();
    await assert.rejects(observed(io,w,{signal:ac.signal}),e=>e.code==='ABORT_ERR'&&e.cause===reason);assert.equal(w.locked,false);await w.close();}
});
compare('stopImmediatePropagation does not suppress genuine wait cancellation',async(io,web)=>{
  const ac=new AbortController();ac.signal.addEventListener('abort',e=>e.stopImmediatePropagation());const w=new web.WritableStream();
  const p=observed(io,w,{signal:ac.signal});ac.abort('reason');await assert.rejects(p,e=>e.code==='ABORT_ERR');await w.close();
});
compare('writable abort completion waits for its asynchronous cleanup',async(io,web)=>{
  let release,closed=false;const gate=new Promise(r=>release=r),reason=new Error('abort');
  const w=new web.WritableStream({async abort(){await gate;closed=true;}}),writer=w.getWriter();let done=false;
  const p=observed(io,w).catch(e=>{assert.equal(e,reason);done=true;});const abort=writer.abort(reason);
  await tick();assert.equal(done,false);release();await abort;await p;assert.equal(closed,true);writer.releaseLock();
});
compare('Readable cancel completion is distinct from the source cleanup promise',async(io,web)=>{
  let release,cleaned=false;const gate=new Promise(r=>release=r);
  const r=new web.ReadableStream({async cancel(){await gate;cleaned=true;}}),p=observed(io,r),cancel=r.cancel();
  await p;assert.equal(cleaned,false);release();await cancel;assert.equal(cleaned,true);
});
compare('multiple observers settle exactly once across pipeTo completion',async(io,web)=>{
  const r=new web.ReadableStream({start(c){c.enqueue('x');c.close();}}),out=[];
  const w=new web.WritableStream({write(x){out.push(x);}});
  const waiters=[];for(let i=0;i<32;i++)waiters.push(observed(io,r),observed(io,w));
  await r.pipeTo(w);await Promise.all(waiters);assert.deepEqual(out,['x']);assert.equal(r.locked,false);assert.equal(w.locked,false);
});
candidate('Node-only finished does not initialize the Web dependency',async(io,web,lane)=>{
  const r=io.Readable.from(['x']),p=observed(io,r);r.resume();await p;assert.equal(lane.loads(),0);
});
candidate('synthetic public abort cannot cancel a wait or consume its registration',async(io,web)=>{
  const ac=new AbortController(),w=new web.WritableStream();let done=false;
  const p=observed(io,w,{signal:ac.signal}).catch(e=>{assert.equal(e.code,'ABORT_ERR');done=true;});
  ac.signal.dispatchEvent(new Event('abort'));await tick();assert.equal(done,false);ac.abort();await p;assert.equal(done,true);await w.close();
});
candidate('genuine completion ignores a forged own closure-promise slot',async(io,web)=>{
  if(process.env.FINISHED_NODE_WEB==='1')return;
  let c,done=false;const r=new web.ReadableStream({start(x){c=x;}});
  Object.defineProperty(r,Symbol.for('nodejs.webstream.isClosedPromise'),{value:{promise:Promise.resolve()}});
  const p=observed(io,r).then(()=>{done=true;});await tick();assert.equal(done,false);c.close();await p;
});
candidate('closed records expose no resolver and share a lazy immutable promise',async(io,web)=>{
  if(process.env.FINISHED_NODE_WEB==='1')return;
  const w=new web.WritableStream(),key=Symbol.for('nodejs.webstream.isClosedPromise');
  const a=w[key],b=w[key];assert.equal(a,b);assert.deepEqual(Reflect.ownKeys(a),['promise']);
  assert.equal(Object.getOwnPropertyDescriptor(a,'promise').writable,false);assert.equal(Object.getPrototypeOf(a),null);
  const p=observed(io,w);await w.close();await p;
});
candidate('falsy Web errors cannot become successful EOF',async(io,web)=>{
  for(const reason of [undefined,null,false,0,'']){let c;const r=new web.ReadableStream({start(x){c=x;}});const p=observed(io,r);c.error(reason);
    await assert.rejects(p,e=>e.code==='ERR_STREAM_WEB'&&Object.is(e.cause,reason));}
});
candidate('standard Node finished can observe the engine Web completion protocol',async(io,web)=>{
  const w=new web.WritableStream(),p=native.promises.finished(w);await w.close();await p;
});
candidate('observation never invokes replaceable getReader or getWriter methods',async(io,web)=>{
  for(const kind of ['read','write']){let c;const v=kind==='read'?new web.ReadableStream({start(x){c=x;}}):new web.WritableStream();
    v.getReader=v.getWriter=()=>{throw new Error('lock acquired');};const p=observed(io,v);if(c)c.close();else await v.close();await p;}
});
compare('monitored Web endpoints share the same Node/Web pipeline adapters',async(io,web)=>{
  const out=[];const r=new web.ReadableStream({start(c){c.enqueue(Buffer.from('café'));c.close();}});
  const w=new web.WritableStream({async write(x){await tick();out.push(Buffer.from(x));}});
  const waiting=Promise.all([observed(io,r),observed(io,w)]);
  const transform=new io.Transform({transform(x,e,done){done(null,Buffer.from(x.toString().toUpperCase()));}});
  await io.promises.pipeline(r,transform,w);await waiting;
  assert.equal(Buffer.concat(out).toString(),'CAFÉ');assert.equal(r.locked,false);assert.equal(w.locked,true);
});
candidate('completion promises are lazy and shared by repeated observers',async()=>{
  const source=fs.readFileSync(process.env.FINISHED_WEB_SOURCE || path.join(root,'web_stream_module.js'),'utf8');let allocations=0;
  function Counted(executor){allocations++;return new Promise(executor);}
  Object.setPrototypeOf(Counted,Promise);Counted.prototype=Promise.prototype;
  const web=new Function('Promise','return '+source)(Counted),key=Symbol.for('nodejs.webstream.isClosedPromise');
  const r=new web.ReadableStream({}, {highWaterMark:0}),w=new web.WritableStream();await tick();
  const before=allocations;const a=r[key],b=r[key],c=w[key],d=w[key];
  assert.equal(allocations-before,2);assert.equal(a,b);assert.equal(c,d);
  await r.cancel();await w.close();await Promise.all([a.promise,c.promise]);
});
compare('a late observer still waits for a pending writable abort algorithm',async(io,web)=>{
  let release;const gate=new Promise(r=>release=r),reason=new Error('stop');
  const w=new web.WritableStream({abort(){return gate;}});
  const stop=w.abort(reason);await tick();let done=false;
  const p=observed(io,w).catch(e=>{assert.equal(e,reason);done=true;});
  await tick();assert.equal(done,false);release();await stop;await p;
});
candidate('callback exceptions escape once from the tick boundary, not a Promise handler',async()=>{
  const {spawnSync}=require('node:child_process');
  const program=`const {loadFinished}=require(${JSON.stringify(__filename)});const {stream:s,web}=loadFinished();let calls=0;
    process.once('uncaughtException',e=>{console.log(e.message,calls);});
    s.finished(new web.WritableStream({start(c){c.error(new Error('sink'));}}),()=>{calls++;throw new Error('callback');});`;
  const p=spawnSync(process.execPath,['-e',program],{env:process.env,encoding:'utf8',timeout:3000});
  assert.equal(p.status,0,p.stderr);assert.equal(p.stdout,'callback 1\n');assert.equal(p.stderr,'');
});
}
module.exports={loadFinished};
