'use strict';
// Tests the shipped bridge on Node primitives, not the Rust interpreter.
// The restricted core rejects unconverted Web stages: the reference cannot
// silently provide an implementation that the submitted bridge is missing.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const node = require('node:stream');
const web = require('node:stream/web');
const bridgePath = process.env.FRANKEN_COMPOSE_SOURCE || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_web_bridge.js');
const install = vm.runInThisContext(fs.readFileSync(bridgePath, 'utf8'));
const raw = value => value instanceof web.ReadableStream || value instanceof web.WritableStream ||
  value instanceof web.TransformStream || value && value.readable instanceof web.ReadableStream;
function restricted(values) { for (const value of values) if (raw(value)) throw Error('Unconverted Web stage'); }
function candidate(load = () => web) {
  class R extends node.Readable {}
  class W extends node.Writable {}
  class D extends node.Duplex {}
  Object.defineProperty(R, 'from', {value(iterable, options) {
    const value = node.Readable.from(iterable, options);
    Object.setPrototypeOf(value, R.prototype); return value;
  }, configurable:true});
  Object.defineProperty(D, 'from', { value(value) { restricted([value]); return node.Duplex.from(value); }, configurable:true });
  Object.defineProperty(R.prototype, 'compose', {value(stage, options) {
    restricted([stage]); return node.Readable.prototype.compose.call(this, stage, options);
  }, writable:true, configurable:true});
  const streams = { Readable:R, Writable:W, Duplex:D, Transform:node.Transform, PassThrough:node.PassThrough,
    finished:node.finished, pipeline:node.pipeline, promises:{...node.promises},
    compose(...values) { restricted(values); return node.compose(...values); } };
  return install(streams, load);
}
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() { let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject}; }
function completion(stream) { return new Promise((resolve,reject)=>node.finished(stream,e=>e?reject(e):resolve())); }
async function collect(stream) { const out=[];for await(const item of stream)out.push(item);return out; }
async function text(stream) { return Buffer.concat((await collect(stream)).map(x=>Buffer.from(x))).toString(); }
function group(name,fn) { test(name,{timeout:5000},async()=>{
  let timer; try { await Promise.race([fn(),new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(Error('Unfinished composition: '+name)),4000);
  })]); } finally { clearTimeout(timer); }
}); }
async function both(fn) { const expected=await fn(node);const actual=await fn(candidate());assert.deepEqual(actual,expected);return actual; }
function transform(fn) { return new web.TransformStream({transform(value,c){c.enqueue(fn(value));}}); }

group('two Web transforms form one reusable writable/readable Node stream', async()=>{
  assert.equal(await both(async s=>{
    const chain=s.compose(transform(x=>String(x).toUpperCase()),transform(x=>String(x)+'!'));
    const out=text(chain);chain.end('hello');return await out;
  }),'HELLO!');
});
group('mixed Node and Web transforms preserve order and flush before EOF', async()=>{
  assert.equal(await both(async s=>{
    const a=new s.Transform({transform(x,e,cb){cb(null,Buffer.from(String(x)+'a'));}});
    const b=new web.TransformStream({async transform(x,c){await Promise.resolve();c.enqueue(String(x)+'b');},flush(c){c.enqueue('end');}});
    const c=new s.Transform({transform(x,e,cb){cb(null,Buffer.from('['+String(x)+']'));}});
    const chain=s.compose(a,b,c),out=text(chain);chain.end('x');return await out;
  }),'[xab][end]');
});
group('record byte batching differences for chunk-dependent nested transforms', async()=>{
  async function run(s) {
    const inner=s.compose(transform(x=>String(x)+'1'),transform(x=>String(x)+'2'));
    const outer=s.compose(inner,transform(x=>String(x)+'3'));
    const seen=[];await s.promises.pipeline(s.Readable.from(['a','b']),outer,
      new s.Writable({write(x,e,cb){seen.push(String(x));cb();}}));return seen.join('');
  }
  // Byte streams need not keep write boundaries. Node coalesces the two
  // inner byte chunks here; the bridge's one-chunk demand does not. Record
  // both literal observations rather than calling this a parity pass.
  assert.equal(await run(node),'a12b123');
  assert.equal(await run(candidate()),'a123b123');
});
group('nested byte transforms preserve chunk-independent output in a real pipeline', async()=>{
  assert.equal(await both(async s=>{
    const inner=s.compose(transform(x=>String(x).toUpperCase()),transform(x=>x));
    const outer=s.compose(inner,transform(x=>String(x).replaceAll('A','X')));
    const seen=[];await s.promises.pipeline(s.Readable.from(['ab','ac']),outer,
      new s.Writable({write(x,e,cb){seen.push(String(x));cb();}}));return seen.join('');
  }),'XBXC');
});
group('Web readable and sink endpoints form a closed composite', async()=>{
  assert.deepEqual(await both(async s=>{
    const seen=[];const out=s.compose(web.ReadableStream.from(['a','b']),new web.WritableStream({write(x){seen.push(String(x));}}));
    const sides=[out.readable,out.writable];await completion(out);return [sides,seen];
  }),[[false,false],['a','b']]);
});
group('single Web endpoints reuse generic byte-mode Duplex adoption', async()=>{
  await both(async s=>{
    const input=web.ReadableStream.from([new Uint8Array([65,66])]);const a=s.compose(input);const flags=[a.readable,a.writable,a.readableObjectMode];
    const bytes=await text(a);const seen=[];const b=s.compose(new web.WritableStream({write(x){seen.push(String(x));}}));
    flags.push(b.readable,b.writable,b.writableObjectMode);b.end('ok');await completion(b);
    return [flags,bytes,seen];
  });
});
group('byte-mode boundaries keep object-valued internal Web stages usable', async()=>{
  assert.equal(await both(async s=>{
    const a=transform(x=>({message:String(x)})),b=transform(x=>x.message+'!');
    const out=s.compose(a,b),p=text(out);out.end('ok');return await p;
  }),'ok!');
});
group('Web tail exposes byte mode while a Node object-mode head stays object mode', async()=>{
  await both(async s=>{
    const a=new s.Transform({objectMode:true,transform(x,e,cb){cb(null,x);}});
    const b=transform(x=>JSON.stringify(x));const out=s.compose(a,b);
    const flags=[out.readableObjectMode,out.writableObjectMode];const p=text(out);out.end({n:42});return [flags,await p];
  });
});
group('unrepresentable tail chunks fail rather than becoming successful output', async()=>{
  await both(async s=>{
    const out=s.compose(transform(x=>x),transform(()=>42));const done=completion(out).then(()=>false,e=>e.code);
    out.resume();out.end('x');return await done;
  });
});
group('async-generator composition stages receive the core iterable and signal', async()=>{
  assert.equal(await both(async s=>{
    let calls=0,signal;const out=s.compose(async function*(source,options){calls++;signal=options.signal;
      for await(const x of source)yield String(x).toUpperCase();},transform(x=>String(x)+'!'));
    const p=text(out);out.end('ok');const value=await p;assert.equal(calls,1);assert(signal instanceof AbortSignal);return value;
  }),'OK!');
});
group('function sink completes only after asynchronous final effects', async()=>{
  await both(async s=>{
    const gate=deferred(),seen=[];const out=s.compose(transform(x=>String(x)+'!'),async function(source){
      for await(const x of source)seen.push(String(x));await gate.promise;seen.push('done');});
    let closed=false;const done=completion(out).then(()=>closed=true);out.end('a');await tick();assert.equal(closed,false);
    gate.resolve();await done;return seen;
  });
});
group('Readable.compose consumes Web transforms through the same adapter', async()=>{
  assert.equal(await both(async s=>{
    const input=new s.Readable({read(){this.push('a');this.push('b');this.push(null);}});
    return text(input.compose(transform(x=>String(x).toUpperCase())));
  }),'AB');
});
group('normal Node-only composition keeps the Web dependency uninitialized', async()=>{
  let loads=0;const s=candidate(()=>{loads++;return web;});
  const out=s.compose(new s.PassThrough(),new s.PassThrough());const p=text(out);out.end('a');assert.equal(await p,'a');
  const input=new s.Readable({read(){this.push('b');this.push(null);}});assert.equal(await text(input.compose(new s.PassThrough())),'b');
  assert.equal(loads,0);
});
group('duplicate and locked Web endpoints are rejected before ownership', async()=>{
  const s=candidate();const t=transform(x=>x);assert.throws(()=>s.compose(t,t),{code:'ERR_INVALID_STATE'});
  assert.equal(t.readable.locked,false);assert.equal(t.writable.locked,false);
  const first=transform(x=>x),last=transform(x=>x);const writer=last.writable.getWriter();
  assert.throws(()=>s.compose(first,last),{code:'ERR_INVALID_STATE'});assert.equal(first.readable.locked,false);assert.equal(first.writable.locked,false);writer.releaseLock();
});
group('composition rejects a missing intermediate side before adopting earlier endpoints', async()=>{
  const s=candidate(),a=transform(x=>x),b=new web.WritableStream(),c=transform(x=>x);
  assert.throws(()=>s.compose(a,b,c));for(const t of [a,c]){assert.equal(t.readable.locked,false);assert.equal(t.writable.locked,false);}assert.equal(b.locked,false);
});
group('a later core setup failure cancels adopted endpoints exactly once', async()=>{
  const s=candidate(),seen=[];const r=new web.ReadableStream({cancel(){seen.push('cancel');}},{highWaterMark:0});
  const w=new web.WritableStream({abort(){seen.push('abort');}});
  assert.throws(()=>s.compose(r,42,w));await tick();assert.deepEqual(seen.sort(),['abort','cancel']);assert.equal(r.locked,false);
});
group('destroying a composite waits for both asynchronous Web cleanup operations', async()=>{
  const s=candidate(),gate=deferred(),started=[],reason=Error('stop');
  const a={readable:new web.ReadableStream({cancel(x){assert.equal(x,reason);started.push('cancel');return gate.promise;}},{highWaterMark:0}),
    writable:new web.WritableStream({abort(x){assert.equal(x,reason);started.push('abort');return gate.promise;}})};
  const out=s.compose(a,new s.PassThrough());let closed=false;const done=new Promise(resolve=>out.once('close',()=>{closed=true;resolve();}));out.on('error',()=>{});out.destroy(reason);
  await tick();assert.deepEqual(started.sort(),['abort','cancel']);assert.equal(closed,false);gate.resolve();await done;assert.equal(a.readable.locked,false);
});
group('source errors abort the Web sink and preserve failure identity', async()=>{
  const s=candidate(),reason=Error('source'),seen=[];let control;
  const input=new web.ReadableStream({start(c){control=c;}},{highWaterMark:0});
  const out=s.compose(input,new web.WritableStream({abort(e){seen.push(e);}}));const done=completion(out).catch(e=>e);
  control.error(reason);assert.equal(await done,reason);assert.deepEqual(seen,[reason]);assert.equal(input.locked,false);
});
group('sink failure cancels a stalled readable and completes cleanup', async()=>{
  const s=candidate(),reason=Error('sink');let cancel;let control;
  const input=new web.ReadableStream({start(c){control=c;},cancel(e){cancel=e;}},{highWaterMark:0});
  const out=s.compose(input,new web.WritableStream({write(){throw reason;}}));const done=completion(out).catch(e=>e);
  control.enqueue('x');assert.equal(await done,reason);assert.equal(cancel,reason);assert.equal(input.locked,false);
});
group('Readable.compose validates options before locking its Web destination', async()=>{
  const s=candidate();const input=new s.Readable({read(){}}),t=transform(x=>x);
  for(const settings of [null,42,{signal:{}}])assert.throws(()=>input.compose(t,settings));
  assert.equal(t.readable.locked,false);assert.equal(t.writable.locked,false);assert.equal(input.destroyed,false);input.destroy();
});
group('Readable.compose aborts stalled inputs and retains the AbortSignal cause', async()=>{
  const s=candidate(),control=new AbortController(),reason=Error('stop'),seen=[];
  const input=new s.Readable({read(){},destroy(e,cb){seen.push('input');cb(e);}});
  const t={readable:new web.ReadableStream({cancel(){seen.push('read');}},{highWaterMark:0}),
    writable:new web.WritableStream({abort(){seen.push('write');}})};
  const out=input.compose(t,{signal:control.signal}),done=completion(out).catch(e=>e);out.resume();control.abort(reason);
  const error=await done;assert.equal(error.code,'ABORT_ERR');assert.equal(error.cause,reason);assert.deepEqual(seen.sort(),['input','read','write']);
});
group('many asynchronous chunks traverse without concurrent transform callbacks', async()=>{
  const s=candidate();let active=0,max=0,n=0;
  const a=new web.TransformStream({async transform(x,c){active++;max=Math.max(max,active);await Promise.resolve();c.enqueue(String(x));active--;}});
  const b=transform(x=>x);const out=s.compose(a,b),read=text(out);
  await s.promises.pipeline(s.Readable.from(Array.from({length:2048},()=>String(n++%10))),out);
  assert.equal((await read).length,2048);assert.equal(max,1);
});
group('Readable.from results cannot inherit reference-only compose support', async()=>{
  const s=candidate(),out=s.Readable.from(['a','b']).compose(transform(x=>String(x).toUpperCase()));
  assert.equal(await text(out),'AB');
});
group('object-valued interior chunks preserve identity without assimilating thenables', async()=>{
  const s=candidate();let called=0;const item={then(){called++;throw Error('not a promise');}};
  const a=transform(()=>item),b=transform(x=>{assert.equal(x,item);return 'ok';});
  const out=s.compose(a,b),p=text(out);out.end('x');assert.equal(await p,'ok');assert.equal(called,0);
});
group('pair getters are read once and their exceptions escape unchanged', async()=>{
  const s=candidate(),t=transform(x=>x);let reads=0,writes=0;
  const pair={get readable(){reads++;return t.readable;},get writable(){writes++;return t.writable;}};
  const out=s.compose(pair,new s.PassThrough()),p=text(out);out.end('a');assert.equal(await p,'a');assert.equal(reads,1);assert.equal(writes,1);
  const e=Error('getter');assert.throws(()=>s.compose(transform(x=>x),{get readable(){throw e;},writable:new web.WritableStream()}),x=>x===e);
});
group('early error during setup does not lose reader release or duplicate cleanup', async()=>{
  const s=candidate(),e=Error('early'),seen=[];
  const input=new web.ReadableStream({start(c){c.error(e);}});
  const out=s.compose(input,new web.WritableStream({abort(x){seen.push(x);}}));
  assert.equal(await completion(out).catch(x=>x),e);assert.deepEqual(seen,[e]);assert.equal(input.locked,false);
});
group('Readable.compose reads signal once before any endpoint adoption', async()=>{
  const s=candidate(),a=new AbortController();let count=0;
  const out=s.Readable.from(['a']).compose(transform(x=>x),{get signal(){count++;return a.signal;}});
  assert.equal(await text(out),'a');assert.equal(count,1);
});
group('mutable public getReader and getWriter do not replace canonical operations', async()=>{
  const s=candidate(),a=transform(x=>x),b=transform(x=>x);
  for(const t of [a,b]){t.readable.getReader=()=>{throw Error('replacement');};t.writable.getWriter=()=>{throw Error('replacement');};}
  const out=s.compose(a,b),p=text(out);out.end('a');assert.equal(await p,'a');
});
group('Node-only single identity and empty-argument validation remain delegated', async()=>{
  const s=candidate(),p=new s.PassThrough();assert.equal(s.compose(p),p);p.destroy();
  assert.throws(()=>s.compose(),{code:'ERR_MISSING_ARGS'});
});
