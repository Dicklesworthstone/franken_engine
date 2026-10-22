'use strict';
// Actual Node-stream kernel, generic Duplex converter, and Web bridge on host
// primitives. This is not Rust execution. Unrelated collection operators are
// deliberately omitted from this focused composition, not mocked as passing.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const reference = require('node:stream');
const web = require('node:stream/web');
const { Blob, File } = require('node:buffer');
const root = path.join(__dirname, '../../crates/franken-engine/src/lowering_pipeline');
function load(webModules = web) {
  const core = fs.readFileSync(process.env.STREAM_SOURCE || path.join(root, 'stream_module.js'), 'utf8');
  const stream = new Function('__franken_stream_events', '__franken_stream_string_decoder',
    '__franken_stream_next_tick', 'return ' + core)(require('node:events'), require('node:string_decoder'),
    callback => process.nextTick(callback));
  const operators = fs.readFileSync(process.env.STREAM_OPERATORS_SOURCE || path.join(root, 'stream_operators.js'), 'utf8');
  const start = operators.indexOf('  function installDuplexFrom() {');
  const end = operators.indexOf('  // The focused Readable-operator host', start);
  assert(start >= 0 && end > start, 'locate the exact production generic converter');
  new Function('Stream', `
    const Readable=Stream.Readable, from=Readable.from, apply=Reflect.apply;
    const PromiseClass=Promise, promiseThen=Promise.prototype.then;
    const createObject=Object.create, defineProperty=Object.defineProperty;
    const asyncIteratorKey=Symbol.asyncIterator, iteratorKey=Symbol.iterator;
    function then(p,yes,no){return apply(promiseThen,p,[yes,no]);}
    function failure(code,message,range){const e=range?new RangeError(message):new TypeError(message);e.code=code;return e;}
    ${operators.slice(start, end)}
    installDuplexFrom();
  `)(stream);
  const source = fs.readFileSync(process.env.STREAM_BRIDGE_SOURCE || path.join(root, 'stream_web_bridge.js'), 'utf8');
  const loads = { web: 0 };
  new Function('return '+source)()(stream, () => { loads.web++; return webModules; });
  return { stream, loads };
}
const tick = () => new Promise(resolve => setImmediate(resolve));
async function collect(stream) { const result=[]; for await (const chunk of stream) result.push(chunk); return result; }
async function both(check) { await check(reference); const c=load(); await check(c.stream); assert.equal(c.loads.web,0); }
function closed(stream) { return new Promise(resolve => stream.once('close',resolve)); }
function deferred() { let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b;});return {promise,resolve,reject}; }
function bytesTransform(s) { return new s.Transform({objectMode:true,transform(chunk,enc,done){done(null,Buffer.from(chunk));}}); }
function sink(s, chunks) { return new s.Writable({write(chunk,enc,done){chunks.push(Buffer.from(chunk));done();}}); }

if (require.main === module) {
for (const [name, make, expected] of [
  ['Unicode Blob',()=>new Blob(['café 😀\n']),'café 😀\n'],
  ['empty Blob',()=>new Blob([]),''],
  ['File',()=>new File(['file-é'],'input.txt',{lastModified:0}),'file-é'],
  ['Blob subclass',()=>new (class Payload extends Blob {})(['subclass']),'subclass'],
]) test(name+' becomes exactly one read-only ArrayBuffer record',async()=>both(async s=>{
  const input=make(), d=s.Duplex.from(input);
  assert(d instanceof s.Duplex);assert.equal(d.writable,false);assert.equal(d.readableObjectMode,true);
  assert.equal(d.readableHighWaterMark,16);
  const chunks=await collect(d);assert.equal(chunks.length,1);assert(chunks[0] instanceof ArrayBuffer);
  assert.equal(Buffer.from(chunks[0]).toString(),expected);assert.equal(d.destroyed,true);
}));

test('immutable Blob snapshot survives mutation of its original view',async()=>both(async s=>{
  const data=new Uint8Array([255,65,66,255]), blob=new Blob([data.subarray(1,3)]);
  data.fill(90);const [out]=await collect(s.Duplex.from(blob));assert.equal(Buffer.from(out).toString(),'AB');
}));
test('public arrayBuffer override is called once immediately with the Blob receiver',async()=>both(async s=>{
  const blob=new Blob(['original']), value=new Uint8Array([65,66]).buffer;let calls=0, gets=0;
  Object.defineProperty(blob,'arrayBuffer',{get(){gets++;return function(){assert.equal(this,blob);calls++;return Promise.resolve(value);};}});
  const d=s.Duplex.from(blob);assert.equal(calls,1);assert.equal(gets,1);
  const chunks=await collect(d);assert.equal(chunks.length,1);assert.equal(chunks[0],value);
}));
test('Blob conversion has priority over an attached iterator and then method',async()=>both(async s=>{
  const blob=new Blob(['actual']);blob[Symbol.iterator]=function*(){throw new Error('iterator selected');};
  blob.then=()=>{throw new Error('then selected');};
  assert.equal(Buffer.from((await collect(s.Duplex.from(blob)))[0]).toString(),'actual');
}));
test('arrayBuffer conversion throws synchronously before returning an adapter',async()=>both(async s=>{
  for(const getter of [false,true]){
    const reason=new Error('conversion failure'), blob=new Blob(['x']);
    Object.defineProperty(blob,'arrayBuffer',getter?{get(){throw reason;}}:{value(){throw reason;}});
    assert.throws(()=>s.Duplex.from(blob), e=>e===reason);
  }
}));
test('rejected conversion is observed without demand and keeps its error identity',async()=>both(async s=>{
  const reason=new Error('snapshot failed'), blob=new Blob(['x']);blob.arrayBuffer=()=>Promise.reject(reason);
  const d=s.Duplex.from(blob), errors=[];d.on('error',e=>errors.push(e));await closed(d);
  assert.deepEqual(errors,[reason]);assert.equal(d.errored,reason);assert.equal(d.readableLength,0);
}));
test('destroy does not wait for a pending Blob conversion or publish its later result',async()=>both(async s=>{
  const pending=deferred(), blob=new Blob(['x']);blob.arrayBuffer=()=>pending.promise;
  const d=s.Duplex.from(blob), rows=[];d.on('data',x=>rows.push(x));d.on('error',()=>{});
  const done=closed(d);d.destroy();await done;pending.resolve(new Uint8Array([88]).buffer);await tick();
  assert.deepEqual(rows,[]);assert.equal(d.readableLength,0);
}));
test('late rejection after destruction stays observed',async()=>both(async s=>{
  const pending=deferred(), blob=new Blob(['x']);blob.arrayBuffer=()=>pending.promise;
  const d=s.Duplex.from(blob), errors=[];d.on('error',e=>errors.push(e));const done=closed(d);
  d.destroy();await done;pending.reject(new Error('too late'));await tick();assert.deepEqual(errors,[]);
}));
test('Promise pipeline accepts Blob source through a binary conversion transform',async()=>both(async s=>{
  const rows=[];await s.promises.pipeline(new Blob(['café 😀']),bytesTransform(s),sink(s,rows));
  assert.equal(Buffer.concat(rows).toString(),'café 😀');
}));
test('callback pipeline returns its destination and calls completion once',async()=>both(async s=>{
  const rows=[], destination=sink(s,rows);let calls=0;
  await new Promise((resolve,reject)=>{
    const returned=s.pipeline(new Blob(['callback']),bytesTransform(s),destination,e=>{calls++;e?reject(e):resolve();});
    assert.equal(returned,destination);
  });await tick();assert.equal(calls,1);assert.equal(Buffer.concat(rows).toString(),'callback');
}));
test('array-form pipeline and object-mode sink retain the single payload record',async()=>both(async s=>{
  const out=[];await s.promises.pipeline([new Blob([]),new s.Writable({objectMode:true,write(x,e,c){out.push(x);c();}})]);
  assert.equal(out.length,1);assert(out[0] instanceof ArrayBuffer);assert.equal(out[0].byteLength,0);
}));
test('reusable composition accepts a Blob as its read-only head',async()=>both(async s=>{
  const output=s.compose(new Blob(['compose']),bytesTransform(s));assert.equal(output.writable,false);
  assert.equal(Buffer.concat(await collect(output)).toString(),'compose');
}));
test('single-source composition uses the same Blob conversion',async()=>both(async s=>{
  const output=s.compose(new Blob(['single']));const rows=await collect(output);assert.equal(rows.length,1);
  assert.equal(Buffer.from(rows[0]).toString(),'single');
}));
test('candidate cancellation settles before pending conversion and suppresses late bytes (Node divergence)',async()=>{
  const s=load().stream;
  const pending=deferred(), blob=new Blob(['x']), controller=new AbortController();blob.arrayBuffer=()=>pending.promise;
  const rows=[], dest=sink(s,rows);let final=0;dest._final=done=>{final++;done();};
  const task=s.promises.pipeline(blob,bytesTransform(s),dest,{signal:controller.signal});
  controller.abort('stop');await assert.rejects(task,e=>e.code==='ABORT_ERR');
  pending.resolve(new Uint8Array([88]).buffer);await tick();assert.deepEqual(rows,[]);assert.equal(final,0);assert.equal(dest.destroyed,true);
});
test('source conversion failure rejects the pipeline and prevents finalization',async()=>both(async s=>{
  const error=new Error('blob unavailable'), blob=new Blob(['x']);blob.arrayBuffer=()=>Promise.reject(error);
  let writes=0, final=0;const dest=new s.Writable({objectMode:true,write(x,e,c){writes++;c();},final(c){final++;c();}});
  await assert.rejects(s.promises.pipeline(blob,dest),e=>e===error);
  assert.equal(writes,0);assert.equal(final,0);assert.equal(dest.destroyed,true);
}));
test('a lookalike cannot invoke an arrayBuffer getter as a native Blob',async()=>both(async s=>{
  let gets=0;const fake={get arrayBuffer(){gets++;throw new Error('untrusted');},[Symbol.toStringTag]:'Blob'};
  assert.throws(()=>s.Duplex.from(fake));assert.equal(gets,0);
}));
test('ordinary streams, promises, strings and iterables keep the converter path',async()=>both(async s=>{
  for (const input of ['x',Buffer.from('y'),['z'],Promise.resolve('p')]) {
    const out=await collect(s.Duplex.from(input));assert.equal(out.length,1);
  }
}));
test('large Blob remains one record without an extra byte stream or Web initialization',async()=>both(async s=>{
  const bytes=Buffer.alloc(131072,65);bytes[bytes.length-1]=90;
  const out=await collect(s.Duplex.from(new Blob([bytes])));
  assert.equal(out.length,1);assert.equal(Buffer.compare(Buffer.from(out[0]),bytes),0);
}));
test('candidate preflights locked Web stages before starting Blob conversion',async()=>{
  const {stream:s}=load(), blob=new Blob(['x']);let called=0;blob.arrayBuffer=()=>{called++;return Promise.resolve(new ArrayBuffer(1));};
  const target=new web.WritableStream(), writer=target.getWriter();
  try {await assert.rejects(s.promises.pipeline(blob,target),e=>e.code==='ERR_INVALID_STATE');assert.equal(called,0);}
  finally {writer.releaseLock();}
});
test('function sources must still return an iterable rather than a Blob',async()=>both(async s=>{
  const target=new s.Writable({objectMode:true,write(x,e,c){c();}});
  await assert.rejects(s.promises.pipeline(()=>new Blob(['not iterable']),target),e=>e.code==='ERR_INVALID_RETURN_VALUE');
}));
test('Blob input composes with Node and engine-owned Web transforms',async()=>{
  const actualWeb=new Function('return '+fs.readFileSync(path.join(root,'web_stream_module.js'),'utf8'))();
  for(const [s,w] of [[reference,web],[load().stream,web],[load(actualWeb).stream,actualWeb]]) {
    const rows=[];let writes=0,flushes=0;
    const transform=new w.TransformStream({transform(value,controller){writes++;controller.enqueue(new Uint8Array(value));},flush(){flushes++;}});
    await s.promises.pipeline(new Blob(['mixed-é']),transform,sink(s,rows));
    assert.equal(Buffer.concat(rows).toString(),'mixed-é');assert.equal(writes,1);assert.equal(flushes,1);
    assert.equal(transform.readable.locked,false);assert.equal(transform.writable.locked,true);
  }
});

}
module.exports={load};
