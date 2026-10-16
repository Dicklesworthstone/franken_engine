'use strict';
// The complete shipped filesystem factory on Node language/Buffer/Web-stream
// primitives. This does not execute Rust, its host provider, or native budgets.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const vm = require('node:vm');
const web = require('node:stream/web');
const source = fs.readFileSync(process.env.FRANKEN_FS_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/fs_module.js'), 'utf8');
const tick = () => new Promise(resolve => setImmediate(resolve));

function fixture(hook = () => undefined) {
  const root = fs.mkdtempSync('/tmp/franken-file-web-');
  const file = path.join(root, 'input');
  const calls = [];
  const live = new Set();
  let loads = 0;
  function effect(authority, tag, ...args) {
    const op = tag.slice(6);
    const call = { authority, op, args };
    calls.push(call);
    const answer = hook(call);
    if (answer && answer.throw) throw answer.value;
    if (answer && answer.return) return answer.value;
    switch (op) {
      case 'open': { const fd = fs.openSync(...args); live.add(fd); return fd; }
      case 'close_fd': live.delete(args[0]); return fs.closeSync(args[0]);
      case 'read_fd': return fs.readSync(args[0], args[1], args[2],
        answer && answer.limit !== undefined ? Math.min(args[3], answer.limit) : args[3], args[4]);
      case 'write_fd': return fs.writeSync(...args);
      default: throw new Error('Unexpected operation ' + op);
    }
  }
  const context = vm.createContext({ Buffer, Promise, WeakMap, Reflect, ArrayBuffer,
    Array, Object, Symbol, AggregateError, Error, TypeError, RangeError, Uint8Array, DataView,
    require(name) { assert.equal(name, 'stream/web'); loads++; return web; },
    __franken_fs_read: effect.bind(null, 'fs:read'),
    __franken_fs_write: effect.bind(null, 'fs:write') });
  const api = vm.runInContext(source, context);
  return { root, file, api, calls, live, loads: () => loads };
}
function closed(f) {
  assert.equal(f.live.size, 0);
  assert.equal(f.calls.filter(c => c.op === 'close_fd').length,
    f.calls.filter(c => c.op === 'open').length);
}
async function contents(stream) {
  const result = [];
  for await (const chunk of stream) {
    assert(chunk instanceof Uint8Array);
    result.push(Buffer.from(chunk));
  }
  return Buffer.concat(result);
}
async function scenario(makeHandle, offset = 0) {
  const h = await makeHandle();
  let reader;
  try {
  const before = await h.read(Buffer.alloc(2));
  const stream = h.readableWebStream();
  assert.throws(() => h.readableWebStream(), {code:'ERR_INVALID_STATE'});
  reader = stream.getReader({mode:'byob'});
  const got = [];
  for (;;) {
    const input = new Uint16Array(new ArrayBuffer(14), offset, 4);
    const result = await reader.read(input, {min:2});
    assert.equal(input.buffer.byteLength, 0, 'BYOB transfers caller storage');
    assert(result.value instanceof Uint16Array);
    got.push(Buffer.from(result.value.buffer, result.value.byteOffset, result.value.byteLength));
    if (result.done) break;
  }
  await reader.closed;
  reader.releaseLock();
  const openAtEnd = h.fd >= 0;
  const eof = (await h.read(Buffer.alloc(1))).bytesRead;
  await h.close();
  return { prefix:before.buffer.toString(), text:Buffer.concat(got).toString(),openAtEnd,eof };
  } finally {
    if (reader) { try { await reader.cancel(); } catch (_) {} try { reader.releaseLock(); } catch (_) {} }
    await h.close();
  }
}

test('default reader drains a multi-chunk file using bounded read-only descriptor effects', async () => {
  const f=fixture(), bytes=Buffer.alloc(65539);for(let i=0;i<bytes.length;i++)bytes[i]=i%251;
  fs.writeFileSync(f.file,bytes);const h=await f.api.promises.open(f.file);
  assert.equal(f.loads(),0);const stream=h.readableWebStream();
  assert(stream instanceof web.ReadableStream);await tick();
  assert.equal(f.calls.filter(c=>c.op==='read_fd').length,0,'no read before demand');
  assert.deepEqual(await contents(stream),bytes);
  const reads=f.calls.filter(c=>c.op==='read_fd');
  assert.equal(reads.length,6);assert(reads.every(c=>c.authority==='fs:read'&&c.args[3]<=16384));
  assert(h.fd>=0,'default retains caller ownership');await h.close();closed(f);
});

test('typed BYOB min-fill, transfer and shared cursor agree with live Node', async () => {
  const f=fixture();fs.writeFileSync(f.file,'0123456789abcdefgh');
  const expected=await scenario(()=>fsp.open(f.file));
  const actual=await scenario(()=>f.api.promises.open(f.file));
  assert.deepEqual(actual,expected);assert.deepEqual(actual,{prefix:'01',text:'23456789abcdefgh',openAtEnd:true,eof:0});closed(f);
});

// Node 22.16's offset-view failure is recorded in the development evidence,
// separately from these assertions; it is not a successful parity result.
test('offset BYOB windows preserve exact bytes and default borrowed ownership', async () => {
  const f=fixture();fs.writeFileSync(f.file,'0123456789abcdefgh');
  const expected={prefix:'01',text:'23456789abcdefgh',openAtEnd:true,eof:0};
  assert.deepEqual(await scenario(()=>f.api.promises.open(f.file),2),expected);closed(f);
});

test('BYOB views larger than the host bound fill through consecutive bounded requests', async () => {
  const f=fixture(c=>c.op==='read_fd'?{limit:997}:undefined);const bytes=Buffer.alloc(50000,82);fs.writeFileSync(f.file,bytes);
  const h=await f.api.promises.open(f.file), reader=h.readableWebStream().getReader({mode:'byob'});
  const first=await reader.read(new Uint8Array(65536),{min:50000});
  assert.equal(first.value.byteLength,50000);assert.deepEqual(Buffer.from(first.value),bytes);
  assert(f.calls.filter(c=>c.op==='read_fd').length>50);
  assert(f.calls.filter(c=>c.op==='read_fd').every(c=>c.args[3]<=16384));
  const last=await reader.read(new DataView(new ArrayBuffer(8)));assert(last.done);assert.equal(last.value.byteLength,0);
  reader.releaseLock();await h.close();closed(f);
});

test('short reads are not EOF and odd typed final data rejects rather than truncates', async () => {
  const f=fixture(c=>c.op==='read_fd'?{limit:1}:undefined);fs.writeFileSync(f.file,'abc');
  const h=await f.api.promises.open(f.file),r=h.readableWebStream().getReader({mode:'byob'});
  const first=await r.read(new Uint16Array(4));assert.equal(Buffer.from(first.value.buffer,first.value.byteOffset,first.value.byteLength).toString(),'ab');
  await assert.rejects(r.read(new Uint16Array(4)),TypeError);await assert.rejects(r.closed,TypeError);
  r.releaseLock();await h.close();closed(f);
});

test('backpressure makes each read demand-driven and preserves the shared descriptor cursor', async () => {
  const f=fixture();fs.writeFileSync(f.file,'abcdefghij');const h=await f.api.promises.open(f.file);
  const r=h.readableWebStream().getReader({mode:'byob'});await tick();assert.equal(f.calls.length,1);
  assert.equal(Buffer.from((await r.read(new Uint8Array(3))).value).toString(),'abc');
  await tick();assert.equal(f.calls.filter(c=>c.op==='read_fd').length,1);
  assert.equal((await h.read(Buffer.alloc(2))).buffer.toString(),'de');
  assert.equal(Buffer.from((await r.read(new Uint8Array(2))).value).toString(),'fg');
  await r.cancel();r.releaseLock();assert.equal((await h.readFile('utf8')),'hij');await h.close();closed(f);
});

test('default cancellation and preventCancel iteration retain caller ownership', async () => {
  for(const preventCancel of [false,true]){
    const f=fixture();fs.writeFileSync(f.file,'content');const h=await f.api.promises.open(f.file);
    const stream=h.readableWebStream();const it=stream.values({preventCancel});await it.return();
    assert(h.fd>=0);assert.equal(f.calls.filter(c=>c.op==='read_fd').length,0);
    if(preventCancel)assert.equal((await contents(stream)).toString(),'content');
    else assert.equal((await stream.getReader().read()).done,true);
    await h.close();closed(f);
  }
});

test('autoClose completes at EOF and cancellation; this option postdates Node 22.16', async () => {
  for(const mode of ['eof','cancel','empty']){
    const f=fixture();fs.writeFileSync(f.file,mode==='empty'?'':'text');const h=await f.api.promises.open(f.file);
    const stream=h.readableWebStream({autoClose:true});
    if(mode==='cancel')await stream.cancel('stop');else assert.equal((await contents(stream)).toString(),mode==='empty'?'':'text');
    assert.equal(h.fd,-1);await h.close();closed(f);
  }
});

test('manual close terminates an unread or locked byte stream without another read', async () => {
  for(const byob of [false,true]){
    const f=fixture();fs.writeFileSync(f.file,'text');const h=await f.api.promises.open(f.file);
    const stream=h.readableWebStream(),r=stream.getReader(byob?{mode:'byob'}:undefined);
    await h.close();const result=await (byob?r.read(new Uint8Array(8)):r.read());
    assert(result.done);await r.closed;r.releaseLock();assert.equal(f.calls.filter(c=>c.op==='read_fd').length,0);closed(f);
  }
});

test('cancel between descriptor read and completion never responds into a retired BYOB request', async () => {
  const f=fixture();fs.writeFileSync(f.file,'abcd');const h=await f.api.promises.open(f.file);
  const r=h.readableWebStream({autoClose:true}).getReader({mode:'byob'});
  const pending=r.read(new Uint8Array(4));await Promise.resolve();const cancelled=r.cancel('stop');
  assert((await pending).done);await cancelled;r.releaseLock();closed(f);
});

test('manual close during Promise delivery discards pending bytes and still closes exactly once', async () => {
  const f=fixture();fs.writeFileSync(f.file,'abcd');const h=await f.api.promises.open(f.file);
  const r=h.readableWebStream().getReader({mode:'byob'});const pending=r.read(new Uint8Array(4));
  await Promise.resolve();const closing=h.close();assert((await pending).done);await closing;await r.closed;r.releaseLock();closed(f);
});

for(const reason of [undefined,null,false,0,new Error('read refused')])test('provider failure survives exactly: '+String(reason),async()=>{
  const f=fixture(c=>c.op==='read_fd'?{throw:true,value:reason}:undefined);fs.writeFileSync(f.file,'data');
  const h=await f.api.promises.open(f.file),r=h.readableWebStream({autoClose:true}).getReader();
  await assert.rejects(r.read(),e=>e===reason);await assert.rejects(r.closed,e=>e===reason);r.releaseLock();closed(f);
});

test('read and close failures both survive; close is not retried on a recycled descriptor',async()=>{
  const first=new Error('read'),second=new Error('close');
  const f=fixture(c=>c.op==='read_fd'?{throw:true,value:first}:c.op==='close_fd'?{throw:true,value:second}:undefined);
  fs.writeFileSync(f.file,'x');const h=await f.api.promises.open(f.file);const fd=h.fd;
  const r=h.readableWebStream({autoClose:true}).getReader();
  await assert.rejects(r.read(),e=>e instanceof AggregateError&&e.errors[0]===first&&e.errors[1]===second);
  await assert.rejects(r.closed);r.releaseLock();await assert.rejects(h.close(),e=>e===second);
  assert.equal(f.calls.filter(c=>c.op==='close_fd').length,1);assert.equal(h.fd,-1);fs.closeSync(fd);
});

test('EOF close failure errors the stream instead of publishing successful completion',async()=>{
  const reason=new Error('close refused');const f=fixture(c=>c.op==='close_fd'?{throw:true,value:reason}:undefined);
  fs.writeFileSync(f.file,'');const h=await f.api.promises.open(f.file),fd=h.fd,r=h.readableWebStream({autoClose:true}).getReader({mode:'byob'});
  await assert.rejects(r.read(new Uint8Array(8)),e=>e===reason);await assert.rejects(r.closed,e=>e===reason);r.releaseLock();fs.closeSync(fd);
});

for(const count of [-1,NaN,20000])test('invalid read count errors before publication: '+count,async()=>{
  const f=fixture(c=>c.op==='read_fd'?{return:true,value:count}:undefined);fs.writeFileSync(f.file,'x');
  const h=await f.api.promises.open(f.file),r=h.readableWebStream({autoClose:true}).getReader();
  await assert.rejects(r.read(),{code:'EIO'});await assert.rejects(r.closed,{code:'EIO'});r.releaseLock();closed(f);
});

test('public descriptor methods and properties cannot redirect admitted file reads',async()=>{
  const f=fixture();fs.writeFileSync(f.file,'original');const h=await f.api.promises.open(f.file),close=h.close;
  h.read=()=>{throw new Error('public read')};h.close=()=>{throw new Error('public close')};
  Object.defineProperty(h,'fd',{value:123});
  assert.equal((await contents(h.readableWebStream({autoClose:true}))).toString(),'original');await close();closed(f);
});

test('capture branded controller methods once instead of consulting replacements on every pull',async()=>{
  const f=fixture(c=>c.op==='read_fd'?{limit:1}:undefined);fs.writeFileSync(f.file,'abc');
  const h=await f.api.promises.open(f.file),s=h.readableWebStream({autoClose:true});
  const bp=web.ReadableByteStreamController.prototype,rp=web.ReadableStreamBYOBRequest.prototype;
  const orig={close:bp.close,error:bp.error,respond:rp.respond};
  try{
    bp.close=bp.error=rp.respond=()=>{throw new Error('public method')};
    assert.equal((await contents(s)).toString(),'abc');closed(f);
  }finally{bp.close=orig.close;bp.error=orig.error;rp.respond=orig.respond;}
});

test('reentrant option getters cannot create two streams or read after close',async()=>{
  for(const action of ['stream','close']){
    const f=fixture();fs.writeFileSync(f.file,'x');const h=await f.api.promises.open(f.file);let nested;
    assert.throws(()=>h.readableWebStream({get autoClose(){nested=action==='stream'?h.readableWebStream():h.close();return false;}}),{code:'ERR_INVALID_STATE'});
    if(action==='stream')await nested.cancel();else await nested;await h.close();closed(f);
  }
});

test('invalid settings and closed handles refuse without descriptor reads',async()=>{
  const f=fixture();fs.writeFileSync(f.file,'x');const h=await f.api.promises.open(f.file);
  for(const options of [null,1,true,[],{autoClose:'yes'}])assert.throws(()=>h.readableWebStream(options),{code:'ERR_INVALID_ARG_TYPE'});
  const s=h.readableWebStream();await s.cancel();assert.throws(()=>h.readableWebStream(),{code:'ERR_INVALID_STATE'});
  await h.close();assert.throws(()=>h.readableWebStream(),{code:'ERR_INVALID_STATE'});assert.equal(f.calls.filter(c=>c.op==='read_fd').length,0);closed(f);
});

test('file bytes feed decoding, transformation and asynchronous sink completion',async()=>{
  const f=fixture(c=>c.op==='read_fd'?{limit:1}:undefined);fs.writeFileSync(f.file,'hé😀\n');
  const h=await f.api.promises.open(f.file);let out='',finished=false;
  await h.readableWebStream({autoClose:true}).pipeThrough(new web.TextDecoderStream())
    .pipeThrough(new web.TransformStream({transform(s,c){c.enqueue(s.toUpperCase());}}))
    .pipeTo(new web.WritableStream({async write(s){await tick();out+=s;},async close(){await tick();finished=true;}}));
  assert.equal(out,'HÉ😀\n');assert.equal(finished,true);closed(f);
});

test('downstream pipeline error closes an auto-owned file and preserves the sink failure',async()=>{
  const f=fixture(c=>c.op==='read_fd'?{limit:1}:undefined);fs.writeFileSync(f.file,'abcdef');
  const h=await f.api.promises.open(f.file),reason=new Error('sink failed');
  await assert.rejects(h.readableWebStream({autoClose:true}).pipeTo(new web.WritableStream({write(){throw reason;}})),e=>e===reason);closed(f);
});

test('reader release during a pending read lets a new reader recover the same bytes',async()=>{
  for(const pause of [false,true]){
    const f=fixture();fs.writeFileSync(f.file,'abcdef');const h=await f.api.promises.open(f.file);
    const stream=h.readableWebStream({autoClose:true}),r=stream.getReader({mode:'byob'});
    const pending=r.read(new Uint8Array(3));pending.catch(()=>{});r.closed.catch(()=>{});
    if(pause)await Promise.resolve();r.releaseLock();await assert.rejects(pending,TypeError);
    assert.equal((await contents(stream)).toString(),'abcdef');closed(f);
  }
});
