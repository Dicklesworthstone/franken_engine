'use strict';
// Production core/bridge and the existing generic converter, on Node primitives.
// This is NOT native lowering, Rust execution, or resource-accounting evidence.
const assert = require('node:assert/strict');
const {test} = require('node:test');
const reference = require('node:stream');
const referenceWeb = require('node:stream/web');
const {load} = require('./stream_pipeline_values.cjs');
const tick = () => new Promise(resolve => setImmediate(resolve));
async function bounded(operation) {
  let timer;
  try { return await Promise.race([operation, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('pair did not settle')), 2000);
  })]); } finally { clearTimeout(timer); }
}
async function collect(source) { const out=[]; for await (const value of source) out.push(value); return out; }
function finish(io, stream) { return io.promises.finished(stream); }
function sink(io, out, extra={}) {
  return new io.Writable({...extra, write(value, enc, done) {out.push(value); done();}});
}
function bytes(web, chunks) { return new web.ReadableStream({start(c){for(const chunk of chunks)c.enqueue(Buffer.from(chunk));c.close();}}); }
function compare(name, action) {
  test(name, {timeout:5000}, async()=>{
    await bounded(action(reference, referenceWeb, 'node'));
    const c=load(); await bounded(action(c.stream, c.web, 'candidate'));
  });
}
function candidate(name, action) {
  test('candidate: '+name, {timeout:3000}, async()=>{const c=load();await bounded(action(c.stream,c.web,c));});
}

compare('Node readable and Web writable retain independent data and modes', async(io,web)=>{
  const written=[];let closed=0;
  const pair=io.Duplex.from({readable:io.Readable.from(['source']),writable:new web.WritableStream({
    write(value){written.push(Buffer.from(value).toString());},close(){closed++;}
  })});
  const completed=finish(io,pair);pair.end('sink');
  assert.equal(pair.readableObjectMode,true);assert.equal(pair.writableObjectMode,false);
  assert.deepEqual(await collect(pair),['source']);await completed;
  assert.deepEqual(written,['sink']);assert.equal(closed,1);
});
compare('Web readable and Node writable preserve exact byte windows', async(io,web)=>{
  const storage=Buffer.from('xCAFÉy'), view=storage.subarray(1,storage.length-1),out=[];
  const input=new web.ReadableStream({start(c){c.enqueue(view);c.close();}});
  const pair=io.Duplex.from({readable:input,writable:sink(io,out)});
  const completed=finish(io,pair);pair.end('written');
  assert.equal(Buffer.concat(await collect(pair)).toString(),'CAFÉ');await completed;
  assert.equal(Buffer.concat(out).toString(),'written');
});
compare('plain Web pairs are converted without requiring TransformStream branding', async(io,web)=>{
  const written=[];const pair=io.Duplex.from({readable:bytes(web,['a','é']),writable:new web.WritableStream({write(v){written.push(Buffer.from(v));}})});
  const completed=finish(io,pair);pair.end(Buffer.from('z'));
  assert.equal(Buffer.concat(await collect(pair)).toString(),'aé');await completed;
  assert.equal(Buffer.concat(written).toString(),'z');
});
compare('read-only Web endpoint disables the writable half', async(io,web)=>{
  const pair=io.Duplex.from({readable:bytes(web,['read-only'])});
  assert.equal(pair.writable,false);assert.equal(Buffer.concat(await collect(pair)).toString(),'read-only');
  await finish(io,pair);
});
compare('write-only Web endpoint awaits asynchronous close', async(io,web)=>{
  let closed=false;const out=[];
  const pair=io.Duplex.from({writable:new web.WritableStream({write(v){out.push(Buffer.from(v));},async close(){await tick();closed=true;}})});
  assert.equal(pair.readable,false);const completed=finish(io,pair);pair.end('write-only');await completed;
  assert.equal(closed,true);assert.equal(Buffer.concat(out).toString(),'write-only');
});
compare('nested Blob source retains one ArrayBuffer record including empty blobs', async(io,web)=>{
  for(const text of ['blob café','']){
    const blob=new Blob([text]);let reads=0;const read=blob.arrayBuffer;
    blob.arrayBuffer=function(){reads++;assert.equal(this,blob);return read.call(this);};
    const out=[];const pair=io.Duplex.from({readable:{readable:blob},writable:new web.WritableStream({write(v){out.push(v);}})});
    const completed=finish(io,pair);pair.end();const chunks=await collect(pair);await completed;
    assert.equal(chunks.length,1);assert(chunks[0] instanceof ArrayBuffer);assert.equal(Buffer.from(chunks[0]).toString(),text);assert.equal(reads,1);
  }
});
compare('nested promised object source retains identity', async(io,web)=>{
  const object={record:'identity'},out=[];
  const pair=io.Duplex.from({readable:{readable:Promise.resolve(object)},writable:new web.WritableStream({write(v){out.push(v);}})});
  const completed=finish(io,pair);pair.end();const got=await collect(pair);await completed;
  assert.equal(got.length,1);assert.equal(got[0],object);assert.deepEqual(out,[]);
});
compare('ordinary Node pair remains independent rather than becoming a pipeline', async(io)=>{
  const input=[{id:1},{id:2}],output=[];
  const pair=io.Duplex.from({readable:io.Readable.from(input),writable:sink(io,output,{objectMode:true})});
  const value={id:'sent'},completed=finish(io,pair);pair.end(value);
  assert.deepEqual(await collect(pair),input);await completed;assert.deepEqual(output,[value]);assert.equal(output[0],value);
});
test('recorded reference difference: Node reads pair properties twice; candidate captures once',async()=>{
  for(const role of ['node','candidate']){
    const lane=role==='node'?{stream:reference,web:referenceWeb}:load(),io=lane.stream,web=lane.web;
    const log=[];const r=bytes(web,['value']),w=new web.WritableStream();
    const input={get readable(){log.push('readable');return r;},get writable(){log.push('writable');return w;}};
    const pair=io.Duplex.from(input);const completed=finish(io,pair);pair.end();await collect(pair);await completed;
    assert.deepEqual(log,role==='node'?['readable','writable','readable','writable']:['readable','writable']);
  }
});
compare('iterable protocol retains precedence over pair properties', async(io)=>{
  let accessed=0;const body={get readable(){accessed++;throw new Error('unexpected pair access');},get writable(){accessed++;throw new Error('unexpected pair access');},
    *[Symbol.iterator](){yield 'iterator';}};
  const pair=io.Duplex.from(body);assert.deepEqual(await collect(pair),['iterator']);assert.equal(accessed,0);
});
test('recorded reference difference: existing candidate thenable precedence remains unchanged',async()=>{
  for(const role of ['node','candidate']){
    const io=role==='node'?reference:load().stream,reason=new Error('pair read');let accessed=0;
    const body={get readable(){accessed++;throw reason;},writable:undefined,then(resolve){resolve('then');}};
    if(role==='node'){assert.throws(()=>io.Duplex.from(body),e=>e===reason);assert.equal(accessed,1);}
    else {assert.deepEqual(await collect(io.Duplex.from(body)),['then']);assert.equal(accessed,0);}
  }
});
compare('setup errors preserve the original thrown value', async(io)=>{
  for(const reason of [new Error('getter failed'),null,false,0]){
    const input={get readable(){throw reason;},writable:undefined};
    let caught=false;try{io.Duplex.from(input);}catch(error){caught=true;assert.equal(error,reason);}assert(caught);
  }
});
compare('mixed pair runs inside a pipeline and waits for both independent halves', async(io,web)=>{
  let calls=0,active=0,maximum=0,closed=false;
  const input=Array.from({length:1024},(_,i)=>Buffer.from(i+'\n'));
  const read=bytes(web,input),written=[];
  const pair=io.Duplex.from({readable:read,writable:new web.WritableStream({async write(v){active++;maximum=Math.max(maximum,active);await tick();written.push(Buffer.from(v).toString());active--;},close(){closed=true;}})});
  const result=[];await io.promises.pipeline(io.Readable.from(['x','y']),pair,new io.Writable({
    highWaterMark:1,write(v,e,cb){calls++;result.push(Buffer.from(v));setImmediate(cb);}
  }));
  assert.equal(Buffer.concat(result).toString(),Buffer.concat(input).toString());assert(calls>0);assert.equal(maximum,1);assert.equal(closed,true);assert.deepEqual(written,['x','y']);
});
compare('rejected Web write fails the pipeline instead of publishing completion', async(io,web)=>{
  const reason=new Error('sink failed');let finals=0;
  const pair=io.Duplex.from({readable:new web.ReadableStream(),writable:new web.WritableStream({write(){throw reason;},close(){finals++;}})});
  const task=io.promises.pipeline(io.Readable.from(['x']),pair,sink(io,[]));
  await assert.rejects(task,error=>error===reason);assert.equal(finals,0);assert.equal(pair.destroyed,true);
});
compare('explicit all-Web transform keeps its existing semantics', async(io,web)=>{
  const transform=new web.TransformStream({transform(value,c){c.enqueue(Buffer.from(value.toString().toUpperCase()));}});
  const pair=io.Duplex.from(transform),completed=finish(io,pair);pair.end('café');
  assert.equal(Buffer.concat(await collect(pair)).toString(),'CAFÉ');await completed;
});
candidate('partial setup failure cancels only the adapter it acquired', async(io,web)=>{
  let cancelled=0,aborted=0;
  const readable=new web.ReadableStream({async cancel(){await tick();cancelled++;}});
  const writable=new web.WritableStream({abort(){aborted++;}}),held=writable.getWriter();
  assert.throws(()=>io.Duplex.from({readable,writable}),TypeError);
  for(let i=0;i<8;i++)await tick();
  assert.equal(cancelled,1);assert.equal(aborted,0);assert.equal(writable.locked,true);
  held.releaseLock();
});
candidate('invalid writable does not destroy an unadopted caller-owned Node reader',async(io)=>{
  let destroyed=0;const readable=new io.Readable({read(){},destroy(error,done){destroyed++;done(error);}});
  assert.throws(()=>io.Duplex.from({readable,writable:{}}),e=>e.code==='ERR_INVALID_ARG_TYPE');
  assert.equal(readable.destroyed,false);assert.equal(destroyed,0);readable.destroy();await tick();assert.equal(destroyed,1);
});
candidate('nested pair cycles have a bounded typed failure',async(io)=>{
  const cycle={};cycle.readable=cycle;
  assert.throws(()=>io.Duplex.from(cycle),e=>e.code==='ERR_INVALID_ARG_VALUE');
});
candidate('both Web cancellation algorithms start before either one is awaited',async(io,web)=>{
  let releaseRead,releaseWrite,starts=0,finishes=0;
  const rDone=new Promise(r=>releaseRead=r),wDone=new Promise(r=>releaseWrite=r);
  const readable=new web.ReadableStream({async cancel(){starts++;releaseWrite();await rDone;finishes++;}});
  const writable=new web.WritableStream({async abort(){starts++;releaseRead();await wDone;finishes++;}});
  const pair=io.Duplex.from({readable,writable});const reason=new Error('stop');
  const completed=finish(io,pair).then(()=>null,e=>e);pair.destroy(reason);
  assert.equal(await completed,reason);assert.equal(starts,2);assert.equal(finishes,2);
});
candidate('Web pair cancellation suppresses late read fulfillment',async(io,web)=>{
  let deliver,started;const running=new Promise(r=>started=r);let cancelled=0,aborted=0;
  const readable=new web.ReadableStream({pull(c){started();return new Promise(resolve=>deliver=()=>{try{c.enqueue(Buffer.from('late'));}catch(e){}resolve();});},cancel(){cancelled++;}});
  const writable=new web.WritableStream({abort(){aborted++;}});
  const pair=io.Duplex.from({readable,writable}),data=[];pair.on('data',c=>data.push(c));const completed=finish(io,pair).catch(e=>e);
  await running;const reason=new Error('cancelled');pair.destroy(reason);assert.equal(await completed,reason);deliver();await tick();
  assert.deepEqual(data,[]);assert.equal(cancelled,1);assert.equal(aborted,1);
});
candidate('single-ended Node and promised pairs leave the Web dependency uninitialized',async(io,web,lane)=>{
  for(const readable of [io.Readable.from(['x']),Promise.resolve('y')]){
    assert.equal((await collect(io.Duplex.from({readable}))).length,1);
  }
  const out=[],pair=io.Duplex.from({writable:sink(io,out)}),complete=finish(io,pair);pair.end('z');await complete;
  assert.equal(lane.loads(),0);assert.equal(Buffer.concat(out).toString(),'z');
});
compare('successful paired completion does not run cancellation callbacks',async(io,web)=>{
  let cancelled=0,aborted=0;
  const readable=new web.ReadableStream({start(c){c.enqueue(Buffer.from('done'));c.close();},cancel(){cancelled++;}});
  const writable=new web.WritableStream({abort(){aborted++;}}),pair=io.Duplex.from({readable,writable});
  const completed=finish(io,pair);pair.end();await collect(pair);await completed;
  assert.equal(cancelled,0);assert.equal(aborted,0);
});
candidate('nested source rejection remains observed after later setup fails',async(io,web)=>{
  let reject;const pending=new Promise((resolve,no)=>reject=no);
  assert.throws(()=>io.Duplex.from({readable:{readable:pending},writable:{}}),e=>e.code==='ERR_INVALID_ARG_TYPE');
  reject(new Error('late producer rejection'));await tick();await tick();
});
candidate('pair-depth bound admits 32 transitions and rejects the next',async(io)=>{
  let value='x';for(let n=0;n<32;n++)value={readable:value};
  assert.deepEqual(await collect(io.Duplex.from(value)),['x']);
  assert.throws(()=>io.Duplex.from({readable:value}),e=>e.code==='ERR_INVALID_ARG_VALUE');
});
compare('large lazy Web sources remain backpressured before paired output is consumed',async(io,web)=>{
  let produced=0;const chunks=64,size=65536;
  const readable=new web.ReadableStream({pull(controller){
    if(produced===chunks){controller.close();return;}
    const bytes=new Uint8Array(size);bytes[0]=produced++;controller.enqueue(bytes);
  }});
  const pair=io.Duplex.from({readable,writable:sink(io,[])}),completed=finish(io,pair);pair.end();
  // Observe teardown even if an assertion interrupts iteration; awaiting the
  // original promise below still enforces successful finalization.
  completed.catch(()=>{});
  for(let i=0;i<8;i++)await tick();assert(produced<chunks/2,'consumer demand must bound upstream reads');
  // Byte-mode readers may coalesce source chunks. Assert the entire payload,
  // not a source chunk boundary that neither runtime promises to preserve.
  const expected=Buffer.alloc(size*chunks);for(let i=0;i<chunks;i++)expected[i*size]=i;
  let total=0;
  for await(const chunk of pair){assert(chunk.equals(expected.subarray(total,total+chunk.length)));total+=chunk.length;}
  await completed;assert.equal(produced,chunks);assert.equal(total,size*chunks);
});
