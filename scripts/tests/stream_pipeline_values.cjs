'use strict';
// Source-level integration, not a native Rust/CLI test. Execute the production
// core and bridge plus the unchanged generic Duplex converter. The remaining
// collection operators are outside this test boundary. Node supplies the
// language, primitive EventEmitter, StringDecoder, signals and scheduling.
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const events = require('node:events');
const decoder = require('node:string_decoder');
const reference = require('node:stream');
const sources = path.resolve(__dirname, '../../crates/franken-engine/src/lowering_pipeline');
function load() {
  const core = fs.readFileSync(process.env.STREAM_SOURCE || path.join(sources, 'stream_module.js'), 'utf8');
  const stream = new Function('__franken_stream_events', '__franken_stream_string_decoder',
    '__franken_stream_next_tick', 'return ' + core)(events, decoder, cb => process.nextTick(cb));
  const operators = fs.readFileSync(process.env.PIPELINE_OPERATORS_SOURCE || path.join(sources, 'stream_operators.js'), 'utf8');
  const start = operators.indexOf('  function installDuplexFrom() {');
  assert(start >= 0, 'canonical converter is present');
  let end = operators.indexOf('  // The focused Readable-operator host', start);
  if (end < 0) end = operators.length; // Optional pinned source excerpt for host-only reproduction.
  const converter = operators.slice(start, end);
  new Function('Stream', `
    const Readable=Stream.Readable, from=Readable.from, apply=Reflect.apply;
    const PromiseClass=Promise, promiseThen=Promise.prototype.then;
    const defineProperty=Object.defineProperty, createObject=Object.create;
    const asyncIteratorKey=Symbol.asyncIterator, iteratorKey=Symbol.iterator;
    function then(promise, success, failure) { return apply(promiseThen, promise, [success, failure]); }
    function failure(code, message, Range) { const error=Range?new RangeError(message):new TypeError(message);error.code=code;return error; }
    ${converter}
    installDuplexFrom();
  `)(stream);
  let conversions=0;
  const convert=stream.Duplex.from;
  stream.Duplex.from=function(value){conversions++;return Reflect.apply(convert,this,[value]);};
  const bridge = fs.readFileSync(process.env.STREAM_BRIDGE_SOURCE || path.join(sources, 'stream_web_bridge.js'), 'utf8');
  let loads=0;
  const web = process.env.PIPELINE_ENGINE_WEB === '1' ?
    new Function('return '+fs.readFileSync(path.join(sources,'web_stream_module.js'),'utf8'))() : require('node:stream/web');
  new Function('return '+bridge)()(stream, () => {loads++; return web;});
  return {stream, web, loads:()=>loads, conversions:()=>conversions};
}
const tick=()=>new Promise(resolve=>setImmediate(resolve));
const candidate=load();
function sink(io, output, options={}) {return new io.Writable({...options, write(value,enc,done){output.push(value);done();}});}
function check(name, action, referenceEnabled=true) {
  test(name, {timeout:3000}, async()=>{
    if(referenceEnabled) await bounded(action(reference,'node'));
    await bounded(action(candidate.stream,'candidate'));
  });
}
async function bounded(promise) {
  let timer;try {return await Promise.race([promise,new Promise((_,reject)=>{
    timer=setTimeout(()=>reject(new Error('pipeline did not settle')),1500);
  })]);}finally{clearTimeout(timer);}
}
if(require.main===module){
check('promised byte source reaches the existing sink and finalization', async io=>{
  const out=[];let finished=0;
  await io.promises.pipeline(Promise.resolve(Buffer.from('café\n')),sink(io,out,{final(cb){finished++;cb();}}));
  assert.equal(Buffer.concat(out).toString(),'café\n');assert.equal(finished,1);
});
check('promised object remains one record with its original identity', async io=>{
  const item={name:'source',data:[1,2]}, out=[];
  await io.promises.pipeline(Promise.resolve(item),sink(io,out,{objectMode:true}));
  assert.equal(out.length,1);assert.equal(out[0],item);
});
check('null and undefined promise values produce empty EOF', async io=>{
  for(const value of [null,undefined]) {const out=[];await io.promises.pipeline(Promise.resolve(value),sink(io,out,{objectMode:true}));assert.deepEqual(out,[]);}
});
check('Promise rejection retains the original error and never finalizes', async io=>{
  const reason=new Error('fetch failed');let final=false;
  const result=await io.promises.pipeline(Promise.reject(reason),sink(io,[],{final(cb){final=true;cb();}})).then(()=>null,e=>e);
  assert.equal(result,reason);assert.equal(final,false);
});
check('callback pipeline returns the original sink and completes once', async io=>{
  const out=[];let count=0;let returned;const destination=sink(io,out);
  await new Promise((resolve,reject)=>{
    returned=io.pipeline(Promise.resolve('value'),destination,error=>{count++;error?reject(error):resolve();});
    assert.equal(returned,destination);
  });
  await tick();assert.equal(count,1);assert.equal(Buffer.concat(out).toString(),'value');
});
check('array-form pipelines keep promised sources', async io=>{
  const out=[];await io.promises.pipeline([Promise.resolve('array'),sink(io,out)]);assert.equal(Buffer.concat(out).toString(),'array');
});
check('end:false retains the final sink for further writes', async io=>{
  const out=[], destination=sink(io,out);
  await io.promises.pipeline(Promise.resolve('first'),destination,{end:false});
  assert.equal(destination.writableFinished,false);
  destination.end('second');await io.promises.finished(destination);
  assert.equal(Buffer.concat(out).toString(),'firstsecond');
});
check('candidate: cancelling an unresolved Promise does not wait for its producer', async io=>{
  let publish;const pending=new Promise(resolve=>publish=resolve), controller=new AbortController();const out=[];
  const result=io.promises.pipeline(pending,sink(io,out),{signal:controller.signal}).then(()=>null,e=>e);
  controller.abort('stop');const error=await result;assert.equal(error.code,'ABORT_ERR');
  publish('too late');await tick();assert.deepEqual(out,[]);
},false);
check('async source functions must still return an iterable, not a Promise', async io=>{
  await assert.rejects(io.promises.pipeline(()=>Promise.resolve('not iterable'),sink(io,[])),e=>e.code==='ERR_INVALID_RETURN_VALUE');
});
check('plain Node pipelines retain their original objects', async io=>{
  const input=io.Readable.from(['ordinary']),out=[],destination=sink(io,out);let returned;
  await new Promise((resolve,reject)=>{returned=io.pipeline(input,destination,e=>e?reject(e):resolve());});
  assert.equal(returned,destination);assert.equal(Buffer.concat(out).toString(),'ordinary');
});
test('Node-only conversions do not initialize Web Streams', async()=>{
  const lane=load(),out=[];await lane.stream.promises.pipeline(Promise.resolve('x'),sink(lane.stream,out));assert.equal(lane.loads(),0);
});
check('promised sources feed async-generator transforms and sink return values', async io=>{
  const result=await io.promises.pipeline(Promise.resolve({name:'café'}),
    async function* (source) {for await(const item of source) yield item.name.toUpperCase();},
    async function (source) {let value='';for await(const item of source)value+=item;return {value};});
  assert.deepEqual(result,{value:'CAFÉ'});
});
check('promised arrays remain one value rather than becoming source iterables', async io=>{
  const input=['a','b'],out=[];await io.promises.pipeline(Promise.resolve(input),sink(io,out,{objectMode:true}));
  assert.equal(out.length,1);assert.equal(out[0],input);
});
check('one then lookup and the original receiver are preserved', async io=>{
  const source=Promise.resolve(Buffer.from('single'));let gets=0,calls=0;
  Object.defineProperty(source,'then',{get(){gets++;return function(yes,no){calls++;assert.equal(this,source);return Promise.prototype.then.call(this,yes,no);};}});
  const out=[];await io.promises.pipeline(source,sink(io,out));
  assert.equal(gets,1);assert.equal(calls,1);assert.equal(Buffer.concat(out).toString(),'single');
});
check('an iterable with a then property retains iterable precedence', async io=>{
  let assimilated=0;const source=['first','second'];source.then=()=>{assimilated++;};const out=[];
  await io.promises.pipeline(source,sink(io,out));assert.equal(assimilated,0);assert.equal(Buffer.concat(out).toString(),'firstsecond');
});
check('promised byte source connects to Web transform and Node sink', async (io,label)=>{
  const web=label==='node'?require('node:stream/web'):candidate.web;
  const out=[];
  const transform=new web.TransformStream({transform(bytes,controller){
    controller.enqueue(Buffer.from(bytes.toString().toUpperCase()));
  }});
  await io.promises.pipeline(Promise.resolve(Buffer.from('web café')),transform,sink(io,out));
  assert.equal(Buffer.concat(out).toString(),'WEB CAFÉ');
});
check('Web destinations wait for asynchronous close after a promised source', async (io,label)=>{
  const web=label==='node'?require('node:stream/web'):candidate.web;const out=[];let closed=false;
  await io.promises.pipeline(Promise.resolve('record'),new web.WritableStream({
    write(value){out.push(value);},async close(){await tick();closed=true;}
  }));
  assert.deepEqual(out,['record']);assert.equal(closed,true);
});
check('util.promisify callback pipeline keeps the Promise-source result', async io=>{
  const run=require('node:util').promisify(io.pipeline),out=[];
  await run(Promise.resolve(Buffer.from('promisified')),sink(io,out));assert.equal(Buffer.concat(out).toString(),'promisified');
});
test('candidate: setup failure closes an already-adopted source before rejection', async()=>{
  const lane=load(),io=lane.stream;let observed=0;
  const source={then(resolve,reject){observed++;queueMicrotask(()=>reject(new Error('later failure')));}};
  const error=await bounded(io.promises.pipeline(source,{},sink(io,[])).then(()=>null,e=>e));
  assert(error instanceof Error);assert.equal(observed,1);await tick();
});
test('candidate: synchronous thenable rejection is observed instead of hanging', async()=>{
  const reason=new Error('synchronous producer failure'),io=candidate.stream;
  const error=await bounded(io.promises.pipeline({then(yes,no){no(reason);}},sink(io,[])).then(()=>null,e=>e));
  assert.equal(error,reason);
});
test('candidate: late rejection after abort is observed without publishing', async()=>{
  const io=candidate.stream,c=new AbortController(),out=[];let reject;
  const source=new Promise((_,no)=>reject=no);
  const outcome=io.promises.pipeline(source,sink(io,out),{signal:c.signal}).then(()=>null,e=>e);
  c.abort(false);assert.equal((await bounded(outcome)).code,'ABORT_ERR');
  reject(new Error('late producer failure'));await tick();assert.deepEqual(out,[]);
});
test('candidate: pre-aborted promised source cannot reach or finalize its sink', async()=>{
  const io=candidate.stream,out=[];let final=0;
  const error=await bounded(io.promises.pipeline(Promise.resolve('never'),sink(io,out,{final(cb){final++;cb();}}),
    {signal:AbortSignal.abort(null)}).then(()=>null,e=>e));
  assert.equal(error.code,'ABORT_ERR');assert.equal(final,0);assert.deepEqual(out,[]);
});
test('candidate: a sink failure releases the source without awaiting its Promise', async()=>{
  const io=candidate.stream,reason=new Error('sink init failed');let resolve;
  const source=new Promise(yes=>resolve=yes),out=[];
  const destination=sink(io,out,{construct(done){done(reason);}});
  const error=await bounded(io.promises.pipeline(source,destination).then(()=>null,e=>e));
  assert.equal(error,reason);assert.equal(destination.destroyed,true);
  resolve('too late');await tick();assert.deepEqual(out,[]);
});
test('candidate: endpoint acquisition failure drains the adopted Promise wrapper', async()=>{
  const lane=load(),io=lane.stream;let locked,started=0,finished=0;
  const destination=new lane.web.WritableStream();
  const previous=io.Duplex.prototype._destroy;
  io.Duplex.prototype._destroy=function(error,done){started++;setImmediate(()=>{finished++;done(error);});};
  try {
    // Preflight sees an unlocked sink. Assimilation is guest code and can
    // lock it before its adapter is acquired; the source wrapper is already
    // ours at that point, despite the core pipeline not having started.
    const source={then(){locked=destination.getWriter();}};
    const error=await bounded(io.promises.pipeline(source,destination).then(()=>null,e=>e));
    assert(error instanceof Error);assert.equal(started,1);assert.equal(finished,1);
  }finally{io.Duplex.prototype._destroy=previous;if(locked)locked.releaseLock();}
});
test('candidate: conversion happens once per promised source, never per record', async()=>{
  const lane=load(),io=lane.stream,out=[];let active=0,peak=0;
  await io.promises.pipeline(io.Readable.from(['control']),sink(io,[]));
  await io.promises.pipeline(['iterable'],sink(io,[]));
  assert.equal(lane.conversions(),0);
  await io.promises.pipeline(Promise.resolve(2048),async function* (source){
    for await(const n of source)for(let i=0;i<n;i++)yield i;
  },new io.Writable({objectMode:true,highWaterMark:1,write(n,e,done){
    active++;peak=Math.max(peak,active);out.push(n);queueMicrotask(()=>{active--;done();});
  }}));
  assert.equal(lane.conversions(),1);assert.equal(peak,1);
  assert.deepEqual(out,Array.from({length:2048},(_,i)=>i));
});
test('candidate: public Duplex.from replacement cannot redirect the captured converter', async()=>{
  const lane=load(),io=lane.stream,out=[];
  io.Duplex.from=()=>{throw new Error('public converter called');};
  await io.promises.pipeline(Promise.resolve('private'),sink(io,out));
  assert.equal(Buffer.concat(out).toString(),'private');
});
check('rebased Blob sources still deliver one ArrayBuffer through shared ownership', async io=>{
  const out=[];let count=0;
  await io.promises.pipeline(new Blob(['blob café']), new io.Transform({objectMode:true,
    transform(value,encoding,done){count++;assert(value instanceof ArrayBuffer);done(null,Buffer.from(value));}
  }),sink(io,out));
  assert.equal(count,1);assert.equal(Buffer.concat(out).toString(),'blob café');
});
check('Blob-returning source factories retain the existing rejection boundary', async io=>{
  await assert.rejects(io.promises.pipeline(()=>new Blob(['not iterable']),sink(io,[])),
    error=>error.code==='ERR_INVALID_RETURN_VALUE');
});
}
module.exports={load};
