'use strict';
// Exact production composition on Node primitives; NOT native Rust execution.
const assert = require('node:assert/strict');
const {test} = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const reference = require('node:stream/web');
const moduleRoot = path.join(__dirname, '../../crates/franken-engine/src/lowering_pipeline');
const base = fs.readFileSync(process.env.WEB_STREAM_SOURCE || path.join(moduleRoot, 'web_stream_module.js'), 'utf8');
const text = fs.readFileSync(path.join(moduleRoot, 'web_text_stream_module.js'), 'utf8');
function candidate(globals) {
  const source = '(' + text + ')(' + base + ')';
  return globals ? vm.runInNewContext(source, globals) : vm.runInThisContext(source);
}
async function collect(readable) { const output=[]; for await(const chunk of readable) output.push(chunk); return output; }
async function transform(api, kind, chunks, ...args) {
  const stream = new api[kind](...args);
  const writer = stream.writable.getWriter();
  const feeding = (async () => { try { for (const chunk of chunks) await writer.write(chunk); await writer.close(); } finally {writer.releaseLock();} })();
  const consuming = collect(stream.readable);
  const result = await Promise.allSettled([feeding, consuming]);
  if (result[0].status === 'rejected' || result[1].status === 'rejected') {
    assert.equal(result[0].status, 'rejected'); assert.equal(result[1].status, 'rejected');
    assert.equal(result[0].reason, result[1].reason, 'both sides retain original error');
    return {error:result[0].reason, failed:true};
  }
  return {chunks: result[1].value, failed:false};
}
function normalized(result) {
  return result.failed ? {failed:true,name:result.error?.name} : {failed:false,chunks:result.chunks.map(c=>typeof c==='string'?c:Array.from(c))};
}
async function compare(kind, chunks, ...args) {
  const expected=await transform(reference,kind,chunks,...args);
  const actual=await transform(candidate(),kind,chunks,...args);
  assert.deepEqual(normalized(actual),normalized(expected));
  return actual;
}
function gate() {let resolve;const promise=new Promise(done=>{resolve=done;});return {promise,resolve};}
async function ticks(n=24) {while(n--)await Promise.resolve();}

for(const chunks of [[],[''],['a','b'],['\ud83d','\ude00'],['\ud83d','','\ude00'],['\ud800'],['\ud800','\ud801'],['\ud800','x'],['\udc00'],['a\ud83d','\ude00b\ud800'],['\ufeffé','\u0000','日']]) {
  test('encoder chunks and flush: '+JSON.stringify(chunks),{timeout:5000},async()=>{
    const actual=await compare('TextEncoderStream',chunks);
    assert(!actual.failed);assert.deepEqual(Array.from(Buffer.concat(actual.chunks)),Array.from(new TextEncoder().encode(chunks.join(''))));
  });
}
test('encoder ToString uses the string hint once, including non-string chunks',async()=>{
  for(const api of [reference,candidate()]) {
    const hints=[];
    const values=[undefined,null,42,false,1n,{[Symbol.toPrimitive](hint){hints.push(hint);return 'value';}}];
    const result=await transform(api,'TextEncoderStream',values);
    assert(!result.failed);assert.equal(Buffer.concat(result.chunks).toString(),'undefinednull42false1value');assert.deepEqual(hints,['string']);
  }
});
test('throwing encoder conversions fail both endpoints with original identity',async()=>{
  for(const api of [reference,candidate()]) {
    for(const error of [undefined,null,false,0,'',{}]) {
      const result=await transform(api,'TextEncoderStream',[{toString(){throw error;}}]);
      assert(result.failed);assert.equal(result.error,error);
    }
  }
});
test('encoder handles deterministic mixed UTF-16 strings at every boundary', {timeout:10000},async()=>{
  let seed=12345;let cases=0;
  const units=[0,65,233,0x7ff,0x800,0xd800,0xdbff,0xdc00,0xdfff,0xfffd];
  for(let n=0;n<32;n++){
    let value='';for(let j=0;j<8;j++){seed=(Math.imul(seed,1664525)+1013904223)>>>0;value+=String.fromCharCode(units[seed%units.length]);}
    for(let i=0;i<=value.length;i++){
      const actual=await compare('TextEncoderStream',[value.slice(0,i),'',value.slice(i)]);
      assert(!actual.failed);assert.deepEqual(Array.from(Buffer.concat(actual.chunks)),Array.from(new TextEncoder().encode(value)));cases++;
    }
  }
  assert.equal(cases,288);
});
for(const label of ['utf-8','utf-16le','utf-16be']) for(const ignoreBOM of [false,true]) {
  test('decoder every byte split with BOM: '+label+' '+ignoreBOM,{timeout:5000},async()=>{
    const value='\ufeffAé😀日\u0000\ufeffZ';
    const bytes=label==='utf-8'?Buffer.from(value):Buffer.from(value,'utf16le');
    if(label==='utf-16be')bytes.swap16();
    for(let i=0;i<=bytes.length;i++){
      const actual=await compare('TextDecoderStream',[bytes.subarray(0,i),new Uint8Array(),bytes.subarray(i)],label,{ignoreBOM});
      assert(!actual.failed);assert.equal(actual.chunks.join(''),ignoreBOM?value:value.slice(1));
    }
  });
}
for(const fatal of [false,true]) for(const chunks of [[[0xe2]],[[0xe2],[0x28],[0xa1]],[[0xf0,0x9f]],[[0xff]],[[0x41,0xe2],[0x82,0xac],[0xff]]]) {
  test('UTF-8 invalid/EOF decoding '+fatal+' '+JSON.stringify(chunks),async()=>{
    const actual=await compare('TextDecoderStream',chunks.map(x=>new Uint8Array(x)),'utf8',{fatal});
    assert.equal(actual.failed,fatal);
  });
}
test('UTF-16 partial code unit and surrogate flush retain native fatal semantics',async()=>{
  for(const label of ['utf-16le','utf-16be'])for(const fatal of [false,true])for(const bytes of [[0x41],[0x00,0xd8],[0xd8,0x00]]){
    await compare('TextDecoderStream',[new Uint8Array(bytes)],label,{fatal});
  }
});
test('decoder views use exact offsets without mutating or retaining consumed input bytes',async()=>{
  for(const api of [reference,candidate()]){
    const stream=new api.TextDecoderStream();const writer=stream.writable.getWriter();const out=collect(stream.readable);
    const bytes=new Uint8Array([9,0xe2,0x82,8]);await writer.write(new DataView(bytes.buffer,1,2));bytes.fill(0);
    await writer.write(new Uint8Array([0xac,65]).buffer);await writer.close();writer.releaseLock();
    assert.deepEqual(await out,['€A']);
  }
});
test('decoder rejects invalid chunks instead of treating undefined as a flush',async()=>{
  for(const chunk of [undefined,null,false,0,'bytes',{},[],{buffer:new ArrayBuffer(2)}]){
    const actual=await compare('TextDecoderStream',[new Uint8Array([0xe2]),chunk]);assert(actual.failed);assert(actual.error instanceof TypeError);
  }
});
test('native supported legacy labels compose without a second codec implementation',async()=>{
  for(const [label,bytes] of [['shift_jis',[0x82,0xa0]],['euc-jp',[0xa4,0xa2]],['koi8-r',[0xe1,0xe2]],['windows-1251',[0xc0,0xc1]]]){
    for(let i=0;i<=bytes.length;i++)await compare('TextDecoderStream',[new Uint8Array(bytes.slice(0,i)),new Uint8Array(bytes.slice(i))],label);
  }
});
test('metadata and endpoint getters are stable and enforce distinct brands',async()=>{
  for(const api of [reference,candidate()]){
    const e=new api.TextEncoderStream(),d=new api.TextDecoderStream('UTF8',{fatal:1,ignoreBOM:true});
    assert.equal(e.encoding,'utf-8');assert.equal(d.encoding,'utf-8');assert.equal(d.fatal,true);assert.equal(d.ignoreBOM,true);
    assert.equal(e.readable,e.readable);assert.equal(e.writable,e.writable);
    assert(e.readable instanceof api.ReadableStream);assert(e.writable instanceof api.WritableStream);
    for(const [type,names] of [['TextEncoderStream',['encoding','readable','writable']],['TextDecoderStream',['encoding','fatal','ignoreBOM','readable','writable']]]){
      for(const name of names){const getter=Object.getOwnPropertyDescriptor(api[type].prototype,name).get;assert.throws(()=>getter.call({}),TypeError);assert.throws(()=>getter.call(type==='TextEncoderStream'?d:e),TypeError);}
    }
  }
});
test('constructors reject unsupported labels and invalid options',async()=>{
  for(const api of [reference,candidate()]){
    for(const label of [Symbol('utf8'),'not-an-encoding','replacement'])assert.throws(()=>new api.TextDecoderStream(label));
    for(const options of [1,false,'invalid'])assert.throws(()=>new api.TextDecoderStream('utf8',options),TypeError);
  }
});
test('record Node 22 Symbol, tagging and duplicate-option-read differences, not parity',async()=>{
  // The Encoding Standard requires DOMString conversion, interface tags and
  // one Web IDL dictionary conversion. Node 22.16 differs in these cases.
  const actual=await transform(candidate(),'TextEncoderStream',[Symbol('x')]);
  assert(actual.failed);assert(actual.error instanceof TypeError);
  const node=await transform(reference,'TextEncoderStream',[Symbol('x')]);
  assert(!node.failed);assert.equal(Buffer.concat(node.chunks).toString(),'Symbol(x)');
  assert.equal(Object.prototype.toString.call(new reference.TextEncoderStream()),'[object Object]');
  assert.equal(Object.prototype.toString.call(new (candidate().TextEncoderStream)()),'[object TextEncoderStream]');
  function options(api){const seen=[];const d=new api.TextDecoderStream(
    {toString(){seen.push('label');return 'UTF8';}},
    {get fatal(){seen.push('fatal');return true;},get ignoreBOM(){seen.push('ignoreBOM');return false;}});
    assert.equal(d.encoding,'utf-8');assert(d.fatal);return seen;
  }
  assert.deepEqual(options(reference),['label','fatal','ignoreBOM','ignoreBOM','fatal']);
  assert.deepEqual(options(candidate()),['label','fatal','ignoreBOM']);
});
test('backpressure prevents string conversion before downstream demand',async()=>{
  for(const api of [reference,candidate()]){
    let conversions=0;const e=new api.TextEncoderStream();const w=e.writable.getWriter();let settled=false;
    const written=w.write({toString(){conversions++;return '42';}}).then(()=>{settled=true;});
    await ticks();assert.equal(conversions,0);assert.equal(settled,false);assert.equal(w.desiredSize,0);
    const r=e.readable.getReader();assert.deepEqual(Array.from((await r.read()).value),[52,50]);await written;
    const closing=w.close();assert.equal((await r.read()).done,true);await closing;
    r.releaseLock();w.releaseLock();assert.equal(conversions,1);
  }
});
test('readable cancellation rejects a blocked write without running its conversion',async()=>{
  for(const api of [reference,candidate()]){
    for(const name of ['TextEncoderStream','TextDecoderStream']){
      let converted=0;const s=new api[name]();const w=s.writable.getWriter();const reason={cancel:true};
      const write=w.write({toString(){converted++;return 'no';}}).catch(e=>e);
      await ticks();await s.readable.cancel(reason);assert.equal(await write,reason);assert.equal(converted,0);
      w.releaseLock();
    }
  }
});
test('writable abort rejects pending readers with the original reason and no flush',async()=>{
  for(const api of [reference,candidate()])for(const name of ['TextEncoderStream','TextDecoderStream']){
    const s=new api[name]();const r=s.readable.getReader(),w=s.writable.getWriter();const reason={abort:true};
    const read=r.read().catch(e=>e);await w.abort(reason);assert.equal(await read,reason);r.releaseLock();w.releaseLock();
  }
});
test('shared encoder decoder tee and sinks finish a full pipeline',async()=>{
  for(const api of [reference,candidate()]){
    const original=api.ReadableStream.from(['a','\ud83d','','\ude00','é','\ud800']);
    const encoded=original.pipeThrough(new api.TextEncoderStream());const [a,b]=encoded.tee();
    const bytes=[],texts=[];
    await Promise.all([
      a.pipeTo(new api.WritableStream({async write(c){await Promise.resolve();bytes.push(...c);}})),
      b.pipeThrough(new api.TextDecoderStream()).pipeTo(new api.WritableStream({write(c){texts.push(c);}}))
    ]);
    assert.equal(texts.join(''),'a😀é�');assert.deepEqual(bytes,Array.from(Buffer.from('a😀é�')));
  }
});
test('many chunks keep independent streams and correct state without precollecting input', {timeout:10000},async()=>{
  for(const api of [reference,candidate()]){
    let generated=0,total=0,chunks=0;
    const source=api.ReadableStream.from((function*(){for(let i=0;i<4096;i++){generated++;yield i%2===0?'\ud83d':'\ude00';}})());
    await source.pipeThrough(new api.TextEncoderStream()).pipeThrough(new api.TextDecoderStream())
      .pipeTo(new api.WritableStream({write(value){total+=value.length;chunks++;}}));
    assert.equal(generated,4096);assert.equal(total,4096);assert.equal(chunks,2048);
  }
});
test('captured codec and controller methods survive public replacement',async()=>{
  const api=candidate();const oldEncode=TextEncoder.prototype.encode,oldDecode=TextDecoder.prototype.decode;
  const oldEnqueue=api.TransformStreamDefaultController.prototype.enqueue;
  let results;
  try{
    TextEncoder.prototype.encode=TextDecoder.prototype.decode=api.TransformStreamDefaultController.prototype.enqueue=()=>{throw Error('replaced');};
    const e=await transform(api,'TextEncoderStream',['\ud83d','\ude00']);
    const d=await transform(api,'TextDecoderStream',[new Uint8Array([0xf0,0x9f]),new Uint8Array([0x98,0x80])]);results=[e,d];
  }finally{TextEncoder.prototype.encode=oldEncode;TextDecoder.prototype.decode=oldDecode;api.TransformStreamDefaultController.prototype.enqueue=oldEnqueue;}
  assert.deepEqual(Array.from(results[0].chunks[0]),[240,159,152,128]);assert.deepEqual(results[1].chunks,['😀']);
});
test('composed module enumerates codec exports and private metadata ignores inherited setters',async()=>{
  const api=candidate();
  assert(Object.keys(api).includes('TextEncoderStream'));assert(Object.keys(api).includes('TextDecoderStream'));
  const names=['encoding','readable','writable'];const saved=names.map(name=>Object.getOwnPropertyDescriptor(Object.prototype,name));
  let decoder,encoder;
  try{
    for(const name of names)Object.defineProperty(Object.prototype,name,{configurable:true,set(){throw Error('inherited private setter');}});
    encoder=new api.TextEncoderStream();decoder=new api.TextDecoderStream('utf8');
  }finally{
    for(let i=0;i<names.length;i++)if(saved[i])Object.defineProperty(Object.prototype,names[i],saved[i]);else delete Object.prototype[names[i]];
  }
  assert.equal(decoder.encoding,'utf-8');assert(encoder.readable instanceof api.ReadableStream);assert(decoder.writable instanceof api.WritableStream);
});
