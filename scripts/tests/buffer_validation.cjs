'use strict';
// Complete production buffer-module source on Node primitives. This is not
// native Rust/interpreter, sandbox, GC/accounting, or Bun execution evidence.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const reference = require('node:buffer');
const sourcePath = process.env.BUFFER_VALIDATION_SOURCE || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/buffer_module.js');
const source = fs.readFileSync(sourcePath, 'utf8');
function load(overrides = {}) {
  const names = Object.keys(overrides);
  return new Function(...names, 'return ' + source)(...names.map(name => overrides[name]));
}
const candidate = load();
module.exports = { load, candidate, sourcePath };
function outcome(fn, input) {
  try { return { value: fn(input) }; }
  catch (error) { return { name: error.name, code: error.code }; }
}
function compare(input) {
  for (const name of ['isUtf8', 'isAscii']) {
    assert.deepEqual(outcome(candidate[name], input), outcome(reference[name], input), name);
  }
}
function byteInput(bytes) { return Uint8Array.from(bytes); }
if (require.main === module) {
  test('UTF-8 scalar boundaries, overlong forms, surrogates, truncation and BOM agree with Node', () => {
    const rows = [[], [0], [0x7f], [0xc2,0x80], [0xdf,0xbf], [0xe0,0xa0,0x80],
      [0xed,0x9f,0xbf], [0xee,0x80,0x80], [0xef,0xbf,0xbf], [0xf0,0x90,0x80,0x80],
      [0xf4,0x8f,0xbf,0xbf], [0xef,0xbb,0xbf], [0x80], [0xc0,0x80], [0xc1,0xbf],
      [0xe0,0x9f,0xbf], [0xed,0xa0,0x80], [0xf0,0x8f,0xbf,0xbf], [0xf4,0x90,0x80,0x80],
      [0xf5,0x80,0x80,0x80], [0xff], [0xe2,0x82], [0xf0,0x9f,0x98], [0xc2,0x7f],
      [0xe2,0x82,0x7f], [0xf0,0x9f,0x98,0x7f]];
    for (const row of rows) {
      compare(byteInput(row));
      for (let prefix=0;prefix<9;prefix++) compare(byteInput([...Array(prefix).fill(65),...row,66]));
    }
  });
  test('every one-byte and two-byte input agrees with Node', () => {
    const two = new Uint8Array(2);
    for (let a=0;a<256;a++) {
      compare(byteInput([a])); two[0]=a;
      for (let b=0;b<256;b++) { two[1]=b; compare(two); }
    }
  });
  test('all boundary-alphabet triples and quadruples agree with Node', () => {
    const alphabet=[0,0x7f,0x80,0x8f,0x90,0x9f,0xa0,0xbf,0xc0,0xc2,0xdf,0xe0,0xed,0xef,0xf0,0xf4,0xf5,0xff];
    const bytes=new Uint8Array(4);
    for(const a of alphabet)for(const b of alphabet)for(const c of alphabet){
      bytes[0]=a;bytes[1]=b;bytes[2]=c;compare(bytes.subarray(0,3));
      for(const d of alphabet){bytes[3]=d;compare(bytes);}
    }
  });
  test('20000 deterministic varied-length inputs agree with Node', () => {
    let seed=0x753c291b;
    for(let i=0;i<20000;i++){
      const bytes=new Uint8Array(i%97);
      for(let j=0;j<bytes.length;j++){
        seed=(Math.imul(seed,1664525)+1013904223)>>>0;bytes[j]=seed>>>24;
      }
      compare(bytes);
    }
  });
  test('sampled Unicode scalar encodings and their truncated prefixes match the reference', () => {
    // Independent Node encoder/oracle, not the candidate algorithm, creates bytes.
    for(let code=0;code<=0x10ffff;code+=17){
      if(code>=0xd800&&code<=0xdfff)continue;
      const bytes=Buffer.from(String.fromCodePoint(code));
      assert.equal(candidate.isUtf8(bytes),true);
      assert.equal(candidate.isAscii(bytes),reference.isAscii(bytes));
      if(bytes.length>1)compare(bytes.subarray(0,bytes.length-1));
    }
  });
  test('validation observes exact view bounds and never adjacent invalid storage', () => {
    const all=Buffer.from([0xff,...Buffer.from('hello é 😀'),0xff]);
    for(let offset=0;offset<5;offset++){
      const backing=new Uint8Array(all.length+offset);backing.set(all,offset);
      const view=new Uint8Array(backing.buffer,offset+1,all.length-2);compare(view);
      assert.equal(candidate.isUtf8(view),true);assert.equal(candidate.isAscii(view),false);
    }
  });
  test('every numeric typed-array kind is inspected as bytes', () => {
    for(const Type of [Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,
      Int32Array,Uint32Array,Float32Array,Float64Array,BigInt64Array,BigUint64Array]){
      const input=new Type(8),bytes=new Uint8Array(input.buffer);
      for(const value of [0,65,0xff]){bytes.fill(value);compare(input);}
    }
  });
  test('raw and typed foreign-realm allocations use brands, not instanceof', () => {
    for(const expression of ['new ArrayBuffer(4)','new Uint8Array([65,66])',
      'new Uint16Array([0x4141,0x4242])','new Uint8Array([0xff])'])compare(vm.runInNewContext(expression));
  });
  test('Buffer and typed-array metadata cannot redirect validation to decoy bytes', () => {
    for(const bytes of [[0xff],[65,66],[0xc0,0xaf],[0xc3,0xa9]]){
      for(const create of [x=>Buffer.from(x),x=>Uint8Array.from(x)]){
        const input=create(bytes),expected=Object.fromEntries(['isUtf8','isAscii'].map(n=>[n,reference[n](input)]));
        Object.defineProperties(input,{buffer:{value:byteInput(expected.isUtf8?[0xff]:[65]).buffer},
          byteOffset:{value:0},byteLength:{value:1},length:{value:1}});
        for(const name of Object.keys(expected))assert.equal(candidate[name](input),expected[name]);
      }
    }
  });
  test('own metadata getters are not invoked even on subclasses', () => {
    class Input extends Uint8Array {}
    const input=new Input([65,66]);let calls=0;
    for(const name of ['buffer','byteOffset','byteLength','length','constructor']){
      Object.defineProperty(input,name,{get(){calls++;throw Error('public metadata read');}});
    }
    assert.equal(candidate.isUtf8(input),true);assert.equal(candidate.isAscii(input),true);assert.equal(calls,0);
  });
  test('raw ArrayBuffer metadata and tags cannot redirect validation', () => {
    const input=byteInput([0xff]).buffer;let calls=0;
    Object.defineProperty(input,'byteLength',{get(){calls++;return 0;}});
    Object.defineProperty(input,Symbol.toStringTag,{get(){calls++;throw Error('public tag read');}});
    assert.equal(candidate.isUtf8(input),false);assert.equal(candidate.isAscii(input),false);assert.equal(calls,0);
  });
  test('DataViews are rejected as unsupported inputs, matching Node', () => {
    for(const input of [new DataView(new ArrayBuffer(4)),vm.runInNewContext('new DataView(new ArrayBuffer(0))')])compare(input);
  });
  test('invalid inputs and forged prototypes do not invoke coercion hooks', () => {
    let calls=0;const fake={get length(){calls++;return 0;},get buffer(){calls++;return new ArrayBuffer(0);},
      valueOf(){calls++;return new ArrayBuffer(0);},[Symbol.toPrimitive](){calls++;return '';}};
    for(const input of [undefined,null,0,'text',[],{},fake,Object.create(ArrayBuffer.prototype),
      Object.create(Uint8Array.prototype),new Proxy(new Uint8Array(4),{})])compare(input);
    assert.equal(calls,0);
  });
  test('detached raw ArrayBuffers report invalid state instead of valid empty text', () => {
    const input=new ArrayBuffer(8);structuredClone(input,{transfer:[input]});compare(input);
  });
  test('candidate safety distinction: detached typed-array storage is rejected, not accepted as empty', () => {
    const input=new Uint8Array(8);structuredClone(input.buffer,{transfer:[input.buffer]});
    for(const name of ['isUtf8','isAscii']){
      assert.throws(()=>candidate[name](input),{name:'Error',code:'ERR_INVALID_STATE'});
      assert.equal(reference[name](input),true,'explicit Node 22.16 difference');
    }
  });
  test('shared-backed typed views work; direct SharedArrayBuffer remains explicitly unsupported', () => {
    const shared=new SharedArrayBuffer(4),input=new Uint8Array(shared);compare(input);input[0]=255;compare(input);
    for(const name of ['isUtf8','isAscii']){
      assert.throws(()=>candidate[name](shared),{code:'ERR_INVALID_ARG_TYPE'});
      assert.equal(reference[name](shared),false,'pre-existing raw-shared boundary, not parity');
    }
  });
  test('validation does not use a public decoder that a package has replaced', () => {
    const previous=TextDecoder.prototype.decode;
    let calls=0,result;
    try{
      TextDecoder.prototype.decode=function(){calls++;return '';};
      result=candidate.isUtf8(byteInput([0xff]));
    }finally{TextDecoder.prototype.decode=previous;}
    assert.equal(result,false);assert.equal(calls,0);
  });
  test('captured branded bounds survive later public accessor and isView replacement', () => {
    const proto=Object.getPrototypeOf(Uint8Array.prototype),names=['buffer','byteOffset','byteLength','length'];
    const descriptors=names.map(name=>Object.getOwnPropertyDescriptor(proto,name));
    const previous=ArrayBuffer.isView,input=byteInput([65,66]);let calls=0,result;
    try{
      for(const name of names)Object.defineProperty(proto,name,{configurable:true,get(){calls++;throw Error('public bounds');}});
      ArrayBuffer.isView=()=>false;
      result=[candidate.isUtf8(input),candidate.isAscii(input)];
    }finally{
      names.forEach((name,i)=>Object.defineProperty(proto,name,descriptors[i]));ArrayBuffer.isView=previous;
    }
    assert.deepEqual(result,[true,true]);assert.equal(calls,0);
  });
  test('valid and invalid large payloads create one view, no decoder or payload-sized output', () => {
    const stats={views:[],decoders:0,decodedUnits:0};
    const Bytes=new Proxy(Uint8Array,{construct(Target,args){stats.views.push(args);return Reflect.construct(Target,args);}});
    const Decoder=new Proxy(TextDecoder,{construct(Target,args){stats.decoders++;const d=new Target(...args);
      return {decode(input){const text=d.decode(input);stats.decodedUnits+=text.length;return text;}};}});
    const api=load({Uint8Array:Bytes,TextDecoder:Decoder});
    for(const bytes of [Buffer.alloc(1024*1024,65),Buffer.from('é😀'.repeat(65536))]){
      stats.views=[];
      assert.equal(api.isUtf8(bytes),true);
      assert.equal(stats.views.length,1);assert.equal(stats.views[0][0],bytes.buffer);
      assert.equal(stats.views[0][1],bytes.byteOffset);assert.equal(stats.views[0][2],bytes.byteLength);
      bytes[bytes.length-1]=255;assert.equal(api.isUtf8(bytes),false);
    }
    assert.equal(stats.decoders,0);assert.equal(stats.decodedUnits,0);
  });
  test('non-TypeError view-allocation failure remains the original failure', () => {
    const reason=new Error('allocation refused');let enabled=false;
    const Bytes=new Proxy(Uint8Array,{construct(Target,args){if(enabled)throw reason;return Reflect.construct(Target,args);}});
    const api=load({Uint8Array:Bytes});enabled=true;
    for(const name of ['isUtf8','isAscii'])assert.throws(()=>api[name](byteInput([65])),e=>e===reason);
  });
  test('validators never modify input or change the module export contract', () => {
    const data=Buffer.from('hello é 😀'),before=Buffer.from(data);
    for(const name of ['isUtf8','isAscii']){
      const fn=candidate[name];assert.equal(fn.name,name);assert.equal(fn.length,1);
      const d=Object.getOwnPropertyDescriptor(candidate,name);assert(d.enumerable&&d.writable&&d.configurable);
      fn(data);
    }
    assert.deepEqual(data,before);assert.equal(candidate.Buffer,Buffer);
    assert.equal(candidate.transcode(Buffer.from('café'),'utf8','latin1').toString('hex'),'636166e9');
  });
}
