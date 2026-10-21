'use strict';
// Tests the production export boundary. Node supplies the codec intrinsics;
// this is NOT a native-codec, native-lowering or resource-accounting test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const { promisify } = require('node:util');
const native = require('node:zlib');
const sourcePath = process.env.FRANKEN_ZLIB_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/zlib_module.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const routes = {
  gzip_sync: 'gzipSync', gunzip_sync: 'gunzipSync',
  deflate_sync: 'deflateSync', inflate_sync: 'inflateSync',
  deflate_raw_sync: 'deflateRawSync', inflate_raw_sync: 'inflateRawSync',
  unzip_sync: 'unzipSync', brotli_compress_sync: 'brotliCompressSync',
  brotli_decompress_sync: 'brotliDecompressSync',
  gzip: 'gzip', gunzip: 'gunzip', deflate: 'deflate', inflate: 'inflate',
};
function candidate(overrides = {}, globals = {}) {
  const imports = Object.create(null);
  for (const [key, method] of Object.entries(routes)) {
    // Capture the native endpoint before constructing the tested exports.
    imports['__franken_zlib_' + key] = Object.hasOwn(overrides, key) ? overrides[key] : native[method];
  }
  imports.__franken_zlib_constants = overrides.constants || (() => native.constants);
  return Function(...Object.keys(imports), ...Object.keys(globals), 'return ' + source)(
    ...Object.values(imports), ...Object.values(globals));
}
const pairs = [
  ['gzipSync','gunzipSync'], ['deflateSync','inflateSync'],
  ['deflateRawSync','inflateRawSync'], ['brotliCompressSync','brotliDecompressSync'],
];
for (const [encode, decode] of pairs) {
  test('detached ' + encode + '/' + decode + ' preserve bytes and options', () => {
    const api = candidate();
    const compress = api[encode], decompress = api[decode];
    for (const input of ['', 'café 😀\n', Buffer.from(Array.from({length:256},(_,i)=>i)),
      Buffer.alloc(8193, 65)]) {
      const options = encode === 'brotliCompressSync' ? {params:{[native.constants.BROTLI_PARAM_QUALITY]:3}} : {level:6};
      const encoded = compress.call({notTheModule:true}, input, options);
      assert(Buffer.isBuffer(encoded));
      assert.deepEqual(decompress(encoded), Buffer.from(input));
      assert.deepEqual(native[decode](encoded), Buffer.from(input));
      assert.deepEqual(decompress(native[encode](input, options)), Buffer.from(input));
    }
  });
}
test('unzip autodetects gzip and zlib wrappers through an escaped export', () => {
  const {unzipSync} = candidate();
  for (const compress of [native.gzipSync,native.deflateSync]) {
    assert.equal(unzipSync(compress('autodetect')).toString(), 'autodetect');
  }
});
test('all thirteen exports route exactly once with original arguments', () => {
  let calls = 0;
  const input = {}, opts = {}, callback = () => {}, sentinel = {};
  const overrides = {};
  for (const [key, name] of Object.entries(routes)) {
    overrides[key] = function (...args) {
      calls++; assert.equal(this, undefined);
      assert.equal(args[0], input); assert.equal(args[1], opts);
      assert.equal(args.length, name.endsWith('Sync') ? 2 : 3);
      if (!name.endsWith('Sync')) assert.equal(args[2], callback);
      return sentinel;
    };
  }
  const api = candidate(overrides);
  for (const name of Object.values(routes)) assert.equal(api[name](input,opts,callback),sentinel);
  assert.equal(calls, 13);
});
test('native callback overloads retain two/three arguments without moving the callback', () => {
  for (const name of ['gzip','gunzip','deflate','inflate']) {
    const calls = [], input = {}, callback = () => {};
    const api = candidate({[name](...args){calls.push(args);}});
    assert.equal(api[name](input, callback), undefined);
    api[name](input, undefined, callback);
    api[name](input, null, callback);
    assert.deepEqual(calls, [[input,callback], [input,undefined,callback], [input,null,callback]]);
  }
});
for (const [encode,decode] of [['gzip','gunzip'],['deflate','inflate']]) {
  test('promisified ' + encode + '/' + decode + ' compose without module receiver', async () => {
    for (const api of [native,candidate()]) {
      const pack = promisify(api[encode]), unpack = promisify(api[decode]);
      const original = Buffer.from('package export: é 😀\n'.repeat(64));
      const output = await unpack(await pack(original,{level:9}));
      assert.deepEqual(output,original);
    }
  });
}
test('native deferred callback delivery and callback identity remain unchanged', async () => {
  for (const api of [native,candidate()]) {
    let synchronous = true, count = 0;
    const done = new Promise((resolve,reject) => {
      const returned = api.gzip('payload', function (error,data) {
        try {
          count++; assert.equal(synchronous,false);
          // Node binds its codec object. The export wrapper must preserve
          // whatever receiver its native completion provider supplies.
          assert(this instanceof native.Gzip); assert.equal(error,null);
          assert.equal(native.gunzipSync(data).toString(),'payload'); resolve();
        } catch (failure) { reject(failure); }
      });
      assert.equal(returned,undefined);
    });
    synchronous = false; await done; assert.equal(count,1);
  }
});
test('native callback exceptions are not caught and redelivered by the module', () => {
  const reason = new Error('callback failure'); let calls=0;
  const api = candidate({gzip(input,callback){callback(null,input);}});
  assert.throws(() => api.gzip('x',()=>{calls++;throw reason;}), e=>e===reason);
  assert.equal(calls,1);
});
test('sync errors and falsy native throws retain their identity', () => {
  for (const reason of [new Error('native refusal'), null, undefined, false, 0, '']) {
    const api=candidate({gzip_sync(){throw reason;}});
    let caught=false;
    try { api.gzipSync('x'); } catch (e) {caught=true;assert.equal(e,reason);}
    assert.equal(caught,true);
  }
});
test('malformed compressed input rejects promisification instead of publishing bytes', async () => {
  for (const api of [native,candidate()]) {
    for (const name of ['gunzip','inflate']) {
      await assert.rejects(promisify(api[name])(Buffer.from('not compressed')), e=>e.code==='Z_DATA_ERROR');
    }
  }
});
test('missing callback and invalid compression level are not swallowed', () => {
  for (const api of [native,candidate()]) {
    assert.throws(()=>api.gzip('x'), {code:'ERR_INVALID_ARG_TYPE'});
    assert.throws(()=>api.gzipSync('x',{level:99}), {code:'ERR_OUT_OF_RANGE'});
  }
});
test('dictionary options are passed to the codec unmodified', () => {
  const dictionary = Buffer.from('shared dictionary for package archives');
  const opts={dictionary}; const api=candidate();
  const payload=Buffer.from('shared dictionary for package archives: contents');
  assert.deepEqual(api.inflateSync(api.deflateSync(payload,opts),opts),payload);
  assert.throws(()=>api.inflateSync(api.deflateSync(payload,opts)),{code:'Z_NEED_DICT'});
  assert.deepEqual(opts,{dictionary});
});
test('view windows and ArrayBuffer inputs retain the native byte interpretation', () => {
  const api=candidate();
  const bytes=Uint8Array.from([88,65,66,67,89]);
  for (const input of [bytes.subarray(1,4),new DataView(bytes.buffer,1,3),bytes.buffer]) {
    assert.deepEqual(api.gunzipSync(api.gzipSync(input)),native.gunzipSync(native.gzipSync(input)));
  }
  assert.deepEqual(Array.from(bytes),[88,65,66,67,89]);
});
test('constants come from one native acquisition and preserve its object identity', () => {
  let acquisitions=0;const constants=Object.freeze({Z_BEST_COMPRESSION:9});
  const api=candidate({constants(){acquisitions++;return constants;}});
  assert.equal(acquisitions,1);assert.equal(api.constants,constants);assert.equal(api.constants,constants);
  assert.equal(acquisitions,1);
  const descriptor=Object.getOwnPropertyDescriptor(api,'constants');
  assert.deepEqual(descriptor,{value:constants,writable:false,enumerable:true,configurable:false});
  assert.throws(()=>{api.constants={};},TypeError);
});
test('mutating the public namespace does not redirect already captured functions', async () => {
  const api=candidate();const gzip=api.gzipSync, gunzip=api.gunzipSync, packed=promisify(api.gzip);
  api.gzipSync=()=>{throw Error('replacement');};api.gzip=()=>{throw Error('replacement');};
  assert.equal(gunzip(gzip('kept')).toString(),'kept');
  assert.equal(gunzip(await packed('also kept')).toString(),'also kept');
});
test('importing the module performs no compression or callback scheduling', () => {
  let calls=0;const overrides={};for (const key of Object.keys(routes)) overrides[key]=()=>{calls++;};
  const api=candidate(overrides); assert.equal(calls,0); assert.equal(typeof api.gzip,'function');
});
test('public function descriptors and arities are usable by package wrappers', () => {
  const api=candidate();
  for (const name of Object.values(routes)) {
    const d=Object.getOwnPropertyDescriptor(api,name);
    assert.equal(d.writable,true);assert.equal(d.enumerable,true);assert.equal(d.configurable,true);
    assert.equal(api[name].length,name.endsWith('Sync')?2:3);
  }
  for (const name of ['createGzip','createInflate','zstdCompress','deflateRaw','brotliCompress']) {
    assert.equal(Object.hasOwn(api,name),false,'unimplemented APIs are not fabricated');
  }
});

// Unlike the codec tests above, these execute the authored checksum algorithm,
// not a forwarding function backed by Node's crc32. Compare with the live
// independent Node API, including rolling seeds and exact backing windows.
test('CRC32 IEEE vectors and UTF-8 text match the live reference', () => {
  const checksum = candidate().crc32;
  assert.notEqual(checksum, native.crc32);
  for (const [data, expected] of [['',0],['123456789',0xcbf43926],['hello',907060870]]) {
    assert.equal(checksum(data),expected); assert.equal(native.crc32(data),expected);
  }
  for (const data of ['café 😀\r\n','\0\ud800\udfff\ud800tail','東京\n','x'.repeat(16385)]) {
    assert.equal(checksum(data),native.crc32(data));
    assert.equal(checksum(data),checksum(Buffer.from(data)));
  }
  assert.equal(checksum('world',checksum('hello')),4192936109);
});

test('CRC32 honors strict uint32 seeds including the high bit', () => {
  const checksum = candidate().crc32;
  for (const seed of [undefined,0,1,0x7fffffff,0x80000000,0xfffffffe,0xffffffff]) {
    for (const data of ['', 'x', Buffer.from([0,255,128,1])]) {
      assert.equal(checksum(data,seed),native.crc32(data,seed));
    }
  }
});

test('CRC32 treats negative zero as zero without a native assertion failure', () => {
  // Node 22.16 aborts its process for a -0 seed (isolated reference probe).
  // Keep this as an explicit candidate-only correction, not a parity claim.
  const checksum=candidate().crc32;
  assert.equal(checksum('abc',-0),891568578);
  assert.equal(Object.is(checksum('',-0),-0),false);
});

test('CRC32 rejects invalid seeds without coercion or codec dispatch', () => {
  const checksum=candidate().crc32;
  for (const seed of [null,true,'0',1n,{},[],()=>0,Symbol('seed')]) {
    for (const api of [checksum,native.crc32]) assert.throws(()=>api('abc',seed), {name:'TypeError',code:'ERR_INVALID_ARG_TYPE'});
  }
  for (const seed of [NaN,Infinity,-Infinity,-1,4294967296,0.5,Number.MAX_SAFE_INTEGER]) {
    for (const api of [checksum,native.crc32]) assert.throws(()=>api('abc',seed), {name:'RangeError',code:'ERR_OUT_OF_RANGE'});
  }
  let conversions=0;
  assert.throws(()=>checksum('abc',{valueOf(){conversions++;return 0;}}),{code:'ERR_INVALID_ARG_TYPE'});
  assert.equal(conversions,0);
});

test('CRC32 validates data before seed and does not coerce lookalikes', () => {
  const checksum=candidate().crc32;
  for (const data of [undefined,null,1,true,{},[],new String('abc'),new ArrayBuffer(4),new SharedArrayBuffer(4),new Proxy(new Uint8Array(1),{})]) {
    for(const api of [checksum,native.crc32]) assert.throws(()=>api(data,-1), {name:'TypeError',code:'ERR_INVALID_ARG_TYPE'});
  }
  let read=0;
  const fake={get buffer(){read++;throw Error('unexpected');},get byteLength(){read++;return 1;},toString(){read++;return 'abc';}};
  assert.throws(()=>checksum(fake),{code:'ERR_INVALID_ARG_TYPE'});assert.equal(read,0);
});

test('CRC32 checks raw windows of every numeric TypedArray, DataView and Buffer', () => {
  const checksum=candidate().crc32;
  const raw=Uint8Array.from({length:64},(_,i)=>(i*73+19)&255);
  const kinds=[Int8Array,Uint8Array,Uint8ClampedArray,Int16Array,Uint16Array,Int32Array,Uint32Array,Float32Array,Float64Array,BigInt64Array,BigUint64Array];
  for(const Kind of kinds){
    const n=Kind.BYTES_PER_ELEMENT, view=new Kind(raw.buffer,n,4);
    assert.equal(checksum(view),native.crc32(view),Kind.name);
    assert.equal(checksum(view),native.crc32(raw.subarray(n,n*5)),Kind.name);
  }
  for(const view of [new DataView(raw.buffer,7,23),Buffer.from(raw.buffer,5,11)]) {
    assert.equal(checksum(view),native.crc32(view));
  }
  assert.deepEqual(raw,Uint8Array.from({length:64},(_,i)=>(i*73+19)&255));
});

test('CRC32 authenticates views from a different realm', () => {
  const vm=require('node:vm'), checksum=candidate().crc32;
  for(const expression of ['new Uint16Array([0x1234,0xabcd])','new DataView(new Uint8Array([9,82,69,65,76,8]).buffer,1,4)']) {
    const view=vm.runInNewContext(expression);
    assert.equal(checksum(view),native.crc32(view));
  }
});

test('CRC32 ignores public byte metadata and subclass getters', () => {
  const checksum=candidate().crc32;
  for(const view of [Uint8Array.from([82,69,65,76]),new DataView(Uint8Array.from([82,69,65,76]).buffer),Buffer.from('REAL')]){
    Object.defineProperties(view,{
      buffer:{get(){throw Error('public buffer');}},byteOffset:{get(){throw Error('public offset');}},
      byteLength:{get(){throw Error('public byteLength');}},length:{get(){throw Error('public length');}},
    });
    assert.equal(checksum(view),2686002401);assert.equal(native.crc32(view),2686002401);
  }
  class PrivateBytes extends Uint8Array {
    get buffer(){throw Error('subclass buffer');}get byteLength(){throw Error('subclass length');}
  }
  const bytes=new PrivateBytes([82,69,65,76]);assert.equal(checksum(bytes),native.crc32(bytes));
});

test('CRC32 rejects detached storage and consistently preserves empty-chunk seeds', () => {
  // Candidate-only correction: Node 22.16 resets detached views and a zero-
  // capacity DataView to zero. Preserve the mathematical empty-chunk identity
  // for valid views, but never call missing storage a successful checksum.
  const checksum=candidate().crc32;
  for(const Kind of [Uint8Array,DataView]){
    const buffer=new ArrayBuffer(8),view=new Kind(buffer);buffer.transfer();
    assert.throws(()=>checksum(view,12345),TypeError);
  }
  for(const view of [new Uint8Array(0),new DataView(new ArrayBuffer(0)),Buffer.alloc(0)]) {
    assert.equal(checksum(view,12345),12345);
  }
  const resized=new ArrayBuffer(16,{maxByteLength:32});
  const a=new Uint8Array(resized,8,8),b=new DataView(resized,8,8);
  resized.resize(4);
  assert.equal(checksum(a,0xf0000000),native.crc32(a,0xf0000000));
  assert.throws(()=>checksum(b,12345),TypeError);
});

test('CRC32 supports shared byte views without treating the buffer itself as data', () => {
  const checksum=candidate().crc32;
  const view=new Uint8Array(new SharedArrayBuffer(16));view.set([1,2,3,4,5,6]);
  for(const data of [view.subarray(1,5),new DataView(view.buffer,2,7)]) assert.equal(checksum(data),native.crc32(data));
});

test('CRC32 matches Node over 1024 seeded byte inputs and all split points of a small fixture', () => {
  const checksum=candidate().crc32;
  let seed=0x19780211;
  function random(){seed^=seed<<13;seed^=seed>>>17;seed^=seed<<5;return seed>>>0;}
  for(let trial=0;trial<1024;trial++){
    const data=Buffer.alloc(random()%4097);
    for(let i=0;i<data.length;i++)data[i]=random()&255;
    const initial=random(),wanted=native.crc32(data,initial);
    assert.equal(checksum(data,initial),wanted,'whole '+trial);
    let actual=initial;
    for(let i=0;i<data.length;){const end=Math.min(data.length,i+1+random()%71);actual=checksum(data.subarray(i,end),actual);i=end;}
    assert.equal(actual,wanted,'partition '+trial);
  }
  const data=Buffer.from('archive/東京/é 😀\r\n\0binary');
  for(let i=0;i<=data.length;i++)for(let j=i;j<=data.length;j++){
    assert.equal(checksum(data.subarray(j),checksum(data.subarray(i,j),checksum(data.subarray(0,i)))),native.crc32(data));
  }
});

test('CRC32 processes 4096 independent chunks with constant auxiliary storage', () => {
  const checksum=candidate().crc32;
  const chunk=Buffer.from('a streamed package record: café\n');
  let actual=0,expected=0;
  for(let i=0;i<4096;i++){actual=checksum(chunk,actual);expected=native.crc32(chunk,expected);}
  assert.equal(actual,expected);
});

test('CRC32 allocates its private 1KiB table once and aliases byte payloads', () => {
  let tables=0,views=0;const realWords=Uint32Array,realBytes=Uint8Array;let backing;
  const Words=new Proxy(realWords,{construct(target,args){tables++;assert.deepEqual(args,[256]);return new target(...args);}});
  const Bytes=new Proxy(realBytes,{construct(target,args){views++;assert.equal(args[0],backing);return new target(...args);}});
  const api=candidate({}, {Uint32Array:Words,Uint8Array:Bytes});
  assert.equal(tables,0);assert.equal(views,0);
  const empty=new Uint8Array(0);backing=empty.buffer;
  assert.equal(api.crc32(empty,17),17);assert.equal(tables,0);
  const data=Buffer.from('data');backing=data.buffer;
  assert.equal(api.crc32(data),native.crc32(data));
  for(let i=0;i<128;i++)assert.equal(api.crc32(data),native.crc32(data));
  assert.equal(tables,1);assert.equal(views,130);
});

test('CRC32 retains the captured checksum function after namespace replacement', () => {
  const api=candidate(),checksum=api.crc32;
  api.crc32=()=>{throw Error('namespace replacement');};
  assert.equal(checksum.call(null,'123456789'),0xcbf43926);
  assert.equal(checksum.call({notAModule:true},'123456789'),0xcbf43926);
  assert.equal(checksum.length,2);
});

test('CRC32 remains correct after public dependency methods are replaced', () => {
  const api=candidate();
  // Isolate replacement to a child so other concurrent test files cannot see it.
  const {spawnSync}=require('node:child_process');
  const child=spawnSync(process.execPath,['-e',`
    const fs=require('fs'),z=require('zlib');const data=Uint8Array.from([82,69,65,76]);
    const names=${JSON.stringify(Object.keys(routes).map(key=>'__franken_zlib_'+key).concat('__franken_zlib_constants'))};
    const methods=${JSON.stringify(Object.values(routes))};
    const values=methods.map(name=>z[name]);values.push(()=>z.constants);
    const api=Function(...names,'return '+fs.readFileSync(${JSON.stringify(sourcePath)},'utf8'))(...values);
    const original=ArrayBuffer.isView,from=Buffer.from;
    ArrayBuffer.isView=()=>false;Buffer.from=()=>{throw Error('changed');};
    Object.getOwnPropertyDescriptor=()=>{throw Error('changed');};
    Reflect.apply=()=>{throw Error('changed');};
    if(api.crc32(data)!==2686002401||api.crc32('REAL')!==2686002401)throw Error('bad checksum');
    ArrayBuffer.isView=original;Buffer.from=from;
    console.log('CRC_DEPENDENCIES_COMPLETE');
  `],{encoding:'utf8',timeout:5000});
  assert.equal(child.status,0,child.stderr);assert.equal(child.stderr,'');assert.equal(child.stdout,'CRC_DEPENDENCIES_COMPLETE\n');
  assert.equal(typeof api.crc32,'function');
});

test('CRC32 encodes string chunks independently rather than carrying surrogate state', () => {
  const checksum=candidate().crc32;
  const chunks=['header:','\ud83d','\ude00','tail'];
  let actual=0,expected=0;
  for(const chunk of chunks){actual=checksum(chunk,actual);expected=native.crc32(chunk,expected);}
  assert.equal(actual,expected);
  assert.notEqual(actual,checksum(chunks.join('')));
});

// The string path feeds UTF-8 bytes into the CRC recurrence without encoding
// a whole temporary Buffer. These assertions still compare with live Node.
test('CRC32 direct UTF-8 matches every individual UTF-16 code unit', () => {
  const checksum = candidate().crc32;
  for (let unit = 0; unit <= 0xffff; unit++) {
    const text = String.fromCharCode(unit);
    const seed = (unit * 65537) >>> 0;
    assert.equal(checksum(text, seed), native.crc32(text, seed), 'unit ' + unit);
  }
});

test('CRC32 direct UTF-8 handles surrogate boundaries without cross-call carry', () => {
  const checksum = candidate().crc32;
  const units = [0, 0x7f, 0x80, 0x7ff, 0x800, 0xd7ff, 0xd800, 0xdbff,
    0xdc00, 0xdfff, 0xe000, 0xffff];
  for (const first of units) for (const second of units) for (const third of units) {
    const text = String.fromCharCode(first, second, third);
    assert.equal(checksum(text, 0x89abcdef), native.crc32(text, 0x89abcdef));
    for (let cut = 0; cut <= text.length; cut++) {
      assert.equal(checksum(text.slice(cut), checksum(text.slice(0, cut))),
        native.crc32(text.slice(cut), native.crc32(text.slice(0, cut))));
    }
  }
});

test('CRC32 direct UTF-8 matches 2048 seeded malformed and valid Unicode records', () => {
  const checksum = candidate().crc32;
  let seed = 0x2ad79e41;
  function random() { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return seed >>> 0; }
  for (let trial = 0; trial < 2048; trial++) {
    let text = '';
    const length = random() % 513;
    for (let i = 0; i < length; i++) text += String.fromCharCode(random() & 0xffff);
    const initial = random();
    assert.equal(checksum(text, initial), native.crc32(text, initial), 'record ' + trial);
  }
});

test('CRC32 string checks allocate neither encoding buffers nor byte views', t => {
  let encodings = 0, views = 0, tables = 0;
  const Bytes = new Proxy(Uint8Array, { construct(target, args) { views++; return new target(...args); } });
  const Words = new Proxy(Uint32Array, { construct(target, args) { tables++; return new target(...args); } });
  const api = candidate({}, {
    Buffer: { from(...args) { encodings++; return Buffer.from(...args); } },
    Uint8Array: Bytes, Uint32Array: Words,
  });
  assert.equal(api.crc32('', 123), 123);
  assert.equal(tables, 0);
  const records = ['a'.repeat(65536), 'café/東京/😀/\ud800\n'.repeat(8192)];
  for (const text of records) assert.equal(api.crc32(text), native.crc32(text));
  assert.equal(encodings, 0, 'no whole-string encoding');
  assert.equal(views, 0, 'no encoded payload window');
  assert.equal(tables, 1, 'one lazy 1024-byte CRC table');
  t.diagnostic(JSON.stringify({ utf16Units: records.map(s => s.length), encodings, views, tables }));
});

test('CRC32 validates a string seed before any encoding or character traversal', () => {
  let encodings = 0, visits = 0;
  const api = candidate({}, {
    Buffer: { from(...args) { encodings++; return Buffer.from(...args); } },
    String: { prototype: { charCodeAt(index) { visits++; return String.prototype.charCodeAt.call(this, index); } } },
  });
  const text = 'x'.repeat(65536);
  for (const seed of [null, {}, -1, NaN, 1.5]) assert.throws(() => api.crc32(text, seed));
  assert.equal(encodings, 0); assert.equal(visits, 0);
});

test('CRC32 captures UTF-16 access before public String methods are replaced', () => {
  const local = { prototype: { charCodeAt: String.prototype.charCodeAt } };
  const api = candidate({}, { String: local });
  local.prototype.charCodeAt = () => { throw Error('replaced character access'); };
  for (const text of ['ASCII', 'é', '東京', '😀', '\ud800', '\udfff']) {
    assert.equal(api.crc32(text), native.crc32(text));
  }
});

test('CRC32 uses one private argument list across a fragmented-surrogate string', () => {
  let first, visits = 0;
  const local = { apply(fn, receiver, args) {
    if (typeof receiver === 'string') {
      if (first === undefined) first = args;
      else assert.equal(args, first, 'no per-unit argument list allocation');
      visits++;
    }
    return Reflect.apply(fn, receiver, args);
  } };
  const api = candidate({}, { Reflect: local });
  const text = ('A\ud800B😀é').repeat(4096);
  assert.equal(api.crc32(text), native.crc32(text));
  assert.equal(visits, text.length + 4096, 'one lookahead for each unmatched high surrogate');
});
