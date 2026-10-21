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
function candidate(overrides = {}) {
  const imports = Object.create(null);
  for (const [key, method] of Object.entries(routes)) {
    // Capture the native endpoint before constructing the tested exports.
    imports['__franken_zlib_' + key] = Object.hasOwn(overrides, key) ? overrides[key] : native[method];
  }
  imports.__franken_zlib_constants = overrides.constants || (() => native.constants);
  return Function(...Object.keys(imports), 'return ' + source)(...Object.values(imports));
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
