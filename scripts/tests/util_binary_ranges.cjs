'use strict';
// The complete production factory runs on Node's language and byte primitives.
// This suite is not native FrankenEngine execution or native memory evidence.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const util = require('node:util');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const root = path.resolve(__dirname, '../..');
const filename = process.env.FRANKEN_UTIL_SOURCE || path.join(root,
  'crates/franken-engine/src/lowering_pipeline/util_module.js');
const source = fs.readFileSync(filename, 'utf8');
const fixture = fs.readFileSync(path.join(root,
  'crates/franken-engine/tests/fixtures/util_binary_ranges.js'), 'utf8');
function tag(value) {
  for (const [name, result] of [
    ['isProxy', 'Proxy'], ['isArrayBuffer', 'ArrayBuffer'], ['isDataView', 'DataView'],
    ['isMap', 'Map'], ['isSet', 'Set'], ['isWeakMap', 'WeakMap'], ['isWeakSet', 'WeakSet'],
    ['isDate', 'Date'], ['isRegExp', 'RegExp'], ['isNativeError', 'Error'],
  ]) if (util.types[name](value)) return result;
  return Object.prototype.toString.call(value).slice(8, -1);
}
function load(text = source, buffer = Buffer, bytes = Uint8Array) {
  return new Function('__franken_util_type_tag', 'Buffer', 'Uint8Array', 'return ' + text)(
    tag, buffer, bytes).isDeepStrictEqual;
}
const eq = load();
function data(n, seed = 3) {
  const bytes = new Uint8Array(n);
  for (let i = 0; i < n; i++) bytes[i] = (i * 31 + seed) & 255;
  return bytes;
}
function observe() {
  const calls = [], views = [];
  const compare = Buffer.compare;
  const holder = { compare(a, b) {
    calls.push([a, b]);
    return compare(a, b);
  } };
  const Bytes = new Proxy(Uint8Array, { construct(target, args) {
    const result = Reflect.construct(target, args);
    views.push(result);
    return result;
  } });
  return { eq: load(source, holder, Bytes), calls, views, holder };
}
function outcome(compare, a, b) {
  try { return { value: compare(a, b) }; }
  catch (error) { return { error: error.name }; }
}

test('shared public fixture runs against both the factory and live Node', () => {
  const verify = new Function(fixture + '; return verifyUtilBinaryRanges;')();
  const expected = 'util binary ranges: windows, payloads, metadata, ordering, exceptions, deep graphs';
  assert.equal(verify(eq), expected);
  assert.equal(verify(util.isDeepStrictEqual), expected);
});
test('all boundary lengths, offsets and mismatch positions match live Node', () => {
  for (const n of [0,1,2,7,31,63,127,128,129,255,256,257,1023,1024,1025,4096]) {
    for (const leftOffset of [0,1,3,7]) for (const rightOffset of [0,2,5]) {
      const a = data(n + leftOffset + 9), b = data(n + rightOffset + 11, 9);
      b.set(a.subarray(leftOffset, leftOffset + n), rightOffset);
      const x = new DataView(a.buffer, leftOffset, n), y = new DataView(b.buffer, rightOffset, n);
      assert.equal(eq(x,y),true);
      assert.equal(eq(x,y),util.isDeepStrictEqual(x,y));
      for (const at of new Set([0, n >> 1, n - 1])) if (at >= 0 && at < n) {
        b[rightOffset + at] ^= 1;
        assert.equal(eq(x,y),false, `n=${n} at=${at}`);
        assert.equal(eq(x,y),util.isDeepStrictEqual(x,y));
        b[rightOffset + at] ^= 1;
      }
    }
  }
});
test('seeded byte windows compare equal and unequal without copying outside bytes', () => {
  let random = 1234567;
  function next() { random = (Math.imul(random, 1664525) + 1013904223) >>> 0; return random; }
  for (let trial = 0; trial < 2048; trial++) {
    const n = next() % 2049, ao = next() % 16, bo = next() % 16;
    const a = data(n+ao+1,next()), b = data(n+bo+1,next());
    b.set(a.subarray(ao,ao+n),bo);
    if (n && trial % 2) b[bo+next()%n] ^= 1;
    const x = new DataView(a.buffer,ao,n), y = new DataView(b.buffer,bo,n);
    assert.equal(eq(x,y),util.isDeepStrictEqual(x,y));
  }
});
test('large payloads make one native comparison over two sharing views', () => {
  const c=observe(), a=data(1024*1024), b=data(1024*1024);
  assert.equal(c.eq(a.buffer,b.buffer),true);
  assert.equal(c.calls.length,1,'bulk comparison, not a per-byte JS loop');
  assert.equal(c.views.length,2);
  assert.equal(c.views[0].buffer,a.buffer); assert.equal(c.views[1].buffer,b.buffer);
  assert.equal(c.views[0].byteLength,a.byteLength);
  assert.equal(c.views[1].byteLength,b.byteLength);
  assert.deepEqual(c.calls[0],c.views);
});
test('native windows retain exact offsets and reject a last-byte mismatch', () => {
  const c=observe(), a=data(8192), b=data(8192,19);
  b.set(a.subarray(3,4099),7);
  const x=new DataView(a.buffer,3,4096), y=new DataView(b.buffer,7,4096);
  assert.equal(c.eq(x,y),true);
  const [l,r]=c.calls[0];
  assert.equal(l.byteOffset,3); assert.equal(r.byteOffset,7);
  assert.equal(l.byteLength,4096); assert.equal(r.byteLength,4096);
  b[4102]^=1;
  assert.equal(c.eq(x,y),false);
  assert.equal(c.calls.length,2);
});
test('short and unequal-length inputs keep the existing cheap path', () => {
  const c=observe();
  for(const n of [0,1,32,127]) assert.equal(c.eq(data(n).buffer,data(n).buffer),true);
  assert.equal(c.calls.length,0);
  const before=c.views.length;
  assert.equal(c.eq(data(1024).buffer,data(1025).buffer),false);
  assert.equal(c.calls.length,0); assert.equal(c.views.length,before);
});
test('an embedding without Buffer retains a working scalar comparator', () => {
  const realm=vm.createContext({TextEncoder,TextDecoder,__franken_util_type_tag:tag});
  const scalar=vm.runInContext(source,realm).isDeepStrictEqual;
  const a=data(1024),b=data(1024);
  assert.equal(scalar(a.buffer,b.buffer),true);
  b[1023]^=1; assert.equal(scalar(a.buffer,b.buffer),false);
});
test('captured comparator does not consult a later replaced public method', () => {
  const c=observe();
  c.holder.compare=()=>{throw new Error('late public compare');};
  const a=data(2048),b=data(2048);
  assert.equal(c.eq(a.buffer,b.buffer),true);
  b[128]^=1; assert.equal(c.eq(a.buffer,b.buffer),false);
  assert.equal(c.calls.length,2);
});
test('private view construction does not consult a replaced global Uint8Array', () => {
  const realm=vm.createContext({Buffer,TextEncoder,TextDecoder,__franken_util_type_tag:tag});
  vm.runInContext(`var a=new Uint8Array(256), b=new Uint8Array(256); var api=${source};
    Uint8Array=function(){throw new Error('guest constructor');};`,realm);
  assert.equal(vm.runInContext('api.isDeepStrictEqual(a.buffer,b.buffer)',realm),true);
});
test('own properties, symbols, prototype differences and cyclic metadata are not bypassed', () => {
  for (const view of [false,true]) {
    const a=data(2048).buffer,b=data(2048).buffer;
    const x=view?new DataView(a):a,y=view?new DataView(b):b;
    x.self=x;y.self=y;
    assert.equal(eq(x,y),true);
    const s=Symbol('extra');x[s]=1;y[s]=2;
    assert.equal(eq(x,y),false);assert.equal(eq(x,y),util.isDeepStrictEqual(x,y));
    y[s]=1;assert.equal(eq(x,y),true);
    Object.setPrototypeOf(y,Object.create(Object.getPrototypeOf(y)));
    assert.equal(eq(x,y),false);
  }
});
test('detached buffers and views keep TypeError and identity behavior', () => {
  const a=data(2048).buffer,b=data(2048).buffer;
  const av=new DataView(a),bv=new DataView(b);
  structuredClone(a,{transfer:[a]});structuredClone(b,{transfer:[b]});
  for(const [x,y] of [[a,b],[av,bv],[a,a],[av,av]])
    assert.deepEqual(outcome(eq,x,y),outcome(util.isDeepStrictEqual,x,y));
});
test('resizable buffers preserve current windows and invalid-view errors', () => {
  for(const grow of [false,true]) {
    const a=new ArrayBuffer(256,{maxByteLength:1024}),b=new ArrayBuffer(256,{maxByteLength:1024});
    const av=new DataView(a,1,128),bv=new DataView(b,1,128);
    a.resize(grow?512:64);b.resize(grow?512:64);
    assert.deepEqual(outcome(eq,av,bv),outcome(util.isDeepStrictEqual,av,bv));
    assert.deepEqual(outcome(eq,a,b),outcome(util.isDeepStrictEqual,a,b));
  }
});
test('shared-backed DataViews keep the scalar path and selected windows', () => {
  const c=observe(),a=new SharedArrayBuffer(2048),b=new SharedArrayBuffer(2048);
  const x=new DataView(a,3,1024),y=new DataView(b,7,1024);
  assert.equal(c.eq(x,y),true);assert.equal(c.calls.length,0);
  new Uint8Array(b)[1030]=1;assert.equal(c.eq(x,y),false);
});
test('guest-coerced offsets do not promote after resizing the earlier byte view', () => {
  // Keep pre-existing public-window semantics. Node uses other metadata paths;
  // this case is a scalar-path invariant, not a new Node-parity assertion.
  const c=observe();
  const a=new ArrayBuffer(2048,{maxByteLength:4096}),b=new ArrayBuffer(2048,{maxByteLength:4096});
  const x=new DataView(a),y=new DataView(b);
  let calls=0;
  Object.defineProperty(y,'byteOffset',{value:{valueOf(){calls++;a.resize(0);return 0;}}});
  assert.equal(c.eq(x,y),false);assert.equal(calls,1);assert.equal(c.calls.length,0);
});
test('bulk failure and later metadata errors propagate exact original values', () => {
  const failure={reason:'native comparator failure'};
  const compare=load(source,{compare(){throw failure;}});
  const a=data(2048).buffer,b=data(2048).buffer;
  assert.throws(()=>compare(a,b),error=>error===failure);
  const c=data(256).buffer,d=data(256).buffer;
  Object.defineProperty(c,'meta',{enumerable:true,get(){throw failure;}});
  Object.defineProperty(d,'meta',{enumerable:true,value:1});
  assert.throws(()=>eq(c,d),error=>error===failure);
  assert.equal(eq(a,b),true,'failed comparison state does not escape');
});

test('promotion starts at 1024 bytes and first-byte mismatches avoid the native call', () => {
  const c=observe();
  assert.equal(c.eq(data(1023).buffer,data(1023).buffer),true);
  assert.equal(c.calls.length,0);
  const a=data(1024),b=data(1024);
  assert.equal(c.eq(a.buffer,b.buffer),true);
  assert.equal(c.calls.length,1);
  b[0]^=1;
  assert.equal(c.eq(a.buffer,b.buffer),false);
  assert.equal(c.calls.length,1);
});
test('non-buffer window metadata keeps the original scalar constructor semantics', () => {
  // Uint8Array(typedArray, offset, length) copies element values, ignoring the
  // latter arguments. Do not bulk-compare that entire copy when the original
  // scalar loop is bounded by a separately supplied public byteLength.
  const c=observe(),a=new DataView(new ArrayBuffer(8)),b=new DataView(new ArrayBuffer(8));
  const x=data(2048),y=data(2048);y[2047]^=1;
  Object.defineProperties(a,{buffer:{value:x},byteLength:{value:1024}});
  Object.defineProperties(b,{buffer:{value:y},byteLength:{value:1024}});
  assert.equal(c.eq(a,b),true);
  assert.equal(c.calls.length,0);
});
