'use strict';
// Execute the complete production factory on Node, not a comparator model.
// Node supplies brand/storage primitives and an independent equality oracle.
// This does not qualify FrankenEngine's native runtime or resource accounting.
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
const integers = [Int8Array, Uint8Array, Uint8ClampedArray, Int16Array, Uint16Array,
  Int32Array, Uint32Array, BigInt64Array, BigUint64Array];
const typed = Object.getPrototypeOf(Uint8Array.prototype);
const nativeTag = Object.getOwnPropertyDescriptor(typed, Symbol.toStringTag).get;
function tag(value) {
  for (const [name, result] of [
    ['isProxy', 'Proxy'], ['isArrayBuffer', 'ArrayBuffer'], ['isSharedArrayBuffer', 'SharedArrayBuffer'],
    ['isDataView', 'DataView'], ['isMap', 'Map'], ['isSet', 'Set'],
    ['isWeakMap', 'WeakMap'], ['isWeakSet', 'WeakSet'], ['isDate', 'Date'],
    ['isRegExp', 'RegExp'], ['isNativeError', 'Error'],
  ]) if (util.types[name](value)) return result;
  if (util.types.isTypedArray(value)) return Reflect.apply(nativeTag, value, []);
  return Array.isArray(value) ? 'Array' : 'Object';
}
function load(text = source, buffer = Buffer) {
  return new Function('__franken_util_type_tag', 'Buffer', 'return ' + text)(tag, buffer).isDeepStrictEqual;
}
const eq = load();
function pair(Type, n, aOffset = 0, bOffset = 0) {
  const width = Type.BYTES_PER_ELEMENT;
  const a = new Type(new ArrayBuffer((n + aOffset + 3) * width), aOffset * width, n);
  const b = new Type(new ArrayBuffer((n + bOffset + 5) * width), bOffset * width, n);
  const bytes = new Uint8Array(a.buffer, a.byteOffset, a.byteLength);
  for (let i = 0; i < bytes.length; i++) bytes[i] = (i * 29 + 7) & 255;
  new Uint8Array(b.buffer, b.byteOffset, b.byteLength).set(bytes);
  return [a, b];
}
function chain(value) { for (let n = 0; n < 80; n++) value = { next: value }; return value; }
function observed() {
  const calls = [];
  const compare = Buffer.compare;
  const buffer = { compare(a, b) { calls.push([a, b]); return compare(a, b); } };
  return { eq: load(source, buffer), calls, buffer };
}
function parity(a, b) {
  assert.equal(eq(a, b), util.isDeepStrictEqual(a, b));
  assert.equal(eq(b, a), util.isDeepStrictEqual(b, a));
}

test('integer kinds preserve every window boundary and mismatch position', () => {
  for (const Type of integers) for (const n of [0, 1, 127, 128, 255, 256, 1023, 1024, 1025]) {
    const [a, b] = pair(Type, n, 1, 3);
    assert.equal(eq(a, b), true, Type.name + ':' + n); parity(a, b);
    const bytes = new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
    for (const at of new Set([0, bytes.length >> 1, bytes.length - 1])) if (at >= 0 && at < bytes.length) {
      bytes[at] ^= 1;
      assert.equal(eq(a, b), false); parity(a, b);
      bytes[at] ^= 1;
    }
    assert.equal(eq(a, new Type(n + 1)), false);
  }
});
test('large integer payloads use exactly one bulk call and authentic byte windows', () => {
  for (const Type of integers) {
    const c = observed(), [a, b] = pair(Type, 2048, 1, 3);
    assert.equal(c.eq(a, b), true);
    assert.equal(c.calls.length, 1, Type.name + ' must not recurse for every element');
    const [x, y] = c.calls[0];
    assert.equal(x.buffer, a.buffer); assert.equal(y.buffer, b.buffer);
    assert.equal(x.byteOffset, a.byteOffset); assert.equal(y.byteOffset, b.byteOffset);
    assert.equal(x.byteLength, a.byteLength); assert.equal(y.byteLength, b.byteLength);
  }
  const c = observed(), a = Buffer.alloc(4096, 5), b = Buffer.alloc(4096, 5);
  assert.equal(c.eq(a, b), true); assert.equal(c.calls.length, 1);
});
test('integer payloads use the same bulk path inside deep graphs and unordered candidates', () => {
  const c = observed(), [a, b] = pair(Uint32Array, 1024);
  assert.equal(c.eq(chain(a), chain(b)), true); assert.equal(c.calls.length, 1);
  const [x, y] = pair(Uint32Array, 1024); y[1023] ^= 1;
  assert.equal(c.eq(new Set([a, y]), new Set([y, b])), true);
  assert.equal(c.eq(new Map([[a, 1]]), new Map([[b, 2]])), false);
  assert.equal(c.eq(chain(a), chain(y)), false);
});
test('matched integer indices are not re-enumerated for descriptors or recursively compared', () => {
  const [a, b] = pair(Uint16Array, 4096);
  const marker = Symbol('extra'); a[marker] = 7; b[marker] = 7;
  const counts = { indices: 0, metadata: 0 };
  const context = vm.createContext({ TextEncoder, TextDecoder, Buffer, tag, a, b, counts });
  vm.runInContext(`
    const original = Object.prototype.propertyIsEnumerable;
    Object.prototype.propertyIsEnumerable = function (key) {
      if (this === a || this === b) {
        if (typeof key === 'string' && /^(0|[1-9][0-9]*)$/.test(key)) counts.indices++;
        else counts.metadata++;
      }
      return Reflect.apply(original, this, [key]);
    };
    const __franken_util_type_tag = tag;
    const api = ${source};
    if (!api.isDeepStrictEqual(a,b)) throw new Error('wrong comparison');
  `, context);
  assert.equal(counts.indices, 0, 'payload must not also visit each numeric descriptor');
  assert.equal(counts.metadata, 3, 'left/right enumeration and right membership check');
});
test('metadata keeps numeric-looking names, symbols, hidden fields and cycles', () => {
  for (const wrap of [x => x, chain]) {
    const [a, b] = pair(Uint8Array, 1024);
    for (const key of ['01', '+0', '1.0', '1e0', '9007199254740993', Symbol('extra')]) {
      a[key] = { value: 1 }; b[key] = { value: 2 };
      assert.equal(eq(wrap(a), wrap(b)), false);
      b[key].value = 1;
      assert.equal(eq(wrap(a), wrap(b)), true);
      delete a[key]; delete b[key];
    }
    a.self = a; b.self = b;
    Object.defineProperty(a, 'hidden', { value: 1 });
    Object.defineProperty(b, 'hidden', { value: 2 });
    assert.equal(eq(wrap(a), wrap(b)), true); parity(a, b);
  }
});
test('own byte-window decoys are not used to select or size a typed payload', () => {
  const c = observed(), [a, b] = pair(Uint8Array, 2048, 1, 3);
  for (const view of [a, b]) for (const key of ['buffer', 'byteOffset', 'byteLength', 'length']) {
    Object.defineProperty(view, key, { get() { throw new Error('decoy ' + key); } });
  }
  assert.equal(c.eq(a, b), true); assert.equal(c.calls.length, 1);
  b[2047] ^= 1;
  assert.equal(c.eq(a, b), false);
});
test('payload precedes metadata getters, including mutation and repeated comparisons', () => {
  for (const wrap of [x => x, chain]) {
    const [a, b] = pair(Uint32Array, 1024), events = [];
    Object.defineProperty(a, 'change', { enumerable: true, get() { events.push('a'); b[1000] ^= 1; return 1; } });
    Object.defineProperty(b, 'change', { enumerable: true, get() { events.push('b'); return 1; } });
    assert.equal(eq(wrap(a), wrap(b)), true);
    assert.deepEqual(events, ['a','b']);
    assert.equal(eq(wrap(a), wrap(b)), false);
    assert.deepEqual(events, ['a','b']);
  }
});
test('metadata exceptions and reentrant comparisons retain identity and clean cycle state', () => {
  const [a, b] = pair(Uint8Array, 1024), reason = { why: 'metadata' };
  let fail = true;
  Object.defineProperty(a, 'extra', { enumerable: true, get() {
    assert.equal(eq(new Uint16Array([1]), new Uint16Array([1])), true);
    if (fail) throw reason; return { value: 1 };
  } });
  b.extra = { value: 1 };
  for (const wrap of [x => x, chain]) {
    fail = true; assert.throws(() => eq(wrap(a), wrap(b)), error => error === reason);
    fail = false; assert.equal(eq(wrap(a), wrap(b)), true);
  }
});
test('floating NaN payloads and signed zeros never use integer byte equality', () => {
  for (const Type of [Float32Array, Float64Array]) {
    const c = observed(), a = new Type(1024), b = new Type(1024);
    const av = new DataView(a.buffer), bv = new DataView(b.buffer);
    if (Type === Float32Array) { av.setUint32(0, 0x7fc00001, true); bv.setUint32(0, 0x7fc00123, true); }
    else { av.setBigUint64(0, 0x7ff8000000000001n, true); bv.setBigUint64(0, 0x7ff8000000000123n, true); }
    assert.equal(c.eq(a,b),true);
    // Existing element-wise engine semantics: all NaNs compare equal. Node
    // v22.16 instead distinguishes these payload bits. Do not claim parity.
    assert.equal(util.isDeepStrictEqual(a,b),false);
    a[1023] = -0; b[1023] = 0;
    assert.equal(c.eq(a,b),false); parity(a,b);
    assert.equal(c.calls.length,0);
  }
});
test('small, shared-backed and Buffer-free comparisons retain scalar execution', () => {
  const c = observed();
  for (const Type of integers) { const [a,b] = pair(Type, 8); assert.equal(c.eq(a,b),true); }
  for (const Type of integers) {
    const a = new Type(new SharedArrayBuffer(2048)), b = new Type(new SharedArrayBuffer(2048));
    assert.equal(c.eq(a,b),true); a[0] = Type === BigInt64Array || Type === BigUint64Array ? 1n : 1;
    assert.equal(c.eq(a,b),false); parity(a,b);
  }
  assert.equal(c.calls.length,0);
  const absent = new Function('__franken_util_type_tag','Buffer','return '+source)(tag,undefined).isDeepStrictEqual;
  const [a,b] = pair(Uint8Array,2048);
  assert.equal(absent(a,b),true); b[2047]^=1; assert.equal(absent(a,b),false);
});
test('first-element and unequal-length rejection precede native comparison and metadata', () => {
  const c=observed(), [a,b]=pair(Uint32Array,1024);
  a.extra=1; b.extra=1; b[0]^=1;
  assert.equal(c.eq(a,b),false); assert.equal(c.calls.length,0);
  assert.equal(c.eq(a,new Uint32Array(1023)),false); assert.equal(c.calls.length,0);
});
test('detached and out-of-bounds views retain the original enumeration behavior', () => {
  const before=process.env.FRANKEN_UTIL_BEFORE;
  const reference=before ? load(fs.readFileSync(before,'utf8')) : null;
  function result(fn,a,b) { try { return { value:fn(a,b) }; } catch(e) { return { error:e.name }; } }
  for (const Type of integers) {
    const a=new Type(2048), b=new Type(2048);
    structuredClone(a.buffer,{transfer:[a.buffer]}); structuredClone(b.buffer,{transfer:[b.buffer]});
    if (reference) assert.deepEqual(result(eq,a,b),result(reference,a,b));
    assert.equal(eq(a,b),true); // Existing engine behavior; Node may refuse detached storage.
    const ar=new ArrayBuffer(4096,{maxByteLength:8192}), br=new ArrayBuffer(4096,{maxByteLength:8192});
    const x=new Type(ar,0,2048/Type.BYTES_PER_ELEMENT), y=new Type(br,0,2048/Type.BYTES_PER_ELEMENT);
    ar.resize(0); br.resize(0);
    if (reference) assert.deepEqual(result(eq,x,y),result(reference,x,y));
    assert.equal(eq(x,y),true);
    ar.resize(4096); br.resize(4096); assert.equal(eq(x,y),true); parity(x,y);
  }
});
test('prototype, class and proxy distinctions remain significant', () => {
  const a=new Uint8Array(2048), b=new Uint8ClampedArray(2048);
  assert.equal(eq(a,b),false); parity(a,b);
  const c=new Uint8Array(2048); Object.setPrototypeOf(c,null);
  assert.equal(eq(a,c),false); parity(a,c);
  const p=new Proxy(a,{}), q=new Proxy(new Uint8Array(2048),{});
  assert.equal(eq(p,q),true); // Existing proxy structural path, not authenticated bulk admission.
  const fake={ [Symbol.toStringTag]:'Uint8Array', value:1 };
  assert.equal(eq(fake,{[Symbol.toStringTag]:'Uint8Array',value:2}),false);
});
test('captured getters and reflection cannot be redirected after initialization', () => {
  const [a,b]=pair(Uint16Array,1024);
  const context=vm.createContext({ TextEncoder,TextDecoder,Buffer,tag,a,b });
  vm.runInContext(`
    const __franken_util_type_tag=tag;
    const api=${source};
    const proto=Object.getPrototypeOf(Uint8Array.prototype);
    for(const key of ['length','buffer','byteOffset','byteLength']) {
      Object.defineProperty(proto,key,{configurable:true,get(){throw new Error('public getter');}});
    }
    Reflect.ownKeys=function(){throw new Error('public keys');};
    if(!api.isDeepStrictEqual(a,b))throw new Error('wrong comparison');
  `,context);
});
test('seeded mixtures, numeric extremes and extra fields match live Node', () => {
  let seed=12345;
  const next=()=>seed=(Math.imul(seed,1664525)+1013904223)>>>0;
  for(let i=0;i<1024;i++) {
    const Type=integers[next()%integers.length],n=1024/Type.BYTES_PER_ELEMENT+next()%65;
    const [a,b]=pair(Type,n,next()%5,next()%5);
    if(i%3===0) new Uint8Array(b.buffer,b.byteOffset,b.byteLength)[next()%b.byteLength]^=1;
    if(i%5===0) { a.extra={x:i};b.extra={x:i+(i%2)}; }
    parity(a,b);
  }
});
