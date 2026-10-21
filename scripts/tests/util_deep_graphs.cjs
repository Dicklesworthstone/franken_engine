'use strict';
// Run the complete production factory. Node supplies native brand predicates
// and a separate isDeepStrictEqual oracle; this does not run FrankenEngine.
const fs = require('node:fs');
const path = require('node:path');
const util = require('node:util');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(process.env.FRANKEN_UTIL_SOURCE || path.join(root,
  'crates/franken-engine/src/lowering_pipeline/util_module.js'), 'utf8');
const fixture = fs.readFileSync(path.join(root,
  'crates/franken-engine/tests/fixtures/util_deep_graphs.js'), 'utf8');
const checks = [
  ['isProxy', 'Proxy'], ['isMap', 'Map'], ['isSet', 'Set'],
  ['isWeakMap', 'WeakMap'], ['isWeakSet', 'WeakSet'],
  ['isDate', 'Date'], ['isRegExp', 'RegExp'], ['isNativeError', 'Error'],
  ['isArrayBuffer', 'ArrayBuffer'], ['isDataView', 'DataView'],
  ['isNumberObject', 'BoxedNumber'], ['isStringObject', 'BoxedString'],
  ['isBooleanObject', 'BoxedBoolean'], ['isBigIntObject', 'BoxedBigInt'],
  ['isSymbolObject', 'BoxedSymbol'], ['isPromise', 'Promise'],
].map(([name, tag]) => [util.types[name], tag]);
function typeTag(value) {
  for (const [test, tag] of checks) if (test(value)) return tag;
  return Object.prototype.toString.call(value).slice(8, -1);
}
function candidate(observe = false) {
  const maps = [], metrics = { gets: 0, sets: 0, has: 0, deletes: 0, live: 0, peak: 0 };
  const size = Object.getOwnPropertyDescriptor(Map.prototype, 'size').get;
  class ObservedMap extends Map {
    constructor() { super(); maps.push(this); }
    get size() { return Reflect.apply(size, this, []); }
    get(key) { metrics.gets++; return super.get(key); }
    has(key) { metrics.has++; return super.has(key); }
    set(key, value) {
      metrics.sets++;
      const before = Reflect.apply(size, this, []);
      super.set(key, value);
      metrics.live += Reflect.apply(size, this, []) - before;
      metrics.peak = Math.max(metrics.peak, metrics.live);
      return this;
    }
    delete(key) {
      metrics.deletes++;
      const removed = super.delete(key);
      metrics.live -= Number(removed);
      return removed;
    }
  }
  const api = new Function('__franken_util_inspect', '__franken_util_format',
    '__franken_util_type_tag', 'Map', 'return ' + source)(
    util.inspect, args => util.format(...args), typeTag, observe ? ObservedMap : Map);
  return { api, metrics, maps, ObservedMap };
}
function chain(depth, leaf = { value: 1 }) {
  let value = leaf;
  for (let i = 0; i < depth; i++) value = { next: value };
  return value;
}
const eq = candidate().api.isDeepStrictEqual;
function parity(a, b) { assert.equal(eq(a, b), util.isDeepStrictEqual(a, b)); }
function clean(c) {
  assert.equal(c.metrics.live, 0, 'no inactive pair remains indexed');
  for (const map of c.maps) assert.equal(map.size, 0, 'no completed result memoization');
}
test('shared native fixture runs in candidate and live Node', () => {
  const run = new Function(fixture + '; return verifyUtilDeepGraphs;')();
  const expected = 'util deep graphs: chains, cycles, partners, rollback, getters, exceptions, reentry';
  assert.equal(run(eq), expected);
  assert.equal(run(util.isDeepStrictEqual), expected);
});
test('promotion boundaries preserve equal and unequal deep values in both orders', () => {
  for (const depth of [0, 1, 31, 32, 63, 64, 65, 127, 128, 256, 512]) {
    const a = chain(depth), b = chain(depth), c = chain(depth, { value: 2 });
    parity(a, b); parity(b, a); parity(a, c); parity(c, a);
  }
});
test('primitive and shallow comparisons allocate no pair index', () => {
  const c = candidate(true), compare = c.api.isDeepStrictEqual;
  const symbol = Symbol('same');
  for (const value of [undefined, null, false, NaN, -0, 1n, symbol, 'text']) assert.equal(compare(value, value), true);
  for (const depth of [0, 1, 8, 32, 63]) assert.equal(compare(chain(depth), chain(depth)), true);
  assert.equal(compare({ a: 1 }, { a: 2 }), false);
  assert.equal(c.maps.length, 0);
});
test('deep distinct-left chains use one index with linear lookup work', () => {
  for (const depth of [64, 128, 256, 512, 1024]) {
    const c = candidate(true);
    assert.equal(c.api.isDeepStrictEqual(chain(depth), chain(depth)), true);
    assert.equal(c.maps.length, 1, 'no per-level hash-table allocation');
    assert.equal(c.metrics.sets, depth + 1);
    assert.equal(c.metrics.deletes, depth + 1);
    assert.equal(c.metrics.gets, 2 * (depth + 1));
    assert.equal(c.metrics.peak, depth + 1);
    clean(c);
  }
});
test('live index entries follow active depth rather than visited breadth', () => {
  const c = candidate(true);
  const a = Array.from({ length: 128 }, () => chain(80));
  const b = Array.from({ length: 128 }, () => chain(80));
  assert.equal(c.api.isDeepStrictEqual(a, b), true);
  assert.equal(c.maps.length, 1);
  assert.equal(c.metrics.peak, 82);
  clean(c);
});
test('a repeated left object keeps every active right partner, including pre-promotion pairs', () => {
  for (const mismatch of [false, true]) {
    const c = candidate(true), a = {}, b = {};
    a.next = a;
    let tail = b;
    for (let i = 0; i < 96; i++) { tail.next = {}; tail = tail.next; }
    tail.next = b;
    if (mismatch) tail.value = 1;
    assert.equal(c.api.isDeepStrictEqual(a, b), !mismatch);
    assert.equal(util.isDeepStrictEqual(a, b), !mismatch);
    assert.equal(c.maps.length, 3, 'primary index, secondary index, one partner set');
    clean(c);
    parity(b, a);
  }
});
test('promotion seeds ancestors without reading their getters again', () => {
  function run(compare) {
    const log = [], a = {}, b = {};
    const aa = [a], bb = [b];
    for (let i = 1; i < 90; i++) { aa.push({}); bb.push({}); }
    for (let i = 0; i < aa.length; i++) {
      Object.defineProperty(aa[i], 'next', { enumerable: true, get() { log.push('a' + i); return aa[(i + 1) % aa.length]; } });
      Object.defineProperty(bb[i], 'next', { enumerable: true, get() { log.push('b' + i); return bb[(i + 1) % bb.length]; } });
    }
    return { equal: compare(a, b), log };
  }
  const expected = run(util.isDeepStrictEqual);
  assert.equal(expected.log.length, 180);
  assert.deepEqual(run(eq), expected);
});
test('completed siblings are reread and can become unequal after promotion', () => {
  function run(compare) {
    let reads = 0;
    const a = { get value() { return ++reads; } }, b = { value: 1 };
    const equal = compare(chain(80, { a, b: a }), chain(80, { a: b, b }));
    return { equal, reads };
  }
  assert.deepEqual(run(eq), { equal: false, reads: 2 });
  assert.deepEqual(run(eq), run(util.isDeepStrictEqual));
});
test('failed unordered candidates are removed, not promoted to cached equal results', () => {
  for (const isMap of [false, true]) {
    for (const bad of [false, true]) {
      const a = [{ child: { value: 1 }, rank: 1 }, { child: { value: 1 }, rank: 2 }];
      const b = [{ child: { value: 1 }, rank: 2 }, { child: { value: bad ? 2 : 1 }, rank: 1 }];
      const left = isMap ? new Map(a.map(x => [x, x.rank])) : new Set(a);
      const right = isMap ? new Map(b.map(x => [x, x.rank])) : new Set(b);
      const first = chain(80, left), second = chain(80, right);
      parity(first, second); parity(second, first);
      assert.equal(eq(first, second), !bad);
    }
  }
});
test('all thrown values unwind indexed state without replacing exception identity', () => {
  for (const reason of [undefined, null, false, 0, Symbol('reason'), new Error('reason'), {}]) {
    const c = candidate(true);
    const a = { get value() { throw reason; } };
    let caught = false;
    try { c.api.isDeepStrictEqual(chain(80, a), chain(80, { value: 1 })); }
    catch (error) { caught = true; assert.equal(error, reason); }
    assert.equal(caught, true);
    assert.equal(c.maps.length, 1);
    clean(c);
    assert.equal(c.api.isDeepStrictEqual(chain(80), chain(80)), true);
    clean(c);
  }
});
test('nested public comparisons own separate indexes and unwind independently', () => {
  const c = candidate(true), compare = c.api.isDeepStrictEqual;
  let nested = 0;
  const a = { get value() { nested++; assert.equal(compare(chain(80), chain(80)), true); return 1; } };
  assert.equal(compare(chain(80, a), chain(80, { value: 1 })), true);
  assert.equal(nested, 1);
  assert.equal(c.maps.length, 2);
  clean(c);
});
test('captured Map methods and size access survive prototype replacement', () => {
  const c = candidate(true), proto = c.ObservedMap.prototype;
  const methods = ['get', 'set', 'has', 'delete', 'size'];
  const descriptors = Object.getOwnPropertyDescriptors(proto);
  const failure = () => { throw new Error('guest Map replacement reached'); };
  for (const name of methods) Object.defineProperty(proto, name, { configurable: true, get: failure });
  try {
    const a = {}; a.next = a;
    const b = chain(96, a);
    assert.equal(c.api.isDeepStrictEqual(a, b), true);
    assert.equal(c.api.isDeepStrictEqual(chain(96), chain(96)), true);
  } finally {
    for (const name of methods) Object.defineProperty(proto, name, descriptors[name]);
  }
  clean(c);
});
test('proxies preserve trap order and thrown-value identity below and above promotion', () => {
  function run(compare, depth, throws) {
    const log = [], reason = {};
    const handler = name => ({
      getPrototypeOf(target) { log.push(name + ':proto'); return Reflect.getPrototypeOf(target); },
      ownKeys(target) { log.push(name + ':keys'); return Reflect.ownKeys(target); },
      getOwnPropertyDescriptor(target, key) { log.push(name + ':desc:' + key); return Reflect.getOwnPropertyDescriptor(target, key); },
      get(target, key, receiver) { log.push(name + ':get:' + String(key)); if (throws && name === 'a' && key === 'value') throw reason; return Reflect.get(target, key, receiver); },
    });
    const a = new Proxy({ value: 1 }, handler('a')), b = new Proxy({ value: 1 }, handler('b'));
    try { return { equal: compare(chain(depth, a), chain(depth, b)), log }; }
    catch (error) { assert.equal(error, reason); return { threw: true, log }; }
  }
  // Promotion must not change this factory's trap sequence. Node uses a
  // different internal enumeration algorithm, so its sequence is not an oracle.
  for (const throws of [false, true]) assert.deepEqual(run(eq, 80, throws), run(eq, 0, throws));
});
test('generated sharing and backedges preserve Node results', () => {
  let comparisons = 0;
  for (let seed = 1; seed <= 128; seed++) {
    let rng = seed;
    const random = n => { rng = (Math.imul(rng, 1664525) + 1013904223) >>> 0; return rng % n; };
    const a = Array.from({ length: 12 }, () => ({}));
    const b = Array.from({ length: 12 }, () => ({}));
    for (let i = 0; i < 12; i++) {
      a[i].value = b[i].value = random(8);
      for (const key of ['left', 'right']) { const j = random(12); a[i][key] = a[j]; b[i][key] = b[j]; }
    }
    for (const depth of [0, 63, 64, 80]) {
      parity(chain(depth, a[0]), chain(depth, b[0])); comparisons++;
      b[0].value += 100;
      parity(chain(depth, a[0]), chain(depth, b[0])); comparisons++;
      b[0].value -= 100;
    }
  }
  assert.equal(comparisons, 1024);
});
test('special objects, sparse arrays, symbol keys and signed zero keep their semantics', () => {
  const symbol = Symbol('key');
  for (const [a, b] of [
    [new Date(3), new Date(3)], [new Date(NaN), new Date(NaN)], [/ab/g, /ab/g],
    [Object(1), Object(2)], [Object(1n), Object(1n)],
    [new Uint8Array([1, 2]), new Uint8Array([1, 2])],
    [new Array(2), [undefined, undefined]], [{ [symbol]: 1 }, { [symbol]: 2 }],
    [{ zero: -0 }, { zero: 0 }], [new WeakMap(), new WeakMap()],
    [new Set([NaN, -0]), new Set([0, NaN])],
  ]) parity(chain(80, a), chain(80, b));
});
