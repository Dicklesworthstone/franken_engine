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

test('shared property-walk fixture runs through candidate and live Node at ordinary depth', () => {
  const run = new Function(fixture + '; return verifyUtilPropertyWalk;')();
  const expected = 'util property walk: depth, mixed arrays, cycles, getter order, failure cleanup';
  assert.equal(run(eq, 96), expected);
  assert.equal(run(util.isDeepStrictEqual, 96), expected);
  // Beyond the incumbent's host call-stack bound, check the same explicit
  // expectations; do not label Node's RangeError as an equality result.
  assert.equal(run(eq, 4096), expected);
});
test('twenty-thousand property levels do not require twenty-thousand JS calls', () => {
  const c = candidate(true);
  assert.equal(c.api.isDeepStrictEqual(chain(20000), chain(20000)), true);
  assert.equal(c.api.isDeepStrictEqual(chain(20000), chain(20000, { value: 2 })), false);
  clean(c);
});
test('getter-observed host stack depth stays bounded after promotion', () => {
  const saved = Error.stackTraceLimit;
  Error.stackTraceLimit = Infinity;
  try {
    function sample(depth) {
      let frames = 0;
      const leaf = { get value() { frames = new Error().stack.split('\n').length; return 1; } };
      assert.equal(eq(chain(depth, leaf), chain(depth, { value: 1 })), true);
      return frames;
    }
    const shallow = sample(128), deep = sample(1024);
    assert.ok(shallow > 0);
    assert.ok(deep <= shallow + 8, `property depth grew the host stack: ${shallow} -> ${deep}`);
  } finally { Error.stackTraceLimit = saved; }
});
test('deep mixed arrays and objects retain sparse holes, key order and signed zero', () => {
  function nest(n, leaf) {
    for (let i = 0; i < n; i++) leaf = i % 2 ? [leaf, i] : { first: leaf, order: i };
    return leaf;
  }
  for (const [a, b, expected] of [[new Array(2), [undefined, undefined], false],
    [{ a: 1, b: 2 }, { b: 2, a: 1 }, true], [{ zero: -0 }, { zero: 0 }, false]]) {
    assert.equal(eq(nest(8192, a), nest(8192, b)), expected);
    assert.equal(eq(nest(96, a), nest(96, b)), util.isDeepStrictEqual(nest(96, a), nest(96, b)));
  }
});
test('property walker leaves sibling values unread until previous descendants finish', () => {
  function run(compare, depth) {
    const trace = [], a = {}, b = {};
    Object.defineProperty(a, 'first', { enumerable: true, get() {
      trace.push('a.first'); return { get child() { trace.push('a.child'); b.last = 9; return 1; } };
    } });
    Object.defineProperty(b, 'first', { enumerable: true, get() {
      trace.push('b.first'); return { get child() { trace.push('b.child'); return 1; } };
    } });
    a.last = 9; b.last = 0;
    return { result: compare(chain(depth, a), chain(depth, b)), trace };
  }
  const expected = { result: true, trace: ['a.first', 'b.first', 'a.child', 'b.child'] };
  assert.deepEqual(run(eq, 4096), expected);
  assert.deepEqual(run(util.isDeepStrictEqual, 96), expected);
});
test('deletion of a later sibling and abrupt enumeration release every indexed child', () => {
  const c = candidate(true);
  const b = { first: { x: 1 }, later: 1 };
  const a = { first: { get x() { delete b.later; return 1; } }, later: 1 };
  assert.equal(c.api.isDeepStrictEqual(chain(4096, a), chain(4096, b)), false);
  clean(c);
  const reason = {};
  const bad = new Proxy({}, { ownKeys() { throw reason; } });
  assert.throws(() => c.api.isDeepStrictEqual(chain(4096, bad), chain(4096, new Proxy({}, {}))),
    error => error === reason);
  clean(c);
});
test('special payloads inside property walks retain independent unordered candidate cleanup', () => {
  const c = candidate(true);
  const left = new Set([{ value: 1, order: 1 }, { value: 1, order: 2 }]);
  const right = new Set([{ value: 1, order: 2 }, { value: 1, order: 1 }]);
  assert.equal(c.api.isDeepStrictEqual(chain(4096, left), chain(4096, right)), true);
  const bad = new Set([{ value: 1, order: 1 }, { value: 1, order: 1 }]);
  assert.equal(c.api.isDeepStrictEqual(chain(4096, bad), chain(4096, right)), false);
  // Snapshot maps for unordered matching are not ancestor indexes. Check
  // exact retry/results here; index-only cleanup is covered separately.
  const a = new Error('x', { cause: chain(1024) }), b = new Error('x', { cause: chain(1024) });
  assert.equal(eq(chain(4096, a), chain(4096, b)), true);
  b.cause = chain(1024, { value: 2 });
  assert.equal(eq(chain(4096, a), chain(4096, b)), false);
});
test('deep property cycles with asymmetric partners and root backedges terminate', () => {
  const c = candidate(true), a = {}, b = {};
  let aa = a, bb = b;
  for (let i = 0; i < 8192; i++) { aa.next = {}; aa = aa.next; bb.next = {}; bb = bb.next; }
  aa.next = a; bb.next = b;
  assert.equal(c.api.isDeepStrictEqual(a, b), true);
  clean(c);
  const self = {}; self.next = self;
  assert.equal(c.api.isDeepStrictEqual(self, b), true);
  clean(c);
  bb.extra = 1;
  assert.equal(c.api.isDeepStrictEqual(self, b), false);
  clean(c);
});
test('special-payload failure does not strand a scheduled property frame', () => {
  const c = candidate(true), reason = {};
  const a = new Date(1), b = new Date(1);
  Object.defineProperty(a, 'getTime', { value() { throw reason; } });
  assert.throws(() => c.api.isDeepStrictEqual(chain(4096, a), chain(4096, b)), error => error === reason);
  clean(c);
  assert.equal(c.api.isDeepStrictEqual(chain(4096, new Date(1)), chain(4096, new Date(2))), false);
  clean(c);
});

function payloadGraph(depth, kind, leaf = { value: 1 }) {
  let value = leaf;
  for (let i = 0; i < depth; i++) {
    const next = kind === 'mixed' ? ['object', 'array', 'map', 'key', 'set', 'cause', 'errors'][i % 7] : kind;
    if (next === 'map') value = new Map([['next', value]]);
    else if (next === 'key') value = new Map([[value, i]]);
    else if (next === 'set') value = new Set([value]);
    else if (next === 'cause') value = new Error('payload', { cause: value });
    else if (next === 'errors') {
      const error = new Error('payload');
      Object.defineProperty(error, 'errors', { value: [value] });
      value = error;
    } else if (next === 'array') value = [value, i];
    else value = { next: value, rank: i };
  }
  return value;
}
test('special payloads agree with live Node across the promotion boundary', () => {
  for (const kind of ['map', 'key', 'set', 'cause', 'errors', 'mixed']) {
    for (const depth of [0, 1, 63, 64, 65, 96, 128]) {
      const a = payloadGraph(depth, kind), b = payloadGraph(depth, kind);
      const wrong = payloadGraph(depth, kind, { value: 2 });
      parity(a, b); parity(b, a); parity(a, wrong); parity(wrong, a);
    }
  }
});
test('20000-level special payloads compare without a host recursion limit', () => {
  // Beyond the incumbent's stack limit these have structural expectations,
  // not a fabricated equality result substituted for its RangeError.
  for (const kind of ['map', 'key', 'set', 'cause', 'errors']) {
    const a = payloadGraph(20000, kind), b = payloadGraph(20000, kind);
    const wrong = payloadGraph(20000, kind, { value: 2 });
    assert.equal(eq(a, b), true, kind);
    assert.equal(eq(a, wrong), false, kind);
  }
});
test('mixed payload and property continuations keep cyclic partner tracking', () => {
  for (const depth of [96, 8192]) {
    const leafA = {}, leafB = {};
    const a = payloadGraph(depth, 'mixed', leafA), b = payloadGraph(depth, 'mixed', leafB);
    leafA.next = a; leafB.next = b;
    assert.equal(eq(a, b), true);
    leafB.extra = 1;
    assert.equal(eq(a, b), false);
    assert.equal(eq(b, a), false);
  }
});
test('deep collection candidate failures retry without leaking active pairs', () => {
  for (const map of [false, true]) {
    const c = candidate(true);
    const a = [payloadGraph(2048, 'mixed', { rank: 1 }), payloadGraph(2048, 'mixed', { rank: 2 })];
    const b = [payloadGraph(2048, 'mixed', { rank: 2 }), payloadGraph(2048, 'mixed', { rank: 1 })];
    const left = map ? new Map(a.map(value => [value, value])) : new Set(a);
    const right = map ? new Map(b.map(value => [value, value])) : new Set(b);
    assert.equal(c.api.isDeepStrictEqual(chain(80, left), chain(80, right)), true);
    assert.equal(c.maps[0].size, 0, 'primary pair index unwound');
    // Snapshot indexes have primitive keys. All object-key entries belong to
    // active-pair indexes and must be gone, including after a failed candidate.
    for (const index of c.maps) for (const key of index.keys()) {
      assert.ok(key === null || typeof key !== 'object', 'no inactive pair');
    }
  }
});
test('cause, errors and ordinary properties retain depth-first getter ordering', () => {
  function run(compare) {
    const log = [], left = new Error('payload'), right = new Error('payload');
    Object.defineProperty(left, 'cause', { get() {
      log.push('cause-a'); return { get value() {
        log.push('child-a'); right.later = 2; return 1;
      } };
    } });
    Object.defineProperty(right, 'cause', { get() {
      log.push('cause-b'); return { get value() { log.push('child-b'); return 1; } };
    } });
    Object.defineProperty(left, 'errors', { get() { log.push('errors-a'); return [1]; } });
    Object.defineProperty(right, 'errors', { get() { log.push('errors-b'); return [1]; } });
    left.later = 2; right.later = 0;
    return { equal: compare(chain(80, left), chain(80, right)), log };
  }
  const got = run(eq);
  assert.equal(got.equal, true);
  assert.deepEqual(got.log, ['cause-a', 'cause-b', 'child-a', 'child-b', 'errors-a', 'errors-b']);
  // Node reads Error payload fields differently; the trace above preserves
  // the engine's pre-existing order, rather than claiming trace parity.
  assert.equal(run(util.isDeepStrictEqual).equal, true);
  const a = new Error('payload'), b = new Error('payload');
  Object.defineProperty(a, 'cause', { value: undefined });
  assert.equal(eq(chain(80, a), chain(80, b)), false, 'absent differs from own undefined');
});
test('enumerable Error payloads are compared again as ordinary properties', () => {
  let reads = 0;
  const a = new Error('payload'), b = new Error('payload');
  Object.defineProperty(a, 'cause', { enumerable: true, get() { return ++reads; } });
  Object.defineProperty(b, 'cause', { enumerable: true, value: 1 });
  assert.equal(eq(chain(80, a), chain(80, b)), false);
  assert.equal(reads, 2, 'completed payload equality is not memoized');
});
test('iterative collections retain right snapshots and live left reinsertion checks', () => {
  const left = new Map(), right = new Map();
  const value = { get value() { right.set('later', 9); return 1; } };
  left.set('first', value); left.set('later', 2);
  right.set('first', { value: 1 }); right.set('later', 2);
  assert.equal(eq(chain(80, left), chain(80, right)), true, 'right values were snapshotted before the getter');
  let reinsert = true;
  const item = { get value() {
    if (reinsert) { reinsert = false; left.delete('first'); left.set('first', item); }
    return 1;
  } };
  left.set('first', item); right.set('later', 2);
  assert.equal(eq(chain(80, left), chain(80, right)), false, 'consumed primitive key cannot match twice');
  assert.equal(eq(chain(80, left), chain(80, right)), true);
});
test('thrown values unwind mixed payload pairs and permit independent reentry', () => {
  for (const reason of [undefined, null, 0, false, Symbol('throw'), {}]) {
    const c = candidate(true), compare = c.api.isDeepStrictEqual;
    let caught = false;
    try {
      compare(chain(80, payloadGraph(512, 'mixed', { get value() { throw reason; } })),
        chain(80, payloadGraph(512, 'mixed')));
    } catch (error) { caught = true; assert.equal(error, reason); }
    assert.equal(caught, true);
    assert.equal(c.maps[0].size, 0);
    const a = { get value() {
      assert.equal(compare(payloadGraph(128, 'mixed'), payloadGraph(128, 'mixed')), true);
      return 1;
    } };
    assert.equal(compare(payloadGraph(128, 'mixed', a), payloadGraph(128, 'mixed')), true);
  }
});

function iteratorScenario(stage, completion, closing, kind) {
  const vm = require('node:vm');
  const realm = vm.createContext({ __franken_util_type_tag: typeTag, TextEncoder, TextDecoder,
    stage, completion, closing, kind });
  vm.runInContext(`
    var log=[], thrown={}, closingError={}, escaped, result, caught=false;
    var a={get value(){log.push('compare');if(completion==='throw')throw thrown;return 1;}};
    var b={value:completion==='false'?2:1};
    var left=kind==='Map'?new Map([['x',a]]):new Set([a]);
    var right=kind==='Map'?new Map([['x',b]]):new Set([b]);
    var Type=kind==='Map'?Map:Set, name=kind==='Map'?'entries':'values';
    var native=Type.prototype[name], labels=new WeakMap();
    Type.prototype[name]=function(){var i=Reflect.apply(native,this,[]);labels.set(i,this===left?'L':'R');return i;};
    var proto=Object.getPrototypeOf(Reflect.apply(native,left,[])), nativeNext=proto.next;
    function nest(value){for(var i=0;i<80;i++)value={child:value};return value;}
  `, realm);
  vm.runInContext('var api=' + source + ';', realm);
  vm.runInContext(`
    Type.prototype[name]=native;
    Object.defineProperty(proto,Symbol.iterator,{configurable:true,get(){
      var label=labels.get(this);log.push(label+':iterator-get');
      return function(){log.push(label+':iterator');return this;};}});
    Object.defineProperty(proto,'next',{configurable:true,get(){
      var label=labels.get(this);log.push(label+':next-get');return function(){
        log.push(label+':next');if(label==='L'&&stage==='next')throw thrown;
        var item=Reflect.apply(nativeNext,this,[]);
        if(label==='L'&&stage==='result')return null;
        return {get done(){log.push(label+':done');if(label==='L'&&stage==='done')throw thrown;return item.done;},
          get value(){log.push(label+':value');if(label==='L'&&stage==='value')throw thrown;return item.value;}};
      };}});
    Object.defineProperty(proto,'return',{configurable:true,get(){
      var label=labels.get(this);log.push(label+':return-get');
      if(closing==='getter-throws')throw closingError;if(closing==='null')return null;if(closing==='noncallable')return 1;
      return function(){log.push(label+':return');if(closing==='throws')throw closingError;
        return closing==='primitive'?1:closing==='function'?function(){}:{};};}});
    try{result=api.isDeepStrictEqual(nest(left),nest(right));}
    catch(e){caught=true;escaped=e===thrown?'original':e===closingError?'closing':e.name;}
  `, realm);
  return JSON.parse(vm.runInContext('JSON.stringify({result,caught,escaped,log})', realm));
}
test('iterative early mismatch closes Map and Set iterators with normal-completion rules', () => {
  for (const kind of ['Map', 'Set']) for (const closing of ['object', 'function', 'primitive', 'throws', 'getter-throws', 'null', 'noncallable']) {
    const got = iteratorScenario('body', 'false', closing, kind);
    const failure = closing === 'primitive' || closing === 'noncallable' ? 'TypeError'
      : closing === 'throws' || closing === 'getter-throws' ? 'closing' : undefined;
    assert.equal(got.escaped, failure, `${kind} ${closing}`);
    assert.equal(got.caught, failure !== undefined);
    if (!got.caught) assert.equal(got.result, false);
    assert.equal(got.log.filter(x => x === 'L:return-get').length, 1);
    assert.equal(got.log.filter(x => x === 'R:return-get').length, 0);
    assert.equal(got.log.filter(x => x === 'L:next-get').length, 1);
  }
});
test('iteration failures do not close the failing iterator and body throws win over close errors', () => {
  for (const kind of ['Map', 'Set']) for (const closing of ['primitive', 'throws', 'getter-throws', 'noncallable', 'object']) {
    for (const stage of ['next', 'done', 'value', 'result', 'body']) {
      const got = iteratorScenario(stage, 'throw', closing, kind);
      assert.equal(got.escaped, stage === 'result' ? 'TypeError' : 'original');
      assert.equal(got.log.filter(x => x === 'L:return-get').length, stage === 'body' ? 1 : 0);
    }
  }
});
test('exhausting the live iterator never consults its return method', () => {
  for (const kind of ['Map', 'Set']) {
    const got = iteratorScenario('body', 'true', 'getter-throws', kind);
    assert.equal(got.result, true);
    assert.equal(got.caught, false);
    assert.equal(got.log.filter(x => x.includes('return')).length, 0);
    assert.equal(got.log.filter(x => x === 'L:next-get').length, 1);
  }
});
test('private collection continuation fields do not invoke inherited named setters', () => {
  const vm = require('node:vm');
  const realm = vm.createContext({ __franken_util_type_tag: typeTag, TextEncoder, TextDecoder });
  vm.runInContext('var api=' + source + ';', realm);
  vm.runInContext(`
    var left=new Map([['x',new Set([{value:1}])]]), right=new Map([['x',new Set([{value:1}])]]);
    for(var i=0;i<80;i++){left={child:left};right={child:right};}
    for(const key of ['iterator','next','entry','key','index','other','collection','phase']){
      Object.defineProperty(Object.prototype,key,{configurable:true,
        get(){throw new Error('private read '+key);},set(){throw new Error('private write '+key);}});
    }
    if(!api.isDeepStrictEqual(left,right))throw new Error('wrong comparison');
  `, realm);
});
test('mixed payload graph traversal has bounded host call-stack depth', () => {
  const saved = Error.stackTraceLimit;
  Error.stackTraceLimit = Infinity;
  const frames = [];
  try {
    for (const depth of [256, 2048, 8192]) {
      const leaf = { get value() { frames.push(new Error().stack.split('\n').length); return 1; } };
      assert.equal(eq(payloadGraph(depth, 'mixed', leaf), payloadGraph(depth, 'mixed')), true);
    }
  } finally { Error.stackTraceLimit = saved; }
  assert.ok(Math.max(...frames) - Math.min(...frames) < 20, JSON.stringify(frames));
  assert.ok(Math.max(...frames) < 512, 'payload depth must not become call depth');
  console.log(JSON.stringify({ payloadDepths: [256, 2048, 8192], hostStackFrames: frames }));
});
test('shared public payload fixture agrees with live Node at a portable depth', () => {
  const run = new Function(fixture + ';return verifyUtilPayloadWalk;')();
  assert.equal(run(eq, 96), 'util payload walk: collections, errors, retries, mutation, cycles');
  assert.equal(run(util.isDeepStrictEqual, 96), 'util payload walk: collections, errors, retries, mutation, cycles');
});
