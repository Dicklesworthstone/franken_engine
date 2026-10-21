'use strict';
// Execute the COMPLETE production factory, never Node's readline implementation
// as the candidate. Node supplies JS, EventEmitter, StringDecoder and signals.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const E = require('node:events');
const nodeReadline = require('node:readline');
const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(process.env.READLINE_SOURCE || path.join(root,
  'crates/franken-engine/src/lowering_pipeline/readline_module.js'), 'utf8');
const fixtureSource = fs.readFileSync(path.join(root,
  'crates/franken-engine/tests/fixtures/readline_fragmentation.js'), 'utf8');
function candidate() {
  const records = new Map();
  const metrics = { joins: 0, unitsJoined: 0, largestJoin: 0, nullRecords: 0 };
  class ObservedWeakMap extends WeakMap {
    set(key, value) {
      if (value && Object.hasOwn(value, 'fragments')) records.set(key, value);
      return super.set(key, value);
    }
  }
  const context = vm.createContext({
    __franken_readline_events: E,
    __franken_readline_decoder: require('node:string_decoder'),
    AbortController, AbortSignal, Symbol, WeakMap: ObservedWeakMap,
    observeCreate(prototype) { if (prototype === null) metrics.nullRecords++; },
    observeJoin(parts) {
      metrics.joins++;
      metrics.largestJoin = Math.max(metrics.largestJoin, parts.length);
      for (let i = 0; i < parts.length; i++) metrics.unitsJoined += parts[i].length;
    }
  });
  vm.runInContext(`{
    const originalCreate = Object.create;
    Object.create = function (prototype, descriptors) {
      observeCreate(prototype);
      return Reflect.apply(originalCreate, Object, [prototype, descriptors]);
    };
    const original = Array.prototype.join;
    Array.prototype.join = function (separator) {
      observeJoin(this);
      return Reflect.apply(original, this, [separator]);
    };
  }`, context);
  const api = vm.runInContext(source, context, { filename: 'production-readline.js' });
  return { api, records, metrics, context };
}
function sourceEmitter() {
  const input = new E();
  input.resume = function () { return this; };
  input.pause = function () { return this; };
  return input;
}
function open(api, options = {}) {
  const input = sourceEmitter();
  const rl = api.createInterface({ input, terminal: false, crlfDelay: Infinity, ...options });
  const lines = [];
  let closes = 0;
  rl.on('line', x => lines.push(x));
  rl.on('close', () => closes++);
  return { input, rl, lines, get closes() { return closes; } };
}
function collect(api, chunks, direct = false) {
  const run = open(api);
  for (const chunk of chunks) {
    if (direct) run.rl.write(chunk); else run.input.emit('data', chunk);
  }
  run.input.emit('end');
  assert.equal(run.closes, 1);
  assert.equal(run.input.listenerCount('data'), 0);
  return run.lines;
}
function parity(chunks, direct = false) {
  const got = collect(candidate().api, chunks, direct);
  assert.deepEqual(got, collect(nodeReadline, chunks, direct));
  return got;
}
function pending(record) {
  const q = record.fragments;
  let nodes = 0, units = 0;
  for (let node = q.head; node !== undefined; node = node.next) {
    nodes++; units += node.value.length;
  }
  const scratch = q.pending || [];
  for (let i = 0; i < scratch.length; i++) units += scratch[i].length;
  return { nodes, scratch: scratch.length, units };
}
test('every string split preserves UTF-16 and CR/LF ordering', () => {
  const text = '\r\naé\ud800🚀\rB\n\nC\r\nfinal';
  for (let split = 0; split <= text.length; split++) {
    assert.deepEqual(parity([text.slice(0, split), text.slice(split)]),
      collect(nodeReadline, [text.slice(0, split), text.slice(split)]));
  }
});
test('every two-cut UTF-8 split matches live Node', () => {
  const data = Buffer.from('aé🚀\r\n第二\nfinal');
  for (let a = 0; a <= data.length; a++) {
    for (let b = a; b <= data.length; b++) parity([data.subarray(0,a), data.subarray(a,b), data.subarray(b)]);
  }
});
test('empty-chunk CRLF behavior is unchanged, including Node quirks', () => {
  for (const empty of ['', Buffer.alloc(0), new Uint8Array(0)]) {
    parity(['first\r', empty, '\nsecond\r', empty, '\n']);
    parity(['first\r', empty, '\n'], true);
  }
});
test('all standard typed views use exact byte windows', () => {
  for (const Type of [Uint8Array, Uint8ClampedArray, Int8Array, Uint16Array, Int16Array,
    Uint32Array, Int32Array, Float32Array, Float64Array, BigInt64Array, BigUint64Array, DataView]) {
    const buffer = new ArrayBuffer(24);
    new Uint8Array(buffer).fill(88);
    new Uint8Array(buffer, 8, 8).set(Buffer.from('ab\r\ncd\r\n'));
    const view = Type === DataView ? new Type(buffer, 8, 8) : new Type(buffer, 8, 8 / Type.BYTES_PER_ELEMENT);
    assert.deepEqual(parity([view]), ['ab','cd']);
  }
});
test('EOF flushes unfinished batches on both sides of every batch boundary', () => {
  for (const count of [0,1,63,64,65,127,128,129,1023,1024,1025]) {
    const chunks = new Array(count).fill('x');
    assert.deepEqual(parity(chunks), count ? ['x'.repeat(count)] : []);
    parity([...chunks, '\n'], true);
  }
});
test('large strings bypass batching without changing output', () => {
  for (const length of [16383,16384,16385,32768]) {
    const large = 'L'.repeat(length);
    assert.deepEqual(parity(['a','b',large,'c','d','\n']), ['ab'+large+'cd']);
  }
});
test('incomplete UTF-8 at EOF keeps existing no-flush behavior', () => {
  for (const data of [[0xe2], [0xe2,0x82], [0x61,0xe2,0x82], [0xf0,0x9f,0x9a]]) {
    parity([Buffer.from(data)]);
  }
});
test('64 deterministic fragmentation patterns match live Node', () => {
  const data = Buffer.from(('é🚀\r\nA\rB\n尾\n').repeat(16));
  for (let seed = 1; seed <= 64; seed++) {
    let rng = seed, at = 0;
    const chunks = [];
    while (at < data.length) {
      rng = (Math.imul(rng, 1664525) + 1013904223) >>> 0;
      const end = Math.min(data.length, at + 1 + rng % 29);
      chunks.push(data.subarray(at,end)); at = end;
    }
    parity(chunks);
  }
});
test('fragment state contains exactly the unfinished line', () => {
  const c = candidate(), r = open(c.api);
  for (let n = 1; n <= 257; n++) {
    r.input.emit('data', '🚀');
    const state = pending(c.records.get(r.rl));
    assert.equal(state.units, n * 2);
    assert.ok(state.scratch < 64);
    assert.ok(state.nodes <= Math.floor(n / 64));
  }
  r.input.emit('data','\n');
  assert.deepEqual(pending(c.records.get(r.rl)), {nodes:0,scratch:0,units:0});
  r.input.emit('end');
});
test('65536 one-character chunks retain 1024 nodes, not one node per chunk', () => {
  const c = candidate(), r = open(c.api), reference = open(nodeReadline);
  const startingRecords = c.metrics.nullRecords;
  for (let n = 0; n < 65536; n++) { r.input.emit('data','x'); reference.input.emit('data','x'); }
  const before = pending(c.records.get(r.rl));
  const chunkRecords = c.metrics.nullRecords - startingRecords;
  assert.equal(before.units, 65536);
  assert.ok(before.nodes <= 1024, `linked nodes: ${before.nodes}`);
  assert.ok(before.scratch < 64);
  assert.equal(chunkRecords, 1024, 'no empty publication queue per chunk');
  r.input.emit('end'); reference.input.emit('end');
  assert.deepEqual(r.lines, reference.lines);
  assert.deepEqual(r.lines, ['x'.repeat(65536)]);
  assert.ok(c.metrics.unitsJoined <= 2 * 65536);
  console.log(JSON.stringify({ workload: '65536 single-character chunks', beforeFlush: before, chunkRecords, ...c.metrics }));
});
test('byte-by-byte UTF-8 does not retain decoder-empty output', () => {
  const c = candidate(), r = open(c.api), text = '🚀'.repeat(1024);
  for (const byte of Buffer.from(text)) r.input.emit('data', Buffer.from([byte]));
  const state = pending(c.records.get(r.rl));
  assert.equal(state.units, text.length);
  assert.ok(state.nodes <= 16);
  r.input.emit('end');
  assert.deepEqual(r.lines, [text]);
});
test('close releases pending and batched fragments without publishing them', () => {
  const c = candidate(), r = open(c.api);
  for (let n = 0; n < 70; n++) r.input.emit('data','x');
  r.rl.close();
  assert.equal(r.closes,1);
  assert.deepEqual(r.lines,[]);
  assert.deepEqual(pending(c.records.get(r.rl)),{nodes:0,scratch:0,units:0});
  assert.equal(r.input.listenerCount('data'),0);
});
test('empty fragments do not allocate empty publication queues', () => {
  const c = candidate(), r = open(c.api);
  const before = c.metrics.nullRecords;
  for (let n=0;n<4096;n++) r.input.emit('data','');
  assert.equal(c.metrics.nullRecords, before);
  assert.deepEqual(r.lines,[]);
  r.input.emit('end');
});
test('pause and close inside listeners retain the already-complete lines', () => {
  for (const action of ['pause','close']) {
    function run(api) {
      const r = open(api);
      r.rl.on('line', () => r.rl[action]());
      r.input.emit('data', 'a\nb\nc\n');
      r.rl.close();
      return r.lines;
    }
    assert.deepEqual(run(candidate().api),run(nodeReadline));
  }
});
test('listener exceptions preserve exact identity and subsequent buffered state', () => {
  for (const reason of [undefined,null,false,0,Symbol('failure'),{}]) {
    const c = candidate(), r = open(c.api);
    const listener = () => { throw reason; };
    r.rl.on('line',listener);
    let caught = false;
    try { r.input.emit('data','first\nsuffix'); } catch (error) { caught=true; assert.equal(error,reason); }
    assert.ok(caught);
    r.rl.removeListener('line',listener);
    r.input.emit('data','tail\n');
    assert.deepEqual(r.lines,['first','suffixtail']);
    r.input.emit('end');
  }
});
test('captured join cannot be replaced between fragments', () => {
  const c = candidate(), r = open(c.api);
  vm.runInContext('Array.prototype.join = function () { throw new Error("guest replacement"); };', c.context);
  for (let n=0; n<129; n++) r.input.emit('data','x');
  r.input.emit('end');
  assert.deepEqual(r.lines,['x'.repeat(129)]);
});
test('abort discards fragment storage without inventing a final line', () => {
  const c = candidate(), controller = new AbortController(), r = open(c.api,{signal:controller.signal});
  for (let n=0;n<129;n++) r.input.emit('data','secret');
  controller.abort(new Error('stop'));
  assert.equal(r.closes,1); assert.deepEqual(r.lines,[]);
  assert.deepEqual(pending(c.records.get(r.rl)),{nodes:0,scratch:0,units:0});
});
test('both APIs execute the exact shared native fixture', async () => {
  const fixture = vm.runInThisContext(fixtureSource+'\nverifyReadlineFragments');
  const got = await fixture(candidate().api, E);
  const expected = await fixture(nodeReadline, E);
  assert.equal(got, expected);
  assert.equal(got, 'readline fragmentation: content, EOF, UTF-16, UTF-8, reentry, question, iteration');
});
test('engine iterator return releases pending fragments without explicit close', async () => {
  const c = candidate(), r = open(c.api);
  const iterator = r.rl[Symbol.asyncIterator]();
  const first = iterator.next();
  r.input.emit('data','line\n');
  assert.equal((await first).value,'line');
  for (let n=0;n<129;n++) r.input.emit('data','pending');
  await iterator.return();
  assert.equal(r.closes,1);
  assert.deepEqual(pending(c.records.get(r.rl)),{nodes:0,scratch:0,units:0});
  assert.equal(r.input.listenerCount('data'),0);
});

test('inherited indexed getters and setters cannot observe private fragments', () => {
  for (const index of [0, 1, 63]) {
    const c = candidate(), r = open(c.api);
    vm.runInContext(`Object.defineProperty(Array.prototype, '${index}', {
      configurable: true,
      get() { throw new Error('private fragment read through prototype'); },
      set() { throw new Error('private fragment written through prototype'); }
    });`, c.context);
    for (let n = 0; n < 4097; n++) r.input.emit('data', 'x');
    r.input.emit('end');
    assert.deepEqual(r.lines, ['x'.repeat(4097)]);
    assert.equal(r.closes, 1);
    assert.equal(r.input.listenerCount('data'), 0);
  }
});

test('late prototype poisoning cannot alter an in-progress line or its final join', () => {
  const c = candidate(), r = open(c.api);
  for (let n = 0; n < 65; n++) r.input.emit('data', 'a');
  vm.runInContext(`Object.defineProperty(Array.prototype, '1', {
    configurable: true,
    get() { throw new Error('unexpected inherited read'); },
    set() { throw new Error('unexpected inherited write'); }
  }); Array.prototype[Symbol.iterator] = function () {
    throw new Error('private fragment iterator was used');
  };`, c.context);
  for (let n = 0; n < 128; n++) r.input.emit('data', 'b');
  r.input.emit('data', '\n');
  r.input.emit('end');
  assert.deepEqual(r.lines, ['a'.repeat(65) + 'b'.repeat(128)]);
});
