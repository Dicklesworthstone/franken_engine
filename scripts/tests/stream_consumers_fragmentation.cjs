'use strict';
// Runs the actual production consumer factory with host codec/stream primitives.
// This is not execution of FrankenEngine's parser, interpreter, or codecs.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { Readable } = require('node:stream');
const { ReadableStream } = require('node:stream/web');
const reference = require('node:stream/consumers');
const filename = process.argv[2] || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_consumers.js');
const source = fs.readFileSync(filename, 'utf8');

function candidate(Decoder = TextDecoder) {
  const stats = { pushes: 0, joins: 0, maxArrayLength: 0, maxJoinInputUnits: 0, totalJoinInputUnits: 0 };
  const context = vm.createContext({ Blob, Buffer, TextDecoder: Decoder,
    observePush(length) { stats.pushes++; stats.maxArrayLength = Math.max(stats.maxArrayLength, length); },
    observeJoin(length, units) {
      stats.joins++; stats.totalJoinInputUnits += units; stats.maxJoinInputUnits = Math.max(stats.maxJoinInputUnits, units);
    }
  });
  vm.runInContext(`(() => {
    const push = Array.prototype.push, join = Array.prototype.join;
    const apply = Reflect.apply, pushed = observePush, joined = observeJoin;
    Array.prototype.push = function (...args) {
      const result = apply(push, this, args); pushed(this.length); return result;
    };
    Array.prototype.join = function (...args) {
      let units = 0;
      for (let i = 0; i < this.length; i++) if (typeof this[i] === 'string') units += this[i].length;
      joined(this.length, units); return apply(join, this, args);
    };
  })()`, context);
  return { api: vm.runInContext(source, context, { filename }), stats };
}
const sleep = () => new Promise(resolve => setImmediate(resolve));
const tests = [];
const measurements = {};
function test(name, run) { tests.push({ name, run }); }
async function compare(make, operation = 'text') {
  const { api } = candidate();
  const actual = await api[operation](make());
  const expected = await reference[operation](make());
  if (operation === 'json') assert.equal(JSON.stringify(actual), JSON.stringify(expected));
  else assert.deepEqual(actual, expected);
  return actual;
}
function* repeated(value, count) { for (let i = 0; i < count; i++) yield value; }
function chunked(bytes, size) {
  return (async function* () {
    for (let offset = 0; offset < bytes.length; offset += size) yield bytes.subarray(offset, offset + size);
  })();
}

test('empty inputs and mixed empty chunks produce no retained fragments', async () => {
  const snapshots = [];
  measurements.empty = {};
  for (const [name, reads, make] of [
    ['noInput', 0, () => []],
    ['strings', 32768, () => repeated('', 32768)],
    ['byteViews', 32768, () => repeated(new Uint8Array(0), 32768)]
  ]) {
    const { api, stats } = candidate();
    assert.equal(await api.text(make()), '');
    assert.equal(await reference.text(make()), '');
    measurements.empty[name] = { reads, ...stats };
    snapshots.push(stats);
  }
  for (const stats of snapshots) {
    assert.equal(stats.pushes, 0, 'zero-output input must not grow collector arrays');
  }
});
test('one-byte input has bounded fragment metadata and matches Node', async () => {
  const { api, stats } = candidate();
  const count = 65536;
  assert.equal(await api.text(repeated('x', count)), 'x'.repeat(count));
  assert.equal(await reference.text(repeated('x', count)), 'x'.repeat(count));
  measurements.oneByte = { reads: count, ...stats };
  assert.ok(stats.maxArrayLength <= count / 64, JSON.stringify(stats));
});
test('every UTF-8 split retains exact BOM, scalar and replacement semantics', async () => {
  const bytes = Buffer.from([0xef, 0xbb, 0xbf, 65, 0xf0, 0x9f, 0x98, 0x80,
    0xe2, 0x82, 0xac, 0xff, 0xe2, 0x82]);
  for (let split = 0; split <= bytes.length; split++) {
    const value = await compare(() => [bytes.subarray(0, split), '', bytes.subarray(split)]);
    assert.equal(value, 'A😀€��');
  }
});
test('pending UTF-8 state is not flushed by strings or batch boundaries', async () => {
  const value = await compare(() => [Buffer.from([0xe2]), ...Array(128).fill('x'),
    new Uint8Array(0), Buffer.from([0x82]), 'y', Buffer.from([0xac])]);
  assert.equal(value, 'x'.repeat(128) + 'y€');
});
test('surrogate string chunks preserve exact UTF-16 across batches', async () => {
  const value = await compare(() => [...Array(63).fill('x'), '\ud83d', '\ude00', '\ud800',
    ...Array(64).fill(''), '\udfff']);
  assert.equal(value, 'x'.repeat(63) + '\ud83d\ude00\ud800\udfff');
});
test('large strings avoid intermediate joins and keep small prefix/suffix order', async () => {
  const huge = '😀'.repeat(32768);
  const { api, stats } = candidate();
  assert.equal(await api.text(['a', 'b', huge, 'c', 'd']), 'ab' + huge + 'cd');
  assert.ok(stats.totalJoinInputUnits <= huge.length + 8, 'large payload must not join twice');
  assert.equal(await reference.text(['a', 'b', huge, 'c', 'd']), 'ab' + huge + 'cd');
});
test('byte-view offsets and reusable producer buffers are read before advancement', async () => {
  function* make() {
    const data = new Uint8Array([120, 65, 66, 120]);
    yield new DataView(data.buffer, 1, 2);
    data[1] = 67; data[2] = 68;
    yield new Uint8Array(data.buffer, 1, 2);
    data[1] = 69;
  }
  assert.equal(await compare(make), 'ABCD');
});
test('ArrayBuffer and every supported view use their byte windows', async () => {
  const types = [Uint8Array, Uint8ClampedArray, Int8Array, Uint16Array, Int16Array,
    Uint32Array, Int32Array, Float32Array, Float64Array, BigInt64Array, BigUint64Array, DataView];
  for (const Type of types) {
    await compare(() => {
      const data = new Uint8Array(32); data.fill(65);
      return [Type === DataView ? new DataView(data.buffer, 8, 8) : new Type(data.buffer, 8, 8 / Type.BYTES_PER_ELEMENT)];
    });
  }
  assert.equal(await compare(() => [new Uint8Array([65, 66]).buffer]), 'AB');
});
test('Node readable streams and Web byte streams share identical text output', async () => {
  const bytes = Buffer.from('a😀b€c'.repeat(256));
  assert.equal(await compare(() => Readable.from(chunked(bytes, 1))), bytes.toString());
  assert.equal(await compare(() => {
    let offset = 0;
    return new ReadableStream({ type: 'bytes', pull(c) {
      if (offset === bytes.length) c.close(); else c.enqueue(Uint8Array.of(bytes[offset++]));
    } });
  }), bytes.toString());
});
test('json uses the same batching without changing numbers or Unicode', async () => {
  const value = JSON.stringify({ values: Array.from({ length: 512 }, (_, i) => i), name: '😀€' });
  const actual = await compare(() => chunked(Buffer.from(value), 1), 'json');
  assert.equal(actual.name, '😀€');
  assert.equal(actual.values.length, 512);
});
test('invalid JSON still rejects after the source is exhausted', async () => {
  for (const api of [candidate().api, reference]) {
    let exhausted = false;
    async function* input() { yield '{"a":'; exhausted = true; }
    await assert.rejects(api.json(input()), error => error.name === 'SyntaxError');
    assert.equal(exhausted, true);
  }
});
test('decoder failures close input exactly once without a second flush', async () => {
  for (const api of [candidate().api, reference]) {
    let closed = 0;
    async function* input() { try { yield 'x'; yield {}; yield 'unreachable'; } finally { closed++; } }
    await assert.rejects(api.text(input()), error => error.name === 'TypeError');
    assert.equal(closed, 1);
  }
});
test('source failures retain exact falsy and object identity', async () => {
  for (const reason of [undefined, null, false, 0, Symbol('reason'), {}]) {
    for (const api of [candidate().api, reference]) {
      let received = false;
      async function* input() { yield 'prefix'; throw reason; }
      await api.text(input()).then(() => assert.fail('source failure must reject'), error => {
        assert.equal(error, reason); received = true;
      });
      assert.equal(received, true);
    }
  }
});
test('concurrent consumers never share fragments or decoder state', async () => {
  const { api } = candidate();
  async function* a() { yield Buffer.from([0xe2]); await sleep(); yield Buffer.from([0x82, 0xac]); }
  async function* b() { yield 'X'; await sleep(); yield Buffer.from([0xf0, 0x9f, 0x98, 0x80]); }
  assert.deepEqual(await Promise.all([api.text(a()), api.text(b())]), ['€', 'X😀']);
});
test('captured array helpers ignore replacement after initialization', async () => {
  const context = vm.createContext({ Blob, Buffer, TextDecoder });
  const api = vm.runInContext(source, context, { filename });
  vm.runInContext(`Array.prototype.push = Array.prototype.join = function () { throw Error('replaced'); };`, context);
  assert.equal(await api.text(repeated('x', 257)), 'x'.repeat(257));
});
test('a replaced decoder returning objects retains deferred coercion', async () => {
  const events = [];
  class Decoder {
    decode(input) {
      if (input === undefined) return '';
      const name = input[0]; events.push('decode:' + name);
      return { get length() { throw Error('length inspected'); },
        toString() { events.push('coerce:' + name); return String(name); } };
    }
  }
  const { api } = candidate(Decoder);
  async function* input() {
    events.push('pull:1'); yield Uint8Array.of(1); yield 'x'; yield 'y';
    events.push('pull:2'); yield Uint8Array.of(2); events.push('done');
  }
  assert.equal(await api.text(input()), '1xy2');
  assert.deepEqual(events, ['pull:1', 'decode:1', 'pull:2', 'decode:2', 'done', 'coerce:1', 'coerce:2']);
});
test('every native decode receives fresh stream options and final flush is last', async () => {
  const calls = [], seen = new Set();
  class Decoder {
    decode(input, options) {
      if (input === undefined) { calls.push('flush'); return '!'; }
      assert.equal(options.stream, true); assert.equal(seen.has(options), false);
      seen.add(options); options.stream = false; calls.push(input[0]); return '';
    }
  }
  const { api, stats } = candidate(Decoder);
  assert.equal(await api.text([Uint8Array.of(1), '', Uint8Array.of(2)]), '!');
  assert.deepEqual(calls, [1, 2, 'flush']);
  assert.ok(stats.maxArrayLength <= 1);
});
test('binary consumers retain their existing bytes and return types', async () => {
  for (const api of [candidate().api, reference]) {
    assert.equal((await api.blob(['a', Uint8Array.of(98)])).size, 2);
    assert.deepEqual([...new Uint8Array(await api.arrayBuffer(['a', Uint8Array.of(98)]))], [97, 98]);
    const value = await api.buffer(['a', Uint8Array.of(98)]);
    assert.equal(Buffer.isBuffer(value), true); assert.equal(value.toString(), 'ab');
  }
});


test('seeded arbitrary byte and string fragmentation agrees with live Node', async () => {
  let state = 0x5eed;
  function random() { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state; }
  for (let run = 0; run < 64; run++) {
    const pieces = [];
    for (let index = 0; index < 257; index++) {
      if (random() % 3 === 0) pieces.push(['', 'x', '😀', '\ud800'][random() % 4]);
      else pieces.push(Uint8Array.from({ length: random() % 8 }, random));
    }
    await compare(() => pieces);
  }
});
test('exact native integration programs agree on both candidate and reference', async () => {
  const program = vm.runInThisContext(fs.readFileSync(path.resolve(__dirname,
    '../../crates/franken-engine/tests/fixtures/stream_consumer_fragmentation.js'), 'utf8'));
  for (let index = 0; index < 6; index++) {
    await program(candidate().api, index);
    await program(reference, index);
  }
});

let completed = false;
process.once('beforeExit', () => {
  if (!completed) { console.error('FAIL consumer suite did not settle'); process.exitCode = 1; }
});
(async () => {
  let failed = 0;
  for (const { name, run } of tests) {
    try { await run(); console.log('PASS ' + name); }
    catch (error) { failed++; console.error('FAIL ' + name, error); }
  }
  console.log(JSON.stringify({ node: process.version, source: filename, passed: tests.length - failed, failed, measurements }));
  completed = true;
  if (failed) process.exitCode = 1;
})().catch(error => { console.error(error); process.exitCode = 1; });
