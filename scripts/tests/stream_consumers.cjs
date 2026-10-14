'use strict';
// Executes the complete production consumer source over Node's realm primitives,
// beside the live Node module. This is not native FrankenEngine execution.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { Readable } = require('node:stream');
const native = require('node:stream/consumers');
const source = fs.readFileSync(path.join(__dirname, '../../crates/franken-engine/src/lowering_pipeline/stream_consumers.js'), 'utf8');
const fresh = () => vm.runInThisContext(source, { filename: 'stream_consumers.js' });
const candidate = fresh();
const lanes = { candidate, node: native };
const timeout = { timeout: 3000 };
const tick = () => new Promise(resolve => setImmediate(resolve));

for (const [name, consumers] of Object.entries(lanes)) {
  test(`${name}: exact public exports and empty results`, timeout, async () => {
    assert.deepEqual(Object.keys(consumers), ['arrayBuffer', 'blob', 'buffer', 'text', 'json']);
    assert.equal((await consumers.arrayBuffer([])).byteLength, 0);
    const blob = await consumers.blob([]);
    assert(blob instanceof Blob); assert.equal(blob.size, 0); assert.equal(blob.type, '');
    const buffer = await consumers.buffer([]);
    assert(Buffer.isBuffer(buffer)); assert.equal(buffer.length, 0);
    assert.equal(await consumers.text([]), '');
    await assert.rejects(consumers.json([]), SyntaxError);
    for (const fn of Object.values(consumers)) assert.equal(fn.length, 1);
  });
  test(`${name}: binary collection respects view byte windows`, timeout, async () => {
    const bytes = Uint8Array.from([99, 65, 66, 67, 68, 88]);
    const chunks = [new DataView(bytes.buffer, 1, 2), bytes.subarray(3, 5), '\u{1f600}'];
    const expected = Buffer.concat([Buffer.from('ABCD'), Buffer.from('\u{1f600}')]);
    assert.deepEqual(Buffer.from(await consumers.arrayBuffer(chunks)), expected);
    assert.deepEqual(await consumers.buffer(chunks), expected);
    const result = await consumers.blob(chunks);
    assert.deepEqual(Buffer.from(await result.arrayBuffer()), expected);
    bytes.fill(0);
    assert.deepEqual(Buffer.from(await result.arrayBuffer()), expected);
  });
  test(`${name}: all typed-array and DataView chunks use bytes not element values`, timeout, async () => {
    for (const Type of [Uint8Array, Uint8ClampedArray, Int8Array, Uint16Array, Int16Array,
      Uint32Array, Int32Array, Float32Array, Float64Array, BigInt64Array, BigUint64Array, DataView]) {
      const storage = new ArrayBuffer(32);
      const view = new Type(storage, 8, Type === DataView ? 8 : 8 / Type.BYTES_PER_ELEMENT);
      new Uint8Array(storage).set(Buffer.from('abcdefgh'), 8);
      assert.deepEqual(await consumers.buffer([view]), Buffer.from('abcdefgh'), Type.name);
      assert.equal(await consumers.text([view]), 'abcdefgh', Type.name);
    }
  });
  test(`${name}: Blob chunks, ArrayBuffers and object coercion`, timeout, async () => {
    const input = [new Blob(['hello']), new Uint8Array([33]).buffer, 123, null, undefined];
    assert.equal(await (await consumers.blob(input)).text(), 'hello!123nullundefined');
    assert.equal((await consumers.buffer(input)).toString(), 'hello!123nullundefined');
    const otherRealm = vm.runInNewContext('new Uint8Array([65, 66]).subarray(1)');
    assert.equal((await consumers.buffer([otherRealm])).toString(), 'B');
  });
  test(`${name}: fragmented UTF-8, BOM and malformed final bytes`, timeout, async () => {
    const text = 'A\u00e9\u4e2d\u{1f600}\u0000Z';
    const input = Buffer.from(text);
    for (let split = 0; split <= input.length; split++) {
      assert.equal(await consumers.text([input.subarray(0, split), input.subarray(split)]), text);
    }
    assert.equal(await consumers.text([Buffer.from([0xef]), Buffer.from([0xbb]), Buffer.from([0xbf, 97])]), 'a');
    assert.equal(await consumers.text(['\ufeffa']), '\ufeffa');
    assert.equal(await consumers.text([Buffer.from([0xf0, 0x9f])]), '\ufffd');
    assert.equal(await consumers.text([Buffer.from([0xff, 65, 0xc0, 0xaf])]), '\ufffdA\ufffd\ufffd');
  });
  test(`${name}: strings preserve decoder state across later binary chunks`, timeout, async () => {
    assert.equal(await consumers.text([Buffer.from([0xf0, 0x9f]), 'middle', Buffer.from([0x98, 0x80])]), 'middle\u{1f600}');
    assert.equal(await consumers.text(['a\ud800', Buffer.from('b')]), 'a\ud800b');
  });
  test(`${name}: sync/async iterables, promises and real Readables`, timeout, async () => {
    assert.equal(await consumers.text('abc'), 'abc');
    assert.equal(await consumers.text([Promise.resolve('a'), Promise.resolve(Buffer.from('b'))]), 'ab');
    async function* chunks() { yield 'a'; await tick(); yield Buffer.from('b'); }
    assert.equal(await consumers.text(chunks()), 'ab');
    const stream = Readable.from([Buffer.from('a'), Buffer.from('b')]);
    assert.equal((await consumers.buffer(stream)).toString(), 'ab');
    assert.equal(stream.destroyed, true);
    const retained = Readable.from(['ok'], { autoDestroy: false });
    assert.equal(await consumers.text(retained), 'ok');
    assert.equal(retained.destroyed, false); retained.destroy();
  });
  test(`${name}: source errors preserve identity with no partial result`, timeout, async () => {
    for (const method of ['arrayBuffer', 'blob', 'buffer', 'text', 'json']) {
      const boom = new Error(method); let closed = 0;
      async function* chunks() { try { yield 'a'; throw boom; } finally { closed++; } }
      await assert.rejects(consumers[method](chunks()), e => e === boom);
      assert.equal(closed, 1);
    }
  });
  test(`${name}: decode failure closes a suspended upstream generator`, timeout, async () => {
    let closed = 0;
    async function* chunks() { try { yield Buffer.from('a'); yield {}; yield 'not consumed'; } finally { closed++; } }
    await assert.rejects(consumers.text(chunks()), TypeError);
    assert.equal(closed, 1);
  });
  test(`${name}: JSON decodes bytes and propagates syntax errors`, timeout, async () => {
    const input = Buffer.from('\ufeff{"word":"\u{1f600}","values":[1,true,null]}');
    assert.deepEqual(await consumers.json(Array.from(input, byte => Uint8Array.of(byte))),
      { word: '\u{1f600}', values: [1, true, null] });
    assert.deepEqual(await consumers.json(['null']), null);
    assert.equal(await consumers.json(['123']), 123);
    await assert.rejects(consumers.json(['{"broken":']), SyntaxError);
  });
  test(`${name}: invalid sources reject promises, not synchronous calls`, timeout, async () => {
    for (const method of Object.keys(consumers)) {
      for (const input of [null, undefined, 1, {}, { [Symbol.asyncIterator]: 1 }]) {
        let promise;
        assert.doesNotThrow(() => { promise = consumers[method](input); });
        await assert.rejects(promise, TypeError);
      }
    }
  });
  test(`${name}: one in-flight input request and highly fragmented output`, timeout, async () => {
    let active = 0, peak = 0, calls = 0;
    const input = { [Symbol.asyncIterator]() { return this; }, async next() {
      peak = Math.max(peak, ++active); await tick(); active--;
      return calls++ < 100 ? { value: Buffer.from('a'), done: false } : { done: true };
    } };
    assert.equal(await consumers.text(input), 'a'.repeat(100)); assert.equal(peak, 1);
    const count = 50000;
    function* fragmented() { for (let i = 0; i < count; i++) yield i % 2 ? '\u00e9' : 'a'; }
    assert.equal(await consumers.text(fragmented()), 'a\u00e9'.repeat(count / 2));
  });
}

test('candidate: captured decoder/parser and binary methods survive public replacement', timeout, async () => {
  const consumers = fresh();
  const original = [JSON.parse, TextDecoder.prototype.decode, Blob.prototype.arrayBuffer, Buffer.from];
  const fail = () => { throw Error('public replacement must not be called'); };
  // Use async generators so no platform stream machinery consults these
  // replaced functions. Restore before assertions or test-runner callbacks.
  let json, bytes;
  try {
    JSON.parse = fail; TextDecoder.prototype.decode = fail;
    Blob.prototype.arrayBuffer = fail; Buffer.from = fail;
    json = await consumers.json(['{"ok":true}']);
    bytes = await consumers.buffer(['abc']);
  } finally {
    [JSON.parse, TextDecoder.prototype.decode, Blob.prototype.arrayBuffer, Buffer.from] = original;
  }
  assert.deepEqual(json, { ok: true }); assert.equal(bytes.toString(), 'abc');
});

test('candidate: exported method replacement does not redirect another consumer', timeout, async () => {
  const consumers = fresh();
  consumers.text = consumers.blob = consumers.arrayBuffer = () => { throw Error('replaced export'); };
  assert.deepEqual(await consumers.json(['{"ok":true}']), { ok: true });
  assert.equal((await consumers.buffer(['abc'])).toString(), 'abc');
});
