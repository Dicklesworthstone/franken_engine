'use strict';
// Execute the production conversion factory on a Node host, not the Rust VM.
// Candidate prototypes never replace Node's oracle constructors. Function
// conversion delegates to the supplied core compose(), as it does in the VM.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const native = require('node:stream');
const { setImmediate: tick } = require('node:timers/promises');
const sourcePath = path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_operators.js');
const install = vm.runInThisContext(fs.readFileSync(sourcePath, 'utf8'), { filename: sourcePath });
class CandidateReadable extends native.Readable {}
CandidateReadable.from = function (input, options) {
  const stream = native.Readable.from(input, options);
  Object.setPrototypeOf(stream, CandidateReadable.prototype);
  return stream;
};
class CandidateDuplex extends native.Duplex {}
Object.defineProperty(CandidateDuplex, Symbol.hasInstance, {
  value: value => value instanceof native.Duplex
});
const candidate = install({ ...native, Readable: CandidateReadable, Duplex: CandidateDuplex });
const timeout = { timeout: 3000 };
function closed(stream) { return new Promise(resolve => stream.once('close', resolve)); }
function finished(stream) { return new Promise((resolve, reject) => stream.once('finish', resolve).once('error', reject)); }
async function collect(stream) { const values = []; for await (const value of stream) values.push(value); return values; }

for (const [name, lane] of Object.entries({ candidate, node: native })) {
  test(name + ': streams preserve identity; scalar and iterable sources remain readable', timeout, async () => {
    const existing = new native.PassThrough();
    assert.equal(lane.Duplex.from(existing), existing);
    existing.destroy();
    for (const [input, expected] of [
      [[1, Promise.resolve(2), 3], [1, 2, 3]], ['abc', ['abc']],
      [Buffer.from([0, 255]), [Buffer.from([0, 255])]],
      [new Uint8Array([1, 2]), [1, 2]], [[], []]
    ]) {
      const d = lane.Duplex.from(input);
      assert(d instanceof native.Duplex);
      assert.equal(d.writable, false);
      assert.deepEqual(await collect(d), expected);
    }
  });
  test(name + ': readable and writable halves are independent', timeout, async () => {
    const written = [];
    const w = new lane.Writable({ objectMode: true, write(x, encoding, done) { written.push(x); done(); } });
    const r = lane.Readable.from([7, 8]);
    const d = lane.Duplex.from({ readable: r, writable: w });
    const ending = finished(d);
    d.end(42);
    await ending;
    assert.equal(d.readableEnded, false, 'finishing writes must not consume reads');
    assert.deepEqual(await collect(d), [7, 8]);
    assert.deepEqual(written, [42]);
  });
  test(name + ': side-specific object modes and binary data are preserved', timeout, async () => {
    const w = new lane.Writable({ objectMode: true, write(x, e, done) { assert.equal(x.answer, 42); done(); } });
    const r = new lane.Readable({ read() { this.push(Buffer.from([0, 255])); this.push(null); } });
    const d = lane.Duplex.from({ readable: r, writable: w });
    assert.equal(d.readableObjectMode, false);
    assert.equal(d.writableObjectMode, true);
    const ending = finished(d); d.end({ answer: 42 });
    assert.deepEqual(Buffer.concat(await collect(d)), Buffer.from([0, 255]));
    await ending;
  });
  test(name + ': write callbacks and final wait for underlying completion', timeout, async () => {
    const pending = [];
    const received = [];
    let releaseFinal;
    const w = new lane.Writable({ objectMode: true, highWaterMark: 1,
      write(x, e, done) { received.push(x); pending.push(done); },
      final(done) { releaseFinal = done; }
    });
    const d = lane.Duplex.from(w);
    const callbacks = [];
    assert.equal(d.write(1, () => callbacks.push(1)), true);
    d.write(2, () => callbacks.push(2));
    const ending = finished(d); d.end();
    await tick();
    assert.deepEqual(received, [1]); assert.deepEqual(callbacks, []);
    pending.shift()(); await tick();
    assert.deepEqual(received, [1, 2]); assert.deepEqual(callbacks, [1]);
    pending.shift()(); await tick();
    assert.equal(d.writableFinished, false);
    assert.equal(typeof releaseFinal, 'function'); releaseFinal(); await ending;
    assert.deepEqual(callbacks, [1, 2]);
  });
  test(name + ': paused output does not eagerly exhaust the source', timeout, async () => {
    let pulled = 0;
    async function* values() { while (pulled < 10000) yield pulled++; }
    const r = lane.Readable.from(values(), { highWaterMark: 1 });
    const d = lane.Duplex.from(r); d.on('error', () => {});
    await tick(); await tick();
    assert(pulled <= 2, 'only source read-ahead before demand');
    const iterator = d[Symbol.asyncIterator]();
    assert.equal((await iterator.next()).value, 0);
    await tick();
    assert(pulled < 100, 'bounded read-ahead, not whole-source materialization');
    await iterator.return();
    assert.equal(r.destroyed, true);
  });
  test(name + ': error identity propagates and destroys the opposite endpoint', timeout, async () => {
    for (const side of ['readable', 'writable']) {
      const r = new lane.Readable({ objectMode: true, read() {} });
      const w = new lane.Writable({ objectMode: true, write(x, e, done) { done(); } });
      const d = lane.Duplex.from({ readable: r, writable: w });
      const error = new Error(side);
      const observed = new Promise(resolve => d.once('error', resolve));
      const closing = closed(d);
      (side === 'readable' ? r : w).destroy(error);
      assert.equal(await observed, error); await closing;
      // Node 22 may leave the opposite endpoint alive. The candidate's
      // stronger owned-cleanup contract is checked separately below.
      r.destroy(); w.destroy();
    }
  });
  test(name + ': premature underlying close is not successful EOF', timeout, async () => {
    const r = new lane.Readable({ read() {} });
    const w = new lane.Writable({ write(x, e, done) { done(); } });
    const d = lane.Duplex.from({ readable: r, writable: w });
    const error = new Promise(resolve => d.once('error', resolve));
    const closing = closed(d); r.destroy();
    assert.equal((await error).code, 'ERR_STREAM_PREMATURE_CLOSE'); await closing;
    w.destroy();
  });
  test(name + ': promise sources observe idle rejection and suppress late values after destroy', timeout, async () => {
    for (const [input, expected] of [[3, [3]], [null, []], [undefined, []]]) {
      assert.deepEqual(await collect(lane.Duplex.from(Promise.resolve(input))), expected);
    }
    const boom = new Error('rejected source');
    const d = lane.Duplex.from(Promise.reject(boom));
    const error = new Promise(resolve => d.once('error', resolve));
    const ending = closed(d); assert.equal(await error, boom); await ending;
    let resolve;
    const late = lane.Duplex.from(new Promise(done => { resolve = done; }));
    late.on('error', () => {}); const closing = closed(late);
    late.destroy(); await closing;
    resolve(42); await tick(); assert.equal(late.readableLength, 0);
  });
  test(name + ': malformed sources and null iterable entries fail explicitly', timeout, async () => {
    for (const source of [null, undefined, {}, 42, false]) {
      assert.throws(() => lane.Duplex.from(source), { code: 'ERR_INVALID_ARG_TYPE' });
    }
    await assert.rejects(collect(lane.Duplex.from([1, null])), { code: 'ERR_STREAM_NULL_VALUES' });
    const empty = lane.Duplex.from({ readable: null, writable: null });
    assert.equal(empty.readable, false); assert.equal(empty.writable, false); empty.destroy();
  });
  test(name + ': function transforms and sinks reuse the core composition owner', timeout, async () => {
    const transform = lane.Duplex.from(async function* (source) {
      for await (const x of source) yield x * 3;
    });
    const result = collect(transform); transform.write(2); transform.end(4);
    assert.deepEqual(await result, [6, 12]);
    const values = [];
    const sink = lane.Duplex.from(async source => { for await (const x of source) values.push(x); });
    const ending = finished(sink); sink.write('a'); sink.end('b'); await ending;
    assert.equal(sink.readable, false); assert.deepEqual(values, ['a', 'b']);
  });
}

test('candidate: waits for owned asynchronous destruction and completes callbacks once', timeout, async () => {
  let release;
  let closeCount = 0;
  let writeCount = 0;
  let lateWrite;
  const r = new candidate.Readable({ read() {}, destroy(error, done) { release = () => done(error); } });
  const w = new candidate.Writable({ write(x, e, done) { lateWrite = done; } });
  const d = candidate.Duplex.from({ readable: r, writable: w });
  const boom = new Error('stop'); d.on('error', error => assert.equal(error, boom));
  d.on('close', () => closeCount++);
  d.write('pending', error => { assert.equal(error, boom); writeCount++; });
  const closing = closed(d); d.destroy(boom);
  await tick(); assert.equal(closeCount, 0); assert.equal(writeCount, 1);
  release(); await closing;
  lateWrite(); await tick();
  assert.equal(writeCount, 1); assert.equal(closeCount, 1);
  for (const endpoint of [r, w]) {
    for (const event of ['readable', 'finish', 'end', 'error', 'close']) assert.equal(endpoint.listenerCount(event), 0, event);
  }
});
test('candidate: cyclic pair conversion fails boundedly without recursion overflow', timeout, () => {
  const pair = {}; pair.readable = pair;
  assert.throws(() => candidate.Duplex.from(pair), { code: 'ERR_INVALID_ARG_VALUE' });
});

// Unlike the Node 22 oracle, the product owns both endpoints after conversion.
// Refusal must not leave an opposite endpoint running after outer close.
test('candidate: failures close both admitted halves and release observers', timeout, async () => {
  for (const side of ['readable', 'writable']) {
    const r = new candidate.Readable({ read() {} });
    const w = new candidate.Writable({ write(x, e, done) { done(); } });
    const d = candidate.Duplex.from({ readable: r, writable: w });
    const boom = new Error(side); d.on('error', e => assert.equal(e, boom));
    const closing = closed(d); (side === 'readable' ? r : w).destroy(boom);
    await closing; assert(r.destroyed && w.destroyed);
    for (const endpoint of [r, w]) for (const event of ['end', 'finish', 'error', 'close', 'readable']) {
      assert.equal(endpoint.listenerCount(event), 0, event);
    }
  }
});
