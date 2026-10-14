'use strict';
// This executes the exact production factory on Node stream primitives, not
// FrankenEngine's parser, lowerer, native stream module or interpreter.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const native = require('node:stream');
const { finished, pipeline } = require('node:stream/promises');
const { setImmediate: tick } = require('node:timers/promises');
const sourcePath = process.env.STREAM_OPERATORS_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_operators.js');
const install = vm.runInThisContext(fs.readFileSync(sourcePath, 'utf8'), { filename: sourcePath });
class CandidateReadable extends native.Readable {}
CandidateReadable.from = function (input, options) {
  const result = native.Readable.from(input, options);
  Object.setPrototypeOf(result, CandidateReadable.prototype);
  return result;
};
class CandidateDuplex extends native.Duplex {}
// Never inherit the reference implementation of the feature under test.
const candidate = install({ ...native, Readable: CandidateReadable, Duplex: CandidateDuplex,
  duplexPair: undefined, addAbortSignal: undefined });
const timeout = { timeout: 2500 };
function cleanup(t, pair) { t.after(() => { for (const s of pair) s.destroy(); }); return pair; }
async function collect(stream) { const result = []; for await (const x of stream) result.push(x); return result; }
function closing(stream) { return new Promise(resolve => stream.once('close', resolve)); }

for (const [name, lane] of Object.entries({ candidate, node: native })) {
  test(name + ': symmetric object transport preserves identity and direction', timeout, async t => {
    const [a, b] = cleanup(t, lane.duplexPair({ objectMode: true }));
    assert(a instanceof lane.Duplex); assert(b instanceof lane.Duplex); assert.notEqual(a, b);
    assert.equal(a.allowHalfOpen, true); assert.equal(b.allowHalfOpen, true);
    const one = { value: 1 }, two = { value: 2 };
    const fromA = collect(b), fromB = collect(a);
    a.end(one); b.end(two);
    const [xs, ys] = await Promise.all([fromA, fromB]);
    assert.equal(xs.length, 1); assert.equal(ys.length, 1);
    assert.equal(xs[0], one); assert.equal(ys[0], two);
  });
  test(name + ': byte transport and multi-chunk UTF-8 decoding', timeout, async t => {
    const [a, b] = cleanup(t, lane.duplexPair({ highWaterMark: 2 }));
    b.setEncoding('utf8');
    const xs = collect(b), ys = collect(a);
    a.write(Buffer.from([0x61, 0xf0, 0x9f])); a.end(Buffer.from([0x98, 0x80, 0x62]));
    b.end(Buffer.from([0, 255, 128]));
    assert.equal((await xs).join(''), 'a😀b');
    assert.deepEqual(Buffer.concat(await ys), Buffer.from([0, 255, 128]));
  });
  test(name + ': buffered write acknowledgements wait for peer demand', timeout, async t => {
    const [a, b] = cleanup(t, lane.duplexPair({ objectMode: true, highWaterMark: 1 }));
    const callbacks = [];
    assert.equal(a.write(1, e => { assert.ifError(e); callbacks.push(1); }), false);
    assert.equal(a.write(2, e => { assert.ifError(e); callbacks.push(2); }), false);
    await tick();
    assert.deepEqual(callbacks, []); assert.equal(b.readableLength, 1);
    assert.equal(a.writableLength, 2);
    assert.equal(b.read(), 1); await tick();
    assert.deepEqual(callbacks, [1]); assert.equal(b.readableLength, 1);
    assert.equal(b.read(), 2); await tick();
    assert.deepEqual(callbacks, [1, 2]);
    const ended = Promise.all([finished(a), finished(b)]);
    a.resume(); b.resume(); a.end(); b.end(); await ended;
  });
  test(name + ': final completion waits for the peer end event', timeout, async t => {
    const [a, b] = cleanup(t, lane.duplexPair());
    let endCallback = false;
    a.end('queued', () => { endCallback = true; });
    await tick();
    assert.equal(a.writableFinished, false); assert.equal(endCallback, false);
    // Consuming one readable half must not implicitly destroy its still-open
    // writable half, as ordinary Readable async-iterator cleanup would.
    const received = (async () => { const chunks = []; for await (const x of b.iterator({ destroyOnReturn: false })) chunks.push(x); return chunks; })();
    assert.equal(Buffer.concat(await received).toString(), 'queued');
    await tick();
    assert.equal(a.writableFinished, true); assert.equal(endCallback, true);
    assert.equal(a.readableEnded, false); assert.equal(b.writableFinished, false);
    const response = collect(a); b.end('reply');
    assert.equal(Buffer.concat(await response).toString(), 'reply');
  });
  test(name + ': no-half-open peers complete after a single end', timeout, async t => {
    const [a, b] = cleanup(t, lane.duplexPair({ allowHalfOpen: false }));
    const completion = Promise.all([finished(a), finished(b)]);
    const xs = collect(a), ys = collect(b);
    a.end('x');
    assert.equal(Buffer.concat(await ys).toString(), 'x');
    assert.deepEqual(await xs, []); await completion;
  });
  test(name + ': pipelines carry simultaneous request and response streams', timeout, async t => {
    const [client, server] = cleanup(t, lane.duplexPair({ objectMode: true, highWaterMark: 1 }));
    const replies = [];
    const request = pipeline(native.Readable.from([1, 2, 3, 4]), client);
    const response = pipeline(server, new native.Transform({ objectMode: true,
      transform(value, encoding, done) { done(null, value * 10); } }), server);
    const receive = pipeline(client, new native.Writable({ objectMode: true,
      write(value, encoding, done) { replies.push(value); done(); } }));
    await Promise.all([request, response, receive]);
    assert.deepEqual(replies, [10, 20, 30, 40]);
  });
  test(name + ': synchronous read and write reentry neither duplicates nor drops chunks', timeout, async t => {
    const [a, b] = cleanup(t, lane.duplexPair({ objectMode: true, highWaterMark: 1 }));
    const received = [], replies = [], callbacks = [];
    b.on('data', value => {
      received.push(value); b.write(value + 100);
      if (value < 9) a.write(value + 1, error => { assert.ifError(error); callbacks.push(value + 1); });
      else { a.end(); b.end(); }
    });
    a.on('data', value => replies.push(value));
    const done = Promise.all([finished(a), finished(b)]);
    a.write(0, error => { assert.ifError(error); callbacks.push(0); });
    await done;
    assert.deepEqual(received, Array.from({ length: 10 }, (_, i) => i));
    assert.deepEqual(replies, Array.from({ length: 10 }, (_, i) => i + 100));
    assert.deepEqual(callbacks.slice().sort((a, b) => a - b), received);
  });
  test(name + ': each endpoint independently receives ordinary Duplex options', timeout, async t => {
    const [a, b] = cleanup(t, lane.duplexPair({ readableHighWaterMark: 3, writableHighWaterMark: 5,
      readableObjectMode: true, writableObjectMode: true, allowHalfOpen: false }));
    for (const stream of [a, b]) {
      assert.equal(stream.readableHighWaterMark, 3); assert.equal(stream.writableHighWaterMark, 5);
      assert.equal(stream.readableObjectMode, true); assert.equal(stream.writableObjectMode, true);
      assert.equal(stream.allowHalfOpen, false);
    }
    a.resume(); b.resume(); const end = Promise.all([finished(a), finished(b)]); a.end(); await end;
  });
  test(name + ': option method overrides retain normal constructor semantics', timeout, async t => {
    const log = [];
    const [a, b] = cleanup(t, lane.duplexPair({ objectMode: true,
      read() { this.push(null); },
      write(value, encoding, done) { log.push(value); done(); },
      final(done) { log.push('final'); done(); }
    }));
    const done = Promise.all([finished(a), finished(b)]);
    a.resume(); b.resume(); a.end('a'); b.end('b'); await done;
    assert.deepEqual(log, ['a', 'final', 'b', 'final']);
  });
  test(name + ': invalid buffer options fail before a transport can be returned', timeout, () => {
    for (const options of [{ highWaterMark: -1 }, { readableHighWaterMark: -1 },
      { writableHighWaterMark: 'invalid' }]) {
      assert.throws(() => lane.duplexPair(options), { code: 'ERR_INVALID_ARG_VALUE' });
    }
  });
}

test('candidate: destroy releases both endpoints and every blocked write exactly once', timeout, async t => {
  const [a, b] = cleanup(t, candidate.duplexPair({ objectMode: true, highWaterMark: 1 }));
  const original = new Error('transport failed');
  const errors = [], completions = [];
  a.on('error', e => errors.push(e)); b.on('error', e => errors.push(e));
  const done = Promise.all([closing(a), closing(b)]);
  a.write(1, e => completions.push(['a1', e])); a.write(2, e => completions.push(['a2', e]));
  b.write(3, e => completions.push(['b', e]));
  a.destroy(original); a.destroy(new Error('late'));
  await done; await tick();
  assert.equal(completions.length, 3);
  for (const [, e] of completions) assert.equal(e, original);
  assert.deepEqual(errors, [original, original]);
  assert(a.destroyed && b.destroyed);
});
test('candidate: destroy retires end observers without waiting for unread EOF', timeout, async t => {
  const [a, b] = cleanup(t, candidate.duplexPair({ autoDestroy: false }));
  let ended = 0, finalError;
  a.end('unread', error => { ended++; finalError = error; });
  assert.equal(b.listenerCount('end'), 1);
  const done = Promise.all([closing(a), closing(b)]);
  a.destroy(); await done; await tick();
  assert.equal(b.listenerCount('end'), 0); assert.equal(ended, 1);
  assert.equal(finalError.code, 'ERR_STREAM_DESTROYED');
});
test('candidate: replacing the public Duplex export cannot replace the transport constructor', timeout, async t => {
  const original = candidate.Duplex;
  candidate.Duplex = function () { throw new Error('public constructor replacement'); };
  let pair;
  try { pair = cleanup(t, candidate.duplexPair()); }
  finally { candidate.Duplex = original; }
  assert(pair[0] instanceof original); assert(pair[1] instanceof original);
  const done = Promise.all(pair.map(stream => finished(stream)));
  pair[0].resume(); pair[1].resume(); pair[0].end(); pair[1].end(); await done;
});
