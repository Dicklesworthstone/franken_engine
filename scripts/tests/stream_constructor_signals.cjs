'use strict';
// Execute the complete production Node-stream state machines, not Node's
// Readable/Writable implementation. Node supplies the language, EventEmitter,
// StringDecoder, AbortSignal and nextTick primitives. This is not Rust execution.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const events = require('node:events');
const decoder = require('node:string_decoder');
const node = require('node:stream');
const source = fs.readFileSync(process.env.STREAM_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_module.js'), 'utf8');
function load(dependencies) {
  const signals = [];
  const signalType = { prototype: AbortSignal.prototype, any(sources) {
    const signal = AbortSignal.any(sources); signals.push(signal); return signal;
  } };
  const stream = new Function('__franken_stream_events', '__franken_stream_string_decoder',
    '__franken_stream_next_tick', 'AbortSignal', 'return ' + source)(
      dependencies?.events || events, dependencies?.decoder || decoder,
      callback => process.nextTick(callback), signalType);
  return { stream, signals };
}
const candidate = load().stream;
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function observed(stream, t) {
  const errors = []; stream.on('error', error => errors.push(error));
  const closed = new Promise(resolve => stream.once('close', resolve));
  t.after(() => { if (!stream.destroyed) stream.destroy(); });
  return { errors, closed };
}
function aborted(error, reason) {
  assert.equal(error.name, 'AbortError'); assert.equal(error.code, 'ABORT_ERR');
  assert.equal(error.cause, reason);
}
for (const [label, io] of [['candidate', candidate], ['node', node]]) {
  for (const name of ['Readable', 'Writable', 'Duplex', 'Transform', 'PassThrough']) {
    test(`${label}: ${name} constructor owns later cancellation`, async t => {
      const controller = new AbortController(), reason = { marker: name };
      let destroyed = 0;
      const stream = new io[name]({
        signal: controller.signal,
        read() {}, write(chunk, encoding, callback) { callback(); },
        destroy(error, callback) { destroyed++; callback(error); }
      });
      const observation = observed(stream, t);
      assert(stream instanceof io[name]);
      controller.abort(reason);
      assert.equal(stream.destroyed, true);
      await observation.closed;
      assert.equal(destroyed, 1); assert.equal(observation.errors.length, 1);
      aborted(observation.errors[0], reason); aborted(stream.errored, reason);
      controller.abort('again'); stream.destroy(); assert.equal(destroyed, 1);
    });
    test(`${label}: ${name} pre-abort refuses reads and writes`, async t => {
      let destroys = 0, reads = 0, writes = 0;
      const stream = new io[name]({ signal: AbortSignal.abort(0),
        read() { reads++; }, write(chunk, encoding, callback) { writes++; callback(); },
        destroy(error, callback) { destroys++; callback(error); }
      });
      const observation = observed(stream, t);
      assert.equal(stream.destroyed, true);
      if (stream.read) stream.read(0);
      if (stream.write) stream.write('late', () => {});
      await observation.closed;
      assert.equal(reads, 0); assert.equal(writes, 0); assert.equal(destroys, 1);
      assert.equal(observation.errors.length, 1); aborted(observation.errors[0], 0);
    });
  }
  test(`${label}: abort waits for asynchronous construction before destruction`, async t => {
    const constructing = deferred(); const controller = new AbortController();
    const calls = []; let finishConstruct;
    const stream = new io.Writable({ signal: controller.signal,
      construct(callback) { calls.push('construct'); finishConstruct = callback; constructing.resolve(); },
      write(chunk, encoding, callback) { calls.push('write'); callback(); },
      destroy(error, callback) { calls.push('destroy'); callback(error); }
    });
    const observation = observed(stream, t);
    stream.write('never-written', () => calls.push('write-callback'));
    await constructing.promise; controller.abort(false);
    assert.equal(stream.destroyed, true); assert.deepEqual(calls, ['construct']);
    finishConstruct(); await observation.closed;
    assert(!calls.includes('write')); assert.equal(calls.filter(c => c === 'destroy').length, 1);
    aborted(observation.errors[0], false);
  });
  test(`${label}: successful non-auto-destroyed writable detaches cancellation`, async t => {
    const controller = new AbortController(); let bytes = '';
    const stream = new io.Writable({ signal: controller.signal, autoDestroy: false,
      write(chunk, encoding, callback) { bytes += chunk; callback(); }
    });
    const observation = observed(stream, t);
    const finished = new Promise(resolve => stream.once('finish', resolve));
    stream.end('complete'); await finished; controller.abort('too late'); await tick();
    assert.equal(bytes, 'complete'); assert.equal(stream.destroyed, false);
    assert.deepEqual(observation.errors, []);
  });
  test(`${label}: half-finished Duplex remains cancellable`, async t => {
    const controller = new AbortController();
    const stream = new io.Duplex({ signal: controller.signal, autoDestroy: false,
      read() {}, write(chunk, encoding, callback) { callback(); }
    });
    const observation = observed(stream, t);
    const finish = new Promise(resolve => stream.once('finish', resolve));
    stream.end('ok'); await finish;
    assert.equal(stream.readableEnded, false); controller.abort('other half');
    assert.equal(stream.destroyed, true); await observation.closed;
    aborted(observation.errors[0], 'other half');
  });
  test(`${label}: successful non-auto-destroyed readable detaches cancellation`, async t => {
    const controller = new AbortController();
    const stream = new io.Readable({ signal: controller.signal, autoDestroy: false,
      read() { this.push('complete'); this.push(null); } });
    const observation = observed(stream, t), chunks = [];
    const ended = new Promise(resolve => stream.once('end', resolve));
    stream.on('data', chunk => chunks.push(String(chunk))); await ended;
    controller.abort('late'); await tick();
    assert.deepEqual(chunks, ['complete']); assert.equal(stream.destroyed, false);
    assert.deepEqual(observation.errors, []);
  });
  test(`${label}: abort during finalization prevents a successful finish`, async t => {
    const controller = new AbortController(), finalizing = deferred();
    let finalCallback, finishes = 0;
    const stream = new io.Writable({ signal: controller.signal,
      write(chunk, encoding, callback) { callback(); },
      final(callback) { finalCallback = callback; finalizing.resolve(); } });
    const observation = observed(stream, t); stream.on('finish', () => finishes++);
    stream.end('accepted'); await finalizing.promise; controller.abort('final');
    assert.equal(stream.destroyed, true); await observation.closed;
    finalCallback(); await tick();
    assert.equal(finishes, 0); assert.equal(stream.writableFinished, false);
    aborted(observation.errors[0], 'final');
  });
  test(`${label}: Readable.from cancellation awaits producer cleanup`, async t => {
    const controller = new AbortController(), cleanup = deferred(), requested = deferred();
    let closes = 0, pulls = 0, next;
    const input = { [Symbol.asyncIterator]() { return this; },
      next() { pulls++; requested.resolve(); return new Promise(resolve => { next = resolve; }); },
      async return() { closes++; await cleanup.promise; return { done: true }; }
    };
    const stream = io.Readable.from(input, { signal: controller.signal });
    const observation = observed(stream, t); stream.resume(); await requested.promise;
    controller.abort('producer'); assert.equal(stream.destroyed, true);
    await tick(); assert.equal(closes, 1); assert.equal(stream.closed, false);
    next({ value: 'too-late', done: false }); cleanup.resolve(); await observation.closed;
    assert.equal(pulls, 1); assert.equal(closes, 1); assert.equal(stream.readableLength, 0);
    aborted(observation.errors[0], 'producer');
  });
  test(`${label}: source constructor abort stops the whole pipeline`, async t => {
    const controller = new AbortController(), accepted = deferred();
    let pulls = 0, finalized = false; const chunks = [];
    const input = new io.Readable({ signal: controller.signal,
      read() { if (pulls++ === 0) this.push('accepted'); }
    });
    const output = new io.Writable({ write(chunk, encoding, callback) {
      chunks.push(String(chunk)); callback(); accepted.resolve();
    }, final(callback) { finalized = true; callback(); } });
    observed(input, t); observed(output, t);
    const result = io.promises.pipeline(input, output).then(
      () => ({ success: true }), error => ({ error }));
    await accepted.promise; controller.abort(null);
    assert.equal(input.destroyed, true);
    const settled = await result; aborted(settled.error, null);
    assert.equal(output.destroyed, true); assert.equal(finalized, false);
    assert.deepEqual(chunks, ['accepted']);
  });
  test(`${label}: transform cancellation waits for asynchronous teardown`, async t => {
    const controller = new AbortController(), entered = deferred();
    let completeTransform, completeDestroy, settled = false, flushed = false;
    const source = io.Readable.from(['payload']);
    const transform = new io.Transform({ signal: controller.signal,
      transform(chunk, encoding, callback) { completeTransform = callback; entered.resolve(); },
      flush(callback) { flushed = true; callback(); },
      destroy(error, callback) { completeDestroy = () => callback(error); }
    });
    const written = [];
    const sink = new io.Writable({ write(chunk, encoding, callback) { written.push(String(chunk)); callback(); } });
    observed(source, t); observed(transform, t); observed(sink, t);
    const result = io.promises.pipeline(source, transform, sink).then(
      () => { settled = true; return { success: true }; },
      error => { settled = true; return { error }; });
    await entered.promise; controller.abort('transform');
    assert.equal(transform.destroyed, true); await tick(); assert.equal(settled, false);
    assert.equal(typeof completeDestroy, 'function'); completeDestroy();
    const outcome = await result; aborted(outcome.error, 'transform');
    completeTransform(null, 'late'); await tick();
    assert.deepEqual(written, []); assert.equal(flushed, false);
    assert(source.destroyed && transform.destroyed && sink.destroyed);
  });
  test(`${label}: ordinary pipeline still completes 4096 chunks`, async () => {
    const values = Array.from({ length: 4096 }, (_, i) => i), actual = [];
    const map = new io.Transform({ objectMode: true, transform(n, encoding, callback) { callback(null, n * 3); } });
    const sink = new io.Writable({ objectMode: true, write(n, encoding, callback) { actual.push(n); callback(); } });
    await io.promises.pipeline(io.Readable.from(values), map, sink);
    assert.deepEqual(actual, values.map(n => n * 3));
  });
}
test('candidate: private dependent signal is released on every terminal route', async t => {
  const { stream: io, signals } = load(); const controller = new AbortController();
  const writable = new io.Writable({ signal: controller.signal, autoDestroy: false,
    write(chunk, encoding, callback) { callback(); } });
  observed(writable, t); assert.equal(signals.length, 1);
  assert.equal(events.getEventListeners(signals[0], 'abort').length, 1);
  const finish = new Promise(resolve => writable.once('finish', resolve));
  writable.end(); await finish;
  assert.equal(events.getEventListeners(signals[0], 'abort').length, 0);
  assert.equal(signals[0].aborted, true); assert.equal(controller.signal.aborted, false);
  const duplex = new io.Duplex({ signal: controller.signal, read() {},
    write(chunk, encoding, callback) { callback(); } });
  const obs = observed(duplex, t); assert.equal(signals.length, 2, 'one owner for both sides');
  duplex.destroy(); await obs.closed;
  assert.equal(events.getEventListeners(signals[1], 'abort').length, 0);
  const silent = new io.Readable({ signal: controller.signal, emitClose: false, read() {} });
  silent.on('error', () => {}); silent.destroy(); await tick();
  assert.equal(events.getEventListeners(signals[2], 'abort').length, 0);
});
test('candidate: constructor validation does not start asynchronous acquisition', async () => {
  const { stream: io, signals } = load(); let constructs = 0;
  for (const name of ['Readable', 'Writable', 'Duplex', 'Transform', 'PassThrough']) {
    for (const signal of [{}, true, 1, 'not-a-signal']) {
      assert.throws(() => new io[name]({ signal, construct(callback) { constructs++; callback(); } }),
        { code: 'ERR_INVALID_ARG_TYPE' });
    }
  }
  await tick(); assert.equal(constructs, 0); assert.equal(signals.length, 0);
});
test('candidate: repeated successful streams release private listeners without aborting a shared signal', async () => {
  const { stream: io, signals } = load(); const controller = new AbortController();
  for (let i = 0; i < 1024; i++) {
    const stream = new io.Writable({ signal: controller.signal, autoDestroy: false,
      write(chunk, encoding, callback) { callback(); } });
    await new Promise(resolve => { stream.once('finish', resolve); stream.end('x'); });
    assert.equal(events.getEventListeners(signals[i], 'abort').length, 0);
    assert.equal(signals[i].aborted, true); stream.destroy();
  }
  assert.equal(controller.signal.aborted, false);
  assert.equal(events.getEventListeners(controller.signal, 'abort').length, 0);
});
test('candidate: synthetic public events cannot release cancellation ownership', async t => {
  const { stream: io, signals } = load(), controller = new AbortController();
  const stream = new io.Duplex({ signal: controller.signal, read() {}, write(x, e, cb) { cb(); } });
  const obs = observed(stream, t);
  stream.emit('end'); stream.emit('finish'); stream.emit('close');
  controller.signal.dispatchEvent(new Event('abort'));
  assert.equal(stream.destroyed, false);
  assert.equal(events.getEventListeners(signals[0], 'abort').length, 1);
  controller.abort('real'); assert.equal(stream.destroyed, true); await tick();
  aborted(obs.errors[0], 'real');
});
test('candidate: later public signal replacements and propagation cannot hide a real abort', async t => {
  const { stream: io } = load(), controller = new AbortController();
  controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
  const stream = new io.Readable({ signal: controller.signal, read() {} });
  const obs = observed(stream, t);
  Object.defineProperties(controller.signal, {
    aborted: { get() { throw Error('public aborted'); } },
    reason: { get() { throw Error('public reason'); } }
  });
  controller.abort(false);
  assert.equal(stream.destroyed, true); await obs.closed; aborted(obs.errors[0], false);
});
test('candidate: pre-aborted iterable closes before publishing completion', async t => {
  let next = 0, closed = 0;
  const stream = candidate.Readable.from({ [Symbol.iterator]() { return this; },
    next() { next++; return { value: 'never', done: false }; },
    return() { closed++; return { done: true }; }
  }, { signal: AbortSignal.abort('preflight') });
  const obs = observed(stream, t); assert.equal(stream.destroyed, true); await obs.closed;
  assert.equal(next, 0); assert.equal(closed, 1); aborted(obs.errors[0], 'preflight');
});
test('reference difference: Node 22.16 does not close a pre-aborted from iterator', async t => {
  let closed = 0;
  const stream = node.Readable.from({ [Symbol.iterator]() { return this; },
    next() { return { value: 'never', done: false }; }, return() { closed++; return { done: true }; }
  }, { signal: AbortSignal.abort('preflight') });
  const obs = observed(stream, t); await obs.closed;
  // This records the reference behavior separately; it is not a parity pass.
  assert.equal(closed, 0);
});
test('reference difference: constructor captures signal once; Node 22.16 reads it twice', async t => {
  for (const name of ['Readable', 'Writable', 'Duplex', 'Transform', 'PassThrough']) {
    for (const [io, expected] of [[candidate, 1], [node, 2]]) {
      let reads = 0;
      const signal = new AbortController().signal;
      const stream = new io[name]({ get signal() { reads++; return signal; },
        read() {}, write(x, e, callback) { callback(); } });
      const obs = observed(stream, t); assert.equal(reads, expected);
      stream.destroy(); await obs.closed;
    }
  }
});
test('host boundary: Node AbortSignal intrinsics accept proxy signals and inspect preexisting own properties', () => {
  // This documents the primitive supplied by this host test, not an engine
  // security guarantee. Native Rust accessor behavior must be tested natively.
  const signal = new AbortController().signal;
  const getter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
  assert.equal(Reflect.apply(getter, new Proxy(signal, {}), []), false);
  const failure = new Error('preexisting property');
  Object.defineProperty(signal, 'aborted', { get() { throw failure; } });
  assert.throws(() => AbortSignal.any([signal]), error => error === failure);
});
