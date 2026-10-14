'use strict';
// Exact production JS factory on Node primitives. No native Rust execution.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const native = require('node:stream');
const { finished } = require('node:stream/promises');
const { setImmediate: tick } = require('node:timers/promises');
const sourcePath = process.env.STREAM_OPERATORS_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_operators.js');
const install = vm.runInThisContext(fs.readFileSync(sourcePath, 'utf8'), { filename: sourcePath });
class CandidateReadable extends native.Readable {}
class CandidateDuplex extends native.Duplex {}
const candidate = install({ ...native, Readable: CandidateReadable, Duplex: CandidateDuplex,
  duplexPair: undefined, addAbortSignal: undefined });
const timeout = { timeout: 2500 };
function close(stream) { return new Promise(resolve => stream.once('close', resolve)); }
function counts(stream) { return ['end', 'finish', 'close', 'error'].map(name => stream.listenerCount(name)); }

for (const [name, lane] of Object.entries({ candidate, node: native })) {
  test(name + ': abort preserves stream identity and exact reason as cause', timeout, async () => {
    const stream = new lane.Readable({ read() {} });
    const controller = new AbortController(), reason = { stop: 42 };
    const errors = [];
    stream.on('error', error => errors.push(error));
    const closed = close(stream);
    assert.equal(lane.addAbortSignal(controller.signal, stream), stream);
    controller.abort(reason); await closed;
    assert.equal(errors.length, 1); assert.equal(errors[0].name, 'AbortError');
    assert.equal(errors[0].code, 'ABORT_ERR'); assert.equal(errors[0].cause, reason);
  });
  test(name + ': a pre-aborted signal destroys without starting a read', timeout, async () => {
    let reads = 0;
    const stream = new lane.Readable({ read() { reads++; } });
    const controller = new AbortController(); controller.abort(false);
    const closed = close(stream), errors = [];
    stream.on('error', error => errors.push(error));
    assert.equal(lane.addAbortSignal(controller.signal, stream), stream);
    assert.equal(stream.destroyed, true); await closed;
    assert.equal(reads, 0); assert.equal(errors[0].cause, false);
  });
  test(name + ': a pending writable is destroyed with the abort reason', timeout, async () => {
    let complete;
    const errors = [], callbacks = [];
    const stream = new lane.Writable({ write(chunk, encoding, done) { complete = done; } });
    stream.on('error', error => errors.push(error));
    const controller = new AbortController(), closed = close(stream);
    lane.addAbortSignal(controller.signal, stream);
    stream.write('pending', error => callbacks.push(error));
    controller.abort('cancel'); await closed;
    // The underlying writer owns this completion, not the signal adapter.
    complete(); await tick();
    assert.equal(stream.destroyed, true); assert.equal(errors.length, 1);
    assert.equal(errors[0].cause, 'cancel'); assert.equal(callbacks.length, 1);
  });
  test(name + ': completed streams are not destroyed by a later abort', timeout, async () => {
    const stream = new lane.Readable({ autoDestroy: false, read() { this.push(null); } });
    const controller = new AbortController();
    lane.addAbortSignal(controller.signal, stream);
    const ended = finished(stream); stream.resume(); await ended; await tick();
    controller.abort('late'); await tick();
    assert.equal(stream.destroyed, false); stream.destroy();
  });
  test(name + ': finishing one duplex half does not detach the other', timeout, async () => {
    const stream = new lane.Duplex({ autoDestroy: false, read() {}, write(c, e, done) { done(); } });
    const errors = [], controller = new AbortController(), closed = close(stream);
    stream.on('error', error => errors.push(error));
    lane.addAbortSignal(controller.signal, stream);
    const ended = new Promise(resolve => stream.once('finish', resolve)); stream.end(); await ended;
    assert.equal(stream.readableEnded, false);
    controller.abort('remaining read'); await closed;
    assert.equal(errors.length, 1); assert.equal(errors[0].cause, 'remaining read');
  });
  test(name + ': repeated attachment and repeated abort destroy once', timeout, async () => {
    const errors = [], controllers = [new AbortController(), new AbortController()];
    let destroyed = 0;
    const stream = new lane.Readable({ read() {}, destroy(error, done) { destroyed++; done(error); } });
    stream.on('error', error => errors.push(error)); const closed = close(stream);
    for (const controller of controllers) lane.addAbortSignal(controller.signal, stream);
    controllers[1].abort('winner'); controllers[0].abort('late'); await closed;
    assert.equal(destroyed, 1); assert.equal(errors.length, 1); assert.equal(errors[0].cause, 'winner');
  });
}

test('candidate: suppressed public events cannot suppress native abort state', timeout, async () => {
  const controller = new AbortController(), stream = new candidate.Readable({ read() {} });
  controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
  const closed = close(stream), errors = [];
  stream.on('error', error => errors.push(error));
  candidate.addAbortSignal(controller.signal, stream);
  controller.signal.dispatchEvent(new Event('abort')); await tick();
  assert.equal(stream.destroyed, false);
  Object.defineProperty(controller.signal, 'aborted', { value: false });
  Object.defineProperty(controller.signal, 'reason', { value: 'forged' });
  controller.abort('native'); await closed;
  assert.equal(errors.length, 1); assert.equal(errors[0].cause, 'native');
});
test('candidate: synthetic stream terminal events do not revoke cancellation', timeout, async () => {
  const stream = new candidate.Readable({ read() {} }), controller = new AbortController();
  const errors = []; stream.on('error', error => errors.push(error));
  candidate.addAbortSignal(controller.signal, stream);
  stream.emit('end'); stream.emit('finish'); stream.emit('close');
  assert.equal(stream.destroyed, false);
  const closed = close(stream); controller.abort('actual'); await closed;
  assert.equal(errors[0].cause, 'actual');
});
test('candidate: emitClose:false destruction detaches even while cleanup is pending', timeout, async () => {
  let finishDestroy, destroys = 0;
  const stream = new candidate.Readable({ read() {}, emitClose: false,
    destroy(error, done) { destroys++; finishDestroy = done; } });
  const controller = new AbortController(), before = counts(stream), original = stream._destroy;
  candidate.addAbortSignal(controller.signal, stream);
  stream.destroy();
  assert.equal(stream._destroy, original); assert.deepEqual(counts(stream), before);
  controller.abort('after destruction'); await tick();
  assert.equal(destroys, 1); finishDestroy(); await tick();
});
test('candidate: success removes observers and restores destructor property shape', timeout, async () => {
  const stream = new candidate.Readable({ autoDestroy: false, read() { this.push(null); } });
  const controller = new AbortController();
  const descriptor = Object.getOwnPropertyDescriptor(stream, '_destroy');
  const completion = new Promise(resolve => stream.once('end', resolve));
  candidate.addAbortSignal(controller.signal, stream);
  stream.resume(); await completion; await tick();
  assert.equal(Object.getOwnPropertyDescriptor(stream, '_destroy'), descriptor);
  assert.deepEqual(counts(stream), [0, 0, 0, 0]);
  controller.abort('late'); assert.equal(stream.destroyed, false); stream.destroy();
});
test('candidate: setup refusal releases observers without destroying the stream', timeout, () => {
  assert.equal(typeof candidate.addAbortSignal, 'function');
  const stream = new candidate.Readable({ read() {} }), controller = new AbortController();
  const original = stream._destroy;
  Object.defineProperty(stream, '_destroy', { value: original, configurable: false, writable: false });
  const before = counts(stream);
  assert.throws(() => candidate.addAbortSignal(controller.signal, stream), TypeError);
  assert.deepEqual(counts(stream), before); assert.equal(stream._destroy, original);
  controller.abort('no attachment'); assert.equal(stream.destroyed, false); stream.destroy();
});
test('candidate: invalid arguments cannot attach listeners or trigger fake signals', timeout, () => {
  const stream = new candidate.Readable({ read() {} });
  try {
    for (const signal of [undefined, null, false, {}, { aborted: true }]) {
      assert.throws(() => candidate.addAbortSignal(signal, stream), { code: 'ERR_INVALID_ARG_TYPE' });
    }
    const controller = new AbortController();
    for (const value of [undefined, null, {}, 1, { destroy() {} }]) {
      assert.throws(() => candidate.addAbortSignal(controller.signal, value), { code: 'ERR_INVALID_ARG_TYPE' });
    }
    assert.deepEqual(counts(stream), [0, 0, 0, 0]);
  } finally { stream.destroy(); }
});
test('candidate: aborting a blocked pair releases both directions and pending callbacks', timeout, async () => {
  const [a, b] = candidate.duplexPair({ objectMode: true, highWaterMark: 1 });
  const controller = new AbortController(), errors = [], callbacks = [];
  a.on('error', error => errors.push(error)); b.on('error', error => errors.push(error));
  const completed = Promise.all([close(a), close(b)]);
  candidate.addAbortSignal(controller.signal, a);
  a.write(1, error => callbacks.push(error)); b.write(2, error => callbacks.push(error));
  controller.abort('pair cancelled'); await completed; await tick();
  assert.equal(callbacks.length, 2); assert.equal(errors.length, 2);
  for (const error of callbacks.concat(errors)) {
    assert.equal(error.code, 'ABORT_ERR'); assert.equal(error.cause, 'pair cancelled');
  }
});
test('candidate: destruction retires the private native signal dependency', timeout, () => {
  const signals = [], originalAny = AbortSignal.any;
  let local;
  try {
    AbortSignal.any = function (sources) { const signal = originalAny(sources); signals.push(signal); return signal; };
    local = install({ ...native, Readable: class extends native.Readable {}, Duplex: class extends native.Duplex {},
      addAbortSignal: undefined, duplexPair: undefined });
  } finally { AbortSignal.any = originalAny; }
  const stream = new local.Readable({ read() {}, emitClose: false });
  const controller = new AbortController();
  local.addAbortSignal(controller.signal, stream);
  assert.equal(signals.length, 1); assert.equal(signals[0].aborted, false);
  stream.destroy();
  assert.equal(signals[0].aborted, true);
  assert.equal(require('node:events').getEventListeners(signals[0], 'abort').length, 0);
  assert.equal(controller.signal.aborted, false);
});
test('candidate: the exact CommonJS CLI fixture reaches its completion marker', timeout, async () => {
  const source = fs.readFileSync(path.join(__dirname, '../../fixtures/stream_operators/abort_signal.cjs'), 'utf8');
  await new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('fixture did not complete')), 1500);
    const console = { log(...values) {
      clearTimeout(timer);
      try { assert.deepEqual(values, ['STREAM_ABORT_SIGNAL_OK']); resolve(); }
      catch (error) { reject(error); }
    } };
    try {
      new Function('require', 'console', source)(name => {
        assert(name === 'stream' || name === 'node:stream'); return candidate;
      }, console);
    } catch (error) { clearTimeout(timer); reject(error); }
  });
});
