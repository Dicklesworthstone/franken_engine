'use strict';
// Execute the shipped pipeline functions with real Node streams as their
// transport adapter. This is not a Rust interpreter, IFC or full-facade test.
// Run: node --test scripts/test_stream_pipeline_cancellation.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const native = require('node:stream');
const events = require('node:events');
const source = fs.readFileSync(process.env.FRANKEN_STREAM_SOURCE || path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/stream_module.js'), 'utf8');
function section(first, last) {
  const start = source.indexOf(first), end = source.indexOf(last, start);
  assert(start >= 0 && end > start, `missing shipped section ${first}`);
  return source.slice(start, end);
}
// All orchestration, completion, predicates and error handling are production
// source. Only the transport/queue/AbortSignal primitives are the Node adapter.
const code = section('  function makeError(', '  function isUint8Array(')
  + section('  function aggregateTwoErrors(', '  // ---- buffer list ----')
  + section('  // ---- finished (end-of-stream) ----', '  // ---- module object ----');
function fixture() {
  const context = {
    AbortController, AbortSignal, EventTarget, Reflect, Object, Array, Symbol, Promise, Buffer,
    Error, TypeError, AggregateError,
    Readable: native.Readable, PassThrough: native.PassThrough, Duplex: native.Duplex,
    nextTick: process.nextTick,
  };
  const api = vm.runInNewContext(`(function () {
    const kIsDestroyed = Symbol('kIsDestroyed');
    function nop() {}
    ${code}
    return {pipeline, pipelinePromise, eos, finishedPromise};
  })()`, context);
  const run = api.pipelinePromise;
  api.pipelinePromise = function (...args) { return bounded(run(...args)); };
  const finished = api.finishedPromise;
  api.finishedPromise = function (...args) { return bounded(finished(...args)); };
  return { ...api, context };
}
function bounded(promise) {
  // A real timer keeps a broken pending pipeline observable as a test failure
  // instead of allowing node:test to cancel the rest of the baseline run.
  let timer;
  const deadline = new Promise((resolve, reject) => {
    timer = setTimeout(() => reject(new Error('pipeline test deadline exceeded')), 400);
  });
  return Promise.race([promise, deadline]).finally(() => clearTimeout(timer));
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const turn = () => new Promise(resolve => setImmediate(resolve));
const testOptions = { timeout: 1500 };
function sink(onWrite = (chunk, callback) => callback(), options = {}) {
  return new native.Writable({ objectMode: true, ...options,
    write(chunk, encoding, callback) { onWrite(chunk, callback); } });
}
function idle(t) {
  const stream = new native.Readable({ objectMode: true, read() {} });
  t.after(() => { stream.destroy(); });
  return stream;
}
function observe(promise) { promise.catch(() => {}); return promise; }

test('ordinary stream transform pipeline preserves data and settles once', testOptions, async () => {
  const { pipeline } = fixture();
  const src = native.Readable.from([1, 2, 3]);
  const transform = new native.Transform({ objectMode: true,
    transform(value, encoding, done) { done(null, value * 2); } });
  const values = [];
  const dst = sink((value, done) => { values.push(value); done(); });
  let calls = 0;
  await new Promise((resolve, reject) => {
    assert.equal(pipeline(src, transform, dst, err => {
      calls++; if (err) reject(err); else resolve();
    }), dst);
  });
  await turn();
  assert.deepEqual(values, [2, 4, 6]);
  assert.equal(calls, 1);
});

test('functional stages receive one real run signal and return destination results', testOptions, async () => {
  const { pipelinePromise } = fixture();
  const seen = [];
  const output = await pipelinePromise(
    ({ signal }) => { seen.push(signal); return [1, 2, 3]; },
    async function* (input, { signal }) {
      seen.push(signal);
      for await (const value of input) yield value * 2;
    },
    async (input, { signal }) => {
      seen.push(signal);
      let sum = 0; for await (const value of input) sum += value;
      return sum;
    });
  assert.equal(output, 12);
  assert(seen[0] instanceof AbortSignal);
  assert(seen.every(signal => signal === seen[0]));
  assert.equal(seen[0].aborted, true, 'run signal releases on completion');
});

test('pre-aborted pipelines reject without writing any source data', testOptions, async () => {
  const { pipelinePromise } = fixture();
  const reason = new Error('cancelled before run');
  const signal = AbortSignal.abort(reason);
  let writes = 0;
  const dst = sink((value, done) => { writes++; done(); });
  await assert.rejects(pipelinePromise([1, 2], dst, { signal }), e =>
    e.code === 'ABORT_ERR' && e.name === 'AbortError' && e.cause === reason);
  assert.equal(writes, 0);
  assert.equal(dst.destroyed, true);
});

test('an external abort destroys all existing stream stages', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const controller = new AbortController();
  const src = idle(t);
  const transform = new native.PassThrough({ objectMode: true });
  const dst = sink();
  const pending = observe(pipelinePromise(src, transform, dst, { signal: controller.signal }));
  controller.abort('stop');
  await assert.rejects(pending, { name: 'AbortError', code: 'ABORT_ERR', cause: 'stop' });
  assert(src.destroyed && transform.destroyed && dst.destroyed);
});

test('late producer output is blocked and asynchronous IteratorClose is drained', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const controller = new AbortController();
  const next = deferred(), cleanup = deferred();
  t.after(() => { next.resolve({ done: true }); cleanup.resolve({ done: true }); });
  let pulled = false, returned = 0, writes = 0, settled = false;
  const producer = {
    [Symbol.asyncIterator]() { return this; },
    next() { if (pulled) return Promise.resolve({ done: true }); pulled = true; return next.promise; },
    return() { returned++; return cleanup.promise; },
  };
  const dst = sink((value, done) => { writes++; done(); });
  const pending = observe(pipelinePromise(producer, dst, { signal: controller.signal }));
  pending.then(() => { settled = true; }, () => { settled = true; });
  await turn();
  controller.abort('stop');
  await turn();
  assert.equal(dst.destroyed, true);
  next.resolve({ value: 'late', done: false });
  await turn();
  assert.equal(writes, 0);
  assert.equal(returned, 1);
  assert.equal(settled, false, 'settlement waits for iterator cleanup');
  cleanup.resolve({ done: true });
  await assert.rejects(pending, { code: 'ABORT_ERR' });
});

test('abort while backpressured closes the producer without another write', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const controller = new AbortController();
  let writeCallback, writes = 0, cleaned = false;
  const dst = sink((value, done) => { writes++; writeCallback = done; }, { highWaterMark: 1 });
  t.after(() => { if (writeCallback) writeCallback(); dst.destroy(); });
  async function* producer() {
    try { yield 1; yield 2; } finally { cleaned = true; }
  }
  const pending = observe(pipelinePromise(producer(), dst, { signal: controller.signal }));
  await turn();
  controller.abort();
  await assert.rejects(pending, { code: 'ABORT_ERR' });
  assert.equal(writes, 1);
  assert.equal(cleaned, true);
});

test('pipeline settlement waits for asynchronous destination destruction', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const controller = new AbortController();
  let release, settled = false;
  const src = idle(t);
  const dst = sink(undefined, { destroy(error, done) { release = () => done(error); } });
  t.after(() => { if (release) release(); });
  const pending = observe(pipelinePromise(src, dst, { signal: controller.signal }));
  pending.then(() => { settled = true; }, () => { settled = true; });
  controller.abort();
  await turn();
  assert.equal(typeof release, 'function');
  assert.equal(settled, false);
  release(); release = undefined;
  await assert.rejects(pending, { code: 'ABORT_ERR' });
});

test('a stopped external abort event cannot suppress pipeline cancellation', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const controller = new AbortController();
  controller.signal.addEventListener('abort', e => e.stopImmediatePropagation());
  const pending = observe(pipelinePromise(idle(t), sink(), { signal: controller.signal }));
  controller.abort('not suppressible');
  await assert.rejects(pending, { code: 'ABORT_ERR', cause: 'not suppressible' });
});

test('synthetic run-signal events do not cancel or consume real abort delivery', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const controller = new AbortController();
  const next = deferred();
  t.after(() => next.resolve({ done: true }));
  let runSignal, first = true;
  const source = ({ signal }) => {
    runSignal = signal;
    return { [Symbol.asyncIterator]() { return this; }, next() {
      if (first) { first = false; return next.promise; }
      return Promise.resolve({ done: true });
    }, return() { return Promise.resolve({ done: true }); } };
  };
  const values = [];
  const dst = sink((value, done) => { values.push(value); done(); });
  const pending = observe(pipelinePromise(source, dst, { signal: controller.signal }));
  assert(runSignal instanceof AbortSignal);
  runSignal.dispatchEvent(new Event('abort'));
  await turn();
  assert.equal(dst.destroyed, false);
  controller.abort();
  next.resolve({ value: 99, done: false });
  await assert.rejects(pending, { code: 'ABORT_ERR' });
  assert.deepEqual(values, []);
});

test('forged public signal state does not hide native cancellation or its cause', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const controller = new AbortController();
  Object.defineProperty(controller.signal, 'aborted', { value: false });
  Object.defineProperty(controller.signal, 'reason', { value: 'forged' });
  const pending = observe(pipelinePromise(idle(t), sink(), { signal: controller.signal }));
  controller.abort('native reason');
  await assert.rejects(pending, { code: 'ABORT_ERR', cause: 'native reason' });
});

test('invalid signal fails before any source factory or stream subscription', testOptions, async () => {
  const { pipelinePromise } = fixture();
  for (const signal of [null, {}, 3, { aborted: false }]) {
    let called = false;
    const dst = sink();
    await assert.rejects(pipelinePromise(() => { called = true; return []; }, dst, { signal }),
      { code: 'ERR_INVALID_ARG_TYPE' });
    assert.equal(called, false);
    assert.equal(dst.listenerCount('error'), 0);
    assert.equal(dst.destroyed, false);
    dst.destroy();
  }
});

test('a stage failure aborts sibling work and retains the original error', testOptions, async () => {
  const { pipelinePromise } = fixture();
  const failure = new Error('transform failed');
  let stageSignal, cleaned = false;
  async function* source({ signal }) {
    stageSignal = signal;
    try { yield 1; yield 2; } finally { cleaned = true; }
  }
  async function* transform(input) { for await (const value of input) throw failure; }
  const dst = sink();
  await assert.rejects(pipelinePromise(source, transform, dst), e => e === failure);
  assert.equal(cleaned, true);
  assert.equal(stageSignal.aborted, true);
  assert.equal(stageSignal.reason, failure);
  assert.equal(dst.destroyed, true);
});

test('source factories returning streams transfer lifecycle ownership to the pipeline', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const controller = new AbortController();
  const src = idle(t);
  const pending = observe(pipelinePromise(() => src, sink(), { signal: controller.signal }));
  controller.abort();
  await assert.rejects(pending, { code: 'ABORT_ERR' });
  assert.equal(src.destroyed, true);
});

test('synchronous setup failures destroy already acquired stream stages', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const src = idle(t);
  await assert.rejects(pipelinePromise(src, () => 42), { code: 'ERR_INVALID_RETURN_VALUE' });
  await turn();
  assert.equal(src.destroyed, true);
});

test('end:false waits for admitted writes but leaves the destination open', testOptions, async t => {
  const { pipelinePromise } = fixture();
  let release, settled = false;
  const dst = sink((chunk, done) => { release = done; });
  t.after(() => { if (release) release(); dst.destroy(); });
  const pending = pipelinePromise(native.Readable.from([1]), dst, { end: false });
  pending.then(() => { settled = true; }, () => { settled = true; });
  await turn();
  assert.equal(typeof release, 'function');
  assert.equal(settled, false);
  release(); release = undefined;
  await pending;
  assert.equal(dst.destroyed, false);
  assert.equal(dst.writableEnded, false);
  dst.end();
});

test('end:false is not a cancellation escape hatch', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const controller = new AbortController();
  const dst = sink();
  const pending = observe(pipelinePromise(idle(t), dst, { signal: controller.signal, end: false }));
  controller.abort();
  await assert.rejects(pending, { code: 'ABORT_ERR' });
  assert.equal(dst.destroyed, true);
});

test('completed pipelines detach their private abort listeners', testOptions, async () => {
  const { pipelinePromise } = fixture();
  const outer = new AbortController();
  for (let i = 0; i < 20; i++) {
    let signal;
    await pipelinePromise(options => { signal = options.signal; return [1]; }, sink(), { signal: outer.signal });
    assert(signal instanceof AbortSignal);
    assert.equal(events.getEventListeners(signal, 'abort').length, 0);
    assert.equal(signal.aborted, true);
  }
  assert.equal(outer.signal.aborted, false);
});

test('a late destination result cannot turn cancellation into success', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const controller = new AbortController(), result = deferred();
  t.after(() => result.resolve(7));
  let signal;
  const pending = observe(pipelinePromise([], (input, options) => {
    signal = options.signal; return result.promise;
  }, { signal: controller.signal }));
  controller.abort();
  result.resolve(7);
  await assert.rejects(pending, { code: 'ABORT_ERR' });
  assert.equal(signal.aborted, true);
});

test('a destination thenable cannot settle the pipeline more than once', testOptions, async () => {
  const { pipelinePromise } = fixture();
  let gets = 0;
  const result = await pipelinePromise([], () => ({
    get then() {
      gets++;
      return (resolve, reject) => { resolve(11); resolve(12); reject(new Error('late')); };
    }
  }));
  assert.equal(result, 11);
  assert.equal(gets, 1);
});

test('callback failure settles exactly once across error and close events', testOptions, async () => {
  const { pipeline } = fixture();
  const failure = new Error('write failed');
  const src = native.Readable.from([1, 2]);
  const dst = sink((value, done) => done(failure));
  let calls = 0;
  const received = await new Promise(resolve => {
    pipeline(src, dst, error => { calls++; resolve(error); });
  });
  await turn();
  assert.equal(received, failure);
  assert.equal(calls, 1);
});

test('finished promise cancellation detaches watchers without destroying the stream', testOptions, async t => {
  const { finishedPromise } = fixture();
  const controller = new AbortController(), src = idle(t);
  const pending = observe(finishedPromise(src, { signal: controller.signal }));
  controller.abort('only stop waiting');
  await assert.rejects(pending, { code: 'ABORT_ERR', name: 'AbortError', cause: 'only stop waiting' });
  assert.equal(src.destroyed, false);
  for (const name of ['end', 'finish', 'error', 'close', 'aborted']) {
    assert.equal(src.listenerCount(name), 0, name);
  }
});

test('callback finished cancellation delivers exactly once and preserves receiver', testOptions, async t => {
  const { eos } = fixture();
  const controller = new AbortController(), src = idle(t);
  let calls = 0, received;
  const cleanup = eos(src, { signal: controller.signal }, function (error) {
    assert.equal(this, src); calls++; received = error;
  });
  controller.abort('stop');
  await turn();
  assert.equal(calls, 1);
  assert.equal(received.code, 'ABORT_ERR');
  cleanup(); cleanup();
  src.push(null); src.resume();
  await turn();
  assert.equal(calls, 1);
});

test('pre-aborted finished rejects asynchronously and never closes its stream', testOptions, async t => {
  const { finishedPromise } = fixture();
  const src = idle(t);
  let synchronous = true;
  const pending = finishedPromise(src, { signal: AbortSignal.abort('already') });
  const rejection = pending.catch(error => {
    assert.equal(synchronous, false);
    assert.equal(error.code, 'ABORT_ERR');
    assert.equal(error.cause, 'already');
  });
  synchronous = false;
  await rejection;
  assert.equal(src.destroyed, false);
  assert.equal(src.listenerCount('error'), 0);
});

test('finished cleanup:true releases successful completion watchers', testOptions, async () => {
  const { finishedPromise } = fixture();
  const src = native.Readable.from(['done']);
  const pending = finishedPromise(src, { cleanup: true });
  src.resume();
  await pending;
  for (const name of ['end', 'finish', 'error', 'close', 'aborted']) {
    assert.equal(src.listenerCount(name), 0, name);
  }
});

test('finished default retains the existing late-error observation contract', testOptions, async () => {
  const { finishedPromise } = fixture();
  const src = native.Readable.from(['done']);
  const pending = finishedPromise(src);
  src.resume();
  await pending;
  assert(src.listenerCount('error') > 0);
  assert.doesNotThrow(() => src.emit('error', new Error('late')));
});

test('finished cleanup:true releases failure watchers and preserves the error', testOptions, async () => {
  const { finishedPromise } = fixture();
  const failure = new Error('read failed');
  const src = new native.Readable({ read() { this.destroy(failure); } });
  const pending = finishedPromise(src, { cleanup: true });
  src.resume();
  await assert.rejects(pending, error => error === failure);
  for (const name of ['end', 'finish', 'error', 'close']) assert.equal(src.listenerCount(name), 0);
});

test('finished manual disposal suppresses abort and completion callbacks', testOptions, async t => {
  const { eos } = fixture();
  const controller = new AbortController(), src = idle(t);
  let calls = 0;
  const dispose = eos(src, { signal: controller.signal }, () => { calls++; });
  dispose(); dispose();
  controller.abort();
  src.push(null); src.resume();
  await turn();
  assert.equal(calls, 0);
  assert.equal(src.listenerCount('error'), 0);
});

test('stopped public abort events cannot leave finished pending', testOptions, async t => {
  const { finishedPromise } = fixture();
  const controller = new AbortController(), src = idle(t);
  controller.signal.addEventListener('abort', e => e.stopImmediatePropagation());
  const pending = finishedPromise(src, { signal: controller.signal });
  controller.abort();
  await assert.rejects(pending, { code: 'ABORT_ERR' });
  assert.equal(src.destroyed, false);
});

test('invalid finished signals attach no listeners', testOptions, async t => {
  const { finishedPromise } = fixture();
  for (const signal of [null, false, { aborted: false }]) {
    const src = idle(t);
    await assert.rejects(finishedPromise(src, { signal }), { code: 'ERR_INVALID_ARG_TYPE' });
    assert.equal(src.eventNames().length, 0);
  }
});

test('finished validates its callback before attaching listeners', testOptions, async t => {
  const { eos } = fixture();
  for (const callback of [null, undefined, {}, 42]) {
    const src = idle(t);
    let dispose;
    try {
      assert.throws(() => { dispose = eos(src, {}, callback); }, { code: 'ERR_INVALID_ARG_TYPE' });
    } finally { if (dispose) dispose(); }
    assert.equal(src.eventNames().length, 0);
  }
});

test('finishing during the public abort event still observes native cancellation', testOptions, async t => {
  const { finishedPromise } = fixture();
  const controller = new AbortController(), src = idle(t);
  controller.signal.addEventListener('abort', () => {
    src.emit('end'); src.emit('close');
  });
  const pending = finishedPromise(src, { signal: controller.signal });
  controller.abort('cancellation wins');
  await assert.rejects(pending, { code: 'ABORT_ERR', cause: 'cancellation wins' });
});

test('already-completed streams honor finished cleanup:true', testOptions, async () => {
  const { finishedPromise } = fixture();
  const src = native.Readable.from([]);
  src.resume();
  await bounded(native.promises.finished(src, { cleanup: true }));
  await finishedPromise(src, { cleanup: true });
  assert.equal(src.eventNames().length, 0);
});

test('normal end:false results and functional signal contracts match Node', testOptions, async () => {
  async function exercise(run) {
    const values = [];
    const dst = sink((value, done) => { values.push(value); done(); });
    let signal;
    await run(({ signal: runSignal }) => { signal = runSignal; return [1, 2, 3]; },
      async function* (input, options) {
        assert.equal(options.signal, signal);
        for await (const value of input) yield value * 3;
      }, dst, { end: false });
    const result = [values, signal instanceof AbortSignal, signal.aborted, dst.writableEnded, dst.destroyed];
    dst.end();
    return result;
  }
  assert.deepEqual(await exercise(fixture().pipelinePromise), await exercise(native.promises.pipeline));
});

test('finished abort ownership and cleanup behavior match Node', testOptions, async t => {
  async function exercise(finish) {
    const controller = new AbortController(), src = idle(t);
    const pending = finish(src, { signal: controller.signal, cleanup: true });
    controller.abort('reason');
    const failure = await pending.then(() => null, error => error);
    return [failure.code, failure.name, failure.cause, src.destroyed,
      ['end', 'finish', 'close', 'error'].map(name => src.listenerCount(name))];
  }
  assert.deepEqual(await exercise(fixture().finishedPromise), await exercise(native.promises.finished));
});

test('falsy producer and destination rejections fail closed instead of stranding streams', testOptions, async () => {
  const { pipelinePromise } = fixture();
  for (const reason of [undefined, null, false, 0, '']) {
    const dst = sink();
    await assert.rejects(pipelinePromise((async function* () { throw reason; })(), dst),
      error => error.code === 'ERR_STREAM_DESTROYED' && error.cause === reason);
    assert.equal(dst.destroyed, true);
    await assert.rejects(pipelinePromise([], () => Promise.reject(reason)),
      error => error.code === 'ERR_STREAM_DESTROYED' && error.cause === reason);
  }
});

test('AbortError emitted by a stage remains a failure, not a completion decrement', testOptions, async () => {
  const { pipelinePromise } = fixture();
  const failure = Object.assign(new Error('stage aborted'), { name: 'AbortError', code: 'ABORT_ERR' });
  const src = native.Readable.from([1, 2]);
  const dst = sink((value, done) => done(failure));
  await assert.rejects(pipelinePromise(src, dst), error => error === failure);
  assert.equal(src.destroyed, true);
  assert.equal(dst.destroyed, true);
});

test('later replacement of public cancellation helpers cannot redirect a pipeline', testOptions, async t => {
  const { pipelinePromise, context } = fixture();
  const fail = () => { throw new Error('guest helper called'); };
  context.AbortController = fail;
  context.AbortSignal = { any: fail };
  context.EventTarget = fail;
  context.Reflect = { apply: fail };
  const controller = new AbortController();
  const pending = observe(pipelinePromise(idle(t), sink(), {signal: controller.signal}));
  controller.abort('native');
  await assert.rejects(pending, { code: 'ABORT_ERR', cause: 'native' });
});

test('completion emitted during the public abort event cannot publish success', testOptions, async t => {
  const { pipelinePromise } = fixture();
  const controller = new AbortController(), src = idle(t), dst = sink();
  controller.signal.addEventListener('abort', () => {
    src.emit('end'); dst.emit('finish'); src.emit('close'); dst.emit('close');
  });
  const pending = observe(pipelinePromise(src, dst, {signal: controller.signal}));
  controller.abort('authoritative state');
  await assert.rejects(pending, {code: 'ABORT_ERR', cause: 'authoritative state'});
});
