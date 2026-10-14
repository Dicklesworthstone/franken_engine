'use strict';
// The complete shipped facade runs under Node with native EventEmitter and
// AbortSignal primitives. This is NOT execution of FrankenEngine's Rust VM.
// Run: node --test scripts/test_events_backpressure.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const native = require('node:events');
const sourcePath = process.env.FRANKEN_EVENTS_SOURCE || path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/events_module.js');
const source = fs.readFileSync(sourcePath, 'utf8');
function facade() {
  class Emitter extends native.EventEmitter {}
  return new Function('__franken_events_constructor', '__franken_events_once',
    'return ' + source)(() => Emitter, native.once);
}
function consumer(api = facade(), options = {}) {
  const emitter = new native.EventEmitter();
  const calls = [];
  emitter.pause = function () { assert.equal(this, emitter); calls.push('pause'); };
  emitter.resume = function () { assert.equal(this, emitter); calls.push('resume'); };
  const iterator = api.on(emitter, 'data', {
    highWaterMark: 1, lowWaterMark: 1, close: ['end'], ...options,
  });
  return { emitter, iterator, calls };
}
async function nextValue(iterator, value) {
  assert.deepEqual(await iterator.next(), { value: [value], done: false });
}
async function exhausted(iterator) {
  assert.deepEqual(await iterator.next(), { value: undefined, done: true });
}
async function rejection(iterator, expected) {
  const observed = await iterator.next().then(
    () => ({ rejected: false }), reason => ({ rejected: true, reason }));
  assert.equal(observed.rejected, true);
  assert.equal(observed.reason, expected);
}
function noSubscriptions(emitter) {
  assert.equal(emitter.listenerCount('data'), 0);
  assert.equal(emitter.listenerCount('error'), 0);
  assert.equal(emitter.listenerCount('end'), 0);
}

async function synchronousProducer(api, limit) {
  const emitter = new native.EventEmitter();
  let produced = 0, consumed = 0, paused = false, peak = 0, pauses = 0, resumes = 0;
  emitter.pause = function () { paused = true; pauses++; };
  emitter.resume = function () {
    paused = false; resumes++;
    while (!paused && produced < limit) {
      const value = produced++;
      peak = Math.max(peak, produced - consumed);
      emitter.emit('data', value);
    }
    if (produced === limit) emitter.emit('end');
  };
  const iterator = api.on(emitter, 'data', { highWaterMark: 2, lowWaterMark: 1, close: ['end'] });
  emitter.resume();
  const values = [];
  while (true) {
    // next() may synchronously resume the producer after reserving this item.
    // Account for that reservation before it runs, not after await returns.
    consumed++;
    const step = await iterator.next();
    if (step.done) { consumed--; break; }
    values.push(step.value[0]);
  }
  noSubscriptions(emitter);
  return { values, peak, pauses, resumes };
}

test('synchronous refill maintains bounded backlog over 12000 events', async () => {
  const actual = await synchronousProducer(facade(), 12000);
  assert.deepEqual(actual.values, Array.from({ length: 12000 }, (_, i) => i));
  assert.equal(actual.peak, 3);
  assert(actual.pauses > 3000);
  assert(actual.resumes > 3000);
  // A live incumbent is exercised in this invocation. Node 22 also loses the
  // reentrant pause: compare content, but report backlog instead of pretending
  // that its resource behavior is a correctness oracle for this regression.
  const reference = await synchronousProducer(native, 12000);
  assert.deepEqual(actual.values, reference.values);
  console.log(JSON.stringify({ probe: 'synchronous-refill', events: actual.values.length,
    facadePeak: actual.peak, nodePeak: reference.peak }));
});

test('ordinary hysteresis and FIFO results remain equal to live Node', async () => {
  async function exercise(api) {
    const { emitter, iterator, calls } = consumer(api, { highWaterMark: 3, lowWaterMark: 2 });
    for (let i = 0; i < 5; i++) emitter.emit('data', i);
    const values = [];
    for (let i = 0; i < 4; i++) values.push((await iterator.next()).value);
    emitter.emit('data', 5);
    emitter.emit('end');
    for await (const item of iterator) values.push(item);
    noSubscriptions(emitter);
    return { calls, values };
  }
  assert.deepEqual(await exercise(facade()), await exercise(native));
});

for (const terminal of ['return', 'end', 'error', 'abort']) {
  test(`buffer draining after ${terminal} never restarts the producer`, async () => {
    const controller = new AbortController();
    const { emitter, iterator, calls } = consumer(facade(), { signal: controller.signal });
    emitter.emit('data', 1); emitter.emit('data', 2);
    const failure = new Error('terminal');
    if (terminal === 'return') await iterator.return();
    else if (terminal === 'abort') controller.abort(failure);
    else emitter.emit(terminal, failure);
    noSubscriptions(emitter);
    await nextValue(iterator, 1); await nextValue(iterator, 2);
    if (terminal === 'error') await rejection(iterator, failure);
    if (terminal === 'abort') await assert.rejects(iterator.next(), error =>
      error.code === 'ABORT_ERR' && error.cause === failure);
    await exhausted(iterator);
    assert.deepEqual(calls, ['pause']);
  });
}

test('pause-time consumer reentry drains without recursive resume or missed demand', async () => {
  const E = facade(), emitter = new native.EventEmitter();
  const requests = [];
  let iterator, produced = 0, paused = false, depth = 0, peakDepth = 0, pauses = 0;
  emitter.pause = function () {
    paused = true; pauses++;
    // Drain the three buffered values and register demand for the next one
    // while the pause callback still owns the physical producer transition.
    if (produced < 2000) for (let i = 0; i < 4; i++) requests.push(iterator.next());
  };
  emitter.resume = function () {
    depth++; peakDepth = Math.max(peakDepth, depth);
    paused = false;
    while (!paused && produced < 2000) emitter.emit('data', produced++);
    if (produced === 2000) emitter.emit('end');
    depth--;
  };
  iterator = E.on(emitter, 'data', { highWaterMark: 2, lowWaterMark: 1, close: ['end'] });
  emitter.resume();
  assert.equal(produced, 2000, 'pending next() calls must not be stranded on a paused source');
  assert(peakDepth <= 2, `recursive producer stack: ${peakDepth}`);
  assert(pauses > 400);
  const steps = await Promise.all(requests);
  const values = steps.filter(step => !step.done).map(step => step.value[0]);
  for await (const [value] of iterator) values.push(value);
  assert.deepEqual(values, Array.from({ length: 2000 }, (_, i) => i));
  noSubscriptions(emitter);
});

test('a pause callback that closes its consumer cannot trigger a resume', async () => {
  const { emitter, iterator, calls } = consumer();
  emitter.pause = function () { calls.push('pause'); iterator.return(); };
  emitter.emit('data', 'a'); emitter.emit('data', 'b');
  await nextValue(iterator, 'a'); await nextValue(iterator, 'b'); await exhausted(iterator);
  assert.deepEqual(calls, ['pause']); noSubscriptions(emitter);
});

for (const failure of [new Error('resume failed'), undefined, null, false, 0]) {
  test(`resume failure preserves reserved values and the exact thrown value (${String(failure)})`, async () => {
    const { emitter, iterator } = consumer();
    emitter.resume = function () { throw failure; };
    emitter.emit('data', 'a'); emitter.emit('data', 'b');
    await nextValue(iterator, 'a'); await nextValue(iterator, 'b');
    await rejection(iterator, failure); await exhausted(iterator); noSubscriptions(emitter);
  });
}

test('events emitted before a resume failure stay ahead of its terminal error', async () => {
  const { emitter, iterator } = consumer();
  const failure = new Error('after delivery');
  emitter.resume = function () { emitter.emit('data', 'c'); emitter.emit('data', 'd'); throw failure; };
  emitter.emit('data', 'a'); emitter.emit('data', 'b');
  for (const value of ['a', 'b', 'c', 'd']) await nextValue(iterator, value);
  await rejection(iterator, failure); await exhausted(iterator); noSubscriptions(emitter);
});

test('throwing pause and resume getters are iterator failures, not dropped events', async () => {
  for (const member of ['pause', 'resume']) {
    const { emitter, iterator } = consumer();
    const failure = new Error(member);
    Object.defineProperty(emitter, member, { get() { throw failure; } });
    emitter.emit('data', 'a'); emitter.emit('data', 'b');
    for (const value of ['a', 'b']) await nextValue(iterator, value);
    await rejection(iterator, failure); await exhausted(iterator); noSubscriptions(emitter);
  }
});

test('pause failure closes subscriptions and reports one error after queued values', async () => {
  const { emitter, iterator } = consumer();
  emitter.pause = function () { throw false; };
  emitter.emit('data', 1); emitter.emit('data', 2);
  for (let i = 0; i < 10000; i++) emitter.emit('data', 'ignored');
  await nextValue(iterator, 1); await nextValue(iterator, 2);
  await rejection(iterator, false); await exhausted(iterator); noSubscriptions(emitter);
});

test('reentrant pending demand receives a resume error without stranding promises', async () => {
  const { emitter, iterator } = consumer();
  const failure = new Error('failed to restart');
  const pending = [];
  emitter.pause = function () { for (let i = 0; i < 4; i++) pending.push(iterator.next()); };
  emitter.resume = function () { throw failure; };
  emitter.emit('data', 'a'); emitter.emit('data', 'b');
  const observations = await Promise.all(pending.map(p => p.then(
    value => ({ value }), reason => ({ reason }))));
  assert.deepEqual(observations, [
    { value: { value: ['a'], done: false } }, { value: { value: ['b'], done: false } },
    { reason: failure }, { value: { value: undefined, done: true } },
  ]);
  await exhausted(iterator); noSubscriptions(emitter);
});

test('abort during resume cannot be replaced by a synchronous success event', async () => {
  const controller = new AbortController();
  const { emitter, iterator } = consumer(facade(), { signal: controller.signal });
  const reason = { stop: true };
  controller.signal.addEventListener('abort', event => {
    event.stopImmediatePropagation(); emitter.emit('data', 'forbidden');
  });
  emitter.resume = function () { controller.abort(reason); emitter.emit('data', 'also-forbidden'); };
  emitter.emit('data', 'a'); emitter.emit('data', 'b');
  await nextValue(iterator, 'a'); await nextValue(iterator, 'b');
  await assert.rejects(iterator.next(), e => e.code === 'ABORT_ERR' && e.cause === reason);
  await exhausted(iterator); noSubscriptions(emitter);
});

test('equal watermarks retain the same strict crossing behavior as Node', async () => {
  async function exercise(api, legacy) {
    const options = legacy ? { highWaterMark: undefined, lowWaterMark: undefined,
      highWatermark: 2, lowWatermark: 2 } :
      { highWaterMark: 2, lowWaterMark: 2 };
    const { emitter, iterator, calls } = consumer(api, options);
    emitter.emit('data', 1); emitter.emit('data', 2);
    assert.deepEqual(calls, []);
    emitter.emit('data', 3);
    await nextValue(iterator, 1);
    assert.deepEqual(calls, ['pause']);
    await nextValue(iterator, 2);
    assert.deepEqual(calls, ['pause', 'resume']);
    emitter.emit('end'); await nextValue(iterator, 3); await exhausted(iterator);
    return calls;
  }
  for (const legacy of [false, true]) {
    assert.deepEqual(await exercise(facade(), legacy), await exercise(native, legacy));
  }
});

test('multiple pending consumers keep FIFO and ordinary terminal behavior', async () => {
  async function exercise(api) {
    const { emitter, iterator } = consumer(api);
    const pending = Array.from({ length: 8 }, () => iterator.next());
    for (let i = 0; i < 5; i++) emitter.emit('data', i);
    emitter.emit('end'); noSubscriptions(emitter);
    return Promise.all(pending);
  }
  assert.deepEqual(await exercise(facade()), await exercise(native));
});

const rustSource = fs.readFileSync(path.join(__dirname,
  '../crates/franken-engine/tests/events_backpressure_lifecycle.rs'), 'utf8');
const programs = new Map([...rustSource.matchAll(/const (\w+): &str = r#"([\s\S]*?)"#;/g)]
  .map(match => [match[1], match[2]]));
for (const [name, expected] of [
  ['SYNCHRONOUS_REFILL', 'fifo 96 4560 3'],
  ['TERMINAL_AND_FAILURE', 'terminal return 12 0 true\nterminal end 12 0 true\nterminal abort 12 0 true\n' +
    'failure false 12 true true\nfailure null 12 true true\nfailure undefined 12 true true'],
  ['REENTRANT_DEMAND', 'reentry 96 4560 2 0'],
]) {
  test(`exact native-test JavaScript under the full host facade: ${name}`, async () => {
    assert.equal(programs.size, 3);
    assert(programs.has(name));
    const api = facade(), lines = [];
    const log = (...args) => lines.push(require('node:util').format(...args));
    new Function('require', 'console', programs.get(name))(specifier => {
      assert(['events', 'node:events'].includes(specifier)); return api;
    }, { log });
    await new Promise(setImmediate);
    assert.equal(lines.join('\n'), expected);
  });
}
