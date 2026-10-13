'use strict';
// Execute the actual engine-owned events prelude with Node transport adapters.
// This validates its JavaScript, NOT the Rust VM, IFC, or native memory meter.
// Run: node scripts/tests/events_queue.cjs
// Optional same-host comparison: node --expose-gc scripts/tests/events_queue.cjs --bench OLD_EVENTS_MODULE.js
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { performance } = require('node:perf_hooks');
const native = require('node:events');
const nativeOnce = native.once;
const source = fs.readFileSync(path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/events_module.js'), 'utf8');

function load(text) {
  class AdapterEmitter extends native.EventEmitter {}
  // Do not invoke inherited Node static setters while initializing the prelude.
  for (const [name, value] of [['defaultMaxListeners', 10], ['captureRejections', false]]) {
    Object.defineProperty(AdapterEmitter, name, { value, writable: true, configurable: true });
  }
  return new Function('__franken_events_constructor', '__franken_events_once',
    'return ' + text)(() => AdapterEmitter, nativeOnce);
}
const candidate = load(source);
let checks = 0;
async function bounded(work) {
  let timer;
  try {
    return await Promise.race([work, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('event scenario did not settle')), 5000);
    })]);
  } finally { clearTimeout(timer); }
}
async function compare(name, scenario) {
  const expected = await bounded(Promise.resolve().then(() => scenario(native)));
  const actual = await bounded(Promise.resolve().then(() => scenario(candidate)));
  assert.deepEqual(actual, expected, name); checks++;
}
async function settle(promise) {
  try { return { ok: await promise }; }
  catch (error) { return { error: [error.name, error.code, error.message, error.cause] }; }
}
async function testPublicAPI() {
  for (const size of [0, 1, 2, 31, 32, 33, 63, 64, 65, 129, 4097]) {
    for (const waiting of [false, true]) {
      await compare(`FIFO size=${size} waiting=${waiting}`, async E => {
        const e = new E, it = E.on(e, 'data', { close: ['end'] });
        const waits = [], token = { shared: true }, results = [];
        if (waiting) for (let i = 0; i < size; i++) waits.push(it.next());
        for (let i = 0; i < size; i++) e.emit('data', i, undefined, token);
        e.emit('end');
        for (let i = 0; i < size; i++) {
          const item = await (waiting ? waits[i] : it.next());
          assert.equal(item.value[2], token, 'payload identity');
          results.push([item.done, item.value[0], item.value[1]]);
        }
        return [results, await it.next(), e.eventNames()];
      });
    }
  }
  for (const buffered of [0, 1, 33, 65]) {
    for (const waiting of [0, 1, 33, 65]) {
      for (const terminal of ['close', 'return', 'error', 'abort', 'throw']) {
        await compare(`terminal ${terminal} buffered=${buffered} waiting=${waiting}`, async E => {
          const e = new E, controller = new AbortController;
          const it = E.on(e, 'data', { close: ['end'], signal: controller.signal });
          const promises = [];
          for (let i = 0; i < waiting; i++) promises.push(settle(it.next()));
          for (let i = 0; i < buffered; i++) e.emit('data', i);
          const error = new Error('terminal');
          if (terminal === 'close') e.emit('end');
          if (terminal === 'return') await it.return();
          if (terminal === 'error') e.emit('error', error);
          if (terminal === 'abort') controller.abort('cancel');
          if (terminal === 'throw') it.throw(error);
          const results = await Promise.all(promises);
          for (let i = 0; i < Math.max(0, buffered - waiting) + 2; i++) {
            results.push(await settle(it.next()));
          }
          return [results, e.eventNames(), native.getEventListeners(controller.signal, 'abort').length];
        });
      }
    }
  }
  await compare('pause/resume with reentrant production across chunks', async E => {
    const e = new E, calls = [], values = [];
    let resumed = false;
    e.pause = () => calls.push('pause');
    e.resume = () => {
      calls.push('resume');
      if (!resumed) {
        resumed = true;
        for (let i = 65; i < 130; i++) e.emit('data', i);
      }
    };
    const it = E.on(e, 'data', { highWaterMark: 32, lowWaterMark: 16 });
    for (let i = 0; i < 65; i++) e.emit('data', i);
    for (let i = 0; i < 130; i++) values.push((await it.next()).value[0]);
    await it.return();
    assert.deepEqual(values, Array.from({ length: 130 }, (_, i) => i));
    return [values, calls, e.eventNames()];
  });
  await compare('throwing resume is retried by the next read', async E => {
    const e = new E, calls = [], failure = new Error('resume failed');
    e.pause = () => calls.push('pause');
    let attempts = 0;
    e.resume = () => {
      calls.push('resume');
      if (++attempts === 1) throw failure;
    };
    const it = E.on(e, 'data', { highWaterMark: 1, lowWaterMark: 2 });
    for (let i = 0; i < 3; i++) e.emit('data', i);
    const first = await it.next();
    let same = false;
    try { await it.next(); } catch (error) { same = error === failure; }
    const last = await it.next();
    await it.return();
    assert.equal(same, true, 'original exception preserved');
    assert.equal(attempts, 2, 'resume retried, not permanently suppressed');
    return [first, same, last, calls, e.eventNames()];
  });
  // Preserve the prelude's stronger native-aborted-state boundary: public
  // synthetic events cannot cancel, and stopped public events cannot hide it.
  const e = new candidate, controller = new AbortController;
  controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
  const it = candidate.on(e, 'data', { signal: controller.signal });
  controller.signal.dispatchEvent(new Event('abort'));
  e.emit('data', 7);
  assert.equal((await it.next()).value[0], 7);
  const waits = Array.from({ length: 65 }, () => settle(it.next()));
  controller.abort('real');
  const outcomes = await bounded(Promise.all(waits));
  assert.equal(outcomes[0].error[0], 'AbortError');
  assert.equal(outcomes[0].error[3], 'real');
  assert.ok(outcomes.slice(1).every(item => item.ok.done));
  assert.equal(e.listenerCount('data'), 0); checks++;
}
async function workload(E, kind, n) {
  const e = new E, it = E.on(e, 'data', { close: ['end'] });
  let sum = 0;
  if (kind === 'buffered') {
    for (let i = 0; i < n; i++) e.emit('data', i);
    for (let i = 0; i < n; i++) sum += (await it.next()).value[0];
  } else if (kind === 'waiters') {
    const waits = [];
    for (let i = 0; i < n; i++) waits.push(it.next());
    for (let i = 0; i < n; i++) e.emit('data', i);
    for (const wait of waits) sum += (await wait).value[0];
  } else {
    for (let i = 0; i < n; i++) {
      const wait = kind === 'single-waiter' ? it.next() : undefined;
      e.emit('data', i);
      sum += (await (wait || it.next())).value[0];
    }
  }
  e.emit('end');
  assert.equal((await it.next()).done, true);
  assert.equal(sum, n * (n - 1) / 2);
  return sum;
}
async function benchmark(baselinePath) {
  const implementations = [['node', native], ['before', load(fs.readFileSync(baselinePath, 'utf8'))],
    ['candidate', candidate]];
  const results = [];
  for (const kind of ['buffered', 'waiters', 'single-buffered', 'single-waiter']) {
    for (let warmup = 0; warmup < 3; warmup++) {
      for (const [, E] of implementations) await workload(E, kind, 5000);
    }
    const samples = Object.fromEntries(implementations.map(([name]) => [name, []]));
    for (let round = 0; round < 9; round++) {
      for (let offset = 0; offset < implementations.length; offset++) {
        const [name, E] = implementations[(round + offset) % implementations.length];
        if (global.gc) global.gc();
        const start = performance.now();
        await workload(E, kind, 30000);
        samples[name].push(performance.now() - start);
      }
    }
    const medians = Object.fromEntries(Object.entries(samples).map(([name, times]) =>
      [name, [...times].sort((a, b) => a - b)[4]]));
    results.push({ kind, samples_ms: samples, median_ms: medians });
  }
  console.log(JSON.stringify({ host: process.version,
    scope: 'Engine-owned JavaScript on Node adapters; NOT the Rust VM or a V8-gap measurement',
    events_per_sample: 30000, results }, null, 2));
}
(async () => {
  await testPublicAPI();
  console.log(`PASS ${checks} public API scenarios`);
  const flag = process.argv.indexOf('--bench');
  if (flag !== -1) {
    assert.ok(process.argv[flag + 1], '--bench requires a baseline source path');
    await benchmark(process.argv[flag + 1]);
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
