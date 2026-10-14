'use strict';
// Reference-host differential tests, NOT a native interpreter conformance run.
// Pass --engine-shim when the full checkout is present to additionally exercise
// stream_module.js itself under Node. Neither mode claims Rust execution.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const native = require('node:stream');
const events = require('node:events');
const decoder = require('node:string_decoder');
const { setImmediate: tick } = require('node:timers/promises');
const root = path.join(__dirname, '../../crates/franken-engine/src/lowering_pipeline');
const install = vm.runInThisContext(fs.readFileSync(path.join(root, 'stream_operators.js'), 'utf8'),
  { filename: 'stream_operators.js' });
let base = native;
if (process.argv.includes('--engine-shim')) {
  const factory = vm.runInThisContext('(function(__franken_stream_events, __franken_stream_string_decoder, __franken_stream_next_tick) { return ' +
    fs.readFileSync(path.join(root, 'stream_module.js'), 'utf8') + '; })', { filename: 'stream_module.js' });
  base = factory(events.EventEmitter, decoder, process.nextTick);
} else if (!process.argv.includes('--reference-host')) {
  throw new Error('Select --reference-host or --engine-shim; never silently substitute Node for the engine');
}
// Do not mutate Node's oracle prototype. Its static from() returns an ordinary
// Readable, so give just the candidate instances our inherited prototype.
class CandidateReadable extends base.Readable {}
CandidateReadable.from = function (iterable, options) {
  const stream = base.Readable.from(iterable, options);
  Object.setPrototypeOf(stream, CandidateReadable.prototype);
  return stream;
};
const candidate = install({ Readable: CandidateReadable });
const lanes = { candidate, node: native };
async function collect(source) { const values = []; for await (const value of source) values.push(value); return values; }
function deferred() { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; }
const timeout = { timeout: 3000 };

for (const [name, { Readable }] of Object.entries(lanes)) {
  test(`${name}: map/filter synchronous and asynchronous chaining`, timeout, async () => {
    assert.deepEqual(await collect(Readable.from([1, 2, 3, 4]).map(async x => x * 3).filter(async x => x % 2 === 0)), [6, 12]);
  });
  test(`${name}: empty inputs and undefined mapping`, timeout, async () => {
    assert.deepEqual(await collect(Readable.from([]).map(() => { throw Error('not called'); })), []);
    assert.deepEqual(await collect(Readable.from([1, 2]).map(() => undefined)), [undefined, undefined]);
    assert.deepEqual(await collect(Readable.from([1, 2]).filter(() => false)), []);
  });
  test(`${name}: input order survives out-of-order mapper completion`, timeout, async () => {
    const gates = Array.from({ length: 4 }, deferred);
    let active = 0, peak = 0;
    const out = collect(Readable.from([0, 1, 2, 3]).map(async x => {
      peak = Math.max(peak, ++active);
      await gates[x].promise;
      active--;
      return x * 2;
    }, { concurrency: 4, highWaterMark: 0 }));
    await tick();
    assert.equal(peak, 4);
    for (const i of [3, 2, 1, 0]) gates[i].resolve();
    assert.deepEqual(await out, [0, 2, 4, 6]);
  });
  test(`${name}: callback limit and bounded slow-consumer prefetch`, timeout, async () => {
    let calls = 0, active = 0, peak = 0;
    const stream = Readable.from(Array.from({ length: 1000 }, (_, i) => i)).map(async x => {
      calls++;
      peak = Math.max(peak, ++active);
      await tick();
      active--;
      return x;
    }, { concurrency: 3, highWaterMark: 2 });
    const iterator = stream[Symbol.asyncIterator]();
    assert.equal((await iterator.next()).value, 0);
    await tick(); await tick(); await tick();
    assert(peak <= 3, `concurrency ${peak}`);
    assert(calls <= 8, `prefetched ${calls} results while consumer paused`);
    await iterator.return();
  });
  test(`${name}: delayed rejection is observed, ordered, and closes input`, timeout, async () => {
    const gate = deferred();
    const boom = new Error('mapper failed');
    let closed = 0;
    async function* input() { try { yield 1; yield 2; yield 3; } finally { closed++; } }
    const stream = Readable.from(input()).map(async x => { if (x === 1) await gate.promise; if (x === 2) throw boom; return x; }, { concurrency: 3 });
    const iterator = stream[Symbol.asyncIterator]();
    const first = iterator.next();
    await tick(); gate.resolve();
    assert.equal((await first).value, 1);
    await assert.rejects(iterator.next(), e => e === boom);
    assert.equal(closed, 1);
  });
  test(`${name}: early return closes the upstream iterator`, timeout, async () => {
    let closed = 0;
    async function* input() { try { for (let i = 0; i < 100; i++) yield i; } finally { closed++; } }
    const source = Readable.from(input());
    for await (const value of source.map(x => x)) { assert.equal(value, 0); break; }
    await tick();
    assert.equal(closed, 1);
    assert.equal(source.destroyed, true);
  });
  test(`${name}: callbacks see a genuine signal and abort rejects`, timeout, async () => {
    const controller = new AbortController();
    let signal;
    const stream = Readable.from([1]).map(async (x, options) => {
      signal = options.signal;
      await new Promise(resolve => options.signal.addEventListener('abort', resolve, { once: true }));
      return x;
    }, { signal: controller.signal });
    const out = collect(stream);
    await tick();
    assert(signal instanceof AbortSignal);
    controller.abort('cancelled');
    await assert.rejects(out, { name: 'AbortError', code: 'ABORT_ERR' });
    assert.equal(signal.aborted, true);
  });
  test(`${name}: pre-aborted input never invokes the mapper`, timeout, async () => {
    let calls = 0;
    const controller = new AbortController(); controller.abort('before');
    await assert.rejects(collect(Readable.from([1]).map(x => { calls++; return x; }, { signal: controller.signal })), { code: 'ABORT_ERR' });
    assert.equal(calls, 0);
  });
  test(`${name}: validates callbacks and bounded options eagerly`, timeout, () => {
    for (const fn of [null, undefined, {}, 1]) assert.throws(() => Readable.from([]).map(fn), { code: 'ERR_INVALID_ARG_TYPE' });
    for (const concurrency of [0, -1, NaN, Infinity]) assert.throws(() => Readable.from([]).map(x => x, { concurrency }), { code: 'ERR_OUT_OF_RANGE' });
    for (const highWaterMark of [-1, NaN, Infinity]) assert.throws(() => Readable.from([]).filter(x => x, { highWaterMark }), { code: 'ERR_OUT_OF_RANGE' });
    assert.throws(() => Readable.from([]).map(x => x, { signal: {} }), { code: 'ERR_INVALID_ARG_TYPE' });
  });
  test(`${name}: Node-compatible numeric coercion and null options`, timeout, async () => {
    assert.deepEqual(await collect(Readable.from([1]).map(x => x, { concurrency: '2', highWaterMark: 1.9 })), [1]);
    assert.deepEqual(await collect(Readable.from([1]).map(x => x, null)), [1]);
  });
  test(`${name}: filter preserves chunk identity`, timeout, async () => {
    const values = [{ id: 1 }, { id: 2 }];
    const output = await collect(Readable.from(values).filter(x => Promise.resolve(x.id === 2)));
    assert.equal(output[0], values[1]);
  });
  test(`${name}: observes thenables once and handles throwing then getters`, timeout, async () => {
    let calls = 0;
    assert.deepEqual(await collect(Readable.from([1]).map(x => ({ then(resolve) { calls++; resolve(x + 1); } }))), [2]);
    assert.equal(calls, 1);
    const boom = new Error('getter');
    await assert.rejects(collect(Readable.from([1]).map(() => ({ get then() { throw boom; } }))), e => e === boom);
  });
}

test('candidate: destruction interrupts a mapper that never settles', timeout, async () => {
  let callbackSignal;
  const source = candidate.Readable.from([1, 2, 3]);
  const stream = source.map((value, { signal }) => { callbackSignal = signal; return new Promise(() => {}); });
  const reading = collect(stream);
  const closed = new Promise(resolve => stream.once('close', resolve));
  await tick();
  stream.destroy();
  await closed;
  await assert.rejects(reading);
  assert.equal(callbackSignal.aborted, true);
  assert.equal(source.destroyed, true);
});
test('candidate: cancellation interrupts an idle upstream read', timeout, async () => {
  const source = new candidate.Readable({ objectMode: true, read() {} });
  const controller = new AbortController();
  const stream = source.map(x => x, { signal: controller.signal });
  const output = collect(stream);
  await tick(); controller.abort('idle');
  await assert.rejects(output, { code: 'ABORT_ERR' });
  assert.equal(source.destroyed, true);
});
test('candidate: spoofed abort events do not cancel an operation', timeout, async () => {
  const controller = new AbortController();
  const stream = candidate.Readable.from([1, 2]).map(x => {
    controller.signal.dispatchEvent(new Event('abort'));
    return x;
  }, { signal: controller.signal });
  assert.deepEqual(await collect(stream), [1, 2]);
});
test('candidate: public abort listeners cannot suppress cancellation', timeout, async () => {
  const controller = new AbortController();
  controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
  const stream = candidate.Readable.from([1]).map(() => new Promise(() => {}), { signal: controller.signal });
  const output = collect(stream);
  await tick(); controller.abort('blocked');
  await assert.rejects(output, { code: 'ABORT_ERR' });
});
test('candidate: methods are writable/configurable/non-enumerable', () => {
  for (const name of ['map', 'filter']) {
    const d = Object.getOwnPropertyDescriptor(candidate.Readable.prototype, name);
    assert.equal(d.enumerable, false); assert.equal(d.writable, true); assert.equal(d.configurable, true);
  }
});

for (const [name, { Readable }] of Object.entries(lanes)) {
  test(`${name}: collection operators compose without eager arrays`, timeout, async () => {
    assert.deepEqual(await Readable.from([1, 2, 3]).map(x => x * 2).flatMap(x => [x, x + 1]).filter(x => x > 3).toArray(), [4, 5, 6, 7]);
  });
  test(`${name}: flatMap accepts promised sync/async iterables and strings`, timeout, async () => {
    async function* inner(x) { yield x; yield Promise.resolve(x + 1); }
    assert.deepEqual(await Readable.from([1, 3]).flatMap(async x => inner(x), { concurrency: 2 }).toArray(), [1, 2, 3, 4]);
    assert.deepEqual(await Readable.from(['a', '😀']).flatMap(x => x).toArray(), ['a', '😀']);
    assert.deepEqual(await Readable.from([1]).flatMap(() => [Promise.resolve(2), Promise.resolve(3)]).toArray(), [2, 3]);
  });
  test(`${name}: flatMap rejects non-iterables`, timeout, async () => {
    for (const value of [null, undefined, 42, {}]) await assert.rejects(Readable.from([1]).flatMap(() => value).toArray(), TypeError);
  });
  test(`${name}: flatMap closes the inner and outer iterators`, timeout, async () => {
    let innerClosed = 0, outerClosed = 0;
    async function* outer() { try { yield 1; yield 2; } finally { outerClosed++; } }
    async function* inner() { try { yield 10; yield 11; } finally { innerClosed++; } }
    for await (const value of Readable.from(outer()).flatMap(inner)) { assert.equal(value, 10); break; }
    await tick(); assert.equal(innerClosed, 1); assert.equal(outerClosed, 1);
  });
  test(`${name}: reduce distinguishes omitted and explicit undefined initial`, timeout, async () => {
    assert.equal(await Readable.from([1, 2, 3]).reduce(async (a, b) => a + b), 6);
    assert.equal(await Readable.from([1, 2, 3]).reduce(async (a, b) => a + b, 10), 16);
    assert.equal(await Readable.from([]).reduce((a, b) => a + b, undefined), undefined);
    await assert.rejects(Readable.from([]).reduce((a, b) => a + b), { code: 'ERR_MISSING_ARGS' });
    const values = [];
    await Readable.from([1]).reduce((a, b) => { values.push(a, b); }, undefined);
    assert.deepEqual(values, [undefined, 1]);
  });
  test(`${name}: reduce is sequential and propagates callback failure`, timeout, async () => {
    let active = 0, peak = 0;
    assert.equal(await Readable.from([1, 2, 3]).reduce(async (a, b) => { peak = Math.max(peak, ++active); await tick(); active--; return a + b; }, 0), 6);
    assert.equal(peak, 1);
    const boom = new Error('reduce');
    await assert.rejects(Readable.from([1]).reduce(() => { throw boom; }, 0), e => e === boom);
  });
  test(`${name}: some/every/find values and empty identities`, timeout, async () => {
    assert.equal(await Readable.from([1, 2, 3]).some(async x => x === 2), true);
    assert.equal(await Readable.from([1, 2, 3]).every(async x => x < 4), true);
    assert.equal(await Readable.from([1, 2, 3]).every(async x => x < 3), false);
    assert.equal(await Readable.from([1, 2, 3]).find(async x => x === 2), 2);
    assert.equal(await Readable.from([]).some(() => true), false);
    assert.equal(await Readable.from([]).every(() => false), true);
    assert.equal(await Readable.from([]).find(() => true), undefined);
  });
  test(`${name}: short-circuiting consumers close the input`, timeout, async () => {
    for (const method of ['some', 'every', 'find']) {
      let closed = false;
      async function* input() { try { let x = 0; while (true) yield x++; } finally { closed = true; } }
      const source = Readable.from(input());
      await source[method](x => method === 'every' ? false : true);
      // Node completes upstream IteratorClose on the following turn.
      await tick();
      assert.equal(closed, true);
      assert.equal(source.destroyed, true);
    }
  });
  test(`${name}: forEach bounds concurrency, awaits callbacks, ignores null output`, timeout, async () => {
    let active = 0, peak = 0, count = 0;
    const value = await Readable.from([1, 2, 3, 4, 5]).forEach(async () => {
      peak = Math.max(peak, ++active); await tick(); active--; count++; return null;
    }, { concurrency: 3 });
    assert.equal(value, undefined); assert.equal(count, 5); assert(peak <= 3); assert(peak > 1);
  });
  test(`${name}: consumption methods reject invalid callbacks/options asynchronously`, timeout, async () => {
    for (const method of ['forEach', 'some', 'every', 'find', 'reduce']) {
      await assert.rejects(Readable.from([])[method](null), { code: 'ERR_INVALID_ARG_TYPE' });
    }
    await assert.rejects(Readable.from([]).toArray({ signal: {} }), { code: 'ERR_INVALID_ARG_TYPE' });
  });
}
test('candidate: aborted toArray releases an idle input', timeout, async () => {
  const controller = new AbortController();
  const source = new candidate.Readable({ objectMode: true, read() {} });
  const result = source.toArray({ signal: controller.signal });
  await tick(); controller.abort('stop');
  await assert.rejects(result, { code: 'ABORT_ERR' });
  assert.equal(source.destroyed, true);
});
test('candidate: flatMap abort interrupts an idle inner Readable', timeout, async () => {
  const controller = new AbortController();
  const inner = new candidate.Readable({ objectMode: true, read() {} });
  const outer = candidate.Readable.from([1]);
  const result = outer.flatMap(() => inner, { signal: controller.signal }).toArray();
  await tick(); controller.abort('inner');
  await assert.rejects(result, { code: 'ABORT_ERR' });
  assert.equal(inner.destroyed, true); assert.equal(outer.destroyed, true);
});

for (const [name, { Readable }] of Object.entries(lanes)) {
  test(`${name}: successful flattening preserves an autoDestroy:false inner stream`, timeout, async () => {
    const inner = Readable.from([10, 11], { autoDestroy: false });
    assert.deepEqual(await Readable.from([1]).flatMap(() => inner).toArray(), [10, 11]);
    assert.equal(inner.destroyed, false);
    inner.destroy();
  });
}

test('candidate: abort interrupts never-settling reducer and sequential forEach', timeout, async () => {
  for (const method of ['reduce', 'forEach']) {
    const controller = new AbortController();
    const source = candidate.Readable.from([1, 2]);
    const callback = () => new Promise(() => {});
    const result = method === 'reduce'
      ? source.reduce(callback, 0, { signal: controller.signal })
      : source.forEach(callback, { signal: controller.signal });
    await tick(); controller.abort('consumer');
    await assert.rejects(result, { code: 'ABORT_ERR' });
    assert.equal(source.destroyed, true);
  }
});
test('candidate: large streaming reduction stays sequential and exact', { timeout: 15000 }, async () => {
  const count = 25000;
  function* input() { for (let i = 0; i < count; i++) yield i; }
  const total = await candidate.Readable.from(input()).map(x => x + 1, { concurrency: 8, highWaterMark: 8 })
    .filter(x => x % 2 === 0, { concurrency: 4 }).reduce((sum, x) => sum + x, 0);
  const even = count / 2;
  assert.equal(total, even * (even + 1));
});

// These adversarial cases target the candidate's cancellation ownership, not
// Node's scheduling choices for a mapper that never cooperates with abort.
test('candidate: synthetic callback-signal abort cannot disable cancellation', timeout, async () => {
  const controller = new AbortController();
  const source = candidate.Readable.from([1]);
  const result = source.map((value, { signal }) => {
    signal.dispatchEvent(new Event('abort'));
    return new Promise(() => {});
  }, { signal: controller.signal });
  const pending = result.toArray();
  // Attach before abort so neither timing nor the test runner masks rejection.
  const verdict = pending.then(() => 'resolved', error => error.code);
  await tick();
  controller.abort('real abort');
  const status = await Promise.race([verdict, new Promise(resolve => setTimeout(() => resolve('stalled'), 50))]);
  result.destroy();
  await verdict;
  assert.equal(status, 'ABORT_ERR');
  assert.equal(source.destroyed, true);
});

test('candidate: abort during iterator.next observes a rejected returned promise', timeout, async () => {
  // Run in an isolated process: node:test treats an unhandledRejection as a
  // failure even when a temporary listener tries to observe it locally.
  const { spawnSync } = require('node:child_process');
  const operatorPath = path.join(root, 'stream_operators.js');
  const script = `
    const fs = require('node:fs');
    const vm = require('node:vm');
    const { Readable } = require('node:stream');
    const install = vm.runInThisContext(fs.readFileSync(${JSON.stringify(operatorPath)}, 'utf8'));
    class R extends Readable {}
    install({ Readable: R });
    const controller = new AbortController();
    const stream = new R({ read() {} });
    stream[Symbol.asyncIterator] = function () { return {
      next() { controller.abort('during next'); return Promise.reject(new Error('late rejection')); },
      return() { return Promise.resolve({ done: true }); }
    }; };
    stream.toArray({ signal: controller.signal }).then(
      () => { throw Error('unexpected success'); },
      error => { if (error.code !== 'ABORT_ERR') throw error; }
    );
    setTimeout(() => {}, 10);
  `;
  const child = spawnSync(process.execPath, ['--unhandled-rejections=strict', '-e', script],
    { encoding: 'utf8', timeout: 2000 });
  assert.equal(child.status, 0, child.stderr || String(child.error));
});

test('candidate: take/drop are installed, not inherited from Node', () => {
  for (const name of ['take', 'drop']) {
    const descriptor = Object.getOwnPropertyDescriptor(candidate.Readable.prototype, name);
    assert(descriptor, `${name} must be owned by the candidate`);
    assert.notEqual(descriptor.value, native.Readable.prototype[name]);
    assert.equal(descriptor.enumerable, false);
    assert.equal(descriptor.configurable, true);
    assert.equal(descriptor.writable, true);
  }
});

for (const [name, { Readable }] of Object.entries(lanes)) {
  test(`${name}: take/drop chain with async mapping and flattening`, timeout, async () => {
    assert.deepEqual(await Readable.from([1, 2, 3, 4, 5]).drop(1).take(3)
      .map(async x => x * 2).flatMap(x => [x, x + 1]).toArray(), [4, 5, 6, 7, 8, 9]);
    assert.deepEqual(await Readable.from([]).take(10).toArray(), []);
    assert.deepEqual(await Readable.from([]).drop(10).toArray(), []);
    assert.deepEqual(await Readable.from([1, 2]).drop(10).toArray(), []);
    assert.deepEqual(await Readable.from([1, 2]).take(10).toArray(), [1, 2]);
  });
  test(`${name}: take/drop coerce counts once and handle fractions and infinity`, timeout, async () => {
    for (const [count, takeExpected, dropExpected] of [
      [0, [], [1, 2, 3]], [-0, [], [1, 2, 3]], [NaN, [], [1, 2, 3]],
      [undefined, [], [1, 2, 3]], [null, [], [1, 2, 3]], [false, [], [1, 2, 3]],
      [true, [1], [2, 3]], ['2', [1, 2], [3]], [1n, [1], [2, 3]],
      [1.5, [1, 2], [3]], [Infinity, [1, 2, 3], []],
      [Number.MAX_SAFE_INTEGER + 1, [1, 2, 3], []],
    ]) {
      assert.deepEqual(await Readable.from([1, 2, 3]).take(count).toArray(), takeExpected);
      assert.deepEqual(await Readable.from([1, 2, 3]).drop(count).toArray(), dropExpected);
    }
    for (const method of ['take', 'drop']) {
      let calls = 0;
      const limit = { valueOf() { calls++; return 1.5; } };
      const stream = Readable.from([1, 2, 3])[method](limit);
      assert.equal(calls, 1);
      await stream.toArray();
      assert.equal(calls, 1);
    }
  });
  test(`${name}: take/drop reject invalid counts/options before starting work`, timeout, async () => {
    for (const method of ['take', 'drop']) {
      for (const count of [-1, -0.5, -Infinity]) {
        assert.throws(() => Readable.from([])[method](count), { code: 'ERR_OUT_OF_RANGE' });
      }
      assert.throws(() => Readable.from([])[method](Symbol('count')), TypeError);
      for (const options of [1, true, 'options', [], { signal: {} }]) {
        assert.throws(() => Readable.from([])[method](1, options), { code: 'ERR_INVALID_ARG_TYPE' });
      }
      const source = Readable.from([1]);
      const error = new Error('count conversion');
      assert.throws(() => source[method]({ valueOf() { throw error; } }), e => e === error);
      assert.equal(source.destroyed, false);
      source.destroy();
    }
  });
  test(`${name}: take/drop preserve undefined and object chunk identity`, timeout, async () => {
    const first = {}, second = {};
    const chunks = [first, undefined, second];
    const result = await Readable.from(chunks).drop(1).take(2).toArray();
    assert.deepEqual(result, [undefined, second]);
    assert.equal(result[1], second);
  });
  test(`${name}: take/drop stay lazy and bound reads on an infinite source`, timeout, async () => {
    let pulls = 0, closes = 0;
    async function* input() { try { while (true) { pulls++; yield pulls; } } finally { closes++; } }
    const source = Readable.from(input());
    const output = source.drop(100).take(5);
    assert.equal(pulls, 0);
    assert.deepEqual(await output.toArray(), [101, 102, 103, 104, 105]);
    await tick();
    assert(pulls <= 109, `unbounded prefetch: ${pulls}`);
    assert.equal(closes, 1);
    assert.equal(source.destroyed, true);
  });
  test(`${name}: early break closes take/drop upstream exactly once`, timeout, async () => {
    for (const method of ['take', 'drop']) {
      let closes = 0;
      async function* input() { try { let i = 0; while (true) yield i++; } finally { closes++; } }
      const source = Readable.from(input());
      for await (const chunk of source[method](5)) break;
      await tick();
      assert.equal(source.destroyed, true);
      assert.equal(closes, 1);
    }
  });
  test(`${name}: exhausted take/drop do not destroy autoDestroy:false inputs`, timeout, async () => {
    for (const method of ['take', 'drop']) {
      const source = Readable.from([1, 2], { autoDestroy: false });
      assert.deepEqual(await source[method](5).toArray(), method === 'take' ? [1, 2] : []);
      assert.equal(source.destroyed, false);
      source.destroy();
    }
  });
  test(`${name}: take/drop propagate original upstream failure`, timeout, async () => {
    const boom = new Error('source');
    for (const method of ['take', 'drop']) {
      async function* input() { yield 1; throw boom; }
      await assert.rejects(Readable.from(input())[method](10).toArray(), e => e === boom);
    }
  });
  test(`${name}: take/drop reject pre-aborted signals without starting a source`, timeout, async () => {
    for (const method of ['take', 'drop']) {
      const controller = new AbortController(); controller.abort('before start');
      let pulls = 0;
      const source = new Readable({ objectMode: true, read() { pulls++; } });
      await assert.rejects(source[method](1, { signal: controller.signal }).toArray(), { code: 'ABORT_ERR' });
      assert.equal(pulls, 0);
      source.destroy();
    }
  });
}

for (const method of ['take', 'drop']) {
  test(`candidate: ${method} abort interrupts an idle upstream read`, timeout, async () => {
    const controller = new AbortController();
    const source = new candidate.Readable({ objectMode: true, read() {} });
    const result = source[method](2, { signal: controller.signal }).toArray();
    const rejected = assert.rejects(result, { code: 'ABORT_ERR', cause: 'idle' });
    await tick(); controller.abort('idle');
    await rejected;
    assert.equal(source.destroyed, true);
  });
  test(`candidate: destroying ${method} interrupts an idle upstream read`, timeout, async () => {
    const source = new candidate.Readable({ objectMode: true, read() {} });
    const output = source[method](2);
    const error = new Error('consumer closed');
    const rejected = assert.rejects(output.toArray(), e => e === error);
    await tick(); output.destroy(error);
    await rejected;
    assert.equal(source.destroyed, true);
  });
}
