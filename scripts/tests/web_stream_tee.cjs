'use strict';
// Execute the exact engine-owned factory on host primitives and compare with
// Node's independent stream implementation. This is NOT native-engine proof.
// Run: node scripts/tests/web_stream_tee.cjs [path/to/web_stream_module.js]
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const reference = require('node:stream/web');
const sourcePath = process.argv[2] || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/web_stream_module.js');
const candidate = vm.runInThisContext(fs.readFileSync(sourcePath, 'utf8'), { filename: sourcePath });
const tick = () => new Promise(resolve => setImmediate(resolve));
const collect = async stream => { const values = []; for await (const value of stream) values.push(value); return values; };
const deferred = () => { let resolve, reject; const promise = new Promise((a, b) => { resolve = a; reject = b; }); return { promise, resolve, reject }; };
async function rejectsSame(promise, reason) {
  const value = await promise.then(() => ({ failed: false }), error => ({ failed: true, error }));
  assert.equal(value.failed, true); assert.equal(value.error, reason);
}
async function bounded(promise, name) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('Unfinished stream test: ' + name)), 10000);
  })]); } finally { clearTimeout(timer); }
}
const cases = [
  ['independent fast and delayed branches preserve all values', async ({ ReadableStream: R }) => {
    let calls = 0;
    const original = new R({ pull(c) { calls++; c.enqueue(calls); if (calls === 128) c.close(); } });
    const [a, b] = original.tee();
    assert.equal(original.locked, true); assert.notEqual(a, b);
    const fast = await collect(a); const slow = await collect(b);
    assert.deepEqual(fast, Array.from({ length: 128 }, (_, i) => i + 1));
    assert.deepEqual(slow, fast);
    return [calls, original.locked, a.locked, b.locked];
  }],
  ['object, byte-view and thenable chunks keep identity across branches', async ({ ReadableStream: R }) => {
    const object = { value: 1 }, bytes = new Uint8Array([1, 2]);
    let thenCalls = 0;
    const thenable = { then() { thenCalls++; throw Error('chunk was assimilated'); } };
    const [a, b] = new R({ start(c) { c.enqueue(object); c.enqueue(bytes); c.enqueue(thenable); c.close(); } }).tee();
    const ar = a.getReader(), br = b.getReader();
    assert.equal((await ar.read()).value, object); object.value = 9;
    assert.equal((await br.read()).value.value, 9);
    assert.equal((await ar.read()).value, bytes); bytes[0] = 7;
    assert.equal((await br.read()).value[0], 7);
    assert.equal((await ar.read()).value, thenable); assert.equal((await br.read()).value, thenable);
    assert.equal((await ar.read()).done, true); assert.equal((await br.read()).done, true);
    return thenCalls;
  }],
  ['both idle branches stop requesting upstream data', async ({ ReadableStream: R }) => {
    let pulls = 0;
    const source = new R({ pull(c) { c.enqueue(++pulls); } });
    const [a, b] = source.tee(); await tick(); const initial = pulls;
    await tick(); assert.equal(pulls, initial);
    const r = a.getReader(); assert.equal((await r.read()).value, 1);
    await tick(); const after = pulls; await tick(); assert.equal(pulls, after);
    await Promise.all([r.cancel('a'), b.cancel('b')]);
    return [initial, after];
  }],
  ['one cancellation waits while its sibling completes normally', async ({ ReadableStream: R }) => {
    let cancelled = 0, settled = false;
    const source = new R({ start(c) { c.enqueue(1); c.enqueue(2); c.close(); }, cancel() { cancelled++; } });
    const [a, b] = source.tee();
    const pending = a.cancel('unused').then(() => { settled = true; });
    await tick(); assert.equal(settled, false);
    assert.deepEqual(await collect(b), [1, 2]); await pending;
    return [cancelled, settled, source.locked];
  }],
  ['both cancellations use branch order and wait for source cleanup', async ({ ReadableStream: R }) => {
    for (const order of [[0, 1], [1, 0]]) {
      const finish = deferred(); const reasons = [{ branch: 1 }, false];
      let calls = 0, received, settled = 0;
      const source = new R({ cancel(value) { calls++; received = value; return finish.promise; } });
      const branches = source.tee();
      const first = branches[order[0]].cancel(reasons[order[0]]).then(() => { settled++; });
      await tick(); assert.equal(calls, 0); assert.equal(settled, 0);
      const second = branches[order[1]].cancel(reasons[order[1]]).then(() => { settled++; });
      assert.equal(calls, 1); assert.deepEqual(received, reasons);
      assert.equal(received[0], reasons[0]); await tick(); assert.equal(settled, 0);
      finish.resolve('ignored result'); await Promise.all([first, second]);
      assert.equal(settled, 2); assert.equal(source.locked, true);
    }
    return 'ordered cleanup';
  }],
  ['source cancellation failure rejects both promises without reopening reads', async ({ ReadableStream: R }) => {
    for (const reason of [undefined, false, 0, '', { marker: 'cleanup' }]) {
      const source = new R({ cancel() { return Promise.reject(reason); } });
      const [a, b] = source.tee(); const ar = a.getReader(), br = b.getReader();
      const pa = ar.read(), pb = br.read();
      const ca = ar.cancel(1), cb = br.cancel(2);
      await Promise.all([rejectsSame(ca, reason), rejectsSame(cb, reason)]);
      assert.equal((await pa).done, true); assert.equal((await pb).done, true);
      await Promise.all([ar.closed, br.closed]);
    }
    return 'all falsy failures retained';
  }],
  ['source errors reach both pending branches with the original value', async ({ ReadableStream: R }) => {
    for (const reason of [undefined, false, 0, '', { marker: 'source' }]) {
      let controller;
      const source = new R({ start(c) { controller = c; } });
      const [a, b] = source.tee(); const ar = a.getReader(), br = b.getReader();
      const checks = [rejectsSame(ar.read(), reason), rejectsSame(br.read(), reason),
        rejectsSame(ar.closed, reason), rejectsSame(br.closed, reason)];
      controller.error(reason); await Promise.all(checks);
    }
    return 'errors propagated';
  }],
  ['source error resolves an abandoned branch cancellation', async ({ ReadableStream: R }) => {
    let controller, calls = 0;
    const source = new R({ start(c) { controller = c; }, cancel() { calls++; } });
    const [a, b] = source.tee(); const pending = a.cancel('finished');
    controller.error(false); await pending;
    await rejectsSame(b.getReader().read(), false);
    return calls;
  }],
  ['an error discards buffered branch chunks before future reads', async ({ ReadableStream: R }) => {
    let controller;
    const source = new R({ start(c) { controller = c; c.enqueue('queued'); } });
    const [a, b] = source.tee(); await tick(); controller.error('stop'); await tick();
    await Promise.all([rejectsSame(a.getReader().read(), 'stop'), rejectsSame(b.getReader().read(), 'stop')]);
    return 'no stale queue';
  }],
  ['enqueue then close in one pull preserves the final chunk', async ({ ReadableStream: R }) => {
    const original = new R({ pull(c) { c.enqueue(42); c.close(); } }, { highWaterMark: 0 });
    const [a, b] = original.tee();
    assert.deepEqual(await Promise.all([collect(a), collect(b)]), [[42], [42]]);
    return original.locked;
  }],
  ['already closed and already errored sources retain terminal behavior', async ({ ReadableStream: R }) => {
    const closed = new R({ start(c) { c.close(); } });
    const pair = closed.tee(); assert.deepEqual(await Promise.all(pair.map(collect)), [[], []]);
    const failure = { same: true };
    const errored = new R({ start(c) { c.error(failure); } });
    const branches = errored.tee();
    await Promise.all(branches.map(s => rejectsSame(s.getReader().read(), failure)));
    return [closed.locked, errored.locked];
  }],
  ['locked and forged receivers reject synchronously', async ({ ReadableStream: R }) => {
    for (const receiver of [undefined, null, {}, Object.create(R.prototype)]) {
      assert.throws(() => R.prototype.tee.call(receiver), TypeError);
    }
    const source = new R(); const reader = source.getReader();
    assert.throws(() => source.tee(), TypeError); reader.releaseLock();
    const [a, b] = source.tee(); assert.throws(() => source.tee(), TypeError);
    await Promise.all([a.cancel(), b.cancel()]);
    return source.locked;
  }],
  ['tee bypasses replaced public reader and controller methods', async ({ ReadableStream: R, ReadableStreamDefaultReader: Reader,
      ReadableStreamDefaultController: Controller }) => {
    const source = new R({ start(c) { c.enqueue('trusted internals'); c.close(); } });
    Object.defineProperty(source, 'getReader', { get() { throw Error('public getter invoked'); } });
    const read = Reader.prototype.read, enqueue = Controller.prototype.enqueue, close = Controller.prototype.close;
    let branches;
    try {
      Reader.prototype.read = () => { throw Error('public read invoked'); };
      Controller.prototype.enqueue = () => { throw Error('public enqueue invoked'); };
      Controller.prototype.close = () => { throw Error('public close invoked'); };
      branches = R.prototype.tee.call(source); await tick();
    } finally { Reader.prototype.read = read; Controller.prototype.enqueue = enqueue; Controller.prototype.close = close; }
    return Promise.all(branches.map(collect));
  }],
  ['nested tees cancel the original once with a reason tree', async ({ ReadableStream: R }) => {
    let reason, calls = 0;
    const source = new R({ cancel(value) { calls++; reason = value; } });
    const [left, right] = source.tee(); const [a, b] = left.tee();
    const pa = a.cancel('a'), pr = right.cancel('r'); await tick(); assert.equal(calls, 0);
    await Promise.all([pa, pr, b.cancel('b')]);
    assert.deepEqual(reason, [['a', 'b'], 'r']); return calls;
  }],
  ['sibling pipe failure does not truncate the successful destination', async ({ ReadableStream: R, WritableStream: W }) => {
    let calls = 0; const failure = { sink: true };
    const source = new R({ start(c) { c.enqueue(1); c.enqueue(2); c.enqueue(3); c.close(); }, cancel() { calls++; } });
    const [a, b] = source.tee(); const output = [];
    const pa = a.pipeTo(new W({ write(value) { if (value === 2) throw failure; } }));
    const pb = b.pipeTo(new W({ write(value) { output.push(value); } }));
    await Promise.all([rejectsSame(pa, failure), pb]); assert.deepEqual(output, [1, 2, 3]);
    return [calls, a.locked, b.locked];
  }],
  ['in-flight asynchronous pulls are serialized across competing readers', async ({ ReadableStream: R }) => {
    let count = 0, active = 0, maximum = 0;
    const source = new R({ async pull(c) { active++; maximum = Math.max(maximum, active); await Promise.resolve();
      c.enqueue(++count); if (count === 512) c.close(); active--; } });
    const [a, b] = source.tee();
    const values = await Promise.all([collect(a), collect(b)]);
    assert.deepEqual(values[0], values[1]); assert.equal(values[0].length, 512);
    assert.equal(maximum, 1); return count;
  }],
  ['cancellation can reenter without a second upstream effect', async ({ ReadableStream: R }) => {
    let a, b, count = 0;
    const source = new R({ cancel() { count++; a.cancel('again'); b.cancel('again'); } });
    [a, b] = source.tee(); await Promise.all([a.cancel('first'), b.cancel('second')]);
    return count;
  }],
  ['cancelling during deferred publication suppresses only that branch', async ({ ReadableStream: R }) => {
    let c;
    const source = new R({ start(value) { c = value; } }, { highWaterMark: 0 });
    const [a, b] = source.tee(); const ar = a.getReader(), br = b.getReader();
    const ra = ar.read(), rb = br.read(); await tick();
    c.enqueue('last'); const cancelled = ar.cancel('abandoned'); c.close();
    assert.deepEqual(await ra, { value: undefined, done: true });
    assert.deepEqual(await rb, { value: 'last', done: false });
    assert.equal((await br.read()).done, true); await cancelled;
    return 'publication cancellation';
  }]
];
(async function () {
  for (const [name, execute] of cases) {
    const expected = await bounded(execute(reference), name + ' (Node)');
    const actual = await bounded(execute(candidate), name + ' (engine factory on host)');
    assert.deepEqual(actual, expected, name);
    console.log('PASS ' + name);
  }
  console.log('TEE_HOST_COMPLETE ' + cases.length);
})().catch(error => { console.error(error); process.exitCode = 1; });
