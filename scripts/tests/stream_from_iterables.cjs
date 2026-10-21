'use strict';
// Execute the complete production stream factory. Node supplies JS, Buffer,
// emitter, decoder, AbortSignal and nextTick primitives, NOT its stream kernel.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const events = require('node:events');
const decoder = require('node:string_decoder');
const reference = require('node:stream');
const { createHook } = require('node:async_hooks');
const sourcePath = process.env.STREAM_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_module.js');
function load(file = sourcePath) {
  return Function('__franken_stream_events', '__franken_stream_string_decoder',
    '__franken_stream_next_tick', 'return ' + fs.readFileSync(file, 'utf8'))(
      events, decoder, process.nextTick);
}
const candidate = load();
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
async function collect(io, source, options, slow = false) {
  const output = [];
  const input = io.Readable.from(source, options);
  const sink = new io.Writable({ objectMode: options?.objectMode !== false,
    highWaterMark: 1, write(value, encoding, done) {
      output.push(value); if (slow) setImmediate(done); else done();
    } });
  await io.promises.pipeline(input, sink);
  return output;
}
function observe(stream, t) {
  const errors = [];
  stream.on('error', error => errors.push(error));
  const closed = new Promise(resolve => stream.once('close', resolve));
  t.after(() => { if (!stream.destroyed) stream.destroy(); });
  return { errors, closed };
}
const bounded = { timeout: 3000 };
for (const [name, io] of [['candidate', candidate], ['node', reference]]) {
  test(`${name}: lazy async cursor records are read exactly once, never skipped`, bounded, async () => {
    const records = ['first', 'second', 'third']; let values = 0, returns = 0;
    const cursor = { [Symbol.asyncIterator]() { return this; },
      async next() { return records.length ? { done: false,
        get value() { values++; return records.shift() ?? null; } } : { done: true }; },
      return() { returns++; return { done: true }; } };
    assert.deepEqual(await collect(io, cursor), ['first', 'second', 'third']);
    assert.equal(values, 3); assert.equal(returns, 1);
  });
  test(`${name}: async cursor byte windows preserve every byte with slow writes`, bounded, async () => {
    let n = 0, values = 0;
    const source = { [Symbol.asyncIterator]() { return this; },
      async next() { const index = n++; return index === 3 ? { done: true } : {
        done: false, get value() { values++; return Buffer.from('_' + index + '_').subarray(1, 2); }
      }; } };
    const chunks = await collect(io, source, { objectMode: false, highWaterMark: 1 }, true);
    assert.equal(Buffer.concat(chunks).toString(), '012'); assert.equal(values, 3);
  });
  test(`${name}: sync records resume after isolated promises without loss or reordering`, bounded, async () => {
    const values = Array.from({ length: 1024 }, (_, i) => i % 173 === 0 ? Promise.resolve(i) : i);
    assert.deepEqual(await collect(io, values, undefined, true), Array.from({ length: 1024 }, (_, i) => i));
  });
  test(`${name}: async iterator values remain values rather than an extra await`, bounded, async () => {
    const value = Promise.resolve('object-mode-value'); let next = 0;
    const source = { [Symbol.asyncIterator]() { return this; },
      async next() { return next++ ? { done: true } : { done: false, value }; } };
    const out = await collect(io, source); assert.equal(out[0], value);
  });
  test(`${name}: null is refused, not silently published as EOF`, bounded, async () => {
    await assert.rejects(collect(io, ['prefix', Promise.resolve(null)]), { code: 'ERR_STREAM_NULL_VALUES' });
  });
  test(`${name}: a producer rejection retains its original identity`, bounded, async () => {
    const reason = new Error('producer failed');
    const source = { [Symbol.iterator]() { return this; }, next() { throw reason; },
      return() { return { done: true }; } };
    await assert.rejects(collect(io, source), error => error === reason);
  });
  test(`${name}: no demand means no next, and backpressure bounds async reads`, bounded, async t => {
    let calls = 0;
    const source = { [Symbol.asyncIterator]() { return this; },
      async next() { calls++; return { value: calls, done: false }; },
      return() { return { done: true }; } };
    const r = io.Readable.from(source, { highWaterMark: 1 }); const observed = observe(r, t);
    await tick(); assert.equal(calls, 0);
    r.read(0); await tick(); assert.equal(calls, 1); assert.equal(r.readableLength, 1);
    r.destroy(); await observed.closed; assert.equal(calls, 1);
  });
  test(`${name}: normal EOF awaits producer return before close`, bounded, async t => {
    const barrier = deferred(); let returned = 0, closed = false;
    const source = { [Symbol.iterator]() { return this; }, next() { return { done: true }; },
      return() { returned++; return barrier.promise; } };
    const r = io.Readable.from(source); const observed = observe(r, t);
    r.on('close', () => { closed = true; }); r.resume(); await tick();
    assert.equal(returned, 1); assert.equal(closed, false);
    barrier.resolve({ done: true }); await observed.closed; assert.equal(closed, true);
  });
  test(`${name}: error cleanup uses throw then return when throw is incomplete`, bounded, async t => {
    const primary = new Error('stop'), calls = [];
    const source = { [Symbol.iterator]() { return this; }, next() { return { value: 1, done: false }; },
      throw(error) { assert.equal(error, primary); calls.push('throw'); return { done: false, value: Promise.resolve() }; },
      return() { calls.push('return'); return { done: true }; } };
    const r = io.Readable.from(source); const observed = observe(r, t);
    r.destroy(primary); await observed.closed;
    assert.deepEqual(calls, ['throw', 'return']); assert.equal(observed.errors[0], primary);
  });
  test(`${name}: completed throw does not return a producer twice`, bounded, async t => {
    const primary = new Error('stop'); let returns = 0;
    const source = { [Symbol.iterator]() { return this; }, next() { return { done: false, value: 1 }; },
      throw() { return { done: true }; }, return() { returns++; return { done: true }; } };
    const r = io.Readable.from(source); const observed = observe(r, t);
    r.destroy(primary); await observed.closed; assert.equal(returns, 0);
  });
  test(`${name}: strings and Buffers retain the single-chunk fast path`, bounded, async () => {
    const bytes = Buffer.from('é');
    assert.deepEqual(await collect(io, 'é'), ['é']);
    const out = await collect(io, bytes); assert.equal(out.length, 1); assert.equal(out[0], bytes);
  });
  test(`${name}: callable iterator result objects retain legitimate properties`, bounded, async () => {
    let n = 0;
    const source = { [Symbol.iterator]() { return this; }, next() {
      const result = function () {}; result.done = n === 3; result.value = n++; return result;
    } };
    assert.deepEqual(await collect(io, source), [0, 1, 2]);
  });
}

test('candidate: late async next cannot read value or done after destruction', bounded, async t => {
  const step = deferred(); let reads = 0, calls = 0, returns = 0;
  const source = { [Symbol.asyncIterator]() { return this; }, next() { calls++; return step.promise; },
    return() { returns++; return { done: true }; } };
  const r = candidate.Readable.from(source); const observed = observe(r, t);
  r.resume(); await tick(); r.destroy(new Error('stop')); await observed.closed;
  step.resolve({ get done() { reads++; return false; }, get value() { reads++; return 42; } });
  await tick(); assert.equal(reads, 0); assert.equal(calls, 1); assert.equal(returns, 1);
});
test('candidate: synchronous next cancellation stops before observing its result', bounded, async t => {
  let r, reads = 0, calls = 0;
  const reason = new Error('cancelled in next');
  const source = { [Symbol.iterator]() { return this; }, next() { calls++; r.destroy(reason);
    return { get done() { reads++; return false; }, get value() { reads++; return 42; } }; },
    return() { return { done: true }; } };
  r = candidate.Readable.from(source); const observed = observe(r, t); r.resume();
  await observed.closed; assert.equal(reads, 0); assert.equal(calls, 1); assert.equal(observed.errors[0], reason);
});
test('candidate: an admitted pending value is observed but never pushed after cancellation', bounded, async t => {
  for (const reject of [false, true]) {
    const value = deferred(); let pushes = 0, calls = 0;
    const source = { [Symbol.iterator]() { return this; }, next() { calls++; return { value: value.promise, done: false }; },
      return() { return { done: true }; } };
    const r = candidate.Readable.from(source); const observed = observe(r, t);
    const push = r.push; r.push = function (chunk) { pushes++; return push.call(this, chunk); };
    r.resume(); await tick(); r.destroy(); await observed.closed;
    if (reject) value.reject(new Error('late rejection')); else value.resolve('late');
    await tick(); assert.equal(pushes, 0); assert.equal(calls, 1);
  }
});
test('candidate: readline-style undefined throw completion retains the abort and awaits return', bounded, async t => {
  const done = deferred(), reason = new Error('abort'); let returned = 0, closed = false;
  const source = { [Symbol.asyncIterator]() { return this; }, next() { return new Promise(() => {}); },
    async throw(error) { assert.equal(error, reason); }, return() { returned++; return done.promise; } };
  const r = candidate.Readable.from(source); const observed = observe(r, t);
  r.on('close', () => { closed = true; }); r.destroy(reason); await tick();
  assert.equal(returned, 1); assert.equal(closed, false);
  done.resolve({ done: true }); await observed.closed; assert.equal(observed.errors[0], reason);
});
test('candidate: cleanup still returns the iterator after throw rejects', bounded, async t => {
  const reason = new Error('source'), cleanup = new Error('cleanup'); let returns = 0;
  const source = { [Symbol.iterator]() { return this; }, next() { throw reason; },
    throw() { throw cleanup; }, return() { returns++; return { done: true }; } };
  const r = candidate.Readable.from(source); const observed = observe(r, t); r.resume(); await observed.closed;
  assert.equal(returns, 1); assert.equal(r.errored, reason);
  assert(observed.errors[0] instanceof AggregateError);
  assert.deepEqual(observed.errors[0].errors, [reason, cleanup]);
});
test('candidate: falsy producer and cleanup rejections cannot become success', bounded, async () => {
  for (const reason of [undefined, null, false, 0, '']) {
    const source = { [Symbol.asyncIterator]() { return this; }, async next() { throw reason; },
      return() { return { done: true }; } };
    await assert.rejects(collect(candidate, source), error => error.code === 'ERR_STREAM_DESTROYED' && error.cause === reason);
    const cleanup = { [Symbol.iterator]() { return this; }, next() { return { done: true }; },
      return() { return Promise.reject(reason); } };
    await assert.rejects(collect(candidate, cleanup), error => error.code === 'ERR_STREAM_DESTROYED' && error.cause === reason);
  }
});
test('candidate: malformed next results fail with one pull instead of an endless stream', bounded, async () => {
  for (const step of [undefined, null, 1, 'x', false]) {
    let calls = 0;
    const source = { [Symbol.iterator]() { return this; }, next() { calls++; return step; } };
    await assert.rejects(collect(candidate, source), { code: 'ERR_INVALID_RETURN_VALUE' }); assert.equal(calls, 1);
  }
});
async function promiseCount(io, length, promised) {
  let promises = 0;
  const values = Array.from({ length }, (_, i) => promised && i === 0 ? Promise.resolve(i) : i);
  const hook = createHook({ init(id, type) { if (type === 'PROMISE') promises++; } });
  hook.enable();
  try {
    const result = await collect(io, values, undefined, true);
    assert.equal(result.length, length); assert.equal(result[length - 1], length - 1);
  } finally { hook.disable(); }
  return promises;
}
test('one early promised value does not allocate one Promise per later plain record', bounded, t => {
  // Isolate instrumentation from node:test's own scheduling promises. The
  // exact candidate and live reference execute in the same fresh process.
  const script = `
    const assert=require('node:assert/strict'),fs=require('node:fs');
    const events=require('node:events'),decoder=require('node:string_decoder');
    const reference=require('node:stream'),{createHook}=require('node:async_hooks');
    const sourcePath=${JSON.stringify(sourcePath)};
    ${load.toString()}
    ${collect.toString()}
    ${promiseCount.toString()}
    (async()=>{
      const counts={};
      for(const [name,io] of [['candidate',load()],['node',reference]]) {
        counts[name]={};
        for(const length of [128,2048]) counts[name][length]={
          plain:await promiseCount(io,length,false),mixed:await promiseCount(io,length,true)};
      }
      console.log(JSON.stringify(counts));
    })().catch(error=>{console.error(error);process.exitCode=1;});`;
  const result = require('node:child_process').spawnSync(process.execPath, ['-e', script],
    { encoding: 'utf8', timeout: 2500 });
  assert.equal(result.status, 0, result.stderr); assert.equal(result.stderr, '');
  const counts = JSON.parse(result.stdout);
  t.diagnostic('Host PROMISE-resource counts, not native allocation or speedup: ' + JSON.stringify(counts));
  const small = counts.candidate[128], large = counts.candidate[2048];
  assert(large.mixed - large.plain <= small.mixed - small.plain + 4,
    'later synchronous chunks must not retain a sticky async pump');
});
