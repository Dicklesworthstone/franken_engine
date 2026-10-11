'use strict';
// Execute the real engine-owned stream source under Node with native host
// primitives. This is a source-level test, not execution of the Rust engine.
// No external packages, engine-source rewrites, or replacement state machines.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const nativeStream = require('node:stream');

const defaultSource = path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_module.js');
function loadStream(filename) {
  const source = fs.readFileSync(filename, 'utf8');
  const factory = vm.runInThisContext(
    '(function (__franken_stream_events, __franken_stream_string_decoder, ' +
    '__franken_stream_next_tick) { return ' + source + '; })',
    { filename });
  return factory(require('node:events').EventEmitter,
    require('node:string_decoder'), process.nextTick.bind(process));
}
const tick = () => new Promise(resolve => setImmediate(resolve));
function queueOf(stream) {
  return new stream.Readable({ objectMode: true, read() {} })._readableState.buffer;
}
function checkQueue(stream) {
  let operations = 0;
  for (let seed = 1; seed <= 8; seed++) {
    const q = queueOf(stream);
    const reference = [];
    let state = seed;
    let peak = 0;
    function random() { state = (Math.imul(state, 1664525) + 1013904223) >>> 0; return state; }
    for (let i = 0; i < 12500; i++) {
      const choice = random() % 17;
      if (choice < 5) {
        const value = { seed, i };
        q.push(value); reference.push(value);
      } else if (choice < 9) {
        const value = { seed, i };
        q.unshift(value); reference.unshift(value);
      } else if (choice < 16) {
        assert.equal(q.shift(), reference.shift());
      } else {
        q.clear(); reference.length = 0; peak = 0;
      }
      peak = Math.max(peak, reference.length);
      assert.equal(q.size(), reference.length);
      assert.equal(q.first(), reference[0]);
      if (i % 19 === 0) assert.deepEqual(q.all(), reference);
      assert(q.chunks.length <= Math.max(8, peak * 2));
      operations++;
    }
    const snapshot = q.all();
    const expectedSnapshot = reference.slice();
    while (reference.length) assert.equal(q.shift(), reference.shift());
    assert.equal(q.size(), 0);
    assert.equal(q.shift(), undefined);
    assert.deepEqual(q.chunks, []);
    assert.deepEqual(snapshot, expectedSnapshot);
  }
  // Stable occupancy is the leak regression: the former backing grew once
  // per refill and retained all consumed array slots until complete drain.
  const q = queueOf(stream);
  for (let i = 0; i < 64; i++) q.push(i);
  for (let i = 0; i < 200000; i++) {
    assert.equal(q.shift(), i < 64 ? i : i - 64);
    q.push(i);
  }
  assert.equal(q.size(), 64);
  assert(q.chunks.length <= 128);
  const backingSlots = q.chunks.length;
  assert.deepEqual(q.all(), Array.from({ length: 64 }, (_, i) => 199936 + i));
  while (q.size()) q.shift();
  assert.deepEqual(q.chunks, []);

  // Growth from a wrapped head, growth by prepend, and object identity.
  const identities = Array.from({ length: 257 }, (_, i) => ({ i }));
  const r = queueOf(stream);
  identities.slice(0, 8).forEach(v => r.push(v));
  for (let i = 0; i < 5; i++) assert.equal(r.shift(), identities[i]);
  identities.slice(8).forEach(v => r.push(v));
  identities.slice(0, 5).reverse().forEach(v => r.unshift(v));
  assert.deepEqual(r.all(), identities);
  const view = r.all(); view[0] = null;
  assert.equal(r.first(), identities[0]);
  // Count numeric array traffic, not elapsed time. Prepending/draining N
  // items must do O(N) work including all geometric-growth copies. This
  // fails the old Array.unshift path without a machine-dependent timing cap.
  const measured = queueOf(stream);
  let traffic = 0;
  function observe(array) {
    return new Proxy(array, {
      get(target, key, receiver) {
        if (typeof key === 'string' && /^(0|[1-9][0-9]*)$/.test(key)) traffic++;
        return Reflect.get(target, key, receiver);
      },
      set(target, key, value) {
        if (typeof key === 'string' && /^(0|[1-9][0-9]*)$/.test(key)) traffic++;
        return Reflect.set(target, key, value);
      },
    });
  }
  let backing = observe(measured.chunks);
  Object.defineProperty(measured, 'chunks', {
    get() { return backing; }, set(value) { backing = observe(value); }, configurable: true,
  });
  const n = 1024;
  for (let i = 0; i < n; i++) measured.unshift(i);
  for (let i = n - 1; i >= 0; i--) assert.equal(measured.shift(), i);
  assert(traffic < 8 * n, `prepend traffic is not linear: ${traffic}`);
  return { randomizedOperations: operations, fifoCycles: 200000, backingSlots,
    prependItems: n, numericArrayTraffic: traffic };
}

function readableProbe(stream, mode) {
  const isObject = mode === 'object';
  const text = mode === 'text';
  const readable = new stream.Readable({ objectMode: isObject,
    encoding: text ? 'utf8' : undefined, highWaterMark: 8, read() {} });
  const reference = [];
  const expected = [];
  const actual = [];
  const marks = [];
  const values = isObject ? Array.from({ length: 48 }, (_, i) => ({ i }))
    : Array.from({ length: 48 }, (_, i) => text
      ? ['ab', '\ud83d\ude00', '\ud800X', '\udc00', '\0'][i % 5]
      : Buffer.from([i, (i * 17) % 256, 255 - i]));
  for (let i = 0; i < values.length; i++) {
    if (i % 3 === 0) { readable.unshift(values[i]); reference.unshift(values[i]); }
    else { marks.push(readable.push(values[i])); reference.push(values[i]); }
    if (i % 5 === 0) {
      if (isObject) {
        const value = readable.read(); assert.equal(value, reference[0]);
        actual.push(value.i); expected.push(reference.shift().i);
      } else {
        const joined = text ? reference.join('') : Buffer.concat(reference);
        const n = Math.min(1 + i % 9, joined.length);
        const result = readable.read(n);
        actual.push(text ? result : result.toString('hex'));
        expected.push(text ? joined.slice(0, n) : joined.subarray(0, n).toString('hex'));
        reference.length = 0;
        if (joined.length > n) reference.push(joined.slice(n));
      }
    }
  }
  readable.push(null);
  if (isObject) {
    while (reference.length) {
      const result = readable.read(); assert.equal(result, reference[0]);
      actual.push(result.i); expected.push(reference.shift().i);
    }
  } else {
    const result = readable.read();
    const joined = text ? reference.join('') : Buffer.concat(reference);
    actual.push(text ? result : result.toString('hex'));
    expected.push(text ? joined : joined.toString('hex'));
  }
  assert.deepEqual(actual, expected);
  assert.equal(readable.readableLength, 0);
  assert.equal(readable.read(), null);
  readable.destroy();
  return { actual, marks };
}
function runFixture(stream, name) {
  const filename = path.resolve(__dirname,
    '../../crates/franken-engine/tests/fixtures/stream_buffering', name);
  const output = [];
  const evaluate = vm.runInThisContext(
    '(function (require, console) {\n' + fs.readFileSync(filename, 'utf8') + '\n})',
    { filename });
  evaluate(specifier => {
    assert.equal(specifier, 'stream');
    return stream;
  }, { log: (...args) => output.push(args.join(' ')) });
  return output;
}
async function sourceTests(filename) {
  const stream = loadStream(filename);
  const queue = checkQueue(stream);
  const modes = ['object', 'text', 'bytes'];
  for (const mode of modes) assert.deepEqual(readableProbe(stream, mode), readableProbe(nativeStream, mode));
  const fixtureOutputs = {};
  for (const name of ['steady_readable.js', 'partial_readable.js']) {
    const expected = runFixture(nativeStream, name);
    const actual = runFixture(stream, name);
    assert.deepEqual(actual, expected, name);
    fixtureOutputs[name] = actual;
  }
  await tick();
  return { queue, readableModes: modes, fixtureOutputs };
}
if (require.main === module) {
  sourceTests(process.argv[2] || defaultSource)
    .then(result => console.log(JSON.stringify({ status: 'pass', runtime: process.version,
      scope: 'engine-owned JavaScript under Node; not the Rust engine', ...result }, null, 2)))
    .catch(error => { console.error(error); process.exitCode = 1; });
}
module.exports = { loadStream, tick, checkQueue, readableProbe, sourceTests, defaultSource };
