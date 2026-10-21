'use strict';
// Actual production factory on host primitives, not Rust engine execution.
// Poison only the candidate realm; use fresh processes for exact Node fixtures.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const sourcePath = process.env.CONSUMER_TEST_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_consumers.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const fixture = fs.readFileSync(path.join(__dirname,
  '../../crates/franken-engine/tests/fixtures/stream_consumer_fragmentation.js'), 'utf8');
// Run the exact same public fixtures under live Node in separate processes.
// Reference failures (including a host abort) stay nonzero, not candidate skips.
if (process.argv.includes('--node-reference')) {
  const results = [];
  for (let index = 6; index < 10; index++) {
    const expected = 'CONSUMER_ISOLATION_OK ' + index;
    const script = `const program = ${fixture};
      program(require('node:stream/consumers'), ${index}).then(() => {
        console.log('${expected}');
      }, error => { console.error(error); process.exitCode = 1; });`;
    const result = spawnSync(process.execPath, ['-e', script], {
      encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024
    });
    results.push({ index, status: result.status, signal: result.signal,
      error: result.error && result.error.message,
      stdout: result.stdout, stderr: result.stderr,
      passed: result.status === 0 && result.stdout.trim() === expected });
  }
  console.log(JSON.stringify({ node: process.version, results }, null, 2));
  process.exit(results.every(result => result.passed) ? 0 : 1);
}

const options = { timeout: 10000 };
const methods = ['text', 'json', 'blob', 'arrayBuffer', 'buffer'];
const binary = methods.slice(2);

function realm(overrides = {}, initialize = true) {
  const context = vm.createContext({ Blob, Buffer, TextDecoder, ...overrides });
  function load() { return vm.runInContext(source, context, { filename: sourcePath }); }
  return { context, load, api: initialize ? load() : undefined };
}
async function output(method, value) {
  value = await value;
  if (method === 'blob') return value.text();
  if (method === 'buffer' || method === 'arrayBuffer') return Buffer.from(value).toString();
  return value;
}
function poisonIndex(context, prototype, index = 0) {
  vm.runInContext(`Object.defineProperty(${prototype}.prototype, '${index}', {
    configurable: true,
    set(value) {
      observe(value, this);
      Object.defineProperty(this, '${index}', {
        value: '"CORRUPTED"', writable: true, enumerable: true, configurable: true
      });
    }
  });`, context);
}

for (const prototype of ['Array', 'Object']) for (const method of methods) {
  test(method + ' excludes inherited ' + prototype + ' index setters before/after initialization', options, async () => {
    for (const before of [false, true]) {
      let interceptions = 0;
      const env = realm({ observe() { interceptions++; } }, !before);
      poisonIndex(env.context, prototype);
      const api = before ? env.load() : env.api;
      async function* input() { yield method === 'json' ? '"original"' : 'original'; }
      assert.equal(await output(method, api[method](input())), 'original');
      assert.equal(interceptions, 0, 'private storage must not escape through a setter');
    }
  });
}

for (const method of binary) {
  test(method + ' owns next even if the array iterator prototype is replaced', options, async () => {
    for (const before of [false, true]) for (const accessor of [false, true]) {
      let interceptions = 0;
      const env = realm({ observe() { interceptions++; } }, !before);
      vm.runInContext(`(() => {
        const prototype = Object.getPrototypeOf([][Symbol.iterator]());
        const next = prototype.next;
        Object.defineProperty(prototype, 'next', ${accessor ? `{
          configurable: true, get() { observe(); throw new Error('private cursor intercepted'); }
        }` : `{
          configurable: true, value: function () {
            const result = Reflect.apply(next, this, []);
            if (!result.done) { observe(); result.value = 'CORRUPTED'; }
            return result;
          }
        }`});
      })();`, env.context);
      const api = before ? env.load() : env.api;
      async function* input() { yield 'original'; }
      assert.equal(await output(method, api[method](input())), 'original');
      assert.equal(interceptions, 0);
    }
  });
}

test('refilled small-fragment batches reject late interception at two index positions', options, async () => {
  for (const prototype of ['Array', 'Object']) for (const at of [0, 1]) {
    let calls = 0;
    const env = realm({ observe() { calls++; } });
    async function* input() {
      for (let n = 0; n < 64; n++) yield 'x';
      poisonIndex(env.context, prototype, at);
      for (let n = 0; n < 129; n++) yield 'y';
    }
    assert.equal(await env.api.text(input()), 'x'.repeat(64) + 'y'.repeat(129));
    assert.equal(calls, 0);
  }
});

test('large fragments cannot be intercepted in the final parts list', options, async () => {
  let calls = 0;
  const env = realm({ observe() { calls++; } });
  async function* input() {
    yield 'a'.repeat(16384);
    poisonIndex(env.context, 'Array', 1);
    yield 'b'.repeat(16384);
    yield 'tail';
  }
  assert.equal(await env.api.text(input()), 'a'.repeat(16384) + 'b'.repeat(16384) + 'tail');
  assert.equal(calls, 0);
});

test('nonwritable inherited indices cannot deny collector writes', options, async () => {
  for (const method of methods) {
    const env = realm();
    vm.runInContext("Object.defineProperty(Array.prototype, '0', { value:'blocked', writable:false })", env.context);
    async function* input() { yield method === 'json' ? '"original"' : 'original'; }
    assert.equal(await output(method, env.api[method](input())), 'original');
  }
});

test('late replacement of prototype helpers cannot access private lists', options, async () => {
  const env = realm();
  vm.runInContext(`Object.setPrototypeOf = function () { throw Error('replaced'); };
    Array.prototype.push = Array.prototype.join = function () { throw Error('replaced'); };`, env.context);
  async function* input() { yield 'a'; yield 'b'; }
  assert.equal(await env.api.text(input()), 'ab');
  assert.equal(await (await env.api.blob(input())).text(), 'ab');
});

test('a late input failure retains exact values and does not invoke private coercion', options, async () => {
  for (const method of methods) for (const reason of [undefined, null, false, 0, -0, '', Symbol('stop'), {}]) {
    let coerced = 0;
    const env = realm();
    async function* input() {
      yield binary.includes(method) ? { toString() { coerced++; return 'unpublished'; } } : 'prefix';
      throw reason;
    }
    let caught = false;
    try { await env.api[method](input()); }
    catch (error) { assert.equal(Object.is(error, reason), true); caught = true; }
    assert.equal(caught, true);
    assert.equal(coerced, 0);
  }
});

test('caller iterator getters and cleanup remain observable', options, async () => {
  const env = realm();
  let gets = 0, calls = 0, closed = 0;
  const cursor = Object.create({ get next() {
    gets++;
    return function () {
      calls++;
      return { value: calls === 1 ? 'ok' : {}, done: false };
    };
  }, return() { closed++; return { done: true }; } });
  await assert.rejects(env.api.text({ [Symbol.asyncIterator]() { return cursor; } }), { name: 'TypeError' });
  assert.equal(gets, 1); assert.equal(calls, 2); assert.equal(closed, 1);
});

test('binary coercion timing, byte-view reuse and Blob snapshots stay unchanged', options, async () => {
  const env = realm();
  const bytes = Uint8Array.of(0, 65, 66, 0);
  const trace = [];
  async function* input() {
    trace.push('first'); yield new DataView(bytes.buffer, 1, 2);
    trace.push('second'); yield { toString() { trace.push('coerce'); return '!'; } };
    trace.push('done'); bytes[1] = 67;
  }
  const result = await env.api.blob(input());
  assert.deepEqual(trace, ['first', 'second', 'done', 'coerce']);
  assert.equal(await result.text(), 'CB!');
  bytes[1] = 88;
  assert.equal(await result.text(), 'CB!', 'Blob owns its completed immutable snapshot');
});

test('private Blob cursors have independent positions and no inherited next or return', options, async () => {
  let inspected = false;
  class InspectBlob extends Blob {
    constructor(parts) {
      assert.equal(Array.isArray(parts), true);
      assert.equal(Object.getPrototypeOf(parts), null);
      const first = parts[Symbol.iterator](), second = parts[Symbol.iterator]();
      assert.equal(Object.getPrototypeOf(first), null);
      assert.equal(first.return, undefined);
      assert.equal(Object.hasOwn(first, 'next'), true);
      assert.equal(first.next().value, 'a'); assert.equal(first.next().value, 'b');
      assert.equal(second.next().value, 'a');
      assert.equal(first.next().done, true); assert.equal(first.next().done, true);
      inspected = true;
      super(parts);
    }
  }
  const env = realm({ Blob: InspectBlob });
  async function* input() { yield 'a'; yield 'b'; }
  assert.equal(await (await env.api.blob(input())).text(), 'ab');
  assert.equal(inspected, true);
});

test('concurrent consumers retain separate private storage across a producer mutation', options, async () => {
  let interceptions = 0;
  const env = realm({ observe() { interceptions++; } });
  let release;
  const wait = new Promise(resolve => { release = resolve; });
  async function* input(prefix) {
    for (let n = 0; n < 64; n++) yield prefix;
    await wait;
    for (let n = 0; n < 67; n++) yield prefix;
  }
  const a = env.api.text(input('a')), b = env.api.buffer(input('b'));
  await new Promise(resolve => setImmediate(resolve));
  poisonIndex(env.context, 'Object'); release();
  assert.equal(await a, 'a'.repeat(131));
  assert.equal((await b).toString(), 'b'.repeat(131));
  assert.equal(interceptions, 0);
});

test('all four new native fixture programs execute through the actual candidate factory', options, async () => {
  for (let index = 6; index < 10; index++) {
    const env = realm();
    const program = vm.runInContext(fixture, env.context);
    await program(env.api, index);
  }
});
