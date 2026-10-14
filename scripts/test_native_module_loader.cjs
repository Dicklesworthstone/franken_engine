'use strict';
// Executes the exact shipped JS template with a test initializer expression.
// This is a reference-host test, not proof of native Rust lowering/execution.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const Module = require('node:module');

const template = fs.readFileSync(path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/native_module_loader.js'), 'utf8');
const placeholder = '__franken_native_module_initializer';
assert.equal(template.split(placeholder).length, 2, 'one initializer insertion site');
const expression = template.replace(placeholder, '__test_initialize()');
function loader(initialize, globals = {}) {
  return vm.runInNewContext(expression, { ...globals, __test_initialize: initialize });
}
let passed = 0;
function test(name, body) {
  body();
  passed++;
  console.log(`ok ${passed} - ${name}`);
}

test('construction and unused branches do not initialize modules', () => {
  let calls = 0;
  const load = loader(() => { calls++; throw new Error('not yet'); });
  function neverCalled() { return load(); }
  if (false) neverCalled();
  assert.equal(calls, 0);
  assert.throws(load, /not yet/);
  assert.equal(calls, 1);
});

test('initialization occurs at first use and exports retain identity', () => {
  const events = [];
  const load = loader(() => { events.push('init'); return { count: 0 }; });
  events.push('before');
  const first = load();
  first.count = 7;
  events.push('after');
  for (let n = 0; n < 1000; n++) assert.strictEqual(load(), first);
  assert.equal(load().count, 7);
  assert.deepEqual(events, ['before', 'init', 'after']);
});

test('all falsy exports are cached, not confused with an empty cache', () => {
  for (const value of [undefined, null, false, 0, -0, NaN, '']) {
    let calls = 0;
    const load = loader(() => { calls++; return value; });
    assert.ok(Object.is(load(), value));
    assert.ok(Object.is(load(), value));
    assert.equal(calls, 1);
  }
});

test('function, class, array, symbol and primitive exports are unchanged', () => {
  const functionExport = function (x) { return x + 1; };
  class ClassExport {}
  for (const value of [functionExport, ClassExport, [1], Symbol('export'), 12n, 'ok']) {
    const load = loader(() => value);
    assert.strictEqual(load(), value);
    assert.strictEqual(load(), value);
  }
  assert.equal(loader(() => functionExport)()(41), 42);
  assert.ok(new (loader(() => ClassExport)())() instanceof ClassExport);
});

test('every thrown value propagates unchanged and a later require can retry', () => {
  for (const failure of [undefined, null, false, 0, '', new Error('failed')]) {
    const value = {};
    let calls = 0;
    const load = loader(() => { if (++calls === 1) throw failure; return value; });
    let caught = false;
    try { load(); } catch (error) { caught = true; assert.strictEqual(error, failure); }
    assert.ok(caught);
    assert.strictEqual(load(), value);
    assert.strictEqual(load(), value);
    assert.equal(calls, 2);
  }
});

test('repeated failures never publish partial exports', () => {
  let attempts = 0;
  const load = loader(() => { attempts++; throw attempts; });
  for (let n = 1; n <= 10; n++) {
    assert.throws(load, value => value === n);
  }
  assert.equal(attempts, 10);
});

test('reentrant initialization fails deterministically and resets on unwind', () => {
  let recursive = true;
  let calls = 0;
  const value = {};
  const load = loader(() => { calls++; return recursive ? load() : value; });
  assert.throws(load, error => error.name === 'TypeError'
    && error.code === 'ERR_NATIVE_MODULE_REENTRANT');
  assert.equal(calls, 1);
  recursive = false;
  assert.strictEqual(load(), value);
  assert.strictEqual(load(), value);
  assert.equal(calls, 2);
});

test('an initializer may handle its own recursive failure and still finish', () => {
  let calls = 0;
  const value = {};
  const load = loader(() => {
    calls++;
    assert.throws(load, error => error.code === 'ERR_NATIVE_MODULE_REENTRANT');
    return value;
  });
  assert.strictEqual(load(), value);
  assert.strictEqual(load(), value);
  assert.equal(calls, 1);
});

test('an initialized dependency remains cached when its parent retries', () => {
  let dependencyCalls = 0;
  let parentCalls = 0;
  const dependency = loader(() => { dependencyCalls++; return {}; });
  const parent = loader(() => {
    const dep = dependency();
    if (++parentCalls === 1) throw new Error('parent');
    return { dep };
  });
  assert.throws(parent, /parent/);
  assert.strictEqual(parent().dep, dependency());
  assert.strictEqual(parent(), parent());
  assert.equal(dependencyCalls, 1);
  assert.equal(parentCalls, 2);
});

test('dependencies are initialized on demand and shared across importers', () => {
  const order = [];
  const events = loader(() => { order.push('events'); return {}; });
  const decoder = loader(() => { order.push('decoder'); return {}; });
  const stream = loader(() => ({ events: events(), decoder: decoder() }));
  const filesystem = loader(() => { order.push('fs'); return { stream: stream() }; });
  assert.deepEqual(order, []);
  const streamExports = stream();
  assert.deepEqual(order, ['events', 'decoder']);
  assert.strictEqual(filesystem().stream, streamExports);
  assert.strictEqual(streamExports.events, events());
  assert.deepEqual(order, ['events', 'decoder', 'fs']);
});

test('different programs receive independent caches', () => {
  let calls = 0;
  const initializer = () => ({ generation: ++calls });
  const first = loader(initializer), second = loader(initializer);
  assert.notStrictEqual(first(), second());
  assert.strictEqual(first(), first());
  assert.strictEqual(second(), second());
  assert.equal(calls, 2);
});

test('cache locals do not capture the initializer lexical environment', () => {
  const source = `
    const state = 'guest state', value = 'guest value', initialize = 'guest initialize';
    const load = ${template.replace(placeholder, '[state, value, initialize]')};
    load();`;
  const result = vm.runInNewContext(source);
  assert.deepEqual(Array.from(result), ['guest state', 'guest value', 'guest initialize']);
});

test('the initializer has ordinary strict-call receiver semantics', () => {
  const load = loader(function () { 'use strict'; return this; });
  assert.strictEqual(load(), undefined);
});

test('construction and successful loads do not consult mutable realm helpers', () => {
  let reads = 0;
  const hostile = new Proxy({}, { get() { reads++; throw new Error('unexpected global read'); } });
  const value = {};
  const load = loader(() => value, { globalThis: hostile, Object: hostile, Reflect: hostile });
  assert.strictEqual(load(), value);
  assert.strictEqual(load(), value);
  assert.equal(reads, 0);
});

test('a failure leaves no stale success value for subsequent attempts', () => {
  let attempt = 0;
  const token = {};
  const load = loader(() => {
    attempt++;
    if (attempt <= 3) throw token;
    return null;
  });
  for (let n = 0; n < 3; n++) assert.throws(load, error => error === token);
  assert.strictEqual(load(), null);
  assert.strictEqual(load(), null);
  assert.equal(attempt, 4);
});

test('first-use, retry and shared-identity behavior matches live Node CommonJS', () => {
  // Keep this directory for inspection; do not delete any session files.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-native-module-'));
  fs.writeFileSync(path.join(root, 'state.cjs'),
    'module.exports = { attempts: 0, order: [] };\n');
  fs.writeFileSync(path.join(root, 'dependency.cjs'),
    "const s = require('./state.cjs'); s.order.push('dep'); module.exports = {};\n");
  fs.writeFileSync(path.join(root, 'parent.cjs'), `
    const s = require('./state.cjs');
    const dep = require('./dependency.cjs');
    s.order.push('parent');
    if (++s.attempts === 1) throw new Error('retry');
    module.exports = { dep };\n`);
  const requireFrom = Module.createRequire(path.join(root, 'entry.cjs'));
  const nativeState = requireFrom('./state.cjs');
  const modelState = { attempts: 0, order: [] };
  const dependency = loader(() => { modelState.order.push('dep'); return {}; });
  const parent = loader(() => {
    const dep = dependency(); modelState.order.push('parent');
    if (++modelState.attempts === 1) throw new Error('retry');
    return { dep };
  });
  assert.deepEqual(nativeState.order, modelState.order);
  assert.throws(() => requireFrom('./parent.cjs'), /retry/);
  assert.throws(parent, /retry/);
  const nativeExport = requireFrom('./parent.cjs'), moduleExport = parent();
  assert.strictEqual(requireFrom('./parent.cjs'), nativeExport);
  assert.strictEqual(parent(), moduleExport);
  assert.strictEqual(nativeExport.dep, requireFrom('./dependency.cjs'));
  assert.strictEqual(moduleExport.dep, dependency());
  assert.deepEqual(nativeState, modelState);
});

console.log(JSON.stringify({ tests_passed: passed, host: process.version,
  scope: 'shipped_javascript_template_on_node', native_rust_executed: false }));
