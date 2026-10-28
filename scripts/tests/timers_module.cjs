'use strict';
// Run the complete shipped factory over Node's intrinsics and real timer
// promises. Native resolver authorization and IFC admission are separate tests.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {test} = require('node:test');
const timers = require('node:timers');
const promises = require('node:timers/promises');
const util = require('node:util');
const vm = require('node:vm');
const source = fs.readFileSync(process.env.TIMERS_SOURCE || path.resolve(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/timers_module.js'), 'utf8');

function load() {
  const context = {
    Symbol,
    __franken_timers_timeout: promises.setTimeout,
    __franken_timers_immediate: promises.setImmediate,
    __franken_timers_interval: promises.setInterval,
  };
  // Fresh forwards retain real timer behavior without inheriting Node's
  // already-installed promisify descriptors, so the shipped installer runs.
  for (const name of ['setTimeout', 'clearTimeout', 'setImmediate',
    'clearImmediate', 'setInterval', 'clearInterval']) {
    context[name] = function (...args) { return timers[name](...args); };
  }
  const api = vm.runInNewContext(source, context, {filename: 'timers_module.js'});
  return {api, context};
}

test('native promise getters match Node names, lengths and constructability', () => {
  const {api, context} = load();
  for (const name of ['setTimeout', 'setImmediate']) {
    const actual = Object.getOwnPropertyDescriptor(api[name], util.promisify.custom);
    const expected = Object.getOwnPropertyDescriptor(timers[name], util.promisify.custom);
    assert.equal(api[name], context[name]);
    assert.equal(actual.get.name, expected.get.name, name);
    assert.equal(actual.get.length, expected.get.length, name);
    assert.equal(Object.hasOwn(actual.get, 'prototype'),
      Object.hasOwn(expected.get, 'prototype'), name);
    assert.equal(actual.enumerable, expected.enumerable, name);
    assert.equal(actual.configurable, expected.configurable, name);
    assert.equal(actual.set, expected.set, name);
    assert.equal(actual.get.call(null), api.promises[name]);
    assert.equal(util.promisify(api[name]), api.promises[name]);
    assert.throws(() => Reflect.construct(actual.get, []), error => error.name === 'TypeError');
    assert.throws(() => Reflect.construct(function () {}, [], actual.get), error => error.name === 'TypeError');
  }
});

test('deferred getters retain the shared promise object after method replacement', () => {
  const {api} = load();
  const parent = Object.getOwnPropertyDescriptor(api, 'promises');
  assert.equal(parent.get.name, 'get');
  assert.equal(parent.get.call(null), api.promises);
  const replacement = function replacement() { return 'changed'; };
  api.promises.setTimeout = replacement;
  const custom = Object.getOwnPropertyDescriptor(api.setTimeout, util.promisify.custom);
  assert.equal(custom.get(), replacement);
  assert.equal(util.promisify(api.setTimeout), replacement);
  assert.equal(api.setInterval[util.promisify.custom], undefined);
});

test('factory promise methods and scheduler use actual timer promises', {timeout: 3000}, async () => {
  const {api} = load();
  assert.equal(await api.promises.setTimeout(0, 'timeout'), 'timeout');
  assert.equal(await api.promises.setImmediate('immediate'), 'immediate');
  const interval = api.promises.setInterval(1, 'tick');
  try {
    const next = await interval.next();
    assert.equal(next.value, 'tick');
    assert.equal(next.done, false);
  } finally {
    await interval.return();
  }
  assert.equal((await interval.next()).done, true);
  assert.equal(await api.promises.scheduler.yield(), undefined);
  assert.equal(await api.promises.scheduler.wait(0), undefined);
});
