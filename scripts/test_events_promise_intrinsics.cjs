'use strict';
// Actual shipped factory, with Node supplying the native EventEmitter and
// Promise/signal machinery. This does not execute the Rust VM or its GC/IFC.
// node --test scripts/test_events_promise_intrinsics.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {test} = require('node:test');
const native = require('node:events');
const RealPromise = Promise;
const source = fs.readFileSync(process.env.FRANKEN_EVENTS_SOURCE || path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/events_module.js'), 'utf8');
function facade() {
  class E extends native.EventEmitter {}
  for (const [key, value] of [['defaultMaxListeners', 10], ['captureRejections', false]]) {
    Object.defineProperty(E, key, {value, writable:true, configurable:true});
  }
  return Function('__franken_events_constructor', 'return ' + source)(() => E);
}
function poison(member, run) {
  const target = member === 'constructor' ? globalThis : RealPromise;
  const name = member === 'constructor' ? 'Promise' : member;
  const descriptor = Object.getOwnPropertyDescriptor(target, name);
  const token = new Error('guest Promise ' + member);
  let calls = 0;
  Object.defineProperty(target, name, {...descriptor, value:function () { calls++; throw token; }});
  try { return {value:run(), calls}; }
  finally { Object.defineProperty(target, name, descriptor); }
}
function observe(promise) {
  return promise.then(value => ({ok:true, value}), error => ({ok:false, error}));
}
for (const member of ['constructor', 'resolve', 'reject']) {
  test('post-initialization ' + member + ' replacement cannot steal queued events or terminals', async () => {
    for (const api of [native, facade()]) {
      const emitter = new api();
      const iterator = api.on(emitter, 'data', {close:['end']});
      const token = {identity:true};
      const error = new Error('original');
      let records;
      const result = poison(member, () => {
        emitter.emit('data', token, undefined);
        emitter.emit('error', error);
        records = [observe(iterator.next()), observe(iterator.next()), observe(iterator.next())];
      });
      assert.equal(result.calls, 0);
      const [value, rejection, done] = await RealPromise.all(records);
      assert.equal(value.ok, true);
      assert.equal(value.value.value[0], token);
      assert.equal(value.value.value[1], undefined);
      assert.equal(value.value.done, false);
      assert.deepEqual(rejection, {ok:false, error});
      assert.deepEqual(done, {ok:true, value:{value:undefined, done:true}});
      assert.equal(emitter.eventNames().length, 0);
    }
  });
  test('post-initialization ' + member + ' replacement cannot intercept pending readers and return', async () => {
    for (const api of [native, facade()]) {
      const emitter = new api(), iterator = api.on(emitter, 'data');
      let pending, returned;
      const result = poison(member, () => {
        pending = [observe(iterator.next()), observe(iterator.next()), observe(iterator.next())];
        emitter.emit('data', 'first');
        returned = iterator.return();
      });
      assert.equal(result.calls, 0);
      assert.deepEqual(await RealPromise.all(pending), [
        {ok:true, value:{value:['first'], done:false}},
        {ok:true, value:{value:undefined, done:true}},
        {ok:true, value:{value:undefined, done:true}},
      ]);
      assert.deepEqual(await returned, {value:undefined, done:true});
      assert.equal(emitter.eventNames().length, 0);
    }
  });
  test('post-initialization ' + member + ' replacement preserves once success and errors', async () => {
    for (const api of [native, facade()]) {
      const emitter = new api(), token = new Error('once failure');
      let success, failure;
      const result = poison(member, () => {
        success = observe(api.once(emitter, 'data'));
        emitter.emit('data', 7, undefined);
        failure = observe(api.once(emitter, 'data'));
        // Check registration before emitting error: a broken factory may have
        // rejected without installing its listener. Do not mask that failure.
        assert.equal(emitter.listenerCount('error'), 1);
        emitter.emit('error', token);
      });
      assert.equal(result.calls, 0);
      assert.deepEqual(await success, {ok:true, value:[7, undefined]});
      assert.deepEqual(await failure, {ok:false, error:token});
      assert.equal(emitter.eventNames().length, 0);
    }
  });
}
test('captured helpers preserve native Promise identity and asynchronous delivery', async () => {
  async function exercise(api) {
    const emitter = new api(), iterator = api.on(emitter, 'data'), trace = [];
    emitter.emit('data', 'buffered');
    const first = iterator.next();
    assert.equal(Object.getPrototypeOf(first), RealPromise.prototype);
    first.then(() => trace.push('value'));
    const pending = iterator.next();
    assert.equal(Object.getPrototypeOf(pending), RealPromise.prototype);
    pending.then(() => trace.push('pending'));
    emitter.emit('data', 'pending');
    trace.push('sync');
    await RealPromise.all([first,pending]);
    await iterator.return();
    return trace;
  }
  assert.deepEqual(await exercise(facade()), await exercise(native));
});
test('once retains newListener registration and microtask order', async () => {
  async function exercise(api) {
    const emitter = new api(), trace = [];
    emitter.on('newListener', name => trace.push('add:' + name));
    const pending = api.once(emitter, 'data');
    pending.then(() => trace.push('once'));
    emitter.emit('data', 1);
    RealPromise.resolve().then(() => trace.push('tick'));
    trace.push('sync');
    await pending;
    await RealPromise.resolve();
    return trace;
  }
  assert.deepEqual(await exercise(facade()), await exercise(native));
});
test('abort settles pending readers once and preserves original cause', async () => {
  for (const api of [native, facade()]) {
    const emitter = new api(), controller = new AbortController(), cause = {stop:true};
    const iterator = api.on(emitter, 'data', {signal:controller.signal});
    const pending = Array.from({length:33}, () => observe(iterator.next()));
    const result = poison('resolve', () => controller.abort(cause));
    assert.equal(result.calls, 0);
    const records = await RealPromise.all(pending);
    assert.equal(records[0].ok, false);
    assert.equal(records[0].error.code, 'ABORT_ERR');
    assert.equal(records[0].error.cause, cause);
    assert(records.slice(1).every(item => item.ok && item.value.done));
    assert.equal(emitter.eventNames().length, 0);
  }
});
const rust = fs.readFileSync(path.join(__dirname,
  '../crates/franken-engine/tests/events_promise_intrinsics.rs'), 'utf8');
const constants = new Map([...rust.matchAll(/const ([A-Z_]+): &str = r#"([\s\S]*?)"#;/g)]
  .map(match => [match[1], match[2]]));
for (const name of ['BUFFERED', 'PENDING']) {
  test('exact native fixture, Node and shipped factory: ' + name, async () => {
    for (const api of [native, facade()]) {
      const lines = [];
      Function('require', 'console', constants.get(name + '_SOURCE'))(specifier => {
        assert(['events', 'node:events'].includes(specifier));return api;
      }, {log:(...args)=>lines.push(require('node:util').format(...args))});
      await new RealPromise(setImmediate);
      assert.equal(lines.join('\n'), constants.get(name + '_EXPECTED'));
    }
  });
}
test('EventTarget one-shot delivery uses the same captured constructor', async () => {
  for (const api of [native, facade()]) {
    const target = new EventTarget(), event = new Event('data');
    let result;
    const observation = poison('constructor', () => {
      result = observe(api.once(target, 'data'));
      target.dispatchEvent(event);
    });
    assert.equal(observation.calls, 0);
    const item = await result;
    assert.equal(item.ok, true);
    assert.equal(item.value[0], event);
    assert.equal(native.getEventListeners(target, 'data').length, 0);
  }
});
