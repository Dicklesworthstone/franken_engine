'use strict';
// Exercises the exact source shipped by the native lowerer. Node supplies only
// the EventEmitter/Promise primitives; the candidate must not delegate once().
// Run: node --test scripts/test_events_once_registration.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const native = require('node:events');
const source = fs.readFileSync(process.env.FRANKEN_EVENTS_SOURCE || path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/events_module.js'), 'utf8');
function candidate() {
  class Emitter extends native.EventEmitter {}
  return new Function('__franken_events_constructor', '__franken_events_once', 'return ' + source)(
    () => Emitter, () => { throw new Error('candidate delegated observable once registration'); });
}
const options = { timeout: 2500 };
async function compare(exercise) {
  assert.deepEqual(await exercise(candidate()), await exercise(native));
}

test('newListener, one-shot wrappers, arguments and cleanup match Node', options, async () => {
  for (const symbol of [false, true]) {
    for (const signalled of [false, true]) {
      await compare(async E => {
        const emitter = new E();
        const key = symbol ? Symbol('ready') : 'ready';
        const log = [];
        emitter.on('newListener', (name, listener) => {
          if (name !== 'removeListener') {
            log.push(['new', name === key ? 'ready' : name, typeof listener]);
          }
        });
        emitter.on('removeListener', name => log.push(['remove', name === key ? 'ready' : name]));
        const controller = new AbortController();
        const pending = E.once(emitter, key, signalled ? { signal: controller.signal } : undefined);
        const raw = emitter.rawListeners(key)[0];
        log.push(['wrapper', raw !== emitter.listeners(key)[0], raw.listener === emitter.listeners(key)[0]]);
        log.push(['counts', emitter.listenerCount(key), emitter.listenerCount('error')]);
        const marker = {};
        emitter.emit(key, marker, 7, undefined);
        emitter.emit(key, 'ignored');
        const values = await pending;
        log.push(['values', values.length, values[0] === marker, values[1], values[2] === undefined]);
        log.push(['after', emitter.listenerCount(key), emitter.listenerCount('error')]);
        return log;
      });
    }
  }
});

test('event and error listener installation uses an overridden once method', options, async () => {
  await compare(async E => {
    const emitter = new E();
    const log = [];
    const original = emitter.once;
    emitter.once = function (name, listener) {
      log.push([name, this === emitter]);
      return Reflect.apply(original, this, [name, listener]);
    };
    const pending = E.once(emitter, 'go');
    emitter.emit('go', 42);
    log.push(await pending);
    return log;
  });
});

test('falsey errors reject by identity and waiting for error resolves', options, async () => {
  for (const reason of [undefined, null, false, 0, '', { marker: true }, new Error('failure')]) {
    await compare(async E => {
      const emitter = new E();
      const rejected = E.once(emitter, 'go').then(() => false, value => value === reason);
      emitter.emit('error', reason);
      const pending = E.once(emitter, 'error');
      emitter.emit('error', reason, 'extra');
      const values = await pending;
      return [await rejected, values[0] === reason, values[1], emitter.eventNames()];
    });
  }
});

test('synchronous emit and microtask emit preserve Node promise ordering', options, async () => {
  for (const delayed of [false, true]) {
    await compare(async E => {
      const emitter = new E();
      const log = [];
      const pending = E.once(emitter, 'go').then(() => log.push('once'));
      Promise.resolve().then(() => log.push('before'));
      if (delayed) { queueMicrotask(() => emitter.emit('go')); }
      else { emitter.emit('go'); }
      Promise.resolve().then(() => log.push('after')).then(() => log.push('after2'));
      log.push('sync');
      await pending;
      await Promise.resolve();
      return log;
    });
  }
});

test('EventTarget once uses one-shot registration and removes its listener', options, async () => {
  await compare(async E => {
    const target = new EventTarget();
    const log = [];
    const add = target.addEventListener;
    target.addEventListener = function (name, listener, settings) {
      log.push([name, settings.once]);
      return Reflect.apply(add, this, [name, listener, settings]);
    };
    const pending = E.once(target, 'go');
    const event = new Event('go');
    target.dispatchEvent(event);
    target.dispatchEvent(new Event('go'));
    const values = await pending;
    log.push([values.length, values[0] === event, native.getEventListeners(target, 'go').length]);
    return log;
  });
});

test('registration failure rejects and removes previously installed listeners', options, async () => {
  const E = candidate();
  for (const failAfterAdd of [false, true]) {
    const emitter = new E();
    const error = new Error('registration failed');
    const original = emitter.once;
    emitter.once = function (name, listener) {
      if (name !== 'error') { return Reflect.apply(original, this, [name, listener]); }
      if (failAfterAdd) { Reflect.apply(original, this, [name, listener]); }
      throw error;
    };
    await assert.rejects(E.once(emitter, 'go'), value => value === error);
    assert.equal(emitter.listenerCount('go'), 0);
    assert.equal(emitter.listenerCount('error'), 0);
  }
});

test('newListener throw and reentrant completion do not leave orphan listeners', options, async () => {
  const E = candidate();
  for (const action of ['throw', 'complete', 'abort']) {
    const emitter = new E();
    const controller = new AbortController();
    const error = new Error(action);
    emitter.on('newListener', name => {
      if (name !== 'error') { return; }
      if (action === 'throw') { throw error; }
      if (action === 'complete') { emitter.emit('go', 42); }
      if (action === 'abort') { controller.abort(error); }
    });
    const pending = E.once(emitter, 'go', action === 'abort' ? { signal: controller.signal } : undefined);
    if (action === 'complete') { assert.deepEqual(await pending, [42]); }
    else if (action === 'throw') { await assert.rejects(pending, value => value === error); }
    else { await assert.rejects(pending, value => value.code === 'ABORT_ERR' && value.cause === error); }
    assert.equal(emitter.listenerCount('go'), 0);
    assert.equal(emitter.listenerCount('error'), 0);
  }
});

test('stopped public abort and synthetic events retain authenticated cancellation', options, async () => {
  const E = candidate();
  const emitter = new E();
  const controller = new AbortController();
  controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
  const pending = E.once(emitter, 'go', { signal: controller.signal });
  controller.signal.dispatchEvent(new Event('abort'));
  assert.equal(emitter.listenerCount('go'), 1);
  controller.abort('real reason');
  await assert.rejects(pending, error => error.code === 'ABORT_ERR' && error.cause === 'real reason');
  assert.equal(emitter.listenerCount('go'), 0);
  assert.equal(emitter.listenerCount('error'), 0);
});

test('iterators retain persistent subscriptions when once gains one-shot registration', options, async () => {
  await compare(async E => {
    const emitter = new E();
    const iterator = E.on(emitter, 'go');
    const listener = emitter.listeners('go')[0];
    const persistent = emitter.rawListeners('go')[0] === listener;
    emitter.emit('go', 1);
    emitter.emit('go', 2);
    const output = [persistent, (await iterator.next()).value, (await iterator.next()).value];
    await iterator.return();
    output.push(emitter.listenerCount('go'), emitter.listenerCount('error'));
    return output;
  });
});

test('bad options and pre-aborted signals reject without registering', options, async () => {
  const E = candidate();
  const emitter = new E();
  for (const settings of [null, 1, [], { signal: {} }]) {
    await assert.rejects(E.once(emitter, 'go', settings), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  const controller = new AbortController();
  controller.abort('before');
  await assert.rejects(E.once(emitter, 'go', { signal: controller.signal }),
    error => error.code === 'ABORT_ERR' && error.cause === 'before');
  assert.deepEqual(emitter.eventNames(), []);
});
