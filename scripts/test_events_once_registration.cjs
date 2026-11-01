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
  // The protected-registration adapter models the private native primitive;
  // these host checks do not exercise the Rust listener record or dispatcher.
  return new Function('__franken_events_constructor', '__franken_events_once',
    '__franken_events_add_abort_listener', 'return ' + source)(
    () => Emitter, () => { throw new Error('candidate delegated observable once registration'); },
    (signal, listener) => { native.addAbortListener(signal, listener); });
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

test('native once regression fixtures agree across constructor, destructured and namespace imports',
  options, async () => {
    const fixtures = fs.readFileSync(path.join(__dirname,
      '../crates/franken-engine/tests/events_once_registration.rs'), 'utf8');
    for (const name of ['REGISTRATION', 'OVERRIDE', 'REJECTION', 'ORDERING',
      'EVENT_TARGET', 'INVALID_EMITTER', 'PROTECTED_REGISTRATION', 'PROTECTED_ABORT', 'PREABORT']) {
      const match = fixtures.match(new RegExp('const ' + name + ': &str = r#"([\\s\\S]*?)"#;'));
      assert.ok(match, 'missing native fixture ' + name);
      const original = match[1];
      for (const source of [
        original,
        original.replace('const E = require(', 'const { EventEmitter: E, once: wait } = require(')
          .replaceAll('E.once(', 'wait('),
        original.replace('const E = require(',
          "const events = require('events'); const { EventEmitter: E } = require(")
          .replaceAll('E.once(', 'events.once('),
      ]) {
        const run = async E => {
          const output = [];
          new Function('require', 'console', source)(name => {
            assert.ok(name === 'events' || name === 'node:events');
            return E;
          }, { log: (...args) => output.push(args.map(String).join(' ')) });
          // All fixtures settle in microtasks. This checkpoint observes async
          // adoption without asserting anything about the native interpreter.
          await new Promise(resolve => setImmediate(resolve));
          return output;
        };
        assert.deepEqual(await run(candidate()), await run(native), name);
      }
    }
  });

test('replacement during newListener cannot corrupt the remaining subscription transaction', options, async () => {
  for (const E of [native, candidate()]) {
    const emitter = new E();
    const push = Array.prototype.push;
    let calls = 0;
    emitter.on('newListener', name => {
      if (name === 'go') {
        Array.prototype.push = function () { calls++; throw new Error('guest push'); };
      }
    });
    let pending;
    try {
      pending = E.once(emitter, 'go');
      emitter.emit('go', 42);
    } finally { Array.prototype.push = push; }
    assert.deepEqual(await pending, [42]);
    assert.equal(calls, 0);
    assert.equal(emitter.listenerCount('go'), 0);
    assert.equal(emitter.listenerCount('error'), 0);
  }
});

test('addAbortListener survives stopped propagation with the original signal and event', options, async () => {
  await compare(async E => {
    const controller = new AbortController(), signal = controller.signal, trace = [];
    let original;
    signal.addEventListener('abort', event => {
      original = event; trace.push('stop'); event.stopImmediatePropagation();
    });
    signal.addEventListener('abort', () => trace.push('ordinary'));
    E.addAbortListener(signal, function (event) {
      trace.push(['protected', this === signal, event === original, event.target === signal,
        signal.aborted, signal.reason]);
    });
    signal.addEventListener('abort', () => trace.push('after'));
    E.addAbortListener(signal, () => trace.push('protected2'));
    controller.abort('reason');
    controller.abort('ignored');
    return trace;
  });
});

test('protected abort registration keeps ordinary ordering, duplicate identity, and disposal', options, async () => {
  for (const dispose of [false, true]) {
    await compare(async E => {
      const controller = new AbortController(), signal = controller.signal, trace = [];
      signal.addEventListener('abort', () => trace.push('first'));
      const registration = E.addAbortListener(signal, () => trace.push('protected'));
      signal.addEventListener('abort', () => trace.push('last'));
      if (dispose) { registration[Symbol.dispose](); registration[Symbol.dispose](); }
      controller.abort();
      return [trace, Object.getPrototypeOf(registration) === null];
    });
  }
  await compare(async E => {
    const controller = new AbortController(), trace = [];
    function duplicate() { trace.push('duplicate'); }
    controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
    controller.signal.addEventListener('abort', duplicate);
    const first = E.addAbortListener(controller.signal, duplicate);
    const second = E.addAbortListener(controller.signal, duplicate);
    controller.abort();
    first[Symbol.dispose](); second[Symbol.dispose]();
    return trace;
  });
});

test('synthetic abort is a one-shot event and reentrant dispatch cannot repeat a protected callback', options, async () => {
  for (const synthetic of [false, true]) {
    await compare(async E => {
      const controller = new AbortController(), signal = controller.signal, trace = [];
      signal.addEventListener('abort', event => { trace.push('stop'); event.stopImmediatePropagation(); });
      E.addAbortListener(signal, function (event) {
        trace.push([this === signal, event.target === signal, signal.aborted]);
        signal.dispatchEvent(new Event('abort'));
      });
      if (synthetic) { signal.dispatchEvent(new Event('abort')); }
      controller.abort();
      return trace;
    });
  }
});

test('pre-aborted callbacks retain microtask order and cannot be cancelled by disposing', options, async () => {
  await compare(async E => {
    const controller = new AbortController(), trace = [];
    controller.abort();
    const registration = E.addAbortListener(controller.signal, function (event) {
      trace.push(['callback', this === undefined, event === undefined]);
    });
    registration[Symbol.dispose]();
    trace.push('sync');
    await Promise.resolve();
    return trace;
  });
});
