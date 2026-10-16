'use strict';
// Run: node --test scripts/test_events_error_monitor.cjs
// Source-level reference checks, not native FrankenEngine execution.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const native = require('node:events');
const source = fs.readFileSync(process.env.FRANKEN_EVENTS_SOURCE || path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/events_module.js'), 'utf8');
function candidate() {
  class Emitter extends native.EventEmitter {}
  return Function('__franken_events_constructor', '__franken_events_once', 'return ' + source)(
    () => Emitter, () => { throw new Error('unexpected native once delegation'); });
}
function compare(exercise) { assert.deepEqual(exercise(candidate()), exercise(native)); }

test('monitors precede error handlers with exact receiver and arguments', () => {
  compare(E => {
    const emitter = new E();
    const error = new Error('original');
    const object = {};
    const trace = [];
    emitter.on('error', function (...args) {
      trace.push(['error', this === emitter, args[0] === error, args[1] === object, args.length]);
    });
    emitter.on(E.errorMonitor, function (...args) {
      trace.push(['monitor', this === emitter, args[0] === error, args[1] === object, args.length]);
    });
    trace.push(['return', emitter.emit('error', error, object, undefined)]);
    return trace;
  });
});

test('monitor alone does not consume an unhandled error', () => {
  compare(E => {
    const emitter = new E();
    const error = new Error('unhandled');
    const trace = [];
    emitter.on(E.errorMonitor, value => trace.push(value === error));
    try { emitter.emit('error', error); }
    catch (value) { trace.push(value === error); }
    return trace;
  });
});

test('monitor exceptions stop ordinary delivery without replacing the thrown value', () => {
  for (const reason of [new Error('monitor'), undefined, null, false, 0]) {
    compare(E => {
      const emitter = new E();
      const trace = [];
      emitter.on(E.errorMonitor, () => { trace.push('monitor'); throw reason; });
      emitter.on('error', () => trace.push('error'));
      try { emitter.emit('error', new Error('original')); }
      catch (value) { trace.push(value === reason); }
      return trace;
    });
  }
});

test('once and prepended monitors preserve registration/removal order', () => {
  compare(E => {
    const emitter = new E();
    const trace = [];
    emitter.on(E.errorMonitor, () => trace.push('persistent'));
    emitter.prependOnceListener(E.errorMonitor, () => trace.push('once'));
    emitter.on('removeListener', name => { if (name === E.errorMonitor) { trace.push('removed'); } });
    emitter.on('error', () => trace.push('error'));
    emitter.emit('error', new Error('first'));
    emitter.emit('error', new Error('second'));
    trace.push(emitter.listenerCount(E.errorMonitor));
    return trace;
  });
});

test('a monitor may add or remove an ordinary error listener before dispatch', () => {
  for (const action of ['add', 'remove']) {
    compare(E => {
      const emitter = new E();
      const trace = [];
      const error = new Error('original');
      const listener = () => trace.push('error');
      if (action === 'remove') { emitter.on('error', listener); }
      emitter.on(E.errorMonitor, () => {
        trace.push('monitor');
        if (action === 'add') { emitter.on('error', listener); }
        else { emitter.removeListener('error', listener); }
      });
      try { trace.push(emitter.emit('error', error)); }
      catch (value) { trace.push(value === error); }
      return trace;
    });
  }
});

test('monitored delivery respects overridden emit and bypasses overridden listenerCount', () => {
  compare(E => {
    const emitter = new E();
    const trace = [];
    const original = emitter.emit;
    emitter.emit = function (type, ...args) {
      trace.push(type === E.errorMonitor ? 'emit:monitor' : 'emit:' + type);
      return Reflect.apply(original, this, [type, ...args]);
    };
    emitter.on(E.errorMonitor, () => trace.push('monitor'));
    emitter.on('error', () => trace.push('error'));
    emitter.listenerCount = () => { throw new Error('must consult native listener storage'); };
    emitter.emit('error', 7);
    return trace;
  });
});

test('nested errors retain their own arguments and monitor ordering', () => {
  compare(E => {
    const emitter = new E();
    const trace = [];
    emitter.on(E.errorMonitor, value => {
      trace.push('monitor:' + value);
      if (value === 'outer') { emitter.emit('error', 'inner'); }
    });
    emitter.on('error', value => trace.push('error:' + value));
    emitter.emit('error', 'outer');
    return trace;
  });
});

test('ordinary events and explicit monitor emissions keep native return values', () => {
  compare(E => {
    const emitter = new E();
    const trace = [];
    emitter.on(E.errorMonitor, value => trace.push(value));
    trace.push(emitter.emit('missing'));
    trace.push(emitter.emit(Symbol('error'), 'not an error'));
    trace.push(emitter.emit(E.errorMonitor, 'explicit'));
    emitter.on('ready', value => trace.push(value));
    trace.push(emitter.emit('ready', 42));
    return trace;
  });
});

test('replacing exported errorMonitor does not change the captured monitor key', () => {
  compare(E => {
    const emitter = new E();
    const key = E.errorMonitor;
    const trace = [];
    try {
      emitter.on(key, () => trace.push('original-key'));
      E.errorMonitor = Symbol('replacement');
      emitter.on(E.errorMonitor, () => trace.push('replacement-key'));
      emitter.on('error', () => trace.push('error'));
      emitter.emit('error', 7);
    } finally { E.errorMonitor = key; }
    return trace;
  });
});

test('subclasses retain native constructor identity and inherited monitor dispatch', () => {
  compare(E => {
    class Subclass extends E {}
    const emitter = new Subclass();
    const trace = [emitter instanceof E, emitter instanceof Subclass, E.EventEmitter === E, E.prototype.emit.length];
    emitter.on(E.errorMonitor, () => trace.push('monitor'));
    emitter.on('error', () => trace.push('error'));
    emitter.emit('error', 1);
    return trace;
  });
});

test('events.once still rejects after monitor delivery and removes both waiters', { timeout: 2500 }, async () => {
  async function exercise(E) {
    const emitter = new E();
    const trace = [];
    const error = new Error('original');
    emitter.on(E.errorMonitor, value => trace.push(['monitor', value === error]));
    const pending = E.once(emitter, 'ready').catch(value => trace.push(['rejected', value === error]));
    emitter.emit('error', error);
    await pending;
    trace.push(emitter.listenerCount('ready'), emitter.listenerCount('error'));
    return trace;
  }
  assert.deepEqual(await exercise(candidate()), await exercise(native));
});
