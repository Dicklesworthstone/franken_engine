'use strict';
// Production JS factory on the Node host, beside the live Node oracle.
// This verifies the intended trace; native lowering is covered separately by
// stream_module_bd_305gi_1 and must not be inferred from this host test.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const events = require('node:events');
const decoder = require('node:string_decoder');
const native = require('node:stream');
const root = path.resolve(__dirname, '../..');
const fixture = fs.readFileSync(path.join(root,
  'crates/franken-engine/tests/fixtures/stream_mixed_routes.js'), 'utf8');
const source = fs.readFileSync(process.env.STREAM_SOURCE || path.join(root,
  'crates/franken-engine/src/lowering_pipeline/stream_module.js'), 'utf8');
const factory = vm.runInThisContext(
  '(function(__franken_stream_events, __franken_stream_string_decoder, ' +
  '__franken_stream_next_tick) { return ' + source + '; })');

function run(module, sourceText) {
  return new Promise((resolve, reject) => {
    const output = [];
    const context = vm.createContext({
      require(name) {
        if (name === 'stream' || name === 'node:stream') return module;
        throw new Error('unexpected fixture module: ' + name);
      },
      console: { log(line) { output.push(line); } },
      queueMicrotask,
      setTimeout(callback, delay) {
        return setTimeout(() => {
          try { callback(); resolve(output); } catch (error) { reject(error); }
        }, delay);
      },
    });
    try { vm.runInContext(sourceText, context, { filename: 'stream_mixed_routes.js' }); }
    catch (error) { reject(error); }
  });
}

test('mixed CJS constructors, event order and shadowed require match live Node', { timeout: 1000 }, async () => {
  const candidate = factory(events.EventEmitter, decoder, process.nextTick);
  // Launch from a timer so both subjects begin before the same nextTick /
  // microtask boundary, independently of node:test's own promise scheduling.
  const [actual, expected] = await new Promise((resolve, reject) => {
    setTimeout(() => Promise.all([run(candidate, fixture), run(native, fixture)])
      .then(resolve, reject), 0);
  });
  assert.deepEqual(actual, expected);
  assert.equal(expected[0], 'identity:true,true');
  assert.equal(expected[1], 'shadow:local');
  assert.equal(expected.length, 3);
  console.log(expected.join('\n'));
});

function writeTrace(module, completion, destroyFromCallback = false) {
  return new Promise((resolve, reject) => {
    const log = [];
    const stream = new module.Writable({
      write(chunk, encoding, callback) {
        log.push('write');
        if (completion === 'sync') callback();
        else if (completion === 'nextTick') process.nextTick(callback);
        else if (completion === 'microtask') queueMicrotask(callback);
        else setTimeout(callback, 0);
      },
    });
    stream.on('error', error => log.push('error:' + error.message));
    stream.on('finish', () => log.push('finish'));
    stream.on('close', () => {
      log.push('close');
      setImmediate(() => resolve(log));
    });
    try {
      stream.write('x', () => {
        log.push('written');
        process.nextTick(() => log.push('callback-tick'));
        if (destroyFromCallback) stream.destroy(new Error('cancelled'));
      });
      stream.end(error => log.push('ended:' + (error ? error.message : 'ok')));
      queueMicrotask(() => log.push('microtask'));
    } catch (error) { reject(error); }
  });
}

for (const completion of ['sync', 'nextTick', 'microtask', 'timer']) {
  for (const cancel of [false, true]) {
    test(`${completion} write completion, cancellation=${cancel}, matches live Node`,
      { timeout: 1000 }, async () => {
        const candidate = factory(events.EventEmitter, decoder, process.nextTick);
        const [actual, expected] = await new Promise((resolve, reject) => {
          setTimeout(() => Promise.all([
            writeTrace(candidate, completion, cancel), writeTrace(native, completion, cancel),
          ]).then(resolve, reject), 0);
        });
        assert.deepEqual(actual, expected);
        assert.equal(actual.filter(event => event === 'finish').length, cancel ? 0 : 1);
        assert.equal(actual.filter(event => event === 'close').length, 1);
        if (!cancel) assert(actual.indexOf('callback-tick') < actual.indexOf('finish'));
      });
  }
}
