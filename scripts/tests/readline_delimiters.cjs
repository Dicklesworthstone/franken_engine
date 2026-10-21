'use strict';
// Run the complete shipped JS factory, not a model of its scanner. Node
// supplies EventEmitter/StringDecoder/signals and a separate readline oracle.
// This does NOT execute the Rust interpreter. No timing assertion is a gate.
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { test } = require('node:test');
const E = require('node:events');
const nodeReadline = require('node:readline');
const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(process.env.READLINE_SOURCE || path.join(root,
  'crates/franken-engine/src/lowering_pipeline/readline_module.js'), 'utf8');
const fixtureSource = fs.readFileSync(path.join(root,
  'crates/franken-engine/tests/fixtures/readline_delimiters.js'), 'utf8');

function candidate(observe = false) {
  const calls = [], clock = { time: 1000 };
  const context = vm.createContext({
    __franken_readline_events: E,
    __franken_readline_decoder: require('node:string_decoder'),
    AbortController, AbortSignal, Symbol,
    Date: { now() { return clock.time; } },
    record(kind, length, needle, from, result) { calls.push({ kind, length, needle, from, result }); },
  });
  if (observe) vm.runInContext(`{
    const search = String.prototype.indexOf;
    const code = String.prototype.charCodeAt;
    String.prototype.indexOf = function (needle, from) {
      const result = Reflect.apply(search, this, [needle, from]);
      record('search', this.length, needle, from, result);
      return result;
    };
    String.prototype.charCodeAt = function (at) {
      const result = Reflect.apply(code, this, [at]);
      record('code', this.length, '', at, result);
      return result;
    };
  }`, context);
  return { api: vm.runInContext(source, context, { filename: 'production-readline.js' }), calls, clock, context };
}
function open(api, options = {}) {
  const input = new E();
  input.resume = input.pause = function () { return this; };
  const rl = api.createInterface({ input, terminal: false, crlfDelay: Infinity, ...options });
  const lines = [];
  let closed = 0;
  rl.on('line', value => lines.push(value));
  rl.on('close', () => closed++);
  return { input, rl, lines, get closed() { return closed; } };
}
function collect(api, chunks, direct = false) {
  const r = open(api);
  for (const chunk of chunks) {
    if (direct) r.rl.write(chunk); else r.input.emit('data', chunk);
  }
  r.input.emit('end');
  assert.equal(r.closed, 1);
  assert.equal(r.input.listenerCount('data'), 0);
  return r.lines;
}
function parity(api, chunks, direct = false) {
  assert.deepEqual(collect(api, chunks, direct), collect(nodeReadline, chunks, direct));
}
function examined(calls) {
  return calls.filter(x => x.kind === 'search').reduce((sum, x) =>
    sum + (x.result === -1 ? x.length - x.from : x.result - x.from + 1), 0);
}

test('all short CR/LF arrangements and split positions match live Node', () => {
  const c = candidate();
  let cases = 0;
  for (let length = 0; length <= 6; length++) {
    for (let value = 0; value < 3 ** length; value++) {
      let text = '', encoded = value;
      for (let at = 0; at < length; at++) { text += ['x', '\r', '\n'][encoded % 3]; encoded = Math.floor(encoded / 3); }
      for (let cut = 0; cut <= length; cut++) {
        const chunks = [text.slice(0, cut), text.slice(cut)];
        parity(c.api, chunks); parity(c.api, chunks, true); cases += 2;
      }
    }
  }
  console.log(JSON.stringify({ suite: 'delimiter arrangements', cases }));
});
test('UTF-16 offsets and lone halves survive all two-cut partitions', () => {
  const c = candidate(), text = 'é\ud800🚀\r\n漢\n\udc00\rfin';
  for (let first = 0; first <= text.length; first++) {
    for (let second = first; second <= text.length; second++) {
      parity(c.api, [text.slice(0, first), text.slice(first, second), text.slice(second)]);
    }
  }
});
test('all UTF-8 byte boundaries use the real incremental decoder', () => {
  const c = candidate(), bytes = Buffer.from('aé🚀\r\n漢\nfinal');
  for (let first = 0; first <= bytes.length; first++) {
    for (let second = first; second <= bytes.length; second++) {
      parity(c.api, [bytes.subarray(0, first), bytes.subarray(first, second), bytes.subarray(second)]);
    }
  }
});
test('empty chunks and incomplete EOF sequences keep Node behavior', () => {
  const c = candidate();
  for (const empty of ['', Buffer.alloc(0), new Uint8Array(0)]) {
    parity(c.api, ['first\r', empty, '\nlast']);
    parity(c.api, ['first\r', empty, '\nlast'], true);
  }
  for (const bytes of [[0xe2], [0xe2, 0x82], [97, 0xf0, 0x9f]]) parity(c.api, [Buffer.from(bytes)]);
});
test('long unterminated text uses two bulk searches, not per-unit calls', () => {
  const c = candidate(true), text = 'é漢🚀x'.repeat(65536);
  assert.deepEqual(collect(c.api, [text]), [text]);
  const searches = c.calls.filter(x => x.kind === 'search');
  assert.equal(searches.length, 2, 'exactly one search per delimiter');
  assert.equal(c.calls.filter(x => x.kind === 'code').length, 0, 'no scalar scan');
  assert.equal(examined(c.calls), text.length * 2);
});
test('missing and distant opposite delimiters are not searched again', () => {
  for (const [delimiter, other] of [['\n', '\r'], ['\r', '\n']]) {
    for (const tail of ['', other, other + delimiter]) {
      const c = candidate(true), text = ('x' + delimiter).repeat(4096) + tail;
      parity(c.api, [text]);
      const calls = c.calls.filter(x => x.kind === 'search');
      assert.ok(calls.length > 0, 'must use the native-search path');
      assert.ok(examined(c.calls) <= 2 * text.length, 'no overlapping suffix search');
      for (const token of [delimiter, other]) {
        const searches = calls.filter(x => x.needle === token);
        assert.ok(searches.filter(x => x.result === -1).length <= 1, 'exhausted cursors stay exhausted');
        for (let i = 1; i < searches.length; i++) {
          assert.ok(searches[i].from > searches[i - 1].result, 'cursor advances past previous hit');
        }
      }
    }
  }
});
test('mixed delimiters scan each directional cursor monotonically', () => {
  const c = candidate(true), text = ('aa\r\nb\nc\r\r\n\n').repeat(1024);
  parity(c.api, [text]);
  assert.ok(examined(c.calls) <= 2 * text.length);
});
test('CRLF delay boundaries preserve the old clock rule', () => {
  for (const [delay, elapsed, expected] of [[100, 99, ['a', 'b']], [100, 100, ['a', 'b']],
    [100, 101, ['a', '', 'b']], [Infinity, 1000000, ['a', 'b']]]) {
    const c = candidate(), r = open(c.api, { crlfDelay: delay });
    r.input.emit('data', 'a\r'); c.clock.time += elapsed;
    r.input.emit('data', '\nb\n'); r.input.emit('end');
    assert.deepEqual(r.lines, expected);
  }
});
test('finite delayed CRLF also agrees with a live Node clock', async () => {
  const c = candidate(), a = open(c.api, { crlfDelay: 100 }), b = open(nodeReadline, { crlfDelay: 100 });
  a.input.emit('data', 'first\r'); b.input.emit('data', 'first\r');
  await new Promise(resolve => setTimeout(resolve, 140)); c.clock.time += 140;
  a.input.emit('data', '\nlast\n'); b.input.emit('data', '\nlast\n');
  a.input.emit('end'); b.input.emit('end');
  assert.deepEqual(a.lines, b.lines);
});
test('captured search survives post-initialization prototype replacement', () => {
  const c = candidate(), r = open(c.api);
  r.input.emit('data', 'first');
  vm.runInContext(`String.prototype.indexOf = function () { throw new Error('replaced search'); };
    String.prototype.charCodeAt = function () { throw new Error('replaced code'); };
    String.prototype.slice = function () { throw new Error('replaced slice'); };`, c.context);
  r.input.emit('data', '\r\nsecond\n'); r.input.emit('end');
  assert.deepEqual(r.lines, ['first', 'second']);
});
test('reentry, close, pause and question delivery use the existing publication queue', () => {
  for (const action of ['reenter', 'close', 'pause', 'question']) {
    function run(api) {
      const r = open(api), order = [];
      if (action === 'question') r.rl.question('?', x => order.push('answer:' + x));
      let first = true;
      r.rl.on('line', line => {
        order.push(line);
        if (!first) return;
        first = false;
        if (action === 'reenter') r.input.emit('data', 'inner\n');
        else if (action !== 'question') r.rl[action]();
      });
      r.input.emit('data', 'first\r\nsecond\nthird\rsuffix'); r.input.emit('end'); r.rl.close();
      return order;
    }
    assert.deepEqual(run(candidate().api), run(nodeReadline), action);
  }
});
test('listener errors retain identity and the already-buffered suffix', () => {
  for (const reason of [undefined, null, 0, false, Symbol('reason'), new Error('reason')]) {
    for (const api of [candidate().api, nodeReadline]) {
      const r = open(api), thrower = () => { throw reason; };
      r.rl.on('line', thrower);
      let caught = false;
      try { r.input.emit('data', 'first\r\nsuffix'); } catch (e) { caught = true; assert.equal(e, reason); }
      assert.ok(caught); r.rl.removeListener('line', thrower);
      r.input.emit('data', 'tail\n'); r.input.emit('end');
      assert.deepEqual(r.lines, ['first', 'suffixtail']);
    }
  }
});
test('the exact shared native fixture passes on both complete implementations', async () => {
  const fixture = vm.runInThisContext(fixtureSource + '\nverifyReadlineDelimiters');
  const actual = await fixture(candidate().api, E), expected = await fixture(nodeReadline, E);
  assert.equal(actual, expected);
  assert.equal(actual, 'readline delimiters: long lines, CRLF, UTF-16, UTF-8, reentry, question, iteration');
});

test('empty decoded chunks do not dispatch substring searches', () => {
  const c = candidate(true), r = open(c.api);
  for (let n = 0; n < 4096; n++) r.input.emit('data', '');
  r.input.emit('end');
  assert.equal(c.calls.filter(x => x.kind === 'search').length, 0);
  assert.deepEqual(r.lines, []);
});

// Observe actual factory allocations and references, without replacing its
// collector. Host-side storage is outside the guest realm being inspected.
function publicationCandidate() {
  const records = new Map(), arrays = [], metrics = { records: 0, joins: 0 };
  class ObservedWeakMap extends WeakMap {
    set(key, value) {
      if (value && Object.hasOwn(value, 'fragments')) records.set(key, value);
      return super.set(key, value);
    }
  }
  const context = vm.createContext({
    __franken_readline_events: E,
    __franken_readline_decoder: require('node:string_decoder'),
    AbortController, AbortSignal, Symbol, WeakMap: ObservedWeakMap,
    observeRecord() { metrics.records++; },
    observeArray(value) { arrays.push(value); },
    observeJoin() { metrics.joins++; },
  });
  vm.runInContext(`{
    const create = Object.create, setPrototype = Object.setPrototypeOf;
    const join = Array.prototype.join, isArray = Array.isArray;
    Object.create = function (prototype, descriptors) {
      if (prototype === null) observeRecord();
      return Reflect.apply(create, Object, [prototype, descriptors]);
    };
    Object.setPrototypeOf = function (value, prototype) {
      const result = Reflect.apply(setPrototype, Object, [value, prototype]);
      if (prototype === null && isArray(value)) observeArray(value);
      return result;
    };
    Array.prototype.join = function (separator) {
      observeJoin();
      return Reflect.apply(join, this, [separator]);
    };
  }`, context);
  const api = vm.runInContext(source, context, { filename: 'production-readline.js' });
  function reset() { metrics.records = 0; metrics.joins = 0; arrays.length = 0; }
  return { api, context, records, arrays, metrics, reset };
}

test('whole lines bypass fragment records, joins and per-line publication nodes', () => {
  for (const count of [1, 2, 65, 4096]) {
    for (const value of ['', 'row', 'é\ud800🚀']) {
      const c = publicationCandidate(), r = open(c.api);
      const pending = c.records.get(r.rl).fragments.pending;
      c.reset();
      r.input.emit('data', (value + '\n').repeat(count));
      assert.deepEqual(r.lines, Array(count).fill(value));
      assert.equal(c.metrics.records, 0, 'no per-line fragment/publication nodes');
      assert.equal(c.metrics.joins, 0, 'complete lines do not visit fragment joins');
      assert.ok(c.arrays.length <= (count > 1 ? 1 : 0), 'at most one list per multi-line chunk');
      assert.equal(c.records.get(r.rl).fragments.pending, pending, 'unused fragment scratch is not replaced');
      r.input.emit('end');
      assert.equal(r.closed, 1);
      assert.equal(r.input.listenerCount('data'), 0);
    }
  }
});

test('single-line chunks need no publication list even after repeated delivery', () => {
  const c = publicationCandidate(), r = open(c.api);
  c.reset();
  for (let n = 0; n < 1024; n++) r.input.emit('data', (n % 2 ? 'line' : '') + '\n');
  assert.equal(r.lines.length, 1024);
  assert.equal(c.metrics.records, 0);
  assert.equal(c.metrics.joins, 0);
  assert.equal(c.arrays.length, 0);
  r.input.emit('end');
});

test('only the first completed line consumes an existing fragmented prefix', () => {
  for (const count of [1, 63, 64, 65, 129]) {
    const c = publicationCandidate(), r = open(c.api), reference = open(nodeReadline);
    for (let n = 0; n < count; n++) {
      r.input.emit('data', 'p'); reference.input.emit('data', 'p');
    }
    c.reset();
    const chunk = 'tail\r\n' + 'row\n'.repeat(4096) + 'unfinished';
    r.input.emit('data', chunk); reference.input.emit('data', chunk);
    assert.deepEqual(r.lines, reference.lines);
    assert.equal(c.metrics.records, 1, 'only the pending prefix needs a fragment node');
    assert.ok(c.metrics.joins <= 2, 'later whole lines do not repeat joins');
    r.input.emit('data', '-end\n'); reference.input.emit('data', '-end\n');
    r.input.emit('end'); reference.input.emit('end');
    assert.deepEqual(r.lines, reference.lines);
    assert.equal(r.lines[0], 'p'.repeat(count) + 'tail');
    assert.equal(r.lines.at(-1), 'unfinished-end');
  }
});

test('publication releases consumed list entries before invoking listeners', () => {
  const c = publicationCandidate(), r = open(c.api);
  c.reset();
  r.rl.on('line', line => {
    assert.equal(c.arrays.length, 1, 'one private list, not one record per line');
    const values = Array.from(c.arrays[0]);
    assert.equal(Object.getPrototypeOf(c.arrays[0]), null);
    if (line === 'first') assert.deepEqual(values, ['second', 'third']);
    else if (line === 'second') assert.deepEqual(values, [undefined, 'third']);
    else assert.deepEqual(values, [undefined, undefined]);
  });
  r.input.emit('data', 'first\nsecond\nthird\n');
  assert.deepEqual(r.lines, ['first', 'second', 'third']);
  r.input.emit('end');
});

test('multi-line reentry, listener replacement and EOF keep live Node ordering', () => {
  for (const action of ['data', 'write', 'end', 'replace', 'question']) {
    function run(api) {
      const r = open(api), order = [];
      const later = line => order.push('later:' + line);
      function listener(line) {
        order.push('line:' + line);
        if (line !== 'first') return;
        if (action === 'data') r.input.emit('data', 'nested1\nnested2\ninner-suffix');
        if (action === 'write') r.rl.write('nested1\nnested2\ninner-suffix');
        if (action === 'end') r.input.emit('end');
        if (action === 'replace') { r.rl.removeListener('line', listener); r.rl.on('line', later); }
        if (action === 'question') r.rl.question('?', answer => order.push('answer:' + answer));
      }
      r.rl.on('line', listener);
      r.rl.on('close', () => order.push('close'));
      r.input.emit('data', 'first\r\nsecond\nthird\rsuffix');
      r.input.emit('end'); r.rl.close();
      return order;
    }
    assert.deepEqual(run(candidate().api), run(nodeReadline), action);
  }
});

test('throwing on a later line drops undelivered complete lines but not the suffix', () => {
  for (const reason of [undefined, null, false, 0, Symbol('later'), {}]) {
    for (const api of [candidate().api, nodeReadline]) {
      const r = open(api), listener = line => { if (line === 'second') throw reason; };
      r.rl.on('line', listener);
      let caught = false;
      try { r.input.emit('data', 'first\nsecond\nthird\nsuffix'); }
      catch (error) { caught = true; assert.equal(error, reason); }
      assert.ok(caught);
      r.rl.removeListener('line', listener);
      r.input.emit('data', 'tail\n'); r.input.emit('end');
      assert.deepEqual(r.lines, ['first', 'second', 'suffixtail']);
    }
  }
});

test('private publication storage ignores indexed hooks and iterators changed during delivery', () => {
  const c = candidate(), r = open(c.api);
  r.rl.on('line', line => {
    if (line !== 'first') return;
    vm.runInContext(`for (const index of ['0', '1', '63']) {
      Object.defineProperty(Array.prototype, index, {
        configurable: true,
        get() { throw new Error('inherited publication read'); },
        set() { throw new Error('inherited publication write'); }
      });
    }
    Array.prototype[Symbol.iterator] = Array.prototype.shift = function () {
      throw new Error('publication must not consult guest iteration or shift');
    };`, c.context);
    r.input.emit('data', 'nested1\nnested2\nnested3\n');
  });
  r.input.emit('data', 'first\n' + 'row\n'.repeat(128) + 'suffix');
  r.input.emit('end');
  assert.deepEqual(r.lines, ['first', 'suffixnested1', 'nested2', 'nested3', ...Array(128).fill('row')]);
});

test('buffered async iteration delivers every line across its pause threshold', async () => {
  async function run(api) {
    const r = open(api), iterator = r.rl[Symbol.asyncIterator]();
    const text = Array.from({ length: 1100 }, (_, i) => 'row' + i).join('\n') + '\n';
    r.input.emit('data', text); r.input.emit('end');
    const result = [];
    for await (const line of iterator) result.push(line);
    r.rl.close();
    assert.equal(r.closed, 1);
    assert.equal(r.input.listenerCount('data'), 0);
    return result;
  }
  assert.deepEqual(await run(candidate().api), await run(nodeReadline));
});

test('abort during publication preserves already-complete lines and one close', () => {
  function run(api) {
    const controller = new AbortController(), r = open(api, { signal: controller.signal });
    r.rl.on('line', line => { if (line === 'first') controller.abort('stop'); });
    r.input.emit('data', 'first\nsecond\nthird\npending');
    r.input.emit('end');
    assert.equal(r.closed, 1);
    assert.equal(r.input.listenerCount('data'), 0);
    return r.lines;
  }
  assert.deepEqual(run(candidate().api), run(nodeReadline));
});
