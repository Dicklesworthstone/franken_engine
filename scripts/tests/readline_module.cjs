'use strict';
// Execute the production factory on Node language/events/decoder primitives.
// This is a host differential suite, NOT Rust parser/interpreter execution.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const events = require('node:events');
const decoder = require('node:string_decoder');
const { PassThrough, Readable, Writable } = require('node:stream');
const reference = require('node:readline');
const sourcePath = process.env.READLINE_TEST_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/readline_module.js');
const text = fs.readFileSync(sourcePath, 'utf8');
function candidate(overrides = {}) {
  const names = Object.keys(overrides);
  return Function('__franken_readline_events', '__franken_readline_decoder', ...names,
    'return ' + text)(events, decoder, ...names.map(name => overrides[name]));
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const testOptions = { timeout: 10000 };
async function both(program) {
  const expected = await program(reference);
  const actual = await program(candidate());
  assert.deepEqual(actual, expected);
  return actual;
}
function input() {
  const source = new events.EventEmitter();
  source.pauses = 0; source.resumes = 0;
  source.pause = function () { this.pauses++; return this; };
  source.resume = function () { this.resumes++; return this; };
  return source;
}
function linesFor(api, chunks, opts = {}) {
  const source = input(), out = [], life = [];
  const rl = api.createInterface({ input: source, terminal: false, crlfDelay: Infinity, ...opts });
  rl.on('line', line => out.push(line));
  rl.on('pause', () => life.push('pause'));
  rl.on('close', () => life.push('close'));
  for (const chunk of chunks) source.emit('data', chunk);
  source.emit('end');
  return { out, life, paused: rl.paused, closed: rl.closed,
    remaining: ['data', 'end', 'error'].map(key => source.listenerCount(key)) };
}

test('mixed newlines, empty lines, no final newline and Unicode bytes', testOptions, async () => {
  for (const fixture of ['', '\n', '\r', '\r\n', 'alpha\r\nbeta\ngamma\rlast', '\r\r\n\n', 'é🚀\r\n終\n']) {
    const bytes = Buffer.from(fixture);
    for (let width = 1; width <= Math.max(1, bytes.length); width++) {
      const chunks = [];
      for (let i = 0; i < bytes.length; i += width) chunks.push(bytes.subarray(i, i + width));
      await both(api => linesFor(api, chunks));
    }
  }
});
test('truncated EOF preserves the already decoded suffix as Node readline does', testOptions, async () => {
  for (const bytes of [[0xe2], [0xf0, 0x9f], [65, 10, 0xe2], [0xe2, 0x82, 0xac, 13]]) {
    await both(api => linesFor(api, bytes.map(byte => Buffer.from([byte]))));
  }
});
test('string chunks preserve UTF-16 and do not treat Unicode separators as newline', testOptions, async () => {
  const result = await both(api => linesFor(api, ['\ud83d', '\ude80\u2028x\u2029', '\r', '', '\n', 'tail']));
  assert.deepEqual(result.out, ['🚀\u2028x\u2029', '', 'tail']);
});
test('all deterministic byte splits match reference independently', testOptions, () => {
  const api = candidate();
  let count = 0;
  for (const fixture of ['a\r\nb\rc\n', 'é🚀\r\n尾', '\n\r\r\n']) {
    const bytes = Buffer.from(fixture);
    for (let a = 0; a <= bytes.length; a++) for (let b = a; b <= bytes.length; b++) {
      const chunks = [bytes.subarray(0, a), bytes.subarray(a, b), bytes.subarray(b)];
      assert.deepEqual(linesFor(api, chunks), linesFor(reference, chunks)); count++;
    }
  }
  // (7+1)(7+2)/2 + (11+1)(11+2)/2 + (4+1)(4+2)/2.
  assert.equal(count, 129);
});
test('finite crlfDelay separates a delayed LF but joins same-chunk CRLF', testOptions, async () => {
  const expected = [];
  for (const api of [reference, candidate()]) {
    const source = input(), lines = [];
    const rl = api.createInterface({ input: source, terminal: false, crlfDelay: 100 });
    rl.on('line', line => lines.push(line));
    source.emit('data', 'a\r');
    await new Promise(resolve => setTimeout(resolve, 220));
    source.emit('data', '\nb\r\nc'); source.emit('end');
    expected.push(lines);
  }
  assert.deepEqual(expected, [['a', '', 'b', 'c'], ['a', '', 'b', 'c']]);
});
test('callback question consumes one line, restores prompt and permits reentrant questions', testOptions, async () => {
  assert.deepEqual(await both(api => {
    const source = input(), output = [], answers = [], lines = [];
    const rl = api.createInterface({ input: source, output: { write(x) { output.push(x); } }, terminal: false, prompt: 'base> ' });
    rl.on('line', line => lines.push(line));
    rl.pause();
    const returned = rl.question('first? ', function (answer) {
      assert.equal(this, undefined); answers.push(answer);
      rl.question('second? ', answer => answers.push(answer));
    });
    source.emit('data', 'one\ntwo\nthree\n');
    const restored = rl.getPrompt(); rl.prompt(); source.emit('end');
    return [output, answers, lines, restored, returned, rl.closed];
  }), [['first? ', 'second? ', 'base> '], ['one', 'two'], ['three'], 'base> ', undefined, true]);
});
test('reentrant input observes already prepared suffix and delivered line order', testOptions, async () => {
  await both(api => {
    const source = input(), lines = [];
    const rl = api.createInterface({ input: source, terminal: false, crlfDelay: Infinity });
    rl.on('line', line => { lines.push(line); if (line === 'a') source.emit('data', 'inner\n'); });
    source.emit('data', 'a\nb\ntail'); source.emit('end');
    return lines;
  });
});
test('close/pause during a chunk retains its already received complete lines', testOptions, async () => {
  for (const action of ['close', 'pause']) await both(api => {
    const source = input(), lines = [], life = [];
    const rl = api.createInterface({ input: source, terminal: false });
    rl.on('line', line => { lines.push(line); if (lines.length === 1) rl[action](); });
    rl.on('close', () => life.push('close'));
    source.emit('data', 'a\nb\nc\n'); rl.close(); rl.close();
    return [lines, life, source.listenerCount('data'), source.listenerCount('end')];
  });
});
test('async iterator consumes real streams and returns one cached iterator', testOptions, async () => {
  assert.deepEqual(await both(async api => {
    const source = Readable.from([Buffer.from('a\r'), Buffer.from('\nb\nc')]);
    const rl = api.createInterface({ input: source, crlfDelay: Infinity });
    const iterator = rl[Symbol.asyncIterator]();
    const same = iterator === rl[Symbol.asyncIterator]();
    const lines = []; for await (const line of iterator) lines.push(line);
    return [same, lines, rl.closed, source.listenerCount('data')];
  }), [true, ['a', 'b', 'c'], true, 0]);
});
test('early return implements documented close; record Node 22 listener-retention difference', testOptions, async () => {
  async function earlyReturn(api) {
    const source = new PassThrough();
    const rl = api.createInterface({ input: source, crlfDelay: Infinity });
    const iterator = rl[Symbol.asyncIterator](); const first = iterator.next();
    source.write('a\nb\n'); assert.equal((await first).value, 'a');
    const result = await iterator.return();
    const next = await iterator.next();
    const status = [result, next, rl.closed, source.destroyed, source.listenerCount('data')];
    rl.close(); source.destroy(); return status;
  }
  const expected = [{ value: undefined, done: true }, { value: undefined, done: true }, true, false, 0];
  assert.deepEqual(await earlyReturn(candidate()), expected);
  // The Node 22.16 implementation retains its input listener, contrary to
  // the documented early-return close contract. Do not count it as parity.
  assert.deepEqual(await earlyReturn(reference), [expected[0], { value: 'b', done: false }, undefined, false, 1]);
});
test('question promises use the same parser and stable module alias', testOptions, async () => {
  await both(async api => {
    const source = new PassThrough(), output = [];
    const rl = api.promises.createInterface({ input: source, output: { write(s) { output.push(s); } }, terminal: false });
    const result = rl.question('value? ');
    source.write('42\n'); const value = await result;
    rl.close(); await assert.rejects(rl.question('late'), { code: 'ERR_USE_AFTER_CLOSE' });
    source.destroy(); return [value, output, rl instanceof api.promises.Interface];
  });
});
test('question abort preserves falsy causes, clears the slot and permits a later answer', testOptions, async () => {
  for (const reason of [false, null, 0, '', { original: true }]) await both(async api => {
    const source = new PassThrough(), controller = new AbortController();
    const rl = api.promises.createInterface({ input: source, terminal: false, prompt: 'restored' });
    const pending = rl.question('abort?', { signal: controller.signal });
    controller.abort(reason);
    await assert.rejects(pending, e => e.name === 'AbortError' && e.code === 'ABORT_ERR' && e.cause === reason);
    const prompt = rl.getPrompt();
    const next = rl.question('next?'); source.write('answer\n'); const answer = await next;
    rl.close(); source.destroy(); return [prompt, answer];
  });
});
test('already aborted question does not write a prompt or consume a later line', testOptions, async () => {
  await both(async api => {
    const source = input(), controller = new AbortController(), output = [], lines = [];
    const rl = api.promises.createInterface({ input: source, output: { write(s) { output.push(s); } }, terminal: false });
    rl.on('line', line => lines.push(line)); controller.abort('cancelled');
    await assert.rejects(rl.question('not written', { signal: controller.signal }), { code: 'ABORT_ERR' });
    source.emit('data', 'line\n'); source.emit('end'); return [output, lines];
  });
});
test('callback question abort never invokes its callback and forwards the next line', testOptions, async () => {
  await both(api => {
    const source = input(), c = new AbortController(), answers = [], lines = [];
    const rl = api.createInterface({ input: source, terminal: false });
    rl.on('line', line => lines.push(line));
    rl.question('cancel?', { signal: c.signal }, answer => answers.push(answer));
    c.abort('stop'); source.emit('data', 'still a line\n'); source.emit('end'); return [answers, lines];
  });
});
test('input errors retain identity and do not become lines', testOptions, async () => {
  await both(api => {
    const source = input(), seen = [], reason = { original: true };
    const rl = api.createInterface({ input: source, terminal: false });
    rl.on('error', error => seen.push(error === reason));
    source.emit('error', reason); rl.close();
    return [seen, source.listenerCount('error')];
  });
});
test('interface signal closes once, removes owned listeners and leaves streams alive', testOptions, async () => {
  await both(async api => {
    const source = new PassThrough(), c = new AbortController(), calls = [];
    const rl = api.createInterface({ input: source, signal: c.signal, terminal: false });
    rl.on('close', () => calls.push('close')); c.abort('stop'); await tick(); rl.close();
    const result = [calls, source.destroyed, source.listenerCount('data'), source.listenerCount('end'), source.listenerCount('error')];
    source.destroy(); return result;
  });
});
test('private abort survives synthetic events and public propagation blockers', testOptions, async () => {
  for (const api of [candidate()]) {
    const source = input(), c = new AbortController();
    c.signal.addEventListener('abort', e => e.stopImmediatePropagation());
    const rl = api.promises.createInterface({ input: source, terminal: false });
    const pending = rl.question('stop?', { signal: c.signal });
    c.signal.dispatchEvent(new Event('abort')); c.abort('real');
    await assert.rejects(pending, e => e.code === 'ABORT_ERR' && e.cause === 'real'); rl.close();
  }
  // Node 22 treats a synthetic event as cancellation with undefined cause.
  // This is an observed difference, not a Node-equivalence assertion.
  const source = input(), c = new AbortController();
  c.signal.addEventListener('abort', e => e.stopImmediatePropagation());
  const rl = reference.promises.createInterface({ input: source, terminal: false });
  const pending = rl.question('stop?', { signal: c.signal });
  c.signal.dispatchEvent(new Event('abort')); c.abort('real');
  await assert.rejects(pending, e => e.code === 'ABORT_ERR' && e.cause === undefined); rl.close();
});
test('write, explicit prompts, callable/new/subclass Interface constructors', testOptions, async () => {
  await both(api => {
    const source = input(), out = [], lines = [];
    class Custom extends api.Interface {}
    const rl = new Custom({ input: source, output: { write(x) { out.push(x); } }, terminal: false });
    rl.on('line', line => lines.push(line));
    rl.setPrompt('hello> '); rl.prompt(); rl.write('line\ntail'); source.emit('end');
    const second = api.Interface({ input: input(), terminal: false }); second.close();
    return [lines, out, rl instanceof Custom, rl instanceof api.Interface, second instanceof api.Interface];
  });
});
test('long fragmented lines do not repeatedly scan their accumulated prefix', testOptions, () => {
  let visits = 0;
  const StringProbe = function (s) { return String(s); };
  StringProbe.prototype = Object.create(String.prototype);
  StringProbe.prototype.charCodeAt = function (at) { visits++; return String.prototype.charCodeAt.call(this, at); };
  const api = candidate({ String: StringProbe });
  const chunks = Array.from({ length: 4096 }, () => 'x'.repeat(16)); chunks.push('\n');
  const result = linesFor(api, chunks);
  assert.deepEqual(result.out, ['x'.repeat(65536)]);
  assert.equal(visits, 65537);
  assert.deepEqual(linesFor(reference, chunks), result);
});
test('line iterator applies the shared event queue backpressure', testOptions, async () => {
  const api = candidate(), source = new PassThrough({ highWaterMark: 8 });
  const rl = api.createInterface({ input: source, crlfDelay: Infinity });
  const iterator = rl[Symbol.asyncIterator]();
  source.write('x\n'.repeat(1100)); await tick();
  assert.equal(rl.paused, true);
  let count = 0;
  while (count < 1100) { assert.equal((await iterator.next()).value, 'x'); count++; }
  assert.equal(rl.paused, false); source.end(); assert.equal((await iterator.next()).done, true);
  assert.equal(rl.closed, true);
});
test('terminal editing is explicitly unsupported before acquiring input listeners', () => {
  const api = candidate(), source = input();
  assert.throws(() => api.createInterface({ input: source, terminal: true }), { code: 'ERR_READLINE_TERMINAL_UNSUPPORTED' });
  assert.equal(source.eventNames().length, 0);
});

test('seeded Unicode byte partitions match Node over 512 independent fixtures', testOptions, () => {
  const api = candidate(); let seed = 0x239176;
  function random(max) { seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0; return seed % max; }
  const alphabet = ['a','é','🚀','\r','\n','\u2028','\0','終','\ud800'];
  for (let trial = 0; trial < 512; trial++) {
    let fixture = ''; for (let n = random(70); n--; ) fixture += alphabet[random(alphabet.length)];
    const bytes = Buffer.from(fixture), chunks = [];
    for (let at = 0; at < bytes.length;) {
      if (random(4) === 0) chunks.push(Buffer.alloc(0));
      const end = at + 1 + random(7); chunks.push(bytes.subarray(at, end)); at = end;
    }
    assert.deepEqual(linesFor(api, chunks), linesFor(reference, chunks), 'partition ' + trial);
  }
});
test('option and listener-admission failures roll back every acquired listener', () => {
  const api = candidate();
  for (const phase of ['options', 'on', 'resume']) {
    const source = input(), reason = { phase };
    const settings = { input: source, terminal: false };
    if (phase === 'options') Object.defineProperty(settings, 'signal', { get() { throw reason; } });
    if (phase === 'on') {
      source.on = function (name, fn) { events.EventEmitter.prototype.on.call(this, name, fn); if (name === 'data') throw reason; return this; };
    }
    if (phase === 'resume') source.resume = function () { throw reason; };
    assert.throws(() => api.createInterface(settings), e => e === reason);
    assert.deepEqual(source.eventNames(), []);
  }
});
test('close attempts all cleanup and settles iteration even when an input method throws', testOptions, async () => {
  const api = candidate();
  for (const phase of ['remove', 'pause']) {
    const source = input(), reason = { phase };
    const rl = api.createInterface({ input: source, terminal: false });
    const iterator = rl[Symbol.asyncIterator](), pending = iterator.next();
    if (phase === 'remove') {
      let first = true;
      source.removeListener = function (name, fn) {
        events.EventEmitter.prototype.removeListener.call(this, name, fn);
        if (first) { first = false; throw reason; } return this;
      };
    } else source.pause = function () { throw reason; };
    assert.throws(() => rl.close(), e => e === reason);
    assert.deepEqual(await pending, { value: undefined, done: true });
    assert.equal(rl.closed, true);
    assert.equal(source.listenerCount('data'), 0);
    assert.equal(source.listenerCount('error'), 0);
    assert.equal(source.listenerCount('end'), 0);
  }
});
test('answered questions dispose signal listeners without responding to later aborts', testOptions, async () => {
  await both(async api => {
    const source = input(), control = new AbortController();
    const rl = api.promises.createInterface({ input: source, terminal: false });
    const q = rl.question('?', { signal: control.signal }); source.emit('data', 'one\n');
    assert.equal(await q, 'one'); control.abort('late');
    const next = rl.question('?'); source.emit('data', 'two\n');
    assert.equal(await next, 'two'); rl.close();
    return events.getEventListeners(control.signal, 'abort').length;
  });
});
test('late iterator acquisition is complete after close and adds no new listeners', testOptions, async () => {
  const api = candidate(), source = input(), rl = api.createInterface({ input: source, terminal: false });
  rl.close(); const before = rl.eventNames();
  assert.deepEqual(await rl[Symbol.asyncIterator]().next(), { value: undefined, done: true });
  assert.deepEqual(rl.eventNames(), before);
});
test('replaced public decoder methods cannot intercept an initialized readline factory', () => {
  const LocalDecoder = function (encoding) { this.inner = new decoder.StringDecoder(encoding); };
  LocalDecoder.prototype.write = function (bytes) { return this.inner.write(bytes); };
  const api = Function('__franken_readline_events', '__franken_readline_decoder', 'return ' + text)(events, { StringDecoder: LocalDecoder });
  LocalDecoder.prototype.write = function () { throw Error('replacement'); };
  assert.deepEqual(linesFor(api, [Buffer.from([0xc3]),Buffer.from([0xa9,10])]).out, ['é']);
});

// Compose the actual engine-owned dependencies as well as readline. Only
// the emitter's primitive constructor and the Buffer/language primitives
// remain Node-hosted. Do not mutate Node's exported EventEmitter statics or
// let an inherited Node events.on accidentally supply a missing algorithm.
function sharedCandidate() {
  function HostEmitter(options) { events.EventEmitter.call(this, options); }
  Object.setPrototypeOf(HostEmitter.prototype, events.EventEmitter.prototype);
  const base = path.join(__dirname, '../../crates/franken-engine/src/lowering_pipeline');
  const sharedEvents = Function('__franken_events_constructor', '__franken_events_once',
    'return ' + fs.readFileSync(path.join(base, 'events_module.js'), 'utf8'))(
      () => HostEmitter, events.once);
  const sharedDecoder = Function('return ' + fs.readFileSync(
    path.join(base, 'string_decoder_module.js'), 'utf8'))();
  assert.notEqual(sharedEvents.on, events.on);
  assert.notEqual(sharedEvents.addAbortListener, events.addAbortListener);
  assert.notEqual(sharedDecoder.StringDecoder, decoder.StringDecoder);
  assert.equal(Object.hasOwn(sharedEvents, 'on'), true);
  const api = Function('__franken_readline_events', '__franken_readline_decoder',
    'return ' + text)(sharedEvents, sharedDecoder);
  return { api, sharedEvents, sharedDecoder };
}

test('canonical events and decoder compose with readline over 512 byte partitions', testOptions, () => {
  const { api, sharedEvents } = sharedCandidate();
  let seed = 0x7e21395;
  function random(max) {
    seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5;
    return (seed >>> 0) % max;
  }
  for (let trial = 0; trial < 512; trial++) {
    const bytes = Buffer.from(Array.from({ length: random(80) }, () => random(256)));
    const chunks = [];
    for (let at = 0; at < bytes.length;) {
      const end = at + 1 + random(8);
      chunks.push(bytes.subarray(at, end)); at = end;
    }
    assert.deepEqual(linesFor(api, chunks), linesFor(reference, chunks), 'raw byte partition ' + trial);
  }
  const rl = api.createInterface({ input: input(), terminal: false });
  assert.equal(rl instanceof sharedEvents, true);
  rl.close();
});

test('canonical event queue resumes a slow line consumer without loss or duplicate delivery', testOptions, async () => {
  const { api } = sharedCandidate();
  const source = new PassThrough({ highWaterMark: 8 });
  const rl = api.createInterface({ input: source, crlfDelay: Infinity });
  const iterator = rl[Symbol.asyncIterator]();
  const waiting = [iterator.next(), iterator.next()];
  source.write(Array.from({ length: 2200 }, (_, i) => i + '\n').join(''));
  await tick();
  assert.equal(rl.paused, true);
  assert.deepEqual(await Promise.all(waiting), [
    { value: '0', done: false }, { value: '1', done: false },
  ]);
  for (let i = 2; i < 2200; i++) {
    assert.deepEqual(await iterator.next(), { value: String(i), done: false });
  }
  assert.equal(rl.paused, false);
  const eof = iterator.next(); source.end();
  assert.deepEqual(await eof, { value: undefined, done: true });
  assert.equal(rl.closed, true);
  for (const name of ['data', 'end', 'error']) assert.equal(source.listenerCount(name), 0);
});

test('canonical abort dependencies keep answers and cancellations isolated across repeated questions', testOptions, async () => {
  const { api } = sharedCandidate();
  const source = new PassThrough();
  const rl = api.promises.createInterface({ input: source, terminal: false });
  for (let i = 0; i < 32; i++) {
    const c = new AbortController(), reason = { round: i };
    c.signal.addEventListener('abort', event => event.stopImmediatePropagation());
    const pending = rl.question('?', { signal: c.signal });
    c.signal.dispatchEvent(new Event('abort'));
    if (i % 2 === 0) {
      c.abort(reason);
      await assert.rejects(pending, error => error.code === 'ABORT_ERR' && error.cause === reason);
    } else {
      source.write('answer-' + i + '\n');
      assert.equal(await pending, 'answer-' + i);
      c.abort('after-answer');
    }
    const next = rl.question('?'); source.write('next\n');
    assert.equal(await next, 'next');
  }
  rl.close();
  assert.equal(source.destroyed, false);
  assert.equal(source.listenerCount('data'), 0);
  assert.equal(source.listenerCount('error'), 0);
  source.destroy();
});

test('canonical readline captures its dependencies while preserving caller-owned byte views', testOptions, async () => {
  const { api, sharedEvents, sharedDecoder } = sharedCandidate();
  sharedEvents.on = sharedEvents.addAbortListener = function () { throw Error('public replacement'); };
  sharedDecoder.StringDecoder.prototype.write = function () { throw Error('decoder replacement'); };
  const source = new PassThrough(), control = new AbortController();
  const rl = api.promises.createInterface({ input: source, terminal: false });
  const answer = rl.question('?', { signal: control.signal });
  const bytes = Buffer.from([99, 0xc3, 0xa9, 10, 88]);
  source.write(bytes.subarray(1, 2)); source.write(bytes.subarray(2, 4));
  assert.equal(await answer, 'é');
  const it = rl[Symbol.asyncIterator](), first = it.next();
  source.write('tail\n');
  assert.deepEqual(await first, { value: 'tail', done: false });
  await it.return();
  assert.deepEqual(await it.next(), { value: undefined, done: true });
  assert.deepEqual(Array.from(bytes), [99, 0xc3, 0xa9, 10, 88]);
  assert.equal(rl.closed, true); assert.equal(source.destroyed, false);
  assert.equal(source.listenerCount('data'), 0); source.destroy();
});

test('canonical line iterator drains buffered lines before an original source error', testOptions, async () => {
  const { api } = sharedCandidate();
  const source = input(), rl = api.createInterface({ input: source, terminal: false });
  const it = rl[Symbol.asyncIterator](), reason = new Error('source failed');
  source.emit('data', Buffer.from('first\nsecond\n'));
  source.emit('error', reason);
  assert.deepEqual(await it.next(), { value: 'first', done: false });
  assert.deepEqual(await it.next(), { value: 'second', done: false });
  await assert.rejects(it.next(), error => error === reason);
  // Explicitly release caller-owned input after a source error. These are
  // readline's chosen error semantics, not Node input-error parity claims.
  await it.return();
  assert.equal(rl.closed, true);
  assert.equal(source.listenerCount('data'), 0);
  assert.equal(source.listenerCount('error'), 0);
});

const { promisify } = require('node:util');

test('promisified questions resolve single-argument answers through the canonical custom hook', testOptions, async () => {
  for (const api of [reference, candidate(), sharedCandidate().api]) {
    const source = new PassThrough(), output = [];
    const rl = api.createInterface({ input: source, output: { write(s) { output.push(s); } }, terminal: false });
    const custom = rl.question[promisify.custom];
    assert.equal(typeof custom, 'function');
    assert.equal(promisify(rl.question), custom);
    const ask = promisify(rl.question).bind(rl);
    for (const answer of ['42', '', 'false', 'é🚀']) {
      const pending = ask('value? '); source.write(answer + '\n');
      assert.equal(await pending, answer);
    }
    assert.deepEqual(output, ['value? ', 'value? ', 'value? ', 'value? ']);
    rl.close(); assert.equal(source.listenerCount('data'), 0); source.destroy();
  }
});

test('promisified questions abort with exact causes and free the answer slot', testOptions, async () => {
  for (const api of [reference, candidate(), sharedCandidate().api]) {
    for (const reason of [false, null, 0, '', { original: true }]) {
      const source = new PassThrough(), controller = new AbortController();
      const rl = api.createInterface({ input: source, terminal: false });
      assert.equal(typeof rl.question[promisify.custom], 'function');
      const ask = promisify(rl.question).bind(rl);
      const pending = ask('?', { signal: controller.signal }); controller.abort(reason);
      await assert.rejects(pending, error => error.code === 'ABORT_ERR' && error.cause === reason);
      const next = ask('?'); source.write('next\n'); assert.equal(await next, 'next');
      rl.close(); source.destroy();
    }
  }
});

test('promisification honors public question overrides and first settlement without brand forgery', testOptions, async () => {
  for (const api of [reference, candidate(), sharedCandidate().api]) {
    const custom = api.Interface.prototype.question[promisify.custom];
    assert.equal(typeof custom, 'function');
    const opts = { marker: true }, reason = { original: true };
    const receiver = { question(query, options, callback) {
      assert.equal(this, receiver); assert.equal(query, 'question'); assert.equal(options, opts);
      callback('first'); callback('second'); throw reason;
    } };
    assert.equal(await custom.call(receiver, 'question', opts), 'first');
    await assert.rejects(custom.call({ question() { throw reason; } }, 'question'), error => error === reason);
    // The borrowed wrapper uses a public callback API, not readline's private
    // brand or state: ordinary Interface methods still validate the receiver.
  }
});

test('promisified closed and already-aborted questions reject without output or new listeners', testOptions, async () => {
  for (const api of [reference, candidate(), sharedCandidate().api]) {
    const source = new PassThrough(), out = [], control = new AbortController();
    const rl = api.createInterface({ input: source, output: { write(s) { out.push(s); } }, terminal: false });
    assert.equal(typeof rl.question[promisify.custom], 'function');
    const ask = promisify(rl.question).bind(rl); control.abort('before');
    await assert.rejects(ask('not printed', { signal: control.signal }), error => error.cause === 'before');
    rl.close(); await assert.rejects(ask('closed'), { code: 'ERR_USE_AFTER_CLOSE' });
    assert.deepEqual(out, []); assert.equal(source.listenerCount('data'), 0); source.destroy();
  }
});

test('question option normalization matches the reference for callback, promise and custom APIs', testOptions, async () => {
  for (const api of [reference, candidate(), sharedCandidate().api]) {
    for (const options of [undefined, null, false, 4, 'ignored', [], { signal: null }, { signal: false }]) {
      const source = new PassThrough();
      const rl = api.createInterface({ input: source, terminal: false });
      const answer = new Promise(resolve => rl.question('?', options, resolve));
      source.write('callback\n'); assert.equal(await answer, 'callback');
      const custom = promisify(rl.question).call(rl, '?', options);
      source.write('custom\n'); assert.equal(await custom, 'custom'); rl.close();
      const promiseInterface = api.promises.createInterface({ input: source, terminal: false });
      const promise = promiseInterface.question('?', options);
      source.write('promise\n'); assert.equal(await promise, 'promise'); promiseInterface.close(); source.destroy();
    }
  }
});

test('promisified questions use private cancellation even with a synchronous callback override', testOptions, async () => {
  const { api } = sharedCandidate();
  const custom = api.Interface.prototype.question[promisify.custom];
  const control = new AbortController(), reason = { real: true };
  control.signal.addEventListener('abort', event => event.stopImmediatePropagation());
  const receiver = { question(query, options, callback) {
    control.signal.dispatchEvent(new Event('abort'));
    control.abort(reason); callback('must not win');
  } };
  await assert.rejects(custom.call(receiver, '?', { signal: control.signal }),
    error => error.code === 'ABORT_ERR' && error.cause === reason);
  // This cancellation authority check is intentionally separate from Node
  // 22's synthetic-event behavior; it is not a claim of Node parity.
});
