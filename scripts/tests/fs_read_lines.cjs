'use strict';
// Exact engine filesystem, core streams and readline composed on Node's
// language, Buffer, EventEmitter, decoder and scheduling primitives. These
// tests do not execute the Rust interpreter or native sandbox provider.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const events = require('node:events');
const decoder = require('node:string_decoder');
const { test } = require('node:test');
const base = path.join(__dirname, '../../crates/franken-engine/src/lowering_pipeline');
const tick = () => new Promise(resolve => setImmediate(resolve));

function createHarness(options = {}) {
  const effects = [], live = new Set(), loads = [];
  const readSource = name => fs.readFileSync(path.join(base, name), 'utf8');
  const streams = new Function('__franken_stream_events', '__franken_stream_string_decoder',
    '__franken_stream_next_tick', 'return ' + readSource('stream_module.js'))(
      events, decoder, callback => process.nextTick(callback));
  const readline = new Function('__franken_readline_events', '__franken_readline_decoder',
    'return ' + readSource('readline_module.js'))(events, decoder);
  const native = Object.fromEntries(['openSync', 'closeSync', 'readSync', 'writeSync', 'fsyncSync',
    'readFileSync', 'writeFileSync'].map(name => [name, fs[name]]));
  function effect(authority, tag, ...args) {
    const op = tag.slice(6);
    effects.push({ authority, op, fd: op === 'open' ? undefined : args[0],
      length: op === 'read_fd' || op === 'write_fd' ? args[3] : undefined,
      position: op === 'read_fd' ? args[4] : undefined });
    if (options.effect) options.effect(op, args, effects);
    if (op === 'open') { const fd = native.openSync(...args); live.add(fd); return fd; }
    if (op === 'close_fd') { const result = native.closeSync(...args); live.delete(args[0]); return result; }
    if (op === 'read_fd') {
      assert(args[3] <= 16384, 'bounded engine descriptor reads');
      if (options.shortRead) args[3] = Math.min(args[3], options.shortRead);
      return native.readSync(...args);
    }
    if (op === 'write_fd') return native.writeSync(...args);
    if (op === 'fsync') return native.fsyncSync(...args);
    throw Error('Unexpected filesystem effect: ' + op);
  }
  function load(name) {
    loads.push(name);
    if (name === 'stream') return streams;
    if (name === 'readline') return readline;
    // The existing, unrelated Web-file API remains available to its caller.
    if (name === 'stream/web') return require('node:stream/web');
    throw Error('Unexpected module dependency: ' + name);
  }
  const source = options.source || fs.readFileSync(process.env.READ_LINES_FS_SOURCE ||
    path.join(base, 'fs_module.js'), 'utf8');
  const api = new Function('__franken_fs_read', '__franken_fs_write', 'require', 'return ' + source)(
    effect.bind(null, 'fs:read'), effect.bind(null, 'fs:write'), load);
  return { api, streams, readline, live, effects, loads };
}
module.exports = { createHarness };

if (require.main === module) {
  const reference = { api: fs, readline: require('node:readline'), streams: require('node:stream') };
  function fixture(t, data) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-read-lines-'));
    // Kept for test inspection; no user source or repository file is removed.
    const file = path.join(root, 'input'); fs.writeFileSync(file, data); return { root, file };
  }
  async function collect(h, options, lane) {
    const rl = h.readLines(options);
    assert(rl instanceof events.EventEmitter);
    assert.equal(typeof rl[Symbol.asyncIterator], 'function');
    assert(rl.input instanceof lane.api.ReadStream);
    const done = options?.autoClose === false || options?.emitClose === false
      ? undefined : new Promise(resolve => rl.input.once('close', resolve));
    const lines = []; for await (const line of rl) lines.push(line);
    if (done) await done; else await tick();
    return { rl, lines };
  }
  for (const [label, make] of [['node', () => reference], ['engine-js', createHarness]]) {
    test(`${label}: exact Unicode and CR/LF lines across tiny and large read windows`, { timeout: 5000 }, async t => {
      const f = fixture(t, 'α\r\n\n😀\rthree\nfour');
      for (const highWaterMark of [1, 2, 7, 65536]) {
        const lane = make(), h = await lane.api.promises.open(f.file);
        const result = await collect(h, { highWaterMark }, lane);
        assert.deepEqual(result.lines, ['α', '', '😀', 'three', 'four']);
        assert.equal(h.fd, -1); if (lane.live) assert.equal(lane.live.size, 0);
      }
    });
    test(`${label}: retained descriptor continues at its actual cursor`, { timeout: 5000 }, async t => {
      const lane = make(), f = fixture(t, 'skip\nfirst\nlast'), h = await lane.api.promises.open(f.file);
      await h.read(Buffer.alloc(5), 0, 5, null);
      const result = await collect(h, { autoClose: false, highWaterMark: 1 }, lane);
      assert.deepEqual(result.lines, ['first', 'last']); assert(h.fd >= 0);
      assert.equal(result.rl.input.destroyed, false); await h.close();
      if (lane.live) assert.equal(lane.live.size, 0);
    });
    test(`${label}: byte ranges and encoding use the shared file-stream decoder`, { timeout: 5000 }, async t => {
      const lane = make(), f = fixture(t, Buffer.from('skip\nα\r\nβ\ntail', 'utf16le'));
      const h = await lane.api.promises.open(f.file);
      const result = await collect(h, { encoding: 'utf16le', start: 10, end: 19, highWaterMark: 1 }, lane);
      assert.deepEqual(result.lines, ['α', 'β']); assert.equal(h.fd, -1);
    });
    test(`${label}: empty input and suppressed close events still release owned handles`, { timeout: 5000 }, async t => {
      const f = fixture(t, '');
      for (const options of [undefined, { emitClose: false }, { autoClose: false }]) {
        const lane = make(), h = await lane.api.promises.open(f.file);
        const result = await collect(h, options, lane);
        assert.deepEqual(result.lines, []); assert.equal(result.rl.closed, true);
        if (options?.autoClose === false) { assert(h.fd >= 0); await h.close(); }
        else assert.equal(h.fd, -1);
        if (lane.live) assert.equal(lane.live.size, 0);
      }
    });
    test(`${label}: closed handles fail without starting another read`, { timeout: 5000 }, async t => {
      const lane = make(), f = fixture(t, 'unchanged\n'), h = await lane.api.promises.open(f.file);
      await h.close(); const before = lane.effects?.length;
      assert.throws(() => h.readLines(), { code: 'ERR_OUT_OF_RANGE' });
      if (lane.effects) assert.equal(lane.effects.length, before);
      assert.equal(fs.readFileSync(f.file, 'utf8'), 'unchanged\n');
    });
    test(`${label}: source read errors reach the line iterator and preserve cleanup`, { timeout: 5000 }, async t => {
      const lane = make(), f = fixture(t, ''), h = await lane.api.promises.open(f.file, 'w');
      const rl = h.readLines(); const closed = new Promise(resolve => rl.input.once('close', resolve));
      await assert.rejects((async () => { for await (const line of rl) assert.fail(line); })(), { code: 'EBADF' });
      rl.close(); await closed; assert.equal(h.fd, -1);
      if (lane.live) assert.equal(lane.live.size, 0);
    });
    test(`${label}: early iteration return pauses without stealing a retained input`, { timeout: 5000 }, async t => {
      const lane = make(), f = fixture(t, 'first\n' + 'rest\n'.repeat(10000));
      const h = await lane.api.promises.open(f.file);
      const rl = h.readLines({ highWaterMark: 1, autoClose: false });
      for await (const line of rl) { assert.equal(line, 'first'); break; }
      assert.equal(rl.input.destroyed, false); assert(h.fd >= 0);
      await tick(); const reads = lane.effects?.filter(e => e.op === 'read_fd').length;
      await tick(); if (lane.effects) {
        assert.equal(rl.closed, true);
        assert.equal(lane.effects.filter(e => e.op === 'read_fd').length, reads);
      }
      const closed = new Promise(resolve => rl.input.once('close', resolve));
      rl.input.destroy(); await closed; await h.close();
      if (lane.live) assert.equal(lane.live.size, 0);
    });
    test(`${label}: event consumers receive all lines and normal descriptor completion`, { timeout: 5000 }, async t => {
      const lane = make(), f = fixture(t, 'one\r\ntwo\nlast'), h = await lane.api.promises.open(f.file);
      const rl = h.readLines({ highWaterMark: 2 }), lines = [];
      rl.on('line', line => lines.push(line));
      await new Promise((resolve, reject) => { rl.input.once('close', resolve); rl.once('error', reject); });
      assert.deepEqual(lines, ['one', 'two', 'last']); assert.equal(h.fd, -1);
    });
    test(`${label}: aborted line reads are failures, not successful empty files`, { timeout: 5000 }, async t => {
      const lane = make(), f = fixture(t, 'never\n'), h = await lane.api.promises.open(f.file);
      const rl = h.readLines({ signal: AbortSignal.abort(false) });
      const closed = new Promise(resolve => rl.input.once('close', resolve));
      await assert.rejects((async () => { for await (const line of rl) assert.fail(line); })(),
        e => e.code === 'ABORT_ERR' && e.cause === false);
      rl.close(); await closed; assert.equal(h.fd, -1);
      if (lane.effects) assert.equal(lane.effects.filter(e => e.op === 'read_fd').length, 0);
    });
  }
  test('engine-js: invalid stream options do not retain a half-constructed descriptor owner', async t => {
    const lane = createHarness(), f = fixture(t, 'unchanged\n'), h = await lane.api.promises.open(f.file);
    const before = lane.effects.length;
    for (const options of [{ start: -1 }, { start: 8, end: 2 },
      { highWaterMark: -2 }, { encoding: 'not-an-encoding' }]) {
      assert.throws(() => h.readLines(options)); assert(h.fd >= 0);
    }
    assert.equal(lane.effects.length, before);
    await h.close(); assert.equal(lane.live.size, 0);
    assert.equal(fs.readFileSync(f.file, 'utf8'), 'unchanged\n');
  });
  test('engine-js: line interface and descriptor dependencies are shared and acquired once', async t => {
    const lane = createHarness(), f = fixture(t, 'one\n');
    assert.deepEqual(lane.loads, []);
    for (let i = 0; i < 3; i++) {
      const h = await lane.api.promises.open(f.file);
      if (i === 0) assert.deepEqual(lane.loads, []);
      const { rl, lines } = await collect(h, undefined, lane);
      // Node 22 returns an internal base Interface rather than the exported
      // callback/Promise subclass. We deliberately reuse the public shared
      // Interface; its additional question API is not a Node identity claim.
      assert(rl instanceof lane.readline.Interface);
      assert(rl.input instanceof lane.streams.Readable);
      assert.deepEqual(lines, ['one']);
    }
    assert.deepEqual(lane.loads, ['readline', 'stream']);
    assert.equal(lane.live.size, 0);
    assert.equal(lane.effects.filter(e => e.op === 'open').length, 3);
    assert.equal(lane.effects.filter(e => e.op === 'close_fd').length, 3);
  });
  test('engine-js: slow consumers pause bounded descriptor input instead of reading the whole file', { timeout: 15000 }, async t => {
    const text = Array.from({ length: 20000 }, (_, i) => 'record-' + i + '\n').join('');
    const lane = createHarness(), f = fixture(t, text), h = await lane.api.promises.open(f.file);
    const rl = h.readLines({ highWaterMark: 1024 });
    const closed = new Promise(resolve => rl.input.once('close', resolve));
    const iterator = rl[Symbol.asyncIterator]();
    assert.deepEqual(await iterator.next(), { value: 'record-0', done: false });
    await tick(); await tick();
    const initialReads = lane.effects.filter(e => e.op === 'read_fd').length;
    assert(initialReads * 1024 < Buffer.byteLength(text) / 2);
    assert.equal(rl.paused, true);
    for (let i = 1; i < 20000; i++) {
      assert.deepEqual(await iterator.next(), { value: 'record-' + i, done: false });
      if (i % 2000 === 0) await tick();
    }
    assert.equal((await iterator.next()).done, true); await closed;
    assert.equal(lane.live.size, 0); assert.equal(h.fd, -1);
    assert(lane.effects.every(e => ['open', 'read_fd', 'close_fd'].includes(e.op)));
  });
  test('engine-js: short provider reads still preserve Unicode line boundaries', async t => {
    const lane = createHarness({ shortRead: 1 }), f = fixture(t, 'α\r\n😀\nlast');
    const h = await lane.api.promises.open(f.file);
    assert.deepEqual((await collect(h, undefined, lane)).lines, ['α', '😀', 'last']);
    assert.equal(lane.live.size, 0);
  });
  test('engine-js: original descriptor operations survive replaced public handle methods', async t => {
    const lane = createHarness(), f = fixture(t, 'real\n'), h = await lane.api.promises.open(f.file);
    for (const name of ['read', 'readFile', 'createReadStream', 'close']) {
      h[name] = () => { throw Error('public replacement ' + name); };
    }
    assert.deepEqual((await collect(h, undefined, lane)).lines, ['real']);
    assert.equal(lane.live.size, 0);
  });
}
