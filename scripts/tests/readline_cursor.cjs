'use strict';
// Execute the exact production installer; Node supplies only the owned output
// streams and nextTick primitive. Reference checks use the untouched Node API.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const node = require('node:readline');
const { Writable, PassThrough } = require('node:stream');
const root = path.resolve(__dirname, '../..');
const source = fs.readFileSync(path.join(root, 'crates/franken-engine/src/lowering_pipeline/readline_cursor.js'), 'utf8');
const install = vm.runInNewContext(source, {
  Array, Number, Object, Promise, RangeError, Reflect, TypeError, WeakMap,
  __franken_readline_cursor_tick: process.nextTick.bind(process),
});
function candidate() {
  const base = { ...node, promises: { ...node.promises } };
  for (const name of ['cursorTo', 'moveCursor', 'clearLine', 'clearScreenDown']) delete base[name];
  delete base.promises.Readline;
  const result = install(base);
  assert.equal(result, base);
  return result;
}
const tick = () => new Promise(resolve => setImmediate(resolve));
function errorOf(fn) {
  try { fn(); return null; }
  catch (e) { return [e.name, e.code]; }
}
function writer(options = {}) {
  const chunks = [];
  const w = new Writable({ decodeStrings: false, write(data, encoding, done) { chunks.push(data); if (options.delayed) setImmediate(done); else done(); }, ...options });
  w.on('error', () => {});
  return { w, chunks };
}
const groups = [];
function compare(name, fn) { groups.push({ name, fn, compare: true }); }
function only(name, fn) { groups.push({ name, fn, compare: false }); }
compare('callback controls emit exact sequences and preserve backpressure', async r => {
  const { w, chunks } = writer({ highWaterMark: 1, delayed: true });
  const callbacks = [], returned = [];
  returned.push(r.cursorTo(w, 2, 3, error => callbacks.push(error)));
  returned.push(r.cursorTo(w, 0, error => callbacks.push(error)));
  returned.push(r.moveCursor(w, -4, 5, error => callbacks.push(error)));
  returned.push(r.clearLine(w, -1, error => callbacks.push(error)));
  returned.push(r.clearLine(w, 1, error => callbacks.push(error)));
  returned.push(r.clearLine(w, 0, error => callbacks.push(error)));
  returned.push(r.clearScreenDown(w, error => callbacks.push(error)));
  await new Promise(resolve => w.end(resolve));
  assert.deepEqual(chunks, ['\x1b[4;3H', '\x1b[1G', '\x1b[4D\x1b[5B', '\x1b[1K', '\x1b[0K', '\x1b[2K', '\x1b[0J']);
  assert.equal(callbacks.length, 7); assert.ok(callbacks.every(x => x === null));
  assert.ok(returned.every(x => x === false));
  w.destroy(); return [chunks, callbacks, returned];
});
compare('no-output callbacks use nextTick and return true', async r => {
  // Start outside the enclosing promise reaction so the relative ordering of
  // nextTick and Promise jobs is meaningful and identical for both runners.
  return new Promise((resolve, reject) => setImmediate(() => {
    try {
      const log = [];
      const cb = x => { assert.equal(x, null); log.push('callback'); };
      assert.equal(r.cursorTo(null, 3, cb), true);
      assert.equal(r.moveCursor(undefined, 8, 9, cb), true);
      assert.equal(r.clearLine(null, 1, cb), true);
      assert.equal(r.clearScreenDown(undefined, cb), true);
      Promise.resolve().then(() => log.push('promise'));
      log.push('sync');
      setImmediate(() => { try { assert.deepEqual(log, ['sync', 'callback', 'callback', 'callback', 'callback', 'promise']); resolve(log); } catch (e) { reject(e); } });
    } catch (e) { reject(e); }
  }));
});
compare('callback argument errors and coordinate validation order', async r => {
  const { w } = writer();
  const out = [
    errorOf(() => r.cursorTo(w, NaN)), errorOf(() => r.cursorTo(w, 0, NaN)),
    errorOf(() => r.cursorTo(w, undefined, 3)),
    errorOf(() => r.cursorTo(null, NaN)),
    errorOf(() => r.cursorTo(w, 0, () => {}, null)),
    errorOf(() => r.clearLine(null, 0, false)),
    errorOf(() => r.clearScreenDown(null, {})),
    errorOf(() => r.moveCursor(null, 0, 0, 1)),
  ];
  w.destroy(); return out;
});
compare('callback API retains historical coordinate coercion', async r => {
  const out = []; const stream = { write(s, cb) { out.push(s); if (cb) cb(); return 17; } };
  assert.equal(r.cursorTo(stream, 0.5, -2), 17);
  r.cursorTo(stream, Infinity); r.cursorTo(stream, -0, null);
  r.moveCursor(stream, '2', '-3'); r.moveCursor(stream, NaN, 1);
  r.clearLine(stream, '-1'); r.clearLine(stream, '1'); r.clearLine(stream, {});
  assert.equal(r.cursorTo(stream, {}, {}), true);
  return out;
});
compare('callback overload captures the selected receiver and callback', async r => {
  const cb = () => {}; let receiver, seen;
  const stream = { write(...args) { receiver = this; seen = args; return false; } };
  assert.equal(r.cursorTo(stream, 4, cb), false);
  assert.equal(receiver, stream); assert.equal(seen[1], cb);
  assert.equal(seen.length, 2); return seen[0];
});
compare('synchronous write throws preserve exact values', async r => {
  const out = [];
  for (const reason of [undefined, null, false, 0, 'bad', { marker: 1 }]) {
    const stream = { write() { throw reason; } };
    for (const call of [() => r.cursorTo(stream, 0), () => r.moveCursor(stream, 1, 1),
      () => r.clearLine(stream, 0), () => r.clearScreenDown(stream)]) {
      let caught = false;
      try { call(); } catch (error) { caught = true; assert.equal(error, reason); }
      assert.equal(caught, true); out.push(caught);
    }
  }
  return out;
});
compare('transaction chains one batch and rollback discards only pending output', async r => {
  const { w, chunks } = writer(); const t = new r.promises.Readline(w);
  assert.equal(t.cursorTo(1, 2).clearLine(0).moveCursor(3, -4).clearScreenDown(), t);
  assert.equal(chunks.length, 0); assert.equal(await t.commit(), null);
  t.clearLine(-1).cursorTo(50); assert.equal(t.rollback(), t); await t.commit();
  t.cursorTo(0); await t.commit();
  assert.deepEqual(chunks, ['\x1b[3;2H\x1b[2K\x1b[3C\x1b[4A\x1b[0J', '', '\x1b[1G']);
  assert.deepEqual(Object.keys(t), []); w.destroy(); return chunks;
});
compare('commits wait for their write callbacks and overlap safely', async r => {
  const held = [], chunks = [], w = new Writable({ decodeStrings: false, write(s, e, cb) { chunks.push(s); held.push(cb); } });
  const t = new r.promises.Readline(w), done = [];
  const a = t.cursorTo(1).commit().then(() => done.push(1));
  const b = t.clearLine(0).commit().then(() => done.push(2));
  await tick(); assert.deepEqual(done, []); assert.equal(chunks.length, 1);
  held.shift()(); await a; assert.deepEqual(done, [1]);
  held.shift()(); await b; assert.deepEqual(done, [1, 2]);
  w.destroy(); return chunks;
});
compare('automatic commits stay scheduled after rollback', async r => {
  const { w, chunks } = writer(); const t = new r.promises.Readline(w, { autoCommit: true });
  t.cursorTo(3).clearLine(1).moveCursor(-2, 0).clearScreenDown().rollback();
  assert.equal(chunks.length, 0); await tick();
  assert.deepEqual(chunks, ['\x1b[4G', '\x1b[0K', '\x1b[2D', '\x1b[0J']);
  w.destroy(); return chunks;
});
compare('transaction arguments reject before admitting actions', async r => {
  const { w, chunks } = writer(); const t = new r.promises.Readline(w);
  const out = [];
  for (const value of ['1', {}, NaN, 0.5, Infinity, 9007199254740992]) {
    out.push(errorOf(() => t.cursorTo(value)));
    out.push(errorOf(() => t.moveCursor(value, 1)));
    out.push(errorOf(() => t.clearLine(value)));
  }
  out.push(errorOf(() => t.clearLine(-2)), errorOf(() => t.clearLine(2)));
  t.moveCursor(0, 0); t.moveCursor(undefined, undefined); t.cursorTo(-0, null);
  await t.commit(); assert.deepEqual(chunks, ['\x1b[1G']);
  w.destroy(); return out;
});
compare('constructors validate writable endpoints and boolean options', async r => {
  const { w } = writer(); const dead = writer().w; dead.destroy();
  const ended = writer().w; ended.end();
  const out = [undefined, null, {}, { write() {} }, dead, ended].map(s => errorOf(() => new r.promises.Readline(s)));
  for (const autoCommit of ['yes', 1, {}, []]) out.push(errorOf(() => new r.promises.Readline(w, { autoCommit })));
  for (const o of [undefined, null, 1, {}, { autoCommit: null }, { autoCommit: false }]) new r.promises.Readline(w, o);
  w.destroy(); return out;
});
compare('constructor reads autoCommit with observable accessors', async r => {
  const { w } = writer(); let reads = 0;
  new r.promises.Readline(w, { get autoCommit() { reads++; return false; } });
  w.destroy(); return reads;
});
compare('write callback values preserve Node commit settlement', async r => {
  const { w } = writer(); const marker = new Error('write callback');
  w.write = function (data, callback) { callback(marker); return false; };
  const result = await new r.promises.Readline(w).clearLine(0).commit();
  assert.equal(result, marker); w.destroy(); return result.message;
});
compare('automatic writes consult output methods when the scheduled task runs', async r => {
  const { w } = writer(); const calls = [];
  const t = new r.promises.Readline(w, { autoCommit: true }); t.cursorTo(2);
  w.write = function (s) { assert.equal(this, w); calls.push(s); return true; };
  await tick(); w.destroy(); return calls;
});
compare('no-movement and zero/negative coordinates remain exact', async r => {
  const { w, chunks } = writer(); const t = new r.promises.Readline(w);
  t.cursorTo(-1, -1).moveCursor(0, 0).moveCursor(-0, -0).moveCursor(-1, 1).clearLine(-0);
  await t.commit(); w.destroy(); return chunks;
});
compare('output operations do not end or destroy the caller stream', async r => {
  const { w } = writer(); const t = new r.promises.Readline(w);
  await t.clearScreenDown().commit(); t.rollback();
  const result = [w.destroyed, w.writableEnded, w.writableFinished, w.writable];
  w.destroy(); return result;
});
compare('rollback does not cancel an already pending commit', async r => {
  let done; const chunks = [];
  const w = new Writable({ decodeStrings: false, write(s, e, cb) { chunks.push(s); done = cb; } });
  const t = new r.promises.Readline(w); const first = t.cursorTo(1).commit();
  t.clearLine(0).rollback(); done(); await first;
  const next = t.commit(); done(); await next;
  w.destroy(); return chunks;
});
only('reentrant actions survive the previous batch completion', async r => {
  const { w, chunks } = writer(); let t, injected = false;
  const original = w.write;
  w.write = function (s, cb) { if (!injected) { injected = true; t.clearLine(0); } return original.call(this, s, cb); };
  t = new r.promises.Readline(w); await t.cursorTo(2).commit(); await t.commit();
  assert.deepEqual(chunks, ['\x1b[3G', '\x1b[2K']); w.destroy(); return chunks;
});
only('reentrant nested commits own disjoint action generations', async r => {
  const { w, chunks } = writer(); let t, nested, once = false;
  const original = w.write;
  w.write = function (s, cb) {
    if (!once) { once = true; nested = t.clearLine(-1).commit(); }
    return original.call(this, s, cb);
  };
  t = new r.promises.Readline(w); await t.cursorTo(3).commit(); await nested;
  assert.deepEqual(chunks, ['\x1b[1K', '\x1b[4G']); w.destroy(); return chunks;
});
only('throwing output rejects once without replaying a potentially written batch', async r => {
  const { w, chunks } = writer(); const error = new Error('after output');
  const t = new r.promises.Readline(w), original = w.write;
  w.write = function (s) { chunks.push(s); t.clearLine(1); throw error; };
  await assert.rejects(t.cursorTo(9).commit(), e => e === error);
  w.write = original; await t.commit();
  assert.deepEqual(chunks, ['\x1b[10G', '\x1b[0K']); w.destroy(); return chunks;
});
compare('many queued actions use one caller write per committed transaction', async r => {
  const { w, chunks } = writer(); const t = new r.promises.Readline(w);
  for (let i = 0; i < 4096; i++) t.cursorTo(i);
  assert.equal(chunks.length, 0); await t.commit(); assert.equal(chunks.length, 1);
  const expected = Array.from({ length: 4096 }, (_, i) => `\x1b[${i + 1}G`).join('');
  assert.equal(chunks[0], expected); w.destroy(); return [1, expected.length];
});
compare('public functions retain documented arity and export descriptors', async r => {
  const lengths = ['cursorTo', 'moveCursor', 'clearLine', 'clearScreenDown'].map(name => r[name].length);
  lengths.push(r.promises.Readline.length, r.promises.Readline.prototype.cursorTo.length);
  const d = Object.getOwnPropertyDescriptor(r.promises, 'Readline');
  assert.equal(d.enumerable, true); assert.equal(d.writable, true); assert.equal(d.configurable, true);
  return lengths;
});
compare('commit rejects incompatible receivers asynchronously', async r => {
  let p;
  assert.doesNotThrow(() => { p = r.promises.Readline.prototype.commit.call({}); });
  await assert.rejects(p, TypeError);
  return true;
});
compare('prototype methods and subclass instances keep independent queues', async r => {
  const { w, chunks } = writer();
  class Cursor extends r.promises.Readline {}
  const a = new Cursor(w), b = new Cursor(w);
  a.cursorTo(1); b.cursorTo(2); await b.commit(); await a.commit();
  const descriptor = Object.getOwnPropertyDescriptor(r.promises.Readline.prototype, 'commit');
  assert.equal(descriptor.enumerable, false);
  w.destroy(); return chunks;
});
compare('output errors still belong to the supplied Writable', async r => {
  const error = new Error('sink failure'), errors = [];
  const w = new Writable({ write(s, e, cb) { cb(error); } });
  w.on('error', e => errors.push(e));
  const result = await new r.promises.Readline(w).clearScreenDown().commit();
  await tick(); assert.equal(result, error); assert.equal(errors.length, 1);
  assert.equal(errors[0], error); return [result.message, errors.length];
});
async function sharedProgram(r, filename, marker) {
  const text = fs.readFileSync(path.join(root, 'crates/franken-engine/tests/fixtures', filename), 'utf8');
  const lines = [];
  const result = vm.runInNewContext(text, {
    __r: r, __Readline: r.promises.Readline, __Writable: Writable,
    console: { log(line) { lines.push(line); } }, Promise, Error,
  });
  await result;
  assert.deepEqual(lines, [marker]);
  return lines;
}
compare('exact public native fixture also executes under both host APIs', async r => {
  return sharedProgram(r, 'readline_cursor.js', 'READLINE_CURSOR_OK');
});
only('exact native reentry fixture executes under the production installer', async r => {
  return sharedProgram(r, 'readline_cursor_reentry.js', 'READLINE_CURSOR_REENTRY_OK');
});
(async () => {
  const report = { node: process.version, strictReference: process.argv.includes('--strict-reference'), groups: [], passed: 0, failed: 0 };
  for (const group of groups) {
    try {
      const actual = await group.fn(candidate());
      if (group.compare || process.argv.includes('--strict-reference')) {
        const reference = await group.fn(node);
        assert.deepEqual(actual, reference);
      }
      report.groups.push({ name: group.name, result: 'pass', nodeCompared: group.compare }); report.passed++;
    } catch (e) { report.groups.push({ name: group.name, result: 'fail', error: String(e), stack: e.stack }); report.failed++; }
  }
  console.log(JSON.stringify(report, null, 2));
  if (report.failed) process.exitCode = 1;
})().catch(e => { console.error(e); process.exitCode = 1; });
