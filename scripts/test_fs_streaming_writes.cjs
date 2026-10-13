'use strict';
// Executes the shipped JS facade against real files through a Node reference
// adapter. This is NOT native interpreter, capability, or IFC validation.
// Run: node --test scripts/test_fs_streaming_writes.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { test, after } = require('node:test');
const { Readable } = require('node:stream');
const source = fs.readFileSync(process.env.FRANKEN_FS_FACADE_SOURCE || path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/fs_module.js'), 'utf8');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-stream-writes-'));
const held = new Set();
let sequence = 0;
after(() => { for (const fd of held) { fs.closeSync(fd); } });
function fixture(hook = () => {}) {
  const calls = [];
  const dispatch = (authority, discriminator, ...args) => {
    const operation = discriminator.slice('\0fsop:'.length);
    calls.push({ authority, operation, args });
    const override = hook(authority, operation, args);
    if (override !== undefined) { return override; }
    switch (operation) {
      case 'open': { const fd = fs.openSync(...args); held.add(fd); return fd; }
      case 'close_fd': fs.closeSync(...args); held.delete(args[0]); return;
      case 'read_fd': return fs.readSync(...args);
      case 'write_fd': return fs.writeSync(...args);
      case 'fsync': return fs.fsyncSync(...args);
      default: throw new Error(`unexpected operation ${operation}`);
    }
  };
  const context = { Buffer, Promise, Symbol, WeakMap, Reflect: { apply: Reflect.apply },
    Error, TypeError, RangeError,
    __franken_fs_read: (...args) => dispatch('fs_read', ...args),
    __franken_fs_write: (...args) => dispatch('fs_write', ...args) };
  return { facade: vm.runInNewContext(source, context), context, calls,
    file: path.join(root, `file-${sequence++}`) };
}
function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}
function operations(calls, name) { return calls.filter(call => call.operation === name); }
async function startedOrFailed(started, operation) {
  await Promise.race([started.promise, operation.then(() => {
    throw new Error('operation completed before source started');
  })]);
}

test('constructing fs remains effect-free', () => {
  const { facade, calls } = fixture();
  assert.equal(typeof facade.promises.open, 'function');
  assert.deepEqual(calls, []);
});

test('streamed chunks and encodings match live Node FileHandle', async () => {
  async function exercise(open, file) {
    const handle = await open(file, 'w+');
    async function* chunks() {
      yield '41'; yield Buffer.from('B'); yield 'c3a9'; yield '';
      yield Buffer.alloc(20000, 67);
    }
    const result = await handle.writeFile(chunks(), 'hex');
    const readable = Buffer.alloc(4);
    await handle.read(readable, 0, 4, 0);
    await handle.close();
    return [result, readable, fs.readFileSync(file)];
  }
  const { facade, file } = fixture();
  assert.deepEqual(await exercise(facade.promises.open, file),
    await exercise(fs.promises.open, file + '-node'));
});

test('sync iterables await promised values and do not buffer the whole source', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w');
  let pulls = 0;
  function* chunks() {
    for (const chunk of ['one', 'two', 'three']) {
      assert.equal(operations(calls, 'write_fd').length, pulls);
      pulls += 1;
      yield Promise.resolve(Buffer.from(chunk));
    }
  }
  assert.equal(await handle.writeFile(chunks()), undefined);
  await handle.close();
  assert.equal(pulls, 3);
  assert.equal(fs.readFileSync(file, 'utf8'), 'onetwothree');
});

test('a Readable async iterator streams directly into a handle', async () => {
  const { facade, file } = fixture();
  const handle = await facade.promises.open(file, 'w');
  await handle.writeFile(Readable.from(['alpha', Buffer.from('beta'), 'gamma']));
  await handle.close();
  assert.equal(fs.readFileSync(file, 'utf8'), 'alphabetagamma');
});

test('partial writes finish one chunk before pulling the next', async () => {
  const { facade, file, calls } = fixture((authority, operation, args) => {
    if (operation === 'write_fd') {
      assert.equal(authority, 'fs_write');
      assert(args[3] <= 16384);
      return fs.writeSync(args[0], args[1], args[2], Math.min(args[3], 7), args[4]);
    }
  });
  const handle = await facade.promises.open(file, 'w');
  const first = Buffer.alloc(20001, 65);
  function* chunks() {
    yield first;
    assert.equal(fs.statSync(file).size, first.length);
    yield 'last';
  }
  await handle.writeFile(chunks());
  await handle.close();
  assert.deepEqual(fs.readFileSync(file), Buffer.concat([first, Buffer.from('last')]));
  assert.equal(operations(calls, 'open').length, 1);
  assert(operations(calls, 'write_fd').length > 2);
});

test('iterator selection reads getters once, prefers async, and preserves this', async () => {
  const { facade, file } = fixture();
  const handle = await facade.promises.open(file, 'w');
  let asyncGets = 0;
  let syncGets = 0;
  let factories = 0;
  const data = {
    get [Symbol.asyncIterator]() {
      asyncGets += 1;
      return function () {
        assert.equal(this, data); factories += 1;
        let index = 0;
        return { next() { return Promise.resolve(index++ === 0 ?
          { value: 'async', done: false } : { done: true }); } };
      };
    },
    get [Symbol.iterator]() { syncGets += 1; throw new Error('wrong protocol'); }
  };
  await handle.writeFile(data);
  await handle.close();
  assert.deepEqual([asyncGets, syncGets, factories], [1, 0, 1]);
  assert.equal(fs.readFileSync(file, 'utf8'), 'async');
});

test('null async method falls back to the sync iterator', async () => {
  const { facade, file } = fixture();
  const handle = await facade.promises.open(file, 'w');
  let gets = 0;
  const data = { [Symbol.asyncIterator]: null,
    get [Symbol.iterator]() { gets += 1; return function* () { yield 'sync'; }; } };
  await handle.writeFile(data);
  await handle.close();
  assert.equal(gets, 1);
  assert.equal(fs.readFileSync(file, 'utf8'), 'sync');
});

test('empty sources make no descriptor writes', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w');
  await handle.writeFile([]);
  await handle.appendFile((async function* () {})());
  await handle.close();
  assert.equal(operations(calls, 'write_fd').length, 0);
  assert.equal(fs.statSync(file).size, 0);
});

test('close waits through pending next and disallows new operations', { timeout: 5000 }, async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const started = deferred();
  const gate = deferred();
  async function* chunks() { started.resolve(); yield await gate.promise; yield 'end'; }
  const write = handle.writeFile(chunks());
  await startedOrFailed(started, write);
  const close = handle.close();
  assert.equal(close, handle.close());
  assert.equal(handle.fd, -1);
  assert.equal(operations(calls, 'close_fd').length, 0);
  await assert.rejects(handle.writeFile(['late']), { code: 'EBADF' });
  await assert.rejects(handle.read(), { code: 'EBADF' });
  gate.resolve('begin');
  await write;
  await close;
  assert.equal(operations(calls, 'close_fd').length, 1);
  assert.equal(calls.at(-1).operation, 'close_fd');
  assert.equal(fs.readFileSync(file, 'utf8'), 'beginend');
});

test('close waits for asynchronous iterator cleanup after an invalid chunk', { timeout: 5000 }, async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w');
  const cleaning = deferred();
  const gate = deferred();
  async function* chunks() {
    try { yield {}; }
    finally { cleaning.resolve(); await gate.promise; }
  }
  const write = handle.writeFile(chunks());
  await startedOrFailed(cleaning, write);
  const close = handle.close();
  assert.equal(operations(calls, 'close_fd').length, 0);
  gate.resolve();
  await assert.rejects(write, { code: 'ERR_INVALID_ARG_TYPE' });
  await close;
  assert.deepEqual(calls.map(call => call.operation), ['open', 'close_fd']);
});

test('pre-aborted writes do not even obtain the iterator', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w');
  let touched = false;
  const input = { get [Symbol.iterator]() { touched = true; throw new Error('pulled'); } };
  const reason = new Error('stop');
  await assert.rejects(handle.writeFile(input, { signal: AbortSignal.abort(reason) }),
    error => error.code === 'ABORT_ERR' && error.cause === reason);
  assert.equal(touched, false);
  assert.equal(operations(calls, 'write_fd').length, 0);
  await handle.close();
});

test('abort while awaiting a source suppresses late bytes and closes the iterator', { timeout: 5000 }, async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w');
  const controller = new AbortController();
  const started = deferred();
  const gate = deferred();
  let finalized = false;
  async function* chunks() {
    try { started.resolve(); yield await gate.promise; yield 'never'; }
    finally { finalized = true; }
  }
  const write = handle.writeFile(chunks(), { signal: controller.signal });
  await startedOrFailed(started, write);
  controller.abort('stop');
  const close = handle.close();
  gate.resolve('late');
  await assert.rejects(write, { code: 'ABORT_ERR', cause: 'stop' });
  await close;
  assert.equal(finalized, true);
  assert.equal(operations(calls, 'write_fd').length, 0);
  assert.equal(fs.statSync(file).size, 0);
});

test('abort after partial output retains those bytes and stops pulling', async () => {
  const controller = new AbortController();
  const { facade, file } = fixture((authority, operation) => {
    if (operation === 'write_fd') { controller.abort('enough'); }
  });
  const handle = await facade.promises.open(file, 'w');
  let finalized = false;
  let pulls = 0;
  function* chunks() {
    try { pulls += 1; yield 'prefix'; pulls += 1; yield 'never'; }
    finally { finalized = true; }
  }
  await assert.rejects(handle.writeFile(chunks(), { signal: controller.signal }), { code: 'ABORT_ERR' });
  await handle.close();
  assert.equal(finalized, true);
  assert.equal(pulls, 1);
  assert.equal(fs.readFileSync(file, 'utf8'), 'prefix');
});

test('provider failure closes the input but not the caller-owned handle', async () => {
  const failure = Object.assign(new Error('provider refused'), { code: 'DENIED' });
  const { facade, file, calls } = fixture((authority, operation) => {
    if (operation === 'write_fd') { throw failure; }
  });
  const handle = await facade.promises.open(file, 'w');
  let finalized = false;
  function* chunks() { try { yield 'denied'; } finally { finalized = true; } }
  await assert.rejects(handle.writeFile(chunks()), error => error === failure);
  assert.equal(finalized, true);
  assert.equal(operations(calls, 'close_fd').length, 0);
  assert(handle.fd >= 0);
  await handle.close();
  assert.equal(fs.statSync(file).size, 0);
});

test('a source next rejection propagates unchanged and releases close ownership', async () => {
  const { facade, file } = fixture();
  const handle = await facade.promises.open(file, 'w');
  const failure = new Error('producer failed');
  const data = { [Symbol.asyncIterator]() { return { next() { return Promise.reject(failure); } }; } };
  await assert.rejects(handle.writeFile(data), error => error === failure);
  await handle.close();
  assert.equal(handle.fd, -1);
});

test('body error wins over a rejecting iterator return, matching for-await semantics', async () => {
  const { facade, file } = fixture();
  const handle = await facade.promises.open(file, 'w');
  let returns = 0;
  const data = { [Symbol.asyncIterator]() { return {
    next() { return Promise.resolve({ value: {}, done: false }); },
    return() { returns += 1; return Promise.reject(new Error('cleanup failed')); }
  }; } };
  await assert.rejects(handle.writeFile(data), { code: 'ERR_INVALID_ARG_TYPE' });
  assert.equal(returns, 1);
  await handle.close();
});

test('invalid inputs reject with no descriptor effects and keep the handle usable', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w');
  for (const data of [null, undefined, 4, true, {}, { [Symbol.asyncIterator]: 5 },
    { [Symbol.iterator]: 'invalid' }]) {
    await assert.rejects(handle.writeFile(data), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  assert.equal(operations(calls, 'write_fd').length, 0);
  await handle.writeFile('usable');
  await handle.close();
  assert.equal(fs.readFileSync(file, 'utf8'), 'usable');
});

test('options are read once and reentrant close drains all streamed chunks', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w');
  let closing;
  let reads = 0;
  await handle.writeFile(['41', '42', '43'], { get encoding() {
    reads += 1; closing = handle.close(); return 'hex';
  } });
  await closing;
  assert.equal(reads, 1);
  assert.equal(calls.at(-1).operation, 'close_fd');
  assert.equal(fs.readFileSync(file, 'utf8'), 'ABC');
});

test('zero-progress writes reject and close the iterator instead of looping', async () => {
  const { facade, file, calls } = fixture((authority, operation) => operation === 'write_fd' ? 0 : undefined);
  const handle = await facade.promises.open(file, 'w');
  let finalized = false;
  function* chunks() { try { yield 'bytes'; } finally { finalized = true; } }
  await assert.rejects(handle.writeFile(chunks()), { code: 'EIO' });
  assert.equal(finalized, true);
  assert.equal(operations(calls, 'write_fd').length, 1);
  await handle.close();
});

test('existing handle overloads dispatch privately even when public methods are replaced', async () => {
  const { facade, context, file } = fixture();
  const handle = await facade.promises.open(file, 'w');
  const fail = () => { throw new Error('guest replacement'); };
  handle.writeFile = fail;
  handle.appendFile = fail;
  facade.writeSync = fail;
  context.Reflect.apply = fail;
  context.Symbol = {};
  await facade.promises.writeFile(handle, ['one', 'two']);
  await facade.promises.appendFile(handle, (async function* () { yield 'three'; })());
  await handle.close();
  assert.equal(fs.readFileSync(file, 'utf8'), 'onetwothree');
});

test('streamed append preserves open flags and nontruncating descriptor cursor', async () => {
  async function exercise(open, file) {
    fs.writeFileSync(file, 'abcdefgh');
    const handle = await open(file, 'r+');
    await handle.read(Buffer.alloc(2));
    await handle.appendFile(['X', Buffer.from('Y')]);
    await handle.close();
    const appender = await open(file, 'a');
    await appender.writeFile(['!', '?']);
    await appender.close();
    return fs.readFileSync(file, 'utf8');
  }
  const { facade, file } = fixture();
  assert.equal(await exercise(facade.promises.open, file),
    await exercise(fs.promises.open, file + '-node'));
});
