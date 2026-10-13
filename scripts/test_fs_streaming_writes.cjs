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
      case 'write': return fs.writeFile(...args);
      case 'append': return fs.appendFile(...args);
      default: throw new Error(`unexpected operation ${operation}`);
    }
  };
  const context = { Buffer, Promise, Symbol, WeakMap, ArrayBuffer,
    Reflect: { apply: Reflect.apply }, Error, TypeError, RangeError, AggregateError,
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

test('pathname iterables match Node default overwrite, append, encoding and return values', async () => {
  async function exercise(api, file) {
    fs.writeFileSync(file, 'old contents');
    const written = await api.writeFile(file, ['41', Buffer.from('B'), 'c3a9'], 'hex');
    const appended = await api.appendFile(file, Readable.from(['!', Buffer.from('?')]));
    return [written, appended, fs.readFileSync(file)];
  }
  const { facade, file, calls } = fixture();
  assert.deepEqual(await exercise(facade.promises, file),
    await exercise(fs.promises, file + '-node'));
  assert.equal(operations(calls, 'open').length, 2);
  assert.equal(operations(calls, 'close_fd').length, 2);
  assert(calls.every(call => call.authority === 'fs_write'));
});

test('pathname writes retain explicit flags and modes, including exclusive creation', async () => {
  const { facade, file, calls } = fixture();
  await facade.promises.writeFile(file, ['first'], { flag: 'wx', mode: 0o600 });
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  await assert.rejects(facade.promises.writeFile(file, ['forbidden'], { flag: 'wx' }),
    { code: 'EEXIST' });
  assert.equal(fs.readFileSync(file, 'utf8'), 'first');
  await facade.promises.writeFile(file, ['!'], { flag: 'a' });
  assert.equal(fs.readFileSync(file, 'utf8'), 'first!');
  assert.equal(operations(calls, 'close_fd').length, 2);
  assert.deepEqual(operations(calls, 'open')[0].args.slice(1), ['wx', 0o600]);
});

test('pathname empty iterable still creates or truncates the destination', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'old');
  await facade.promises.writeFile(file, []);
  assert.equal(fs.statSync(file).size, 0);
  assert.deepEqual(calls.map(call => call.operation), ['open', 'close_fd']);
});

test('pathname validation and pre-abort occur before open or truncation', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'preserved');
  for (const options of [{ encoding: 'nonsense' }, { flush: 'yes' }, 3]) {
    await assert.rejects(facade.promises.writeFile(file, ['data'], options));
  }
  let touched = false;
  const input = { get [Symbol.asyncIterator]() { touched = true; throw new Error('source'); } };
  await assert.rejects(facade.promises.writeFile(file, input, {
    signal: AbortSignal.abort('stop'),
  }), { code: 'ABORT_ERR', cause: 'stop' });
  assert.equal(touched, false);
  await assert.rejects(facade.promises.writeFile(file, {}), { code: 'ERR_INVALID_ARG_TYPE' });
  assert.equal(operations(calls, 'open').length, 0);
  assert.equal(fs.readFileSync(file, 'utf8'), 'preserved');
});

test('pathname option and protocol getters are read once before opening', async () => {
  const { facade, file, calls } = fixture();
  const reads = { encoding: 0, signal: 0, flag: 0, mode: 0, flush: 0, iterator: 0 };
  const options = {};
  for (const [key, value] of Object.entries({ encoding: 'hex', signal: undefined,
    flag: 'w', mode: 0o600, flush: false })) {
    Object.defineProperty(options, key, { get() {
      assert.equal(operations(calls, 'open').length, 0);
      reads[key] += 1; return value;
    } });
  }
  const input = { get [Symbol.iterator]() {
    assert.equal(operations(calls, 'open').length, 0);
    reads.iterator += 1;
    return function* () { assert.equal(this, input); yield '41'; yield '42'; };
  } };
  await facade.promises.writeFile(file, input, options);
  assert.deepEqual(Object.values(reads), [1, 1, 1, 1, 1, 1]);
  assert.equal(fs.readFileSync(file, 'utf8'), 'AB');
});

test('pathname open refusal does not start the producer or try to close a missing fd', async () => {
  const denied = Object.assign(new Error('denied'), { code: 'DENIED' });
  const { facade, file, calls } = fixture((authority, operation) => {
    if (operation === 'open') { throw denied; }
  });
  let started = false;
  const input = { [Symbol.iterator]() { started = true; return [][Symbol.iterator](); } };
  await assert.rejects(facade.promises.writeFile(file, input), error => error === denied);
  assert.equal(started, false);
  assert.equal(operations(calls, 'close_fd').length, 0);
  assert.equal(fs.existsSync(file), false);
});

test('pathname input uses one descriptor across pending producers and path replacement',
  { timeout: 5000 }, async () => {
    const { facade, file, calls } = fixture();
    const started = deferred();
    const gate = deferred();
    async function* input() { started.resolve(); yield await gate.promise; yield 'tail'; }
    const writing = facade.promises.writeFile(file, input());
    await startedOrFailed(started, writing);
    fs.renameSync(file, file + '-held');
    fs.writeFileSync(file, 'replacement');
    assert.equal(operations(calls, 'close_fd').length, 0);
    gate.resolve('head');
    await writing;
    assert.equal(fs.readFileSync(file, 'utf8'), 'replacement');
    assert.equal(fs.readFileSync(file + '-held', 'utf8'), 'headtail');
    assert.equal(operations(calls, 'open').length, 1);
    assert.equal(operations(calls, 'close_fd').length, 1);
  });

test('pathname provider failure waits for async iterator cleanup before closing',
  { timeout: 5000 }, async () => {
    const failure = Object.assign(new Error('write failure'), { code: 'EIO' });
    const { facade, file, calls } = fixture((authority, operation) => {
      if (operation === 'write_fd') { throw failure; }
    });
    const cleaning = deferred();
    const gate = deferred();
    async function* input() {
      try { yield 'data'; }
      finally { cleaning.resolve(); await gate.promise; }
    }
    const writing = facade.promises.writeFile(file, input());
    await startedOrFailed(cleaning, writing);
    assert.equal(operations(calls, 'close_fd').length, 0);
    gate.resolve();
    await assert.rejects(writing, error => error === failure);
    assert.equal(operations(calls, 'close_fd').length, 1);
    assert.equal(calls.at(-1).operation, 'close_fd');
  });

test('pathname producer rejection closes its owned fd and retains partial bytes', async () => {
  const { facade, file, calls } = fixture();
  const failure = new Error('source failed');
  async function* input() { yield 'prefix'; throw failure; }
  await assert.rejects(facade.promises.appendFile(file, input()), error => error === failure);
  assert.equal(operations(calls, 'close_fd').length, 1);
  assert.equal(fs.readFileSync(file, 'utf8'), 'prefix');
});

test('pathname abort after a chunk stops writes, finalizes input, and closes once', async () => {
  const controller = new AbortController();
  const { facade, file, calls } = fixture((authority, operation) => {
    if (operation === 'write_fd') { controller.abort('stop'); }
  });
  let finalized = false;
  let pulls = 0;
  async function* input() {
    try { pulls += 1; yield 'prefix'; pulls += 1; yield 'never'; }
    finally { finalized = true; }
  }
  await assert.rejects(facade.promises.writeFile(file, input(), { signal: controller.signal }),
    { code: 'ABORT_ERR', cause: 'stop' });
  assert.equal(finalized, true);
  assert.equal(pulls, 1);
  assert.equal(fs.readFileSync(file, 'utf8'), 'prefix');
  assert.equal(operations(calls, 'close_fd').length, 1);
});

test('pathname flush syncs after the last chunk and before close', async () => {
  const { facade, file, calls } = fixture();
  await facade.promises.writeFile(file, ['one', 'two'], { flush: true });
  assert.deepEqual(calls.map(call => call.operation),
    ['open', 'write_fd', 'write_fd', 'fsync', 'close_fd']);
  assert.equal(fs.readFileSync(file, 'utf8'), 'onetwo');
});

test('pathname fsync failure rejects but still closes the descriptor', async () => {
  const failure = Object.assign(new Error('sync failed'), { code: 'EIO' });
  const { facade, file, calls } = fixture((authority, operation) => {
    if (operation === 'fsync') { throw failure; }
  });
  await assert.rejects(facade.promises.writeFile(file, ['data'], { flush: true }),
    error => error === failure);
  assert.equal(operations(calls, 'close_fd').length, 1);
  assert.equal(fs.readFileSync(file, 'utf8'), 'data');
});

test('pathname close failure is reported once and never retried', async () => {
  const failure = Object.assign(new Error('close failed'), { code: 'EIO' });
  const { facade, file, calls } = fixture((authority, operation) => {
    if (operation === 'close_fd') { throw failure; }
  });
  await assert.rejects(facade.promises.writeFile(file, ['data']), error => error === failure);
  assert.equal(operations(calls, 'close_fd').length, 1);
  assert.equal(fs.readFileSync(file, 'utf8'), 'data');
  // This adapter deliberately retained the real descriptor on close failure;
  // the suite's held-fd teardown releases it, not the production facade.
});

test('pathname simultaneous write and close failures retain both errors', async () => {
  const writeError = Object.assign(new Error('write failed'), { code: 'WRITE_FAILED' });
  const closeError = Object.assign(new Error('close failed'), { code: 'CLOSE_FAILED' });
  const { facade, file, calls } = fixture((authority, operation) => {
    if (operation === 'write_fd') { throw writeError; }
    if (operation === 'close_fd') { throw closeError; }
  });
  await assert.rejects(facade.promises.writeFile(file, ['data']), error => {
    assert.equal(error.name, 'AggregateError');
    assert.deepEqual(Array.from(error.errors), [writeError, closeError]);
    return true;
  });
  assert.equal(operations(calls, 'close_fd').length, 1);
});

test('pathname falsy producer throws are not mistaken for successful completion', async () => {
  for (const failure of [undefined, null, false, 0]) {
    const { facade, file, calls } = fixture();
    function* input() { yield 'prefix'; throw failure; }
    let rejected = false;
    try { await facade.promises.writeFile(file, input()); }
    catch (error) { rejected = true; assert.equal(error, failure); }
    assert.equal(rejected, true);
    assert.equal(operations(calls, 'close_fd').length, 1);
    assert.equal(fs.readFileSync(file, 'utf8'), 'prefix');
  }
});

test('pathname streaming ignores replaced public file methods', async () => {
  const { facade, context, file } = fixture();
  const fail = () => { throw new Error('public replacement'); };
  facade.promises.open = fail;
  facade.openSync = fail;
  facade.closeSync = fail;
  facade.writeSync = fail;
  facade.fsyncSync = fail;
  context.Promise = fail;
  context.ArrayBuffer = { isView: fail };
  context.Reflect.apply = fail;
  await facade.promises.writeFile(file, ['one', 'two'], { flush: true });
  assert.equal(fs.readFileSync(file, 'utf8'), 'onetwo');
});

test('scalar and binary-view pathname writes retain the native callback route', async () => {
  const { facade, file, calls } = fixture();
  for (const data of ['text', Buffer.from('buffer'), new Uint8Array([65, 66]),
    new DataView(new Uint8Array([67, 68]).buffer)]) {
    await facade.promises.writeFile(file, data);
  }
  await facade.promises.appendFile(file, '!');
  assert.equal(operations(calls, 'open').length, 0);
  assert.deepEqual(calls.map(call => call.operation), ['write', 'write', 'write', 'write', 'append']);
  assert.equal(fs.readFileSync(file, 'utf8'), 'CD!');
});

test('pathname iterator acquisition failures close the descriptor after open', async () => {
  const failure = new Error('iterator factory failed');
  for (const input of [
    { [Symbol.iterator]() { throw failure; } },
    { [Symbol.asyncIterator]() { return 0; } },
    { [Symbol.iterator]() { return { get next() { throw failure; } }; } },
    { [Symbol.asyncIterator]() { return { next() { return Promise.resolve(0); } }; } },
  ]) {
    const { facade, file, calls } = fixture();
    await assert.rejects(facade.promises.writeFile(file, input));
    assert.equal(operations(calls, 'open').length, 1);
    assert.equal(operations(calls, 'close_fd').length, 1);
    assert.equal(operations(calls, 'write_fd').length, 0);
  }
});

test('pathname streaming bounds each native request and finishes short writes before pulling', async () => {
  const { facade, file, calls } = fixture((authority, operation, args) => {
    if (operation === 'write_fd') {
      assert(args[3] <= 16384);
      return fs.writeSync(args[0], args[1], args[2], Math.min(args[3], 3000), args[4]);
    }
  });
  const bytes = Buffer.alloc(50000, 65);
  async function* input() {
    yield bytes;
    assert.equal(fs.statSync(file).size, bytes.length);
    yield 'tail';
  }
  await facade.promises.writeFile(file, input());
  assert.deepEqual(fs.readFileSync(file), Buffer.concat([bytes, Buffer.from('tail')]));
  assert.equal(operations(calls, 'open').length, 1);
  assert.equal(operations(calls, 'close_fd').length, 1);
});
