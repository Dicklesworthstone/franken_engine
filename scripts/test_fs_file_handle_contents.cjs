'use strict';
// Execute the shipped facade against real files. Node is a reference adapter,
// not a runtime dependency. This does not verify Rust execution or IFC policy.
// Run: node --test scripts/test_fs_file_handle_contents.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { test, after } = require('node:test');
const source = fs.readFileSync(process.env.FRANKEN_FS_FACADE_SOURCE || path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/fs_module.js'), 'utf8');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-fs-contents-'));
const descriptors = new Set();
let nextFile = 0;
after(() => {
  for (const fd of descriptors) { fs.closeSync(fd); }
  fs.rmSync(root, { recursive: true, force: true });
});
function fixture(hook = () => {}) {
  const calls = [];
  const dispatch = (authority, discriminator, ...args) => {
    const operation = discriminator.slice('\0fsop:'.length);
    calls.push({ authority, operation, args });
    const override = hook(authority, operation, args);
    if (override !== undefined) { return override; }
    switch (operation) {
      case 'open': {
        const fd = fs.openSync(...args);
        descriptors.add(fd);
        return fd;
      }
      case 'close_fd': {
        fs.closeSync(...args);
        descriptors.delete(args[0]);
        return;
      }
      case 'read_fd': return fs.readSync(...args);
      case 'write_fd': return fs.writeSync(...args);
      case 'fsync': return fs.fsyncSync(...args);
      default: throw new Error(`unexpected host operation: ${operation}`);
    }
  };
  const context = { Buffer, Promise, Reflect: { apply: Reflect.apply }, Error, TypeError, RangeError,
    __franken_fs_read: (...args) => dispatch('fs_read', ...args),
    __franken_fs_write: (...args) => dispatch('fs_write', ...args) };
  return { facade: vm.runInNewContext(source, context), context, calls,
    file: path.join(root, `file-${nextFile++}`) };
}

test('whole-file operations match Node cursors, non-truncation and return values', async () => {
  async function exercise(open, file) {
    fs.writeFileSync(file, 'abcdefghij');
    const handle = await open(file, 'r+');
    try {
      const first = await handle.read(Buffer.alloc(2));
      const written = await handle.writeFile('XY');
      const appended = await handle.appendFile(Buffer.from('Z'));
      const tail = await handle.readFile({ encoding: 'utf8' });
      const eof = await handle.readFile();
      return [first.buffer.toString(), written, appended, tail, Buffer.isBuffer(eof),
        eof.length, fs.readFileSync(file, 'utf8')];
    } finally { await handle.close(); }
  }
  const { facade, file, calls } = fixture();
  assert.deepEqual(await exercise(facade.promises.open, file),
    await exercise(fs.promises.open, file + '-node'));
  assert.equal(calls.filter(call => call.operation === 'open').length, 1);
  for (const call of calls) {
    assert.equal(call.authority, call.operation === 'read_fd' ? 'fs_read' : 'fs_write');
  }
});

test('append-mode handles append without changing descriptor ownership', async () => {
  const { facade, file } = fixture();
  fs.writeFileSync(file, 'prefix');
  const handle = await facade.promises.open(file, 'a');
  assert.equal(await handle.appendFile('4142', 'hex'), undefined);
  assert.equal(await handle.writeFile('!'), undefined);
  await handle.close();
  assert.equal(fs.readFileSync(file, 'utf8'), 'prefixAB!');
});

test('readFile remains attached to the open file after its path is replaced', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'original');
  const handle = await facade.promises.open(file, 'r');
  fs.renameSync(file, file + '-held');
  fs.writeFileSync(file, 'replacement');
  assert.equal(await handle.readFile('utf8'), 'original');
  await handle.close();
  assert.equal(calls.filter(call => call.operation === 'open').length, 1);
});

test('multi-chunk UTF-8 reads decode only after byte assembly', async () => {
  const { facade, file } = fixture();
  const text = 'x'.repeat(16383) + '\u20ac' + '\ud83d\ude03'.repeat(9000);
  fs.writeFileSync(file, text);
  const handle = await facade.promises.open(file);
  assert.equal(await handle.readFile('utf8'), text);
  await handle.close();
});

test('short reads continue until zero and exclude unused buffer bytes', async () => {
  const { facade, file, calls } = fixture((authority, operation, args) => {
    if (operation === 'read_fd') {
      return fs.readSync(args[0], args[1], args[2], Math.min(args[3], 3), args[4]);
    }
  });
  fs.writeFileSync(file, 'abcdefghijk');
  const handle = await facade.promises.open(file);
  const data = await handle.readFile();
  assert(Buffer.isBuffer(data));
  assert.equal(data.toString(), 'abcdefghijk');
  assert.equal(data.length, 11);
  assert.equal(calls.filter(call => call.operation === 'read_fd').length, 5);
  await handle.close();
});

test('partial writes advance the buffer offset and complete every byte', async () => {
  const { facade, file } = fixture((authority, operation, args) => {
    if (operation === 'write_fd') {
      return fs.writeSync(args[0], args[1], args[2], Math.min(args[3], 7), args[4]);
    }
  });
  const data = Buffer.from('abcdefghij'.repeat(1700));
  const handle = await facade.promises.open(file, 'w');
  assert.equal(await handle.writeFile(data), undefined);
  await handle.close();
  assert.deepEqual(fs.readFileSync(file), data);
});

test('zero and invalid write counts reject instead of hanging or succeeding', async () => {
  for (const count of [0, -1, 5, NaN, Infinity, 0.5, '1']) {
    const { facade, file, calls } = fixture((authority, operation) =>
      operation === 'write_fd' ? count : undefined);
    const handle = await facade.promises.open(file, 'w');
    await assert.rejects(handle.writeFile('data'), { code: 'EIO', syscall: 'write' });
    assert.equal(calls.filter(call => call.operation === 'write_fd').length, 1);
    await handle.close();
  }
});

test('invalid read counts reject without exposing fabricated contents', async () => {
  for (const count of [-1, 16385, NaN, Infinity, 0.5, '1']) {
    const { facade, file } = fixture((authority, operation) =>
      operation === 'read_fd' ? count : undefined);
    fs.writeFileSync(file, 'data');
    const handle = await facade.promises.open(file);
    await assert.rejects(handle.readFile(), { code: 'EIO', syscall: 'read' });
    await handle.close();
  }
});

test('invalid options, encodings and data reject before descriptor I/O', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  for (const options of [5, true, () => {}]) {
    await assert.rejects(handle.readFile(options), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  for (const encoding of ['madeup', 5]) {
    await assert.rejects(handle.readFile({ encoding }), { code: 'ERR_INVALID_ARG_VALUE' });
    await assert.rejects(handle.writeFile('data', { encoding }), { code: 'ERR_INVALID_ARG_VALUE' });
  }
  for (const signal of [null, {}, 5]) {
    await assert.rejects(handle.readFile({ signal }), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  await assert.rejects(handle.writeFile({}), { code: 'ERR_INVALID_ARG_TYPE' });
  assert.equal(calls.filter(call => /^(read|write)_fd$/.test(call.operation)).length, 0);
  await handle.close();
});

test('pre-aborted reads and writes reject with cause and perform no I/O', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const reason = new Error('cancelled');
  const signal = AbortSignal.abort(reason);
  for (const pending of [handle.readFile({ signal }), handle.writeFile('data', { signal }),
    handle.appendFile('data', { signal })]) {
    await assert.rejects(pending, error => error.code === 'ABORT_ERR' &&
      error.name === 'AbortError' && error.cause === reason);
  }
  assert.equal(calls.filter(call => /^(read|write)_fd$/.test(call.operation)).length, 0);
  await handle.close();
});

test('abort between chunks rejects and does not claim partial writes were rolled back', async () => {
  const controller = new AbortController();
  const { facade, file, calls } = fixture((authority, operation) => {
    if (operation === 'write_fd') { controller.abort('stop'); }
  });
  const handle = await facade.promises.open(file, 'w');
  await assert.rejects(handle.writeFile(Buffer.alloc(40000, 65), { signal: controller.signal }),
    { code: 'ABORT_ERR', cause: 'stop' });
  await handle.close();
  assert.equal(calls.filter(call => call.operation === 'write_fd').length, 1);
  assert.equal(fs.statSync(file).size, 16384);
});

test('abort after a read rejects rather than returning partial data', async () => {
  const controller = new AbortController();
  const { facade, file, calls } = fixture((authority, operation) => {
    if (operation === 'read_fd') { controller.abort(); }
  });
  fs.writeFileSync(file, 'data');
  const handle = await facade.promises.open(file);
  await assert.rejects(handle.readFile({ signal: controller.signal }), { code: 'ABORT_ERR' });
  assert.equal(calls.filter(call => call.operation === 'read_fd').length, 1);
  await handle.close();
});

test('close reentered by an encoding getter waits for the entire operation', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  let closing;
  await handle.writeFile('x'.repeat(40000), {
    get encoding() {
      closing = handle.close();
      assert.equal(calls.filter(call => call.operation === 'close_fd').length, 0);
      return 'utf8';
    }
  });
  await closing;
  assert.equal(fs.statSync(file).size, 40000);
  assert.equal(calls.at(-1).operation, 'close_fd');
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
});

test('a throwing options getter drains a reentrant close without I/O', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const sentinel = new Error('getter failed');
  let closing;
  await assert.rejects(handle.readFile({ get encoding() {
    closing = handle.close(); throw sentinel;
  } }), error => error === sentinel);
  await closing;
  assert.deepEqual(calls.map(call => call.operation), ['open', 'close_fd']);
});

test('all whole-file methods reject after close without touching recycled descriptors', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  await handle.close();
  const count = calls.length;
  for (const pending of [handle.readFile(), handle.writeFile('late'), handle.appendFile('late')]) {
    await assert.rejects(pending, { code: 'EBADF' });
  }
  assert.equal(calls.length, count);
});

test('provider denial propagates unchanged; whole-file methods never reopen paths', async () => {
  const denied = Object.assign(new Error('denied'), { code: 'DENIED' });
  const { facade, file, calls } = fixture((authority, operation) => {
    if (/^(read|write)_fd$/.test(operation)) { throw denied; }
  });
  const handle = await facade.promises.open(file, 'w+');
  await assert.rejects(handle.readFile(), error => error === denied);
  await assert.rejects(handle.writeFile('no'), error => error === denied);
  await handle.close();
  assert.equal(fs.statSync(file).size, 0);
  assert.equal(calls.filter(call => call.operation === 'open').length, 1);
});

test('captured helpers and private operations ignore mutated public bindings', async () => {
  const { facade, context, file } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const fail = () => { throw new Error('guest helper'); };
  facade.readSync = fail;
  facade.writeSync = fail;
  facade.readFileSync = fail;
  facade.writeFileSync = fail;
  context.Buffer = { alloc: fail, from: fail, concat: fail, isEncoding: fail };
  context.Promise = fail;
  context.Reflect.apply = fail;
  await handle.writeFile('safe');
  assert.equal((await handle.read(Buffer.alloc(4), 0, 4, 0)).buffer.toString(), 'safe');
  await handle.close();
  const reader = await facade.promises.open(file);
  assert.equal(await reader.readFile('utf8'), 'safe');
  await reader.close();
});
