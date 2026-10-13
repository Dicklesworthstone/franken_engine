'use strict';
// Runs the shipped JS facade against real files through a Node reference
// adapter. This tests facade semantics, NOT FrankenEngine's Rust execution,
// capability enforcement, or off-thread I/O. Native coverage is in
// crates/franken-engine/tests/fs_file_handles.rs.
// Run: node --test scripts/test_fs_file_handle_facade.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const source = fs.readFileSync(path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/fs_module.js'), 'utf8');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-fs-handles-'));
let nextFile = 0;
function fixture(hook = () => {}) {
  const calls = [];
  const dispatch = (authority, discriminator, ...args) => {
    const operation = discriminator.slice('\0fsop:'.length);
    calls.push({ authority, operation, args });
    hook(authority, operation, args);
    switch (operation) {
      case 'open': return fs.openSync(...args);
      case 'close_fd': return fs.closeSync(...args);
      case 'fsync': return fs.fsyncSync(...args);
      case 'read_fd': return fs.readSync(...args);
      case 'write_fd': return fs.writeSync(...args);
      case 'stat': return fs.statSync(...args);
      case 'mkdir': return fs.mkdirSync(...args);
      default: throw new Error(`unexpected native operation: ${operation}`);
    }
  };
  const context = {
    Buffer, Promise, Reflect: { apply: Reflect.apply }, Error, TypeError, RangeError,
    __franken_fs_read: (...args) => dispatch('fs_read', ...args),
    __franken_fs_write: (...args) => dispatch('fs_write', ...args),
  };
  return {
    facade: vm.runInNewContext(source, context), calls, context,
    file: path.join(root, `file-${nextFile++}`),
  };
}

test('constructing the module has no host effects', () => {
  const { facade, calls } = fixture();
  assert.equal(typeof facade.promises.open, 'function');
  assert.deepEqual(calls, []);
});

test('string encodings, byte counts, buffer identity and sync use descriptors', async () => {
  const { facade, calls, file } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const result = await handle.write('h\u00e9llo', 0, 'utf8');
  assert.equal(result.bytesWritten, 6);
  assert.equal(result.buffer, 'h\u00e9llo');
  const encoded = await handle.write('4142', 6, 'hex');
  assert.equal(encoded.bytesWritten, 2);
  assert.equal(encoded.buffer, '4142');
  assert.equal(await handle.sync(), undefined);
  const buffer = Buffer.alloc(2);
  const read = await handle.read(buffer, 0, 2, 1);
  assert.equal(read.bytesRead, 2);
  assert.equal(read.buffer, buffer);
  assert.equal(buffer.toString(), '\u00e9');
  await handle.close();
  assert.equal(fs.readFileSync(file, 'utf8'), 'h\u00e9lloAB');
  assert(calls.some(call => call.operation === 'fsync' && call.authority === 'fs_write'));
  assert(calls.some(call => call.operation === 'read_fd' && call.authority === 'fs_read'));
});

test('buffer windows and positional operations agree with Node FileHandle', async () => {
  async function exercise(open, file) {
    const handle = await open(file, 'w+');
    const buffer = Buffer.from('_abcd_');
    const put = await handle.write(buffer, { offset: 1, length: 4, position: 0 });
    assert.equal(put.buffer, buffer);
    const window = Buffer.alloc(4, 45);
    const got = await handle.read(window, { offset: 1, length: 2, position: 1 });
    assert.equal(got.buffer, window);
    const cursor = Buffer.alloc(2);
    const sequential = await handle.read(cursor);
    const eof = await handle.read({ position: 4 });
    await handle.close();
    return [put.bytesWritten, got.bytesRead, window.toString(), sequential.bytesRead,
      cursor.toString(), eof.bytesRead, eof.buffer.length, handle.fd];
  }
  const { facade, file } = fixture();
  const actual = await exercise(facade.promises.open, file);
  const expected = await exercise(fs.promises.open, file + '-node');
  assert.deepEqual(actual, expected);
});

test('read defaults, explicit options buffer and -1 current position', async () => {
  const { facade, file } = fixture();
  fs.writeFileSync(file, 'abcdef');
  const handle = await facade.promises.open(file);
  const buffer = Buffer.alloc(2);
  assert.equal((await handle.read({ buffer, position: -1 })).buffer, buffer);
  assert.equal(buffer.toString(), 'ab');
  const remaining = await handle.read();
  assert.equal(remaining.bytesRead, 4);
  assert.equal(remaining.buffer.length, 16384);
  assert.equal(remaining.buffer.subarray(0, 4).toString(), 'cdef');
  assert.equal((await handle.read(Buffer.alloc(0))).bytesRead, 0);
  await handle.close();
});

test('invalid windows reject without I/O or closing the handle', async () => {
  const { facade, calls, file } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  for (const [offset, length] of [[-1, 1], [0, -1], [0.5, 1], [0, 5], [NaN, 1]]) {
    await assert.rejects(handle.write(Buffer.alloc(4), offset, length),
      { code: 'ERR_OUT_OF_RANGE' });
  }
  await assert.rejects(handle.read(null), { code: 'ERR_INVALID_ARG_TYPE' });
  await assert.rejects(handle.write({}), { code: 'ERR_INVALID_ARG_TYPE' });
  assert.equal(calls.filter(call => /^(read|write)_fd$/.test(call.operation)).length, 0);
  assert.equal((await handle.write('ok')).bytesWritten, 2);
  await handle.close();
});

test('open failure is a deferred rejection, not a synchronous throw', async () => {
  const { facade, file } = fixture();
  let inline = true;
  const pending = facade.promises.open(file, 'r');
  assert(pending instanceof Promise);
  const observed = pending.catch(error => {
    assert.equal(inline, false);
    assert.equal(error.code, 'ENOENT');
  });
  inline = false;
  await observed;
});

test('close is idempotent and later operations cannot use a stale fd', async () => {
  const { facade, calls, file } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const descriptor = handle.fd;
  assert.equal(typeof descriptor, 'number');
  assert.throws(() => { handle.fd = descriptor + 1; });
  const closing = handle.close();
  assert.equal(handle.fd, -1);
  assert.equal(handle.close(), closing);
  assert.equal(await closing, undefined);
  assert.equal(await handle.close(), undefined);
  for (const pending of [handle.read(), handle.write('late'), handle.sync()]) {
    await assert.rejects(pending, { code: 'EBADF' });
  }
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
  assert.equal(calls.filter(call => /^(read|write)_fd$/.test(call.operation)).length, 0);
});

test('reentrant close waits for the active operation, including option getters', async () => {
  const { facade, calls, file } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  let closing;
  const written = await handle.write(Buffer.from('safe'), {
    get offset() {
      closing = handle.close();
      assert.equal(handle.fd, -1);
      assert.equal(calls.filter(call => call.operation === 'close_fd').length, 0);
      return 0;
    },
    length: 4,
  });
  assert.equal(written.bytesWritten, 4);
  await closing;
  assert.deepEqual(calls.map(call => call.operation), ['open', 'write_fd', 'close_fd']);
  assert.equal(fs.readFileSync(file, 'utf8'), 'safe');
});

test('reentrant close also drains when validation or a getter throws', async () => {
  const { facade, calls, file } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const sentinel = new Error('getter failed');
  let closing;
  await assert.rejects(handle.read({
    get buffer() { closing = handle.close(); throw sentinel; },
  }), error => error === sentinel);
  await closing;
  assert.deepEqual(calls.map(call => call.operation), ['open', 'close_fd']);
});

test('public helper mutation cannot redirect handle I/O', async () => {
  const { facade, context, file } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const fail = () => { throw new Error('guest helper invoked'); };
  facade.openSync = fail;
  facade.writeSync = fail;
  facade.closeSync = fail;
  context.Promise = fail;
  context.Reflect.apply = fail;
  context.Buffer = { alloc: fail, from: fail, isBuffer: fail };
  assert.equal((await handle.write('native')).bytesWritten, 6);
  assert.equal((await handle.read({ position: 0 })).bytesRead, 6);
  await handle.close();
  assert.equal(fs.readFileSync(file, 'utf8'), 'native');
});

test('provider errors propagate; close failures are not retried on a recycled fd', async () => {
  const failure = Object.assign(new Error('close failed'), { code: 'EIO' });
  let held;
  const { facade, calls, file } = fixture((authority, operation, args) => {
    if (operation === 'close_fd') { held = args[0]; throw failure; }
  });
  const handle = await facade.promises.open(file, 'w');
  await assert.rejects(handle.close(), error => error === failure);
  await assert.rejects(handle.close(), error => error === failure);
  assert.equal(handle.fd, -1);
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
  fs.closeSync(held); // Release the real fd retained by the fault-injection adapter.
});

test('open retains the existing FsWrite effect instead of bypassing the provider', async () => {
  const denied = Object.assign(new Error('write authority required'), { code: 'DENIED' });
  const { facade, file } = fixture(authority => {
    if (authority === 'fs_write') { throw denied; }
  });
  await assert.rejects(facade.promises.open(file, 'w'), error => error === denied);
  assert.equal(fs.existsSync(file), false);
});
