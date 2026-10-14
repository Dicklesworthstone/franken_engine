'use strict';
// Execute the complete shipped fs facade through a real-file reference
// adapter. Node supplies stream/Promise primitives; this is NOT native Rust
// execution or proof of the engine's capability/IFC gates.
// node --test scripts/test_fs_read_streams.cjs
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { test, after } = require('node:test');
const source = fs.readFileSync(process.env.FRANKEN_FS_FACADE_SOURCE || path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/fs_module.js'), 'utf8');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-fs-read-streams-'));
const descriptors = new Set();
let sequence = 0;
after(() => {
  for (const fd of descriptors) fs.closeSync(fd);
});
function fixture(hook = () => {}, globals = {}) {
  const calls = [];
  const file = path.join(root, `input-${sequence++}`);
  const dispatch = (authority, tag, ...args) => {
    const operation = tag.slice('\0fsop:'.length);
    calls.push({ authority, operation, args });
    const override = hook(operation, args);
    if (override !== undefined) return override;
    switch (operation) {
      case 'open': {
        const fd = fs.openSync(...args); descriptors.add(fd); return fd;
      }
      case 'close_fd': fs.closeSync(...args); descriptors.delete(args[0]); return;
      case 'read_fd': return fs.readSync(...args);
      case 'write_fd': return fs.writeSync(...args);
      case 'fsync': return fs.fsyncSync(...args);
      case 'read': return fs.readFile(...args);
      default: throw new Error(`unexpected operation ${operation}`);
    }
  };
  const context = { Buffer, Promise, Reflect: { apply: Reflect.apply }, Error, TypeError, RangeError,
    require(name) { assert.equal(name, 'stream'); return require('node:stream'); },
    __franken_fs_read: (...args) => dispatch('fs_read', ...args),
    __franken_fs_write: (...args) => dispatch('fs_write', ...args) };
  Object.assign(context, globals);
  return { facade: vm.runInNewContext(source, context), context, file, calls };
}
async function collect(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  return Buffer.concat(chunks);
}
const tick = () => new Promise(resolve => setImmediate(resolve));
const close = stream => new Promise((resolve, reject) => {
  stream.once('error', reject);
  stream.close(resolve);
});

test('module/class acquisition does no filesystem I/O and class identity is stable', () => {
  const { facade, calls } = fixture();
  assert.equal(typeof facade.createReadStream, 'function');
  assert.equal(facade.ReadStream, facade.ReadStream);
  assert.deepEqual(calls, []);
});

test('path reads, inclusive ranges, Unicode decoding and events match live Node', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'Aé€😃Z');
  async function exercise(create, options) {
    const stream = create(file, options);
    const events = [];
    for (const event of ['open', 'ready', 'end', 'close']) stream.on(event, () => events.push(event));
    const data = await collect(stream);
    await tick();
    return [data.toString('hex'), stream.bytesRead, stream.fd, stream.pending, events];
  }
  for (const options of [{}, { start: 1, end: 5, highWaterMark: 2 },
    { encoding: 'utf8', highWaterMark: 1 }, { start: 50 }, { start: 0, end: 0 }]) {
    assert.deepEqual(await exercise(facade.createReadStream, options),
      await exercise(fs.createReadStream, options));
  }
  for (const call of calls) {
    assert.equal(call.authority, call.operation === 'read_fd' ? 'fs_read' : 'fs_write');
    if (call.operation === 'read_fd') assert(call.args[3] <= 16384);
  }
});

test('Readable subclasses, piping and public constructor work with real data', async () => {
  const { facade, file } = fixture();
  fs.writeFileSync(file, 'stream data');
  class Reader extends facade.ReadStream {}
  const input = new Reader(file, { highWaterMark: 3 });
  assert(input instanceof facade.ReadStream);
  assert(input instanceof require('node:stream').Readable);
  const output = new require('node:stream').PassThrough();
  input.pipe(output);
  assert.equal((await collect(output)).toString(), 'stream data');
});

test('a paused consumer bounds read-ahead; destroying closes exactly once', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, Buffer.alloc(100000, 65));
  const stream = facade.createReadStream(file, { highWaterMark: 16 });
  await new Promise(resolve => stream.once('readable', resolve));
  const reads = calls.filter(call => call.operation === 'read_fd').length;
  assert.equal(stream.readableLength, 16);
  await tick(); await tick();
  assert.equal(calls.filter(call => call.operation === 'read_fd').length, reads);
  const closed = new Promise(resolve => stream.once('close', resolve));
  stream.destroy(); stream.destroy();
  await closed;
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
});

test('short native reads are not EOF and retain every exact byte', async () => {
  const { facade, file, calls } = fixture((operation, args) => operation === 'read_fd'
    ? fs.readSync(args[0], args[1], args[2], Math.min(args[3], 3), args[4]) : undefined);
  const data = Buffer.from('Aé€😃Z'.repeat(300));
  fs.writeFileSync(file, data);
  const stream = facade.createReadStream(file);
  assert.deepEqual(await collect(stream), data);
  assert.equal(stream.bytesRead, data.length);
  assert(calls.filter(call => call.operation === 'read_fd').length > 100);
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
});

test('FileHandle ranges retain cursor and ownership with autoClose false', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'abcdefghij');
  async function exercise(open) {
    const handle = await open(file, 'r');
    const stream = handle.createReadStream({ start: 2, end: 5, autoClose: false, highWaterMark: 2 });
    const data = await collect(stream);
    const next = await handle.read(Buffer.alloc(2));
    const openAfterEnd = handle.fd >= 0;
    await close(stream);
    return [data.toString(), next.buffer.toString(), openAfterEnd, handle.fd];
  }
  assert.deepEqual(await exercise(facade.promises.open), await exercise(fs.promises.open));
  assert.equal(calls.filter(call => call.operation === 'open').length, 1);
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
});

test('raw descriptor reads use its current offset and never reopen the pathname', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'abcdef');
  const fd = fs.openSync(file, 'r'); descriptors.add(fd);
  fs.readSync(fd, Buffer.alloc(2), 0, 2, null);
  const stream = facade.createReadStream('not-a-real-path', { fd, autoClose: false });
  assert.equal((await collect(stream)).toString(), 'cdef');
  assert.equal(stream.fd, fd);
  assert.equal(calls.filter(call => call.operation === 'open').length, 0);
  await close(stream);
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
});

test('early async-iterator return and destroy before open release owned descriptors', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, Buffer.alloc(1000, 65));
  const stream = facade.createReadStream(file, { highWaterMark: 2 });
  const closed = new Promise(resolve => stream.once('close', resolve));
  for await (const chunk of stream) { assert(chunk.length > 0); break; }
  await closed;
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
  const immediate = facade.createReadStream(file);
  const done = new Promise(resolve => immediate.once('close', resolve));
  immediate.destroy();
  await done;
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 2);
});

test('abort during reading closes and emits the original abort reason', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, Buffer.alloc(1000, 65));
  const controller = new AbortController();
  const reason = new Error('stop');
  const stream = facade.createReadStream(file, { highWaterMark: 2, signal: controller.signal });
  stream.once('data', () => controller.abort(reason));
  await assert.rejects(collect(stream), error => error.code === 'ABORT_ERR' && error.cause === reason);
  await tick();
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
});

test('provider failures and invalid read counts error, never fabricate EOF', async () => {
  for (const value of [-1, 16385, NaN, 0.5, '1']) {
    const { facade, file, calls } = fixture(operation => operation === 'read_fd' ? value : undefined);
    fs.writeFileSync(file, 'data');
    await assert.rejects(collect(facade.createReadStream(file)), { code: 'EIO' });
    await tick();
    assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
  }
  const denied = Object.assign(new Error('denied'), { code: 'DENIED' });
  const { facade, file } = fixture(operation => { if (operation === 'open') throw denied; });
  await assert.rejects(collect(facade.createReadStream(file)), error => error === denied);
});

test('invalid ranges, descriptors and provider overrides fail before host effects', () => {
  const { facade, file, calls } = fixture();
  for (const options of [{ start: -1 }, { start: 1.5 }, { end: NaN }, { start: 4, end: 2 },
    { fd: {} }, { fd: -1 }, { fs: {} }, { highWaterMark: -1 }]) {
    assert.throws(() => facade.createReadStream(file, options));
  }
  assert.deepEqual(calls, []);
});

test('public fd, handle methods and fs exports cannot redirect private stream I/O', async () => {
  const { facade, file } = fixture();
  fs.writeFileSync(file, 'private');
  const handle = await facade.promises.open(file, 'r');
  const stream = handle.createReadStream({ highWaterMark: 2 });
  const fail = () => { throw new Error('public method used'); };
  handle.read = fail; handle.close = fail;
  facade.promises.open = fail; facade.readSync = fail; facade.closeSync = fail;
  Object.defineProperty(stream, 'fd', { value: 123456 });
  stream.path = 'wrong';
  assert.equal((await collect(stream)).toString(), 'private');
  assert.equal(handle.fd, -1);
});

test('short-result allocation failure destroys the stream and releases its owner', async () => {
  const failure = new Error('allocation refused');
  const InstrumentedBuffer = new Proxy(Buffer, {
    get(target, key) {
      if (key === 'from') return () => { throw failure; };
      return Reflect.get(target, key);
    }
  });
  const { facade, file, calls } = fixture(() => {}, { Buffer: InstrumentedBuffer });
  fs.writeFileSync(file, 'short');
  await assert.rejects(collect(facade.createReadStream(file)), error => error === failure);
  await tick();
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
});

test('read and close failures are both preserved, with no descriptor-close retry', async () => {
  const readError = Object.assign(new Error('read failed'), { code: 'EIO' });
  const closeError = Object.assign(new Error('close failed'), { code: 'EIO' });
  const { facade, file, calls } = fixture(operation => {
    if (operation === 'read_fd') throw readError;
    if (operation === 'close_fd') throw closeError;
  });
  fs.writeFileSync(file, 'data');
  const stream = facade.createReadStream(file);
  await assert.rejects(collect(stream), error =>
    error.name === 'AggregateError' && error.errors[0] === readError && error.errors[1] === closeError);
  await tick();
  stream.destroy();
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
});
