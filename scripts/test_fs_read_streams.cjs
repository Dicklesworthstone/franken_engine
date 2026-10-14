'use strict';
// Execute the complete shipped fs read/write stream facade through a real-file reference
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

// Writer coverage uses the same complete facade and the same real-file adapter.
const { finished, pipeline } = require('node:stream/promises');

test('write streams match Node bytes, encodings, event order and positioned writes', async () => {
  const { facade, file } = fixture();
  async function exercise(create, target, options) {
    fs.writeFileSync(target, 'abcdefghij');
    const stream = create(target, options);
    const events = [];
    for (const event of ['open', 'ready', 'finish', 'close']) stream.on(event, () => events.push(event));
    const completion = finished(stream);
    stream.write('A'); stream.write(Buffer.from([0, 255])); stream.end('é');
    await completion;
    return [fs.readFileSync(target).toString('hex'), stream.bytesWritten, stream.fd, events];
  }
  for (const options of [{}, { flags: 'r+', start: 2, highWaterMark: 2 }, { flags: 'a' }]) {
    assert.deepEqual(await exercise(facade.createWriteStream, file, options),
      await exercise(fs.createWriteStream, file + '-node', options));
  }
  const hex = facade.createWriteStream(file, { encoding: 'hex' });
  const done = finished(hex); hex.end('414243'); await done;
  assert.equal(fs.readFileSync(file, 'utf8'), 'ABC');
  assert.equal(hex.bytesWritten, 3);
  assert(hex instanceof facade.WriteStream);
  assert(hex instanceof require('node:stream').Writable);
});

test('file-to-file pipeline preserves all bytes and closes both private owners', async () => {
  const { facade, file, calls } = fixture();
  const data = Buffer.from('line é€😃\n'.repeat(10000));
  fs.writeFileSync(file, data);
  const input = facade.createReadStream(file, { highWaterMark: 16385 });
  const output = facade.createWriteStream(file + '-out', { highWaterMark: 4 });
  await pipeline(input, output);
  assert.deepEqual(fs.readFileSync(file + '-out'), data);
  assert.equal(input.bytesRead, data.length);
  assert.equal(output.bytesWritten, data.length);
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 2);
  for (const call of calls.filter(call => /^(read|write)_fd$/.test(call.operation))) {
    assert(call.args[3] <= 16384);
    assert.equal(call.authority, call.operation === 'read_fd' ? 'fs_read' : 'fs_write');
  }
});

test('corked tiny writes coalesce into bounded batches with every callback once', async () => {
  const allocations = [];
  const InstrumentedBuffer = new Proxy(Buffer, { get(target, key) {
    if (key === 'alloc') return size => { allocations.push(size); return Buffer.alloc(size); };
    return Reflect.get(target, key);
  } });
  const { facade, file, calls } = fixture(() => {}, { Buffer: InstrumentedBuffer });
  const stream = facade.createWriteStream(file);
  const done = finished(stream);
  let callbacks = 0;
  stream.cork();
  for (let index = 0; index < 20000; index++) {
    stream.write(Buffer.from([index % 251]), error => { assert.ifError(error); callbacks++; });
  }
  stream.end();
  await done;
  assert.equal(callbacks, 20000);
  assert.equal(stream.bytesWritten, 20000);
  assert.deepEqual(fs.readFileSync(file), Buffer.from(Array.from({ length: 20000 }, (_, i) => i % 251)));
  const writes = calls.filter(call => call.operation === 'write_fd');
  assert.equal(writes.length, 2);
  assert(writes.every(call => call.args[3] <= 16384));
  assert.deepEqual(allocations, [16384, 3616]);
  const node = fs.createWriteStream(file + '-node');
  const nodeDone = finished(node);
  node.cork();
  for (let index = 0; index < 20000; index++) node.write(Buffer.from([index % 251]));
  node.end(); await nodeDone;
  assert.deepEqual(fs.readFileSync(file), fs.readFileSync(file + '-node'));
});

test('large single writes borrow byte windows without a staging allocation', async () => {
  let allocations = 0;
  const InstrumentedBuffer = new Proxy(Buffer, { get(target, key) {
    if (key === 'alloc') return size => { allocations++; return Buffer.alloc(size); };
    return Reflect.get(target, key);
  } });
  const { facade, file, calls } = fixture(() => {}, { Buffer: InstrumentedBuffer });
  const data = Buffer.alloc(49157, 65);
  const stream = facade.createWriteStream(file);
  const done = finished(stream); stream.end(data); await done;
  assert.equal(allocations, 0);
  const writes = calls.filter(call => call.operation === 'write_fd');
  assert.equal(writes.length, 4);
  assert(writes.every(call => call.args[1] === data));
  assert.deepEqual(writes.map(call => call.args.slice(2, 4)), [[0,16384],[16384,16384],[32768,16384],[49152,5]]);
  assert.deepEqual(fs.readFileSync(file), data);
});

test('short writes advance the same batch without loss, duplication or stack recursion', async () => {
  const { facade, file, calls } = fixture((operation, args) => operation === 'write_fd'
    ? fs.writeSync(args[0], args[1], args[2], Math.min(args[3], 3), args[4]) : undefined);
  const stream = facade.createWriteStream(file);
  const done = finished(stream);
  stream.cork();
  const buffers = [Buffer.alloc(10000, 65), Buffer.alloc(0), Buffer.alloc(12000, 66), Buffer.alloc(8000, 67)];
  for (const buffer of buffers) stream.write(buffer);
  stream.end(); await done;
  assert.deepEqual(fs.readFileSync(file), Buffer.concat(buffers));
  assert.equal(stream.bytesWritten, 30000);
  const writes = calls.filter(call => call.operation === 'write_fd');
  assert(writes.length >= 10000);
  assert.equal(new Set(writes.map(call => call.args[1])).size, 2);
});

test('FileHandle write streams keep positioned I/O and borrowed-descriptor ownership', async () => {
  const { facade, file, calls } = fixture();
  async function exercise(open, target) {
    fs.writeFileSync(target, 'abcdefghij');
    const handle = await open(target, 'r+');
    const stream = handle.createWriteStream({ start: 1, autoClose: false });
    const done = finished(stream); stream.end('XY'); await done;
    const kept = handle.fd >= 0;
    await handle.write('!');
    // Node v22.16.0 WriteStream.close after an already emitted finish waits
    // forever with autoClose:false. Destroy releases its stream reference
    // before closing the handle; explicit close is tested before finish below.
    const destroyed = new Promise(resolve => stream.once('close', resolve));
    stream.destroy(); await destroyed;
    await handle.close();
    return [fs.readFileSync(target, 'utf8'), kept, handle.fd, stream.bytesWritten];
  }
  assert.deepEqual(await exercise(facade.promises.open, file), await exercise(fs.promises.open, file + '-node'));
  assert.equal(calls.filter(call => call.operation === 'open').length, 1);
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
});

test('writer close drains queued writes even with autoClose false', async () => {
  const { facade, file, calls } = fixture();
  const stream = facade.createWriteStream(file, { autoClose: false, highWaterMark: 2 });
  const events = [];
  stream.on('finish', () => events.push('finish'));
  stream.on('close', () => events.push('close'));
  assert.equal(stream.write(Buffer.alloc(20000, 65)), false);
  stream.write('tail');
  await close(stream);
  assert.deepEqual(events, ['finish', 'close']);
  assert.equal(fs.readFileSync(file).length, 20004);
  assert.equal(stream.bytesWritten, 20004);
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
  const node = fs.createWriteStream(file + '-node', { autoClose: false, highWaterMark: 2 });
  node.write(Buffer.alloc(20000, 65)); node.write('tail');
  await close(node);
  assert.deepEqual(fs.readFileSync(file), fs.readFileSync(file + '-node'));
});

test('flush happens once before close, including repeated explicit close', async () => {
  const { facade, file, calls } = fixture();
  const stream = facade.createWriteStream(file, { flush: true });
  const done = finished(stream); stream.end('durable'); await done;
  await close(stream); await close(stream);
  assert.deepEqual(calls.map(call => call.operation), ['open', 'write_fd', 'fsync', 'close_fd']);
  assert.equal(fs.readFileSync(file, 'utf8'), 'durable');
});

test('flush failure still closes; flush plus close errors both survive', async () => {
  const syncError = new Error('flush failed'), closeError = new Error('close failed');
  for (const failClose of [false, true]) {
    const { facade, file, calls } = fixture(operation => {
      if (operation === 'fsync') throw syncError;
      if (operation === 'close_fd' && failClose) throw closeError;
    });
    const stream = facade.createWriteStream(file, { flush: true });
    const done = finished(stream); stream.end('written');
    await assert.rejects(done, error => failClose
      ? error.name === 'AggregateError' && error.errors[0] === syncError && error.errors[1] === closeError
      : error === syncError);
    assert.equal(fs.readFileSync(file, 'utf8'), 'written');
    assert.equal(calls.filter(call => call.operation === 'fsync').length, 1);
    assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
  }
});

test('zero and invalid write counts reject rather than completing or looping', async () => {
  for (const value of [0, -1, 5, NaN, 0.5, '1']) {
    const { facade, file, calls } = fixture(operation => operation === 'write_fd' ? value : undefined);
    const stream = facade.createWriteStream(file);
    const done = finished(stream); stream.end('data');
    await assert.rejects(done, { code: 'EIO' });
    assert.equal(calls.filter(call => call.operation === 'write_fd').length, 1);
    assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
    assert.equal(fs.statSync(file).size, 0);
  }
});

test('destroy during a partial write stops subsequent effects and drains once', async () => {
  const failure = new Error('cancel write');
  let stream;
  const { facade, file, calls } = fixture((operation, args) => {
    if (operation === 'write_fd') {
      const count = fs.writeSync(args[0], args[1], args[2], 1, args[4]);
      stream.destroy(failure);
      return count;
    }
  });
  stream = facade.createWriteStream(file);
  let callbacks = 0;
  const done = finished(stream);
  stream.write(Buffer.alloc(40000, 65), error => { assert.equal(error, failure); callbacks++; });
  stream.end();
  await assert.rejects(done, error => error === failure);
  assert.equal(callbacks, 1);
  assert.equal(stream.bytesWritten, 1);
  assert.deepEqual(calls.map(call => call.operation), ['open', 'write_fd', 'close_fd']);
  assert.equal(fs.readFileSync(file, 'utf8'), 'A');
});

test('writer rejects invalid configuration before opening or truncating a file', () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'keep');
  for (const options of [{ start: -1 }, { flush: 1 }, { encoding: 'not-an-encoding' },
    { highWaterMark: -1 }, { fd: {} }, { fs: {} }]) {
    assert.throws(() => facade.createWriteStream(file, options));
  }
  assert.deepEqual(calls, []);
  assert.equal(fs.readFileSync(file, 'utf8'), 'keep');
});

test('falsy provider rejections stay failures, not success-shaped callbacks', async () => {
  for (const operation of ['open', 'read_fd', 'write_fd', 'fsync', 'close_fd']) {
    const { facade, file } = fixture(actual => { if (actual === operation) throw null; });
    fs.writeFileSync(file, 'data');
    const stream = operation === 'read_fd' ? facade.createReadStream(file)
      : facade.createWriteStream(file, { flush: true });
    const done = operation === 'read_fd' ? collect(stream) : finished(stream);
    if (operation !== 'read_fd') stream.end('data');
    await assert.rejects(done, error => error.code === 'EIO' && error.cause === null);
  }
});

test('pre-aborted streams cannot open or truncate a path', async () => {
  for (const write of [false, true]) {
    const { facade, file, calls } = fixture();
    fs.writeFileSync(file, 'keep');
    const signal = AbortSignal.abort(0);
    const stream = write ? facade.createWriteStream(file, { signal })
      : facade.createReadStream(file, { signal });
    const done = write ? finished(stream) : collect(stream);
    if (write) stream.end('forbidden');
    await assert.rejects(done, error => error.code === 'ABORT_ERR' && error.cause === 0);
    await tick();
    assert.deepEqual(calls, []);
    assert.equal(fs.readFileSync(file, 'utf8'), 'keep');
  }
});

test('abort listener belongs to the adapter and is removed without a close event', async () => {
  const controller = new AbortController();
  const reason = new Error('stop after first fragment');
  let adds = 0, removes = 0;
  const signal = {
    get aborted() { return controller.signal.aborted; },
    get reason() { return controller.signal.reason; },
    addEventListener(...args) { adds++; controller.signal.addEventListener(...args); },
    removeEventListener(...args) { removes++; controller.signal.removeEventListener(...args); }
  };
  const { facade, file, calls } = fixture((operation, args) => {
    if (operation === 'write_fd') {
      const count = fs.writeSync(args[0], args[1], args[2], 1, args[4]);
      controller.abort(reason);
      return count;
    }
  });
  const stream = facade.createWriteStream(file, { signal, emitClose: false });
  const done = finished(stream); stream.end(Buffer.alloc(40000, 65));
  await assert.rejects(done, error => error.code === 'ABORT_ERR' && error.cause === reason);
  await tick();
  assert.equal(adds, 1); assert.equal(removes, 1);
  assert.equal(stream.bytesWritten, 1);
  assert.deepEqual(calls.map(call => call.operation), ['open', 'write_fd', 'close_fd']);
  assert.equal(fs.readFileSync(file, 'utf8'), 'A');
});

test('signal-registration failure and invalid signals leave the path untouched', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'keep');
  for (const signal of [null, {}, 1, { aborted: false }]) {
    assert.throws(() => facade.createWriteStream(file, { signal }));
    assert.throws(() => facade.createReadStream(file, { signal }));
  }
  const sentinel = new Error('cannot register');
  let removed = 0;
  const signal = { aborted: false, addEventListener() { throw sentinel; },
    removeEventListener() { removed++; } };
  const stream = facade.createWriteStream(file, { signal });
  const done = finished(stream); stream.end('not written');
  await assert.rejects(done, error => error === sentinel);
  assert.equal(removed, 1);
  assert.deepEqual(calls, []);
  assert.equal(fs.readFileSync(file, 'utf8'), 'keep');
});

test('private write/sync/close operations ignore replaced handle methods and public fd', async () => {
  const { facade, file } = fixture();
  const handle = await facade.promises.open(file, 'w');
  const stream = handle.createWriteStream({ flush: true });
  const fail = () => { throw new Error('public helper used'); };
  handle.write = fail; handle.sync = fail; handle.close = fail;
  facade.promises.open = fail; facade.writeSync = fail; facade.fsyncSync = fail;
  Object.defineProperty(stream, 'fd', { value: 123456 });
  const done = finished(stream); stream.end('private'); await done;
  assert.equal(fs.readFileSync(file, 'utf8'), 'private');
  assert.equal(handle.fd, -1);
});

test('raw descriptor writes preserve the cursor without reopening an unrelated path', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'abcdefghij');
  const fd = fs.openSync(file, 'r+'); descriptors.add(fd);
  fs.writeSync(fd, Buffer.from('AB'), 0, 2, null);
  const stream = facade.createWriteStream('not-a-path', { fd, autoClose: false });
  stream.write('CD');
  await close(stream);
  assert.equal(fs.readFileSync(file, 'utf8'), 'ABCDefghij');
  assert.deepEqual(calls.map(call => call.operation), ['write_fd', 'close_fd']);
});

test('corked staging allocation failure closes its owner without any write', async () => {
  const InstrumentedBuffer = new Proxy(Buffer, { get(target, key) {
    if (key === 'alloc') return () => { throw null; };
    return Reflect.get(target, key);
  } });
  const { facade, file, calls } = fixture(() => {}, { Buffer: InstrumentedBuffer });
  const stream = facade.createWriteStream(file);
  const done = finished(stream);
  stream.cork(); stream.write('a'); stream.write('b'); stream.end();
  await assert.rejects(done, error => error.code === 'EIO' && error.cause === null);
  assert.deepEqual(calls.map(call => call.operation), ['open', 'close_fd']);
  assert.equal(fs.statSync(file).size, 0);
});

test('explicit close after finish releases a non-autoclosing writer exactly once', async () => {
  // Node v22.16.0 hangs for this late close; keep the useful adapter behavior
  // explicit rather than claiming this is a matching reference observation.
  const { facade, file, calls } = fixture();
  const stream = facade.createWriteStream(file, { autoClose: false, flush: true });
  const done = finished(stream); stream.end('saved'); await done;
  assert(stream.fd >= 0);
  await close(stream); await close(stream);
  assert.equal(stream.fd, null);
  assert.deepEqual(calls.map(call => call.operation), ['open', 'write_fd', 'fsync', 'close_fd']);
});
