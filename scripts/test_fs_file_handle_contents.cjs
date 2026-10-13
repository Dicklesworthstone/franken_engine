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
function fixture(hook = () => {}, globals = {}) {
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
      case 'read': return fs.readFile(...args);
      case 'write': return fs.writeFile(...args);
      case 'append': return fs.appendFile(...args);
      default: throw new Error(`unexpected host operation: ${operation}`);
    }
  };
  const context = { Buffer, Promise, Reflect: { apply: Reflect.apply }, Error, TypeError, RangeError,
    __franken_fs_read: (...args) => dispatch('fs_read', ...args),
    __franken_fs_write: (...args) => dispatch('fs_write', ...args) };
  Object.assign(context, globals);
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

test('vector reads and writes match Node contents, identities and descriptor cursors', async () => {
  async function exercise(open, file) {
    fs.writeFileSync(file, 'abcdefghij');
    const handle = await open(file, 'r+');
    try {
      const input = [Buffer.from('XY'), Buffer.alloc(0), Buffer.from('Z')];
      const written = await handle.writev(input, 2);
      const output = [Buffer.alloc(2, 45), Buffer.alloc(0), Buffer.alloc(5, 45)];
      const read = await handle.readv(output, 6);
      const cursor = await handle.read(Buffer.alloc(2));
      return [written.bytesWritten, written.buffers === input, read.bytesRead,
        read.buffers === output, output.map(b => b.toString()), cursor.buffer.toString(),
        fs.readFileSync(file, 'utf8')];
    } finally { await handle.close(); }
  }
  const { facade, file, calls } = fixture();
  assert.deepEqual(await exercise(facade.promises.open, file),
    await exercise(fs.promises.open, file + '-node'));
  assert.equal(calls.filter(call => call.operation === 'write_fd').length, 1);
  assert.equal(calls.filter(call => call.operation === 'read_fd').length, 2);
});

test('vector writes report partial and zero writes without retrying', async () => {
  for (const limit of [0, 3, 6]) {
    const { facade, file, calls } = fixture((authority, operation, args) => {
      if (operation === 'write_fd') {
        return fs.writeSync(args[0], args[1], args[2], Math.min(args[3], limit), args[4]);
      }
    });
    const handle = await facade.promises.open(file, 'w');
    const input = [Buffer.from('ab'), Buffer.from('cdef')];
    const result = await handle.writev(input);
    assert.equal(result.bytesWritten, limit);
    assert.equal(result.buffers, input);
    assert.equal(fs.readFileSync(file, 'utf8'), 'abcdef'.slice(0, limit));
    assert.equal(calls.filter(call => call.operation === 'write_fd').length, 1);
    await handle.close();
  }
});

test('a short vector read fills only the returned prefix', async () => {
  const { facade, file, calls } = fixture((authority, operation, args) => {
    if (operation === 'read_fd') { return fs.readSync(args[0], args[1], args[2], 3, args[4]); }
  });
  fs.writeFileSync(file, 'abcdef');
  const handle = await facade.promises.open(file);
  const buffers = [Buffer.alloc(2, 45), Buffer.alloc(3, 45), Buffer.alloc(1, 45)];
  assert.equal((await handle.readv(buffers)).bytesRead, 3);
  assert.deepEqual(buffers.map(buffer => buffer.toString()), ['ab', 'c--', '-']);
  assert.equal(calls.filter(call => call.operation === 'read_fd').length, 1);
  await handle.close();
});

test('overlapping vector destinations have Node scatter order', async () => {
  async function exercise(open, file) {
    fs.writeFileSync(file, 'abcdef');
    const h = await open(file);
    const backing = Buffer.alloc(5, 45);
    try {
      const result = await h.readv([backing.subarray(0, 3), backing.subarray(2, 5)]);
      return [result.bytesRead, backing.toString()];
    } finally { await h.close(); }
  }
  const { facade, file } = fixture();
  assert.deepEqual(await exercise(facade.promises.open, file),
    await exercise(fs.promises.open, file + '-node'));
});

test('invalid vector entries are rejected before any partial read or write', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  for (const buffers of [null, {}, 'bad', [Buffer.from('valid'), 'invalid'], [Buffer.alloc(1), ,]]) {
    await assert.rejects(handle.writev(buffers), { code: 'ERR_INVALID_ARG_TYPE' });
    await assert.rejects(handle.readv(buffers), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  assert.equal(calls.filter(call => /^(read|write)_fd$/.test(call.operation)).length, 0);
  await handle.close();
});

test('empty vector results keep identity and require an open FileHandle', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const buffers = [Buffer.alloc(0), Buffer.alloc(0)];
  const read = await handle.readv(buffers);
  const write = await handle.writev(buffers);
  assert.equal(read.bytesRead, 0);
  assert.equal(read.buffers, buffers);
  assert.equal(write.bytesWritten, 0);
  assert.equal(write.buffers, buffers);
  assert.equal((await handle.readv([])).bytesRead, 0);
  assert.equal((await handle.writev([])).bytesWritten, 0);
  assert.equal(calls.filter(call => /^(read|write)_fd$/.test(call.operation)).length, 0);
  await handle.close();
  await assert.rejects(handle.readv(buffers), { code: 'EBADF' });
  await assert.rejects(handle.writev(buffers), { code: 'EBADF' });
});

test('vector getter reentrancy cannot close a descriptor before its admitted I/O', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  let closing;
  const buffers = [Buffer.from('first'), Buffer.from('second')];
  Object.defineProperty(buffers, 1, { get() {
    closing = handle.close();
    return Buffer.from('second');
  } });
  const result = await handle.writev(buffers);
  await closing;
  assert.equal(result.bytesWritten, 11);
  assert.equal(fs.readFileSync(file, 'utf8'), 'firstsecond');
  assert.deepEqual(calls.map(call => call.operation), ['open', 'write_fd', 'close_fd']);
});

test('a throwing vector getter releases a reentrantly closing handle without I/O', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const failure = new Error('vector getter failed');
  let closing;
  const buffers = [Buffer.alloc(2)];
  Object.defineProperty(buffers, 1, { get() { closing = handle.close(); throw failure; } });
  await assert.rejects(handle.readv(buffers), error => error === failure);
  await closing;
  assert.deepEqual(calls.map(call => call.operation), ['open', 'close_fd']);
});

test('vector I/O preserves provider denials and rejects invalid byte counts', async () => {
  for (const method of ['readv', 'writev']) {
    for (const value of [-1, 100, NaN, 0.5, '1']) {
      const { facade, file } = fixture((authority, operation) =>
        /^(read|write)_fd$/.test(operation) ? value : undefined);
      const handle = await facade.promises.open(file, 'w+');
      await assert.rejects(handle[method]([Buffer.alloc(2)]), { code: 'EIO' });
      await handle.close();
    }
    const denied = new Error('provider denied');
    const { facade, file } = fixture((authority, operation) => {
      if (/^(read|write)_fd$/.test(operation)) { throw denied; }
    });
    const handle = await facade.promises.open(file, 'w+');
    await assert.rejects(handle[method]([Buffer.alloc(2)]), error => error === denied);
    await handle.close();
  }
});

test('vector append mode uses one descriptor write even with an explicit position', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'prefix');
  const handle = await facade.promises.open(file, 'a');
  assert.equal((await handle.writev([Buffer.from('A'), Buffer.from('B')], 0)).bytesWritten, 2);
  await handle.close();
  assert.equal(fs.readFileSync(file, 'utf8'), 'prefixAB');
  assert.equal(calls.filter(call => call.operation === 'write_fd').length, 1);
});

test('vector position defaults match Node without coercing nonnumeric inputs', async () => {
  async function exercise(open, file, position) {
    fs.writeFileSync(file, 'abcdef');
    const handle = await open(file, 'r+');
    try {
      await handle.read(Buffer.alloc(1));
      await handle.writev([Buffer.from('XY')], position);
      return [await handle.readFile('utf8'), fs.readFileSync(file, 'utf8')];
    } finally { await handle.close(); }
  }
  const { facade, file } = fixture();
  for (const position of [undefined, null, '2', -1, -2, 0.5, NaN, Infinity, 2 ** 53, 0, 3]) {
    assert.deepEqual(await exercise(facade.promises.open, file, position),
      await exercise(fs.promises.open, file + '-node', position), String(position));
  }
});

test('vector methods do not dispatch through guest-replaced public helpers', async () => {
  const { facade, context, file } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const fail = () => { throw new Error('replaced helper'); };
  context.Array = { isArray: fail };
  context.Buffer = { alloc: fail, concat: fail };
  facade.readSync = fail;
  facade.writeSync = fail;
  facade.readvSync = fail;
  facade.writevSync = fail;
  await handle.writev([Buffer.from('safe')]);
  const buffers = [Buffer.alloc(2), Buffer.alloc(2)];
  assert.equal((await handle.readv(buffers, 0)).bytesRead, 4);
  assert.equal(Buffer.concat(buffers).toString(), 'safe');
  await handle.close();
});

test('fs.promises handle overloads agree with Node and never auto-close caller handles', async () => {
  async function exercise(promises, file) {
    fs.writeFileSync(file, 'abcdefghij');
    const handle = await promises.open(file, 'r+');
    try {
      await handle.read(Buffer.alloc(2));
      const written = await promises.writeFile(handle, 'XY');
      const appended = await promises.appendFile(handle, Buffer.from('Z'));
      const text = await promises.readFile(handle, 'utf8');
      const empty = await promises.readFile(handle);
      return [written, appended, text, Buffer.isBuffer(empty), empty.length,
        handle.fd >= 0, fs.readFileSync(file, 'utf8')];
    } finally { await handle.close(); }
  }
  const { facade, file, calls } = fixture();
  assert.deepEqual(await exercise(facade.promises, file),
    await exercise(fs.promises, file + '-node'));
  assert.equal(calls.filter(call => call.operation === 'open').length, 1);
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
  assert.equal(calls.filter(call => /^(read|write|append)$/.test(call.operation)).length, 0);
});

test('pathname promises keep their native callback path before and after handle registration', async () => {
  const { facade, file, calls } = fixture();
  await facade.promises.writeFile(file, 'ab');
  await facade.promises.appendFile(file, 'cd');
  assert.equal(await facade.promises.readFile(file, 'utf8'), 'abcd');
  const handle = await facade.promises.open(file);
  assert.equal(await facade.promises.readFile(Buffer.from(file), 'utf8'), 'abcd');
  assert.equal(await facade.promises.readFile(handle, 'utf8'), 'abcd');
  await handle.close();
  assert.deepEqual(calls.filter(call => /^(read|write|append)$/.test(call.operation))
    .map(call => call.operation), ['write', 'append', 'read', 'read']);
});

test('handle overloads ignore forged public fd values and overwritten public methods', async () => {
  const { facade, file } = fixture();
  fs.writeFileSync(file, 'original');
  fs.writeFileSync(file + '-other', 'other');
  const handle = await facade.promises.open(file, 'r+');
  const other = await facade.promises.open(file + '-other', 'r+');
  Object.defineProperty(handle, 'fd', { value: other.fd });
  const fail = () => { throw new Error('public method hijacked'); };
  handle.readFile = fail;
  handle.writeFile = fail;
  handle.appendFile = fail;
  assert.equal(await facade.promises.readFile(handle, 'utf8'), 'original');
  await facade.promises.writeFile(handle, 'AB', { flag: 'w' });
  await facade.promises.appendFile(handle, 'CD');
  await handle.close();
  await assert.rejects(facade.promises.readFile(handle), { code: 'EBADF' });
  assert.equal(await facade.promises.readFile(other, 'utf8'), 'other');
  await other.close();
  assert.equal(fs.readFileSync(file, 'utf8'), 'originalABCD');
  assert.equal(fs.readFileSync(file + '-other', 'utf8'), 'other');
});

test('closed-handle overloads reject asynchronously without any descriptor I/O', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  await handle.close();
  const count = calls.length;
  let inline = true;
  const pending = facade.promises.readFile(handle).catch(error => {
    assert.equal(inline, false);
    assert.equal(error.code, 'EBADF');
  });
  inline = false;
  await pending;
  await assert.rejects(facade.promises.writeFile(handle, 'late'), { code: 'EBADF' });
  await assert.rejects(facade.promises.appendFile(handle, 'late'), { code: 'EBADF' });
  assert.equal(calls.length, count);
});

test('duck-typed, cloned and proxied handles cannot impersonate a registered handle', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'untouched');
  const handle = await facade.promises.open(file, 'r+');
  let reads = 0;
  let invoked = 0;
  const fake = { get fd() { reads += 1; return handle.fd; },
    readFile() { invoked += 1; }, writeFile() { invoked += 1; }, appendFile() { invoked += 1; } };
  const clone = { fd: handle.fd, readFile: handle.readFile,
    writeFile: handle.writeFile, appendFile: handle.appendFile };
  for (const value of [fake, clone, new Proxy(handle, {})]) {
    await assert.rejects(facade.promises.readFile(value), { code: 'ERR_INVALID_ARG_TYPE' });
    await assert.rejects(facade.promises.writeFile(value, 'no'), { code: 'ERR_INVALID_ARG_TYPE' });
    await assert.rejects(facade.promises.appendFile(value, 'no'), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  assert.equal(reads, 0);
  assert.equal(invoked, 0);
  assert.equal(calls.filter(call => /^(read|write)_fd$/.test(call.operation)).length, 0);
  await handle.close();
  assert.equal(fs.readFileSync(file, 'utf8'), 'untouched');
});

test('namespace readFile uses the opened descriptor after pathname replacement', async () => {
  const { facade, file, calls } = fixture();
  fs.writeFileSync(file, 'held');
  const handle = await facade.promises.open(file);
  fs.renameSync(file, file + '-held');
  fs.writeFileSync(file, 'replacement');
  assert.equal(await facade.promises.readFile(handle, 'utf8'), 'held');
  assert.equal(await facade.promises.readFile(file, 'utf8'), 'replacement');
  assert(handle.fd >= 0);
  await handle.close();
  assert.equal(calls.filter(call => call.operation === 'open').length, 1);
});

test('namespace writeFile pins ownership across a reentrant close in options', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  let closing;
  await facade.promises.writeFile(handle, 'x'.repeat(40000), {
    get encoding() { closing = handle.close(); return 'utf8'; }
  });
  await closing;
  assert.equal(fs.statSync(file).size, 40000);
  assert.equal(calls.at(-1).operation, 'close_fd');
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
});

test('namespace handle overloads preserve abort failures without I/O', async () => {
  const { facade, file, calls } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const signal = AbortSignal.abort('cancelled');
  await assert.rejects(facade.promises.readFile(handle, { signal }),
    { name: 'AbortError', code: 'ABORT_ERR', cause: 'cancelled' });
  await assert.rejects(facade.promises.writeFile(handle, 'no', { signal }), { code: 'ABORT_ERR' });
  await assert.rejects(facade.promises.appendFile(handle, 'no', { signal }), { code: 'ABORT_ERR' });
  assert.equal(calls.filter(call => /^(read|write)_fd$/.test(call.operation)).length, 0);
  await handle.close();
});

test('the handle registry is lazy and initialization failure occurs before opening an fd', async () => {
  const failure = new Error('registry allocation failed');
  const FailingWeakMap = new Proxy(WeakMap, { construct() { throw failure; } });
  const { facade, file, calls } = fixture(undefined, { WeakMap: FailingWeakMap });
  assert.deepEqual(calls, []);
  await facade.promises.writeFile(file, 'path-only');
  await assert.rejects(facade.promises.open(file + '-handle', 'w'), error => error === failure);
  assert.equal(fs.existsSync(file + '-handle'), false);
  assert.equal(calls.filter(call => call.operation === 'open').length, 0);
});

test('the private handle registry uses captured constructor and get/set helpers', async () => {
  class LocalWeakMap extends WeakMap {}
  const { facade, context, file } = fixture(undefined, { WeakMap: LocalWeakMap });
  const fail = () => { throw new Error('replaced registry helper'); };
  context.WeakMap = fail;
  LocalWeakMap.prototype.get = fail;
  LocalWeakMap.prototype.set = fail;
  context.Reflect.apply = fail;
  const handle = await facade.promises.open(file, 'w+');
  await facade.promises.writeFile(handle, 'safe');
  await handle.close();
  const reader = await facade.promises.open(file);
  assert.equal(await facade.promises.readFile(reader, 'utf8'), 'safe');
  await reader.close();
});
