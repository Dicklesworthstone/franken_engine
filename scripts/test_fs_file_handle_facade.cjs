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
const source = fs.readFileSync(process.env.FRANKEN_FS_SOURCE || path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/fs_module.js'), 'utf8');
const callbacksSource = fs.readFileSync(path.join(__dirname,
  '../crates/franken-engine/src/lowering_pipeline/fs_callbacks.js'), 'utf8');
const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-fs-handles-'));
let nextFile = 0;
function fixture(hook = () => {}, globals = {}) {
  const calls = [];
  const dispatch = (authority, discriminator, ...args) => {
    const operation = discriminator.slice('\0fsop:'.length);
    calls.push({ authority, operation, args });
    hook(authority, operation, args);
    switch (operation) {
      case 'open': return fs.openSync(...args);
      case 'close_fd': return fs.closeSync(...args);
      case 'fsync': return fs.fsyncSync(...args);
      case 'fdatasync': return fs.fdatasyncSync(...args);
      case 'ftruncate': return fs.ftruncateSync(...args);
      case 'truncate': return fs.truncateSync(...args);
      case 'fchmod': return fs.fchmodSync(...args);
      case 'chmod': return fs.chmodSync(...args);
      // The intrinsic receives already-normalized seconds. Node's public API
      // would otherwise reinterpret a pre-epoch number as a request for now.
      case 'futimes': return fs.futimesSync(args[0], String(args[1]), String(args[2]));
      case 'utimes': return fs.utimesSync(args[0], String(args[1]), String(args[2]));
      case 'read_fd': return fs.readSync(...args);
      case 'write_fd': return fs.writeSync(...args);
      case 'stat': return fs.statSync(...args);
      case 'fstat': return fs.fstatSync(...args);
      case 'mkdir': return fs.mkdirSync(...args);
      default: throw new Error(`unexpected native operation: ${operation}`);
    }
  };
  const context = {
    Buffer, Promise, Reflect: { apply: Reflect.apply }, Error, TypeError, RangeError,
    __franken_fs_read: (...args) => dispatch('fs_read', ...args),
    __franken_fs_write: (...args) => dispatch('fs_write', ...args),
  };
  Object.assign(context, globals);
  return {
    facade: vm.runInNewContext(source, context), calls, context,
    file: path.join(root, `file-${nextFile++}`),
  };
}

function callbackFixture(hook = () => {}) {
  const result = fixture(hook, { queueMicrotask, URL });
  result.facade = vm.runInNewContext(callbacksSource, result.context)(result.facade);
  return result;
}

function invokeWrite(api, name, ...args) {
  return new Promise((resolve, reject) => {
    let returned = false;
    assert.equal(api[name](...args, function (error) {
      try {
        assert.equal(returned, true, 'whole-file callback must be deferred');
        if (error) reject(error); else resolve();
      } catch (failure) { reject(failure); }
    }), undefined);
    returned = true;
  });
}

test('constructing the module has no host effects', () => {
  const { facade, calls } = fixture();
  assert.equal(typeof facade.promises.open, 'function');
  assert.deepEqual(calls, []);
});

test('path metadata shares Node octal modes and signed timestamp seconds with descriptors', async () => {
  async function exercise(api, file) {
    fs.writeFileSync(file, 'metadata');
    const observations = [];
    for (const mode of ['0644', '600', 0o640]) {
      assert.equal(api.chmodSync(file, mode), undefined);
      observations.push(fs.statSync(file).mode & 0o777);
    }
    for (const [atime, mtime] of [[1.25, 2.5], [new Date(-2500), '-1.25'],
      ['0x10', '1e3'], [vm.runInNewContext('new Date(3250)'), ' ']]) {
      assert.equal(api.utimesSync(file, atime, mtime), undefined);
      const stats = fs.statSync(file);
      observations.push([stats.atimeMs, stats.mtimeMs]);
    }
    assert.equal(await api.promises.chmod(file, '640'), undefined);
    assert.equal(await api.promises.utimes(file, new Date(-1500), '2.75'), undefined);
    const final = fs.statSync(file);
    observations.push([final.mode & 0o777, final.atimeMs, final.mtimeMs]);
    return observations;
  }
  const { facade, calls, file } = fixture();
  assert.deepEqual(await exercise(facade, file), await exercise(fs, file + '-node'));
  assert(calls.every(call => call.authority === 'fs_write'));
  assert.deepEqual(calls.filter(call => call.operation === 'chmod').map(call => call.args[1]),
    [0o644, 0o600, 0o640, 0o640]);
  assert.deepEqual(calls.filter(call => call.operation === 'utimes').map(call => call.args.slice(1)),
    [['1.25', '2.5'], ['-2.5', '-1.25'], ['16', '1000'], ['3.25', '0'], ['-1.5', '2.75']]);
});

test('path metadata validates both operands before host entry and retains intrinsic Date identity', async () => {
  const { facade, calls, file, context } = fixture();
  fs.writeFileSync(file, 'untouched');
  for (const mode of ['', '8', '0o600', '600tail', ' 600 ']) {
    assert.throws(() => facade.chmodSync(file, mode), { code: 'ERR_INVALID_ARG_VALUE' });
  }
  for (const mode of [NaN, Infinity, -1, 1.5, 4294967296]) {
    assert.throws(() => facade.chmodSync(file, mode), { code: 'ERR_OUT_OF_RANGE' });
  }
  for (const mode of [undefined, null, true, {}, 1n]) {
    assert.throws(() => facade.chmodSync(file, mode), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  for (const time of [NaN, Infinity, -Infinity, null, undefined, true, {}, 1n, 'bad', new Date(NaN)]) {
    assert.throws(() => facade.utimesSync(file, time, 1), { code: 'ERR_INVALID_ARG_TYPE' });
    assert.throws(() => facade.utimesSync(file, 1, time), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  await assert.rejects(facade.promises.utimes(file, 1, NaN), { code: 'ERR_INVALID_ARG_TYPE' });
  assert.equal(calls.length, 0);
  const date = new Date(-2500);
  date.getTime = date.valueOf = () => { throw new Error('public Date hook'); };
  vm.runInNewContext('Date.prototype.getTime = function () { throw new Error("replaced"); }; Date.now = function () { throw new Error("replaced"); };', context);
  facade.utimesSync(file, date, '-1.25');
  const stats = fs.statSync(file);
  assert.equal(stats.atimeMs, -2500);
  assert.equal(stats.mtimeMs, -1250);
  assert.equal(fs.readFileSync(file, 'utf8'), 'untouched');
});

test('negative numeric times snapshot now while negative Date and string times remain before epoch', () => {
  class FixedDate extends Date { static now() { return 123456; } }
  const { facade, calls, file } = fixture(() => {}, { Date: FixedDate });
  fs.writeFileSync(file, 'time');
  facade.utimesSync(file, -1, -2);
  const fd = fs.openSync(file, 'r+');
  facade.futimesSync(fd, new Date(-1250), '-2.5');
  fs.closeSync(fd);
  assert.deepEqual(calls.map(call => call.args.slice(1)),
    [['123.456', '123.456'], ['-1.25', '-2.5']]);
  const stats = fs.statSync(file);
  assert.equal(stats.atimeMs, -1250);
  assert.equal(stats.mtimeMs, -2500);
});

test('negative zero is canonical before unsigned descriptor arguments cross the host boundary', async () => {
  const { facade, calls, file } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  await handle.write('abc');
  await handle.truncate(-0);
  await handle.chmod(-0);
  for (const call of calls.filter(call => ['ftruncate', 'fchmod'].includes(call.operation))) {
    assert.equal(Object.is(call.args[1], -0), false);
    assert.equal(call.args[1], 0);
  }
  await handle.chmod('600');
  assert.equal((await handle.stat()).size, 0);
  await handle.close();
});

test('path truncate sync and promises match Node for shrinking, extension and zero defaults', async () => {
  async function exercise(api, file) {
    fs.writeFileSync(file, 'abcdef');
    const states = [];
    for (const length of [4, 8, -1, undefined, -0, -9007199254740991]) {
      assert.equal(api.truncateSync(file, length), undefined);
      states.push(fs.readFileSync(file).toString('hex'));
    }
    fs.writeFileSync(file, 'promise');
    assert.equal(await api.promises.truncate(file, 3), undefined);
    states.push(fs.readFileSync(file, 'utf8'));
    assert.equal(await api.promises.truncate(file), undefined);
    states.push(fs.statSync(file).size);
    return states;
  }
  const { facade, file, calls } = fixture();
  assert.deepEqual(await exercise(facade, file), await exercise(fs, file + '-node'));
  assert.deepEqual(calls.map(call => call.args[1]), [4, 8, 0, 0, 0, 0, 3, 0]);
  assert(calls.every(call => call.operation === 'truncate' && call.authority === 'fs_write'));
});

test('invalid path truncate lengths reject before any host call or file mutation', async () => {
  const { facade, calls, file } = fixture();
  fs.writeFileSync(file, 'must remain intact');
  for (const [length, code] of [
    ...[null, '2', 'bad', true, {}, 2n].map(value => [value, 'ERR_INVALID_ARG_TYPE']),
    ...[NaN, Infinity, -Infinity, 1.5, -1.5, 9007199254740992, -9007199254740992]
      .map(value => [value, 'ERR_OUT_OF_RANGE']),
  ]) {
    assert.throws(() => fs.truncateSync(file, length), { code });
    assert.throws(() => facade.truncateSync(file, length), { code });
    await assert.rejects(facade.promises.truncate(file, length), { code });
    assert.equal(calls.length, 0);
    assert.equal(fs.readFileSync(file, 'utf8'), 'must remain intact');
  }
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

test('FileHandle mutations preserve the held inode, cursor and Node results', async () => {
  async function exercise(open, file) {
    fs.writeFileSync(file, 'abcdef');
    const handle = await open(file, 'r+');
    const prefix = Buffer.alloc(2);
    await handle.read(prefix);
    fs.renameSync(file, file + '-held');
    fs.writeFileSync(file, 'replacement');
    const results = [await handle.truncate(4), await handle.truncate(8),
      await handle.chmod('640'), await handle.utimes(new Date(-2500), '1234.5'),
      await handle.datasync()];
    const stat = fs.statSync(file + '-held');
    const remaining = Buffer.alloc(6);
    const read = await handle.read(remaining);
    await handle.close();
    return [results, prefix.toString(), read.bytesRead, remaining.toString('hex'),
      stat.size, stat.mode & 0o777, stat.atimeMs, stat.mtimeMs,
      fs.readFileSync(file, 'utf8')];
  }
  const { facade, file, calls } = fixture();
  assert.deepEqual(await exercise(facade.promises.open, file),
    await exercise(fs.promises.open, file + '-node'));
  const mutations = calls.filter(call => ['ftruncate', 'fdatasync', 'fchmod', 'futimes'].includes(call.operation));
  assert.equal(mutations.length, 5);
  assert(mutations.every(call => call.authority === 'fs_write'));
  assert.equal(calls.filter(call => call.operation === 'open').length, 1);
});

test('exclusive and synchronous flags flow through handle and whole-file Promise opens', async () => {
  async function exercise(api, file) {
    const handle = await api.promises.open(file, 'wx+');
    await handle.write('first');
    await handle.close();
    await assert.rejects(api.promises.open(file, 'xw'), { code: 'EEXIST' });
    await assert.rejects(api.promises.writeFile(file, 'overwrite', { flag: 'wx' }), { code: 'EEXIST' });
    await assert.rejects(api.promises.appendFile(file, 'append', { flag: 'ax' }), { code: 'EEXIST' });
    const original = fs.readFileSync(file, 'utf8');
    const append = await api.promises.open(file, 'sa+');
    await append.write('!', 0);
    await append.close();
    const reader = await api.promises.open(file, 'sr');
    const content = await reader.readFile('utf8');
    await reader.close();
    await api.promises.writeFile(file + '-new', 'created', { flag: 'xw' });
    await api.promises.appendFile(file + '-log', 'log', { flag: 'xa' });
    return [original, content, fs.readFileSync(file + '-new', 'utf8'), fs.readFileSync(file + '-log', 'utf8')];
  }
  const { facade, file, calls } = fixture();
  assert.deepEqual(await exercise(facade, file), await exercise(fs, file + '-node'));
  const openCalls = calls.filter(call => call.operation === 'open');
  assert.deepEqual(openCalls.map(call => call.args[1]), ['wx+', 'xw', 'wx', 'ax', 'sa+', 'sr', 'xw', 'xa']);
  assert(openCalls.every(call => call.authority === 'fs_write'));
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 5);
});

test('sync whole-file options honor exclusive append and nontruncating flags like Node', () => {
  function exercise(api, file) {
    fs.writeFileSync(file, 'original');
    assert.throws(() => api.writeFileSync(file, 'destroyed', { flag: 'wx' }), { code: 'EEXIST' });
    assert.throws(() => api.appendFileSync(file, 'destroyed', { flag: 'ax' }), { code: 'EEXIST' });
    const preserved = fs.readFileSync(file, 'utf8');
    api.writeFileSync(file, 'AB', { flag: 'r+' });
    const retained = fs.readFileSync(file, 'utf8');
    api.writeFileSync(file, '!', { flag: 'as', flush: true });
    const appended = fs.readFileSync(file, 'utf8');
    api.appendFileSync(file, 'replacement', { flag: 'w' });
    api.writeFileSync(file + '-new', '4142', { flag: 'wx+', encoding: 'hex', flush: true });
    const fd = fs.openSync(file, 'r+');
    api.writeFileSync(fd, 'Z', { flag: 'wx', flush: true });
    assert.equal(fs.fstatSync(fd).isFile(), true, 'borrowed descriptor stays open');
    fs.closeSync(fd);
    return [preserved, retained, appended, fs.readFileSync(file, 'utf8'), fs.readFileSync(file + '-new', 'hex')];
  }
  const { facade, file, calls } = fixture();
  assert.deepEqual(exercise(facade, file), exercise(fs, file + '-node'));
  assert.equal(calls.filter(call => call.operation === 'open').length, 6);
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 4);
  assert.equal(calls.filter(call => call.operation === 'fsync').length, 3);
});

test('whole-file callbacks share exclusive creation and descriptor cleanup with Promise writes', async () => {
  async function exercise(api, file) {
    fs.writeFileSync(file, 'original');
    await assert.rejects(invokeWrite(api, 'writeFile', file, 'destroyed', { flag: 'wx' }), { code: 'EEXIST' });
    await assert.rejects(invokeWrite(api, 'appendFile', file, 'destroyed', { flag: 'ax' }), { code: 'EEXIST' });
    const preserved = fs.readFileSync(file, 'utf8');
    await invokeWrite(api, 'writeFile', file, '!', { flag: 'as', flush: true });
    const appended = fs.readFileSync(file, 'utf8');
    await invokeWrite(api, 'appendFile', file, 'replacement', { flag: 'w' });
    const fd = fs.openSync(file, 'r+');
    await invokeWrite(api, 'writeFile', fd, 'Z', { flag: 'wx' });
    fs.closeSync(fd);
    return [preserved, appended, fs.readFileSync(file, 'utf8')];
  }
  const { facade, file, calls } = callbackFixture();
  assert.deepEqual(await exercise(facade, file), await exercise(fs, file + '-node'));
  assert.equal(calls.filter(call => call.operation === 'open').length, 4);
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 2);
});

test('queued whole-file callbacks snapshot options and keep captured methods', async () => {
  const { facade, file, calls } = callbackFixture();
  fs.writeFileSync(file, 'must survive');
  let reads = 0;
  const options = { get flag() { reads += 1; return 'wx'; } };
  const pending = invokeWrite(facade, 'writeFile', file, 'destroyed', options);
  Object.defineProperty(options, 'flag', { value: 'w' });
  facade.promises.writeFile = () => { throw new Error('replacement must not be called'); };
  assert.equal(reads, 1);
  assert.equal(calls.length, 0, 'no host effect before the queued operation');
  await assert.rejects(pending, { code: 'EEXIST' });
  assert.equal(fs.readFileSync(file, 'utf8'), 'must survive');
  assert.deepEqual(calls.map(call => call.operation), ['open']);
});

test('whole-file option validation and pre-abort never truncate or acquire a descriptor', () => {
  const { facade, file, calls } = callbackFixture();
  fs.writeFileSync(file, 'must survive');
  for (const options of [{ flag: 'w', flush: 1 }, { flag: 'w', encoding: 'invalid' }]) {
    assert.throws(() => facade.writeFileSync(file, 'x', options));
    assert.throws(() => facade.writeFile(file, 'x', options, () => {}));
  }
  assert.throws(() => facade.writeFileSync(file, {}, { flag: 'w' }), { code: 'ERR_INVALID_ARG_TYPE' });
  assert.throws(() => facade.writeFile(file, {}, { flag: 'w' }, () => {}), { code: 'ERR_INVALID_ARG_TYPE' });
  const controller = new AbortController();
  controller.abort('stop');
  let deliveries = 0;
  facade.writeFile(file, 'x', { flag: 'w', signal: controller.signal }, error => {
    assert.equal(error.code, 'ABORT_ERR'); assert.equal(error.cause, 'stop'); deliveries += 1;
  });
  assert.equal(deliveries, 1);
  assert.equal(calls.length, 0);
  assert.equal(fs.readFileSync(file, 'utf8'), 'must survive');
});

test('sync option writes close owned descriptors after short-write and flush failures', () => {
  let writes = 0;
  const failure = new Error('host write failed');
  const { facade, file, calls } = fixture((authority, operation) => {
    if (operation === 'write_fd' && ++writes === 2) throw failure;
  });
  assert.throws(() => facade.writeFileSync(file, Buffer.alloc(20000), { flag: 'wx' }), error => error === failure);
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
  assert.equal(fs.statSync(file).size, 16384);
  const flush = fixture((authority, operation) => { if (operation === 'fsync') throw failure; });
  assert.throws(() => flush.facade.appendFileSync(flush.file, 'x', { flag: 'ax', flush: true }), error => error === failure);
  assert.equal(flush.calls.filter(call => call.operation === 'close_fd').length, 1);
});

test('descriptor mutation arguments reject before host entry and closed handles stay closed', async () => {
  const { facade, calls, file } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  await handle.write('abcdef');
  const before = calls.length;
  for (const length of [NaN, Infinity, 1.5, 9007199254740992, -9007199254740992]) {
    await assert.rejects(handle.truncate(length), { code: 'ERR_OUT_OF_RANGE' });
  }
  await assert.rejects(handle.truncate('2'), { code: 'ERR_INVALID_ARG_TYPE' });
  for (const mode of ['', '8', '0o640', '600tail']) {
    await assert.rejects(handle.chmod(mode), { code: 'ERR_INVALID_ARG_VALUE' });
  }
  for (const mode of [NaN, 0.5, -1, 4294967296]) {
    await assert.rejects(handle.chmod(mode), { code: 'ERR_OUT_OF_RANGE' });
  }
  await assert.rejects(handle.chmod({}), { code: 'ERR_INVALID_ARG_TYPE' });
  for (const time of [NaN, Infinity, null, {}, 'bad', new Date(NaN)]) {
    await assert.rejects(handle.utimes(1, time), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  for (const name of ['ftruncateSync', 'fdatasyncSync', 'fchmodSync', 'futimesSync']) {
    assert.throws(() => facade[name](-1, 0, 0), { code: 'ERR_OUT_OF_RANGE' });
    assert.throws(() => facade[name]('3', 0, 0), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  assert.equal(calls.length, before);
  assert.equal(fs.statSync(file).size, 6);
  assert.equal(await handle.truncate(-1), undefined);
  assert.equal(fs.statSync(file).size, 0);
  await handle.write('x', 0);
  assert.equal(await handle.truncate(), undefined);
  await handle.close();
  const closed = calls.length;
  for (const [method, syscall, args] of [['truncate', 'ftruncate', [1]],
    ['datasync', 'fdatasync', []], ['chmod', 'fchmod', [0o600]], ['utimes', 'futimes', [1, 2]]]) {
    await assert.rejects(handle[method](...args), { code: 'EBADF', syscall });
  }
  assert.equal(calls.length, closed);
});

test('descriptor timestamps use captured Date intrinsics and preserve pre-epoch values', async () => {
  const { facade, file, context } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  const accessed = new Date(-2500);
  accessed.getTime = () => { throw new Error('public Date method must not be called'); };
  accessed.valueOf = () => { throw new Error('generic coercion must not run'); };
  vm.runInNewContext('Date.prototype.getTime = function () { throw new Error("replaced"); }; Date.now = function () { throw new Error("replaced"); };', context);
  // Public fs functions and a forged fd never redirect the owned methods.
  facade.futimesSync = () => { throw new Error('replaced fs method'); };
  Object.defineProperty(handle, 'fd', { value: 999999 });
  await handle.utimes(accessed, '-1.25');
  const stats = fs.statSync(file);
  assert.equal(stats.atimeMs, -2500);
  assert.equal(stats.mtimeMs, -1250);
  const before = Date.now();
  await handle.utimes(-1, -1);
  const after = Date.now();
  const current = fs.statSync(file);
  assert(current.atimeMs >= before - 1 && current.atimeMs <= after);
  assert(current.mtimeMs >= before - 1 && current.mtimeMs <= after);
  await handle.close();
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
  for (const pending of [handle.read(), handle.write('late'), handle.sync(), handle.stat()]) {
    await assert.rejects(pending, { code: 'EBADF' });
  }
  assert.equal(calls.filter(call => call.operation === 'close_fd').length, 1);
  assert.equal(calls.filter(call => /^(read|write)_fd$/.test(call.operation)).length, 0);
});

test('descriptor stats survive rename, replacement and unlink without moving the cursor', async () => {
  const { facade, calls, file } = fixture();
  fs.writeFileSync(file, 'abcdef');
  const handle = await facade.promises.open(file, 'r+');
  const descriptor = handle.fd;
  assert.equal((await handle.read(Buffer.alloc(2))).buffer.toString(), 'ab');
  const expected = fs.fstatSync(descriptor);
  const pick = value => [value.size, value.mode, value.mtime.getTime(),
    value.isFile(), value.isDirectory(), value.isSymbolicLink()];
  fs.renameSync(file, file + '-moved');
  fs.writeFileSync(file, 'replacement data with another size');
  assert.deepEqual(pick(facade.fstatSync(descriptor)), pick(expected));
  fs.unlinkSync(file + '-moved');
  // Public properties cannot change the privately owned file identity.
  Object.defineProperty(handle, 'fd', { value: descriptor + 100 });
  facade.fstatSync = () => { throw new Error('guest replacement called'); };
  assert.deepEqual(pick(await handle.stat()), pick(expected));
  assert.equal((await handle.read(Buffer.alloc(2))).buffer.toString(), 'cd');
  await handle.write('!', 6);
  assert.equal((await handle.stat()).size, 7);
  assert.equal((await handle.read(Buffer.alloc(2))).buffer.toString(), 'ef');
  await handle.close();
  assert.deepEqual(calls.filter(call => call.operation === 'fstat').map(call =>
    [call.authority, call.args[0]]), Array(3).fill(['fs_read', descriptor]));
  assert.equal(calls.filter(call => call.operation === 'open').length, 1);
});

test('fstat validates before host entry and observes bigint exactly once', async () => {
  const { facade, calls, file } = fixture();
  const handle = await facade.promises.open(file, 'w');
  await handle.write('1234');
  for (const descriptor of [undefined, null, '3', 3n, {}]) {
    assert.throws(() => facade.fstatSync(descriptor), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  for (const descriptor of [-1, NaN, 1.5, Infinity, 2147483648]) {
    assert.throws(() => facade.fstatSync(descriptor), { code: 'ERR_OUT_OF_RANGE' });
  }
  assert.throws(() => facade.fstatSync(handle.fd, null), { name: 'TypeError' });
  assert.equal(calls.filter(call => call.operation === 'fstat').length, 0);
  let reads = 0;
  const stats = await handle.stat({ get bigint() { reads += 1; return true; } });
  assert.equal(reads, 1);
  assert.equal(stats.size, 4n);
  assert.equal(typeof stats.mode, 'bigint');
  assert.equal(stats.isFile(), true);
  assert.equal(typeof (await handle.stat({ bigint: 1 })).size, 'number');
  const descriptor = handle.fd;
  await handle.close();
  assert.throws(() => facade.fstatSync(descriptor), { code: 'EBADF' });
  await assert.rejects(handle.stat(), { code: 'EBADF', syscall: 'fstat' });
});

test('FileHandle stat retains ownership through a reentrant option getter and exceptional exit', async () => {
  for (const fails of [false, true]) {
    const { facade, calls, file } = fixture();
    const handle = await facade.promises.open(file, 'w');
    let closing;
    const sentinel = new Error('stat option failed');
    const result = handle.stat({ get bigint() {
      closing = handle.close();
      assert.equal(calls.filter(call => call.operation === 'close_fd').length, 0);
      if (fails) throw sentinel;
      return true;
    } });
    if (fails) await assert.rejects(result, error => error === sentinel);
    else assert.equal((await result).size, 0n);
    await closing;
    assert.deepEqual(calls.map(call => call.operation),
      fails ? ['open', 'close_fd'] : ['open', 'fstat', 'close_fd']);
    await assert.rejects(handle.stat(), { code: 'EBADF' });
  }
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

test('all ArrayBufferView handle windows count bytes and preserve identity like Node', async () => {
  const constructors = [Int8Array, Uint8Array, Uint8ClampedArray, Int16Array,
    Uint16Array, Int32Array, Uint32Array, Float32Array, Float64Array,
    BigInt64Array, BigUint64Array, DataView];
  async function exercise(open, file, Type) {
    const handle = await open(file, 'w+');
    try {
      const backing = new ArrayBuffer(64);
      const bytes = new Uint8Array(backing);
      for (let i = 0; i < bytes.length; ++i) bytes[i] = 33 + i;
      const view = new Type(backing, 8, 4);
      const put = await handle.write(view, { offset: 1, length: view.byteLength - 2, position: 0 });
      assert.equal(put.buffer, view, Type.name);
      bytes.fill(45);
      const got = await handle.read(view, { offset: 1, length: view.byteLength - 2, position: 0 });
      assert.equal(got.buffer, view, Type.name);
      const explicit = await handle.read({ buffer: view, offset: 0, length: 1, position: 0 });
      assert.equal(explicit.buffer, view, Type.name);
      return [put.bytesWritten, got.bytesRead, explicit.bytesRead,
        Buffer.from(backing).toString('hex'), fs.readFileSync(file).toString('hex')];
    } finally { await handle.close(); }
  }
  for (const Type of constructors) {
    const { facade, calls, file } = fixture();
    assert.deepEqual(await exercise(facade.promises.open, file, Type),
      await exercise(fs.promises.open, file + '-node', Type), Type.name);
    const effects = calls.filter(call => /^(read|write)_fd$/.test(call.operation));
    assert.equal(effects.length, 3);
    for (const effect of effects) {
      assert(Buffer.isBuffer(effect.args[1]), 'native boundary receives a byte Buffer');
      assert.equal(effect.authority, effect.operation === 'read_fd' ? 'fs_read' : 'fs_write');
    }
  }
});

test('mixed and overlapping vector views match Node, including partial EOF and cursor', async () => {
  async function exercise(open, file) {
    const handle = await open(file, 'w+');
    try {
      const source = Uint8Array.from([33, 65, 66, 67, 68, 69, 70, 33]);
      const inputs = [new DataView(source.buffer, 1, 2),
        new Uint16Array(source.buffer, 2, 2), new Uint8Array(0)];
      const put = await handle.writev(inputs, 0);
      assert.equal(put.buffers, inputs);
      const target = new Uint8Array(12).fill(45);
      const outputs = [new Uint16Array(target.buffer, 2, 2),
        new DataView(target.buffer, 4, 4), new Uint8Array(0)];
      const got = await handle.readv(outputs, 0);
      assert.equal(got.buffers, outputs);
      const sequential = new DataView(new ArrayBuffer(2));
      const cursor = await handle.read(sequential);
      assert.equal(cursor.buffer, sequential);
      return [put.bytesWritten, got.bytesRead, cursor.bytesRead,
        Buffer.from(target).toString(), Buffer.from(sequential.buffer).toString(),
        fs.readFileSync(file).toString()];
    } finally { await handle.close(); }
  }
  const { facade, calls, file } = fixture();
  assert.deepEqual(await exercise(facade.promises.open, file),
    await exercise(fs.promises.open, file + '-node'));
  assert.equal(calls.filter(call => call.operation === 'write_fd').length, 1);
  assert.equal(calls.filter(call => call.operation === 'read_fd').length, 2);
});

test('fs exports synchronous vector I/O over the same gated descriptor operations', () => {
  const { facade, calls, file } = fixture();
  const fd = facade.openSync(file, 'w+');
  try {
    const bytes = Uint8Array.from([45, 97, 98, 99, 100, 45]);
    const inputs = [new DataView(bytes.buffer, 1, 2), bytes.subarray(3, 5)];
    assert.equal(facade.writevSync(fd, inputs, 0), 4);
    const output = new Uint8Array(8).fill(45);
    assert.equal(facade.readvSync(fd, [new DataView(output.buffer, 1, 2),
      new Uint16Array(output.buffer, 4, 2)], 0), 4);
    assert.equal(Buffer.from(output).toString(), '-ab-cd--');
    assert.equal(facade.readvSync(fd, [], 0), 0);
    assert.equal(facade.writevSync(fd, [new DataView(new ArrayBuffer(0))], 0), 0);
    assert.deepEqual(calls.map(call => call.operation), ['open', 'write_fd', 'read_fd']);
  } finally { facade.closeSync(fd); }
});

test('typed views and iterable chunks write their byte windows, not their elements', async () => {
  async function exercise(open, file) {
    const handle = await open(file, 'w+');
    try {
      const backing = Uint8Array.from([45, 45, 65, 66, 67, 68, 69, 70, 45, 45]);
      const words = new Uint16Array(backing.buffer, 2, 2);
      const data = new DataView(backing.buffer, 5, 3);
      await handle.writeFile(words);
      await handle.appendFile(data);
      await handle.writeFile((async function* () { yield words; yield data; })());
      return fs.readFileSync(file).toString();
    } finally { await handle.close(); }
  }
  const { facade, file } = fixture();
  assert.deepEqual(await exercise(facade.promises.open, file),
    await exercise(fs.promises.open, file + '-node'));
});

test('cross-realm views are accepted, but invalid views/windows reject before I/O', async () => {
  const { facade, calls, file } = fixture();
  const handle = await facade.promises.open(file, 'w+');
  try {
    const view = vm.runInNewContext('new DataView(new ArrayBuffer(8), 2, 3)');
    view.setUint8(0, 65);
    assert.equal((await handle.write(view)).buffer, view);
    const before = calls.length;
    for (const value of [{ buffer: new ArrayBuffer(4), byteLength: 4 },
      new ArrayBuffer(4), new Proxy(new Uint8Array(4), {})]) {
      await assert.rejects(handle.write(value), { code: 'ERR_INVALID_ARG_TYPE' });
      await assert.rejects(handle.readv([view, value]), { code: 'ERR_INVALID_ARG_TYPE' });
    }
    for (const offset of [-1, 0.5, NaN, Infinity, 4]) {
      await assert.rejects(handle.read(view, offset, 1, 0), { code: 'ERR_OUT_OF_RANGE' });
    }
    assert.equal(calls.length, before, 'validation failure must not touch the descriptor');
  } finally { await handle.close(); }
});

test('view option getters cannot close a descriptor before its active read drains', async () => {
  const { facade, calls, file } = fixture();
  fs.writeFileSync(file, 'safe');
  const handle = await facade.promises.open(file, 'r');
  const buffer = new DataView(new ArrayBuffer(4));
  let closing;
  const result = await handle.read(buffer, {
    get offset() { closing = handle.close(); return 0; }, length: 4,
  });
  assert.equal(result.buffer, buffer);
  assert.equal(Buffer.from(buffer.buffer).toString(), 'safe');
  await closing;
  assert.deepEqual(calls.map(call => call.operation), ['open', 'read_fd', 'close_fd']);
});

// Count only the facade's explicit staging requests, not Node's allocator or
// FrankenEngine heap usage. The wrapped methods still operate on real Buffers.
function measuredBuffers() {
  const counts = { allocations: 0, allocatedBytes: 0, concats: 0, copies: 0 };
  const methods = Object.assign(Object.create(Buffer.prototype), {
    copy(...args) {
      counts.copies++;
      return Reflect.apply(Buffer.prototype.copy, this, args);
    },
  });
  const api = Object.assign(Object.create(Buffer), {
    prototype: methods,
    alloc(length, ...args) {
      counts.allocations++;
      counts.allocatedBytes += length;
      return Buffer.alloc(length, ...args);
    },
    concat(...args) { counts.concats++; return Buffer.concat(...args); },
  });
  return { api, counts };
}

test('short-read staging is bounded by payload bytes, not fragment count', async t => {
  for (const [size, fragment] of [[0, 1], [17, 1], [16384, 7], [49157, 7]]) {
    const { api, counts } = measuredBuffers();
    const { facade, file, calls } = fixture((authority, operation, args) => {
      if (operation === 'read_fd') args[3] = Math.min(args[3], fragment);
    }, { Buffer: api });
    const payload = Buffer.alloc(size);
    for (let i = 0; i < size; i++) payload[i] = (i * 37 + 11) & 255;
    fs.writeFileSync(file, payload);
    const handle = await facade.promises.open(file);
    try {
      const data = await handle.readFile();
      assert.deepEqual(data, payload);
      assert.equal(data.length, size, 'unused staging bytes must never escape');
      // One active block, including the EOF probe after an exactly full block.
      const bound = Math.floor(size / 16384) + 1;
      t.diagnostic(`${size} bytes / ${fragment}-byte reads: ${counts.allocations} staging allocations`);
      assert.equal(counts.allocations, bound);
      assert.equal(counts.allocatedBytes, bound * 16384);
      assert.equal(counts.concats, 1, 'compact the final public Buffer once');
      const reads = calls.filter(call => call.operation === 'read_fd');
      assert(reads.length >= Math.ceil(size / fragment) + 1);
      assert(reads.every(call => call.authority === 'fs_read' && call.args[3] <= 16384));
      assert.equal(new Set(reads.map(call => call.args[1])).size, bound);
    } finally { await handle.close(); }
  }
});

test('one nonempty vector borrows its Buffer window without staging or scatter', async () => {
  for (const typed of [false, true]) {
    const { api, counts } = measuredBuffers();
    const { facade, file, calls } = fixture(undefined, { Buffer: api });
    const handle = await facade.promises.open(file, 'w+');
    try {
      const backing = Uint8Array.from([45, 65, 66, 67, 68, 45]);
      const data = typed ? new DataView(backing.buffer, 1, 4) : Buffer.from('ABCD');
      const parts = [Buffer.alloc(0), data, new Uint8Array(0)];
      const put = await handle.writev(parts, 0);
      assert.equal(put.buffers, parts);
      assert.equal(put.bytesWritten, 4);
      const out = Buffer.alloc(8, 45);
      const target = typed ? new DataView(out.buffer, out.byteOffset + 2, 4) : out.subarray(2, 6);
      const targets = [new Uint8Array(0), target, Buffer.alloc(0)];
      const got = await handle.readv(targets, 1);
      assert.equal(got.buffers, targets);
      assert.equal(got.bytesRead, 3, 'short read leaves the last byte untouched');
      assert.equal(out.toString(), '--BCD---');
      assert.deepEqual(counts, { allocations: 0, allocatedBytes: 0, concats: 0, copies: 0 });
      const effects = calls.filter(call => /^(read|write)_fd$/.test(call.operation));
      assert.equal(effects.length, 2);
      // The private bridge authenticates a fresh byte view even for Buffers,
      // so guest-owned metadata cannot redirect I/O. Borrowing promises the
      // same storage window, not the same wrapper identity. Public result
      // identities and the zero-staging/copy counters remain checked above.
      for (const [effect, original] of [[effects[0], data], [effects[1], target]]) {
        assert.equal(effect.args[1].buffer, original.buffer);
        assert.equal(effect.args[1].byteOffset, original.byteOffset);
        assert.equal(effect.args[1].byteLength, original.byteLength);
      }
    } finally { await handle.close(); }
  }
});

test('single-vector selection still visits trailing getters before any I/O', async () => {
  for (const operation of ['readv', 'writev']) {
    const { facade, file, calls } = fixture();
    const handle = await facade.promises.open(file, 'w+');
    const failure = new Error('invalid tail');
    let closing;
    const parts = [Buffer.from('data')];
    Object.defineProperty(parts, 1, { get() {
      closing = handle.close();
      throw failure;
    } });
    await assert.rejects(handle[operation](parts), error => error === failure);
    await closing;
    assert.deepEqual(calls.map(call => call.operation), ['open', 'close_fd']);
    assert.equal(fs.statSync(file).size, 0);
  }
});

test('packed reads reject a count larger than the remaining window', async () => {
  const { facade, file, context } = fixture();
  fs.writeFileSync(file, 'data');
  const handle = await facade.promises.open(file);
  let reads = 0;
  context.__franken_fs_read = (tag, fd, data, offset, length, position) => {
    if (++reads === 1) return fs.readSync(fd, data, offset, 1, position);
    assert.equal(offset, 1);
    assert.equal(length, 16383);
    return 16384; // Fits the allocation but exceeds the authorized byte window.
  };
  try {
    await assert.rejects(handle.readFile(), { code: 'EIO', syscall: 'read' });
    assert.equal(reads, 2);
  } finally { await handle.close(); }
});

test('short-read packing preserves UTF-8 assembly, abort checks and close draining', async () => {
  const { api, counts } = measuredBuffers();
  const controller = new AbortController();
  let abort = false;
  let closing;
  let handle;
  const { facade, file, calls } = fixture((authority, operation, args) => {
    if (operation === 'read_fd') {
      args[3] = Math.min(args[3], 3);
      if (abort) { closing = handle.close(); controller.abort('stop'); }
    }
  }, { Buffer: api });
  const text = 'x'.repeat(16383) + '\u20ac' + '\ud83d\ude03'.repeat(30);
  fs.writeFileSync(file, text);
  handle = await facade.promises.open(file);
  assert.equal(await handle.readFile('utf8'), text);
  await handle.close();
  handle = await facade.promises.open(file);
  const before = counts.allocations;
  await assert.rejects(handle.readFile({ signal: AbortSignal.abort('pre') }),
    { code: 'ABORT_ERR', cause: 'pre' });
  assert.equal(counts.allocations, before, 'pre-abort must precede staging allocation');
  const priorReads = calls.filter(call => call.operation === 'read_fd').length;
  abort = true;
  await assert.rejects(handle.readFile({ signal: controller.signal }),
    { code: 'ABORT_ERR', cause: 'stop' });
  await closing;
  assert.equal(calls.filter(call => call.operation === 'read_fd').length, priorReads + 1);
  assert.equal(calls.at(-1).operation, 'close_fd');
});
