'use strict';
// Exact production installer on Node's Blob storage and Web Stream primitives.
// This is not execution of the Rust parser, interpreter or native Blob code.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const reference = require('node:buffer');
const web = require('node:stream/web');
const source = fs.readFileSync(process.env.BUFFER_FILES_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/buffer_file_module.js'), 'utf8');
const hostBlob = reference.Blob;
const nativeSize = Object.getOwnPropertyDescriptor(hostBlob.prototype, 'size');
const nativeType = Object.getOwnPropertyDescriptor(hostBlob.prototype, 'type');
const nativeSlice = hostBlob.prototype.slice;
const nativeArrayBuffer = hostBlob.prototype.arrayBuffer;
function factory(options = {}) {
  const stats = { dependencies: 0, ranges: [], reads: [], constructed: 0 };
  class PayloadBlob extends hostBlob {
    constructor(parts, settings) { super(parts, settings); stats.constructed++; }
    slice(start, end, type) {
      stats.ranges.push([start, end]);
      const part = Reflect.apply(nativeSlice, this, [start, end, type]);
      Object.setPrototypeOf(part, PayloadBlob.prototype);
      return part;
    }
    arrayBuffer() {
      stats.reads.push(Reflect.apply(nativeSize.get, this, []));
      return options.binaryRead ? options.binaryRead(this, nativeArrayBuffer) :
        Reflect.apply(nativeArrayBuffer, this, []);
    }
  }
  // Hide the reference stream so inherited Node support cannot fake success.
  Object.defineProperties(PayloadBlob.prototype, {
    stream: { value: undefined, writable: true, configurable: true },
    size: nativeSize, type: nativeType,
  });
  const context = { Reflect, Object, WeakMap, Symbol, String, ArrayBuffer, Uint8Array,
    TypeError, Date: options.Date || Date,
    process: { platform: options.platform || process.platform } };
  Object.defineProperty(context, '__franken_buffer_web_streams', {
    get() { stats.dependencies++; return options.web || web; },
  });
  const module = { Blob: PayloadBlob };
  const install = vm.runInNewContext(source, context, { filename: 'buffer_file_module.js' });
  install(module);
  return { module, stats, install, context };
}
const microtasks = async () => { for (let i = 0; i < 8; i++) await Promise.resolve(); };
const timeout = async (promise) => {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(Error('operation did not settle')), 1500);
  })]); } finally { clearTimeout(timer); }
};
async function contents(stream) {
  const chunks = [];
  for await (const chunk of stream) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks);
}
async function describe(File) {
  const f = new File(['hé', new Uint8Array([33])], 'a\ud800/b.txt',
    { type: 'TEXT/PLAIN', lastModified: -1.5 });
  return { name: f.name, type: f.type, size: f.size, lastModified: f.lastModified,
    tag: Object.prototype.toString.call(f), text: await f.text(),
    own: Object.keys(f), file: f instanceof File, blob: f instanceof hostBlob,
    sliceName: Object.prototype.toString.call(f.slice(0, 1)),
    descriptor: Object.getOwnPropertyDescriptor(File.prototype, 'name').enumerable };
}
test('File metadata, Unicode names, inherited storage and slices match Node', async () => {
  const { module, stats } = factory();
  assert.deepEqual(await describe(module.File), await describe(reference.File));
  assert.equal(module.File.length, reference.File.length);
  assert.equal(module.File.name, 'File');
  assert.equal(stats.dependencies, 0, 'construction must not initialize streams');
});
test('constructor validation and timestamps match Node', async () => {
  const { module } = factory();
  const cases = [[], [[]], [undefined, 'x'], [null, 'x'], ['x', 'x'], [42, 'x'],
    [[], undefined], [[], null], [[], Symbol('x')], [[], 'x', 4], [[], 'x', null],
    [[], 'x', () => {}], [[], 'x', { endings: 'invalid' }], [[], 'x', { endings: null }],
    [[], 'x', { lastModified: NaN }], [[], 'x', { lastModified: Infinity }],
    [[], 'x', { lastModified: -1.5 }], [[], 'x', { lastModified: 1n }],
    [[], 'x', { type: Symbol('type') }], [[Symbol('part')], 'x']];
  function outcome(File, args) {
    try { const f = new File(...args); return ['ok', f.name, f.type, f.size,
      args[2] && 'lastModified' in Object(args[2]) ? f.lastModified : 'clock']; }
    catch (e) { return ['error', e.name, e.code]; }
  }
  for (const args of cases) assert.deepEqual(outcome(module.File, args), outcome(reference.File, args));
});
test('option getters, iterable acquisition, conversions and name ordering match Node', () => {
  function exercise(File) {
    const seen = [];
    const parts = { get [Symbol.iterator]() {
      seen.push('iterator-get'); return function* () { seen.push('iterator-call');
        yield { toString() { seen.push('part'); return 'ab'; } }; seen.push('end'); };
    } };
    const opts = {
      get type() { seen.push('type'); return { toString() { seen.push('typeString'); return 'X/TYPE'; } }; },
      get endings() { seen.push('endings'); return { toString() { seen.push('endingString'); return 'native'; } }; },
      get lastModified() { seen.push('last'); return { valueOf() { seen.push('time'); return 7; } }; },
    };
    const f = new File(parts, { toString() { seen.push('name'); return 'x'; } }, opts);
    return { seen, name: f.name, type: f.type, size: f.size, lastModified: f.lastModified };
  }
  assert.deepEqual(exercise(factory().module.File), exercise(reference.File));
});
test('binary snapshots are taken before requesting another iterable part', async () => {
  async function exercise(File) {
    const storage = new Uint8Array([0, 65, 66, 0]);
    function* bits() { yield new DataView(storage.buffer, 1, 2); storage[1] = 67; storage[2] = 68;
      yield new Uint16Array(storage.buffer, 0, 2); storage.fill(90); }
    return Buffer.from(await new File(bits(), 'x', { lastModified: 0 }).arrayBuffer()).toString('hex');
  }
  assert.equal(await exercise(factory().module.File), await exercise(reference.File));
});
test('native endings change string parts only and preserve binary boundaries', async () => {
  const pieces = ['a\r\nb\rc\n', new Uint8Array([13, 10]), '\r', '\n'];
  for (const endings of ['transparent', 'native']) {
    const actual = new (factory().module.File)(pieces, 'x', { endings });
    const expected = new reference.File(pieces, 'x', { endings });
    assert.equal(await actual.text(), await expected.text());
  }
  const f = new (factory({ platform: 'win32' }).module.File)(pieces, 'x', { endings: 'native' });
  assert.equal(await f.text(), 'a\r\nb\rc\r\n\r\n\r\r\n');
});
test('timestamp default is captured clock; metadata getters are privately branded', () => {
  const { module } = factory({ Date: { now: () => 12345 } });
  const f = new module.File([], 'kept');
  assert.equal(f.lastModified, 12345);
  const getName = Object.getOwnPropertyDescriptor(module.File.prototype, 'name').get;
  Object.defineProperty(f, 'name', { value: 'public override' });
  assert.equal(Reflect.apply(getName, f, []), 'kept');
  for (const value of [{}, new module.Blob(), Object.create(module.File.prototype), null]) {
    assert.throws(() => Reflect.apply(getName, value, []), TypeError);
  }
  class Child extends module.File {}
  const child = new Child(['x'], 'child');
  assert.equal(child.name, 'child'); assert(child instanceof Child); assert(child instanceof module.Blob);
});
test('failed part coercion closes its producer and never reads filename', () => {
  const failure = { original: true }, trace = [];
  const bits = { *[Symbol.iterator]() { try { yield { toString() { throw failure; } }; }
    finally { trace.push('return'); } } };
  assert.throws(() => new (factory().module.File)(bits, { toString() { trace.push('name'); return 'x'; } }),
    e => e === failure);
  assert.deepEqual(trace, ['return']);
});
test('cross-realm views and blobs keep exact bytes', async () => {
  const parts = vm.runInNewContext('[new Uint8Array([1,2,3]).subarray(1), new DataView(new Uint8Array([4,5]).buffer)]');
  parts.push(new reference.Blob(['!']));
  const { module } = factory();
  assert.deepEqual(Buffer.from(await new module.File(parts, 'x').arrayBuffer()), Buffer.from([2,3,4,5,33]));
});
test('streams initialize lazily, require demand and bound every slice', async () => {
  const { module, stats } = factory();
  const expected = Buffer.alloc(200003);
  for (let i = 0; i < expected.length; i++) expected[i] = i % 251;
  const f = new module.File([expected], 'large', { lastModified: 0 });
  expected.fill(9, 0, 1); // File is an immutable snapshot.
  const stream = f.stream();
  assert(stream instanceof web.ReadableStream); assert.equal(stats.dependencies, 1);
  await microtasks(); assert.deepEqual(stats.ranges, []);
  const reader = stream.getReader();
  const first = await timeout(reader.read());
  assert.equal(first.value.byteLength, 65536); assert.equal(first.value[0], 0);
  first.value[0] = 255;
  await microtasks(); assert.equal(stats.ranges.length, 1, 'no prefetch between reads');
  const output = [Buffer.from(first.value)];
  for (;;) { const step = await timeout(reader.read()); if (step.done) break; output.push(Buffer.from(step.value)); }
  const joined = Buffer.concat(output); expected[0] = 255; assert.deepEqual(joined, expected);
  assert.deepEqual(stats.reads, [65536,65536,65536,3395]);
  assert.equal((await f.bytes())[0], 0);
});
test('empty Blob default and BYOB reads both settle at EOF', async () => {
  for (const mode of ['default', 'byob']) {
    const { module, stats } = factory();
    const stream = new module.Blob().stream();
    const reader = mode === 'byob' ? stream.getReader({ mode }) : stream.getReader();
    const step = await timeout(mode === 'byob' ? reader.read(new Uint8Array(8)) : reader.read());
    assert.equal(step.done, true); assert.equal(stats.reads.length, 0);
    if (mode === 'byob') assert.equal(step.value.byteLength, 0);
  }
});
test('BYOB reads preserve element type, min and final partial byte results', async () => {
  for (const View of [Uint8Array, Uint16Array, DataView]) {
    const { module, stats } = factory();
    const input = Buffer.from([1,2,3,4,5,6]);
    const reader = new module.File([input], 'x').stream().getReader({ mode: 'byob' });
    const target = View === DataView ? new DataView(new ArrayBuffer(16), 2, 8) : new View(8);
    const result = await timeout(reader.read(target, { min: View === DataView ? 8 : 4 }));
    assert.equal(result.value.constructor, View);
    // A short EOF result is done:true when it cannot reach the requested min.
    assert.equal(result.done, View !== Uint8Array);
    assert.deepEqual(Buffer.from(result.value.buffer, result.value.byteOffset, result.value.byteLength), input);
    assert.equal(target.buffer.byteLength, 0, 'ownership transferred');
    const end = await timeout(reader.read(View === DataView ? new DataView(new ArrayBuffer(8)) : new View(4)));
    assert.equal(end.done, true); assert.equal(end.value.byteLength, 0);
    assert.deepEqual(stats.reads, [6]);
  }
});
test('BYOB min spanning several bounded pulls finishes without collecting the Blob', async () => {
  const { module, stats } = factory();
  const expected = Buffer.alloc(150000, 37);
  const reader = new module.Blob([expected]).stream().getReader({ mode: 'byob' });
  const step = await timeout(reader.read(new Uint8Array(200000), { min: 160000 }));
  assert.equal(step.value.length, expected.length); assert.equal(step.done, true);
  assert.deepEqual(Buffer.from(step.value), expected);
  assert.deepEqual(stats.reads, [65536,65536,18928]);
});
test('an incomplete BYOB element errors rather than dropping a final byte', async () => {
  const { module } = factory();
  const reader = new module.Blob([new Uint8Array([1,2,3])]).stream().getReader({ mode:'byob' });
  const observed = reader.closed.catch(e => e);
  const first = await timeout(reader.read(new Uint16Array(4)));
  assert.equal(first.value.byteLength, 2);
  await assert.rejects(timeout(reader.read(new Uint16Array(4))), TypeError);
  assert(await observed instanceof TypeError);
});
test('concurrent default reads consume each range once', async () => {
  const { module, stats } = factory();
  const reader = new module.Blob([Buffer.alloc(65539, 7)]).stream().getReader();
  const steps = await timeout(Promise.all([reader.read(), reader.read(), reader.read()]));
  assert.deepEqual(steps.map(s => [s.done, s.value && s.value.length]), [[false,65536],[false,3],[true,undefined]]);
  assert.deepEqual(stats.ranges, [[0,65536],[65536,65539]]);
});
test('cancelling before demand never copies payload bytes', async () => {
  const { module, stats } = factory();
  const stream = new module.File([Buffer.alloc(1000)], 'x').stream();
  await stream.cancel('stop'); await microtasks();
  assert.deepEqual(stats.reads, []); assert.equal((await stream.getReader().read()).done, true);
});
test('cancelling a pending binary read suppresses late publication', async () => {
  let resolveRead, entered;
  const started = new Promise(resolve => { entered = resolve; });
  const { module, stats } = factory({ binaryRead(blob, method) {
    entered(); return new Promise(resolve => { resolveRead = async () => resolve(await Reflect.apply(method, blob, [])); });
  } });
  const reader = new module.File(['retained'], 'x').stream().getReader();
  const pending = reader.read(); await timeout(started);
  await timeout(reader.cancel({ marker: true }));
  assert.equal((await timeout(pending)).done, true);
  await resolveRead(); await microtasks();
  assert.equal((await reader.read()).done, true); assert.equal(stats.reads.length, 1);
});
test('binary read rejection retains its exact reason and prevents further reads', async () => {
  for (const reason of [undefined, null, false, { original: true }]) {
    const { module, stats } = factory({ binaryRead() { return Promise.reject(reason); } });
    const reader = new module.Blob(['x']).stream().getReader();
    const terminal = reader.closed.then(() => ({ ok: true }), e => ({ e }));
    const result = await timeout(reader.read().then(() => ({ ok: true }), e => ({ e })));
    assert.equal(result.e, reason); assert.equal('ok' in result, false);
    assert.equal((await terminal).e, reason);
    await reader.read().catch(() => {}); assert.equal(stats.reads.length, 1);
  }
});
test('own Blob metadata and public binary methods cannot redirect a stream', async () => {
  const { module } = factory();
  const blob = new module.Blob(['REAL']);
  Object.defineProperties(blob, {
    size: { get() { throw Error('size'); } },
    slice: { value() { throw Error('slice'); } },
    arrayBuffer: { value() { throw Error('read'); } },
  });
  assert.equal((await contents(blob.stream())).toString(), 'REAL');
  assert.throws(() => module.Blob.prototype.stream.call({}), TypeError);
});
test('prototype binary method replacement after module initialization cannot redirect', async () => {
  const { module } = factory();
  module.Blob.prototype.slice = () => { throw Error('replaced slice'); };
  module.Blob.prototype.arrayBuffer = () => { throw Error('replaced read'); };
  assert.equal((await contents(new module.File(['safe'], 'x').stream())).toString(), 'safe');
});
test('already supplied File and Blob streaming implementations are retained', () => {
  const { install } = factory();
  const original = { Blob: reference.Blob, File: reference.File };
  const stream = original.Blob.prototype.stream;
  assert.equal(install(original), original);
  assert.equal(original.File, reference.File); assert.equal(original.Blob.prototype.stream, stream);
});

test('full buffer-source composition exports File without replacing Buffer or initializing streams', async () => {
  const { module, stats, context } = factory();
  Object.defineProperty(module.Blob.prototype, 'stream', { value: undefined, configurable: true, writable: true });
  const base = fs.readFileSync(path.join(__dirname,
    '../../crates/franken-engine/src/lowering_pipeline/buffer_module.js'), 'utf8');
  Object.assign(context, { Blob: module.Blob, Buffer, File: undefined, atob, btoa, TextDecoder });
  const composite = vm.runInNewContext('(' + source + ')(' + base + ')', context);
  assert.equal(composite.Buffer, Buffer);
  assert.equal(stats.dependencies, 0);
  const file = new composite.File(['composed'], 'x', { lastModified: 0 });
  assert.equal((await contents(file.stream())).toString(), 'composed');
  assert.equal(stats.dependencies, 1);
  assert.equal(composite.transcode(Buffer.from('6162', 'hex'), 'utf8', 'latin1').toString(), 'ab');
});

test('bounded slices match independent Node bytes for deterministic partition sizes', async () => {
  let seed = 0x713a523f;
  for (let n = 0; n < 32; n++) {
    seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5;
    const length = (seed >>> 0) % 140000;
    const input = Buffer.alloc(length);
    for (let i = 0; i < length; i++) input[i] = (i * 37 + n) % 256;
    const { module, stats } = factory();
    const actual = await contents(new module.File([input], 'bytes', { lastModified: 0 }).stream());
    const expected = Buffer.from(await new reference.File([input], 'bytes', { lastModified: 0 }).arrayBuffer());
    assert.deepEqual(actual, expected);
    assert(stats.reads.every(size => size <= 65536));
  }
});
