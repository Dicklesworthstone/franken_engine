'use strict';
// Execute the complete production Node-stream state machines, not Node's
// Readable/Writable implementation. Node supplies the language, EventEmitter,
// StringDecoder, AbortSignal and nextTick primitives. This is not Rust execution.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const events = require('node:events');
const decoder = require('node:string_decoder');
const node = require('node:stream');
const source = fs.readFileSync(process.env.STREAM_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_module.js'), 'utf8');
function load(dependencies) {
  const signals = [];
  const signalType = { prototype: AbortSignal.prototype, any(sources) {
    const signal = AbortSignal.any(sources); signals.push(signal); return signal;
  } };
  const stream = new Function('__franken_stream_events', '__franken_stream_string_decoder',
    '__franken_stream_next_tick', 'AbortSignal', 'return ' + source)(
      dependencies?.events || events, dependencies?.decoder || decoder,
      callback => process.nextTick(callback), signalType);
  return { stream, signals };
}
const candidate = load().stream;
const tick = () => new Promise(resolve => setImmediate(resolve));
function deferred() { let resolve; const promise = new Promise(r => { resolve = r; }); return { promise, resolve }; }
function observed(stream, t) {
  const errors = []; stream.on('error', error => errors.push(error));
  const closed = new Promise(resolve => stream.once('close', resolve));
  t.after(() => { if (!stream.destroyed) stream.destroy(); });
  return { errors, closed };
}
function aborted(error, reason) {
  assert.equal(error.name, 'AbortError'); assert.equal(error.code, 'ABORT_ERR');
  assert.equal(error.cause, reason);
}
for (const [label, io] of [['candidate', candidate], ['node', node]]) {
  for (const name of ['Readable', 'Writable', 'Duplex', 'Transform', 'PassThrough']) {
    test(`${label}: ${name} constructor owns later cancellation`, async t => {
      const controller = new AbortController(), reason = { marker: name };
      let destroyed = 0;
      const stream = new io[name]({
        signal: controller.signal,
        read() {}, write(chunk, encoding, callback) { callback(); },
        destroy(error, callback) { destroyed++; callback(error); }
      });
      const observation = observed(stream, t);
      assert(stream instanceof io[name]);
      controller.abort(reason);
      assert.equal(stream.destroyed, true);
      await observation.closed;
      assert.equal(destroyed, 1); assert.equal(observation.errors.length, 1);
      aborted(observation.errors[0], reason); aborted(stream.errored, reason);
      controller.abort('again'); stream.destroy(); assert.equal(destroyed, 1);
    });
    test(`${label}: ${name} pre-abort refuses reads and writes`, async t => {
      let destroys = 0, reads = 0, writes = 0;
      const stream = new io[name]({ signal: AbortSignal.abort(0),
        read() { reads++; }, write(chunk, encoding, callback) { writes++; callback(); },
        destroy(error, callback) { destroys++; callback(error); }
      });
      const observation = observed(stream, t);
      assert.equal(stream.destroyed, true);
      if (stream.read) stream.read(0);
      if (stream.write) stream.write('late', () => {});
      await observation.closed;
      assert.equal(reads, 0); assert.equal(writes, 0); assert.equal(destroys, 1);
      assert.equal(observation.errors.length, 1); aborted(observation.errors[0], 0);
    });
  }
  test(`${label}: abort waits for asynchronous construction before destruction`, async t => {
    const constructing = deferred(); const controller = new AbortController();
    const calls = []; let finishConstruct;
    const stream = new io.Writable({ signal: controller.signal,
      construct(callback) { calls.push('construct'); finishConstruct = callback; constructing.resolve(); },
      write(chunk, encoding, callback) { calls.push('write'); callback(); },
      destroy(error, callback) { calls.push('destroy'); callback(error); }
    });
    const observation = observed(stream, t);
    stream.write('never-written', () => calls.push('write-callback'));
    await constructing.promise; controller.abort(false);
    assert.equal(stream.destroyed, true); assert.deepEqual(calls, ['construct']);
    finishConstruct(); await observation.closed;
    assert(!calls.includes('write')); assert.equal(calls.filter(c => c === 'destroy').length, 1);
    aborted(observation.errors[0], false);
  });
  test(`${label}: successful non-auto-destroyed writable detaches cancellation`, async t => {
    const controller = new AbortController(); let bytes = '';
    const stream = new io.Writable({ signal: controller.signal, autoDestroy: false,
      write(chunk, encoding, callback) { bytes += chunk; callback(); }
    });
    const observation = observed(stream, t);
    const finished = new Promise(resolve => stream.once('finish', resolve));
    stream.end('complete'); await finished; controller.abort('too late'); await tick();
    assert.equal(bytes, 'complete'); assert.equal(stream.destroyed, false);
    assert.deepEqual(observation.errors, []);
  });
  test(`${label}: half-finished Duplex remains cancellable`, async t => {
    const controller = new AbortController();
    const stream = new io.Duplex({ signal: controller.signal, autoDestroy: false,
      read() {}, write(chunk, encoding, callback) { callback(); }
    });
    const observation = observed(stream, t);
    const finish = new Promise(resolve => stream.once('finish', resolve));
    stream.end('ok'); await finish;
    assert.equal(stream.readableEnded, false); controller.abort('other half');
    assert.equal(stream.destroyed, true); await observation.closed;
    aborted(observation.errors[0], 'other half');
  });
  test(`${label}: successful non-auto-destroyed readable detaches cancellation`, async t => {
    const controller = new AbortController();
    const stream = new io.Readable({ signal: controller.signal, autoDestroy: false,
      read() { this.push('complete'); this.push(null); } });
    const observation = observed(stream, t), chunks = [];
    const ended = new Promise(resolve => stream.once('end', resolve));
    stream.on('data', chunk => chunks.push(String(chunk))); await ended;
    controller.abort('late'); await tick();
    assert.deepEqual(chunks, ['complete']); assert.equal(stream.destroyed, false);
    assert.deepEqual(observation.errors, []);
  });
  test(`${label}: abort during finalization prevents a successful finish`, async t => {
    const controller = new AbortController(), finalizing = deferred();
    let finalCallback, finishes = 0;
    const stream = new io.Writable({ signal: controller.signal,
      write(chunk, encoding, callback) { callback(); },
      final(callback) { finalCallback = callback; finalizing.resolve(); } });
    const observation = observed(stream, t); stream.on('finish', () => finishes++);
    stream.end('accepted'); await finalizing.promise; controller.abort('final');
    assert.equal(stream.destroyed, true); await observation.closed;
    finalCallback(); await tick();
    assert.equal(finishes, 0); assert.equal(stream.writableFinished, false);
    aborted(observation.errors[0], 'final');
  });
  test(`${label}: Readable.from cancellation awaits producer cleanup`, async t => {
    const controller = new AbortController(), cleanup = deferred(), requested = deferred();
    let closes = 0, pulls = 0, next;
    const input = { [Symbol.asyncIterator]() { return this; },
      next() { pulls++; requested.resolve(); return new Promise(resolve => { next = resolve; }); },
      async return() { closes++; await cleanup.promise; return { done: true }; }
    };
    const stream = io.Readable.from(input, { signal: controller.signal });
    const observation = observed(stream, t); stream.resume(); await requested.promise;
    controller.abort('producer'); assert.equal(stream.destroyed, true);
    await tick(); assert.equal(closes, 1); assert.equal(stream.closed, false);
    next({ value: 'too-late', done: false }); cleanup.resolve(); await observation.closed;
    assert.equal(pulls, 1); assert.equal(closes, 1); assert.equal(stream.readableLength, 0);
    aborted(observation.errors[0], 'producer');
  });
  test(`${label}: source constructor abort stops the whole pipeline`, async t => {
    const controller = new AbortController(), accepted = deferred();
    let pulls = 0, finalized = false; const chunks = [];
    const input = new io.Readable({ signal: controller.signal,
      read() { if (pulls++ === 0) this.push('accepted'); }
    });
    const output = new io.Writable({ write(chunk, encoding, callback) {
      chunks.push(String(chunk)); callback(); accepted.resolve();
    }, final(callback) { finalized = true; callback(); } });
    observed(input, t); observed(output, t);
    const result = io.promises.pipeline(input, output).then(
      () => ({ success: true }), error => ({ error }));
    await accepted.promise; controller.abort(null);
    assert.equal(input.destroyed, true);
    const settled = await result; aborted(settled.error, null);
    assert.equal(output.destroyed, true); assert.equal(finalized, false);
    assert.deepEqual(chunks, ['accepted']);
  });
  test(`${label}: transform cancellation waits for asynchronous teardown`, async t => {
    const controller = new AbortController(), entered = deferred();
    let completeTransform, completeDestroy, settled = false, flushed = false;
    const source = io.Readable.from(['payload']);
    const transform = new io.Transform({ signal: controller.signal,
      transform(chunk, encoding, callback) { completeTransform = callback; entered.resolve(); },
      flush(callback) { flushed = true; callback(); },
      destroy(error, callback) { completeDestroy = () => callback(error); }
    });
    const written = [];
    const sink = new io.Writable({ write(chunk, encoding, callback) { written.push(String(chunk)); callback(); } });
    observed(source, t); observed(transform, t); observed(sink, t);
    const result = io.promises.pipeline(source, transform, sink).then(
      () => { settled = true; return { success: true }; },
      error => { settled = true; return { error }; });
    await entered.promise; controller.abort('transform');
    assert.equal(transform.destroyed, true); await tick(); assert.equal(settled, false);
    assert.equal(typeof completeDestroy, 'function'); completeDestroy();
    const outcome = await result; aborted(outcome.error, 'transform');
    completeTransform(null, 'late'); await tick();
    assert.deepEqual(written, []); assert.equal(flushed, false);
    assert(source.destroyed && transform.destroyed && sink.destroyed);
  });
  test(`${label}: ordinary pipeline still completes 4096 chunks`, async () => {
    const values = Array.from({ length: 4096 }, (_, i) => i), actual = [];
    const map = new io.Transform({ objectMode: true, transform(n, encoding, callback) { callback(null, n * 3); } });
    const sink = new io.Writable({ objectMode: true, write(n, encoding, callback) { actual.push(n); callback(); } });
    await io.promises.pipeline(io.Readable.from(values), map, sink);
    assert.deepEqual(actual, values.map(n => n * 3));
  });
}
test('candidate: private dependent signal is released on every terminal route', async t => {
  const { stream: io, signals } = load(); const controller = new AbortController();
  const writable = new io.Writable({ signal: controller.signal, autoDestroy: false,
    write(chunk, encoding, callback) { callback(); } });
  observed(writable, t); assert.equal(signals.length, 1);
  assert.equal(events.getEventListeners(signals[0], 'abort').length, 1);
  const finish = new Promise(resolve => writable.once('finish', resolve));
  writable.end(); await finish;
  assert.equal(events.getEventListeners(signals[0], 'abort').length, 0);
  assert.equal(signals[0].aborted, true); assert.equal(controller.signal.aborted, false);
  const duplex = new io.Duplex({ signal: controller.signal, read() {},
    write(chunk, encoding, callback) { callback(); } });
  const obs = observed(duplex, t); assert.equal(signals.length, 2, 'one owner for both sides');
  duplex.destroy(); await obs.closed;
  assert.equal(events.getEventListeners(signals[1], 'abort').length, 0);
  const silent = new io.Readable({ signal: controller.signal, emitClose: false, read() {} });
  silent.on('error', () => {}); silent.destroy(); await tick();
  assert.equal(events.getEventListeners(signals[2], 'abort').length, 0);
});
test('candidate: constructor validation does not start asynchronous acquisition', async () => {
  const { stream: io, signals } = load(); let constructs = 0;
  for (const name of ['Readable', 'Writable', 'Duplex', 'Transform', 'PassThrough']) {
    for (const signal of [{}, true, 1, 'not-a-signal']) {
      assert.throws(() => new io[name]({ signal, construct(callback) { constructs++; callback(); } }),
        { code: 'ERR_INVALID_ARG_TYPE' });
    }
  }
  await tick(); assert.equal(constructs, 0); assert.equal(signals.length, 0);
});
test('candidate: repeated successful streams release private listeners without aborting a shared signal', async () => {
  const { stream: io, signals } = load(); const controller = new AbortController();
  for (let i = 0; i < 1024; i++) {
    const stream = new io.Writable({ signal: controller.signal, autoDestroy: false,
      write(chunk, encoding, callback) { callback(); } });
    await new Promise(resolve => { stream.once('finish', resolve); stream.end('x'); });
    assert.equal(events.getEventListeners(signals[i], 'abort').length, 0);
    assert.equal(signals[i].aborted, true); stream.destroy();
  }
  assert.equal(controller.signal.aborted, false);
  assert.equal(events.getEventListeners(controller.signal, 'abort').length, 0);
});
test('candidate: synthetic public events cannot release cancellation ownership', async t => {
  const { stream: io, signals } = load(), controller = new AbortController();
  const stream = new io.Duplex({ signal: controller.signal, read() {}, write(x, e, cb) { cb(); } });
  const obs = observed(stream, t);
  stream.emit('end'); stream.emit('finish'); stream.emit('close');
  controller.signal.dispatchEvent(new Event('abort'));
  assert.equal(stream.destroyed, false);
  assert.equal(events.getEventListeners(signals[0], 'abort').length, 1);
  controller.abort('real'); assert.equal(stream.destroyed, true); await tick();
  aborted(obs.errors[0], 'real');
});
test('candidate: later public signal replacements and propagation cannot hide a real abort', async t => {
  const { stream: io } = load(), controller = new AbortController();
  controller.signal.addEventListener('abort', event => event.stopImmediatePropagation());
  const stream = new io.Readable({ signal: controller.signal, read() {} });
  const obs = observed(stream, t);
  Object.defineProperties(controller.signal, {
    aborted: { get() { throw Error('public aborted'); } },
    reason: { get() { throw Error('public reason'); } }
  });
  controller.abort(false);
  assert.equal(stream.destroyed, true); await obs.closed; aborted(obs.errors[0], false);
});
test('candidate: pre-aborted iterable closes before publishing completion', async t => {
  let next = 0, closed = 0;
  const stream = candidate.Readable.from({ [Symbol.iterator]() { return this; },
    next() { next++; return { value: 'never', done: false }; },
    return() { closed++; return { done: true }; }
  }, { signal: AbortSignal.abort('preflight') });
  const obs = observed(stream, t); assert.equal(stream.destroyed, true); await obs.closed;
  assert.equal(next, 0); assert.equal(closed, 1); aborted(obs.errors[0], 'preflight');
});
test('reference difference: Node 22.16 does not close a pre-aborted from iterator', async t => {
  let closed = 0;
  const stream = node.Readable.from({ [Symbol.iterator]() { return this; },
    next() { return { value: 'never', done: false }; }, return() { closed++; return { done: true }; }
  }, { signal: AbortSignal.abort('preflight') });
  const obs = observed(stream, t); await obs.closed;
  // This records the reference behavior separately; it is not a parity pass.
  assert.equal(closed, 0);
});
test('reference difference: constructor captures signal once; Node 22.16 reads it twice', async t => {
  for (const name of ['Readable', 'Writable', 'Duplex', 'Transform', 'PassThrough']) {
    for (const [io, expected] of [[candidate, 1], [node, 2]]) {
      let reads = 0;
      const signal = new AbortController().signal;
      const stream = new io[name]({ get signal() { reads++; return signal; },
        read() {}, write(x, e, callback) { callback(); } });
      const obs = observed(stream, t); assert.equal(reads, expected);
      stream.destroy(); await obs.closed;
    }
  }
});
test('host boundary: Node AbortSignal intrinsics accept proxy signals and inspect preexisting own properties', () => {
  // This documents the primitive supplied by this host test, not an engine
  // security guarantee. Native Rust accessor behavior must be tested natively.
  const signal = new AbortController().signal;
  const getter = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
  assert.equal(Reflect.apply(getter, new Proxy(signal, {}), []), false);
  const failure = new Error('preexisting property');
  Object.defineProperty(signal, 'aborted', { get() { throw failure; } });
  assert.throws(() => AbortSignal.any([signal]), error => error === failure);
});

// Exercise the production Web adapter together with the complete production
// Node stream state machines. Node supplies Web Streams and host primitives;
// this is not Rust or execution of the engine-owned Web Stream kernel.
const web = require('node:stream/web');
const bridgeSource = fs.readFileSync(process.env.STREAM_BRIDGE_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/stream_web_bridge.js'), 'utf8');
function bridgeCandidate() {
  const core = load().stream;
  assert.notEqual(core.Readable, node.Readable);
  assert.notEqual(core.Writable, node.Writable);
  return new Function('return ' + bridgeSource)()(core, () => web);
}
const adapterKinds = ['Readable', 'Writable', 'Duplex'];
function adapt(io, kind, source, destination, options) {
  return io[kind].fromWeb(kind === 'Readable' ? source : kind === 'Writable' ? destination :
    { readable: source, writable: destination }, options);
}
for (const kind of adapterKinds) {
  for (const timing of ['pre-aborted', 'option-getter', 'before-construction-job']) {
    test(`Web adoption: ${kind} ${timing} waits for acquired endpoint cleanup`,
      { timeout: 3000 }, async () => {
        for (const io of [bridgeCandidate(), node]) {
          const c = new AbortController(), left = deferred(), right = deferred();
          const reason = false, calls = [], errors = [];
          let pulls = 0, writes = 0, closed = false;
          const input = new web.ReadableStream({
            pull() { pulls++; },
            cancel(error) { aborted(error, reason); calls.push('cancel'); return left.promise; }
          }, { highWaterMark: 0 });
          const output = new web.WritableStream({
            write() { writes++; },
            abort(error) { aborted(error, reason); calls.push('abort'); return right.promise; }
          });
          const options = { signal: c.signal };
          if (timing === 'pre-aborted') c.abort(reason);
          if (timing === 'option-getter') Object.defineProperty(options, 'objectMode', {
            get() { c.abort(reason); return false; }
          });
          const stream = adapt(io, kind, input, output, options);
          stream.on('error', error => errors.push(error));
          const completion = new Promise(resolve => stream.once('close', () => { closed = true; resolve(); }));
          if (timing === 'before-construction-job') c.abort(reason);
          assert.equal(stream.destroyed, true);
          await tick();
          assert.deepEqual(calls, kind === 'Readable' ? ['cancel'] : kind === 'Writable' ? ['abort'] : ['cancel', 'abort']);
          assert.equal(closed, false, 'close must not overtake resource release');
          assert.equal(errors.length, 0, 'destruction has not completed');
          assert.equal(pulls, 0); assert.equal(writes, 0);
          left.resolve(); await tick();
          if (kind !== 'Readable') assert.equal(closed, false, 'writable cleanup still pending');
          right.resolve(); await completion;
          assert.equal(errors.length, 1); aborted(errors[0], reason);
          assert.equal(input.locked, kind !== 'Writable');
          assert.equal(output.locked, kind !== 'Readable');
          // Explicit fromWeb adapters retain their established lock ownership.
          c.abort('again'); await tick();
          assert.equal(calls.length, kind === 'Duplex' ? 2 : 1);
        }
      });
  }
}

test('Web adoption: pre-aborted Duplex starts interdependent cancellation algorithms together',
  { timeout: 3000 }, async () => {
    for (const io of [bridgeCandidate(), node]) {
      const c = new AbortController(); c.abort(null);
      const readStarted = deferred(), writeStarted = deferred();
      const calls = [];
      const input = new web.ReadableStream({ cancel(error) {
        aborted(error, null); calls.push('cancel'); readStarted.resolve(); return writeStarted.promise;
      } }, { highWaterMark: 0 });
      const output = new web.WritableStream({ abort(error) {
        aborted(error, null); calls.push('abort'); writeStarted.resolve(); return readStarted.promise;
      } });
      const stream = io.Duplex.fromWeb({ readable: input, writable: output }, { signal: c.signal });
      const errors = []; stream.on('error', e => errors.push(e));
      await new Promise(resolve => stream.once('close', resolve));
      assert.deepEqual(calls, ['cancel', 'abort']); assert.equal(errors.length, 1);
      aborted(errors[0], null);
    }
  });

for (const kind of adapterKinds) {
  test(`Web adoption: ${kind} locked endpoint throws without an orphan abort event`, { timeout: 3000 }, () => {
    // A thrown factory never exposes the intermediate Node stream to callers.
    // A fresh process makes any unhandled error/rejection a hard test failure.
    const { spawnSync } = require('node:child_process');
    for (const role of ['candidate', 'node']) {
      const code = `
        const assert=require('node:assert/strict'),web=require('node:stream/web');
        const core=${JSON.stringify(source)},bridge=${JSON.stringify(bridgeSource)};
        const s=${JSON.stringify(role)}==='node'?require('node:stream'):
          new Function('return '+bridge)()(new Function('__franken_stream_events',
            '__franken_stream_string_decoder','__franken_stream_next_tick','return '+core)(
              require('node:events'),require('node:string_decoder'),f=>process.nextTick(f)),()=>web);
        const c=new AbortController();c.abort('never-owned');let effects=0;
        const r=new web.ReadableStream({cancel(){effects++;}},{highWaterMark:0});
        const w=new web.WritableStream({abort(){effects++;}});
        const kind=${JSON.stringify(kind)};
        const held=kind==='Readable'?r.getReader():w.getWriter();
        assert.throws(()=>s[kind].fromWeb(kind==='Readable'?r:kind==='Writable'?w:
          {readable:r,writable:w},{signal:c.signal}),e=>e.code==='ERR_INVALID_STATE');
        setImmediate(()=>{assert.equal(effects,0);assert.equal(r.locked,kind==='Readable');
          assert.equal(w.locked,kind!=='Readable');held.releaseLock();console.log('NO_ORPHAN');});
      `;
      const result = spawnSync(process.execPath, ['--unhandled-rejections=strict'],
        { input: code, encoding: 'utf8', timeout: 2000 });
      assert.equal(result.status, 0, role + ': ' + result.stderr);
      assert.equal(result.stdout, 'NO_ORPHAN\n'); assert.equal(result.stderr, '');
    }
  });
}

test('Web adoption: pre-aborted source closes its descriptor before pipeline rejection',
  { timeout: 3000 }, async () => {
    for (const io of [bridgeCandidate(), node]) {
      const c = new AbortController(); c.abort('cancel-job');
      const release = deferred(); const receipt = [];
      let closed = false, published = false;
      const source = new web.ReadableStream({ cancel(error) {
        aborted(error, 'cancel-job'); receipt.push('cancel');
        return release.promise.then(() => { receipt.push('release'); });
      } }, { highWaterMark: 0 });
      const input = io.Readable.fromWeb(source, { signal: c.signal });
      input.on('close', () => { closed = true; });
      const output = new io.Writable({
        write(chunk, encoding, done) { receipt.push('unexpected-write'); done(); },
        final(done) { published = true; done(); }
      });
      let settled = false;
      const done = io.promises.pipeline(input, output).then(() => { throw Error('unexpected success'); },
        error => { settled = true; return error; });
      await tick();
      assert.deepEqual(receipt, ['cancel']); assert.equal(settled, false); assert.equal(closed, false);
      release.resolve(); const error = await done;
      aborted(error, 'cancel-job'); assert.deepEqual(receipt, ['cancel', 'release']);
      assert.equal(closed, true); assert.equal(published, false);
    }
  });

test('Web adoption: the no-signal fast path does not add a construction job', () => {
  const io = bridgeCandidate();
  for (const kind of adapterKinds) {
    const r = new web.ReadableStream({}, { highWaterMark: 0 }), w = new web.WritableStream();
    const stream = adapt(io, kind, r, w);
    assert.equal(stream._construct, undefined);
    if (stream._readableState) assert.equal(stream._readableState.constructed, true);
    if (stream._writableState) assert.equal(stream._writableState.constructed, true);
    stream.on('error', () => {}); stream.destroy();
  }
});

// The adapter and both complete stream kernels run together here. This is
// still JavaScript-on-Node: language, Buffer, native emitter/decoder, signals
// and scheduling are host primitives, not a Rust interpreter execution.
const webSource = fs.readFileSync(path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/web_stream_module.js'), 'utf8');
function fullBridgeCandidate() {
  const kernel = new Function('return ' + webSource)();
  const io = new Function('return ' + bridgeSource)()(load().stream, () => kernel);
  assert.notEqual(kernel.ReadableStream, web.ReadableStream);
  assert.notEqual(io.Readable, node.Readable);
  return { io, web: kernel };
}
function fullLanes() {
  return [['node', { io: node, web }], ['engine-kernels', fullBridgeCandidate()]];
}
// Node 22.16's explicit adapters discard an admitted chunk in this race,
// although its direct pipeline(WebReadable, NodeWritable) preserves it. Its
// Duplex also differs in failure cleanup. These five stronger groups are NOT
// parity passes. Strict mode includes Node with the SAME assertions and must
// exit nonzero on that reference; it never rewrites the desired expectations.
const strictDelivery = process.env.STRICT_NODE_STREAM_DELIVERY === '1';
function admissionLanes(directPipeline) {
  return fullLanes().filter(([label]) => directPipeline || strictDelivery || label !== 'node');
}
for (const kind of ['Readable', 'Duplex', 'pipeline']) {
  test(`Shared kernels / reference differences: ${kind} admitted bytes before source failure`,
    { timeout: 3000 }, async () => {
      for (const [label, lane] of admissionLanes(kind === 'pipeline')) {
        const io = lane.io, failure = new Error('after-record'), seen = [];
        let pulls = 0, final = false, abortedWith;
        const source = new lane.web.ReadableStream({ pull(c) {
          pulls++; c.enqueue(Buffer.from('accepted\n')); c.error(failure);
        } }, { highWaterMark: 0 });
        const output = new io.Writable({ write(chunk, encoding, done) {
          seen.push(chunk.toString()); done();
        }, final(done) { final = true; done(); } });
        let input = source;
        if (kind === 'Readable') input = io.Readable.fromWeb(source);
        if (kind === 'Duplex') input = io.Duplex.fromWeb({ readable: source,
          writable: new lane.web.WritableStream({ abort(error) { abortedWith = error; } }) });
        await assert.rejects(io.promises.pipeline(input, output), error => error === failure);
        assert.deepEqual(seen, ['accepted\n'], label);
        assert.equal(pulls, 1); assert.equal(final, false);
        if (kind === 'Duplex') assert.equal(abortedWith, failure);
      }
    });
}

test('Shared kernels / reference differences: object-mode admission retains identity and falsy chunks',
  { timeout: 3000 }, async () => {
    for (const [label, lane] of admissionLanes(false)) {
      for (const chunk of [undefined, false, 0, '', { record: 7 }]) {
        const error = new Error('record boundary'), seen = [];
        const source = new lane.web.ReadableStream({ pull(c) {
          c.enqueue(chunk); c.error(error);
        } }, { highWaterMark: 0 });
        const input = lane.io.Readable.fromWeb(source, { objectMode: true });
        const output = new lane.io.Writable({ objectMode: true,
          write(value, encoding, done) { seen.push(value); done(); } });
        await assert.rejects(lane.io.promises.pipeline(input, output), e => e === error);
        assert.equal(seen.length, 1, label); assert.equal(seen[0], chunk, label);
      }
    }
  });

test('Shared kernels / reference differences: source failure awaits Duplex cleanup after admitted output',
  { timeout: 3000 }, async () => {
    for (const [label, lane] of admissionLanes(false)) {
      const error = new Error('source failed'), release = deferred();
      let abortCalls = 0, settled = false;
      const source = new lane.web.ReadableStream({ pull(c) {
        c.enqueue(Buffer.from('record')); c.error(error);
      } }, { highWaterMark: 0 });
      const destination = new lane.web.WritableStream({ abort(reason) {
        assert.equal(reason, error); abortCalls++; return release.promise;
      } });
      const input = lane.io.Duplex.fromWeb({ readable: source, writable: destination });
      const seen = [];
      const output = new lane.io.Writable({ write(chunk, encoding, done) {
        seen.push(chunk.toString()); done();
      } });
      const completion = lane.io.promises.pipeline(input, output).then(
        () => { settled = true; return undefined; }, reason => { settled = true; return reason; });
      try {
        await tick();
        assert.deepEqual(seen, ['record'], label);
        assert.equal(abortCalls, 1); assert.equal(settled, false);
      } finally { release.resolve(); }
      assert.equal(await completion, error);
      assert.equal(input.closed, true); assert.equal(output.closed, true);
    }
  });

test('Shared kernels / reference difference: destination failure cancels a stalled source immediately',
  { timeout: 3000 }, async () => {
    for (const [label, lane] of admissionLanes(false)) {
      const error = new Error('destination failed'), release = deferred();
      let sourceController, sinkController, pulls = 0, cancels = 0;
      const source = new lane.web.ReadableStream({ start(c) { sourceController = c; },
        pull() { pulls++; }, cancel(reason) {
          assert.equal(reason, error); cancels++; return release.promise;
        } }, { highWaterMark: 0 });
      const destination = new lane.web.WritableStream({ start(c) { sinkController = c; } });
      const input = lane.io.Duplex.fromWeb({ readable: source, writable: destination });
      const seen = [], output = new lane.io.Writable({ write(x, e, done) { seen.push(x); done(); } });
      let settled = false;
      const completion = lane.io.promises.pipeline(input, output).then(
        () => { settled = true; return undefined; }, reason => { settled = true; return reason; });
      try {
        await tick(); assert.equal(pulls, 1, label); sinkController.error(error);
        await tick();
        assert.equal(cancels, 1, label); assert.equal(settled, false);
        assert.throws(() => sourceController.enqueue(Buffer.from('late')), TypeError);
      } finally {
        // Node's reference Duplex does not observe the idle writer failure.
        // Explicit teardown is test cleanup, not a claimed adapter success.
        if (!input.destroyed) input.destroy(error);
        release.resolve();
      }
      assert.equal(await completion, error); assert.deepEqual(seen, []);
    }
  });

test('Shared kernels: caller cancellation still suppresses a late admitted read',
  { timeout: 3000 }, async () => {
    for (const [label, lane] of fullLanes()) {
      const control = new AbortController(); let cancels = 0;
      const source = new lane.web.ReadableStream({ pull(c) {
        c.enqueue(Buffer.from('must-not-publish')); control.abort('stop');
      }, cancel(reason) { aborted(reason, 'stop'); cancels++; } }, { highWaterMark: 0 });
      const input = lane.io.Readable.fromWeb(source, { signal: control.signal });
      const seen = [], output = new lane.io.Writable({ write(x, e, done) { seen.push(x); done(); } });
      await assert.rejects(lane.io.promises.pipeline(input, output), error => {
        aborted(error, 'stop'); return true;
      });
      assert.deepEqual(seen, [], label); assert.equal(cancels, 1, label);
    }
  });

test('Shared kernels: pending and idle read failures propagate without requiring more demand',
  { timeout: 3000 }, async () => {
    for (const [label, lane] of fullLanes()) {
      for (const pending of [false, true]) {
        const error = new Error('no chunk'), errors = []; let controller;
        const source = new lane.web.ReadableStream({ start(c) { controller = c; } }, { highWaterMark: 0 });
        const input = lane.io.Readable.fromWeb(source);
        input.on('error', e => errors.push(e));
        const closed = new Promise(resolve => input.once('close', resolve));
        if (pending) input.read(0);
        controller.error(error); await closed;
        assert.deepEqual(errors, [error], label); assert.equal(input.closed, true);
      }
    }
  });

test('Shared kernels: ordinary close preserves the last byte chunk and successful finalization',
  { timeout: 3000 }, async () => {
    for (const [label, lane] of fullLanes()) {
      const seen = []; let final = 0;
      const source = new lane.web.ReadableStream({ pull(c) {
        c.enqueue(Buffer.from('last')); c.close();
      } }, { highWaterMark: 0 });
      const output = new lane.io.Writable({ write(chunk, e, done) { seen.push(chunk.toString()); done(); },
        final(done) { final++; done(); } });
      await lane.io.promises.pipeline(lane.io.Readable.fromWeb(source), output);
      assert.deepEqual(seen, ['last'], label); assert.equal(final, 1);
    }
  });

test('Shared kernels: fragmented transforms respect slow Node destination demand',
  { timeout: 5000 }, async () => {
    for (const [label, lane] of fullLanes()) {
      let next = 0, expected = 0, active = 0, peak = 0, sum = 0;
      const source = new lane.web.ReadableStream({ pull(c) {
        if (next === 1024) c.close(); else c.enqueue(next++);
      } }, { highWaterMark: 0 });
      const transform = new lane.web.TransformStream({ transform(value, c) {
        c.enqueue(value * 2); c.enqueue(value * 2 + 1);
      } });
      const output = new lane.io.Writable({ objectMode: true, highWaterMark: 1,
        write(value, encoding, done) {
          assert.equal(value, expected++, label); sum += value;
          peak = Math.max(peak, ++active);
          setImmediate(() => { active--; done(); });
        } });
      await lane.io.promises.pipeline(source, transform, output);
      assert.equal(expected, 2048); assert.equal(sum, 2096128); assert.equal(peak, 1);
    }
  });

test('Shared kernels: falsy source failures retain their cause after accepted output',
  { timeout: 3000 }, async () => {
    // Err-first Node callbacks cannot carry these rejection values. This is
    // the existing explicit failure-wrapper contract, not Node parity.
    for (const reason of [undefined, null, false, 0, '']) {
      const lane = fullBridgeCandidate(), seen = [];
      const source = new lane.web.ReadableStream({ pull(c) {
        c.enqueue(Buffer.from('prefix')); c.error(reason);
      } }, { highWaterMark: 0 });
      const input = lane.io.Readable.fromWeb(source);
      const output = new lane.io.Writable({ write(chunk, encoding, done) { seen.push(chunk.toString()); done(); } });
      await assert.rejects(lane.io.promises.pipeline(input, output), error =>
        error.code === 'ERR_STREAM_WEB' && Object.hasOwn(error, 'cause') && error.cause === reason);
      assert.deepEqual(seen, ['prefix']);
    }
  });
