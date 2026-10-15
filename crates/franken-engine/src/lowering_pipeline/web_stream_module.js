(function () {
  'use strict';
  // Default-mode WHATWG streams, executed by the native interpreter. Queues,
  // callbacks and promise jobs use its ordinary heap/work accounting. There
  // is no host stream implementation, I/O permission or external evaluator.
  // Byte/BYOB streams and transferable streams are deliberately unsupported.
  const P = Promise;
  const resolvePromise = Promise.resolve;
  const promiseThen = Promise.prototype.then;
  const apply = Reflect.apply;
  const create = Object.create;
  const define = Object.defineProperty;
  const NativeTypeError = TypeError;
  const NativeRangeError = RangeError;
  const Weak = WeakMap;
  const weakGet = WeakMap.prototype.get;
  const weakSet = WeakMap.prototype.set;
  const iteratorKey = Symbol.iterator;
  const asyncIteratorKey = Symbol.asyncIterator;
  const tagKey = Symbol.toStringTag;
  const Abort = AbortController;
  const abortController = AbortController.prototype.abort;
  const controllerSignal = Object.getOwnPropertyDescriptor(AbortController.prototype, 'signal').get;
  const signalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
  const signalReason = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'reason').get;
  const Signals = AbortSignal;
  const anySignal = AbortSignal.any;
  const listen = EventTarget.prototype.addEventListener;
  const unlisten = EventTarget.prototype.removeEventListener;
  const streams = new Weak();
  const readers = new Weak();
  const controllers = new Weak();
  const strategies = new Weak();
  const sinks = new Weak();
  const writers = new Weak();
  const writeControllers = new Weak();
  const transforms = new Weak();
  const transformControllers = new Weak();
  const token = {};

  function invalid(message) { return new NativeTypeError(message); }
  function resolved(value) { return apply(resolvePromise, P, [value]); }
  function rejected(reason) { return new P(function (resolve, reject) { reject(reason); }); }
  function then(promise, success, failure) { return apply(promiseThen, promise, [success, failure]); }
  function handled(promise) { then(promise, undefined, function () {}); return promise; }
  function deferred(internal) {
    const d = create(null);
    d.pending = true;
    d.promise = new P(function (resolve, reject) {
      d.resolve = function (value) { if (d.pending) { d.pending = false; resolve(value); } };
      d.reject = function (error) { if (d.pending) { d.pending = false; reject(error); } };
    });
    if (internal) handled(d.promise);
    return d;
  }
  function get(map, value, name) {
    const state = apply(weakGet, map, [value]);
    if (state === undefined) throw invalid('Invalid ' + name + ' receiver');
    return state;
  }
  function set(map, value, state) { apply(weakSet, map, [value, state]); }
  function dictionary(value, name) {
    if (value === undefined || value === null) return create(null);
    if (typeof value !== 'object' && typeof value !== 'function') throw invalid(name + ' must be an object');
    return value;
  }
  function method(object, name) {
    const value = object[name];
    if (value === undefined) return undefined;
    if (typeof value !== 'function') throw invalid(name + ' must be a function');
    return value;
  }
  function invoke(fn, receiver, args) { return fn === undefined ? undefined : apply(fn, receiver, args); }
  function promised(fn, receiver, args) {
    try { return resolved(invoke(fn, receiver, args)); } catch (error) { return rejected(error); }
  }
  function queue() { return { head: undefined, tail: undefined, length: 0, total: 0 }; }
  function push(q, value, size) {
    const node = { value: value, size: size, next: undefined };
    if (q.tail === undefined) q.head = node; else q.tail.next = node;
    q.tail = node; q.length++; q.total += size;
  }
  function shift(q) {
    const node = q.head;
    q.head = node.next;
    if (q.head === undefined) q.tail = undefined;
    node.next = undefined; q.length--; q.total -= node.size;
    if (q.total < 0 || q.length === 0) q.total = 0;
    return node.value;
  }
  function clear(q) { q.head = undefined; q.tail = undefined; q.length = 0; q.total = 0; }
  function strategy(value, fallback) {
    const object = dictionary(value, 'strategy');
    const size = method(object, 'size');
    const h = object.highWaterMark;
    const highWaterMark = h === undefined ? fallback : +h;
    if (!(highWaterMark >= 0)) throw new NativeRangeError('Invalid highWaterMark');
    return { size: size, highWaterMark: highWaterMark };
  }
  function chunkSize(size, chunk) {
    const value = size === undefined ? 1 : +apply(size, undefined, [chunk]);
    if (!(value >= 0) || value === Infinity) throw new NativeRangeError('Invalid chunk size');
    return value;
  }
  function property(object, name, value) {
    const descriptor = create(null);
    descriptor.value = value; descriptor.writable = true; descriptor.configurable = true;
    define(object, name, descriptor);
  }
  function result(value, done) { return { value: value, done: done }; }

  function releaseSource(s) { s.source = undefined; s.pull = undefined; s.cancel = undefined; s.size = undefined; }
  function closeReadable(s) {
    s.state = 'closed';
    releaseSource(s);
    if (s.reader !== undefined) {
      const r = get(readers, s.reader, 'reader');
      r.closed.resolve();
      while (r.requests.length !== 0) shift(r.requests).resolve(result(undefined, true));
    }
  }
  function errorReadable(s, error) {
    if (s.state !== 'readable') return;
    s.state = 'errored'; s.error = error;
    clear(s.queue); releaseSource(s);
    if (s.reader !== undefined) {
      const r = get(readers, s.reader, 'reader');
      r.closed.reject(error);
      while (r.requests.length !== 0) shift(r.requests).reject(error);
    }
  }
  function canEnqueue(s) { return s.state === 'readable' && !s.closeRequested; }
  function needsPull(s) {
    return canEnqueue(s) && s.started &&
      ((s.reader !== undefined && get(readers, s.reader, 'reader').requests.length !== 0) ||
        s.highWaterMark - s.queue.total > 0);
  }
  function pull(s) {
    if (!needsPull(s)) return;
    if (s.pulling) { s.pullAgain = true; return; }
    s.pulling = true;
    then(promised(s.pull, s.source, [s.controller]), function () {
      s.pulling = false;
      if (s.pullAgain) { s.pullAgain = false; pull(s); }
    }, function (error) { s.pulling = false; errorReadable(s, error); });
  }
  function enqueue(s, value) {
    if (!canEnqueue(s)) throw invalid('Stream is closed or closing');
    if (s.reader !== undefined && get(readers, s.reader, 'reader').requests.length !== 0) {
      shift(get(readers, s.reader, 'reader').requests).resolve(result(value, false));
    } else {
      try {
        const size = chunkSize(s.size, value);
        // A size callback may reenter cancel/error/close. Never resurrect its
        // queue or publish after a terminal transition.
        if (!canEnqueue(s)) throw invalid('Stream changed while sizing a chunk');
        push(s.queue, value, size);
      } catch (error) { errorReadable(s, error); throw error; }
    }
    pull(s);
  }
  function cancelReadable(s, reason) {
    s.disturbed = true;
    if (s.state === 'closed') return resolved();
    if (s.state === 'errored') return rejected(s.error);
    const algorithm = s.cancel, source = s.source;
    clear(s.queue); closeReadable(s);
    return then(promised(algorithm, source, [reason]), function () {});
  }
  function read(r, receive) {
    if (r.stream === undefined) return rejected(invalid('Reader lock is released'));
    const s = get(streams, r.stream, 'stream');
    s.disturbed = true;
    if (s.state === 'closed') {
      const item = result(undefined, true);
      if (receive !== undefined) receive(item);
      return resolved(item);
    }
    if (s.state === 'errored') return rejected(s.error);
    if (s.queue.length !== 0) {
      const value = shift(s.queue);
      const item = result(value, false);
      if (receive !== undefined) receive(item);
      if (s.closeRequested && s.queue.length === 0) closeReadable(s); else pull(s);
      return resolved(item);
    }
    const request = deferred(false);
    if (receive !== undefined) {
      const publish = request.resolve;
      request.resolve = function (item) {
        if (request.pending) receive(item);
        publish(item);
      };
    }
    push(r.requests, request, 0); pull(s);
    return request.promise;
  }
  function releaseReader(r) {
    if (r.stream === undefined) return;
    const s = get(streams, r.stream, 'stream');
    const error = invalid('Reader lock is released');
    if (!r.closed.pending) r.closed = deferred(true);
    r.closed.reject(error);
    s.reader = undefined; r.stream = undefined;
    while (r.requests.length !== 0) shift(r.requests).reject(error);
  }
  class ReadableStreamDefaultController {
    constructor(key, state) {
      if (key !== token) throw invalid('Illegal constructor');
      set(controllers, this, state);
    }
    get desiredSize() {
      const s = get(controllers, this, 'ReadableStreamDefaultController');
      return s.state === 'errored' ? null : s.state === 'closed' ? 0 : s.highWaterMark - s.queue.total;
    }
    close() {
      const s = get(controllers, this, 'ReadableStreamDefaultController');
      if (!canEnqueue(s)) throw invalid('Stream is closed or closing');
      s.closeRequested = true;
      if (s.queue.length === 0) closeReadable(s);
    }
    enqueue(chunk) { enqueue(get(controllers, this, 'ReadableStreamDefaultController'), chunk); }
    error(reason) { errorReadable(get(controllers, this, 'ReadableStreamDefaultController'), reason); }
  }
  class ReadableStreamDefaultReader {
    constructor(stream) {
      const s = get(streams, stream, 'ReadableStream');
      if (s.reader !== undefined) throw invalid('ReadableStream is locked');
      const r = { stream: stream, requests: queue(), closed: deferred(true) };
      set(readers, this, r); s.reader = this;
      if (s.state === 'closed') r.closed.resolve();
      else if (s.state === 'errored') r.closed.reject(s.error);
    }
    get closed() {
      try { return get(readers, this, 'ReadableStreamDefaultReader').closed.promise; }
      catch (error) { return rejected(error); }
    }
    read() {
      try { return read(get(readers, this, 'ReadableStreamDefaultReader')); }
      catch (error) { return rejected(error); }
    }
    cancel(reason) {
      try {
        const r = get(readers, this, 'ReadableStreamDefaultReader');
        if (r.stream === undefined) throw invalid('Reader lock is released');
        return cancelReadable(get(streams, r.stream, 'ReadableStream'), reason);
      } catch (error) { return rejected(error); }
    }
    releaseLock() { releaseReader(get(readers, this, 'ReadableStreamDefaultReader')); }
  }
  class ReadableStream {
    constructor(underlyingSource, queuingStrategy) {
      const source = dictionary(underlyingSource, 'underlyingSource');
      const cancel = method(source, 'cancel');
      const pullAlgorithm = method(source, 'pull');
      const start = method(source, 'start');
      if (source.type !== undefined) throw new NativeRangeError('Byte streams are not supported');
      const config = strategy(queuingStrategy, 1);
      const s = { state: 'readable', error: undefined, reader: undefined,
        queue: queue(), closeRequested: false, started: false, pulling: false,
        pullAgain: false, disturbed: false, source: source, cancel: cancel,
        pull: pullAlgorithm, size: config.size, highWaterMark: config.highWaterMark,
        controller: undefined };
      s.controller = new ReadableStreamDefaultController(token, s);
      set(streams, this, s);
      // start is synchronous and a synchronous exception escapes construction.
      const started = invoke(start, source, [s.controller]);
      then(resolved(started), function () { s.started = true; pull(s); },
        function (error) { errorReadable(s, error); });
    }
    get locked() { return get(streams, this, 'ReadableStream').reader !== undefined; }
    getReader(options) {
      get(streams, this, 'ReadableStream');
      const mode = dictionary(options, 'options').mode;
      if (mode !== undefined) throw new NativeRangeError('BYOB readers are not supported');
      return new ReadableStreamDefaultReader(this);
    }
    cancel(reason) {
      try {
        const s = get(streams, this, 'ReadableStream');
        if (s.reader !== undefined) throw invalid('ReadableStream is locked');
        return cancelReadable(s, reason);
      } catch (error) { return rejected(error); }
    }
    pipeTo(destination, options) {
      try { return pipe(this, destination, pipeOptions(options)); }
      catch (error) { return rejected(error); }
    }
    pipeThrough(transform, options) {
      const pair = dictionary(transform, 'transform');
      const readable = pair.readable, writable = pair.writable;
      get(streams, readable, 'ReadableStream');
      handled(pipe(this, writable, pipeOptions(options)));
      return readable;
    }
    values(options) {
      get(streams, this, 'ReadableStream');
      const preventCancel = !!dictionary(options, 'options').preventCancel;
      const reader = new ReadableStreamDefaultReader(this);
      const r = get(readers, reader, 'ReadableStreamDefaultReader');
      let done = false;
      let tail = resolved();
      function serialized(action) {
        const promise = then(tail, action);
        tail = then(promise, function () {}, function () {});
        return promise;
      }
      const iterator = {
        next: function () { return serialized(function () {
          if (done) return result(undefined, true);
          return then(read(r), function (value) {
            if (value.done) { done = true; releaseReader(r); }
            return value;
          }, function (error) { done = true; releaseReader(r); throw error; });
        }); },
        return: function (value) { return serialized(function () {
          if (done) return result(value, true);
          done = true;
          let promise;
          try {
            promise = preventCancel ? resolved() : cancelReadable(get(streams, r.stream, 'ReadableStream'), value);
          } finally { releaseReader(r); }
          return then(promise, function () { return result(value, true); });
        }); }
      };
      property(iterator, asyncIteratorKey, function () { return this; });
      return iterator;
    }
    static from(iterable) {
      if (iterable === null || iterable === undefined) throw invalid('Value is not iterable');
      let iteratorMethod = iterable[asyncIteratorKey];
      let synchronous = false;
      if (iteratorMethod === undefined || iteratorMethod === null) {
        iteratorMethod = iterable[iteratorKey]; synchronous = true;
      }
      if (typeof iteratorMethod !== 'function') throw invalid('Value is not iterable');
      const iterator = apply(iteratorMethod, iterable, []);
      if (iterator === null || (typeof iterator !== 'object' && typeof iterator !== 'function')) throw invalid('Invalid iterator');
      const next = method(iterator, 'next');
      if (next === undefined) throw invalid('Iterator has no next method');
      return new ReadableStream({
        pull: function (controller) {
          return then(promised(next, iterator, []), function (item) {
            if (item === null || (typeof item !== 'object' && typeof item !== 'function')) throw invalid('Invalid iterator result');
            if (item.done) { controller.close(); return; }
            if (synchronous) return then(resolved(item.value), function (value) { controller.enqueue(value); });
            controller.enqueue(item.value);
          });
        },
        cancel: function (reason) {
          const finish = method(iterator, 'return');
          if (finish === undefined) return;
          return then(promised(finish, iterator, [reason]), function (item) {
            if (item === null || (typeof item !== 'object' && typeof item !== 'function')) throw invalid('Invalid iterator return result');
          });
        }
      }, { highWaterMark: 0 });
    }
  }
  const readableValues = ReadableStream.prototype.values;
  property(ReadableStream.prototype, asyncIteratorKey, readableValues);

  // A queued write remains counted while its sink callback is in flight.
  // Only one callback is active; erroring waits for it (and start) before
  // rejecting later writes. Releasing a writer does not revoke accepted work.
  function writerState(s) { return s.writer === undefined ? undefined : get(writers, s.writer, 'writer'); }
  function rejectLifecycle(w, name, reason) {
    if (!w[name].pending) w[name] = deferred(true);
    w[name].reject(reason);
  }
  function sinkPressure(s) {
    const pressured = s.highWaterMark - s.queue.total <= 0;
    if (s.state !== 'writable' || s.closing || pressured === s.backpressure) return;
    s.backpressure = pressured;
    const w = writerState(s);
    if (w !== undefined) {
      if (pressured) w.ready = deferred(true); else w.ready.resolve();
    }
  }
  function releaseSink(s) { s.sink = undefined; s.write = undefined; s.close = undefined; s.abort = undefined; s.size = undefined; }
  function rejectSinkClosure(s) {
    if (s.closeRequest !== undefined) { s.closeRequest.reject(s.error); s.closeRequest = undefined; }
    const w = writerState(s);
    if (w !== undefined) w.closed.reject(s.error);
  }
  function finishErroring(s) {
    if (s.state !== 'erroring' || !s.started || s.inflight !== undefined) return;
    s.state = 'errored';
    while (s.queue.length !== 0) {
      const request = shift(s.queue);
      if (!request.close) request.done.reject(s.error);
    }
    const abort = s.pendingAbort;
    s.pendingAbort = undefined;
    if (abort === undefined || abort.alreadyErroring) {
      if (abort !== undefined) abort.done.reject(s.error);
      releaseSink(s); rejectSinkClosure(s); return;
    }
    const completion = promised(s.abort, s.sink, [abort.reason]);
    releaseSink(s);
    then(completion, function () { abort.done.resolve(); rejectSinkClosure(s); },
      function (error) { abort.done.reject(error); rejectSinkClosure(s); });
  }
  function errorSink(s, reason) {
    if (s.state === 'writable') {
      s.state = 'erroring'; s.error = reason;
      const w = writerState(s);
      if (w !== undefined) rejectLifecycle(w, 'ready', reason);
    }
    finishErroring(s);
  }
  function controllerErrorSink(s, reason) {
    if (s.state !== 'writable') return;
    releaseSink(s); errorSink(s, reason);
  }
  function advanceSink(s) {
    if (!s.started || s.inflight !== undefined) return;
    if (s.state === 'erroring') { finishErroring(s); return; }
    if (s.state !== 'writable' || s.queue.length === 0) return;
    const request = s.queue.head.value;
    s.inflight = request;
    if (request.close) {
      s.closeRequest = undefined;
      const completion = promised(s.close, s.sink, []);
      releaseSink(s);
      then(completion, function () {
        shift(s.queue); s.inflight = undefined;
        // A successful in-flight close wins a concurrent abort/error request.
        s.state = 'closed'; s.error = undefined;
        request.done.resolve();
        if (s.pendingAbort !== undefined) { s.pendingAbort.done.resolve(); s.pendingAbort = undefined; }
        const w = writerState(s);
        if (w !== undefined) w.closed.resolve();
      }, function (error) {
        shift(s.queue); s.inflight = undefined; request.done.reject(error);
        if (s.pendingAbort !== undefined) { s.pendingAbort.done.reject(error); s.pendingAbort = undefined; }
        errorSink(s, error);
      });
    } else {
      then(promised(s.write, s.sink, [request.chunk, s.controller]), function () {
        shift(s.queue); s.inflight = undefined; request.done.resolve();
        sinkPressure(s); advanceSink(s);
      }, function (error) {
        shift(s.queue); s.inflight = undefined; request.done.reject(error);
        if (s.state === 'writable') releaseSink(s);
        errorSink(s, error);
      });
    }
  }
  function write(w, chunk) {
    const stream = w.stream;
    if (stream === undefined) return rejected(invalid('Writer lock is released'));
    const s = get(sinks, stream, 'WritableStream');
    let size;
    try { size = chunkSize(s.size, chunk); }
    catch (error) { controllerErrorSink(s, error); size = 1; }
    // Size is user code: it can release the lock, close, abort or error.
    if (w.stream !== stream) return rejected(invalid('Writer lock is released'));
    if (s.state === 'erroring' || s.state === 'errored') return rejected(s.error);
    if (s.state === 'closed' || s.closing) return rejected(invalid('WritableStream is closed or closing'));
    const done = deferred(false);
    push(s.queue, { chunk: chunk, done: done, close: false }, size);
    sinkPressure(s); advanceSink(s);
    return done.promise;
  }
  function closeSink(s) {
    if (s.state === 'closed' || s.state === 'errored' || s.closing) return rejected(invalid('WritableStream is closed or closing'));
    const done = deferred(false);
    s.closing = true; s.closeRequest = done;
    const w = writerState(s);
    if (w !== undefined && s.state === 'writable') w.ready.resolve();
    push(s.queue, { close: true, done: done }, 0); advanceSink(s);
    return done.promise;
  }
  function abortSink(s, reason) {
    if (s.state === 'closed' || s.state === 'errored') return resolved();
    apply(abortController, s.abortController, [reason]);
    // Signal listeners can reenter abort/error/close before this request exists.
    if (s.state === 'closed' || s.state === 'errored') return resolved();
    if (s.pendingAbort !== undefined) return s.pendingAbort.done.promise;
    const done = deferred(false);
    const alreadyErroring = s.state === 'erroring';
    s.pendingAbort = { done: done, reason: alreadyErroring ? undefined : reason, alreadyErroring: alreadyErroring };
    if (!alreadyErroring) errorSink(s, reason);
    return done.promise;
  }
  function releaseWriter(w) {
    if (w.stream === undefined) return;
    const s = get(sinks, w.stream, 'WritableStream');
    const reason = invalid('Writer lock is released');
    rejectLifecycle(w, 'ready', reason); rejectLifecycle(w, 'closed', reason);
    s.writer = undefined; w.stream = undefined;
  }
  class WritableStreamDefaultController {
    constructor(key, state) {
      if (key !== token) throw invalid('Illegal constructor');
      set(writeControllers, this, state);
    }
    get signal() { return apply(controllerSignal, get(writeControllers, this, 'WritableStreamDefaultController').abortController, []); }
    error(reason) {
      const s = get(writeControllers, this, 'WritableStreamDefaultController');
      controllerErrorSink(s, reason);
    }
  }
  class WritableStreamDefaultWriter {
    constructor(stream) {
      const s = get(sinks, stream, 'WritableStream');
      if (s.writer !== undefined) throw invalid('WritableStream is locked');
      const w = { stream: stream, ready: deferred(true), closed: deferred(true) };
      set(writers, this, w); s.writer = this;
      if (s.state === 'errored' || s.state === 'erroring') w.ready.reject(s.error);
      else if (s.state === 'closed' || s.closing || !s.backpressure) w.ready.resolve();
      if (s.state === 'closed') w.closed.resolve();
      else if (s.state === 'errored') w.closed.reject(s.error);
    }
    get closed() { try { return get(writers, this, 'WritableStreamDefaultWriter').closed.promise; } catch (error) { return rejected(error); } }
    get ready() { try { return get(writers, this, 'WritableStreamDefaultWriter').ready.promise; } catch (error) { return rejected(error); } }
    get desiredSize() {
      const w = get(writers, this, 'WritableStreamDefaultWriter');
      if (w.stream === undefined) throw invalid('Writer lock is released');
      const s = get(sinks, w.stream, 'WritableStream');
      return s.state === 'errored' || s.state === 'erroring' ? null : s.state === 'closed' ? 0 : s.highWaterMark - s.queue.total;
    }
    write(chunk) { try { return write(get(writers, this, 'WritableStreamDefaultWriter'), chunk); } catch (error) { return rejected(error); } }
    close() {
      try {
        const w = get(writers, this, 'WritableStreamDefaultWriter');
        if (w.stream === undefined) throw invalid('Writer lock is released');
        return closeSink(get(sinks, w.stream, 'WritableStream'));
      } catch (error) { return rejected(error); }
    }
    abort(reason) {
      try {
        const w = get(writers, this, 'WritableStreamDefaultWriter');
        if (w.stream === undefined) throw invalid('Writer lock is released');
        return abortSink(get(sinks, w.stream, 'WritableStream'), reason);
      } catch (error) { return rejected(error); }
    }
    releaseLock() { releaseWriter(get(writers, this, 'WritableStreamDefaultWriter')); }
  }
  class WritableStream {
    constructor(underlyingSink, queuingStrategy) {
      const sink = dictionary(underlyingSink, 'underlyingSink');
      const abort = method(sink, 'abort'), close = method(sink, 'close');
      const start = method(sink, 'start'), writeAlgorithm = method(sink, 'write');
      if (sink.type !== undefined) throw new NativeRangeError('Typed writable sinks are not supported');
      const config = strategy(queuingStrategy, 1);
      const s = { state: 'writable', error: undefined, writer: undefined, started: false,
        queue: queue(), inflight: undefined, closing: false, closeRequest: undefined,
        pendingAbort: undefined, sink: sink, write: writeAlgorithm, close: close, abort: abort,
        size: config.size, highWaterMark: config.highWaterMark, backpressure: config.highWaterMark === 0,
        abortController: new Abort(), controller: undefined };
      s.controller = new WritableStreamDefaultController(token, s);
      set(sinks, this, s);
      const started = invoke(start, sink, [s.controller]);
      then(resolved(started), function () { s.started = true; advanceSink(s); },
        function (error) { s.started = true; errorSink(s, error); });
    }
    get locked() { return get(sinks, this, 'WritableStream').writer !== undefined; }
    getWriter() { return new WritableStreamDefaultWriter(this); }
    abort(reason) {
      try {
        const s = get(sinks, this, 'WritableStream');
        if (s.writer !== undefined) throw invalid('WritableStream is locked');
        return abortSink(s, reason);
      } catch (error) { return rejected(error); }
    }
    close() {
      try {
        const s = get(sinks, this, 'WritableStream');
        if (s.writer !== undefined) throw invalid('WritableStream is locked');
        return closeSink(s);
      } catch (error) { return rejected(error); }
    }
  }

  function pipeOptions(value) {
    const options = dictionary(value, 'options');
    const preventAbort = !!options.preventAbort;
    const preventCancel = !!options.preventCancel;
    const preventClose = !!options.preventClose;
    const signal = options.signal;
    if (signal !== undefined) apply(signalAborted, signal, []);
    return { preventAbort: preventAbort, preventCancel: preventCancel, preventClose: preventClose, signal: signal };
  }

  // TransformStream uses these same reader/writer state machines. A change
  // promise hands demand from the readable side to a blocked write; it does
  // not pre-collect input, run callbacks concurrently or spin microtasks.
  function transformPressure(t, value) {
    if (t.backpressure === value) return;
    t.changed.resolve(); t.changed = deferred(true); t.backpressure = value;
  }
  function clearTransform(t) { t.receiver = undefined; t.transform = undefined; t.flush = undefined; t.cancel = undefined; }
  function errorTransform(t, reason) {
    errorReadable(t.readState, reason); controllerErrorSink(t.writeState, reason);
    clearTransform(t); transformPressure(t, false);
  }
  function enqueueTransform(t, value) {
    try { enqueue(t.readState, value); }
    catch (error) { errorTransform(t, error); throw error; }
    if (!needsPull(t.readState)) transformPressure(t, true);
  }
  function performTransform(t, value) {
    if (t.writeState.state !== 'writable') return rejected(t.writeState.error);
    let promise;
    if (t.transform === undefined) {
      try { enqueueTransform(t, value); promise = resolved(); }
      catch (error) { promise = rejected(error); }
    } else promise = promised(t.transform, t.receiver, [value, t.controller]);
    return then(promise, undefined, function (error) { errorTransform(t, error); throw error; });
  }
  function finishTransform(t, kind, reason) {
    if (t.finish !== undefined) return t.finish.promise;
    const finish = deferred(false);
    t.finish = finish;
    const promise = kind === 'close' ? promised(t.flush, t.receiver, [t.controller]) :
      promised(t.cancel, t.receiver, [reason]);
    clearTransform(t);
    then(promise, function () {
      if (kind === 'cancel') {
        if (t.writeState.state === 'errored') { finish.reject(t.writeState.error); return; }
        controllerErrorSink(t.writeState, reason); transformPressure(t, false); finish.resolve();
      } else {
        if (t.readState.state === 'errored') { finish.reject(t.readState.error); return; }
        if (kind === 'close') {
          if (canEnqueue(t.readState)) {
            t.readState.closeRequested = true;
            if (t.readState.queue.length === 0) closeReadable(t.readState);
          }
        } else errorReadable(t.readState, reason);
        finish.resolve();
      }
    }, function (error) {
      if (kind === 'cancel') { controllerErrorSink(t.writeState, error); transformPressure(t, false); }
      else errorReadable(t.readState, error);
      finish.reject(error);
    });
    return finish.promise;
  }
  class TransformStreamDefaultController {
    constructor(key, state) {
      if (key !== token) throw invalid('Illegal constructor');
      set(transformControllers, this, state);
    }
    get desiredSize() {
      const t = get(transformControllers, this, 'TransformStreamDefaultController');
      const s = t.readState;
      return s.state === 'errored' ? null : s.state === 'closed' ? 0 : s.highWaterMark - s.queue.total;
    }
    enqueue(value) { enqueueTransform(get(transformControllers, this, 'TransformStreamDefaultController'), value); }
    error(reason) { errorTransform(get(transformControllers, this, 'TransformStreamDefaultController'), reason); }
    terminate() {
      const t = get(transformControllers, this, 'TransformStreamDefaultController');
      if (canEnqueue(t.readState)) {
        t.readState.closeRequested = true;
        if (t.readState.queue.length === 0) closeReadable(t.readState);
      }
      controllerErrorSink(t.writeState, invalid('TransformStream is terminated'));
      clearTransform(t); transformPressure(t, false);
    }
  }
  class TransformStream {
    constructor(transformer, writableStrategy, readableStrategy) {
      const receiver = dictionary(transformer, 'transformer');
      const cancel = method(receiver, 'cancel'), flush = method(receiver, 'flush');
      const start = method(receiver, 'start'), transform = method(receiver, 'transform');
      if (receiver.readableType !== undefined || receiver.writableType !== undefined) throw new NativeRangeError('Typed transform streams are not supported');
      const writable = strategy(writableStrategy, 1), readable = strategy(readableStrategy, 0);
      const started = deferred(true);
      const t = { receiver: receiver, transform: transform, flush: flush, cancel: cancel,
        readable: undefined, writable: undefined, readState: undefined, writeState: undefined,
        controller: undefined, backpressure: true, changed: deferred(true), finish: undefined };
      const sink = create(null), source = create(null);
      sink.start = function () { return started.promise; };
      sink.write = function (value) {
        return t.backpressure ? then(t.changed.promise, function () { return performTransform(t, value); }) : performTransform(t, value);
      };
      sink.close = function () { return finishTransform(t, 'close'); };
      sink.abort = function (reason) { return finishTransform(t, 'abort', reason); };
      source.start = function () { return started.promise; };
      source.pull = function () { transformPressure(t, false); return t.changed.promise; };
      source.cancel = function (reason) { return finishTransform(t, 'cancel', reason); };
      t.writable = new WritableStream(sink, writable);
      t.writeState = get(sinks, t.writable, 'WritableStream');
      t.readable = new ReadableStream(source, readable);
      t.readState = get(streams, t.readable, 'ReadableStream');
      t.controller = new TransformStreamDefaultController(token, t);
      set(transforms, this, t);
      started.resolve(invoke(start, receiver, [t.controller]));
    }
    get readable() { return get(transforms, this, 'TransformStream').readable; }
    get writable() { return get(transforms, this, 'TransformStream').writable; }
  }
  function pipe(source, destination, config) {
    const s = get(streams, source, 'ReadableStream');
    const d = get(sinks, destination, 'WritableStream');
    if (s.reader !== undefined || d.writer !== undefined) throw invalid('Pipe endpoint is locked');
    const reader = new ReadableStreamDefaultReader(source);
    const writer = new WritableStreamDefaultWriter(destination);
    const r = get(readers, reader, 'reader'), w = get(writers, writer, 'writer');
    const completion = deferred(false);
    let stopping = false, reading = false, sourceEnded = false;
    let lastWrite = resolved();
    let pendingItem;
    let tracked, ownAbort;
    s.disturbed = true;
    function finish(failed, reason) {
      if (tracked !== undefined) {
        apply(unlisten, tracked, ['abort', onAbort]);
        apply(abortController, ownAbort, []);
      }
      pendingItem = undefined;
      releaseReader(r); releaseWriter(w);
      if (failed) completion.reject(reason); else completion.resolve();
    }
    function bothActions(first, second) {
      // Start both cleanup operations before awaiting either. Observe both
      // rejections even when the first fails; never leave a rejected sibling.
      return new P(function (resolve, reject) {
        let remaining = 2;
        function success() { if (--remaining === 0) resolve(); }
        then(first, success, reject); then(second, success, reject);
      });
    }
    function shutdown(kind, reason) {
      if (stopping) return;
      stopping = true;
      // A read can publish synchronously, then source.error/abort can run
      // before its Promise reaction. Shutdown must write that admitted chunk
      // once before cleanup, without waiting on a still-unfulfilled read.
      if (pendingItem !== undefined && !pendingItem.done && d.state === 'writable' && !d.closing) {
        const item = pendingItem; pendingItem = undefined;
        lastWrite = write(w, item.value);
      }
      // Accepted writes finish before normal close/source-error cleanup. An
      // already-erroring sink owns its own in-flight drain and must not block
      // cancelling a source whose next read will never arrive.
      const pending = d.state === 'writable' && !d.closing ? lastWrite : resolved();
      const wait = then(pending, function () {}, function () {});
      then(wait, function () {
        let action;
        if (kind === 'end') action = config.preventClose || d.state === 'closed' || d.closing ? resolved() :
          d.state === 'errored' ? rejected(d.error) : closeSink(d);
        else if (kind === 'source') action = config.preventAbort || d.state !== 'writable' ? resolved() : abortSink(d, reason);
        else if (kind === 'destination') action = config.preventCancel ? resolved() : cancelReadable(s, reason);
        else action = bothActions(
          config.preventAbort || d.state !== 'writable' ? resolved() : abortSink(d, reason),
          config.preventCancel || s.state !== 'readable' ? resolved() : cancelReadable(s, reason));
        then(action, function () { finish(kind !== 'end', reason); }, function (error) { finish(true, error); });
      });
    }
    function onAbort() {
      if (apply(signalAborted, tracked, [])) shutdown('abort', apply(signalReason, config.signal, []));
    }
    function stopForState() {
      if (stopping) return true;
      if (tracked !== undefined && apply(signalAborted, tracked, [])) onAbort();
      else if (s.state === 'errored') shutdown('source', s.error);
      else if (d.state === 'errored' || d.state === 'erroring') shutdown('destination', d.error);
      else if (s.state === 'closed') shutdown('end');
      else if (d.state === 'closed' || d.closing) shutdown('destination', invalid('Destination is closed or closing'));
      return stopping;
    }
    function pump() {
      if (stopForState()) return;
      then(w.ready.promise, function () {
        if (stopForState()) return;
        reading = true;
        then(read(r, function (item) { pendingItem = item; }), function (item) {
          reading = false;
          if (stopping) return;
          pendingItem = undefined;
          if (item.done) { shutdown('end'); return; }
          lastWrite = write(w, item.value);
          then(lastWrite, undefined, function (error) { shutdown('destination', error); });
          if (sourceEnded) shutdown('end'); else pump();
        }, function (error) { reading = false; shutdown('source', error); });
      }, function (error) { shutdown('destination', error); });
    }
    if (config.signal !== undefined) {
      // A private dependent signal cannot be silenced by an earlier public
      // listener's stopImmediatePropagation or consumed by a synthetic event.
      ownAbort = new Abort();
      const own = apply(controllerSignal, ownAbort, []);
      const dependencies = [config.signal, own];
      property(dependencies, iteratorKey, function () {
        let index = 0;
        return { next: function () {
          if (index++ === 0) return result(config.signal, false);
          if (index === 2) return result(own, false);
          return result(undefined, true);
        } };
      });
      tracked = apply(anySignal, Signals, [dependencies]);
      apply(listen, tracked, ['abort', onAbort]);
      if (apply(signalAborted, tracked, [])) onAbort();
    }
    then(r.closed.promise, function () {
      sourceEnded = true;
      // close can settle before the read returning the final queued chunk.
      // Let that read publish its value before initiating close on the sink.
      if (!reading) shutdown('end');
    }, function (error) { shutdown('source', error); });
    then(w.closed.promise, function () {
      shutdown('destination', invalid('Destination closed before the source'));
    }, function (error) { shutdown('destination', error); });
    if (s.state === 'errored') shutdown('source', s.error);
    else if (d.state === 'errored') shutdown('destination', d.error);
    else if (s.state === 'closed') shutdown('end');
    else if (d.state === 'closed' || d.closing) shutdown('destination', invalid('Destination is closed or closing'));
    pump();
    return completion.promise;
  }
  class CountQueuingStrategy {
    constructor(init) {
      const value = dictionary(init, 'init').highWaterMark;
      if (value === undefined) throw invalid('highWaterMark is required');
      set(strategies, this, { kind: 'count', highWaterMark: +value });
    }
    get highWaterMark() { return get(strategies, this, 'queuing strategy').highWaterMark; }
    get size() { get(strategies, this, 'queuing strategy'); return countSize; }
  }
  class ByteLengthQueuingStrategy {
    constructor(init) {
      const value = dictionary(init, 'init').highWaterMark;
      if (value === undefined) throw invalid('highWaterMark is required');
      set(strategies, this, { kind: 'bytes', highWaterMark: +value });
    }
    get highWaterMark() { return get(strategies, this, 'queuing strategy').highWaterMark; }
    get size() { get(strategies, this, 'queuing strategy'); return byteSize; }
  }
  function countSize() { return 1; }
  function byteSize(chunk) { return chunk.byteLength; }
  property(ReadableStream.prototype, tagKey, 'ReadableStream');
  property(ReadableStreamDefaultReader.prototype, tagKey, 'ReadableStreamDefaultReader');
  property(ReadableStreamDefaultController.prototype, tagKey, 'ReadableStreamDefaultController');
  property(CountQueuingStrategy.prototype, tagKey, 'CountQueuingStrategy');
  property(ByteLengthQueuingStrategy.prototype, tagKey, 'ByteLengthQueuingStrategy');
  property(WritableStream.prototype, tagKey, 'WritableStream');
  property(WritableStreamDefaultWriter.prototype, tagKey, 'WritableStreamDefaultWriter');
  property(WritableStreamDefaultController.prototype, tagKey, 'WritableStreamDefaultController');
  property(TransformStream.prototype, tagKey, 'TransformStream');
  property(TransformStreamDefaultController.prototype, tagKey, 'TransformStreamDefaultController');
  return { ReadableStream: ReadableStream, ReadableStreamDefaultReader: ReadableStreamDefaultReader,
    ReadableStreamDefaultController: ReadableStreamDefaultController,
    WritableStream: WritableStream, WritableStreamDefaultWriter: WritableStreamDefaultWriter,
    WritableStreamDefaultController: WritableStreamDefaultController,
    TransformStream: TransformStream, TransformStreamDefaultController: TransformStreamDefaultController,
    CountQueuingStrategy: CountQueuingStrategy, ByteLengthQueuingStrategy: ByteLengthQueuingStrategy };
})()
