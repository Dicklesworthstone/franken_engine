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
  const streams = new Weak();
  const readers = new Weak();
  const controllers = new Weak();
  const strategies = new Weak();
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
  function read(r) {
    if (r.stream === undefined) return rejected(invalid('Reader lock is released'));
    const s = get(streams, r.stream, 'stream');
    s.disturbed = true;
    if (s.state === 'closed') return resolved(result(undefined, true));
    if (s.state === 'errored') return rejected(s.error);
    if (s.queue.length !== 0) {
      const value = shift(s.queue);
      if (s.closeRequested && s.queue.length === 0) closeReadable(s); else pull(s);
      return resolved(result(value, false));
    }
    const request = deferred(false);
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
  return { ReadableStream: ReadableStream, ReadableStreamDefaultReader: ReadableStreamDefaultReader,
    ReadableStreamDefaultController: ReadableStreamDefaultController,
    CountQueuingStrategy: CountQueuingStrategy, ByteLengthQueuingStrategy: ByteLengthQueuingStrategy };
})()
