(function () {
  'use strict';
  // WHATWG streams, executed by the native interpreter. Queues,
  // callbacks and promise jobs use its ordinary heap/work accounting. There
  // is no host stream implementation, I/O permission or external evaluator.
  // Transferable stream objects remain unsupported; byte buffers are moved
  // through the same native ArrayBuffer transfer primitive as guest buffers.
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
  const closedPromiseKey = Symbol.for('nodejs.webstream.isClosedPromise');
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
  const byteControllers = new Weak();
  const byobRequests = new Weak();
  const Bytes = Uint8Array;
  const Buffers = ArrayBuffer;
  const isView = ArrayBuffer.isView;
  const transferBuffer = ArrayBuffer.prototype.transfer;
  const bufferLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
  const typedPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  const typedBuffer = Object.getOwnPropertyDescriptor(typedPrototype, 'buffer').get;
  const typedOffset = Object.getOwnPropertyDescriptor(typedPrototype, 'byteOffset').get;
  const typedLength = Object.getOwnPropertyDescriptor(typedPrototype, 'byteLength').get;
  const typedName = Object.getOwnPropertyDescriptor(typedPrototype, tagKey).get;
  const dataBuffer = Object.getOwnPropertyDescriptor(DataView.prototype, 'buffer').get;
  const dataOffset = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteOffset').get;
  const dataLength = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get;
  const copyBytes = Uint8Array.prototype.set;
  const viewKinds = create(null);
  viewKinds.Int8Array = { ctor: Int8Array, element: 1 };
  viewKinds.Uint8Array = { ctor: Bytes, element: 1 };
  viewKinds.Uint8ClampedArray = { ctor: Uint8ClampedArray, element: 1 };
  viewKinds.Int16Array = { ctor: Int16Array, element: 2 };
  viewKinds.Uint16Array = { ctor: Uint16Array, element: 2 };
  viewKinds.Int32Array = { ctor: Int32Array, element: 4 };
  viewKinds.Uint32Array = { ctor: Uint32Array, element: 4 };
  viewKinds.Float32Array = { ctor: Float32Array, element: 4 };
  viewKinds.Float64Array = { ctor: Float64Array, element: 8 };
  viewKinds.BigInt64Array = { ctor: BigInt64Array, element: 8 };
  viewKinds.BigUint64Array = { ctor: BigUint64Array, element: 8 };
  viewKinds.DataView = { ctor: DataView, element: 1 };

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

  // Node's completion protocol observes the stream, not a reader/writer lock.
  // Allocate it only when observed. Never publish resolve/reject functions or
  // the mutable state record; the branded getter also ignores own decoy slots.
  function closedRecord(s) {
    if (s.completion === undefined) {
      s.completion = deferred(true);
      const record = create(null), descriptor = create(null);
      descriptor.value = s.completion.promise;
      define(record, 'promise', descriptor);
      s.completionRecord = record;
      if (s.completionDone) settleCompletion(s);
    }
    return s.completionRecord;
  }
  function settleCompletion(s) {
    s.completionDone = true;
    if (s.completion !== undefined) {
      if (s.state === 'errored') s.completion.reject(s.error);
      else s.completion.resolve();
    }
  }
  function completionGetter(prototype, states, name) {
    const descriptor = create(null);
    descriptor.get = function () { return closedRecord(get(states, this, name)); };
    define(prototype, closedPromiseKey, descriptor);
  }

  function releaseSource(s) { s.source = undefined; s.pull = undefined; s.cancel = undefined; s.size = undefined; }
  function closeReadable(s) {
    s.state = 'closed';
    releaseSource(s);
    if (s.reader !== undefined) {
      const r = get(readers, s.reader, 'reader');
      r.closed.resolve();
      if (!r.byob) while (r.requests.length !== 0) shift(r.requests).resolve(result(undefined, true));
    }
    settleCompletion(s);
  }
  function errorReadable(s, error) {
    if (s.state !== 'readable') return;
    s.state = 'errored'; s.error = error;
    clear(s.queue); clearPullIntos(s); releaseSource(s);
    if (s.reader !== undefined) {
      const r = get(readers, s.reader, 'reader');
      r.closed.reject(error);
      while (r.requests.length !== 0) shift(r.requests).reject(error);
    }
    settleCompletion(s);
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
    if (s.byte) { enqueueByte(s, value); return; }
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
    clear(s.queue); closeReadable(s); clearPullIntos(s);
    if (s.reader !== undefined) {
      const r = get(readers, s.reader, 'reader');
      while (r.requests.length !== 0) shift(r.requests).resolve(result(undefined, true));
    }
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
      const entry = shift(s.queue);
      const value = s.byte ? byteValue(entry) : entry;
      const item = result(value, false);
      if (receive !== undefined) receive(item);
      if (s.byte) byteDrain(s);
      else if (s.closeRequested && s.queue.length === 0) closeReadable(s); else pull(s);
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
    if (s.byte && s.autoAllocate !== undefined) {
      try {
        const buffer = new Buffers(s.autoAllocate);
        push(s.pullIntos, { buffer: buffer, capacity: s.autoAllocate, offset: 0,
          length: s.autoAllocate, filled: 0, minimum: 1, ctor: Bytes, element: 1, kind: 'default' }, 0);
      } catch (error) { return rejected(error); }
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
    if (s.byte && s.pullIntos.length !== 0) {
      // A source may still own the first request's exposed view. Preserve that
      // descriptor as an orphan until it responds/enqueues; reject all old
      // reader promises now without donating their buffers to a new reader.
      const head = s.pullIntos.head;
      head.value.kind = 'none'; head.next = undefined;
      s.pullIntos.tail = head; s.pullIntos.length = 1; s.pullIntos.total = 0;
    }
    s.reader = undefined; r.stream = undefined;
    while (r.requests.length !== 0) shift(r.requests).reject(error);
  }
  // Byte streams share the ordinary stream/reader lifecycle and linked FIFO.
  // Only queue entries and pending pull-into descriptors are specialized. All
  // buffers, copies and transfers use the interpreter's existing intrinsics.
  function viewInfo(view) {
    if (!isView(view)) throw invalid('Expected an ArrayBuffer view');
    let buffer, offset, length, name;
    try {
      buffer = apply(typedBuffer, view, []);
      offset = apply(typedOffset, view, []);
      length = apply(typedLength, view, []);
      name = apply(typedName, view, []);
    } catch (error) {
      buffer = apply(dataBuffer, view, []);
      offset = apply(dataOffset, view, []);
      length = apply(dataLength, view, []);
      name = 'DataView';
    }
    // Reject shared/detached allocations and out-of-bounds views. Never read
    // replaceable .buffer/.byteOffset/.byteLength/.constructor properties.
    const capacity = apply(bufferLength, buffer, []);
    new Bytes(buffer, offset, length);
    const kind = viewKinds[name];
    if (kind === undefined) throw invalid('Unsupported byte view');
    return { buffer: buffer, offset: offset, length: length, capacity: capacity,
      ctor: kind.ctor, element: kind.element };
  }
  function moved(buffer) { return apply(transferBuffer, buffer, []); }
  function byteRecord(buffer, offset, length) { return { buffer: buffer, offset: offset, length: length }; }
  function byteValue(entry) { return new Bytes(entry.buffer, entry.offset, entry.length); }
  function cloneBytes(buffer, offset, length) {
    const copy = new Bytes(length);
    apply(copyBytes, copy, [new Bytes(buffer, offset, length)]);
    return byteRecord(apply(typedBuffer, copy, []), 0, length);
  }
  function invalidateRequest(s) {
    if (s.byobRequest !== undefined) {
      const request = get(byobRequests, s.byobRequest, 'ReadableStreamBYOBRequest');
      request.stream = undefined; request.view = null; s.byobRequest = undefined;
    }
  }
  function clearPullIntos(s) {
    if (!s.byte) return;
    invalidateRequest(s); clear(s.pullIntos);
  }
  function closeByte(s) {
    if (s.queue.total !== 0) { s.closeRequested = true; return; }
    if (s.pullIntos.length !== 0) {
      const d = s.pullIntos.head.value;
      if (d.filled % d.element !== 0) {
        const error = invalid('Byte stream closed with an incomplete element');
        errorReadable(s, error); throw error;
      }
    }
    closeReadable(s);
  }
  function byteDrain(s) {
    if (s.queue.total === 0 && s.closeRequested) closeByte(s); else pull(s);
  }
  function commitPullInto(s, d, done) {
    const ctor = d.ctor;
    const value = new ctor(moved(d.buffer), d.offset, d.filled / d.element);
    if (s.reader !== undefined) {
      const r = get(readers, s.reader, 'reader');
      if (r.requests.length !== 0) shift(r.requests).resolve(result(value, done));
    }
  }
  function fillPullInto(s, d) {
    let amount = s.queue.total;
    if (amount > d.length - d.filled) amount = d.length - d.filled;
    const available = d.filled + amount;
    const aligned = available - available % d.element;
    const ready = aligned >= d.minimum;
    if (ready) amount = aligned - d.filled;
    while (amount !== 0) {
      const node = s.queue.head, entry = node.value;
      const count = amount < entry.length ? amount : entry.length;
      apply(copyBytes, new Bytes(d.buffer, d.offset + d.filled, count),
        [new Bytes(entry.buffer, entry.offset, count)]);
      if (count === entry.length) shift(s.queue);
      else { entry.offset += count; entry.length -= count; node.size -= count; s.queue.total -= count; }
      d.filled += count; amount -= count;
    }
    return ready;
  }
  function processPullIntos(s) {
    while (s.pullIntos.length !== 0 && s.queue.total !== 0) {
      const d = s.pullIntos.head.value;
      if (d.kind === 'none' || !fillPullInto(s, d)) break;
      shift(s.pullIntos); commitPullInto(s, d, false);
    }
  }
  function enqueueByte(s, chunk) {
    const info = viewInfo(chunk);
    if (info.length === 0 || info.capacity === 0) throw invalid('Cannot enqueue an empty byte view');
    if (!canEnqueue(s)) throw invalid('Stream is closed or closing');
    const entry = byteRecord(moved(info.buffer), info.offset, info.length);
    if (s.pullIntos.length !== 0) {
      const d = s.pullIntos.head.value;
      d.buffer = moved(d.buffer);
      invalidateRequest(s);
      if (d.kind === 'none') {
        if (d.filled !== 0) push(s.queue, cloneBytes(d.buffer, d.offset, d.filled), d.filled);
        shift(s.pullIntos);
      }
    }
    const r = s.reader === undefined ? undefined : get(readers, s.reader, 'reader');
    if (r !== undefined && !r.byob) {
      while (r.requests.length !== 0 && s.queue.total !== 0) {
        shift(r.requests).resolve(result(byteValue(shift(s.queue)), false));
      }
      if (r.requests.length !== 0) {
        if (s.pullIntos.length !== 0) shift(s.pullIntos);
        shift(r.requests).resolve(result(byteValue(entry), false));
      } else push(s.queue, entry, entry.length);
    } else {
      push(s.queue, entry, entry.length);
      if (r !== undefined) processPullIntos(s);
    }
    pull(s);
  }
  function unsigned(value, name) {
    const number = +value;
    if (!(number >= 0) || number > 9007199254740991) throw new NativeRangeError('Invalid ' + name);
    return number - number % 1;
  }
  function descriptor(info, minimum, kind) {
    return { buffer: moved(info.buffer), capacity: info.capacity, offset: info.offset,
      length: info.length, filled: 0, minimum: minimum * info.element,
      ctor: info.ctor, element: info.element, kind: kind };
  }
  function readInto(r, view, options, receive) {
    const info = viewInfo(view);
    if (info.length === 0 || info.capacity === 0) throw invalid('Cannot read into an empty byte view');
    const minimum = dictionary(options, 'options').min;
    // Node's BYOB extension accepts a positive integer number, not a coerced
    // dictionary value. Reading the option may still reenter/release below.
    const min = minimum === undefined ? 1 : minimum;
    if (typeof min !== 'number' || !(min > 0) || min % 1 !== 0) throw invalid('Invalid min');
    if (min > info.length / info.element) throw new NativeRangeError('Invalid min');
    if (r.stream === undefined) throw invalid('Reader lock is released');
    const s = get(streams, r.stream, 'ReadableStream');
    s.disturbed = true;
    if (s.state === 'errored') return rejected(s.error);
    const d = descriptor(info, min, 'byob');
    if (s.pullIntos.length === 0 && s.state === 'closed') {
      const ctor = d.ctor;
      const item = result(new ctor(d.buffer, d.offset, 0), true);
      if (receive !== undefined) receive(item);
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
    if (s.pullIntos.length === 0 && s.queue.total !== 0) {
      if (fillPullInto(s, d)) {
        const ctor = d.ctor;
        const value = new ctor(moved(d.buffer), d.offset, d.filled / d.element);
        byteDrain(s); request.resolve(result(value, false)); return request.promise;
      }
      if (s.closeRequested) {
        const error = invalid('Byte stream ended before the minimum read');
        errorReadable(s, error); request.reject(error); return request.promise;
      }
    }
    push(s.pullIntos, d, 0); push(r.requests, request, 0); pull(s);
    return request.promise;
  }
  function respondBytes(s, count) {
    const d = s.pullIntos.head.value;
    invalidateRequest(s);
    if (s.state === 'closed') {
      if (d.kind === 'none') shift(s.pullIntos);
      if (s.reader !== undefined && get(readers, s.reader, 'reader').byob) {
        while (s.pullIntos.length !== 0) commitPullInto(s, shift(s.pullIntos), true);
      } else clear(s.pullIntos);
      return;
    }
    d.filled += count;
    if (d.kind === 'none') {
      if (d.filled !== 0) push(s.queue, cloneBytes(d.buffer, d.offset, d.filled), d.filled);
      shift(s.pullIntos); processPullIntos(s);
    } else if (d.filled >= d.minimum) {
      shift(s.pullIntos);
      const remainder = d.filled % d.element;
      if (remainder !== 0) {
        push(s.queue, cloneBytes(d.buffer, d.offset + d.filled - remainder, remainder), remainder);
        d.filled -= remainder;
      }
      commitPullInto(s, d, false); processPullIntos(s);
    }
    pull(s);
  }
  function byobState(value) {
    const r = get(readers, value, 'ReadableStreamBYOBReader');
    if (!r.byob) throw invalid('Invalid ReadableStreamBYOBReader receiver');
    return r;
  }
  class ReadableStreamBYOBRequest {
    constructor(key, state) {
      if (key !== token) throw invalid('Illegal constructor');
      set(byobRequests, this, state);
    }
    get view() { return get(byobRequests, this, 'ReadableStreamBYOBRequest').view; }
    respond(bytesWritten) {
      const request = get(byobRequests, this, 'ReadableStreamBYOBRequest');
      const count = unsigned(bytesWritten, 'bytesWritten');
      const s = request.stream;
      if (s === undefined) throw invalid('BYOB request is no longer active');
      const d = s.pullIntos.head.value;
      if (s.state === 'closed' ? count !== 0 : count === 0) throw invalid('Invalid byte count for stream state');
      if (count > d.length - d.filled) throw new NativeRangeError('Byte count exceeds request');
      d.buffer = moved(d.buffer); respondBytes(s, count);
    }
    respondWithNewView(view) {
      const request = get(byobRequests, this, 'ReadableStreamBYOBRequest');
      const info = viewInfo(view), s = request.stream;
      if (s === undefined) throw invalid('BYOB request is no longer active');
      const d = s.pullIntos.head.value;
      if (s.state === 'closed' ? info.length !== 0 : info.length === 0) throw invalid('Invalid view length for stream state');
      if (info.offset !== d.offset + d.filled || info.capacity !== d.capacity || info.length > d.length - d.filled) {
        throw new NativeRangeError('View does not match pending byte request');
      }
      d.buffer = moved(info.buffer); respondBytes(s, info.length);
    }
  }
  class ReadableByteStreamController {
    constructor(key, state) {
      if (key !== token) throw invalid('Illegal constructor');
      set(byteControllers, this, state);
    }
    get desiredSize() {
      const s = get(byteControllers, this, 'ReadableByteStreamController');
      return s.state === 'errored' ? null : s.state === 'closed' ? 0 : s.highWaterMark - s.queue.total;
    }
    get byobRequest() {
      const s = get(byteControllers, this, 'ReadableByteStreamController');
      if (s.byobRequest === undefined && s.pullIntos.length !== 0) {
        const d = s.pullIntos.head.value;
        s.byobRequest = new ReadableStreamBYOBRequest(token,
          { stream: s, view: new Bytes(d.buffer, d.offset + d.filled, d.length - d.filled) });
      }
      return s.byobRequest === undefined ? null : s.byobRequest;
    }
    close() {
      const s = get(byteControllers, this, 'ReadableByteStreamController');
      if (!canEnqueue(s)) throw invalid('Stream is closed or closing');
      closeByte(s);
    }
    enqueue(chunk) { enqueueByte(get(byteControllers, this, 'ReadableByteStreamController'), chunk); }
    error(reason) { errorReadable(get(byteControllers, this, 'ReadableByteStreamController'), reason); }
  }
  class ReadableStreamBYOBReader {
    constructor(stream) {
      const s = get(streams, stream, 'ReadableStream');
      if (!s.byte) throw invalid('BYOB requires a byte stream');
      if (s.reader !== undefined) throw invalid('ReadableStream is locked');
      const r = { stream: stream, byob: true, requests: queue(), closed: deferred(true) };
      set(readers, this, r); s.reader = this;
      if (s.state === 'closed') r.closed.resolve();
      else if (s.state === 'errored') r.closed.reject(s.error);
    }
    get closed() { try { return byobState(this).closed.promise; } catch (error) { return rejected(error); } }
    read(view, options) {
      try { return readInto(byobState(this), view, options); } catch (error) { return rejected(error); }
    }
    cancel(reason) {
      try {
        const r = byobState(this);
        if (r.stream === undefined) throw invalid('Reader lock is released');
        return cancelReadable(get(streams, r.stream, 'ReadableStream'), reason);
      } catch (error) { return rejected(error); }
    }
    releaseLock() { releaseReader(byobState(this)); }
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
  function defaultReaderState(value) {
    const r = get(readers, value, 'ReadableStreamDefaultReader');
    if (r.byob) throw invalid('Invalid ReadableStreamDefaultReader receiver');
    return r;
  }
  class ReadableStreamDefaultReader {
    constructor(stream) {
      const s = get(streams, stream, 'ReadableStream');
      if (s.reader !== undefined) throw invalid('ReadableStream is locked');
      const r = { stream: stream, byob: false, requests: queue(), closed: deferred(true) };
      set(readers, this, r); s.reader = this;
      if (s.state === 'closed') r.closed.resolve();
      else if (s.state === 'errored') r.closed.reject(s.error);
    }
    get closed() {
      try { return defaultReaderState(this).closed.promise; }
      catch (error) { return rejected(error); }
    }
    read() {
      try { return read(defaultReaderState(this)); }
      catch (error) { return rejected(error); }
    }
    cancel(reason) {
      try {
        const r = defaultReaderState(this);
        if (r.stream === undefined) throw invalid('Reader lock is released');
        return cancelReadable(get(streams, r.stream, 'ReadableStream'), reason);
      } catch (error) { return rejected(error); }
    }
    releaseLock() { releaseReader(defaultReaderState(this)); }
  }

  // Both byte branches use the canonical byte controller and pull-into queue.
  // Only one upstream reader exists; switch its mode between completed reads
  // to forward consumer storage without allocating an intermediate default
  // buffer. A live sibling receives a copy before either branch can mutate it.
  // As with default tee, an unread sibling can accumulate queued data.
  function teeBytes(source, s) {
    let reader = new ReadableStreamDefaultReader(source);
    let r = get(readers, reader, 'reader');
    let reading = false, again1 = false, again2 = false, ended = false;
    let cancelled1 = false, cancelled2 = false, reason1, reason2, first, second;
    const cancellation = deferred(true);
    function fail(error, cancelSource) {
      ended = true; reading = false;
      errorReadable(first, error); errorReadable(second, error);
      if (cancelSource) cancellation.resolve(cancelReadable(s, error));
      else if (!cancelled1 || !cancelled2) cancellation.resolve();
    }
    function watch() {
      const observed = r;
      then(r.closed.promise, undefined, function (error) {
        // A normal mode switch rejects the released reader's closed promise.
        // Only the current reader can report a source failure to the branches.
        if (r === observed && !ended) fail(error, false);
      });
    }
    function acceptView(branch, value) {
      const info = viewInfo(value), d = branch.pullIntos.head.value;
      // This view came from the internal upstream BYOB read of this exact
      // descriptor. Its old backing store is detached; adopt the returned one.
      d.buffer = moved(info.buffer); respondBytes(branch, info.length);
    }
    function closeBranch(branch, value) {
      if (branch.state !== 'readable') return;
      closeByte(branch);
      if (branch.pullIntos.length !== 0) {
        if (value !== undefined) acceptView(branch, value);
        else {
          const d = branch.pullIntos.head.value;
          d.buffer = moved(d.buffer); respondBytes(branch, 0);
        }
      }
    }
    function cancelBranch(which, reason) {
      if (which === 1) { cancelled1 = true; reason1 = reason; }
      else { cancelled2 = true; reason2 = reason; }
      if (cancelled1 && cancelled2) {
        ended = true;
        const reasons = [reason1, reason2]; reason1 = undefined; reason2 = undefined;
        // Synchronous closure of pending reads is not completion of cleanup.
        // Both branch cancellations adopt the real upstream cancellation.
        cancellation.resolve(cancelReadable(s, reasons));
      }
      return cancellation.promise;
    }
    function pullBranches(which) {
      if (ended) return resolved();
      if (reading) {
        if (which === 1) again1 = true; else again2 = true;
        return resolved();
      }
      reading = true;
      const branch = which === 1 ? first : second;
      const into = branch.pullIntos.length !== 0;
      try {
        if (r.byob !== into) {
          releaseReader(r);
          reader = into ? new ReadableStreamBYOBReader(source) : new ReadableStreamDefaultReader(source);
          r = get(readers, reader, 'reader'); watch();
        }
        const d = into ? branch.pullIntos.head.value : undefined;
        function receive(item) {
          if (ended) return;
          // EOF closes branches at the read's close step, before the next
          // consumer reaction. Delaying this changes queued min-read results.
          if (item.done) {
            ended = true; reading = false;
            try {
              if (!cancelled1) closeBranch(first, into && which === 1 ? item.value : undefined);
              if (!cancelled2) closeBranch(second, into && which === 2 ? item.value : undefined);
              if (!cancelled1 || !cancelled2) cancellation.resolve();
            } catch (error) { fail(error, true); }
            return;
          }
          // Queue at admission, not after read() returns: a synchronous source
          // can respond and then error before the caller attaches a reaction.
          // Preserve that ordering using the existing internal read callback.
          then(resolved(), function () {
            if (ended) return;
            try {
              again1 = false; again2 = false;
              const info = viewInfo(item.value);
              if (!into) {
                const other = !cancelled1 && !cancelled2 ?
                  byteValue(cloneBytes(info.buffer, info.offset, info.length)) : item.value;
                if (!cancelled1) enqueueByte(first, item.value);
                if (!cancelled2) enqueueByte(second, other);
              } else {
                const other = which === 1 ? second : first;
                const ownCancelled = which === 1 ? cancelled1 : cancelled2;
                const otherCancelled = which === 1 ? cancelled2 : cancelled1;
                const copy = otherCancelled ? undefined : byteValue(cloneBytes(info.buffer, info.offset, info.length));
                if (!ownCancelled) acceptView(branch, item.value);
                if (!otherCancelled) enqueueByte(other, copy);
              }
              reading = false;
              if (again1) pullBranches(1); else if (again2) pullBranches(2);
            } catch (error) { fail(error, true); }
          });
        }
        const pending = into ? readInto(r, new Bytes(d.buffer, d.offset + d.filled, d.length - d.filled), undefined, receive) : read(r, receive);
        then(pending, undefined, function (error) { if (!ended) fail(error, false); });
      } catch (error) { fail(error, true); }
      return resolved();
    }
    const left = create(null), right = create(null);
    left.type = 'bytes'; right.type = 'bytes';
    left.pull = function () { return pullBranches(1); };
    right.pull = function () { return pullBranches(2); };
    left.cancel = function (reason) { return cancelBranch(1, reason); };
    right.cancel = function (reason) { return cancelBranch(2, reason); };
    const one = new ReadableStream(left), two = new ReadableStream(right);
    first = get(streams, one, 'ReadableStream'); second = get(streams, two, 'ReadableStream');
    watch(); return [one, two];
  }

  // Default-stream tee shares chunk identities, not a collected copy of the
  // source. Demand from either branch may advance the single upstream reader;
  // the other branch retains its own FIFO until read or cancelled. As in the
  // standard, a slow branch can therefore accumulate data from a fast sibling.
  // The private reader intentionally keeps the original stream locked even
  // after completion. No public getReader/read/enqueue override participates.
  function teeReadable(source) {
    const s = get(streams, source, 'ReadableStream');
    if (s.byte) return teeBytes(source, s);
    const reader = new ReadableStreamDefaultReader(source);
    const r = get(readers, reader, 'ReadableStreamDefaultReader');
    const cancellation = deferred(true);
    let reading = false, readAgain = false, ended = false;
    let cancelled1 = false, cancelled2 = false;
    let reason1, reason2, first, second;

    function closeBranch(branch) {
      if (!canEnqueue(branch)) return;
      branch.closeRequested = true;
      if (branch.queue.length === 0) closeReadable(branch);
    }
    function closeBranches() {
      reading = false; ended = true;
      if (!cancelled1) closeBranch(first);
      if (!cancelled2) closeBranch(second);
      // When both cancel, their promise must adopt the source's actual
      // cleanup result, not this synchronous close of a pending upstream read.
      if (!cancelled1 || !cancelled2) cancellation.resolve();
    }
    function failBranches(error) {
      reading = false; ended = true;
      errorReadable(first, error); errorReadable(second, error);
      if (!cancelled1 || !cancelled2) cancellation.resolve();
    }
    function pullBranches() {
      if (ended || (cancelled1 && cancelled2)) return resolved();
      if (reading) { readAgain = true; return resolved(); }
      reading = true;
      then(read(r, function (item) {
        if (item.done) { closeBranches(); return; }
        // Exactly one job separates upstream publication from branch
        // publication. Observe source errors before delivering a stale chunk;
        // a queued close, in contrast, must not discard the final chunk.
        then(resolved(), function () {
          readAgain = false;
          if (!cancelled1 && canEnqueue(first)) enqueue(first, item.value);
          if (!cancelled2 && canEnqueue(second)) enqueue(second, item.value);
          reading = false;
          if (readAgain) pullBranches();
        });
      }), function () {}, failBranches);
      return resolved();
    }
    function cancelBranch(which, reason) {
      if (which === 1) { cancelled1 = true; reason1 = reason; }
      else { cancelled2 = true; reason2 = reason; }
      if (cancelled1 && cancelled2) {
        const reasons = [reason1, reason2];
        reason1 = undefined; reason2 = undefined;
        ended = true;
        cancellation.resolve(cancelReadable(s, reasons));
      }
      return cancellation.promise;
    }
    const source1 = create(null), source2 = create(null);
    source1.pull = pullBranches; source2.pull = pullBranches;
    source1.cancel = function (reason) { return cancelBranch(1, reason); };
    source2.cancel = function (reason) { return cancelBranch(2, reason); };
    const branch1 = new ReadableStream(source1);
    const branch2 = new ReadableStream(source2);
    first = get(streams, branch1, 'ReadableStream');
    second = get(streams, branch2, 'ReadableStream');
    then(r.closed.promise, undefined, failBranches);
    return [branch1, branch2];
  }
  class ReadableStream {
    constructor(underlyingSource, queuingStrategy) {
      const source = dictionary(underlyingSource, 'underlyingSource');
      const cancel = method(source, 'cancel');
      const pullAlgorithm = method(source, 'pull');
      const start = method(source, 'start');
      const type = source.type;
      const byte = type !== undefined;
      if (byte && `${type}` !== 'bytes') throw invalid('Invalid stream type');
      const config = strategy(queuingStrategy, byte ? 0 : 1);
      if (byte && config.size !== undefined) throw new NativeRangeError('Byte streams cannot use a size callback');
      let autoAllocate;
      if (byte) {
        const size = source.autoAllocateChunkSize;
        if (size !== undefined) {
          autoAllocate = unsigned(size, 'autoAllocateChunkSize');
          if (autoAllocate === 0) throw invalid('autoAllocateChunkSize must be positive');
        }
      }
      const s = { state: 'readable', error: undefined, reader: undefined,
        completion: undefined, completionRecord: undefined, completionDone: false,
        queue: queue(), closeRequested: false, started: false, pulling: false,
        pullAgain: false, disturbed: false, source: source, cancel: cancel,
        pull: pullAlgorithm, size: config.size, highWaterMark: config.highWaterMark,
        controller: undefined, byte: byte, autoAllocate: autoAllocate,
        pullIntos: byte ? queue() : undefined, byobRequest: undefined };
      s.controller = byte ? new ReadableByteStreamController(token, s) : new ReadableStreamDefaultController(token, s);
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
      if (mode !== undefined) {
        if (`${mode}` !== 'byob') throw invalid('Invalid reader mode');
        return new ReadableStreamBYOBReader(this);
      }
      return new ReadableStreamDefaultReader(this);
    }
    cancel(reason) {
      try {
        const s = get(streams, this, 'ReadableStream');
        if (s.reader !== undefined) throw invalid('ReadableStream is locked');
        return cancelReadable(s, reason);
      } catch (error) { return rejected(error); }
    }
    tee() { return teeReadable(this); }
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
  completionGetter(ReadableStream.prototype, streams, 'ReadableStream');

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
    settleCompletion(s);
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
        settleCompletion(s);
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
        completion: undefined, completionRecord: undefined, completionDone: false,
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

  completionGetter(WritableStream.prototype, sinks, 'WritableStream');

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
  property(ReadableByteStreamController.prototype, tagKey, 'ReadableByteStreamController');
  property(ReadableStreamBYOBReader.prototype, tagKey, 'ReadableStreamBYOBReader');
  property(ReadableStreamBYOBRequest.prototype, tagKey, 'ReadableStreamBYOBRequest');
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
    ReadableByteStreamController: ReadableByteStreamController,
    ReadableStreamBYOBReader: ReadableStreamBYOBReader, ReadableStreamBYOBRequest: ReadableStreamBYOBRequest,
    WritableStream: WritableStream, WritableStreamDefaultWriter: WritableStreamDefaultWriter,
    WritableStreamDefaultController: WritableStreamDefaultController,
    TransformStream: TransformStream, TransformStreamDefaultController: TransformStreamDefaultController,
    CountQueuingStrategy: CountQueuingStrategy, ByteLengthQueuingStrategy: ByteLengthQueuingStrategy };
})()
