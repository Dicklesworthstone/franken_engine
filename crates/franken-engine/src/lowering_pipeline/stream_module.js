(function () {
  'use strict';
  // Engine-owned `stream` (bd-305gi.1): Node's Readable / Writable / Duplex /
  // Transform / PassThrough state machines, finished and pipeline, over the
  // events module's EventEmitter, string_decoder's StringDecoder and the
  // process.nextTick queue (placeholders the lowering rewrite resolves).
  const EventEmitter = __franken_stream_events;
  const StringDecoder = __franken_stream_string_decoder.StringDecoder;
  // process.nextTick's queue, through an intrinsic that is only ever called.
  function nextTick(callback) {
    const args = Array.prototype.slice.call(arguments, 1);
    __franken_stream_next_tick(function () {
      callback.apply(undefined, args);
    });
  }
  const kOnFinished = Symbol('kOnFinished');
  const kCallback = Symbol('kCallback');
  const kIsDestroyed = Symbol('kIsDestroyed');
  // Callbacks waiting for _construct to finish (Node waits on an internal
  // symbol-named event; a list keeps them off the emitter).
  const kConstructWaiters = Symbol('kConstructWaiters');
  // Constructor cancellation is owned by the stream's actual lifecycle, not
  // its public events. No registry is allocated on the no-signal path.
  const StreamWeakMap = WeakMap;
  const streamWeakGet = WeakMap.prototype.get;
  const streamWeakSet = WeakMap.prototype.set;
  const streamWeakDelete = WeakMap.prototype.delete;
  let constructorSignals;
  function nop() {}
  const ENCODINGS = ['utf8', 'utf-8', 'ucs2', 'ucs-2', 'utf16le', 'utf-16le', 'latin1', 'binary',
    'base64', 'base64url', 'hex', 'ascii'];
  function isEncoding(encoding) {
    if (typeof Buffer.isEncoding === 'function') return Buffer.isEncoding(encoding);
    return typeof encoding === 'string' && encoding.length !== 0
      && ENCODINGS.indexOf(encoding.toLowerCase()) !== -1;
  }

  // ---- errors (Node's codes and messages) ----
  function makeError(Base, code, message) {
    const error = new Base(message);
    Object.defineProperty(error, 'code', { value: code, enumerable: false, writable: true, configurable: true });
    error.name = Base.name;
    return error;
  }
  function describeReceived(value) {
    if (value == null) return ' Received ' + value;
    if (typeof value === 'function') return ' Received function ' + value.name;
    if (typeof value === 'object') {
      if (value.constructor && value.constructor.name) return ' Received an instance of ' + value.constructor.name;
      return ' Received ' + String(value);
    }
    let shown = String(value);
    if (shown.length > 28) shown = shown.slice(0, 25) + '...';
    if (typeof value === 'string') shown = "'" + shown + "'";
    return ' Received type ' + typeof value + ' (' + shown + ')';
  }
  const errors = {
    prematureClose: () => makeError(Error, 'ERR_STREAM_PREMATURE_CLOSE', 'Premature close'),
    writeAfterEnd: () => makeError(Error, 'ERR_STREAM_WRITE_AFTER_END', 'write after end'),
    destroyed: (what) => makeError(Error, 'ERR_STREAM_DESTROYED', 'Cannot call ' + what + ' after a stream was destroyed'),
    pushAfterEof: () => makeError(Error, 'ERR_STREAM_PUSH_AFTER_EOF', 'stream.push() after EOF'),
    unshiftAfterEnd: () => makeError(Error, 'ERR_STREAM_UNSHIFT_AFTER_END_EVENT', 'stream.unshift() after end event'),
    nullValues: () => makeError(TypeError, 'ERR_STREAM_NULL_VALUES', 'May not write null values to stream'),
    alreadyFinished: (what) => makeError(Error, 'ERR_STREAM_ALREADY_FINISHED', 'Cannot call ' + what + ' after a stream was finished'),
    multipleCallback: () => makeError(Error, 'ERR_MULTIPLE_CALLBACK', 'Callback called multiple times'),
    notImplemented: (what) => makeError(Error, 'ERR_METHOD_NOT_IMPLEMENTED', 'The ' + what + ' method is not implemented'),
    missingArgs: (name) => makeError(TypeError, 'ERR_MISSING_ARGS', 'The "' + name + '" argument must be specified'),
    unknownEncoding: (encoding) => makeError(TypeError, 'ERR_UNKNOWN_ENCODING', 'Unknown encoding: ' + encoding),
    invalidChunk: (value) => makeError(TypeError, 'ERR_INVALID_ARG_TYPE',
      'The "chunk" argument must be of type string or an instance of Buffer, TypedArray, or DataView.'
      + describeReceived(value)),
    invalidIterable: (value) => makeError(TypeError, 'ERR_INVALID_ARG_TYPE',
      'The "iterable" argument must be an instance of Iterable.' + describeReceived(value)),
    invalidReturn: (name) => makeError(TypeError, 'ERR_INVALID_RETURN_VALUE',
      'Expected Iterable, AsyncIterable or Stream to be returned from the "' + name + '" function.'),
  };

  // Node byte-mode streams consume the raw viewed bytes, not typed-array
  // element values. Use intrinsic accessors so cross-realm views and subclasses
  // work without reading replaceable .buffer/.byteOffset/.byteLength getters.
  // All views use one path before entering the existing queues/state machines.
  const streamIsView = ArrayBuffer.isView;
  const streamBuffer = Buffer;
  const streamBufferFrom = Buffer.from;
  const streamIsBuffer = Buffer.isBuffer;
  const streamApply = Reflect.apply;
  const streamTypedPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  const streamTypedBuffer = Object.getOwnPropertyDescriptor(streamTypedPrototype, 'buffer').get;
  const streamTypedOffset = Object.getOwnPropertyDescriptor(streamTypedPrototype, 'byteOffset').get;
  const streamTypedLength = Object.getOwnPropertyDescriptor(streamTypedPrototype, 'byteLength').get;
  const streamDataBuffer = Object.getOwnPropertyDescriptor(DataView.prototype, 'buffer').get;
  const streamDataOffset = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteOffset').get;
  const streamDataLength = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get;

  function isUint8Array(value) {
    return value instanceof Uint8Array;
  }
  function toBuffer(chunk) {
    if (!streamIsView(chunk)) throw errors.invalidChunk(chunk);
    let buffer;
    let offset;
    let length;
    try {
      buffer = streamApply(streamTypedBuffer, chunk, []);
    } catch (error) {
      buffer = streamApply(streamDataBuffer, chunk, []);
      offset = streamApply(streamDataOffset, chunk, []);
      length = streamApply(streamDataLength, chunk, []);
      return streamApply(streamBufferFrom, streamBuffer, [buffer, offset, length]);
    }
    offset = streamApply(streamTypedOffset, chunk, []);
    length = streamApply(streamTypedLength, chunk, []);
    return streamApply(streamBufferFrom, streamBuffer, [buffer, offset, length]);
  }
  function getHighWaterMark(state, options, duplexKey, isDuplex) {
    const fromKey = options == null ? null
      : options.highWaterMark != null ? options.highWaterMark
        : isDuplex ? options[duplexKey] : null;
    if (fromKey != null) {
      return Math.floor(fromKey);
    }
    return state.objectMode ? 16 : 65536;
  }

  // ---- Stream (legacy base) ----
  function Stream(options) {
    EventEmitter.call(this, options);
  }
  Object.setPrototypeOf(Stream.prototype, EventEmitter.prototype);
  Object.setPrototypeOf(Stream, EventEmitter);
  Stream.prototype.pipe = function (dest, options) {
    const source = this;
    function ondata(chunk) {
      if (dest.writable && dest.write(chunk) === false && source.pause) source.pause();
    }
    source.on('data', ondata);
    function ondrain() {
      if (source.readable && source.resume) source.resume();
    }
    dest.on('drain', ondrain);
    let didOnEnd = false;
    if (!dest._isStdio && (!options || options.end !== false)) {
      source.on('end', onend);
      source.on('close', onclose);
    }
    function onend() {
      if (didOnEnd) return;
      didOnEnd = true;
      dest.end();
    }
    function onclose() {
      if (didOnEnd) return;
      didOnEnd = true;
      if (typeof dest.destroy === 'function') dest.destroy();
    }
    function onerror(error) {
      cleanup();
      if (this.listenerCount('error') === 0) this.emit('error', error);
    }
    source.prependListener('error', onerror);
    dest.prependListener('error', onerror);
    function cleanup() {
      source.removeListener('data', ondata);
      dest.removeListener('drain', ondrain);
      source.removeListener('end', onend);
      source.removeListener('close', onclose);
      source.removeListener('error', onerror);
      dest.removeListener('error', onerror);
      source.removeListener('end', cleanup);
      source.removeListener('close', cleanup);
      dest.removeListener('close', cleanup);
    }
    source.on('end', cleanup);
    source.on('close', cleanup);
    dest.on('close', cleanup);
    dest.emit('pipe', source);
    return dest;
  };

  // ---- destroy ----
  function checkError(error, writableState, readableState) {
    if (error) {
      if (writableState && !writableState.errored) writableState.errored = error;
      if (readableState && !readableState.errored) readableState.errored = error;
    }
  }
  function destroy(error, callback) {
    const readableState = this._readableState;
    const writableState = this._writableState;
    const state = writableState || readableState;
    if ((writableState && writableState.destroyed) || (readableState && readableState.destroyed)) {
      if (typeof callback === 'function') callback();
      return this;
    }
    checkError(error, writableState, readableState);
    if (writableState) writableState.destroyed = true;
    if (readableState) readableState.destroyed = true;
    releaseConstructorSignal(this);
    if (!state.constructed) {
      const self = this;
      this[kConstructWaiters].push(function (constructError) {
        destroyNow(self, aggregateTwoErrors(constructError, error), callback);
      });
    } else {
      destroyNow(this, error, callback);
    }
    return this;
  }
  function destroyNow(self, error, callback) {
    let called = false;
    function onDestroy(destroyError) {
      if (called) return;
      called = true;
      const readableState = self._readableState;
      const writableState = self._writableState;
      checkError(destroyError, writableState, readableState);
      if (writableState) writableState.closed = true;
      if (readableState) readableState.closed = true;
      if (typeof callback === 'function') callback(destroyError);
      if (destroyError) {
        nextTick(emitErrorCloseNT, self, destroyError);
      } else {
        nextTick(emitCloseNT, self);
      }
    }
    try {
      self._destroy(error || null, onDestroy);
    } catch (thrown) {
      onDestroy(thrown);
    }
  }
  function emitErrorCloseNT(self, error) {
    emitErrorNT(self, error);
    emitCloseNT(self);
  }
  function emitCloseNT(self) {
    const readableState = self._readableState;
    const writableState = self._writableState;
    if (writableState) writableState.closeEmitted = true;
    if (readableState) readableState.closeEmitted = true;
    if ((writableState && writableState.emitClose) || (readableState && readableState.emitClose)) {
      self.emit('close');
    }
  }
  function emitErrorNT(self, error) {
    const readableState = self._readableState;
    const writableState = self._writableState;
    if ((writableState && writableState.errorEmitted) || (readableState && readableState.errorEmitted)) return;
    if (writableState) writableState.errorEmitted = true;
    if (readableState) readableState.errorEmitted = true;
    self.emit('error', error);
  }
  function undestroy() {
    const readableState = this._readableState;
    const writableState = this._writableState;
    if (readableState) {
      readableState.constructed = true;
      readableState.closed = false;
      readableState.closeEmitted = false;
      readableState.destroyed = false;
      readableState.errored = null;
      readableState.errorEmitted = false;
      readableState.reading = false;
      readableState.ended = readableState.readable === false;
      readableState.endEmitted = readableState.readable === false;
    }
    if (writableState) {
      writableState.constructed = true;
      writableState.destroyed = false;
      writableState.closed = false;
      writableState.closeEmitted = false;
      writableState.errored = null;
      writableState.errorEmitted = false;
      writableState.finalCalled = false;
      writableState.prefinished = false;
      writableState.ended = writableState.writable === false;
      writableState.ending = writableState.writable === false;
      writableState.finished = writableState.writable === false;
    }
  }
  function errorOrDestroy(stream, error, sync) {
    const readableState = stream._readableState;
    const writableState = stream._writableState;
    if ((writableState && writableState.destroyed) || (readableState && readableState.destroyed)) return;
    if ((readableState && readableState.autoDestroy) || (writableState && writableState.autoDestroy)) {
      stream.destroy(error);
    } else if (error) {
      if (writableState && !writableState.errored) writableState.errored = error;
      if (readableState && !readableState.errored) readableState.errored = error;
      if (sync) {
        nextTick(emitErrorNT, stream, error);
      } else {
        emitErrorNT(stream, error);
      }
    }
  }
  function constructStream(stream, callback) {
    if (typeof stream._construct !== 'function') return;
    const readableState = stream._readableState;
    const writableState = stream._writableState;
    if (readableState) readableState.constructed = false;
    if (writableState) writableState.constructed = false;
    const waiters = stream[kConstructWaiters];
    if (waiters) {
      waiters.push(callback);
      return;
    }
    stream[kConstructWaiters] = [callback];
    nextTick(constructNT, stream);
  }
  function constructDone(stream, error) {
    const waiters = stream[kConstructWaiters].splice(0);
    for (let i = 0; i < waiters.length; i++) waiters[i].call(stream, error);
  }
  function constructNT(stream) {
    let called = false;
    function onConstruct(error) {
      if (called) {
        errorOrDestroy(stream, error != null ? error : errors.multipleCallback());
        return;
      }
      called = true;
      const readableState = stream._readableState;
      const writableState = stream._writableState;
      const state = writableState || readableState;
      if (readableState) readableState.constructed = true;
      if (writableState) writableState.constructed = true;
      if (state.destroyed) {
        constructDone(stream, error);
      } else if (error) {
        errorOrDestroy(stream, error, true);
      } else {
        nextTick(constructDone, stream);
      }
    }
    try {
      stream._construct(function (error) { nextTick(onConstruct, error); });
    } catch (error) {
      nextTick(onConstruct, error);
    }
  }
  function aggregateTwoErrors(inner, outer) {
    if (inner && outer && inner !== outer) {
      if (Array.isArray(outer.errors)) {
        outer.errors.push(inner);
        return outer;
      }
      const error = new AggregateError([outer, inner], outer.message);
      error.code = outer.code;
      return error;
    }
    return inner || outer;
  }
  function destroyer(stream, error) {
    if (!stream || isDestroyed(stream)) return;
    if (!error && !isFinished(stream)) error = makeAbortError();
    if (typeof stream.destroy === 'function') {
      stream.destroy(error);
    } else if (typeof stream.close === 'function') {
      stream.close();
    }
    if (!stream.destroyed) stream[kIsDestroyed] = true;
  }
  function makeAbortError() {
    const error = new Error('The operation was aborted');
    error.code = 'ABORT_ERR';
    error.name = 'AbortError';
    return error;
  }

  // ---- stream predicates (lib/internal/streams/utils.js) ----
  function isReadableNodeStream(obj, strict) {
    return !!(obj && typeof obj.pipe === 'function' && typeof obj.on === 'function'
      && (!strict || (typeof obj.pause === 'function' && typeof obj.resume === 'function'))
      && (!obj._writableState || (obj._readableState && obj._readableState.readable !== false))
      && (!obj._writableState || obj._readableState));
  }
  function isWritableNodeStream(obj) {
    return !!(obj && typeof obj.write === 'function' && typeof obj.on === 'function'
      && (!obj._readableState || (obj._writableState && obj._writableState.writable !== false)));
  }
  function isNodeStream(obj) {
    return !!(obj && (obj._readableState || obj._writableState
      || (typeof obj.write === 'function' && typeof obj.on === 'function')
      || (typeof obj.pipe === 'function' && typeof obj.on === 'function')));
  }
  function isIterable(obj, isAsync) {
    if (obj == null) return false;
    if (isAsync === true) return typeof obj[Symbol.asyncIterator] === 'function';
    if (isAsync === false) return typeof obj[Symbol.iterator] === 'function';
    return typeof obj[Symbol.asyncIterator] === 'function' || typeof obj[Symbol.iterator] === 'function';
  }
  function isDestroyed(stream) {
    if (!isNodeStream(stream)) return null;
    const writableState = stream._writableState;
    const readableState = stream._readableState;
    const state = writableState || readableState;
    return !!(stream.destroyed || stream[kIsDestroyed] || (state && state.destroyed));
  }
  function isWritableEnded(stream) {
    if (!isWritableNodeStream(stream)) return null;
    if (stream.writableEnded === true) return true;
    const writableState = stream._writableState;
    if (writableState && writableState.errored) return false;
    if (!writableState || typeof writableState.ended !== 'boolean') return null;
    return writableState.ended;
  }
  function isWritableFinished(stream, strict) {
    if (!isWritableNodeStream(stream)) return null;
    if (stream.writableFinished === true) return true;
    const writableState = stream._writableState;
    if (writableState && writableState.errored) return false;
    if (!writableState || typeof writableState.finished !== 'boolean') return null;
    return !!(writableState.finished
      || (strict === false && writableState.ended === true && writableState.length === 0));
  }
  function isReadableFinished(stream, strict) {
    if (!isReadableNodeStream(stream)) return null;
    const readableState = stream._readableState;
    if (readableState && readableState.errored) return false;
    if (!readableState || typeof readableState.endEmitted !== 'boolean') return null;
    return !!(readableState.endEmitted
      || (strict === false && readableState.ended === true && readableState.length === 0));
  }
  function isReadable(stream) {
    if (typeof (stream && stream.readable) !== 'boolean') return null;
    if (isDestroyed(stream)) return false;
    return isReadableNodeStream(stream) && stream.readable && !isReadableFinished(stream);
  }
  function isWritable(stream) {
    if (typeof (stream && stream.writable) !== 'boolean') return null;
    if (isDestroyed(stream)) return false;
    return isWritableNodeStream(stream) && stream.writable && !isWritableEnded(stream);
  }
  function isFinished(stream, options) {
    if (!isNodeStream(stream)) return null;
    if (isDestroyed(stream)) return true;
    if ((!options || options.readable !== false) && isReadable(stream)) return false;
    if ((!options || options.writable !== false) && isWritable(stream)) return false;
    return true;
  }
  function isWritableErrored(stream) {
    if (!isNodeStream(stream)) return null;
    if (stream.writableErrored) return stream.writableErrored;
    const writableState = stream._writableState;
    return writableState && writableState.errored != null ? writableState.errored : null;
  }
  function isReadableErrored(stream) {
    if (!isNodeStream(stream)) return null;
    if (stream.readableErrored) return stream.readableErrored;
    const readableState = stream._readableState;
    return readableState && readableState.errored != null ? readableState.errored : null;
  }
  function isClosed(stream) {
    if (!isNodeStream(stream)) return null;
    const writableState = stream._writableState;
    const readableState = stream._readableState;
    if (typeof (writableState && writableState.closed) === 'boolean'
      || typeof (readableState && readableState.closed) === 'boolean') {
      return (writableState && writableState.closed) || (readableState && readableState.closed);
    }
    return null;
  }
  function willEmitClose(stream) {
    if (!isNodeStream(stream)) return null;
    const writableState = stream._writableState;
    const readableState = stream._readableState;
    const state = writableState || readableState;
    return !!(state && state.autoDestroy && state.emitClose && state.closed === false);
  }

  // ---- buffer list ----
  // Circular storage reuses consumed slots even when a live stream never
  // empties. Both ends are amortized O(1); prepend never shifts the backlog.
  // Growth is geometric and clear releases the backing after a full drain.
  function BufferList() {
    this.chunks = [];
    this.index = 0;
    this.length = 0;
  }
  function growBufferList(list) {
    const old = list.chunks;
    const capacity = old.length === 0 ? 8 : old.length * 2;
    const chunks = new Array(capacity);
    let index = list.index;
    for (let i = 0; i < list.length; i++) {
      chunks[i] = old[index];
      index += 1;
      if (index === old.length) index = 0;
    }
    list.chunks = chunks;
    list.index = 0;
  }
  BufferList.prototype.size = function () { return this.length; };
  BufferList.prototype.push = function (chunk) {
    if (this.length === this.chunks.length) growBufferList(this);
    let index = this.index + this.length;
    if (index >= this.chunks.length) index -= this.chunks.length;
    this.chunks[index] = chunk;
    this.length += 1;
  };
  BufferList.prototype.unshift = function (chunk) {
    if (this.length === this.chunks.length) growBufferList(this);
    this.index = this.index === 0 ? this.chunks.length - 1 : this.index - 1;
    this.chunks[this.index] = chunk;
    this.length += 1;
  };
  BufferList.prototype.first = function () {
    return this.length === 0 ? undefined : this.chunks[this.index];
  };
  BufferList.prototype.shift = function () {
    if (this.length === 0) return undefined;
    const chunk = this.chunks[this.index];
    this.chunks[this.index] = null;
    this.index += 1;
    if (this.index === this.chunks.length) this.index = 0;
    this.length -= 1;
    if (this.length === 0) this.clear();
    return chunk;
  };
  BufferList.prototype.clear = function () {
    this.chunks = [];
    this.index = 0;
    this.length = 0;
  };
  BufferList.prototype.all = function () {
    const chunks = new Array(this.length);
    let index = this.index;
    for (let i = 0; i < this.length; i++) {
      chunks[i] = this.chunks[index];
      index += 1;
      if (index === this.chunks.length) index = 0;
    }
    return chunks;
  };
  // Take `n` bytes (or characters when the chunks are strings) from the front.
  BufferList.prototype.consume = function (n, hasStrings) {
    const first = this.first();
    if (n < first.length) {
      this.chunks[this.index] = first.slice(n);
      return first.slice(0, n);
    }
    if (n === first.length) return this.shift();
    if (hasStrings) {
      let out = '';
      while (n > 0) {
        const chunk = this.first();
        if (n >= chunk.length) {
          out += chunk;
          n -= chunk.length;
          this.shift();
        } else {
          out += chunk.slice(0, n);
          this.chunks[this.index] = chunk.slice(n);
          n = 0;
        }
      }
      return out;
    }
    const parts = [];
    let total = 0;
    while (n > 0) {
      const chunk = this.first();
      if (n >= chunk.length) {
        parts.push(chunk);
        total += chunk.length;
        n -= chunk.length;
        this.shift();
      } else {
        parts.push(chunk.slice(0, n));
        total += n;
        this.chunks[this.index] = chunk.slice(n);
        n = 0;
      }
    }
    return Buffer.concat(parts, total);
  };

  // ---- Readable ----
  function ReadableState(options, stream, isDuplex) {
    this.objectMode = !!(options && options.objectMode);
    if (isDuplex) this.objectMode = this.objectMode || !!(options && options.readableObjectMode);
    this.highWaterMark = getHighWaterMark(this, options, 'readableHighWaterMark', isDuplex);
    this.buffer = new BufferList();
    this.length = 0;
    this.pipes = [];
    this.flowing = null;
    this.ended = false;
    this.endEmitted = false;
    this.reading = false;
    this.constructed = true;
    this.sync = true;
    this.needReadable = false;
    this.emittedReadable = false;
    this.readableListening = false;
    this.resumeScheduled = false;
    this.paused = null;
    this.errorEmitted = false;
    this.emitClose = !options || options.emitClose !== false;
    this.autoDestroy = !options || options.autoDestroy !== false;
    this.destroyed = false;
    this.errored = null;
    this.closed = false;
    this.closeEmitted = false;
    this.defaultEncoding = (options && options.defaultEncoding) || 'utf8';
    this.awaitDrainWriters = null;
    this.multiAwaitDrain = false;
    this.readingMore = false;
    this.dataEmitted = false;
    this.decoder = null;
    this.encoding = null;
    if (options && options.encoding) {
      this.decoder = new StringDecoder(options.encoding);
      this.encoding = options.encoding;
    }
  }
  function Readable(options) {
    if (!(this instanceof Readable)) return new Readable(options);
    const isDuplex = this instanceof Duplex;
    const signal = isDuplex ? undefined : constructorSignalOption(options);
    this._readableState = new ReadableState(options, this, isDuplex);
    if (options) {
      if (typeof options.read === 'function') this._read = options.read;
      if (typeof options.destroy === 'function') this._destroy = options.destroy;
      if (typeof options.construct === 'function') this._construct = options.construct;
    }
    Stream.call(this, options);
    const self = this;
    constructStream(this, function () {
      if (self._readableState.needReadable) maybeReadMore(self, self._readableState);
    });
    if (signal !== undefined) attachConstructorSignal(this, signal);
  }
  Object.setPrototypeOf(Readable.prototype, Stream.prototype);
  Object.setPrototypeOf(Readable, Stream);
  Readable.ReadableState = ReadableState;
  Readable.prototype.destroy = destroy;
  Readable.prototype._undestroy = undestroy;
  Readable.prototype._destroy = function (error, callback) { callback(error); };
  Readable.prototype.push = function (chunk, encoding) {
    return readableAddChunk(this, chunk, encoding, false);
  };
  Readable.prototype.unshift = function (chunk, encoding) {
    return readableAddChunk(this, chunk, encoding, true);
  };
  function readableAddChunk(stream, chunk, encoding, addToFront) {
    const state = stream._readableState;
    let error;
    if (!state.objectMode) {
      if (typeof chunk === 'string') {
        encoding = encoding || state.defaultEncoding;
        if (state.encoding !== encoding) {
          if (addToFront && state.encoding) {
            chunk = Buffer.from(chunk, encoding).toString(state.encoding);
          } else {
            chunk = Buffer.from(chunk, encoding);
            encoding = '';
          }
        }
      } else if (streamIsView(chunk)) {
        if (!streamIsBuffer(chunk)) chunk = toBuffer(chunk);
        encoding = '';
      } else if (chunk != null) {
        error = errors.invalidChunk(chunk);
      }
    }
    if (error) {
      errorOrDestroy(stream, error);
    } else if (chunk === null) {
      state.reading = false;
      onEofChunk(stream, state);
    } else if (state.objectMode || (chunk && chunk.length > 0)) {
      if (addToFront) {
        if (state.endEmitted) {
          errorOrDestroy(stream, errors.unshiftAfterEnd());
        } else if (state.destroyed || state.errored) {
          return false;
        } else {
          addChunk(stream, state, chunk, true);
        }
      } else if (state.ended) {
        errorOrDestroy(stream, errors.pushAfterEof());
      } else if (state.destroyed || state.errored) {
        return false;
      } else {
        state.reading = false;
        if (state.decoder && !encoding) {
          chunk = state.decoder.write(chunk);
          if (state.objectMode || chunk.length !== 0) {
            addChunk(stream, state, chunk, false);
          } else {
            maybeReadMore(stream, state);
          }
        } else {
          addChunk(stream, state, chunk, false);
        }
      }
    } else if (!addToFront) {
      state.reading = false;
      maybeReadMore(stream, state);
    }
    return !state.ended && (state.length < state.highWaterMark || state.length === 0);
  }
  function addChunk(stream, state, chunk, addToFront) {
    if (state.flowing && state.length === 0 && !state.sync && stream.listenerCount('data') > 0) {
      if (state.multiAwaitDrain) {
        state.awaitDrainWriters.clear();
      } else {
        state.awaitDrainWriters = null;
      }
      state.dataEmitted = true;
      stream.emit('data', chunk);
    } else {
      state.length += state.objectMode ? 1 : chunk.length;
      if (addToFront) {
        state.buffer.unshift(chunk);
      } else {
        state.buffer.push(chunk);
      }
      if (state.needReadable) emitReadable(stream);
    }
    maybeReadMore(stream, state);
  }
  Readable.prototype.isPaused = function () {
    const state = this._readableState;
    return state.paused === true || state.flowing === false;
  };
  Readable.prototype.setEncoding = function (encoding) {
    const state = this._readableState;
    const decoder = new StringDecoder(encoding);
    state.decoder = decoder;
    state.encoding = decoder.encoding;
    let content = '';
    const chunks = state.buffer.all();
    for (let i = 0; i < chunks.length; i++) content += decoder.write(chunks[i]);
    state.buffer.clear();
    if (content !== '') state.buffer.push(content);
    state.length = content.length;
    return this;
  };
  function computeNewHighWaterMark(n) {
    if (n > 0x40000000) throw makeError(RangeError, 'ERR_OUT_OF_RANGE',
      'The value of "size" is out of range. It must be <= 1GiB. Received ' + n);
    n -= 1;
    n |= n >>> 1;
    n |= n >>> 2;
    n |= n >>> 4;
    n |= n >>> 8;
    n |= n >>> 16;
    return n + 1;
  }
  function howMuchToRead(n, state) {
    if (n <= 0 || (state.length === 0 && state.ended)) return 0;
    if (state.objectMode) return 1;
    if (Number.isNaN(n)) {
      if (state.flowing && state.length) return state.buffer.first().length;
      return state.length;
    }
    if (n <= state.length) return n;
    return state.ended ? state.length : 0;
  }
  Readable.prototype.read = function (n) {
    if (n === undefined) {
      n = NaN;
    } else if (!Number.isInteger(n)) {
      n = Number.parseInt(n, 10);
    }
    const state = this._readableState;
    const nOrig = n;
    if (n > state.highWaterMark) state.highWaterMark = computeNewHighWaterMark(n);
    if (n !== 0) state.emittedReadable = false;
    if (n === 0 && state.needReadable
      && ((state.highWaterMark !== 0 ? state.length >= state.highWaterMark : state.length > 0) || state.ended)) {
      if (state.length === 0 && state.ended) {
        endReadable(this);
      } else {
        emitReadable(this);
      }
      return null;
    }
    n = howMuchToRead(n, state);
    if (n === 0 && state.ended) {
      if (state.length === 0) endReadable(this);
      return null;
    }
    let doRead = state.needReadable;
    if (state.length === 0 || state.length - n < state.highWaterMark) doRead = true;
    if (state.ended || state.reading || state.destroyed || state.errored || !state.constructed) {
      doRead = false;
    } else if (doRead) {
      state.reading = true;
      state.sync = true;
      if (state.length === 0) state.needReadable = true;
      try {
        this._read(state.highWaterMark);
      } catch (error) {
        errorOrDestroy(this, error);
      }
      state.sync = false;
      if (!state.reading) n = howMuchToRead(nOrig, state);
    }
    let ret = n > 0 ? fromList(n, state) : null;
    if (ret === null) {
      state.needReadable = state.length <= state.highWaterMark;
      n = 0;
    } else {
      state.length -= n;
      if (state.multiAwaitDrain) {
        state.awaitDrainWriters.clear();
      } else {
        state.awaitDrainWriters = null;
      }
    }
    if (state.length === 0) {
      if (!state.ended) state.needReadable = true;
      if (nOrig !== n && state.ended) endReadable(this);
    }
    if (ret !== null && !state.errorEmitted && !state.closeEmitted) {
      state.dataEmitted = true;
      this.emit('data', ret);
    }
    return ret;
  };
  function fromList(n, state) {
    if (state.length === 0) return null;
    let ret;
    if (state.objectMode) {
      ret = state.buffer.shift();
    } else if (!n || n >= state.length) {
      const chunks = state.buffer.all();
      if (state.decoder) {
        ret = chunks.join('');
      } else if (chunks.length === 1) {
        ret = chunks[0];
      } else {
        ret = Buffer.concat(chunks, state.length);
      }
      state.buffer.clear();
    } else {
      ret = state.buffer.consume(n, !!state.decoder);
    }
    return ret;
  }
  function onEofChunk(stream, state) {
    if (state.ended) return;
    if (state.decoder) {
      const chunk = state.decoder.end();
      if (chunk && chunk.length) {
        state.buffer.push(chunk);
        state.length += state.objectMode ? 1 : chunk.length;
      }
    }
    state.ended = true;
    if (state.sync) {
      emitReadable(stream);
    } else {
      state.needReadable = false;
      state.emittedReadable = true;
      emitReadableNT(stream);
    }
  }
  function emitReadable(stream) {
    const state = stream._readableState;
    state.needReadable = false;
    if (!state.emittedReadable) {
      state.emittedReadable = true;
      nextTick(emitReadableNT, stream);
    }
  }
  function emitReadableNT(stream) {
    const state = stream._readableState;
    if (!state.destroyed && !state.errored && (state.length || state.ended)) {
      stream.emit('readable');
      state.emittedReadable = false;
    }
    state.needReadable = !state.flowing && !state.ended && state.length <= state.highWaterMark;
    flow(stream);
  }
  function maybeReadMore(stream, state) {
    if (!state.readingMore && state.constructed) {
      state.readingMore = true;
      nextTick(maybeReadMoreNT, stream, state);
    }
  }
  function maybeReadMoreNT(stream, state) {
    while (!state.reading && !state.ended
      && (state.length < state.highWaterMark || (state.flowing && state.length === 0))) {
      const length = state.length;
      stream.read(0);
      if (length === state.length) break;
    }
    state.readingMore = false;
  }
  Readable.prototype._read = function () {
    throw errors.notImplemented('_read()');
  };
  Readable.prototype.pipe = function (dest, pipeOptions) {
    const src = this;
    const state = this._readableState;
    if (state.pipes.length === 1 && !state.multiAwaitDrain) {
      state.multiAwaitDrain = true;
      state.awaitDrainWriters = new Set(state.awaitDrainWriters ? [state.awaitDrainWriters] : []);
    }
    state.pipes.push(dest);
    const doEnd = !pipeOptions || pipeOptions.end !== false;
    const endFn = doEnd ? onend : unpipe;
    if (state.endEmitted) {
      nextTick(endFn);
    } else {
      src.once('end', endFn);
    }
    dest.on('unpipe', onunpipe);
    function onunpipe(readable, unpipeInfo) {
      if (readable === src && unpipeInfo && unpipeInfo.hasUnpiped === false) {
        unpipeInfo.hasUnpiped = true;
        cleanup();
      }
    }
    function onend() {
      dest.end();
    }
    let ondrain;
    let cleanedUp = false;
    function cleanup() {
      dest.removeListener('close', onclose);
      dest.removeListener('finish', onfinish);
      if (ondrain) dest.removeListener('drain', ondrain);
      dest.removeListener('error', onerror);
      dest.removeListener('unpipe', onunpipe);
      src.removeListener('end', onend);
      src.removeListener('end', unpipe);
      src.removeListener('data', ondata);
      cleanedUp = true;
      if (ondrain && state.awaitDrainWriters && (!dest._writableState || dest._writableState.needDrain)) {
        ondrain();
      }
    }
    function pause() {
      if (!cleanedUp) {
        if (state.pipes.length === 1 && state.pipes[0] === dest) {
          state.awaitDrainWriters = dest;
          state.multiAwaitDrain = false;
        } else if (state.pipes.length > 1 && state.pipes.includes(dest)) {
          state.awaitDrainWriters.add(dest);
        }
        src.pause();
      }
      if (!ondrain) {
        ondrain = pipeOnDrain(src, dest);
        dest.on('drain', ondrain);
      }
    }
    src.on('data', ondata);
    function ondata(chunk) {
      const ret = dest.write(chunk);
      if (ret === false) pause();
    }
    function onerror(error) {
      unpipe();
      dest.removeListener('error', onerror);
      if (dest.listenerCount('error') === 0) {
        const destState = dest._writableState || dest._readableState;
        if (destState && !destState.errorEmitted) {
          errorOrDestroy(dest, error);
        } else {
          dest.emit('error', error);
        }
      }
    }
    dest.prependListener('error', onerror);
    function onclose() {
      dest.removeListener('finish', onfinish);
      unpipe();
    }
    dest.once('close', onclose);
    function onfinish() {
      dest.removeListener('close', onclose);
      unpipe();
    }
    dest.once('finish', onfinish);
    function unpipe() {
      src.unpipe(dest);
    }
    dest.emit('pipe', src);
    if (dest.writableNeedDrain === true) {
      pause();
    } else if (!state.flowing) {
      src.resume();
    }
    return dest;
  };
  function pipeOnDrain(src, dest) {
    return function pipeOnDrainFunctionResult() {
      const state = src._readableState;
      if (state.awaitDrainWriters === dest) {
        state.awaitDrainWriters = null;
      } else if (state.multiAwaitDrain) {
        state.awaitDrainWriters.delete(dest);
      }
      if ((!state.awaitDrainWriters || state.awaitDrainWriters.size === 0) && src.listenerCount('data')) {
        src.resume();
      }
    };
  }
  Readable.prototype.unpipe = function (dest) {
    const state = this._readableState;
    const unpipeInfo = { hasUnpiped: false };
    if (state.pipes.length === 0) return this;
    if (!dest) {
      const dests = state.pipes;
      state.pipes = [];
      this.pause();
      for (let i = 0; i < dests.length; i++) dests[i].emit('unpipe', this, { hasUnpiped: false });
      return this;
    }
    const index = state.pipes.indexOf(dest);
    if (index === -1) return this;
    state.pipes.splice(index, 1);
    if (state.pipes.length === 0) this.pause();
    dest.emit('unpipe', this, unpipeInfo);
    return this;
  };
  function afterListenerAdded(stream, event) {
    const state = stream._readableState;
    if (event === 'data') {
      state.readableListening = stream.listenerCount('readable') > 0;
      if (state.flowing !== false) stream.resume();
    } else if (event === 'readable') {
      if (!state.endEmitted && !state.readableListening) {
        state.readableListening = state.needReadable = true;
        state.flowing = false;
        state.emittedReadable = false;
        if (state.length) {
          emitReadable(stream);
        } else if (!state.reading) {
          nextTick(nReadingNextTick, stream);
        }
      }
    }
  }
  Readable.prototype.on = function (event, listener) {
    const result = Stream.prototype.on.call(this, event, listener);
    afterListenerAdded(this, event);
    return result;
  };
  Readable.prototype.addListener = Readable.prototype.on;
  Readable.prototype.once = function (event, listener) {
    const result = Stream.prototype.once.call(this, event, listener);
    afterListenerAdded(this, event);
    return result;
  };
  Readable.prototype.prependListener = function (event, listener) {
    const result = Stream.prototype.prependListener.call(this, event, listener);
    afterListenerAdded(this, event);
    return result;
  };
  Readable.prototype.prependOnceListener = function (event, listener) {
    const result = Stream.prototype.prependOnceListener.call(this, event, listener);
    afterListenerAdded(this, event);
    return result;
  };
  Readable.prototype.removeListener = function (event, listener) {
    const result = Stream.prototype.removeListener.call(this, event, listener);
    if (event === 'readable') nextTick(updateReadableListening, this);
    return result;
  };
  Readable.prototype.off = Readable.prototype.removeListener;
  Readable.prototype.removeAllListeners = function (event) {
    const result = Stream.prototype.removeAllListeners.apply(this, arguments);
    if (event === 'readable' || event === undefined) nextTick(updateReadableListening, this);
    return result;
  };
  function updateReadableListening(self) {
    const state = self._readableState;
    state.readableListening = self.listenerCount('readable') > 0;
    if (state.resumeScheduled && state.paused === false) {
      state.flowing = true;
    } else if (self.listenerCount('data') > 0) {
      self.resume();
    } else if (!state.readableListening) {
      state.flowing = null;
    }
  }
  function nReadingNextTick(self) {
    self.read(0);
  }
  Readable.prototype.resume = function () {
    const state = this._readableState;
    if (!state.flowing) {
      state.flowing = !state.readableListening;
      if (!state.resumeScheduled) {
        state.resumeScheduled = true;
        nextTick(resumeNT, this, state);
      }
    }
    state.paused = false;
    return this;
  };
  function resumeNT(stream, state) {
    if (!state.reading) stream.read(0);
    state.resumeScheduled = false;
    stream.emit('resume');
    flow(stream);
    if (state.flowing && !state.reading) stream.read(0);
  }
  Readable.prototype.pause = function () {
    const state = this._readableState;
    if (state.flowing !== false) {
      state.flowing = false;
      this.emit('pause');
    }
    state.paused = true;
    return this;
  };
  function flow(stream) {
    const state = stream._readableState;
    while (state.flowing && stream.read() !== null);
  }
  Readable.prototype.wrap = function (stream) {
    let paused = false;
    const self = this;
    stream.on('data', function (chunk) {
      if (!self.push(chunk) && stream.pause) {
        paused = true;
        stream.pause();
      }
    });
    stream.on('end', function () { self.push(null); });
    stream.on('error', function (error) { errorOrDestroy(self, error); });
    stream.on('close', function () { self.destroy(); });
    stream.on('destroy', function () { self.destroy(); });
    this._read = function () {
      if (paused && stream.resume) {
        paused = false;
        stream.resume();
      }
    };
    return this;
  };
  Readable.prototype[Symbol.asyncIterator] = function () {
    return createAsyncIterator(this);
  };
  Readable.prototype.iterator = function (options) {
    return createAsyncIterator(this, options);
  };
  async function* createAsyncIterator(stream, options) {
    let callback = nop;
    function next(resolve) {
      if (this === stream) {
        callback();
        callback = nop;
      } else {
        callback = resolve;
      }
    }
    stream.on('readable', next);
    let error;
    const cleanup = eos(stream, { writable: false }, function (finishError) {
      error = finishError ? aggregateTwoErrors(error, finishError) : null;
      callback();
      callback = nop;
    });
    try {
      while (true) {
        const chunk = stream.destroyed ? null : stream.read();
        if (chunk !== null) {
          yield chunk;
        } else if (error) {
          throw error;
        } else if (error === null) {
          return;
        } else {
          await new Promise(next);
        }
      }
    } catch (thrown) {
      error = aggregateTwoErrors(error, thrown);
      throw error;
    } finally {
      if ((error || !options || options.destroyOnReturn !== false)
        && (error === undefined || stream._readableState.autoDestroy)) {
        destroyer(stream, null);
      } else {
        stream.off('readable', next);
        cleanup();
      }
    }
  }
  Readable.prototype.toArray = async function () {
    const result = [];
    for await (const chunk of this) result.push(chunk);
    return result;
  };
  function defineGetters(prototype, getters) {
    for (const name of Object.keys(getters)) {
      const getter = getters[name];
      const descriptor = typeof getter === 'function'
        ? { get: getter, enumerable: false, configurable: true }
        : Object.assign({ enumerable: false, configurable: true }, getter);
      Object.defineProperty(prototype, name, descriptor);
    }
  }
  defineGetters(Readable.prototype, {
    readable: {
      get() {
        const r = this._readableState;
        return !!r && r.readable !== false && !r.destroyed && !r.errorEmitted && !r.endEmitted;
      },
      set(value) {
        if (this._readableState) this._readableState.readable = !!value;
      },
    },
    readableDidRead() { return this._readableState.dataEmitted; },
    readableAborted() {
      return !!(this._readableState.readable !== false
        && (this._readableState.destroyed || this._readableState.errored) && !this._readableState.endEmitted);
    },
    readableHighWaterMark() { return this._readableState.highWaterMark; },
    readableBuffer() { return this._readableState && this._readableState.buffer; },
    readableFlowing: {
      get() { return this._readableState.flowing; },
      set(value) { if (this._readableState) this._readableState.flowing = value; },
    },
    readableLength() { return this._readableState.length; },
    readableObjectMode() { return this._readableState ? this._readableState.objectMode : false; },
    readableEncoding() { return this._readableState ? this._readableState.encoding : null; },
    errored() { return this._readableState ? this._readableState.errored : null; },
    closed() { return this._readableState ? this._readableState.closed : false; },
    destroyed: {
      get() { return this._readableState ? this._readableState.destroyed : false; },
      set(value) { if (this._readableState) this._readableState.destroyed = value; },
    },
    readableEnded() { return this._readableState ? this._readableState.endEmitted : false; },
  });
  function endReadable(stream) {
    const state = stream._readableState;
    if (!state.endEmitted) {
      state.ended = true;
      nextTick(endReadableNT, state, stream);
    }
  }
  function endReadableNT(state, stream) {
    if (!state.errored && !state.closeEmitted && !state.endEmitted && state.length === 0) {
      state.endEmitted = true;
      releaseFinishedConstructorSignal(stream);
      stream.emit('end');
      if (stream.writable && stream.allowHalfOpen === false) {
        nextTick(endWritableNT, stream);
      } else if (state.autoDestroy) {
        const writableState = stream._writableState;
        const autoDestroy = !writableState
          || (writableState.autoDestroy && (writableState.finished || writableState.writable === false));
        if (autoDestroy) stream.destroy();
      }
    }
  }
  function endWritableNT(stream) {
    const writable = stream.writable && !stream.writableEnded && !stream.destroyed;
    if (writable) stream.end();
  }
  Readable.from = function (iterable, options) {
    return from(Readable, iterable, options);
  };
  function from(ReadableClass, iterable, options) {
    if (typeof iterable === 'string' || iterable instanceof Buffer) {
      return new ReadableClass(Object.assign({ objectMode: true }, options, {
        read() {
          this.push(iterable);
          this.push(null);
        },
      }));
    }
    let iterator;
    let isAsync;
    if (iterable && typeof iterable[Symbol.asyncIterator] === 'function') {
      isAsync = true;
      iterator = iterable[Symbol.asyncIterator]();
    } else if (iterable && typeof iterable[Symbol.iterator] === 'function') {
      isAsync = false;
      iterator = iterable[Symbol.iterator]();
    } else {
      throw errors.invalidIterable(iterable);
    }
    function resultObject(value, method) {
      if (value === null || (typeof value !== 'object' && typeof value !== 'function')) {
        throw makeError(TypeError, 'ERR_INVALID_RETURN_VALUE',
          'Expected an object from iterator.' + method + '()');
      }
      return value;
    }
    resultObject(iterator, isAsync ? '[Symbol.asyncIterator]' : '[Symbol.iterator]');
    const settings = Object.assign({ objectMode: true, highWaterMark: 1 }, options);
    const signal = constructorSignalOption(settings);
    // Install producer cleanup before observing a pre-aborted signal.
    settings.signal = undefined;
    const readable = new ReadableClass(settings);
    let reading = false;
    let stopped = false;
    function live() { return !stopped && !readable.destroyed; }
    function failed(reason) {
      reading = false;
      // A rejected producer may throw any JS value. Falsy errors must not
      // become destroy-without-error and a successful partial pipeline.
      if (live()) readable.destroy(pipelineRejection(reason));
    }
    function publish(value) {
      if (!live()) return false;
      if (value === null) throw errors.nullValues();
      const more = readable.push(value);
      // push() can synchronously call arbitrary consumers, including destroy.
      if (!more || !live()) { reading = false; return false; }
      return true;
    }
    readable._read = function () {
      if (reading || !live()) return;
      reading = true;
      if (isAsync) nextAsync(); else nextSync();
    };
    readable._destroy = function (error, callback) {
      // Retire the pump before invoking guest cleanup. Late next()/value
      // completions are observed, but cannot inspect or publish another step.
      stopped = true;
      reading = false;
      close(error).then(
        function () { nextTick(callback, error); },
        function (closeError) { nextTick(callback, aggregateTwoErrors(closeError, error)); },
      );
    };
    async function close(error) {
      let cleanupError;
      let done = false;
      if (error !== undefined && error !== null) {
        try {
          const method = iterator.throw;
          if (typeof method === 'function') {
            const result = await streamApply(method, iterator, [error]);
            // readline's iterator.throw deliberately settles with undefined.
            // That is not a completed iterator: still call return(), rather
            // than replacing the original abort with a property-access error.
            if (result !== undefined) {
              resultObject(result, 'throw');
              await result.value;
              done = !!result.done;
            }
          }
        } catch (reason) {
          if (reason !== error) cleanupError = pipelineRejection(reason);
        }
      }
      if (!done) {
        try {
          const method = iterator.return;
          if (typeof method === 'function') {
            const result = resultObject(await streamApply(method, iterator, []), 'return');
            await result.value;
          }
        } catch (reason) {
          const nextError = pipelineRejection(reason);
          cleanupError = aggregateTwoErrors(nextError, cleanupError);
        }
      }
      if (cleanupError !== undefined) throw cleanupError;
    }
    function nextSync() {
      while (live()) {
        try {
          const step = iterator.next();
          if (!live()) return;
          resultObject(step, 'next');
          const done = step.done;
          if (!live()) return;
          if (done) { readable.push(null); return; }
          const value = step.value;
          if (!live()) return;
          if (value && typeof value.then === 'function') {
            settleValue(value);
            return;
          }
          if (!publish(value)) return;
        } catch (error) { failed(error); return; }
      }
    }
    async function settleValue(value) {
      try {
        const resolved = await value;
        if (publish(resolved)) nextSync();
      } catch (error) { failed(error); }
      // No sticky async-value mode: after this one awaited value, plain
      // synchronous chunks return to the allocation-free synchronous pump.
    }
    async function nextAsync() {
      while (live()) {
        try {
          const step = await iterator.next();
          if (!live()) return;
          resultObject(step, 'next');
          const done = step.done;
          if (!live()) return;
          if (done) { readable.push(null); return; }
          const value = step.value;
          if (!publish(value)) return;
        } catch (error) { failed(error); return; }
      }
    }
    if (signal !== undefined) attachConstructorSignal(readable, signal);
    return readable;
  }

  // ---- Writable ----
  function WritableState(options, stream, isDuplex) {
    this.objectMode = !!(options && options.objectMode);
    if (isDuplex) this.objectMode = this.objectMode || !!(options && options.writableObjectMode);
    this.highWaterMark = getHighWaterMark(this, options, 'writableHighWaterMark', isDuplex);
    this.finalCalled = false;
    this.needDrain = false;
    this.ending = false;
    this.ended = false;
    this.finished = false;
    this.destroyed = false;
    this.decodeStrings = !(options && options.decodeStrings === false);
    this.defaultEncoding = (options && options.defaultEncoding) || 'utf8';
    this.length = 0;
    this.writing = false;
    this.corked = 0;
    this.sync = true;
    this.bufferProcessing = false;
    const self = this;
    this.onwrite = function (error) { onwrite(stream, error); };
    this.writecb = null;
    this.writelen = 0;
    this.afterWriteTickInfo = null;
    resetBuffer(this);
    this.pendingcb = 0;
    this.constructed = true;
    this.prefinished = false;
    this.errorEmitted = false;
    this.emitClose = !options || options.emitClose !== false;
    this.autoDestroy = !options || options.autoDestroy !== false;
    this.errored = null;
    this.closed = false;
    this.closeEmitted = false;
    this[kOnFinished] = [];
    void self;
  }
  function resetBuffer(state) {
    state.buffered = [];
    state.bufferedIndex = 0;
    state.allBuffers = true;
    state.allNoop = true;
  }
  WritableState.prototype.getBuffer = function () {
    return this.buffered.slice(this.bufferedIndex);
  };
  Object.defineProperty(WritableState.prototype, 'bufferedRequestCount', {
    get() { return this.buffered.length - this.bufferedIndex; },
    configurable: true,
  });
  function Writable(options) {
    const isDuplex = this instanceof Duplex;
    if (!isDuplex && !Function.prototype[Symbol.hasInstance].call(Writable, this)) {
      return new Writable(options);
    }
    const signal = isDuplex ? undefined : constructorSignalOption(options);
    this._writableState = new WritableState(options, this, isDuplex);
    if (options) {
      if (typeof options.write === 'function') this._write = options.write;
      if (typeof options.writev === 'function') this._writev = options.writev;
      if (typeof options.destroy === 'function') this._destroy = options.destroy;
      if (typeof options.final === 'function') this._final = options.final;
      if (typeof options.construct === 'function') this._construct = options.construct;
    }
    Stream.call(this, options);
    const self = this;
    constructStream(this, function () {
      const state = self._writableState;
      if (!state.writing) clearBuffer(self, state);
      finishMaybe(self, state);
    });
    if (signal !== undefined) attachConstructorSignal(this, signal);
  }
  Object.setPrototypeOf(Writable.prototype, Stream.prototype);
  Object.setPrototypeOf(Writable, Stream);
  Writable.WritableState = WritableState;
  Object.defineProperty(Writable, Symbol.hasInstance, {
    value: function (object) {
      if (Function.prototype[Symbol.hasInstance].call(this, object)) return true;
      if (this !== Writable) return false;
      return !!(object && object._writableState instanceof WritableState);
    },
    configurable: true,
  });
  Writable.prototype.pipe = function () {
    errorOrDestroy(this, makeError(Error, 'ERR_STREAM_CANNOT_PIPE', 'Cannot pipe, not readable'));
  };
  function writeChunk(stream, chunk, encoding, callback) {
    const state = stream._writableState;
    if (typeof encoding === 'function') {
      callback = encoding;
      encoding = state.defaultEncoding;
    } else {
      if (!encoding) {
        encoding = state.defaultEncoding;
      } else if (encoding !== 'buffer' && !isEncoding(encoding)) {
        throw errors.unknownEncoding(encoding);
      }
      if (typeof callback !== 'function') callback = nop;
    }
    if (chunk === null) {
      throw errors.nullValues();
    } else if (!state.objectMode) {
      if (typeof chunk === 'string') {
        if (state.decodeStrings !== false) {
          chunk = Buffer.from(chunk, encoding);
          encoding = 'buffer';
        }
      } else if (streamIsView(chunk)) {
        if (!streamIsBuffer(chunk)) chunk = toBuffer(chunk);
        encoding = 'buffer';
      } else {
        throw errors.invalidChunk(chunk);
      }
    }
    let error;
    if (state.ending) {
      error = errors.writeAfterEnd();
    } else if (state.destroyed) {
      error = errors.destroyed('write');
    }
    if (error) {
      nextTick(callback, error);
      errorOrDestroy(stream, error, true);
      return error;
    }
    state.pendingcb++;
    return writeOrBuffer(stream, state, chunk, encoding, callback);
  }
  Writable.prototype.write = function (chunk, encoding, callback) {
    return writeChunk(this, chunk, encoding, callback) === true;
  };
  Writable.prototype.cork = function () {
    this._writableState.corked++;
  };
  Writable.prototype.uncork = function () {
    const state = this._writableState;
    if (state.corked) {
      state.corked--;
      if (!state.writing) clearBuffer(this, state);
    }
  };
  Writable.prototype.setDefaultEncoding = function (encoding) {
    if (typeof encoding === 'string') encoding = encoding.toLowerCase();
    if (!isEncoding(encoding)) throw errors.unknownEncoding(encoding);
    this._writableState.defaultEncoding = encoding;
    return this;
  };
  function writeOrBuffer(stream, state, chunk, encoding, callback) {
    const length = state.objectMode ? 1 : chunk.length;
    state.length += length;
    const ret = state.length < state.highWaterMark;
    if (!ret) state.needDrain = true;
    if (state.writing || state.bufferProcessing || state.corked || state.errored || !state.constructed) {
      state.buffered.push({ chunk: chunk, encoding: encoding, callback: callback });
      if (state.allBuffers && encoding !== 'buffer') state.allBuffers = false;
      if (state.allNoop && callback !== nop) state.allNoop = false;
    } else {
      state.writelen = length;
      state.writecb = callback;
      state.writing = true;
      state.sync = true;
      stream._write(chunk, encoding, state.onwrite);
      state.sync = false;
    }
    return ret && !state.errored && !state.destroyed;
  }
  function doWrite(stream, state, writev, length, chunk, encoding, callback) {
    state.writelen = length;
    state.writecb = callback;
    state.writing = true;
    state.sync = true;
    if (state.destroyed) {
      state.onwrite(errors.destroyed('write'));
    } else if (writev) {
      streamApply(writev, stream, [chunk, state.onwrite]);
    } else {
      stream._write(chunk, encoding, state.onwrite);
    }
    state.sync = false;
  }
  function onwriteError(stream, state, error, callback) {
    --state.pendingcb;
    callback(error);
    errorBuffer(state);
    errorOrDestroy(stream, error);
  }
  function onwrite(stream, error) {
    const state = stream._writableState;
    const sync = state.sync;
    const callback = state.writecb;
    if (typeof callback !== 'function') {
      errorOrDestroy(stream, errors.multipleCallback());
      return;
    }
    state.writing = false;
    state.writecb = null;
    state.length -= state.writelen;
    state.writelen = 0;
    if (error) {
      if (!state.errored) state.errored = error;
      if (stream._readableState && !stream._readableState.errored) stream._readableState.errored = error;
      if (sync) {
        nextTick(onwriteError, stream, state, error, callback);
      } else {
        onwriteError(stream, state, error, callback);
      }
    } else {
      if (state.buffered.length > state.bufferedIndex) clearBuffer(stream, state);
      if (sync) {
        if (state.afterWriteTickInfo !== null && state.afterWriteTickInfo.callback === callback) {
          state.afterWriteTickInfo.count++;
        } else {
          state.afterWriteTickInfo = { count: 1, callback: callback, stream: stream, state: state };
          nextTick(afterWriteTick, state.afterWriteTickInfo);
        }
      } else {
        afterWrite(stream, state, 1, callback);
      }
    }
  }
  function afterWriteTick(info) {
    info.state.afterWriteTickInfo = null;
    return afterWrite(info.stream, info.state, info.count, info.callback);
  }
  function afterWrite(stream, state, count, callback) {
    const needDrain = !state.ending && !stream.destroyed && state.length === 0 && state.needDrain;
    if (needDrain) {
      state.needDrain = false;
      stream.emit('drain');
    }
    while (count-- > 0) {
      state.pendingcb--;
      callback(null);
    }
    if (state.destroyed) errorBuffer(state);
    // Completion after a write callback still crosses a nextTick boundary.
    // Emitting finish here can overtake readable end and callback-scheduled
    // work, even when _write itself completed asynchronously (bd-305gi.2).
    if (state.ending) finishMaybe(stream, state, true);
  }
  function errorBuffer(state) {
    if (state.writing) return;
    const buffered = state.buffered;
    const start = state.bufferedIndex;
    const finishedCallbacks = state[kOnFinished].splice(0);
    const error = state.errored != null ? state.errored : errors.destroyed('write');
    resetBuffer(state);
    for (let n = start; n < buffered.length; ++n) {
      const entry = buffered[n];
      state.length -= state.objectMode ? 1 : entry.chunk.length;
      state.pendingcb--;
      entry.callback(error);
    }
    for (let i = 0; i < finishedCallbacks.length; i++) {
      finishedCallbacks[i](state.errored != null ? state.errored : errors.destroyed('end'));
    }
  }
  function clearBuffer(stream, state) {
    if (state.corked || state.bufferProcessing || state.writing || state.destroyed
      || state.errored || !state.constructed) return;
    state.bufferProcessing = true;
    try {
      while (!state.writing && !state.corked && !state.destroyed && !state.errored) {
        if (state.bufferedIndex === state.buffered.length) break;
        const writev = state.buffered.length - state.bufferedIndex > 1 ? stream._writev : null;
        if (state.corked || state.destroyed || state.errored || state.writing) break;
        const buffered = state.buffered;
        let i = state.bufferedIndex;
        const bufferedLength = buffered.length - i;
        if (!bufferedLength) break;
        if (bufferedLength > 1 && writev) {
          const length = state.length;
          let callback = nop;
          if (!state.allNoop) {
            const callbacks = new Array(bufferedLength);
            for (let n = 0; n < bufferedLength; n++) callbacks[n] = buffered[i + n].callback;
            callback = function (error) {
              for (let n = 0; n < callbacks.length; n++) callbacks[n](error);
            };
          }
          const chunks = state.allNoop && i === 0 ? buffered : buffered.slice(i);
          chunks.allBuffers = state.allBuffers;
          resetBuffer(state);
          state.pendingcb -= bufferedLength - 1;
          doWrite(stream, state, writev, length, chunks, '', callback);
        } else {
          do {
            const entry = buffered[i];
            buffered[i++] = null;
            const length = state.objectMode ? 1 : entry.chunk.length;
            doWrite(stream, state, null, length, entry.chunk, entry.encoding, entry.callback);
          } while (i < buffered.length && !state.writing && !state.corked
            && !state.destroyed && !state.errored);
          if (i === buffered.length) {
            resetBuffer(state);
          } else if (i > 256 && i >= buffered.length - i) {
            buffered.splice(0, i);
            state.bufferedIndex = 0;
          } else {
            state.bufferedIndex = i;
          }
        }
      }
    } finally {
      state.bufferProcessing = false;
    }
  }
  Writable.prototype._write = function (chunk, encoding, callback) {
    if (this._writev) {
      this._writev([{ chunk: chunk, encoding: encoding }], callback);
    } else {
      throw errors.notImplemented('_write()');
    }
  };
  Writable.prototype._writev = null;
  Writable.prototype.end = function (chunk, encoding, callback) {
    const state = this._writableState;
    if (typeof chunk === 'function') {
      callback = chunk;
      chunk = null;
      encoding = null;
    } else if (typeof encoding === 'function') {
      callback = encoding;
      encoding = null;
    }
    let error;
    if (chunk !== null && chunk !== undefined) {
      const ret = writeChunk(this, chunk, encoding);
      if (ret instanceof Error) error = ret;
    }
    if (state.corked) {
      state.corked = 1;
      this.uncork();
    }
    if (error) {
      // the write's error is reported through its callback and destroy
    } else if (!state.errored && !state.ending) {
      state.ending = true;
      finishMaybe(this, state, true);
      state.ended = true;
    } else if (state.finished) {
      error = errors.alreadyFinished('end');
    } else if (state.destroyed) {
      error = errors.destroyed('end');
    }
    if (typeof callback === 'function') {
      if (error || state.finished) {
        nextTick(callback, error);
      } else {
        state[kOnFinished].push(callback);
      }
    }
    return this;
  };
  function needFinish(state) {
    return state.ending && !state.destroyed && state.constructed && state.length === 0
      && !state.errored && state.buffered.length === 0 && !state.finished && !state.writing
      && !state.errorEmitted && !state.closeEmitted;
  }
  function callFinal(stream, state) {
    let called = false;
    function onFinish(error) {
      if (called) {
        errorOrDestroy(stream, error != null ? error : errors.multipleCallback());
        return;
      }
      called = true;
      state.pendingcb--;
      if (error) {
        const finishedCallbacks = state[kOnFinished].splice(0);
        for (let i = 0; i < finishedCallbacks.length; i++) finishedCallbacks[i](error);
        errorOrDestroy(stream, error, state.sync);
      } else if (needFinish(state)) {
        state.prefinished = true;
        stream.emit('prefinish');
        state.pendingcb++;
        nextTick(finish, stream, state);
      }
    }
    state.sync = true;
    state.pendingcb++;
    try {
      stream._final(onFinish);
    } catch (error) {
      onFinish(error);
    }
    state.sync = false;
  }
  function prefinish(stream, state) {
    if (!state.prefinished && !state.finalCalled) {
      if (typeof stream._final === 'function' && !state.destroyed) {
        state.finalCalled = true;
        callFinal(stream, state);
      } else {
        state.prefinished = true;
        stream.emit('prefinish');
      }
    }
  }
  function finishMaybe(stream, state, sync) {
    if (needFinish(state)) {
      prefinish(stream, state);
      if (state.pendingcb === 0) {
        if (sync) {
          state.pendingcb++;
          nextTick(function () {
            if (needFinish(state)) {
              finish(stream, state);
            } else {
              state.pendingcb--;
            }
          });
        } else if (needFinish(state)) {
          state.pendingcb++;
          finish(stream, state);
        }
      }
    }
  }
  function finish(stream, state) {
    state.pendingcb--;
    state.finished = true;
    releaseFinishedConstructorSignal(stream);
    const finishedCallbacks = state[kOnFinished].splice(0);
    for (let i = 0; i < finishedCallbacks.length; i++) finishedCallbacks[i](null);
    stream.emit('finish');
    if (state.autoDestroy) {
      const readableState = stream._readableState;
      const autoDestroy = !readableState
        || (readableState.autoDestroy && (readableState.endEmitted || readableState.readable === false));
      if (autoDestroy) stream.destroy();
    }
  }
  defineGetters(Writable.prototype, {
    closed() { return this._writableState ? this._writableState.closed : false; },
    destroyed: {
      get() { return this._writableState ? this._writableState.destroyed : false; },
      set(value) { if (this._writableState) this._writableState.destroyed = value; },
    },
    writable: {
      get() {
        const w = this._writableState;
        return !!w && w.writable !== false && !w.destroyed && !w.errored && !w.ending && !w.ended;
      },
      set(value) {
        if (this._writableState) this._writableState.writable = !!value;
      },
    },
    writableFinished() { return this._writableState ? this._writableState.finished : false; },
    writableObjectMode() { return this._writableState ? this._writableState.objectMode : false; },
    writableBuffer() { return this._writableState && this._writableState.getBuffer(); },
    writableEnded() { return this._writableState ? this._writableState.ending : false; },
    writableNeedDrain() {
      const w = this._writableState;
      if (!w) return false;
      return !w.destroyed && !w.ending && w.needDrain;
    },
    writableHighWaterMark() { return this._writableState && this._writableState.highWaterMark; },
    writableCorked() { return this._writableState ? this._writableState.corked : 0; },
    writableLength() { return this._writableState && this._writableState.length; },
    errored() { return this._writableState ? this._writableState.errored : null; },
    writableAborted() {
      return !!(this._writableState.writable !== false
        && (this._writableState.destroyed || this._writableState.errored) && !this._writableState.finished);
    },
  });
  Writable.prototype.destroy = function (error, callback) {
    const state = this._writableState;
    if (!state.destroyed && (state.bufferedIndex < state.buffered.length || state[kOnFinished].length)) {
      nextTick(errorBuffer, state);
    }
    destroy.call(this, error, callback);
    return this;
  };
  Writable.prototype._undestroy = undestroy;
  Writable.prototype._destroy = function (error, callback) { callback(error); };

  // ---- Duplex ----
  function Duplex(options) {
    if (!(this instanceof Duplex)) return new Duplex(options);
    const signal = constructorSignalOption(options);
    Readable.call(this, options);
    Writable.call(this, options);
    if (options) {
      this.allowHalfOpen = options.allowHalfOpen !== false;
      if (options.readable === false) {
        this._readableState.readable = false;
        this._readableState.ended = true;
        this._readableState.endEmitted = true;
      }
      if (options.writable === false) {
        this._writableState.writable = false;
        this._writableState.ending = true;
        this._writableState.ended = true;
        this._writableState.finished = true;
      }
    } else {
      this.allowHalfOpen = true;
    }
    // Readable/Writable defer here: both halves and disabled-side flags must
    // exist before cancellation invokes the subclass's destroy implementation.
    if (signal !== undefined) attachConstructorSignal(this, signal);
  }
  Object.setPrototypeOf(Duplex.prototype, Readable.prototype);
  Object.setPrototypeOf(Duplex, Readable);
  {
    const keys = Object.keys(Writable.prototype);
    for (let i = 0; i < keys.length; i++) {
      const method = keys[i];
      if (!Duplex.prototype[method]) Duplex.prototype[method] = Writable.prototype[method];
    }
    for (const name of ['writable', 'writableHighWaterMark', 'writableObjectMode', 'writableBuffer',
      'writableLength', 'writableFinished', 'writableCorked', 'writableEnded', 'writableNeedDrain']) {
      Object.defineProperty(Duplex.prototype, name, Object.getOwnPropertyDescriptor(Writable.prototype, name));
    }
  }
  defineGetters(Duplex.prototype, {
    destroyed: {
      get() {
        if (this._readableState === undefined || this._writableState === undefined) return false;
        return this._readableState.destroyed && this._writableState.destroyed;
      },
      set(value) {
        if (this._readableState && this._writableState) {
          this._readableState.destroyed = value;
          this._writableState.destroyed = value;
        }
      },
    },
  });
  Duplex.prototype.destroy = Writable.prototype.destroy;

  // ---- Transform / PassThrough ----
  function Transform(options) {
    if (!(this instanceof Transform)) return new Transform(options);
    const readableHighWaterMark = options
      ? getHighWaterMark(this, options, 'readableHighWaterMark', true) : null;
    if (readableHighWaterMark === 0) {
      options = Object.assign({}, options, {
        highWaterMark: null,
        readableHighWaterMark: readableHighWaterMark,
        writableHighWaterMark: options.writableHighWaterMark || 0,
      });
    }
    Duplex.call(this, options);
    this._readableState.sync = false;
    this[kCallback] = null;
    if (options) {
      if (typeof options.transform === 'function') this._transform = options.transform;
      if (typeof options.flush === 'function') this._flush = options.flush;
    }
    this.on('prefinish', transformPrefinish);
  }
  Object.setPrototypeOf(Transform.prototype, Duplex.prototype);
  Object.setPrototypeOf(Transform, Duplex);
  function transformFinal(callback) {
    const self = this;
    if (typeof this._flush === 'function' && !this.destroyed) {
      this._flush(function (error, data) {
        if (error) {
          if (callback) {
            callback(error);
          } else {
            self.destroy(error);
          }
          return;
        }
        if (data != null) self.push(data);
        self.push(null);
        if (callback) callback();
      });
    } else {
      this.push(null);
      if (callback) callback();
    }
  }
  function transformPrefinish() {
    if (this._final !== transformFinal) transformFinal.call(this);
  }
  Transform.prototype._final = transformFinal;
  Transform.prototype._transform = function () {
    throw errors.notImplemented('_transform()');
  };
  Transform.prototype._write = function (chunk, encoding, callback) {
    const self = this;
    const readableState = self._readableState;
    const writableState = self._writableState;
    const length = readableState.length;
    this._transform(chunk, encoding, function (error, value) {
      if (error) {
        callback(error);
        return;
      }
      if (value != null) self.push(value);
      if (readableState.ended) {
        nextTick(callback);
      } else if (writableState.ended || length === readableState.length
        || readableState.length < readableState.highWaterMark) {
        callback();
      } else {
        self[kCallback] = callback;
      }
    });
  };
  Transform.prototype._read = function () {
    if (this[kCallback]) {
      const callback = this[kCallback];
      this[kCallback] = null;
      callback();
    }
  };
  function PassThrough(options) {
    if (!(this instanceof PassThrough)) return new PassThrough(options);
    Transform.call(this, options);
  }
  Object.setPrototypeOf(PassThrough.prototype, Transform.prototype);
  Object.setPrototypeOf(PassThrough, Transform);
  PassThrough.prototype._transform = function (chunk, encoding, callback) {
    callback(null, chunk);
  };

  // ---- finished (end-of-stream) ----
  function once(callback) {
    let called = false;
    return function () {
      if (called) return;
      called = true;
      return callback.apply(this, arguments);
    };
  }
  function eos(stream, options, callback) {
    if (arguments.length === 2) {
      callback = options;
      options = {};
    } else if (options == null) {
      options = {};
    }
    if (typeof callback !== 'function') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "callback" argument must be a function');
    }
    const signal = options.signal;
    const cancellation = signal === undefined ? null : pipelineCancellation(signal);
    let removeAbort = nop;
    const complete = once(callback);
    callback = function (error) {
      if (cancellation) {
        if (!error && cancellation.aborted()) error = cancellation.error();
        removeAbort();
        cancellation.abort(error);
      }
      return complete.call(this, error);
    };
    function onabort() {
      const error = cancellation.error();
      const done = callback;
      cleanup();
      done.call(stream, error);
    }
    const readable = options.readable != null ? options.readable : isReadableNodeStream(stream);
    const writable = options.writable != null ? options.writable : isWritableNodeStream(stream);
    const writableState = stream._writableState;
    const readableState = stream._readableState;
    const onlegacyfinish = function () {
      if (!stream.writable) onfinish();
    };
    let emitsClose = willEmitClose(stream) && isReadableNodeStream(stream) === readable
      && isWritableNodeStream(stream) === writable;
    let writableFinished = isWritableFinished(stream, false);
    const onfinish = function () {
      writableFinished = true;
      if (stream.destroyed) emitsClose = false;
      if (emitsClose && (!stream.readable || readable)) return;
      if (!readable || readableFinished) callback.call(stream);
    };
    let readableFinished = isReadableFinished(stream, false);
    const onend = function () {
      readableFinished = true;
      if (stream.destroyed) emitsClose = false;
      if (emitsClose && (!stream.writable || writable)) return;
      if (!writable || writableFinished) callback.call(stream);
    };
    const onerror = function (error) {
      callback.call(stream, error);
    };
    let closed = isClosed(stream);
    const onclose = function () {
      closed = true;
      const errored = isWritableErrored(stream) || isReadableErrored(stream);
      if (errored && typeof errored !== 'boolean') return callback.call(stream, errored);
      if (readable && !readableFinished && isReadableNodeStream(stream, true)) {
        if (!isReadableFinished(stream, false)) return callback.call(stream, errors.prematureClose());
      }
      if (writable && !writableFinished) {
        if (!isWritableFinished(stream, false)) return callback.call(stream, errors.prematureClose());
      }
      callback.call(stream);
    };
    const onclosed = function () {
      closed = true;
      const errored = isWritableErrored(stream) || isReadableErrored(stream);
      if (errored && typeof errored !== 'boolean') return callback.call(stream, errored);
      callback.call(stream);
    };
    if (writable && !writableState) {
      stream.on('end', onlegacyfinish);
      stream.on('close', onlegacyfinish);
    }
    if (!emitsClose && typeof stream.aborted === 'boolean') stream.on('aborted', onclose);
    stream.on('end', onend);
    stream.on('finish', onfinish);
    if (options.error !== false) stream.on('error', onerror);
    stream.on('close', onclose);
    if (cancellation) {
      removeAbort = cancellation.listen(onabort);
      if (cancellation.aborted()) nextTick(onabort);
    }
    if (closed) {
      nextTick(onclose);
    } else if ((writableState && writableState.errorEmitted) || (readableState && readableState.errorEmitted)) {
      if (!emitsClose) nextTick(onclosed);
    } else if (!readable && (!emitsClose || isReadable(stream))
      && (writableFinished || isWritable(stream) === false)) {
      nextTick(onclosed);
    } else if (!writable && (!emitsClose || isWritable(stream))
      && (readableFinished || isReadable(stream) === false)) {
      nextTick(onclosed);
    }
    function cleanup() {
      callback = nop;
      removeAbort();
      if (cancellation) cancellation.abort();
      stream.removeListener('aborted', onclose);
      stream.removeListener('end', onlegacyfinish);
      stream.removeListener('close', onlegacyfinish);
      stream.removeListener('finish', onfinish);
      stream.removeListener('end', onend);
      stream.removeListener('error', onerror);
      stream.removeListener('close', onclose);
    }
    return cleanup;
  }
  function finishedPromise(stream, options) {
    return new PipelinePromise(function (resolve, reject) {
      const autoCleanup = options != null && options.cleanup === true;
      let cleanup = nop;
      let settled = false;
      cleanup = eos(stream, options, function (error) {
        settled = true;
        if (autoCleanup) cleanup();
        if (error) reject(error);
        else resolve();
      });
      // A custom emitter can complete reentrantly during registration.
      if (autoCleanup && settled) cleanup();
    });
  }
  eos.finished = finishedPromise;

  // ---- pipeline ----
  // Capture cancellation intrinsics before a stage can replace public methods.
  // AbortSignal.any carries the source's native state even when an earlier
  // public listener stops propagation. The controller is private to this run.
  const PipelineController = AbortController;
  const pipelineApply = Reflect.apply;
  const pipelineCompose = AbortSignal.any;
  const pipelineControllerSignal = Object.getOwnPropertyDescriptor(AbortController.prototype, 'signal').get;
  const pipelineSignalAborted = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'aborted').get;
  const pipelineSignalReason = Object.getOwnPropertyDescriptor(AbortSignal.prototype, 'reason').get;
  const pipelineAbort = AbortController.prototype.abort;
  const pipelineAddListener = EventTarget.prototype.addEventListener;
  const pipelineRemoveListener = EventTarget.prototype.removeEventListener;
  const pipelineDefineProperty = Object.defineProperty;
  const pipelineCreateObject = Object.create;
  const pipelineIterator = Symbol.iterator;
  const PipelinePromise = Promise;

  function constructorSignalOption(options) {
    const signal = options == null ? undefined : options.signal;
    // The Node constructor band ignores null/falsy optional signals. Every
    // supplied object is authenticated without consulting replaceable fields.
    if (!signal) return undefined;
    try { pipelineApply(pipelineSignalAborted, signal, []); }
    catch (error) {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "signal" option must be an AbortSignal');
    }
    return signal;
  }
  function releaseConstructorSignal(stream) {
    if (constructorSignals === undefined) return;
    const owned = pipelineApply(streamWeakGet, constructorSignals, [stream]);
    if (owned === undefined) return;
    pipelineApply(streamWeakDelete, constructorSignals, [stream]);
    try { owned.remove(); }
    finally {
      // Remove first: successful completion must not look like cancellation.
      // Revoke the private source to unlink its dependent from a long-lived
      // caller signal, without allocating a default DOMException.
      owned.scope.abort(null);
    }
  }
  function releaseFinishedConstructorSignal(stream) {
    if (constructorSignals === undefined) return;
    const readable = stream._readableState;
    const writable = stream._writableState;
    if ((!readable || readable.readable === false || readable.endEmitted)
      && (!writable || writable.writable === false || writable.finished)) {
      releaseConstructorSignal(stream);
    }
  }
  function attachConstructorSignal(stream, signal) {
    const scope = pipelineCancellation(signal);
    const owned = { scope: scope, remove: nop };
    if (constructorSignals === undefined) constructorSignals = new StreamWeakMap();
    pipelineApply(streamWeakSet, constructorSignals, [stream, owned]);
    function cancel() {
      if (pipelineApply(streamWeakGet, constructorSignals, [stream]) !== owned) return;
      // Reuse ordinary destroy, including _construct synchronization and the
      // caller's asynchronous _destroy. An abort is not successful EOF.
      stream.destroy(scope.error());
    }
    try {
      owned.remove = scope.listen(cancel);
      if (scope.aborted()) cancel();
      else releaseFinishedConstructorSignal(stream);
    } catch (error) {
      releaseConstructorSignal(stream);
      throw error;
    }
  }

  function pipelineCancellation(outer) {
    if (outer !== undefined) {
      try { pipelineApply(pipelineSignalAborted, outer, []); }
      catch (error) {
        throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "signal" option must be an AbortSignal');
      }
    }
    const controller = new PipelineController();
    const own = pipelineApply(pipelineControllerSignal, controller, []);
    let signal = own;
    if (outer !== undefined) {
      const pair = [outer, own];
      const descriptor = pipelineCreateObject(null);
      descriptor.value = function () {
        let index = 0;
        return { next() {
          if (index++ === 0) return { value: outer, done: false };
          if (index === 2) return { value: own, done: false };
          return { value: undefined, done: true };
        } };
      };
      pipelineDefineProperty(pair, pipelineIterator, descriptor);
      signal = pipelineCompose(pair);
    }
    function aborted() { return pipelineApply(pipelineSignalAborted, signal, []); }
    return {
      signal: signal,
      aborted: aborted,
      error() {
        const error = makeError(Error, 'ABORT_ERR', 'The operation was aborted');
        error.name = 'AbortError';
        const descriptor = pipelineCreateObject(null);
        descriptor.value = pipelineApply(pipelineSignalReason, signal, []);
        descriptor.writable = true;
        descriptor.configurable = true;
        pipelineDefineProperty(error, 'cause', descriptor);
        return error;
      },
      abort(reason) { pipelineApply(pipelineAbort, controller, [reason]); },
      listen(callback) {
        // Synthetic events must not cancel a live run. Register before handing
        // the signal to any stage, so guest listeners cannot suppress cleanup.
        function listener() { if (aborted()) callback(); }
        pipelineApply(pipelineAddListener, signal, ['abort', listener, { once: false, capture: false, passive: false, signal: undefined }]);
        return function () { pipelineApply(pipelineRemoveListener, signal, ['abort', listener]); };
      }
    };
  }
  function pipelineRejection(reason) {
    if (reason) return reason;
    // Err-first completion cannot represent a falsy rejection. Do not let
    // throw null/undefined/false strand a live destination (or report success).
    const error = makeError(Error, 'ERR_STREAM_DESTROYED', 'Pipeline stage rejected without an error');
    const descriptor = pipelineCreateObject(null);
    descriptor.value = reason;
    descriptor.writable = true;
    descriptor.configurable = true;
    pipelineDefineProperty(error, 'cause', descriptor);
    return error;
  }
  function popCallback(streams) {
    if (typeof streams[streams.length - 1] !== 'function') {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE',
        'The "streams[stream.length - 1]" property must be of type function.'
        + describeReceived(streams[streams.length - 1]));
    }
    return streams.pop();
  }
  function pipeline() {
    const streams = Array.prototype.slice.call(arguments);
    return pipelineImpl(streams, once(popCallback(streams)), {});
  }
  function pipelineDestroyer(stream, reading, writing, settled) {
    let finished = false;
    const onclose = function () { finished = true; };
    stream.on('close', onclose);
    const cleanup = eos(stream, { readable: reading, writable: writing }, function (error) {
      finished = !error;
      if (settled) settled(error);
    });
    return {
      destroy(error) {
        if (finished) return;
        finished = true;
        destroyer(stream, error || errors.destroyed('pipe'));
      },
      cleanup() { cleanup(); stream.removeListener('close', onclose); },
    };
  }
  function makeAsyncIterable(value) {
    if (isIterable(value)) return value;
    if (isReadableNodeStream(value)) return fromReadable(value);
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE',
      'The "val" argument must be an instance of Readable, Iterable, or AsyncIterable.' + describeReceived(value));
  }
  async function* fromReadable(value) {
    yield* Readable.prototype[Symbol.asyncIterator].call(value);
  }
  async function pumpToNode(iterable, writable, finish, options) {
    let error;
    let ended = false;
    let pendingWrites = 0;
    let onresolve = null;
    const cancellation = options.cancellation;
    function resume(resumeError) {
      if (resumeError && !error) error = resumeError;
      if (onresolve) {
        const callback = onresolve;
        onresolve = null;
        callback();
      }
    }
    function check() {
      if (error) throw error;
      if (cancellation.aborted()) throw cancellation.error();
    }
    function wait() {
      return new PipelinePromise(function (resolve, reject) {
        try { check(); }
        catch (error) { reject(error); return; }
        onresolve = function () {
          try { check(); resolve(); } catch (error) { reject(error); }
        };
      });
    }
    const removeAbort = cancellation.listen(function () { resume(cancellation.error()); });
    writable.on('drain', resume);
    const cleanup = eos(writable, { readable: false }, function (error) {
      ended = true;
      resume(error);
    });
    let failure;
    try {
      check();
      while (writable.writableNeedDrain) await wait();
      for await (const chunk of iterable) {
        // A producer may resume after downstream cancellation. Never publish
        // that late result. Throwing here also awaits its IteratorClose.
        check();
        pendingWrites++;
        writable.write(chunk, function (error) { pendingWrites--; resume(error); });
        while (writable.writableNeedDrain) await wait();
      }
      check();
      while (pendingWrites > 0) await wait();
      if (options.end) {
        writable.end();
        while (!ended) await wait();
      }
      check();
    } catch (thrown) {
      failure = error && error !== thrown ? aggregateTwoErrors(error, thrown) : pipelineRejection(thrown);
    } finally {
      cleanup();
      writable.off('drain', resume);
      removeAbort();
    }
    finish(failure);
  }
  function pipelineImpl(streams, callback, options, setController) {
    if (streams.length === 1 && Array.isArray(streams[0])) streams = streams[0];
    if (streams.length < 2) throw errors.missingArgs('streams');
    const cancellation = pipelineCancellation(options.signal);
    let error;
    let value;
    const destroys = [];
    const cleanups = [];
    // Setup owns a participant until all streams and asynchronous work have
    // registered. A synchronous error cannot finish a half-built pipeline.
    let finishCount = 1;
    let building = true;
    let updating = false;
    let completed = false;
    let setupThrew = false;
    let removeAbort = function () {};
    function participant() {
      finishCount++;
      return once(function (error) { finishCount--; finishImpl(error); });
    }
    function finishImpl(finishError) {
      if (completed) return;
      if (!error && !finishError && cancellation.aborted()) finishError = cancellation.error();
      if (finishError && (!error || error.code === 'ERR_STREAM_PREMATURE_CLOSE')) error = finishError;
      if (updating) return;
      updating = true;
      try {
        if (error && !cancellation.aborted()) cancellation.abort(error);
        if (building) return;
        if (error || finishCount === 0) {
          while (destroys.length) destroys.shift()(error);
        }
        if (finishCount !== 0) return;
        completed = true;
        removeAbort();
        // Release the dependent's link to a long-lived external signal even
        // on success. Function stages receive completion cancellation too.
        cancellation.abort(error);
        if (!error) cleanups.forEach(function (cleanup) { cleanup(); });
        if (!setupThrew) nextTick(callback, error, value);
      } finally { updating = false; }
    }
    function ownStream(stream, reading, writing, end) {
      const onError = function (error) { finishImpl(error); };
      stream.on('error', onError);
      cleanups.push(function () { stream.removeListener('error', onError); });
      if (end) {
        const handles = pipelineDestroyer(stream, reading, writing, participant());
        destroys.push(handles.destroy);
        cleanups.push(handles.cleanup);
      } else {
        // end:false keeps the destination open on success, not on failure.
        // Destruction is registered before the call so synchronous _destroy
        // completion cannot escape the participant count.
        destroys.push(function (error) {
          if (!error) return;
          const done = participant();
          const cleanup = eos(stream, { readable: reading, writable: writing }, done);
          cleanups.push(cleanup);
          destroyer(stream, error);
        });
      }
    }
    removeAbort = cancellation.listen(function () { finishImpl(cancellation.error()); });
    if (setController !== undefined) {
      setController(finishImpl, cancellation, function () { return error; });
    }
    if (cancellation.aborted()) finishImpl(cancellation.error());
    let ret;
    try {
      for (let i = 0; i < streams.length; i++) {
        const stream = streams[i];
        const reading = i < streams.length - 1;
        const writing = i > 0;
        const end = reading || options.end !== false;
        if (isNodeStream(stream)) ownStream(stream, reading, writing, end);
        if (i === 0) {
          if (typeof stream === 'function') {
            ret = stream({ signal: cancellation.signal });
            if (!isIterable(ret)) throw errors.invalidReturn('source');
            if (isNodeStream(ret)) ownStream(ret, true, false, true);
          } else if (isIterable(stream) || isNodeStream(stream)) {
            ret = stream;
          } else {
            throw errors.invalidReturn('source');
          }
        } else if (typeof stream === 'function') {
          ret = makeAsyncIterable(ret);
          ret = stream(ret, { signal: cancellation.signal });
          if (reading) {
            if (!isIterable(ret, true)) throw errors.invalidReturn('transform[' + (i - 1) + ']');
            if (isNodeStream(ret)) ownStream(ret, true, false, true);
          } else {
            const pt = new PassThrough({ objectMode: true });
            ownStream(pt, false, true, end);
            const then = ret && ret.then;
            if (typeof then === 'function') {
              const done = participant();
              const result = ret;
              new PipelinePromise(function (resolve, reject) {
                pipelineApply(then, result, [resolve, reject]);
              }).then(function (resolved) {
                if (cancellation.aborted()) throw error || cancellation.error();
                value = resolved;
                if (resolved != null) pt.write(resolved);
                if (end) pt.end();
              }).then(function () { done(); }, function (error) { done(pipelineRejection(error)); });
            } else if (isIterable(ret, true)) {
              pumpToNode(ret, pt, participant(), { end: end, cancellation: cancellation });
            } else {
              throw errors.invalidReturn('destination');
            }
            ret = pt;
          }
        } else if (isNodeStream(stream)) {
          if (isReadableNodeStream(ret) && end) {
            const cleanup = pipeStreams(ret, stream, participant(), participant());
            cleanups.push(cleanup);
          } else if (isIterable(ret) || isReadableNodeStream(ret)) {
            pumpToNode(makeAsyncIterable(ret), stream, participant(), { end: end, cancellation: cancellation });
          } else {
            throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE',
              'The "val" argument must be an instance of Readable, Iterable, AsyncIterable, ReadableStream, or TransformStream.'
              + describeReceived(ret));
          }
          ret = stream;
        } else {
          throw errors.invalidReturn(reading ? 'transform[' + (i - 1) + ']' : 'destination');
        }
      }
    } catch (thrown) {
      setupThrew = true;
      finishImpl(pipelineRejection(thrown));
      throw thrown;
    } finally {
      building = false;
      finishCount--;
      finishImpl();
    }
    return ret;
  }
  function pipeStreams(src, dst, sourceDone, destinationDone) {
    function endFn() { dst.end(); }
    const sourceCleanup = eos(src, { readable: true, writable: false }, function (error) {
      const readableState = src._readableState;
      if (error && error.code === 'ERR_STREAM_PREMATURE_CLOSE'
        && readableState && readableState.ended && !readableState.errored && !readableState.errorEmitted) {
        src.once('end', sourceDone).once('error', sourceDone);
      } else { sourceDone(error); }
    });
    const destinationCleanup = eos(dst, { readable: false, writable: true }, destinationDone);
    if (isReadableFinished(src)) nextTick(endFn);
    else src.once('end', endFn);
    src.pipe(dst, { end: false });
    return function () {
      sourceCleanup();
      destinationCleanup();
      src.removeListener('end', endFn);
      src.removeListener('end', sourceDone);
      src.removeListener('error', sourceDone);
    };
  }
  function pipelinePromise() {
    const streams = Array.prototype.slice.call(arguments);
    let options = {};
    const last = streams[streams.length - 1];
    if (last && typeof last === 'object' && !isNodeStream(last) && !isIterable(last)) {
      options = streams.pop();
    }
    return new PipelinePromise(function (resolve, reject) {
      pipelineImpl(streams, function (error, value) {
        if (error) reject(error);
        else resolve(value);
      }, { end: options.end, signal: options.signal });
    });
  }

  // ---- composition ----
  const composeReadableFrom = Readable.from;
  const composeIsBuffer = Buffer.isBuffer;

  function composeSource(source) {
    if (isReadableNodeStream(source)) return source;
    if (typeof source === 'string' || composeIsBuffer(source) || isIterable(source)) {
      return composeReadableFrom(source);
    }
    throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE',
      'The first composition stage must be a readable stream, iterable, or function');
  }

  function composeStreams(stages, signal) {
    if (stages.length === 0) throw errors.missingArgs('streams');
    // Validate before invoking factories, subscribing, or starting any source.
    if (signal !== undefined) {
      try { pipelineApply(pipelineSignalAborted, signal, []); }
      catch (error) {
        throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "signal" option must be an AbortSignal');
      }
    }
    for (let i = 0; i < stages.length; i++) {
      const stage = stages[i];
      if (typeof stage === 'function') continue;
      if (isNodeStream(stage)) {
        if (isDestroyed(stage) || (i > 0 && !isWritableNodeStream(stage))
          || (i < stages.length - 1 && !isReadableNodeStream(stage))) {
          throw makeError(TypeError, 'ERR_INVALID_ARG_VALUE', 'Invalid composition stream at index ' + i);
        }
      } else if (i !== 0 || !(typeof stage === 'string' || composeIsBuffer(stage) || isIterable(stage))) {
        throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'Invalid composition stage at index ' + i);
      }
    }
    if (stages.length === 1 && stages[0] instanceof Duplex && signal === undefined) {
      return stages[0];
    }

    let head;
    let outputReadable = true;
    if (typeof stages[0] === 'function') {
      // A function in compose is a transform/sink over input, not a pipeline
      // source factory. The private stream supplies demand-driven async input.
      head = new PassThrough({ objectMode: true });
      stages.unshift(head);
    } else if (stages.length === 1 && isWritableNodeStream(stages[0])
      && !isReadableNodeStream(stages[0])) {
      const sink = stages[0];
      head = new PassThrough({ objectMode: !!sink.writableObjectMode,
        highWaterMark: sink.writableHighWaterMark });
      stages.unshift(head);
    } else {
      stages[0] = composeSource(stages[0]);
      if (isWritableNodeStream(stages[0])) head = stages[0];
      if (stages.length === 1) {
        const source = stages[0];
        stages.push(new PassThrough({ objectMode: !!source.readableObjectMode,
          highWaterMark: source.readableHighWaterMark }));
      }
    }
    const last = stages.length - 1;
    if (typeof stages[last] === 'function') {
      const operation = stages[last];
      stages[last] = function (input, options) {
        const result = operation(input, options);
        if (isIterable(result, true)) return result;
        const then = result && result.then;
        if (typeof then !== 'function') throw errors.invalidReturn('destination');
        outputReadable = false;
        return new PipelinePromise(function (resolve, reject) {
          pipelineApply(then, result, [resolve, reject]);
        }).then(function (value) {
          if (value !== undefined && value !== null) {
            throw makeError(TypeError, 'ERR_INVALID_RETURN_VALUE',
              'A composition sink function must resolve to null or undefined');
          }
        });
      };
    } else {
      outputReadable = isReadableNodeStream(stages[last]);
    }

    let duplex;
    let stop = nop;
    let pipelineError = function () {};
    let removeStopListener = nop;
    let innerDone = false;
    let innerError;
    let destroyCallback;
    let destroyError;
    let writeCallback;
    let finalCallback;
    let reading = false;
    let pumping = false;
    let tailEnded = false;
    function finishWrite(error) {
      const callback = writeCallback;
      writeCallback = undefined;
      if (callback) callback(error);
    }
    function finishFinal(error) {
      const callback = finalCallback;
      finalCallback = undefined;
      if (callback) callback(error);
    }
    function cleanup() {
      if (outputReadable) {
        tail.removeListener('readable', drain);
        tail.removeListener('end', onend);
      }
    }
    function finishDestroy() {
      if (!destroyCallback || !innerDone) return;
      const callback = destroyCallback;
      destroyCallback = undefined;
      cleanup();
      const error = destroyError || innerError;
      finishWrite(error || errors.destroyed('write'));
      finishFinal(error || errors.destroyed('end'));
      callback(error);
    }
    function complete(error) {
      removeStopListener();
      innerDone = true;
      innerError = error;
      stop = nop;
      if (!duplex) return;
      if (destroyCallback) finishDestroy();
      else if (error) duplex.destroy(error);
      else finishFinal();
    }
    // The private stop endpoint uses the same pipeline owner and participant
    // count, preserving the original error and awaiting all admitted cleanup.
    // It is not exposed through public pipeline options.
    const tail = pipelineImpl(stages, complete, { signal: signal },
      function (controller, cancellation, currentError) {
        stop = controller;
        pipelineError = currentError;
        removeStopListener = cancellation.listen(function () {
          // Observe stop immediately; do not leave the outer stream writable
          // while an inner async destructor or IteratorClose is still pending.
          const error = currentError();
          if (duplex && error) duplex.destroy(error);
        });
      });
    function drain() {
      if (!reading || pumping || duplex.destroyed || tailEnded) return;
      pumping = true;
      try {
        while (reading && !duplex.destroyed) {
          const chunk = tail.read();
          if (chunk === null) break;
          reading = duplex.push(chunk);
        }
      } catch (error) { duplex.destroy(error); }
      finally { pumping = false; }
    }
    function onend() {
      if (tailEnded) return;
      tailEnded = true;
      reading = false;
      if (!duplex.destroyed) duplex.push(null);
    }
    try {
      duplex = new Duplex({
        readable: outputReadable,
        writable: head !== undefined,
        readableObjectMode: outputReadable && !!tail.readableObjectMode,
        writableObjectMode: head !== undefined && !!head.writableObjectMode,
        readableHighWaterMark: outputReadable ? tail.readableHighWaterMark : undefined,
        writableHighWaterMark: head === undefined ? undefined : head.writableHighWaterMark,
        read() { reading = true; drain(); },
        write(chunk, encoding, callback) {
          const pending = once(callback);
          writeCallback = pending;
          const written = once(function (error) {
            if (writeCallback === pending) writeCallback = undefined;
            pending(error);
          });
          try { head.write(chunk, encoding, written); }
          catch (error) { written(error); }
        },
        final(callback) {
          finalCallback = once(callback);
          try { head.end(); }
          catch (error) { finishFinal(error); return; }
          if (innerDone) finishFinal(innerError);
        },
        destroy(error, callback) {
          // Readable EOF can auto-destroy a read-only outer stream one tick
          // before the inner pipeline reports completion. Drain that successful
          // close instead of turning natural EOF into cancellation.
          const finishedSides = (!outputReadable || duplex.readableEnded)
            && (head === undefined || duplex.writableFinished);
          destroyError = error || (innerDone ? innerError : finishedSides ? undefined : makeAbortError());
          destroyCallback = callback;
          reading = false;
          if (!innerDone && destroyError) stop(destroyError);
          finishDestroy();
        }
      });
      if (outputReadable) {
        tail.on('readable', drain);
        tail.on('end', onend);
        if (tail.readableEnded) nextTick(onend);
      }
    } catch (error) {
      // Endpoint getters and listener registration are guest-observable. A
      // failure after pipeline startup must not strand its acquired stages.
      if (duplex) { duplex.on('error', nop); duplex.destroy(error); }
      else stop(error);
      throw error;
    }
    const failure = pipelineError();
    if (failure) duplex.destroy(failure);
    return duplex;
  }
  function compose() {
    return composeStreams(Array.prototype.slice.call(arguments), undefined);
  }
  function readableCompose(stage, options) {
    if (options !== undefined && (options === null || typeof options !== 'object')) {
      throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE', 'The "options" argument must be an object');
    }
    return composeStreams([this, stage], options === undefined ? undefined : options.signal);
  }

  // ---- module object ----
  const promises = { pipeline: pipelinePromise, finished: finishedPromise };
  Stream.Stream = Stream;
  Stream.Readable = Readable;
  Stream.Writable = Writable;
  Stream.Duplex = Duplex;
  Stream.Transform = Transform;
  Stream.PassThrough = PassThrough;
  Stream.pipeline = pipeline;
  Stream.compose = compose;
  Object.defineProperty(Readable.prototype, 'compose', {
    value: readableCompose, writable: true, configurable: true
  });
  Stream.finished = eos;
  Stream.destroy = destroyer;
  Stream.isReadable = isReadable;
  Stream.isWritable = isWritable;
  Stream.isErrored = function (stream) {
    return !!(isNodeStream(stream) && (isWritableErrored(stream) || isReadableErrored(stream)));
  };
  Stream.isDisturbed = function (stream) {
    return !!(stream && stream._readableState
      && (stream._readableState.dataEmitted || isDestroyed(stream)));
  };
  Stream.isDestroyed = isDestroyed;
  Stream._isUint8Array = isUint8Array;
  Stream._uint8ArrayToBuffer = toBuffer;
  Object.defineProperty(Stream, 'promises', { value: promises, enumerable: true, configurable: true });
  Object.defineProperty(pipeline, Symbol.for('nodejs.util.promisify.custom'), {
    value: pipelinePromise, enumerable: true, configurable: true,
  });
  Object.defineProperty(eos, Symbol.for('nodejs.util.promisify.custom'), {
    value: finishedPromise, enumerable: true, configurable: true,
  });
  return Stream;
})()
