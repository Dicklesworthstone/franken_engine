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

  function isUint8Array(value) {
    return value instanceof Uint8Array;
  }
  function toBuffer(chunk) {
    return Buffer.from(chunk.buffer, chunk.byteOffset, chunk.byteLength);
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
  function BufferList() {
    this.chunks = [];
    this.index = 0;
  }
  BufferList.prototype.size = function () { return this.chunks.length - this.index; };
  BufferList.prototype.push = function (chunk) { this.chunks.push(chunk); };
  BufferList.prototype.unshift = function (chunk) {
    if (this.index > 0) {
      this.index -= 1;
      this.chunks[this.index] = chunk;
    } else {
      this.chunks.unshift(chunk);
    }
  };
  BufferList.prototype.first = function () { return this.chunks[this.index]; };
  BufferList.prototype.shift = function () {
    const chunk = this.chunks[this.index];
    this.chunks[this.index] = null;
    this.index += 1;
    if (this.index === this.chunks.length) this.clear();
    return chunk;
  };
  BufferList.prototype.clear = function () {
    this.chunks = [];
    this.index = 0;
  };
  BufferList.prototype.all = function () { return this.chunks.slice(this.index); };
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
      } else if (chunk instanceof Buffer) {
        encoding = '';
      } else if (isUint8Array(chunk)) {
        chunk = toBuffer(chunk);
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
    const readable = new ReadableClass(Object.assign({ objectMode: true, highWaterMark: 1 }, options));
    let reading = false;
    let isAsyncValues = false;
    readable._read = function () {
      if (!reading) {
        reading = true;
        if (isAsync) {
          nextAsync();
        } else if (isAsyncValues) {
          nextSyncWithAsyncValues();
        } else {
          nextSyncWithSyncValues();
        }
      }
    };
    readable._destroy = function (error, callback) {
      close(error).then(
        function () { nextTick(callback, error); },
        function (closeError) { nextTick(callback, closeError || error); },
      );
    };
    async function close(error) {
      const hadError = error !== undefined && error !== null;
      const hasThrow = typeof iterator.throw === 'function';
      if (hadError && hasThrow) {
        const result = await iterator.throw(error);
        await result.value;
        if (result.done) return;
      }
      if (typeof iterator.return === 'function') {
        const result = await iterator.return();
        await result.value;
      }
    }
    function nextSyncWithSyncValues() {
      for (;;) {
        try {
          const step = iterator.next();
          if (step.done) {
            readable.push(null);
            return;
          }
          const value = step.value;
          if (value && typeof value.then === 'function') {
            isAsyncValues = true;
            changeToAsyncValues(value);
            return;
          }
          if (value === null) {
            reading = false;
            throw errors.nullValues();
          }
          if (readable.push(value)) continue;
          reading = false;
        } catch (error) {
          readable.destroy(error);
        }
        break;
      }
    }
    async function changeToAsyncValues(value) {
      try {
        const resolved = await value;
        if (resolved === null) {
          reading = false;
          throw errors.nullValues();
        }
        if (readable.push(resolved)) {
          nextSyncWithAsyncValues();
          return;
        }
        reading = false;
      } catch (error) {
        readable.destroy(error);
      }
    }
    async function nextSyncWithAsyncValues() {
      for (;;) {
        try {
          const step = iterator.next();
          if (step.done) {
            readable.push(null);
            return;
          }
          const value = step.value;
          const resolved = value && typeof value.then === 'function' ? await value : value;
          if (resolved === null) {
            reading = false;
            throw errors.nullValues();
          }
          if (readable.push(resolved)) continue;
          reading = false;
        } catch (error) {
          readable.destroy(error);
        }
        break;
      }
    }
    async function nextAsync() {
      for (;;) {
        try {
          const step = await iterator.next();
          if (step.done) {
            readable.push(null);
            return;
          }
          if (step.value === null) {
            reading = false;
            throw errors.nullValues();
          }
          if (readable.push(step.value)) continue;
          reading = false;
        } catch (error) {
          readable.destroy(error);
        }
        break;
      }
    }
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
      } else if (chunk instanceof Buffer) {
        encoding = 'buffer';
      } else if (isUint8Array(chunk)) {
        chunk = toBuffer(chunk);
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
    if (state.writing || state.corked || state.errored || !state.constructed) {
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
      stream._writev(chunk, state.onwrite);
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
    finishMaybe(stream, state);
  }
  function errorBuffer(state) {
    if (state.writing) return;
    for (let n = state.bufferedIndex; n < state.buffered.length; ++n) {
      const entry = state.buffered[n];
      const length = state.objectMode ? 1 : entry.chunk.length;
      state.length -= length;
      entry.callback(state.errored != null ? state.errored : errors.destroyed('write'));
    }
    const finishedCallbacks = state[kOnFinished].splice(0);
    for (let i = 0; i < finishedCallbacks.length; i++) {
      finishedCallbacks[i](state.errored != null ? state.errored : errors.destroyed('end'));
    }
    resetBuffer(state);
  }
  function clearBuffer(stream, state) {
    if (state.corked || state.bufferProcessing || state.destroyed || !state.constructed) return;
    const buffered = state.buffered;
    const bufferedLength = buffered.length - state.bufferedIndex;
    if (!bufferedLength) return;
    let i = state.bufferedIndex;
    state.bufferProcessing = true;
    if (bufferedLength > 1 && stream._writev) {
      state.pendingcb -= bufferedLength - 1;
      const callback = state.allNoop ? nop : function (error) {
        for (let n = i; n < buffered.length; ++n) buffered[n].callback(error);
      };
      const chunks = state.allNoop && i === 0 ? buffered : buffered.slice(i);
      chunks.allBuffers = state.allBuffers;
      doWrite(stream, state, true, state.length, chunks, '', callback);
      resetBuffer(state);
    } else {
      do {
        const entry = buffered[i];
        buffered[i++] = null;
        const length = state.objectMode ? 1 : entry.chunk.length;
        doWrite(stream, state, false, length, entry.chunk, entry.encoding, entry.callback);
      } while (i < buffered.length && !state.writing);
      if (i === buffered.length) {
        resetBuffer(state);
      } else if (i > 256) {
        buffered.splice(0, i);
        state.bufferedIndex = 0;
      } else {
        state.bufferedIndex = i;
      }
    }
    state.bufferProcessing = false;
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
    const readableState = this._readableState;
    const writableState = this._writableState;
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
    callback = once(callback);
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
    return function cleanup() {
      callback = nop;
      stream.removeListener('aborted', onclose);
      stream.removeListener('end', onlegacyfinish);
      stream.removeListener('close', onlegacyfinish);
      stream.removeListener('finish', onfinish);
      stream.removeListener('end', onend);
      stream.removeListener('error', onerror);
      stream.removeListener('close', onclose);
    };
  }
  function finishedPromise(stream, options) {
    return new Promise(function (resolve, reject) {
      eos(stream, options, function (error) {
        if (error) {
          reject(error);
        } else {
          resolve();
        }
      });
    });
  }
  eos.finished = finishedPromise;

  // ---- pipeline ----
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
  function pipelineDestroyer(stream, reading, writing) {
    let finished = false;
    stream.on('close', function () { finished = true; });
    const cleanup = eos(stream, { readable: reading, writable: writing }, function (error) {
      finished = !error;
    });
    return {
      destroy(error) {
        if (finished) return;
        finished = true;
        destroyer(stream, error || errors.destroyed('pipe'));
      },
      cleanup: cleanup,
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
    let onresolve = null;
    function resume(resumeError) {
      if (resumeError) error = resumeError;
      if (onresolve) {
        const callback = onresolve;
        onresolve = null;
        callback();
      }
    }
    function wait() {
      return new Promise(function (resolve, reject) {
        if (error) {
          reject(error);
        } else {
          onresolve = function () {
            if (error) {
              reject(error);
            } else {
              resolve();
            }
          };
        }
      });
    }
    writable.on('drain', resume);
    const cleanup = eos(writable, { readable: false }, resume);
    try {
      if (writable.writableNeedDrain) await wait();
      for await (const chunk of iterable) {
        if (!writable.write(chunk)) await wait();
      }
      if (options.end) {
        writable.end();
        await wait();
      }
      finish();
    } catch (thrown) {
      finish(error !== thrown ? aggregateTwoErrors(error, thrown) : thrown);
    } finally {
      cleanup();
      writable.off('drain', resume);
    }
  }
  function pipelineImpl(streams, callback, options) {
    if (streams.length === 1 && Array.isArray(streams[0])) streams = streams[0];
    if (streams.length < 2) throw errors.missingArgs('streams');
    let error;
    let value;
    const destroys = [];
    let finishCount = 0;
    const lastStreamCleanup = [];
    function finish(finishError) {
      finishImpl(finishError, --finishCount === 0);
    }
    function finishImpl(finishError, final) {
      if (finishError && (!error || error.code === 'ERR_STREAM_PREMATURE_CLOSE')) error = finishError;
      if (!error && !final) return;
      while (destroys.length) destroys.shift()(error);
      if (final) {
        if (!error) lastStreamCleanup.forEach(function (cleanup) { cleanup(); });
        nextTick(callback, error, value);
      }
    }
    let ret;
    for (let i = 0; i < streams.length; i++) {
      const stream = streams[i];
      const reading = i < streams.length - 1;
      const writing = i > 0;
      const end = reading || options.end !== false;
      const isLastStream = i === streams.length - 1;
      if (isNodeStream(stream)) {
        if (end) {
          const handles = pipelineDestroyer(stream, reading, writing);
          destroys.push(handles.destroy);
          if (isReadable(stream) && isLastStream) lastStreamCleanup.push(handles.cleanup);
        }
        stream.on('error', function onError(streamError) {
          if (streamError && streamError.name !== 'AbortError' && streamError.code !== 'ERR_STREAM_PREMATURE_CLOSE') {
            finish(streamError);
          }
        });
      }
      if (i === 0) {
        if (typeof stream === 'function') {
          ret = stream({ signal: undefined });
          if (!isIterable(ret)) throw errors.invalidReturn('source');
        } else if (isIterable(stream) || isNodeStream(stream)) {
          ret = stream;
        } else {
          throw errors.invalidReturn('source');
        }
      } else if (typeof stream === 'function') {
        ret = makeAsyncIterable(ret);
        ret = stream(ret, { signal: undefined });
        if (reading) {
          if (!isIterable(ret, true)) throw errors.invalidReturn('transform[' + (i - 1) + ']');
        } else {
          const pt = new PassThrough({ objectMode: true });
          const then = ret && ret.then;
          if (typeof then === 'function') {
            finishCount++;
            then.call(ret,
              function (resolved) {
                value = resolved;
                if (resolved != null) pt.write(resolved);
                if (end) pt.end();
                nextTick(finish);
              },
              function (rejected) {
                pt.destroy(rejected);
                nextTick(finish, rejected);
              });
          } else if (isIterable(ret, true)) {
            finishCount++;
            pumpToNode(ret, pt, finish, { end: end });
          } else {
            throw errors.invalidReturn('destination');
          }
          ret = pt;
          const handles = pipelineDestroyer(ret, false, true);
          destroys.push(handles.destroy);
          if (isLastStream) lastStreamCleanup.push(handles.cleanup);
        }
      } else if (isNodeStream(stream)) {
        if (isReadableNodeStream(ret)) {
          finishCount += 2;
          const cleanup = pipeStreams(ret, stream, finish, { end: end });
          if (isReadable(stream) && isLastStream) lastStreamCleanup.push(cleanup);
        } else if (isIterable(ret)) {
          finishCount++;
          pumpToNode(ret, stream, finish, { end: end });
        } else {
          throw makeError(TypeError, 'ERR_INVALID_ARG_TYPE',
            'The "val" argument must be an instance of Readable, Iterable, AsyncIterable, ReadableStream, or TransformStream.'
            + describeReceived(ret));
        }
        ret = stream;
      } else {
        ret = Duplex.from ? Duplex.from(stream) : stream;
      }
    }
    return ret;
  }
  function pipeStreams(src, dst, finish, options) {
    let ended = false;
    dst.on('close', function () {
      if (!ended) finish(errors.prematureClose());
    });
    src.pipe(dst, { end: false });
    if (options.end) {
      function endFn() {
        ended = true;
        dst.end();
      }
      if (isReadableFinished(src)) {
        nextTick(endFn);
      } else {
        src.once('end', endFn);
      }
      eos(src, { readable: true, writable: false }, function (error) {
        const readableState = src._readableState;
        if (error && error.code === 'ERR_STREAM_PREMATURE_CLOSE'
          && readableState && readableState.ended && !readableState.errored && !readableState.errorEmitted) {
          src.once('end', finish).once('error', finish);
        } else {
          finish(error);
        }
      });
    } else {
      finish();
    }
    return eos(dst, { readable: false, writable: true }, finish);
  }
  function pipelinePromise() {
    const streams = Array.prototype.slice.call(arguments);
    let options = {};
    const last = streams[streams.length - 1];
    if (last && typeof last === 'object' && !isNodeStream(last) && !isIterable(last)) {
      options = streams.pop();
    }
    return new Promise(function (resolve, reject) {
      pipelineImpl(streams, function (error, value) {
        if (error) {
          reject(error);
        } else {
          resolve(value);
        }
      }, { end: options.end });
    });
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
