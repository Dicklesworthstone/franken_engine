(function () {
  'use strict';
  // Capture realm helpers before guest code can replace their public bindings.
  // Capturing them performs no filesystem effect and grants no filesystem authority.
  var NativePromise = Promise;
  var promiseThen = Promise.prototype.then;
  var apply = Reflect.apply;
  var bufferAlloc = Buffer.alloc;
  var bufferFrom = Buffer.from;
  var isBuffer = Buffer.isBuffer;
  var isEncoding = Buffer.isEncoding;
  var bufferConcat = Buffer.concat;
  var bufferSlice = Buffer.prototype.subarray;
  var bufferToString = Buffer.prototype.toString;
  var bufferCopy = Buffer.prototype.copy;
  var arrayIsArray = Array.isArray;
  var NativeWeakMap = WeakMap;
  var getHandle = WeakMap.prototype.get;
  var setHandle = WeakMap.prototype.set;
  var handles;
  var iteratorKey = Symbol.iterator;
  var asyncIteratorKey = Symbol.asyncIterator;
  var isView = ArrayBuffer.isView;
  var NativeAggregateError = AggregateError;
  // Authenticate byte windows at the same boundary for scalar, vector and
  // stream I/O. Public view metadata (including subclass getters) is not the
  // storage selected by the caller's ArrayBufferView. Capture realm accessors
  // before guest code replaces them, as the shared stream/decoder modules do.
  var typedPrototype = Object.getPrototypeOf(Uint8Array.prototype);
  var typedBuffer = Object.getOwnPropertyDescriptor(typedPrototype, 'buffer').get;
  var typedOffset = Object.getOwnPropertyDescriptor(typedPrototype, 'byteOffset').get;
  var typedLength = Object.getOwnPropertyDescriptor(typedPrototype, 'byteLength').get;
  var dataBuffer = Object.getOwnPropertyDescriptor(DataView.prototype, 'buffer').get;
  var dataOffset = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteOffset').get;
  var dataLength = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get;
  // The discriminator is the same typed FsOperation argument the old direct
  // call lowering emits. In particular, fd lifecycle operations require write
  // authority. No wrapper performs host I/O outside these two intrinsics.
  function readFileSync(path, options) {
    return __franken_fs_read('\0fsop:read', path, options);
  }
  function writeFileSync(path, data, options) {
    return __franken_fs_write('\0fsop:write', path, data, options);
  }
  function appendFileSync(path, data, options) {
    return __franken_fs_write('\0fsop:append', path, data, options);
  }
  function existsSync(path) {
    return __franken_fs_read('\0fsop:exists', path);
  }
  function statSync(path, options) {
    return __franken_fs_read('\0fsop:stat', path, options);
  }
  function lstatSync(path, options) {
    return __franken_fs_read('\0fsop:lstat', path, options);
  }
  function readdirSync(path, options) {
    return __franken_fs_read('\0fsop:readdir', path, options);
  }
  function mkdirSync(path, options) {
    return __franken_fs_write('\0fsop:mkdir', path, options);
  }
  function unlinkSync(path) {
    return __franken_fs_write('\0fsop:unlink', path);
  }
  function rmdirSync(path, options) {
    return __franken_fs_write('\0fsop:rmdir', path, options);
  }
  function rmSync(path, options) {
    return __franken_fs_write('\0fsop:remove', path, options);
  }
  function renameSync(oldPath, newPath) {
    return __franken_fs_write('\0fsop:rename', oldPath, newPath);
  }
  function copyFileSync(source, destination, mode) {
    return __franken_fs_write('\0fsop:copy_file', source, destination, mode);
  }
  function accessSync(path, mode) {
    return __franken_fs_read('\0fsop:access', path, mode);
  }
  function chmodSync(path, mode) {
    return __franken_fs_write('\0fsop:chmod', path, mode);
  }
  function utimesSync(path, atime, mtime) {
    return __franken_fs_write('\0fsop:utimes', path, atime, mtime);
  }
  function realpathSync(path, options) {
    return __franken_fs_read('\0fsop:realpath', path, options);
  }
  function readlinkSync(path, options) {
    return __franken_fs_read('\0fsop:readlink', path, options);
  }
  function symlinkSync(target, path, type) {
    return __franken_fs_write('\0fsop:symlink', target, path, type);
  }
  function truncateSync(path, length) {
    return __franken_fs_write('\0fsop:truncate', path, length);
  }
  function mkdtempSync(prefix, options) {
    return __franken_fs_write('\0fsop:mkdtemp', prefix, options);
  }
  function openSync(path, flags, mode) {
    return __franken_fs_write('\0fsop:open', path, flags, mode);
  }
  function closeSync(fd) {
    return __franken_fs_write('\0fsop:close_fd', fd);
  }
  function fsyncSync(fd) {
    return __franken_fs_write('\0fsop:fsync', fd);
  }
  function readSync(fd, buffer, offset, length, position) {
    return __franken_fs_read('\0fsop:read_fd', fd, buffer, offset, length, position);
  }
  function writeSync(fd, data, offset, length, position) {
    return __franken_fs_write('\0fsop:write_fd', fd, data, offset, length, position);
  }
  function vectorBuffers(buffers) {
    if (!arrayIsArray(buffers)) { throw argumentError('buffers (expected ArrayBufferView array)'); }
    // Snapshot entries before I/O. An array getter can mutate a later entry or
    // re-enter close(); validation must finish before any descriptor effect.
    var entries = [];
    var lengths = [];
    var total = 0;
    var nonempty = 0;
    var single;
    var count = buffers.length;
    for (var index = 0; index < count; index += 1) {
      var buffer = buffers[index];
      var window = bufferWindow(buffer);
      entries[index] = window.buffer;
      lengths[index] = window.length;
      total += window.length;
      if (window.length !== 0) { nonempty += 1; single = window.buffer; }
      if (total > 9007199254740991) {
        var error = new RangeError('Combined buffer length is out of range');
        error.code = 'ERR_OUT_OF_RANGE';
        throw error;
      }
    }
    return { entries: entries, lengths: lengths, total: total,
      single: nonempty === 1 ? single : undefined };
  }
  function vectorPosition(position) {
    // Node's vector APIs use the descriptor cursor unless given a valid,
    // nonnegative, safe-integer position. No coercion invokes guest code.
    return typeof position === 'number' && position % 1 === 0 &&
      position >= 0 && position <= 9007199254740991 ? position : null;
  }
  function readvSync(fd, buffers, position) {
    var vector = vectorBuffers(buffers);
    if (vector.total === 0) { return 0; }
    // A single nonempty byte view is already a native read target. Validate
    // every entry first, including empty entries and getters after that view.
    // Multiple targets still stage one read and scatter its returned prefix;
    // in particular, overlapping views must keep their ordered scatter.
    var data = vector.single === undefined ? bufferAlloc(vector.total) : vector.single;
    var count = checkedCount(readSync(fd, data, 0, vector.total, vectorPosition(position)),
      vector.total, 'readv', false);
    if (vector.single !== undefined) { return count; }
    var offset = 0;
    for (var index = 0; index < vector.entries.length && offset < count; index += 1) {
      var length = vector.lengths[index];
      if (length > count - offset) { length = count - offset; }
      if (length === 0) { continue; }
      var copied = apply(bufferCopy, data, [vector.entries[index], 0, offset, offset + length]);
      if (checkedCount(copied, length, 'readv', true) !== length) {
        var error = new Error('Incomplete scatter from filesystem buffer');
        error.code = 'EIO';
        error.syscall = 'readv';
        throw error;
      }
      offset += length;
    }
    return count;
  }
  function writevSync(fd, buffers, position) {
    var vector = vectorBuffers(buffers);
    if (vector.total === 0) { return 0; }
    // One write preserves the native operation's append/partial-write
    // behavior. Unlike writeFile, writev reports short writes without retry.
    var data = vector.single === undefined ? bufferConcat(vector.entries, vector.total) : vector.single;
    return checkedCount(writeSync(fd, data, 0, vector.total, vectorPosition(position)),
      vector.total, 'writev', false);
  }
  function validateCallback(callback) {
    if (typeof callback !== 'function') {
      var error = new TypeError('The "cb" argument must be of type function');
      error.code = 'ERR_INVALID_ARG_TYPE';
      throw error;
    }
  }
  function readFile(path, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    validateCallback(callback);
    // The closure adapter also accepts bound/builtin callbacks; the native
    // host-I/O scheduler owns completion timing and filesystem result labels.
    return __franken_fs_read('\0fsop:read', path, options, function (error, value) {
      callback(error, value);
    });
  }
  function writeFile(path, data, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    validateCallback(callback);
    return __franken_fs_write('\0fsop:write', path, data, options, function (error) {
      callback(error);
    });
  }
  function appendFile(path, data, options, callback) {
    if (typeof options === 'function') {
      callback = options;
      options = undefined;
    }
    validateCallback(callback);
    return __franken_fs_write('\0fsop:append', path, data, options, function (error) {
      callback(error);
    });
  }
  // Matches the engine's existing platform-neutral access-constant contract.
  // Like Node's, the object is not frozen. A plain literal calls no builtin,
  // so building the module needs no authority beyond the program's own
  // (Object.freeze here made every fs program require the builtin
  // capability), and it touches no `__proto__` key, which the agent-sandbox
  // guardplane scores as prototype pollution (a `{ __proto__: null }`
  // literal suspended every sandboxed fs program). Node's has a null
  // prototype; this one inherits from Object.prototype.
  var constants = { F_OK: 0, R_OK: 4, W_OK: 2, X_OK: 1 };
  // Metadata operations use the engine's existing synchronous host effect and
  // Promise completion model. Executor throws become rejections, not fabricated
  // success values. This does not introduce an off-thread I/O implementation.
  function asPromise(method) {
    return function () {
      var args = arguments;
      return new NativePromise(function (resolve) {
        resolve(apply(method, undefined, args));
      });
    };
  }
  function argumentError(name) {
    var error = new TypeError('Invalid ' + name + ' argument');
    error.code = 'ERR_INVALID_ARG_TYPE';
    return error;
  }
  function byteBuffer(buffer) {
    if (!isView(buffer)) { throw argumentError('buffer (expected ArrayBufferView)'); }
    var backing;
    var offset;
    var length;
    try { backing = apply(typedBuffer, buffer, []); }
    catch (error) {
      // Only brand selection belongs in this catch. A failure reading a
      // genuine typed array's bounds must not retry through another brand.
      backing = apply(dataBuffer, buffer, []);
      offset = apply(dataOffset, buffer, []);
      length = apply(dataLength, buffer, []);
      return bufferFrom(backing, offset, length);
    }
    offset = apply(typedOffset, buffer, []);
    length = apply(typedLength, buffer, []);
    // Normalize Buffers too: an own length getter must not control later
    // bounds checks. This makes a fresh byte view, not a payload copy. Public
    // read/write results still return the original caller-supplied object.
    return bufferFrom(backing, offset, length);
  }
  function bufferWindow(buffer, offset, length) {
    buffer = byteBuffer(buffer);
    if (offset === undefined) { offset = 0; }
    if (length === undefined) { length = buffer.length - offset; }
    if (typeof offset !== 'number' || typeof length !== 'number') {
      throw argumentError('offset or length');
    }
    if (offset % 1 !== 0 || length % 1 !== 0 || offset < 0 || length < 0 ||
        offset > buffer.length || length > buffer.length - offset) {
      var error = new RangeError('Buffer offset or length is out of range');
      error.code = 'ERR_OUT_OF_RANGE';
      throw error;
    }
    return { buffer: buffer, offset: offset, length: length };
  }
  function fileOptions(options, defaultEncoding) {
    if (options === undefined || options === null) { options = {}; }
    if (typeof options === 'string') { options = { encoding: options }; }
    if (typeof options !== 'object') { throw argumentError('options'); }
    var encoding = options.encoding;
    if (encoding === undefined || encoding === null) { encoding = defaultEncoding; }
    if (encoding !== null && !isEncoding(encoding)) {
      var error = new TypeError('Invalid encoding: ' + encoding);
      error.code = 'ERR_INVALID_ARG_VALUE';
      throw error;
    }
    var signal = options.signal;
    if (signal !== undefined && (signal === null || typeof signal !== 'object' ||
        typeof signal.aborted !== 'boolean')) {
      throw argumentError('options.signal');
    }
    return { encoding: encoding, signal: signal };
  }
  function checkAbort(signal) {
    if (signal !== undefined && signal.aborted) {
      var error = new Error('The operation was aborted');
      error.name = 'AbortError';
      error.code = 'ABORT_ERR';
      error.cause = signal.reason;
      throw error;
    }
  }
  function checkedCount(count, length, syscall, requireProgress) {
    if (typeof count !== 'number' || count % 1 !== 0 || count < 0 ||
        count > length || (requireProgress && count === 0)) {
      var error = new Error('Invalid byte count from filesystem provider');
      error.code = 'EIO';
      error.syscall = syscall;
      throw error;
    }
    return count;
  }
  function readContents(fd, options) {
    options = fileOptions(options, null);
    var chunks = [];
    var total = 0;
    var chunk;
    var filled = 0;
    // A short read is not EOF (pipes and interrupted reads can return less
    // than requested). Fill the current allocation across short reads: keeping
    // a 16 KiB backing store for every tiny subarray made retained memory grow
    // with the number of reads instead of the number of bytes. Only zero ends
    // the descriptor stream; all native requests remain at most 16 KiB.
    for (;;) {
      checkAbort(options.signal);
      if (chunk === undefined) { chunk = bufferAlloc(16384); filled = 0; }
      var remaining = chunk.length - filled;
      var count = checkedCount(readSync(fd, chunk, filled, remaining, null),
        remaining, 'read', false);
      checkAbort(options.signal);
      if (count === 0) { break; }
      total += count;
      filled += count;
      if (filled === chunk.length) {
        chunks[chunks.length] = chunk;
        chunk = undefined;
      }
    }
    if (filled !== 0) {
      chunks[chunks.length] = apply(bufferSlice, chunk, [0, filled]);
    }
    // Compact even a single partial chunk so a tiny public result does not
    // keep its entire 16 KiB staging allocation alive.
    var result = bufferConcat(chunks, total);
    return options.encoding === null ? result :
      apply(bufferToString, result, [options.encoding]);
  }
  function writeChunk(fd, data, options) {
    checkAbort(options.signal);
    if (typeof data === 'string') { data = bufferFrom(data, options.encoding); }
    data = byteBuffer(data);
    var offset = 0;
    while (offset < data.length) {
      checkAbort(options.signal);
      var length = data.length - offset;
      if (length > 16384) { length = 16384; }
      // Continue partial writes, but reject a non-progressing provider rather
      // than hanging or reporting success with truncated data.
      offset += checkedCount(writeSync(fd, data, offset, length, null),
        length, 'write', true);
    }
    checkAbort(options.signal);
  }
  function iterableSource(data) {
    if (data === null || (typeof data !== 'object' && typeof data !== 'function')) {
      throw argumentError('data (expected string, Buffer or iterable)');
    }
    // GetMethod once, with async precedence and the original receiver. A
    // second protocol lookup could run a getter twice or select another source.
    var key = asyncIteratorKey;
    var method = data[key];
    if (method === undefined || method === null) {
      key = iteratorKey;
      method = data[key];
    }
    if (typeof method !== 'function') {
      throw argumentError('data (expected string, Buffer or iterable)');
    }
    var source = { [iteratorKey]: undefined, [asyncIteratorKey]: undefined };
    source[key] = function () { return apply(method, data, []); };
    return source;
  }
  // Descriptor ownership stays in this closure, never in a guest-writable fd
  // property. These methods use the existing synchronous descriptor effects
  // with Promise completion, not an off-thread I/O backend. Buffer/string I/O
  // and iterable writes are supported. Read streams below share this owner;
  // stat-on-fd and automatic finalization are not implemented here.
  function fileHandle(descriptor) {
    var closing = false;
    var active = 0;
    var closePromise;
    var resolveClose;
    var rejectClose;
    var webStreamUsed = false;
    var closeWebStream;
    function finishClose() {
      if (!closing || active !== 0 || descriptor < 0) { return; }
      var fd = descriptor;
      descriptor = -1;
      try { closeSync(fd); resolveClose(); }
      catch (error) { rejectClose(error); }
    }
    function perform(syscall, operation) {
      return new NativePromise(function (resolve) {
        if (closing) {
          var error = new Error('file closed');
          error.code = 'EBADF';
          error.syscall = syscall;
          throw error;
        }
        // Option getters can re-enter close(). Keep ownership until this
        // operation finishes, including validation and any exceptional exit.
        active += 1;
        try { resolve(operation(descriptor)); }
        finally { active -= 1; finishClose(); }
      });
    }
    async function writeAll(data, options) {
      if (closing) {
        var error = new Error('file closed');
        error.code = 'EBADF';
        error.syscall = 'writeFile';
        throw error;
      }
      // Ownership belongs to this async body, not a .then attached to its
      // public Promise. close() must wait through next(), writes, and iterator
      // cleanup even if guest code tampers with that Promise's public surface.
      active += 1;
      try {
        options = fileOptions(options, 'utf8');
        checkAbort(options.signal);
        if (typeof data === 'string' || isBuffer(data) || isView(data)) {
          writeChunk(descriptor, data, options);
          return;
        }
        var source = iterableSource(data);
        checkAbort(options.signal);
        // Native async iteration supplies backpressure, AsyncFromSync value
        // awaiting, and IteratorClose on body failures. Never collect the
        // source into one Buffer. Every chunk retains the same gated write_fd
        // effect and byte limit; the next chunk is requested only after the
        // current one has been completely written.
        for await (var chunk of source) {
          writeChunk(descriptor, chunk, options);
        }
        // Also observe an abort that races the final done:true result.
        // A pending producer is not preempted: cancellation is checked when
        // it resumes, before any bytes are written.
        checkAbort(options.signal);
      } finally {
        active -= 1;
        finishClose();
      }
    }
    var handle = {
      get fd() { return closing ? -1 : descriptor; },
      close: function () {
        if (closePromise !== undefined) { return closePromise; }
        closing = true;
        closePromise = new NativePromise(function (resolve, reject) {
          resolveClose = resolve;
          rejectClose = reject;
        });
        // Terminate the readable side before releasing its descriptor. A
        // locked Web stream cannot be cancelled through its public cancel().
        // The private controller also retires a pending BYOB read at EOF.
        if (closeWebStream !== undefined) { closeWebStream(); }
        finishClose();
        return closePromise;
      },
      readableWebStream: function (options) {
        function unavailable() {
          var error = new Error('Invalid state: The FileHandle is ' +
            (closing ? 'closed or closing' : 'locked'));
          error.code = 'ERR_INVALID_STATE';
          return error;
        }
        if (closing || webStreamUsed) { throw unavailable(); }
        if (options === undefined) { options = {}; }
        if (options === null || typeof options !== 'object' || arrayIsArray(options)) {
          throw argumentError('options');
        }
        var autoClose = options.autoClose;
        if (autoClose !== undefined && typeof autoClose !== 'boolean') {
          throw argumentError('options.autoClose');
        }
        var methods = fileWebStreamMethods();
        // The options getter can close this handle or create its one stream.
        if (closing || webStreamUsed) { throw unavailable(); }
        webStreamUsed = true;
        var stopped = false;
        var controller;
        var read = handleOperation(handle, 'read');
        var close = handleOperation(handle, 'close');
        function retire() { stopped = true; closeWebStream = undefined; }
        function endReadable() {
          var request = apply(methods.request, controller, []);
          apply(methods.close, controller, []);
          // Closing a byte controller alone leaves a pending BYOB read open.
          // respond(0) finishes its empty or aligned final view after close.
          if (request !== null) { apply(methods.respond, request, [0]); }
        }
        try {
          return new methods.ReadableStream({
            type: 'bytes', autoAllocateChunkSize: 16384,
            start: function (value) {
              controller = value;
              closeWebStream = function () {
                if (stopped) { return; }
                retire();
                try { endReadable(); }
                catch (error) { apply(methods.error, controller, [error]); }
              };
            },
            pull: async function () {
              if (stopped) { return; }
              try {
                var request = apply(methods.request, controller, []);
                if (request === null) { return; }
                var view = apply(methods.view, request, []);
                // The shared byte-stream controller owns transfer, minimum
                // fill, alignment and default-reader allocation. Fill its
                // actual request in place; do not collect or copy the file.
                var length = apply(typedLength, view, []);
                if (length > 16384) { length = 16384; }
                var result = await read(view, 0, length, null);
                // Cancellation/manual close may win during Promise delivery.
                // Its controller owns the retired request; never respond twice.
                if (stopped) { return; }
                if (result.bytesRead !== 0) {
                  apply(methods.respond, request, [result.bytesRead]);
                  return;
                }
                retire();
                if (autoClose === true) { await close(); }
                endReadable();
              } catch (error) {
                if (stopped) { throw error; }
                retire();
                if (autoClose === true) {
                  try { await close(); }
                  catch (closeError) {
                    throw new NativeAggregateError([error, closeError],
                      'File stream read and descriptor close both failed');
                  }
                }
                throw error;
              }
            },
            cancel: function () {
              retire();
              if (autoClose === true) { return close(); }
            }
          }, { highWaterMark: 0, size: undefined });
        } catch (error) {
          retire();
          webStreamUsed = false;
          throw error;
        }
      },
      sync: function () {
        return perform('fsync', function (fd) { fsyncSync(fd); });
      },
      readFile: function (options) {
        return perform('readFile', function (fd) { return readContents(fd, options); });
      },
      readLines: function (options) {
        // Compose the same descriptor-backed stream and readline Interface
        // exposed by their modules. No whole-file read, second line parser,
        // reopened pathname or replacement filesystem provider is involved.
        if (closing) {
          var error = new RangeError('The FileHandle is closed or closing');
          error.code = 'ERR_OUT_OF_RANGE';
          throw error;
        }
        var createInterface = lineInterfaceFactory();
        var input = new (streamClasses().ReadStream)(undefined, options, handle);
        return createInterface({ input: input, crlfDelay: 1 / 0, terminal: false });
      },
      createReadStream: function (options) {
        return new (streamClasses().ReadStream)(undefined, options, handle);
      },
      createWriteStream: function (options) {
        return new (streamClasses().WriteStream)(undefined, options, handle);
      },
      writeFile: function (data, options) {
        return writeAll(data, options);
      },
      appendFile: function (data, options) {
        // Like Node, appendFile on an existing handle uses that descriptor's
        // open flags and current offset; it does not reopen or truncate a path.
        return writeAll(data, options);
      },
      readv: function (buffers, position) {
        return perform('readv', function (fd) {
          return { bytesRead: readvSync(fd, buffers, position), buffers: buffers };
        });
      },
      writev: function (buffers, position) {
        return perform('writev', function (fd) {
          return { bytesWritten: writevSync(fd, buffers, position), buffers: buffers };
        });
      },
      read: function (buffer, offset, length, position) {
        return perform('read', function (fd) {
          var options;
          if (!isBuffer(buffer) && !isView(buffer)) {
            options = buffer === undefined ? {} : buffer;
            if (options === null || typeof options !== 'object') {
              throw argumentError('options');
            }
            buffer = options.buffer;
            if (buffer === undefined) { buffer = bufferAlloc(16384); }
            offset = options.offset;
            length = options.length;
            position = options.position;
          } else if (offset !== null && typeof offset === 'object') {
            options = offset;
            offset = options.offset;
            length = options.length;
            position = options.position;
          }
          var window = bufferWindow(buffer, offset, length);
          if (position === undefined || position === -1) { position = null; }
          var count = checkedCount(readSync(fd, window.buffer, window.offset, window.length, position),
            window.length, 'read', false);
          return { bytesRead: count, buffer: buffer };
        });
      },
      write: function (data, offset, length, position) {
        return perform('write', function (fd) {
          var buffer = data;
          if (typeof data === 'string') {
            // The public string overload is (string, position, encoding).
            // Encode first so native descriptor writes always count bytes.
            buffer = bufferFrom(data, length === undefined ? 'utf8' : length);
            position = typeof offset === 'number' ? offset : null;
            offset = 0;
            length = buffer.length;
          } else if (offset !== null && typeof offset === 'object') {
            var options = offset;
            offset = options.offset;
            length = options.length;
            position = options.position;
          }
          var window = bufferWindow(buffer, offset, length);
          if (position === undefined || position === -1) { position = null; }
          var count = checkedCount(writeSync(fd, window.buffer, window.offset, window.length, position),
            window.length, 'write', false);
          return { bytesWritten: count, buffer: data };
        });
      }
    };
    // Keep the original operations in a private identity registry. Neither
    // a forged fd property nor overwritten public methods can redirect an
    // fs.promises operation to another descriptor. Keys are weakly held.
    apply(setHandle, handles, [handle, {
      readFile: handle.readFile,
      writeFile: handle.writeFile,
      appendFile: handle.appendFile,
      read: handle.read,
      write: handle.write,
      sync: handle.sync,
      close: handle.close,
      descriptor: function () { return closing ? -1 : descriptor; }
    }]);
    return handle;
  }
  function handleOperation(value, name) {
    if (handles === undefined || value === null ||
        (typeof value !== 'object' && typeof value !== 'function')) { return undefined; }
    var operations = apply(getHandle, handles, [value]);
    return operations === undefined ? undefined : operations[name];
  }
  function open(path, flags, mode) {
    return new NativePromise(function (resolve) {
      if (handles === undefined) { handles = new NativeWeakMap(); }
      if (flags === undefined) { flags = 'r'; }
      resolve(fileHandle(openSync(path, flags, mode)));
    });
  }
  // These are adapters over the SAME engine-owned stream module that serves
  // require('stream'), not a second stream state machine. The pure-module
  // lowering resolves the literal require before guest execution. It embeds
  // the stream dependency with the full fs facade; no path is opened merely
  // by loading either module. Class/owner registries initialize on first use.
  var fileStreamClasses;
  var fileLineInterface;
  function lineInterfaceFactory() {
    if (fileLineInterface === undefined) {
      // The native module rewrite resolves this literal private dependency.
      // Its loader initializes readline only when readLines is requested.
      fileLineInterface = require('readline').createInterface;
    }
    return fileLineInterface;
  }
  var fileWebMethods;
  function fileWebStreamMethods() {
    if (fileWebMethods !== undefined) { return fileWebMethods; }
    // Literal dependency goes through the canonical shared module loader.
    // Loading fs does not create a stream or start descriptor reads. Capture
    // branded methods once rather than consult mutable public methods per pull.
    var web = require('stream/web');
    var bytes = web.ReadableByteStreamController.prototype;
    var request = web.ReadableStreamBYOBRequest.prototype;
    var descriptor = Object.getOwnPropertyDescriptor;
    fileWebMethods = {
      ReadableStream: web.ReadableStream,
      request: descriptor(bytes, 'byobRequest').get,
      view: descriptor(request, 'view').get,
      respond: request.respond,
      close: bytes.close,
      error: bytes.error
    };
    return fileWebMethods;
  }
  function streamClasses() {
    if (fileStreamClasses !== undefined) { return fileStreamClasses; }
    var streams = require('stream');
    var states = new NativeWeakMap();
    function stateOf(stream) {
      var state = apply(getHandle, states, [stream]);
      if (state === undefined) { throw argumentError('stream receiver'); }
      return state;
    }
    function position(value, name) {
      if (typeof value !== 'number') { throw argumentError(name); }
      if (value % 1 !== 0 || value < 0 || value > 9007199254740991) {
        var error = new RangeError('Invalid ' + name + ' position');
        error.code = 'ERR_OUT_OF_RANGE';
        throw error;
      }
      return value;
    }
    function settings(options, owner, writable) {
      if (options === undefined || options === null) { options = {}; }
      if (typeof options === 'string') { options = { encoding: options }; }
      if (typeof options !== 'object') { throw argumentError('options'); }
      // Do not silently accept a replacement provider while ignoring it.
      // All I/O in this adapter belongs to the existing gated host provider.
      if (options.fs !== undefined) { throw argumentError('options.fs (unsupported provider override)'); }
      var start = options.start;
      var end = writable ? undefined : options.end;
      var fd = owner === undefined ? options.fd : owner;
      var flags = options.flags;
      var mode = options.mode;
      var autoClose = options.autoClose;
      var highWaterMark = options.highWaterMark;
      var encoding = options.encoding;
      var emitClose = options.emitClose;
      var signal = options.signal;
      var flush = writable ? options.flush : undefined;
      if (flush !== undefined && typeof flush !== 'boolean') { throw argumentError('options.flush'); }
      // Validate here, not only in the stream constructor. The engine-owned
      // stream implementation does not provide all of Node's option checks.
      if (highWaterMark !== undefined) { position(highWaterMark, 'highWaterMark'); }
      if (encoding !== undefined && encoding !== null && !isEncoding(encoding)) {
        throw argumentError('encoding');
      }
      // Keep the file API's optional-signal shape check. The shared stream
      // constructor authenticates the AbortSignal brand using realm accessors;
      // never consult replaceable public state or listener methods here.
      if (signal !== undefined && (signal === null || typeof signal !== 'object')) {
        throw argumentError('options.signal');
      }
      if (start !== undefined) { position(start, 'start'); }
      if (end === undefined) { end = 1 / 0; }
      if (end !== 1 / 0) { position(end, 'end'); }
      if (start !== undefined && start > end) {
        var error = new RangeError('start must not exceed end');
        error.code = 'ERR_OUT_OF_RANGE';
        throw error;
      }
      if (fd !== undefined && fd !== null && typeof fd !== 'number' &&
          handleOperation(fd, 'descriptor') === undefined) { throw argumentError('fd'); }
      if (typeof fd === 'number') { position(fd, 'fd'); }
      return { start: start, end: end, fd: fd,
        flags: flags === undefined ? (writable ? 'w' : 'r') : flags, mode: mode,
        autoClose: autoClose === undefined ? true : !!autoClose,
        highWaterMark: highWaterMark === undefined ? 65536 : highWaterMark,
        encoding: encoding, emitClose: emitClose, signal: signal, flush: flush === true };
    }
    function bindOwner(state, owner) {
      state.owner = owner;
      state.read = handleOperation(owner, 'read');
      state.write = handleOperation(owner, 'write');
      state.sync = handleOperation(owner, 'sync');
      state.close = handleOperation(owner, 'close');
      state.descriptor = handleOperation(owner, 'descriptor');
    }
    function observe(promise, success, failure) {
      // Never consult a guest-writable .then on an exposed handle Promise.
      return apply(promiseThen, promise, [success, failure]);
    }
    function failure(reason) {
      // Error-first stream callbacks cannot represent a falsy rejection.
      // Preserve its cause instead of turning a rejected operation into EOF
      // or reporting a successfully closed/flushed file.
      if (reason) { return reason; }
      var error = new Error('Filesystem stream operation failed');
      error.code = 'EIO';
      error.cause = reason;
      return error;
    }
    function closeOwner(state, callback) {
      if (state.owner === undefined) { callback(); return; }
      if (state.closeCompletion === undefined) {
        var resolveClose;
        var rejectClose;
        // Publish before invoking either effect: repeated/reentrant closes
        // join this operation, including its fsync, rather than repeating it.
        state.closeCompletion = new NativePromise(function (resolve, reject) {
          resolveClose = resolve;
          rejectClose = reject;
        });
        function release(syncError) {
          observe(state.close(), function () {
            if (syncError) { rejectClose(syncError); } else { resolveClose(); }
          }, function (closeError) {
            closeError = failure(closeError);
            rejectClose(syncError ? new NativeAggregateError([syncError, closeError],
              'Filesystem flush and descriptor close both failed') : closeError);
          });
        }
        if (state.options.flush && state.descriptor() >= 0) {
          observe(state.sync(), function () { release(); }, function (error) { release(failure(error)); });
        } else { release(); }
      }
      observe(state.closeCompletion, function () { callback(); }, callback);
    }
    function drainDestroy(state) {
      if (state.destroyCallback === undefined || state.inflight !== 0) { return; }
      var callback = state.destroyCallback;
      state.destroyCallback = undefined;
      function done(closeError) {
        state.destroyFinished = true;
        var error = state.destroyError;
        if (closeError) {
          error = error ? new NativeAggregateError([error, closeError],
            'Filesystem stream and descriptor close both failed') : closeError;
        }
        state.finalError = error;
        callback(error);
      }
      if (state.options.autoClose || state.forceClose) { closeOwner(state, done); }
      else { done(); }
    }
    function construct(stream, callback) {
      var state = stateOf(stream);
      // Constructor cancellation marks the stream destroyed before this
      // deferred acquisition runs. Do not open/truncate a cancelled path.
      // The base stream waits for this callback before _destroy, so initialize
      // has already published the private owner even for a pre-aborted signal.
      if (stream.destroyed) { callback(); return; }
      if (state.owner !== undefined) {
        if (state.descriptor() < 0) {
          var error = new Error('file closed');
          error.code = 'EBADF';
          callback(error);
        } else { callback(); }
        return;
      }
      state.inflight += 1;
      observe(open(state.path, state.options.flags, state.options.mode), function (owner) {
        bindOwner(state, owner);
        state.inflight -= 1;
        var fd = state.descriptor();
        callback();
        stream.emit('open', fd);
        stream.emit('ready');
        drainDestroy(state);
      }, function (error) {
        state.inflight -= 1;
        callback(failure(error));
        drainDestroy(state);
      });
    }
    function initialize(stream, path, options) {
      var state = { path: path, options: options, owner: undefined,
        inflight: 0, bytes: 0, offset: options.start, forceClose: false,
        destroyCallback: undefined, destroyError: null, destroyFinished: false };
      if (options.fd !== undefined && options.fd !== null) {
        var owner = options.fd;
        if (typeof owner === 'number') {
          if (handles === undefined) { handles = new NativeWeakMap(); }
          owner = fileHandle(owner);
        }
        bindOwner(state, owner);
      }
      apply(setHandle, states, [stream, state]);
      stream.path = path;
      stream.flags = options.flags;
      stream.mode = options.mode;
      // Signal lifetime belongs to the shared base stream. This owner only
      // drains admitted descriptor I/O, optional flushing and descriptor close.
      return state;
    }
    class ReadStream extends streams.Readable {
      constructor(path, options, owner) {
        var config = settings(options, owner);
        super({ highWaterMark: config.highWaterMark, encoding: config.encoding,
          autoDestroy: config.autoClose, emitClose: config.emitClose, signal: config.signal });
        initialize(this, path, config);
      }
      get fd() {
        var state = stateOf(this);
        if (state.owner === undefined) { return null; }
        var fd = state.descriptor();
        return fd < 0 ? null : fd;
      }
      get pending() { return this.fd === null; }
      get bytesRead() { return stateOf(this).bytes; }
      _construct(callback) { construct(this, callback); }
      _read(size) {
        var state = stateOf(this);
        if (this.destroyed || state.inflight !== 0) { return; }
        var remaining = state.options.end - (state.offset === undefined ? state.bytes : state.offset) + 1;
        var length = size > 0 ? size : 1;
        if (length > 16384) { length = 16384; }
        if (length > remaining) { length = remaining; }
        if (length <= 0) { this.push(null); return; }
        var buffer;
        try { buffer = bufferAlloc(length); }
        catch (error) { this.destroy(failure(error)); return; }
        var stream = this;
        state.inflight += 1;
        observe(state.read(buffer, 0, length, state.offset), function (result) {
          state.inflight -= 1;
          var count = result.bytesRead;
          state.bytes += count;
          if (state.offset !== undefined) { state.offset += count; }
          if (!stream.destroyed) {
            if (count === 0) { stream.push(null); }
            else {
              // Compact a short result; a slow consumer must not retain a
              // full 16 KiB allocation for every tiny provider fragment.
              if (count !== buffer.length) {
                try { buffer = bufferFrom(apply(bufferSlice, buffer, [0, count])); }
                catch (error) { stream.destroy(failure(error)); drainDestroy(state); return; }
              }
              stream.push(buffer);
            }
          }
          drainDestroy(state);
        }, function (error) {
          state.inflight -= 1;
          stream.destroy(failure(error));
          drainDestroy(state);
        });
      }
      _destroy(error, callback) {
        var state = stateOf(this);
        state.destroyError = error;
        state.destroyCallback = callback;
        drainDestroy(state);
      }
      close(callback) {
        if (callback !== undefined) { validateCallback(callback); }
        var state = stateOf(this);
        state.forceClose = true;
        if (state.destroyFinished) {
          var stream = this;
          closeOwner(state, function (error) {
            if (callback) { callback(error); }
            else if (error) { stream.emit('error', error); }
          });
          return;
        }
        if (callback) { this.once('close', function () { callback(state.finalError || undefined); }); }
        this.destroy();
      }
    }
    function destroyedWrite() {
      var error = new Error('Cannot call write after a stream was destroyed');
      error.code = 'ERR_STREAM_DESTROYED';
      return error;
    }
    function writeWindow(chunk, encoding) {
      if (typeof chunk === 'string') { chunk = bufferFrom(chunk, encoding); }
      var buffer = byteBuffer(chunk);
      return { buffer: buffer, length: buffer.length };
    }
    function writeWindows(stream, windows, callback) {
      var state = stateOf(stream);
      var index = 0;
      var offset = 0;
      var pending;
      var cursor = 0;
      var stop = 0;
      state.inflight += 1;
      function done(error) {
        state.inflight -= 1;
        callback(error);
        drainDestroy(state);
      }
      function advance() {
        if (stream.destroyed) { done(state.destroyError || destroyedWrite()); return; }
        if (cursor === stop) {
          while (index < windows.length && offset === windows[index].length) { index += 1; offset = 0; }
          if (index === windows.length) { done(); return; }
          try {
            var window = windows[index];
            var available = window.length - offset;
            if (available >= 16384 || index + 1 === windows.length) {
              // Borrow large or final windows; no payload-sized staging copy.
              var length = available > 16384 ? 16384 : available;
              pending = window.buffer;
              cursor = offset;
              stop = offset + length;
              offset += length;
            } else {
              // Corked tiny writes share a bounded batch, rather than one
              // host effect each or a copy of the entire unbounded queue.
              var total = 0;
              var scan = index;
              var skipped = offset;
              while (scan < windows.length && total < 16384) {
                var take = windows[scan].length - skipped;
                if (take > 16384 - total) { take = 16384 - total; }
                total += take;
                scan += 1;
                skipped = 0;
              }
              pending = bufferAlloc(total);
              var filled = 0;
              while (filled < total) {
                var take = windows[index].length - offset;
                if (take > total - filled) { take = total - filled; }
                if (take !== 0) {
                  var copied = apply(bufferCopy, windows[index].buffer,
                    [pending, filled, offset, offset + take]);
                  if (checkedCount(copied, take, 'writev', true) !== take) {
                    throw failure(undefined);
                  }
                }
                filled += take;
                offset += take;
                if (offset === windows[index].length) { index += 1; offset = 0; }
              }
              cursor = 0;
              stop = total;
            }
          } catch (error) { done(failure(error)); return; }
        }
        observe(state.write(pending, cursor, stop - cursor, state.offset), function (result) {
          var count;
          try { count = checkedCount(result.bytesWritten, stop - cursor, 'write', true); }
          catch (error) { done(error); return; }
          cursor += count;
          state.bytes += count;
          if (state.offset !== undefined) { state.offset += count; }
          // Partial writes reuse the same batch and advance only by bytes
          // actually accepted. The next iteration is a Promise continuation,
          // not synchronous recursion through a short-writing host provider.
          advance();
        }, function (error) { done(failure(error)); });
      }
      advance();
    }
    class WriteStream extends streams.Writable {
      constructor(path, options, owner) {
        var config = settings(options, owner, true);
        super({ highWaterMark: config.highWaterMark, defaultEncoding: config.encoding,
          decodeStrings: true, autoDestroy: config.autoClose,
          emitClose: config.emitClose, signal: config.signal });
        initialize(this, path, config);
      }
      get fd() {
        var state = stateOf(this);
        if (state.owner === undefined) { return null; }
        var fd = state.descriptor();
        return fd < 0 ? null : fd;
      }
      get pending() { return this.fd === null; }
      get bytesWritten() { return stateOf(this).bytes; }
      _construct(callback) { construct(this, callback); }
      _write(chunk, encoding, callback) {
        var window;
        try { window = writeWindow(chunk, encoding); }
        catch (error) { callback(failure(error)); return; }
        writeWindows(this, [window], callback);
      }
      _writev(chunks, callback) {
        var windows = [];
        // Snapshot and validate all entries before any descriptor effect.
        try {
          for (var index = 0; index < chunks.length; index += 1) {
            var entry = chunks[index];
            windows[windows.length] = writeWindow(entry.chunk, entry.encoding);
          }
        } catch (error) { callback(failure(error)); return; }
        writeWindows(this, windows, callback);
      }
      _destroy(error, callback) {
        var state = stateOf(this);
        state.destroyError = error;
        state.destroyCallback = callback;
        drainDestroy(state);
      }
      close(callback) {
        if (callback !== undefined) { validateCallback(callback); }
        var state = stateOf(this);
        state.forceClose = true;
        if (state.destroyFinished) {
          var stream = this;
          closeOwner(state, function (error) {
            if (callback) { callback(error); }
            else if (error) { stream.emit('error', error); }
          });
          return;
        }
        if (callback) { this.once('close', function () { callback(state.finalError || undefined); }); }
        // Unlike a reader, close on a writer must drain queued writes first.
        if (this.writableFinished) { this.destroy(); }
        else { this.once('finish', function () { this.destroy(); }); this.end(); }
      }
    }
    fileStreamClasses = { ReadStream: ReadStream, WriteStream: WriteStream };
    return fileStreamClasses;
  }
  async function writePathContents(path, data, options, defaultFlag) {
    // Scalar and iterable Promise writes share descriptor ownership, bounded
    // writeChunk requests, short-write retries, explicit flush and close. The
    // old scalar hostcall bypassed this protocol, including flush:true.
    // Resolve options and scalar conversion before open, so invalid data or
    // pre-abort cannot truncate the destination. An iterator starts after open.
    if (options === undefined || options === null) { options = {}; }
    if (typeof options === 'string') { options = { encoding: options }; }
    var settings = fileOptions(options, 'utf8');
    var flag = options.flag;
    var mode = options.mode;
    var flush = options.flush;
    if (flush !== undefined && typeof flush !== 'boolean') {
      throw argumentError('options.flush');
    }
    checkAbort(settings.signal);
    var scalar = typeof data === 'string' || isBuffer(data) || isView(data);
    var source;
    if (scalar) {
      // Encode only once, before acquiring the descriptor. Views keep their
      // byte range; they must not become iterables of numeric elements.
      data = typeof data === 'string' ? bufferFrom(data, settings.encoding) : byteBuffer(data);
    } else {
      source = iterableSource(data);
    }
    checkAbort(settings.signal);
    var fd = openSync(path, flag === undefined ? defaultFlag : flag, mode);
    var failed = false;
    var failure;
    try {
      if (scalar) {
        writeChunk(fd, data, settings);
      } else {
        for await (var chunk of source) {
          writeChunk(fd, chunk, settings);
        }
      }
      checkAbort(settings.signal);
      if (flush === true) { fsyncSync(fd); }
    } catch (error) {
      // JavaScript can throw undefined/null/false: truthiness cannot represent
      // whether the writer failed. IteratorClose has already drained here.
      failed = true;
      failure = error;
    }
    // Only this path owns its fd. Do not use public fs methods or a guest fd
    // property, and never retry close on a possibly recycled descriptor.
    try { closeSync(fd); }
    catch (closeError) {
      if (failed) {
        throw new NativeAggregateError([failure, closeError],
          'Filesystem write and descriptor close both failed');
      }
      throw closeError;
    }
    if (failed) { throw failure; }
  }
  var promises = {
    constants: constants,
    open: open,
    mkdir: asPromise(mkdirSync), readdir: asPromise(readdirSync),
    stat: asPromise(statSync), lstat: asPromise(lstatSync),
    unlink: asPromise(unlinkSync), rmdir: asPromise(rmdirSync), rm: asPromise(rmSync),
    rename: asPromise(renameSync), copyFile: asPromise(copyFileSync),
    access: asPromise(accessSync), chmod: asPromise(chmodSync), utimes: asPromise(utimesSync),
    realpath: asPromise(realpathSync), readlink: asPromise(readlinkSync),
    symlink: asPromise(symlinkSync), truncate: asPromise(truncateSync),
    mkdtemp: asPromise(mkdtempSync),
    readFile: function readFile(path, options) {
      return new NativePromise(function (resolve, reject) {
        var operation = handleOperation(path, 'readFile');
        if (operation !== undefined) { resolve(operation(options)); return; }
        __franken_fs_read('\0fsop:read', path, options, function (error, value) {
          if (error) { reject(error); } else { resolve(value); }
        });
      });
    },
    writeFile: function writeFile(path, data, options) {
      return new NativePromise(function (resolve) {
        var operation = handleOperation(path, 'writeFile');
        if (operation !== undefined) { resolve(operation(data, options)); return; }
        resolve(writePathContents(path, data, options, 'w'));
      });
    },
    appendFile: function appendFile(path, data, options) {
      return new NativePromise(function (resolve) {
        var operation = handleOperation(path, 'appendFile');
        if (operation !== undefined) { resolve(operation(data, options)); return; }
        resolve(writePathContents(path, data, options, 'a'));
      });
    }
  };
  return {
    readFileSync: readFileSync, writeFileSync: writeFileSync, appendFileSync: appendFileSync,
    existsSync: existsSync, statSync: statSync, lstatSync: lstatSync, readdirSync: readdirSync,
    mkdirSync: mkdirSync, unlinkSync: unlinkSync, rmdirSync: rmdirSync, rmSync: rmSync,
    renameSync: renameSync, copyFileSync: copyFileSync, accessSync: accessSync,
    chmodSync: chmodSync, utimesSync: utimesSync, realpathSync: realpathSync,
    readlinkSync: readlinkSync, symlinkSync: symlinkSync, truncateSync: truncateSync,
    mkdtempSync: mkdtempSync, openSync: openSync, closeSync: closeSync, fsyncSync: fsyncSync,
    readSync: readSync, writeSync: writeSync,
    readvSync: readvSync, writevSync: writevSync,
    readFile: readFile, writeFile: writeFile, appendFile: appendFile,
    createReadStream: function (path, options) {
      return new (streamClasses().ReadStream)(path, options);
    },
    get ReadStream() { return streamClasses().ReadStream; },
    createWriteStream: function (path, options) {
      return new (streamClasses().WriteStream)(path, options);
    },
    get WriteStream() { return streamClasses().WriteStream; },
    constants: constants, promises: promises
  };
})()
