(function () {
  'use strict';
  // Capture realm helpers before guest code can replace their public bindings.
  // Capturing them performs no builtin call and grants no filesystem authority.
  var NativePromise = Promise;
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
    var count = buffers.length;
    for (var index = 0; index < count; index += 1) {
      var buffer = buffers[index];
      var window = bufferWindow(buffer);
      entries[index] = window.buffer;
      lengths[index] = window.length;
      total += window.length;
      if (total > 9007199254740991) {
        var error = new RangeError('Combined buffer length is out of range');
        error.code = 'ERR_OUT_OF_RANGE';
        throw error;
      }
    }
    return { entries: entries, lengths: lengths, total: total };
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
    // Coalesce to ONE native descriptor read, then scatter only the returned
    // prefix. Existing Buffer allocation and host-I/O budgets still apply.
    // This is not a zero-copy readv syscall; no new host authority is added.
    var data = bufferAlloc(vector.total);
    var count = checkedCount(readSync(fd, data, 0, vector.total, vectorPosition(position)),
      vector.total, 'readv', false);
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
    var data = bufferConcat(vector.entries, vector.total);
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
    if (isBuffer(buffer)) { return buffer; }
    if (!isView(buffer)) { throw argumentError('buffer (expected ArrayBufferView)'); }
    // Buffer.from(view) converts ELEMENTS (and loses DataView contents).
    // The ArrayBuffer overload instead shares precisely the view's bytes,
    // including a nonzero byteOffset, without copying or changing identity
    // in the public result. Native descriptor effects still receive a Buffer.
    return bufferFrom(buffer.buffer, buffer.byteOffset, buffer.byteLength);
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
    // A short read is not EOF (pipes and interrupted reads can return less
    // than requested). Only a zero count ends the descriptor stream.
    for (;;) {
      checkAbort(options.signal);
      var chunk = bufferAlloc(16384);
      var count = checkedCount(readSync(fd, chunk, 0, chunk.length, null),
        chunk.length, 'read', false);
      checkAbort(options.signal);
      if (count === 0) { break; }
      chunks[chunks.length] = count === chunk.length ? chunk :
        apply(bufferSlice, chunk, [0, count]);
      total += count;
    }
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
  // and iterable writes are supported; stream factories, stat-on-fd and
  // automatic finalization are not.
  function fileHandle(descriptor) {
    var closing = false;
    var active = 0;
    var closePromise;
    var resolveClose;
    var rejectClose;
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
        finishClose();
        return closePromise;
      },
      sync: function () {
        return perform('fsync', function (fd) { fsyncSync(fd); });
      },
      readFile: function (options) {
        return perform('readFile', function (fd) { return readContents(fd, options); });
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
      appendFile: handle.appendFile
    }]);
    return handle;
  }
  function handleOperation(value, name) {
    if (handles === undefined || value === null ||
        (typeof value !== 'object' && typeof value !== 'function')) { return undefined; }
    var operations = apply(getHandle, handles, [value]);
    return operations === undefined ? undefined : operations[name];
  }
  async function writeIterablePath(path, data, options, defaultFlag) {
    // Resolve user-controlled options and iterator getters before acquiring a
    // descriptor. In particular, invalid data or pre-abort must not truncate
    // the destination. The iterator factory itself runs only after open.
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
    var source = iterableSource(data);
    checkAbort(settings.signal);
    var fd = openSync(path, flag === undefined ? defaultFlag : flag, mode);
    var failed = false;
    var failure;
    try {
      for await (var chunk of source) {
        writeChunk(fd, chunk, settings);
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
    open: function open(path, flags, mode) {
      return new NativePromise(function (resolve) {
        // Initialize before opening a descriptor: allocation failure must not
        // strand a newly opened fd. Merely constructing fs still calls no
        // builtin and creates no registry.
        if (handles === undefined) { handles = new NativeWeakMap(); }
        if (flags === undefined) { flags = 'r'; }
        resolve(fileHandle(openSync(path, flags, mode)));
      });
    },
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
      return new NativePromise(function (resolve, reject) {
        var operation = handleOperation(path, 'writeFile');
        if (operation !== undefined) { resolve(operation(data, options)); return; }
        if (typeof data !== 'string' && !isBuffer(data) && !isView(data)) {
          resolve(writeIterablePath(path, data, options, 'w'));
          return;
        }
        __franken_fs_write('\0fsop:write', path, data, options, function (error) {
          if (error) { reject(error); } else { resolve(); }
        });
      });
    },
    appendFile: function appendFile(path, data, options) {
      return new NativePromise(function (resolve, reject) {
        var operation = handleOperation(path, 'appendFile');
        if (operation !== undefined) { resolve(operation(data, options)); return; }
        if (typeof data !== 'string' && !isBuffer(data) && !isView(data)) {
          resolve(writeIterablePath(path, data, options, 'a'));
          return;
        }
        __franken_fs_write('\0fsop:append', path, data, options, function (error) {
          if (error) { reject(error); } else { resolve(); }
        });
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
    constants: constants, promises: promises
  };
})()
