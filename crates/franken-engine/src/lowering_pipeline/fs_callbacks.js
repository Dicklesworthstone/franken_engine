(function installFilesystemCallbacks(fs) {
  'use strict';
  // Complete the callback surface using the same admitted descriptor and
  // metadata operations. This queues work on the native microtask scheduler;
  // it is not a second I/O provider or an off-thread filesystem backend.
  const apply = Reflect.apply;
  const enqueue = queueMicrotask;
  const create = Object.create;
  const define = Object.defineProperty;
  const own = Object.prototype.hasOwnProperty;
  const Type = TypeError;
  const Range = RangeError;
  const ErrorClass = Error;
  const isView = ArrayBuffer.isView;
  const alloc = Buffer.alloc;
  const from = Buffer.from;
  const isEncoding = Buffer.isEncoding;
  const isBuffer = Buffer.isBuffer;
  const arrayIsArray = Array.isArray;
  const slice = Array.prototype.slice;
  const indexOf = String.prototype.indexOf;
  const URLClass = URL;
  const urlString = URL.prototype.toString;
  const dateTime = Date.prototype.getTime;
  const dateNow = Date.now;
  const PromiseClass = Promise;
  const promiseThen = Promise.prototype.then;
  const custom = Symbol.for('nodejs.util.promisify.custom');
  const typed = Object.getPrototypeOf(Uint8Array.prototype);
  const typedBuffer = Object.getOwnPropertyDescriptor(typed, 'buffer').get;
  const typedOffset = Object.getOwnPropertyDescriptor(typed, 'byteOffset').get;
  const typedLength = Object.getOwnPropertyDescriptor(typed, 'byteLength').get;
  const dataBuffer = Object.getOwnPropertyDescriptor(DataView.prototype, 'buffer').get;
  const dataOffset = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteOffset').get;
  const dataLength = Object.getOwnPropertyDescriptor(DataView.prototype, 'byteLength').get;
  const readSync = fs.readSync, writeSync = fs.writeSync;
  const readvSync = fs.readvSync, writevSync = fs.writevSync;
  const openSync = fs.openSync, closeSync = fs.closeSync;

  function invalid(name) {
    const error = new Type('Invalid ' + name + ' argument');
    error.code = 'ERR_INVALID_ARG_TYPE'; return error;
  }
  function range(name) {
    const error = new Range('Out of range ' + name + ' argument');
    error.code = 'ERR_OUT_OF_RANGE'; return error;
  }
  function nulPath() {
    const error = new Type('The path must not contain null bytes');
    error.code = 'ERR_INVALID_ARG_VALUE'; return error;
  }
  function callback(value) { if (typeof value !== 'function') throw invalid('callback'); return value; }
  function fd(value) {
    if (typeof value !== 'number') throw invalid('fd');
    if (value % 1 !== 0 || value < 0 || value > 2147483647) throw range('fd');
    return value;
  }
  function integer(value, name, maximum) {
    if (typeof value !== 'number') throw invalid(name);
    if (value % 1 !== 0 || value < 0 || value > maximum) throw range(name);
    return value;
  }
  function position(value) {
    if (value === undefined || value === null || value === -1) return null;
    return integer(value, 'position', 9007199254740991);
  }
  function options(value) {
    if (value === undefined) return create(null);
    if (value === null || typeof value !== 'object') throw invalid('options');
    return value;
  }
  function errorFirst(reason) {
    // A callback cannot represent a falsy exception in its first slot.
    // Do not silently convert a failed admission/provider operation to success.
    if (reason) return reason;
    const error = new ErrorClass('Filesystem operation failed');
    error.code = 'EIO'; error.cause = reason; return error;
  }
  function run(operation, cb, success, failure) {
    enqueue(function () {
      let value, error, failed = false;
      try { value = operation(); }
      catch (reason) { failed = true; error = errorFirst(reason); }
      // Deliberately outside the operation's catch. A throwing callback is an
      // uncaught job exception, not a second callback or rejected hidden Promise.
      if (failed) apply(cb, undefined, failure === undefined ? [error] : failure(error));
      else apply(cb, undefined, success(value));
      // Callback return values, including rejected Promises, are not adopted.
    });
  }
  function valueResult(value) { return [null, value]; }
  function voidResult() { return [null]; }
  function pathValue(value) {
    let result = value;
    if (typeof value === 'string') {
      if (apply(indexOf, value, ['\0']) !== -1) throw nulPath();
    } else if (isBuffer(value)) {
      result = from(value);
      for (let i = 0; i < result.length; i++) if (result[i] === 0) throw nulPath();
    } else {
      try { result = new URLClass(apply(urlString, value, [])); }
      catch (error) { throw invalid('path'); }
      if (result.protocol !== 'file:') {
        const error = invalid('path'); error.code = 'ERR_INVALID_URL_SCHEME'; throw error;
      }
    }
    return result;
  }
  function settingsValue(value, keys) {
    if (value === undefined || value === null || typeof value !== 'object') return value;
    // Only the documented options participate. Snapshot before scheduling so
    // later guest mutation cannot change recursive deletion or result shape.
    const result = create(null);
    for (let i = 0; i < keys.length; i++) {
      const setting = value[keys[i]];
      if (setting !== undefined || apply(own, value, [keys[i]])) result[keys[i]] = setting;
    }
    return result;
  }
  function install(name, fn) {
    const descriptor = create(null);
    descriptor.value = fn; descriptor.enumerable = true;
    descriptor.configurable = true; descriptor.writable = true;
    define(fs, name, descriptor);
  }
  function one(name, method, result) {
    install(name, function (path, cb) {
      callback(cb); path = pathValue(path);
      run(function () { return method(path); }, cb, result);
    });
  }
  function optional(name, method, result, keys) {
    install(name, function (path, settings, cb) {
      if (typeof settings === 'function') { cb = settings; settings = undefined; }
      callback(cb); path = pathValue(path);
      if (keys !== undefined) settings = settingsValue(settings, keys);
      run(function () { return method(path, settings); }, cb, result);
    });
  }
  function two(name, method, secondPath) {
    install(name, function (first, second, cb) {
      callback(cb); first = pathValue(first);
      if (secondPath) second = pathValue(second);
      run(function () { return method(first, second); }, cb, voidResult);
    });
  }
  function three(name, method) {
    install(name, function (first, second, third, cb) {
      callback(cb); first = pathValue(first);
      second = descriptorTime(second, 'atime'); third = descriptorTime(third, 'mtime');
      run(function () { return method(first, second, third); }, cb, voidResult);
    });
  }
  function writeAborted(signal) {
    if (signal === undefined || !signal.aborted) return undefined;
    const error = new ErrorClass('The operation was aborted');
    error.name = 'AbortError'; error.code = 'ABORT_ERR'; error.cause = signal.reason;
    return error;
  }
  function wholeFileWrite(name) {
    const previous = fs[name], sync = fs[name + 'Sync'], promiseWrite = fs.promises[name];
    install(name, function (path, data, settings, cb) {
      if (typeof settings === 'function') { cb = settings; settings = undefined; }
      callback(cb);
      if (settings === null || typeof settings !== 'object') {
        return apply(previous, fs, [path, data, settings, cb]);
      }
      path = typeof path === 'number' ? fd(path) : pathValue(path);
      settings = settingsValue(settings, ['encoding', 'flag', 'mode', 'flush', 'signal']);
      if (settings.encoding !== undefined && settings.encoding !== null && !isEncoding(settings.encoding)) {
        const error = invalid('encoding'); error.code = 'ERR_INVALID_ARG_VALUE'; throw error;
      }
      if (settings.flush !== undefined && typeof settings.flush !== 'boolean') throw invalid('options.flush');
      const signal = settings.signal;
      if (signal !== undefined && (signal === null || typeof signal !== 'object' ||
          typeof signal.aborted !== 'boolean')) throw invalid('options.signal');
      if (typeof data !== 'string') {
        if (!isView(data)) throw invalid('data');
        data = view(data).buffer;
      }
      const aborted = writeAborted(signal);
      if (aborted !== undefined) { cb(aborted); return; }
      if (typeof path === 'number') {
        // Numeric descriptors remain caller-owned and must not be reopened or
        // closed by a whole-file callback operation.
        run(function () {
          const aborted = writeAborted(signal);
          if (aborted !== undefined) throw aborted;
          return sync(path, data, settings);
        }, cb, voidResult);
        return;
      }
      // Reuse the Promise writer's owned descriptor, short-write retry, abort
      // and flush/close protocol. Snapshot options before scheduling so later
      // mutation cannot turn an exclusive create into an overwriting write.
      enqueue(function () {
        let pending, failure, failed = false;
        try { pending = promiseWrite(path, data, settings); }
        catch (error) { failed = true; failure = error; }
        if (failed) { cb(errorFirst(failure)); return; }
        apply(promiseThen, pending, [
          function () { enqueue(function () { cb(null); }); },
          function (error) { enqueue(function () { cb(errorFirst(error)); }); },
        ]);
      });
    });
  }
  wholeFileWrite('writeFile');
  wholeFileWrite('appendFile');
  optional('stat', fs.statSync, valueResult, ['bigint']);
  optional('lstat', fs.lstatSync, valueResult, ['bigint']);
  optional('readdir', fs.readdirSync, valueResult, ['encoding', 'withFileTypes', 'recursive']);
  optional('mkdir', fs.mkdirSync, function (value) { return value === undefined ? [null] : [null, value]; }, ['mode', 'recursive']);
  optional('mkdtemp', fs.mkdtempSync, valueResult, ['encoding']);
  optional('realpath', fs.realpathSync, valueResult, ['encoding']);
  optional('readlink', fs.readlinkSync, valueResult, ['encoding']);
  optional('access', fs.accessSync, voidResult);
  optional('rmdir', fs.rmdirSync, voidResult, ['recursive', 'maxRetries', 'retryDelay']);
  optional('rm', fs.rmSync, voidResult, ['recursive', 'force', 'maxRetries', 'retryDelay']);
  const truncateSync = fs.truncateSync;
  install('truncate', function (path, length, cb) {
    if (typeof length === 'function') { cb = length; length = undefined; }
    callback(cb); path = pathValue(path); length = descriptorLength(length);
    run(function () { return truncateSync(path, length); }, cb, voidResult);
  });
  one('unlink', fs.unlinkSync, voidResult);
  two('rename', fs.renameSync, true);
  const chmodSync = fs.chmodSync;
  install('chmod', function (path, mode, cb) {
    callback(cb); path = pathValue(path); mode = descriptorMode(mode);
    run(function () { return chmodSync(path, mode); }, cb, voidResult);
  });
  three('utimes', fs.utimesSync);
  const copyFileSync = fs.copyFileSync, symlinkSync = fs.symlinkSync;
  function copyMode(value) {
    if (value === undefined || value === null) return 0;
    if (typeof value !== 'number') throw invalid('mode');
    // Truncate before range validation, without wrapping large numeric masks.
    if (!(value > -1 && value < 8)) throw range('mode');
    return value | 0;
  }
  install('copyFile', function (source, destination, mode, cb) {
    if (typeof mode === 'function') { cb = mode; mode = undefined; }
    callback(cb); source = pathValue(source); destination = pathValue(destination);
    mode = copyMode(mode);
    run(function () { return copyFileSync(source, destination, mode); }, cb, voidResult);
  });
  const copy = fs.promises.cp;
  install('cp', function (source, destination, settings, cb) {
    if (typeof settings === 'function') { cb = settings; settings = undefined; }
    callback(cb); source = pathValue(source); destination = pathValue(destination);
    settings = settingsValue(settings, ['recursive', 'force', 'errorOnExist', 'dereference',
      'preserveTimestamps', 'verbatimSymlinks', 'mode', 'filter']);
    let promise;
    try { promise = copy(source, destination, settings); }
    catch (error) { enqueue(function () { cb(errorFirst(error)); }); return; }
    // Recursive cp supports async filters. Reuse its existing Promise body,
    // rather than silently routing async filtering through cpSync.
    apply(promiseThen, promise, [function () { enqueue(function () { cb(null, undefined); }); },
      function (error) { enqueue(function () { cb(errorFirst(error)); }); }]);
  });
  install('symlink', function (target, path, type, cb) {
    if (typeof type === 'function') { cb = type; type = undefined; }
    callback(cb); target = pathValue(target); path = pathValue(path);
    run(function () { return symlinkSync(target, path, type); }, cb, voidResult);
  });
  const existsSync = fs.existsSync;
  install('exists', function (path, cb) {
    callback(cb);
    try { path = pathValue(path); }
    catch (error) { cb(false); return; } // Node's legacy invalid-path exception.
    // Legacy exists has no error-first argument. All errors become false.
    run(function () { return existsSync(path); }, cb, function (value) { return [!!value]; },
      function () { return [false]; });
  });
  install('open', function (path, flags, mode, cb) {
    if (typeof flags === 'function') { cb = flags; flags = 'r'; mode = undefined; }
    else if (typeof mode === 'function') { cb = mode; mode = undefined; }
    callback(cb); path = pathValue(path);
    if (flags === undefined) flags = 'r';
    run(function () { return openSync(path, flags, mode); }, cb, valueResult);
  });
  install('close', function (descriptor, cb) {
    // Node permits omission of this one callback, but not arbitrary values.
    if (cb === undefined) cb = function (error) { if (error) throw error; };
    callback(cb); fd(descriptor);
    run(function () { return closeSync(descriptor); }, cb, voidResult);
  });
  const fsyncSync = fs.fsyncSync;
  install('fsync', function (descriptor, cb) {
    callback(cb); fd(descriptor);
    run(function () { return fsyncSync(descriptor); }, cb, voidResult);
  });
  const fdatasyncSync = fs.fdatasyncSync, ftruncateSync = fs.ftruncateSync;
  const fchmodSync = fs.fchmodSync, futimesSync = fs.futimesSync;
  install('fdatasync', function (descriptor, cb) {
    callback(cb); fd(descriptor);
    run(function () { return fdatasyncSync(descriptor); }, cb, voidResult);
  });
  install('ftruncate', function (descriptor, length, cb) {
    if (typeof length === 'function') { cb = length; length = undefined; }
    callback(cb); fd(descriptor); length = descriptorLength(length);
    run(function () { return ftruncateSync(descriptor, length); }, cb, voidResult);
  });
  function descriptorLength(length) {
    if (length === undefined) return 0;
    if (typeof length !== 'number') throw invalid('len');
    if (length % 1 !== 0 || length < -9007199254740991 || length > 9007199254740991) throw range('len');
    return length <= 0 ? 0 : length;
  }
  function descriptorMode(mode) {
    if (typeof mode === 'string') {
      let parsed = 0, i = 0;
      for (; i < mode.length; i++) {
        const digit = mode[i];
        if (digit < '0' || digit > '7') break;
        parsed = parsed * 8 + +digit;
      }
      if (mode.length === 0 || i !== mode.length) {
        const error = invalid('mode'); error.code = 'ERR_INVALID_ARG_VALUE'; throw error;
      }
      mode = parsed;
    }
    integer(mode, 'mode', 4294967295);
    return mode === 0 ? 0 : mode;
  }
  install('fchmod', function (descriptor, mode, cb) {
    callback(cb); fd(descriptor); mode = descriptorMode(mode);
    run(function () { return fchmodSync(descriptor, mode); }, cb, voidResult);
  });
  function descriptorTime(value, name) {
    let seconds;
    if (typeof value === 'number') {
      seconds = value;
      if (seconds < 0 && seconds !== -1 / 0) seconds = dateNow() / 1000;
    } else if (typeof value === 'string') {
      seconds = +value;
    } else {
      try { seconds = apply(dateTime, value, []) / 1000; }
      catch (error) { throw invalid(name); }
    }
    if (seconds !== seconds || seconds === 1 / 0 || seconds === -1 / 0) throw invalid(name);
    // Snapshot Date objects before scheduling. A string preserves pre-epoch
    // Date/string values when the sync facade normalizes its public arguments;
    // a negative number would incorrectly request the current time again.
    return '' + seconds;
  }
  install('futimes', function (descriptor, atime, mtime, cb) {
    callback(cb); fd(descriptor);
    atime = descriptorTime(atime, 'atime'); mtime = descriptorTime(mtime, 'mtime');
    run(function () { return futimesSync(descriptor, atime, mtime); }, cb, voidResult);
  });
  const fstatSync = fs.fstatSync;
  install('fstat', function (descriptor, settings, cb) {
    if (typeof settings === 'function') { cb = settings; settings = undefined; }
    callback(cb); fd(descriptor);
    // Snapshot the one supported option before scheduling, including accessors
    // on primitive wrappers. Like fstatSync, null fails before any fd effect.
    const bigint = settings === undefined ? false : settings.bigint === true;
    run(function () { return fstatSync(descriptor, { bigint: bigint }); }, cb, valueResult);
  });

  function view(value) {
    if (!isView(value)) throw invalid('buffer');
    let backing, offset, length;
    try {
      backing = apply(typedBuffer, value, []);
      offset = apply(typedOffset, value, []);
      length = apply(typedLength, value, []);
    } catch (error) {
      backing = apply(dataBuffer, value, []);
      offset = apply(dataOffset, value, []);
      length = apply(dataLength, value, []);
    }
    return { buffer: from(backing, offset, length), length: length };
  }
  function window(buffer, offset, length) {
    const bytes = view(buffer);
    if (offset === undefined) offset = 0;
    integer(offset, 'offset', bytes.length);
    if (length === undefined) length = bytes.length - offset;
    integer(length, 'length', bytes.length - offset);
    return { buffer: bytes.buffer, offset: offset, length: length };
  }
  function count(value, length) {
    if (typeof value !== 'number' || value % 1 !== 0 || value < 0 || value > length) {
      const error = new ErrorClass('Invalid byte count from filesystem provider');
      error.code = 'EIO'; throw error;
    }
    return value;
  }
  install('read', function (descriptor, buffer, offset, length, at, cb) {
    fd(descriptor);
    if (!isView(buffer)) {
      if (typeof buffer === 'function') { cb = buffer; buffer = undefined; }
      else cb = offset;
      const settings = options(buffer);
      buffer = settings.buffer;
      if (buffer === undefined) buffer = alloc(16384);
      offset = settings.offset; length = settings.length; at = settings.position;
    } else if (typeof offset === 'object' && offset !== null) {
      cb = length;
      const settings = offset;
      offset = settings.offset; length = settings.length; at = settings.position;
    } else if (typeof offset === 'function') {
      cb = offset; offset = undefined; length = undefined; at = undefined;
    }
    callback(cb);
    const bytes = window(buffer, offset, length), pos = position(at);
    run(function () {
      return count(readSync(descriptor, bytes.buffer, bytes.offset, bytes.length, pos), bytes.length);
    }, cb, function (n) { return [null, n, buffer]; }, function (error) { return [error, 0, buffer]; });
  });
  install('write', function (descriptor, data, offset, length, at, cb) {
    fd(descriptor);
    let bytes, pos;
    if (typeof data === 'string') {
      if (typeof offset === 'function') { cb = offset; offset = undefined; length = undefined; }
      else if (typeof length === 'function') { cb = length; length = undefined; }
      else cb = at;
      callback(cb); pos = position(offset);
      const encoding = length === undefined ? 'utf8' : length;
      if (!isEncoding(encoding)) {
        const error = invalid('encoding'); error.code = 'ERR_UNKNOWN_ENCODING'; throw error;
      }
      const buffer = from(data, encoding);
      bytes = { buffer: buffer, offset: 0, length: buffer.length };
    } else {
      if (offset !== null && typeof offset === 'object') {
        cb = length; const settings = offset;
        offset = settings.offset; length = settings.length; at = settings.position;
      } else if (typeof offset === 'function') { cb = offset; offset = undefined; length = undefined; at = undefined; }
      else if (typeof length === 'function') { cb = length; length = undefined; at = undefined; }
      else if (typeof at === 'function') { cb = at; at = undefined; }
      callback(cb); bytes = window(data, offset, length); pos = position(at);
    }
    run(function () {
      return count(writeSync(descriptor, bytes.buffer, bytes.offset, bytes.length, pos), bytes.length);
    }, cb, function (n) { return [null, n, data]; }, function (error) { return [error, 0, data]; });
  });
  function vector(name, operation) {
    install(name, function (descriptor, buffers, at, cb) {
      if (typeof at === 'function') { cb = at; at = undefined; }
      callback(cb); fd(descriptor);
      if (!arrayIsArray(buffers)) throw invalid('buffers');
      const entries = [], length = buffers.length;
      let total = 0;
      for (let i = 0; i < length; i++) {
        const bytes = view(buffers[i]); entries[i] = bytes.buffer; total += bytes.length;
        if (total > 9007199254740991) throw range('buffers');
      }
      // Vectored Node I/O uses the cursor for other position types, without coercion.
      const pos = typeof at === 'number' && at % 1 === 0 && at >= 0 && at <= 9007199254740991 ? at : null;
      run(function () { return count(operation(descriptor, entries, pos), total); }, cb,
        function (n) { return [null, n, buffers]; }, function (error) { return [error, 0, buffers]; });
    });
  }
  vector('readv', readvSync); vector('writev', writevSync);
  function multiResult(name, countName, bufferName) {
    const operation = fs[name];
    const descriptor = create(null);
    descriptor.value = function () {
      const args = apply(slice, arguments, []);
      return new PromiseClass(function (resolve, reject) {
        args[args.length] = function (error, n, buffer) {
          if (error) { reject(error); return; }
          const result = {};
          const countDescriptor = create(null), bufferDescriptor = create(null);
          countDescriptor.value = n; countDescriptor.enumerable = true;
          countDescriptor.writable = true; countDescriptor.configurable = true;
          bufferDescriptor.value = buffer; bufferDescriptor.enumerable = true;
          bufferDescriptor.writable = true; bufferDescriptor.configurable = true;
          define(result, countName, countDescriptor); define(result, bufferName, bufferDescriptor);
          resolve(result);
        };
        apply(operation, undefined, args);
      });
    };
    descriptor.configurable = true;
    define(operation, custom, descriptor);
  }
  multiResult('read', 'bytesRead', 'buffer');
  multiResult('write', 'bytesWritten', 'buffer');
  multiResult('readv', 'bytesRead', 'buffers');
  multiResult('writev', 'bytesWritten', 'buffer');
  return fs;
})
