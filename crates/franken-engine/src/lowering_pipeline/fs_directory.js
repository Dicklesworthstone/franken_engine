(function installDirectoryIteration(fs) {
  'use strict';
  // Directory iteration over the existing gated readdir/realpath/lstat effects.
  // The host currently returns a per-directory snapshot, not an open DIR fd.
  // Descendants are acquired on demand; neither an entire recursive tree nor
  // an OS directory handle is retained. This is not a filesystem snapshot or
  // an off-thread I/O backend. Every visited directory is admitted by the host.
  const readdir = fs.readdirSync;
  const realpath = fs.realpathSync;
  const lstat = fs.lstatSync;
  const PromiseClass = Promise;
  const promiseThen = Promise.prototype.then;
  const apply = Reflect.apply;
  const define = Object.defineProperty;
  const create = Object.create;
  const isArray = Array.isArray;
  const WeakMapClass = WeakMap;
  const weakGet = WeakMap.prototype.get;
  const weakSet = WeakMap.prototype.set;
  const asyncIterator = Symbol.asyncIterator;
  const indexOf = String.prototype.indexOf;
  const MAX_ENTRIES = 100000;
  const MAX_NAMES = 4 * 1024 * 1024;
  const MAX_DEPTH = 64;
  const MAX_PENDING = 1024;
  const token = {};
  let owners;

  function error(code, message) { const value = new Error(message); value.code = code; return value; }
  function invalid(name) { const value = new TypeError('Invalid ' + name); value.code = 'ERR_INVALID_ARG_TYPE'; return value; }
  function closed() { return error('ERR_DIR_CLOSED', 'Directory handle was closed'); }
  function concurrent() { return error('ERR_DIR_CONCURRENT_OPERATION', 'A directory operation is already pending'); }
  function limit() { return error('ERR_FS_DIR_LIMIT', 'Directory traversal resource limit exceeded'); }
  function unsupported() { return error('ERR_FS_DIR_UNSUPPORTED', 'Directory snapshots support UTF-8 string paths, default buffering, and sync or Promise operations'); }
  function owner(value) {
    const state = owners === undefined ? undefined : apply(weakGet, owners, [value]);
    if (state === undefined) throw invalid('Dir receiver');
    return state;
  }
  function path(value) {
    if (typeof value !== 'string') throw invalid('path');
    if (value.length === 0 || value.length > 4096 || apply(indexOf, value, ['\0']) !== -1 ||
        apply(indexOf, value, ['\\']) !== -1) throw invalid('path');
    return value;
  }
  function child(parent, name) { return parent + (parent[parent.length - 1] === '/' ? '' : '/') + name; }
  function options(value) {
    if (value === undefined || value === null) value = {};
    if (typeof value === 'string') value = { encoding: value };
    if (typeof value !== 'object' || isArray(value)) throw invalid('options');
    const encoding = value.encoding;
    const bufferSize = value.bufferSize;
    const recursive = value.recursive;
    if (recursive !== undefined && typeof recursive !== 'boolean') throw invalid('options.recursive');
    // A snapshot provider cannot implement an arbitrary native DIR buffer size
    // or recover original non-UTF-8 filename bytes. Never pretend otherwise.
    if ((encoding != null && encoding !== 'utf8' && encoding !== 'utf-8') ||
        (bufferSize !== undefined && bufferSize !== 32)) throw unsupported();
    return recursive === true;
  }
  function property(object, name, value) {
    const descriptor = create(null);
    descriptor.value = value; descriptor.writable = true;
    descriptor.enumerable = true; descriptor.configurable = true;
    define(object, name, descriptor);
  }
  function snapshot(state, physical, publicPath, depth) {
    if (depth > MAX_DEPTH || physical.length > 4096 || publicPath.length > 4096) throw limit();
    const entries = readdir(physical, { withFileTypes: true, encoding: 'utf8' });
    if (!isArray(entries) || entries.length > MAX_ENTRIES - state.seen) throw limit();
    let bytes = physical.length + publicPath.length;
    // Capture immutable traversal decisions before any Dirent reaches guest
    // code. Rewriting a returned name or type method cannot redirect descent.
    const records = create(null);
    records.length = entries.length;
    for (let i = 0; i < entries.length; i++) {
      const entry = entries[i];
      if (entry === null || typeof entry !== 'object') throw invalid('directory entry');
      const name = path(entry.name);
      if (name === '.' || name === '..' || apply(indexOf, name, ['/']) !== -1 ||
          typeof entry.isDirectory !== 'function' || typeof entry.isSymbolicLink !== 'function') {
        throw invalid('directory entry');
      }
      const directory = !!entry.isDirectory() && !entry.isSymbolicLink();
      bytes += name.length;
      if (bytes > MAX_NAMES - state.names) throw limit();
      records[i] = { value: entry, name: name, directory: directory };
    }
    state.seen += entries.length;
    state.names += bytes;
    return { records: records, index: 0, physical: physical, path: publicPath,
      depth: depth, bytes: bytes, parent: state.frame };
  }
  function release(state) {
    state.closed = true; state.frame = undefined; state.descend = undefined;
    state.names = 0;
  }
  function nextEntry(state) {
    if (state.closed) throw closed();
    if (state.failed) throw state.failure;
    try {
      if (state.descend !== undefined) {
        const pending = state.descend; state.descend = undefined;
        // A guest may replace a yielded directory by a symlink before next().
        // Do not follow that new link just because the prior Dirent was a dir.
        const info = lstat(pending.physical);
        if (!info.isDirectory() || info.isSymbolicLink() || realpath(pending.physical) !== pending.physical) {
          throw error('ERR_FS_DIR_CHANGED', 'Directory changed before recursive descent');
        }
        state.frame = snapshot(state, pending.physical, pending.path, pending.depth);
      }
      while (state.frame !== undefined) {
        const frame = state.frame;
        if (frame.index === frame.records.length) {
          state.names -= frame.bytes;
          state.frame = frame.parent;
          continue;
        }
        const record = frame.records[frame.index];
        frame.records[frame.index++] = undefined;
        // Once yielded, a record is no longer retained by the cursor.
        state.names -= record.name.length; frame.bytes -= record.name.length;
        if (state.recursive && record.directory) {
          state.descend = { physical: child(frame.physical, record.name),
            path: child(frame.path, record.name), depth: frame.depth + 1 };
        }
        property(record.value, 'parentPath', frame.path);
        property(record.value, 'path', frame.path);
        return record.value;
      }
      return null;
    } catch (failure) {
      // A rejected traversal never silently skips an unreadable directory or
      // retries the same partial snapshot. close() still releases its state.
      state.failed = true; state.failure = failure;
      state.frame = undefined; state.descend = undefined; state.names = 0;
      throw failure;
    }
  }
  function schedule(state) {
    // One reaction drives one accepted request, not an accumulating chain of
    // promises retaining every earlier result. Queued reads/close are FIFO.
    apply(promiseThen, new PromiseClass(function (resolve) { resolve(); }), [function () {
      const request = state.head;
      state.head = request.next;
      if (state.head === undefined) state.tail = undefined;
      try {
        if (request.close) {
          if (state.closed) throw closed();
          release(state); request.resolve();
        } else request.resolve(nextEntry(state));
      } catch (failure) { request.reject(failure); }
      state.pending--;
      if (state.head !== undefined) schedule(state);
    }]);
  }
  function enqueue(state, closing) {
    if (!closing && state.pending >= MAX_PENDING) throw limit();
    if (closing) state.closing = true;
    return new PromiseClass(function (resolve, reject) {
      const request = { close: closing, resolve: resolve, reject: reject, next: undefined };
      if (state.tail === undefined) state.head = request; else state.tail.next = request;
      state.tail = request;
      if (state.pending++ === 0) schedule(state);
    });
  }
  function read(state) {
    if (state.closed || state.closing) throw closed();
    return enqueue(state, false);
  }
  function close(state) {
    // Node read() throws for a closed Dir; close() instead rejects its Promise.
    if (state.closed || state.closing) return new PromiseClass(function (resolve, reject) { reject(closed()); });
    const promise = enqueue(state, true);
    state.closePromise = promise;
    return promise;
  }
  class Dir {
    constructor(key, state) {
      if (key !== token) throw error('ERR_ILLEGAL_CONSTRUCTOR', 'Dir objects are created by opendir');
      if (owners === undefined) owners = new WeakMapClass();
      apply(weakSet, owners, [this, state]);
    }
    get path() { return owner(this).path; }
    readSync() {
      const state = owner(this);
      if (state.pending !== 0 || state.busy) throw concurrent();
      state.busy = true;
      try { return nextEntry(state); } finally { state.busy = false; }
    }
    closeSync() {
      const state = owner(this);
      if (state.pending !== 0 || state.busy) throw concurrent();
      if (state.closed) throw closed();
      release(state);
    }
    read() { if (arguments.length !== 0) throw unsupported(); return read(owner(this)); }
    close() { if (arguments.length !== 0) throw unsupported(); return close(owner(this)); }
    [asyncIterator]() {
      const state = owner(this);
      let done = false;
      // Serialize iterator requests independently of the shared Dir queue;
      // return() before first next() still releases this adapter's ownership.
      let tail = new PromiseClass(function (resolve) { resolve(); });
      let queued = 0;
      function operation(action, cleanup) {
        if (!cleanup && queued >= MAX_PENDING) return new PromiseClass(function (resolve, reject) { reject(limit()); });
        queued++;
        const result = apply(promiseThen, tail, [action]);
        tail = apply(promiseThen, result, [function () { queued--; }, function () { queued--; }]);
        return result;
      }
      async function finish() {
        if (state.closing) await state.closePromise;
        else if (!state.closed) await close(state);
      }
      const iterator = {
        next: function () { return operation(async function () {
          if (done) return { value: undefined, done: true };
          try {
            const entry = await read(state);
            if (entry !== null) return { value: entry, done: false };
            done = true; await finish();
            return { value: undefined, done: true };
          } catch (failure) { done = true; await finish(); throw failure; }
        }); },
        return: function () { return operation(async function () {
          done = true; await finish(); return { value: undefined, done: true };
        }, true); },
        throw: function (failure) { return operation(async function () {
          done = true; await finish(); throw failure;
        }, true); }
      };
      property(iterator, asyncIterator, function () { return this; });
      return iterator;
    }
  }
  function opendirSync(input, settings) {
    input = path(input);
    const recursive = options(settings);
    const physical = path(realpath(input));
    const state = { path: input, recursive: recursive, closed: false, closing: false,
      failed: false, failure: undefined, frame: undefined, descend: undefined,
      seen: 0, names: 0, closePromise: undefined, pending: 0, head: undefined, tail: undefined, busy: false };
    state.frame = snapshot(state, physical, input, 0);
    return new Dir(token, state);
  }
  function opendir(input, settings) {
    return new PromiseClass(function (resolve) { resolve(opendirSync(input, settings)); });
  }
  property(fs, 'Dir', Dir);
  property(fs, 'opendirSync', opendirSync);
  property(fs.promises, 'opendir', opendir);
  return fs;
})
