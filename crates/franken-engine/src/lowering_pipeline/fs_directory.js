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

  // File discovery uses the same captured directory records and host effects
  // as Dir. An inclusion automaton decides whether a subtree can match BEFORE
  // it is opened. Exclusions prune before descent too. No regex backtracking,
  // ambient glob library, whole-tree collection, or implicit symlink following.
  // Supported portable syntax: *, ?, **, character classes and brace lists.
  // Ordering follows host directory observations and is not an oracle claim.
  const splitString = String.prototype.split;
  const sliceString = String.prototype.slice;
  const MAX_GLOB_PATTERNS = 128;
  const MAX_GLOB_PATTERN_UNITS = 65536;
  const MAX_GLOB_WORK = 8000000;
  function globLimit() { return error('ERR_FS_GLOB_LIMIT', 'Glob resource limit exceeded'); }
  function globUnsupported() {
    return error('ERR_FS_GLOB_UNSUPPORTED',
      'Glob supports relative slash-separated patterns, brace lists, UTF-8 cwd, and synchronous predicate or pattern-array exclusions');
  }
  function chargeGlob(budget, amount) {
    if (amount > MAX_GLOB_WORK - budget.work) throw globLimit();
    budget.work += amount;
  }
  function slice(value, start, end) { return apply(sliceString, value, [start, end]); }
  function expandGlob(pattern, output, budget, depth) {
    if (depth > 16 || output.length >= MAX_GLOB_PATTERNS) throw globLimit();
    chargeGlob(budget, pattern.length + 1);
    for (let start = 0; start < pattern.length; start++) {
      // Braces inside a character class are literal characters, not a list.
      if (pattern[start] === '[') {
        const closing = apply(indexOf, pattern, [']', start + 1]);
        if (closing !== -1) { start = closing; continue; }
      }
      if (pattern[start] !== '{') continue;
      let nesting = 1;
      let end = start + 1;
      let last = end;
      const choices = [];
      for (; end < pattern.length && nesting !== 0; end++) {
        chargeGlob(budget, 1);
        const c = pattern[end];
        if (c === '{') nesting++;
        else if (c === '}') nesting--;
        else if (c === ',' && nesting === 1) {
          choices[choices.length] = slice(pattern, last, end); last = end + 1;
        }
        if (choices.length >= MAX_GLOB_PATTERNS) throw globLimit();
      }
      if (nesting !== 0) throw globUnsupported();
      if (choices.length === 0) {
        if (apply(indexOf, slice(pattern, start + 1, end - 1), ['..']) !== -1) throw globUnsupported();
        continue;
      }
      choices[choices.length] = slice(pattern, last, end - 1);
      for (let i = 0; i < choices.length; i++) {
        expandGlob(slice(pattern, 0, start) + choices[i] + slice(pattern, end), output, budget, depth + 1);
      }
      return;
    }
    budget.patternUnits += pattern.length;
    if (budget.patternUnits > MAX_GLOB_PATTERN_UNITS) throw globLimit();
    output[output.length] = pattern;
  }
  function globSegment(value) {
    if (value === '**') return { globstar: true };
    const tokens = [];
    for (let i = 0; i < value.length; i++) {
      const c = value[i];
      if (c === '*' || c === '?') {
        if (value[i + 1] === '(') throw globUnsupported();
        if (c !== '*' || tokens.length === 0 || tokens[tokens.length - 1].kind !== '*') {
          tokens[tokens.length] = { kind: c };
        }
      } else if ((c === '@' || c === '+' || c === '!') && value[i + 1] === '(') {
        throw globUnsupported();
      } else if (c === '[') {
        let end = i + 1;
        const negate = value[end] === '!' || value[end] === '^';
        if (negate) end++;
        const first = end;
        if (value[end] === ']') end++;
        while (end < value.length && value[end] !== ']') end++;
        if (end === value.length) { tokens[tokens.length] = { kind: 'literal', value: c }; continue; }
        const ranges = [];
        for (let j = first; j < end; j++) {
          if (value[j] === '[' && (value[j + 1] === ':' || value[j + 1] === '.')) throw globUnsupported();
          let upper = value[j];
          const lower = upper;
          if (j + 2 < end && value[j + 1] === '-') { upper = value[j + 2]; j += 2; }
          if (lower > upper) throw globUnsupported();
          ranges[ranges.length] = { lower: lower, upper: upper };
        }
        tokens[tokens.length] = { kind: 'class', ranges: ranges, negate: negate };
        i = end;
      } else tokens[tokens.length] = { kind: 'literal', value: c };
    }
    return { globstar: false, tokens: tokens };
  }
  function classMatches(token, c) {
    let found = false;
    for (let i = 0; i < token.ranges.length; i++) {
      const range = token.ranges[i];
      if (c >= range.lower && c <= range.upper) { found = true; break; }
    }
    return token.negate ? !found : found;
  }
  function segmentMatches(segment, name, budget) {
    const tokens = segment.tokens;
    const first = tokens[0];
    if (name[0] === '.' && !(first && ((first.kind === 'literal' && first.value === '.') ||
        (first.kind === 'class' && !first.negate && classMatches(first, '.'))))) return false;
    // Two bounded rows: worst-case work is pattern length times name length,
    // not exponential in adjacent stars. UTF-16 units match the Node 22 band.
    let before = create(null);
    before[0] = true;
    for (let i = 0; i < tokens.length; i++) {
      const token = tokens[i];
      chargeGlob(budget, (name.length + 1) * (token.kind === 'class' ? token.ranges.length + 1 : 1));
      const after = create(null);
      after[0] = token.kind === '*' && !!before[0];
      for (let j = 1; j <= name.length; j++) {
        const c = name[j - 1];
        after[j] = token.kind === '*' ? !!(before[j] || after[j - 1]) :
          !!before[j - 1] && (token.kind === '?' ||
            (token.kind === 'literal' ? c === token.value : classMatches(token, c)));
      }
      before = after;
    }
    return !!before[name.length];
  }
  function compileGlobs(input, budget, exclusion) {
    const items = typeof input === 'string' ? [input] : input;
    if (!isArray(items)) throw invalid('pattern');
    const count = items.length;
    if (count > MAX_GLOB_PATTERNS) throw globLimit();
    const expanded = [];
    for (let i = 0; i < count; i++) {
      const value = items[i];
      if (typeof value !== 'string') throw invalid('pattern');
      if (value === '') continue;
      path(value);
      if (value[0] === '/' || value[0] === '!') throw globUnsupported();
      expandGlob(value, expanded, budget, 0);
    }
    const patterns = [];
    for (let i = 0; i < expanded.length; i++) {
      const value = expanded[i];
      const parts = apply(splitString, value, ['/']);
      const segments = [];
      for (let j = 0; j < parts.length; j++) {
        if (parts[j] === '..') throw globUnsupported();
        if (parts[j] === '' || parts[j] === '.') continue;
        segments[segments.length] = globSegment(parts[j]);
      }
      if (segments.length > MAX_DEPTH) throw globLimit();
      if (segments.length !== 0 || exclusion) patterns[patterns.length] = {
        segments: segments, directory: !exclusion &&
          (value[value.length - 1] === '/' || parts[parts.length - 1] === '.')
      };
    }
    return patterns;
  }
  function globClosure(pattern, states) {
    for (let i = 0; i < pattern.segments.length; i++) {
      if (states[i] && pattern.segments[i].globstar) states[i + 1] = true;
    }
    return states;
  }
  function initialGlobs(patterns) {
    const states = [];
    for (let i = 0; i < patterns.length; i++) {
      const positions = create(null); positions[0] = true;
      states[i] = globClosure(patterns[i], positions);
    }
    return states;
  }
  function advanceGlobs(patterns, states, name, budget) {
    const result = [];
    for (let p = 0; p < patterns.length; p++) {
      const pattern = patterns[p];
      const current = states[p];
      const next = create(null);
      let hiddenByGlobstar = false;
      for (let i = 0; i < pattern.segments.length; i++) {
        if (current[i] && pattern.segments[i].globstar) hiddenByGlobstar = true;
      }
      chargeGlob(budget, pattern.segments.length + 1);
      // Node 22 does not admit dot entries through **, even with a dot-leading
      // tail. An explicitly named dot-directory prefix remains supported.
      if (name[0] !== '.' || !hiddenByGlobstar) {
        for (let i = 0; i < pattern.segments.length; i++) {
          if (!current[i]) continue;
          const segment = pattern.segments[i];
          if (segment.globstar) next[i] = true;
          else if (segmentMatches(segment, name, budget)) next[i + 1] = true;
        }
      }
      result[p] = globClosure(pattern, next);
    }
    return result;
  }
  function globAccepts(patterns, states, directory) {
    for (let i = 0; i < patterns.length; i++) {
      if (states[i][patterns[i].segments.length] && (!patterns[i].directory || directory)) return true;
    }
    return false;
  }
  function globCanDescend(patterns, states) {
    for (let p = 0; p < patterns.length; p++) {
      for (let i = 0; i < patterns[p].segments.length; i++) if (states[p][i]) return true;
    }
    return false;
  }
  function globOptions(pattern, settings) {
    if (settings === undefined) settings = {};
    if (settings === null || typeof settings !== 'object' || isArray(settings)) throw invalid('options');
    const cwd = settings.cwd;
    const typed = settings.withFileTypes;
    const exclude = settings.exclude;
    const follow = settings.followSymlinks;
    const depth = settings.maxDepth;
    if (typed !== undefined && typeof typed !== 'boolean') throw invalid('options.withFileTypes');
    if ((follow !== undefined && follow !== false) || depth !== undefined) throw globUnsupported();
    const predicate = typeof exclude === 'function' ? exclude : undefined;
    if (exclude !== undefined && predicate === undefined && !isArray(exclude)) throw invalid('options.exclude');
    const budget = { work: 0, patternUnits: 0 };
    return { cwd: cwd === undefined ? '.' : path(cwd), typed: typed === true,
      include: compileGlobs(pattern, budget, false),
      exclude: compileGlobs(exclude === undefined || predicate !== undefined ? [] : exclude, budget, true),
      predicate: predicate, budget: budget, collect: false, outputUnits: 0 };
  }
  function predicateExcludes(config, record, relative, directory, descend) {
    if (config.predicate === undefined) return false;
    chargeGlob(config.budget, 1);
    // The Node 22 band supplies a basename for each entry, plus a relative
    // directory route before descent in string mode. Typed callbacks receive
    // the real Dirent instead. Match/traversal decisions use captured records,
    // never fields a predicate can replace. Predicates are synchronous: their
    // return value is tested for truthiness, not awaited or then-inspected.
    if (config.typed) {
      property(record.value, 'parentPath', directory);
      property(record.value, 'path', directory);
      return !!apply(config.predicate, undefined, [record.value]);
    }
    if (apply(config.predicate, undefined, [record.name])) return true;
    if (!descend) return false;
    chargeGlob(config.budget, 1);
    return !!apply(config.predicate, undefined, [relative]);
  }
  function globResult(config, value, units) {
    // Charge captured names, not guest-mutable Dirent fields or their getters.
    if (config.collect) {
      config.outputUnits += units;
      if (config.outputUnits > MAX_NAMES) throw globLimit();
    }
    return value;
  }
  function* globEntries(config) {
    if (config.include.length === 0) return;
    // A literal cwd exclusion suppresses the entire query. In contrast, Node
    // 22's ** exclusion applies to entries, not the synthetic cwd match.
    for (let i = 0; i < config.exclude.length; i++) if (config.exclude[i].segments.length === 0) return;
    let physical;
    try { physical = path(realpath(config.cwd)); }
    catch (failure) { if (failure && (failure.code === 'ENOENT' || failure.code === 'ENOTDIR')) return; throw failure; }
    const included = initialGlobs(config.include);
    const excluded = initialGlobs(config.exclude);
    const accounting = { seen: 0, names: 0, frame: undefined };
    function* visit(directory, relative, depth, states, exclusions) {
      let frame;
      try { frame = snapshot(accounting, directory, directory, depth); }
      catch (failure) { if (failure && (failure.code === 'ENOENT' || failure.code === 'ENOTDIR')) return; throw failure; }
      try {
        while (frame.index < frame.records.length) {
          const record = frame.records[frame.index];
          frame.records[frame.index++] = undefined;
          accounting.names -= record.name.length; frame.bytes -= record.name.length;
          const name = relative === '' ? record.name : child(relative, record.name);
          const target = child(directory, record.name);
          const next = advanceGlobs(config.include, states, record.name, config.budget);
          const blocked = advanceGlobs(config.exclude, exclusions, record.name, config.budget);
          if (globAccepts(config.exclude, blocked, record.directory)) continue;
          const descend = record.directory && globCanDescend(config.include, next);
          const matches = globAccepts(config.include, next, record.directory);
          if (!matches && !descend) continue;
          // Evaluate before publication AND before acquiring a child snapshot.
          // A predicate may mutate the filesystem; the existing descent check
          // below must still run after it, even when no directory was yielded.
          if (predicateExcludes(config, record, name, directory, descend)) continue;
          if (matches) {
            property(record.value, 'parentPath', directory);
            property(record.value, 'path', directory);
            yield globResult(config, config.typed ? record.value : name,
              config.typed ? record.name.length + directory.length : name.length);
          }
          if (descend) {
            const info = lstat(target);
            if (!info.isDirectory() || info.isSymbolicLink() || realpath(target) !== target) {
              throw error('ERR_FS_DIR_CHANGED', 'Directory changed before glob descent');
            }
            yield* visit(target, name, depth + 1, next, blocked);
          }
        }
      } finally { accounting.names -= frame.bytes; }
    }
    // ** includes cwd itself. Use its real metadata, not a fabricated Dirent.
    let publishedRoot = false;
    if (globAccepts(config.include, included, true)) {
      const info = lstat(physical);
      if (info.isDirectory()) {
        if (config.typed) {
          let split = physical.length - 1;
          while (split > 0 && physical[split] !== '/') split--;
          const name = slice(physical, split + 1) || '/';
          property(info, 'name', name);
          property(info, 'parentPath', slice(physical, 0, split) || '/');
          property(info, 'path', slice(physical, 0, split) || '/');
          yield globResult(config, info, name.length + (slice(physical, 0, split) || '/').length);
        } else yield globResult(config, '.', 1);
        publishedRoot = true;
      }
    }
    if (!globAccepts(config.exclude, excluded, true)) {
      if (publishedRoot) {
        const info = lstat(physical);
        if (!info.isDirectory() || info.isSymbolicLink() || realpath(physical) !== physical) {
          throw error('ERR_FS_DIR_CHANGED', 'Directory changed before glob descent');
        }
      }
      yield* visit(physical, '', 0, included, excluded);
    }
  }
  function globSync(pattern, settings) {
    const config = globOptions(pattern, settings);
    config.collect = true;
    const output = [];
    for (const entry of globEntries(config)) {
      if (output.length >= MAX_ENTRIES) throw globLimit();
      output[output.length] = entry;
    }
    return output;
  }
  async function* glob(pattern, settings) {
    // No filesystem access until demand. AsyncGenerator owns serialized next,
    // return and throw; returning releases the suspended snapshot frames.
    yield* globEntries(globOptions(pattern, settings));
  }
  property(fs, 'Dir', Dir);
  property(fs, 'opendirSync', opendirSync);
  property(fs.promises, 'opendir', opendir);
  property(fs, 'globSync', globSync);
  property(fs.promises, 'glob', glob);
  return fs;
})
