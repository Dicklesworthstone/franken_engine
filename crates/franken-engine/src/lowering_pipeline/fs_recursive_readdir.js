(function installRecursiveReaddir(fs) {
  'use strict';
  // Collect the existing Dir snapshots; do not introduce another provider or
  // flatten the tree through one unbounded host operation. Callback readdir
  // captures this sync entry point in the outer callback installer.
  const shallow = fs.readdirSync;
  const shallowPromise = fs.promises.readdir;
  const open = fs.opendirSync;
  const read = fs.Dir.prototype.readSync;
  const close = fs.Dir.prototype.closeSync;
  const realpath = fs.realpathSync;
  const stat = fs.statSync;
  const apply = Reflect.apply;
  const define = Object.defineProperty;
  const create = Object.create;
  const P = Promise;
  const then = Promise.prototype.then;
  const Aggregate = AggregateError;
  const indexOf = String.prototype.indexOf;
  const slice = String.prototype.slice;
  // Match the existing directory admission ceilings, never raise them to
  // accommodate collection. Charge accumulated results AND traversal paths.
  const MAX_ENTRIES = 100000;
  const MAX_NAMES = 4 * 1024 * 1024;
  const MAX_DEPTH = 64;

  function error(code, message, Type) {
    const value = new (Type === undefined ? Error : Type)(message);
    value.code = code; return value;
  }
  function unsupported() {
    return error('ERR_FS_READDIR_UNSUPPORTED',
      'Recursive directory snapshots require UTF-8 string paths', TypeError);
  }
  function charge(state, units) {
    if (units > MAX_NAMES - state.units) {
      throw error('ERR_FS_DIR_LIMIT', 'Directory traversal resource limit exceeded');
    }
    state.units += units;
  }
  function checkPath(value) {
    if (typeof value !== 'string') throw unsupported();
    if (value.length === 0 || value.length > 4096 ||
        apply(indexOf, value, ['\0']) !== -1 || apply(indexOf, value, ['\\']) !== -1) {
      throw error('ERR_INVALID_ARG_VALUE', 'Invalid recursive directory path', TypeError);
    }
    return value;
  }
  function prepare(input, settings) {
    if (settings === undefined || settings === null || typeof settings === 'string') return undefined;
    if (typeof settings !== 'object') return undefined; // existing shallow validation
    const recursive = settings.recursive;
    if (recursive !== undefined && typeof recursive !== 'boolean') {
      throw error('ERR_INVALID_ARG_TYPE', 'options.recursive must be a boolean', TypeError);
    }
    if (recursive !== true) return undefined;
    const encoding = settings.encoding;
    const typed = !!settings.withFileTypes;
    if (encoding != null && encoding !== 'utf8' && encoding !== 'utf-8') throw unsupported();
    return { path: checkPath(input), typed: typed };
  }
  // POSIX join for one observed child name. Preserve the user's root spelling
  // for its own Dirents; normalize subsequent parent paths as Node does.
  function child(parent, name) {
    const text = parent + '/' + name;
    const parts = [];
    let start = 0;
    for (let i = 0; i <= text.length; i++) {
      if (i !== text.length && text[i] !== '/') continue;
      const part = apply(slice, text, [start, i]); start = i + 1;
      if (part === '' || part === '.') continue;
      if (part === '..' && parts.length !== 0 && parts[parts.length - 1] !== '..') parts.length--;
      else if (part !== '..' || text[0] !== '/') parts[parts.length] = part;
    }
    let out = text[0] === '/' ? '/' : '';
    for (let i = 0; i < parts.length; i++) {
      if (i !== 0) out += '/';
      out += parts[i];
    }
    return out || '.';
  }
  function property(object, key, value) {
    const descriptor = create(null);
    descriptor.value = value; descriptor.enumerable = true;
    descriptor.writable = true; descriptor.configurable = true;
    define(object, key, descriptor);
  }
  function collect(config, depthFirst) {
    const state = { units: 0, count: 0 };
    const output = [];
    let head = { path: config.path, physical: config.path, relative: '', depth: 0, ancestor: undefined, next: undefined };
    let tail = head;
    charge(state, config.path.length);
    while (head !== undefined) {
      const item = head; head = item.next;
      if (head === undefined) tail = undefined;
      item.next = undefined; // ancestry must not retain the pending queue
      if (item.depth > MAX_DEPTH) throw error('ERR_FS_DIR_LIMIT', 'Directory traversal depth exceeded');
      const physical = checkPath(realpath(item.physical));
      for (let ancestor = item.ancestor; ancestor !== undefined; ancestor = ancestor.parent) {
        if (ancestor.path === physical) {
          throw error('ERR_FS_DIR_CYCLE', 'Recursive directory symlink cycle');
        }
      }
      charge(state, physical.length);
      const ancestry = { path: physical, parent: item.ancestor };
      // Open the admitted physical directory; public parent paths remain
      // lexical. Dir closes even on a limit, provider error or bad entry.
      const directory = open(physical, { encoding: 'utf8', recursive: false });
      let failed = false, failure;
      try {
        for (;;) {
          const entry = apply(read, directory, []);
          if (entry === null) break;
          if (++state.count > MAX_ENTRIES) throw error('ERR_FS_DIR_LIMIT', 'Directory entry limit exceeded');
          // Dir validates names/types before exposing a record. Capture the
          // observed name once before assembling any future traversal request.
          const name = checkPath(entry.name);
          if (name === '.' || name === '..' || apply(indexOf, name, ['/']) !== -1) {
            throw error('ERR_INVALID_ARG_VALUE', 'Invalid recursive directory entry', TypeError);
          }
          const relative = item.relative === '' ? name : item.relative + '/' + name;
          const publicPath = child(item.path, name);
          const target = child(physical, name);
          charge(state, relative.length + publicPath.length + target.length + item.path.length);
          let descend = entry.isDirectory();
          if (!descend && !(depthFirst && config.typed) && entry.isSymbolicLink()) {
            // Node sync/callback and untyped Promise listings follow directory
            // links. The typed Promise form, like opendir, does not. Visit aliases independently; only an ancestor
            // link is a cycle. Broken/non-directory links stay in the result.
            try { descend = stat(target).isDirectory(); }
            catch (reason) {
              if (reason === null || typeof reason !== 'object' ||
                  (reason.code !== 'ENOENT' && reason.code !== 'ENOTDIR')) throw reason;
            }
          }
          if (config.typed) {
            property(entry, 'parentPath', item.path);
            property(entry, 'path', item.path);
          }
          output[output.length] = config.typed ? entry : relative;
          if (descend) {
            // Keep public spelling separate from the physical source so a
            // previously followed alias is not re-resolved at every level.
            const next = { path: publicPath, physical: target, relative: relative, depth: item.depth + 1,
              ancestor: ancestry, next: undefined };
            if (depthFirst) { next.next = head; head = next; if (tail === undefined) tail = next; }
            else { if (tail === undefined) head = next; else tail.next = next; tail = next; }
          }
        }
      } catch (reason) { failed = true; failure = reason; }
      try { apply(close, directory, []); }
      catch (reason) {
        if (failed) throw new Aggregate([failure, reason], 'Directory traversal and close both failed');
        throw reason;
      }
      if (failed) throw failure;
    }
    return output;
  }
  function readdirSync(input, settings) {
    const config = prepare(input, settings);
    return config === undefined ? apply(shallow, fs, arguments) : collect(config, false);
  }
  function readdir(input, settings) {
    // Snapshot supported settings before queued work. Validation throws become
    // Promise rejections; no partial collection can escape a failed traversal.
    return new P(function (resolve, reject) {
      const config = prepare(input, settings);
      if (config === undefined) { resolve(apply(shallowPromise, fs.promises, [input, settings])); return; }
      resolve(apply(then, new P(function (ready) { ready(); }), [function () {
        // Node's Promise API drains a LIFO directory worklist; sync/callback
        // variants drain FIFO. Neither sorts the host's observed entries.
        return collect(config, true);
      }]));
    });
  }
  property(fs, 'readdirSync', readdirSync);
  property(fs.promises, 'readdir', readdir);
  return fs;
})
