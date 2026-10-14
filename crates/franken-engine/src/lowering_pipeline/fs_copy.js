(function installFilesystemCopy(fs) {
  'use strict';
  // Composite operations on the existing fs object, not a second provider.
  // Every metadata/read/write/link effect still crosses its native capability,
  // containment, transcript, cancellation and byte-budget boundary. Construction
  // performs no I/O. The promise driver awaits filters; I/O itself remains the
  // engine's current synchronous host operation, not a new off-thread backend.
  const lstat = fs.lstatSync;
  const stat = fs.statSync;
  const realpath = fs.realpathSync;
  const readdir = fs.readdirSync;
  const mkdir = fs.mkdirSync;
  const open = fs.openSync;
  const closeFd = fs.closeSync;
  const read = fs.readSync;
  const write = fs.writeSync;
  const allocate = Buffer.alloc;
  const NativeAggregateError = AggregateError;
  const unlink = fs.unlinkSync;
  const readlink = fs.readlinkSync;
  const symlink = fs.symlinkSync;
  const chmod = fs.chmodSync;
  const apply = Reflect.apply;
  const split = String.prototype.split;
  const slice = String.prototype.slice;
  const lastIndexOf = String.prototype.lastIndexOf;
  const startsWith = String.prototype.startsWith;
  const arrayIsArray = Array.isArray;
  const ownKeys = Object.keys;
  const create = Object.create;
  const generator = (function* () {})();
  const next = generator.next;
  const close = generator.return;
  const MAX_ENTRIES = 50000;
  const MAX_DEPTH = 64;
  const MAX_PATH = 4096;
  const MAX_NAMES = 8 * 1024 * 1024;

  function error(code, message, source, destination) {
    const failure = new Error(message);
    failure.code = code;
    failure.syscall = 'cp';
    if (source !== undefined) failure.path = source;
    if (destination !== undefined) failure.dest = destination;
    return failure;
  }
  function invalid(name) {
    const failure = new TypeError('Invalid ' + name + ' argument');
    failure.code = 'ERR_INVALID_ARG_TYPE';
    return failure;
  }
  function limit() { return error('ERR_FS_CP_LIMIT', 'Filesystem copy exceeds its traversal or path limit'); }
  function path(value, name) {
    // The native path authority is project-contained and slash-separated.
    // URL and Windows-path conversion require a separate native path contract;
    // do not coerce arbitrary objects or silently reinterpret a backslash.
    if (typeof value !== 'string') throw invalid(name + ' (expected a path string)');
    if (value.length === 0 || value.length > MAX_PATH) throw limit();
    for (let i = 0; i < value.length; i++) {
      if (value[i] === '\0' || value[i] === '\\' || value[i] === ':') {
        throw error('ERR_FS_CP_INVALID', 'Unsupported copy path spelling', value);
      }
    }
    return value;
  }
  function optionsFor(options) {
    if (options === undefined) options = {};
    if (options === null || typeof options !== 'object' || arrayIsArray(options)) throw invalid('options');
    // Unknown options must not quietly disable a requested safety property.
    const keys = ownKeys(options);
    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];
      if (key !== 'recursive' && key !== 'force' && key !== 'errorOnExist' &&
          key !== 'dereference' && key !== 'verbatimSymlinks' && key !== 'filter' &&
          key !== 'preserveTimestamps' && key !== 'mode') {
        throw error('ERR_FS_CP_UNSUPPORTED', 'Unsupported copy option: ' + key);
      }
    }
    const config = create(null);
    const booleans = apply(split, 'recursive force errorOnExist dereference verbatimSymlinks preserveTimestamps', [' ']);
    for (let i = 0; i < booleans.length; i++) {
      const key = booleans[i];
      const value = options[key];
      if (value !== undefined && typeof value !== 'boolean') throw invalid('options.' + key);
      config[key] = value === undefined ? key === 'force' : value;
    }
    config.filter = options.filter;
    if (config.filter !== undefined && typeof config.filter !== 'function') throw invalid('options.filter');
    const mode = options.mode;
    if (mode !== undefined && (typeof mode !== 'number' || mode % 1 !== 0 || mode < 0 || mode > 7)) {
      throw invalid('options.mode');
    }
    // FsMetadata has mtime but no atime; the descriptor opener has neither
    // exclusive creation nor reflinks. Refuse those requests before any effect.
    // Do not pretend to preserve metadata or silently weaken COPYFILE_EXCL.
    if (config.preserveTimestamps || (mode !== undefined && mode !== 0)) {
      throw error('ERR_FS_CP_UNSUPPORTED', 'Timestamp preservation and nonzero copy modes require native support');
    }
    return config;
  }
  function parent(value) {
    const index = apply(lastIndexOf, value, ['/']);
    return index <= 0 ? (value[0] === '/' ? '/' : '.') : apply(slice, value, [0, index]);
  }
  function leaf(value) { return apply(slice, value, [apply(lastIndexOf, value, ['/']) + 1]); }
  function child(directory, name) {
    const value = directory === '/' ? '/' + name : directory + '/' + name;
    if (value.length > MAX_PATH) throw limit();
    return value;
  }
  function absolute(base, value) {
    let result = value[0] === '/' ? '' : base;
    const parts = apply(split, value, ['/']);
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      if (part === '' || part === '.') continue;
      if (part === '..') result = result === '/' ? '' : parent(result);
      else result = (result === '/' ? '' : result) + '/' + part;
    }
    return path(result || '/', 'resolved path');
  }
  function contained(root, candidate) {
    return candidate === root || apply(startsWith, candidate, [root === '/' ? '/' : root + '/']);
  }
  function inspect(value) {
    try { return lstat(value); }
    catch (failure) { if (failure && failure.code === 'ENOENT') return undefined; throw failure; }
  }
  function futureLocation(value) {
    // Canonicalize the nearest existing parent, retaining not-yet-created
    // components. This catches output nested through an existing symlink.
    let probe = parent(value);
    let suffix = leaf(value);
    for (let depth = 0; depth <= MAX_DEPTH; depth++) {
      const entry = inspect(probe);
      if (entry !== undefined) return absolute(realpath(probe), suffix);
      if (probe === '/') break;
      suffix = child(leaf(probe), suffix);
      probe = parent(probe);
    }
    throw limit();
  }
  function metadata(source, config) { return config.dereference ? stat(source) : lstat(source); }
  function kind(info) {
    if (info.isDirectory()) return 'directory';
    if (info.isFile()) return 'file';
    if (info.isSymbolicLink()) return 'link';
    return 'unsupported';
  }
  function sourceLocation(source, type) {
    return type === 'link' ? absolute(realpath(parent(source)), leaf(source)) : realpath(source);
  }
  function validatePair(source, destination, info, target, type) {
    const origin = sourceLocation(source, type);
    const output = futureLocation(destination);
    if (origin === output || (type === 'directory' && contained(origin, output))) {
      throw error('ERR_FS_CP_EINVAL', 'Source and destination overlap', source, destination);
    }
    if (target !== undefined) {
      if (type === 'directory' && !target.isDirectory()) {
        throw error('ERR_FS_CP_DIR_TO_NON_DIR', 'Cannot copy a directory onto a non-directory', source, destination);
      }
      if (type !== 'directory' && target.isDirectory()) {
        throw error('ERR_FS_CP_NON_DIR_TO_DIR', 'Cannot copy a non-directory onto a directory', source, destination);
      }
      // Hosts exposing exact identities can reject hard-link self-copies too.
      // The native metadata subset currently does not. Existing leaves are
      // unlinked before writing, so they cannot truncate the source
      // through an unreported hard-link alias. That is not inode equivalence.
      if (info.ino !== undefined && info.ino !== 0 && info.dev !== undefined &&
          info.ino === target.ino && info.dev === target.dev) {
        throw error('ERR_FS_CP_EINVAL', 'Source and destination are the same file', source, destination);
      }
    }
    return origin;
  }
  function count(value, maximum, writing) {
    if (typeof value !== 'number' || value % 1 !== 0 || value < 0 ||
        value > maximum || (writing && value === 0)) {
      throw error('EIO', 'Invalid byte count from filesystem provider');
    }
    return value;
  }
  function copyRegularFile(source, destination) {
    // A fixed-size buffer, not readFile + writeFile or the host's unbounded
    // copy syscall. Positive short reads/writes continue; only read EOF ends
    // the transfer. Every chunk is another controlled and transcripted effect.
    const bytes = allocate(16384);
    let input;
    let output;
    let failed = false;
    let failure;
    function remember(reason) {
      failure = failed ? new NativeAggregateError([failure, reason], 'Copy and descriptor cleanup failed') : reason;
      failed = true;
    }
    try {
      input = open(source, 'r');
      output = open(destination, 'w');
      for (;;) {
        const length = count(read(input, bytes, 0, bytes.length, null), bytes.length, false);
        if (length === 0) break;
        let offset = 0;
        while (offset < length) offset += count(write(output, bytes, offset, length - offset, null), length - offset, true);
      }
    } catch (reason) { remember(reason); }
    // Each descriptor is closed exactly once, even when the other close fails.
    // Do not mistake a falsy thrown value for a completed successful copy.
    if (output !== undefined) { try { closeFd(output); } catch (reason) { remember(reason); } }
    if (input !== undefined) { try { closeFd(input); } catch (reason) { remember(reason); } }
    if (failed) throw failure;
  }
  function* traversal(source, destination, config) {
    const base = realpath('.');
    const sourcePath = absolute(base, source);
    const destinationPath = absolute(base, destination);
    let entries = 0;
    let names = 0;
    function* visit(src, dst, sourceName, destinationName, ancestor, depth) {
      if (depth > MAX_DEPTH || ++entries > MAX_ENTRIES) throw limit();
      names += src.length + dst.length;
      if (names > MAX_NAMES) throw limit();
      // Never retain metadata across a user callback/await. A filter may
      // reenter the copier or change either filesystem tree before accepting.
      if (!(yield { source: sourceName, destination: destinationName })) return;
      const info = metadata(src, config);
      const target = inspect(dst);
      const type = kind(info);
      const origin = validatePair(src, dst, info, target, type);
      if (type === 'directory') {
        if (!config.recursive) throw error('ERR_FS_EISDIR', 'Recursive option is required for a directory', sourceName, destinationName);
        for (let seen = ancestor; seen !== undefined; seen = seen.parent) {
          if (seen.path === origin) throw error('ERR_FS_CP_ELOOP', 'Dereferenced directory cycle', sourceName, destinationName);
        }
        const children = readdir(src);
        if (!arrayIsArray(children) || children.length > MAX_ENTRIES - entries) throw limit();
        // Validate the entire returned directory list before creating output.
        for (let i = 0; i < children.length; i++) {
          const name = path(children[i], 'directory entry');
          if (name === '.' || name === '..' || apply(lastIndexOf, name, ['/']) !== -1) {
            throw error('ERR_FS_CP_INVALID', 'Filesystem returned a non-child directory entry');
          }
        }
        const created = target === undefined;
        if (created) mkdir(dst, { recursive: true, mode: (info.mode & 511) | 448 });
        const current = { path: origin, parent: ancestor };
        for (let i = 0; i < children.length; i++) {
          const name = children[i];
          yield* visit(child(src, name), child(dst, name), child(sourceName, name), child(destinationName, name), current, depth + 1);
        }
        if (created) chmod(dst, info.mode & 511);
        return;
      }
      if (type !== 'file' && type !== 'link') {
        throw error('ERR_FS_CP_UNKNOWN', 'Only regular files, directories and symlinks can be copied', sourceName, destinationName);
      }
      if (target !== undefined && !config.force) {
        if (config.errorOnExist) throw error('ERR_FS_CP_EEXIST', 'Destination already exists', sourceName, destinationName);
        return;
      }
      let link;
      if (type === 'link') {
        link = readlink(src);
        if (!config.verbatimSymlinks) link = absolute(realpath(parent(src)), path(link, 'symlink target'));
      }
      mkdir(parent(dst), { recursive: true });
      // Do not truncate an observed existing leaf through a hard-link alias.
      // This sequence is not atomic against concurrent replacement; the host
      // still enforces containment on each effect. Earlier copies are not
      // rolled back after a later failure. There is no snapshot claim.
      if (target !== undefined) unlink(dst);
      if (type === 'link') symlink(link, dst);
      else { copyRegularFile(origin, dst); chmod(dst, info.mode & 511); }
    }
    yield* visit(sourcePath, destinationPath, source, destination, undefined, 0);
  }
  function cpSync(source, destination, options) {
    path(source, 'src'); path(destination, 'dest');
    const config = optionsFor(options);
    const plan = traversal(source, destination, config);
    let finished = false;
    try {
      let step = apply(next, plan, []);
      while (!step.done) {
        let accepted = true;
        if (config.filter !== undefined) accepted = apply(config.filter, undefined, [step.value.source, step.value.destination]);
        if (accepted !== null && (typeof accepted === 'object' || typeof accepted === 'function') && typeof accepted.then === 'function') {
          throw error('ERR_INVALID_RETURN_VALUE', 'A synchronous copy filter cannot return a promise');
        }
        step = apply(next, plan, [!!accepted]);
      }
      finished = true;
    } finally { if (!finished) apply(close, plan, []); }
  }
  async function cp(source, destination, options) {
    path(source, 'src'); path(destination, 'dest');
    const config = optionsFor(options);
    const plan = traversal(source, destination, config);
    let finished = false;
    try {
      let step = apply(next, plan, []);
      while (!step.done) {
        const accepted = config.filter === undefined ? true :
          await apply(config.filter, undefined, [step.value.source, step.value.destination]);
        step = apply(next, plan, [!!accepted]);
      }
      finished = true;
    } finally { if (!finished) apply(close, plan, []); }
  }
  fs.cpSync = cpSync;
  fs.promises.cp = cp;
  return fs;
})
