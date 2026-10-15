'use strict';
// Exact shipped filesystem/Dir/collector/callback JavaScript on Node primitives.
// The provider deliberately supports SHALLOW readdir only. These are not
// Rust, native-host, IFC, GC or product execution tests.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const { promisify } = require('node:util');
const base = path.join(__dirname, '../../crates/franken-engine/src/lowering_pipeline');
const source = name => fs.readFileSync(path.join(base, name), 'utf8');
const directoryInstaller = vm.runInThisContext(source('fs_directory.js'));
const callbackInstaller = vm.runInThisContext(source('fs_callbacks.js'));
const installer = process.env.FRANKEN_READDIR_BASELINE === '1' ? value => value :
  vm.runInThisContext(source('fs_recursive_readdir.js'));

function fixture(t, hooks = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-recursive-readdir-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const calls = [], lifetime = { opened: 0, closed: 0, active: 0, maximum: 0 };
  function host(tag, ...args) {
    const operation = tag.slice('\0fsop:'.length);
    calls.push({ operation, path: args[0] });
    if (hooks.effect) hooks.effect(operation, args);
    if (operation === 'readdir') {
      if (hooks.list) return hooks.list(args[0]);
      const options = args[1];
      return fs.readdirSync(args[0], typeof options === 'object' && options !== null ?
        { ...options, recursive: false } : options);
    }
    if (operation === 'realpath') return hooks.realpath ? hooks.realpath(args[0]) : fs.realpathSync(...args);
    if (operation === 'stat') return hooks.stat ? hooks.stat(args[0]) : fs.statSync(...args);
    if (operation === 'lstat') return fs.lstatSync(...args);
    throw new Error('Unexpected host effect ' + operation);
  }
  const raw = new Function('__franken_fs_read', '__franken_fs_write', 'require',
    'return ' + source('fs_module.js'))(host, () => { throw new Error('No write authority'); }, require);
  const module = directoryInstaller(raw);
  const originalOpen = module.opendirSync, originalRead = module.Dir.prototype.readSync;
  const originalClose = module.Dir.prototype.closeSync;
  module.opendirSync = function (...args) {
    const result = originalOpen(...args);
    lifetime.opened++; lifetime.active++; lifetime.maximum = Math.max(lifetime.maximum, lifetime.active);
    return result;
  };
  module.Dir.prototype.readSync = function () {
    if (hooks.read) hooks.read(this);
    return originalRead.call(this);
  };
  module.Dir.prototype.closeSync = function () {
    const result = originalClose.call(this);
    lifetime.closed++; lifetime.active--;
    if (hooks.close) hooks.close(this);
    return result;
  };
  installer(module);
  callbackInstaller(module);
  function write(name, contents = '') {
    const file = path.join(root, name); fs.mkdirSync(path.dirname(file), { recursive: true }); fs.writeFileSync(file, contents);
  }
  return { module, root, calls, lifetime, write };
}
function view(entries) {
  return entries.map(entry => typeof entry === 'string' ? entry : {
    name: entry.name, parentPath: entry.parentPath, path: entry.path,
    file: entry.isFile(), directory: entry.isDirectory(), symlink: entry.isSymbolicLink()
  });
}
function tree(f) {
  f.write('a/deep/alpha.json', '{}'); f.write('a/é.txt', 'é');
  f.write('b/deep/beta.json', '{}'); f.write('top.js', 'top');
  f.write('.hidden/config.json', '{}'); fs.mkdirSync(f.root + '/empty');
}
function dirent(name, directory = false) {
  return { name, isDirectory: () => directory, isSymbolicLink: () => false, isFile: () => !directory };
}

for (const typed of [false, true]) {
  test('sync matches live Node ordered recursive output, typed=' + typed, t => {
    const f = fixture(t); tree(f);
    const options = { recursive: true, withFileTypes: typed };
    assert.deepEqual(view(f.module.readdirSync(f.root, options)), view(fs.readdirSync(f.root, options)));
    assert.equal(f.calls.filter(x => x.operation === 'readdir').length, 7);
    assert.equal(f.lifetime.active, 0); assert.equal(f.lifetime.maximum, 1);
  });
  test('Promise matches live Node LIFO discovery, typed=' + typed, async t => {
    const f = fixture(t); tree(f);
    const options = { recursive: true, withFileTypes: typed };
    const pending = f.module.promises.readdir(f.root, options);
    assert.equal(f.calls.length, 0, 'deferred recursive provider effects');
    assert.deepEqual(view(await pending), view(await fs.promises.readdir(f.root, options)));
    assert.equal(f.lifetime.active, 0);
  });
  test('callback and promisify use FIFO collector, typed=' + typed, async t => {
    const f = fixture(t); tree(f);
    const options = { recursive: true, withFileTypes: typed };
    let synchronous = true, completions = 0;
    const pending = new Promise((resolve, reject) => f.module.readdir(f.root, options, (error, entries) => {
      completions++; assert.equal(synchronous, false); if (error) reject(error); else resolve(entries);
    }));
    synchronous = false;
    assert.deepEqual(view(await pending), view(fs.readdirSync(f.root, options)));
    assert.deepEqual(view(await promisify(f.module.readdir)(f.root, options)), view(fs.readdirSync(f.root, options)));
    assert.equal(completions, 1); assert.equal(f.lifetime.active, 0);
  });
  test('directory aliases, broken links and file links match Node, typed=' + typed, async t => {
    const f = fixture(t); tree(f);
    fs.symlinkSync('a', f.root + '/alias'); fs.symlinkSync('none', f.root + '/broken');
    fs.symlinkSync('top.js', f.root + '/filelink');
    const options = { recursive: true, withFileTypes: typed };
    assert.deepEqual(view(f.module.readdirSync(f.root, options)), view(fs.readdirSync(f.root, options)));
    assert.deepEqual(view(await f.module.promises.readdir(f.root, options)), view(await fs.promises.readdir(f.root, options)));
    assert.equal(f.lifetime.active, 0);
  });
}

test('relative and redundant root spellings preserve correct public parent paths', t => {
  const f = fixture(t); tree(f);
  const relative = path.relative(process.cwd(), f.root);
  for (const input of [relative, './' + relative + '//', f.root + '/a/../', f.root + '/']) {
    const options = { recursive: true, withFileTypes: true };
    assert.deepEqual(view(f.module.readdirSync(input, options)), view(fs.readdirSync(input, options)), input);
  }
});

test('shallow APIs retain original encodings and one-directory effects', async t => {
  const f = fixture(t); tree(f);
  for (const options of [undefined, null, 'utf8', 'buffer', { recursive: false }, { withFileTypes: true }]) {
    assert.deepEqual(f.module.readdirSync(f.root, options), fs.readdirSync(f.root, options));
    assert.deepEqual(await f.module.promises.readdir(f.root, options), await fs.promises.readdir(f.root, options));
  }
  assert.equal(f.lifetime.opened, 0, 'no recursive cursor for shallow requests');
});

test('recursive options are captured once before queued Promise work', async t => {
  const f = fixture(t); tree(f); let gets = [];
  const options = Object.defineProperties({}, {
    recursive: { get() { gets.push('recursive'); return true; } },
    encoding: { get() { gets.push('encoding'); return 'utf8'; } },
    withFileTypes: { get() { gets.push('typed'); return false; } }
  });
  const pending = f.module.promises.readdir(f.root, options);
  assert.deepEqual(gets, ['recursive', 'encoding', 'typed']);
  assert.deepEqual(await pending, await fs.promises.readdir(f.root, { recursive: true }));
  assert.deepEqual(gets, ['recursive', 'encoding', 'typed']);
});

test('unsupported recursive encodings and paths refuse before provider access', async t => {
  const f = fixture(t);
  for (const encoding of ['buffer', 'hex', 'latin1']) {
    assert.throws(() => f.module.readdirSync(f.root, { recursive: true, encoding }), { code: 'ERR_FS_READDIR_UNSUPPORTED' });
    await assert.rejects(f.module.promises.readdir(f.root, { recursive: true, encoding }), { code: 'ERR_FS_READDIR_UNSUPPORTED' });
  }
  assert.throws(() => f.module.readdirSync(Buffer.from(f.root), { recursive: true }), { code: 'ERR_FS_READDIR_UNSUPPORTED' });
  assert.equal(f.calls.length, 0);
});

test('invalid recursive booleans and callbacks perform no filesystem work', async t => {
  const f = fixture(t);
  for (const recursive of ['yes', 1, null]) {
    assert.throws(() => f.module.readdirSync(f.root, { recursive }), { code: 'ERR_INVALID_ARG_TYPE' });
    await assert.rejects(f.module.promises.readdir(f.root, { recursive }), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  assert.throws(() => f.module.readdir(f.root, { recursive: true }, null), { code: 'ERR_INVALID_ARG_TYPE' });
  assert.equal(f.calls.length, 0);
});

test('ancestor cycles reject explicitly; no partial callback or Promise result escapes', async t => {
  const f = fixture(t); f.write('a/kept'); fs.symlinkSync('..', f.root + '/a/loop');
  assert.throws(() => f.module.readdirSync(f.root, { recursive: true }), { code: 'ERR_FS_DIR_CYCLE' });
  await assert.rejects(f.module.promises.readdir(f.root, { recursive: true }), { code: 'ERR_FS_DIR_CYCLE' });
  let count = 0;
  await new Promise(resolve => f.module.readdir(f.root, { recursive: true }, (error, result) => {
    count++; assert.equal(error.code, 'ERR_FS_DIR_CYCLE'); assert.equal(result, undefined); resolve();
  }));
  assert.equal(count, 1); assert.equal(f.lifetime.active, 0);
});

test('provider refusal in an admitted child propagates without skipping it', async t => {
  const failure = Object.assign(new Error('denied'), { code: 'EACCES' });
  const f = fixture(t, { effect(operation, args) { if (operation === 'readdir' && args[0].endsWith('/b')) throw failure; } }); tree(f);
  assert.throws(() => f.module.readdirSync(f.root, { recursive: true }), error => error === failure);
  await assert.rejects(f.module.promises.readdir(f.root, { recursive: true }), error => error === failure);
  assert.equal(f.lifetime.active, 0);
});

test('symlink authority refusal is not swallowed as a broken link', t => {
  const denied = Object.assign(new Error('outside permitted root'), { code: 'EACCES' });
  const f = fixture(t, { stat() { throw denied; } }); f.write('data'); fs.symlinkSync('data', f.root + '/link');
  assert.throws(() => f.module.readdirSync(f.root, { recursive: true }), error => error === denied);
  assert.equal(f.lifetime.closed, f.lifetime.opened);
});

for (const failure of [undefined, null, false, 0]) {
  test('cursor cleanup preserves a falsy thrown value: ' + String(failure), async t => {
    const f = fixture(t, { read() { throw failure; } }); f.write('a');
    let caught = false;
    try { f.module.readdirSync(f.root, { recursive: true }); }
    catch (error) { caught = true; assert.equal(error, failure); }
    assert.equal(caught, true); assert.equal(f.lifetime.active, 0);
    await assert.rejects(f.module.promises.readdir(f.root, { recursive: true }), error => error === failure);
    assert.equal(f.lifetime.active, 0);
  });
}

test('read and close failures are retained together', t => {
  const closeError = new Error('close failure');
  const f = fixture(t, { read() { throw false; }, close() { throw closeError; } }); f.write('a');
  assert.throws(() => f.module.readdirSync(f.root, { recursive: true }), error =>
    error instanceof AggregateError && error.errors[0] === false && error.errors[1] === closeError);
  assert.equal(f.lifetime.active, 0);
});

test('depth ceiling refuses before opening a directory beyond the limit', t => {
  const f = fixture(t, { realpath: value => value,
    list: value => value.split('/').length < 72 ? [dirent('d', true)] : [] });
  assert.throws(() => f.module.readdirSync('/r', { recursive: true }), { code: 'ERR_FS_DIR_LIMIT' });
  assert.equal(f.calls.filter(x => x.operation === 'readdir').length, 65);
  assert.equal(f.lifetime.active, 0); assert.equal(f.lifetime.maximum, 1);
});

test('name accounting bounds the complete result, not merely each snapshot', t => {
  const f = fixture(t, { realpath: value => value,
    list: () => Array.from({ length: 6000 }, (_, i) => dirent(String(i) + 'x'.repeat(246))) });
  assert.throws(() => f.module.readdirSync('/r', { recursive: true }), { code: 'ERR_FS_DIR_LIMIT' });
  assert.equal(f.lifetime.opened, 1); assert.equal(f.lifetime.active, 0);
});

test('entry accounting is shared across directories', t => {
  const f = fixture(t, { realpath: value => value,
    list: value => value === '/r' ? Array.from({ length: 250 }, (_, i) => dirent(String(i), true)) :
      Array.from({ length: 400 }, (_, i) => dirent(String(i))) });
  assert.throws(() => f.module.readdirSync('/r', { recursive: true }), { code: 'ERR_FS_DIR_LIMIT' });
  assert.equal(f.lifetime.active, 0); assert.equal(f.lifetime.opened, 251);
});

test('capture of Dir methods and facade exports prevents replacement during a scan', t => {
  const f = fixture(t); tree(f);
  f.module.opendirSync = f.module.Dir.prototype.readSync = f.module.Dir.prototype.closeSync =
    f.module.statSync = f.module.realpathSync = () => { throw new Error('public replacement'); };
  assert.deepEqual(f.module.readdirSync(f.root, { recursive: true }), fs.readdirSync(f.root, { recursive: true }));
  assert.equal(f.lifetime.active, 0);
});

test('existing Dir and glob operations retain their behavior after installation', async t => {
  const f = fixture(t); tree(f);
  const before = fs.readdirSync(f.root).sort();
  const directory = f.module.opendirSync(f.root); const observed = [];
  for await (const entry of directory) observed.push(entry.name);
  assert.deepEqual(observed.sort(), before);
  assert.deepEqual(f.module.globSync('**/*.json', { cwd: f.root }).sort(), ['a/deep/alpha.json', 'b/deep/beta.json']);
});

test('wide listing uses one snapshot per directory and one active cursor', async t => {
  const f = fixture(t);
  for (let i = 0; i < 128; i++) for (let j = 0; j < 8; j++) f.write('p' + i + '/f' + j);
  const observed = await f.module.promises.readdir(f.root, { recursive: true });
  assert.deepEqual(observed, await fs.promises.readdir(f.root, { recursive: true }));
  assert.equal(observed.length, 1152); assert.equal(f.lifetime.opened, 129);
  assert.equal(f.lifetime.maximum, 1); assert.equal(f.lifetime.active, 0);
});
