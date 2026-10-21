'use strict';
// Execute the shipped directory/glob factory on Node primitives, NOT Rust.
// The Node oracle remains untouched. Compare path sets, not traversal order.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/fs_directory.js'), 'utf8');
const install = vm.runInThisContext(source, { filename: 'fs_directory.js' });
function factory(overrides = {}) {
  const calls = [];
  const base = { promises: {} };
  for (const name of ['readdirSync', 'lstatSync', 'realpathSync']) {
    base[name] = (...args) => {
      calls.push([name, ...args]);
      return (overrides[name] || fs[name])(...args);
    };
  }
  return { io: install(base), calls };
}
function fixture(t) {
  // Use the physical fixture root on hosts whose temporary directory is a
  // symlink (for example /var -> /private/var on macOS). Retain fixtures for
  // failure inspection; this test must not delete files.
  const root = fs.realpathSync(fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'franken-glob-')));
  for (const name of [
    'app.js', 'app.ts', '.hidden.js', 'file1.txt', 'file2.txt', 'file9.txt',
    'src/a.js', 'src/b.ts', 'src/deep/c.js', 'src/.secret.js',
    'dist/x.js', 'node_modules/pkg/index.js', '.config/setup.js',
    'packages/a/package.json', 'packages/b/package.json', 'packages/a/src/main.ts',
    'unicode/é.js', 'unicode/😀.js', 'literal/[data].js', 'literal/brace{x}.js',
  ]) {
    fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    fs.writeFileSync(path.join(root, name), name);
  }
  return root;
}
async function collect(iterable) { const output = []; for await (const entry of iterable) output.push(entry); return output; }
function rows(entries, root) {
  return entries.map(entry => typeof entry === 'string' ? entry :
    [path.relative(root, path.join(entry.parentPath, entry.name)) || '.',
      entry.isDirectory(), entry.isFile(), entry.isSymbolicLink()]).sort();
}
const patterns = [
  '*', '**', '**/*.js', 'src/**', 'src/', 'src/*/', 'src/*', 'src/??.js',
  '{src,dist}/**/*.{js,ts}', 'packages/*/package.json', '**/package.json',
  ['**/*.js', 'src/**', 'src/a.js', '**/*.js'],
  'file[1-2].txt', 'file[!1-2].txt', 'file?.txt', 'file*.txt',
  '.*', '.config/*', '**/.*', '[.]hidden.js', './src/./a.js',
  'missing/**/*.js', ['src/*.js', 'dist/*.js'], [], '', '.',
  'unicode/?.js', 'unicode/??.js', 'literal/[[]data].js', 'literal/brace{x}.js',
  '{app,src/{a,b}}.{js,ts}', '{,src/}*.js', '**/**/**/*.json', 'src/*/.',
  'src/*.@(js|ts)', '@(src|dist)/**', 'file+([1-2]).txt', '@(app|file)?(1).@(js|txt)',
];
for (const [index, pattern] of patterns.entries()) {
  test(`reference and production glob agree on supported pattern ${index}: ${JSON.stringify(pattern)}`, async t => {
    const root = fixture(t);
    const { io } = factory();
    const expected = fs.globSync(pattern, { cwd: root }).sort();
    assert.deepEqual(io.globSync(pattern, { cwd: root }).sort(), expected);
    assert.deepEqual((await collect(io.promises.glob(pattern, { cwd: root }))).sort(), expected);
    assert.deepEqual((await collect(fs.promises.glob(pattern, { cwd: root }))).sort(), expected);
  });
}
for (const exclude of [['node_modules/**', 'dist/**'], ['src'], ['**/*.js'], ['src/*'], ['**'], ['**/'], ['.'], ['./'], []]) {
  test(`exclusions agree and prune: ${JSON.stringify(exclude)}`, async t => {
    const root = fixture(t), { io, calls } = factory();
    const options = { cwd: root, exclude };
    const expected = fs.globSync('**', options).sort();
    assert.deepEqual(io.globSync('**', options).sort(), expected);
    assert.deepEqual((await collect(io.promises.glob('**', options))).sort(), expected);
    if (exclude.includes('node_modules/**')) {
      assert(!calls.some(call => call[0] === 'readdirSync' && call[1].startsWith(root + '/node_modules')));
    }
  });
}
for (const pattern of ['**/*.js', 'packages/*', '**', 'src/*/']) {
  test(`typed entries retain physical parents and actual types: ${pattern}`, async t => {
    const root = fixture(t), { io } = factory();
    const options = { cwd: root, withFileTypes: true };
    assert.deepEqual(rows(io.globSync(pattern, options), root), rows(fs.globSync(pattern, options), root));
    assert.deepEqual(rows(await collect(io.promises.glob(pattern, options)), root), rows(fs.globSync(pattern, options), root));
  });
}
test('static prefixes do not open unrelated package or output trees', t => {
  const root = fixture(t), { io, calls } = factory();
  assert.deepEqual(io.globSync('src/*.js', { cwd: root }), ['src/a.js']);
  assert.deepEqual(calls.filter(c => c[0] === 'readdirSync').map(c => c[1]), [root, root + '/src']);
});
test('lazy async iterator has no filesystem effects before demand or after return', async t => {
  const root = fixture(t), { io, calls } = factory();
  const never = io.promises.glob('**/*.js', { cwd: root });
  assert.equal(calls.length, 0);
  await never.return();
  assert.equal(calls.length, 0);
  const iterator = io.promises.glob('**/*.js', { cwd: root });
  assert.equal((await iterator.next()).value, 'app.js');
  const atYield = calls.length;
  await iterator.return();
  assert.deepEqual(await iterator.next(), { done: true, value: undefined });
  assert.equal(calls.length, atYield);
});
test('overlapping pattern alternatives yield each path once without retaining a seen-path set', async t => {
  const root = fixture(t), { io } = factory();
  const result = await collect(io.promises.glob(['src/**', '**/*.js', 'src/a.js', 'src/**'], { cwd: root }));
  assert.equal(result.filter(x => x === 'src/a.js').length, 1);
  assert.equal(result.length, new Set(result).size);
});
test('patterns, exclusions and options are captured before the first published match', async t => {
  const root = fixture(t), { io } = factory();
  const patterns = ['src/**'], exclude = ['src/deep/**'];
  const options = { cwd: root, exclude };
  const iterator = io.promises.glob(patterns, options);
  const first = await iterator.next();
  patterns[0] = '**'; exclude[0] = '**'; options.cwd = '/not-used'; options.withFileTypes = true;
  assert.deepEqual([first.value, ...await collect(iterator)].sort(), ['src', 'src/a.js', 'src/b.ts']);
});
test('returned Dirent mutations cannot redirect or suppress traversal', async t => {
  const root = fixture(t), { io } = factory();
  const iterator = io.promises.glob('src/**', { cwd: root, withFileTypes: true });
  const first = (await iterator.next()).value;
  assert.equal(first.name, 'src');
  first.name = '../node_modules'; first.parentPath = '/outside'; first.isDirectory = () => false;
  const rest = rows(await collect(iterator), root);
  assert(rest.some(row => row[0] === 'src/deep/c.js'));
  assert(!rest.some(row => row[0].includes('node_modules')));
});
test('directory-to-symlink replacement after a yield never acquires the target', async t => {
  const root = fixture(t), { io, calls } = factory();
  const iterator = io.promises.glob('src/**', { cwd: root });
  assert.equal((await iterator.next()).value, 'src');
  fs.renameSync(root + '/src', root + '/retained');
  fs.symlinkSync('node_modules', root + '/src');
  await assert.rejects(iterator.next(), { code: 'ERR_FS_DIR_CHANGED' });
  assert.deepEqual(await iterator.next(), { value: undefined, done: true });
  assert.equal(calls.filter(call => call[0] === 'readdirSync').length, 1);
});
test('symlinks are leaf matches and not traversed by globstar', async t => {
  const root = fixture(t), { io, calls } = factory();
  fs.symlinkSync('src', root + '/alias');
  const expected = fs.globSync('**/*.js', { cwd: root }).sort();
  assert.deepEqual(io.globSync('**/*.js', { cwd: root }).sort(), expected);
  assert(io.globSync('*', { cwd: root }).includes('alias'));
  assert(!calls.some(call => call[0] === 'readdirSync' && call[1] === root + '/alias'));
});
test('a published cwd match is rechecked before its first directory read', async t => {
  const root = fixture(t), { io, calls } = factory();
  const iterator = io.promises.glob('**', { cwd: root + '/src' });
  assert.equal((await iterator.next()).value, '.');
  fs.renameSync(root + '/src', root + '/retained');
  fs.symlinkSync('node_modules', root + '/src');
  await assert.rejects(iterator.next(), { code: 'ERR_FS_DIR_CHANGED' });
  assert.equal(calls.filter(call => call[0] === 'readdirSync').length, 0);
});
test('glob and Dir keep separate traversal ownership in the same filesystem module', async t => {
  const root = fixture(t), { io } = factory();
  const dir = io.opendirSync(root + '/src', { recursive: true });
  const original = dir.readSync();
  assert(original);
  const matches = io.globSync('src/**/*.js', { cwd: root });
  assert.deepEqual(matches.sort(), ['src/a.js', 'src/deep/c.js']);
  const remaining = await collect(dir);
  assert(remaining.length > 0);
  assert.throws(() => dir.readSync(), { code: 'ERR_DIR_CLOSED' });
  assert.deepEqual(io.globSync('src/*.js', { cwd: root }), ['src/a.js']);
});
test('no-match is distinct from capability, permission, and provider refusal', async t => {
  const root = fixture(t), { io } = factory();
  for (const cwd of [root + '/missing', root + '/app.js']) assert.deepEqual(io.globSync('**/*.js', { cwd }), []);
  for (const code of ['EACCES', 'EPERM', 'ERR_CAPABILITY_MISSING']) {
    const refusal = Object.assign(Error('refused'), { code });
    const denied = factory({ readdirSync() { throw refusal; } }).io;
    assert.throws(() => denied.globSync('**/*.js', { cwd: root }), e => e === refusal);
    await assert.rejects(collect(denied.promises.glob('**/*.js', { cwd: root })), e => e === refusal);
  }
});
test('invalid and unsupported query contracts refuse before filesystem access', async () => {
  const { io, calls } = factory();
  for (const p of [null, 4, ['ok', null], '/absolute/*', '../*', '!*.js', '!(a|b)', '{1..5}', 'a\0b', 'a\\b']) {
    assert.throws(() => io.globSync(p));
    await assert.rejects(collect(io.promises.glob(p)));
  }
  for (const options of [null, [], {cwd:{}}, {exclude:'dist'}, {exclude:{}}, {withFileTypes:1}, {followSymlinks:true}, {maxDepth:2}]) {
    assert.throws(() => io.globSync('*', options));
  }
  assert.equal(calls.length, 0);
});
test('pattern-array expansion and matching work are independently bounded', () => {
  const { io, calls } = factory();
  assert.throws(() => io.globSync(Array(129).fill('*')), { code: 'ERR_FS_GLOB_LIMIT' });
  assert.throws(() => io.globSync('{a,b}'.repeat(8)), { code: 'ERR_FS_GLOB_LIMIT' });
  assert.equal(calls.length, 0);
  const wide = factory({ realpathSync: x => x, readdirSync: () =>
    Array.from({ length: 10 }, (_, i) => ({name: 'a'.repeat(1000) + i, isDirectory:()=>false, isSymbolicLink:()=>false})) }).io;
  assert.throws(() => wide.globSync('*a'.repeat(500), { cwd: '/safe' }), { code: 'ERR_FS_GLOB_LIMIT' });
});
test('shared snapshot depth and entry bounds still apply to glob traversal', async () => {
  const deep = factory({ realpathSync: x => x, lstatSync: () => ({isDirectory:()=>true,isSymbolicLink:()=>false}),
    readdirSync: () => [{name:'d',isDirectory:()=>true,isSymbolicLink:()=>false}] }).io;
  assert.throws(() => deep.globSync('**', {cwd:'/safe'}), {code:'ERR_FS_DIR_LIMIT'});
  await assert.rejects(collect(deep.promises.glob('**', {cwd:'/safe'})), {code:'ERR_FS_DIR_LIMIT'});
  const wide = factory({realpathSync:x=>x,readdirSync:()=>new Array(100001)}).io;
  assert.throws(()=>wide.globSync('*',{cwd:'/safe'}), {code:'ERR_FS_DIR_LIMIT'});
});
test('captured helpers survive replacement of public filesystem and string methods', t => {
  const root = fixture(t), { io } = factory();
  io.readdirSync = () => { throw Error('public replacement'); };
  io.opendirSync = () => { throw Error('public replacement'); };
  io.realpathSync = () => { throw Error('public replacement'); };
  const split = String.prototype.split, slice = String.prototype.slice;
  let result;
  try {
    String.prototype.split = () => { throw Error('guest split'); };
    String.prototype.slice = () => { throw Error('guest slice'); };
    result = io.globSync('{src,dist}/*.js', { cwd: root });
  } finally { String.prototype.split = split; String.prototype.slice = slice; }
  assert.deepEqual(result.sort(), ['dist/x.js', 'src/a.js']);
});

for (const pattern of ['**', '**/*.js', ['**/*.js', 'src/**']]) {
  for (const typed of [false, true]) {
    test(`predicate discovery agrees with Node: ${JSON.stringify(pattern)}, typed=${typed}`, async t => {
      const root = fixture(t), { io, calls } = factory();
      const exclude = typed ? entry => entry.name === 'node_modules' || entry.name === 'dist' || entry.name === 'c.js' :
        name => name === 'node_modules' || name === 'dist' || name === 'c.js';
      const options = { cwd: root, withFileTypes: typed, exclude };
      const expected = rows(fs.globSync(pattern, options), root);
      assert.deepEqual(rows(io.globSync(pattern, options), root), expected);
      assert.deepEqual(rows(await collect(io.promises.glob(pattern, options)), root), expected);
      assert(!calls.some(c => c[0] === 'readdirSync' && (c[1].includes('/node_modules') || c[1].endsWith('/dist'))));
    });
  }
}
test('string predicate can prune a nested relative directory route', async t => {
  const root = fixture(t), { io, calls } = factory();
  const options = { cwd: root, exclude: name => name === 'src/deep' };
  const expected = fs.globSync('**/*.js', options).sort();
  assert.deepEqual(io.globSync('**/*.js', options).sort(), expected);
  assert.deepEqual((await collect(io.promises.glob('**/*.js', options))).sort(), expected);
  assert(!calls.some(c => c[0] === 'readdirSync' && c[1].endsWith('/src/deep')));
});
test('predicate and options are captured once, before callback reentry', t => {
  const root = fixture(t), { io } = factory();
  let gets = 0, invoked = 0;
  const options = { cwd: root, withFileTypes: true, get exclude() {
    gets++;
    return function (entry) {
      assert.equal(arguments.length, 1);
      assert.equal(this, undefined);
      if (invoked++ === 0) {
        options.cwd = '/unused'; options.withFileTypes = false;
        Object.defineProperty(options, 'exclude', { value() { throw Error('late replacement'); } });
        assert.deepEqual(io.globSync('src/*.js', { cwd: root }), ['src/a.js']);
      }
      return entry.name === 'dist';
    };
  } };
  const expected = rows(fs.globSync('**/*.js', { cwd: root, withFileTypes: true, exclude: entry => entry.name === 'dist' }), root);
  assert.deepEqual(rows(io.globSync('**/*.js', options), root), expected);
  assert.equal(gets, 1);
  assert(invoked > 1);
});
test('typed predicates cannot redirect or suppress descent by rewriting Dirents', async t => {
  const root = fixture(t), { io, calls } = factory();
  const options = { cwd: root, withFileTypes: true, exclude(entry) {
    if (entry.name === 'src') {
      entry.name = '../node_modules'; entry.parentPath = '/outside';
      entry.isDirectory = () => false; entry.isSymbolicLink = () => true;
    }
    return false;
  } };
  const result = rows(await collect(io.promises.glob('src/**/*.js', options)), root);
  assert.deepEqual(result.map(row => row[0]), ['src/a.js', 'src/deep/c.js']);
  assert(!calls.some(c => c[0] === 'readdirSync' && (c[1].includes('node_modules') || c[1] === '/outside')));
});
test('filesystem mutation in a nonmatching-directory predicate is checked before descent', t => {
  const root = fixture(t), { io, calls } = factory();
  assert.throws(() => io.globSync('src/**/*.js', { cwd: root, withFileTypes: true, exclude(entry) {
    if (entry.name === 'src') {
      fs.renameSync(root + '/src', root + '/retained');
      fs.symlinkSync('node_modules', root + '/src');
    }
    return false;
  } }), { code: 'ERR_FS_DIR_CHANGED' });
  assert.equal(calls.filter(call => call[0] === 'readdirSync').length, 1);
});
test('async predicate execution is demand-driven and stops on return', async t => {
  const root = fixture(t), { io, calls } = factory();
  let predicates = 0;
  const options = { cwd: root, exclude() { predicates++; return false; } };
  const unopened = io.promises.glob('**/*.js', options);
  await unopened.return();
  assert.equal(predicates, 0); assert.equal(calls.length, 0);
  const scan = io.promises.glob('**/*.js', options);
  assert.equal((await scan.next()).value, 'app.js');
  const observed = [predicates, calls.length];
  await scan.return();
  assert.deepEqual(await scan.next(), { done: true, value: undefined });
  assert.deepEqual([predicates, calls.length], observed);
});
test('predicate failures retain identity, including falsy thrown values, without partial success', async t => {
  const root = fixture(t), { io } = factory();
  for (const failure of [undefined, null, 0, 'stop', Error('predicate failure')]) {
    const options = { cwd: root, exclude() { throw failure; } };
    assert.throws(() => io.globSync('**/*.js', options), e => Object.is(e, failure));
    const scan = io.promises.glob('**/*.js', options);
    await assert.rejects(scan.next(), e => Object.is(e, failure));
    assert.deepEqual(await scan.next(), { done: true, value: undefined });
  }
  assert.deepEqual(io.globSync('src/*.js', { cwd: root }), ['src/a.js']);
});
test('a predicate failure after publication closes all suspended traversal frames', async t => {
  const root = fixture(t), { io, calls } = factory();
  const failure = Error('after first match'); let stopped = false;
  const scan = io.promises.glob('**/*.js', { cwd: root, exclude() { if (stopped) throw failure; return false; } });
  assert.equal((await scan.next()).value, 'app.js');
  stopped = true;
  await assert.rejects(scan.next(), e => e === failure);
  const count = calls.length;
  await scan.return();
  assert.deepEqual(await scan.next(), { done: true, value: undefined });
  assert.equal(calls.length, count);
});
test('predicate return values use synchronous truthiness without touching then', async t => {
  const root = fixture(t), { io } = factory();
  const sentinel = { get then() { throw Error('must not assimilate predicate return'); } };
  const options = { cwd: root, exclude: () => sentinel };
  assert.deepEqual(io.globSync('**/*.js', options), []);
  assert.deepEqual(await collect(io.promises.glob('**/*.js', options)), []);
  assert.deepEqual(fs.globSync('**/*.js', options), []);
});
test('predicate-mutable names cannot bypass collected-name limits or invoke getters during accounting', () => {
  let reads = 0;
  const root = '/safe/' + 'd'.repeat(3000);
  const { io } = factory({ realpathSync: x => x, readdirSync: () =>
    Array.from({ length: 2000 }, (_, i) => ({ name: String(i), isDirectory: () => false, isSymbolicLink: () => false })) });
  assert.throws(() => io.globSync('*', { cwd: root, withFileTypes: true, exclude(entry) {
    Object.defineProperty(entry, 'name', { get() { reads++; throw Error('mutable name read'); } });
    return false;
  } }), { code: 'ERR_FS_GLOB_LIMIT' });
  assert.equal(reads, 0);
});
test('predicate cannot turn provider refusal into an empty successful scan', async t => {
  const root = fixture(t), refusal = Object.assign(Error('no read capability'), { code: 'ERR_CAPABILITY_MISSING' });
  const { io } = factory({ readdirSync() { throw refusal; } });
  let invoked = 0;
  const options = { cwd: root, exclude() { invoked++; return true; } };
  assert.throws(() => io.globSync('**/*.js', options), e => e === refusal);
  await assert.rejects(collect(io.promises.glob('**/*.js', options)), e => e === refusal);
  assert.equal(invoked, 0);
});
test('static leaf predicates are honored, including the known Node 22.16 reference difference', t => {
  const root = fixture(t), { io } = factory();
  const options = { cwd: root, exclude: name => name === 'a.js' };
  assert.deepEqual(io.globSync('src/*.js', options), []);
  const reference = fs.globSync('src/*.js', options);
  if (reference.length !== 0) {
    t.diagnostic('REFERENCE DIFFERENCE: this Node version skips the a.js predicate for src/*.js; production filters the leaf. Not a parity pass.');
  }
});

function callbackGlob(io, pattern, options) {
  return new Promise((resolve, reject) => {
    assert.equal(io.glob(pattern, options, (error, values) => error ? reject(error) : resolve(values)), undefined);
  });
}
for (const pattern of ['**/*.js', 'packages/*/package.json', ['src/**', '**/*.js'], []]) {
  for (const typed of [false, true]) {
    test(`callback discovery shares sync/iterator results: ${JSON.stringify(pattern)}, typed=${typed}`, async t => {
      const root = fixture(t), { io } = factory();
      const options = { cwd: root, withFileTypes: typed, exclude: ['node_modules/**', 'dist/**'] };
      const expected = rows(await callbackGlob(fs, pattern, options), root);
      assert.deepEqual(rows(await callbackGlob(io, pattern, options), root), expected);
      assert.deepEqual(rows(io.globSync(pattern, options), root), expected);
    });
  }
}
test('callback-only overload returns undefined and does not run inline', async () => {
  const { io, calls } = factory(); let sync = true;
  assert.equal(io.glob.name, 'glob'); assert.equal(io.glob.length, 3);
  const result = new Promise((resolve, reject) => {
    assert.equal(io.glob([], function (error, entries) {
      try {
        assert.equal(sync, false); assert.equal(this, undefined);
        assert.equal(arguments.length, 2); assert.equal(error, null);
        assert.deepEqual(entries, []); resolve();
      } catch (failure) { reject(failure); }
    }), undefined);
  });
  sync = false; await result;
  assert.equal(calls.length, 0);
});
test('callback query is captured before return but no host effects run inline', async t => {
  const root = fixture(t), { io, calls } = factory();
  const pattern = ['src/*.js'], options = { cwd: root, exclude: [] };
  const pending = callbackGlob(io, pattern, options);
  assert.equal(calls.length, 0);
  pattern[0] = '**'; options.cwd = '/unused'; options.exclude.push('**');
  assert.deepEqual(await pending, ['src/a.js']);
});
test('callback type errors are synchronous and do not inspect queries or perform I/O', () => {
  const { io, calls } = factory();
  const pattern = []; Object.defineProperty(pattern, 0, { get() { throw Error('query inspected'); } });
  for (const value of [null, undefined, 0, 'callback', {}]) {
    assert.throws(() => io.glob(pattern, {}, value), { code: 'ERR_INVALID_ARG_TYPE' });
  }
  assert.equal(calls.length, 0);
});
test('query errors are delivered asynchronously once with no partial result', async () => {
  const { io, calls } = factory();
  for (const [pattern, options] of [[null, {}], ['*', { exclude: 42 }], ['../*', {}]]) {
    let sync = true, count = 0;
    const completion = new Promise((resolve, reject) => {
      io.glob(pattern, options, function (error) {
        try {
          count++; assert.equal(sync, false); assert.equal(arguments.length, 1);
          assert(error.code); resolve();
        } catch (failure) { reject(failure); }
      });
    });
    sync = false; await completion; await Promise.resolve(); assert.equal(count, 1);
  }
  assert.equal(calls.length, 0);
});
test('provider and predicate failures keep identity through callback completion', async t => {
  const root = fixture(t);
  for (const failure of [Error('provider refused'), null, undefined, false]) {
    const { io } = factory({ readdirSync() { throw failure; } });
    let count = 0;
    await new Promise((resolve, reject) => io.glob('**/*.js', { cwd: root }, function (error) {
      try { count++; assert.equal(arguments.length, 1); assert.equal(error, failure); resolve(); }
      catch (wrong) { reject(wrong); }
    }));
    await Promise.resolve(); assert.equal(count, 1);
  }
  const { io } = factory(), failure = Error('predicate refused');
  await assert.rejects(callbackGlob(io, '**/*.js', { cwd: root, exclude() { throw failure; } }), e => e === failure);
  assert.deepEqual(await callbackGlob(io, '**/*.js', { cwd: root + '/missing' }), []);
});
test('callback discovery retains predicate pruning and bounded typed accounting', async t => {
  const root = fixture(t), { io, calls } = factory();
  const options = { cwd: root, withFileTypes: true, exclude: entry => entry.name === 'node_modules' || entry.name === 'dist' };
  assert.deepEqual(rows(await callbackGlob(io, '**/*.js', options), root), rows(await callbackGlob(fs, '**/*.js', options), root));
  assert(!calls.some(c => c[0] === 'readdirSync' && (c[1].includes('/node_modules') || c[1].endsWith('/dist'))));
  const wide = factory({ realpathSync: x => x, readdirSync: () => new Array(100001) }).io;
  await assert.rejects(callbackGlob(wide, '*', { cwd: '/safe' }), { code: 'ERR_FS_DIR_LIMIT' });
});
test('callback return values are ignored rather than assimilated', async () => {
  const { io } = factory(); let inspected = 0;
  await new Promise(resolve => io.glob([], () => {
    resolve(); return { get then() { inspected++; throw Error('callback return inspected'); } };
  }));
  await Promise.resolve(); assert.equal(inspected, 0);
});
test('captured Promise reactions survive public replacement during submission', async t => {
  const root = fixture(t), { io } = factory();
  const original = Promise.prototype.then;
  let pending;
  try {
    Promise.prototype.then = () => { throw Error('public then replaced'); };
    pending = callbackGlob(io, 'src/*.js', { cwd: root });
  } finally { Promise.prototype.then = original; }
  assert.deepEqual(await pending, ['src/a.js']);
});
test('a throwing completion callback is never invoked twice, with Node difference reported', t => {
  const { spawnSync } = require('node:child_process');
  const program = `
    'use strict'; const fs=require('node:fs'), vm=require('node:vm');
    const io=process.argv[1]==='candidate' ? vm.runInThisContext(fs.readFileSync(process.argv[2],'utf8'))({
      promises:{},readdirSync:fs.readdirSync,lstatSync:fs.lstatSync,realpathSync:fs.realpathSync
    }) : fs;
    let calls=0;
    process.on('uncaughtException',e=>console.log('UNEXPECTED_UNCAUGHT',e.message));
    process.on('unhandledRejection',e=>console.log('CALLBACK_THROW',e.message,calls));
    io.glob([],()=>{calls++;throw Error('completion');});
  `;
  for (const mode of ['reference', 'candidate']) {
    const result = spawnSync(process.execPath, ['--no-warnings', '-e', program, mode,
      path.join(__dirname, '../../crates/franken-engine/src/lowering_pipeline/fs_directory.js')], { encoding: 'utf8', timeout: 5000 });
    assert.equal(result.error, undefined); assert.equal(result.status, 0);
    assert.equal(result.stderr, '');
    if (mode === 'reference' && result.stdout !== 'CALLBACK_THROW completion 1\n') {
      t.diagnostic('REFERENCE DIFFERENCE: ' + result.stdout.trim() + '; production invokes the callback once. Not a parity pass.');
    } else assert.equal(result.stdout, 'CALLBACK_THROW completion 1\n');
  }
});
