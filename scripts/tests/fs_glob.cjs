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
  const root = fs.mkdtempSync(path.join(require('node:os').tmpdir(), 'franken-glob-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
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
  for (const p of [null, 4, ['ok', null], '/absolute/*', '../*', '!*.js', '@(a|b)', '{1..5}', 'a\0b', 'a\\b']) {
    assert.throws(() => io.globSync(p));
    await assert.rejects(collect(io.promises.glob(p)));
  }
  for (const options of [null, [], {cwd:{}}, {exclude:'dist'}, {exclude:()=>false}, {withFileTypes:1}, {followSymlinks:true}, {maxDepth:2}]) {
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
