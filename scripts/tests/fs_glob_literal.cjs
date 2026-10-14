'use strict';
// Functional and allocation-work regression for the exact shipped factory.
// Runs on Node primitives; not native-engine throughput or Bun parity.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const source = fs.readFileSync(process.env.FRANKEN_GLOB_TEST_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/fs_directory.js'), 'utf8');
function candidate(overrides = {}, instrument = false) {
  const context = vm.createContext({});
  if (instrument) vm.runInContext(`
    globalThis.allocations = 0;
    const originalCreate = Object.create;
    Object.create = function (prototype) { allocations++; return originalCreate(prototype); };
  `, context);
  const install = vm.runInContext(source, context);
  const io = install({ promises: {}, readdirSync: fs.readdirSync,
    realpathSync: fs.realpathSync, lstatSync: fs.lstatSync, ...overrides });
  return { io, context };
}
function dirent(name) { return { name, isDirectory: () => false, isSymbolicLink: () => false }; }
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-literal-glob-'));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const name of ['package.json', 'package.JSON', 'manifest.json', 'manifest[',
    'brace{x}.json', '.hidden.json', 'é.json', '😀.json',
    'sub/package.json', 'sub/deep/package.json', 'sub/other.json']) {
    fs.mkdirSync(path.dirname(path.join(root, name)), { recursive: true });
    fs.writeFileSync(path.join(root, name), name);
  }
  return root;
}
async function collected(iterable) { const result = []; for await (const entry of iterable) result.push(entry); return result.sort(); }
for (const pattern of ['package.json', 'manifest[', 'brace{x}.json', '.hidden.json', 'é.json', '😀.json',
  'missing.json', 'sub/package.json', '**/package.json', '{package,manifest}.json', 'p[a]ckage.json', '*.json']) {
  test(`literal specialization preserves reference results: ${pattern}`, async t => {
    const root = fixture(t), { io } = candidate();
    const options = { cwd: root };
    const expected = fs.globSync(pattern, options).sort();
    assert.deepEqual(Array.from(io.globSync(pattern, options)).sort(), expected);
    assert.deepEqual(await collected(io.promises.glob(pattern, options)), expected);
    const callback = await new Promise((resolve, reject) => io.glob(pattern, options,
      (error, entries) => error ? reject(error) : resolve(Array.from(entries).sort())));
    assert.deepEqual(callback, expected);
  });
}
test('literal matching does not allocate dynamic-programming rows per filename', () => {
  for (const count of [64, 512, 2048]) {
    const { io, context } = candidate({ realpathSync: x => x,
      readdirSync: () => Array.from({ length: count }, (_, i) => dirent('manifest-' + i + '.json')) }, true);
    assert.deepEqual(Array.from(io.globSync('package.json', { cwd: '/safe' })), []);
    // One initial NFA state, one snapshot, one transition object per entry.
    // The bound allows fixed setup changes but not one DP row per literal unit.
    assert(context.allocations <= count + 16, `${count} names allocated ${context.allocations} null objects`);
  }
});
test('long literal queries fit the existing work limit without increasing it', () => {
  const literal = 'manifest-' + 'x'.repeat(120) + '.json';
  const names = Array.from({ length: 1024 }, (_, i) => literal + i);
  names.push(literal);
  const { io } = candidate({ realpathSync: x => x, readdirSync: () => names.map(dirent) });
  assert.deepEqual(Array.from(io.globSync(literal, { cwd: '/safe' })), [literal]);
});
test('literal state cannot be inherited by wildcard segments from guest prototypes', t => {
  const root = fixture(t), { io, context } = candidate();
  vm.runInContext("Object.prototype.literal = 'never-match';", context);
  assert.deepEqual(Array.from(io.globSync('*.json', { cwd: root })).sort(), fs.globSync('*.json', { cwd: root }).sort());
});
test('literal optimization does not skip unsupported-pattern or resource validation', () => {
  let reads = 0;
  const { io } = candidate({ realpathSync: x => x, readdirSync: () => { reads++; return []; } });
  for (const pattern of ['name@(a|b).json', 'name+(a|b).json', '{1..9}', '../package.json', 'x'.repeat(4097)]) {
    assert.throws(() => io.globSync(pattern, { cwd: '/safe' }));
  }
  assert.equal(reads, 0);
});
