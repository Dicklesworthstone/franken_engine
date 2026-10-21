'use strict';
// The production directory/glob installer runs here on Node language and fs
// primitives. These checks do not execute the Rust parser, interpreter or host.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');
const sourcePath = process.env.FRANKEN_DIRECTORY_SOURCE || path.join(__dirname,
  '../../crates/franken-engine/src/lowering_pipeline/fs_directory.js');
const source = fs.readFileSync(sourcePath, 'utf8');
const install = vm.runInThisContext(source, { filename: sourcePath });
const options = { timeout: 10000 };
function candidate(root, visits = []) {
  const api = { promises: {}, readdirSync(p, o) { visits.push(path.relative(root, p)); return fs.readdirSync(p, o); },
    realpathSync: fs.realpathSync, lstatSync: fs.lstatSync };
  return install(api);
}
function fixture(files) {
  // Provider paths and traversal assertions use the same physical root even
  // when the host's temporary directory is reached through a symlink.
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'franken-extglob-')));
  for (const [name, text] of Object.entries(files)) {
    const file = path.join(root, name); fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
  }
  // Do not delete fixtures: the invocation's temporary paths remain available
  // for inspecting failures. The OS/session owns eventual temporary cleanup.
  return root;
}
function callbackGlob(api, pattern, opts) {
  return new Promise((resolve, reject) => api.glob(pattern, opts, (error, names) => error ? reject(error) : resolve(names)));
}
async function allForms(api, pattern, opts) {
  return [api.globSync(pattern, opts).sort(),
    (await callbackGlob(api, pattern, opts)).sort(),
    (await Array.fromAsync(api.promises.glob(pattern, opts))).sort()];
}
function flatApi(names, count = {}) {
  return install({ promises: {}, realpathSync() { return '/fixture'; },
    lstatSync() { return { isDirectory: () => true, isSymbolicLink: () => false }; },
    readdirSync() { count.reads = (count.reads || 0) + 1;
      return names.map(name => ({ name, isDirectory: () => false, isSymbolicLink: () => false })); } });
}
const ordinary = ['a', 'b', 'ab', 'aa', 'aba', 'aaaa', 'c', 'ac', 'abc', 'x', 'file.js', 'file.ts',
  'file.jsx', 'file.tsx', 'file.cjs', 'file.mjs', '.env', '.config', '.foo.js', 'foo.js', 'foo.test.js',
  'thing-1.js', 'thing-2.ts', 'café.ts', 'é.js', 'x-y', 'x--y', 'a|b', 'foo(bar)', '😀.js'];
const cases = [
  '@(a|b)', '+(a|b)', '?(a|b)', '*(a|b)', 'a@(b|c)', '@(ab|a)b',
  '*.@(js|ts)', '*.@(cjs|mjs|js|ts|tsx)', '@(foo|bar)?(.test).@(js|ts)',
  '+(a|aa)b', '*(@(a|ab)|b)', '?(@(a|b))', 'thing-@([12]|[34]).@(js|ts)',
  '@(.env|.config)', '@(.env|*.js)', '@(café|é).@(js|ts)', '@(😀|é).js',
  '@(a|b)*', '@(file|thing)*.@(js|ts)', '?(a).env', '*(a).env',
  '@(|a).env', '+(|a).env', '?(*)*', '*(|a)*', '@(.*|*)', '@(a|.env)*'
];

test('positive extglob operators match the live Node filename oracle', options, () => {
  const api = flatApi(ordinary);
  for (const pattern of cases) {
    const actual = api.globSync(pattern).sort();
    const expected = ordinary.filter(name => path.matchesGlob(name, pattern)).sort();
    assert.deepEqual(actual, expected, pattern);
  }
});

test('one traversal serves sync, callback, Promise discovery and pattern exclusions', options, async () => {
  const root = fixture({
    'packages/alpha/package.json': '{"name":"alpha"}', 'packages/beta/package.json': '{"name":"beta"}',
    'apps/ui/package.json': '{"name":"ui"}', 'vendor/skip/package.json': '{}',
    'packages/alpha/src/main.js': 'alpha', 'packages/alpha/src/main.test.js': 'test',
    'packages/beta/src/index.ts': 'beta', 'packages/beta/src/helper.mjs': 'helper',
    'apps/ui/src/app.tsx': 'ui', 'apps/ui/build/cache.js': 'cache', 'docs/index.md': 'docs'
  });
  const api = candidate(root), settings = { cwd: root };
  for (const pattern of ['@(packages|apps)/**/package.json',
    '@(packages|apps)/**/src/*.@(js|ts|tsx|mjs)',
    '@(packages|apps)/**/@(main|index|app).@(js|ts|tsx)']) {
    const expected = fs.globSync(pattern, settings).sort();
    for (const actual of await allForms(api, pattern, settings)) assert.deepEqual(actual, expected, pattern);
  }
  const visits = [], pruned = candidate(root, visits);
  const config = { cwd: root, exclude: ['@(vendor|docs)', '**/@(build|dist)', '**/*.@(test|spec).js'] };
  const actual = pruned.globSync('**/*.@(js|ts|tsx|mjs)', config).sort();
  assert.deepEqual(actual, fs.globSync('**/*.@(js|ts|tsx|mjs)', config).sort());
  assert(!visits.some(name => /^(vendor|docs)(\/|$)/.test(name) || /(^|\/)build$/.test(name)), visits.join(','));
});

test('typed discovery preserves canonical Dirent identity, methods and parent paths', options, async () => {
  const root = fixture({ 'src/a.js': 'a', 'src/b.ts': 'b', 'src/c.txt': 'c', '.config/data.json': '{}' });
  const api = candidate(root);
  const entries = api.globSync('@(src|.config)/*.@(js|ts|json)', { cwd: root, withFileTypes: true });
  assert.deepEqual(entries.map(e => path.relative(root, path.join(e.parentPath, e.name))).sort(),
    ['.config/data.json', 'src/a.js', 'src/b.ts']);
  for (const entry of entries) { assert(entry instanceof fs.Dirent); assert(entry.isFile()); assert(!entry.isSymbolicLink()); }
  const predicate = item => item.isFile() && item.name === 'b.ts';
  const filtered = await Array.fromAsync(api.promises.glob('src/*.@(js|ts)',
    { cwd: root, withFileTypes: true, exclude: predicate }));
  assert.deepEqual(filtered.map(x => x.name), ['a.js']);
});

test('alternation does not enumerate Cartesian combinations and nullable cycles terminate', options, () => {
  const pattern = '@(a|b)'.repeat(32) + '.js';
  const name = 'ab'.repeat(16) + '.js';
  assert.deepEqual(flatApi([name, name + 'x']).globSync(pattern), [name]);
  const nullable = '*(@(|a)|?(b))c';
  const names = ['c', 'ac', 'bc', 'abac', 'zzc'];
  assert.deepEqual(flatApi(names).globSync(nullable).sort(), names.filter(n => path.matchesGlob(n, nullable)).sort());
});

test('malformed, negative, deeply nested and oversized machines fail before filesystem effects', options, async () => {
  for (const pattern of ['@(abc', '@()', '@(a(b)|c)', 'src/!(test).js', '@(a|!(b))', '@('.repeat(17) + 'a' + ')'.repeat(17)]) {
    const counter = {}, api = flatApi(['a'], counter);
    assert.throws(() => api.globSync(pattern), e => /^ERR_FS_GLOB_(UNSUPPORTED|LIMIT)$/.test(e.code), pattern);
    assert.equal(counter.reads, undefined);
    await assert.rejects(callbackGlob(api, pattern), e => /^ERR_FS_GLOB_(UNSUPPORTED|LIMIT)$/.test(e.code));
    assert.equal(counter.reads, undefined);
  }
  const counter = {}, api = flatApi(['a'], counter);
  const patterns = Array.from({length:128}, () => '@(' + 'a'.repeat(260) + '|b)');
  assert.throws(() => api.globSync(patterns), e => e.code === 'ERR_FS_GLOB_LIMIT');
  assert.equal(counter.reads, undefined);
});

test('overlapping patterns and brace expansion still publish each observed path once', options, () => {
  const names = ['main.js', 'main.ts', 'helper.mjs', 'helper.cjs', 'other.txt'];
  const api = flatApi(names);
  assert.deepEqual(api.globSync(['*.@(js|ts)', '*.{js,ts}', '@(helper).@(mjs|cjs)']).sort(), names.slice(0,4).sort());
});

test('character classes containing extglob punctuation remain literal', options, () => {
  const names = ['@a', '+a', '(a', ')a', '|a', '*a', '?a'];
  const api = flatApi(names);
  for (const pattern of ['[@+()?*|]a', '[@(]@(a|b)', '[(]@(a|b)', '@([@+]|[?*])a']) {
    assert.deepEqual(api.globSync(pattern).sort(), names.filter(n => path.matchesGlob(n, pattern)).sort(), pattern);
  }
});

// Deterministic language sampling checks both ambiguous alternatives and
// repeated positive groups against the live reference, not a second matcher.
test('seeded positive extglob programs agree with Node on generated filenames', options, () => {
  let seed = 0x6a4f09;
  function random(n) { seed ^= seed << 13; seed ^= seed >>> 17; seed ^= seed << 5; return (seed >>> 0) % n; }
  const names = new Set(ordinary);
  for (let i=0;i<150;i++) { let n=''; for(let j=random(9);j>=0;j--)n+='ab.c'[random(4)]; if(n!=='.' && n!=='..')names.add(n); }
  const all=[...names]; const api=flatApi(all);
  const atoms=['a','b','ab','a*','?b','[ab]','a?','*','@(a|b)','+(a|b)','?(a|b)'];
  for(let i=0;i<300;i++) {
    const op='@+?*'[random(4)];
    const pattern=(random(3)===0?'x':'')+op+'('+atoms[random(atoms.length)]+'|'+atoms[random(atoms.length)]+')'+
      ['', 'a', 'b', '.@(js|ts)', '*','*b'][random(6)];
    assert.deepEqual(api.globSync(pattern).sort(),all.filter(n=>path.matchesGlob(n,pattern)).sort(),pattern);
  }
});

test('repeated ambiguous groups exhaust the existing work budget without partial callback success', options, async () => {
  const names = Array.from({length:200}, (_, i) => 'a'.repeat(1000) + i);
  const api = flatApi(names);
  const patterns = Array.from({length:32}, () => '+(a|aa)b');
  assert.throws(() => api.globSync(patterns), e => e.code === 'ERR_FS_GLOB_LIMIT');
  let calls = 0;
  await new Promise((resolve, reject) => api.glob(patterns, function (error) {
    try {
      calls++; assert.equal(arguments.length, 1); assert.equal(error.code, 'ERR_FS_GLOB_LIMIT'); resolve();
    } catch (failure) { reject(failure); }
  }));
  await Promise.resolve(); assert.equal(calls, 1);
  assert.deepEqual(api.globSync('@(missing|absent)'), []);
});

test('early iterator return stops extglob traversal before child snapshots', options, async () => {
  const root = fixture({'src/a.js':'a','src/deep/b.ts':'b','vendor/c.js':'c'}), visits=[];
  const api = candidate(root, visits);
  const unopened = api.promises.glob('@(src|vendor)/**', {cwd:root});
  await unopened.return(); assert.deepEqual(visits, []);
  const scan = api.promises.glob('@(src|vendor)/**', {cwd:root});
  const first = await scan.next(); assert.equal(first.done, false); assert.equal(first.value, 'src');
  assert.deepEqual(visits, ['']); await scan.return();
  assert.deepEqual(await scan.next(), {value:undefined,done:true}); assert.deepEqual(visits, ['']);
});

test('extglob discovery retains provider refusal identity and closes failed iterators', options, async () => {
  for (const reason of [Error('denied'), null, undefined, false]) {
    const api=install({promises:{},realpathSync:p=>p,lstatSync:fs.lstatSync,readdirSync(){throw reason;}});
    assert.throws(()=>api.globSync('*.@(js|ts)'), e=>Object.is(e,reason));
    const scan=api.promises.glob('*.@(js|ts)');
    await assert.rejects(scan.next(), e=>Object.is(e,reason));
    assert.deepEqual(await scan.next(), {value:undefined,done:true});
  }
});
