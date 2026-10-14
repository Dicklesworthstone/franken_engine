'use strict';
// Execute the production copy factory on an explicit Node reference host.
// This tests its algorithms, real filesystem effects and injected short I/O;
// it is NOT evidence that the Rust parser, lowerer or host provider passed.
const assert = require('node:assert/strict');
const { test } = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const vm = require('node:vm');
const source = fs.readFileSync(path.join(__dirname, '../../crates/franken-engine/src/lowering_pipeline/fs_copy.js'), 'utf8');
const install = vm.runInThisContext(source, { filename: 'fs_copy.js' });
function candidate(overrides = {}) {
  return install({ ...fs, ...overrides, promises: { ...fs.promises } });
}
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'franken-copy-'));
  t.after(() => fs.rmSync(root, { force: true, recursive: true }));
  return root;
}
function put(root, file, data = file) {
  const target = path.join(root, file);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, data);
  return target;
}
function tree(root) {
  const result = {};
  function visit(directory, relative = '') {
    for (const name of fs.readdirSync(directory).sort()) {
      const key = relative + name;
      const file = path.join(directory, name);
      const info = fs.lstatSync(file);
      if (info.isDirectory()) { result[key + '/'] = 'directory'; visit(file, key + '/'); }
      else if (info.isSymbolicLink()) result[key] = ['link', fs.readlinkSync(file)];
      else result[key] = ['file', fs.readFileSync(file).toString('hex'), info.mode & 511];
    }
  }
  visit(root);
  return result;
}
for (const [name, implementation] of [['candidate', candidate()], ['node', fs]]) {
  for (const asyncMode of [false, true]) {
    const run = asyncMode ? implementation.promises.cp : implementation.cpSync;
    const label = name + (asyncMode ? ': promise' : ': sync');
    test(label + ' recursively copies binary trees and directory modes', async t => {
      const root = fixture(t);
      const src = path.join(root, 'src'); const dst = path.join(root, 'nested/dst');
      put(src, 'a/binary', Buffer.from([0, 128, 255, 13, 10]));
      put(src, 'empty', ''); put(src, 'empty-dir/.placeholder', '');
      fs.unlinkSync(path.join(src, 'empty-dir/.placeholder'));
      fs.chmodSync(path.join(src, 'a'), 0o751);
      fs.chmodSync(path.join(src, 'a/binary'), 0o640);
      assert.equal(await run(src, dst, { recursive: true }), undefined);
      assert.deepEqual(tree(dst), tree(src));
      assert.equal(fs.statSync(path.join(dst, 'a')).mode & 511, 0o751);
    });
    test(label + ' force and errorOnExist preserve existing data', async t => {
      const root = fixture(t); const src = put(root, 'src', 'new'); const dst = put(root, 'dst', 'old');
      await run(src, dst, { force: false });
      assert.equal(fs.readFileSync(dst, 'utf8'), 'old');
      await assert.rejects(async () => run(src, dst, { force: false, errorOnExist: true }), { code: 'ERR_FS_CP_EEXIST' });
      assert.equal(fs.readFileSync(dst, 'utf8'), 'old');
      await run(src, dst);
      assert.equal(fs.readFileSync(dst, 'utf8'), 'new');
      assert.equal(fs.readFileSync(src, 'utf8'), 'new');
    });
    test(label + ' excludes complete filtered subtrees', async t => {
      const root = fixture(t); const src = path.join(root, 'src'); const dst = path.join(root, 'dst');
      put(src, 'keep/value', 'yes'); put(src, 'skip/value', 'no');
      const seen = [];
      await run(src, dst, { recursive: true, filter(a, b) { seen.push(path.relative(src, a)); return path.basename(a) !== 'skip'; } });
      assert.equal(fs.readFileSync(path.join(dst, 'keep/value'), 'utf8'), 'yes');
      assert.equal(fs.existsSync(path.join(dst, 'skip')), false);
      assert.equal(seen.includes(path.join('skip', 'value')), false);
    });
    test(label + ' rejects self-copy and output inside its source before mutation', async t => {
      const root = fixture(t); const src = path.join(root, 'src'); put(src, 'file', 'retained');
      for (const dest of [src, path.join(src, 'out')]) {
        await assert.rejects(async () => run(src, dest, { recursive: true }), { code: 'ERR_FS_CP_EINVAL' });
      }
      assert.equal(fs.existsSync(path.join(src, 'out')), false);
      assert.equal(fs.readFileSync(path.join(src, 'file'), 'utf8'), 'retained');
    });
    test(label + ' directory conflicts and missing recursive option fail', async t => {
      const root = fixture(t); const src = path.join(root, 'src'); put(src, 'file');
      const file = put(root, 'destination', 'unchanged');
      await assert.rejects(async () => run(src, path.join(root, 'out')), { code: 'ERR_FS_EISDIR' });
      await assert.rejects(async () => run(src, file, { recursive: true }), { code: 'ERR_FS_CP_DIR_TO_NON_DIR' });
      await assert.rejects(async () => run(file, src), { code: 'ERR_FS_CP_NON_DIR_TO_DIR' });
      assert.equal(fs.readFileSync(file, 'utf8'), 'unchanged');
    });
    test(label + ' copies symlink text or dereferenced file contents', async t => {
      const root = fixture(t); put(root, 'src/value', 'value');
      const link = path.join(root, 'src/link'); fs.symlinkSync('value', link);
      await run(link, path.join(root, 'verbatim'), { verbatimSymlinks: true });
      assert.equal(fs.readlinkSync(path.join(root, 'verbatim')), 'value');
      await run(link, path.join(root, 'absolute'));
      assert.equal(fs.readlinkSync(path.join(root, 'absolute')), path.join(root, 'src/value'));
      // Node 22.16's synchronous cp rejects a dereferenced symlink unless
      // recursive is enabled; use the common recursive contract in this row.
      await run(link, path.join(root, 'followed'), { dereference: true, recursive: true });
      assert.equal(fs.lstatSync(path.join(root, 'followed')).isFile(), true);
      assert.equal(fs.readFileSync(path.join(root, 'followed'), 'utf8'), 'value');
    });
    test(label + ' preserves falsy filter failures rather than treating them as success', async t => {
      const root = fixture(t); const src = put(root, 'src', 'value');
      let caught = true;
      try { await run(src, path.join(root, 'dst'), { filter() { throw false; } }); }
      catch (error) { caught = error; }
      assert.equal(caught, false);
      assert.equal(fs.existsSync(path.join(root, 'dst')), false);
    });
  }
  test(name + ': asynchronous filters complete before copying and may reenter', async t => {
    const root = fixture(t); const src = path.join(root, 'src'); const dst = path.join(root, 'dst');
    put(src, 'keep', 'old'); put(src, 'skip', 'skip');
    let active = 0; let peak = 0; let release;
    const gate = new Promise(resolve => { release = resolve; });
    const copying = implementation.promises.cp(src, dst, {
      recursive: true,
      async filter(a, b) {
        peak = Math.max(peak, ++active);
        await gate;
        if (path.basename(a) === 'keep') {
          fs.writeFileSync(a, 'new');
          await implementation.promises.cp(a, path.join(root, 'independent'));
        }
        active--;
        return path.basename(a) !== 'skip';
      }
    });
    await Promise.resolve(); assert.equal(fs.existsSync(dst), false);
    release(); await copying;
    assert.equal(peak, 1);
    assert.equal(fs.readFileSync(path.join(dst, 'keep'), 'utf8'), 'new');
    assert.equal(fs.readFileSync(path.join(root, 'independent'), 'utf8'), 'new');
    assert.equal(fs.existsSync(path.join(dst, 'skip')), false);
  });
}

test('candidate: fixed-size buffer continues short reads and writes without whole-file materialization', t => {
  const root = fixture(t); const bytes = Buffer.alloc(40007); for (let i = 0; i < bytes.length; i++) bytes[i] = i % 251;
  const src = put(root, 'src', bytes); const dst = path.join(root, 'dst');
  let reads = 0; let writes = 0; let maximum = 0; const active = new Set(); let peak = 0;
  const copy = candidate({
    copyFileSync() { throw Error('must not use the unbounded copy primitive'); },
    openSync(file, flags) { const fd = fs.openSync(file, flags); active.add(fd); peak = Math.max(peak, active.size); return fd; },
    closeSync(fd) { assert(active.delete(fd)); return fs.closeSync(fd); },
    readSync(fd, data, offset, length, position) { reads++; maximum = Math.max(maximum, length); return fs.readSync(fd, data, offset, Math.min(length, 997), position); },
    writeSync(fd, data, offset, length, position) { writes++; maximum = Math.max(maximum, length); return fs.writeSync(fd, data, offset, Math.min(length, 211), position); },
  });
  copy.cpSync(src, dst);
  assert.deepEqual(fs.readFileSync(dst), bytes);
  assert(maximum <= 16384); assert(reads > 40); assert(writes > reads);
  assert.equal(peak, 2); assert.equal(active.size, 0);
});

test('candidate: failed destination acquisition releases the already-open source', t => {
  const root = fixture(t); const src = put(root, 'src'); const boom = Error('cannot open output'); let opened = 0; let closed = 0;
  const copy = candidate({ openSync(p, flags) { if (flags === 'w') throw boom; opened++; return fs.openSync(p, flags); }, closeSync(fd) { closed++; fs.closeSync(fd); } });
  assert.throws(() => copy.cpSync(src, path.join(root, 'dst')), e => e === boom);
  assert.equal(opened, 1); assert.equal(closed, 1);
});

test('candidate: no-progress and invalid counts fail and close both descriptors', t => {
  for (const bad of [0, -1, NaN, 0.5, 65536]) {
    const root = fixture(t); const src = put(root, 'src', 'abc'); let closed = 0;
    const copy = candidate({ writeSync() { return bad; }, closeSync(fd) { closed++; fs.closeSync(fd); } });
    assert.throws(() => copy.cpSync(src, path.join(root, 'dst')), { code: 'EIO' });
    assert.equal(closed, 2);
  }
});

test('candidate: original I/O failure and both cleanup failures remain observable', t => {
  const root = fixture(t); const src = put(root, 'src', 'abc'); let closed = 0;
  const copy = candidate({ writeSync() { throw null; }, closeSync(fd) { fs.closeSync(fd); closed++; throw Error('close-' + closed); } });
  assert.throws(() => copy.cpSync(src, path.join(root, 'dst')), e => {
    assert(e instanceof AggregateError); assert(e.errors[0] instanceof AggregateError);
    assert.equal(e.errors[0].errors[0], null); return true;
  });
  assert.equal(closed, 2);
});

test('candidate: unsupported options fail before any filesystem effect', async () => {
  let effects = 0;
  const refuse = () => { effects++; throw Error('unexpected filesystem effect'); };
  const copy = candidate({ lstatSync: refuse, realpathSync: refuse, openSync: refuse });
  for (const options of [{ preserveTimestamps: true }, { mode: 1 }, { mode: 2 }, { mode: 4 }, { signal: {} }, { recursive: 'true' }]) {
    assert.throws(() => copy.cpSync('src', 'dst', options));
    await assert.rejects(copy.promises.cp('src', 'dst', options));
  }
  assert.equal(effects, 0);
});

test('candidate: output redirected into source through an ancestor symlink is refused', t => {
  const root = fixture(t); const src = path.join(root, 'src'); put(src, 'file', 'unchanged');
  fs.symlinkSync(src, path.join(root, 'alias'));
  assert.throws(() => candidate().cpSync(src, path.join(root, 'alias/out'), { recursive: true }), { code: 'ERR_FS_CP_EINVAL' });
  assert.equal(fs.existsSync(path.join(src, 'out')), false);
});

test('candidate: dereferenced directory cycles terminate with an explicit error', t => {
  const root = fixture(t); const src = path.join(root, 'src'); fs.mkdirSync(src);
  fs.symlinkSync('.', path.join(src, 'loop'));
  assert.throws(() => candidate().cpSync(src, path.join(root, 'dst'), { recursive: true, dereference: true }), { code: 'ERR_FS_CP_ELOOP' });
});

test('candidate: native-subset metadata cannot make a hard-linked overwrite truncate its source', t => {
  const root = fixture(t); const src = put(root, 'src', 'retained'); const dst = path.join(root, 'dst'); fs.linkSync(src, dst);
  function subset(p) { const info = fs.lstatSync(p); info.ino = undefined; info.dev = undefined; return info; }
  const copy = candidate({ lstatSync: subset }); copy.cpSync(src, dst);
  assert.equal(fs.readFileSync(src, 'utf8'), 'retained');
  assert.equal(fs.readFileSync(dst, 'utf8'), 'retained');
  assert.notEqual(fs.statSync(src).ino, fs.statSync(dst).ino);
});

test('candidate: invalid directory entry metadata cannot produce a path traversal', t => {
  const root = fixture(t); const src = path.join(root, 'src'); fs.mkdirSync(src);
  const copy = candidate({ readdirSync() { return ['../outside']; } });
  assert.throws(() => copy.cpSync(src, path.join(root, 'dst'), { recursive: true }), { code: 'ERR_FS_CP_INVALID' });
  assert.equal(fs.existsSync(path.join(root, 'dst')), false);
});

test('candidate: changing the public fs methods during filtering does not replace the native operations', t => {
  const root = fixture(t); const src = put(root, 'src', 'original'); const dst = path.join(root, 'dst');
  const copy = candidate(); copy.cpSync(src, dst, { filter() {
    copy.openSync = () => { throw Error('guest replacement'); };
    copy.readSync = () => { throw Error('guest replacement'); };
    return true;
  } });
  assert.equal(fs.readFileSync(dst, 'utf8'), 'original');
});


test('candidate: a symlink to an ordinary file can be dereferenced without directory recursion', t => {
  const root = fixture(t); put(root, 'src', 'bytes'); fs.symlinkSync('src', path.join(root, 'link'));
  candidate().cpSync(path.join(root, 'link'), path.join(root, 'dst'), { dereference: true });
  assert.equal(fs.readFileSync(path.join(root, 'dst'), 'utf8'), 'bytes');
});

test('candidate: traversal refuses excessive depth without pretending the partial tree is complete', t => {
  const root = fixture(t); const src = path.join(root, 'src');
  fs.mkdirSync(path.join(src, ...Array(66).fill('d')), { recursive: true });
  assert.throws(() => candidate().cpSync(src, path.join(root, 'dst'), { recursive: true }), { code: 'ERR_FS_CP_LIMIT' });
});

test('candidate: synchronous filter promises fail before that entry is copied', t => {
  const root = fixture(t); const src = put(root, 'src');
  assert.throws(() => candidate().cpSync(src, path.join(root, 'dst'), { filter() { return Promise.resolve(true); } }), { code: 'ERR_INVALID_RETURN_VALUE' });
  assert.equal(fs.existsSync(path.join(root, 'dst')), false);
});
